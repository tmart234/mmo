pub use anyhow::{anyhow, bail, Context, Result};

use common::{
    crypto::{client_input_sign_bytes, now_ms},
    framing::{recv_msg, send_msg},
    proto::{ClientCmd, ClientInput, ClientToGs, PlayTicket, ServerHello, WorldSnapshot},
};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use quinn::{ClientConfig, Endpoint, RecvStream, SendStream};
use rand::rngs::OsRng;
use std::{fs, path::Path, sync::Arc};
use tokio::time::{sleep, timeout, Duration};

pub struct Session {
    pub send_stream: SendStream,
    pub recv_stream: RecvStream,
    pub session_id: [u8; 16],
    pub vs_pub: [u8; 32],
    pub ticket: PlayTicket,
    pub client_pub: [u8; 32],
    pub client_sk: SigningKey,
}

/// Configure QUIC client with insecure cert verification for localhost dev.
fn configure_quic_client() -> Result<ClientConfig> {
    // For localhost dev, we skip cert verification
    let crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();

    let mut client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?,
    ));

    // Performance tuning
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_concurrent_bidi_streams(10_u32.into());
    transport_config.keep_alive_interval(Some(Duration::from_secs(5)));

    client_config.transport_config(Arc::new(transport_config));
    Ok(client_config)
}

/// Skip server certificate verification for localhost development.
#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

// ---------- key / trust roots ----------

/// Read the pinned VS public key from disk (keys/vs_ed25519.pub).
pub fn load_pinned_vs_pub() -> Result<[u8; 32]> {
    let bytes =
        fs::read("keys/vs_ed25519.pub").context("read VS pubkey from keys/vs_ed25519.pub")?;
    if bytes.len() != 32 {
        return Err(anyhow!(
            "vs_ed25519.pub length was {}, expected 32",
            bytes.len()
        ));
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&bytes);
    Ok(pk)
}

/// Load or create the player's Ed25519 identity keypair; returns (sk, pub_bytes).
pub fn load_or_create_client_keys() -> Result<(SigningKey, [u8; 32])> {
    let sk_path = Path::new("keys/client_ed25519.pk8");
    let pk_path = Path::new("keys/client_ed25519.pub");

    if sk_path.exists() && pk_path.exists() {
        let sk_bytes = fs::read(sk_path).context("read client_ed25519.pk8")?;
        let pk_bytes = fs::read(pk_path).context("read client_ed25519.pub")?;

        if sk_bytes.len() != 32 {
            return Err(anyhow!(
                "client_ed25519.pk8 length was {}, expected 32",
                sk_bytes.len()
            ));
        }
        if pk_bytes.len() != 32 {
            return Err(anyhow!(
                "client_ed25519.pub length was {}, expected 32",
                pk_bytes.len()
            ));
        }

        let sk = SigningKey::from_bytes(
            &sk_bytes
                .try_into()
                .map_err(|_| anyhow!("client_sk not 32 bytes"))?,
        );
        let claimed_pub: [u8; 32] = pk_bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("client_pub not 32 bytes"))?;

        // sanity: derived pub must match stored pub
        let derived_pub = sk.verifying_key().to_bytes();
        if derived_pub != claimed_pub {
            return Err(anyhow!(
                "client key mismatch: stored pub != derived pub from stored sk"
            ));
        }
        Ok((sk, claimed_pub))
    } else {
        fs::create_dir_all("keys").context("mkdir keys")?;
        let sk = SigningKey::generate(&mut OsRng);
        let pub_bytes = sk.verifying_key().to_bytes();
        fs::write(sk_path, sk.to_bytes()).context("write client_ed25519.pk8")?;
        fs::write(pk_path, pub_bytes).context("write client_ed25519.pub")?;
        Ok((sk, pub_bytes))
    }
}

// ---------- connect / handshake ----------

/// One-shot connect + handshake. Kept for callers that don't want retry logic.
pub async fn connect_and_handshake(gs_addr: &str) -> Result<Session> {
    attempt_connect_and_handshake(gs_addr, Duration::from_secs(10)).await
}

/// Connect + handshake with retry/backoff. Retries only *transient* failures
/// (connect errors, Hello timeout, EOF) — *not* trust or signature failures.
pub async fn connect_and_handshake_with_retry(
    gs_addr: &str,
    max_attempts: usize,
    initial_backoff: Duration,
) -> Result<Session> {
    let mut backoff = initial_backoff;
    let mut attempt = 1usize;

    loop {
        match attempt_connect_and_handshake(gs_addr, Duration::from_secs(10)).await {
            Ok(sess) => return Ok(sess),
            Err(e) => {
                // Fatal classes (do not retry): VS pinning mismatch or bad ticket signature/body.
                let msg = format!("{e:#}");
                let fatal = msg.contains("untrusted VS pubkey")
                    || msg.contains("signature on PlayTicket did not verify")
                    || msg.contains("ticket client_binding mismatch")
                    || msg.contains("ServerHello session mismatch");

                if fatal {
                    return Err(e);
                }

                eprintln!(
                    "[CLIENT] attempt {}/{} failed: {e}. Retrying in {} ms...",
                    attempt,
                    max_attempts,
                    backoff.as_millis()
                );

                if attempt >= max_attempts {
                    return Err(anyhow!("exhausted retries connecting to {}", gs_addr));
                }

                sleep(backoff).await;
                // exponential backoff with cap ~2s
                backoff = std::cmp::min(backoff * 2, Duration::from_millis(2000));
                attempt += 1;
            }
        }
    }
}

/// Internal: a single attempt to connect + receive `ServerHello` with a timeout.
/// Uses a short deadline so the caller can decide on retry policy.
async fn attempt_connect_and_handshake(gs_addr: &str, hello_timeout: Duration) -> Result<Session> {
    // 0) roots + identity
    let pinned_vs_pub = load_pinned_vs_pub()?;
    let (client_sk, client_pub) = load_or_create_client_keys()?;

    // 1) configure QUIC client
    let client_config = configure_quic_client()?;
    let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(client_config);

    // 2) connect to GS
    let t0 = std::time::Instant::now();
    let conn = endpoint
        .connect(gs_addr.parse()?, "localhost")?
        .await
        .with_context(|| format!("QUIC connect to {}", gs_addr))?;
    let conn_id = conn.stable_id();
    println!(
        "[CLIENT] {:?} QUIC connected to {} (conn_id={})",
        t0.elapsed(),
        gs_addr,
        conn_id
    );

    // 3) open bi-directional stream
    println!(
        "[CLIENT] {:?} opening bi-stream on conn_id={}...",
        t0.elapsed(),
        conn_id
    );
    let (send_stream, mut recv_stream) = conn.open_bi().await.context("open bi-stream")?;
    println!(
        "[CLIENT] {:?} bi-stream opened on conn_id={}, waiting for ServerHello (timeout={}s)...",
        t0.elapsed(),
        conn_id,
        hello_timeout.as_secs()
    );

    // 4) recv ServerHello { session_id, ticket, vs_pub } with timeout
    let sh: ServerHello = timeout(hello_timeout, recv_msg(&mut recv_stream))
        .await
        .map_err(|_| {
            eprintln!(
                "[CLIENT] {:?} TIMEOUT waiting for ServerHello after {}s",
                t0.elapsed(),
                hello_timeout.as_secs()
            );
            anyhow!("timeout waiting for ServerHello")
        })?
        .context("recv ServerHello")?;
    println!("[CLIENT] {:?} ServerHello received!", t0.elapsed());

    let ticket: PlayTicket = sh.ticket.clone();

    // 3) enforce VS key pinning
    if sh.vs_pub != pinned_vs_pub {
        bail!(
            "untrusted VS pubkey from GS.\n  got:  {:02x?}\n  want: {:02x?}",
            sh.vs_pub,
            pinned_vs_pub
        );
    }

    // 4) enforce ticket client binding (if bound)
    if ticket.client_binding != [0u8; 32] && ticket.client_binding != client_pub {
        bail!("ticket client_binding mismatch: this ticket isn't for our client_pub");
    }

    // 5) session_id must match
    if ticket.session_id != sh.session_id {
        bail!("ServerHello session mismatch between GS and ticket");
    }

    // 6) verify VS signature on ticket
    // VS signed: (session_id, client_binding, counter, not_before_ms, not_after_ms, prev_ticket_hash)
    let body_tuple = (
        ticket.session_id,
        ticket.client_binding,
        ticket.counter,
        ticket.not_before_ms,
        ticket.not_after_ms,
        ticket.prev_ticket_hash,
    );
    let body_bytes =
        bincode::serialize(&body_tuple).context("serialize PlayTicket body for verify")?;
    let vs_vk = VerifyingKey::from_bytes(&sh.vs_pub).context("vs_pub in ServerHello invalid")?;
    let sig_vs = Signature::from_bytes(&ticket.sig_vs);
    if vs_vk.verify_strict(&body_bytes, &sig_vs).is_err() {
        bail!("VS signature on PlayTicket did not verify");
    }

    // optional freshness check for logs/UX where used
    let _fresh_now = {
        let now = now_ms();
        ticket.not_before_ms.saturating_sub(500) <= now
            && now <= ticket.not_after_ms.saturating_add(500)
    };

    Ok(Session {
        send_stream,
        recv_stream,
        session_id: sh.session_id,
        vs_pub: sh.vs_pub,
        ticket,
        client_pub,
        client_sk,
    })
}

// ---------- per-tick send/recv ----------

/// Sign and send a single input for this session.
pub async fn send_input(sess: &mut Session, nonce: u64, cmd: ClientCmd) -> Result<()> {
    // Canonical bytes; must match GS verification.
    let sign_bytes = client_input_sign_bytes(
        &sess.session_id, // <-- [u8;16]
        sess.ticket.counter,
        &sess.ticket.sig_vs,
        nonce,
        &cmd,
    );
    let sig = sess.client_sk.sign(&sign_bytes);

    let ci = ClientInput {
        session_id: sess.session_id,         // <-- [u8;16]
        ticket_counter: sess.ticket.counter, // u32
        ticket_sig_vs: sess.ticket.sig_vs,   // [u8;64]
        client_nonce: nonce,
        cmd,
        client_pub: sess.client_pub, // [u8;32]
        client_sig: sig.to_bytes(),  // [u8;64]
    };

    let msg = ClientToGs::Input(Box::new(ci));
    send_msg(&mut sess.send_stream, &msg)
        .await
        .context("send ClientInput")
}

/// Read the authoritative world snapshot from GS.
pub async fn recv_world(sess: &mut Session) -> Result<WorldSnapshot> {
    recv_msg::<WorldSnapshot>(&mut sess.recv_stream)
        .await
        .context("recv WorldSnapshot")
}
