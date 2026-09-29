pub use anyhow::{anyhow, bail, Context, Result};

use common::{
    crypto::{client_input_sign_bytes, now_ms},
    framing::{recv_msg, recv_msg_max, send_msg_continue, MAX_SNAPSHOT_FRAME},
    proto::{
        ClientCmd, ClientHello, ClientInput, ClientToGs, GsToClient, PlayTicket, ServerHello,
        WorldSnapshot,
    },
    tickets::TicketChain,
};

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use quinn::{ClientConfig, Endpoint, RecvStream, SendStream};
use rand::rngs::OsRng;
use std::{fs, path::Path, sync::Arc};
use tokio::time::{sleep, timeout, Duration};

pub struct Session {
    pub send_stream: SendStream,
    pub recv_stream: RecvStream,
    pub session_id: [u8; 16],
    pub vs_pub: [u8; 32],
    /// VS ticket chain proving the GS is still blessed; checked on every send.
    pub tickets: TicketChain,
    pub client_pub: [u8; 32],
    pub client_sk: SigningKey,
}

impl Session {
    /// The ticket currently stapled to inputs.
    pub fn ticket(&self) -> &PlayTicket {
        self.tickets.current()
    }
}

/// What the client trusts: the VS signing key and the CA for GS certificates.
#[derive(Clone)]
pub struct ClientTrust {
    pub vs_pub: VerifyingKey,
    pub ca_der: Vec<u8>,
}

impl ClientTrust {
    /// Load `keys/vs_ed25519.pub` and `keys/dev_ca.der`.
    pub fn load_default() -> Result<Self> {
        Ok(Self {
            vs_pub: VerifyingKey::from_bytes(&load_pinned_vs_pub()?)
                .context("pinned VS key invalid")?,
            ca_der: common::pki::load_ca(common::pki::DEFAULT_CA_CERT)?,
        })
    }
}

/// QUIC client config that only accepts GS certificates chaining to the pinned CA.
fn configure_quic_client(ca_der: &[u8]) -> Result<ClientConfig> {
    let mut client_config = common::pki::quic_client_config(ca_der)?;

    // Performance tuning
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_concurrent_bidi_streams(10_u32.into());
    transport_config.keep_alive_interval(Some(Duration::from_secs(5)));

    client_config.transport_config(Arc::new(transport_config));
    Ok(client_config)
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
    let trust = ClientTrust::load_default()?;
    attempt_connect_and_handshake(gs_addr, &trust, Duration::from_secs(10)).await
}

/// Connect + handshake with retry/backoff, trusting the default keys on disk.
pub async fn connect_and_handshake_with_retry(
    gs_addr: &str,
    max_attempts: usize,
    initial_backoff: Duration,
) -> Result<Session> {
    let trust = ClientTrust::load_default()?;
    connect_and_handshake_with_trust(gs_addr, &trust, max_attempts, initial_backoff).await
}

/// Connect + handshake with retry/backoff. Retries only *transient* failures
/// (connect errors, Hello timeout, EOF) — *not* trust or signature failures.
pub async fn connect_and_handshake_with_trust(
    gs_addr: &str,
    trust: &ClientTrust,
    max_attempts: usize,
    initial_backoff: Duration,
) -> Result<Session> {
    let mut backoff = initial_backoff;
    let mut attempt = 1usize;

    loop {
        match attempt_connect_and_handshake(gs_addr, trust, Duration::from_secs(10)).await {
            Ok(sess) => return Ok(sess),
            Err(e) => {
                // Fatal classes (do not retry): untrusted GS certificate, VS pinning
                // mismatch, or bad ticket signature/body.
                let msg = format!("{e:#}");
                let fatal = msg.contains("invalid peer certificate")
                    || msg.contains("untrusted VS pubkey")
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

/// Dial a GS client port over QUIC, verifying its certificate against `ca_der`.
pub async fn dial_gs(gs_addr: &str, ca_der: &[u8]) -> Result<quinn::Connection> {
    let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(configure_quic_client(ca_der)?);
    endpoint
        .connect(gs_addr.parse()?, common::pki::GS_SERVER_NAME)?
        .await
        .with_context(|| format!("QUIC connect to {}", gs_addr))
}

/// Internal: a single attempt to connect + receive `ServerHello` with a timeout.
/// Uses a short deadline so the caller can decide on retry policy.
async fn attempt_connect_and_handshake(
    gs_addr: &str,
    trust: &ClientTrust,
    hello_timeout: Duration,
) -> Result<Session> {
    // 0) identity
    let pinned_vs_pub = trust.vs_pub.to_bytes();
    let (client_sk, client_pub) = load_or_create_client_keys()?;

    // 1-2) connect to GS; TLS verifies its certificate chains to the pinned CA
    let t0 = std::time::Instant::now();
    println!("[CLIENT] {:?} connecting to {}...", t0.elapsed(), gs_addr);
    let conn = dial_gs(gs_addr, &trust.ca_der).await?;
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
    let (mut send_stream, mut recv_stream) = conn.open_bi().await.context("open bi-stream")?;
    println!(
        "[CLIENT] {:?} bi-stream opened on conn_id={}",
        t0.elapsed(),
        conn_id
    );

    // =========================================================================
    // CRITICAL FIX: Send ClientHello FIRST to materialize the QUIC stream!
    //
    // In QUIC (quinn), a bi-stream created via `open_bi()` is NOT visible to
    // the peer's `accept_bi()` until data actually flows on it. Without this
    // send, both sides deadlock:
    //   - Client waits for ServerHello
    //   - GS waits for accept_bi() to return (which never happens)
    //
    // The ClientHello also provides early client identification.
    // =========================================================================
    let client_hello = ClientHello::new(client_pub);
    println!(
        "[CLIENT] {:?} sending ClientHello (pub={}) to materialize stream...",
        t0.elapsed(),
        hex::encode(&client_pub[..4])
    );
    send_msg_continue(&mut send_stream, &client_hello)
        .await
        .context("send ClientHello")?;
    println!(
        "[CLIENT] {:?} ClientHello sent, waiting for ServerHello (timeout={}s)...",
        t0.elapsed(),
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
    println!(
        "[CLIENT] {:?} ServerHello received! (session={})",
        t0.elapsed(),
        hex::encode(&sh.session_id[..4])
    );

    let ticket: PlayTicket = sh.ticket.clone();

    // 5) enforce VS key pinning
    if sh.vs_pub != pinned_vs_pub {
        bail!(
            "untrusted VS pubkey from GS.\n  got:  {:02x?}\n  want: {:02x?}",
            sh.vs_pub,
            pinned_vs_pub
        );
    }

    // 6-8) session match, client binding, VS signature and freshness;
    //      later TicketUpdates must extend this chain (TicketChain::advance)
    let tickets = TicketChain::start(trust.vs_pub, sh.session_id, client_pub, ticket, now_ms())?;

    println!(
        "[CLIENT] {:?} handshake complete, session={}, ticket_ctr={}",
        t0.elapsed(),
        hex::encode(&sh.session_id[..4]),
        tickets.current().counter
    );

    Ok(Session {
        send_stream,
        recv_stream,
        session_id: sh.session_id,
        vs_pub: sh.vs_pub,
        tickets,
        client_pub,
        client_sk,
    })
}

// ---------- per-tick send/recv ----------

/// Sign and send a single input for this session.
pub async fn send_input(sess: &mut Session, nonce: u64, cmd: ClientCmd) -> Result<()> {
    // Refuse to keep playing on a GS the VS no longer blesses.
    sess.tickets.ensure_fresh(now_ms())?;
    let ticket = sess.ticket();

    // Canonical bytes; must match GS verification.
    let sign_bytes = client_input_sign_bytes(
        &sess.session_id, // <-- [u8;16]
        ticket.counter,
        &ticket.sig_vs,
        nonce,
        &cmd,
    );
    let sig = sess.client_sk.sign(&sign_bytes);

    let ci = ClientInput {
        session_id: sess.session_id, // <-- [u8;16]
        ticket_counter: ticket.counter,
        ticket_sig_vs: ticket.sig_vs,
        client_nonce: nonce,
        cmd,
        client_pub: sess.client_pub, // [u8;32]
        client_sig: sig.to_bytes(),  // [u8;64]
    };

    let msg = ClientToGs::Input(Box::new(ci));
    send_msg_continue(&mut sess.send_stream, &msg)
        .await
        .context("send ClientInput")
}

/// Read the authoritative world snapshot from GS.
/// Also handles TicketUpdate messages and updates the session's ticket.
pub async fn recv_world(sess: &mut Session) -> Result<WorldSnapshot> {
    loop {
        let msg: GsToClient = recv_msg_max(&mut sess.recv_stream, MAX_SNAPSHOT_FRAME)
            .await
            .context("recv GsToClient")?;

        match msg {
            GsToClient::WorldSnapshot(ws) => {
                return Ok(ws);
            }
            GsToClient::TicketUpdate(tu) => {
                // Must be VS-signed and extend our chain; otherwise the GS is
                // feeding us tickets the VS did not issue for this session.
                sess.tickets
                    .advance(tu.ticket, now_ms())
                    .context("rejected TicketUpdate from GS")?;
            }
            GsToClient::ServerHello(_) => {
                // Unexpected at this point, but just ignore
                eprintln!("[CLIENT] unexpected ServerHello in game loop, ignoring");
            }
        }
    }
}
