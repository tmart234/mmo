// crates/gs-sim/src/main.rs
use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use common::{
    crypto::{file_sha256, join_request_sign_bytes, now_ms, sign, verify},
    framing::{recv_msg, send_msg},
    proto::{JoinAccept, JoinRequest, PlayTicket, Sig},
    tpm::{SimulatedTpm, TpmProvider},
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use quinn::{Connection, Endpoint};
use rand::{rngs::OsRng, RngCore};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    path::PathBuf,
    sync::{atomic::AtomicU64, Arc, Mutex},
    time::Duration,
};
use tokio::{sync::watch, time::sleep};

mod client_port;
mod heartbeat;
mod ledger;
mod state;
mod tickets;

use crate::client_port::client_port_task;
use crate::heartbeat::heartbeat_loop;
use crate::ledger::Ledger;
use crate::state::{GsShared, Shared};
use crate::tickets::ticket_listener;

#[derive(Parser, Debug)]
struct Opts {
    /// VS address (ip:port)
    #[arg(long, default_value = "127.0.0.1:4444")]
    vs: String,

    /// Exit after first join/heartbeat/ticket/client-proof exchange.
    #[arg(long)]
    test_once: bool,

    /// Logical GS ID label
    #[arg(long, default_value = "gs-sim-local")]
    gs_id: String,

    /// Paths to GS *long-term* keypair
    #[arg(long, default_value = "keys/gs_ed25519.pk8")]
    gs_sk: String,
    #[arg(long, default_value = "keys/gs_ed25519.pub")]
    gs_pk: String,

    /// Enable TPM attestation (uses simulated TPM for testing)
    #[arg(long)]
    enable_tpm: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opts = Opts::parse();

    // rustls 0.23+ needs a global CryptoProvider (ring or aws-lc-rs).
    {
        use rustls::crypto::{ring, CryptoProvider};
        CryptoProvider::install_default(ring::default_provider())
            .expect("install ring CryptoProvider");
    }

    //
    // 1. Load/generate GS long-term keypair.
    //
    let (gs_sk_long, gs_pk_long) = load_or_make_keys(&opts.gs_sk, &opts.gs_pk)?;

    //
    // 2. Create per-session ephemeral signing key (this run).
    //
    let eph_sk = SigningKey::generate(&mut OsRng);
    let eph_pub_bytes = eph_sk.verifying_key().to_bytes();

    //
    // 3. Compute sw_hash of our running binary (attestation of code identity).
    //
    let exe = std::env::current_exe()?;
    let sw_hash = file_sha256(&exe)?;

    //
    // 3b. Initialize TPM (simulated for testing, hardware for production).
    //
    let tpm: Option<Box<dyn TpmProvider>> = if opts.enable_tpm {
        println!("[GS] initializing simulated TPM for attestation");
        let mut tpm = SimulatedTpm::new();

        // Extend PCR 0 with binary hash (code measurement)
        tpm.extend_pcr(0, &sw_hash)
            .context("extend PCR 0 with sw_hash")?;

        // Extend PCR 1 with GS ID (configuration measurement)
        tpm.extend_pcr(1, opts.gs_id.as_bytes())
            .context("extend PCR 1 with gs_id")?;

        Some(Box::new(tpm))
    } else {
        None
    };

    //
    // 4. QUIC connect to Validation Server (VS).
    //
    let (endpoint, server_addr) = make_endpoint_and_addr(&opts.vs)?;
    let conn: Connection = endpoint
        .connect_with(make_client_cfg_insecure()?, server_addr, "vs.dev")?
        .await?;
    println!("[GS] connected to VS at {server_addr}");

    //
    // 5. Send JoinRequest over a bi-stream and receive JoinAccept.
    //
    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);

    let now = now_ms();
    let to_sign = join_request_sign_bytes(&opts.gs_id, &sw_hash, now, &nonce, &eph_pub_bytes);
    let sig_gs: Sig = sign(&gs_sk_long, &to_sign).to_vec(); // [u8;64] -> Vec<u8>

    // Generate TPM quote if TPM is enabled
    let tpm_quote = if let Some(ref tpm) = tpm {
        println!("[GS] generating TPM attestation quote (PCRs 0,1)");
        let quote_nonce = nonce; // Reuse join request nonce
        let mut nonce_32 = [0u8; 32];
        nonce_32[..16].copy_from_slice(&quote_nonce);

        Some(
            tpm.quote(&[0, 1], &nonce_32)
                .context("generate TPM quote")?,
        )
    } else {
        None
    };

    let jr = JoinRequest {
        gs_id: opts.gs_id.clone(),
        sw_hash,
        t_unix_ms: now,
        nonce,
        ephemeral_pub: eph_pub_bytes,
        sig_gs,
        gs_pub: gs_pk_long.to_bytes(),
        tpm_quote,
    };

    let (mut jsend, mut jrecv) = conn.open_bi().await?;
    send_msg(&mut jsend, &jr).await?;
    let ja: JoinAccept = recv_msg(&mut jrecv).await?;

    //
    // 6. Verify VS identity + session_id signature in JoinAccept.
    //
    let vs_vk = VerifyingKey::from_bytes(&ja.vs_pub).context("bad vs_pub from JoinAccept")?;

    // ja.sig_vs is Vec<u8>, but verify() wants &[u8; 64]
    let sig_vs_arr: [u8; 64] = ja
        .sig_vs
        .clone()
        .try_into()
        .map_err(|_| anyhow!("VS sig length != 64"))?;

    let sig_ok = verify(&vs_vk, &ja.session_id, &sig_vs_arr);
    if !sig_ok {
        bail!("VS signature invalid on JoinAccept");
    }

    println!(
        "[GS] joined. session_id={}.. (vs sig OK, len={})",
        hex::encode(&ja.session_id[..4]),
        ja.sig_vs.len()
    );

    //
    // 7. Shared GS state (session, sw_hash, latest ticket, receipt_tip, revoked flag...).
    //
    let shared: Shared = Arc::new(Mutex::new(GsShared::new(ja.session_id, vs_vk, sw_hash)));

    //
    // 7b. Open a session ledger (best-effort).
    //
    {
        let mut guard = shared.lock().unwrap();
        let hex4 = format!("{:02x}{:02x}", guard.session_id[0], guard.session_id[1]);
        guard.ledger = Ledger::open_for_session(&hex4).ok();
    }

    //
    // 8. Channels:
    //    - revoke_tx / revoke_rx: broadcast "VS revoked this GS"
    //    - ticket_tx / ticket_rx: broadcast latest PlayTicket
    //
    let (revoke_tx, revoke_rx) = watch::channel(false);
    let (ticket_tx, ticket_rx) = watch::channel::<Option<PlayTicket>>(None);

    //
    // 9. Spawn runtime tasks: heartbeat, ticket listener, (client port later).
    //
    // a) heartbeat_loop: GS → VS liveness + receipt_tip + sw_hash re-attestation
    let hb_counter = Arc::new(AtomicU64::new(0));
    let heartbeat_task = tokio::spawn(heartbeat_loop(
        conn.clone(),
        hb_counter.clone(),
        eph_sk, // move ephemeral GS session signing key
        ja.session_id,
        shared.clone(),
    ));

    // b) ticket_listener:
    //    VS → GS PlayTickets stream + revocation watchdog
    let tickets_task = tokio::spawn(ticket_listener(
        conn.clone(),
        shared.clone(),
        vs_vk,
        revoke_tx.clone(),
        ticket_tx.clone(),
    ));

    // === CRITICAL FIX: gate client port with timeout to prevent deadlock ===
    {
        use common::config::GsConfig;
        use tokio::time::timeout;

        let config = GsConfig::default();
        let first_ticket_timeout = Duration::from_millis(config.first_ticket_timeout_ms);

        let mut first_ticket_rx = ticket_tx.subscribe();
        let wait_for_ticket = async {
            while first_ticket_rx.borrow().is_none() {
                if first_ticket_rx.changed().await.is_err() {
                    bail!("ticket channel closed before first ticket");
                }
            }
            Ok::<_, anyhow::Error>(())
        };

        match timeout(first_ticket_timeout, wait_for_ticket).await {
            Ok(Ok(_)) => {
                println!("[GS] first PlayTicket received — opening client port");
            }
            Ok(Err(e)) => {
                bail!("ticket channel error: {}", e);
            }
            Err(_) => {
                bail!(
                    "timeout waiting for first ticket from VS after {}ms - check VS connectivity",
                    config.first_ticket_timeout_ms
                );
            }
        }
    }

    // c) client_port_task:
    //    TCP listener accepting local client-sim connections.
    //    Each client waits for first ticket via ticket_rx before we send ServerHello.
    let client_port_task_handle = tokio::spawn(client_port_task(
        shared.clone(),
        revoke_rx.clone(),
        ticket_rx.clone(),
    ));

    //
    // 10. --test_once mode: let smoke test run, then exit.
    //     Give client enough time to connect, handshake, and complete its test.
    //
    if opts.test_once {
        sleep(Duration::from_secs(15)).await;

        heartbeat_task.abort();
        tickets_task.abort();
        client_port_task_handle.abort();

        println!("[GS] test_once complete.");
        return Ok(());
    }

    //
    // 11. "Prod-ish": loop until any task dies.
    //
    loop {
        sleep(Duration::from_secs(60)).await;
        if heartbeat_task.is_finished()
            || tickets_task.is_finished()
            || client_port_task_handle.is_finished()
        {
            eprintln!("[GS] background task ended, exiting main loop");
            break;
        }
    }

    Ok(())
}

/// Load GS long-term Ed25519 keypair from disk or create dev keys.
fn load_or_make_keys(sk_path: &str, pk_path: &str) -> Result<(SigningKey, VerifyingKey)> {
    let skp = PathBuf::from(sk_path);
    let pkp = PathBuf::from(pk_path);

    if skp.exists() && pkp.exists() {
        let sk_bytes = std::fs::read(&skp).context("read gs_sk")?;
        let pk_bytes = std::fs::read(&pkp).context("read gs_pk")?;

        let sk = SigningKey::from_bytes(
            &sk_bytes
                .try_into()
                .map_err(|_| anyhow!("sk length != 32"))?,
        );
        let pk = VerifyingKey::from_bytes(
            &pk_bytes
                .try_into()
                .map_err(|_| anyhow!("pk length != 32"))?,
        )?;
        Ok((sk, pk))
    } else {
        std::fs::create_dir_all("keys").context("mkdir keys")?;
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key();
        std::fs::write(&skp, sk.to_bytes()).context("write gs_sk")?;
        std::fs::write(&pkp, pk.to_bytes()).context("write gs_pk")?;
        println!(
            "[GS] generated dev keypair at {}, {}",
            skp.display(),
            pkp.display()
        );
        Ok((sk, pk))
    }
}

/// Dev-only QUIC client config that skips cert verification.
fn make_client_cfg_insecure() -> Result<quinn::ClientConfig> {
    use rustls::{
        client::{
            danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
            ClientConfig as RustlsClientConfig,
        },
        pki_types::{CertificateDer, ServerName, UnixTime},
        DigitallySignedStruct, SignatureScheme,
    };

    #[derive(Debug)]
    struct NoVerify;

    impl ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> std::result::Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ED25519,
                SignatureScheme::RSA_PSS_SHA256,
            ]
        }
    }

    let tls_cfg = RustlsClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();

    let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(tls_cfg))
        .map_err(|e| anyhow!("QuicClientConfig::try_from: {e:?}"))?;

    Ok(quinn::ClientConfig::new(Arc::new(quic_crypto)))
}

/// Create a Quinn client Endpoint bound to an ephemeral UDP port.
fn make_endpoint_and_addr(vs: &str) -> Result<(Endpoint, SocketAddr)> {
    use quinn::{EndpointConfig, TokioRuntime};

    let server_addr: SocketAddr = vs.parse().context("bad vs address")?;

    // bind to wildcard IP in same family as VS address
    let bind_ip = match server_addr {
        SocketAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        SocketAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    let local_addr = SocketAddr::new(bind_ip, 0);

    let udp = UdpSocket::bind(local_addr)?;
    udp.set_nonblocking(true)?;

    let endpoint = Endpoint::new(
        EndpointConfig::default(),
        None, // client-only endpoint
        udp,
        Arc::new(TokioRuntime),
    )?;

    Ok((endpoint, server_addr))
}
