// crates/gs-sim/src/main.rs
use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use common::{
    crypto::{file_sha256, join_request_sign_bytes, now_ms, sign},
    framing::{recv_msg, send_msg, send_msg_continue},
    proto::{AttestChallenge, ChallengeRequest, JoinAccept, JoinRequest, PlayTicket, Sig},
    tpm::{join_quote_nonce, SimulatedTpm, TpmProvider},
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
use tokio::sync::{watch, Mutex as TokioMutex};
use tokio::time::sleep;

mod admission;
mod client_port;
mod heartbeat;
mod ledger;
mod state;
mod tickets;

use crate::client_port::client_port_task;
use crate::heartbeat::heartbeat_loop_with_tpm;
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
    /// Stage 1.2: When enabled, GS will:
    /// - Generate initial TPM quote at JoinRequest
    /// - Periodically re-attest every ~60 seconds in heartbeats
    #[arg(long)]
    enable_tpm: bool,

    /// Pinned VS signing key. JoinAccept and PlayTickets must be signed by it.
    #[arg(long, default_value = "keys/vs_ed25519.pub")]
    vs_pk: String,

    /// CA certificate (DER) the VS's TLS certificate must chain to.
    #[arg(long, default_value = common::pki::DEFAULT_CA_CERT)]
    ca_cert: String,

    /// TLS certificate (DER) presented on the client port; must chain to the CA clients pin.
    #[arg(long, default_value = common::pki::DEFAULT_GS_TLS_CERT)]
    tls_cert: String,
    /// PKCS#8 private key (DER) for `--tls-cert`.
    #[arg(long, default_value = common::pki::DEFAULT_GS_TLS_KEY)]
    tls_key: String,
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
    // 1b. Trust roots: the pinned VS signing key, the CA for TLS, and our own
    //     client-port certificate. Loaded up front so a misconfigured GS fails fast.
    //
    let pinned_vs = common::crypto::load_verifying_key(&opts.vs_pk)?;
    let ca_der = common::pki::load_ca(&opts.ca_cert)?;
    let client_port_identity = common::pki::ServerIdentity::load(&opts.tls_cert, &opts.tls_key)?;

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
    //     Stage 1.2: TPM is now passed to heartbeat loop for continuous attestation.
    //
    let tpm: Option<Arc<TokioMutex<Box<dyn TpmProvider>>>> = if opts.enable_tpm {
        println!("[GS] initializing simulated TPM for attestation");
        let mut tpm = SimulatedTpm::new();

        // Extend PCR 0 with binary hash (code measurement)
        tpm.extend_pcr(0, &sw_hash)
            .context("extend PCR 0 with sw_hash")?;

        // Extend PCR 1 with GS ID (configuration measurement)
        tpm.extend_pcr(1, opts.gs_id.as_bytes())
            .context("extend PCR 1 with gs_id")?;

        println!(
            "[GS] TPM PCRs extended: PCR0=sw_hash, PCR1=gs_id ({})",
            opts.gs_id
        );

        // Wrap in Arc<TokioMutex> for async sharing with heartbeat loop
        Some(Arc::new(TokioMutex::new(
            Box::new(tpm) as Box<dyn TpmProvider>
        )))
    } else {
        None
    };

    //
    // 4. QUIC connect to Validation Server (VS).
    //
    let (endpoint, server_addr) = make_endpoint_and_addr(&opts.vs)?;
    let conn: Connection = endpoint
        .connect_with(
            common::pki::quic_client_config(&ca_der)?,
            server_addr,
            common::pki::VS_SERVER_NAME,
        )?
        .await?;
    println!("[GS] connected to VS at {server_addr}");

    //
    // 5. Send JoinRequest over a bi-stream and receive JoinAccept.
    //
    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);

    let now = now_ms();
    let to_sign = join_request_sign_bytes(&opts.gs_id, &sw_hash, now, &nonce, &eph_pub_bytes);
    let sig_gs: Sig = sign(&gs_sk_long, &to_sign).to_vec();

    // Admission stream: ask for the VS's attestation challenge first, so the
    // quote covers a nonce the VS chose (F04), then send the JoinRequest.
    let (mut jsend, mut jrecv) = conn.open_bi().await?;
    send_msg_continue(&mut jsend, &ChallengeRequest { version: 1 }).await?;
    let challenge: AttestChallenge = recv_msg(&mut jrecv).await.context("recv AttestChallenge")?;

    let tpm_quote = if let Some(ref tpm_arc) = tpm {
        println!("[GS] generating initial TPM attestation quote (PCRs 0,1)");
        let tpm_guard = tpm_arc.lock().await;
        Some(
            tpm_guard
                .quote(&[0, 1], &join_quote_nonce(&challenge.nonce, &to_sign))
                .context("generate initial TPM quote")?,
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

    send_msg(&mut jsend, &jr).await?;
    let ja: JoinAccept = recv_msg(&mut jrecv).await?;

    //
    // 6. Verify JoinAccept against the pinned VS key (never the key it carries).
    //
    admission::verify_join_accept(&pinned_vs, &ja)?;
    let vs_vk = pinned_vs;

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
    //    Stage 1.2: Now includes periodic TPM quotes when TPM is enabled
    let hb_counter = Arc::new(AtomicU64::new(0));
    let heartbeat_task = tokio::spawn(heartbeat_loop_with_tpm(
        conn.clone(),
        hb_counter.clone(),
        eph_sk,
        ja.session_id,
        shared.clone(),
        tpm, // Stage 1.2: Pass TPM for continuous attestation
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
    let client_port_task_handle = tokio::spawn(client_port_task(
        client_port_identity,
        shared.clone(),
        revoke_rx.clone(),
        ticket_rx.clone(),
    ));

    //
    // 10. --test_once mode: let smoke test run, then exit.
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

/// Create a Quinn client Endpoint bound to an ephemeral UDP port.
fn make_endpoint_and_addr(vs: &str) -> Result<(Endpoint, SocketAddr)> {
    use quinn::{EndpointConfig, TokioRuntime};

    let server_addr: SocketAddr = vs.parse().context("bad vs address")?;

    let bind_ip = match server_addr {
        SocketAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        SocketAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    let local_addr = SocketAddr::new(bind_ip, 0);

    let udp = UdpSocket::bind(local_addr)?;
    udp.set_nonblocking(true)?;

    let endpoint = Endpoint::new(EndpointConfig::default(), None, udp, Arc::new(TokioRuntime))?;

    Ok((endpoint, server_addr))
}
