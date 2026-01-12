//! VS (Validation Server)
//
// Files:
// - ctx.rs       : shared context + session map + constants
// - admission.rs : JoinRequest handling and session admission
// - streams.rs   : ticket loop + inbound bi-stream dispatch
// - watchdog.rs  : per-session liveness watchdog
// - enforcer.rs  : physics/logic invariants and revocation

mod admission;
mod ctx;
mod enforcer;
mod metrics;
mod streams;
mod watchdog;

use anyhow::{Context, Result};
use clap::Parser;
use ctx::VsCtx;
use ed25519_dalek::{SigningKey, VerifyingKey};
use quinn::Endpoint;
use rand::rngs::OsRng;
use rcgen::generate_simple_self_signed;
use std::{
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};

#[derive(Parser, Debug)]
struct Opts {
    /// UDP bind address for VS QUIC endpoint. gs-sim defaults to 127.0.0.1:4444
    #[arg(long, default_value = "127.0.0.1:4444")]
    bind: String,

    /// VS signing keypair (ed25519) used to sign JoinAccept, PlayTicket, and ProtectedReceipt.
    #[arg(long, default_value = "keys/vs_ed25519.pk8")]
    vs_sk: String,
    #[arg(long, default_value = "keys/vs_ed25519.pub")]
    vs_pk: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opts = Opts::parse();

    // rustls 0.23+: pick a crypto backend (ring) for this process.
    {
        use rustls::crypto::{ring, CryptoProvider};
        CryptoProvider::install_default(ring::default_provider())
            .expect("install ring CryptoProvider");
    }

    // Initialize Prometheus metrics
    metrics::register_metrics();
    println!("[VS] Prometheus metrics initialized");

    // Load (or create) VS signing key
    let (vs_sk_raw, _vs_pk_raw) = load_or_make_keys(&opts.vs_sk, &opts.vs_pk)?;
    let ctx = VsCtx::new(Arc::new(vs_sk_raw));

    // Start QUIC listener
    let (endpoint, _local_addr) = make_endpoint(&opts.bind)?;
    println!("[VS] listening on {}", opts.bind);
    println!("[VS] Metrics available via metrics::gather_metrics()");

    loop {
        let incoming_opt = endpoint.accept().await; // Option<Incoming>
        let Some(incoming) = incoming_opt else {
            break;
        };

        let ctx_clone = ctx.clone();
        tokio::spawn(async move {
            if let Err(e) = admission::admit_and_run(incoming, ctx_clone).await {
                eprintln!("[VS] conn error: {e:?}");
            }
        });
    }

    Ok(())
}

/// Build QUIC Endpoint bound to `bind` (e.g. "127.0.0.1:4444"),
/// with a fresh self-signed cert for "vs.dev" (dev mode).
fn make_endpoint(bind: &str) -> Result<(Endpoint, SocketAddr)> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    // Self-signed cert for this VS process (dev only).
    let cert = generate_simple_self_signed(vec!["vs.dev".into()]).context("self-signed cert")?;
    let cert_der = CertificateDer::from(cert.serialize_der().context("cert der")?);

    // rcgen gives us a PKCS#8 private key as Vec<u8>.
    // rustls 0.23 represents keys using PrivateKeyDer<'static>.
    let key_der_vec = cert.serialize_private_key_der();
    let priv_key: PrivateKeyDer<'static> = PrivatePkcs8KeyDer::from(key_der_vec).into();

    // Build Quinn server config from that cert/key.
    let server_cfg = quinn::ServerConfig::with_single_cert(vec![cert_der], priv_key)
        .context("with_single_cert")?;

    // Parse requested bind addr like "127.0.0.1:4444".
    let req_addr: SocketAddr = bind
        .parse()
        .with_context(|| format!("bad bind addr: {bind}"))?;

    // Bind 0.0.0.0:<port> (or ::/<port>) so a GS on localhost can connect.
    let bind_ip = match req_addr {
        SocketAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        SocketAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    let local_addr = SocketAddr::new(bind_ip, req_addr.port());

    let endpoint = Endpoint::server(server_cfg, local_addr).context("Endpoint::server")?;
    Ok((endpoint, local_addr))
}

/// Ensure we have a VS ed25519 signing keypair on disk.
/// If missing, generate dev keys and persist them.
fn load_or_make_keys(sk_path: &str, pk_path: &str) -> Result<(SigningKey, VerifyingKey)> {
    let skp = PathBuf::from(sk_path);
    let pkp = PathBuf::from(pk_path);

    if skp.exists() && pkp.exists() {
        let sk_bytes = fs::read(&skp).context("read vs_sk")?;
        let pk_bytes = fs::read(&pkp).context("read vs_pk")?;

        let sk = SigningKey::from_bytes(
            &sk_bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("sk length != 32"))?,
        );
        let pk = VerifyingKey::from_bytes(
            &pk_bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("pk length != 32"))?,
        )?;
        Ok((sk, pk))
    } else {
        fs::create_dir_all("keys").context("mkdir keys")?;
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key();
        fs::write(&skp, sk.to_bytes()).context("write vs_sk")?;
        fs::write(&pkp, pk.to_bytes()).context("write vs_pk")?;
        println!(
            "[VS] generated dev keypair at {}, {}",
            skp.display(),
            pkp.display()
        );
        Ok((sk, pk))
    }
}
