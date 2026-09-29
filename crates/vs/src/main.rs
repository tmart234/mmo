//! VS (Validation Server)
//
//
// The prototype VS plays the FPP trust-plane roles until P2 splits them into
// services: GS admission, Server Liveness (SAR chain), Checkpoint intake,
// and stub Verifier + Broker for clients.
//
// Files:
// - ctx.rs         : shared context, role keys, session map
// - admission.rs   : control-connection entry (GS join, client admission)
// - broker.rs      : stub Verifier (AR) and Broker (SAT) for clients
// - liveness.rs    : SAR chain per game server
// - checkpoints.rs : Checkpoint verification and evidence storage
// - attest.rs      : TPM quote appraisal
// - watchdog.rs    : revoke when Checkpoints stop

mod admission;
mod attest;
mod broker;
mod checkpoints;
mod ctx;
mod liveness;
mod metrics;
mod watchdog;

use anyhow::{Context, Result};
use clap::Parser;
use ctx::VsCtx;
use ed25519_dalek::{SigningKey, VerifyingKey};
use quinn::Endpoint;
use rand::rngs::OsRng;
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

    /// VS seed (ed25519): signs JoinAccepts; the Verifier, Broker and Server
    /// Liveness role keys are derived from it (dev only, `common::keys`).
    #[arg(long, default_value = "keys/vs_ed25519.pk8")]
    vs_sk: String,
    #[arg(long, default_value = "keys/vs_ed25519.pub")]
    vs_pk: String,

    /// TLS certificate (DER) presented to game servers; must chain to the CA they pin.
    #[arg(long, default_value = common::pki::DEFAULT_VS_TLS_CERT)]
    tls_cert: String,
    /// PKCS#8 private key (DER) for `--tls-cert`.
    #[arg(long, default_value = common::pki::DEFAULT_VS_TLS_KEY)]
    tls_key: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opts = Opts::parse();

    // Initialize Prometheus metrics
    metrics::register_metrics();
    println!("[VS] Prometheus metrics initialized");

    // Load (or create) VS signing key
    let (vs_sk_raw, _vs_pk_raw) = load_or_make_keys(&opts.vs_sk, &opts.vs_pk)?;
    let ctx = VsCtx::new(Arc::new(vs_sk_raw));
    ctx.keys
        .bundle()
        .save(common::keys::DEFAULT_BUNDLE)
        .context("write key bundle")?;
    println!("[VS] role key bundle at {}", common::keys::DEFAULT_BUNDLE);

    // Start QUIC listener
    let identity = common::pki::ServerIdentity::load(&opts.tls_cert, &opts.tls_key)?;
    let (endpoint, _local_addr) = make_endpoint(&opts.bind, &identity)?;
    println!("[VS] listening on {}", opts.bind);
    println!("[VS] Metrics available via metrics::gather_metrics()");

    loop {
        let incoming_opt = endpoint.accept().await; // Option<Incoming>
        let Some(incoming) = incoming_opt else {
            break;
        };

        // QUIC address validation: a peer must prove it receives traffic at its
        // source address (Retry round trip) before we spend per-connection work.
        if !incoming.remote_address_validated() {
            if let Err(e) = incoming.retry() {
                eprintln!("[VS] retry failed: {e}");
            }
            continue;
        }

        let ctx_clone = ctx.clone();
        tokio::spawn(async move {
            if let Err(e) = admission::admit_and_run(incoming, ctx_clone).await {
                eprintln!("[VS] conn error: {e:?}");
            }
        });
    }

    Ok(())
}

/// Build QUIC Endpoint bound to `bind` (e.g. "127.0.0.1:4444") presenting
/// the VS certificate, which game servers verify against their pinned CA.
fn make_endpoint(
    bind: &str,
    identity: &common::pki::ServerIdentity,
) -> Result<(Endpoint, SocketAddr)> {
    let server_cfg = common::pki::quic_server_config(identity)?;

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
