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
// - broker.rs      : Verifier (AR) and Broker (SAT) for clients
// - appraisal.rs   : client platform evidence (Android key attestation,
//                    Apple App Attest) -> device tier
// - liveness.rs    : SAR chain per game server
// - checkpoints.rs : Checkpoint verification and evidence storage
// - attest.rs      : TPM quote appraisal (the prototype's simulated TPM)
// - tpm2.rs        : TPM 2.0 evidence: EK chain, quote, logs, Build
//                    Registry, credential activation (attest-tpm)
// - watchdog.rs    : revoke when Checkpoints stop

mod admission;
mod appraisal;
mod attest;
mod broker;
mod checkpoints;
mod ctx;
mod liveness;
mod metrics;
mod tpm2;
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

    /// Android app allowed to attest: `package:sha256hex` of its signing
    /// certificate (repeatable). Without one, Android evidence earns D0.
    #[arg(long = "android-app")]
    android_apps: Vec<String>,
    /// Google's attestation status list (JSON from
    /// https://android.googleapis.com/attestation/status); refresh daily.
    #[arg(long)]
    android_status: Option<PathBuf>,
    /// Apple App ID allowed to attest: `TEAMID.bundle.id` (repeatable).
    /// Without one, App Attest evidence earns D0.
    #[arg(long = "apple-app-id")]
    apple_app_ids: Vec<String>,
    /// Accept App Attest keys from Apple's development environment. Never in
    /// production.
    #[arg(long)]
    apple_allow_development: bool,

    /// TPM manufacturers' root certificates (PEM bundle): a game server's
    /// TPM 2.0 evidence counts only with an EK certificate chaining to one.
    #[arg(long)]
    tpm_ek_roots: Option<PathBuf>,
    /// Build Registry (`sha256sum` lines: hash, label) of the GS builds CI
    /// made with signed provenance. With one, a game server is admitted
    /// only if the kernel measured one of these at `--gs-program` (F06).
    #[arg(long)]
    build_registry: Option<PathBuf>,
    /// Where the GS binary is installed, as the kernel's IMA log names it.
    #[arg(long, default_value = common::config::DEFAULT_GS_PROGRAM_PATH)]
    gs_program: String,
    /// Require the measured-boot log to show Secure Boot on.
    #[arg(long)]
    require_secure_boot: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opts = Opts::parse();

    // Initialize Prometheus metrics
    metrics::register_metrics();
    println!("[VS] Prometheus metrics initialized");

    // Load (or create) VS signing key
    let (vs_sk_raw, _vs_pk_raw) = load_or_make_keys(&opts.vs_sk, &opts.vs_pk)?;
    let mut config = common::config::VsConfig {
        gs_program_path: opts.gs_program.clone(),
        require_secure_boot: opts.require_secure_boot,
        ..Default::default()
    };
    tpm2::load_options(
        &mut config,
        opts.tpm_ek_roots.as_deref(),
        opts.build_registry.as_deref(),
    )?;
    println!(
        "[VS] game servers: {} TPM manufacturer root(s); Build Registry {}",
        config.tpm_ek_roots.len(),
        if config.build_registry.is_empty() {
            "off (self-reported builds accepted: dev only)".to_string()
        } else {
            format!(
                "{} build(s) at {}",
                config.build_registry.len(),
                config.gs_program_path
            )
        }
    );
    let mut ctx = VsCtx::new_with_config(Arc::new(vs_sk_raw), config);
    let status = opts
        .android_status
        .as_ref()
        .map(fs::read_to_string)
        .transpose()
        .context("read --android-status")?;
    ctx.attestation = Arc::new(appraisal::ClientAttestation::from_options(
        &opts.android_apps,
        status.as_deref(),
        &opts.apple_app_ids,
        opts.apple_allow_development,
    )?);
    println!(
        "[VS] client evidence: android {}, apple {}",
        if ctx.attestation.android.is_some() {
            "on"
        } else {
            "off"
        },
        if ctx.attestation.apple.is_some() {
            "on"
        } else {
            "off"
        }
    );
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
