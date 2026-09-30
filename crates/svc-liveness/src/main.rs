//! svc-liveness: Server Liveness as its own service.

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use svc_liveness::{config::LivenessConfig, tpm2};

#[derive(Parser, Debug)]
struct Opts {
    /// Cell directory: Server Liveness's key and cell identity are in
    /// `<cell>/liveness/`.
    #[arg(long, default_value = "cell")]
    cell: PathBuf,
    /// Public UDP address for game servers (QUIC).
    #[arg(long, default_value = "127.0.0.1:4444")]
    bind: std::net::SocketAddr,
    /// Cell address (mutual TLS) for the Broker.
    #[arg(long, default_value = "127.0.0.1:4454")]
    rpc: std::net::SocketAddr,
    /// Cell services allowed to place players.
    #[arg(long, value_delimiter = ',', default_value = "broker")]
    callers: Vec<String>,
    /// The Revocation Feed's cell address.
    #[arg(long)]
    feed: Option<std::net::SocketAddr>,
    /// The Evidence Store's cell address (without one, Checkpoints are
    /// verified but not kept).
    #[arg(long)]
    evidence: Option<std::net::SocketAddr>,
    /// TLS certificate (DER) presented to game servers; must chain to the CA they pin.
    #[arg(long, default_value = "keys/liveness_tls.der")]
    tls_cert: String,
    /// PKCS#8 private key (DER) for `--tls-cert`.
    #[arg(long, default_value = "keys/liveness_tls.key.der")]
    tls_key: String,

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
    #[arg(long, default_value = svc_liveness::config::DEFAULT_GS_PROGRAM_PATH)]
    gs_program: String,
    /// Require the measured-boot log to show Secure Boot on.
    #[arg(long)]
    require_secure_boot: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let o = Opts::parse();
    let mut config = LivenessConfig {
        gs_program_path: o.gs_program.clone(),
        require_secure_boot: o.require_secure_boot,
        ..Default::default()
    };
    tpm2::load_options(
        &mut config,
        o.tpm_ek_roots.as_deref(),
        o.build_registry.as_deref(),
    )?;
    println!(
        "[liveness] game servers: {} TPM manufacturer root(s); Build Registry {}",
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
    if o.evidence.is_none() {
        println!("[liveness] no --evidence: Checkpoints are verified, not kept");
    }
    let identity = common::pki::ServerIdentity::load(&o.tls_cert, &o.tls_key)?;
    svc_liveness::start(
        &o.cell,
        &identity,
        svc_liveness::Addrs {
            public: o.bind,
            rpc: o.rpc,
            callers: o.callers,
            feed: o.feed,
            evidence: o.evidence,
        },
        config,
    )?;
    println!(
        "[liveness] key published in {}; game servers on {}; cell API on {}",
        o.cell.join("public/liveness").display(),
        o.bind,
        o.rpc
    );
    std::future::pending::<()>().await;
    Ok(())
}
