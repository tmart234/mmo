//! svc-log: the Transparency Log service.

use anyhow::Result;
use clap::Parser;
use fpp_crypto::hybrid::HybridSigner;
use svc_log::{LogConfig, LogService, PublicKeys};

#[derive(Parser)]
struct Opts {
    /// Cell directory (`fpp-cell init`).
    #[arg(long, default_value = "cell")]
    cell: std::path::PathBuf,
    #[arg(long, default_value = "127.0.0.1:7201")]
    bind: std::net::SocketAddr,
    /// The log's name in checkpoints (and its key's).
    #[arg(long, default_value = "fpp.dev/log/dev-1")]
    origin: String,
    /// Where the tiles and checkpoint live (serve it as static files).
    #[arg(long, default_value = "cell/log/data")]
    data: std::path::PathBuf,
    /// Maximum merge delay promised in receipts (seconds).
    #[arg(long, default_value_t = 60)]
    mmd: u64,
    /// Services that may append.
    #[arg(
        long,
        value_delimiter = ',',
        default_value = "revocation,enforcement,liveness"
    )]
    writers: Vec<String>,
    /// Witness services.
    #[arg(long, value_delimiter = ',', default_value = "witness")]
    witnesses: Vec<String>,
    /// Public UDP address for players' gossip (QUIC; none: cell only).
    #[arg(long)]
    public: Option<std::net::SocketAddr>,
    /// TLS certificate (DER) for `--public`; must chain to the CA players pin.
    #[arg(long, default_value = "keys/log_tls.der")]
    tls_cert: String,
    /// PKCS#8 private key (DER) for `--tls-cert`.
    #[arg(long, default_value = "keys/log_tls.key.der")]
    tls_key: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let o = Opts::parse();
    let id = fpp_svc::cell::load(&o.cell, "log")?;
    let key = HybridSigner::from_seeds(
        &fpp_svc::cell::signing_seed(&o.cell, "log", "ed25519")?,
        &fpp_svc::cell::signing_seed(&o.cell, "log", "ml-dsa-65")?,
    )?;
    let log = fpp_log::Log::open(&o.data, &o.origin, key, o.mmd)?;
    PublicKeys {
        name: o.origin.clone(),
        ed25519: log.public_key(),
        ml_dsa: Some(log.ml_dsa_public_key().to_vec()),
    }
    .write(&o.cell, "log")?;
    println!(
        "[log] {} at size {}, serving on {}",
        o.origin,
        log.size(),
        o.bind
    );
    let endpoint = fpp_svc::mtls::server_endpoint(&id, o.bind)?;
    let svc = LogService::new(
        log,
        LogConfig {
            writers: o.writers,
            witnesses: o.witnesses,
            cell: o.cell,
        },
    )?;
    if let Some(public) = o.public {
        let identity = common::pki::ServerIdentity::load(&o.tls_cert, &o.tls_key)?;
        let endpoint = common::admission::server_endpoint(&identity, public)?;
        println!("[log] gossip for players on {public}");
        tokio::spawn(svc.clone().serve_public(endpoint));
    }
    svc.serve_cell(endpoint).await;
    Ok(())
}
