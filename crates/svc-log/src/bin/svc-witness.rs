//! svc-witness: cosigns the log's checkpoints that extend the last one it
//! cosigned (a split view is refused, and logged).

use anyhow::Result;
use clap::Parser;
use ed25519_dalek::SigningKey;
use svc_log::{witness_round, PublicKeys};

#[derive(Parser)]
struct Opts {
    #[arg(long, default_value = "cell")]
    cell: std::path::PathBuf,
    /// The log service's address.
    #[arg(long, default_value = "127.0.0.1:7201")]
    log: std::net::SocketAddr,
    /// This witness's name in cosignatures.
    #[arg(long, default_value = "fpp.dev/witness/dev-1")]
    name: String,
    #[arg(long, default_value_t = 5)]
    interval_s: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let o = Opts::parse();
    let id = fpp_svc::cell::load(&o.cell, "witness")?;
    let key = SigningKey::from_bytes(&fpp_svc::cell::signing_seed(&o.cell, "witness", "ed25519")?);
    PublicKeys {
        name: o.name.clone(),
        ed25519: key.verifying_key().to_bytes(),
        ml_dsa: None,
    }
    .write(&o.cell, "witness")?;
    let log_keys = PublicKeys::read(&o.cell, "log")?;
    let ml = log_keys
        .ml_dsa
        .clone()
        .ok_or_else(|| anyhow::anyhow!("the log publishes no ML-DSA key"))?;
    let mut witness = fpp_log::Witness::open(
        &o.name,
        key,
        &log_keys.name,
        log_keys.ed25519,
        ml,
        o.cell.join("witness").join("state"),
    )?;
    let endpoint = fpp_svc::mtls::client_endpoint(&id)?;
    println!("[witness] {} witnessing {}", o.name, log_keys.name);
    loop {
        match fpp_svc::mtls::connect(&endpoint, o.log, "log").await {
            Ok(conn) => match witness_round(&conn, &mut witness).await {
                Ok(Some(size)) => println!("[witness] cosigned size {size}"),
                Ok(None) => {}
                Err(e) => eprintln!("[witness] REFUSED: {e:#}"),
            },
            Err(e) => eprintln!("[witness] {e:#}"),
        }
        tokio::time::sleep(std::time::Duration::from_secs(o.interval_s)).await;
    }
}
