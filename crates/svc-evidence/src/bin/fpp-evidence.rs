//! fpp-evidence: read the Evidence Store, as an auditor.
//!
//!     fpp-evidence list <match hex>
//!     fpp-evidence get <digest hex> <file>

use anyhow::{anyhow, bail, Result};
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
struct Opts {
    /// Cell directory.
    #[arg(long, default_value = "cell")]
    cell: PathBuf,
    /// The cell identity to read as.
    #[arg(long, default_value = "audit")]
    identity: String,
    /// The Evidence Store.
    #[arg(long, default_value = "127.0.0.1:4470")]
    store: std::net::SocketAddr,
    /// `list <match>` or `get <digest> <file>`.
    args: Vec<String>,
}

fn fixed<const N: usize>(h: &str) -> Result<[u8; N]> {
    hex::decode(h)?
        .try_into()
        .map_err(|_| anyhow!("expected {N} bytes of hex"))
}

#[tokio::main]
async fn main() -> Result<()> {
    let o = Opts::parse();
    let client = svc_evidence::Client::new(&fpp_svc::cell::load(&o.cell, &o.identity)?, o.store)?;
    match o
        .args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["list", m] => {
            for d in client.list(fixed(m)?).await? {
                println!("{}", hex::encode(d));
            }
        }
        ["get", d, file] => match client.get(fixed(d)?).await? {
            Some(bytes) => std::fs::write(file, bytes)?,
            None => bail!("no object {d}"),
        },
        _ => bail!("usage: fpp-evidence list <match> | get <digest> <file>"),
    }
    Ok(())
}
