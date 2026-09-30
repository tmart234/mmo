//! svc-evidence: the Evidence Store as its own service.

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
struct Opts {
    /// Cell directory: the store's cell identity is in `<cell>/evidence/`.
    #[arg(long, default_value = "cell")]
    cell: PathBuf,
    /// Cell address (mutual TLS).
    #[arg(long, default_value = "127.0.0.1:4470")]
    bind: std::net::SocketAddr,
    /// Where objects are kept (default `<cell>/evidence/data`).
    #[arg(long)]
    data: Option<PathBuf>,
    /// Services that may store.
    #[arg(long, value_delimiter = ',', default_value = "liveness")]
    writers: Vec<String>,
    /// Services that may read.
    #[arg(long, value_delimiter = ',', default_value = "audit,enforcement")]
    readers: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let o = Opts::parse();
    let identity = fpp_svc::cell::load(&o.cell, "evidence")?;
    let data = o.data.unwrap_or_else(|| o.cell.join("evidence/data"));
    let store = svc_evidence::Store::open(&data)?;
    println!(
        "[evidence] objects in {}; writers {:?}, readers {:?}; listening on {}",
        data.display(),
        o.writers,
        o.readers,
        o.bind
    );
    let endpoint = fpp_svc::mtls::server_endpoint(&identity, o.bind)?;
    svc_evidence::serve(
        endpoint,
        store,
        svc_evidence::Access {
            writers: o.writers,
            readers: o.readers,
        },
    )
    .await;
    Ok(())
}
