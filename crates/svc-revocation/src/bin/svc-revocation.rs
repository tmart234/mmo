//! svc-revocation: the Revocation Feed as its own service.

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use svc_revocation::{Feed, FeedConfig, LogLink};

#[derive(Parser)]
struct Opts {
    /// Cell directory: the feed's cell identity is in `<cell>/revocation/`;
    /// Enforcement's public key in `<cell>/public/enforcement`.
    #[arg(long, default_value = "cell")]
    cell: PathBuf,
    /// Cell address (mutual TLS).
    #[arg(long, default_value = "127.0.0.1:4460")]
    bind: std::net::SocketAddr,
    /// Where events are kept (default `<cell>/revocation/data`).
    #[arg(long)]
    data: Option<PathBuf>,
    /// The Transparency Log: every event is appended before it is accepted.
    #[arg(long)]
    log: Option<std::net::SocketAddr>,
    /// Services that may publish.
    #[arg(long, value_delimiter = ',', default_value = "enforcement")]
    publishers: Vec<String>,
    /// Services that may follow the feed.
    #[arg(long, value_delimiter = ',', default_value = "broker,liveness")]
    subscribers: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let o = Opts::parse();
    let identity = fpp_svc::cell::load(&o.cell, "revocation")?;
    let log = o.log.map(|a| LogLink::new(&identity, a)).transpose()?;
    let feed = Feed::open(FeedConfig {
        publishers: o.publishers,
        subscribers: o.subscribers,
        data: o.data.unwrap_or_else(|| o.cell.join("revocation/data")),
        cell: o.cell.clone(),
        log,
    })?;
    println!(
        "[revocation] {} event(s); Transparency Log {}; listening on {}",
        feed.len(),
        o.log.map(|a| a.to_string()).unwrap_or_else(|| "off".into()),
        o.bind
    );
    let endpoint = fpp_svc::mtls::server_endpoint(&identity, o.bind)?;
    feed.serve(endpoint).await;
    Ok(())
}
