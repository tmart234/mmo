//! svc-broker: the Broker as its own service.

use anyhow::Result;
use clap::Parser;
use fpp_crypto::Ed25519Signer;
use std::path::PathBuf;
use std::sync::Arc;
use svc_broker::{Broker, LivenessLink, BROKER_ISS};

#[derive(Parser, Debug)]
struct Opts {
    /// Cell directory: the Broker's key and cell identity are in
    /// `<cell>/broker/`; the Verifier's public key in `<cell>/public/verifier`.
    #[arg(long, default_value = "cell")]
    cell: PathBuf,
    /// Public UDP address for clients (QUIC).
    #[arg(long, default_value = "127.0.0.1:4446")]
    bind: std::net::SocketAddr,
    /// Server Liveness's cell address (mutual TLS).
    #[arg(long, default_value = "127.0.0.1:4454")]
    liveness: std::net::SocketAddr,
    /// The Revocation Feed's cell address.
    #[arg(long)]
    feed: Option<std::net::SocketAddr>,
    /// TLS certificate (DER) presented to clients; must chain to the CA they pin.
    #[arg(long, default_value = "keys/broker_tls.der")]
    tls_cert: String,
    /// PKCS#8 private key (DER) for `--tls-cert`.
    #[arg(long, default_value = "keys/broker_tls.key.der")]
    tls_key: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let o = Opts::parse();
    let key = fpp_svc::keys::ed25519(&o.cell, "broker", BROKER_ISS)?;
    let identity = fpp_svc::cell::load(&o.cell, "broker")?;
    let link = LivenessLink::new(&identity, o.liveness)?;
    let broker = Arc::new(Broker::new(Ed25519Signer::new(key), o.cell.clone(), link));
    if let Some(feed) = o.feed {
        tokio::spawn(broker.clone().follow(identity, feed));
    }
    let identity = common::pki::ServerIdentity::load(&o.tls_cert, &o.tls_key)?;
    let endpoint = common::admission::server_endpoint(&identity, o.bind)?;
    println!(
        "[broker] key published in {}; Server Liveness at {}; listening on {}",
        o.cell.join("public/broker").display(),
        o.liveness,
        o.bind
    );
    broker.serve(endpoint).await;
    Ok(())
}
