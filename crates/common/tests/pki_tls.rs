//! F01: every QUIC link verifies the server certificate against the pinned CA.

use common::pki::{self, DevPki, ServerIdentity};
use std::net::SocketAddr;

/// Start a QUIC server presenting `identity` that completes handshakes.
fn serve(identity: &ServerIdentity) -> (quinn::Endpoint, SocketAddr) {
    let endpoint = quinn::Endpoint::server(
        pki::quic_server_config(identity).unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let addr = endpoint.local_addr().unwrap();
    let acceptor = endpoint.clone();
    tokio::spawn(async move {
        while let Some(incoming) = acceptor.accept().await {
            tokio::spawn(async move {
                if let Ok(conn) = incoming.await {
                    conn.closed().await;
                }
            });
        }
    });
    (endpoint, addr)
}

async fn dial(addr: SocketAddr, ca_der: &[u8], name: &str) -> anyhow::Result<quinn::Connection> {
    let endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap())?;
    let conn = endpoint
        .connect_with(pki::quic_client_config(ca_der)?, addr, name)?
        .await?;
    Ok(conn)
}

#[tokio::test]
async fn accepts_server_signed_by_pinned_ca() {
    let pki = DevPki::generate().unwrap();
    let (_server, addr) = serve(&pki.vs);
    dial(addr, &pki.ca_cert_der, pki::VS_SERVER_NAME)
        .await
        .expect("server signed by the pinned CA must be accepted");
}

#[tokio::test]
async fn rejects_server_signed_by_another_ca() {
    // An impersonator with a perfectly valid certificate from a different CA.
    let trusted = DevPki::generate().unwrap();
    let attacker = DevPki::generate().unwrap();
    let (_server, addr) = serve(&attacker.vs);
    let err = dial(addr, &trusted.ca_cert_der, pki::VS_SERVER_NAME)
        .await
        .expect_err("certificate from an unpinned CA must be rejected");
    assert!(
        format!("{err:#}").contains("invalid peer certificate"),
        "unexpected error: {err:#}"
    );
}

#[tokio::test]
async fn rejects_certificate_for_another_name() {
    // A GS certificate (valid, same CA) presented where the VS is expected.
    let pki = DevPki::generate().unwrap();
    let (_server, addr) = serve(&pki.gs);
    let err = dial(addr, &pki.ca_cert_der, pki::VS_SERVER_NAME)
        .await
        .expect_err("certificate for another server name must be rejected");
    assert!(
        format!("{err:#}").contains("invalid peer certificate"),
        "unexpected error: {err:#}"
    );
}

#[test]
fn ensure_dev_pki_writes_once() {
    let dir = std::env::temp_dir().join(format!("mmo-pki-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    assert!(pki::ensure_dev_pki(&dir).unwrap(), "first call generates");
    let ca = std::fs::read(dir.join("dev_ca.der")).unwrap();
    assert!(
        !pki::ensure_dev_pki(&dir).unwrap(),
        "second call keeps files"
    );
    assert_eq!(ca, std::fs::read(dir.join("dev_ca.der")).unwrap());
    let _ = std::fs::remove_dir_all(&dir);
}
