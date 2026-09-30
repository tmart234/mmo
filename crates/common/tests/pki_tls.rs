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
    let (_server, addr) = serve(pki.service("liveness"));
    dial(addr, &pki.ca_cert_der, &pki::server_name("liveness"))
        .await
        .expect("server signed by the pinned CA must be accepted");
}

#[tokio::test]
async fn rejects_server_signed_by_another_ca() {
    // An impersonator with a perfectly valid certificate from a different CA.
    let trusted = DevPki::generate().unwrap();
    let attacker = DevPki::generate().unwrap();
    let (_server, addr) = serve(attacker.service("liveness"));
    let err = dial(addr, &trusted.ca_cert_der, &pki::server_name("liveness"))
        .await
        .expect_err("certificate from an unpinned CA must be rejected");
    assert!(
        format!("{err:#}").contains("invalid peer certificate"),
        "unexpected error: {err:#}"
    );
}

#[tokio::test]
async fn rejects_certificate_for_another_name() {
    // Valid certificates from the same CA, presented where another server
    // is expected: a GS's, and one service's where another is expected.
    let pki = DevPki::generate().unwrap();
    for (identity, expected) in [(&pki.gs, "liveness"), (pki.service("verifier"), "broker")] {
        let (_server, addr) = serve(identity);
        let err = dial(addr, &pki.ca_cert_der, &pki::server_name(expected))
            .await
            .expect_err("certificate for another server name must be rejected");
        assert!(
            format!("{err:#}").contains("invalid peer certificate"),
            "unexpected error: {err:#}"
        );
    }
}

/// FPP-T1: the control links agree on the hybrid post-quantum group
/// X25519MLKEM768, so recorded traffic resists later quantum decryption.
#[test]
fn handshake_negotiates_hybrid_post_quantum_key_exchange() {
    use rustls::{ClientConnection, NamedGroup, ServerConnection};
    use std::sync::Arc;

    let pki = DevPki::generate().unwrap();
    let client_cfg = Arc::new(pki::tls_client_config(&pki.ca_cert_der).unwrap());
    let server_cfg = Arc::new(pki::tls_server_config(pki.service("liveness")).unwrap());
    let name = pki::server_name("liveness").try_into().unwrap();
    let mut client = ClientConnection::new(client_cfg, name).unwrap();
    let mut server = ServerConnection::new(server_cfg).unwrap();

    // Shuttle bytes in memory until both sides finish the handshake.
    for _ in 0..10 {
        let mut buf = Vec::new();
        while client.wants_write() {
            client.write_tls(&mut buf).unwrap();
        }
        server.read_tls(&mut buf.as_slice()).unwrap();
        server.process_new_packets().unwrap();
        let mut buf = Vec::new();
        while server.wants_write() {
            server.write_tls(&mut buf).unwrap();
        }
        client.read_tls(&mut buf.as_slice()).unwrap();
        client.process_new_packets().unwrap();
        if !client.is_handshaking() && !server.is_handshaking() {
            break;
        }
    }
    assert!(!client.is_handshaking());
    let group = client.negotiated_key_exchange_group().unwrap().name();
    assert_eq!(group, NamedGroup::X25519MLKEM768);
    assert_eq!(
        server.negotiated_key_exchange_group().unwrap().name(),
        group
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
