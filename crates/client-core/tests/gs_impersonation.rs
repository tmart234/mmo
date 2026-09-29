//! F01 through the client's own dial path: an impersonating GS is refused.

use common::pki::{self, DevPki};

#[tokio::test]
async fn refuses_gs_with_untrusted_certificate() {
    let trusted = DevPki::generate().unwrap();
    let attacker = DevPki::generate().unwrap();

    let server = quinn::Endpoint::server(
        pki::quic_server_config(&attacker.gs).unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let addr = server.local_addr().unwrap().to_string();
    let acceptor = server.clone();
    tokio::spawn(async move {
        while let Some(incoming) = acceptor.accept().await {
            let _ = incoming.await;
        }
    });

    let err = client_core::dial_gs(&addr, &trusted.ca_cert_der)
        .await
        .expect_err("client must refuse a GS whose certificate is not from the pinned CA");
    assert!(
        format!("{err:#}").contains("invalid peer certificate"),
        "unexpected error: {err:#}"
    );

    // The genuine GS certificate is accepted by the same code path.
    let genuine = quinn::Endpoint::server(
        pki::quic_server_config(&trusted.gs).unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let genuine_addr = genuine.local_addr().unwrap().to_string();
    let acceptor = genuine.clone();
    tokio::spawn(async move {
        while let Some(incoming) = acceptor.accept().await {
            if let Ok(conn) = incoming.await {
                conn.closed().await;
            }
        }
    });
    client_core::dial_gs(&genuine_addr, &trusted.ca_cert_der)
        .await
        .expect("genuine GS must be accepted");
}
