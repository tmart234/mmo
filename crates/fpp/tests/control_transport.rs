//! Security tests for the owned `Noise_IK_25519_ChaChaPoly_SHA256` control
//! transport (findings F01, F07, F08): pinned server key authentication,
//! mutual client key authentication, pre-allocation frame caps, deadlines,
//! multi-chunk framing, and sync ↔ async wire interoperability.

use fpp::control::{ChallengeRequest, CheckpointSubmit, Purpose, CONTROL_VERSION};
use fpp::session::StaticKeypair;
use fpp::transport::{check_frame_len, sync::NoiseStream, TransportError};
use std::net::TcpListener;
use std::time::Duration;

/// F07: oversized length prefix is refused before allocating.
#[test]
fn oversized_frame_length_rejected_before_alloc() {
    let err = check_frame_len(u32::MAX.to_be_bytes(), 64 * 1024).unwrap_err();
    assert!(matches!(
        err,
        TransportError::FrameTooLarge {
            len: 0xffff_ffff,
            max: 65536
        }
    ));
    assert_eq!(
        check_frame_len(1024u32.to_be_bytes(), 64 * 1024).unwrap(),
        1024
    );
}

/// F01: a server without the pinned static private key is rejected at handshake.
#[test]
fn server_impersonation_rejected() {
    let real = StaticKeypair::generate();
    let impostor = StaticKeypair::generate();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let srv = std::thread::spawn(move || {
        let _ = NoiseStream::accept(&listener, &impostor, Duration::from_secs(2));
    });
    let err = NoiseStream::connect(addr, &real.public, None, Duration::from_secs(2))
        .err()
        .expect("impostor must fail handshake");
    assert!(matches!(
        err,
        TransportError::Noise(_) | TransportError::Io(_)
    ));
    let _ = srv.join();
}

/// Mutual auth + multi-chunk payload (> 64 KiB) across sync client and server.
#[test]
fn sync_mutual_auth_and_large_multichunk_frame() {
    let server_kp = StaticKeypair::generate();
    let server_pub = server_kp.public;
    let client_kp = StaticKeypair::generate();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let expected_client = client_kp.public;
    let payload = vec![0xab; 180_000];
    let payload_srv = payload.clone();

    let srv = std::thread::spawn(move || {
        let mut s = NoiseStream::accept(&listener, &server_kp, Duration::from_secs(5)).unwrap();
        assert_eq!(s.peer_static, expected_client);
        let req: ChallengeRequest = s.recv().unwrap();
        assert_eq!(req.version, CONTROL_VERSION);
        assert_eq!(req.purpose, Purpose::GsJoin);
        let big: CheckpointSubmit = s.recv_max(256 * 1024).unwrap();
        assert_eq!(big.checkpoint, payload_srv);
        // Oversized check on receiver cap:
        let small_err = s.recv_max::<CheckpointSubmit>(128);
        assert!(matches!(
            small_err,
            Err(TransportError::FrameTooLarge { .. })
        ));
    });

    let mut c =
        NoiseStream::connect(addr, &server_pub, Some(&client_kp), Duration::from_secs(5)).unwrap();
    c.send(&ChallengeRequest {
        version: CONTROL_VERSION,
        purpose: Purpose::GsJoin,
    })
    .unwrap();
    c.send(&CheckpointSubmit {
        checkpoint: payload,
    })
    .unwrap();
    // Send a 512-byte payload to trigger FrameTooLarge against the 128-byte cap.
    c.send(&CheckpointSubmit {
        checkpoint: vec![0xcd; 512],
    })
    .unwrap();
    srv.join().unwrap();
}

/// F08 + sync ↔ async interop: idle peer dropped at deadline, and sync client
/// talks full-duplex to async server seamlessly.
#[cfg(feature = "async-net")]
#[tokio::test]
async fn async_server_interop_and_idle_deadline() {
    use fpp::transport::async_io::AsyncNoiseStream;
    use std::time::Instant;
    use tokio::net::TcpListener as AsyncListener;

    let server_kp = StaticKeypair::generate();
    let listener = AsyncListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // 1) Idle peer completes TCP connect, never sends Noise msg1 -> timed out (F08).
    let raw_client = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (sock, _) = listener.accept().await.unwrap();
    let started = Instant::now();
    let err = AsyncNoiseStream::accept(sock, &server_kp, Duration::from_millis(150))
        .await
        .err()
        .expect("idle peer must time out");
    assert!(matches!(err, TransportError::Timeout));
    assert!(started.elapsed() < Duration::from_secs(2));
    drop(raw_client);

    // 2) Sync client <-> async server full-duplex message exchange.
    let srv_pub = server_kp.public;
    let client_handle = std::thread::spawn(move || {
        let mut s = NoiseStream::connect(addr, &srv_pub, None, Duration::from_secs(5)).unwrap();
        s.send(&ChallengeRequest {
            version: CONTROL_VERSION,
            purpose: Purpose::Gossip,
        })
        .unwrap();
        let echo: ChallengeRequest = s.recv().unwrap();
        assert_eq!(echo.purpose, Purpose::Gossip);
    });

    let (sock, _) = listener.accept().await.unwrap();
    let mut s = AsyncNoiseStream::accept(sock, &server_kp, Duration::from_secs(5))
        .await
        .unwrap();
    let req: ChallengeRequest = s.recv().await.unwrap();
    assert_eq!(req.purpose, Purpose::Gossip);
    s.send(&req).await.unwrap();
    client_handle.join().unwrap();
}
