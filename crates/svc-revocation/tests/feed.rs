//! The Revocation Feed with its Transparency Log, over mutual TLS: who may
//! publish and follow, what is refused, what is logged, and a restart.

use fpp_crypto::{Ed25519Signer, KeyRole, KeySet};
use fpp_svc::api::revocation::{Request, Response};
use fpp_wire::{Action, RevocationEvent, Scope, SubjectKind};
use std::net::SocketAddr;
use std::path::Path;
use svc_revocation::enforce::{Enforcer, Order};
use svc_revocation::{Feed, FeedConfig, LogLink};

fn free_addr() -> SocketAddr {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

fn order(kind: SubjectKind, id: Vec<u8>, action: Action) -> Order {
    Order {
        subject_kind: kind,
        subject_id: id,
        action,
        scope: Scope::default(),
        reason: fpp_types::Reason::PolicyKick as u16,
        duration_s: Some(3600),
        note: "test".into(),
    }
}

/// A Transparency Log for the cell, with "revocation" and "enforcement" as writers.
fn log_key() -> fpp_crypto::hybrid::HybridSigner {
    fpp_crypto::hybrid::HybridSigner::from_seeds(&[1; 32], &[2; 32]).unwrap()
}

fn start_log(cell: &Path) -> SocketAddr {
    let log = fpp_log::Log::open(cell.join("log/data"), "fpp.test/log", log_key(), 60).unwrap();
    let addr = free_addr();
    let endpoint =
        fpp_svc::mtls::server_endpoint(&fpp_svc::cell::load(cell, "log").unwrap(), addr).unwrap();
    tokio::spawn(svc_log::serve_log(
        endpoint,
        log,
        svc_log::LogConfig {
            writers: vec!["revocation".into(), "enforcement".into()],
            witnesses: vec![],
            cell: cell.to_path_buf(),
        },
    ));
    addr
}

fn start_feed(cell: &Path, log: SocketAddr) -> (SocketAddr, std::sync::Arc<Feed>) {
    let identity = fpp_svc::cell::load(cell, "revocation").unwrap();
    let feed = Feed::open(FeedConfig {
        publishers: vec!["enforcement".into()],
        subscribers: vec!["broker".into(), "liveness".into()],
        cell: cell.to_path_buf(),
        data: cell.join("revocation/data"),
        log: Some(LogLink::new(&identity, log).unwrap()),
    })
    .unwrap();
    let addr = free_addr();
    let endpoint = fpp_svc::mtls::server_endpoint(&identity, addr).unwrap();
    tokio::spawn(feed.clone().serve(endpoint));
    (addr, feed)
}

async fn as_service(cell: &Path, name: &str, addr: SocketAddr) -> fpp_svc::quinn::Connection {
    let endpoint =
        fpp_svc::mtls::client_endpoint(&fpp_svc::cell::load(cell, name).unwrap()).unwrap();
    fpp_svc::mtls::connect(&endpoint, addr, "revocation")
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn the_feed_takes_enforcement_events_logs_them_and_serves_them() {
    let cell = std::env::temp_dir().join(format!("svc-revocation-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&cell);
    fpp_svc::cell::init(
        &cell,
        &["revocation", "enforcement", "log", "broker", "verifier"],
    )
    .unwrap();
    let log_addr = start_log(&cell);
    let (feed_addr, _feed) = start_feed(&cell, log_addr);
    let enforcer = Enforcer::open(&cell, feed_addr, Some(log_addr)).unwrap();

    // a subscriber waiting before anything is published gets it at once
    let broker = as_service(&cell, "broker", feed_addr).await;
    let waiting = {
        let broker = broker.clone();
        tokio::spawn(async move {
            let started = std::time::Instant::now();
            let r: Response = fpp_svc::call(
                &broker,
                &Request::Since {
                    from: 0,
                    wait_ms: 20_000,
                },
            )
            .await
            .unwrap();
            (r, started.elapsed())
        })
    };
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let kicked = enforcer
        .enforce(order(SubjectKind::Session, vec![7; 32], Action::Kick))
        .await
        .unwrap();
    assert_eq!(kicked.seq, 0);
    let (Response::Events(events), waited) = waiting.await.unwrap() else {
        panic!("no events")
    };
    assert!(waited < std::time::Duration::from_secs(5));
    assert_eq!(events, vec![(0, kicked.signed.clone())]);
    let enforcement_key = ed25519_dalek::VerifyingKey::from_bytes(
        &fpp_svc::PublicKeys::read(&cell, "enforcement")
            .unwrap()
            .ed25519,
    )
    .unwrap();
    let mut keys = KeySet::default();
    keys.insert_ed25519(KeyRole::Enforcement, enforcement_key);
    let event = fpp_crypto::verify::<RevocationEvent>(&events[0].1, &keys)
        .unwrap()
        .payload;
    assert_eq!(event, kicked.event);

    // the record and the event are in the log (record first, then event)
    let on_disk = fpp_log::Log::open(cell.join("log/data"), "fpp.test/log", log_key(), 60).unwrap();
    assert_eq!(on_disk.size(), 2);
    assert_eq!(kicked.record_index, Some(0));
    drop(on_disk);

    // only Enforcement may publish; only subscribers may follow
    let other = Ed25519Signer::new(ed25519_dalek::SigningKey::from_bytes(&[9; 32]));
    let forged = fpp_crypto::sign(
        &other,
        &RevocationEvent {
            id: [2; 16],
            ..kicked.event.clone()
        },
    );
    let as_enforcement = as_service(&cell, "enforcement", feed_addr).await;
    let r: Response = fpp_svc::call(&as_enforcement, &Request::Publish(forged))
        .await
        .unwrap();
    assert!(matches!(r, Response::Refused(_)), "{r:?}");
    let r: Response = fpp_svc::call(&broker, &Request::Publish(kicked.signed.clone()))
        .await
        .unwrap();
    assert!(matches!(r, Response::Refused(_)), "{r:?}");
    let verifier = as_service(&cell, "verifier", feed_addr).await;
    let r: Response = fpp_svc::call(
        &verifier,
        &Request::Since {
            from: 0,
            wait_ms: 0,
        },
    )
    .await
    .unwrap();
    assert!(matches!(r, Response::Refused(_)), "{r:?}");

    // publishing the same event again is idempotent
    let r: Response = fpp_svc::call(&as_enforcement, &Request::Publish(kicked.signed.clone()))
        .await
        .unwrap();
    assert_eq!(
        r,
        Response::Published {
            seq: 0,
            log_index: None
        }
    );
    // an id of the wrong size for its kind never gets signed
    assert!(enforcer
        .enforce(order(SubjectKind::Sat, vec![1; 32], Action::Kick))
        .await
        .is_err());
    let banned = enforcer
        .enforce(order(SubjectKind::Account, vec![3; 32], Action::Ban))
        .await
        .unwrap();
    assert_eq!(banned.seq, 1);

    // a restarted feed has the same events
    let reopened = Feed::open(FeedConfig {
        publishers: vec![],
        subscribers: vec![],
        cell: cell.clone(),
        data: cell.join("revocation/data"),
        log: None,
    })
    .unwrap();
    assert_eq!(reopened.len(), 2);
    let again = reopened.since(0, std::time::Duration::from_millis(0)).await;
    assert_eq!(again[1].1, banned.signed);

    let _ = std::fs::remove_dir_all(&cell);
}
