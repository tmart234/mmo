//! The Evidence Store over mutual TLS: who may store and read, content
//! addressing, the match index, a corrupted disk, and a restart.

use fpp_svc::api::evidence::{Request, Response};
use svc_evidence::{digest, Access, Client, Store};

#[tokio::test(flavor = "multi_thread")]
async fn evidence_is_stored_by_content_and_read_back_checked() {
    let cell = std::env::temp_dir().join(format!("svc-evidence-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&cell);
    fpp_svc::cell::init(&cell, &["evidence", "liveness", "audit", "broker"]).unwrap();
    let data = cell.join("evidence/data");
    let addr = std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let endpoint =
        fpp_svc::mtls::server_endpoint(&fpp_svc::cell::load(&cell, "evidence").unwrap(), addr)
            .unwrap();
    tokio::spawn(svc_evidence::serve(
        endpoint,
        Store::open(&data).unwrap(),
        Access {
            writers: vec!["liveness".into()],
            readers: vec!["audit".into()],
        },
    ));
    let client =
        |name: &str| Client::new(&fpp_svc::cell::load(&cell, name).unwrap(), addr).unwrap();
    let (liveness, audit, broker) = (client("liveness"), client("audit"), client("broker"));

    // Server Liveness stores two Checkpoints of a match (one twice)
    let (m, other) = ([1u8; 16], [2u8; 16]);
    let (a, b) = (
        b"checkpoint epoch 0".to_vec(),
        b"checkpoint epoch 1".to_vec(),
    );
    assert_eq!(liveness.put(m, a.clone()).await.unwrap(), digest(&a));
    assert_eq!(liveness.put(m, b.clone()).await.unwrap(), digest(&b));
    liveness.put(m, a.clone()).await.unwrap();
    assert_eq!(audit.list(m).await.unwrap(), vec![digest(&a), digest(&b)]);
    assert!(audit.list(other).await.unwrap().is_empty());
    assert_eq!(audit.get(digest(&b)).await.unwrap(), Some(b.clone()));
    assert_eq!(audit.get([9; 32]).await.unwrap(), None);

    // only writers store, only readers read
    for (who, request) in [
        (
            &audit,
            Request::Put {
                match_id: m,
                object: b"x".to_vec(),
            },
        ),
        (
            &broker,
            Request::Put {
                match_id: m,
                object: b"x".to_vec(),
            },
        ),
        (&broker, Request::Get(digest(&a))),
        (&liveness, Request::List(m)),
    ] {
        let r = who.call(&request).await.unwrap();
        assert!(matches!(r, Response::Refused(_)), "{request:?}: {r:?}");
    }
    assert!(liveness.put(m, Vec::new()).await.is_err());

    // a corrupted object is reported, never served
    let h = hex::encode(digest(&a));
    let path = data.join("objects").join(&h[..2]).join(&h);
    std::fs::write(&path, b"checkpoint epoch 9").unwrap();
    let r = audit.call(&Request::Get(digest(&a))).await.unwrap();
    assert!(
        matches!(&r, Response::Refused(why) if why.contains("corrupt")),
        "{r:?}"
    );

    // a restarted store has the index and the objects
    let reopened = Store::open(&data).unwrap();
    assert_eq!(reopened.list(&m).unwrap(), vec![digest(&a), digest(&b)]);
    assert_eq!(reopened.get(&digest(&b)).unwrap(), Some(b));

    let _ = std::fs::remove_dir_all(&cell);
}
