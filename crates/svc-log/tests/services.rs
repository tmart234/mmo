//! The log and witness services over mutual TLS: who may append, who may
//! cosign, receipts, proofs, and a certificate from another cell.

use fpp_crypto::hybrid::{verify_hybrid, HybridSigner};
use fpp_crypto::{KeyRole, KeySet};
use fpp_log::{Checkpoint, Log, Note, Witness};
use fpp_types::Digest;
use fpp_wire::LogReceipt;
use svc_log::{serve_log, witness_round, LogConfig, PublicKeys, Request, Response};

const ORIGIN: &str = "fpp.test/log/svc";

#[tokio::test(flavor = "multi_thread")]
async fn log_and_witness_services() {
    let cell = std::env::temp_dir().join(format!("svc-log-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&cell);
    fpp_svc::cell::init(&cell, &["log", "witness", "revocation", "broker"]).unwrap();

    // the log, with its own key
    let key = HybridSigner::from_seeds(
        &fpp_svc::cell::signing_seed(&cell, "log", "ed25519").unwrap(),
        &fpp_svc::cell::signing_seed(&cell, "log", "ml-dsa-65").unwrap(),
    )
    .unwrap();
    let log = Log::open(cell.join("log/data"), ORIGIN, key, 60).unwrap();
    let log_keys = PublicKeys {
        name: ORIGIN.into(),
        ed25519: log.public_key(),
        ml_dsa: Some(log.ml_dsa_public_key().to_vec()),
    };
    log_keys.write(&cell, "log").unwrap();
    let server = fpp_svc::mtls::server_endpoint(
        &fpp_svc::cell::load(&cell, "log").unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let addr = server.local_addr().unwrap();
    tokio::spawn(serve_log(
        server,
        log,
        LogConfig {
            writers: vec!["revocation".into()],
            witnesses: vec!["witness".into()],
            cell: cell.clone(),
        },
    ));

    let as_service = |name: &str| {
        fpp_svc::mtls::client_endpoint(&fpp_svc::cell::load(&cell, name).unwrap()).unwrap()
    };
    let revocation = fpp_svc::mtls::connect(&as_service("revocation"), addr, "log")
        .await
        .unwrap();
    let broker = fpp_svc::mtls::connect(&as_service("broker"), addr, "log")
        .await
        .unwrap();

    // a writer appends, and gets hybrid-signed receipts
    let entries: Vec<Vec<u8>> = (0..300)
        .map(|i| format!("revocation {i}").into_bytes())
        .collect();
    let Response::Added(added) = fpp_svc::call(&revocation, &Request::Add(entries.clone()))
        .await
        .unwrap()
    else {
        panic!("not added");
    };
    assert_eq!(added.len(), 300);
    let mut keys = KeySet::default();
    keys.insert_hybrid(
        KeyRole::Log,
        ed25519_dalek::VerifyingKey::from_bytes(&log_keys.ed25519).unwrap(),
        log_keys.ml_dsa.clone().unwrap(),
    );
    let receipt: LogReceipt = verify_hybrid(&added[7].1, &keys).unwrap().payload;
    assert_eq!(receipt.leaf_hash, fpp_merkle::leaf_hash(b"revocation 7"));

    // anyone else may read, not append
    assert!(matches!(
        fpp_svc::call(&broker, &Request::Add(vec![b"x".to_vec()]))
            .await
            .unwrap(),
        Response::Refused(_)
    ));
    let Response::Checkpoint(note) = fpp_svc::call(&broker, &Request::Checkpoint).await.unwrap()
    else {
        panic!()
    };
    let head = Checkpoint::parse(&Note::parse(&note).unwrap().text).unwrap();
    assert_eq!(head.size, 300);
    let Response::Proof(proof) = fpp_svc::call(
        &broker,
        &Request::Inclusion {
            index: 7,
            size: 300,
        },
    )
    .await
    .unwrap() else {
        panic!()
    };
    let proof: Vec<Digest> = proof.into_iter().map(Digest).collect();
    assert!(fpp_merkle::verify_inclusion(
        &receipt.leaf_hash,
        7,
        300,
        &proof,
        &Digest(head.root)
    ));

    // the witness cosigns, twice as the log grows, and the log publishes it
    let wkey = ed25519_dalek::SigningKey::from_bytes(
        &fpp_svc::cell::signing_seed(&cell, "witness", "ed25519").unwrap(),
    );
    let wpub = wkey.verifying_key().to_bytes();
    PublicKeys {
        name: "fpp.test/witness".into(),
        ed25519: wpub,
        ml_dsa: None,
    }
    .write(&cell, "witness")
    .unwrap();
    let mut witness = Witness::open(
        "fpp.test/witness",
        wkey,
        ORIGIN,
        log_keys.ed25519,
        log_keys.ml_dsa.clone().unwrap(),
        cell.join("witness/state"),
    )
    .unwrap();
    let witness_conn = fpp_svc::mtls::connect(&as_service("witness"), addr, "log")
        .await
        .unwrap();
    assert_eq!(
        witness_round(&witness_conn, &mut witness).await.unwrap(),
        Some(300)
    );
    fpp_svc::call::<_, Response>(&revocation, &Request::Add(vec![b"one more".to_vec()]))
        .await
        .unwrap();
    assert_eq!(
        witness_round(&witness_conn, &mut witness).await.unwrap(),
        Some(301)
    );
    let Response::Checkpoint(note) = fpp_svc::call(&broker, &Request::Checkpoint).await.unwrap()
    else {
        panic!()
    };
    let note = Note::parse(&note).unwrap();
    note.verify_hybrid(ORIGIN, &log_keys.ed25519, log_keys.ml_dsa.as_ref().unwrap())
        .unwrap();
    note.verify_cosignature("fpp.test/witness", &wpub).unwrap();

    // only the witness may add cosignatures
    let line = fpp_log::note::cosign(
        &note.text,
        "fpp.test/witness",
        &ed25519_dalek::SigningKey::from_bytes(&[1; 32]),
        5,
    );
    assert!(matches!(
        fpp_svc::call(
            &revocation,
            &Request::Cosign {
                text: note.text.clone(),
                line
            }
        )
        .await
        .unwrap(),
        Response::Refused(_)
    ));

    // a certificate from another cell is refused at the TLS handshake
    let other = std::env::temp_dir().join(format!("svc-log-other-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&other);
    fpp_svc::cell::init(&other, &["revocation"]).unwrap();
    let stranger =
        fpp_svc::mtls::client_endpoint(&fpp_svc::cell::load(&other, "revocation").unwrap())
            .unwrap();
    let attempt = async {
        let conn = fpp_svc::mtls::connect(&stranger, addr, "log").await?;
        fpp_svc::call::<_, Response>(&conn, &Request::Checkpoint).await
    };
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(10), attempt)
            .await
            .map_or(true, |r| r.is_err())
    );

    let _ = std::fs::remove_dir_all(&cell);
    let _ = std::fs::remove_dir_all(&other);
}
