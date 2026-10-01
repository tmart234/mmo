//! A cell in one process: Server Liveness, the Verifier and the Broker, each
//! with its own key from its own cell directory. A client is admitted
//! through all three; and each service holds its line when another
//! misbehaves, is impersonated, or is down.

use client_core::{request_admission, ClientTrust, Services, SessionEnd};
use common::admission::request_challenge;
use common::crypto::{match_request_sign_bytes, now_ms};
use common::framing::{recv_msg, send_msg};
use common::pki::DevPki;
use common::proto::{MatchAnswer, MatchRequest};
use ed25519_dalek::SigningKey;
use fpp_crypto::{Ed25519Signer, Signer as _};
use fpp_svc::api::liveness::{Request, Response};
use fpp_tokens::{instance_id, verify_ar, AttestationResult, Features};
use fpp_types::{BuildId, DeviceTier, Did, Digest, Reason};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use svc_liveness::config::LivenessConfig;
use svc_liveness::ctx::Session;

fn free_addr() -> SocketAddr {
    let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    s.local_addr().unwrap()
}

struct TestCell {
    services: Services,
    trust: ClientTrust,
    liveness: svc_liveness::ctx::Ctx,
    liveness_rpc: SocketAddr,
    dir: std::path::PathBuf,
}

/// Start the three services; one game server is admitted and has
/// checkpointed (as Server Liveness would record it).
async fn start(dir: &Path) -> TestCell {
    let _ = std::fs::remove_dir_all(dir);
    fpp_svc::cell::init(dir, &["liveness", "verifier", "broker"]).unwrap();
    fpp_svc::keys::ed25519(dir, "enforcement", "enforcement.test").unwrap();
    let pki = DevPki::generate().unwrap();
    let (public, rpc) = (free_addr(), free_addr());

    let liveness = svc_liveness::start(
        dir,
        pki.service("liveness"),
        svc_liveness::Addrs {
            public,
            rpc,
            callers: vec!["broker".into()],
            feed: None,
            evidence: None,
            log: None,
        },
        LivenessConfig::default(),
    )
    .unwrap();
    liveness.sessions.insert(
        [7; 16],
        Session {
            instance_pub: [8; 32],
            noise_static: [9; 32],
            game_addr: "127.0.0.1:50000".into(),
            sw_hash: [0; 32],
            last_seen_ms: now_ms(),
            revoked: false,
            last_checkpoint: Some((0, Digest::default())),
            verified: vec![Digest::default()],
            next_slot: 0,
        },
    );

    let verifier_addr = free_addr();
    let (verifier, endpoint) = svc_verifier::start(
        dir,
        pki.service("verifier"),
        verifier_addr,
        Default::default(),
    )
    .unwrap();
    tokio::spawn(verifier.serve(endpoint));

    let broker_addr = free_addr();
    let key = fpp_svc::keys::ed25519(dir, "broker", svc_broker::BROKER_ISS).unwrap();
    let link =
        svc_broker::LivenessLink::new(&fpp_svc::cell::load(dir, "broker").unwrap(), rpc).unwrap();
    let broker = Arc::new(svc_broker::Broker::new(
        Ed25519Signer::new(key),
        dir.to_path_buf(),
        link,
    ));
    tokio::spawn(
        broker
            .serve(common::admission::server_endpoint(pki.service("broker"), broker_addr).unwrap()),
    );

    TestCell {
        services: Services {
            verifier: verifier_addr,
            broker: broker_addr,
            ..Services::default()
        },
        trust: ClientTrust {
            ca_der: pki.ca_cert_der.clone(),
            bundle: fpp_svc::keys::bundle(dir).unwrap(),
        },
        liveness,
        liveness_rpc: rpc,
        dir: dir.to_path_buf(),
    }
}

/// Ask the Broker for `queue` with `ar`, signing with `session`.
async fn ask_broker(cell: &TestCell, ar: &[u8], session: &Ed25519Signer) -> MatchAnswer {
    let mut b = request_challenge(&cell.trust.ca_der, cell.services.broker, "broker")
        .await
        .unwrap();
    let msg = match_request_sign_bytes(&b.challenge, ar, "open");
    let pop_sig: [u8; 64] = session.sign(&msg).try_into().unwrap();
    send_msg(
        &mut b.send,
        &MatchRequest {
            ar: ar.to_vec(),
            queue: "open".into(),
            pop_sig,
        },
    )
    .await
    .unwrap();
    recv_msg(&mut b.recv).await.unwrap()
}

fn refused(answer: MatchAnswer) -> u16 {
    match answer {
        MatchAnswer::Refused { code } => code,
        MatchAnswer::Granted { .. } => panic!("granted"),
    }
}

/// An AR for `session`, signed by `key`.
fn ar(key: &Ed25519Signer, session: &Ed25519Signer) -> Vec<u8> {
    let now = now_ms() / 1000;
    fpp_crypto::sign(
        key,
        &AttestationResult {
            iss: "ver.dev".into(),
            iat: now,
            exp: now + 600,
            cti: [1; 16],
            cnf: fpp_types::SessionKey::Ed25519(session.verifying_key().to_bytes()),
            nonce: [0; 32],
            did: Did([2; 32]),
            tier: DeviceTier::D3Hardened,
            features: Features::default(),
            client_build: BuildId([0; 32]),
            platform: "linux".into(),
            policy_ver: 1,
            warnings: vec![],
        },
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn a_cell_of_three_services() {
    let dir = std::env::temp_dir().join(format!("svc-cell-{}", std::process::id()));
    let cell = start(&dir).await;

    // three keys, one per service, none derived from another
    let b = &cell.trust.bundle;
    assert_ne!(b.verifier_ar, b.broker_sat);
    assert_ne!(b.broker_sat, b.server_liveness);
    assert_ne!(b.verifier_ar, b.server_liveness);
    for s in ["liveness", "verifier", "broker"] {
        assert!(dir.join(s).join("ed25519.seed").exists());
    }

    // a client through the Verifier and the Broker, to the admitted server
    let creds = request_admission(&cell.services, &cell.trust, "open")
        .await
        .unwrap();
    assert_eq!(creds.sat_claims.aud, instance_id(&[8; 32]));
    assert_eq!(creds.sat_claims.match_id.0, [7; 16]);
    assert_eq!(creds.sat_claims.slot, 0);
    assert_eq!(creds.gs_noise_static, [9; 32]);
    // (the AR is the Verifier's alone: the Broker's key does not verify it)
    let mut broker_only = fpp_crypto::KeySet::default();
    broker_only.insert_ed25519(fpp_crypto::KeyRole::VerifierAr, b.broker_sat);
    assert!(verify_ar(&creds.ar, &broker_only, now_ms() / 1000).is_err());
    // and a queue above the device's tier is refused by the Broker
    let Err(err) = request_admission(&cell.services, &cell.trust, "verified").await else {
        panic!("admitted to `verified` at tier D0");
    };
    assert_eq!(
        err.downcast_ref::<SessionEnd>(),
        Some(&SessionEnd::Refused(Reason::TierInsufficient as u16))
    );

    let session = Ed25519Signer::new(SigningKey::from_bytes(&[5; 32]));
    // an AR signed by any key but the Verifier's: refused
    for s in ["broker", "liveness"] {
        let seed = fpp_svc::cell::signing_seed(&dir, s, "ed25519").unwrap();
        let other = Ed25519Signer::new(SigningKey::from_bytes(&seed));
        let answer = ask_broker(&cell, &ar(&other, &session), &session).await;
        assert_eq!(
            refused(answer),
            Reason::ArInvalid as u16,
            "AR signed by {s}"
        );
    }
    // the Verifier's AR, presented by another key than it names: refused
    let seed = fpp_svc::cell::signing_seed(&dir, "verifier", "ed25519").unwrap();
    let verifier = Ed25519Signer::new(SigningKey::from_bytes(&seed));
    let good = ar(&verifier, &session);
    let thief = Ed25519Signer::new(SigningKey::from_bytes(&[6; 32]));
    assert_eq!(
        refused(ask_broker(&cell, &good, &thief).await),
        Reason::PopInvalid as u16
    );
    // (and by its own key: granted, the next slot)
    match ask_broker(&cell, &good, &session).await {
        MatchAnswer::Granted { .. } => {}
        other => panic!("{other:?}"),
    }

    // Server Liveness places players for the Broker only
    let as_verifier =
        fpp_svc::mtls::client_endpoint(&fpp_svc::cell::load(&dir, "verifier").unwrap()).unwrap();
    let conn = fpp_svc::mtls::connect(&as_verifier, cell.liveness_rpc, "liveness")
        .await
        .unwrap();
    assert!(matches!(
        fpp_svc::call::<_, Response>(&conn, &Request::Place)
            .await
            .unwrap(),
        Response::Refused(_)
    ));

    // a revoked server gets no more players
    cell.liveness.revoke(&[7; 16], "test");
    let Err(err) = request_admission(&cell.services, &cell.trust, "open").await else {
        panic!("placed on a revoked server");
    };
    assert_eq!(
        err.downcast_ref::<SessionEnd>(),
        Some(&SessionEnd::Refused(Reason::ServerDraining as u16))
    );

    let _ = std::fs::remove_dir_all(&cell.dir);
}
