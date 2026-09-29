//! End to end over real UDP sockets: a game server (`gs_sim::game`) fed by a
//! test liveness service, and the reference client. These carry the P0 exit
//! tests over to FPP: server impersonation is refused, a stolen or foreign
//! admission token is refused, and clients stop as soon as the server's SAR
//! chain stops (revocation).

use client_core::*;
use common::keys::ServiceKeys;
use common::proto::ClientCmd;
use ed25519_dalek::SigningKey;
use fpp_crypto::Ed25519Signer;
use fpp_session::{Host, HostConfig, StaticKeypair};
use fpp_tokens::{
    instance_id, sar_link, AttestationResult, Features, ServerAttestationResult,
    SessionAdmissionToken,
};
use fpp_types::{BuildId, DeviceTier, Did, Digest, MatchId, Reason, ServerClass};
use gs_sim::game::{self, Match, MatchConfig};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, watch};

const MATCH: MatchId = MatchId(*b"test-match-00001");

fn unix_s() -> u64 {
    common::crypto::now_ms() / 1000
}

struct Server {
    addr: std::net::SocketAddr,
    noise_public: [u8; 32],
    instance_pub: [u8; 32],
    /// While true, the test liveness service keeps issuing SARs.
    feeding: Arc<AtomicBool>,
    checkpoints: mpsc::UnboundedReceiver<(u32, Vec<u8>)>,
    _stop: Arc<AtomicBool>,
}

/// Start a match. `sar_noise_static` overrides the key the SARs certify
/// (an attacker replaying another server's SARs).
async fn start_server(keys: &Arc<ServiceKeys>, sar_noise_static: Option<[u8; 32]>) -> Server {
    let instance = Ed25519Signer::new(SigningKey::generate(&mut rand::rngs::OsRng));
    let instance_pub = instance.verifying_key().to_bytes();
    let noise = StaticKeypair::generate();
    let noise_public = noise.public;
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let m = Match::new(
        MatchConfig {
            match_id: MATCH,
            instance,
            build_id: BuildId([7; 32]),
            keys: keys.bundle().keyset(),
            min_tier: DeviceTier::D0Unknown,
            sar_grace_ms: 1_500,
        },
        Host::new(HostConfig::new(noise)),
    );
    let (sar_tx, sar_rx) = watch::channel(None);
    let (cp_tx, checkpoints) = mpsc::unbounded_channel();
    let stop = Arc::new(AtomicBool::new(false));
    tokio::spawn(game::run(socket, m, sar_rx, cp_tx, None, stop.clone()));

    let feeding = Arc::new(AtomicBool::new(true));
    let (keys, feed) = (keys.clone(), feeding.clone());
    let certified = sar_noise_static.unwrap_or(noise_public);
    tokio::spawn(async move {
        let (mut seq, mut prev) = (0u64, Digest::default());
        while feed.load(Ordering::Relaxed) {
            let iat = unix_s();
            let sar = fpp_crypto::sign(
                &keys.liveness,
                &ServerAttestationResult {
                    iss: "live.test".into(),
                    sub: instance_id(&instance_pub),
                    iat,
                    exp: iat + 10,
                    cnf: instance_pub,
                    tls_spki_sha256: None,
                    noise_static: Some(certified),
                    server_class: ServerClass::FirstParty,
                    build_id: BuildId([7; 32]),
                    region: "test".into(),
                    seq,
                    prev,
                    vrf_pub: None,
                },
            );
            prev = sar_link(&sar).unwrap();
            seq += 1;
            if sar_tx.send(Some(sar)).is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
        // Keep the channel open: the server must notice by the silence alone.
        std::future::pending::<()>().await;
    });
    Server {
        addr,
        noise_public,
        instance_pub,
        feeding,
        checkpoints,
        _stop: stop,
    }
}

/// Tokens as the Verifier and Broker would issue them for `session`.
fn credentials(
    keys: &ServiceKeys,
    s: &Server,
    session: Ed25519Signer,
    slot: u16,
    match_id: MatchId,
) -> Credentials {
    let session_pub = session.verifying_key().to_bytes();
    let now = unix_s();
    let ar = AttestationResult {
        iss: "ver.test".into(),
        iat: now,
        exp: now + 600,
        cti: [slot as u8; 16],
        cnf: session_pub,
        nonce: [0; 32],
        did: Did([slot as u8; 32]),
        tier: DeviceTier::D0Unknown,
        features: Features::default(),
        client_build: BuildId([1; 32]),
        platform: "linux".into(),
        policy_ver: 1,
        warnings: vec![],
    };
    let sat = SessionAdmissionToken {
        iss: "broker.test".into(),
        sub: [slot as u8; 32],
        aud: instance_id(&s.instance_pub),
        iat: now,
        exp: now + 600,
        cti: [0x40 + slot as u8; 16],
        cnf: session_pub,
        did: ar.did,
        tier: ar.tier,
        match_id,
        slot,
        queue: "open".into(),
        policy_ver: 1,
        ar_cti: ar.cti,
    };
    Credentials {
        ar: fpp_crypto::sign(&keys.verifier, &ar),
        sat: fpp_crypto::sign(&keys.broker, &sat),
        sat_claims: sat,
        session,
        gs_addr: s.addr,
        gs_noise_static: s.noise_public,
    }
}

fn setup() -> (Arc<ServiceKeys>, ClientTrust) {
    let keys = Arc::new(ServiceKeys::derive(&[9; 32]));
    let trust = ClientTrust {
        ca_der: Vec::new(),
        bundle: keys.bundle(),
    };
    (keys, trust)
}

fn new_session() -> Ed25519Signer {
    Ed25519Signer::new(SigningKey::generate(&mut rand::rngs::OsRng))
}

fn end_of(e: anyhow::Error) -> SessionEnd {
    *e.downcast_ref::<SessionEnd>()
        .unwrap_or_else(|| panic!("not a SessionEnd: {e:#}"))
}

const JOIN: Duration = Duration::from_secs(5);
const GRACE: Duration = Duration::from_millis(1_500);

#[tokio::test]
async fn admitted_client_plays_and_the_server_checkpoints_its_inputs() {
    let (keys, trust) = setup();
    let mut s = start_server(&keys, None).await;
    let creds = credentials(&keys, &s, new_session(), 0, MATCH);
    let mut c = GameClient::connect_with_grace(creds, &trust, JOIN, GRACE)
        .await
        .unwrap();
    let (mut x, mut heads) = (0.0f32, 0);
    for _ in 0..100 {
        for ev in c.step(&ClientCmd::Move { dx: 3.0, dy: 0.0 }).await.unwrap() {
            match ev {
                ClientEvent::Snapshot(snap) => x = snap.you.0,
                ClientEvent::CheckpointHead { .. } => heads += 1,
            }
        }
    }
    // Intents were clamped to MAX_STEP per tick, not the 3.0 asked for.
    assert!(x > 20.0 && x <= 100.0 * game::MAX_STEP, "x = {x}");
    assert!(heads >= 1, "checkpoint heads: {heads}");
    // The server's checkpoints verify under its instance key and chain.
    let mut last = None;
    while let Ok((epoch, cp)) = s.checkpoints.try_recv() {
        let mut keyset = fpp_crypto::KeySet::default();
        keyset.insert_ed25519(
            fpp_crypto::KeyRole::GsInstance,
            ed25519_dalek::VerifyingKey::from_bytes(&s.instance_pub).unwrap(),
        );
        let v = fpp_crypto::verify::<fpp_wire::Checkpoint>(&cp, &keyset).unwrap();
        assert_eq!(v.payload.epoch, epoch);
        if let Some((e, d)) = last {
            assert_eq!(v.payload.epoch, e + 1);
            assert_eq!(v.payload.prev, d);
        }
        last = Some((epoch, v.digest));
    }
    assert!(last.is_some(), "no checkpoints produced");
    c.bye().await.unwrap();
}

/// Revocation = the liveness service stops issuing SARs. Within the grace
/// period the server kicks everyone and the client stops on its own.
#[tokio::test]
async fn client_stops_when_the_servers_sars_stop() {
    let (keys, trust) = setup();
    let s = start_server(&keys, None).await;
    let creds = credentials(&keys, &s, new_session(), 0, MATCH);
    let mut c = GameClient::connect_with_grace(creds, &trust, JOIN, GRACE)
        .await
        .unwrap();
    for _ in 0..10 {
        c.step(&ClientCmd::Move { dx: 1.0, dy: 0.0 }).await.unwrap();
    }
    s.feeding.store(false, Ordering::Relaxed);
    let started = std::time::Instant::now();
    let end = loop {
        match c.step(&ClientCmd::Move { dx: 1.0, dy: 0.0 }).await {
            Ok(_) => assert!(started.elapsed() < Duration::from_secs(5), "still playing"),
            Err(e) => break end_of(e),
        }
    };
    assert!(
        matches!(end, SessionEnd::SarLapsed | SessionEnd::Kicked(7)),
        "{end:?}"
    );
    assert!(started.elapsed() < Duration::from_secs(3));
}

/// Impersonation: an endpoint without the server's static key cannot
/// complete the handshake the client starts to that key.
#[tokio::test]
async fn impersonator_without_the_servers_key_cannot_answer() {
    let (keys, trust) = setup();
    let real = start_server(&keys, None).await;
    let impostor = start_server(&keys, None).await;
    let mut creds = credentials(&keys, &real, new_session(), 0, MATCH);
    creds.gs_addr = impostor.addr; // traffic redirected to the impostor
    let r = GameClient::connect_with_grace(creds, &trust, Duration::from_secs(2), GRACE).await;
    assert!(format!("{:#}", r.err().unwrap()).contains("timed out"));
}

/// A server that holds a valid SAR chain, but for another transport key
/// (e.g. it replays a real server's SARs), is refused.
#[tokio::test]
async fn sar_must_certify_the_key_the_client_dialled() {
    let (keys, trust) = setup();
    let s = start_server(&keys, Some([0x55; 32])).await;
    let creds = credentials(&keys, &s, new_session(), 0, MATCH);
    let r = GameClient::connect_with_grace(creds, &trust, JOIN, GRACE).await;
    assert_eq!(end_of(r.err().unwrap()), SessionEnd::SarLapsed);
}

/// A SAT presented by anyone but its session key's holder is refused
/// (no bearer tokens, F10), and so is a SAT for another match.
#[tokio::test]
async fn stolen_or_foreign_admission_tokens_are_refused() {
    let (keys, trust) = setup();
    let s = start_server(&keys, None).await;

    let victim = credentials(&keys, &s, new_session(), 0, MATCH);
    let thief_session = new_session();
    let stolen = Credentials {
        session: thief_session,
        ..victim
    };
    let r = GameClient::connect_with_grace(stolen, &trust, JOIN, GRACE).await;
    assert_eq!(
        end_of(r.err().unwrap()),
        SessionEnd::Rejected(Reason::PopInvalid as u16)
    );

    let foreign = credentials(&keys, &s, new_session(), 1, MatchId([0xEE; 16]));
    let r = GameClient::connect_with_grace(foreign, &trust, JOIN, GRACE).await;
    assert_eq!(
        end_of(r.err().unwrap()),
        SessionEnd::Rejected(Reason::SatInvalid as u16)
    );
}
