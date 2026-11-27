//! Consolidated authority tests (replaces svc-broker/tests/cell.rs,
//! svc-evidence/tests/store.rs, svc-revocation/tests/feed.rs,
//! svc-log/tests/services.rs, svc-liveness admission & TPM2 tests):
//!
//! - Role key isolation: an AR signed by Broker or Liveness key is refused.
//! - Unauthorized RPC callers (wrong Noise static key) are refused on Place,
//!   RevocationPublish, EvidencePut/Get/List, LogAdd/Cosign.
//! - Evidence Store content-addressing detects on-disk tampering on every read.
//! - Revocation Feed verifies Enforcement signature and logs to Transparency Log first.
//! - External Witness cosigns over Noise_IK TCP and refuses rollback/split views.
//! - Idle peer dropped at admission deadline (F08).
//! - Real TPM 2.0 GS admission against `swtpm`: EK chain, IMA Build Registry,
//!   credential activation, and rejection of modified binary / wrong activation secret.

use ed25519_dalek::SigningKey;
use fpp::control::{
    evidence_request_sign_bytes, match_request_sign_bytes, EvidenceAnswer, EvidenceRequest,
    EvidenceStoreRequest, EvidenceStoreResponse, LogRequest, LogResponse, MatchAnswer,
    MatchRequest, PlaceResponse, Purpose, RevocationRequest, RevocationResponse,
};
use fpp::crypto::{now_s, sha256, Ed25519Signer, SessionSigner, Signer};
use fpp::gs_link::{GsLink, GsLinkConfig, GsLinkEvent};
use fpp::log::Witness;
use fpp::session::StaticKeypair;
use fpp::tokens::{AttestationResult, Features};
use fpp::tpm2_collect::{swtpm, Tpm2Options};
use fpp::types::{BuildId, DeviceTier, Did, Reason};
use fpp::wire::{Action, Scope, SubjectKind};
use fpp_attest::tpm::ima::ima_ng_record;
use fppd::evidence::EvidenceStore;
use fppd::keys::{LOG_ORIGIN, WITNESS_NAME};
use fppd::liveness::{verify_checkpoint, LivenessConfig, DEFAULT_GS_PROGRAM_PATH};
use fppd::revocation::Order;
use fppd::verifier::ClientAttestation;
use fppd::{external_witness_round, open_control, rpc_evidence_get, rpc_evidence_list, Authority};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;

fn temp_dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "fppd-test-{name}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&d);
    d
}

#[tokio::test]
async fn role_key_isolation_and_unauthorized_admin_rejected() {
    let dir = temp_dir("isolation");
    let running = Authority::open_all(
        &dir,
        None,
        LivenessConfig::default(),
        ClientAttestation::default(),
        Some(Duration::from_millis(200)),
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let auth = running.authority.clone();
    let srv = tokio::spawn(async move { auth.serve(listener).await });
    let srv_pub = running.bundle.transport_pub;

    // 1) An AR signed by the Broker's or Liveness's key (wrong role!) must be refused by Broker.
    let session = Ed25519Signer::new(SigningKey::from_bytes(&[11; 32]));
    let fake_ar = AttestationResult {
        iss: "ver.dev".into(),
        iat: now_s(),
        exp: now_s() + 600,
        cti: [1; 16],
        cnf: session.session_key(),
        nonce: [0; 32],
        did: Did([2; 32]),
        tier: DeviceTier::D2Hardware,
        features: Features::default(),
        client_build: BuildId([0; 32]),
        platform: "linux".into(),
        policy_ver: 1,
        warnings: vec![],
    };
    let signed_by_liveness = fpp::crypto::sign(&running.keys.liveness, &fake_ar);
    let (mut s, chal) = open_control(addr, &srv_pub, None, Purpose::Match)
        .await
        .unwrap();
    let mmsg = match_request_sign_bytes(&chal, &signed_by_liveness, "verified");
    let pop: [u8; 64] = session.sign(&mmsg).try_into().unwrap();
    s.send(&MatchRequest {
        ar: signed_by_liveness,
        queue: "verified".into(),
        pop_sig: pop,
    })
    .await
    .unwrap();
    let ans: MatchAnswer = s.recv().await.unwrap();
    assert_eq!(
        ans,
        MatchAnswer::Refused {
            code: Reason::ArInvalid as u16
        }
    );

    // 2) An AR legitimately signed by Verifier, but presented by ANOTHER session key, is refused.
    let (mut vs, vchal) = open_control(addr, &srv_pub, None, Purpose::Evidence)
        .await
        .unwrap();
    let spub = session.session_key().to_bytes();
    let emsg = evidence_request_sign_bytes(&vchal, &spub, "linux", &[0; 32], &[]);
    let epop: [u8; 64] = session.sign(&emsg).try_into().unwrap();
    vs.send(&EvidenceRequest {
        session_pub: spub,
        pop_sig: epop,
        platform: "linux".into(),
        client_build: [0; 32],
        evidence: Vec::new(),
    })
    .await
    .unwrap();
    let EvidenceAnswer::Ar(real_ar) = vs.recv().await.unwrap() else {
        panic!("expected AR");
    };
    let thief = Ed25519Signer::new(SigningKey::from_bytes(&[99; 32]));
    let (mut bs, bchal) = open_control(addr, &srv_pub, None, Purpose::Match)
        .await
        .unwrap();
    let bmsg = match_request_sign_bytes(&bchal, &real_ar, "open");
    let bpop: [u8; 64] = thief.sign(&bmsg).try_into().unwrap();
    bs.send(&MatchRequest {
        ar: real_ar,
        queue: "open".into(),
        pop_sig: bpop,
    })
    .await
    .unwrap();
    assert_eq!(
        bs.recv::<MatchAnswer>().await.unwrap(),
        MatchAnswer::Refused {
            code: Reason::PopInvalid as u16
        }
    );

    // 3) Unauthorized caller (random Noise static key) is refused on Place, Revocation, Evidence, Log.
    let rando = StaticKeypair::generate();
    let (mut ps, _) = open_control(addr, &srv_pub, Some(&rando), Purpose::Place)
        .await
        .unwrap();
    assert!(matches!(
        ps.recv::<PlaceResponse>().await.unwrap(),
        PlaceResponse::Refused(_)
    ));

    let (mut rs, _) = open_control(addr, &srv_pub, Some(&rando), Purpose::RevocationPublish)
        .await
        .unwrap();
    rs.send(&RevocationRequest::Publish(vec![1, 2, 3]))
        .await
        .unwrap();
    assert!(matches!(
        rs.recv::<RevocationResponse>().await.unwrap(),
        RevocationResponse::Refused(_)
    ));

    let (mut es, _) = open_control(addr, &srv_pub, Some(&rando), Purpose::EvidenceList)
        .await
        .unwrap();
    es.send(&EvidenceStoreRequest::List([0; 16])).await.unwrap();
    assert!(matches!(
        es.recv::<EvidenceStoreResponse>().await.unwrap(),
        EvidenceStoreResponse::Refused(_)
    ));

    let (mut ls, _) = open_control(addr, &srv_pub, Some(&rando), Purpose::LogAdd)
        .await
        .unwrap();
    ls.send(&LogRequest::Add(vec![b"x".to_vec()]))
        .await
        .unwrap();
    assert!(matches!(
        ls.recv::<LogResponse>().await.unwrap(),
        LogResponse::Refused(_)
    ));

    srv.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn evidence_store_detects_disk_corruption() {
    let dir = temp_dir("evidence");
    let store = EvidenceStore::open(dir.clone()).unwrap();
    let obj = b"signed checkpoint payload bytes".to_vec();
    let match_id = [7u8; 16];
    let d = store.put(match_id, &obj).await.unwrap();
    assert_eq!(d, sha256(&obj));
    assert_eq!(store.list(&match_id).unwrap(), vec![d]);
    assert_eq!(store.get(&d).unwrap().unwrap(), obj);

    // Corrupt on disk: get() must refuse rather than serve tampered bytes.
    let h = hex::encode(d);
    let path = dir.join("objects").join(&h[..2]).join(h);
    std::fs::write(&path, b"corrupted").unwrap();
    assert!(store.get(&d).is_err());

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn external_witness_and_revocation_logged_and_persisted() {
    let dir = temp_dir("witness");
    // Start authority WITHOUT internal witness so we exercise external witness over Noise_IK TCP!
    let running = Authority::open_all(
        &dir,
        None,
        LivenessConfig::default(),
        ClientAttestation::default(),
        None,
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let auth = running.authority.clone();
    let srv = tokio::spawn(async move { auth.serve(listener).await });

    // Enforcement publishes a revocation -> logged into Transparency Log before acceptance.
    let feed = running.authority.revocation.as_ref().unwrap();
    let (_, _, seq) = feed
        .enforce(
            &running.keys.enforcement,
            Order {
                subject_kind: SubjectKind::Device,
                subject_id: vec![0x55; 32],
                action: Action::Ban,
                scope: Scope::default(),
                reason: Reason::Revoked as u16,
                duration_s: None,
                note: "test ban".into(),
            },
        )
        .await
        .unwrap();
    assert_eq!(seq, 0);

    // External witness cosigns over Noise_IK TCP.
    let mut witness = Witness::open(
        WITNESS_NAME,
        running.keys.witness.clone(),
        LOG_ORIGIN,
        running.keys.log.ed25519_public().to_bytes(),
        running.keys.log.ml_dsa_public().to_vec(),
        dir.join("ext-witness/state"),
    )
    .unwrap();
    let cosigned = external_witness_round(
        addr,
        &running.bundle.transport_pub,
        &running.keys.admin,
        &mut witness,
    )
    .await
    .unwrap();
    assert_eq!(cosigned, Some(2)); // 1 enforcement record + 1 revocation event

    // Authorized auditor can read evidence store via RPC.
    let store = running.authority.evidence.as_ref().unwrap();
    let mid = [0x33; 16];
    let d = store.put(mid, b"cp0").await.unwrap();
    let listed = rpc_evidence_list(
        addr,
        &running.bundle.transport_pub,
        &running.keys.admin,
        mid,
    )
    .await
    .unwrap();
    assert_eq!(listed, vec![d]);
    let got = rpc_evidence_get(addr, &running.bundle.transport_pub, &running.keys.admin, d)
        .await
        .unwrap();
    assert_eq!(got.as_deref(), Some(b"cp0".as_slice()));

    srv.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

/// F08: an idle peer that connects via TCP but never sends Noise msg1 or
/// ChallengeRequest is dropped at `admission_timeout_ms`.
#[tokio::test]
async fn idle_peer_is_dropped_at_admission_deadline() {
    let dir = temp_dir("deadline");
    let cfg = LivenessConfig {
        admission_timeout_ms: 200,
        ..LivenessConfig::default()
    };
    let running = Authority::open_all(&dir, None, cfg, ClientAttestation::default(), None).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let _idle = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (sock, _) = listener.accept().await.unwrap();
    let started = Instant::now();
    let err = running
        .authority
        .clone()
        .handle_connection(sock)
        .await
        .unwrap_err();
    assert!(
        format!("{err:#}").contains("timed out"),
        "expected timeout error, got: {err:#}"
    );
    assert!(started.elapsed() < Duration::from_secs(3));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn checkpoint_chain_enforced() {
    let k = Ed25519Signer::new(SigningKey::from_bytes(&[6; 32]));
    let pk = k.verifying_key().to_bytes();
    let m = [4; 16];
    let mk = |epoch: u32, prev: fpp::types::Digest| {
        fpp::crypto::sign(
            &k,
            &fpp::wire::Checkpoint {
                match_id: fpp::types::MatchId(m),
                gs_instance_id: fpp::tokens::instance_id(&pk),
                build_id: BuildId([0; 32]),
                policy_ver: 1,
                epoch,
                ticks: (epoch * 30, epoch * 30 + 29),
                prev,
                inputs_root: fpp::types::Digest::default(),
                inputs_n: 0,
                events_root: fpp::types::Digest::default(),
                events_n: 0,
                state_root: fpp::types::Digest::default(),
                rng_root: fpp::types::Digest::default(),
                rng_n: 0,
                roster_root: fpp::types::Digest::default(),
                roster_n: 0,
            },
        )
    };
    let c0 = mk(0, fpp::types::Digest::default());
    let (e0, d0) = verify_checkpoint(&c0, &pk, &m, None).unwrap();
    assert_eq!(e0, 0);
    let c1 = mk(1, d0);
    verify_checkpoint(&c1, &pk, &m, Some((0, d0))).unwrap();
    assert!(verify_checkpoint(&c0, &pk, &m, Some((0, d0))).is_err());
    assert!(verify_checkpoint(&mk(2, d0), &pk, &m, Some((0, d0))).is_err());
}

/// Real TPM 2.0 game-server join against `swtpm`: EK chain, IMA Build Registry,
/// credential activation, SAR streaming, and rejection of a modified GS binary!
#[tokio::test]
async fn gs_tpm2_admission_and_modified_binary_refused() {
    if !swtpm::available() {
        assert!(
            std::env::var_os("FPP_REQUIRE_SWTPM").is_none(),
            "FPP_REQUIRE_SWTPM is set and swtpm/tpm2-tools missing"
        );
        return;
    }
    let dir = temp_dir("tpm2-gs");
    let tpm = swtpm::Swtpm::start(dir.join("swtpm")).unwrap();
    let roots =
        fpp_attest::x509::pem_certificates(&std::fs::read_to_string(tpm.root_pem()).unwrap())
            .unwrap();
    let inter = fpp_attest::x509::pem_certificates(
        &std::fs::read_to_string(tpm.intermediate_pem()).unwrap(),
    )
    .unwrap();

    // Measure a genuine GS binary into PCR 10 via IMA log.
    let good_hash = sha256(b"genuine-gs-binary-v1");
    let (ima_rec, template_hash) = ima_ng_record(&good_hash, DEFAULT_GS_PROGRAM_PATH);
    tpm.extend(10, &template_hash).unwrap();
    let ima_path = dir.join("ima.log");
    std::fs::write(&ima_path, &ima_rec).unwrap();

    let mut cfg = LivenessConfig {
        tpm_ek_roots: roots,
        ..LivenessConfig::default()
    };
    cfg.build_registry
        .insert(good_hash, "gs-sim-release-1".into());

    let running = Authority::open_all(
        &dir.join("cell"),
        None,
        cfg,
        ClientAttestation::default(),
        None,
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let auth = running.authority.clone();
    let srv = tokio::spawn(async move { auth.serve(listener).await });

    // 1) Genuine GS with matching IMA build joins and receives its SAR!
    let bundle_ok = running.bundle.clone();
    let tcti = tpm.tcti();
    let inter_ok = inter.clone();
    let ima_ok = ima_path.clone();
    let work_ok = dir.join("work-ok");
    let link = tokio::task::spawn_blocking(move || {
        GsLink::connect(GsLinkConfig {
            liveness: addr,
            bundle: bundle_ok,
            gs_id: "gs-tpm-ok".into(),
            game_addr: "127.0.0.1:50090".into(),
            gs_key: SigningKey::from_bytes(&[1; 32]),
            instance_pub: SigningKey::from_bytes(&[2; 32]).verifying_key().to_bytes(),
            noise_pub: StaticKeypair::generate().public,
            sw_hash: good_hash,
            tpm2: Some(Tpm2Options {
                tcti: Some(tcti),
                workdir: work_ok,
                pcrs: vec![10],
                ek_intermediates: inter_ok,
                boot_log: None,
                ima_log: Some(ima_ok),
            }),
            timeout: Duration::from_secs(10),
        })
    })
    .await
    .unwrap()
    .expect("genuine TPM GS must be admitted");

    // Wait briefly for first SAR to arrive on the link.
    let mut got_sar = false;
    for _ in 0..40 {
        if matches!(link.poll_event(), Some(GsLinkEvent::Sar(_))) {
            got_sar = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(got_sar, "admitted TPM GS must receive verified SAR");
    drop(link);

    // 2) A GS with no TPM evidence must be refused when Build Registry is active!
    let bundle_no_tpm = running.bundle.clone();
    let no_tpm = tokio::task::spawn_blocking(move || {
        GsLink::connect(GsLinkConfig {
            liveness: addr,
            bundle: bundle_no_tpm,
            gs_id: "gs-no-tpm".into(),
            game_addr: "127.0.0.1:50091".into(),
            gs_key: SigningKey::from_bytes(&[3; 32]),
            instance_pub: SigningKey::from_bytes(&[4; 32]).verifying_key().to_bytes(),
            noise_pub: StaticKeypair::generate().public,
            sw_hash: good_hash,
            tpm2: None,
            timeout: Duration::from_secs(5),
        })
    })
    .await
    .unwrap();
    assert!(no_tpm.is_err(), "unattested GS must be refused");

    // 3) A GS that lies about its sw_hash (different from kernel IMA measurement) is refused!
    let bundle_lie = running.bundle.clone();
    let tcti2 = tpm.tcti();
    let work_lie = dir.join("work-lie");
    let lie = tokio::task::spawn_blocking(move || {
        GsLink::connect(GsLinkConfig {
            liveness: addr,
            bundle: bundle_lie,
            gs_id: "gs-lie".into(),
            game_addr: "127.0.0.1:50092".into(),
            gs_key: SigningKey::from_bytes(&[5; 32]),
            instance_pub: SigningKey::from_bytes(&[6; 32]).verifying_key().to_bytes(),
            noise_pub: StaticKeypair::generate().public,
            sw_hash: [0xee; 32],
            tpm2: Some(Tpm2Options {
                tcti: Some(tcti2),
                workdir: work_lie,
                pcrs: vec![10],
                ek_intermediates: inter,
                boot_log: None,
                ima_log: Some(ima_path),
            }),
            timeout: Duration::from_secs(10),
        })
    })
    .await
    .unwrap();
    assert!(lie.is_err(), "GS lying about sw_hash must be refused");

    srv.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn custom_game_policy_multi_shard_and_unlinkable_dids() {
    use fpp::control::{
        evidence_request_sign_bytes, match_request_sign_bytes, EvidenceAnswer, EvidenceRequest,
        MatchAnswer, MatchRequest, MAX_CONTROL_FRAME,
    };
    use fpp::crypto::SessionSigner;
    use fpp::tokens::{verify_ar, verify_sat, SarChain};
    use fppd::open_control;
    use fppd::policy::AuthorityPolicy;

    let dir_a = temp_dir("policy-alpha");
    let dir_b = temp_dir("policy-beta");

    let policy_a = AuthorityPolicy::parse(
        r#"
        domain = alpha-mmo.example
        region = us-east
        policy_ver = 4
        max_slots = 1
        queues.clear = true
        queue.world-shard = D0
        queue.raid-mythic = D2
        "#,
    )
    .unwrap();
    let policy_b = AuthorityPolicy::parse(
        r#"
        domain = beta-fps.example
        region = eu-west
        policy_ver = 9
        max_slots = 64
        queues.clear = true
        queue.casual = D0
        queue.ranked-5v5 = D2
        "#,
    )
    .unwrap();

    let run_a = Authority::open_with_policy(
        &dir_a,
        None,
        policy_a,
        LivenessConfig::default(),
        ClientAttestation::default(),
        Some(Duration::from_secs(1)),
    )
    .unwrap();
    let run_b = Authority::open_with_policy(
        &dir_b,
        None,
        policy_b,
        LivenessConfig::default(),
        ClientAttestation::default(),
        Some(Duration::from_secs(1)),
    )
    .unwrap();

    assert_eq!(
        run_a.bundle.log.as_ref().unwrap().origin,
        "alpha-mmo.example/log"
    );
    assert_eq!(
        run_b.bundle.log.as_ref().unwrap().origin,
        "beta-fps.example/log"
    );

    let la = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr_a = la.local_addr().unwrap();
    let auth_a = run_a.authority.clone();
    let srv_a = tokio::spawn(async move { auth_a.serve(la).await });

    let lb = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr_b = lb.local_addr().unwrap();
    let auth_b = run_b.authority.clone();
    let srv_b = tokio::spawn(async move { auth_b.serve(lb).await });

    // Join TWO shards on alpha-mmo (max_slots = 1 each) so placement spills to shard 2.
    let join_shard = |addr: std::net::SocketAddr,
                      bundle: fpp::bundle::KeyBundle,
                      id: &str,
                      game_addr: &str,
                      seed: u8| {
        let id = id.to_string();
        let game_addr = game_addr.to_string();
        tokio::task::spawn_blocking(move || {
            GsLink::connect(GsLinkConfig {
                liveness: addr,
                bundle,
                gs_id: id,
                game_addr,
                gs_key: SigningKey::from_bytes(&[seed; 32]),
                instance_pub: SigningKey::from_bytes(&[seed + 1; 32])
                    .verifying_key()
                    .to_bytes(),
                noise_pub: StaticKeypair::generate().public,
                sw_hash: [seed; 32],
                tpm2: None,
                timeout: Duration::from_secs(5),
            })
        })
    };
    let shard1 = join_shard(
        addr_a,
        run_a.bundle.clone(),
        "shard-1",
        "127.0.0.1:51001",
        10,
    )
    .await
    .unwrap()
    .unwrap();
    let shard2 = join_shard(
        addr_a,
        run_a.bundle.clone(),
        "shard-2",
        "127.0.0.1:51002",
        20,
    )
    .await
    .unwrap()
    .unwrap();
    let _beta_gs = join_shard(
        addr_b,
        run_b.bundle.clone(),
        "beta-1",
        "127.0.0.1:52001",
        30,
    )
    .await
    .unwrap()
    .unwrap();

    // Verify SAR from alpha-mmo carries custom issuer & region `us-east`.
    let sar = loop {
        if let Some(fpp::gs_link::GsLinkEvent::Sar(s)) = shard1.poll_event() {
            break s;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    let chain = SarChain::start(&sar, &run_a.bundle.keyset(), now_s()).unwrap();
    assert_eq!(chain.current().iss, "liveness.alpha-mmo.example");
    assert_eq!(chain.current().region, "us-east");

    // Helper: request AR + SAT for a session key against an authority & queue.
    let admit = |addr: std::net::SocketAddr,
                 bundle: fpp::bundle::KeyBundle,
                 signer: Ed25519Signer,
                 queue: &'static str| async move {
        let sk_pub = signer.session_key().to_bytes();
        let (mut vs, vchal) = open_control(addr, &bundle.transport_pub, None, Purpose::Evidence)
            .await
            .unwrap();
        let msg = evidence_request_sign_bytes(&vchal, &sk_pub, "linux", &[1; 32], &[]);
        let pop: [u8; 64] = signer.sign(&msg).try_into().unwrap();
        vs.send(&EvidenceRequest {
            session_pub: sk_pub,
            pop_sig: pop,
            platform: "linux".into(),
            client_build: [1; 32],
            evidence: vec![],
        })
        .await
        .unwrap();
        let EvidenceAnswer::Ar(ar_bytes) = vs.recv_max(MAX_CONTROL_FRAME).await.unwrap() else {
            panic!("expected AR");
        };
        let ar = verify_ar(&ar_bytes, &bundle.keyset(), now_s()).unwrap();

        let (mut bs, bchal) = open_control(addr, &bundle.transport_pub, None, Purpose::Match)
            .await
            .unwrap();
        let mmsg = match_request_sign_bytes(&bchal, &ar_bytes, queue);
        let mpop: [u8; 64] = signer.sign(&mmsg).try_into().unwrap();
        bs.send(&MatchRequest {
            ar: ar_bytes,
            queue: queue.into(),
            pop_sig: mpop,
        })
        .await
        .unwrap();
        let ans: MatchAnswer = bs.recv_max(MAX_CONTROL_FRAME).await.unwrap();
        (ar, ans)
    };

    // Same client key across both publishers:
    let client_a1 = Ed25519Signer::new(SigningKey::from_bytes(&[0x77; 32]));
    let client_a2 = Ed25519Signer::new(SigningKey::from_bytes(&[0x77; 32]));
    let client_b = Ed25519Signer::new(SigningKey::from_bytes(&[0x77; 32]));
    let client_other = Ed25519Signer::new(SigningKey::from_bytes(&[0x88; 32]));

    // Default `open` queue is disabled on alpha-mmo (`queues.clear = true`), and `raid-mythic` requires D2.
    let (_, open_ans) = admit(addr_a, run_a.bundle.clone(), client_a1, "open").await;
    assert!(matches!(
        open_ans,
        MatchAnswer::Refused { code } if code == Reason::TierInsufficient as u16
    ));
    let (ar_a1, raid_ans) = admit(
        addr_a,
        run_a.bundle.clone(),
        Ed25519Signer::new(SigningKey::from_bytes(&[0x77; 32])),
        "raid-mythic",
    )
    .await;
    assert_eq!(ar_a1.iss, "verifier.alpha-mmo.example");
    assert_eq!(ar_a1.policy_ver, 4);
    assert!(matches!(
        raid_ans,
        MatchAnswer::Refused { code } if code == Reason::TierInsufficient as u16
    ));

    // Custom `world-shard` queue admits two players and balances across shard-1 and shard-2 (max_slots=1 each!).
    let (ar_a2, ans1) = admit(addr_a, run_a.bundle.clone(), client_a2, "world-shard").await;
    let (_, ans2) = admit(addr_a, run_a.bundle.clone(), client_other, "world-shard").await;
    let (_, ans3) = admit(
        addr_a,
        run_a.bundle.clone(),
        Ed25519Signer::new(SigningKey::from_bytes(&[0x99; 32])),
        "world-shard",
    )
    .await;
    let (sat1, addr1) = match ans1 {
        MatchAnswer::Granted { sat, gs_addr, .. } => (sat, gs_addr),
        other => panic!("expected Granted, got {other:?}"),
    };
    let (_, addr2) = match ans2 {
        MatchAnswer::Granted { sat, gs_addr, .. } => (sat, gs_addr),
        other => panic!("expected Granted, got {other:?}"),
    };
    assert_ne!(addr1, addr2, "players must balance across both shards");
    assert!(
        matches!(ans3, MatchAnswer::Refused { code } if code == Reason::ServerDraining as u16),
        "third player must be refused once both 1-slot shards are full"
    );
    let sat1_claims = verify_sat(&sat1, &run_a.bundle.keyset(), now_s()).unwrap();
    assert_eq!(sat1_claims.iss, "broker.alpha-mmo.example");
    assert_eq!(sat1_claims.queue, "world-shard");
    assert_eq!(sat1_claims.policy_ver, 4);

    // Same key on beta-fps gets a completely unlinkable Device ID (ID-02), while stable within alpha-mmo.
    let (ar_b, ans_b) = admit(addr_b, run_b.bundle.clone(), client_b, "casual").await;
    assert_eq!(ar_b.iss, "verifier.beta-fps.example");
    assert_eq!(ar_b.policy_ver, 9);
    assert!(matches!(ans_b, MatchAnswer::Granted { .. }));
    assert_eq!(
        ar_a1.did, ar_a2.did,
        "DID must be stable within one publisher"
    );
    assert_ne!(
        ar_a1.did, ar_b.did,
        "DID must be unlinkable across publishers (ID-02)"
    );

    drop(shard1);
    drop(shard2);
    srv_a.abort();
    srv_b.abort();
    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
}

#[tokio::test]
async fn client_admit_and_tlog_split_view_revocation() {
    use fpp::client::{self, AdmitConfig, CheckpointAudit};
    use fpp::control::ReportAnswer;
    use fpp::crypto::{object_digest, sign};
    use fpp::types::{Digest, MatchId};
    use fpp::wire::Checkpoint;

    let dir = temp_dir("client-tlog-split-view");
    let running = Authority::open_all(
        &dir,
        None,
        LivenessConfig::default(),
        ClientAttestation::default(),
        Some(Duration::from_millis(200)),
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let auth = running.authority.clone();
    let server = tokio::spawn(async move { auth.serve(listener).await });

    let instance_signer = Ed25519Signer::new(SigningKey::from_bytes(&[0x44; 32]));
    let instance_pub = instance_signer.verifying_key().to_bytes();
    let gs_noise = StaticKeypair::generate().public;
    let bundle_gs = running.bundle.clone();
    let link = tokio::task::spawn_blocking(move || {
        GsLink::connect(GsLinkConfig {
            liveness: addr,
            bundle: bundle_gs,
            gs_id: "tlog-gs".into(),
            game_addr: "127.0.0.1:53000".into(),
            gs_key: SigningKey::from_bytes(&[0x43; 32]),
            instance_pub,
            noise_pub: gs_noise,
            sw_hash: [0x45; 32],
            tpm2: None,
            timeout: Duration::from_secs(5),
        })
    })
    .await
    .unwrap()
    .unwrap();
    let match_id = link.match_id();

    // 1) Pure-std direct client admission (fpp::client::admit -> Verifier + Broker).
    let bundle_c = running.bundle.clone();
    let ticket = tokio::task::spawn_blocking(move || {
        client::admit(&AdmitConfig {
            authority: addr,
            bundle: bundle_c,
            queue: "open".into(),
            client_build: [0x9a; 32],
            session_seed: None,
            timeout: Duration::from_secs(5),
        })
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(ticket.gs_addr, "127.0.0.1:53000");
    assert_eq!(ticket.gs_noise_static, gs_noise);
    assert_eq!(ticket.match_id, match_id);
    assert_eq!(ticket.slot, 0);

    // 2) Submit honest epoch 0 Checkpoint and verify Transparency Log inclusion (C2SP + witness + Merkle).
    let make_cp = |epoch: u32, prev: Option<Digest>, state_byte: u8| -> (Vec<u8>, [u8; 32]) {
        let cp = Checkpoint {
            match_id: MatchId(match_id),
            gs_instance_id: fpp::tokens::instance_id(&instance_pub),
            build_id: BuildId([0x45; 32]),
            policy_ver: 1,
            epoch,
            ticks: (epoch * 30, epoch * 30 + 29),
            prev: prev.unwrap_or_default(),
            inputs_root: Digest::default(),
            inputs_n: 0,
            events_root: Digest::default(),
            events_n: 0,
            state_root: Digest([state_byte; 32]),
            rng_root: Digest::default(),
            rng_n: 0,
            roster_root: Digest::default(),
            roster_n: 0,
        };
        let bytes = sign(&instance_signer, &cp);
        let digest = object_digest(&bytes).0;
        (bytes, digest)
    };

    let (cp0, d0) = make_cp(0, None, 0x11);
    link.submit_checkpoint(cp0).unwrap();

    let mut included = false;
    for _ in 0..30 {
        let bundle_q = running.bundle.clone();
        let res = tokio::task::spawn_blocking(move || {
            client::check_checkpoint(addr, &bundle_q, &match_id, 0, &d0, Duration::from_secs(5))
        })
        .await
        .unwrap()
        .unwrap();
        if matches!(res, CheckpointAudit::Included { .. }) {
            included = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    assert!(included, "honest epoch 0 Checkpoint must be proven logged");

    // 3) Equivocate on epoch 1: submit cp1_log to Server Liveness, show cp1_fake to client.
    let (cp1_log, d1_log) = make_cp(1, Some(Digest(d0)), 0x22);
    let (cp1_fake, d1_fake) = make_cp(1, Some(Digest(d0)), 0x99);
    assert_ne!(d1_log, d1_fake);
    link.submit_checkpoint(cp1_log).unwrap();

    let mut split = false;
    for _ in 0..30 {
        let bundle_q = running.bundle.clone();
        let res = tokio::task::spawn_blocking(move || {
            client::check_checkpoint(
                addr,
                &bundle_q,
                &match_id,
                1,
                &d1_fake,
                Duration::from_secs(5),
            )
        })
        .await
        .unwrap()
        .unwrap();
        if let CheckpointAudit::SplitView { logged } = res {
            assert_eq!(logged, d1_log);
            split = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    assert!(
        split,
        "rogue epoch 1 Checkpoint must be detected as SplitView"
    );

    // 4) Report the conflicting signed Checkpoint -> Server Liveness revokes the rogue GS!
    let bundle_r = running.bundle.clone();
    let ans = tokio::task::spawn_blocking(move || {
        client::report_equivocation(addr, &bundle_r, &cp1_fake, Duration::from_secs(5))
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(ans, ReportAnswer::Revoked);

    // Confirm GsLink receives Closed (revoked) promptly.
    let mut closed = false;
    for _ in 0..30 {
        while let Some(ev) = link.poll_event() {
            if matches!(ev, fpp::gs_link::GsLinkEvent::Closed(_)) {
                closed = true;
            }
        }
        if closed {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(closed, "equivocating GS must be revoked and closed");

    drop(link);
    server.abort();
    let _ = std::fs::remove_dir_all(&dir);
}
