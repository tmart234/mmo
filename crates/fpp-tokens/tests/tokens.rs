use ed25519_dalek::SigningKey;
use fpp_crypto::{sign, Ed25519Signer, KeyRole, KeySet};
use fpp_tokens::admission::{admit, AdmissionPolicy, Revocations};
use fpp_tokens::control::{quic_pop, Control};
use fpp_tokens::*;
use fpp_types::{BuildId, DeviceTier, Did, Digest, MatchId, Reason, ServerClass};
use fpp_wire::{AdmitPop, Payload};

const NOW: u64 = 1_790_000_000;
const MATCH: MatchId = MatchId(*b"match-0000000001");

fn key(seed: u8) -> Ed25519Signer {
    Ed25519Signer::new(SigningKey::from_bytes(&[seed; 32]))
}

struct Fx {
    verifier: Ed25519Signer,
    broker: Ed25519Signer,
    liveness: Ed25519Signer,
    session: Ed25519Signer,
    instance: Ed25519Signer,
    keys: KeySet,
}

fn fx() -> Fx {
    let (verifier, broker, liveness) = (key(0x11), key(0x12), key(0x13));
    let mut keys = KeySet::default();
    keys.insert_ed25519(KeyRole::VerifierAr, verifier.verifying_key());
    keys.insert_ed25519(KeyRole::BrokerSat, broker.verifying_key());
    keys.insert_ed25519(KeyRole::ServerLiveness, liveness.verifying_key());
    Fx {
        verifier,
        broker,
        liveness,
        session: key(0x51),
        instance: key(0x61),
        keys,
    }
}

fn raw(k: &Ed25519Signer) -> [u8; 32] {
    k.verifying_key().to_bytes()
}

fn pk(k: &Ed25519Signer) -> fpp_types::SessionKey {
    fpp_types::SessionKey::Ed25519(k.verifying_key().to_bytes())
}

fn ar(f: &Fx, tier: DeviceTier) -> AttestationResult {
    AttestationResult {
        iss: "ver.dev".into(),
        iat: NOW,
        exp: NOW + 1800,
        cti: [1; 16],
        cnf: pk(&f.session),
        nonce: [2; 32],
        did: Did([3; 32]),
        tier,
        features: Features {
            secure_boot: Some(true),
            key_in_hw: Some(false),
            os_patch_age_days: Some(12),
            ..Features::default()
        },
        client_build: BuildId([4; 32]),
        platform: "windows".into(),
        policy_ver: 42,
        warnings: vec!["os-patch-stale".into()],
    }
}

fn sat(f: &Fx, a: &AttestationResult) -> SessionAdmissionToken {
    SessionAdmissionToken {
        iss: "broker.dev".into(),
        sub: [5; 32],
        aud: instance_id(&raw(&f.instance)),
        iat: NOW,
        exp: NOW + 3600,
        cti: [6; 16],
        cnf: a.cnf,
        did: a.did,
        tier: a.tier,
        match_id: MATCH,
        slot: 3,
        queue: "verified-slayer".into(),
        policy_ver: 42,
        ar_cti: a.cti,
    }
}

fn sar(f: &Fx, seq: u64, prev: Digest, iat: u64) -> ServerAttestationResult {
    ServerAttestationResult {
        iss: "live.dev".into(),
        sub: instance_id(&raw(&f.instance)),
        iat,
        exp: iat + 10,
        cnf: raw(&f.instance),
        tls_spki_sha256: None,
        noise_static: Some([9; 32]),
        server_class: ServerClass::FirstParty,
        build_id: BuildId([7; 32]),
        region: "dev".into(),
        seq,
        prev,
        vrf_pub: None,
    }
}

#[test]
fn tokens_round_trip_through_signing() {
    let f = fx();
    let a = ar(&f, DeviceTier::D2Hardware);
    let signed = sign(&f.verifier, &a);
    assert_eq!(verify_ar(&signed, &f.keys, NOW).unwrap(), a);
    let s = sat(&f, &a);
    assert_eq!(verify_sat(&sign(&f.broker, &s), &f.keys, NOW).unwrap(), s);
    let r = sar(&f, 0, Digest::default(), NOW);
    let chain = SarChain::start(&sign(&f.liveness, &r), &f.keys, NOW).unwrap();
    assert_eq!(chain.current(), &r);
}

#[test]
fn each_token_needs_its_own_role() {
    let f = fx();
    let a = ar(&f, DeviceTier::D2Hardware);
    // An AR signed by the Broker key, a SAT by the Verifier key: refused.
    assert!(matches!(
        verify_ar(&sign(&f.broker, &a), &f.keys, NOW),
        Err(TokenError::Verify(_))
    ));
    assert!(matches!(
        verify_sat(&sign(&f.verifier, &sat(&f, &a)), &f.keys, NOW),
        Err(TokenError::Verify(_))
    ));
}

#[test]
fn lifetimes_and_clock_are_enforced() {
    let f = fx();
    let mut a = ar(&f, DeviceTier::D1Software);
    assert_eq!(
        verify_ar(&sign(&f.verifier, &a), &f.keys, NOW + 1800 + 61),
        Err(TokenError::Expired)
    );
    assert!(
        verify_ar(&sign(&f.verifier, &a), &f.keys, NOW + 1800 + 59).is_ok(),
        "skew"
    );
    assert_eq!(
        verify_ar(&sign(&f.verifier, &a), &f.keys, NOW - 61),
        Err(TokenError::NotYetValid)
    );
    a.exp = a.iat + AR_MAX_LIFETIME_S + 1;
    assert!(matches!(
        verify_ar(&sign(&f.verifier, &a), &f.keys, NOW),
        Err(TokenError::Verify(_))
    ));
    let mut r = sar(&f, 0, Digest::default(), NOW);
    r.exp = r.iat + SAR_MAX_LIFETIME_S + 1;
    assert!(SarChain::start(&sign(&f.liveness, &r), &f.keys, NOW).is_err());
}

#[test]
fn sar_must_name_its_instance_key_and_a_transport() {
    let f = fx();
    let mut r = sar(&f, 0, Digest::default(), NOW);
    r.sub = instance_id(&raw(&f.session));
    assert!(SarChain::start(&sign(&f.liveness, &r), &f.keys, NOW).is_err());
    let mut r = sar(&f, 0, Digest::default(), NOW);
    r.noise_static = None;
    assert!(SarChain::start(&sign(&f.liveness, &r), &f.keys, NOW).is_err());
}

/// The P0 ticket-chain attacks, now against the SAR chain.
#[test]
fn sar_chain_rejects_forged_replayed_skipped_forked_and_expired_updates() {
    let f = fx();
    let s0 = sign(&f.liveness, &sar(&f, 0, Digest::default(), NOW));
    let mut chain = SarChain::start(&s0, &f.keys, NOW).unwrap();
    let s1 = sign(&f.liveness, &sar(&f, 1, sar_link(&s0).unwrap(), NOW + 2));
    let s2 = sign(&f.liveness, &sar(&f, 2, sar_link(&s1).unwrap(), NOW + 4));

    // Forged (someone else's key), skipped (s2 before s1), replayed (s0).
    let forged = sign(&key(0x99), &sar(&f, 1, sar_link(&s0).unwrap(), NOW + 2));
    assert!(chain.update(&forged, &f.keys, NOW + 2).is_err());
    assert_eq!(chain.update(&s2, &f.keys, NOW + 4), Err(TokenError::Chain));
    assert_eq!(chain.update(&s0, &f.keys, NOW + 2), Err(TokenError::Chain));
    chain.update(&s1, &f.keys, NOW + 2).unwrap();
    // Fork: a different seq-2 SAR whose prev is not s1.
    let fork = sign(&f.liveness, &sar(&f, 2, sar_link(&s0).unwrap(), NOW + 4));
    assert_eq!(
        chain.update(&fork, &f.keys, NOW + 4),
        Err(TokenError::Chain)
    );
    chain.update(&s2, &f.keys, NOW + 4).unwrap();
    // Revocation = SARs stop: the chain lapses at exp (+ skew).
    assert!(chain.live(NOW + 4 + 10 + 59));
    assert!(!chain.live(NOW + 4 + 10 + 60));
    // A SAR for another instance cannot splice in.
    let mut other = sar(&f, 3, sar_link(&s2).unwrap(), NOW + 6);
    other.cnf = raw(&key(0x62));
    other.sub = instance_id(&other.cnf);
    assert_eq!(
        chain.update(&sign(&f.liveness, &other), &f.keys, NOW + 6),
        Err(TokenError::Audience)
    );
}

fn policy(f: &Fx, min_tier: DeviceTier) -> AdmissionPolicy {
    AdmissionPolicy {
        gs_instance_id: instance_id(&raw(&f.instance)),
        matches: vec![MATCH],
        min_tier,
    }
}

#[test]
fn admission_accepts_a_consistent_pair() {
    let f = fx();
    let a = ar(&f, DeviceTier::D2Hardware);
    let s = sat(&f, &a);
    let ok = admit(
        &sign(&f.broker, &s),
        &sign(&f.verifier, &a),
        &pk(&f.session),
        &f.keys,
        &policy(&f, DeviceTier::D2Hardware),
        &Revocations::default(),
        NOW,
    )
    .unwrap();
    assert_eq!(ok.sat.slot, 3);
}

#[test]
fn admission_rejects_each_broken_rule_with_its_reason() {
    let f = fx();
    let a = ar(&f, DeviceTier::D2Hardware);
    let s = sat(&f, &a);
    let run = |s: &SessionAdmissionToken,
               a: &AttestationResult,
               key: fpp_types::SessionKey,
               min: DeviceTier,
               rev: &Revocations| {
        admit(
            &sign(&f.broker, s),
            &sign(&f.verifier, a),
            &key,
            &f.keys,
            &policy(&f, min),
            rev,
            NOW,
        )
        .err()
        .map(|(t, e)| e.reason(t))
    };
    let none = Revocations::default();
    let me = pk(&f.session);

    let mut other_server = s.clone();
    other_server.aud = instance_id(&raw(&key(0x62)));
    assert_eq!(
        run(&other_server, &a, me, DeviceTier::D0Unknown, &none),
        Some(Reason::SatInvalid)
    );
    let mut other_match = s.clone();
    other_match.match_id = MatchId([0; 16]);
    assert_eq!(
        run(&other_match, &a, me, DeviceTier::D0Unknown, &none),
        Some(Reason::SatInvalid)
    );
    // Stolen SAT presented by another key: the proven session key differs.
    assert_eq!(
        run(&s, &a, pk(&key(0x66)), DeviceTier::D0Unknown, &none),
        Some(Reason::PopInvalid)
    );
    // AR for another device key, or not the AR the Broker used.
    let mut foreign_ar = a.clone();
    foreign_ar.cnf = pk(&key(0x66));
    assert_eq!(
        run(&s, &foreign_ar, me, DeviceTier::D0Unknown, &none),
        Some(Reason::PopInvalid)
    );
    let mut other_ar = a.clone();
    other_ar.cti = [9; 16];
    assert_eq!(
        run(&s, &other_ar, me, DeviceTier::D0Unknown, &none),
        Some(Reason::ArInvalid)
    );
    // Tier below the queue minimum, or a SAT claiming more than the AR.
    assert_eq!(
        run(&s, &a, me, DeviceTier::D3Hardened, &none),
        Some(Reason::TierInsufficient)
    );
    let mut inflated = s.clone();
    inflated.tier = DeviceTier::D3Hardened;
    assert_eq!(
        run(&inflated, &a, me, DeviceTier::D0Unknown, &none),
        Some(Reason::TierInsufficient)
    );
    // Revoked device.
    let mut rev = Revocations::default();
    rev.devices.insert(a.did);
    assert_eq!(
        run(&s, &a, me, DeviceTier::D0Unknown, &rev),
        Some(Reason::Revoked)
    );
}

#[test]
fn control_messages_round_trip() {
    let msgs = [
        Control::Hello {
            versions: vec![1],
            client_build_id: [1; 32],
        },
        Control::HelloAck {
            version: 1,
            sar: vec![1, 2],
            server_nonce: [3; 32],
            tick_hz: 30,
            ticks_per_epoch: 30,
        },
        Control::Admit {
            sat: vec![1],
            ar: vec![2],
            pop: vec![3],
        },
        Control::Admitted {
            slot: 2,
            start_tick: 900,
        },
        Control::Reject { code: 5 },
        Control::SarUpdate { sar: vec![9; 200] },
        Control::kick(Reason::SarLapsed),
        Control::Bye,
        Control::CheckpointHead {
            checkpoint: vec![8; 400],
        },
        Control::InputCommit {
            commit: vec![7; 300],
        },
    ];
    for m in msgs {
        assert_eq!(Control::decode(&m.encode()).unwrap(), m);
    }
    assert!(
        Control::decode(&[0x82, 0x18, 0x63, 0xa0]).is_err(),
        "unknown type 99"
    );
    assert!(Control::decode(&vec![0; control::MAX_CONTROL + 1]).is_err());
}

#[test]
fn quic_pop_binds_connection_handshake_and_sat() {
    let f = fx();
    let base = quic_pop(&[1; 32], b"hello", b"ack", &[2; 32], &[3; 16]);
    assert_eq!(base.channel, AdmitPop::QUIC_TLS);
    assert_eq!(base.binding.len(), 64);
    // Any change to connection, handshake, nonce or SAT changes the binding.
    for other in [
        quic_pop(&[9; 32], b"hello", b"ack", &[2; 32], &[3; 16]),
        quic_pop(&[1; 32], b"hellO", b"ack", &[2; 32], &[3; 16]),
        quic_pop(&[1; 32], b"hel", b"loack", &[2; 32], &[3; 16]),
        quic_pop(&[1; 32], b"hello", b"ack", &[9; 32], &[3; 16]),
        quic_pop(&[1; 32], b"hello", b"ack", &[2; 32], &[9; 16]),
    ] {
        assert_ne!(other.binding, base.binding);
    }
    // It is an ordinary AdmitPop, signed by the session key.
    let mut keys = KeySet::default();
    keys.insert_ed25519(KeyRole::Session, f.session.verifying_key());
    let v = fpp_crypto::verify::<AdmitPop>(&sign(&f.session, &base), &keys).unwrap();
    assert_eq!(v.payload, base);
    assert!(AdmitPop::from_cbor(&base.to_cbor()).is_ok());
}
