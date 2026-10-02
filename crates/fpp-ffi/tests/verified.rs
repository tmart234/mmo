//! Verified playlists through the C ABI (stage H5): a player's SAR chain,
//! a dedicated server's admission of SAT + AR (client builds, device bans,
//! revocations) and the control messages between them.

use ed25519_dalek::SigningKey;
use fpp::*;
use fpp_crypto::{sign, Ed25519Signer};
use fpp_tokens::{
    instance_id, sar_link, AttestationResult, Features, ServerAttestationResult,
    SessionAdmissionToken,
};
use fpp_types::{BuildId, DeviceTier, Did, Digest, MatchId, Reason, ServerClass};
use fpp_wire::{Action, RevocationEvent, Scope, SubjectKind};
use std::ptr;

const NOW: u64 = 1_790_000_000;
const MATCH: [u8; 16] = *b"match-0000000001";
const NOISE: [u8; 32] = [9; 32];

fn key(seed: u8) -> Ed25519Signer {
    Ed25519Signer::new(SigningKey::from_bytes(&[seed; 32]))
}

fn public(k: &Ed25519Signer) -> [u8; 32] {
    k.verifying_key().to_bytes()
}

struct Fx {
    verifier: Ed25519Signer,
    broker: Ed25519Signer,
    liveness: Ed25519Signer,
    enforcement: Ed25519Signer,
    instance: Ed25519Signer,
    keys: *mut FppKeys,
}

impl Drop for Fx {
    fn drop(&mut self) {
        unsafe { fpp_keys_free(self.keys) };
    }
}

fn fx() -> Fx {
    let mut f = Fx {
        verifier: key(0x11),
        broker: key(0x12),
        liveness: key(0x13),
        enforcement: key(0x14),
        instance: key(0x61),
        keys: ptr::null_mut(),
    };
    let mut keys = ptr::null_mut();
    unsafe {
        assert_eq!(fpp_keys_new(&mut keys), FppStatus::Ok);
        for (role, k) in [
            (FPP_KEY_VERIFIER, &f.verifier),
            (FPP_KEY_BROKER, &f.broker),
            (FPP_KEY_LIVENESS, &f.liveness),
            (FPP_KEY_ENFORCEMENT, &f.enforcement),
        ] {
            assert_eq!(fpp_keys_add(keys, role, public(k).as_ptr()), FppStatus::Ok);
        }
        assert_eq!(
            fpp_keys_add(keys, 99, public(&f.verifier).as_ptr()),
            FppStatus::InvalidArgument
        );
    }
    f.keys = keys;
    f
}

fn sar(f: &Fx, seq: u64, prev: Digest, iat: u64) -> ServerAttestationResult {
    ServerAttestationResult {
        iss: "live.dev".into(),
        sub: instance_id(&public(&f.instance)),
        iat,
        exp: iat + 10,
        cnf: public(&f.instance),
        tls_spki_sha256: None,
        noise_static: Some(NOISE),
        server_class: ServerClass::FirstParty,
        build_id: BuildId([7; 32]),
        region: "eu-home".into(),
        seq,
        prev,
        vrf_pub: None,
    }
}

fn ar(session: &Ed25519Signer, cti: u8, did: u8) -> AttestationResult {
    AttestationResult {
        iss: "ver.dev".into(),
        iat: NOW,
        exp: NOW + 1800,
        cti: [cti; 16],
        cnf: fpp_types::SessionKey::Ed25519(public(session)),
        nonce: [2; 32],
        did: Did([did; 32]),
        tier: DeviceTier::D2Hardware,
        features: Features::default(),
        client_build: BuildId([4; 32]),
        platform: "linux".into(),
        policy_ver: 1,
        warnings: vec![],
    }
}

fn sat(f: &Fx, a: &AttestationResult, cti: u8, slot: u16) -> SessionAdmissionToken {
    SessionAdmissionToken {
        iss: "broker.dev".into(),
        sub: [5; 32],
        aud: instance_id(&public(&f.instance)),
        iat: NOW,
        exp: NOW + 3600,
        cti: [cti; 16],
        cnf: a.cnf,
        did: a.did,
        tier: a.tier,
        match_id: MatchId(MATCH),
        slot,
        queue: "verified-slayer".into(),
        policy_ver: 1,
        ar_cti: a.cti,
    }
}

/// A player's signed SAT and AR (distinct ctis per player).
fn tokens(f: &Fx, session: &Ed25519Signer, n: u8, slot: u16) -> (Vec<u8>, Vec<u8>) {
    let a = ar(session, 0x20 + n, 0x30 + n);
    (
        sign(&f.broker, &sat(f, &a, 0x40 + n, slot)),
        sign(&f.verifier, &a),
    )
}

fn admission(f: &Fx) -> *mut FppAdmission {
    let mut a = ptr::null_mut();
    let status = unsafe {
        fpp_admission_new(
            f.keys,
            public(&f.instance).as_ptr(),
            MATCH.as_ptr(),
            2,
            &mut a,
        )
    };
    assert_eq!(status, FppStatus::Ok);
    a
}

fn admit(
    a: *mut FppAdmission,
    t: &(Vec<u8>, Vec<u8>),
    session: &Ed25519Signer,
    now: u64,
) -> (FppStatus, FppAdmitted) {
    let mut out = unsafe { std::mem::zeroed::<FppAdmitted>() };
    let key = public(session);
    let status = unsafe {
        fpp_admission_admit(
            a,
            t.0.as_ptr(),
            t.0.len(),
            t.1.as_ptr(),
            t.1.len(),
            key.as_ptr(),
            key.len(),
            now,
            &mut out,
        )
    };
    (status, out)
}

fn removed(a: *mut FppAdmission) -> Vec<(u16, u16)> {
    let mut all = Vec::new();
    let (mut slot, mut reason) = (0u16, 0u16);
    while unsafe { fpp_admission_poll_removed(a, &mut slot, &mut reason) } == FppStatus::Ok {
        all.push((slot, reason));
    }
    all
}

fn revocation(f: &Fx, kind: SubjectKind, id: Vec<u8>, action: Action, at: u64) -> Vec<u8> {
    sign(
        &f.enforcement,
        &RevocationEvent {
            id: [0xEE; 16],
            subject_kind: kind,
            subject_id: id,
            action,
            scope: Scope::default(),
            effective_at: at,
            expires_at: None,
            reason: Reason::PolicyKick as u16,
            record: Digest([1; 32]),
        },
    )
}

fn revoke(a: *mut FppAdmission, event: &[u8], now: u64) -> FppRevocationOutcome {
    let mut outcome = FppRevocationOutcome::Ignored;
    let status =
        unsafe { fpp_admission_revocation(a, event.as_ptr(), event.len(), now, &mut outcome) };
    assert_eq!(status, FppStatus::Ok);
    outcome
}

#[test]
fn a_player_follows_the_sar_chain_and_drops_when_it_breaks() {
    let f = fx();
    let s0 = sign(&f.liveness, &sar(&f, 0, Digest::default(), NOW));
    let mut chain = ptr::null_mut();
    unsafe {
        assert_eq!(
            fpp_sar_chain_start(f.keys, s0.as_ptr(), s0.len(), NOW, &mut chain),
            FppStatus::Ok
        );
        let mut info = std::mem::zeroed::<FppSarInfo>();
        assert_eq!(fpp_sar_chain_info(chain, &mut info), FppStatus::Ok);
        // What the player checks: the key it dialled, and its SAT's audience.
        assert_eq!(info.has_noise_static, 1);
        assert_eq!(info.noise_static, NOISE);
        assert_eq!(info.sub, instance_id(&public(&f.instance)).0);
        assert_eq!(info.cnf, public(&f.instance));
        assert_eq!(info.server_class, FPP_SERVER_FIRST_PARTY);
        assert_eq!(&info.region[..8], b"eu-home\0");

        let s1 = sign(&f.liveness, &sar(&f, 1, sar_link(&s0).unwrap(), NOW + 2));
        assert_eq!(
            fpp_sar_chain_update(chain, s1.as_ptr(), s1.len(), NOW + 2),
            FppStatus::Ok
        );
        assert_eq!(fpp_sar_chain_live(chain, NOW + 3), FppStatus::Ok);
        // A gap (seq 3 after 1), a fork (seq 2 not after s1) and a SAR
        // signed by another key: each refused, the chain unchanged.
        let gap = sign(&f.liveness, &sar(&f, 3, sar_link(&s1).unwrap(), NOW + 4));
        assert_eq!(
            fpp_sar_chain_update(chain, gap.as_ptr(), gap.len(), NOW + 4),
            FppStatus::TokenChain
        );
        let fork = sign(&f.liveness, &sar(&f, 2, sar_link(&s0).unwrap(), NOW + 4));
        assert_eq!(
            fpp_sar_chain_update(chain, fork.as_ptr(), fork.len(), NOW + 4),
            FppStatus::TokenChain
        );
        let forged = sign(&f.broker, &sar(&f, 2, sar_link(&s1).unwrap(), NOW + 4));
        assert_ne!(
            fpp_sar_chain_update(chain, forged.as_ptr(), forged.len(), NOW + 4),
            FppStatus::Ok
        );
        assert_eq!(fpp_sar_chain_info(chain, &mut info), FppStatus::Ok);
        assert_eq!(info.seq, 1);
        // No new SAR: the last one runs out (exp + the 60 s skew).
        assert_eq!(
            fpp_sar_chain_live(chain, NOW + 2 + 10 + 60),
            FppStatus::TokenExpired
        );
        fpp_sar_chain_free(chain);
    }
}

#[test]
fn a_server_admits_by_sat_and_ar_once_per_slot_and_sat() {
    let f = fx();
    let a = admission(&f);
    let (p1, p2) = (key(0x51), key(0x52));
    let t1 = tokens(&f, &p1, 1, 3);
    let (status, info) = admit(a, &t1, &p1, NOW);
    assert_eq!(status, FppStatus::Ok);
    assert_eq!((info.reason, info.slot, info.tier), (0, 3, 2));
    assert_eq!(info.did, [0x31; 32]);
    assert_eq!(info.client_build, [4; 32]);
    assert_eq!(&info.platform[..6], b"linux\0");
    assert_eq!(&info.queue[..16], b"verified-slayer\0");

    // The same SAT again (a replay, or the player rejoining with it).
    let (status, info) = admit(a, &t1, &p1, NOW);
    assert_eq!(status, FppStatus::TokenRevoked);
    assert_eq!(info.reason, Reason::Revoked as u16);
    // Another player's tokens presented by the wrong key.
    let t2 = tokens(&f, &p2, 2, 4);
    let (status, info) = admit(a, &t2, &p1, NOW);
    assert_eq!(status, FppStatus::TokenBinding);
    assert_eq!(info.reason, Reason::PopInvalid as u16);
    // A SAT for a slot already taken.
    let clash = tokens(&f, &p2, 3, 3);
    let (status, info) = admit(a, &clash, &p2, NOW);
    assert_eq!(status, FppStatus::TokenAudience);
    assert_eq!(info.reason, Reason::SatInvalid as u16);
    // Expired tokens.
    let (status, _) = admit(a, &t2, &p2, NOW + 4000);
    assert_eq!(status, FppStatus::TokenExpired);
    // The slot frees when its player leaves.
    unsafe {
        assert_eq!(fpp_admission_remove(a, 3), FppStatus::Ok);
        assert_eq!(fpp_admission_remove(a, 3), FppStatus::InvalidArgument);
    }
    assert_eq!(admit(a, &clash, &p2, NOW).0, FppStatus::Ok);
    unsafe { fpp_admission_free(a) };
}

#[test]
fn a_server_admits_only_listed_builds_and_refuses_banned_devices() {
    let f = fx();
    let a = admission(&f);
    let (p1, p2) = (key(0x51), key(0x52));
    unsafe {
        assert_eq!(
            fpp_admission_add_client_build(a, [0xAB; 32].as_ptr()),
            FppStatus::Ok
        );
    }
    // H07: the AR measures build [4; 32], not one this server lists.
    let (status, info) = admit(a, &tokens(&f, &p1, 1, 1), &p1, NOW);
    assert_eq!(status, FppStatus::TokenBuild);
    assert_eq!(info.reason, Reason::BuildUnlisted as u16);
    unsafe {
        assert_eq!(
            fpp_admission_add_client_build(a, [4; 32].as_ptr()),
            FppStatus::Ok
        );
    }
    assert_eq!(admit(a, &tokens(&f, &p2, 2, 2), &p2, NOW).0, FppStatus::Ok);

    // H08: banning the admitted player's device removes it and refuses it.
    unsafe {
        assert_eq!(
            fpp_admission_ban_device(a, [0x32; 32].as_ptr()),
            FppStatus::Ok
        );
    }
    assert_eq!(removed(a), vec![(2, Reason::Revoked as u16)]);
    let (status, _) = admit(a, &tokens(&f, &p2, 2, 5), &p2, NOW);
    assert_eq!(status, FppStatus::TokenRevoked);
    unsafe { fpp_admission_free(a) };
}

#[test]
fn revocation_events_remove_refuse_schedule_or_end_the_match() {
    let f = fx();
    let a = admission(&f);
    let (p1, p2) = (key(0x51), key(0x52));
    assert_eq!(admit(a, &tokens(&f, &p1, 1, 1), &p1, NOW).0, FppStatus::Ok);
    assert_eq!(admit(a, &tokens(&f, &p2, 2, 2), &p2, NOW).0, FppStatus::Ok);

    // Kick player 2's device now.
    let kick = revocation(&f, SubjectKind::Device, vec![0x32; 32], Action::Ban, NOW);
    assert_eq!(revoke(a, &kick, NOW), FppRevocationOutcome::Removing);
    assert_eq!(removed(a), vec![(2, Reason::PolicyKick as u16)]);
    // An event not signed by Enforcement is refused.
    let forged = sign(
        &f.broker,
        &RevocationEvent {
            id: [1; 16],
            subject_kind: SubjectKind::Device,
            subject_id: vec![0x31; 32],
            action: Action::Ban,
            scope: Scope::default(),
            effective_at: NOW,
            expires_at: None,
            reason: 11,
            record: Digest([1; 32]),
        },
    );
    let status =
        unsafe { fpp_admission_revocation(a, forged.as_ptr(), forged.len(), NOW, ptr::null_mut()) };
    assert_ne!(status, FppStatus::Ok);
    // Player 1's device, from ten minutes on: nothing now, then removed.
    let later = revocation(
        &f,
        SubjectKind::Device,
        vec![0x31; 32],
        Action::Ban,
        NOW + 600,
    );
    assert_eq!(revoke(a, &later, NOW), FppRevocationOutcome::Scheduled);
    assert_eq!(unsafe { fpp_admission_tick(a, NOW + 60) }, FppStatus::Ok);
    assert!(removed(a).is_empty());
    assert_eq!(unsafe { fpp_admission_tick(a, NOW + 600) }, FppStatus::Ok);
    assert_eq!(removed(a), vec![(1, Reason::PolicyKick as u16)]);
    // Refusing admission only: recorded, nobody removed.
    let deny = revocation(
        &f,
        SubjectKind::Account,
        vec![5; 32],
        Action::DenyAdmission,
        NOW,
    );
    assert_eq!(revoke(a, &deny, NOW), FppRevocationOutcome::Recorded);
    // Another server's instance: ignored; this one's: the match ends.
    let other = revocation(
        &f,
        SubjectKind::GsInstance,
        instance_id(&public(&key(0x62))).0.to_vec(),
        Action::Ban,
        NOW,
    );
    assert_eq!(revoke(a, &other, NOW), FppRevocationOutcome::Ignored);
    let ours = revocation(
        &f,
        SubjectKind::GsInstance,
        instance_id(&public(&f.instance)).0.to_vec(),
        Action::Ban,
        NOW,
    );
    assert_eq!(revoke(a, &ours, NOW), FppRevocationOutcome::InstanceRevoked);
    unsafe { fpp_admission_free(a) };
}

fn blank() -> FppControl {
    FppControl {
        kind: FppControlKind::Bye,
        code: 0,
        slot: 0,
        start_tick: 0,
        first_len: 0,
        second_len: 0,
    }
}

fn decode(msg: &[u8]) -> (FppStatus, FppControl, Vec<u8>) {
    let mut c = blank();
    let mut data = vec![0u8; 4096];
    let status =
        unsafe { fpp_control_decode(msg.as_ptr(), msg.len(), &mut c, data.as_mut_ptr(), 4096) };
    data.truncate(c.first_len + c.second_len);
    (status, c, data)
}

fn encoded(f: impl Fn(*mut u8, usize, *mut usize) -> FppStatus) -> Vec<u8> {
    let mut len = 0usize;
    assert_eq!(f(ptr::null_mut(), 0, &mut len), FppStatus::BufferTooSmall);
    let mut out = vec![0u8; len];
    assert_eq!(f(out.as_mut_ptr(), len, &mut len), FppStatus::Ok);
    out
}

#[test]
fn control_messages_round_trip() {
    let (sat, ar, sar) = (vec![1u8; 300], vec![2u8; 400], vec![3u8; 350]);
    let msg = encoded(|o, c, l| unsafe {
        fpp_control_admit(sat.as_ptr(), sat.len(), ar.as_ptr(), ar.len(), o, c, l)
    });
    let (status, c, data) = decode(&msg);
    assert_eq!(status, FppStatus::Ok);
    assert_eq!(c.kind, FppControlKind::Admit);
    assert_eq!((c.first_len, c.second_len), (300, 400));
    assert_eq!(data, [sat, ar].concat());
    // (a short buffer: the lengths, and BUFFER_TOO_SMALL)
    let mut c2 = blank();
    let status =
        unsafe { fpp_control_decode(msg.as_ptr(), msg.len(), &mut c2, ptr::null_mut(), 0) };
    assert_eq!(status, FppStatus::BufferTooSmall);
    assert_eq!(c2.first_len, 300);

    let msg =
        encoded(|o, c, l| unsafe { fpp_control_sar_update(sar.as_ptr(), sar.len(), o, c, l) });
    let (_, c, data) = decode(&msg);
    assert_eq!((c.kind, data), (FppControlKind::SarUpdate, sar));
    let msg = encoded(|o, c, l| unsafe { fpp_control_admitted(7, 900, o, c, l) });
    let (_, c, _) = decode(&msg);
    assert_eq!(
        (c.kind, c.slot, c.start_tick),
        (FppControlKind::Admitted, 7, 900)
    );
    let msg = encoded(|o, c, l| unsafe { fpp_control_refuse(14, 0, o, c, l) });
    let (_, c, _) = decode(&msg);
    assert_eq!((c.kind, c.code), (FppControlKind::Reject, 14));
    let msg = encoded(|o, c, l| unsafe { fpp_control_refuse(7, 1, o, c, l) });
    let (_, c, _) = decode(&msg);
    assert_eq!((c.kind, c.code), (FppControlKind::Kick, 7));
    let cp = vec![4u8; 500];
    let msg =
        encoded(|o, c, l| unsafe { fpp_control_checkpoint_head(cp.as_ptr(), cp.len(), o, c, l) });
    let (_, c, data) = decode(&msg);
    assert_eq!((c.kind, data), (FppControlKind::CheckpointHead, cp));
    // Not a control message (the fork's evidence messages start with a tag).
    assert_ne!(decode(b"Mxxxxxxxxxxxxxxxx").0, FppStatus::Ok);
    let s = unsafe { std::ffi::CStr::from_ptr(fpp_reason_str(14)) };
    assert_eq!(s.to_str().unwrap(), "client build not admitted");
}
