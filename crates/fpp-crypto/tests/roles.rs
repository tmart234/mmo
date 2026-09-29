use ed25519_dalek::SigningKey;
use fpp_crypto::*;
use fpp_types::{ctx, BuildId, Digest, GsInstanceId, MatchId};
use fpp_wire::Checkpoint;

const ALL_ROLES: [KeyRole; 10] = [
    KeyRole::PublisherRoot,
    KeyRole::BuildSigning,
    KeyRole::PolicySigning,
    KeyRole::VerifierAr,
    KeyRole::BrokerSat,
    KeyRole::ServerLiveness,
    KeyRole::Log,
    KeyRole::Enforcement,
    KeyRole::GsInstance,
    KeyRole::Session,
];

/// Every context has exactly one role that may sign it (04-protocol.md §4).
#[test]
fn each_context_has_exactly_one_signing_role() {
    let contexts = [
        ctx::CERT,
        ctx::BUILD_MANIFEST,
        ctx::POLICY,
        ctx::ATTESTATION_RESULT,
        ctx::SAT,
        ctx::SAR,
        ctx::TREE_HEAD,
        ctx::LOG_RECEIPT,
        ctx::REVOCATION,
        ctx::ENFORCEMENT_RECORD,
        ctx::CHECKPOINT,
        ctx::HOST_BATCH,
        ctx::ADMIT_POP,
        ctx::INPUT_COMMIT,
        ctx::INTEGRITY_REPORT,
    ];
    for c in contexts {
        let owners: Vec<_> = ALL_ROLES.iter().filter(|r| r.allows(c)).collect();
        assert_eq!(owners.len(), 1, "{c}: {owners:?}");
    }
}

fn checkpoint() -> Checkpoint {
    Checkpoint {
        match_id: MatchId([1; 16]),
        gs_instance_id: GsInstanceId([2; 32]),
        build_id: BuildId([3; 32]),
        policy_ver: 1,
        epoch: 0,
        ticks: (0, 63),
        prev: Digest::default(),
        inputs_root: Digest([4; 32]),
        inputs_n: 0,
        events_root: Digest([5; 32]),
        events_n: 0,
        state_root: Digest([6; 32]),
        rng_root: Digest([7; 32]),
        rng_n: 0,
        roster_root: Digest([8; 32]),
        roster_n: 0,
    }
}

#[test]
fn verified_object_reports_key_and_digest() {
    let gs = Ed25519Signer::new(SigningKey::from_bytes(&[9; 32]));
    let mut keys = KeySet::default();
    let k = keys.insert_ed25519(KeyRole::GsInstance, gs.verifying_key());
    let signed = sign(&gs, &checkpoint());
    let v = verify::<Checkpoint>(&signed, &keys).unwrap();
    assert_eq!(v.payload, checkpoint());
    assert_eq!(v.kid, k);
    assert_eq!(v.role, KeyRole::GsInstance);
    assert_eq!(v.digest, object_digest(&signed));
    // Signing is deterministic (Ed25519), so object digests are stable.
    assert_eq!(sign(&gs, &checkpoint()), signed);
}

#[test]
fn hybrid_roots_cannot_use_single_signatures() {
    for role in ALL_ROLES {
        let expect = matches!(
            role,
            KeyRole::PublisherRoot | KeyRole::BuildSigning | KeyRole::PolicySigning | KeyRole::Log
        );
        assert_eq!(role.requires_hybrid(), expect, "{role:?}");
    }
    let root = Ed25519Signer::new(SigningKey::from_bytes(&[10; 32]));
    let mut keys = KeySet::default();
    keys.insert_ed25519(KeyRole::PublisherRoot, root.verifying_key());
    let err = verify::<Checkpoint>(&sign(&root, &checkpoint()), &keys).unwrap_err();
    assert_eq!(err, VerifyError::HybridRequired(KeyRole::PublisherRoot));
}

#[test]
fn kid_is_truncated_key_digest() {
    let s = Ed25519Signer::new(SigningKey::from_bytes(&[11; 32]));
    assert_eq!(s.kid().0, key_digest(&s.verifying_key()).0[..16]);
}
