// crates/vs/src/broker.rs
//! Verifier and Broker for clients (roles split out in P2). The flow and the
//! tokens are the real ones (04 §5.1, §5.2, §6.1, §6.2). The Verifier
//! appraises Android key attestation and Apple App Attest evidence
//! (`appraisal.rs`); without evidence, or with evidence that fails, a device
//! is tier D0.
//!
//! Queues carry a tier floor (03 §4.4): `open` admits everyone; `verified`
//! requires D2, so today's clients are refused there and would be placed in
//! `open` by a real matchmaker.

use common::crypto::{client_admission_sign_bytes, now_ms};
use common::proto::{ClientAdmission, ClientAdmissionRequest};
use ed25519_dalek::{Signature, VerifyingKey};
use fpp_tokens::{instance_id, AttestationResult, SessionAdmissionToken};
use fpp_types::{BuildId, DeviceTier, Did, MatchId, Reason};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};

use crate::ctx::VsCtx;

pub const VERIFIER_ISS: &str = "ver.dev";
pub const BROKER_ISS: &str = "broker.dev";
pub const POLICY_VER: u64 = 1;
const AR_LIFETIME_S: u64 = 1800;
const SAT_LIFETIME_S: u64 = 3600;

/// Tier floor per queue (the example policy of 03 §4.4).
pub fn queue_min_tier(queue: &str) -> Option<DeviceTier> {
    match queue {
        "open" => Some(DeviceTier::D0Unknown),
        "verified" => Some(DeviceTier::D2Hardware),
        _ => None,
    }
}

fn random16() -> [u8; 16] {
    let mut b = [0u8; 16];
    OsRng.fill_bytes(&mut b);
    b
}

fn tagged_hash(tag: &str, data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(tag.as_bytes());
    h.update([0]);
    h.update(data);
    h.finalize().into()
}

fn refuse(reason: Reason) -> ClientAdmission {
    ClientAdmission::Refused {
        code: reason as u16,
    }
}

pub fn admit_client(
    ctx: &VsCtx,
    challenge: &[u8; 32],
    req: &ClientAdmissionRequest,
) -> ClientAdmission {
    // Proof of possession of the session key, bound to this challenge.
    let Ok(key) = VerifyingKey::from_bytes(&req.session_pub) else {
        return refuse(Reason::PopInvalid);
    };
    let msg = client_admission_sign_bytes(
        challenge,
        &req.session_pub,
        &req.platform,
        &req.client_build,
        &req.queue,
        &req.evidence,
    );
    if key
        .verify_strict(&msg, &Signature::from_bytes(&req.pop_sig))
        .is_err()
    {
        return refuse(Reason::PopInvalid);
    }
    if req.platform.is_empty() || req.platform.len() > 32 {
        return refuse(Reason::ArInvalid);
    }

    // ---- Verifier: platform evidence bound to this challenge and session key.
    let appraised =
        crate::appraisal::appraise(&ctx.attestation, challenge, &req.session_pub, &req.evidence);
    let tier = appraised.tier;
    // A hardware-rooted identity where the platform gives one (dev stand-in
    // for HMAC(publisher_did_key, hardware_identity), 04 §5); else a
    // per-key pseudonym.
    let did = match &appraised.identity {
        Some(id) => Did(tagged_hash("mmo/dev-did-hw", id)),
        None => Did(tagged_hash("mmo/dev-did", &req.session_pub)),
    };
    let now = now_ms() / 1000;
    let ar = AttestationResult {
        iss: VERIFIER_ISS.into(),
        iat: now,
        exp: now + AR_LIFETIME_S,
        cti: random16(),
        cnf: req.session_pub,
        nonce: *challenge,
        did,
        tier,
        features: appraised.features,
        client_build: BuildId(req.client_build),
        platform: req.platform.clone(),
        policy_ver: POLICY_VER,
        warnings: appraised.warnings,
    };

    // ---- Broker: queue policy, then a match on a live server.
    let Some(min) = queue_min_tier(&req.queue) else {
        return refuse(Reason::PolicyKick);
    };
    if tier < min {
        return refuse(Reason::TierInsufficient);
    }
    let pick = ctx
        .sessions
        .iter_mut()
        .filter(|s| !s.revoked && s.last_checkpoint.is_some())
        .map(|mut s| {
            let slot = s.next_slot;
            s.next_slot = s.next_slot.wrapping_add(1);
            (
                *s.key(),
                s.instance_pub,
                s.noise_static,
                s.game_addr.clone(),
                slot,
            )
        })
        .next();
    let Some((match_id, instance_pub, noise_static, gs_addr, slot)) = pick else {
        return refuse(Reason::ServerDraining);
    };
    let sat = SessionAdmissionToken {
        iss: BROKER_ISS.into(),
        // No account system yet: a per-key pseudonym.
        sub: tagged_hash("mmo/dev-acct", &req.session_pub),
        aud: instance_id(&instance_pub),
        iat: now,
        exp: now + SAT_LIFETIME_S,
        cti: random16(),
        cnf: req.session_pub,
        did: ar.did,
        tier,
        match_id: MatchId(match_id),
        slot,
        queue: req.queue.clone(),
        policy_ver: POLICY_VER,
        ar_cti: ar.cti,
    };
    println!(
        "[VS] admitted client ..{} to match {}.. slot {slot} (tier D{})",
        hex::encode(&req.session_pub[..3]),
        hex::encode(&match_id[..4]),
        tier as u8
    );
    ClientAdmission::Granted {
        ar: fpp_crypto::sign(&ctx.keys.verifier, &ar),
        sat: fpp_crypto::sign(&ctx.keys.broker, &sat),
        gs_addr,
        gs_noise_static: noise_static,
    }
}
