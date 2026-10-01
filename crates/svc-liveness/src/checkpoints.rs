//! Receive one signed Checkpoint per epoch (04 §8.1). Each must be signed by the instance
//! key certified in this session's SARs, be for this session's match, and
//! extend the `prev` chain epoch by epoch. Anything else is misbehavior and
//! revokes the instance. Verified Checkpoints go to the Evidence Store
//! ([`crate::evidence`]), and a leaf naming each to the Transparency Log
//! ([`crate::transparency`]), where players check theirs.

use anyhow::{bail, Result};
use common::framing::recv_msg;
use common::proto::CheckpointSubmit;
use fpp_crypto::{KeyRole, KeySet};
use fpp_tokens::instance_id;
use fpp_types::{Digest, MatchId};
use fpp_wire::Checkpoint;
use quinn::Connection;

use crate::ctx::Ctx;

/// Check a Checkpoint against the session's instance key and chain.
/// Returns its epoch and digest.
pub fn verify_checkpoint(
    cose: &[u8],
    instance_pub: &[u8; 32],
    match_id: &[u8; 16],
    last: Option<(u32, Digest)>,
) -> Result<(u32, Digest)> {
    let key = ed25519_dalek::VerifyingKey::from_bytes(instance_pub)?;
    let mut keys = KeySet::default();
    keys.insert_ed25519(KeyRole::GsInstance, key);
    let v = fpp_crypto::verify::<Checkpoint>(cose, &keys)?;
    let cp = v.payload;
    if cp.gs_instance_id != instance_id(instance_pub) {
        bail!("gs_instance_id does not name the instance key");
    }
    if cp.match_id != MatchId(*match_id) {
        bail!("checkpoint for another match");
    }
    let (want_epoch, want_prev) = match last {
        None => (0, Digest::default()),
        Some((e, d)) => (e + 1, d),
    };
    if cp.epoch != want_epoch || cp.prev != want_prev {
        bail!(
            "chain broken: epoch {} (want {want_epoch}) or prev mismatch",
            cp.epoch
        );
    }
    Ok((cp.epoch, v.digest))
}

pub fn spawn_checkpoint_listener(conn: &Connection, ctx: Ctx, session_id: [u8; 16]) {
    let conn = conn.clone();
    tokio::spawn(async move {
        loop {
            let mut uni = match conn.accept_uni().await {
                Ok(u) => u,
                Err(e) => {
                    eprintln!("[liveness] accept_uni: {e}");
                    break;
                }
            };
            let submit: CheckpointSubmit = match recv_msg(&mut uni).await {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("[liveness] bad CheckpointSubmit: {e:#}");
                    continue;
                }
            };
            let Some(s) = ctx.sessions.get(&session_id).map(|s| s.clone()) else {
                break;
            };
            if s.revoked {
                continue;
            }
            let (epoch, digest) = match verify_checkpoint(
                &submit.checkpoint,
                &s.instance_pub,
                &session_id,
                s.last_checkpoint,
            ) {
                Ok(ok) => ok,
                Err(e) => {
                    ctx.revoke(&session_id, &format!("invalid checkpoint: {e:#}"));
                    continue;
                }
            };
            ctx.keep_evidence(session_id, submit.checkpoint);
            ctx.log_entry(fpp_log::leaf::checkpoint(&session_id, epoch, &digest.0));
            if let Some(mut s) = ctx.sessions.get_mut(&session_id) {
                s.last_checkpoint = Some((epoch, digest));
                s.verified.push(digest);
                s.last_seen_ms = common::crypto::now_ms();
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use fpp_crypto::Ed25519Signer;
    use fpp_types::{BuildId, GsInstanceId};

    const MATCH: [u8; 16] = [4; 16];

    fn cp(key: &Ed25519Signer, epoch: u32, prev: Digest, match_id: [u8; 16]) -> Vec<u8> {
        let c = Checkpoint {
            match_id: MatchId(match_id),
            gs_instance_id: GsInstanceId(instance_id(&key.verifying_key().to_bytes()).0),
            build_id: BuildId([0; 32]),
            policy_ver: 1,
            epoch,
            ticks: (epoch * 30, epoch * 30 + 29),
            prev,
            inputs_root: Digest::default(),
            inputs_n: 0,
            events_root: Digest::default(),
            events_n: 0,
            state_root: Digest::default(),
            rng_root: Digest::default(),
            rng_n: 0,
            roster_root: Digest::default(),
            roster_n: 0,
        };
        fpp_crypto::sign(key, &c)
    }

    #[test]
    fn chain_of_checkpoints_is_enforced() {
        let k = Ed25519Signer::new(SigningKey::from_bytes(&[6; 32]));
        let pk = k.verifying_key().to_bytes();
        let c0 = cp(&k, 0, Digest::default(), MATCH);
        let (e0, d0) = verify_checkpoint(&c0, &pk, &MATCH, None).unwrap();
        assert_eq!(e0, 0);
        let c1 = cp(&k, 1, d0, MATCH);
        verify_checkpoint(&c1, &pk, &MATCH, Some((0, d0))).unwrap();
        // Replayed, skipped, forked, other match, other key: all refused.
        assert!(verify_checkpoint(&c0, &pk, &MATCH, Some((0, d0))).is_err());
        assert!(verify_checkpoint(&cp(&k, 2, d0, MATCH), &pk, &MATCH, Some((0, d0))).is_err());
        assert!(verify_checkpoint(
            &cp(&k, 1, Digest([1; 32]), MATCH),
            &pk,
            &MATCH,
            Some((0, d0))
        )
        .is_err());
        assert!(verify_checkpoint(&cp(&k, 1, d0, [5; 16]), &pk, &MATCH, Some((0, d0))).is_err());
        let other = Ed25519Signer::new(SigningKey::from_bytes(&[7; 32]));
        assert!(verify_checkpoint(&cp(&other, 1, d0, MATCH), &pk, &MATCH, Some((0, d0))).is_err());
    }
}
