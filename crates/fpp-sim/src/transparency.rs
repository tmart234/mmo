//! Checking the server's Checkpoints against the Transparency Log (EVD-03).
//!
//! - The log's checkpoint note verifies under BOTH halves of the log's hybrid
//!   key (Ed25519 and ML-DSA-65, FPP-S1H) and carries a cosignature from a
//!   witness in the key bundle;
//! - The inclusion proof puts the leaf `(match, epoch, digest)` under that
//!   checkpoint's root.
//!
//! A logged leaf with another digest is a split view: the player holds a
//! Checkpoint the server signed for the same match and epoch, so it reports it
//! to Server Liveness, which revokes the server.

use crate::client::ClientTrust;
use anyhow::{anyhow, bail, Context, Result};
use fpp::bundle::LogKeys;
use fpp::control::{
    EquivocationReport, GossipAnswer, GossipRequest, Purpose, ReportAnswer, MAX_CONTROL_FRAME,
};
use fpp::log::{self, Checkpoint, Note};
use fpp::merkle;
use fpp::types::Digest;
use fppd::open_control;
use std::net::SocketAddr;

/// A Checkpoint the server sent this player, verified under its instance key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Head {
    pub epoch: u32,
    pub digest: Digest,
    pub signed: Vec<u8>,
}

/// What the log says about a head.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HeadCheck {
    Included { index: u64, size: u64 },
    Pending,
    SplitView { logged: Digest },
}

/// Verify the log's checkpoint note under BOTH Ed25519 and ML-DSA-65 + at least
/// one known witness cosignature.
pub fn verify_checkpoint(log_keys: &LogKeys, note: &str) -> Result<(u64, Digest)> {
    let note = Note::parse(note).map_err(|e| anyhow!("checkpoint: {e}"))?;
    note.verify_hybrid(&log_keys.origin, &log_keys.ed25519, &log_keys.ml_dsa)
        .map_err(|e| anyhow!("checkpoint not signed by the log (Ed25519 and ML-DSA): {e}"))?;
    if !log_keys
        .witnesses
        .iter()
        .any(|(name, key)| note.verify_cosignature(name, key).is_ok())
    {
        bail!("checkpoint not cosigned by a known witness");
    }
    let c = Checkpoint::parse(&note.text).map_err(|e| anyhow!("checkpoint: {e}"))?;
    if c.origin != log_keys.origin {
        bail!("checkpoint of another log");
    }
    Ok((c.size, Digest(c.root)))
}

fn proven(
    log_keys: &LogKeys,
    note: &str,
    leaf: &[u8],
    index: u64,
    proof: &[[u8; 32]],
) -> Result<u64> {
    let (size, root) = verify_checkpoint(log_keys, note)?;
    let proof: Vec<Digest> = proof.iter().copied().map(Digest).collect();
    if !merkle::verify_inclusion(&merkle::leaf_hash(leaf), index, size, &proof, &root) {
        bail!("inclusion proof does not verify");
    }
    Ok(size)
}

/// Ask the Transparency Log at `addr` about `head` of `match_id`, and check its answer.
pub async fn check_head(
    trust: &ClientTrust,
    addr: SocketAddr,
    match_id: [u8; 16],
    head: &Head,
) -> Result<HeadCheck> {
    let log_keys = trust
        .bundle
        .log
        .as_ref()
        .context("the key bundle names no Transparency Log")?;
    let server_pub = trust
        .bundle
        .transport_key("log")
        .map_err(|e| anyhow!("{e}"))?;
    let (mut s, _) = open_control(addr, &server_pub, None, Purpose::Gossip).await?;
    s.send(&GossipRequest {
        match_id,
        epoch: head.epoch,
        digest: head.digest.0,
    })
    .await?;
    let answer: GossipAnswer = s.recv_max(MAX_CONTROL_FRAME).await.context("gossip")?;
    match answer {
        GossipAnswer::Pending => Ok(HeadCheck::Pending),
        GossipAnswer::Included {
            checkpoint,
            index,
            proof,
        } => {
            let leaf = log::leaf::checkpoint(&match_id, head.epoch, &head.digest.0);
            let size = proven(log_keys, &checkpoint, &leaf, index, &proof)?;
            Ok(HeadCheck::Included { index, size })
        }
        GossipAnswer::Conflict {
            checkpoint,
            index,
            logged,
            proof,
        } => {
            if logged == head.digest.0 {
                bail!("the log calls our own Checkpoint a conflict");
            }
            let leaf = log::leaf::checkpoint(&match_id, head.epoch, &logged);
            proven(log_keys, &checkpoint, &leaf, index, &proof)?;
            Ok(HeadCheck::SplitView {
                logged: Digest(logged),
            })
        }
    }
}

/// Report a split view to Server Liveness at `addr`.
pub async fn report(trust: &ClientTrust, addr: SocketAddr, head: &Head) -> Result<ReportAnswer> {
    let server_pub = trust
        .bundle
        .transport_key("liveness")
        .map_err(|e| anyhow!("{e}"))?;
    let (mut s, _) = open_control(addr, &server_pub, None, Purpose::Report).await?;
    s.send(&EquivocationReport {
        checkpoint: head.signed.clone(),
    })
    .await?;
    s.recv_max(MAX_CONTROL_FRAME)
        .await
        .context("recv ReportAnswer")
}

#[derive(Clone, Debug, Default)]
pub struct Audit {
    pub included: usize,
    pub pending: Vec<u32>,
    pub split_views: Vec<(u32, Result<ReportAnswer, String>)>,
}

/// Check `heads` against `log`, retrying pending ones until `deadline`; report
/// any split view to `liveness`.
pub async fn audit(
    trust: &ClientTrust,
    log_addr: SocketAddr,
    liveness_addr: SocketAddr,
    match_id: [u8; 16],
    heads: &[Head],
    deadline: std::time::Instant,
) -> Result<Audit> {
    let mut out = Audit::default();
    let mut todo: Vec<&Head> = heads.iter().collect();
    loop {
        let mut pending = Vec::new();
        for head in todo {
            match check_head(trust, log_addr, match_id, head).await? {
                HeadCheck::Included { .. } => out.included += 1,
                HeadCheck::Pending => pending.push(head),
                HeadCheck::SplitView { .. } => {
                    let answer = report(trust, liveness_addr, head)
                        .await
                        .map_err(|e| format!("{e:#}"));
                    out.split_views.push((head.epoch, answer));
                }
            }
        }
        if pending.is_empty() || std::time::Instant::now() >= deadline {
            out.pending = pending.iter().map(|h| h.epoch).collect();
            return Ok(out);
        }
        todo = pending;
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
}
