//! Checking the server's Checkpoints against the Transparency Log (EVD-03,
//! 04 §7.6). The server sends each player every Checkpoint it signs; Server
//! Liveness logs the one the server gave it. A player asks the log (gossip)
//! whether its Checkpoint is the one logged for that match and epoch, and
//! checks the answer itself:
//!
//! - the log's checkpoint note verifies under **both** halves of the log's
//!   hybrid key (Ed25519 and ML-DSA-65, FPP-S1H) and carries a cosignature
//!   from a witness in the key bundle;
//! - the inclusion proof puts the leaf (match, epoch, digest) under that
//!   checkpoint's root.
//!
//! A logged leaf with another digest is a split view: the player holds a
//! Checkpoint the server signed for the same match and epoch, so it reports
//! it to Server Liveness, which revokes the server ([`report`]).

use anyhow::{anyhow, bail, Context, Result};
use common::framing::{recv_msg, send_msg};
use common::keys::LogKeys;
use common::proto::{EquivocationReport, GossipAnswer, GossipRequest, Purpose, ReportAnswer};
use fpp_types::Digest;
use std::net::SocketAddr;

use crate::ClientTrust;

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
    /// Logged, proven under a cosigned checkpoint of `size` leaves.
    Included { index: u64, size: u64 },
    /// Not (yet) in a cosigned checkpoint; ask again before the log's
    /// maximum merge delay is up.
    Pending,
    /// Another Checkpoint is logged for this match and epoch (proven):
    /// the server showed this player something else.
    SplitView { logged: Digest },
}

/// Check the log's checkpoint note: both halves of its hybrid key, and at
/// least one cosignature from a known witness. Its size and root.
pub fn verify_checkpoint(log: &LogKeys, note: &str) -> Result<(u64, Digest)> {
    let note = fpp_log::Note::parse(note).map_err(|e| anyhow!("checkpoint: {e}"))?;
    note.verify_hybrid(&log.origin, &log.ed25519, &log.ml_dsa)
        .map_err(|e| anyhow!("checkpoint not signed by the log (Ed25519 and ML-DSA): {e}"))?;
    if !log
        .witnesses
        .iter()
        .any(|(name, key)| note.verify_cosignature(name, key).is_ok())
    {
        bail!("checkpoint not cosigned by a known witness");
    }
    let c = fpp_log::Checkpoint::parse(&note.text).map_err(|e| anyhow!("checkpoint: {e}"))?;
    if c.origin != log.origin {
        bail!("checkpoint of another log");
    }
    Ok((c.size, Digest(c.root)))
}

fn proven(log: &LogKeys, note: &str, leaf: &[u8], index: u64, proof: &[[u8; 32]]) -> Result<u64> {
    let (size, root) = verify_checkpoint(log, note)?;
    let proof: Vec<Digest> = proof.iter().copied().map(Digest).collect();
    if !fpp_merkle::verify_inclusion(&fpp_merkle::leaf_hash(leaf), index, size, &proof, &root) {
        bail!("inclusion proof does not verify");
    }
    Ok(size)
}

/// Ask the log at `addr` about `head` of match `match_id`, and check its
/// answer.
pub async fn check_head(
    trust: &ClientTrust,
    addr: SocketAddr,
    match_id: [u8; 16],
    head: &Head,
) -> Result<HeadCheck> {
    let log = trust
        .bundle
        .log
        .as_ref()
        .context("the key bundle names no Transparency Log")?;
    let request = GossipRequest {
        match_id,
        epoch: head.epoch,
        digest: head.digest.0,
    };
    let answer: GossipAnswer = common::admission::query(&trust.ca_der, addr, "log", &request)
        .await
        .context("gossip")?;
    match answer {
        GossipAnswer::Pending => Ok(HeadCheck::Pending),
        GossipAnswer::Included {
            checkpoint,
            index,
            proof,
        } => {
            let leaf = fpp_log::leaf::checkpoint(&match_id, head.epoch, &head.digest.0);
            let size = proven(log, &checkpoint, &leaf, index, &proof)?;
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
            let leaf = fpp_log::leaf::checkpoint(&match_id, head.epoch, &logged);
            proven(log, &checkpoint, &leaf, index, &proof)?;
            Ok(HeadCheck::SplitView {
                logged: Digest(logged),
            })
        }
    }
}

/// Report a split view to Server Liveness at `addr`: the server-signed
/// Checkpoint this player holds.
pub async fn report(trust: &ClientTrust, addr: SocketAddr, head: &Head) -> Result<ReportAnswer> {
    let mut o =
        common::admission::request_challenge_for(&trust.ca_der, addr, "liveness", Purpose::Report)
            .await?;
    send_msg(
        &mut o.send,
        &EquivocationReport {
            checkpoint: head.signed.clone(),
        },
    )
    .await?;
    let answer = recv_msg(&mut o.recv).await.context("recv ReportAnswer")?;
    o.conn.close(0u32.into(), b"thanks");
    Ok(answer)
}

/// What checking a match's heads found.
#[derive(Clone, Debug, Default)]
pub struct Audit {
    /// Heads proven logged.
    pub included: usize,
    /// Heads still not in a cosigned checkpoint at the deadline.
    pub pending: Vec<u32>,
    /// Split views found, and what Server Liveness said to the report.
    pub split_views: Vec<(u32, Result<ReportAnswer, String>)>,
}

/// Check `heads` of match `match_id` against the log at `log`, asking
/// again for pending ones until `deadline`; report split views to Server
/// Liveness at `liveness`. An answer that does not verify is an error.
pub async fn audit(
    trust: &ClientTrust,
    log: SocketAddr,
    liveness: SocketAddr,
    match_id: [u8; 16],
    heads: &[Head],
    deadline: std::time::Instant,
) -> Result<Audit> {
    let mut out = Audit::default();
    let mut todo: Vec<&Head> = heads.iter().collect();
    loop {
        let mut pending = Vec::new();
        for head in todo {
            match check_head(trust, log, match_id, head).await? {
                HeadCheck::Included { .. } => out.included += 1,
                HeadCheck::Pending => pending.push(head),
                HeadCheck::SplitView { .. } => {
                    let answer = report(trust, liveness, head)
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
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}
