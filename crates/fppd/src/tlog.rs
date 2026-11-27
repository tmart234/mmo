//! Transparency Log engine, gossip index, and Witness cosigner (04 §8.2).
//!
//! Every Checkpoint Server Liveness verifies and every RevocationEvent goes
//! into the append-only RFC 9162 Merkle log (`fpp::log::Log`, hybrid-signed
//! with Ed25519 + ML-DSA-65). The Witness holds its own key and persisted
//! state, verifies consistency proofs on every round, refuses rollbacks or
//! split views, and cosigns the log's tree head.

use anyhow::{anyhow, Result};
use fpp::control::{GossipAnswer, GossipRequest, LogRequest, LogResponse};
use fpp::crypto::now_s;
use fpp::log::{leaf, Checkpoint, Log, Note, Witness};
use fpp::types::Digest;
use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};
use tokio::sync::Mutex;

type MatchIndex = HashMap<([u8; 16], u32), Vec<(u64, [u8; 32])>>;

pub struct LogEngine {
    log: Mutex<Log>,
    index: StdMutex<MatchIndex>,
    witnesses: Vec<(String, [u8; 32])>,
}

fn index_entries(index: &mut MatchIndex, from: u64, entries: &[Vec<u8>]) {
    for (offset, entry) in entries.iter().enumerate() {
        if let Some((match_id, epoch, digest)) = leaf::parse_checkpoint(entry) {
            index
                .entry((match_id, epoch))
                .or_default()
                .push((from + offset as u64, digest));
        }
    }
}

impl LogEngine {
    pub fn open(mut log: Log, witnesses: Vec<(String, [u8; 32])>) -> Result<Self> {
        log.set_witnesses(witnesses.clone());
        let mut index = HashMap::new();
        let all = log
            .entries(0)
            .map_err(|e| anyhow!("reindex log entries: {e}"))?;
        index_entries(&mut index, 0, &all);
        Ok(Self {
            log: Mutex::new(log),
            index: StdMutex::new(index),
            witnesses,
        })
    }

    /// Append entries directly (from in-process Liveness/Revocation or authorized RPC).
    pub async fn append(&self, entries: &[Vec<u8>]) -> Result<Vec<(u64, Vec<u8>)>> {
        let mut log = self.log.lock().await;
        let from = log.size();
        let added = log
            .append(entries, now_s())
            .map_err(|e| anyhow!("log append: {e}"))?;
        index_entries(&mut self.index.lock().expect("index"), from, entries);
        Ok(added.into_iter().map(|a| (a.index, a.receipt)).collect())
    }

    pub async fn checkpoint(&self) -> String {
        self.log.lock().await.checkpoint()
    }

    pub async fn consistency(&self, old: u64, new: u64) -> Result<Vec<Digest>> {
        self.log
            .lock()
            .await
            .consistency_proof(old, new)
            .map_err(|e| anyhow!("consistency proof: {e}"))
    }

    pub async fn add_cosignature(&self, text: &str, line: &str) -> Result<()> {
        let mut log = self.log.lock().await;
        log.set_witnesses(self.witnesses.clone());
        log.add_cosignature(text, line)
            .map_err(|e| anyhow!("cosign: {e}"))
    }

    /// Perform one in-process witness cosign round (with the Witness's isolated key & state).
    pub async fn witness_step(&self, witness: &mut Witness) -> Result<Option<u64>> {
        let note = self.checkpoint().await;
        let text = Note::parse(&note)
            .map_err(|e| anyhow!("parse note: {e}"))?
            .text;
        let cp = Checkpoint::parse(&text).map_err(|e| anyhow!("parse checkpoint: {e}"))?;
        let last = witness.last_size();
        let proof = if cp.size > last && last > 0 {
            self.consistency(last, cp.size).await?
        } else {
            Vec::new()
        };
        let line = witness
            .cosign(&note, &proof, now_s())
            .map_err(|e| anyhow!("witness cosign: {e}"))?;
        match self.add_cosignature(&text, &line).await {
            Ok(()) => Ok(Some(cp.size)),
            Err(e) if e.to_string().contains("changed") => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Answer public player gossip against the latest witness-cosigned checkpoint.
    pub async fn gossip(&self, req: &GossipRequest) -> GossipAnswer {
        let leaves = self
            .index
            .lock()
            .expect("index")
            .get(&(req.match_id, req.epoch))
            .cloned()
            .unwrap_or_default();
        let log = self.log.lock().await;
        let Some(checkpoint) = log.cosigned_checkpoint() else {
            return GossipAnswer::Pending;
        };
        let size = Note::parse(&checkpoint)
            .ok()
            .and_then(|n| Checkpoint::parse(&n.text).ok())
            .map_or(0, |c| c.size);
        let covered: Vec<(u64, [u8; 32])> = leaves.into_iter().filter(|(i, _)| *i < size).collect();
        let pick = covered
            .iter()
            .find(|(_, d)| *d == req.digest)
            .or_else(|| covered.first());
        let Some(&(index, logged)) = pick else {
            return GossipAnswer::Pending;
        };
        let Ok(proof) = log.inclusion_proof(index, size) else {
            return GossipAnswer::Pending;
        };
        let proof = proof.iter().map(|d| d.0).collect();
        if logged == req.digest {
            GossipAnswer::Included {
                checkpoint,
                index,
                proof,
            }
        } else {
            GossipAnswer::Conflict {
                checkpoint,
                index,
                logged,
                proof,
            }
        }
    }

    /// Handle an authenticated role/admin log RPC request.
    pub async fn handle_rpc(
        &self,
        req: LogRequest,
        can_write: bool,
        can_cosign: bool,
    ) -> LogResponse {
        match req {
            LogRequest::Add(entries) => {
                if !can_write {
                    return LogResponse::Refused("caller may not append".into());
                }
                match self.append(&entries).await {
                    Ok(added) => LogResponse::Added(added),
                    Err(e) => LogResponse::Refused(e.to_string()),
                }
            }
            LogRequest::Checkpoint => LogResponse::Checkpoint(self.checkpoint().await),
            LogRequest::Inclusion { index, size } => {
                match self.log.lock().await.inclusion_proof(index, size) {
                    Ok(p) => LogResponse::Proof(p.iter().map(|d| d.0).collect()),
                    Err(e) => LogResponse::Refused(e.to_string()),
                }
            }
            LogRequest::Consistency { old, new } => match self.consistency(old, new).await {
                Ok(p) => LogResponse::Proof(p.iter().map(|d| d.0).collect()),
                Err(e) => LogResponse::Refused(e.to_string()),
            },
            LogRequest::Cosign { text, line } => {
                if !can_cosign {
                    return LogResponse::Refused("caller is not an authorized witness".into());
                }
                match self.add_cosignature(&text, &line).await {
                    Ok(()) => LogResponse::Done,
                    Err(e) => LogResponse::Refused(e.to_string()),
                }
            }
        }
    }
}

/// Spawn the background internal Witness loop (cosigns the log periodically).
pub fn spawn_internal_witness(
    engine: Arc<LogEngine>,
    mut witness: Witness,
    interval: std::time::Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut last_logged = u64::MAX;
        loop {
            match engine.witness_step(&mut witness).await {
                Ok(Some(size)) if size != last_logged => {
                    println!("[witness] cosigned size {size}");
                    last_logged = size;
                }
                Ok(_) => {}
                Err(e) => eprintln!("[witness] {e:#}"),
            }
            tokio::time::sleep(interval).await;
        }
    })
}
