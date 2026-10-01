//! The Transparency Log as a service, and a witness that cosigns it.
//!
//! The log appends entries for the services allowed to write (the
//! Revocation Feed, Enforcement, Server Liveness), answers proof requests
//! from any cell service, and publishes cosignatures from its witnesses.
//! Publicly, it answers players' gossip: is the Checkpoint a game server
//! showed them the one Server Liveness logged for that match and epoch?
//! Its tiles and checkpoint are files in its data directory, served as
//! static files (C2SP `tlog-tiles`) by any web server or bucket.
//!
//! Keys: the log's is hybrid (FPP-S1H), made on first start in its own cell
//! directory; the witness's is its own Ed25519 key. Each publishes its
//! public keys in `<cell>/public/<service>` for the others to read.

use anyhow::{anyhow, Result};
use common::proto::{GossipAnswer, GossipRequest};
use fpp_log::Log;
pub use fpp_svc::PublicKeys;
use fpp_svc::{rpc::serve, Caller};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// Append entries (writers only).
    Add(Vec<Vec<u8>>),
    /// The current checkpoint (a signed note).
    Checkpoint,
    Inclusion {
        index: u64,
        size: u64,
    },
    Consistency {
        old: u64,
        new: u64,
    },
    /// A witness's cosignature line over checkpoint `text` (witnesses only).
    Cosign {
        text: String,
        line: String,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum Response {
    /// (index, `LogReceipt` COSE_Sign) per entry.
    Added(Vec<(u64, Vec<u8>)>),
    Checkpoint(String),
    Proof(Vec<[u8; 32]>),
    Done,
    Refused(String),
}

pub struct LogConfig {
    /// Services allowed to append.
    pub writers: Vec<String>,
    /// Witness services whose cosignatures the log publishes (their keys
    /// are read from the cell as they come).
    pub witnesses: Vec<String>,
    pub cell: std::path::PathBuf,
}

fn now_s() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

type Index = HashMap<([u8; 16], u32), Vec<(u64, [u8; 32])>>;

/// The log as a service: the cell API (append, proofs, cosignatures) and
/// the public gossip API (is this Checkpoint the one logged?).
pub struct LogService {
    log: Mutex<Log>,
    /// Checkpoint leaves by (match, epoch): (index, digest).
    index: std::sync::Mutex<Index>,
    config: LogConfig,
}

fn index_entries(index: &mut Index, from: u64, entries: &[Vec<u8>]) {
    for (i, e) in entries.iter().enumerate() {
        if let Some((m, epoch, digest)) = fpp_log::leaf::parse_checkpoint(e) {
            index
                .entry((m, epoch))
                .or_default()
                .push((from + i as u64, digest));
        }
    }
}

impl LogService {
    /// The service over `log`, its checkpoint index rebuilt from the entries.
    pub fn new(log: Log, config: LogConfig) -> Result<Arc<Self>> {
        let mut index = Index::new();
        index_entries(&mut index, 0, &log.entries(0)?);
        Ok(Arc::new(Self {
            log: Mutex::new(log),
            index: std::sync::Mutex::new(index),
            config,
        }))
    }

    /// Serve the cell API on `endpoint` (mutual TLS) until it closes.
    pub async fn serve_cell(self: Arc<Self>, endpoint: fpp_svc::quinn::Endpoint) {
        serve(endpoint, move |caller: Caller, request: Request| {
            let svc = self.clone();
            async move { svc.handle(&caller, request).await }
        })
        .await
    }

    /// Serve gossip on a public `endpoint` until it closes: anyone may ask.
    pub async fn serve_public(self: Arc<Self>, endpoint: fpp_svc::quinn::Endpoint) {
        common::admission::serve(endpoint, "log", move |incoming| {
            let svc = self.clone();
            async move {
                let conn = tokio::time::timeout(Duration::from_secs(10), incoming)
                    .await
                    .map_err(|_| anyhow!("handshake timed out"))??;
                while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                    let request: GossipRequest = tokio::time::timeout(
                        Duration::from_secs(10),
                        common::framing::recv_msg(&mut recv),
                    )
                    .await
                    .map_err(|_| anyhow!("request timed out"))??;
                    let answer = svc.gossip(&request).await;
                    common::framing::send_msg(&mut send, &answer).await?;
                }
                Ok(())
            }
        })
        .await
    }

    /// Answer gossip against the latest cosigned checkpoint.
    pub async fn gossip(&self, request: &GossipRequest) -> GossipAnswer {
        let leaves = self
            .index
            .lock()
            .expect("index lock")
            .get(&(request.match_id, request.epoch))
            .cloned()
            .unwrap_or_default();
        let log = self.log.lock().await;
        let Some(checkpoint) = log.cosigned_checkpoint() else {
            return GossipAnswer::Pending;
        };
        let size = fpp_log::Note::parse(&checkpoint)
            .ok()
            .and_then(|n| fpp_log::Checkpoint::parse(&n.text).ok())
            .map_or(0, |c| c.size);
        let covered: Vec<(u64, [u8; 32])> = leaves.into_iter().filter(|(i, _)| *i < size).collect();
        let pick = covered
            .iter()
            .find(|(_, d)| *d == request.digest)
            .or_else(|| covered.first());
        let Some(&(index, logged)) = pick else {
            return GossipAnswer::Pending;
        };
        let Ok(proof) = log.inclusion_proof(index, size) else {
            return GossipAnswer::Pending;
        };
        let proof = proof.iter().map(|d| d.0).collect();
        if logged == request.digest {
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

    async fn handle(&self, caller: &Caller, request: Request) -> Response {
        let config = &self.config;
        let refused = |why: &str| Response::Refused(why.to_string());
        let mut log = self.log.lock().await;
        let result = match request {
            Request::Add(entries) => {
                if !caller.is(&config.writers) {
                    return refused(&format!("{} may not append", caller.0));
                }
                let from = log.size();
                let added = log.append(&entries, now_s());
                if added.is_ok() {
                    index_entries(&mut self.index.lock().expect("index lock"), from, &entries);
                }
                added
                    .map(|a| Response::Added(a.into_iter().map(|x| (x.index, x.receipt)).collect()))
            }
            Request::Checkpoint => Ok(Response::Checkpoint(log.checkpoint())),
            Request::Inclusion { index, size } => log
                .inclusion_proof(index, size)
                .map(|p| Response::Proof(p.iter().map(|d| d.0).collect())),
            Request::Consistency { old, new } => log
                .consistency_proof(old, new)
                .map(|p| Response::Proof(p.iter().map(|d| d.0).collect())),
            Request::Cosign { text, line } => {
                if !caller.is(&config.witnesses) {
                    return refused(&format!("{} is not a witness of this log", caller.0));
                }
                let witnesses: Vec<(String, [u8; 32])> = config
                    .witnesses
                    .iter()
                    .filter_map(|w| {
                        PublicKeys::read(&config.cell, w)
                            .ok()
                            .map(|k| (k.name, k.ed25519))
                    })
                    .collect();
                log.set_witnesses(witnesses);
                log.add_cosignature(&text, &line).map(|_| Response::Done)
            }
        };
        result.unwrap_or_else(|e| Response::Refused(e.to_string()))
    }
}

/// Serve the log's cell API on `endpoint` until it closes.
pub async fn serve_log(endpoint: fpp_svc::quinn::Endpoint, log: Log, config: LogConfig) {
    match LogService::new(log, config) {
        Ok(svc) => svc.serve_cell(endpoint).await,
        Err(e) => eprintln!("[log] {e:#}"),
    }
}

/// A writer's connection to the log (reconnecting as needed).
pub struct Writer {
    endpoint: fpp_svc::quinn::Endpoint,
    addr: std::net::SocketAddr,
    conn: Mutex<Option<fpp_svc::quinn::Connection>>,
}

impl Writer {
    pub fn new(identity: &fpp_svc::Identity, addr: std::net::SocketAddr) -> Result<Self> {
        Ok(Self {
            endpoint: fpp_svc::mtls::client_endpoint(identity)?,
            addr,
            conn: Mutex::new(None),
        })
    }

    /// Append entries; the index of the first.
    pub async fn append(&self, entries: Vec<Vec<u8>>) -> Result<u64> {
        let n = entries.len();
        let mut guard = self.conn.lock().await;
        let conn = match guard.as_ref().filter(|c| c.close_reason().is_none()) {
            Some(c) => c.clone(),
            None => {
                let c = tokio::time::timeout(
                    Duration::from_secs(5),
                    fpp_svc::mtls::connect(&self.endpoint, self.addr, "log"),
                )
                .await
                .map_err(|_| anyhow!("Transparency Log unreachable"))??;
                *guard = Some(c.clone());
                c
            }
        };
        let answer = tokio::time::timeout(
            Duration::from_secs(10),
            fpp_svc::call(&conn, &Request::Add(entries)),
        )
        .await
        .map_err(|_| anyhow!("Transparency Log timed out"));
        match answer {
            Ok(Ok(Response::Added(added))) if added.len() == n && n > 0 => Ok(added[0].0),
            Ok(Ok(other)) => Err(anyhow!("Transparency Log: {other:?}")),
            Ok(Err(e)) | Err(e) => {
                *guard = None;
                Err(e)
            }
        }
    }
}

/// One witness round: fetch the checkpoint, and cosign it if it extends
/// the last one cosigned. Returns the size cosigned, if any.
pub async fn witness_round(
    conn: &fpp_svc::quinn::Connection,
    witness: &mut fpp_log::Witness,
) -> Result<Option<u64>> {
    let Response::Checkpoint(note) = fpp_svc::call(conn, &Request::Checkpoint).await? else {
        return Err(anyhow!("no checkpoint"));
    };
    let text = fpp_log::Note::parse(&note)?.text;
    let checkpoint = fpp_log::Checkpoint::parse(&text)?;
    let last = witness.last_size();
    let proof = if checkpoint.size > last && last > 0 {
        match fpp_svc::call(
            conn,
            &Request::Consistency {
                old: last,
                new: checkpoint.size,
            },
        )
        .await?
        {
            Response::Proof(p) => p.into_iter().map(fpp_types::Digest).collect(),
            other => return Err(anyhow!("consistency proof: {other:?}")),
        }
    } else {
        Vec::new()
    };
    let line = witness.cosign(&note, &proof, now_s())?;
    match fpp_svc::call(conn, &Request::Cosign { text, line }).await? {
        Response::Done => Ok(Some(checkpoint.size)),
        // (the log moved on meanwhile: the next round cosigns the new one)
        Response::Refused(why) if why.contains("changed") => Ok(None),
        other => Err(anyhow!("cosignature refused: {other:?}")),
    }
}
