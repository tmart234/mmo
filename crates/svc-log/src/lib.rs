//! The Transparency Log as a service, and a witness that cosigns it.
//!
//! The log appends entries for the services allowed to write (the
//! Revocation Feed, Enforcement, Server Liveness), answers proof requests
//! from any cell service, and publishes cosignatures from its witnesses.
//! Its tiles and checkpoint are files in its data directory, served as
//! static files (C2SP `tlog-tiles`) by any web server or bucket.
//!
//! Keys: the log's is hybrid (FPP-S1H), made on first start in its own cell
//! directory; the witness's is its own Ed25519 key. Each publishes its
//! public keys in `<cell>/public/<service>` for the others to read.

use anyhow::{anyhow, Result};
use fpp_log::Log;
pub use fpp_svc::PublicKeys;
use fpp_svc::{rpc::serve, Caller};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
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

/// Serve the log on `endpoint` until it closes.
pub async fn serve_log(endpoint: fpp_svc::quinn::Endpoint, log: Log, config: LogConfig) {
    let log = Arc::new(Mutex::new(log));
    let config = Arc::new(config);
    serve(endpoint, move |caller: Caller, request: Request| {
        let log = log.clone();
        let config = config.clone();
        async move { handle(&log, &config, &caller, request).await }
    })
    .await
}

async fn handle(
    log: &Mutex<Log>,
    config: &LogConfig,
    caller: &Caller,
    request: Request,
) -> Response {
    let refused = |why: &str| Response::Refused(why.to_string());
    let mut log = log.lock().await;
    let result = match request {
        Request::Add(entries) => {
            if !caller.is(&config.writers) {
                return refused(&format!("{} may not append", caller.0));
            }
            log.append(&entries, now_s())
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
