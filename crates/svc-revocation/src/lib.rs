//! The Revocation Feed (04 §9), a service of the cell.
//!
//! Enforcement publishes `RevocationEvent`s signed with its own key; the
//! feed checks the signature, appends the event to the Transparency Log
//! (when it has one: then nothing is accepted without a log entry), keeps
//! it on disk, and serves the feed to its subscribers (Brokers, Server
//! Liveness) by sequence number, holding each request open until there is
//! something new. It is idempotent by event id.
//!
//! The feed holds no signing key of its own: a compromised feed can delay
//! or drop events (bounded by token lifetimes, 03 §7), but not forge one.
//!
//! [`enforce`] is the Enforcement side: sign an event over an enforcement
//! record and publish both.

pub mod enforce;

use anyhow::{anyhow, Context, Result};
use ed25519_dalek::VerifyingKey;
use fpp_crypto::{KeyRole, KeySet};
use fpp_svc::api::revocation::{Request, Response, MAX_WAIT_MS};
use fpp_svc::Caller;
use fpp_wire::RevocationEvent;
use std::collections::HashMap;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{watch, Mutex};

/// Largest event accepted (a COSE_Sign1 over a small map).
pub const MAX_EVENT: usize = 4096;
/// Most events returned by one `Since`.
pub const MAX_BATCH: usize = 1000;

pub struct FeedConfig {
    /// Services allowed to publish.
    pub publishers: Vec<String>,
    /// Services allowed to follow.
    pub subscribers: Vec<String>,
    /// The cell (Enforcement's public key is read from it).
    pub cell: PathBuf,
    /// Where events are kept.
    pub data: PathBuf,
    /// The Transparency Log, as this service ("revocation") appends to it.
    pub log: Option<LogLink>,
}

/// The feed's connection to the Transparency Log.
pub struct LogLink {
    endpoint: fpp_svc::quinn::Endpoint,
    addr: SocketAddr,
    conn: Mutex<Option<fpp_svc::quinn::Connection>>,
}

impl LogLink {
    pub fn new(identity: &fpp_svc::Identity, addr: SocketAddr) -> Result<Self> {
        Ok(Self {
            endpoint: fpp_svc::mtls::client_endpoint(identity)?,
            addr,
            conn: Mutex::new(None),
        })
    }

    /// Append one entry; its index in the log.
    pub async fn append(&self, entry: Vec<u8>) -> Result<u64> {
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
            fpp_svc::call(&conn, &svc_log::Request::Add(vec![entry])),
        )
        .await
        .map_err(|_| anyhow!("Transparency Log timed out"));
        match answer {
            Ok(Ok(svc_log::Response::Added(added))) if added.len() == 1 => Ok(added[0].0),
            Ok(Ok(other)) => Err(anyhow!("Transparency Log: {other:?}")),
            Ok(Err(e)) | Err(e) => {
                *guard = None;
                Err(e)
            }
        }
    }
}

struct State {
    events: Vec<Vec<u8>>,
    ids: HashMap<[u8; 16], u64>,
    file: std::fs::File,
}

pub struct Feed {
    config: FeedConfig,
    state: Mutex<State>,
    /// Number of events, for waiting subscribers.
    len: watch::Sender<u64>,
    enforcement: Mutex<Option<KeySet>>,
}

/// Events kept in `path`: `u32le(len) ‖ bytes`, in order. A torn last
/// record (a crash while writing) is dropped.
fn load(path: &Path) -> Result<Vec<Vec<u8>>> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
    };
    let mut out = Vec::new();
    let mut at = 0;
    while at + 4 <= bytes.len() {
        let len = u32::from_le_bytes(bytes[at..at + 4].try_into().expect("4 bytes")) as usize;
        if len > MAX_EVENT || at + 4 + len > bytes.len() {
            break;
        }
        out.push(bytes[at + 4..at + 4 + len].to_vec());
        at += 4 + len;
    }
    Ok(out)
}

impl Feed {
    pub fn open(config: FeedConfig) -> Result<Arc<Self>> {
        std::fs::create_dir_all(&config.data)?;
        let path = config.data.join("events");
        let events = load(&path)?;
        // rewrite without a torn tail
        let mut file = std::fs::File::create(&path)?;
        for e in &events {
            file.write_all(&(e.len() as u32).to_le_bytes())?;
            file.write_all(e)?;
        }
        file.sync_all()?;
        let mut ids = HashMap::new();
        // (each was verified when it was published)
        for (seq, e) in events.iter().enumerate() {
            let event = fpp_wire::cose::Sign1::decode(e)
                .and_then(|s| <RevocationEvent as fpp_wire::Payload>::from_cbor(&s.payload));
            if let Ok(ev) = event {
                ids.insert(ev.id, seq as u64);
            }
        }
        let (len, _) = watch::channel(events.len() as u64);
        Ok(Arc::new(Self {
            config,
            state: Mutex::new(State { events, ids, file }),
            len,
            enforcement: Mutex::new(None),
        }))
    }

    pub fn len(&self) -> u64 {
        *self.len.borrow()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    async fn enforcement_keys(&self) -> Result<KeySet> {
        let mut guard = self.enforcement.lock().await;
        if guard.is_none() {
            let public = fpp_svc::PublicKeys::read(&self.config.cell, "enforcement")?;
            let key = VerifyingKey::from_bytes(&public.ed25519)
                .map_err(|_| anyhow!("Enforcement's published key is invalid"))?;
            let mut keys = KeySet::default();
            keys.insert_ed25519(KeyRole::Enforcement, key);
            *guard = Some(keys);
        }
        Ok(guard.clone().expect("set above"))
    }

    /// Publish one signed event.
    pub async fn publish(&self, cose: Vec<u8>) -> Result<(u64, Option<u64>)> {
        if cose.len() > MAX_EVENT {
            return Err(anyhow!("event too large"));
        }
        let keys = self.enforcement_keys().await?;
        let event = fpp_crypto::verify::<RevocationEvent>(&cose, &keys)
            .map_err(|e| anyhow!("not a revocation event signed by Enforcement: {e}"))?
            .payload;
        // One event at a time, so the log order is the feed order.
        let mut state = self.state.lock().await;
        if let Some(seq) = state.ids.get(&event.id) {
            return Ok((*seq, None));
        }
        let log_index = match &self.config.log {
            Some(log) => Some(log.append(cose.clone()).await?),
            None => None,
        };
        state.file.write_all(&(cose.len() as u32).to_le_bytes())?;
        state.file.write_all(&cose)?;
        state.file.sync_data()?;
        let seq = state.events.len() as u64;
        state.events.push(cose);
        state.ids.insert(event.id, seq);
        self.len.send_replace(seq + 1);
        println!(
            "[revocation] #{seq}: {:?} {:?} {}..{}",
            event.action,
            event.subject_kind,
            hex::encode(&event.subject_id[..4]),
            log_index
                .map(|i| format!(" (log index {i})"))
                .unwrap_or_default()
        );
        Ok((seq, log_index))
    }

    /// Events from `from` on, waiting up to `wait` for one.
    pub async fn since(&self, from: u64, wait: Duration) -> Vec<(u64, Vec<u8>)> {
        let mut rx = self.len.subscribe();
        let _ = tokio::time::timeout(wait, rx.wait_for(|n| *n > from)).await;
        let state = self.state.lock().await;
        state
            .events
            .iter()
            .enumerate()
            .skip(from as usize)
            .take(MAX_BATCH)
            .map(|(seq, e)| (seq as u64, e.clone()))
            .collect()
    }

    async fn handle(self: Arc<Self>, caller: Caller, request: Request) -> Response {
        match request {
            Request::Publish(cose) => {
                if !caller.is(&self.config.publishers) {
                    return Response::Refused(format!("{} may not publish", caller.0));
                }
                match self.publish(cose).await {
                    Ok((seq, log_index)) => Response::Published { seq, log_index },
                    Err(e) => Response::Refused(format!("{e:#}")),
                }
            }
            Request::Since { from, wait_ms } => {
                if !caller.is(&self.config.subscribers) {
                    return Response::Refused(format!("{} may not follow the feed", caller.0));
                }
                let wait = Duration::from_millis(wait_ms.min(MAX_WAIT_MS));
                Response::Events(self.since(from, wait).await)
            }
        }
    }

    /// Serve the feed on `endpoint` (mutual TLS) until it closes.
    pub async fn serve(self: Arc<Self>, endpoint: fpp_svc::quinn::Endpoint) {
        fpp_svc::serve(endpoint, move |caller: Caller, request: Request| {
            self.clone().handle(caller, request)
        })
        .await
    }
}
