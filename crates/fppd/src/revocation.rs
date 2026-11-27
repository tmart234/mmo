//! Revocation Feed and Enforcement order builder (04 §9, P2.2).
//!
//! Every `RevocationEvent` must verify under the isolated Enforcement key,
//! is appended to the Transparency Log BEFORE acceptance, persisted on disk,
//! and broadcast immediately to Broker and Server Liveness (and relayed to
//! connected game servers). Enforcement records are encoded in deterministic
//! CBOR (`fpp::wire::cbor`), removing `serde_json`.

use crate::tlog::LogEngine;
use anyhow::{anyhow, Context, Result};
use ed25519_dalek::VerifyingKey;
use fpp::control::{RevocationRequest, RevocationResponse};
use fpp::crypto::{self, now_s, sha256, Ed25519Signer, KeyRole, KeySet};
use fpp::types::Digest;
use fpp::wire::cbor::{self, text_map, Value};
use fpp::wire::{Action, RevocationEvent, Scope, SubjectKind};
use rand::RngCore;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, watch, Mutex};

const MAX_BATCH: usize = 256;

/// One Enforcement decision.
#[derive(Clone, Debug)]
pub struct Order {
    pub subject_kind: SubjectKind,
    pub subject_id: Vec<u8>,
    pub action: Action,
    pub scope: Scope,
    pub reason: u16,
    pub duration_s: Option<u64>,
    pub note: String,
}

/// Encode an immutable enforcement record in deterministic CBOR (logged in the Transparency Log).
pub fn encode_enforcement_record(order: &Order, at: u64) -> Vec<u8> {
    let mut fields = vec![
        ("action", Value::text(format!("{:?}", order.action))),
        ("at", Value::Unsigned(at)),
        ("note", Value::text(&order.note)),
        ("reason", Value::Unsigned(order.reason.into())),
        ("subject_id", Value::bytes(order.subject_id.clone())),
        (
            "subject_kind",
            Value::text(format!("{:?}", order.subject_kind)),
        ),
    ];
    if let Some(d) = order.duration_s {
        fields.push(("duration_s", Value::Unsigned(d)));
    }
    cbor::encode(&text_map(fields)).expect("enforcement record CBOR encodes")
}

/// Sign a [`RevocationEvent`] for `order` referencing `record_bytes`.
pub fn sign_order(
    key: &Ed25519Signer,
    order: &Order,
    record_bytes: &[u8],
    now: u64,
) -> Result<(RevocationEvent, Vec<u8>)> {
    if order.subject_id.len() != order.subject_kind.id_len() {
        return Err(anyhow!(
            "a {:?} id is {} bytes",
            order.subject_kind,
            order.subject_kind.id_len()
        ));
    }
    let mut id = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut id);
    let event = RevocationEvent {
        id,
        subject_kind: order.subject_kind,
        subject_id: order.subject_id.clone(),
        action: order.action,
        scope: order.scope.clone(),
        effective_at: now,
        expires_at: order.duration_s.map(|d| now + d.max(1)),
        reason: order.reason,
        record: Digest(sha256(record_bytes)),
    };
    let signed = crypto::sign(key, &event);
    Ok((event, signed))
}

struct FeedState {
    events: Vec<(RevocationEvent, Vec<u8>)>,
    ids: HashMap<[u8; 16], u64>,
    file: File,
}

/// Durable, Transparency-Logged Revocation Feed with real-time in-process broadcast.
pub struct RevocationFeed {
    keys: KeySet,
    log: Option<Arc<LogEngine>>,
    state: Mutex<FeedState>,
    len: watch::Sender<u64>,
    tx: broadcast::Sender<(RevocationEvent, Vec<u8>)>,
}

impl RevocationFeed {
    pub fn open(
        path: &Path,
        enforcement_key: VerifyingKey,
        log: Option<Arc<LogEngine>>,
    ) -> Result<Self> {
        let mut keys = KeySet::default();
        keys.insert_ed25519(KeyRole::Enforcement, enforcement_key);
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let mut events = Vec::new();
        let mut ids = HashMap::new();
        if path.exists() {
            let mut r = File::open(path).with_context(|| format!("open {}", path.display()))?;
            let mut len_buf = [0u8; 4];
            loop {
                match r.read_exact(&mut len_buf) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                    Err(e) => return Err(e.into()),
                }
                let n = u32::from_le_bytes(len_buf) as usize;
                if n > 64 * 1024 {
                    return Err(anyhow!("revocation log corrupt: frame {n} bytes"));
                }
                let mut cose = vec![0u8; n];
                r.read_exact(&mut cose)?;
                let verified = crypto::verify::<RevocationEvent>(&cose, &keys)
                    .map_err(|e| anyhow!("stored revocation event failed verify: {e:?}"))?;
                let seq = events.len() as u64;
                ids.insert(verified.payload.id, seq);
                events.push((verified.payload, cose));
            }
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        let initial_len = events.len() as u64;
        let (len, _) = watch::channel(initial_len);
        let (tx, _) = broadcast::channel(1024);
        Ok(Self {
            keys,
            log,
            state: Mutex::new(FeedState { events, ids, file }),
            len,
            tx,
        })
    }

    pub fn subscribe(&self) -> broadcast::Receiver<(RevocationEvent, Vec<u8>)> {
        self.tx.subscribe()
    }

    pub async fn all_events(&self) -> Vec<(RevocationEvent, Vec<u8>)> {
        self.state.lock().await.events.clone()
    }

    /// Verify Enforcement's signature, log to Transparency Log FIRST, persist, and broadcast.
    pub async fn publish(&self, cose: Vec<u8>) -> Result<(u64, Option<u64>)> {
        let verified = crypto::verify::<RevocationEvent>(&cose, &self.keys)
            .map_err(|e| anyhow!("invalid RevocationEvent: {e:?}"))?;
        let event = verified.payload;
        let mut state = self.state.lock().await;
        if let Some(&seq) = state.ids.get(&event.id) {
            return Ok((seq, None));
        }
        let log_index = match &self.log {
            Some(log) => {
                let added = log.append(std::slice::from_ref(&cose)).await?;
                added.first().map(|(i, _)| *i)
            }
            None => None,
        };
        state.file.write_all(&(cose.len() as u32).to_le_bytes())?;
        state.file.write_all(&cose)?;
        state.file.sync_data()?;
        let seq = state.events.len() as u64;
        state.ids.insert(event.id, seq);
        state.events.push((event.clone(), cose.clone()));
        self.len.send_replace(seq + 1);
        let _ = self.tx.send((event.clone(), cose));
        println!(
            "[revocation] #{seq}: {:?} {:?} {}..{}",
            event.action,
            event.subject_kind,
            hex::encode(&event.subject_id[..4.min(event.subject_id.len())]),
            log_index
                .map(|i| format!(" (log index {i})"))
                .unwrap_or_default()
        );
        Ok((seq, log_index))
    }

    /// Record an enforcement order directly (log record -> sign event -> publish).
    pub async fn enforce(
        &self,
        key: &Ed25519Signer,
        order: Order,
    ) -> Result<(RevocationEvent, Vec<u8>, u64)> {
        let now = now_s();
        let record = encode_enforcement_record(&order, now);
        if let Some(log) = &self.log {
            let _ = log.append(std::slice::from_ref(&record)).await?;
        }
        let (event, signed) = sign_order(key, &order, &record, now)?;
        let (seq, _) = self.publish(signed.clone()).await?;
        Ok((event, signed, seq))
    }

    /// Long-poll events starting at `from`.
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
            .map(|(seq, (_, cose))| (seq as u64, cose.clone()))
            .collect()
    }

    pub async fn handle_rpc(
        &self,
        req: RevocationRequest,
        can_publish: bool,
        can_subscribe: bool,
    ) -> RevocationResponse {
        match req {
            RevocationRequest::Publish(cose) => {
                if !can_publish {
                    return RevocationResponse::Refused(
                        "caller may not publish revocations".into(),
                    );
                }
                match self.publish(cose).await {
                    Ok((seq, log_index)) => RevocationResponse::Published { seq, log_index },
                    Err(e) => RevocationResponse::Refused(e.to_string()),
                }
            }
            RevocationRequest::Since { from, wait_ms } => {
                if !can_subscribe {
                    return RevocationResponse::Refused("caller may not follow revocations".into());
                }
                let wait = Duration::from_millis(wait_ms.min(30_000));
                RevocationResponse::Events(self.since(from, wait).await)
            }
        }
    }
}
