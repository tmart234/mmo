//! Enforcement (03 §3): decide, record, revoke. An enforcement record says
//! who is acted on, how and why; it goes into the Transparency Log (when
//! the cell has one), and the `RevocationEvent` that carries it out names
//! its hash, signed with the Enforcement key, and goes to the feed.
//!
//! The Enforcement key lives in `<cell>/enforcement/` and nowhere else; the
//! feed and every relying party check its signature.

use crate::LogLink;
use anyhow::{anyhow, Context, Result};
use fpp_crypto::Ed25519Signer;
use fpp_svc::api::revocation::{Request, Response};
use fpp_types::Digest;
use fpp_wire::{Action, RevocationEvent, Scope, SubjectKind};
use rand::RngCore;
use sha2::{Digest as _, Sha256};
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;
use tokio::sync::Mutex;

/// Name under which Enforcement publishes its key.
pub const ENFORCEMENT_NAME: &str = "enforcement.dev";

/// One decision.
#[derive(Clone, Debug)]
pub struct Order {
    pub subject_kind: SubjectKind,
    pub subject_id: Vec<u8>,
    pub action: Action,
    pub scope: Scope,
    /// `fpp_types::Reason` code.
    pub reason: u16,
    /// How long it lasts (none: until revoked otherwise).
    pub duration_s: Option<u64>,
    /// Why, for the record (and an appeal).
    pub note: String,
}

/// What an order became.
#[derive(Clone, Debug)]
pub struct Enforced {
    pub event: RevocationEvent,
    pub signed: Vec<u8>,
    /// Sequence number in the feed.
    pub seq: u64,
    /// Index of the enforcement record in the Transparency Log.
    pub record_index: Option<u64>,
}

pub struct Enforcer {
    key: Ed25519Signer,
    endpoint: fpp_svc::quinn::Endpoint,
    feed: SocketAddr,
    conn: Mutex<Option<fpp_svc::quinn::Connection>>,
    log: Option<LogLink>,
}

fn now_s() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl Enforcer {
    /// The Enforcement key in `cell` (made on first use, its public half
    /// published), calling the feed at `feed` and the log at `log`.
    pub fn open(cell: &Path, feed: SocketAddr, log: Option<SocketAddr>) -> Result<Self> {
        let key = fpp_svc::keys::ed25519(cell, "enforcement", ENFORCEMENT_NAME)?;
        let identity = fpp_svc::cell::load(cell, "enforcement")?;
        Ok(Self {
            key: Ed25519Signer::new(key),
            endpoint: fpp_svc::mtls::client_endpoint(&identity)?,
            feed,
            conn: Mutex::new(None),
            log: log.map(|a| LogLink::new(&identity, a)).transpose()?,
        })
    }

    /// Make only the key (and publish its public half).
    pub fn init(cell: &Path) -> Result<ed25519_dalek::VerifyingKey> {
        Ok(fpp_svc::keys::ed25519(cell, "enforcement", ENFORCEMENT_NAME)?.verifying_key())
    }

    async fn call(&self, request: &Request) -> Result<Response> {
        let mut guard = self.conn.lock().await;
        let conn = match guard.as_ref().filter(|c| c.close_reason().is_none()) {
            Some(c) => c.clone(),
            None => {
                let c = tokio::time::timeout(
                    Duration::from_secs(5),
                    fpp_svc::mtls::connect(&self.endpoint, self.feed, "revocation"),
                )
                .await
                .map_err(|_| anyhow!("Revocation Feed unreachable"))??;
                *guard = Some(c.clone());
                c
            }
        };
        let answer = tokio::time::timeout(Duration::from_secs(15), fpp_svc::call(&conn, request))
            .await
            .map_err(|_| anyhow!("Revocation Feed timed out"))
            .and_then(|r| r);
        if answer.is_err() {
            *guard = None;
        }
        answer
    }

    /// Record the order, then sign and publish its event.
    pub async fn enforce(&self, order: Order) -> Result<Enforced> {
        if order.subject_id.len() != order.subject_kind.id_len() {
            return Err(anyhow!(
                "a {:?} id is {} bytes",
                order.subject_kind,
                order.subject_kind.id_len()
            ));
        }
        let now = now_s();
        let record = serde_json::to_vec(&serde_json::json!({
            "subject": {"kind": format!("{:?}", order.subject_kind), "id": hex::encode(&order.subject_id)},
            "action": format!("{:?}", order.action),
            "reason": order.reason,
            "at": now,
            "duration_s": order.duration_s,
            "note": order.note,
        }))?;
        let record_index = match &self.log {
            Some(log) => Some(
                log.append(vec![record.clone()])
                    .await
                    .context("log the record")?,
            ),
            None => None,
        };
        let mut id = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut id);
        let event = RevocationEvent {
            id,
            subject_kind: order.subject_kind,
            subject_id: order.subject_id,
            action: order.action,
            scope: order.scope,
            effective_at: now,
            expires_at: order.duration_s.map(|d| now + d.max(1)),
            reason: order.reason,
            record: Digest(Sha256::digest(&record).into()),
        };
        let signed = fpp_crypto::sign(&self.key, &event);
        match self.call(&Request::Publish(signed.clone())).await? {
            Response::Published { seq, .. } => Ok(Enforced {
                event,
                signed,
                seq,
                record_index,
            }),
            other => Err(anyhow!("the feed refused: {other:?}")),
        }
    }
}
