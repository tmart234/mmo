//! Server Liveness's shared state: its key, config and admitted servers.

use crate::config::LivenessConfig;
use dashmap::DashMap;
use fpp_crypto::Ed25519Signer;
use fpp_types::Digest;
use std::sync::Arc;

/// Revocation events seen, each with its signed bytes.
pub type Revocations = Vec<(fpp_wire::RevocationEvent, Vec<u8>)>;

#[derive(Clone)]
pub struct Ctx {
    /// Signs SARs (Server Liveness role, 04 §4); made in this service's own
    /// cell directory.
    pub key: Arc<Ed25519Signer>,
    pub sessions: Arc<DashMap<[u8; 16], Session>>,
    pub config: LivenessConfig,
    /// Each admitted game server's link, for pushing revocation events.
    pub links: Arc<DashMap<[u8; 16], quinn::Connection>>,
    /// Revocation events seen so far (signed), sent to each game server
    /// as it joins.
    pub revocations: Arc<std::sync::Mutex<Revocations>>,
    /// Verified Checkpoints on their way to the Evidence Store (none: not kept).
    pub evidence: Option<tokio::sync::mpsc::UnboundedSender<([u8; 16], Vec<u8>)>>,
}

/// One admitted game server instance; its session id is also the id of the
/// match it hosts.
#[derive(Clone)]
pub struct Session {
    /// Instance key: signs Checkpoints; certified by every SAR.
    pub instance_pub: [u8; 32],
    /// fpp-session static key and address of the game port.
    pub noise_static: [u8; 32],
    pub game_addr: String,
    pub sw_hash: [u8; 32],
    pub last_seen_ms: u64,
    pub revoked: bool,
    /// Epoch and digest of the last verified Checkpoint (the `prev` chain).
    pub last_checkpoint: Option<(u32, Digest)>,
    /// Next player slot handed out (to the Broker) for this match.
    pub next_slot: u16,
}

impl Ctx {
    pub fn new(key: Ed25519Signer, config: LivenessConfig) -> Self {
        Self {
            key: Arc::new(key),
            sessions: Arc::new(DashMap::new()),
            config,
            links: Arc::new(DashMap::new()),
            revocations: Arc::default(),
            evidence: None,
        }
    }

    /// Send a verified Checkpoint of match `session_id` to the Evidence Store.
    pub fn keep_evidence(&self, session_id: [u8; 16], checkpoint: Vec<u8>) {
        if let Some(tx) = &self.evidence {
            let _ = tx.send((session_id, checkpoint));
        }
    }

    pub fn revoke(&self, session_id: &[u8; 16], why: &str) {
        if let Some(mut s) = self.sessions.get_mut(session_id) {
            if !s.revoked {
                s.revoked = true;
                eprintln!(
                    "[liveness] REVOKED session {}.. ({why}); no further SARs",
                    hex::encode(&session_id[..4])
                );
            }
        }
    }
}
