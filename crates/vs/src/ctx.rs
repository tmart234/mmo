// crates/vs/src/ctx.rs
use common::config::VsConfig;
use common::proto::Heartbeat;
use dashmap::DashMap;
use ed25519_dalek::SigningKey;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::Notify;

#[derive(Clone)]
pub struct VsCtx {
    pub vs_sk: Arc<SigningKey>,
    pub sessions: Arc<DashMap<[u8; 16], Session>>,
    pub config: VsConfig,
}

#[derive(Clone)]
pub struct Session {
    pub ephemeral_pub: [u8; 32],
    pub last_counter: u64,
    pub last_seen_ms: u64,
    pub revoked: bool,

    // For ProtectedReceipt de-dup / tidy logs
    pub last_pr_counter: Option<u64>,
    pub last_pr_tip: [u8; 32],

    /// Fix 2 (Tick Synchronization): staging area for Heartbeats that have
    /// arrived on the uni-stream but whose matching TranscriptDigest bi-stream
    /// has not yet been processed.  Keyed by gs_counter.
    ///
    /// The bi-stream handler waits here (with a timeout) before calling the
    /// enforcer, guaranteeing that receipt_tip and snapshot_root from the
    /// *signed* Heartbeat are always available when on_transcript() runs.
    /// This closes the Premature Notarization exploit where a TranscriptDigest
    /// could arrive and be receipted before the Heartbeat signature was verified.
    pub staged_hbs: Arc<Mutex<HashMap<u64, Heartbeat>>>,

    /// Notified whenever a new Heartbeat is staged into `staged_hbs`, waking
    /// any bi-stream handlers that are waiting for their matching HB.
    pub hb_notify: Arc<Notify>,
}

impl VsCtx {
    pub fn new(vs_sk: Arc<SigningKey>) -> Self {
        Self::new_with_config(vs_sk, VsConfig::default())
    }

    pub fn new_with_config(vs_sk: Arc<SigningKey>, config: VsConfig) -> Self {
        Self {
            vs_sk,
            sessions: Arc::new(DashMap::new()),
            config,
        }
    }
}
