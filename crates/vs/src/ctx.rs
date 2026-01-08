// crates/vs/src/ctx.rs
use common::config::VsConfig;
use dashmap::DashMap;
use ed25519_dalek::SigningKey;
use std::sync::Arc;

// Legacy constants for backwards compatibility - prefer using VsConfig
pub const JOIN_MAX_SKEW_MS: u64 = 30_000; // 30s (increased from 10s for cross-region)
#[allow(dead_code)]
pub const HEARTBEAT_TIMEOUT_MS: u64 = 30_000; // 30s (increased from 10s)

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
