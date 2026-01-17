use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use common::proto::{OpId, PlayTicket};
use ed25519_dalek::VerifyingKey;
use lru::LruCache;
use std::num::NonZeroUsize;

use crate::ledger::Ledger;

/// Maximum number of processed operations to track per player.
/// Sized to cover ~10 minutes of rapid operations at 10 ops/sec.
const OP_CACHE_SIZE: usize = 6000;

#[derive(Hash, Eq, PartialEq, Clone, Copy, Debug)]
pub enum CmdKey {
    Move, // future: Econ, Craft, etc.
}

/// Per-player world state tracked by GS.
#[derive(Clone, Copy, Debug, Default)]
pub struct PlayerState {
    pub x: f32,
    pub y: f32,
    pub last_nonce: u64,
}

/// Result of a processed economy operation (for idempotent replay).
#[derive(Clone, Debug)]
pub struct OpResult {
    /// Unix timestamp when this op was processed
    pub processed_at_ms: u64,
    /// Whether the operation succeeded
    pub success: bool,
    /// Balance after operation (if applicable) - used for idempotent response
    #[allow(dead_code)]
    pub balance_after: Option<u64>,
}

#[derive(Debug)]
pub struct PlayerRuntime {
    pub buckets: HashMap<([u8; 32], CmdKey), TokenBucket>,

    /// Stage 1.1: LRU cache for economy operation idempotency.
    /// Key: (client_pub, op_id) to prevent cross-client interference.
    /// Value: Result of the operation for proper idempotent responses.
    ///
    /// Why (client_pub, op_id) instead of just op_id?
    /// - Prevents DoS where attacker pre-populates op_ids to block legitimate users
    /// - Each client has their own namespace of operation IDs
    pub processed_ops: LruCache<([u8; 32], OpId), OpResult>,
}

impl PlayerRuntime {
    pub fn new() -> Self {
        Self {
            buckets: HashMap::new(),
            processed_ops: LruCache::new(
                NonZeroUsize::new(OP_CACHE_SIZE).expect("OP_CACHE_SIZE must be > 0"),
            ),
        }
    }

    /// Check if an operation has already been processed for this client.
    /// Returns Some(OpResult) if already processed (replay), None if new.
    pub fn check_idempotency(&mut self, client_pub: &[u8; 32], op_id: &OpId) -> Option<&OpResult> {
        self.processed_ops.get(&(*client_pub, *op_id))
    }

    /// Record that an operation was processed.
    pub fn record_op(&mut self, client_pub: [u8; 32], op_id: OpId, result: OpResult) {
        self.processed_ops.put((client_pub, op_id), result);
    }
}

impl Default for PlayerRuntime {
    fn default() -> Self {
        Self::new()
    }
}

/// Global mutable GS session state shared across tasks.
/// Wrapped as `Shared = Arc<Mutex<GsShared>>`.
#[derive(Debug)]
pub struct GsShared {
    // Session basics
    pub session_id: [u8; 16],
    pub vs_pub: VerifyingKey,
    pub sw_hash: [u8; 32], // included so heartbeat can attach it

    // Rolling transcript tip advertised in heartbeats
    pub receipt_tip: [u8; 32],

    // Tickets (supporting rollover grace)
    pub latest_ticket: Option<PlayTicket>,
    pub prev_ticket: Option<PlayTicket>,
    pub last_ticket_ms: u64,

    // World state
    pub players: HashMap<[u8; 32], PlayerState>,

    // Trust state
    pub revoked: bool,

    // Economy/audit (initialized on first use)
    pub ledger: Option<Ledger>,

    // Runtime buckets / guards (initialized on first use)
    pub runtime: Option<PlayerRuntime>,
}

impl GsShared {
    pub fn new(session_id: [u8; 16], vs_pub: VerifyingKey, sw_hash: [u8; 32]) -> Self {
        Self {
            session_id,
            vs_pub,
            sw_hash,
            receipt_tip: [0u8; 32],

            latest_ticket: None,
            prev_ticket: None,
            last_ticket_ms: 0,

            players: HashMap::new(),
            revoked: false,

            ledger: None,
            runtime: None,
        }
    }

    /// Get or initialize the player runtime (lazy init).
    pub fn runtime_mut(&mut self) -> &mut PlayerRuntime {
        self.runtime.get_or_insert_with(PlayerRuntime::new)
    }
}

#[derive(Debug, Clone)]
pub struct TokenBucket {
    capacity: f32,
    tokens: f32,
    refill_per_ms: f32, // tokens per ms
    last_ms: u64,
}

impl TokenBucket {
    pub fn new(capacity: f32, refill_per_sec: f32, now_ms: u64) -> Self {
        Self {
            capacity,
            tokens: capacity,
            refill_per_ms: refill_per_sec / 1000.0,
            last_ms: now_ms,
        }
    }
    pub fn take(&mut self, cost: f32, now_ms: u64) -> bool {
        // refill first
        if now_ms > self.last_ms {
            let dt = (now_ms - self.last_ms) as f32;
            self.tokens = (self.tokens + dt * self.refill_per_ms).min(self.capacity);
            self.last_ms = now_ms;
        }
        if self.tokens >= cost {
            self.tokens -= cost;
            true
        } else {
            false
        }
    }
}

pub type Shared = Arc<Mutex<GsShared>>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_idempotency_cache() {
        let mut runtime = PlayerRuntime::new();
        let client_pub = [0xAA; 32];
        let op_id = [0xBB; 16];

        // First check: should be None (new operation)
        assert!(runtime.check_idempotency(&client_pub, &op_id).is_none());

        // Record the operation
        runtime.record_op(
            client_pub,
            op_id,
            OpResult {
                processed_at_ms: 1000,
                success: true,
                balance_after: Some(100),
            },
        );

        // Second check: should return the result (replay detected)
        let result = runtime.check_idempotency(&client_pub, &op_id);
        assert!(result.is_some());
        assert_eq!(result.unwrap().balance_after, Some(100));
    }

    #[test]
    fn test_idempotency_per_client_isolation() {
        let mut runtime = PlayerRuntime::new();
        let client_a = [0xAA; 32];
        let client_b = [0xBB; 32];
        let op_id = [0xCC; 16]; // Same op_id

        // Client A records an op
        runtime.record_op(
            client_a,
            op_id,
            OpResult {
                processed_at_ms: 1000,
                success: true,
                balance_after: Some(100),
            },
        );

        // Client B with same op_id should NOT be blocked
        assert!(runtime.check_idempotency(&client_b, &op_id).is_none());
    }
}
