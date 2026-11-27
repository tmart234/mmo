//! Bounded per-client economy idempotency cache and token bucket rate limiter
//! (owned directly with `std::collections`, zero `lru` dependency).

use crate::game_wire::OpId;
use std::collections::{HashMap, VecDeque};

/// Maximum number of processed operations to track.
/// Sized to cover ~10 minutes of rapid operations at 10 ops/sec.
const OP_CACHE_SIZE: usize = 6000;

#[derive(Hash, Eq, PartialEq, Clone, Copy, Debug)]
pub enum CmdKey {
    Move,
}

/// Result of a processed economy operation (for idempotent replay).
#[derive(Clone, Debug)]
pub struct OpResult {
    /// Unix timestamp when this op was processed
    pub processed_at_ms: u64,
    /// Whether the operation succeeded
    pub success: bool,
}

#[derive(Debug)]
pub struct PlayerRuntime {
    pub buckets: HashMap<([u8; 32], CmdKey), TokenBucket>,

    /// Bounded idempotency cache keyed by `(client_pub, op_id)` to prevent
    /// cross-client interference and memory exhaustion.
    processed_ops: HashMap<([u8; 32], OpId), OpResult>,
    order: VecDeque<([u8; 32], OpId)>,
}

impl PlayerRuntime {
    pub fn new() -> Self {
        Self {
            buckets: HashMap::new(),
            processed_ops: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    /// Check if an operation has already been processed for this client.
    /// Returns `Some(&OpResult)` if already processed (replay), `None` if new.
    pub fn check_idempotency(&mut self, client_pub: &[u8; 32], op_id: &OpId) -> Option<&OpResult> {
        self.processed_ops.get(&(*client_pub, *op_id))
    }

    /// Record that an operation was processed, evicting the oldest entry once
    /// the cache reaches `OP_CACHE_SIZE`.
    pub fn record_op(&mut self, client_pub: [u8; 32], op_id: OpId, result: OpResult) {
        let key = (client_pub, op_id);
        if let Some(slot) = self.processed_ops.get_mut(&key) {
            *slot = result;
            return;
        }
        if self.processed_ops.len() >= OP_CACHE_SIZE {
            if let Some(oldest) = self.order.pop_front() {
                self.processed_ops.remove(&oldest);
            }
        }
        self.processed_ops.insert(key, result);
        self.order.push_back(key);
    }
}

impl Default for PlayerRuntime {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct TokenBucket {
    capacity: f32,
    tokens: f32,
    refill_per_ms: f32,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_idempotency_cache() {
        let mut runtime = PlayerRuntime::new();
        let client_pub = [0xAA; 32];
        let op_id = [0xBB; 16];

        assert!(runtime.check_idempotency(&client_pub, &op_id).is_none());
        runtime.record_op(
            client_pub,
            op_id,
            OpResult {
                processed_at_ms: 1000,
                success: true,
            },
        );
        let result = runtime.check_idempotency(&client_pub, &op_id);
        assert!(result.is_some());
        assert!(result.unwrap().success);
    }

    #[test]
    fn test_idempotency_per_client_isolation() {
        let mut runtime = PlayerRuntime::new();
        let client_a = [0xAA; 32];
        let client_b = [0xBB; 32];
        let op_id = [0xCC; 16];

        runtime.record_op(
            client_a,
            op_id,
            OpResult {
                processed_at_ms: 1000,
                success: true,
            },
        );
        assert!(runtime.check_idempotency(&client_b, &op_id).is_none());
    }
}
