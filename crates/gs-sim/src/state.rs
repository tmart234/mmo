use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use common::proto::PlayTicket;
use ed25519_dalek::VerifyingKey;

use crate::ledger::Ledger;

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

#[derive(Debug)]
pub struct PlayerRuntime {
    pub buckets: HashMap<([u8; 32], CmdKey), TokenBucket>,
    // future: recent_ops LRU for idempotency
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
