//! FPP v1 signed payloads (04-protocol.md §7.4, §8.1).
//!
//! Each payload type is bound to one `fpp-ctx` and content type, so a
//! signature over one kind of object can never be accepted as another.

use crate::cbor::{self, text_map, MapView, Value};
use crate::WireError;
use fpp_types::{content_type, ctx, BuildId, Digest, GsInstanceId, MatchId};

/// A CBOR payload bound to one domain-separation context.
pub trait Payload: Sized {
    const CTX: &'static str;
    const CONTENT_TYPE: &'static str;

    fn to_value(&self) -> Value;
    fn from_value(v: &Value) -> Result<Self, WireError>;

    fn to_cbor(&self) -> Vec<u8> {
        cbor::encode(&self.to_value()).expect("payload maps have unique keys")
    }

    fn from_cbor(bytes: &[u8]) -> Result<Self, WireError> {
        Self::from_value(&cbor::decode(bytes)?)
    }
}

fn digest(d: &Digest) -> Value {
    Value::bytes(d.0.to_vec())
}

/// Leaf data for one input frame in an `InputCommit`'s `frames_root`:
/// `u32le(tick) ‖ payload`. The Merkle leaf hash adds the RFC 9162 `0x00` prefix.
pub fn frame_leaf_data(tick: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&tick.to_le_bytes());
    out.extend_from_slice(payload);
    out
}

/// Client-signed commitment to its input frames for one epoch (§7.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputCommit {
    pub match_id: MatchId,
    pub slot: u16,
    pub epoch: u32,
    pub first_tick: u32,
    pub last_tick: u32,
    /// Frames the client sent in the epoch.
    pub n: u32,
    /// Merkle root over `frame_leaf_data`, ascending tick.
    pub frames_root: Digest,
    /// SHA-256 of the previous signed InputCommit; zeros at epoch 0.
    pub prev: Digest,
}

impl Payload for InputCommit {
    const CTX: &'static str = ctx::INPUT_COMMIT;
    const CONTENT_TYPE: &'static str = content_type::INPUT_COMMIT;

    fn to_value(&self) -> Value {
        text_map([
            ("match_id", Value::bytes(self.match_id.0.to_vec())),
            ("slot", Value::Unsigned(self.slot.into())),
            ("epoch", Value::Unsigned(self.epoch.into())),
            ("first_tick", Value::Unsigned(self.first_tick.into())),
            ("last_tick", Value::Unsigned(self.last_tick.into())),
            ("n", Value::Unsigned(self.n.into())),
            ("frames_root", digest(&self.frames_root)),
            ("prev", digest(&self.prev)),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, WireError> {
        const WHAT: &str = "InputCommit";
        let m = MapView::new(v, WHAT)?;
        let commit = Self {
            match_id: MatchId(m.fixed("match_id")?),
            slot: m.u16("slot")?,
            epoch: m.u32("epoch")?,
            first_tick: m.u32("first_tick")?,
            last_tick: m.u32("last_tick")?,
            n: m.u32("n")?,
            frames_root: Digest(m.fixed("frames_root")?),
            prev: Digest(m.fixed("prev")?),
        };
        if commit.first_tick > commit.last_tick {
            return Err(WireError::Schema(WHAT, "first_tick > last_tick"));
        }
        if u64::from(commit.n) > u64::from(commit.last_tick - commit.first_tick) + 1 {
            return Err(WireError::Schema(WHAT, "more frames than ticks"));
        }
        Ok(commit)
    }
}

/// One slot's entry under a Checkpoint's `inputs_root` (§8.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputLeaf {
    pub slot: u16,
    /// SHA-256 of the client's signed InputCommit; `None` if none arrived.
    pub commit: Option<Digest>,
    /// Bitset over the epoch's ticks: bit i set = frame for tick
    /// `ticks[0] + i` was applied in time (LSB-first within each byte).
    pub applied: Vec<u8>,
}

impl InputLeaf {
    pub fn to_value(&self) -> Value {
        text_map([
            ("slot", Value::Unsigned(self.slot.into())),
            ("commit", self.commit.as_ref().map_or(Value::Null, digest)),
            ("applied", Value::bytes(self.applied.clone())),
        ])
    }

    pub fn from_value(v: &Value) -> Result<Self, WireError> {
        const WHAT: &str = "InputLeaf";
        let m = MapView::new(v, WHAT)?;
        let commit = match m.field("commit")? {
            Value::Null => None,
            other => Some(Digest(
                other
                    .as_bytes()
                    .and_then(|b| b.try_into().ok())
                    .ok_or(WireError::Schema(WHAT, "commit"))?,
            )),
        };
        Ok(Self {
            slot: m.u16("slot")?,
            commit,
            applied: m.bytes("applied")?.to_vec(),
        })
    }

    /// Leaf data under `inputs_root`: the deterministic CBOR of this leaf.
    pub fn leaf_data(&self) -> Vec<u8> {
        cbor::encode(&self.to_value()).expect("InputLeaf keys are unique")
    }
}

/// GS-instance-signed commitment per match per epoch (§8.1). Replaces the
/// prototype's former Heartbeat + TranscriptDigest pair with one object.
///
/// Every Merkle root is signed together with its leaf count: RFC 9162
/// inclusion proofs do not authenticate the tree size on their own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub match_id: MatchId,
    pub gs_instance_id: GsInstanceId,
    pub build_id: BuildId,
    pub policy_ver: u64,
    pub epoch: u32,
    /// Inclusive tick range.
    pub ticks: (u32, u32),
    /// SHA-256 of the previous signed Checkpoint; zeros at epoch 0.
    pub prev: Digest,
    /// Merkle root over `InputLeaf::leaf_data`, ascending slot; `inputs_n` leaves.
    pub inputs_root: Digest,
    pub inputs_n: u32,
    /// Merkle root over authoritative events in simulation order; `events_n` leaves.
    pub events_root: Digest,
    pub events_n: u32,
    /// Digest of the canonical audit-projection state at `ticks.1`.
    pub state_root: Digest,
    /// Merkle root over the epoch's VRF proofs; `rng_n` leaves.
    pub rng_root: Digest,
    pub rng_n: u32,
    /// Merkle root over admitted (slot, sat_cti, did); `roster_n` leaves.
    pub roster_root: Digest,
    pub roster_n: u32,
}

impl Payload for Checkpoint {
    const CTX: &'static str = ctx::CHECKPOINT;
    const CONTENT_TYPE: &'static str = content_type::CHECKPOINT;

    fn to_value(&self) -> Value {
        text_map([
            ("match_id", Value::bytes(self.match_id.0.to_vec())),
            (
                "gs_instance_id",
                Value::bytes(self.gs_instance_id.0.to_vec()),
            ),
            ("build_id", Value::bytes(self.build_id.0.to_vec())),
            ("policy_ver", Value::Unsigned(self.policy_ver)),
            ("epoch", Value::Unsigned(self.epoch.into())),
            (
                "ticks",
                Value::Array(vec![
                    Value::Unsigned(self.ticks.0.into()),
                    Value::Unsigned(self.ticks.1.into()),
                ]),
            ),
            ("prev", digest(&self.prev)),
            ("inputs_root", digest(&self.inputs_root)),
            ("inputs_n", Value::Unsigned(self.inputs_n.into())),
            ("events_root", digest(&self.events_root)),
            ("events_n", Value::Unsigned(self.events_n.into())),
            ("state_root", digest(&self.state_root)),
            ("rng_root", digest(&self.rng_root)),
            ("rng_n", Value::Unsigned(self.rng_n.into())),
            ("roster_root", digest(&self.roster_root)),
            ("roster_n", Value::Unsigned(self.roster_n.into())),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, WireError> {
        const WHAT: &str = "Checkpoint";
        let m = MapView::new(v, WHAT)?;
        let ticks = match m.field("ticks")?.as_array() {
            Some([a, b]) => (
                a.as_u64().and_then(|t| u32::try_from(t).ok()),
                b.as_u64().and_then(|t| u32::try_from(t).ok()),
            ),
            _ => (None, None),
        };
        let ticks = match ticks {
            (Some(a), Some(b)) if a <= b => (a, b),
            _ => return Err(WireError::Schema(WHAT, "ticks")),
        };
        Ok(Self {
            match_id: MatchId(m.fixed("match_id")?),
            gs_instance_id: GsInstanceId(m.fixed("gs_instance_id")?),
            build_id: BuildId(m.fixed("build_id")?),
            policy_ver: m.u64("policy_ver")?,
            epoch: m.u32("epoch")?,
            ticks,
            prev: Digest(m.fixed("prev")?),
            inputs_root: Digest(m.fixed("inputs_root")?),
            inputs_n: m.u32("inputs_n")?,
            events_root: Digest(m.fixed("events_root")?),
            events_n: m.u32("events_n")?,
            state_root: Digest(m.fixed("state_root")?),
            rng_root: Digest(m.fixed("rng_root")?),
            rng_n: m.u32("rng_n")?,
            roster_root: Digest(m.fixed("roster_root")?),
            roster_n: m.u32("roster_n")?,
        })
    }
}

/// Proof that the holder of a session key opened one specific secure channel
/// (04-protocol.md §5.2 `pop_sig`, §7.7). Signed with the session key under
/// `fpp/1/admit-pop`, so the key that later signs InputCommits is bound to
/// the channel its frames arrived on, and a relayed proof fails elsewhere.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmitPop {
    /// Channel type, e.g. [`AdmitPop::NOISE_IK`].
    pub channel: String,
    /// Channel binding. For `NOISE_IK`: host static key ‖ joiner static key.
    pub binding: Vec<u8>,
}

impl AdmitPop {
    /// Player-hosted sessions (fpp-session): Noise IK over UDP.
    pub const NOISE_IK: &'static str = "fpp-p2p/noise-ik";
    /// QUIC session plane: TLS exporter ‖ SHA-256(handshake, nonce, SAT cti).
    pub const QUIC_TLS: &'static str = "fpp/quic-tls";
    /// Longest accepted channel name.
    pub const MAX_CHANNEL: usize = 32;
    /// Accepted binding sizes (a 32-byte exporter up to two 32-byte keys).
    pub const BINDING_LEN: core::ops::RangeInclusive<usize> = 32..=64;
}

impl Payload for AdmitPop {
    const CTX: &'static str = ctx::ADMIT_POP;
    const CONTENT_TYPE: &'static str = content_type::ADMIT_POP;

    fn to_value(&self) -> Value {
        text_map([
            ("channel", Value::text(self.channel.clone())),
            ("binding", Value::bytes(self.binding.clone())),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, WireError> {
        const WHAT: &str = "AdmitPop";
        let m = MapView::new(v, WHAT)?;
        let channel = m
            .field("channel")?
            .as_text()
            .filter(|c| !c.is_empty() && c.len() <= Self::MAX_CHANNEL)
            .ok_or(WireError::Schema(WHAT, "channel"))?;
        let binding = m.bytes("binding")?;
        if !Self::BINDING_LEN.contains(&binding.len()) {
            return Err(WireError::Schema(WHAT, "binding"));
        }
        Ok(Self {
            channel: channel.to_owned(),
            binding: binding.to_vec(),
        })
    }
}

/// The Transparency Log's promise to include a leaf within `mmd_s` of
/// `timestamp` (04 §8.2). A log that breaks it is provably at fault: the
/// receipt is signed, and its tree heads are public.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogReceipt {
    /// SHA-256 of the log's public key.
    pub log_id: Digest,
    /// RFC 9162 leaf hash of the entry.
    pub leaf_hash: Digest,
    /// Unix seconds.
    pub timestamp: u64,
    /// Maximum merge delay, seconds.
    pub mmd_s: u64,
}

impl Payload for LogReceipt {
    const CTX: &'static str = ctx::LOG_RECEIPT;
    const CONTENT_TYPE: &'static str = content_type::LOG_RECEIPT;

    fn to_value(&self) -> Value {
        text_map([
            ("log_id", digest(&self.log_id)),
            ("leaf_hash", digest(&self.leaf_hash)),
            ("timestamp", Value::Unsigned(self.timestamp)),
            ("mmd_s", Value::Unsigned(self.mmd_s)),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, WireError> {
        let m = MapView::new(v, "LogReceipt")?;
        Ok(Self {
            log_id: Digest(m.fixed("log_id")?),
            leaf_hash: Digest(m.fixed("leaf_hash")?),
            timestamp: m.u64("timestamp")?,
            mmd_s: m.u64("mmd_s")?,
        })
    }
}
