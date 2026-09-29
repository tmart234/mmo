//! Session-plane control messages (04-protocol.md §7.2), shared by both
//! transports (ADR-002): on QUIC they travel on the control stream, on
//! fpp-session as reliable-channel messages. Each is `[type, {fields}]` in
//! deterministic CBOR, capped at [`MAX_CONTROL`] bytes before decoding.

use fpp_types::{Digest, MatchId, Reason};
use fpp_wire::cbor::{self, text_map, MapView, Value};
use fpp_wire::{AdmitPop, WireError};
use sha2::{Digest as _, Sha256};

pub const MAX_CONTROL: usize = 64 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Control {
    Hello {
        versions: Vec<u64>,
        client_build_id: [u8; 32],
    },
    HelloAck {
        version: u64,
        sar: Vec<u8>,
        server_nonce: [u8; 32],
        tick_hz: u32,
        ticks_per_epoch: u32,
    },
    Admit {
        sat: Vec<u8>,
        ar: Vec<u8>,
        pop: Vec<u8>,
    },
    Admitted {
        slot: u16,
        start_tick: u32,
    },
    Reject {
        code: u16,
    },
    SarUpdate {
        sar: Vec<u8>,
    },
    Kick {
        code: u16,
    },
    Bye,
    /// §7.6: digest of the Checkpoint the server just signed.
    CheckpointHead {
        match_id: MatchId,
        epoch: u32,
        digest: Digest,
    },
    /// §7.4 over fpp-session: the client's signed InputCommit.
    InputCommit {
        commit: Vec<u8>,
    },
}

mod ty {
    pub const HELLO: u64 = 1;
    pub const HELLO_ACK: u64 = 2;
    pub const ADMIT: u64 = 3;
    pub const ADMITTED: u64 = 4;
    pub const REJECT: u64 = 5;
    pub const SAR_UPDATE: u64 = 6;
    pub const KICK: u64 = 10;
    pub const BYE: u64 = 11;
    pub const CHECKPOINT_HEAD: u64 = 12;
    pub const INPUT_COMMIT: u64 = 13;
}

fn b(x: &[u8]) -> Value {
    Value::bytes(x.to_vec())
}

impl Control {
    pub fn kick(reason: Reason) -> Self {
        Control::Kick {
            code: reason as u16,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let (t, fields) = match self {
            Control::Hello {
                versions,
                client_build_id,
            } => (
                ty::HELLO,
                text_map([
                    (
                        "versions",
                        Value::Array(versions.iter().map(|v| Value::Unsigned(*v)).collect()),
                    ),
                    ("client_build_id", b(client_build_id)),
                ]),
            ),
            Control::HelloAck {
                version,
                sar,
                server_nonce,
                tick_hz,
                ticks_per_epoch,
            } => (
                ty::HELLO_ACK,
                text_map([
                    ("version", Value::Unsigned(*version)),
                    ("sar", b(sar)),
                    ("server_nonce", b(server_nonce)),
                    ("tick_hz", Value::Unsigned((*tick_hz).into())),
                    (
                        "ticks_per_epoch",
                        Value::Unsigned((*ticks_per_epoch).into()),
                    ),
                ]),
            ),
            Control::Admit { sat, ar, pop } => (
                ty::ADMIT,
                text_map([("sat", b(sat)), ("ar", b(ar)), ("pop", b(pop))]),
            ),
            Control::Admitted { slot, start_tick } => (
                ty::ADMITTED,
                text_map([
                    ("slot", Value::Unsigned((*slot).into())),
                    ("start_tick", Value::Unsigned((*start_tick).into())),
                ]),
            ),
            Control::Reject { code } => (
                ty::REJECT,
                text_map([("code", Value::Unsigned((*code).into()))]),
            ),
            Control::SarUpdate { sar } => (ty::SAR_UPDATE, text_map([("sar", b(sar))])),
            Control::Kick { code } => (
                ty::KICK,
                text_map([("code", Value::Unsigned((*code).into()))]),
            ),
            Control::Bye => (ty::BYE, Value::Map(Vec::new())),
            Control::CheckpointHead {
                match_id,
                epoch,
                digest,
            } => (
                ty::CHECKPOINT_HEAD,
                text_map([
                    ("match_id", b(&match_id.0)),
                    ("epoch", Value::Unsigned((*epoch).into())),
                    ("digest", b(&digest.0)),
                ]),
            ),
            Control::InputCommit { commit } => {
                (ty::INPUT_COMMIT, text_map([("commit", b(commit))]))
            }
        };
        cbor::encode(&Value::Array(vec![Value::Unsigned(t), fields])).expect("unique keys")
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        const WHAT: &str = "Control";
        if bytes.len() > MAX_CONTROL {
            return Err(WireError::Schema(WHAT, "too large"));
        }
        let v = cbor::decode(bytes)?;
        let [t, fields] = v.as_array().ok_or(WireError::Schema(WHAT, "array"))? else {
            return Err(WireError::Schema(WHAT, "[type, fields]"));
        };
        let m = MapView::new(fields, WHAT)?;
        let u16f = |name| m.u16(name);
        Ok(match t.as_u64().ok_or(WireError::Schema(WHAT, "type"))? {
            ty::HELLO => Control::Hello {
                versions: m
                    .field("versions")?
                    .as_array()
                    .filter(|a| !a.is_empty() && a.len() <= 8)
                    .ok_or(WireError::Schema(WHAT, "versions"))?
                    .iter()
                    .map(|v| v.as_u64().ok_or(WireError::Schema(WHAT, "versions")))
                    .collect::<Result<_, _>>()?,
                client_build_id: m.fixed("client_build_id")?,
            },
            ty::HELLO_ACK => Control::HelloAck {
                version: m.u64("version")?,
                sar: m.bytes("sar")?.to_vec(),
                server_nonce: m.fixed("server_nonce")?,
                tick_hz: m.u32("tick_hz")?,
                ticks_per_epoch: m.u32("ticks_per_epoch")?,
            },
            ty::ADMIT => Control::Admit {
                sat: m.bytes("sat")?.to_vec(),
                ar: m.bytes("ar")?.to_vec(),
                pop: m.bytes("pop")?.to_vec(),
            },
            ty::ADMITTED => Control::Admitted {
                slot: u16f("slot")?,
                start_tick: m.u32("start_tick")?,
            },
            ty::REJECT => Control::Reject {
                code: u16f("code")?,
            },
            ty::SAR_UPDATE => Control::SarUpdate {
                sar: m.bytes("sar")?.to_vec(),
            },
            ty::KICK => Control::Kick {
                code: u16f("code")?,
            },
            ty::BYE => Control::Bye,
            ty::CHECKPOINT_HEAD => Control::CheckpointHead {
                match_id: MatchId(m.fixed("match_id")?),
                epoch: m.u32("epoch")?,
                digest: Digest(m.fixed("digest")?),
            },
            ty::INPUT_COMMIT => Control::InputCommit {
                commit: m.bytes("commit")?.to_vec(),
            },
            _ => return Err(WireError::Schema(WHAT, "unknown type")),
        })
    }
}

/// Channel binding for an Admit PoP over QUIC (§7.2): the TLS exporter of
/// this connection, then a hash of the exact handshake messages, the server
/// nonce and the SAT it accompanies. A PoP relayed to another connection
/// fails the exporter; a downgraded Hello/HelloAck fails the hash.
pub fn quic_pop(
    exporter: &[u8; 32],
    hello: &[u8],
    hello_ack: &[u8],
    server_nonce: &[u8; 32],
    sat_cti: &[u8; 16],
) -> AdmitPop {
    let mut h = Sha256::new();
    h.update(b"fpp/1/quic-admit\0");
    for part in [hello, hello_ack] {
        h.update((part.len() as u64).to_le_bytes());
        h.update(part);
    }
    h.update(server_nonce);
    h.update(sat_cti);
    let mut binding = exporter.to_vec();
    binding.extend_from_slice(&h.finalize());
    AdmitPop {
        channel: AdmitPop::QUIC_TLS.into(),
        binding,
    }
}

/// TLS exporter label for the Admit PoP (RFC 8446 §7.5).
pub const EXPORTER_LABEL: &[u8] = b"EXPORTER-fpp-admit";
