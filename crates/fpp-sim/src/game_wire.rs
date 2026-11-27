//! Deterministic CBOR wire format for the reference simulation game commands
//! and world snapshots. Owned directly on `fpp::wire::cbor` (zero `bincode`,
//! zero `serde`).

use fpp::wire::cbor::{decode, encode, Value};
use fpp::wire::WireError;

/// 16-byte client-generated idempotency key for economy operations.
pub type OpId = [u8; 16];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpendCoins {
    pub op_id: OpId,
    pub amount: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ClientCmd {
    Move { dx: f32, dy: f32 },
    SpendCoins(SpendCoins),
}

#[derive(Clone, Debug, PartialEq)]
pub struct WorldSnapshot {
    pub tick: u64,
    pub you: (f32, f32),
    pub others: Vec<(u16, f32, f32)>,
}

fn as_u32(v: &Value, what: &'static str, field: &'static str) -> Result<u32, WireError> {
    let n = v.as_u64().ok_or(WireError::Schema(what, field))?;
    u32::try_from(n).map_err(|_| WireError::Schema(what, field))
}

fn as_u16(v: &Value, what: &'static str, field: &'static str) -> Result<u16, WireError> {
    let n = v.as_u64().ok_or(WireError::Schema(what, field))?;
    u16::try_from(n).map_err(|_| WireError::Schema(what, field))
}

impl ClientCmd {
    pub fn encode(&self) -> Vec<u8> {
        let v = match self {
            ClientCmd::Move { dx, dy } => Value::Array(vec![
                Value::Unsigned(1),
                Value::Unsigned(dx.to_bits() as u64),
                Value::Unsigned(dy.to_bits() as u64),
            ]),
            ClientCmd::SpendCoins(sc) => Value::Array(vec![
                Value::Unsigned(2),
                Value::bytes(sc.op_id.to_vec()),
                Value::Unsigned(sc.amount),
            ]),
        };
        encode(&v).expect("deterministic CBOR")
    }

    pub fn decode(raw: &[u8]) -> Result<Self, WireError> {
        let v = decode(raw)?;
        let items = v
            .as_array()
            .ok_or(WireError::Schema("ClientCmd", "array"))?;
        let tag = items
            .first()
            .and_then(Value::as_u64)
            .ok_or(WireError::Schema("ClientCmd", "tag"))?;
        match tag {
            1 => {
                if items.len() != 3 {
                    return Err(WireError::Schema("ClientCmd", "Move length"));
                }
                Ok(ClientCmd::Move {
                    dx: f32::from_bits(as_u32(&items[1], "ClientCmd", "dx")?),
                    dy: f32::from_bits(as_u32(&items[2], "ClientCmd", "dy")?),
                })
            }
            2 => {
                if items.len() != 3 {
                    return Err(WireError::Schema("ClientCmd", "SpendCoins length"));
                }
                let b = items[1]
                    .as_bytes()
                    .ok_or(WireError::Schema("ClientCmd", "op_id"))?;
                let op_id: OpId = b
                    .try_into()
                    .map_err(|_| WireError::Schema("ClientCmd", "op_id len"))?;
                let amount = items[2]
                    .as_u64()
                    .ok_or(WireError::Schema("ClientCmd", "amount"))?;
                Ok(ClientCmd::SpendCoins(SpendCoins { op_id, amount }))
            }
            _ => Err(WireError::Schema("ClientCmd", "tag")),
        }
    }
}

impl WorldSnapshot {
    pub fn encode(&self) -> Vec<u8> {
        let others = self
            .others
            .iter()
            .map(|(slot, x, y)| {
                Value::Array(vec![
                    Value::Unsigned(u64::from(*slot)),
                    Value::Unsigned(x.to_bits() as u64),
                    Value::Unsigned(y.to_bits() as u64),
                ])
            })
            .collect();
        encode(&Value::Array(vec![
            Value::Unsigned(self.tick),
            Value::Unsigned(self.you.0.to_bits() as u64),
            Value::Unsigned(self.you.1.to_bits() as u64),
            Value::Array(others),
        ]))
        .expect("deterministic CBOR")
    }

    pub fn decode(raw: &[u8]) -> Result<Self, WireError> {
        let v = decode(raw)?;
        let items = v
            .as_array()
            .ok_or(WireError::Schema("WorldSnapshot", "array"))?;
        if items.len() != 4 {
            return Err(WireError::Schema("WorldSnapshot", "length"));
        }
        let tick = items[0]
            .as_u64()
            .ok_or(WireError::Schema("WorldSnapshot", "tick"))?;
        let x = f32::from_bits(as_u32(&items[1], "WorldSnapshot", "x")?);
        let y = f32::from_bits(as_u32(&items[2], "WorldSnapshot", "y")?);
        let raw_others = items[3]
            .as_array()
            .ok_or(WireError::Schema("WorldSnapshot", "others"))?;
        let mut others = Vec::with_capacity(raw_others.len());
        for entry in raw_others {
            let e = entry
                .as_array()
                .ok_or(WireError::Schema("WorldSnapshot", "other entry"))?;
            if e.len() != 3 {
                return Err(WireError::Schema("WorldSnapshot", "other entry len"));
            }
            others.push((
                as_u16(&e[0], "WorldSnapshot", "slot")?,
                f32::from_bits(as_u32(&e[1], "WorldSnapshot", "x")?),
                f32::from_bits(as_u32(&e[2], "WorldSnapshot", "y")?),
            ));
        }
        Ok(WorldSnapshot {
            tick,
            you: (x, y),
            others,
        })
    }
}
