//! Strict deterministic CBOR (RFC 8949 §4.2.1, "core deterministic encoding").
//!
//! FPP signs CBOR bytes, so there must be exactly one encoding of every value
//! and receivers must reject anything else (04-protocol.md §2). This module
//! implements the subset FPP uses and nothing more:
//!
//! - unsigned and negative integers, byte strings, UTF-8 text strings,
//!   arrays, maps with integer or text keys, `false`, `true`, `null`;
//! - no floats, tags, undefined or other simple values, and no
//!   indefinite-length items.
//!
//! The encoder always emits shortest-form heads and sorts map keys by the
//! bytewise order of their encodings. The decoder accepts only that form:
//! non-minimal heads, unsorted or duplicate keys, invalid UTF-8, trailing
//! bytes and nesting deeper than `MAX_DEPTH` are errors, and no length is
//! trusted before it is checked against the remaining input.

use crate::WireError;

/// Maximum nesting of arrays and maps. FPP objects need at most 4.
pub const MAX_DEPTH: usize = 16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Unsigned(u64),
    /// The integer `-1 - n`.
    Negative(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    /// Entries in deterministic order once decoded; the encoder sorts them.
    Map(Vec<(Value, Value)>),
    Bool(bool),
    Null,
}

impl Value {
    /// An integer in the CBOR range that fits `i64`.
    pub fn int(v: i64) -> Self {
        if v >= 0 {
            Value::Unsigned(v as u64)
        } else {
            Value::Negative((-1 - v) as u64)
        }
    }

    pub fn text(s: impl Into<String>) -> Self {
        Value::Text(s.into())
    }

    pub fn bytes(b: impl Into<Vec<u8>>) -> Self {
        Value::Bytes(b.into())
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::Unsigned(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Unsigned(v) => i64::try_from(*v).ok(),
            Value::Negative(n) => i64::try_from(*n).ok().map(|n| -1 - n),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }

    pub fn as_text(&self) -> Option<&str> {
        match self {
            Value::Text(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }

    pub fn as_map(&self) -> Option<&[(Value, Value)]> {
        match self {
            Value::Map(m) => Some(m),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------- encoding

fn write_head(out: &mut Vec<u8>, major: u8, arg: u64) {
    let m = major << 5;
    if arg < 24 {
        out.push(m | arg as u8);
    } else if arg <= 0xff {
        out.push(m | 24);
        out.push(arg as u8);
    } else if arg <= 0xffff {
        out.push(m | 25);
        out.extend_from_slice(&(arg as u16).to_be_bytes());
    } else if arg <= 0xffff_ffff {
        out.push(m | 26);
        out.extend_from_slice(&(arg as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&arg.to_be_bytes());
    }
}

fn encode_into(v: &Value, out: &mut Vec<u8>) -> Result<(), WireError> {
    match v {
        Value::Unsigned(n) => write_head(out, 0, *n),
        Value::Negative(n) => write_head(out, 1, *n),
        Value::Bytes(b) => {
            write_head(out, 2, b.len() as u64);
            out.extend_from_slice(b);
        }
        Value::Text(s) => {
            write_head(out, 3, s.len() as u64);
            out.extend_from_slice(s.as_bytes());
        }
        Value::Array(items) => {
            write_head(out, 4, items.len() as u64);
            for item in items {
                encode_into(item, out)?;
            }
        }
        Value::Map(entries) => {
            let mut encoded = Vec::with_capacity(entries.len());
            for (k, val) in entries {
                if !matches!(k, Value::Unsigned(_) | Value::Negative(_) | Value::Text(_)) {
                    return Err(WireError::UnsupportedKey);
                }
                let mut kb = Vec::new();
                encode_into(k, &mut kb)?;
                encoded.push((kb, val));
            }
            encoded.sort_by(|a, b| a.0.cmp(&b.0));
            if encoded.windows(2).any(|w| w[0].0 == w[1].0) {
                return Err(WireError::UnsortedOrDuplicateKey);
            }
            write_head(out, 5, encoded.len() as u64);
            for (kb, val) in encoded {
                out.extend_from_slice(&kb);
                encode_into(val, out)?;
            }
        }
        Value::Bool(false) => out.push(0xf4),
        Value::Bool(true) => out.push(0xf5),
        Value::Null => out.push(0xf6),
    }
    Ok(())
}

/// Deterministic encoding of `v`. Fails only on duplicate or unsupported map keys.
pub fn encode(v: &Value) -> Result<Vec<u8>, WireError> {
    let mut out = Vec::new();
    encode_into(v, &mut out)?;
    Ok(out)
}

// ---------------------------------------------------------------- decoding

struct Decoder<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        if n > self.remaining() {
            return Err(WireError::Truncated);
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn byte(&mut self) -> Result<u8, WireError> {
        Ok(self.take(1)?[0])
    }

    /// Read a head's argument, rejecting non-shortest forms.
    fn argument(&mut self, info: u8) -> Result<u64, WireError> {
        let (value, min) = match info {
            0..=23 => return Ok(info as u64),
            24 => (self.byte()? as u64, 24),
            25 => (
                u16::from_be_bytes(self.take(2)?.try_into().unwrap()) as u64,
                0x100,
            ),
            26 => (
                u32::from_be_bytes(self.take(4)?.try_into().unwrap()) as u64,
                0x1_0000,
            ),
            27 => (
                u64::from_be_bytes(self.take(8)?.try_into().unwrap()),
                0x1_0000_0000,
            ),
            31 => return Err(WireError::IndefiniteLength),
            _ => return Err(WireError::Reserved),
        };
        if value < min {
            return Err(WireError::NonCanonical);
        }
        Ok(value)
    }

    fn length(&mut self, info: u8) -> Result<usize, WireError> {
        let len = self.argument(info)?;
        // Every length is bounded by the bytes still unread, before allocating.
        if len > self.remaining() as u64 {
            return Err(WireError::Truncated);
        }
        Ok(len as usize)
    }

    fn item(&mut self, depth: usize) -> Result<Value, WireError> {
        let initial = self.byte()?;
        let (major, info) = (initial >> 5, initial & 0x1f);
        match major {
            0 => Ok(Value::Unsigned(self.argument(info)?)),
            1 => Ok(Value::Negative(self.argument(info)?)),
            2 => {
                let len = self.length(info)?;
                Ok(Value::Bytes(self.take(len)?.to_vec()))
            }
            3 => {
                let len = self.length(info)?;
                let raw = self.take(len)?;
                let s = core::str::from_utf8(raw).map_err(|_| WireError::InvalidUtf8)?;
                Ok(Value::Text(s.to_owned()))
            }
            4 | 5 => {
                if depth == 0 {
                    return Err(WireError::TooDeep);
                }
                // Each element takes at least one byte (two per map entry).
                let count = self.length(info)?;
                if major == 4 {
                    let mut items = Vec::with_capacity(count);
                    for _ in 0..count {
                        items.push(self.item(depth - 1)?);
                    }
                    Ok(Value::Array(items))
                } else {
                    if count > self.remaining() / 2 {
                        return Err(WireError::Truncated);
                    }
                    let mut entries = Vec::with_capacity(count);
                    let mut prev_key: Option<&'a [u8]> = None;
                    for _ in 0..count {
                        let start = self.pos;
                        let key = self.item(depth - 1)?;
                        if !matches!(
                            key,
                            Value::Unsigned(_) | Value::Negative(_) | Value::Text(_)
                        ) {
                            return Err(WireError::UnsupportedKey);
                        }
                        let key_bytes = &self.buf[start..self.pos];
                        if prev_key.is_some_and(|p| p >= key_bytes) {
                            return Err(WireError::UnsortedOrDuplicateKey);
                        }
                        prev_key = Some(key_bytes);
                        let value = self.item(depth - 1)?;
                        entries.push((key, value));
                    }
                    Ok(Value::Map(entries))
                }
            }
            6 => Err(WireError::Unsupported),
            _ => match info {
                20 => Ok(Value::Bool(false)),
                21 => Ok(Value::Bool(true)),
                22 => Ok(Value::Null),
                31 => Err(WireError::IndefiniteLength),
                _ => Err(WireError::Unsupported),
            },
        }
    }
}

/// Decode exactly one value occupying all of `bytes`, accepting only the
/// deterministic encoding.
pub fn decode(bytes: &[u8]) -> Result<Value, WireError> {
    let mut d = Decoder { buf: bytes, pos: 0 };
    let v = d.item(MAX_DEPTH)?;
    if d.remaining() != 0 {
        return Err(WireError::TrailingBytes);
    }
    Ok(v)
}

// ---------------------------------------------------------------- typed access

/// Read fields from a decoded map by text or integer key.
pub struct MapView<'a> {
    entries: &'a [(Value, Value)],
    what: &'static str,
}

impl<'a> MapView<'a> {
    pub fn new(v: &'a Value, what: &'static str) -> Result<Self, WireError> {
        let entries = v
            .as_map()
            .ok_or(WireError::Schema(what, "expected a map"))?;
        Ok(Self { entries, what })
    }

    pub fn get(&self, key: &Value) -> Option<&'a Value> {
        self.entries.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    pub fn field(&self, name: &'static str) -> Result<&'a Value, WireError> {
        self.get(&Value::text(name))
            .ok_or(WireError::Schema(self.what, name))
    }

    pub fn u64(&self, name: &'static str) -> Result<u64, WireError> {
        self.field(name)?
            .as_u64()
            .ok_or(WireError::Schema(self.what, name))
    }

    pub fn u32(&self, name: &'static str) -> Result<u32, WireError> {
        u32::try_from(self.u64(name)?).map_err(|_| WireError::Schema(self.what, name))
    }

    pub fn u16(&self, name: &'static str) -> Result<u16, WireError> {
        u16::try_from(self.u64(name)?).map_err(|_| WireError::Schema(self.what, name))
    }

    pub fn bytes(&self, name: &'static str) -> Result<&'a [u8], WireError> {
        self.field(name)?
            .as_bytes()
            .ok_or(WireError::Schema(self.what, name))
    }

    pub fn fixed<const N: usize>(&self, name: &'static str) -> Result<[u8; N], WireError> {
        self.bytes(name)?
            .try_into()
            .map_err(|_| WireError::Schema(self.what, name))
    }
}

/// Build a text-keyed map.
pub fn text_map<const N: usize>(entries: [(&str, Value); N]) -> Value {
    Value::Map(
        entries
            .into_iter()
            .map(|(k, v)| (Value::text(k), v))
            .collect(),
    )
}
