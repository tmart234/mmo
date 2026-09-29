//! Fair-Play Protocol v1 wire format (docs/anticheat/04-protocol.md §2):
//! strict deterministic CBOR, the COSE_Sign1 container, and message payloads.
//! No cryptography here; signing and verification live in `fpp-crypto`.

#![forbid(unsafe_code)]

pub mod cbor;
pub mod cose;
pub mod frame;
pub mod msg;

pub use cbor::Value;
pub use frame::InputFrame;
pub use msg::{AdmitPop, Checkpoint, InputCommit, InputLeaf, Payload};

/// Why bytes were rejected. Decoders never panic on untrusted input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WireError {
    /// Input ends before a declared length.
    Truncated,
    /// Bytes remain after the top-level item.
    TrailingBytes,
    /// A head is not in shortest form.
    NonCanonical,
    /// Indefinite-length items are not allowed.
    IndefiniteLength,
    /// Reserved additional-information value.
    Reserved,
    /// Floats, tags, undefined and other simple values are not allowed.
    Unsupported,
    /// Map keys must be integers or text.
    UnsupportedKey,
    /// Map keys must be unique and in deterministic order.
    UnsortedOrDuplicateKey,
    InvalidUtf8,
    /// Nesting deeper than `cbor::MAX_DEPTH`.
    TooDeep,
    /// A COSE header rule was violated.
    Header(&'static str),
    /// A required field is missing or has the wrong type: (object, field).
    Schema(&'static str, &'static str),
}

impl WireError {
    /// Whether the input was not in deterministic encoding (as opposed to
    /// being well-formed but not matching a schema).
    pub fn is_encoding(&self) -> bool {
        !matches!(self, WireError::Header(_) | WireError::Schema(..))
    }
}

impl core::fmt::Display for WireError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            WireError::Header(why) => write!(f, "COSE header: {why}"),
            WireError::Schema(what, field) => write!(f, "{what}: bad or missing {field}"),
            other => write!(f, "CBOR: {other:?}"),
        }
    }
}

impl std::error::Error for WireError {}
