//! COSE_Sign1 (RFC 9052 §4.2) as FPP v1 uses it (04-protocol.md §2).
//!
//! FPP narrows COSE to one shape so that every signed object has exactly one
//! encoding:
//! - untagged `COSE_Sign1 = [protected: bstr, unprotected: {}, payload: bstr,
//!   signature: bstr]`;
//! - the protected header holds exactly `alg` (1), `content type` (3, text),
//!   `kid` (4, 16 bytes), `fpp-ctx` (-65537) and `fpp-v` (-65538);
//! - the unprotected header is empty, `crit` is never used, and detached
//!   payloads are not allowed.
//!
//! Signing and verification live in `fpp-crypto`; this module only builds
//! and parses the container and the `Sig_structure` bytes.

use crate::cbor::{self, Value};
use crate::WireError;
use fpp_types::{header, Kid};

const ALG: i64 = 1;
const CRIT: i64 = 2;
const CONTENT_TYPE: i64 = 3;
const KID: i64 = 4;

/// COSE algorithm identifiers FPP v1 accepts.
pub mod alg {
    /// EdDSA with Ed25519.
    pub const EDDSA: i64 = -8;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtectedHeader {
    pub alg: i64,
    pub content_type: String,
    pub kid: Kid,
    pub ctx: String,
    pub version: u64,
}

impl ProtectedHeader {
    pub fn to_value(&self) -> Value {
        Value::Map(vec![
            (Value::int(ALG), Value::int(self.alg)),
            (Value::int(CONTENT_TYPE), Value::text(&self.content_type)),
            (Value::int(KID), Value::bytes(self.kid.0.to_vec())),
            (Value::int(header::FPP_CTX), Value::text(&self.ctx)),
            (Value::int(header::FPP_V), Value::Unsigned(self.version)),
        ])
    }

    pub fn from_value(v: &Value) -> Result<Self, WireError> {
        const WHAT: &str = "protected header";
        let entries = v.as_map().ok_or(WireError::Header("not a map"))?;
        let mut alg_v = None;
        let mut content_type = None;
        let mut kid = None;
        let mut ctx = None;
        let mut version = None;
        for (k, val) in entries {
            match k.as_i64() {
                Some(ALG) => alg_v = val.as_i64(),
                Some(CRIT) => return Err(WireError::Header("crit is not allowed")),
                Some(CONTENT_TYPE) => content_type = val.as_text().map(str::to_owned),
                Some(KID) => kid = val.as_bytes().and_then(Kid::from_slice),
                Some(header::FPP_CTX) => ctx = val.as_text().map(str::to_owned),
                Some(header::FPP_V) => version = val.as_u64(),
                _ => return Err(WireError::Header("unknown header parameter")),
            }
        }
        Ok(Self {
            alg: alg_v.ok_or(WireError::Schema(WHAT, "alg"))?,
            content_type: content_type.ok_or(WireError::Schema(WHAT, "content type"))?,
            kid: kid.ok_or(WireError::Schema(WHAT, "kid"))?,
            ctx: ctx.ok_or(WireError::Schema(WHAT, "fpp-ctx"))?,
            version: version.ok_or(WireError::Schema(WHAT, "fpp-v"))?,
        })
    }
}

/// A parsed COSE_Sign1. `protected_raw` is kept byte-exact because the
/// signature covers it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sign1 {
    pub protected_raw: Vec<u8>,
    pub protected: ProtectedHeader,
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
}

impl Sign1 {
    /// Assemble an unsigned object; call `to_be_signed`, sign, then set `signature`.
    pub fn new(protected: ProtectedHeader, payload: Vec<u8>) -> Result<Self, WireError> {
        Ok(Self {
            protected_raw: cbor::encode(&protected.to_value())?,
            protected,
            payload,
            signature: Vec::new(),
        })
    }

    /// `Sig_structure = ["Signature1", protected, external_aad = h'', payload]`.
    pub fn to_be_signed(&self) -> Vec<u8> {
        let tbs = Value::Array(vec![
            Value::text("Signature1"),
            Value::bytes(self.protected_raw.clone()),
            Value::bytes(Vec::new()),
            Value::bytes(self.payload.clone()),
        ]);
        cbor::encode(&tbs).expect("Sig_structure has no maps")
    }

    pub fn encode(&self) -> Vec<u8> {
        let v = Value::Array(vec![
            Value::bytes(self.protected_raw.clone()),
            Value::Map(Vec::new()),
            Value::bytes(self.payload.clone()),
            Value::bytes(self.signature.clone()),
        ]);
        cbor::encode(&v).expect("COSE_Sign1 has no non-empty maps")
    }

    /// Parse strictly. Does not verify the signature.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let v = cbor::decode(bytes)?;
        let parts = v
            .as_array()
            .ok_or(WireError::Header("COSE_Sign1 is not an array"))?;
        let [protected, unprotected, payload, signature] = parts else {
            return Err(WireError::Header("COSE_Sign1 must have 4 elements"));
        };
        let protected_raw = protected
            .as_bytes()
            .ok_or(WireError::Header("protected header is not a bstr"))?
            .to_vec();
        if unprotected.as_map().is_none_or(|m| !m.is_empty()) {
            return Err(WireError::Header("unprotected header must be an empty map"));
        }
        let payload = payload
            .as_bytes()
            .ok_or(WireError::Header("payload must be an attached bstr"))?
            .to_vec();
        let signature = signature
            .as_bytes()
            .ok_or(WireError::Header("signature is not a bstr"))?
            .to_vec();
        let protected = ProtectedHeader::from_value(&cbor::decode(&protected_raw)?)?;
        Ok(Self {
            protected_raw,
            protected,
            payload,
            signature,
        })
    }
}
