//! Handshake payloads: deterministic CBOR maps inside the Noise messages, so
//! they are encrypted and authenticated by the handshake itself.

use crate::{Error, MAX_ATTESTATION, MAX_HELLO, VERSION};
use fpp_types::SessionKey;
use fpp_wire::cbor::{self, text_map, MapView, Value};

/// Joiner → host, inside Noise message 1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct JoinHello {
    pub invite: Option<[u8; 32]>,
    /// FPP session key, Ed25519 or P-256 (signs this player's InputCommits).
    pub session_key: SessionKey,
    /// COSE_Sign1 `AdmitPop` by `session_key` over host ‖ joiner static keys.
    pub admit_pop: Vec<u8>,
    /// Attestation Result (empty when the device has none: tier D0).
    pub attestation: Vec<u8>,
    pub app: Vec<u8>,
}

/// Host → joiner, inside Noise message 2.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HostHello {
    /// Ed25519 key that signs the host's Checkpoints, if it keeps evidence.
    pub instance_key: Option<[u8; 32]>,
    pub app: Vec<u8>,
}

/// Largest encoded COSE AdmitPop accepted (the real one is about 170 bytes).
const MAX_ADMIT_POP: usize = 256;

fn opt32(v: &Option<[u8; 32]>) -> Value {
    v.map_or(Value::Null, |k| Value::bytes(k.to_vec()))
}

fn read_opt32(m: &MapView<'_>, name: &'static str) -> Result<Option<[u8; 32]>, Error> {
    match m.field(name).map_err(|_| Error::Malformed)? {
        Value::Null => Ok(None),
        v => v
            .as_bytes()
            .and_then(|b| b.try_into().ok())
            .map(Some)
            .ok_or(Error::Malformed),
    }
}

fn read_bytes(m: &MapView<'_>, name: &'static str, max: usize) -> Result<Vec<u8>, Error> {
    let b = m.bytes(name).map_err(|_| Error::Malformed)?;
    if b.len() > max {
        return Err(Error::TooLarge);
    }
    Ok(b.to_vec())
}

fn check_version(m: &MapView<'_>) -> Result<(), Error> {
    match m.u64("v") {
        Ok(VERSION) => Ok(()),
        Ok(_) => Err(Error::Version),
        Err(_) => Err(Error::Malformed),
    }
}

impl JoinHello {
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        if self.attestation.len() > MAX_ATTESTATION || self.app.len() > MAX_HELLO {
            return Err(Error::TooLarge);
        }
        let v = text_map([
            ("v", Value::Unsigned(VERSION)),
            ("invite", opt32(&self.invite)),
            ("session_key", Value::bytes(self.session_key.to_bytes())),
            ("admit_pop", Value::bytes(self.admit_pop.clone())),
            ("attestation", Value::bytes(self.attestation.clone())),
            ("app", Value::bytes(self.app.clone())),
        ]);
        Ok(cbor::encode(&v).expect("unique keys"))
    }

    pub fn decode(b: &[u8]) -> Result<Self, Error> {
        let v = cbor::decode(b).map_err(|_| Error::Malformed)?;
        let m = MapView::new(&v, "JoinHello").map_err(|_| Error::Malformed)?;
        check_version(&m)?;
        Ok(Self {
            invite: read_opt32(&m, "invite")?,
            session_key: m
                .bytes("session_key")
                .ok()
                .and_then(SessionKey::from_bytes)
                .ok_or(Error::Malformed)?,
            admit_pop: read_bytes(&m, "admit_pop", MAX_ADMIT_POP)?,
            attestation: read_bytes(&m, "attestation", MAX_ATTESTATION)?,
            app: read_bytes(&m, "app", MAX_HELLO)?,
        })
    }
}

impl HostHello {
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        if self.app.len() > MAX_HELLO {
            return Err(Error::TooLarge);
        }
        let v = text_map([
            ("v", Value::Unsigned(VERSION)),
            ("instance_key", opt32(&self.instance_key)),
            ("app", Value::bytes(self.app.clone())),
        ]);
        Ok(cbor::encode(&v).expect("unique keys"))
    }

    pub fn decode(b: &[u8]) -> Result<Self, Error> {
        let v = cbor::decode(b).map_err(|_| Error::Malformed)?;
        let m = MapView::new(&v, "HostHello").map_err(|_| Error::Malformed)?;
        check_version(&m)?;
        Ok(Self {
            instance_key: read_opt32(&m, "instance_key")?,
            app: read_bytes(&m, "app", MAX_HELLO)?,
        })
    }
}
