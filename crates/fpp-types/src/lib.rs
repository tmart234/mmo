//! Fair-Play Protocol (FPP) v1 vocabulary: identifiers, trust tiers, reason
//! codes and the domain-separation labels every signature is bound to.
//!
//! Normative source: `docs/anticheat/04-protocol.md`. Names follow the
//! canonical terms in `docs/anticheat/05-ontology.md`. This crate has no I/O
//! and no dependencies so the client SDK, services and tools share it.

#![forbid(unsafe_code)]

/// Protocol version carried in every signed object's `fpp-v` header.
pub const FPP_VERSION: u64 = 1;
/// QUIC ALPN for the session plane.
pub const ALPN: &[u8] = b"fpp/1";

/// COSE private-use header labels (RFC 9052: labels < -65536 are private use).
pub mod header {
    /// Domain-separation string (`fpp-ctx`).
    pub const FPP_CTX: i64 = -65537;
    /// Protocol version (`fpp-v`).
    pub const FPP_V: i64 = -65538;
}

/// Domain-separation contexts (`fpp-ctx`). A signature is valid only for the
/// context it was made in, and only if the signing key's role allows it.
pub mod ctx {
    pub const CERT: &str = "fpp/1/cert";
    pub const BUILD_MANIFEST: &str = "fpp/1/build-manifest";
    pub const POLICY: &str = "fpp/1/policy";
    pub const ATTESTATION_RESULT: &str = "fpp/1/attestation-result";
    pub const SAT: &str = "fpp/1/sat";
    pub const SAR: &str = "fpp/1/sar";
    pub const TREE_HEAD: &str = "fpp/1/tree-head";
    pub const LOG_RECEIPT: &str = "fpp/1/log-receipt";
    pub const REVOCATION: &str = "fpp/1/revocation";
    pub const ENFORCEMENT_RECORD: &str = "fpp/1/enforcement-record";
    pub const CHECKPOINT: &str = "fpp/1/checkpoint";
    pub const HOST_BATCH: &str = "fpp/1/host-batch";
    pub const ADMIT_POP: &str = "fpp/1/admit-pop";
    pub const INPUT_COMMIT: &str = "fpp/1/input-commit";
    pub const INTEGRITY_REPORT: &str = "fpp/1/integrity-report";
}

/// Media types carried in the COSE `content type` header.
pub mod content_type {
    pub const INPUT_COMMIT: &str = "application/fpp-input-commit+cbor";
    pub const CHECKPOINT: &str = "application/fpp-checkpoint+cbor";
    pub const ADMIT_POP: &str = "application/fpp-admit-pop+cbor";
    pub const ATTESTATION_RESULT: &str = "application/fpp-ar+cwt";
    pub const SAT: &str = "application/fpp-sat+cwt";
    pub const SAR: &str = "application/fpp-sar+cwt";
    pub const LOG_RECEIPT: &str = "application/fpp-log-receipt+cbor";
    pub const REVOCATION: &str = "application/fpp-revocation+cbor";
}

macro_rules! fixed_id {
    ($(#[$doc:meta])* $name:ident, $len:expr) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
        pub struct $name(pub [u8; $len]);

        impl $name {
            pub const LEN: usize = $len;

            pub fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }

            pub fn from_slice(bytes: &[u8]) -> Option<Self> {
                bytes.try_into().ok().map(Self)
            }
        }

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "{}(", stringify!($name))?;
                for b in &self.0[..4] {
                    write!(f, "{b:02x}")?;
                }
                write!(f, "..)")
            }
        }
    };
}

fixed_id!(
    /// Match (simulation instance) id, minted by the Broker.
    MatchId, 16
);
fixed_id!(
    /// SHA-256 of a GS instance key's COSE_Key.
    GsInstanceId, 32
);
fixed_id!(
    /// SHA-256 of a build manifest payload.
    BuildId, 32
);
fixed_id!(
    /// Keyed pseudonym of a device's hardware identity.
    Did, 32
);
fixed_id!(
    /// Pseudonymous account id used outside the Identity context.
    Acct, 32
);
fixed_id!(
    /// COSE `kid`: SHA-256 of the signer's COSE_Key, truncated.
    Kid, 16
);
fixed_id!(
    /// SHA-256 digest (Merkle roots, object digests, chain links).
    Digest, 32
);

/// A player's session key (the `cnf` of ARs and SATs, 04 §3): Ed25519, or
/// ECDSA P-256 (ES256) for keys held in hardware that has no Ed25519 (TPMs,
/// Secure Enclave, StrongBox). Only the format is checked here; whether a
/// P-256 point is on the curve is checked where it is used (`fpp-crypto`).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionKey {
    Ed25519([u8; 32]),
    /// Affine coordinates, big-endian.
    P256 {
        x: [u8; 32],
        y: [u8; 32],
    },
}

impl SessionKey {
    /// The canonical bytes: an Ed25519 key's 32 bytes, or a P-256 point as
    /// uncompressed SEC1 (`0x04 ‖ x ‖ y`, 65 bytes). Bound into evidence
    /// challenges and proof-of-possession messages.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            SessionKey::Ed25519(k) => k.to_vec(),
            SessionKey::P256 { x, y } => {
                let mut v = Vec::with_capacity(65);
                v.push(4);
                v.extend_from_slice(x);
                v.extend_from_slice(y);
                v
            }
        }
    }

    /// Inverse of [`SessionKey::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        match bytes.len() {
            32 => Some(SessionKey::Ed25519(bytes.try_into().ok()?)),
            65 if bytes[0] == 4 => Some(SessionKey::P256 {
                x: bytes[1..33].try_into().ok()?,
                y: bytes[33..].try_into().ok()?,
            }),
            _ => None,
        }
    }

    /// The COSE algorithm this key signs with (`EdDSA` -8 or `ES256` -7).
    pub fn alg(&self) -> i64 {
        match self {
            SessionKey::Ed25519(_) => -8,
            SessionKey::P256 { .. } => -7,
        }
    }
}

impl core::fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let (name, b) = match self {
            SessionKey::Ed25519(k) => ("Ed25519", &k[..4]),
            SessionKey::P256 { x, .. } => ("P256", &x[..4]),
        };
        write!(f, "SessionKey::{name}(")?;
        for b in b {
            write!(f, "{b:02x}")?;
        }
        write!(f, "..)")
    }
}

/// Device Trust Tier, computed by the Verifier (03-architecture.md §4.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum DeviceTier {
    D0Unknown = 0,
    D1Software = 1,
    D2Hardware = 2,
    D3Hardened = 3,
}

impl DeviceTier {
    pub fn from_u64(v: u64) -> Option<Self> {
        Some(match v {
            0 => Self::D0Unknown,
            1 => Self::D1Software,
            2 => Self::D2Hardware,
            3 => Self::D3Hardened,
            _ => return None,
        })
    }
}

/// Who operates a game server (03-architecture.md §4.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ServerClass {
    Community = 0,
    Partner = 1,
    FirstParty = 2,
    FirstPartyCvm = 3,
}

impl ServerClass {
    pub fn from_u64(v: u64) -> Option<Self> {
        Some(match v {
            0 => Self::Community,
            1 => Self::Partner,
            2 => Self::FirstParty,
            3 => Self::FirstPartyCvm,
            _ => return None,
        })
    }
}

/// What detections and enforcement actions target (04-protocol.md §9).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SubjectKind {
    Account = 0,
    Device = 1,
    Session = 2,
    Sat = 3,
    GsInstance = 4,
    Build = 5,
}

/// Reject / kick reason codes (04-protocol.md §11).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum Reason {
    VersionUnsupported = 1,
    SatInvalid = 2,
    ArInvalid = 3,
    PopInvalid = 4,
    TierInsufficient = 5,
    Revoked = 6,
    SarLapsed = 7,
    IntegrityFailed = 8,
    CommitMismatch = 9,
    InputEquivocation = 10,
    PolicyKick = 11,
    ServerDraining = 12,
    /// The host has no free player slot.
    ServerFull = 13,
    /// The AR's measured client build is not one this queue admits.
    BuildUnlisted = 14,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contexts_are_unique_and_versioned() {
        let all = [
            ctx::CERT,
            ctx::BUILD_MANIFEST,
            ctx::POLICY,
            ctx::ATTESTATION_RESULT,
            ctx::SAT,
            ctx::SAR,
            ctx::TREE_HEAD,
            ctx::LOG_RECEIPT,
            ctx::REVOCATION,
            ctx::ENFORCEMENT_RECORD,
            ctx::CHECKPOINT,
            ctx::HOST_BATCH,
            ctx::ADMIT_POP,
            ctx::INPUT_COMMIT,
            ctx::INTEGRITY_REPORT,
        ];
        let mut sorted = all.to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), all.len());
        assert!(all.iter().all(|c| c.starts_with("fpp/1/")));
    }

    // RFC 9052: header labels below -65536 are private use.
    const _: () = assert!(header::FPP_CTX < -65536 && header::FPP_V < -65536);

    #[test]
    fn tier_roundtrip() {
        for v in 0..4 {
            assert_eq!(DeviceTier::from_u64(v).unwrap() as u64, v);
            assert_eq!(ServerClass::from_u64(v).unwrap() as u64, v);
        }
        assert!(DeviceTier::from_u64(4).is_none());
        assert!(DeviceTier::D3Hardened > DeviceTier::D2Hardware);
    }
}
