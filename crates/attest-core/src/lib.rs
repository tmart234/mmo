//! Verifier-side appraisal shared by the platform crates (07 §3, roadmap P3).
//!
//! - [`attest_challenge`]: the value a device puts in its platform evidence,
//!   binding the evidence to the Verifier's single-use challenge *and* to the
//!   session key the Attestation Result will be bound to (`cnf`).
//! - [`Evidence`]: the envelope carried in `ClientAdmissionRequest.evidence`.
//! - [`Claims`] and [`device_tier`]: what an appraiser observed, and the
//!   Device Trust Tier it earns (03 §4.2).
//! - [`x509`] and [`der`]: certificate chains to a pinned vendor root, and a
//!   small strict DER reader for the vendors' extensions.
//!
//! Nothing here does I/O: the vendor roots and policy come from the caller.

pub mod der;
pub mod x509;

pub use fpp_tokens::evidence::{
    attest_challenge, attest_challenge_hw_key, Evidence, EvidenceError, ATTEST_CHALLENGE_CTX,
    MAX_CHAIN, MAX_EVIDENCE,
};
use fpp_types::DeviceTier;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AttestError {
    #[error("evidence envelope: {0}")]
    Envelope(&'static str),
    #[error("certificate: {0}")]
    Certificate(&'static str),
    #[error("chain does not reach a pinned vendor root")]
    UntrustedRoot,
    #[error("signature does not verify: {0}")]
    BadSignature(&'static str),
    #[error("certificate revoked")]
    Revoked,
    #[error("challenge does not match")]
    ChallengeMismatch,
    #[error("malformed platform structure: {0}")]
    Malformed(&'static str),
    #[error("policy: {0}")]
    Policy(&'static str),
}

/// Where a device's attested key lives.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum KeyStorage {
    /// Software keystore: no hardware claim at all.
    Software,
    /// A trusted execution environment (Android TEE).
    Tee,
    /// A discrete secure element (Android StrongBox).
    StrongBox,
    /// Apple's Secure Enclave.
    SecureEnclave,
    /// A PC's TPM 2.0 (with an EK certified by its manufacturer).
    Tpm,
}

/// An app build as a platform attests it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttestedApp {
    /// `android:<package>`, ...
    pub id: String,
    pub version: u64,
}

/// What a PC's measured boot showed beyond Secure Boot (Windows' boot
/// configuration). `None`: not measured.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BootClaims {
    /// A measured-boot log replayed to the quoted PCRs.
    pub measured_boot: Option<bool>,
    /// The secure kernel (VBS) and hypervisor-enforced code integrity.
    pub vbs: Option<bool>,
    pub hvci: Option<bool>,
    /// Boot DMA protection by the IOMMU.
    pub iommu: Option<bool>,
}

/// What an appraiser established from valid evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claims {
    /// `android`, `ios`.
    pub platform: &'static str,
    pub key_storage: KeyStorage,
    /// The boot chain was verified by the platform and the bootloader is
    /// locked (Android `verifiedBootState == Verified` and `deviceLocked`).
    /// `None`: the platform does not report it (App Attest attests a genuine
    /// device and app, and says nothing about the OS).
    pub verified_boot: Option<bool>,
    /// The evidence names our app (package + signing certificate, or App ID).
    pub app_attested: bool,
    /// The session key itself is the attested hardware key, so it cannot be
    /// copied out of the device. Otherwise the hardware key only endorsed a
    /// software session key for this challenge.
    pub session_key_in_hw: bool,
    /// OS security patch level, `YYYYMM`, when reported.
    pub os_patch_level: Option<u32>,
    /// Stable hardware-rooted identity for the DID (04 §5), when the platform
    /// gives one. Android key attestation has none by design (privacy).
    pub hardware_identity: Option<Vec<u8>>,
    /// PCs: what measured boot showed (`Default` elsewhere).
    pub boot: BootClaims,
    /// The app and its version, when the platform attests them (Android:
    /// package and versionCode). The Verifier looks the build up in its
    /// client Build Registry.
    pub app: Option<AttestedApp>,
    pub warnings: Vec<String>,
}

/// The Device Trust Tier valid evidence earns (03 §4.2, 04 §4.1):
///
/// - boot chain not verified (unlocked bootloader, custom OS) → D0;
/// - hardware key, app attested, and the session key is that hardware key → D2;
/// - hardware key and app attested, but a software session key → D1 (04 §4.1:
///   "software fallback ⇒ tier ≤ D1");
/// - anything else → D0.
///
/// PCs (a TPM, 03 §4.2 "TPM 2.0 EK chain + measured boot + Secure Boot"):
/// there is no app attestation, so the rule is the boot and the key:
///
/// - the kernel can run unsigned code or a debugger (test-signing, Secure
///   Boot off, ...) → D0;
/// - Windows booted measured and locked, and the session key is in the
///   TPM → D2;
/// - the session key in the TPM, the OS not measured (Linux) → D1;
/// - anything else → D0.
///
/// D3 needs a hardened, runtime-attested platform (Windows 25H2+,
/// `GetRuntimeAttestationReport`); nothing here reaches it, HVCI included.
pub fn device_tier(c: &Claims) -> DeviceTier {
    if c.verified_boot == Some(false) {
        return DeviceTier::D0Unknown;
    }
    if c.key_storage == KeyStorage::Tpm {
        return match (c.verified_boot, c.session_key_in_hw) {
            (Some(true), true) => DeviceTier::D2Hardware,
            (None, true) => DeviceTier::D1Software,
            _ => DeviceTier::D0Unknown,
        };
    }
    let hw = c.key_storage > KeyStorage::Software;
    match (hw && c.app_attested, c.session_key_in_hw) {
        (true, true) => DeviceTier::D2Hardware,
        (true, false) => DeviceTier::D1Software,
        _ => DeviceTier::D0Unknown,
    }
}

/// Months between a `YYYYMM` patch level and `now` (`YYYYMM`), 0 if ahead.
pub fn patch_age_months(patch: u32, now: u32) -> u32 {
    let months = |v: u32| (v / 100) * 12 + (v % 100).saturating_sub(1);
    months(now).saturating_sub(months(patch))
}

impl From<EvidenceError> for AttestError {
    fn from(e: EvidenceError) -> Self {
        AttestError::Envelope(e.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_round_trips() {
        for e in [
            Evidence::AndroidKey {
                chain: vec![vec![1, 2], vec![3]],
                integrity: None,
            },
            Evidence::AndroidKey {
                chain: vec![vec![1]],
                integrity: Some("a.b.c.d.e".into()),
            },
            Evidence::AppleAppAttest {
                attestation: vec![9; 40],
            },
            Evidence::AppleAppAssert {
                key_id: vec![7; 32],
                assertion: vec![8; 70],
            },
        ] {
            assert_eq!(Evidence::decode(&e.encode()).unwrap(), Some(e));
        }
        assert_eq!(Evidence::decode(&[]).unwrap(), None);
        assert!(Evidence::decode(&[0xa0]).is_err());
        assert!(Evidence::decode(&vec![0; MAX_EVIDENCE + 1]).is_err());
    }

    fn claims() -> Claims {
        Claims {
            platform: "android",
            key_storage: KeyStorage::Tee,
            verified_boot: Some(true),
            app_attested: true,
            session_key_in_hw: true,
            os_patch_level: None,
            hardware_identity: None,
            boot: BootClaims::default(),
            app: None,
            warnings: vec![],
        }
    }

    #[test]
    fn tiers() {
        assert_eq!(device_tier(&claims()), DeviceTier::D2Hardware);
        let c = Claims {
            session_key_in_hw: false,
            ..claims()
        };
        assert_eq!(device_tier(&c), DeviceTier::D1Software);
        let c = Claims {
            verified_boot: Some(false),
            ..claims()
        };
        assert_eq!(device_tier(&c), DeviceTier::D0Unknown);
        let c = Claims {
            key_storage: KeyStorage::Software,
            ..claims()
        };
        assert_eq!(device_tier(&c), DeviceTier::D0Unknown);
        let c = Claims {
            app_attested: false,
            ..claims()
        };
        assert_eq!(device_tier(&c), DeviceTier::D0Unknown);
    }

    #[test]
    fn patch_age() {
        assert_eq!(patch_age_months(202601, 202609), 8);
        assert_eq!(patch_age_months(202512, 202601), 1);
        assert_eq!(patch_age_months(202610, 202609), 0);
    }
}
