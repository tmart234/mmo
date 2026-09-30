//! Android Keystore key attestation (KeyMint), Verifier side (ATT-03,
//! roadmap P3).
//!
//! The device generates a key in its TEE or StrongBox with
//! `setAttestationChallenge(attest_challenge(verifier_challenge, session_pub))`
//! and sends the key's certificate chain. The leaf carries the
//! KeyDescription extension (OID `1.3.6.1.4.1.11129.2.1.17`), written by the
//! secure hardware. This crate checks:
//!
//! 1. the chain reaches a pinned Google root, and no certificate in it is on
//!    Google's revocation list (leaked attestation keys are revoked there);
//! 2. attestation and key both in hardware (TEE or StrongBox, not Software);
//! 3. the attestation challenge is ours (this challenge, this session key);
//! 4. the key was generated in hardware (`origin == GENERATED`);
//! 5. the root of trust is hardware-enforced: `verifiedBootState` and
//!    `deviceLocked` give the verified-boot claim (an unlocked bootloader or
//!    a custom OS earns tier D0);
//! 6. the app: package name and signing-certificate digest are on the
//!    allowlist (`attestationApplicationId`);
//! 7. the OS patch level is recent enough.
//!
//! What it cannot establish: a stable device identity (key attestation has
//! none, by design), or that the OS is not rooted *after* a verified boot.
//! Play Integrity's verdicts cover part of that and are a separate adapter.

use std::collections::HashSet;

use attest_core::der::{self, Tlv, CLASS_CONTEXT, TAG_SEQUENCE, TAG_SET};
use attest_core::x509::{self, ChainOptions, OID_ED25519};
use attest_core::{AttestError, Claims, KeyStorage};

pub const OID_KEY_DESCRIPTION: &str = "1.3.6.1.4.1.11129.2.1.17";

/// Google's hardware attestation roots (roots/README.md).
pub const GOOGLE_ROOTS_PEM: &str = include_str!("../roots/google_hardware_attestation_roots.pem");

pub fn google_roots() -> Vec<Vec<u8>> {
    x509::pem_certificates(GOOGLE_ROOTS_PEM).expect("vendored Google roots parse")
}

/// Google's attestation status list (the JSON at
/// `https://android.googleapis.com/attestation/status`): every listed serial
/// (revoked or suspended), in lowercase hex.
pub fn parse_status_list(json: &str) -> Result<HashSet<String>, AttestError> {
    let v: serde_json::Value =
        serde_json::from_str(json).map_err(|_| AttestError::Policy("status list JSON"))?;
    let entries = v
        .get("entries")
        .and_then(|e| e.as_object())
        .ok_or(AttestError::Policy("status list entries"))?;
    Ok(entries
        .keys()
        .map(|k| k.trim_start_matches('0').to_ascii_lowercase())
        .collect())
}

/// An app allowed to attest: its package name and the SHA-256 digests of the
/// certificates it is signed with (any one must be present).
#[derive(Clone, Debug)]
pub struct AllowedApp {
    pub package: String,
    pub signer_sha256: Vec<[u8; 32]>,
}

#[derive(Clone, Debug)]
pub struct AndroidPolicy {
    /// Trust anchors (DER); `google_roots()` in production.
    pub roots: Vec<Vec<u8>>,
    pub apps: Vec<AllowedApp>,
    /// Revoked or suspended attestation certificates (lowercase hex serials).
    pub revoked: HashSet<String>,
    /// Oldest OS patch level accepted, in months; `None` for any.
    pub max_patch_age_months: Option<u32>,
}

impl AndroidPolicy {
    pub fn production(apps: Vec<AllowedApp>) -> Self {
        AndroidPolicy {
            roots: google_roots(),
            apps,
            revoked: HashSet::new(),
            max_patch_age_months: Some(12),
        }
    }
}

/// KeyMint `SecurityLevel`.
fn storage(level: u64) -> Result<KeyStorage, AttestError> {
    match level {
        0 => Ok(KeyStorage::Software),
        1 => Ok(KeyStorage::Tee),
        2 => Ok(KeyStorage::StrongBox),
        _ => Err(AttestError::Malformed("security level")),
    }
}

// AuthorizationList tags used here (KeyMint `Tag` numbers).
const TAG_ORIGIN: u32 = 702;
const TAG_ROOT_OF_TRUST: u32 = 704;
const TAG_OS_PATCH_LEVEL: u32 = 706;
const TAG_ATTESTATION_APPLICATION_ID: u32 = 709;
const ORIGIN_GENERATED: u64 = 0;
const VERIFIED_BOOT_VERIFIED: u64 = 0;

/// An AuthorizationList: its explicitly tagged fields, each tag at most once.
struct AuthList<'a>(Vec<(u32, Tlv<'a>)>);

impl<'a> AuthList<'a> {
    fn parse(t: &Tlv<'a>, what: &'static str) -> Result<Self, AttestError> {
        let mut fields: Vec<(u32, Tlv<'a>)> = Vec::new();
        for f in t.children(TAG_SEQUENCE, what)? {
            if f.class != CLASS_CONTEXT {
                return Err(AttestError::Malformed(what));
            }
            if fields.iter().any(|(tag, _)| *tag == f.tag) {
                return Err(AttestError::Malformed("duplicate authorization tag"));
            }
            fields.push((f.tag, f.explicit(what)?));
        }
        Ok(AuthList(fields))
    }

    fn get(&self, tag: u32) -> Option<&Tlv<'a>> {
        self.0.iter().find(|(t, _)| *t == tag).map(|(_, v)| v)
    }
}

/// The hardware-enforced `RootOfTrust`.
#[derive(Debug)]
pub struct RootOfTrust {
    pub verified_boot_key: Vec<u8>,
    pub device_locked: bool,
    /// Verified (0), SelfSigned (1), Unverified (2), Failed (3).
    pub verified_boot_state: u64,
    pub verified_boot_hash: Option<Vec<u8>>,
}

/// The parts of the KeyDescription the appraisal uses.
#[derive(Debug)]
pub struct KeyDescription {
    pub attestation_version: u64,
    pub attestation_security_level: KeyStorage,
    pub keymint_security_level: KeyStorage,
    pub challenge: Vec<u8>,
    /// From the hardware-enforced list.
    pub origin: Option<u64>,
    /// Hardware-enforced only.
    pub root_of_trust: Option<RootOfTrust>,
    pub os_patch_level: Option<u32>,
    /// `(package names, signing-certificate digests)`.
    pub application: Option<(Vec<String>, Vec<Vec<u8>>)>,
}

pub fn parse_key_description(ext: &[u8]) -> Result<KeyDescription, AttestError> {
    let top = der::read_one(ext)?;
    let f = top.children(TAG_SEQUENCE, "KeyDescription")?;
    if f.len() != 8 {
        return Err(AttestError::Malformed("KeyDescription fields"));
    }
    let software = AuthList::parse(&f[6], "softwareEnforced")?;
    let hardware = AuthList::parse(&f[7], "hardwareEnforced")?;

    let root_of_trust = match hardware.get(TAG_ROOT_OF_TRUST) {
        None => None,
        Some(r) => {
            let r = r.children(TAG_SEQUENCE, "RootOfTrust")?;
            if r.len() < 3 {
                return Err(AttestError::Malformed("RootOfTrust"));
            }
            Some(RootOfTrust {
                verified_boot_key: r[0].octets("verifiedBootKey")?.to_vec(),
                device_locked: r[1].boolean("deviceLocked")?,
                verified_boot_state: r[2].uint("verifiedBootState")?,
                verified_boot_hash: r
                    .get(3)
                    .map(|h| h.octets("verifiedBootHash").map(<[u8]>::to_vec))
                    .transpose()?,
            })
        }
    };
    // The application id is reported by the OS (software-enforced on most
    // devices); a verified boot is what makes it trustworthy.
    let application = match software
        .get(TAG_ATTESTATION_APPLICATION_ID)
        .or_else(|| hardware.get(TAG_ATTESTATION_APPLICATION_ID))
    {
        None => None,
        Some(a) => {
            let id = der::read_one(a.octets("attestationApplicationId")?)?;
            let parts = id.children(TAG_SEQUENCE, "AttestationApplicationId")?;
            if parts.len() != 2 {
                return Err(AttestError::Malformed("AttestationApplicationId"));
            }
            let mut packages = Vec::new();
            for p in parts[0].children(TAG_SET, "package infos")? {
                let info = p.children(TAG_SEQUENCE, "AttestationPackageInfo")?;
                let name = info
                    .first()
                    .ok_or(AttestError::Malformed("package name"))?
                    .octets("package name")?;
                packages.push(
                    String::from_utf8(name.to_vec())
                        .map_err(|_| AttestError::Malformed("package name"))?,
                );
            }
            let digests = parts[1]
                .children(TAG_SET, "signature digests")?
                .iter()
                .map(|d| d.octets("signature digest").map(<[u8]>::to_vec))
                .collect::<Result<Vec<_>, _>>()?;
            Some((packages, digests))
        }
    };
    Ok(KeyDescription {
        attestation_version: f[0].uint("attestationVersion")?,
        attestation_security_level: storage(f[1].uint("attestationSecurityLevel")?)?,
        keymint_security_level: storage(f[3].uint("keyMintSecurityLevel")?)?,
        challenge: f[4].octets("attestationChallenge")?.to_vec(),
        origin: hardware
            .get(TAG_ORIGIN)
            .map(|o| o.uint("origin"))
            .transpose()?,
        root_of_trust,
        os_patch_level: hardware
            .get(TAG_OS_PATCH_LEVEL)
            .map(|p| p.uint("osPatchLevel").map(|v| v as u32))
            .transpose()?,
        application,
    })
}

/// Appraise an attested key's certificate chain (leaf first).
///
/// `expected_challenge` is `attest_challenge(verifier_challenge, session_pub)`.
/// `now_yyyymm` is today's month for the patch-level check.
pub fn appraise(
    chain: &[Vec<u8>],
    expected_challenge: &[u8; 32],
    session_pub: &[u8; 32],
    policy: &AndroidPolicy,
    now_unix: i64,
    now_yyyymm: u32,
) -> Result<Claims, AttestError> {
    let revoked = |serial: &str| policy.revoked.contains(serial);
    let certs = x509::verify_chain(
        chain,
        &policy.roots,
        ChainOptions {
            now_unix: Some(now_unix),
            // Leaves carry placeholder validity (1970 .. 2048 and similar).
            skip_leaf_validity: true,
            revoked: Some(&revoked),
        },
    )?;
    let leaf = &certs[0];
    // Only the leaf may carry a KeyDescription: one higher up would mean an
    // attested key signed another "attestation".
    if certs[1..]
        .iter()
        .any(|c| c.extension(OID_KEY_DESCRIPTION).is_some())
    {
        return Err(AttestError::Malformed("KeyDescription above the leaf"));
    }
    let kd = parse_key_description(
        leaf.extension(OID_KEY_DESCRIPTION)
            .ok_or(AttestError::Malformed("no KeyDescription"))?,
    )?;

    if kd.attestation_version < 3 {
        return Err(AttestError::Policy("attestation version too old"));
    }
    let key_storage = kd.attestation_security_level.min(kd.keymint_security_level);
    if key_storage == KeyStorage::Software {
        return Err(AttestError::Policy("software attestation"));
    }
    if kd.challenge != expected_challenge {
        return Err(AttestError::ChallengeMismatch);
    }
    if kd.origin != Some(ORIGIN_GENERATED) {
        return Err(AttestError::Policy("key not generated in hardware"));
    }
    let root_of_trust = kd
        .root_of_trust
        .as_ref()
        .ok_or(AttestError::Policy("no hardware root of trust"))?;
    let verified_boot =
        root_of_trust.device_locked && root_of_trust.verified_boot_state == VERIFIED_BOOT_VERIFIED;

    let mut warnings = vec!["no-stable-device-id".to_string()];
    let app_attested = match &kd.application {
        Some((packages, digests)) => policy.apps.iter().any(|app| {
            packages.contains(&app.package)
                && digests
                    .iter()
                    .any(|d| app.signer_sha256.iter().any(|a| d[..] == a[..]))
        }),
        None => false,
    };
    if !app_attested {
        warnings.push("app-not-attested".into());
    }
    if let (Some(max), Some(patch)) = (policy.max_patch_age_months, kd.os_patch_level) {
        if attest_core::patch_age_months(patch, now_yyyymm) > max {
            return Err(AttestError::Policy("OS patch level too old"));
        }
    }
    if !verified_boot {
        warnings.push("boot-not-verified".into());
    }
    // KeyMint 2 (Android 13+) makes Ed25519 keys in the TEE: then the session
    // key itself is the attested hardware key.
    let session_key_in_hw =
        leaf.key_algorithm() == OID_ED25519 && leaf.public_key_bytes() == &session_pub[..];
    if !session_key_in_hw {
        warnings.push("session-key-in-software".into());
    }
    Ok(Claims {
        platform: "android",
        key_storage,
        verified_boot: Some(verified_boot),
        app_attested,
        session_key_in_hw,
        os_patch_level: kd.os_patch_level,
        hardware_identity: None,
        warnings,
    })
}
