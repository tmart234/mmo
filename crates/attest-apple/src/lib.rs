//! Apple App Attest, Verifier side (ATT-03, roadmap P3).
//!
//! An app instance makes a key in the Secure Enclave
//! (`DCAppAttestService.generateKey`) and has Apple attest it once
//! (`attestKey(keyId, clientDataHash:)`). Later sessions prove possession of
//! the same key with assertions (`generateAssertion`). In both, the client
//! data hash is `attest_challenge(verifier_challenge, session_pub)`.
//!
//! [`appraise_attestation`] checks, as Apple documents: the `x5c` chain to
//! the pinned Apple App Attestation Root CA; the nonce extension
//! (`1.2.840.113635.100.8.2`) equals `SHA-256(authData || clientDataHash)`;
//! the key id is `SHA-256` of the leaf's public key and is the credential id;
//! the RP id hash is `SHA-256` of an allowed App ID (`TEAMID.bundle.id`);
//! the counter is 0; and the AAGUID is production (`appattest` + zeros) or,
//! where allowed, `appattestdevelop`. The Verifier keeps the result as an
//! [`AppKey`].
//!
//! [`appraise_assertion`] checks an assertion by such a key: the signature
//! over `SHA-256(authenticatorData || clientDataHash)`, the RP id hash, and a
//! counter that only moves forward (a replayed or cloned assertion fails).
//!
//! What App Attest does *not* establish: anything about the OS. Its evidence
//! carries no boot measurements, no OS version and no jailbreak verdict. It
//! proves a genuine Apple device's Secure Enclave holds the key and that the
//! key belongs to our app as signed by our team. So `verified_boot` is left
//! unreported, and the receipt (for Apple's fraud-risk metric) is kept for a
//! later adapter.

use attest_core::der::{self, CLASS_CONTEXT, TAG_SEQUENCE};
use attest_core::x509::{self, ChainOptions, OID_EC_PUBLIC_KEY};
use attest_core::{AttestError, Claims, KeyStorage};
use aws_lc_rs::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1};
use fpp_wire::cbor::{self, MapView, Value};
use sha2::{Digest, Sha256};

pub const OID_APP_ATTEST_NONCE: &str = "1.2.840.113635.100.8.2";
pub const AAGUID_PRODUCTION: [u8; 16] = *b"appattest\0\0\0\0\0\0\0";
pub const AAGUID_DEVELOPMENT: [u8; 16] = *b"appattestdevelop";

/// The Apple App Attestation Root CA (roots/README.md).
pub const APPLE_ROOT_PEM: &str = include_str!("../roots/Apple_App_Attestation_Root_CA.pem");

pub fn apple_roots() -> Vec<Vec<u8>> {
    x509::pem_certificates(APPLE_ROOT_PEM).expect("vendored Apple root parses")
}

#[derive(Clone, Debug)]
pub struct ApplePolicy {
    /// Trust anchors (DER); `apple_roots()` in production.
    pub roots: Vec<Vec<u8>>,
    /// Allowed App IDs: `TEAMID.bundle.identifier`.
    pub app_ids: Vec<String>,
    /// Accept keys from the development environment (`appattestdevelop`).
    /// Never in production queues.
    pub allow_development: bool,
}

impl ApplePolicy {
    pub fn production(app_ids: Vec<String>) -> Self {
        ApplePolicy {
            roots: apple_roots(),
            app_ids,
            allow_development: false,
        }
    }
}

/// An attested app key, kept by the Verifier for later assertions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppKey {
    /// `SHA-256` of the public key: Apple's key id.
    pub key_id: [u8; 32],
    /// Uncompressed P-256 point.
    pub public_key: Vec<u8>,
    pub rp_id_hash: [u8; 32],
    pub counter: u32,
    pub development: bool,
}

fn malformed(what: &'static str) -> AttestError {
    AttestError::Malformed(what)
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// WebAuthn-style authenticator data, as App Attest uses it.
struct AuthData<'a> {
    rp_id_hash: [u8; 32],
    counter: u32,
    aaguid: Option<[u8; 16]>,
    credential_id: Option<&'a [u8]>,
}

fn parse_auth_data(b: &[u8], attested: bool) -> Result<AuthData<'_>, AttestError> {
    if b.len() < 37 {
        return Err(malformed("authData"));
    }
    let rp_id_hash = b[..32].try_into().unwrap();
    let counter = u32::from_be_bytes(b[33..37].try_into().unwrap());
    if !attested {
        return Ok(AuthData {
            rp_id_hash,
            counter,
            aaguid: None,
            credential_id: None,
        });
    }
    // flags bit 6 (AT): attested credential data follows.
    if b[32] & 0x40 == 0 || b.len() < 55 {
        return Err(malformed("attested credential data"));
    }
    let aaguid = b[37..53].try_into().unwrap();
    let len = u16::from_be_bytes(b[53..55].try_into().unwrap()) as usize;
    let credential_id = b.get(55..55 + len).ok_or(malformed("credential id"))?;
    Ok(AuthData {
        rp_id_hash,
        counter,
        aaguid: Some(aaguid),
        credential_id: Some(credential_id),
    })
}

fn allowed_rp(policy: &ApplePolicy, rp_id_hash: &[u8; 32]) -> bool {
    policy
        .app_ids
        .iter()
        .any(|id| sha256(&[id.as_bytes()]) == *rp_id_hash)
}

fn claims(key_id: &[u8; 32], development: bool) -> Claims {
    let mut warnings = vec!["session-key-in-software".to_string()];
    if development {
        warnings.push("app-attest-development".into());
    }
    Claims {
        platform: "ios",
        key_storage: KeyStorage::SecureEnclave,
        verified_boot: None,
        app_attested: true,
        // The App Attest key signs only assertions, so it cannot be the FPP
        // session key; a Secure Enclave session key needs P-256 session keys
        // (04 §4.1 S1), a later step.
        session_key_in_hw: false,
        os_patch_level: None,
        // App Attest's key id: stable for the app install (a reinstall makes
        // a new one).
        hardware_identity: Some(key_id.to_vec()),
        warnings,
    }
}

/// Appraise an attestation object; `client_data_hash` is
/// `attest_challenge(verifier_challenge, session_pub)`.
pub fn appraise_attestation(
    attestation: &[u8],
    client_data_hash: &[u8; 32],
    policy: &ApplePolicy,
    now_unix: i64,
) -> Result<(Claims, AppKey), AttestError> {
    let v = cbor::decode_foreign(attestation).map_err(|_| malformed("attestation CBOR"))?;
    let m = MapView::new(&v, "attestation").map_err(|_| malformed("attestation map"))?;
    if m.field("fmt").ok().and_then(Value::as_text) != Some("apple-appattest") {
        return Err(malformed("fmt"));
    }
    let stmt = MapView::new(
        m.field("attStmt").map_err(|_| malformed("attStmt"))?,
        "attStmt",
    )
    .map_err(|_| malformed("attStmt"))?;
    let chain = stmt
        .field("x5c")
        .ok()
        .and_then(Value::as_array)
        .ok_or(malformed("x5c"))?
        .iter()
        .map(|c| c.as_bytes().map(<[u8]>::to_vec))
        .collect::<Option<Vec<_>>>()
        .ok_or(malformed("x5c entry"))?;
    let auth_data = m.bytes("authData").map_err(|_| malformed("authData"))?;

    let certs = x509::verify_chain(
        &chain,
        &policy.roots,
        ChainOptions {
            now_unix: Some(now_unix),
            skip_leaf_validity: false,
            revoked: None,
        },
    )?;
    let leaf = &certs[0];

    // The nonce: SEQUENCE { [1] EXPLICIT OCTET STRING }.
    let nonce_ext = leaf
        .extension(OID_APP_ATTEST_NONCE)
        .ok_or(malformed("no nonce extension"))?;
    let seq = der::read_one(nonce_ext)?.children(TAG_SEQUENCE, "nonce")?;
    let tagged = seq.first().ok_or(malformed("nonce"))?;
    if seq.len() != 1 || !tagged.is(CLASS_CONTEXT, 1) {
        return Err(malformed("nonce"));
    }
    let nonce = tagged.explicit("nonce")?.octets("nonce")?;
    if nonce != sha256(&[auth_data, client_data_hash]) {
        return Err(AttestError::ChallengeMismatch);
    }

    if leaf.key_algorithm() != OID_EC_PUBLIC_KEY || leaf.public_key_bytes().len() != 65 {
        return Err(malformed("leaf key"));
    }
    let key_id = sha256(&[leaf.public_key_bytes()]);
    let ad = parse_auth_data(auth_data, true)?;
    if ad.credential_id != Some(&key_id[..]) {
        return Err(AttestError::Policy("credential id is not the key id"));
    }
    if !allowed_rp(policy, &ad.rp_id_hash) {
        return Err(AttestError::Policy("App ID not allowed"));
    }
    if ad.counter != 0 {
        return Err(AttestError::Policy("attestation counter not 0"));
    }
    let development = match ad.aaguid {
        Some(AAGUID_PRODUCTION) => false,
        Some(AAGUID_DEVELOPMENT) if policy.allow_development => true,
        Some(AAGUID_DEVELOPMENT) => return Err(AttestError::Policy("development environment")),
        _ => return Err(AttestError::Policy("AAGUID")),
    };
    Ok((
        claims(&key_id, development),
        AppKey {
            key_id,
            public_key: leaf.public_key_bytes().to_vec(),
            rp_id_hash: ad.rp_id_hash,
            counter: 0,
            development,
        },
    ))
}

/// Appraise an assertion by a key already attested. On success `key.counter`
/// moves to the assertion's.
pub fn appraise_assertion(
    assertion: &[u8],
    client_data_hash: &[u8; 32],
    key: &mut AppKey,
    policy: &ApplePolicy,
) -> Result<Claims, AttestError> {
    let v = cbor::decode_foreign(assertion).map_err(|_| malformed("assertion CBOR"))?;
    let m = MapView::new(&v, "assertion").map_err(|_| malformed("assertion map"))?;
    let signature = m.bytes("signature").map_err(|_| malformed("signature"))?;
    let auth_data = m
        .bytes("authenticatorData")
        .map_err(|_| malformed("authenticatorData"))?;
    let nonce = sha256(&[auth_data, client_data_hash]);
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &key.public_key)
        .verify(&nonce, signature)
        .map_err(|_| AttestError::BadSignature("assertion"))?;
    let ad = parse_auth_data(auth_data, false)?;
    if ad.rp_id_hash != key.rp_id_hash || !allowed_rp(policy, &ad.rp_id_hash) {
        return Err(AttestError::Policy("App ID not allowed"));
    }
    if key.development && !policy.allow_development {
        return Err(AttestError::Policy("development environment"));
    }
    if ad.counter <= key.counter {
        return Err(AttestError::Policy("assertion counter did not advance"));
    }
    key.counter = ad.counter;
    Ok(claims(&key.key_id, key.development))
}
