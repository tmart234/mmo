//! Play Integrity verdicts, minted here as Google mints them (an ES256 JWS
//! in an A256KW/A256GCM JWE), and the ways a client could cheat with one.

use attest_android::integrity::testing::Google;
use attest_android::integrity::{b64url, verify, IntegrityKeys, Verdict};
use attest_android::AllowedApp;
use attest_core::AttestError;
use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use serde_json::{json, Value};

const PACKAGE: &str = "com.halo.decomp";
const SIGNER: [u8; 32] = [0x5a; 32];
const NONCE: [u8; 32] = [0x11; 32];
const NOW: u64 = 1_790_000_000_000;
const MAX_AGE: u64 = 5 * 60 * 1000;

fn verdict(labels: &[&str]) -> Value {
    json!({
        "requestDetails": {
            "requestPackageName": PACKAGE,
            "nonce": b64url(&NONCE),
            "timestampMillis": (NOW - 1000).to_string(),
        },
        "appIntegrity": {
            "appRecognitionVerdict": "PLAY_RECOGNIZED",
            "packageName": PACKAGE,
            "certificateSha256Digest": [b64url(&SIGNER)],
            "versionCode": "42",
        },
        "deviceIntegrity": {"deviceRecognitionVerdict": labels},
        "accountDetails": {"appLicensingVerdict": "LICENSED"},
    })
}

fn apps() -> Vec<AllowedApp> {
    vec![AllowedApp {
        package: PACKAGE.into(),
        signer_sha256: vec![SIGNER],
    }]
}

fn check(g: &Google, token: &str) -> Result<Verdict, AttestError> {
    verify(token, &g.keys(), &NONCE, &apps(), NOW, MAX_AGE)
}

#[test]
fn strong_integrity_verdict() {
    let g = Google::new();
    let v = check(
        &g,
        &g.token(&verdict(&[
            "MEETS_DEVICE_INTEGRITY",
            "MEETS_STRONG_INTEGRITY",
        ])),
    )
    .unwrap();
    assert!(v.device && v.strong);
    assert_eq!(v.package, PACKAGE);
    assert_eq!(v.version_code, Some(42));
    let v = check(&g, &g.token(&verdict(&["MEETS_DEVICE_INTEGRITY"]))).unwrap();
    assert!(v.device && !v.strong);
    let v = check(&g, &g.token(&verdict(&[]))).unwrap();
    assert!(!v.device && !v.strong);
}

#[test]
fn console_keys_parse() {
    let g = Google::new();
    let mut spki = vec![
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ];
    spki.extend_from_slice(g.signing.public_key().as_ref());
    let keys = IntegrityKeys::from_console(&b64url(&g.encryption), &b64url(&spki)).unwrap();
    assert_eq!(keys.decryption, g.encryption);
    assert!(IntegrityKeys::from_console(&b64url(&[1; 16]), &b64url(&spki)).is_err());
    assert!(IntegrityKeys::from_console(&b64url(&g.encryption), &b64url(&spki[1..])).is_err());
}

#[test]
fn a_verdict_for_another_admission_is_refused() {
    let g = Google::new();
    let mut v = verdict(&["MEETS_STRONG_INTEGRITY"]);
    v["requestDetails"]["nonce"] = json!(b64url(&[0x22; 32]));
    assert_eq!(
        check(&g, &g.token(&v)).unwrap_err(),
        AttestError::ChallengeMismatch
    );
}

#[test]
fn a_stale_verdict_is_refused() {
    let g = Google::new();
    let mut v = verdict(&["MEETS_STRONG_INTEGRITY"]);
    v["requestDetails"]["timestampMillis"] = json!((NOW - MAX_AGE - 1).to_string());
    assert!(check(&g, &g.token(&v)).is_err());
}

#[test]
fn another_or_unrecognised_app_is_refused() {
    let g = Google::new();
    let mut v = verdict(&["MEETS_STRONG_INTEGRITY"]);
    v["appIntegrity"]["appRecognitionVerdict"] = json!("UNRECOGNIZED_VERSION");
    assert!(check(&g, &g.token(&v)).is_err());
    let mut v = verdict(&["MEETS_STRONG_INTEGRITY"]);
    v["appIntegrity"]["certificateSha256Digest"] = json!([b64url(&[0x66; 32])]);
    assert!(check(&g, &g.token(&v)).is_err());
    let mut v = verdict(&["MEETS_STRONG_INTEGRITY"]);
    v["appIntegrity"]["packageName"] = json!("com.cheat.loader");
    assert!(check(&g, &g.token(&v)).is_err());
}

#[test]
fn a_forged_or_misdirected_token_is_refused() {
    let g = Google::new();
    let other = Google::new();
    let v = verdict(&["MEETS_STRONG_INTEGRITY"]);
    // signed by another key, encrypted for us
    let forged = Google {
        signing: EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap(),
        encryption: g.encryption,
    };
    assert!(matches!(
        check(&g, &forged.token(&v)),
        Err(AttestError::BadSignature(_))
    ));
    // a genuine token for another app's key
    assert!(matches!(
        check(&g, &other.token(&v)),
        Err(AttestError::BadSignature(_))
    ));
    // tampered ciphertext
    let token = g.token(&v);
    let mut parts: Vec<String> = token.split('.').map(str::to_string).collect();
    let mut c = attest_android::integrity::b64(&parts[3]).unwrap();
    c[0] ^= 1;
    parts[3] = b64url(&c);
    assert!(check(&g, &parts.join(".")).is_err());
    assert!(check(&g, "not.a.token").is_err());
}
