//! Android key attestation appraisal against synthetic chains (a test root
//! standing in for Google's), one attack per test.

use attest_android::{appraise, parse_status_list, AllowedApp, AndroidPolicy, OID_KEY_DESCRIPTION};
use attest_core::der::write as w;
use attest_core::{
    attest_challenge, attest_challenge_hw_key, device_tier, AttestError, Claims, KeyStorage,
};
use fpp_types::DeviceTier;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CustomExtension, DistinguishedName, DnType,
    IsCa, KeyPair, SerialNumber,
};

const NOW: i64 = 1_790_000_000; // 2026-09
const NOW_YYYYMM: u32 = 202609;
const PACKAGE: &str = "com.halo.decomp";
const SIGNER: [u8; 32] = [0x5a; 32];

struct Kd {
    version: u64,
    att_level: u64,
    key_level: u64,
    challenge: Vec<u8>,
    origin: Option<u64>,
    locked: bool,
    boot_state: u64,
    root_of_trust_in_software: bool,
    patch: u64,
    package: &'static str,
    signer: [u8; 32],
}

impl Kd {
    fn good(challenge: [u8; 32]) -> Self {
        Kd {
            version: 200,
            att_level: 1,
            key_level: 1,
            challenge: challenge.to_vec(),
            origin: Some(0),
            locked: true,
            boot_state: 0,
            root_of_trust_in_software: false,
            patch: 202608,
            package: PACKAGE,
            signer: SIGNER,
        }
    }

    fn der(&self) -> Vec<u8> {
        let rot = w::explicit(
            704,
            &w::seq(&[
                w::octets(&[1; 32]),
                w::boolean(self.locked),
                w::enumerated(self.boot_state),
                w::octets(&[2; 32]),
            ]),
        );
        let app_id = w::seq(&[
            w::set(&[w::seq(&[w::octets(self.package.as_bytes()), w::int(42)])]),
            w::set(&[w::octets(&self.signer)]),
        ]);
        let mut software = vec![w::explicit(709, &w::octets(&app_id))];
        let mut hardware = vec![w::explicit(1, &w::set(&[w::int(2)]))];
        if let Some(o) = self.origin {
            hardware.push(w::explicit(702, &w::int(o)));
        }
        if self.root_of_trust_in_software {
            software.push(rot);
        } else {
            hardware.push(rot);
        }
        hardware.push(w::explicit(706, &w::int(self.patch)));
        w::seq(&[
            w::int(self.version),
            w::enumerated(self.att_level),
            w::int(self.version),
            w::enumerated(self.key_level),
            w::octets(&self.challenge),
            w::octets(&[]),
            w::seq(&software),
            w::seq(&hardware),
        ])
    }
}

fn name(cn: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn);
    dn
}

fn ca(cn: &str, serial: u64) -> CertificateParams {
    let mut p = CertificateParams::new(vec![]);
    p.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
    p.distinguished_name = name(cn);
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.serial_number = Some(SerialNumber::from(serial));
    p
}

struct Fixture {
    root: Certificate,
    intermediate: Certificate,
}

impl Fixture {
    fn new() -> Self {
        Fixture {
            root: Certificate::from_params(ca("test root", 1)).unwrap(),
            intermediate: Certificate::from_params(ca("attestation batch", 2)).unwrap(),
        }
    }

    fn roots(&self) -> Vec<Vec<u8>> {
        vec![self.root.serialize_der().unwrap()]
    }

    /// A chain for a leaf with this key and KeyDescription.
    fn chain(&self, kd: &Kd, leaf_key: KeyPair) -> Vec<Vec<u8>> {
        let mut p = CertificateParams::new(vec![]);
        p.alg = if leaf_key.is_compatible(&rcgen::PKCS_ED25519) {
            &rcgen::PKCS_ED25519
        } else {
            &rcgen::PKCS_ECDSA_P256_SHA256
        };
        p.key_pair = Some(leaf_key);
        p.distinguished_name = name("Android Keystore Key");
        p.serial_number = Some(SerialNumber::from(3u64));
        p.custom_extensions.push(CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17],
            kd.der(),
        ));
        let leaf = Certificate::from_params(p).unwrap();
        vec![
            leaf.serialize_der_with_signer(&self.intermediate).unwrap(),
            self.intermediate
                .serialize_der_with_signer(&self.root)
                .unwrap(),
            self.root.serialize_der().unwrap(),
        ]
    }

    fn policy(&self) -> AndroidPolicy {
        AndroidPolicy {
            roots: self.roots(),
            apps: vec![AllowedApp {
                package: PACKAGE.into(),
                signer_sha256: vec![SIGNER],
            }],
            revoked: Default::default(),
            max_patch_age_months: Some(12),
        }
    }
}

const VS_CHALLENGE: [u8; 32] = [9; 32];
const SESSION: [u8; 32] = [7; 32];

fn good() -> Kd {
    Kd::good(attest_challenge(&VS_CHALLENGE, &SESSION))
}

fn p256() -> KeyPair {
    KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap()
}

/// A P-256 leaf endorsing the software session key `SESSION`.
fn run_with(f: &Fixture, kd: &Kd, policy: &AndroidPolicy) -> Result<Claims, AttestError> {
    let chain = f.chain(kd, p256());
    appraise(&chain, &VS_CHALLENGE, &SESSION, policy, NOW, NOW_YYYYMM)
}

fn run(kd: &Kd) -> Result<Claims, AttestError> {
    let f = Fixture::new();
    run_with(&f, kd, &f.policy())
}

#[test]
fn oid_constant_matches_fixture() {
    assert_eq!(OID_KEY_DESCRIPTION, "1.3.6.1.4.1.11129.2.1.17");
}

#[test]
fn tee_key_with_software_session_key_is_d1() {
    let c = run(&good()).unwrap();
    assert_eq!(c.key_storage, KeyStorage::Tee);
    assert_eq!(c.verified_boot, Some(true));
    assert!(c.app_attested);
    assert!(!c.session_key_in_hw);
    assert_eq!(c.os_patch_level, Some(202608));
    assert_eq!(device_tier(&c), DeviceTier::D1Software);
}

#[test]
fn ed25519_session_key_in_hardware_is_d2() {
    let f = Fixture::new();
    let key = KeyPair::generate(&rcgen::PKCS_ED25519).unwrap();
    let session: [u8; 32] = key.public_key_raw().try_into().unwrap();
    // the key is made with the challenge, so the challenge cannot hold its
    // public key: it binds the Verifier's challenge, and the key itself is
    // the session key
    let chain = f.chain(&Kd::good(attest_challenge_hw_key(&VS_CHALLENGE)), key);
    let c = appraise(
        &chain,
        &VS_CHALLENGE,
        &session,
        &f.policy(),
        NOW,
        NOW_YYYYMM,
    )
    .unwrap();
    assert!(c.session_key_in_hw);
    assert_eq!(device_tier(&c), DeviceTier::D2Hardware);
    // The same chain presented for another session key is refused: the key
    // is not that session key, and the challenge does not name it.
    let err = appraise(
        &chain,
        &VS_CHALLENGE,
        &[8u8; 32],
        &f.policy(),
        NOW,
        NOW_YYYYMM,
    );
    assert_eq!(err.unwrap_err(), AttestError::ChallengeMismatch);
    // Nor for another admission.
    let err = appraise(&chain, &[0x77; 32], &session, &f.policy(), NOW, NOW_YYYYMM);
    assert_eq!(err.unwrap_err(), AttestError::ChallengeMismatch);
}

/// StrongBox (and the Secure Enclave, TPMs) have no Ed25519: an ES256
/// session key that is the attested P-256 key itself earns D2 as well.
#[test]
fn p256_session_key_in_strongbox_is_d2() {
    let f = Fixture::new();
    let strongbox = |challenge| {
        let mut kd = Kd::good(challenge);
        kd.att_level = 2;
        kd.key_level = 2;
        kd
    };
    let key = p256();
    let session = key.public_key_raw().to_vec();
    assert_eq!((session.len(), session[0]), (65, 4));
    let chain = f.chain(&strongbox(attest_challenge_hw_key(&VS_CHALLENGE)), key);
    let c = appraise(
        &chain,
        &VS_CHALLENGE,
        &session,
        &f.policy(),
        NOW,
        NOW_YYYYMM,
    )
    .unwrap();
    assert_eq!(c.key_storage, KeyStorage::StrongBox);
    assert!(c.session_key_in_hw);
    assert_eq!(device_tier(&c), DeviceTier::D2Hardware);
    // A P-256 key that endorses a software session key (made first, so its
    // challenge names it) is D1: the session key can be copied out.
    let chain = f.chain(
        &strongbox(attest_challenge(&VS_CHALLENGE, &SESSION)),
        p256(),
    );
    let c = appraise(
        &chain,
        &VS_CHALLENGE,
        &SESSION,
        &f.policy(),
        NOW,
        NOW_YYYYMM,
    )
    .unwrap();
    assert!(!c.session_key_in_hw);
    assert_eq!(device_tier(&c), DeviceTier::D1Software);
    // A hardware key's chain (no session key in its challenge) presented for
    // a software session key is refused.
    let chain = f.chain(&strongbox(attest_challenge_hw_key(&VS_CHALLENGE)), p256());
    let err = appraise(
        &chain,
        &VS_CHALLENGE,
        &SESSION,
        &f.policy(),
        NOW,
        NOW_YYYYMM,
    );
    assert_eq!(err.unwrap_err(), AttestError::ChallengeMismatch);
}

#[test]
fn strongbox_is_reported() {
    let mut kd = good();
    kd.att_level = 2;
    kd.key_level = 2;
    assert_eq!(run(&kd).unwrap().key_storage, KeyStorage::StrongBox);
}

#[test]
fn replayed_for_another_challenge_is_refused() {
    let kd = Kd::good(attest_challenge(&[1; 32], &SESSION));
    assert_eq!(run(&kd).unwrap_err(), AttestError::ChallengeMismatch);
}

#[test]
fn software_keystore_is_refused() {
    let mut kd = good();
    kd.att_level = 0;
    kd.key_level = 0;
    assert_eq!(
        run(&kd).unwrap_err(),
        AttestError::Policy("software attestation")
    );
    // Attested in the TEE, but the key itself in software: still refused.
    let mut kd = good();
    kd.key_level = 0;
    assert!(run(&kd).is_err());
}

#[test]
fn unlocked_bootloader_is_d0() {
    let mut kd = good();
    kd.locked = false;
    kd.boot_state = 2; // Unverified
    let c = run(&kd).unwrap();
    assert_eq!(c.verified_boot, Some(false));
    assert_eq!(device_tier(&c), DeviceTier::D0Unknown);
}

#[test]
fn root_of_trust_only_in_software_list_is_refused() {
    let mut kd = good();
    kd.root_of_trust_in_software = true;
    assert_eq!(
        run(&kd).unwrap_err(),
        AttestError::Policy("no hardware root of trust")
    );
}

#[test]
fn imported_key_is_refused() {
    let mut kd = good();
    kd.origin = Some(2); // IMPORTED
    assert!(run(&kd).is_err());
    kd.origin = None;
    assert!(run(&kd).is_err());
}

#[test]
fn other_app_is_not_attested() {
    let mut kd = good();
    kd.package = "com.cheat.loader";
    let c = run(&kd).unwrap();
    assert!(!c.app_attested);
    assert_eq!(device_tier(&c), DeviceTier::D0Unknown);
    // Our package name, re-signed by someone else.
    let mut kd = good();
    kd.signer = [0x11; 32];
    assert!(!run(&kd).unwrap().app_attested);
}

#[test]
fn stale_patch_level_is_refused() {
    let mut kd = good();
    kd.patch = 202401;
    assert_eq!(
        run(&kd).unwrap_err(),
        AttestError::Policy("OS patch level too old")
    );
}

#[test]
fn old_attestation_version_is_refused() {
    let mut kd = good();
    kd.version = 2;
    assert!(run(&kd).is_err());
}

#[test]
fn untrusted_root_is_refused() {
    let f = Fixture::new();
    let other = Fixture::new();
    let chain = f.chain(&good(), p256());
    let err = appraise(
        &chain,
        &VS_CHALLENGE,
        &SESSION,
        &other.policy(),
        NOW,
        NOW_YYYYMM,
    );
    assert_eq!(err.unwrap_err(), AttestError::UntrustedRoot);
    // Nor do Google's real roots accept the test chain.
    let mut policy = f.policy();
    policy.roots = attest_android::google_roots();
    assert_eq!(
        run_with(&f, &good(), &policy).unwrap_err(),
        AttestError::UntrustedRoot
    );
}

#[test]
fn revoked_batch_certificate_is_refused() {
    let f = Fixture::new();
    let mut policy = f.policy();
    policy.revoked = parse_status_list(
        r#"{"entries": {"2": {"status": "REVOKED", "reason": "KEY_COMPROMISE"}}}"#,
    )
    .unwrap();
    assert_eq!(
        run_with(&f, &good(), &policy).unwrap_err(),
        AttestError::Revoked
    );
}

#[test]
fn tampered_leaf_is_refused() {
    let f = Fixture::new();
    let mut chain = f.chain(&good(), p256());
    let n = chain[0].len();
    chain[0][n - 1] ^= 1; // the signature
    let err = appraise(
        &chain,
        &VS_CHALLENGE,
        &SESSION,
        &f.policy(),
        NOW,
        NOW_YYYYMM,
    );
    assert!(err.is_err());
    // A leaf presented without its intermediate does not chain.
    let chain = f.chain(&good(), p256());
    let err = appraise(
        &chain[..1],
        &VS_CHALLENGE,
        &SESSION,
        &f.policy(),
        NOW,
        NOW_YYYYMM,
    );
    assert!(err.is_err());
}

#[test]
fn google_roots_are_pinned() {
    assert_eq!(attest_android::google_roots().len(), 2);
}
