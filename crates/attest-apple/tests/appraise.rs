//! App Attest appraisal against synthetic objects (a test root standing in
//! for Apple's), one attack per test.

use attest_apple::{
    appraise_assertion, appraise_attestation, AppKey, ApplePolicy, AAGUID_DEVELOPMENT,
    AAGUID_PRODUCTION,
};
use attest_core::der::write as w;
use attest_core::{attest_challenge, device_tier, AttestError, KeyStorage};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use fpp_types::DeviceTier;
use fpp_wire::cbor::{self, Value};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CustomExtension, DistinguishedName, DnType,
    IsCa, KeyPair,
};
use sha2::{Digest, Sha256};

const NOW: i64 = 1_790_000_000;
const APP_ID: &str = "ABCDE12345.com.halo.decomp";
const CHALLENGE: [u8; 32] = [3; 32];

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn ca(cn: &str, alg: &'static rcgen::SignatureAlgorithm) -> Certificate {
    let mut p = CertificateParams::new(vec![]);
    p.alg = alg;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn);
    p.distinguished_name = dn;
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    Certificate::from_params(p).unwrap()
}

struct Device {
    root: Certificate,
    intermediate: Certificate,
    key_pkcs8: Vec<u8>,
    public_key: Vec<u8>,
}

impl Device {
    fn new() -> Self {
        let key = KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        Device {
            root: ca("test App Attestation Root", &rcgen::PKCS_ECDSA_P384_SHA384),
            intermediate: ca("test App Attestation CA 1", &rcgen::PKCS_ECDSA_P384_SHA384),
            key_pkcs8: key.serialize_der(),
            public_key: key.public_key_raw().to_vec(),
        }
    }

    fn key_id(&self) -> [u8; 32] {
        sha256(&[&self.public_key])
    }

    fn policy(&self) -> ApplePolicy {
        ApplePolicy {
            roots: vec![self.root.serialize_der().unwrap()],
            app_ids: vec![APP_ID.into()],
            allow_development: false,
        }
    }

    fn auth_data(
        &self,
        app_id: &str,
        counter: u32,
        aaguid: [u8; 16],
        credential_id: &[u8],
    ) -> Vec<u8> {
        let mut a = sha256(&[app_id.as_bytes()]).to_vec();
        a.push(0x40);
        a.extend(counter.to_be_bytes());
        a.extend(aaguid);
        a.extend((credential_id.len() as u16).to_be_bytes());
        a.extend(credential_id);
        a.extend([0xa0]); // (the COSE key, not read)
        a
    }

    /// An attestation object for `auth_data`, with the nonce made from
    /// `nonce_client_data`.
    fn attestation(&self, auth_data: &[u8], nonce_client_data: &[u8; 32]) -> Vec<u8> {
        let nonce = sha256(&[auth_data, nonce_client_data]);
        let mut p = CertificateParams::new(vec![]);
        p.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
        p.key_pair = Some(KeyPair::from_der(&self.key_pkcs8).unwrap());
        p.custom_extensions.push(CustomExtension::from_oid_content(
            &[1, 2, 840, 113635, 100, 8, 2],
            w::seq(&[w::explicit(1, &w::octets(&nonce))]),
        ));
        let leaf = Certificate::from_params(p).unwrap();
        // Apple's key order (fmt, attStmt, authData) is not ours to choose.
        let v = Value::Map(vec![
            (Value::text("fmt"), Value::text("apple-appattest")),
            (
                Value::text("attStmt"),
                Value::Map(vec![
                    (
                        Value::text("x5c"),
                        Value::Array(vec![
                            Value::bytes(
                                leaf.serialize_der_with_signer(&self.intermediate).unwrap(),
                            ),
                            Value::bytes(
                                self.intermediate
                                    .serialize_der_with_signer(&self.root)
                                    .unwrap(),
                            ),
                        ]),
                    ),
                    (Value::text("receipt"), Value::bytes(vec![1, 2, 3])),
                ]),
            ),
            (Value::text("authData"), Value::bytes(auth_data.to_vec())),
        ]);
        cbor::encode(&v).unwrap()
    }

    fn good_attestation(&self) -> Vec<u8> {
        let ad = self.auth_data(APP_ID, 0, AAGUID_PRODUCTION, &self.key_id());
        self.attestation(&ad, &CHALLENGE)
    }

    fn assertion(&self, app_id: &str, counter: u32, client_data: &[u8; 32]) -> Vec<u8> {
        let mut ad = sha256(&[app_id.as_bytes()]).to_vec();
        ad.push(0);
        ad.extend(counter.to_be_bytes());
        let nonce = sha256(&[&ad, client_data]);
        let key =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &self.key_pkcs8).unwrap();
        let sig = key.sign(&SystemRandom::new(), &nonce).unwrap();
        cbor::encode(&cbor::text_map([
            ("signature", Value::bytes(sig.as_ref().to_vec())),
            ("authenticatorData", Value::bytes(ad)),
        ]))
        .unwrap()
    }

    fn attested(&self) -> AppKey {
        appraise_attestation(&self.good_attestation(), &CHALLENGE, &self.policy(), NOW)
            .unwrap()
            .1
    }
}

#[test]
fn attestation_is_accepted_as_d1() {
    let d = Device::new();
    let (c, key) =
        appraise_attestation(&d.good_attestation(), &CHALLENGE, &d.policy(), NOW).unwrap();
    assert_eq!(c.key_storage, KeyStorage::SecureEnclave);
    assert!(c.app_attested);
    assert_eq!(c.verified_boot, None);
    assert_eq!(c.hardware_identity.as_deref(), Some(&d.key_id()[..]));
    assert_eq!(key.key_id, d.key_id());
    // A genuine device and app, with a software session key: D1 (04 §4.1).
    assert_eq!(device_tier(&c), DeviceTier::D1Software);
}

#[test]
fn attestation_for_another_challenge_is_refused() {
    let d = Device::new();
    let other = attest_challenge(&[1; 32], &[2; 32]);
    assert_eq!(
        appraise_attestation(&d.good_attestation(), &other, &d.policy(), NOW).unwrap_err(),
        AttestError::ChallengeMismatch
    );
}

#[test]
fn another_app_is_refused() {
    let d = Device::new();
    let ad = d.auth_data(
        "ZZZZZ99999.com.cheat.app",
        0,
        AAGUID_PRODUCTION,
        &d.key_id(),
    );
    assert!(appraise_attestation(
        &d.attestation(&ad, &CHALLENGE),
        &CHALLENGE,
        &d.policy(),
        NOW
    )
    .is_err());
}

#[test]
fn development_keys_need_the_policy() {
    let d = Device::new();
    let ad = d.auth_data(APP_ID, 0, AAGUID_DEVELOPMENT, &d.key_id());
    let att = d.attestation(&ad, &CHALLENGE);
    assert_eq!(
        appraise_attestation(&att, &CHALLENGE, &d.policy(), NOW).unwrap_err(),
        AttestError::Policy("development environment")
    );
    let mut policy = d.policy();
    policy.allow_development = true;
    let (c, _) = appraise_attestation(&att, &CHALLENGE, &policy, NOW).unwrap();
    assert!(c.warnings.iter().any(|w| w == "app-attest-development"));
}

#[test]
fn credential_id_must_be_the_key_id() {
    let d = Device::new();
    let ad = d.auth_data(APP_ID, 0, AAGUID_PRODUCTION, &[0; 32]);
    assert!(appraise_attestation(
        &d.attestation(&ad, &CHALLENGE),
        &CHALLENGE,
        &d.policy(),
        NOW
    )
    .is_err());
}

#[test]
fn nonzero_counter_is_refused() {
    let d = Device::new();
    let ad = d.auth_data(APP_ID, 5, AAGUID_PRODUCTION, &d.key_id());
    assert!(appraise_attestation(
        &d.attestation(&ad, &CHALLENGE),
        &CHALLENGE,
        &d.policy(),
        NOW
    )
    .is_err());
}

#[test]
fn untrusted_root_is_refused() {
    let d = Device::new();
    let mut policy = d.policy();
    policy.roots = attest_apple::apple_roots();
    assert_eq!(
        appraise_attestation(&d.good_attestation(), &CHALLENGE, &policy, NOW).unwrap_err(),
        AttestError::UntrustedRoot
    );
}

#[test]
fn assertions_advance_and_bind_the_challenge() {
    let d = Device::new();
    let mut key = d.attested();
    let session = attest_challenge(&[4; 32], &[5; 32]);
    appraise_assertion(
        &d.assertion(APP_ID, 1, &session),
        &session,
        &mut key,
        &d.policy(),
    )
    .unwrap();
    assert_eq!(key.counter, 1);
    // Replayed: the counter did not advance.
    assert!(appraise_assertion(
        &d.assertion(APP_ID, 1, &session),
        &session,
        &mut key,
        &d.policy()
    )
    .is_err());
    // Made for another challenge.
    let other = attest_challenge(&[6; 32], &[5; 32]);
    assert_eq!(
        appraise_assertion(
            &d.assertion(APP_ID, 2, &session),
            &other,
            &mut key,
            &d.policy()
        )
        .unwrap_err(),
        AttestError::BadSignature("assertion")
    );
    // By another key.
    let stranger = Device::new();
    assert!(appraise_assertion(
        &stranger.assertion(APP_ID, 3, &session),
        &session,
        &mut key,
        &d.policy()
    )
    .is_err());
    appraise_assertion(
        &d.assertion(APP_ID, 7, &session),
        &session,
        &mut key,
        &d.policy(),
    )
    .unwrap();
    assert_eq!(key.counter, 7);
}

#[test]
fn apple_root_is_pinned() {
    assert_eq!(attest_apple::apple_roots().len(), 1);
}
