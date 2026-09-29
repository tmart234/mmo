//! X.509 chains to a pinned vendor root, with signatures checked by
//! aws-lc-rs (the same library as the TLS stack).
//!
//! These chains are not TLS chains: attestation certificates carry no
//! extended key usage and no names to match, so a TLS verifier does not fit.
//! What is checked: each certificate's signature by the next one's key, the
//! top one by (or equal to) a pinned root, issuer/subject names along the
//! chain, validity at `now` where the caller asks for it, and a revocation
//! list of serial numbers.

use aws_lc_rs::signature::{self, UnparsedPublicKey, VerificationAlgorithm};
use x509_parser::prelude::*;

use crate::AttestError;

pub const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
pub const OID_RSA: &str = "1.2.840.113549.1.1.1";
pub const OID_ED25519: &str = "1.3.101.112";
const OID_P256: &str = "1.2.840.10045.3.1.7";
const OID_P384: &str = "1.3.132.0.34";
const OID_ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";
const OID_ECDSA_SHA384: &str = "1.2.840.10045.4.3.3";
const OID_RSA_SHA256: &str = "1.2.840.113549.1.1.11";
const OID_RSA_SHA384: &str = "1.2.840.113549.1.1.12";
const OID_RSA_SHA512: &str = "1.2.840.113549.1.1.13";

fn cert_err(what: &'static str) -> AttestError {
    AttestError::Certificate(what)
}

/// A parsed certificate, keeping its DER.
pub struct Cert<'a> {
    pub der: &'a [u8],
    pub x509: X509Certificate<'a>,
}

impl<'a> Cert<'a> {
    pub fn parse(der: &'a [u8]) -> Result<Self, AttestError> {
        let (rest, x509) = X509Certificate::from_der(der).map_err(|_| cert_err("not DER X.509"))?;
        if !rest.is_empty() {
            return Err(cert_err("trailing bytes"));
        }
        Ok(Cert { der, x509 })
    }

    /// The raw value of an extension, by dotted OID.
    pub fn extension(&self, oid: &str) -> Option<&'a [u8]> {
        self.x509
            .extensions()
            .iter()
            .find(|e| e.oid.to_id_string() == oid)
            .map(|e| e.value)
    }

    /// Lowercase hex serial, without leading zeros (Google's status list form).
    pub fn serial_hex(&self) -> String {
        let s = self.x509.tbs_certificate.serial.to_str_radix(16);
        s.to_ascii_lowercase()
    }

    pub fn spki_der(&self) -> &[u8] {
        self.x509.public_key().raw
    }

    /// The subject public key: the uncompressed point (EC), `RSAPublicKey`
    /// (RSA) or 32 bytes (Ed25519).
    pub fn public_key_bytes(&self) -> &[u8] {
        &self.x509.public_key().subject_public_key.data
    }

    pub fn key_algorithm(&self) -> String {
        self.x509.public_key().algorithm.algorithm.to_id_string()
    }

    fn curve(&self) -> Option<String> {
        let params = self.x509.public_key().algorithm.parameters.as_ref()?;
        params.as_oid().ok().map(|o| o.to_id_string())
    }

    /// Verify `sig` over `msg` with this certificate's key, the algorithm
    /// given by `sig_alg` (a signature-algorithm OID).
    pub fn verify(&self, sig_alg: &str, msg: &[u8], sig: &[u8]) -> Result<(), AttestError> {
        let alg: &'static dyn VerificationAlgorithm = match (self.key_algorithm().as_str(), sig_alg)
        {
            (OID_EC_PUBLIC_KEY, OID_ECDSA_SHA256) => match self.curve().as_deref() {
                Some(OID_P256) => &signature::ECDSA_P256_SHA256_ASN1,
                Some(OID_P384) => &signature::ECDSA_P384_SHA256_ASN1,
                _ => return Err(AttestError::BadSignature("curve")),
            },
            (OID_EC_PUBLIC_KEY, OID_ECDSA_SHA384) => match self.curve().as_deref() {
                Some(OID_P256) => &signature::ECDSA_P256_SHA384_ASN1,
                Some(OID_P384) => &signature::ECDSA_P384_SHA384_ASN1,
                _ => return Err(AttestError::BadSignature("curve")),
            },
            (OID_RSA, OID_RSA_SHA256) => &signature::RSA_PKCS1_2048_8192_SHA256,
            (OID_RSA, OID_RSA_SHA384) => &signature::RSA_PKCS1_2048_8192_SHA384,
            (OID_RSA, OID_RSA_SHA512) => &signature::RSA_PKCS1_2048_8192_SHA512,
            (OID_ED25519, OID_ED25519) => &signature::ED25519,
            _ => return Err(AttestError::BadSignature("algorithm")),
        };
        UnparsedPublicKey::new(alg, self.public_key_bytes())
            .verify(msg, sig)
            .map_err(|_| AttestError::BadSignature("value"))
    }

    /// Whether `issuer` signed this certificate (and names match).
    fn signed_by(&self, issuer: &Cert<'_>) -> Result<(), AttestError> {
        if self.x509.issuer().as_raw() != issuer.x509.subject().as_raw() {
            return Err(cert_err("issuer name"));
        }
        let alg = self.x509.signature_algorithm.algorithm.to_id_string();
        issuer.verify(
            &alg,
            self.x509.tbs_certificate.as_ref(),
            &self.x509.signature_value.data,
        )
    }

    fn valid_at(&self, now_unix: i64) -> bool {
        match ASN1Time::from_timestamp(now_unix) {
            Ok(t) => self.x509.validity().is_valid_at(t),
            Err(_) => false,
        }
    }
}

/// Parse PEM certificates (a vendor root bundle) into DER.
pub fn pem_certificates(pem: &str) -> Result<Vec<Vec<u8>>, AttestError> {
    let mut out = Vec::new();
    for p in Pem::iter_from_buffer(pem.as_bytes()) {
        let p = p.map_err(|_| cert_err("PEM"))?;
        if p.label == "CERTIFICATE" {
            Cert::parse(&p.contents)?;
            out.push(p.contents);
        }
    }
    if out.is_empty() {
        return Err(cert_err("no certificates in PEM"));
    }
    Ok(out)
}

/// What to check besides signatures.
#[derive(Clone, Copy)]
pub struct ChainOptions<'r> {
    /// Unix time to check validity at; `None` skips validity.
    pub now_unix: Option<i64>,
    /// Skip validity on the leaf only (Android leaves carry placeholder dates).
    pub skip_leaf_validity: bool,
    /// Serial numbers (lowercase hex) that are revoked.
    pub revoked: Option<&'r dyn Fn(&str) -> bool>,
}

/// Verify `chain` (leaf first) up to one of `roots` (DER). The chain may end
/// with the root itself or with a certificate the root signed.
pub fn verify_chain<'c>(
    chain: &'c [Vec<u8>],
    roots: &[Vec<u8>],
    opts: ChainOptions<'_>,
) -> Result<Vec<Cert<'c>>, AttestError> {
    if chain.is_empty() || chain.len() > crate::MAX_CHAIN {
        return Err(cert_err("chain length"));
    }
    let certs = chain
        .iter()
        .map(|d| Cert::parse(d))
        .collect::<Result<Vec<_>, _>>()?;
    for (i, c) in certs.iter().enumerate() {
        if let Some(revoked) = opts.revoked {
            if revoked(&c.serial_hex()) {
                return Err(AttestError::Revoked);
            }
        }
        if let Some(now) = opts.now_unix {
            let checked = i != 0 || !opts.skip_leaf_validity;
            if checked && !c.valid_at(now) {
                return Err(cert_err("not valid now"));
            }
        }
    }
    for pair in certs.windows(2) {
        pair[0].signed_by(&pair[1])?;
    }
    let roots = roots
        .iter()
        .map(|d| Cert::parse(d))
        .collect::<Result<Vec<_>, _>>()?;
    let top = certs.last().expect("non-empty");
    let anchored = roots.iter().any(|r| {
        // The top is the pinned root (same key and name, and self-signed) ...
        (r.spki_der() == top.spki_der()
            && r.x509.subject().as_raw() == top.x509.subject().as_raw()
            && top.signed_by(top).is_ok())
            // ... or the pinned root signed it.
            || top.signed_by(r).is_ok()
    });
    if !anchored {
        return Err(AttestError::UntrustedRoot);
    }
    Ok(certs)
}
