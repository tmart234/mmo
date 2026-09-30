//! Endorsement Key certificates: the TPM manufacturer's statement that an
//! EK belongs to a genuine TPM. The certificate is read from the TPM's NV
//! storage (RSA EK at `0x01c00002`, ECC EK at `0x01c0000a`; some firmware
//! TPMs publish theirs online instead), and chains to the manufacturer's
//! root, which the Verifier pins.

use attest_core::der;
use attest_core::x509::{self, ChainOptions, OID_EC_PUBLIC_KEY, OID_RSA};

use crate::public::{hash, KeyParams, Public};
use crate::{alg, TpmError};

/// A verified EK.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endorsement {
    /// SHA-256 of the EK's public area: a stable hardware identity (the
    /// DID's input, 04 §5), and the key revocation lists use.
    pub ek_digest: [u8; 32],
    /// The certificate's issuer, as a string, for logs.
    pub issuer: String,
}

/// Check the EK certificate `chain` (leaf first; intermediates the device
/// sent or the Verifier has) to one of `roots` (DER), and that it certifies
/// `ek` (its public key is the EK's, and the EK has the EK attributes).
pub fn verify_ek(
    ek: &Public,
    chain: &[Vec<u8>],
    roots: &[Vec<u8>],
    now_unix: Option<i64>,
) -> Result<Endorsement, TpmError> {
    ek.check_endorsement_key()?;
    let certs = x509::verify_chain(
        chain,
        roots,
        ChainOptions {
            now_unix,
            skip_leaf_validity: false,
            revoked: None,
        },
    )
    .map_err(TpmError::Certificate)?;
    let leaf = &certs[0];
    let matches = match (&ek.params, leaf.key_algorithm().as_str()) {
        (
            KeyParams::Rsa {
                modulus, exponent, ..
            },
            OID_RSA,
        ) => {
            // RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
            let key = der::read_one(leaf.public_key_bytes()).map_err(TpmError::Certificate)?;
            let parts = der::read_all(key.value).map_err(TpmError::Certificate)?;
            match parts.as_slice() {
                [n, e] => {
                    let strip = |v: &[u8]| v[v.iter().take_while(|b| **b == 0).count()..].to_vec();
                    strip(n.value) == strip(modulus)
                        && strip(e.value) == strip(&exponent.to_be_bytes())
                }
                _ => false,
            }
        }
        (KeyParams::Ecc { x, y, .. }, OID_EC_PUBLIC_KEY) => {
            let point = leaf.public_key_bytes();
            let n = (point.len().saturating_sub(1)) / 2;
            let pad = |v: &[u8]| {
                let mut out = vec![0u8; n.saturating_sub(v.len())];
                out.extend_from_slice(v);
                out
            };
            point.first() == Some(&4)
                && point[1..1 + n] == pad(x)[..]
                && point[1 + n..] == pad(y)[..]
        }
        _ => false,
    };
    if !matches {
        return Err(TpmError::Policy("the EK certificate certifies another key"));
    }
    let mut ek_digest = [0u8; 32];
    ek_digest.copy_from_slice(&hash(alg::SHA256, &ek.bytes)?);
    Ok(Endorsement {
        ek_digest,
        issuer: leaf.x509.issuer().to_string(),
    })
}
