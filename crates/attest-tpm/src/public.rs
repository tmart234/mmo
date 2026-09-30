//! `TPMT_PUBLIC` (TPM 2.0 Part 2, 12.2.4): a TPM key's public area, its
//! attributes, and its Name (the name algorithm's digest of the area, which
//! credential activation and quotes refer to).

use aws_lc_rs::digest;

use crate::marshal::Reader;
use crate::{alg, TpmError};

/// `TPMA_OBJECT` bits.
pub mod attr {
    pub const FIXED_TPM: u32 = 1 << 1;
    pub const ST_CLEAR: u32 = 1 << 2;
    pub const FIXED_PARENT: u32 = 1 << 4;
    pub const SENSITIVE_DATA_ORIGIN: u32 = 1 << 5;
    pub const USER_WITH_AUTH: u32 = 1 << 6;
    pub const ADMIN_WITH_POLICY: u32 = 1 << 7;
    pub const NO_DA: u32 = 1 << 10;
    pub const ENCRYPTED_DUPLICATION: u32 = 1 << 11;
    pub const RESTRICTED: u32 = 1 << 16;
    pub const DECRYPT: u32 = 1 << 17;
    pub const SIGN_ENCRYPT: u32 = 1 << 18;
}

/// A key's algorithm and public value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyParams {
    Rsa {
        /// `TPMT_RSA_SCHEME` (`TPM_ALG_NULL` if none) and its hash.
        scheme: (u16, Option<u16>),
        bits: u16,
        exponent: u32,
        modulus: Vec<u8>,
    },
    Ecc {
        scheme: (u16, Option<u16>),
        curve: u16,
        x: Vec<u8>,
        y: Vec<u8>,
    },
}

/// A parsed `TPMT_PUBLIC`, keeping its bytes (the Name is their digest).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Public {
    pub name_alg: u16,
    pub attributes: u32,
    pub auth_policy: Vec<u8>,
    /// `TPMT_SYM_DEF_OBJECT` for storage keys (an EK): algorithm, key bits,
    /// mode; `None` for `TPM_ALG_NULL`.
    pub symmetric: Option<(u16, u16, u16)>,
    pub params: KeyParams,
    /// The marshalled `TPMT_PUBLIC`.
    pub bytes: Vec<u8>,
}

fn scheme(r: &mut Reader<'_>) -> Result<(u16, Option<u16>), TpmError> {
    let scheme = r.u16()?;
    Ok(match scheme {
        alg::NULL | alg::RSAES => (scheme, None),
        alg::ECDAA => {
            let hash = r.u16()?;
            let _count = r.u16()?;
            (scheme, Some(hash))
        }
        _ => (scheme, Some(r.u16()?)),
    })
}

impl Public {
    /// A `TPM2B_PUBLIC` (what `tpm2_createak -f tss` and `TPM2_ReadPublic`
    /// give).
    pub fn from_tpm2b(bytes: &[u8]) -> Result<Self, TpmError> {
        let mut r = Reader::new(bytes, "TPM2B_PUBLIC");
        let inner = r.tpm2b()?;
        r.end()?;
        Self::from_tpmt(inner)
    }

    /// A `TPMT_PUBLIC`.
    pub fn from_tpmt(bytes: &[u8]) -> Result<Self, TpmError> {
        let mut r = Reader::new(bytes, "TPMT_PUBLIC");
        let kind = r.u16()?;
        let name_alg = r.u16()?;
        let attributes = r.u32()?;
        let auth_policy = r.tpm2b()?.to_vec();
        let symmetric = match r.u16()? {
            alg::NULL => None,
            a => Some((a, r.u16()?, r.u16()?)),
        };
        let params = match kind {
            alg::RSA => {
                let scheme = scheme(&mut r)?;
                let bits = r.u16()?;
                let exponent = r.u32()?;
                let modulus = r.tpm2b()?.to_vec();
                if modulus.len() * 8 != bits as usize {
                    return Err(TpmError::Malformed("RSA modulus size"));
                }
                KeyParams::Rsa {
                    scheme,
                    bits,
                    // (0 means the default, 2^16 + 1)
                    exponent: if exponent == 0 { 65537 } else { exponent },
                    modulus,
                }
            }
            alg::ECC => {
                let scheme = scheme(&mut r)?;
                let curve = r.u16()?;
                let _kdf = scheme_kdf(&mut r)?;
                let x = r.tpm2b()?.to_vec();
                let y = r.tpm2b()?.to_vec();
                KeyParams::Ecc {
                    scheme,
                    curve,
                    x,
                    y,
                }
            }
            _ => return Err(TpmError::Unsupported("key type")),
        };
        r.end()?;
        Ok(Public {
            name_alg,
            attributes,
            auth_policy,
            symmetric,
            params,
            bytes: bytes.to_vec(),
        })
    }

    pub fn has(&self, bits: u32) -> bool {
        self.attributes & bits == bits
    }

    /// The Name: `nameAlg || H_nameAlg(TPMT_PUBLIC)`.
    pub fn name(&self) -> Result<Vec<u8>, TpmError> {
        let mut out = self.name_alg.to_be_bytes().to_vec();
        out.extend_from_slice(&hash(self.name_alg, &self.bytes)?);
        Ok(out)
    }

    /// A key the TPM made and keeps (`fixedTPM`, `fixedParent`,
    /// `sensitiveDataOrigin`) that only signs what the TPM itself produced
    /// (`restricted` + `sign`, not `decrypt`): an Attestation Key. A quote
    /// signed by anything else could be forged by whoever holds the key.
    pub fn check_attestation_key(&self) -> Result<(), TpmError> {
        let required = attr::FIXED_TPM
            | attr::FIXED_PARENT
            | attr::SENSITIVE_DATA_ORIGIN
            | attr::RESTRICTED
            | attr::SIGN_ENCRYPT;
        if !self.has(required) || self.has(attr::DECRYPT) {
            return Err(TpmError::Policy(
                "not a restricted signing key made in the TPM",
            ));
        }
        Ok(())
    }

    /// An Endorsement Key: a restricted decryption key fixed to the TPM
    /// (the TCG EK templates). Credential activation encrypts to it.
    pub fn check_endorsement_key(&self) -> Result<(), TpmError> {
        let required = attr::FIXED_TPM
            | attr::FIXED_PARENT
            | attr::SENSITIVE_DATA_ORIGIN
            | attr::RESTRICTED
            | attr::DECRYPT;
        if !self.has(required) || self.has(attr::SIGN_ENCRYPT) {
            return Err(TpmError::Policy(
                "not a restricted decryption key fixed to the TPM",
            ));
        }
        match self.symmetric {
            Some((alg::AES, 128 | 256, alg::CFB)) => Ok(()),
            _ => Err(TpmError::Unsupported("EK symmetric algorithm")),
        }
    }
}

fn scheme_kdf(r: &mut Reader<'_>) -> Result<(u16, Option<u16>), TpmError> {
    let kdf = r.u16()?;
    Ok(if kdf == alg::NULL {
        (kdf, None)
    } else {
        (kdf, Some(r.u16()?))
    })
}

/// A TPM hash algorithm's digest.
pub fn hash(hash_alg: u16, data: &[u8]) -> Result<Vec<u8>, TpmError> {
    let a = match hash_alg {
        alg::SHA256 => &digest::SHA256,
        alg::SHA384 => &digest::SHA384,
        alg::SHA512 => &digest::SHA512,
        alg::SHA1 => &digest::SHA1_FOR_LEGACY_USE_ONLY,
        _ => return Err(TpmError::Unsupported("hash algorithm")),
    };
    Ok(digest::digest(a, data).as_ref().to_vec())
}

pub fn hash_len(hash_alg: u16) -> Result<usize, TpmError> {
    Ok(match hash_alg {
        alg::SHA1 => 20,
        alg::SHA256 => 32,
        alg::SHA384 => 48,
        alg::SHA512 => 64,
        _ => return Err(TpmError::Unsupported("hash algorithm")),
    })
}
