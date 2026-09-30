//! Credential activation (TPM 2.0 Part 1, 24 "Credential Protection";
//! Part 3, `TPM2_MakeCredential` / `TPM2_ActivateCredential`), done by the
//! Verifier without a TPM.
//!
//! An Attestation Key proves nothing by itself: anyone can make a key with
//! the right attributes in software (finding F21). The Verifier ties an AK
//! to a genuine TPM this way:
//!
//! 1. the device sends its EK certificate (checked to a manufacturer root,
//!    [`crate::ek`]), its EK public area and its AK public area;
//! 2. the Verifier checks the AK's attributes, and encrypts a random secret
//!    to the EK, bound to the AK's Name ([`make_credential`]);
//! 3. only the TPM holding that EK can decrypt it, and it does so only for
//!    a key with that Name loaded in the same TPM (`ActivateCredential`);
//! 4. the device returns the secret, and the Verifier enrolls the AK.

use aws_lc_rs::agreement::{self, EphemeralPrivateKey, UnparsedPublicKey};
use aws_lc_rs::cipher::{EncryptingKey, EncryptionContext, UnboundCipherKey, AES_128, AES_256};
use aws_lc_rs::hmac;
use aws_lc_rs::iv::FixedLength;
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use aws_lc_rs::rsa::{
    OaepPublicEncryptingKey, PublicEncryptingKey, PublicKeyComponents, OAEP_SHA256_MGF1SHA256,
};

use crate::marshal::tpm2b;
use crate::public::{hash, hash_len, KeyParams, Public};
use crate::{alg, TpmError};

/// What the device's TPM gets: `TPM2B_ID_OBJECT` and
/// `TPM2B_ENCRYPTED_SECRET`, their contents (without the size prefix).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialChallenge {
    pub id_object: Vec<u8>,
    pub encrypted_secret: Vec<u8>,
}

fn hmac_alg(hash_alg: u16) -> Result<hmac::Algorithm, TpmError> {
    Ok(match hash_alg {
        alg::SHA256 => hmac::HMAC_SHA256,
        alg::SHA384 => hmac::HMAC_SHA384,
        alg::SHA512 => hmac::HMAC_SHA512,
        _ => return Err(TpmError::Unsupported("EK name algorithm")),
    })
}

/// KDFa (Part 1, 11.4.10.2): SP 800-108 counter mode with HMAC.
pub fn kdfa(
    hash_alg: u16,
    key: &[u8],
    label: &str,
    context_u: &[u8],
    context_v: &[u8],
    bits: u32,
) -> Result<Vec<u8>, TpmError> {
    let k = hmac::Key::new(hmac_alg(hash_alg)?, key);
    let bytes = bits.div_ceil(8) as usize;
    let mut out = Vec::with_capacity(bytes);
    let mut counter = 1u32;
    while out.len() < bytes {
        let mut ctx = hmac::Context::with_key(&k);
        ctx.update(&counter.to_be_bytes());
        ctx.update(label.as_bytes());
        ctx.update(&[0]);
        ctx.update(context_u);
        ctx.update(context_v);
        ctx.update(&bits.to_be_bytes());
        out.extend_from_slice(ctx.sign().as_ref());
        counter += 1;
    }
    out.truncate(bytes);
    Ok(out)
}

/// KDFe (Part 1, 11.4.10.3): SP 800-56A concatenation KDF, for ECDH.
pub fn kdfe(
    hash_alg: u16,
    z: &[u8],
    label: &str,
    party_u: &[u8],
    party_v: &[u8],
    bits: u32,
) -> Result<Vec<u8>, TpmError> {
    let bytes = bits.div_ceil(8) as usize;
    let mut out = Vec::with_capacity(bytes);
    let mut counter = 1u32;
    while out.len() < bytes {
        let mut input = counter.to_be_bytes().to_vec();
        input.extend_from_slice(z);
        input.extend_from_slice(label.as_bytes());
        input.push(0);
        input.extend_from_slice(party_u);
        input.extend_from_slice(party_v);
        out.extend(hash(hash_alg, &input)?);
        counter += 1;
    }
    out.truncate(bytes);
    Ok(out)
}

fn left_pad(v: &[u8], n: usize) -> Vec<u8> {
    let mut out = vec![0u8; n.saturating_sub(v.len())];
    out.extend_from_slice(v);
    out
}

/// The seed, and how it travels to the EK: RSA-OAEP with the label
/// "IDENTITY", or an ephemeral ECDH key and KDFe.
fn seed_for(ek: &Public, random: &SystemRandom) -> Result<(Vec<u8>, Vec<u8>), TpmError> {
    let size = hash_len(ek.name_alg)?;
    match &ek.params {
        KeyParams::Rsa {
            modulus, exponent, ..
        } => {
            if ek.name_alg != alg::SHA256 {
                return Err(TpmError::Unsupported("RSA EK name algorithm"));
            }
            let mut seed = vec![0u8; size];
            random.fill(&mut seed).map_err(|_| TpmError::Crypto)?;
            let e = exponent.to_be_bytes();
            let key: PublicEncryptingKey = PublicKeyComponents {
                n: modulus.as_slice(),
                e: &e[e.iter().take_while(|b| **b == 0).count()..],
            }
            .try_into()
            .map_err(|_| TpmError::Unsupported("RSA EK"))?;
            let oaep = OaepPublicEncryptingKey::new(key).map_err(|_| TpmError::Crypto)?;
            let mut out = vec![0u8; oaep.ciphertext_size()];
            let n = oaep
                .encrypt(
                    &OAEP_SHA256_MGF1SHA256,
                    &seed,
                    &mut out,
                    Some(b"IDENTITY\0"),
                )
                .map_err(|_| TpmError::Crypto)?
                .len();
            out.truncate(n);
            Ok((seed, out))
        }
        KeyParams::Ecc { curve, x, y, .. } => {
            let (curve_alg, n) = match *curve {
                alg::NIST_P256 => (&agreement::ECDH_P256, 32),
                alg::NIST_P384 => (&agreement::ECDH_P384, 48),
                _ => return Err(TpmError::Unsupported("EK curve")),
            };
            let ephemeral =
                EphemeralPrivateKey::generate(curve_alg, random).map_err(|_| TpmError::Crypto)?;
            let public = ephemeral
                .compute_public_key()
                .map_err(|_| TpmError::Crypto)?;
            let public = public.as_ref();
            let (ex, ey) = (&public[1..1 + n], &public[1 + n..]);
            let mut point = vec![4u8];
            point.extend(left_pad(x, n));
            point.extend(left_pad(y, n));
            let seed = agreement::agree_ephemeral(
                ephemeral,
                UnparsedPublicKey::new(curve_alg, &point),
                TpmError::Crypto,
                |z| {
                    kdfe(
                        ek.name_alg,
                        z,
                        "IDENTITY",
                        ex,
                        &left_pad(x, n),
                        size as u32 * 8,
                    )
                },
            )?;
            let mut secret = tpm2b(ex);
            secret.extend(tpm2b(ey));
            Ok((seed, secret))
        }
    }
}

/// `TPM2_MakeCredential` in software: `credential` (at most the EK name
/// algorithm's digest size) for the key named `ak_name`, openable only by
/// the TPM holding `ek`.
pub fn make_credential(
    ek: &Public,
    ak_name: &[u8],
    credential: &[u8],
) -> Result<CredentialChallenge, TpmError> {
    ek.check_endorsement_key()?;
    let digest_size = hash_len(ek.name_alg)?;
    if credential.is_empty() || credential.len() > digest_size {
        return Err(TpmError::Policy("credential size"));
    }
    let random = SystemRandom::new();
    let (seed, encrypted_secret) = seed_for(ek, &random)?;
    let (_, key_bits, _) = ek.symmetric.expect("checked");
    let sym_key = kdfa(ek.name_alg, &seed, "STORAGE", ak_name, &[], key_bits as u32)?;
    let cipher = if key_bits == 128 { &AES_128 } else { &AES_256 };
    let key = EncryptingKey::cfb128(
        UnboundCipherKey::new(cipher, &sym_key).map_err(|_| TpmError::Crypto)?,
    )
    .map_err(|_| TpmError::Crypto)?;
    let mut enc_identity = tpm2b(credential);
    key.less_safe_encrypt(
        &mut enc_identity,
        EncryptionContext::Iv128(FixedLength::from([0u8; 16])),
    )
    .map_err(|_| TpmError::Crypto)?;
    let hmac_key = kdfa(
        ek.name_alg,
        &seed,
        "INTEGRITY",
        &[],
        &[],
        digest_size as u32 * 8,
    )?;
    let mut ctx = hmac::Context::with_key(&hmac::Key::new(hmac_alg(ek.name_alg)?, &hmac_key));
    ctx.update(&enc_identity);
    ctx.update(ak_name);
    let mut id_object = tpm2b(ctx.sign().as_ref());
    id_object.extend(enc_identity);
    Ok(CredentialChallenge {
        id_object,
        encrypted_secret,
    })
}
