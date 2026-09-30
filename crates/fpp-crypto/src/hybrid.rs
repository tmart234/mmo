//! Suite FPP-S1H (04 §2–§4): objects signed by long-lived keys (the
//! Publisher Root, Build and Policy Signing, the Log) are a `COSE_Sign`
//! with two signatures, Ed25519 and ML-DSA-65 (FIPS 204), and both must
//! verify. A forger needs to break both: Ed25519 today, ML-DSA after a
//! quantum computer.
//!
//! Verification order mirrors §2.1 for COSE_Sign1: encoding, header,
//! version, ctx, kid (both signers resolve to one registered hybrid key),
//! role (it allows the context, and it is a hybrid role), alg, signatures,
//! schema.

use aws_lc_rs::signature::{
    KeyPair, PqdsaKeyPair, UnparsedPublicKey, ML_DSA_65, ML_DSA_65_SIGNING,
};
use ed25519_dalek::{Signature, Signer as _, SigningKey};
use fpp_types::{Kid, FPP_VERSION};
use fpp_wire::cose::{alg, BodyHeader, CoseSignature, SignMulti};
use fpp_wire::Payload;

use crate::{kid, ml_dsa_kid, object_digest, KeyResolver, KeyRole, Verified, VerifyError};

/// A hybrid signing key: an Ed25519 key and an ML-DSA-65 key, one role.
pub struct HybridSigner {
    ed: SigningKey,
    ml: PqdsaKeyPair,
    ed_kid: Kid,
    ml_kid: Kid,
    ml_public: Vec<u8>,
}

impl HybridSigner {
    /// From two 32-byte seeds (ML-DSA key generation from its seed, FIPS 204
    /// §6.1, is deterministic).
    pub fn from_seeds(ed_seed: &[u8; 32], ml_seed: &[u8; 32]) -> Result<Self, VerifyError> {
        let ed = SigningKey::from_bytes(ed_seed);
        let ml = PqdsaKeyPair::from_seed(&ML_DSA_65_SIGNING, ml_seed)
            .map_err(|_| VerifyError::Signature)?;
        let ml_public = ml.public_key().as_ref().to_vec();
        Ok(Self {
            ed_kid: kid(&ed.verifying_key()),
            ml_kid: ml_dsa_kid(&ml_public),
            ed,
            ml,
            ml_public,
        })
    }

    pub fn ed25519_public(&self) -> ed25519_dalek::VerifyingKey {
        self.ed.verifying_key()
    }

    pub fn ml_dsa_public(&self) -> &[u8] {
        &self.ml_public
    }

    /// The Ed25519 half, for formats that sign with it directly (the log's
    /// C2SP checkpoint notes).
    pub fn ed25519(&self) -> &SigningKey {
        &self.ed
    }

    /// An ML-DSA-65 signature over `msg` (FIPS 204, empty context).
    pub fn sign_ml_dsa(&self, msg: &[u8]) -> Vec<u8> {
        let mut sig = vec![0u8; ML_DSA_65_SIGNING.signature_len()];
        let n = self.ml.sign(msg, &mut sig).expect("ML-DSA signing");
        sig.truncate(n);
        sig
    }
}

/// Whether `sig` is an ML-DSA-65 signature by `public` over `msg`.
pub fn ml_dsa_verify(public: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    UnparsedPublicKey::new(&ML_DSA_65, public)
        .verify(msg, sig)
        .is_ok()
}

/// Sign `payload` with both keys (`COSE_Sign`, Ed25519 first).
pub fn sign_hybrid<P: Payload>(signer: &HybridSigner, payload: &P) -> Vec<u8> {
    let body = BodyHeader {
        content_type: P::CONTENT_TYPE.to_owned(),
        ctx: P::CTX.to_owned(),
        version: FPP_VERSION,
    };
    let mut object = SignMulti::new(
        body,
        payload.to_cbor(),
        vec![
            CoseSignature::new(alg::EDDSA, signer.ed_kid),
            CoseSignature::new(alg::ML_DSA_65, signer.ml_kid),
        ],
    )
    .expect("body header keys are unique");
    let ed_tbs = object.to_be_signed(&object.signatures[0]);
    let ml_tbs = object.to_be_signed(&object.signatures[1]);
    object.signatures[0].signature = signer.ed.sign(&ed_tbs).to_bytes().to_vec();
    object.signatures[1].signature = signer.sign_ml_dsa(&ml_tbs);
    object.encode()
}

/// Verify a hybrid object of type `P`.
pub fn verify_hybrid<P: Payload>(
    signed: &[u8],
    keys: &impl KeyResolver,
) -> Result<Verified<P>, VerifyError> {
    let s = SignMulti::decode(signed).map_err(VerifyError::Encoding)?;
    let h = &s.protected;
    if h.version != FPP_VERSION {
        return Err(VerifyError::Version(h.version));
    }
    if h.ctx != P::CTX {
        return Err(VerifyError::Context {
            expected: P::CTX,
            found: h.ctx.clone(),
        });
    }
    if h.content_type != P::CONTENT_TYPE {
        return Err(VerifyError::Context {
            expected: P::CONTENT_TYPE,
            found: h.content_type.clone(),
        });
    }
    let [ed_sig, ml_sig] = s.signatures.as_slice() else {
        return Err(VerifyError::Encoding(fpp_wire::WireError::Header(
            "S1H needs exactly two signatures",
        )));
    };
    let key = keys
        .resolve_hybrid(&ed_sig.kid)
        .ok_or(VerifyError::UnknownKey(ed_sig.kid))?;
    if key.ml_kid != ml_sig.kid {
        return Err(VerifyError::UnknownKey(ml_sig.kid));
    }
    if !key.role.allows(&h.ctx) || !key.role.requires_hybrid() {
        return Err(VerifyError::RoleNotAllowed {
            role: key.role,
            context: h.ctx.clone(),
        });
    }
    if ed_sig.alg != alg::EDDSA {
        return Err(VerifyError::Algorithm(ed_sig.alg));
    }
    if ml_sig.alg != alg::ML_DSA_65 {
        return Err(VerifyError::Algorithm(ml_sig.alg));
    }
    let sig = Signature::from_slice(&ed_sig.signature).map_err(|_| VerifyError::Signature)?;
    key.ed
        .verify_strict(&s.to_be_signed(ed_sig), &sig)
        .map_err(|_| VerifyError::Signature)?;
    UnparsedPublicKey::new(&ML_DSA_65, &key.ml)
        .verify(&s.to_be_signed(ml_sig), &ml_sig.signature)
        .map_err(|_| VerifyError::Signature)?;
    let payload = P::from_cbor(&s.payload).map_err(VerifyError::Payload)?;
    Ok(Verified {
        payload,
        kid: ed_sig.kid,
        role: key.role,
        digest: object_digest(signed),
    })
}

/// The role a hybrid key was registered for (for callers that list them).
pub fn role_of(keys: &impl KeyResolver, ed_kid: &Kid) -> Option<KeyRole> {
    keys.resolve_hybrid(ed_kid).map(|k| k.role)
}
