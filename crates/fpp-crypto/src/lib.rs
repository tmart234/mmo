//! FPP v1 signing and verification (docs/anticheat/04-protocol.md §2–§4).
//!
//! Every signed object is a COSE_Sign1 whose protected header names the key
//! (`kid`), the algorithm, the protocol version and a domain-separation
//! context (`fpp-ctx`). Verification enforces all of them:
//!
//! 1. the object is in deterministic encoding (strict decode);
//! 2. `fpp-v` is this protocol version;
//! 3. `fpp-ctx` and content type are those of the expected payload type;
//! 4. the `kid` resolves to a known key, and that key's role allows the
//!    context (a session key can never sign a Checkpoint, a GS key can never
//!    sign an InputCommit);
//! 5. the signature verifies over `Sig_structure`;
//! 6. only then is the payload decoded, strictly, against its schema.

#![forbid(unsafe_code)]

use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use fpp_types::{ctx, Digest, Kid, FPP_VERSION};
use fpp_wire::cbor::{self, Value};
use fpp_wire::cose::{alg, ProtectedHeader, Sign1};
use fpp_wire::{Payload, WireError};
use sha2::{Digest as _, Sha256};
use std::collections::HashMap;

/// What a key is for (04-protocol.md §4). Each role may sign only its contexts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KeyRole {
    PublisherRoot,
    BuildSigning,
    PolicySigning,
    VerifierAr,
    BrokerSat,
    ServerLiveness,
    Log,
    Enforcement,
    GsInstance,
    Session,
}

impl KeyRole {
    pub fn contexts(self) -> &'static [&'static str] {
        match self {
            KeyRole::PublisherRoot => &[ctx::CERT],
            KeyRole::BuildSigning => &[ctx::BUILD_MANIFEST],
            KeyRole::PolicySigning => &[ctx::POLICY],
            KeyRole::VerifierAr => &[ctx::ATTESTATION_RESULT],
            KeyRole::BrokerSat => &[ctx::SAT],
            KeyRole::ServerLiveness => &[ctx::SAR],
            KeyRole::Log => &[ctx::TREE_HEAD, ctx::LOG_RECEIPT],
            KeyRole::Enforcement => &[ctx::REVOCATION, ctx::ENFORCEMENT_RECORD],
            KeyRole::GsInstance => &[ctx::CHECKPOINT, ctx::HOST_BATCH],
            KeyRole::Session => &[ctx::ADMIT_POP, ctx::INPUT_COMMIT, ctx::INTEGRITY_REPORT],
        }
    }

    pub fn allows(self, context: &str) -> bool {
        self.contexts().contains(&context)
    }

    /// Long-lived roots must sign with hybrid Ed25519 + ML-DSA-65 (`COSE_Sign`,
    /// suite FPP-S1H), never with a single Ed25519 COSE_Sign1.
    pub fn requires_hybrid(self) -> bool {
        matches!(
            self,
            KeyRole::PublisherRoot | KeyRole::BuildSigning | KeyRole::PolicySigning | KeyRole::Log
        )
    }
}

/// `COSE_Key` for an Ed25519 public key: `{1: 1 (OKP), -1: 6 (Ed25519), -2: x}`.
pub fn cose_key_ed25519(public: &VerifyingKey) -> Value {
    Value::Map(vec![
        (Value::int(1), Value::int(1)),
        (Value::int(-1), Value::int(6)),
        (Value::int(-2), Value::bytes(public.to_bytes().to_vec())),
    ])
}

/// SHA-256 of the key's deterministic COSE_Key encoding (e.g. `gs_instance_id`).
pub fn key_digest(public: &VerifyingKey) -> Digest {
    let enc = cbor::encode(&cose_key_ed25519(public)).expect("COSE_Key keys are unique");
    Digest(Sha256::digest(enc).into())
}

/// `kid`: the key digest truncated to 16 bytes.
pub fn kid(public: &VerifyingKey) -> Kid {
    Kid(key_digest(public).0[..16].try_into().expect("16 bytes"))
}

/// SHA-256 of a signed object's exact bytes: the link used in `prev` chains
/// and in Merkle leaves that reference signed objects.
pub fn object_digest(signed: &[u8]) -> Digest {
    Digest(Sha256::digest(signed).into())
}

pub trait Signer {
    fn alg(&self) -> i64;
    fn kid(&self) -> Kid;
    fn sign(&self, to_be_signed: &[u8]) -> Vec<u8>;
}

/// Ed25519 signer (suite FPP-S1). Keys held in hardware implement `Signer` too.
pub struct Ed25519Signer {
    sk: SigningKey,
    kid: Kid,
}

impl Ed25519Signer {
    pub fn new(sk: SigningKey) -> Self {
        let kid = kid(&sk.verifying_key());
        Self { sk, kid }
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.sk.verifying_key()
    }
}

impl Signer for Ed25519Signer {
    fn alg(&self) -> i64 {
        alg::EDDSA
    }

    fn kid(&self) -> Kid {
        self.kid
    }

    fn sign(&self, to_be_signed: &[u8]) -> Vec<u8> {
        self.sk.sign(to_be_signed).to_bytes().to_vec()
    }
}

/// Sign a payload under its own context and content type.
pub fn sign<P: Payload>(signer: &impl Signer, payload: &P) -> Vec<u8> {
    sign_raw(signer, P::CTX, P::CONTENT_TYPE, payload.to_cbor())
}

/// Sign arbitrary payload bytes under `context`. Verification still enforces
/// deterministic encoding, role and schema; this exists for producing
/// interop vectors, including negative ones.
pub fn sign_raw(
    signer: &impl Signer,
    context: &str,
    content_type: &str,
    payload: Vec<u8>,
) -> Vec<u8> {
    let header = ProtectedHeader {
        alg: signer.alg(),
        content_type: content_type.to_owned(),
        kid: signer.kid(),
        ctx: context.to_owned(),
        version: FPP_VERSION,
    };
    let mut s = Sign1::new(header, payload).expect("protected header keys are unique");
    s.signature = signer.sign(&s.to_be_signed());
    s.encode()
}

#[derive(Clone, Debug)]
pub struct VerificationKey {
    pub role: KeyRole,
    pub alg: i64,
    pub key: VerifyingKey,
}

pub trait KeyResolver {
    fn resolve(&self, kid: &Kid) -> Option<&VerificationKey>;
}

/// Known keys by `kid` (in production: loaded from the signed regional key bundle).
#[derive(Clone, Debug, Default)]
pub struct KeySet {
    keys: HashMap<Kid, VerificationKey>,
}

impl KeySet {
    pub fn insert_ed25519(&mut self, role: KeyRole, key: VerifyingKey) -> Kid {
        let k = kid(&key);
        self.keys.insert(
            k,
            VerificationKey {
                role,
                alg: alg::EDDSA,
                key,
            },
        );
        k
    }
}

impl KeyResolver for KeySet {
    fn resolve(&self, kid: &Kid) -> Option<&VerificationKey> {
        self.keys.get(kid)
    }
}

/// A verified object.
#[derive(Clone, Debug)]
pub struct Verified<P> {
    pub payload: P,
    pub kid: Kid,
    pub role: KeyRole,
    /// `object_digest` of the signed bytes.
    pub digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// Not deterministic CBOR, or a malformed COSE_Sign1.
    Encoding(WireError),
    Version(u64),
    Context {
        expected: &'static str,
        found: String,
    },
    UnknownKey(Kid),
    Algorithm(i64),
    RoleNotAllowed {
        role: KeyRole,
        context: String,
    },
    HybridRequired(KeyRole),
    Signature,
    /// The signed payload does not match its schema or encoding rules.
    Payload(WireError),
}

impl VerifyError {
    /// Stable category shared with the interop vectors and other implementations.
    pub fn category(&self) -> &'static str {
        match self {
            VerifyError::Encoding(e) | VerifyError::Payload(e) if e.is_encoding() => "encoding",
            VerifyError::Encoding(_) => "header",
            VerifyError::Version(_) => "version",
            VerifyError::Context { .. } => "ctx",
            VerifyError::UnknownKey(_) => "kid",
            VerifyError::Algorithm(_) => "alg",
            VerifyError::RoleNotAllowed { .. } | VerifyError::HybridRequired(_) => "role",
            VerifyError::Signature => "signature",
            VerifyError::Payload(_) => "schema",
        }
    }
}

impl core::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}: {self:?}", self.category())
    }
}

impl std::error::Error for VerifyError {}

/// Verify a signed object of type `P` against known keys.
pub fn verify<P: Payload>(
    signed: &[u8],
    keys: &impl KeyResolver,
) -> Result<Verified<P>, VerifyError> {
    let s = Sign1::decode(signed).map_err(VerifyError::Encoding)?;
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
    let key = keys.resolve(&h.kid).ok_or(VerifyError::UnknownKey(h.kid))?;
    if key.role.requires_hybrid() {
        return Err(VerifyError::HybridRequired(key.role));
    }
    if !key.role.allows(&h.ctx) {
        return Err(VerifyError::RoleNotAllowed {
            role: key.role,
            context: h.ctx.clone(),
        });
    }
    if h.alg != key.alg {
        return Err(VerifyError::Algorithm(h.alg));
    }
    let sig = Signature::from_slice(&s.signature).map_err(|_| VerifyError::Signature)?;
    key.key
        .verify_strict(&s.to_be_signed(), &sig)
        .map_err(|_| VerifyError::Signature)?;
    let payload = P::from_cbor(&s.payload).map_err(VerifyError::Payload)?;
    Ok(Verified {
        payload,
        kid: h.kid,
        role: key.role,
        digest: object_digest(signed),
    })
}
