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
//! 5. the signature verifies over `Sig_structure` (Ed25519, or ES256 for
//!    session keys held in hardware, with a low-S signature);
//! 6. only then is the payload decoded, strictly, against its schema.

#![forbid(unsafe_code)]

use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use fpp_types::{ctx, Digest, Kid, SessionKey, FPP_VERSION};
use fpp_wire::cbor::{self, Value};
use fpp_wire::cose::{alg, ProtectedHeader, Sign1};
use fpp_wire::{Payload, WireError};
use sha2::{Digest as _, Sha256};
use std::collections::HashMap;

#[cfg(feature = "s1h")]
pub mod hybrid;

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

/// `COSE_Key` for a session key: Ed25519 as [`cose_key_ed25519`], P-256 as
/// `{1: 2 (EC2), -1: 1 (P-256), -2: x, -3: y}`.
pub fn cose_key_session(key: &SessionKey) -> Value {
    match key {
        SessionKey::Ed25519(x) => Value::Map(vec![
            (Value::int(1), Value::int(1)),
            (Value::int(-1), Value::int(6)),
            (Value::int(-2), Value::bytes(x.to_vec())),
        ]),
        SessionKey::P256 { x, y } => Value::Map(vec![
            (Value::int(1), Value::int(2)),
            (Value::int(-1), Value::int(1)),
            (Value::int(-2), Value::bytes(x.to_vec())),
            (Value::int(-3), Value::bytes(y.to_vec())),
        ]),
    }
}

/// The session key a `COSE_Key` holds, if it is exactly one of the two
/// encodings of [`cose_key_session`] and a valid point.
pub fn session_key_from_cose(v: &Value) -> Option<SessionKey> {
    let Value::Map(entries) = v else { return None };
    let get = |k: i64| {
        entries
            .iter()
            .find(|(key, _)| *key == Value::int(k))
            .map(|(_, v)| v)
    };
    let fixed = |k: i64| -> Option<[u8; 32]> { get(k)?.as_bytes()?.try_into().ok() };
    let key = match entries.len() {
        3 => SessionKey::Ed25519(fixed(-2)?),
        4 => SessionKey::P256 {
            x: fixed(-2)?,
            y: fixed(-3)?,
        },
        _ => return None,
    };
    (cose_key_session(&key) == *v && PublicKey::session(&key).is_some()).then_some(key)
}

/// `kid` of a session key (for Ed25519 the same as [`kid`]).
pub fn session_kid(key: &SessionKey) -> Kid {
    let enc = cbor::encode(&cose_key_session(key)).expect("COSE_Key keys are unique");
    Kid(Sha256::digest(enc)[..16].try_into().expect("16 bytes"))
}

/// The 32 bytes that name a session key in revocations (`session:<hex>`,
/// 04 §9): an Ed25519 key itself; for P-256, SHA-256 of the compressed
/// point.
pub fn session_key_id(key: &SessionKey) -> [u8; 32] {
    match key {
        SessionKey::Ed25519(k) => *k,
        SessionKey::P256 { x, y } => {
            let mut h = Sha256::new();
            h.update([2 + (y[31] & 1)]);
            h.update(x);
            h.finalize().into()
        }
    }
}

/// Verify a raw signature (not a COSE object) by a session key over `msg`:
/// proofs of possession in the admission messages. ES256 signatures are
/// `r ‖ s` with low `s`.
pub fn verify_session_raw(key: &SessionKey, msg: &[u8], sig: &[u8]) -> bool {
    PublicKey::session(key).is_some_and(|k| k.verify(msg, sig))
}

/// `COSE_Key` for an ML-DSA-65 public key (draft-ietf-cose-dilithium):
/// `{1: 7 (AKP), 3: -49 (ML-DSA-65), -1: pub}`.
pub fn cose_key_ml_dsa(public: &[u8]) -> Value {
    Value::Map(vec![
        (Value::int(1), Value::int(7)),
        (Value::int(3), Value::int(fpp_wire::cose::alg::ML_DSA_65)),
        (Value::int(-1), Value::bytes(public.to_vec())),
    ])
}

/// `kid` of an ML-DSA-65 key.
pub fn ml_dsa_kid(public: &[u8]) -> Kid {
    let enc = cbor::encode(&cose_key_ml_dsa(public)).expect("COSE_Key keys are unique");
    Kid(Sha256::digest(enc)[..16].try_into().expect("16 bytes"))
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

/// A player's session key, held here or in hardware (Ed25519 or ES256).
pub trait SessionSigner: Signer {
    fn session_key(&self) -> SessionKey;
}

/// An Ed25519 signing key whose private half may live outside this process
/// (an Android Keystore key, a TPM): the session and instance keys of FPP.
pub trait Ed25519Key: Signer {
    fn public_key(&self) -> [u8; 32];
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

impl Ed25519Key for Ed25519Signer {
    fn public_key(&self) -> [u8; 32] {
        self.sk.verifying_key().to_bytes()
    }
}

impl SessionSigner for Ed25519Signer {
    fn session_key(&self) -> SessionKey {
        SessionKey::Ed25519(self.public_key())
    }
}

/// An ES256 session key in software (simulators and tests; a real one
/// stays in a TPM, the Secure Enclave or StrongBox). Signatures are
/// `r ‖ s` with low `s`.
pub struct P256Signer {
    sk: p256::ecdsa::SigningKey,
    kid: Kid,
}

impl P256Signer {
    pub fn new(sk: p256::ecdsa::SigningKey) -> Self {
        let kid = session_kid(&p256_session_key(sk.verifying_key()));
        Self { sk, kid }
    }

    pub fn generate() -> Self {
        Self::new(p256::ecdsa::SigningKey::random(
            &mut p256::elliptic_curve::rand_core::OsRng,
        ))
    }
}

/// A P-256 public key as a [`SessionKey`].
pub fn p256_session_key(key: &p256::ecdsa::VerifyingKey) -> SessionKey {
    SessionKey::from_bytes(key.to_encoded_point(false).as_bytes()).expect("uncompressed point")
}

/// `r ‖ s` of an ECDSA signature, with `s` made low (the other valid
/// signature of the same message: `(r, n - s)`). Verifiers here accept only
/// low `s`, so a signed object has exactly one valid encoding per signing.
pub fn es256_normalize(sig: &[u8]) -> Option<[u8; 64]> {
    let sig = p256::ecdsa::Signature::from_slice(sig).ok()?;
    let sig = sig.normalize_s().unwrap_or(sig);
    Some(sig.to_bytes().into())
}

impl Signer for P256Signer {
    fn alg(&self) -> i64 {
        alg::ES256
    }

    fn kid(&self) -> Kid {
        self.kid
    }

    fn sign(&self, to_be_signed: &[u8]) -> Vec<u8> {
        use p256::ecdsa::signature::Signer as _;
        let sig: p256::ecdsa::Signature = self.sk.sign(to_be_signed);
        es256_normalize(&sig.to_bytes())
            .expect("a signature")
            .to_vec()
    }
}

impl SessionSigner for P256Signer {
    fn session_key(&self) -> SessionKey {
        p256_session_key(self.sk.verifying_key())
    }
}

/// Sign a payload under its own context and content type.
pub fn sign<P: Payload>(signer: &(impl Signer + ?Sized), payload: &P) -> Vec<u8> {
    sign_raw(signer, P::CTX, P::CONTENT_TYPE, payload.to_cbor())
}

/// Sign arbitrary payload bytes under `context`. Verification still enforces
/// deterministic encoding, role and schema; this exists for producing
/// interop vectors, including negative ones.
pub fn sign_raw(
    signer: &(impl Signer + ?Sized),
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

/// A public key that signs FPP-S1 objects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicKey {
    Ed25519(VerifyingKey),
    /// ES256, for device-held session keys only.
    P256(p256::ecdsa::VerifyingKey),
}

impl PublicKey {
    /// A session key's verifying key, if it is a valid point.
    pub fn session(key: &SessionKey) -> Option<Self> {
        match key {
            SessionKey::Ed25519(k) => VerifyingKey::from_bytes(k).ok().map(PublicKey::Ed25519),
            SessionKey::P256 { .. } => p256::ecdsa::VerifyingKey::from_sec1_bytes(&key.to_bytes())
                .ok()
                .map(PublicKey::P256),
        }
    }

    pub fn alg(&self) -> i64 {
        match self {
            PublicKey::Ed25519(_) => alg::EDDSA,
            PublicKey::P256(_) => alg::ES256,
        }
    }

    /// Ed25519 strictly (RFC 8032 §5.1.7, no small-order keys); ES256 with
    /// `r ‖ s` and low `s` only.
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        match self {
            PublicKey::Ed25519(k) => {
                Signature::from_slice(sig).is_ok_and(|sig| k.verify_strict(msg, &sig).is_ok())
            }
            PublicKey::P256(k) => {
                use p256::ecdsa::signature::Verifier as _;
                let Ok(sig) = p256::ecdsa::Signature::from_slice(sig) else {
                    return false;
                };
                sig.normalize_s().is_none() && k.verify(msg, &sig).is_ok()
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct VerificationKey {
    pub role: KeyRole,
    pub alg: i64,
    pub key: PublicKey,
}

/// A hybrid (FPP-S1H) key: both halves, one role.
#[derive(Clone, Debug)]
pub struct HybridKey {
    pub role: KeyRole,
    pub ed: VerifyingKey,
    pub ml: Vec<u8>,
    pub ml_kid: Kid,
}

pub trait KeyResolver {
    fn resolve(&self, kid: &Kid) -> Option<&VerificationKey>;
    /// A hybrid key by the `kid` of its Ed25519 half.
    fn resolve_hybrid(&self, _ed_kid: &Kid) -> Option<&HybridKey> {
        None
    }
}

/// Known keys by `kid` (in production: loaded from the signed regional key bundle).
#[derive(Clone, Debug, Default)]
pub struct KeySet {
    keys: HashMap<Kid, VerificationKey>,
    hybrid: HashMap<Kid, HybridKey>,
}

impl KeySet {
    pub fn insert_ed25519(&mut self, role: KeyRole, key: VerifyingKey) -> Kid {
        let k = kid(&key);
        self.keys.insert(
            k,
            VerificationKey {
                role,
                alg: alg::EDDSA,
                key: PublicKey::Ed25519(key),
            },
        );
        k
    }

    /// Register a player's session key (role [`KeyRole::Session`]). `None`
    /// if it is not a valid point.
    pub fn insert_session(&mut self, key: &SessionKey) -> Option<Kid> {
        let public = PublicKey::session(key)?;
        let k = session_kid(key);
        self.keys.insert(
            k,
            VerificationKey {
                role: KeyRole::Session,
                alg: public.alg(),
                key: public,
            },
        );
        Some(k)
    }
}

impl KeySet {
    /// Register a hybrid key (roles that require FPP-S1H). Returns the
    /// `kid`s of its Ed25519 and ML-DSA halves.
    pub fn insert_hybrid(&mut self, role: KeyRole, ed: VerifyingKey, ml: Vec<u8>) -> (Kid, Kid) {
        let ed_kid = kid(&ed);
        let ml_kid = ml_dsa_kid(&ml);
        self.hybrid.insert(
            ed_kid,
            HybridKey {
                role,
                ed,
                ml,
                ml_kid,
            },
        );
        (ed_kid, ml_kid)
    }
}

impl KeyResolver for KeySet {
    fn resolve(&self, kid: &Kid) -> Option<&VerificationKey> {
        self.keys.get(kid)
    }

    fn resolve_hybrid(&self, ed_kid: &Kid) -> Option<&HybridKey> {
        self.hybrid.get(ed_kid)
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
    // ES256 only for session keys (04 §3)
    if matches!(key.key, PublicKey::P256(_)) && key.role != KeyRole::Session {
        return Err(VerifyError::Algorithm(h.alg));
    }
    if !key.key.verify(&s.to_be_signed(), &s.signature) {
        return Err(VerifyError::Signature);
    }
    let payload = P::from_cbor(&s.payload).map_err(VerifyError::Payload)?;
    Ok(Verified {
        payload,
        kid: h.kid,
        role: key.role,
        digest: object_digest(signed),
    })
}
