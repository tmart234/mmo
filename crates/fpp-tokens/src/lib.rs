//! FPP v1 tokens (docs/anticheat/04-protocol.md §6): CWT/EAT claim sets
//! signed as COSE_Sign1 by `fpp-crypto`, each under its own `fpp-ctx`.
//!
//! - [`AttestationResult`] (AR): Verifier → device. What the device proved
//!   and its trust tier, bound to its session key (`cnf`).
//! - [`SessionAdmissionToken`] (SAT): Broker → client. Admission to one match
//!   on one game server, bound to the same session key.
//! - [`ServerAttestationResult`] (SAR): liveness service → game server →
//!   clients. Short-lived, hash-chained proof that the server is still
//!   blessed, bound to its instance key and transport key.
//!
//! Structural rules (field types, sizes, lifetimes such as `exp ≤ iat + 1800`)
//! are schema checks shared with the independent verifier through golden
//! vectors. Time-dependent checks take `now` explicitly ([`check_time`]).

#![forbid(unsafe_code)]

use ed25519_dalek::VerifyingKey;
use fpp_crypto::{cose_key_ed25519, KeyResolver, VerifyError};
use fpp_types::{
    content_type, ctx, BuildId, DeviceTier, Did, Digest, GsInstanceId, MatchId, Reason, ServerClass,
};
use fpp_wire::cbor::{self, Value};
use fpp_wire::{Payload, WireError};
use sha2::{Digest as _, Sha256};

pub mod admission;
pub mod control;

/// Allowed clock skew between parties (§13).
pub const SKEW_S: u64 = 60;
/// Longest AR lifetime.
pub const AR_MAX_LIFETIME_S: u64 = 1800;
/// Longest SAR lifetime: revocation reaches clients within this (plus skew).
pub const SAR_MAX_LIFETIME_S: u64 = 120;
/// Longest SAT lifetime (a long match plus slack).
pub const SAT_MAX_LIFETIME_S: u64 = 6 * 3600;

pub const EAT_PROFILE_AR: &str = "tag:fpp,2026:ar/1";

/// Claim keys: registered CWT/EAT keys, private-use (< -65536) for FPP.
pub mod claim {
    pub const ISS: i64 = 1;
    pub const SUB: i64 = 2;
    pub const AUD: i64 = 3;
    pub const EXP: i64 = 4;
    pub const IAT: i64 = 6;
    pub const CTI: i64 = 7;
    pub const CNF: i64 = 8;
    pub const EAT_NONCE: i64 = 10;
    pub const EAT_PROFILE: i64 = 265;
    pub const DID: i64 = -65601;
    pub const TIER: i64 = -65602;
    pub const FEATURES: i64 = -65603;
    pub const CLIENT_BUILD: i64 = -65604;
    pub const PLATFORM: i64 = -65605;
    pub const POLICY_VER: i64 = -65606;
    pub const WARNINGS: i64 = -65607;
    pub const MATCH_ID: i64 = -65620;
    pub const SLOT: i64 = -65621;
    pub const QUEUE: i64 = -65622;
    pub const AR_CTI: i64 = -65623;
    pub const TLS_SPKI: i64 = -65640;
    pub const SERVER_CLASS: i64 = -65641;
    pub const GS_BUILD: i64 = -65642;
    pub const REGION: i64 = -65643;
    pub const SEQ: i64 = -65644;
    pub const PREV: i64 = -65645;
    pub const VRF_PUB: i64 = -65646;
    pub const NOISE_STATIC: i64 = -65647;
}

/// Why a token was refused. [`TokenError::reason`] maps it to a §11 code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TokenError {
    /// Signature, key, role, context or schema (04 §2.1).
    Verify(VerifyError),
    Expired,
    NotYetValid,
    /// `aud`/`sub` names another server, or `match_id` is not hosted here.
    Audience,
    /// `cnf` keys differ (AR vs SAT vs the proven session key), or the
    /// transport key is not the one in the SAR.
    Binding,
    /// SAT does not reference this AR.
    ArLink,
    /// Device tier below the queue minimum.
    Tier,
    /// SAR sequence or `prev` does not continue the chain.
    Chain,
    /// A subject (token, device, account, build) is revoked.
    Revoked,
}

impl TokenError {
    pub fn reason(&self, token: Token) -> Reason {
        match (self, token) {
            (TokenError::Tier, _) => Reason::TierInsufficient,
            (TokenError::Revoked, _) => Reason::Revoked,
            (TokenError::Binding, Token::Sat | Token::Ar) => Reason::PopInvalid,
            (_, Token::Ar) => Reason::ArInvalid,
            (_, Token::Sat) => Reason::SatInvalid,
            (_, Token::Sar) => Reason::SarLapsed,
        }
    }
}

impl core::fmt::Display for TokenError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(self, f)
    }
}

impl std::error::Error for TokenError {}

impl From<VerifyError> for TokenError {
    fn from(e: VerifyError) -> Self {
        TokenError::Verify(e)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Token {
    Ar,
    Sat,
    Sar,
}

// ------------------------------------------------------------------ claim codec

fn schema(what: &'static str, field: &'static str) -> WireError {
    WireError::Schema(what, field)
}

struct Claims<'a> {
    map: &'a [(Value, Value)],
    what: &'static str,
}

impl<'a> Claims<'a> {
    fn new(v: &'a Value, what: &'static str) -> Result<Self, WireError> {
        Ok(Self {
            map: v.as_map().ok_or(schema(what, "claims map"))?,
            what,
        })
    }

    fn opt(&self, key: i64) -> Option<&'a Value> {
        self.map
            .iter()
            .find(|(k, _)| k.as_i64() == Some(key))
            .map(|(_, v)| v)
    }

    fn get(&self, key: i64, name: &'static str) -> Result<&'a Value, WireError> {
        self.opt(key).ok_or(schema(self.what, name))
    }

    fn uint(&self, key: i64, name: &'static str) -> Result<u64, WireError> {
        self.get(key, name)?.as_u64().ok_or(schema(self.what, name))
    }

    fn text(&self, key: i64, name: &'static str, max: usize) -> Result<String, WireError> {
        self.get(key, name)?
            .as_text()
            .filter(|t| !t.is_empty() && t.len() <= max)
            .map(str::to_owned)
            .ok_or(schema(self.what, name))
    }

    fn fixed<const N: usize>(&self, key: i64, name: &'static str) -> Result<[u8; N], WireError> {
        self.get(key, name)?
            .as_bytes()
            .and_then(|b| b.try_into().ok())
            .ok_or(schema(self.what, name))
    }

    fn opt_fixed<const N: usize>(
        &self,
        key: i64,
        name: &'static str,
    ) -> Result<Option<[u8; N]>, WireError> {
        match self.opt(key) {
            None => Ok(None),
            Some(_) => self.fixed(key, name).map(Some),
        }
    }

    fn tier(&self) -> Result<DeviceTier, WireError> {
        DeviceTier::from_u64(self.uint(claim::TIER, "tier")?).ok_or(schema(self.what, "tier"))
    }

    /// `cnf = {1: COSE_Key}` holding an Ed25519 key; returns the 32-byte key.
    fn cnf(&self, key: i64, name: &'static str) -> Result<[u8; 32], WireError> {
        let v = self.get(key, name)?;
        let inner = if key == claim::CNF {
            Claims::new(v, self.what)?.get(1, name)?
        } else {
            v
        };
        cose_key_x(inner).ok_or(schema(self.what, name))
    }

    fn lifetime(&self, max: u64) -> Result<(u64, u64), WireError> {
        let iat = self.uint(claim::IAT, "iat")?;
        let exp = self.uint(claim::EXP, "exp")?;
        if exp <= iat || exp - iat > max {
            return Err(schema(self.what, "exp: lifetime"));
        }
        Ok((iat, exp))
    }
}

/// The `x` of an Ed25519 OKP COSE_Key, if that is what `v` is (exactly).
fn cose_key_x(v: &Value) -> Option<[u8; 32]> {
    let x: [u8; 32] = Claims::new(v, "COSE_Key")
        .ok()?
        .opt(-2)?
        .as_bytes()?
        .try_into()
        .ok()?;
    let key = VerifyingKey::from_bytes(&x).ok()?;
    (cose_key_ed25519(&key) == *v).then_some(x)
}

fn cose_key(x: &[u8; 32]) -> Value {
    // Callers only pass keys that decoded; an invalid point would be refused
    // on the verifying side anyway.
    match VerifyingKey::from_bytes(x) {
        Ok(k) => cose_key_ed25519(&k),
        Err(_) => Value::Map(vec![
            (Value::int(1), Value::int(1)),
            (Value::int(-1), Value::int(6)),
            (Value::int(-2), Value::bytes(x.to_vec())),
        ]),
    }
}

fn cnf(x: &[u8; 32]) -> Value {
    Value::Map(vec![(Value::int(1), cose_key(x))])
}

fn map(entries: Vec<(i64, Value)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .map(|(k, v)| (Value::int(k), v))
            .collect(),
    )
}

fn b(bytes: &[u8]) -> Value {
    Value::bytes(bytes.to_vec())
}

// ------------------------------------------------------------------ AR

/// What the Verifier observed (§6.1 `features`). Absent means "not reported".
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Features {
    pub secure_boot: Option<bool>,
    pub measured_boot: Option<bool>,
    pub hvci: Option<bool>,
    pub vbs: Option<bool>,
    pub iommu: Option<bool>,
    pub runtime_report: Option<bool>,
    pub key_in_hw: Option<bool>,
    pub strong_integrity: Option<bool>,
    pub app_attested: Option<bool>,
    pub os_patch_age_days: Option<u64>,
}

impl Features {
    fn flags(&self) -> [(&'static str, Option<bool>); 9] {
        [
            ("secure_boot", self.secure_boot),
            ("measured_boot", self.measured_boot),
            ("hvci", self.hvci),
            ("vbs", self.vbs),
            ("iommu", self.iommu),
            ("runtime_report", self.runtime_report),
            ("key_in_hw", self.key_in_hw),
            ("strong_integrity", self.strong_integrity),
            ("app_attested", self.app_attested),
        ]
    }

    fn to_value(&self) -> Value {
        let mut m: Vec<(Value, Value)> = self
            .flags()
            .into_iter()
            .filter_map(|(k, v)| v.map(|v| (Value::text(k), Value::Bool(v))))
            .collect();
        if let Some(d) = self.os_patch_age_days {
            m.push((Value::text("os_patch_age_days"), Value::Unsigned(d)));
        }
        Value::Map(m)
    }

    fn from_value(v: &Value) -> Result<Self, WireError> {
        const WHAT: &str = "AR features";
        let entries = v.as_map().ok_or(schema(WHAT, "map"))?;
        let mut f = Features::default();
        for (k, val) in entries {
            let name = k.as_text().ok_or(schema(WHAT, "key"))?;
            let flag = match val {
                Value::Bool(x) => Some(*x),
                _ => None,
            };
            let slot = match name {
                "secure_boot" => &mut f.secure_boot,
                "measured_boot" => &mut f.measured_boot,
                "hvci" => &mut f.hvci,
                "vbs" => &mut f.vbs,
                "iommu" => &mut f.iommu,
                "runtime_report" => &mut f.runtime_report,
                "key_in_hw" => &mut f.key_in_hw,
                "strong_integrity" => &mut f.strong_integrity,
                "app_attested" => &mut f.app_attested,
                "os_patch_age_days" => {
                    f.os_patch_age_days =
                        Some(val.as_u64().ok_or(schema(WHAT, "os_patch_age_days"))?);
                    continue;
                }
                // Unknown features are ignored (§12: additive extension).
                _ => continue,
            };
            *slot = Some(flag.ok_or(schema(WHAT, "flag"))?);
        }
        Ok(f)
    }
}

/// §6.1: Verifier → device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttestationResult {
    pub iss: String,
    pub iat: u64,
    pub exp: u64,
    pub cti: [u8; 16],
    /// Session public key (Ed25519) the result is bound to.
    pub cnf: [u8; 32],
    /// Echo of the Verifier's challenge.
    pub nonce: [u8; 32],
    pub did: Did,
    pub tier: DeviceTier,
    pub features: Features,
    pub client_build: BuildId,
    pub platform: String,
    pub policy_ver: u64,
    pub warnings: Vec<String>,
}

impl Payload for AttestationResult {
    const CTX: &'static str = ctx::ATTESTATION_RESULT;
    const CONTENT_TYPE: &'static str = content_type::ATTESTATION_RESULT;

    fn to_value(&self) -> Value {
        let mut m = vec![
            (claim::ISS, Value::text(&self.iss)),
            (claim::EXP, Value::Unsigned(self.exp)),
            (claim::IAT, Value::Unsigned(self.iat)),
            (claim::CTI, b(&self.cti)),
            (claim::CNF, cnf(&self.cnf)),
            (claim::EAT_NONCE, b(&self.nonce)),
            (claim::EAT_PROFILE, Value::text(EAT_PROFILE_AR)),
            (claim::DID, b(&self.did.0)),
            (claim::TIER, Value::Unsigned(self.tier as u64)),
            (claim::FEATURES, self.features.to_value()),
            (claim::CLIENT_BUILD, b(&self.client_build.0)),
            (claim::PLATFORM, Value::text(&self.platform)),
            (claim::POLICY_VER, Value::Unsigned(self.policy_ver)),
        ];
        if !self.warnings.is_empty() {
            m.push((
                claim::WARNINGS,
                Value::Array(self.warnings.iter().map(Value::text).collect()),
            ));
        }
        map(m)
    }

    fn from_value(v: &Value) -> Result<Self, WireError> {
        const WHAT: &str = "AttestationResult";
        let c = Claims::new(v, WHAT)?;
        if c.get(claim::EAT_PROFILE, "eat_profile")?.as_text() != Some(EAT_PROFILE_AR) {
            return Err(schema(WHAT, "eat_profile"));
        }
        let (iat, exp) = c.lifetime(AR_MAX_LIFETIME_S)?;
        let warnings = match c.opt(claim::WARNINGS) {
            None => Vec::new(),
            Some(w) => w
                .as_array()
                .filter(|a| !a.is_empty() && a.len() <= 16)
                .ok_or(schema(WHAT, "warnings"))?
                .iter()
                .map(|x| {
                    x.as_text()
                        .map(str::to_owned)
                        .ok_or(schema(WHAT, "warnings"))
                })
                .collect::<Result<_, _>>()?,
        };
        Ok(Self {
            iss: c.text(claim::ISS, "iss", 64)?,
            iat,
            exp,
            cti: c.fixed(claim::CTI, "cti")?,
            cnf: c.cnf(claim::CNF, "cnf")?,
            nonce: c.fixed(claim::EAT_NONCE, "eat_nonce")?,
            did: Did(c.fixed(claim::DID, "did")?),
            tier: c.tier()?,
            features: Features::from_value(c.get(claim::FEATURES, "features")?)?,
            client_build: BuildId(c.fixed(claim::CLIENT_BUILD, "client_build")?),
            platform: c.text(claim::PLATFORM, "platform", 32)?,
            policy_ver: c.uint(claim::POLICY_VER, "policy_ver")?,
            warnings,
        })
    }
}

// ------------------------------------------------------------------ SAT

/// §6.2: Broker → client, presented to the game server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionAdmissionToken {
    pub iss: String,
    /// Pseudonymous account id.
    pub sub: [u8; 32],
    /// The game server instance it admits to.
    pub aud: GsInstanceId,
    pub iat: u64,
    pub exp: u64,
    pub cti: [u8; 16],
    pub cnf: [u8; 32],
    pub did: Did,
    pub tier: DeviceTier,
    pub match_id: MatchId,
    pub slot: u16,
    pub queue: String,
    pub policy_ver: u64,
    /// `cti` of the AR the Broker relied on.
    pub ar_cti: [u8; 16],
}

impl Payload for SessionAdmissionToken {
    const CTX: &'static str = ctx::SAT;
    const CONTENT_TYPE: &'static str = content_type::SAT;

    fn to_value(&self) -> Value {
        map(vec![
            (claim::ISS, Value::text(&self.iss)),
            (claim::SUB, b(&self.sub)),
            (claim::AUD, b(&self.aud.0)),
            (claim::EXP, Value::Unsigned(self.exp)),
            (claim::IAT, Value::Unsigned(self.iat)),
            (claim::CTI, b(&self.cti)),
            (claim::CNF, cnf(&self.cnf)),
            (claim::DID, b(&self.did.0)),
            (claim::TIER, Value::Unsigned(self.tier as u64)),
            (claim::MATCH_ID, b(&self.match_id.0)),
            (claim::SLOT, Value::Unsigned(self.slot.into())),
            (claim::QUEUE, Value::text(&self.queue)),
            (claim::POLICY_VER, Value::Unsigned(self.policy_ver)),
            (claim::AR_CTI, b(&self.ar_cti)),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, WireError> {
        const WHAT: &str = "SessionAdmissionToken";
        let c = Claims::new(v, WHAT)?;
        let (iat, exp) = c.lifetime(SAT_MAX_LIFETIME_S)?;
        Ok(Self {
            iss: c.text(claim::ISS, "iss", 64)?,
            sub: c.fixed(claim::SUB, "sub")?,
            aud: GsInstanceId(c.fixed(claim::AUD, "aud")?),
            iat,
            exp,
            cti: c.fixed(claim::CTI, "cti")?,
            cnf: c.cnf(claim::CNF, "cnf")?,
            did: Did(c.fixed(claim::DID, "did")?),
            tier: c.tier()?,
            match_id: MatchId(c.fixed(claim::MATCH_ID, "match_id")?),
            slot: u16::try_from(c.uint(claim::SLOT, "slot")?).map_err(|_| schema(WHAT, "slot"))?,
            queue: c.text(claim::QUEUE, "queue", 64)?,
            policy_ver: c.uint(claim::POLICY_VER, "policy_ver")?,
            ar_cti: c.fixed(claim::AR_CTI, "ar_cti")?,
        })
    }
}

// ------------------------------------------------------------------ SAR

/// §6.3: liveness service → game server → clients. Successor of the
/// prototype's PlayTicket: hash-chained, short-lived, bound to the server's
/// keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerAttestationResult {
    pub iss: String,
    pub sub: GsInstanceId,
    pub iat: u64,
    pub exp: u64,
    /// Instance key: signs the server's Checkpoints. `sub` is its digest.
    pub cnf: [u8; 32],
    /// SHA-256 of the TLS leaf SPKI (QUIC transport).
    pub tls_spki_sha256: Option<[u8; 32]>,
    /// Static X25519 key of the server's fpp-session endpoint (UDP transport).
    pub noise_static: Option<[u8; 32]>,
    pub server_class: ServerClass,
    pub build_id: BuildId,
    pub region: String,
    /// Strictly increasing per instance.
    pub seq: u64,
    /// SHA-256 of the previous SAR's payload bytes; zeros at seq 0.
    pub prev: Digest,
    /// VRF public key (FPP-VRF1), once the server uses verifiable randomness.
    pub vrf_pub: Option<[u8; 32]>,
}

impl Payload for ServerAttestationResult {
    const CTX: &'static str = ctx::SAR;
    const CONTENT_TYPE: &'static str = content_type::SAR;

    fn to_value(&self) -> Value {
        let mut m = vec![
            (claim::ISS, Value::text(&self.iss)),
            (claim::SUB, b(&self.sub.0)),
            (claim::EXP, Value::Unsigned(self.exp)),
            (claim::IAT, Value::Unsigned(self.iat)),
            (claim::CNF, cnf(&self.cnf)),
            (
                claim::SERVER_CLASS,
                Value::Unsigned(self.server_class as u64),
            ),
            (claim::GS_BUILD, b(&self.build_id.0)),
            (claim::REGION, Value::text(&self.region)),
            (claim::SEQ, Value::Unsigned(self.seq)),
            (claim::PREV, b(&self.prev.0)),
        ];
        if let Some(t) = &self.tls_spki_sha256 {
            m.push((claim::TLS_SPKI, b(t)));
        }
        if let Some(v) = &self.vrf_pub {
            m.push((claim::VRF_PUB, cose_key(v)));
        }
        if let Some(n) = &self.noise_static {
            m.push((claim::NOISE_STATIC, b(n)));
        }
        map(m)
    }

    fn from_value(v: &Value) -> Result<Self, WireError> {
        const WHAT: &str = "ServerAttestationResult";
        let c = Claims::new(v, WHAT)?;
        let (iat, exp) = c.lifetime(SAR_MAX_LIFETIME_S)?;
        let sar = Self {
            iss: c.text(claim::ISS, "iss", 64)?,
            sub: GsInstanceId(c.fixed(claim::SUB, "sub")?),
            iat,
            exp,
            cnf: c.cnf(claim::CNF, "cnf")?,
            tls_spki_sha256: c.opt_fixed(claim::TLS_SPKI, "tls_spki_sha256")?,
            noise_static: c.opt_fixed(claim::NOISE_STATIC, "noise_static")?,
            server_class: ServerClass::from_u64(c.uint(claim::SERVER_CLASS, "server_class")?)
                .ok_or(schema(WHAT, "server_class"))?,
            build_id: BuildId(c.fixed(claim::GS_BUILD, "build_id")?),
            region: c.text(claim::REGION, "region", 32)?,
            seq: c.uint(claim::SEQ, "seq")?,
            prev: Digest(c.fixed(claim::PREV, "prev")?),
            vrf_pub: match c.opt(claim::VRF_PUB) {
                None => None,
                Some(v) => Some(cose_key_x(v).ok_or(schema(WHAT, "vrf_pub"))?),
            },
        };
        // `sub` names the instance key; a transport binding is mandatory.
        if sar.sub.0 != instance_id(&sar.cnf).0 {
            return Err(schema(WHAT, "sub != digest(cnf)"));
        }
        if sar.tls_spki_sha256.is_none() && sar.noise_static.is_none() {
            return Err(schema(WHAT, "no transport binding"));
        }
        Ok(sar)
    }
}

/// `gs_instance_id` of an instance public key (§5).
pub fn instance_id(key: &[u8; 32]) -> GsInstanceId {
    let v = cbor::encode(&cose_key(key)).expect("COSE_Key keys are unique");
    GsInstanceId(Sha256::digest(v).into())
}

// ------------------------------------------------------------------ verification

/// Common time rule: `iat` not in the future and `exp` not passed, ±[`SKEW_S`].
pub fn check_time(iat: u64, exp: u64, now: u64) -> Result<(), TokenError> {
    if iat > now + SKEW_S {
        return Err(TokenError::NotYetValid);
    }
    if exp + SKEW_S <= now {
        return Err(TokenError::Expired);
    }
    Ok(())
}

pub fn verify_ar(
    token: &[u8],
    keys: &impl KeyResolver,
    now: u64,
) -> Result<AttestationResult, TokenError> {
    let ar = fpp_crypto::verify::<AttestationResult>(token, keys)?.payload;
    check_time(ar.iat, ar.exp, now)?;
    Ok(ar)
}

pub fn verify_sat(
    token: &[u8],
    keys: &impl KeyResolver,
    now: u64,
) -> Result<SessionAdmissionToken, TokenError> {
    let sat = fpp_crypto::verify::<SessionAdmissionToken>(token, keys)?.payload;
    check_time(sat.iat, sat.exp, now)?;
    Ok(sat)
}

/// SHA-256 of a signed SAR's payload: the next SAR's `prev`.
pub fn sar_link(token: &[u8]) -> Result<Digest, TokenError> {
    let s = fpp_wire::cose::Sign1::decode(token)
        .map_err(|e| TokenError::Verify(VerifyError::Encoding(e)))?;
    Ok(Digest(Sha256::digest(&s.payload).into()))
}

/// Client-side SAR chain (§6.3): every update must verify, name the same
/// instance, continue `seq`/`prev` exactly, and be unexpired. Any failure,
/// or simply running past the last `exp`, means the server lost its
/// blessing: disconnect with `SAR_LAPSED`.
#[derive(Clone, Debug)]
pub struct SarChain {
    current: ServerAttestationResult,
    link: Digest,
}

impl SarChain {
    /// Start from the SAR in the server's handshake.
    pub fn start(token: &[u8], keys: &impl KeyResolver, now: u64) -> Result<Self, TokenError> {
        let current = fpp_crypto::verify::<ServerAttestationResult>(token, keys)?.payload;
        check_time(current.iat, current.exp, now)?;
        Ok(Self {
            current,
            link: sar_link(token)?,
        })
    }

    pub fn update(
        &mut self,
        token: &[u8],
        keys: &impl KeyResolver,
        now: u64,
    ) -> Result<(), TokenError> {
        let next = fpp_crypto::verify::<ServerAttestationResult>(token, keys)?.payload;
        check_time(next.iat, next.exp, now)?;
        if next.sub != self.current.sub || next.cnf != self.current.cnf {
            return Err(TokenError::Audience);
        }
        if next.seq != self.current.seq + 1 || next.prev != self.link {
            return Err(TokenError::Chain);
        }
        self.link = sar_link(token)?;
        self.current = next;
        Ok(())
    }

    /// Still blessed at `now`?
    pub fn live(&self, now: u64) -> bool {
        check_time(self.current.iat, self.current.exp, now).is_ok()
    }

    pub fn current(&self) -> &ServerAttestationResult {
        &self.current
    }
}
