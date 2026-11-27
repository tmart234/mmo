//! Owned control-plane and inter-role wire messages in strict deterministic
//! CBOR (`crate::wire::cbor`): zero `bincode`, zero `serde`.
//!
//! Replaces both `common::proto` and `fpp-svc::api` with a single,
//! language-neutral, strictly canonical wire format.

use crate::crypto::sha256_parts;
use crate::tokens::evidence::{Evidence, TpmEvidence};
use crate::wire::cbor::{self, text_map, MapView, Value};
use crate::wire::WireError;

/// Version carried in [`ChallengeRequest`].
pub const CONTROL_VERSION: u32 = 1;

/// Default maximum control-plane frame (64 KiB, finding F07).
pub const MAX_CONTROL_FRAME: usize = 64 * 1024;
/// Largest admission frame (TPM 2.0 quotes + measured-boot/IMA logs, or log batches).
pub const MAX_JOIN_FRAME: usize = 8 * 1024 * 1024;

/// Trait for owned deterministic-CBOR control messages.
pub trait CborMsg: Sized {
    fn encode(&self) -> Vec<u8>;
    fn decode(bytes: &[u8]) -> Result<Self, WireError>;
}

fn enc(v: &Value) -> Vec<u8> {
    cbor::encode(v).expect("control CBOR encodes")
}

/// What a Noise-authenticated TCP connection to the authority is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum Purpose {
    GsJoin = 1,
    Report = 2,
    Evidence = 3,
    Match = 4,
    Gossip = 5,
    Place = 6,
    RevocationPublish = 7,
    RevocationSince = 8,
    EvidencePut = 9,
    EvidenceGet = 10,
    EvidenceList = 11,
    LogAdd = 12,
    LogCheckpoint = 13,
    LogInclusion = 14,
    LogConsistency = 15,
    LogCosign = 16,
}

impl Purpose {
    pub fn from_u64(v: u64) -> Option<Self> {
        Some(match v {
            1 => Purpose::GsJoin,
            2 => Purpose::Report,
            3 => Purpose::Evidence,
            4 => Purpose::Match,
            5 => Purpose::Gossip,
            6 => Purpose::Place,
            7 => Purpose::RevocationPublish,
            8 => Purpose::RevocationSince,
            9 => Purpose::EvidencePut,
            10 => Purpose::EvidenceGet,
            11 => Purpose::EvidenceList,
            12 => Purpose::LogAdd,
            13 => Purpose::LogCheckpoint,
            14 => Purpose::LogInclusion,
            15 => Purpose::LogConsistency,
            16 => Purpose::LogCosign,
            _ => return None,
        })
    }
}

/// First message on every control connection: protocol version + purpose.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChallengeRequest {
    pub version: u32,
    pub purpose: Purpose,
}

impl CborMsg for ChallengeRequest {
    fn encode(&self) -> Vec<u8> {
        enc(&text_map([
            ("purpose", Value::Unsigned(self.purpose as u64)),
            ("version", Value::Unsigned(self.version.into())),
        ]))
    }

    fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let v = cbor::decode(bytes)?;
        let m = MapView::new(&v, "ChallengeRequest")?;
        let purpose = Purpose::from_u64(m.u64("purpose")?)
            .ok_or(WireError::Schema("ChallengeRequest", "purpose"))?;
        Ok(Self {
            version: m.u32("version")?,
            purpose,
        })
    }
}

/// Authority → peer: single-use 32-byte freshness nonce (finding F04).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttestChallenge {
    pub nonce: [u8; 32],
}

impl CborMsg for AttestChallenge {
    fn encode(&self) -> Vec<u8> {
        enc(&text_map([("nonce", Value::bytes(self.nonce.to_vec()))]))
    }

    fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let v = cbor::decode(bytes)?;
        let m = MapView::new(&v, "AttestChallenge")?;
        Ok(Self {
            nonce: m.fixed("nonce")?,
        })
    }
}

// ---------------------------------------------------------------- domain-separated CBOR PoP bytes

/// Deterministic CBOR bytes the GS long-term key signs in a [`JoinRequest`].
#[allow(clippy::too_many_arguments)]
pub fn join_request_sign_bytes(
    gs_id: &str,
    sw_hash: &[u8; 32],
    t_unix_ms: u64,
    nonce: &[u8; 16],
    ephemeral_pub: &[u8; 32],
    noise_static: &[u8; 32],
    game_addr: &str,
) -> Vec<u8> {
    enc(&Value::Array(vec![
        Value::text("fpp/1/join-request"),
        Value::text(gs_id),
        Value::bytes(sw_hash.to_vec()),
        Value::Unsigned(t_unix_ms),
        Value::bytes(nonce.to_vec()),
        Value::bytes(ephemeral_pub.to_vec()),
        Value::bytes(noise_static.to_vec()),
        Value::text(game_addr),
    ]))
}

/// Qualifying data for a GS TPM 2.0 join quote (finding F04).
pub fn join_quote_nonce(challenge: &[u8; 32], join_sign_bytes: &[u8]) -> [u8; 32] {
    sha256_parts(&[b"fpp/1/tpm-join-quote\0", challenge, join_sign_bytes])
}

/// Deterministic CBOR bytes a client's session key signs for the Verifier.
pub fn evidence_request_sign_bytes(
    challenge: &[u8; 32],
    session_pub: &[u8],
    platform: &str,
    client_build: &[u8; 32],
    evidence: &[u8],
) -> Vec<u8> {
    enc(&Value::Array(vec![
        Value::text("fpp/1/evidence-request"),
        Value::bytes(challenge.to_vec()),
        Value::bytes(session_pub.to_vec()),
        Value::text(platform),
        Value::bytes(client_build.to_vec()),
        Value::bytes(evidence.to_vec()),
    ]))
}

/// Deterministic CBOR bytes a client's session key signs for the Broker.
pub fn match_request_sign_bytes(challenge: &[u8; 32], ar: &[u8], queue: &str) -> Vec<u8> {
    enc(&Value::Array(vec![
        Value::text("fpp/1/match-request"),
        Value::bytes(challenge.to_vec()),
        Value::bytes(ar.to_vec()),
        Value::text(queue),
    ]))
}

// ---------------------------------------------------------------- GS <-> Server Liveness

/// GS → Server Liveness during admission, after [`AttestChallenge`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JoinRequest {
    pub gs_id: String,
    pub sw_hash: [u8; 32],
    pub t_unix_ms: u64,
    pub nonce: [u8; 16],
    pub ephemeral_pub: [u8; 32],
    pub noise_static: [u8; 32],
    pub game_addr: String,
    pub sig_gs: [u8; 64],
    pub gs_pub: [u8; 32],
    /// Unified TPM 2.0 evidence (`TpmEvidence`), encoded via `Evidence::Tpm`.
    pub tpm2: Option<Box<TpmEvidence>>,
}

impl CborMsg for JoinRequest {
    fn encode(&self) -> Vec<u8> {
        let mut fields = vec![
            ("ephemeral_pub", Value::bytes(self.ephemeral_pub.to_vec())),
            ("game_addr", Value::text(&self.game_addr)),
            ("gs_id", Value::text(&self.gs_id)),
            ("gs_pub", Value::bytes(self.gs_pub.to_vec())),
            ("noise_static", Value::bytes(self.noise_static.to_vec())),
            ("nonce", Value::bytes(self.nonce.to_vec())),
            ("sig_gs", Value::bytes(self.sig_gs.to_vec())),
            ("sw_hash", Value::bytes(self.sw_hash.to_vec())),
            ("t_unix_ms", Value::Unsigned(self.t_unix_ms)),
        ];
        if let Some(tpm) = &self.tpm2 {
            fields.push(("tpm2", Value::bytes(Evidence::Tpm(tpm.clone()).encode())));
        }
        enc(&text_map(fields))
    }

    fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let v = cbor::decode(bytes)?;
        let m = MapView::new(&v, "JoinRequest")?;
        let tpm2 = match m.field("tpm2") {
            Ok(tv) => {
                let raw = tv
                    .as_bytes()
                    .ok_or(WireError::Schema("JoinRequest", "tpm2"))?;
                match Evidence::decode(raw).map_err(|_| WireError::Schema("JoinRequest", "tpm2"))? {
                    Some(Evidence::Tpm(t)) => Some(t),
                    _ => return Err(WireError::Schema("JoinRequest", "tpm2")),
                }
            }
            Err(_) => None,
        };
        Ok(Self {
            gs_id: m.text("gs_id")?.to_string(),
            sw_hash: m.fixed("sw_hash")?,
            t_unix_ms: m.u64("t_unix_ms")?,
            nonce: m.fixed("nonce")?,
            ephemeral_pub: m.fixed("ephemeral_pub")?,
            noise_static: m.fixed("noise_static")?,
            game_addr: m.text("game_addr")?.to_string(),
            sig_gs: m.fixed("sig_gs")?,
            gs_pub: m.fixed("gs_pub")?,
            tpm2,
        })
    }
}

/// Authority → attester: TPM 2.0 credential activation challenge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialChallenge {
    pub id_object: Vec<u8>,
    pub encrypted_secret: Vec<u8>,
}

impl CborMsg for CredentialChallenge {
    fn encode(&self) -> Vec<u8> {
        enc(&text_map([
            (
                "encrypted_secret",
                Value::bytes(self.encrypted_secret.clone()),
            ),
            ("id_object", Value::bytes(self.id_object.clone())),
        ]))
    }

    fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let v = cbor::decode(bytes)?;
        let m = MapView::new(&v, "CredentialChallenge")?;
        Ok(Self {
            id_object: m.bytes("id_object")?.to_vec(),
            encrypted_secret: m.bytes("encrypted_secret")?.to_vec(),
        })
    }
}

/// Attester → authority: secret recovered by `TPM2_ActivateCredential`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialResponse {
    pub secret: Vec<u8>,
}

impl CborMsg for CredentialResponse {
    fn encode(&self) -> Vec<u8> {
        enc(&text_map([("secret", Value::bytes(self.secret.clone()))]))
    }

    fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let v = cbor::decode(bytes)?;
        let m = MapView::new(&v, "CredentialResponse")?;
        Ok(Self {
            secret: m.bytes("secret")?.to_vec(),
        })
    }
}

/// Server Liveness → GS after admission succeeds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JoinAccept {
    pub session_id: [u8; 16],
}

impl CborMsg for JoinAccept {
    fn encode(&self) -> Vec<u8> {
        enc(&text_map([(
            "session_id",
            Value::bytes(self.session_id.to_vec()),
        )]))
    }

    fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let v = cbor::decode(bytes)?;
        let m = MapView::new(&v, "JoinAccept")?;
        Ok(Self {
            session_id: m.fixed("session_id")?,
        })
    }
}

/// Server Liveness → GS stream messages (after `JoinAccept`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ToGameServer {
    Sar(Vec<u8>),
    Revocation(Vec<u8>),
}

impl CborMsg for ToGameServer {
    fn encode(&self) -> Vec<u8> {
        match self {
            ToGameServer::Sar(b) => enc(&text_map([
                ("data", Value::bytes(b.clone())),
                ("kind", Value::Unsigned(1)),
            ])),
            ToGameServer::Revocation(b) => enc(&text_map([
                ("data", Value::bytes(b.clone())),
                ("kind", Value::Unsigned(2)),
            ])),
        }
    }

    fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let v = cbor::decode(bytes)?;
        let m = MapView::new(&v, "ToGameServer")?;
        let data = m.bytes("data")?.to_vec();
        match m.u64("kind")? {
            1 => Ok(ToGameServer::Sar(data)),
            2 => Ok(ToGameServer::Revocation(data)),
            _ => Err(WireError::Schema("ToGameServer", "kind")),
        }
    }
}

/// GS → Server Liveness: signed Checkpoint per epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckpointSubmit {
    pub checkpoint: Vec<u8>,
}

impl CborMsg for CheckpointSubmit {
    fn encode(&self) -> Vec<u8> {
        enc(&text_map([(
            "checkpoint",
            Value::bytes(self.checkpoint.clone()),
        )]))
    }

    fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let v = cbor::decode(bytes)?;
        let m = MapView::new(&v, "CheckpointSubmit")?;
        Ok(Self {
            checkpoint: m.bytes("checkpoint")?.to_vec(),
        })
    }
}

// ---------------------------------------------------------------- client <-> Verifier & Broker

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceRequest {
    pub session_pub: Vec<u8>,
    pub pop_sig: [u8; 64],
    pub platform: String,
    pub client_build: [u8; 32],
    pub evidence: Vec<u8>,
}

impl CborMsg for EvidenceRequest {
    fn encode(&self) -> Vec<u8> {
        enc(&text_map([
            ("client_build", Value::bytes(self.client_build.to_vec())),
            ("evidence", Value::bytes(self.evidence.clone())),
            ("platform", Value::text(&self.platform)),
            ("pop_sig", Value::bytes(self.pop_sig.to_vec())),
            ("session_pub", Value::bytes(self.session_pub.clone())),
        ]))
    }

    fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let v = cbor::decode(bytes)?;
        let m = MapView::new(&v, "EvidenceRequest")?;
        Ok(Self {
            session_pub: m.bytes("session_pub")?.to_vec(),
            pop_sig: m.fixed("pop_sig")?,
            platform: m.text("platform")?.to_string(),
            client_build: m.fixed("client_build")?,
            evidence: m.bytes("evidence")?.to_vec(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvidenceAnswer {
    Ar(Vec<u8>),
    Refused { code: u16 },
    Activate(CredentialChallenge),
}

impl CborMsg for EvidenceAnswer {
    fn encode(&self) -> Vec<u8> {
        match self {
            EvidenceAnswer::Ar(ar) => enc(&text_map([
                ("ar", Value::bytes(ar.clone())),
                ("kind", Value::Unsigned(1)),
            ])),
            EvidenceAnswer::Refused { code } => enc(&text_map([
                ("code", Value::Unsigned((*code).into())),
                ("kind", Value::Unsigned(2)),
            ])),
            EvidenceAnswer::Activate(c) => enc(&text_map([
                ("encrypted_secret", Value::bytes(c.encrypted_secret.clone())),
                ("id_object", Value::bytes(c.id_object.clone())),
                ("kind", Value::Unsigned(3)),
            ])),
        }
    }

    fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let v = cbor::decode(bytes)?;
        let m = MapView::new(&v, "EvidenceAnswer")?;
        match m.u64("kind")? {
            1 => Ok(EvidenceAnswer::Ar(m.bytes("ar")?.to_vec())),
            2 => Ok(EvidenceAnswer::Refused {
                code: m.u16("code")?,
            }),
            3 => Ok(EvidenceAnswer::Activate(CredentialChallenge {
                id_object: m.bytes("id_object")?.to_vec(),
                encrypted_secret: m.bytes("encrypted_secret")?.to_vec(),
            })),
            _ => Err(WireError::Schema("EvidenceAnswer", "kind")),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MatchRequest {
    pub ar: Vec<u8>,
    pub queue: String,
    pub pop_sig: [u8; 64],
}

impl CborMsg for MatchRequest {
    fn encode(&self) -> Vec<u8> {
        enc(&text_map([
            ("ar", Value::bytes(self.ar.clone())),
            ("pop_sig", Value::bytes(self.pop_sig.to_vec())),
            ("queue", Value::text(&self.queue)),
        ]))
    }

    fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let v = cbor::decode(bytes)?;
        let m = MapView::new(&v, "MatchRequest")?;
        Ok(Self {
            ar: m.bytes("ar")?.to_vec(),
            queue: m.text("queue")?.to_string(),
            pop_sig: m.fixed("pop_sig")?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MatchAnswer {
    Granted {
        sat: Vec<u8>,
        gs_addr: String,
        gs_noise_static: [u8; 32],
    },
    Refused {
        code: u16,
    },
}

impl CborMsg for MatchAnswer {
    fn encode(&self) -> Vec<u8> {
        match self {
            MatchAnswer::Granted {
                sat,
                gs_addr,
                gs_noise_static,
            } => enc(&text_map([
                ("gs_addr", Value::text(gs_addr)),
                ("gs_noise_static", Value::bytes(gs_noise_static.to_vec())),
                ("kind", Value::Unsigned(1)),
                ("sat", Value::bytes(sat.clone())),
            ])),
            MatchAnswer::Refused { code } => enc(&text_map([
                ("code", Value::Unsigned((*code).into())),
                ("kind", Value::Unsigned(2)),
            ])),
        }
    }

    fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let v = cbor::decode(bytes)?;
        let m = MapView::new(&v, "MatchAnswer")?;
        match m.u64("kind")? {
            1 => Ok(MatchAnswer::Granted {
                sat: m.bytes("sat")?.to_vec(),
                gs_addr: m.text("gs_addr")?.to_string(),
                gs_noise_static: m.fixed("gs_noise_static")?,
            }),
            2 => Ok(MatchAnswer::Refused {
                code: m.u16("code")?,
            }),
            _ => Err(WireError::Schema("MatchAnswer", "kind")),
        }
    }
}

// ---------------------------------------------------------------- Gossip & Equivocation Report

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GossipRequest {
    pub match_id: [u8; 16],
    pub epoch: u32,
    pub digest: [u8; 32],
}

impl CborMsg for GossipRequest {
    fn encode(&self) -> Vec<u8> {
        enc(&text_map([
            ("digest", Value::bytes(self.digest.to_vec())),
            ("epoch", Value::Unsigned(self.epoch.into())),
            ("match_id", Value::bytes(self.match_id.to_vec())),
        ]))
    }

    fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let v = cbor::decode(bytes)?;
        let m = MapView::new(&v, "GossipRequest")?;
        Ok(Self {
            match_id: m.fixed("match_id")?,
            epoch: m.u32("epoch")?,
            digest: m.fixed("digest")?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GossipAnswer {
    Included {
        checkpoint: String,
        index: u64,
        proof: Vec<[u8; 32]>,
    },
    Conflict {
        checkpoint: String,
        index: u64,
        logged: [u8; 32],
        proof: Vec<[u8; 32]>,
    },
    Pending,
}

fn encode_hashes(hashes: &[[u8; 32]]) -> Value {
    Value::Array(hashes.iter().map(|h| Value::bytes(h.to_vec())).collect())
}

fn decode_hashes(
    v: &Value,
    what: &'static str,
    field: &'static str,
) -> Result<Vec<[u8; 32]>, WireError> {
    let arr = v.as_array().ok_or(WireError::Schema(what, field))?;
    arr.iter()
        .map(|item| {
            item.as_bytes()
                .and_then(|b| b.try_into().ok())
                .ok_or(WireError::Schema(what, field))
        })
        .collect()
}

impl CborMsg for GossipAnswer {
    fn encode(&self) -> Vec<u8> {
        match self {
            GossipAnswer::Included {
                checkpoint,
                index,
                proof,
            } => enc(&text_map([
                ("checkpoint", Value::text(checkpoint)),
                ("index", Value::Unsigned(*index)),
                ("kind", Value::Unsigned(1)),
                ("proof", encode_hashes(proof)),
            ])),
            GossipAnswer::Conflict {
                checkpoint,
                index,
                logged,
                proof,
            } => enc(&text_map([
                ("checkpoint", Value::text(checkpoint)),
                ("index", Value::Unsigned(*index)),
                ("kind", Value::Unsigned(2)),
                ("logged", Value::bytes(logged.to_vec())),
                ("proof", encode_hashes(proof)),
            ])),
            GossipAnswer::Pending => enc(&text_map([("kind", Value::Unsigned(3))])),
        }
    }

    fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let v = cbor::decode(bytes)?;
        let m = MapView::new(&v, "GossipAnswer")?;
        match m.u64("kind")? {
            1 => Ok(GossipAnswer::Included {
                checkpoint: m.text("checkpoint")?.to_string(),
                index: m.u64("index")?,
                proof: decode_hashes(m.field("proof")?, "GossipAnswer", "proof")?,
            }),
            2 => Ok(GossipAnswer::Conflict {
                checkpoint: m.text("checkpoint")?.to_string(),
                index: m.u64("index")?,
                logged: m.fixed("logged")?,
                proof: decode_hashes(m.field("proof")?, "GossipAnswer", "proof")?,
            }),
            3 => Ok(GossipAnswer::Pending),
            _ => Err(WireError::Schema("GossipAnswer", "kind")),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EquivocationReport {
    pub checkpoint: Vec<u8>,
}

impl CborMsg for EquivocationReport {
    fn encode(&self) -> Vec<u8> {
        enc(&text_map([(
            "checkpoint",
            Value::bytes(self.checkpoint.clone()),
        )]))
    }

    fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let v = cbor::decode(bytes)?;
        let m = MapView::new(&v, "EquivocationReport")?;
        Ok(Self {
            checkpoint: m.bytes("checkpoint")?.to_vec(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReportAnswer {
    Revoked,
    Rejected(String),
}

impl CborMsg for ReportAnswer {
    fn encode(&self) -> Vec<u8> {
        match self {
            ReportAnswer::Revoked => enc(&text_map([("kind", Value::Unsigned(1))])),
            ReportAnswer::Rejected(why) => enc(&text_map([
                ("kind", Value::Unsigned(2)),
                ("why", Value::text(why)),
            ])),
        }
    }

    fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let v = cbor::decode(bytes)?;
        let m = MapView::new(&v, "ReportAnswer")?;
        match m.u64("kind")? {
            1 => Ok(ReportAnswer::Revoked),
            2 => Ok(ReportAnswer::Rejected(m.text("why")?.to_string())),
            _ => Err(WireError::Schema("ReportAnswer", "kind")),
        }
    }
}

// ---------------------------------------------------------------- Role & Admin RPCs (CBOR)

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Placement {
    pub match_id: [u8; 16],
    pub instance_pub: [u8; 32],
    pub noise_static: [u8; 32],
    pub game_addr: String,
    pub slot: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlaceResponse {
    Placed(Placement),
    NoServer,
    Refused(String),
}

impl CborMsg for PlaceResponse {
    fn encode(&self) -> Vec<u8> {
        match self {
            PlaceResponse::Placed(p) => enc(&text_map([
                ("game_addr", Value::text(&p.game_addr)),
                ("instance_pub", Value::bytes(p.instance_pub.to_vec())),
                ("kind", Value::Unsigned(1)),
                ("match_id", Value::bytes(p.match_id.to_vec())),
                ("noise_static", Value::bytes(p.noise_static.to_vec())),
                ("slot", Value::Unsigned(p.slot.into())),
            ])),
            PlaceResponse::NoServer => enc(&text_map([("kind", Value::Unsigned(2))])),
            PlaceResponse::Refused(why) => enc(&text_map([
                ("kind", Value::Unsigned(3)),
                ("why", Value::text(why)),
            ])),
        }
    }

    fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let v = cbor::decode(bytes)?;
        let m = MapView::new(&v, "PlaceResponse")?;
        match m.u64("kind")? {
            1 => Ok(PlaceResponse::Placed(Placement {
                match_id: m.fixed("match_id")?,
                instance_pub: m.fixed("instance_pub")?,
                noise_static: m.fixed("noise_static")?,
                game_addr: m.text("game_addr")?.to_string(),
                slot: m.u16("slot")?,
            })),
            2 => Ok(PlaceResponse::NoServer),
            3 => Ok(PlaceResponse::Refused(m.text("why")?.to_string())),
            _ => Err(WireError::Schema("PlaceResponse", "kind")),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RevocationRequest {
    Publish(Vec<u8>),
    Since { from: u64, wait_ms: u64 },
}

impl CborMsg for RevocationRequest {
    fn encode(&self) -> Vec<u8> {
        match self {
            RevocationRequest::Publish(cose) => enc(&text_map([
                ("cose", Value::bytes(cose.clone())),
                ("kind", Value::Unsigned(1)),
            ])),
            RevocationRequest::Since { from, wait_ms } => enc(&text_map([
                ("from", Value::Unsigned(*from)),
                ("kind", Value::Unsigned(2)),
                ("wait_ms", Value::Unsigned(*wait_ms)),
            ])),
        }
    }

    fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let v = cbor::decode(bytes)?;
        let m = MapView::new(&v, "RevocationRequest")?;
        match m.u64("kind")? {
            1 => Ok(RevocationRequest::Publish(m.bytes("cose")?.to_vec())),
            2 => Ok(RevocationRequest::Since {
                from: m.u64("from")?,
                wait_ms: m.u64("wait_ms")?,
            }),
            _ => Err(WireError::Schema("RevocationRequest", "kind")),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RevocationResponse {
    Published { seq: u64, log_index: Option<u64> },
    Events(Vec<(u64, Vec<u8>)>),
    Refused(String),
}

impl CborMsg for RevocationResponse {
    fn encode(&self) -> Vec<u8> {
        match self {
            RevocationResponse::Published { seq, log_index } => {
                let mut f = vec![("kind", Value::Unsigned(1)), ("seq", Value::Unsigned(*seq))];
                if let Some(idx) = log_index {
                    f.push(("log_index", Value::Unsigned(*idx)));
                }
                enc(&text_map(f))
            }
            RevocationResponse::Events(evs) => enc(&text_map([
                (
                    "events",
                    Value::Array(
                        evs.iter()
                            .map(|(s, b)| {
                                Value::Array(vec![Value::Unsigned(*s), Value::bytes(b.clone())])
                            })
                            .collect(),
                    ),
                ),
                ("kind", Value::Unsigned(2)),
            ])),
            RevocationResponse::Refused(why) => enc(&text_map([
                ("kind", Value::Unsigned(3)),
                ("why", Value::text(why)),
            ])),
        }
    }

    fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let v = cbor::decode(bytes)?;
        let m = MapView::new(&v, "RevocationResponse")?;
        match m.u64("kind")? {
            1 => Ok(RevocationResponse::Published {
                seq: m.u64("seq")?,
                log_index: m.u64("log_index").ok(),
            }),
            2 => {
                let arr = m
                    .field("events")?
                    .as_array()
                    .ok_or(WireError::Schema("RevocationResponse", "events"))?;
                let mut out = Vec::with_capacity(arr.len());
                for item in arr {
                    let pair = item
                        .as_array()
                        .ok_or(WireError::Schema("RevocationResponse", "events"))?;
                    if pair.len() != 2 {
                        return Err(WireError::Schema("RevocationResponse", "events"));
                    }
                    let seq = pair[0]
                        .as_u64()
                        .ok_or(WireError::Schema("RevocationResponse", "seq"))?;
                    let ev = pair[1]
                        .as_bytes()
                        .ok_or(WireError::Schema("RevocationResponse", "cose"))?
                        .to_vec();
                    out.push((seq, ev));
                }
                Ok(RevocationResponse::Events(out))
            }
            3 => Ok(RevocationResponse::Refused(m.text("why")?.to_string())),
            _ => Err(WireError::Schema("RevocationResponse", "kind")),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvidenceStoreRequest {
    Put { match_id: [u8; 16], object: Vec<u8> },
    Get([u8; 32]),
    List([u8; 16]),
}

impl CborMsg for EvidenceStoreRequest {
    fn encode(&self) -> Vec<u8> {
        match self {
            EvidenceStoreRequest::Put { match_id, object } => enc(&text_map([
                ("kind", Value::Unsigned(1)),
                ("match_id", Value::bytes(match_id.to_vec())),
                ("object", Value::bytes(object.clone())),
            ])),
            EvidenceStoreRequest::Get(digest) => enc(&text_map([
                ("digest", Value::bytes(digest.to_vec())),
                ("kind", Value::Unsigned(2)),
            ])),
            EvidenceStoreRequest::List(match_id) => enc(&text_map([
                ("kind", Value::Unsigned(3)),
                ("match_id", Value::bytes(match_id.to_vec())),
            ])),
        }
    }

    fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let v = cbor::decode(bytes)?;
        let m = MapView::new(&v, "EvidenceStoreRequest")?;
        match m.u64("kind")? {
            1 => Ok(EvidenceStoreRequest::Put {
                match_id: m.fixed("match_id")?,
                object: m.bytes("object")?.to_vec(),
            }),
            2 => Ok(EvidenceStoreRequest::Get(m.fixed("digest")?)),
            3 => Ok(EvidenceStoreRequest::List(m.fixed("match_id")?)),
            _ => Err(WireError::Schema("EvidenceStoreRequest", "kind")),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvidenceStoreResponse {
    Stored([u8; 32]),
    Object(Option<Vec<u8>>),
    Digests(Vec<[u8; 32]>),
    Refused(String),
}

impl CborMsg for EvidenceStoreResponse {
    fn encode(&self) -> Vec<u8> {
        match self {
            EvidenceStoreResponse::Stored(d) => enc(&text_map([
                ("digest", Value::bytes(d.to_vec())),
                ("kind", Value::Unsigned(1)),
            ])),
            EvidenceStoreResponse::Object(obj) => {
                let mut f = vec![("kind", Value::Unsigned(2))];
                if let Some(o) = obj {
                    f.push(("object", Value::bytes(o.clone())));
                }
                enc(&text_map(f))
            }
            EvidenceStoreResponse::Digests(ds) => enc(&text_map([
                ("digests", encode_hashes(ds)),
                ("kind", Value::Unsigned(3)),
            ])),
            EvidenceStoreResponse::Refused(why) => enc(&text_map([
                ("kind", Value::Unsigned(4)),
                ("why", Value::text(why)),
            ])),
        }
    }

    fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let v = cbor::decode(bytes)?;
        let m = MapView::new(&v, "EvidenceStoreResponse")?;
        match m.u64("kind")? {
            1 => Ok(EvidenceStoreResponse::Stored(m.fixed("digest")?)),
            2 => Ok(EvidenceStoreResponse::Object(
                m.bytes("object").ok().map(<[u8]>::to_vec),
            )),
            3 => Ok(EvidenceStoreResponse::Digests(decode_hashes(
                m.field("digests")?,
                "EvidenceStoreResponse",
                "digests",
            )?)),
            4 => Ok(EvidenceStoreResponse::Refused(m.text("why")?.to_string())),
            _ => Err(WireError::Schema("EvidenceStoreResponse", "kind")),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LogRequest {
    Add(Vec<Vec<u8>>),
    Checkpoint,
    Inclusion { index: u64, size: u64 },
    Consistency { old: u64, new: u64 },
    Cosign { text: String, line: String },
}

impl CborMsg for LogRequest {
    fn encode(&self) -> Vec<u8> {
        match self {
            LogRequest::Add(entries) => enc(&text_map([
                (
                    "entries",
                    Value::Array(entries.iter().map(|e| Value::bytes(e.clone())).collect()),
                ),
                ("kind", Value::Unsigned(1)),
            ])),
            LogRequest::Checkpoint => enc(&text_map([("kind", Value::Unsigned(2))])),
            LogRequest::Inclusion { index, size } => enc(&text_map([
                ("index", Value::Unsigned(*index)),
                ("kind", Value::Unsigned(3)),
                ("size", Value::Unsigned(*size)),
            ])),
            LogRequest::Consistency { old, new } => enc(&text_map([
                ("kind", Value::Unsigned(4)),
                ("new", Value::Unsigned(*new)),
                ("old", Value::Unsigned(*old)),
            ])),
            LogRequest::Cosign { text, line } => enc(&text_map([
                ("kind", Value::Unsigned(5)),
                ("line", Value::text(line)),
                ("text", Value::text(text)),
            ])),
        }
    }

    fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let v = cbor::decode(bytes)?;
        let m = MapView::new(&v, "LogRequest")?;
        match m.u64("kind")? {
            1 => {
                let arr = m
                    .field("entries")?
                    .as_array()
                    .ok_or(WireError::Schema("LogRequest", "entries"))?;
                let entries = arr
                    .iter()
                    .map(|e| {
                        e.as_bytes()
                            .map(<[u8]>::to_vec)
                            .ok_or(WireError::Schema("LogRequest", "entries"))
                    })
                    .collect::<Result<_, _>>()?;
                Ok(LogRequest::Add(entries))
            }
            2 => Ok(LogRequest::Checkpoint),
            3 => Ok(LogRequest::Inclusion {
                index: m.u64("index")?,
                size: m.u64("size")?,
            }),
            4 => Ok(LogRequest::Consistency {
                old: m.u64("old")?,
                new: m.u64("new")?,
            }),
            5 => Ok(LogRequest::Cosign {
                text: m.text("text")?.to_string(),
                line: m.text("line")?.to_string(),
            }),
            _ => Err(WireError::Schema("LogRequest", "kind")),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LogResponse {
    Added(Vec<(u64, Vec<u8>)>),
    Checkpoint(String),
    Proof(Vec<[u8; 32]>),
    Done,
    Refused(String),
}

impl CborMsg for LogResponse {
    fn encode(&self) -> Vec<u8> {
        match self {
            LogResponse::Added(items) => enc(&text_map([
                (
                    "added",
                    Value::Array(
                        items
                            .iter()
                            .map(|(i, r)| {
                                Value::Array(vec![Value::Unsigned(*i), Value::bytes(r.clone())])
                            })
                            .collect(),
                    ),
                ),
                ("kind", Value::Unsigned(1)),
            ])),
            LogResponse::Checkpoint(note) => enc(&text_map([
                ("checkpoint", Value::text(note)),
                ("kind", Value::Unsigned(2)),
            ])),
            LogResponse::Proof(hashes) => enc(&text_map([
                ("kind", Value::Unsigned(3)),
                ("proof", encode_hashes(hashes)),
            ])),
            LogResponse::Done => enc(&text_map([("kind", Value::Unsigned(4))])),
            LogResponse::Refused(why) => enc(&text_map([
                ("kind", Value::Unsigned(5)),
                ("why", Value::text(why)),
            ])),
        }
    }

    fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let v = cbor::decode(bytes)?;
        let m = MapView::new(&v, "LogResponse")?;
        match m.u64("kind")? {
            1 => {
                let arr = m
                    .field("added")?
                    .as_array()
                    .ok_or(WireError::Schema("LogResponse", "added"))?;
                let mut out = Vec::with_capacity(arr.len());
                for item in arr {
                    let pair = item
                        .as_array()
                        .ok_or(WireError::Schema("LogResponse", "added"))?;
                    if pair.len() != 2 {
                        return Err(WireError::Schema("LogResponse", "added"));
                    }
                    let idx = pair[0]
                        .as_u64()
                        .ok_or(WireError::Schema("LogResponse", "index"))?;
                    let rec = pair[1]
                        .as_bytes()
                        .ok_or(WireError::Schema("LogResponse", "receipt"))?
                        .to_vec();
                    out.push((idx, rec));
                }
                Ok(LogResponse::Added(out))
            }
            2 => Ok(LogResponse::Checkpoint(m.text("checkpoint")?.to_string())),
            3 => Ok(LogResponse::Proof(decode_hashes(
                m.field("proof")?,
                "LogResponse",
                "proof",
            )?)),
            4 => Ok(LogResponse::Done),
            5 => Ok(LogResponse::Refused(m.text("why")?.to_string())),
            _ => Err(WireError::Schema("LogResponse", "kind")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_messages_round_trip() {
        let cr = ChallengeRequest {
            version: CONTROL_VERSION,
            purpose: Purpose::GsJoin,
        };
        assert_eq!(ChallengeRequest::decode(&cr.encode()).unwrap(), cr);

        let jr = JoinRequest {
            gs_id: "gs-1".into(),
            sw_hash: [1; 32],
            t_unix_ms: 1_700_000_000_000,
            nonce: [2; 16],
            ephemeral_pub: [3; 32],
            noise_static: [4; 32],
            game_addr: "127.0.0.1:50000".into(),
            sig_gs: [5; 64],
            gs_pub: [6; 32],
            tpm2: Some(Box::new(TpmEvidence {
                ek_public: vec![7; 8],
                ek_chain: vec![vec![8; 16]],
                ak_public: vec![9; 8],
                quote: vec![10; 8],
                quote_signature: vec![11; 8],
                pcrs: vec![(0, vec![0; 32]), (10, vec![1; 32])],
                boot_log: vec![12; 4],
                ima_log: vec![13; 6],
                session_public: Vec::new(),
                certify: Vec::new(),
                certify_signature: Vec::new(),
            })),
        };
        assert_eq!(JoinRequest::decode(&jr.encode()).unwrap(), jr);

        let ga = GossipAnswer::Conflict {
            checkpoint: "origin\n1\nabc\n".into(),
            index: 4,
            logged: [0xaa; 32],
            proof: vec![[0xbb; 32], [0xcc; 32]],
        };
        assert_eq!(GossipAnswer::decode(&ga.encode()).unwrap(), ga);
    }
}
