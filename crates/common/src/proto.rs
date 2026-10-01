//! Prototype control-plane messages (QUIC, bincode-framed) and the reference
//! title's game payloads.
//!
//! FPP objects themselves (ARs, SATs, SARs, Checkpoints, InputCommits) travel
//! as opaque signed bytes inside these messages and are verified with
//! `fpp-tokens` / `fpp-crypto`; bincode only frames the envelope. Game data
//! between clients and the GS uses `fpp-session` (ADR-002), not these types.

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

/// Signature bytes (Ed25519, 64 bytes).
pub type Sig = Vec<u8>;

pub type OpId = [u8; 16];

/// Version in `ChallengeRequest`; bump on any admission-flow change (7:
/// a purpose, and players' equivocation reports to Server Liveness).
pub const ADMISSION_VERSION: u32 = 7;

/// First message on a connection to a public service (Server Liveness, the
/// Verifier, the Broker): asks for a single-use challenge.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ChallengeRequest {
    pub version: u32,
    pub purpose: Purpose,
}

/// Service → peer: single-use nonce. A GS's join TPM quote must cover it (F04);
/// a client's session key signs it to prove possession.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct AttestChallenge {
    pub nonce: [u8; 32],
}

// ---------------------------------------------------------------- GS <-> Server Liveness

/// GS → Server Liveness during admission, after `AttestChallenge`.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JoinRequest {
    pub gs_id: String,
    /// Hash of the GS binary, as the GS reports it. Self-reported, so worth
    /// nothing alone (F06): with `tpm2` evidence Server Liveness takes the build from
    /// the kernel's measurement instead, and refuses a report that differs.
    pub sw_hash: [u8; 32],
    pub t_unix_ms: u64,
    pub nonce: [u8; 16],
    /// Per-session Ed25519 **instance key**: signs this GS's Checkpoints;
    /// SARs certify it (`cnf`), SATs name its digest (`aud`).
    pub ephemeral_pub: [u8; 32],
    /// Static X25519 key of the GS's fpp-session game port (SAR `noise_static`).
    pub noise_static: [u8; 32],
    /// Where clients reach the game port (UDP), e.g. "127.0.0.1:50000".
    pub game_addr: String,
    /// Signature by the GS long-term key over `join_request_sign_bytes`.
    pub sig_gs: Sig,
    pub gs_pub: [u8; 32],
    /// A real TPM 2.0's evidence (attest-tpm): the quote covers
    /// `join_quote_nonce(challenge, join_request_sign_bytes)`. Server Liveness answers
    /// with a [`CredentialChallenge`] before `JoinAccept`.
    pub tpm2: Option<Tpm2Evidence>,
}

/// A TPM 2.0's evidence for admission, as the TPM and kernel produced it.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct Tpm2Evidence {
    /// `TPM2B_PUBLIC` of the Endorsement Key, and its certificate chain
    /// (leaf first; to a manufacturer root Server Liveness pins).
    pub ek_public: Vec<u8>,
    pub ek_chain: Vec<Vec<u8>>,
    /// `TPM2B_PUBLIC` of the Attestation Key that signed the quote.
    pub ak_public: Vec<u8>,
    /// `TPMS_ATTEST` and `TPMT_SIGNATURE`.
    pub attest: Vec<u8>,
    pub signature: Vec<u8>,
    /// The quoted PCRs' values (SHA-256 bank).
    pub pcrs: std::collections::BTreeMap<u8, Vec<u8>>,
    /// The firmware's measured-boot log and the kernel's IMA log.
    pub boot_log: Option<Vec<u8>>,
    pub ima_log: Option<Vec<u8>>,
}

/// Server Liveness → GS, when the JoinRequest carries `tpm2`: a secret only the TPM with
/// that EK can open, and only for that AK (credential activation). Contents
/// of `TPM2B_ID_OBJECT` and `TPM2B_ENCRYPTED_SECRET`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct CredentialChallenge {
    pub id_object: Vec<u8>,
    pub encrypted_secret: Vec<u8>,
}

/// GS → Server Liveness: what `TPM2_ActivateCredential` gave.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct CredentialResponse {
    pub secret: Vec<u8>,
}

/// Server Liveness → GS after admitting it. It needs no signature: it comes
/// over TLS to the pinned Server Liveness certificate, and what blesses the
/// GS is its SAR chain, under the Server Liveness key in the bundle (the GS
/// checks each SAR certifies its own keys, and clients play only under one).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JoinAccept {
    /// Session id; also the match id of the match this GS hosts.
    pub session_id: [u8; 16],
}

/// Server Liveness → GS, one per unidirectional stream.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ToGameServer {
    /// The next Server Attestation Result in this instance's chain
    /// (04 §6.3). Every ~2 s while blessed.
    Sar(Vec<u8>),
    /// A revocation event (04 §9, COSE signed by Enforcement), relayed from
    /// the Revocation Feed; the GS checks the signature and applies it.
    Revocation(Vec<u8>),
}

/// GS → Server Liveness: one signed Checkpoint per epoch (04 §8.1).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CheckpointSubmit {
    pub checkpoint: Vec<u8>,
}

// ---------------------------------------------------------------- client <-> Verifier, Broker

/// Client → Verifier after `AttestChallenge`: a fresh session key and the
/// device's platform evidence, for an Attestation Result.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EvidenceRequest {
    /// Ed25519 session key the AR (and later the SAT) is bound to.
    pub session_pub: [u8; 32],
    /// Session-key signature over `evidence_request_sign_bytes` (proof of
    /// possession, bound to the Verifier's challenge).
    #[serde(with = "BigArray")]
    pub pop_sig: [u8; 64],
    pub platform: String,
    pub client_build: [u8; 32],
    /// Platform evidence (Android key attestation, App Attest), opaque to
    /// everyone but the Verifier. Empty: no evidence (tier D0).
    pub evidence: Vec<u8>,
}

/// Verifier → client.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum EvidenceAnswer {
    /// The Attestation Result (evidence that fails appraisal still gets
    /// one, at tier D0).
    Ar(Vec<u8>),
    Refused {
        /// `fpp_types::Reason` code.
        code: u16,
    },
}

/// Client → Broker after `AttestChallenge`: an AR and a queue, for a match.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MatchRequest {
    pub ar: Vec<u8>,
    pub queue: String,
    /// Signature by the AR's session key (`cnf`) over
    /// `match_request_sign_bytes`: the AR is used by the key it names, now.
    #[serde(with = "BigArray")]
    pub pop_sig: [u8; 64],
}

/// Broker → client.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum MatchAnswer {
    Granted {
        sat: Vec<u8>,
        /// The game server to join and its static key (checked against its SAR).
        gs_addr: String,
        gs_noise_static: [u8; 32],
    },
    Refused {
        /// `fpp_types::Reason` code.
        code: u16,
    },
}

// ---------------------------------------------------------------- client <-> Transparency Log

/// Client → Transparency Log (public, read only): is this Checkpoint the
/// one Server Liveness logged for its match and epoch? (EVD-03, 04 §7.6)
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct GossipRequest {
    pub match_id: [u8; 16],
    pub epoch: u32,
    /// SHA-256 of the signed Checkpoint the client holds.
    pub digest: [u8; 32],
}

/// Transparency Log → client. Proofs are against `checkpoint`, the log's
/// latest witness-cosigned checkpoint (a signed note).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum GossipAnswer {
    /// The client's Checkpoint is logged at `index`.
    Included {
        checkpoint: String,
        index: u64,
        proof: Vec<[u8; 32]>,
    },
    /// Another Checkpoint (`logged`) is logged for this match and epoch, at
    /// `index`: the server showed this client something else.
    Conflict {
        checkpoint: String,
        index: u64,
        logged: [u8; 32],
        proof: Vec<[u8; 32]>,
    },
    /// Nothing for this match and epoch in a cosigned checkpoint yet.
    Pending,
}

// ---------------------------------------------------------------- client -> Server Liveness

/// What a connection to Server Liveness is for (in `ChallengeRequest`).
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    /// A game server joins (then `JoinRequest`).
    Join,
    /// A player reports a split view (then `EquivocationReport`).
    Report,
}

/// Player → Server Liveness: a Checkpoint the game server signed and sent
/// this player, which the log shows differs from the one it gave Server
/// Liveness for the same match and epoch.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct EquivocationReport {
    pub checkpoint: Vec<u8>,
}

/// Server Liveness → player.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ReportAnswer {
    /// Proven: the instance is revoked (no more SARs).
    Revoked,
    /// Not a proof of equivocation, and why.
    Rejected(String),
}

// ---------------------------------------------------------------- title payloads

/// The reference title's input intent (04 §7.3 payload): what the player
/// wants, never positions or outcomes.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum ClientCmd {
    Move {
        dx: f32,
        dy: f32,
    },
    /// Value-changing example, idempotent via `op_id`.
    SpendCoins(SpendCoins),
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SpendCoins {
    pub op_id: OpId,
    pub amount: u64,
}

/// GS → client each tick (unreliable, latest wins).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct WorldSnapshot {
    pub tick: u64,
    pub you: (f32, f32),
    /// Every other player (the prototype has no interest management yet:
    /// a built-in ESP, INFO-01, roadmap P4).
    pub others: Vec<(u16, f32, f32)>,
}
