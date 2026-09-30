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

pub use crate::tpm::TpmQuote;

/// Version in `ChallengeRequest`; bump on any admission-flow change (3: a
/// GS's `JoinRequest.tpm2` and credential activation).
pub const ADMISSION_VERSION: u32 = 3;

/// Who is opening a control connection to the VS.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerRole {
    GameServer,
    Client,
}

/// First message on a control connection: asks for a single-use challenge.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ChallengeRequest {
    pub version: u32,
    pub role: PeerRole,
}

/// VS → peer: single-use nonce. A GS's join TPM quote must cover it (F04);
/// a client's session key signs it to prove possession.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct AttestChallenge {
    pub nonce: [u8; 32],
}

// ---------------------------------------------------------------- GS <-> VS

/// GS → VS during admission, after `AttestChallenge`.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JoinRequest {
    pub gs_id: String,
    /// Hash of the GS binary, as the GS reports it. Self-reported, so worth
    /// nothing alone (F06): with `tpm2` evidence the VS takes the build from
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
    /// The prototype's simulated TPM quote.
    pub tpm_quote: Option<TpmQuote>,
    /// A real TPM 2.0's evidence (attest-tpm): the quote covers
    /// `join_quote_nonce(challenge, join_request_sign_bytes)`. The VS answers
    /// with a [`CredentialChallenge`] before `JoinAccept`.
    pub tpm2: Option<Tpm2Evidence>,
}

/// A TPM 2.0's evidence for admission, as the TPM and kernel produced it.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct Tpm2Evidence {
    /// `TPM2B_PUBLIC` of the Endorsement Key, and its certificate chain
    /// (leaf first; to a manufacturer root the VS pins).
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

/// VS → GS, when the JoinRequest carries `tpm2`: a secret only the TPM with
/// that EK can open, and only for that AK (credential activation). Contents
/// of `TPM2B_ID_OBJECT` and `TPM2B_ENCRYPTED_SECRET`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct CredentialChallenge {
    pub id_object: Vec<u8>,
    pub encrypted_secret: Vec<u8>,
}

/// GS → VS: what `TPM2_ActivateCredential` gave.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct CredentialResponse {
    pub secret: Vec<u8>,
}

/// VS → GS after admitting it.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JoinAccept {
    /// VS-minted session id; also the match id of the match this GS hosts.
    pub session_id: [u8; 16],
    /// VS signature binding this session_id to the GS.
    pub sig_vs: Sig,
    pub vs_pub: [u8; 32],
}

/// VS → GS: the next Server Attestation Result in this instance's chain
/// (successor of the PlayTicket, 04 §6.3). Every ~2 s while blessed.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SarIssue {
    pub sar: Vec<u8>,
}

/// GS → VS: one signed Checkpoint per epoch (04 §8.1), replacing the
/// Heartbeat + TranscriptDigest pair. Optionally carries a TPM
/// re-attestation quote seeded by the SAR with sequence `quote_sar_seq`.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CheckpointSubmit {
    pub checkpoint: Vec<u8>,
    pub tpm_quote: Option<TpmQuote>,
    pub quote_sar_seq: u64,
}

// ---------------------------------------------------------------- client <-> VS

/// Client → VS after `AttestChallenge`: device evidence for the (stub)
/// Verifier and an admission request for the (stub) Broker.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ClientAdmissionRequest {
    /// Ed25519 session key the AR and SAT will be bound to.
    pub session_pub: [u8; 32],
    /// Session-key signature over `client_admission_sign_bytes` (proof of
    /// possession, bound to the challenge).
    #[serde(with = "BigArray")]
    pub pop_sig: [u8; 64],
    pub platform: String,
    pub client_build: [u8; 32],
    pub queue: String,
    /// Platform evidence (TPM quote, Play Integrity token, ...), opaque to
    /// everyone but the Verifier. Empty: no evidence (tier D0).
    pub evidence: Vec<u8>,
}

/// VS → client.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ClientAdmission {
    Granted {
        ar: Vec<u8>,
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
