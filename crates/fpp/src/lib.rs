//! Fair-Play Protocol (FPP) v1 — an owned, fairness-maximalist,
//! cryptographically enforced authority-and-trust protocol for video games.
//!
//! Consolidated into one self-contained protocol crate:
//! - [`types`]: identifiers, device trust tiers, server classes, reason codes, domain labels
//! - [`wire`]: zero-dep strict deterministic CBOR, COSE_Sign1 / COSE_Sign, wire payloads
//! - [`crypto`]: key roles with `fpp-ctx` allowlists, Ed25519 + ES256 (low-S), optional
//!   hybrid ML-DSA-65 (`s1h`), plus shared SHA-256 / HMAC-SHA256 / ChaCha20-Poly1305
//! - [`merkle`]: RFC 9162 Merkle trees with inclusion and consistency proofs
//! - [`tokens`]: AR, SAT, SAR (CWT/EAT), SAR chain verification, §7.2 admission, control messages
//! - [`session`]: sans-I/O `Noise_IK_25519_ChaChaPoly_SHA256` UDP game sessions
//! - [`bundle`]: zero-dep regional KeyBundle (signing keys + pinned Noise transport keys)
//! - [`control`]: deterministic-CBOR control-plane and inter-role wire messages
//! - [`transport`]: owned `Noise_IK` framed TCP transport (sync + optional `async-net`)
//! - [`tpm2_collect`]: pure-std `tpm2-tools` evidence collector & `swtpm` harness
//! - [`gs_link`]: unified game-server ↔ Server Liveness link
//! - [`log`]: C2SP Transparency Log (`tlog-tiles`, signed notes, witnesses, receipts) (`log` feature)
//! - [`audit`]: evidence bundle accounting & equivocation auditor

#![forbid(unsafe_code)]

pub mod audit;
pub mod b64;
pub mod bundle;
pub mod control;
pub mod crypto;
pub mod gs_link;
#[cfg(feature = "log")]
pub mod log;
pub mod merkle;
pub mod session;
pub mod tokens;
pub mod tpm2_collect;
pub mod transport;
pub mod types;
pub mod wire;
