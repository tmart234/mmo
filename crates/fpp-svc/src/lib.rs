//! Plumbing for the trust-plane services (roadmap P2): the Verifier,
//! Broker, Server Liveness, Revocation Feed, Transparency Log, its witness
//! and the Evidence Store run as separate processes, each with its own
//! keys, so that one failing or compromised does not take the others' keys
//! or their availability with it (03 §3).
//!
//! - [`cell`]: one regional cell's CA and each service's TLS identity
//!   (`<service>.fpp-cell`), issued at once by `fpp-cell init`; the CA's
//!   private key is never written.
//! - [`mtls`]: QUIC with mutual TLS 1.3 (FPP-T1): both sides present a
//!   cell certificate, and a service learns who is calling from it.
//! - [`rpc`]: one request and one response per stream, and serving them
//!   with the caller's name, which each service checks against the callers
//!   it allows.

pub mod cell;
pub mod mtls;
pub mod rpc;

pub use cell::{Identity, CELL_DOMAIN};
pub use quinn;
pub use rpc::{call, serve, Caller};
