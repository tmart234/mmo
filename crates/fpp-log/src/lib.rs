//! The FPP Transparency Log (04 §8.2): an append-only RFC 9162 Merkle log
//! in the C2SP formats (`tlog-tiles`, `tlog-checkpoint`, `signed-note`,
//! `tlog-cosignature`), signed `LogReceipt`s, inclusion and consistency
//! proofs, and a witness.
//!
//! What it is for: enforcement records, revocations, host batches and
//! build releases go in, and no one (including the operator) can later
//! change or hide one without the change showing in a checkpoint that
//! witnesses refuse to cosign. The formats are the ones Go's
//! `golang.org/x/mod/sumdb` and the public witness network use, and the
//! tests check this log against Go's implementation (`tests/go/`).

pub mod b64;
pub mod leaf;
pub mod log;
pub mod note;
pub mod tiles;
pub mod witness;

pub use log::{Appended, Log};
pub use note::{Checkpoint, Note};
pub use witness::Witness;

#[derive(Debug, thiserror::Error)]
pub enum LogError {
    #[error("note: {0}")]
    Note(&'static str),
    #[error("storage: {0}")]
    Storage(&'static str),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("entry larger than 65535 bytes")]
    TooLarge,
    #[error("index or tree size out of range")]
    Range,
    #[error("the checkpoint changed meanwhile")]
    Stale,
    #[error("a smaller tree than the one already cosigned")]
    Rollback,
    #[error("inconsistent with the checkpoint already cosigned (split view)")]
    SplitView,
}
