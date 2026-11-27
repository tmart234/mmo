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
//! tests check this log against Go's implementation (`interop/go/tlog`).

pub mod leaf;
#[allow(clippy::module_inception)]
pub mod log;
pub mod note;
pub mod tiles;
pub mod witness;

pub use log::{Appended, Log};
pub use note::{Checkpoint, Note};
pub use witness::Witness;

#[derive(Debug)]
pub enum LogError {
    Note(&'static str),
    Storage(&'static str),
    Io(std::io::Error),
    TooLarge,
    Range,
    Stale,
    Rollback,
    SplitView,
}

impl core::fmt::Display for LogError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            LogError::Note(m) => write!(f, "note: {m}"),
            LogError::Storage(m) => write!(f, "storage: {m}"),
            LogError::Io(e) => write!(f, "io: {e}"),
            LogError::TooLarge => f.write_str("entry larger than 65535 bytes"),
            LogError::Range => f.write_str("index or tree size out of range"),
            LogError::Stale => f.write_str("the checkpoint changed meanwhile"),
            LogError::Rollback => f.write_str("a smaller tree than the one already cosigned"),
            LogError::SplitView => {
                f.write_str("inconsistent with the checkpoint already cosigned (split view)")
            }
        }
    }
}

impl std::error::Error for LogError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            LogError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for LogError {
    fn from(e: std::io::Error) -> Self {
        LogError::Io(e)
    }
}
