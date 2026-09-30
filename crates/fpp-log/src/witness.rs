//! A witness (C2SP `tlog-witness` semantics): it cosigns a log's
//! checkpoint only if the log signed it and it extends, by a valid
//! consistency proof, the last checkpoint the witness cosigned. A log that
//! shows two views (a split view, to hide an entry from some) cannot get
//! both cosigned by the same witness; verifiers that require cosignatures
//! see one history.
//!
//! The witness keeps only the latest (size, root) per log, on disk, so a
//! restart cannot be used to roll it back.

use std::path::PathBuf;

use ed25519_dalek::SigningKey;
use fpp_merkle::verify_consistency;
use fpp_types::Digest;

use crate::note::{self, Checkpoint, Note};
use crate::{b64, LogError};

pub struct Witness {
    name: String,
    key: SigningKey,
    log_origin: String,
    log_key: [u8; 32],
    log_ml_key: Vec<u8>,
    state: PathBuf,
    last: Option<Checkpoint>,
}

impl Witness {
    pub fn open(
        name: &str,
        key: SigningKey,
        log_origin: &str,
        log_key: [u8; 32],
        log_ml_key: Vec<u8>,
        state: impl Into<PathBuf>,
    ) -> Result<Witness, LogError> {
        if !note::valid_name(name) {
            return Err(LogError::Note("witness name"));
        }
        let state = state.into();
        let last = match std::fs::read_to_string(&state) {
            Ok(text) => Some(Checkpoint::parse(&text)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        };
        Ok(Witness {
            name: name.to_string(),
            key,
            log_origin: log_origin.to_string(),
            log_key,
            log_ml_key,
            state,
            last,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    /// The size of the last checkpoint cosigned (what a consistency proof
    /// must start from).
    pub fn last_size(&self) -> u64 {
        self.last.as_ref().map_or(0, |c| c.size)
    }

    /// Cosign `signed_checkpoint` given a consistency proof from the last
    /// cosigned size; the cosignature line to add to the note.
    pub fn cosign(
        &mut self,
        signed_checkpoint: &str,
        proof: &[Digest],
        now_s: u64,
    ) -> Result<String, LogError> {
        let note = Note::parse(signed_checkpoint)?;
        // (both halves of the log's hybrid key)
        note.verify_hybrid(&self.log_origin, &self.log_key, &self.log_ml_key)?;
        let new = Checkpoint::parse(&note.text)?;
        if new.origin != self.log_origin {
            return Err(LogError::Note("another log's checkpoint"));
        }
        if let Some(last) = &self.last {
            if new.size < last.size {
                return Err(LogError::Rollback);
            }
            if new.size == last.size {
                if new.root != last.root {
                    return Err(LogError::SplitView);
                }
            } else if last.size > 0
                && !verify_consistency(
                    last.size,
                    new.size,
                    &Digest(last.root),
                    &Digest(new.root),
                    proof,
                )
            {
                return Err(LogError::SplitView);
            }
        }
        std::fs::write(&self.state, new.text())?;
        let line = note::cosign(&note.text, &self.name, &self.key, now_s);
        self.last = Some(new);
        Ok(line)
    }
}

/// `origin`, size and root of a checkpoint, for messages.
pub fn describe(c: &Checkpoint) -> String {
    format!(
        "{} @ {} ({})",
        c.origin,
        c.size,
        &b64::encode(&c.root)[..12]
    )
}
