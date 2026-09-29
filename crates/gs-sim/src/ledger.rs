//! Append-only match ledger (JSON lines): what the GS decided, for audit and
//! the smoke test. The signed record is the Checkpoint chain; this is the
//! human-readable side.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

#[derive(Debug)]
pub struct Ledger {
    file: File,
}

impl Ledger {
    pub fn open_for_session(session_id_hex4: &str) -> std::io::Result<Self> {
        let mut p = PathBuf::from("ledger");
        std::fs::create_dir_all(&p)?;
        p.push(format!("session_{session_id_hex4}.log"));
        let file = OpenOptions::new().create(true).append(true).open(p)?;
        Ok(Self { file })
    }

    /// Best effort: a full disk must not stop the match.
    pub fn append_line(&mut self, line: &str) {
        let _ = self
            .file
            .write_all(line.as_bytes())
            .and_then(|_| self.file.write_all(b"\n"))
            .and_then(|_| self.file.flush());
    }
}
