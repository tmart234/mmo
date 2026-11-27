//! Append-only match ledger (JSON lines): human-readable counterpart to the
//! signed Checkpoint chain.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct Ledger {
    file: File,
    pub path: PathBuf,
}

impl Ledger {
    pub fn open_in(dir: &Path, session_id_hex4: &str) -> std::io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let path = dir.join(format!("session_{session_id_hex4}.log"));
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self { file, path })
    }

    pub fn append_line(&mut self, line: &str) {
        let _ = self
            .file
            .write_all(line.as_bytes())
            .and_then(|_| self.file.write_all(b"\n"))
            .and_then(|_| self.file.flush());
    }
}
