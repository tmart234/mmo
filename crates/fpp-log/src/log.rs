//! The log: an append-only RFC 9162 tree kept as C2SP tiles in a
//! directory, a signed checkpoint, receipts, and proofs.
//!
//! The directory is the log: `checkpoint` (the signed note, with witness
//! cosignatures), `tile/...` (hash tiles and entry bundles). Tiles and
//! entries are written before the checkpoint that covers them, so a
//! published checkpoint never names a tree its tiles cannot rebuild. On
//! open, the tree is rebuilt from the entry bundles and must hash to the
//! checkpoint's root, or the storage was changed.

use std::path::{Path, PathBuf};

use fpp_crypto::hybrid::{sign_hybrid, HybridSigner};
use fpp_merkle::{consistency_proof, inclusion_proof, leaf_hash, node_hash, root_from_leaf_hashes};
use fpp_types::Digest;
use fpp_wire::LogReceipt;
use sha2::{Digest as _, Sha256};

use crate::note::{self, Checkpoint, Note};
use crate::tiles::{entries_path, tile_path, tiles_at, HEIGHT, WIDTH};
use crate::LogError;

/// Largest entry: entry bundles prefix each with 16 bits.
pub const MAX_ENTRY: usize = u16::MAX as usize;

/// Where an appended entry landed, and the signed promise of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Appended {
    pub index: u64,
    pub leaf_hash: Digest,
    /// COSE_Sign1 `LogReceipt`.
    pub receipt: Vec<u8>,
}

pub struct Log {
    dir: PathBuf,
    origin: String,
    key: HybridSigner,
    mmd_s: u64,
    /// `levels[h][i]`: hash of the complete subtree of 2^h leaves at `i`.
    levels: Vec<Vec<Digest>>,
    /// Entries of the last, incomplete bundle.
    bundle: Vec<Vec<u8>>,
    /// The published checkpoint, with cosignatures.
    note: Note,
    /// Witnesses whose cosignatures it publishes: name and key.
    witnesses: Vec<(String, [u8; 32])>,
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), LogError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn encode_bundle(entries: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for e in entries {
        out.extend_from_slice(&(e.len() as u16).to_be_bytes());
        out.extend_from_slice(e);
    }
    out
}

/// Split an entry bundle into its entries.
pub fn decode_bundle(mut bytes: &[u8]) -> Result<Vec<Vec<u8>>, LogError> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < 2 {
            return Err(LogError::Storage("entry bundle"));
        }
        let n = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
        if bytes.len() < 2 + n {
            return Err(LogError::Storage("entry bundle"));
        }
        out.push(bytes[2..2 + n].to_vec());
        bytes = &bytes[2 + n..];
    }
    Ok(out)
}

impl Log {
    /// The log ID: SHA-256 of its Ed25519 public key.
    pub fn log_id(key: &HybridSigner) -> Digest {
        Digest(Sha256::digest(key.ed25519_public().to_bytes()).into())
    }

    /// Open (or create) the log in `dir`. `origin` names it (and its key)
    /// in checkpoints, e.g. `fpp.example/log/eu-1`.
    /// The key is hybrid (FPP-S1H): receipts are `COSE_Sign`, checkpoints
    /// carry both an Ed25519 and an ML-DSA-65 line.
    pub fn open(
        dir: impl Into<PathBuf>,
        origin: &str,
        key: HybridSigner,
        mmd_s: u64,
    ) -> Result<Log, LogError> {
        if !note::valid_name(origin) {
            return Err(LogError::Note("origin"));
        }
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;
        let mut log = Log {
            dir,
            origin: origin.to_string(),
            key,
            mmd_s,
            levels: vec![Vec::new()],
            bundle: Vec::new(),
            note: Note {
                text: String::new(),
                signatures: Vec::new(),
            },
            witnesses: Vec::new(),
        };
        let path = log.dir.join("checkpoint");
        if path.exists() {
            let note = Note::parse(&std::fs::read_to_string(&path)?)?;
            note.verify_hybrid(&log.origin, &log.public_key(), log.key.ml_dsa_public())?;
            let checkpoint = Checkpoint::parse(&note.text)?;
            if checkpoint.origin != log.origin {
                return Err(LogError::Storage("checkpoint of another log"));
            }
            for (index, width) in tiles_at(checkpoint.size) {
                let bytes = std::fs::read(log.dir.join(entries_path(index, width)))?;
                let entries = decode_bundle(&bytes)?;
                if entries.len() as u64 != width {
                    return Err(LogError::Storage("entry bundle width"));
                }
                for e in &entries {
                    log.push(leaf_hash(e));
                }
                log.bundle = if width < WIDTH { entries } else { Vec::new() };
            }
            if log.root().0 != checkpoint.root {
                return Err(LogError::Storage(
                    "entries do not hash to the checkpoint's root",
                ));
            }
            log.note = note;
        } else {
            log.publish()?;
        }
        Ok(log)
    }

    fn push(&mut self, leaf: Digest) {
        self.levels[0].push(leaf);
        let mut h = 0;
        while self.levels[h].len().is_multiple_of(2) {
            let n = self.levels[h].len();
            let parent = node_hash(&self.levels[h][n - 2], &self.levels[h][n - 1]);
            if self.levels.len() == h + 1 {
                self.levels.push(Vec::new());
            }
            self.levels[h + 1].push(parent);
            h += 1;
        }
    }

    /// The witnesses whose cosignatures the log accepts.
    pub fn set_witnesses(&mut self, witnesses: Vec<(String, [u8; 32])>) {
        self.witnesses = witnesses;
    }

    pub fn size(&self) -> u64 {
        self.levels[0].len() as u64
    }

    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// The Ed25519 half of the log key (what C2SP verifiers check).
    pub fn public_key(&self) -> [u8; 32] {
        self.key.ed25519_public().to_bytes()
    }

    /// The ML-DSA-65 half.
    pub fn ml_dsa_public_key(&self) -> &[u8] {
        self.key.ml_dsa_public()
    }

    fn leaves(&self) -> &[Digest] {
        &self.levels[0]
    }

    /// The root, from the stored complete subtrees (O(log n)): the tree of
    /// n leaves is its complete subtrees of 2^h leaves for each bit h of n,
    /// largest first, combined right to left.
    pub fn root(&self) -> Digest {
        let n = self.size();
        if n == 0 {
            return root_from_leaf_hashes(&[]);
        }
        let mut parts = Vec::new();
        let mut start = 0u64;
        for h in (0..64).rev() {
            if n & (1 << h) != 0 {
                parts.push(self.levels[h][(start >> h) as usize]);
                start += 1 << h;
            }
        }
        let mut root = parts.pop().expect("n > 0");
        while let Some(left) = parts.pop() {
            root = node_hash(&left, &root);
        }
        root
    }

    /// The published checkpoint (a signed note, with any cosignatures).
    pub fn checkpoint(&self) -> String {
        self.note.encode()
    }

    fn publish(&mut self) -> Result<(), LogError> {
        let checkpoint = Checkpoint {
            origin: self.origin.clone(),
            size: self.size(),
            root: self.root().0,
        };
        let signed = note::sign_hybrid(&checkpoint.text(), &self.origin, &self.key)?;
        write_atomic(&self.dir.join("checkpoint"), signed.as_bytes())?;
        self.note = Note::parse(&signed)?;
        Ok(())
    }

    /// Append entries (sequenced at once, so within any MMD), write their
    /// tiles, publish a new checkpoint, and return a receipt for each.
    pub fn append(&mut self, entries: &[Vec<u8>], now_s: u64) -> Result<Vec<Appended>, LogError> {
        let old = self.size();
        self.append_without_receipts(entries)?;
        let log_id = Self::log_id(&self.key);
        Ok(entries
            .iter()
            .enumerate()
            .map(|(i, e)| {
                let leaf = leaf_hash(e);
                Appended {
                    index: old + i as u64,
                    leaf_hash: leaf,
                    receipt: sign_hybrid(
                        &self.key,
                        &LogReceipt {
                            log_id,
                            leaf_hash: leaf,
                            timestamp: now_s,
                            mmd_s: self.mmd_s,
                        },
                    ),
                }
            })
            .collect())
    }

    /// Append without receipts (a hybrid signature per entry is the costly
    /// part): for bulk imports whose writer does not need them. Returns
    /// the new size.
    pub fn append_without_receipts(&mut self, entries: &[Vec<u8>]) -> Result<u64, LogError> {
        if entries.iter().any(|e| e.len() > MAX_ENTRY) {
            return Err(LogError::TooLarge);
        }
        let old = self.size();
        let old_level_sizes: Vec<u64> = self.levels.iter().map(|l| l.len() as u64).collect();
        for e in entries {
            self.push(leaf_hash(e));
        }
        // entry bundles
        let mut index = old / WIDTH;
        let mut pending = std::mem::take(&mut self.bundle);
        for e in entries {
            pending.push(e.clone());
            if pending.len() as u64 == WIDTH {
                write_atomic(
                    &self.dir.join(entries_path(index, WIDTH)),
                    &encode_bundle(&pending),
                )?;
                pending.clear();
                index += 1;
            }
        }
        if !pending.is_empty() {
            write_atomic(
                &self.dir.join(entries_path(index, pending.len() as u64)),
                &encode_bundle(&pending),
            )?;
        }
        self.bundle = pending;
        // hash tiles, level by level, from the first one that changed
        let mut level = 0u8;
        loop {
            let height = level as usize * HEIGHT as usize;
            let Some(hashes) = self.levels.get(height) else {
                break;
            };
            let before = old_level_sizes.get(height).copied().unwrap_or(0);
            let now = hashes.len() as u64;
            if now == 0 {
                break;
            }
            for (tile, width) in tiles_at(now).skip((before / WIDTH) as usize) {
                let start = (tile * WIDTH) as usize;
                let body: Vec<u8> = hashes[start..start + width as usize]
                    .iter()
                    .flat_map(|d| d.0)
                    .collect();
                write_atomic(&self.dir.join(tile_path(level, tile, width)), &body)?;
            }
            level += 1;
        }
        self.publish()?;
        Ok(self.size())
    }

    /// Audit path for `index` in the tree of `size` leaves.
    pub fn inclusion_proof(&self, index: u64, size: u64) -> Result<Vec<Digest>, LogError> {
        if size > self.size() || index >= size {
            return Err(LogError::Range);
        }
        inclusion_proof(&self.leaves()[..size as usize], index as usize).ok_or(LogError::Range)
    }

    /// Consistency proof from the tree of `old` leaves to that of `new`.
    pub fn consistency_proof(&self, old: u64, new: u64) -> Result<Vec<Digest>, LogError> {
        if new > self.size() || old > new {
            return Err(LogError::Range);
        }
        if old == 0 || old == new {
            return Ok(Vec::new());
        }
        consistency_proof(&self.leaves()[..new as usize], old as usize).ok_or(LogError::Range)
    }

    /// Add a witness's cosignature line for the current checkpoint (the one
    /// it cosigned must still be current); replaces an older one by the
    /// same witness.
    pub fn add_cosignature(&mut self, text: &str, line: &str) -> Result<(), LogError> {
        if text != self.note.text {
            return Err(LogError::Stale);
        }
        let parsed = Note::parse(&format!("{text}\n{line}"))?;
        let [(name, sig)] = parsed.signatures.as_slice() else {
            return Err(LogError::Note("one cosignature line"));
        };
        let key = self
            .witnesses
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, k)| *k)
            .ok_or(LogError::Note("not a witness of this log"))?;
        parsed.verify_cosignature(name, &key)?;
        self.note.signatures.retain(|(n, _)| n != name);
        self.note.signatures.push((name.clone(), sig.clone()));
        write_atomic(&self.dir.join("checkpoint"), self.note.encode().as_bytes())?;
        Ok(())
    }
}
