//! Content-addressed Evidence Store (03 §3, P2.3): stores verified Checkpoints
//! under SHA-256 of their bytes, indexed by `match_id`, and re-hashes every
//! object on every read so disk corruption is refused rather than served.

use anyhow::{bail, Context, Result};
use fpp::control::{EvidenceStoreRequest, EvidenceStoreResponse};
use fpp::crypto::sha256;
use std::io::Write;
use std::path::{Path, PathBuf};
use tokio::sync::Mutex;

pub const MAX_OBJECT: usize = 4 * 1024 * 1024;

pub struct EvidenceStore {
    root: PathBuf,
    write_lock: Mutex<()>,
}

impl EvidenceStore {
    pub fn open(root: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(root.join("objects"))
            .with_context(|| format!("create {}", root.display()))?;
        std::fs::create_dir_all(root.join("matches"))?;
        Ok(Self {
            root,
            write_lock: Mutex::new(()),
        })
    }

    fn object_path(&self, digest: &[u8; 32]) -> PathBuf {
        let h = hex::encode(digest);
        self.root.join("objects").join(&h[..2]).join(h)
    }

    fn match_path(&self, match_id: &[u8; 16]) -> PathBuf {
        self.root.join("matches").join(hex::encode(match_id))
    }

    /// Store `object` under its SHA-256 digest and index it under `match_id`.
    pub async fn put(&self, match_id: [u8; 16], object: &[u8]) -> Result<[u8; 32]> {
        if object.is_empty() || object.len() > MAX_OBJECT {
            bail!("object size out of range");
        }
        let digest = sha256(object);
        let _guard = self.write_lock.lock().await;
        let path = self.object_path(&digest);
        if !path.exists() {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let tmp = path.with_extension("tmp");
            std::fs::write(&tmp, object)?;
            std::fs::rename(&tmp, &path)?;
        }
        let mpath = self.match_path(&match_id);
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&mpath)?;
        writeln!(f, "{}", hex::encode(digest))?;
        f.sync_data()?;
        Ok(digest)
    }

    /// Read an object and verify its SHA-256 matches `digest` before returning.
    pub fn get(&self, digest: &[u8; 32]) -> Result<Option<Vec<u8>>> {
        let path = self.object_path(digest);
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        if &sha256(&bytes) != digest {
            bail!("corrupt evidence object {}", hex::encode(digest));
        }
        Ok(Some(bytes))
    }

    /// Digests stored under `match_id`, in storage order.
    pub fn list(&self, match_id: &[u8; 16]) -> Result<Vec<[u8; 32]>> {
        let path = self.match_path(match_id);
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let mut out = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let raw = hex::decode(line)?;
            let d: [u8; 32] = raw
                .try_into()
                .map_err(|_| anyhow::anyhow!("corrupt digest line in {}", path.display()))?;
            out.push(d);
        }
        Ok(out)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub async fn handle_rpc(
        &self,
        req: EvidenceStoreRequest,
        can_write: bool,
        can_read: bool,
    ) -> EvidenceStoreResponse {
        match req {
            EvidenceStoreRequest::Put { match_id, object } => {
                if !can_write {
                    return EvidenceStoreResponse::Refused("caller may not write evidence".into());
                }
                match self.put(match_id, &object).await {
                    Ok(d) => EvidenceStoreResponse::Stored(d),
                    Err(e) => EvidenceStoreResponse::Refused(e.to_string()),
                }
            }
            EvidenceStoreRequest::Get(digest) => {
                if !can_read {
                    return EvidenceStoreResponse::Refused("caller may not read evidence".into());
                }
                match self.get(&digest) {
                    Ok(obj) => EvidenceStoreResponse::Object(obj),
                    Err(e) => EvidenceStoreResponse::Refused(e.to_string()),
                }
            }
            EvidenceStoreRequest::List(match_id) => {
                if !can_read {
                    return EvidenceStoreResponse::Refused("caller may not list evidence".into());
                }
                match self.list(&match_id) {
                    Ok(ds) => EvidenceStoreResponse::Digests(ds),
                    Err(e) => EvidenceStoreResponse::Refused(e.to_string()),
                }
            }
        }
    }
}
