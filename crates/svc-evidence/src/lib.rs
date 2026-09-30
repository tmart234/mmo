//! The Evidence Store (03 §3), a service of the cell: evidence objects
//! (today: the signed Checkpoints Server Liveness verified) stored under
//! the SHA-256 of their bytes, and indexed by match.
//!
//! Content addressing makes the store unable to substitute evidence: a
//! reader asks for a digest (from a Checkpoint chain, a player's bundle or
//! the Transparency Log) and checks what comes back. The store re-checks
//! every object against its name on every read, so a corrupted disk is
//! reported, not served. Only configured writers store; only configured
//! readers read.
//!
//! On disk: `objects/<2 hex>/<64 hex>` (written whole, then renamed) and
//! `matches/<32 hex>` (the match's digests, 32 bytes each, in order).
//!
//! [`Client`] is how other services and tools call it.

use anyhow::{anyhow, bail, Context, Result};
use fpp_svc::api::evidence::{Request, Response};
use fpp_svc::Caller;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

/// Largest object stored.
pub const MAX_OBJECT: usize = 4 * 1024 * 1024;

pub struct Store {
    dir: PathBuf,
    /// Serializes index appends.
    index: std::sync::Mutex<()>,
}

pub fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

impl Store {
    pub fn open(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir.join("objects"))?;
        std::fs::create_dir_all(dir.join("matches"))?;
        Ok(Self {
            dir: dir.to_path_buf(),
            index: std::sync::Mutex::new(()),
        })
    }

    fn object_path(&self, d: &[u8; 32]) -> PathBuf {
        let h = hex::encode(d);
        self.dir.join("objects").join(&h[..2]).join(h)
    }

    fn match_path(&self, m: &[u8; 16]) -> PathBuf {
        self.dir.join("matches").join(hex::encode(m))
    }

    /// Store `object` and list it under `match_id` (once). Its digest.
    pub fn put(&self, match_id: &[u8; 16], object: &[u8]) -> Result<[u8; 32]> {
        if object.is_empty() || object.len() > MAX_OBJECT {
            bail!("object size {} out of range", object.len());
        }
        let d = digest(object);
        let path = self.object_path(&d);
        if !path.exists() {
            let parent = path.parent().expect("object dir");
            std::fs::create_dir_all(parent)?;
            let tmp = parent.join(format!("{}.tmp", hex::encode(d)));
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(object)?;
            f.sync_all()?;
            std::fs::rename(&tmp, &path)?;
        }
        let _guard = self.index.lock().expect("index lock");
        if !self.list(match_id)?.contains(&d) {
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(self.match_path(match_id))?;
            f.write_all(&d)?;
            f.sync_data()?;
        }
        Ok(d)
    }

    /// The object named `d`, checked against its name.
    pub fn get(&self, d: &[u8; 32]) -> Result<Option<Vec<u8>>> {
        let bytes = match std::fs::read(self.object_path(d)) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        if digest(&bytes) != *d {
            bail!("object {} is corrupt on disk", hex::encode(d));
        }
        Ok(Some(bytes))
    }

    /// Digests listed under `match_id`, in the order stored.
    pub fn list(&self, match_id: &[u8; 16]) -> Result<Vec<[u8; 32]>> {
        let bytes = match std::fs::read(self.match_path(match_id)) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        // (a torn last entry, from a crash while appending, is ignored)
        Ok(bytes.as_chunks::<32>().0.to_vec())
    }
}

pub struct Access {
    pub writers: Vec<String>,
    pub readers: Vec<String>,
}

fn handle(store: &Store, access: &Access, caller: &Caller, request: Request) -> Response {
    let refused = |e: anyhow::Error| Response::Refused(format!("{e:#}"));
    match request {
        Request::Put { match_id, object } => {
            if !caller.is(&access.writers) {
                return Response::Refused(format!("{} may not store evidence", caller.0));
            }
            store
                .put(&match_id, &object)
                .map_or_else(refused, Response::Stored)
        }
        Request::Get(d) => {
            if !caller.is(&access.readers) {
                return Response::Refused(format!("{} may not read evidence", caller.0));
            }
            store.get(&d).map_or_else(refused, Response::Object)
        }
        Request::List(m) => {
            if !caller.is(&access.readers) {
                return Response::Refused(format!("{} may not read evidence", caller.0));
            }
            store.list(&m).map_or_else(refused, Response::Digests)
        }
    }
}

/// Serve `store` on `endpoint` (mutual TLS) until it closes.
pub async fn serve(endpoint: fpp_svc::quinn::Endpoint, store: Store, access: Access) {
    let (store, access) = (Arc::new(store), Arc::new(access));
    fpp_svc::serve(endpoint, move |caller: Caller, request: Request| {
        let (store, access) = (store.clone(), access.clone());
        async move {
            tokio::task::spawn_blocking(move || handle(&store, &access, &caller, request))
                .await
                .unwrap_or_else(|e| Response::Refused(format!("{e}")))
        }
    })
    .await
}

/// A connection to the store, as one cell service.
pub struct Client {
    endpoint: fpp_svc::quinn::Endpoint,
    addr: SocketAddr,
    conn: Mutex<Option<fpp_svc::quinn::Connection>>,
}

impl Client {
    pub fn new(identity: &fpp_svc::Identity, addr: SocketAddr) -> Result<Self> {
        Ok(Self {
            endpoint: fpp_svc::mtls::client_endpoint(identity)?,
            addr,
            conn: Mutex::new(None),
        })
    }

    pub async fn call(&self, request: &Request) -> Result<Response> {
        let mut guard = self.conn.lock().await;
        let conn = match guard.as_ref().filter(|c| c.close_reason().is_none()) {
            Some(c) => c.clone(),
            None => {
                let c = tokio::time::timeout(
                    Duration::from_secs(5),
                    fpp_svc::mtls::connect(&self.endpoint, self.addr, "evidence"),
                )
                .await
                .map_err(|_| anyhow!("Evidence Store unreachable"))??;
                *guard = Some(c.clone());
                c
            }
        };
        let answer = tokio::time::timeout(Duration::from_secs(15), fpp_svc::call(&conn, request))
            .await
            .map_err(|_| anyhow!("Evidence Store timed out"))
            .and_then(|r| r);
        if answer.is_err() {
            *guard = None;
        }
        answer
    }

    pub async fn put(&self, match_id: [u8; 16], object: Vec<u8>) -> Result<[u8; 32]> {
        let want = digest(&object);
        match self.call(&Request::Put { match_id, object }).await? {
            Response::Stored(d) if d == want => Ok(d),
            other => Err(anyhow!("store: {other:?}")),
        }
    }

    /// The object named `d`, checked here too.
    pub async fn get(&self, d: [u8; 32]) -> Result<Option<Vec<u8>>> {
        match self.call(&Request::Get(d)).await? {
            Response::Object(Some(b)) if digest(&b) == d => Ok(Some(b)),
            Response::Object(Some(_)) => Err(anyhow!("the store returned other bytes")),
            Response::Object(None) => Ok(None),
            other => Err(anyhow!("get: {other:?}")),
        }
    }

    pub async fn list(&self, match_id: [u8; 16]) -> Result<Vec<[u8; 32]>> {
        match self.call(&Request::List(match_id)).await? {
            Response::Digests(d) => Ok(d),
            other => Err(anyhow!("list: {other:?}")).context("Evidence Store"),
        }
    }
}
