//! A development cell on this machine: Server Liveness, the Verifier and
//! the Broker as three processes, each with its own key in `cell/<service>/`,
//! its own public certificate in `keys/`, and the Broker calling Server
//! Liveness over the cell's mutual TLS.

use anyhow::{bail, Context, Result};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

pub const CELL_DIR: &str = "cell";
/// The services a dev cell runs, in start order (the Broker reads the
/// Verifier's key and calls Server Liveness).
pub const SERVICES: [&str; 3] = ["liveness", "verifier", "broker"];

#[cfg(target_os = "windows")]
const BIN_EXT: &str = ".exe";
#[cfg(not(target_os = "windows"))]
const BIN_EXT: &str = "";

/// `target/<profile>/<bin>` in this workspace.
pub fn bin_path(bin: &str, profile: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .join("target")
        .join(profile)
        .join(format!("{bin}{BIN_EXT}"))
}

/// The dev PKI in `keys/` (public certificates for each service and the GS)
/// and the cell's CA and service identities in `cell/`, if missing.
pub fn ensure_dev_keys() -> Result<()> {
    if common::pki::ensure_dev_pki("keys").context("dev PKI")? {
        println!("[cell] generated dev PKI under keys/");
    }
    let cell = Path::new(CELL_DIR);
    if !cell.join("ca.der").exists() {
        fpp_svc::cell::init(cell, &SERVICES)?;
        println!("[cell] initialized {CELL_DIR}/ for {}", SERVICES.join(", "));
    }
    for s in SERVICES {
        if !cell.join(s).join("tls.der").exists() {
            bail!("{CELL_DIR}/ has no identity for {s}: remove {CELL_DIR}/ to make a new cell");
        }
    }
    Ok(())
}

/// How to start the services.
pub struct Launch {
    /// Directory of the `svc-*` binaries.
    pub bin_dir: PathBuf,
    /// Run each through this command (e.g. `qemu-aarch64-static`).
    pub wrapper: Option<OsString>,
    /// Wait this long after starting each service.
    pub startup: Duration,
}

impl Launch {
    /// From `SMOKE_BIN_DIR`, `SMOKE_WRAPPER` and `SMOKE_STARTUP_MS`
    /// (defaults: this build's `target/<profile>`, none, 200 ms).
    pub fn from_env(profile: &str) -> Self {
        Self {
            bin_dir: std::env::var_os("SMOKE_BIN_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| {
                    bin_path("svc-liveness", profile)
                        .parent()
                        .expect("dir")
                        .to_path_buf()
                }),
            wrapper: std::env::var_os("SMOKE_WRAPPER"),
            startup: Duration::from_millis(
                std::env::var("SMOKE_STARTUP_MS")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(200),
            ),
        }
    }
}

/// A running cell; its services are stopped when it is dropped.
pub struct Cell {
    children: Vec<(String, Child)>,
}

impl Cell {
    /// Start the services and write the key bundle they published to
    /// `keys/fpp_key_bundle.json`.
    pub fn start(launch: &Launch) -> Result<Self> {
        let mut cell = Cell {
            children: Vec::new(),
        };
        for s in SERVICES {
            let bin = launch.bin_dir.join(format!("svc-{s}{BIN_EXT}"));
            let mut cmd = match &launch.wrapper {
                Some(w) => {
                    let mut c = Command::new(w);
                    c.arg(&bin);
                    c
                }
                None => Command::new(&bin),
            };
            let child = cmd
                .args(["--cell", CELL_DIR])
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .spawn()
                .with_context(|| format!("spawn {}", bin.display()))?;
            cell.children.push((s.to_string(), child));
            std::thread::sleep(launch.startup);
        }
        // Each publishes its public key on start (the same key every start:
        // the seed stays in its directory).
        let deadline = Instant::now() + Duration::from_secs(30);
        let bundle = loop {
            cell.check_running()?;
            match fpp_svc::keys::bundle(Path::new(CELL_DIR)) {
                Ok(b) => break b,
                Err(e) if Instant::now() > deadline => return Err(e),
                Err(_) => std::thread::sleep(Duration::from_millis(100)),
            }
        };
        bundle.save(common::keys::DEFAULT_BUNDLE)?;
        println!("[cell] key bundle at {}", common::keys::DEFAULT_BUNDLE);
        Ok(cell)
    }

    /// Fail if a service (not stopped with [`Cell::stop`]) has exited.
    pub fn check_running(&mut self) -> Result<()> {
        for (name, child) in &mut self.children {
            if let Some(status) = child.try_wait()? {
                bail!("svc-{name} exited ({status})");
            }
        }
        Ok(())
    }

    /// Stop one service (to test the others without it).
    pub fn stop(&mut self, service: &str) {
        if let Some(i) = self.children.iter().position(|(n, _)| n == service) {
            let (_, mut child) = self.children.remove(i);
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Drop for Cell {
    fn drop(&mut self) {
        for (_, child) in self.children.iter_mut().rev() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
