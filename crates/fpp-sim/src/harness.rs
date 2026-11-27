//! Subprocess harness for spawning the real `fppd` binary (all-in-one or with
//! a separate `fppd role witness` process) in exit tests.

use anyhow::{anyhow, bail, Context, Result};
use fpp::bundle::KeyBundle;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

/// Locate the `fppd` binary (honouring `SMOKE_BIN_DIR` if set, otherwise next
/// to the currently running test binary).
pub fn fppd_bin() -> Result<PathBuf> {
    let exe_name = format!("fppd{}", std::env::consts::EXE_SUFFIX);
    if let Ok(dir) = std::env::var("SMOKE_BIN_DIR") {
        return Ok(PathBuf::from(dir).join(exe_name));
    }
    let me = std::env::current_exe().context("current_exe")?;
    let dir = me.parent().context("exe parent")?;
    let candidate = dir.join(&exe_name);
    if candidate.exists() {
        return Ok(candidate);
    }
    // `cargo test` puts integration tests in `target/debug/deps/`.
    if let Some(parent) = dir.parent() {
        let up = parent.join(&exe_name);
        if up.exists() {
            return Ok(up);
        }
    }
    bail!(
        "fppd binary not found near {}; build it first with `cargo build -p fppd`",
        me.display()
    )
}

fn spawn_wrapped(bin: &Path, args: &[String]) -> Result<Child> {
    if let Ok(wrapper) = std::env::var("SMOKE_WRAPPER") {
        let mut parts = wrapper.split_whitespace();
        let prog = parts.next().context("empty SMOKE_WRAPPER")?;
        let mut cmd = Command::new(prog);
        cmd.args(parts);
        cmd.arg(bin);
        cmd.args(args);
        return cmd
            .spawn()
            .with_context(|| format!("spawn {wrapper} {}", bin.display()));
    }
    Command::new(bin)
        .args(args)
        .spawn()
        .with_context(|| format!("spawn {}", bin.display()))
}

pub fn pick_free_port() -> Result<SocketAddr> {
    let l = TcpListener::bind("127.0.0.1:0")?;
    Ok(l.local_addr()?)
}

pub struct TestCell {
    pub dir: PathBuf,
    pub bundle_path: PathBuf,
    pub bundle: KeyBundle,
    pub addr: SocketAddr,
    children: Vec<Child>,
}

impl TestCell {
    /// Start `fppd serve` in a fresh temporary directory, optionally with a
    /// standalone external `fppd role witness` process.
    pub fn start(name: &str, external_witness: bool, extra_serve_args: &[String]) -> Result<Self> {
        let fppd = fppd_bin()?;
        let dir = std::env::temp_dir().join(format!(
            "fpp-cell-{name}-{}-{}",
            std::process::id(),
            fpp::crypto::now_ms()
        ));
        std::fs::create_dir_all(&dir)?;
        let cell_dir = dir.join("cell");
        let bundle_path = dir.join("fpp_key_bundle.json");
        let addr = pick_free_port()?;

        let mut serve_args = vec![
            "serve".to_string(),
            "--dir".to_string(),
            cell_dir.display().to_string(),
            "--bundle".to_string(),
            bundle_path.display().to_string(),
            "--bind".to_string(),
            addr.to_string(),
        ];
        if external_witness {
            serve_args.push("--no-witness".to_string());
        }
        serve_args.extend(extra_serve_args.iter().cloned());

        let mut children = Vec::new();
        children.push(spawn_wrapped(&fppd, &serve_args)?);

        let startup_ms: u64 = std::env::var("SMOKE_STARTUP_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(10_000);
        let deadline = Instant::now() + Duration::from_millis(startup_ms);
        let bundle = loop {
            if let Some(status) = children[0].try_wait()? {
                bail!("fppd serve exited early: {status}");
            }
            if bundle_path.exists()
                && TcpStream::connect_timeout(&addr, Duration::from_millis(100)).is_ok()
            {
                if let Ok(b) = KeyBundle::load(&bundle_path) {
                    break b;
                }
            }
            if Instant::now() >= deadline {
                bail!("fppd serve did not become ready on {addr} within {startup_ms}ms");
            }
            std::thread::sleep(Duration::from_millis(50));
        };

        if external_witness {
            let witness_args = vec![
                "role".to_string(),
                "witness".to_string(),
                "--dir".to_string(),
                cell_dir.display().to_string(),
                "--log".to_string(),
                addr.to_string(),
                "--bundle".to_string(),
                bundle_path.display().to_string(),
                "--interval-s".to_string(),
                "1".to_string(),
            ];
            children.push(spawn_wrapped(&fppd, &witness_args)?);
        }

        Ok(Self {
            dir,
            bundle_path,
            bundle,
            addr,
            children,
        })
    }

    pub fn cell_dir(&self) -> PathBuf {
        self.dir.join("cell")
    }

    pub fn admin_key(&self) -> Result<fpp::session::StaticKeypair> {
        fppd::keys::load_noise(&self.cell_dir(), "admin")
            .map_err(|e| anyhow!("load admin noise key: {e}"))
    }

    pub fn enforcement_signer(&self) -> Result<fpp::crypto::Ed25519Signer> {
        let sk = fppd::keys::load_ed25519(&self.cell_dir(), "enforcement")?;
        Ok(fpp::crypto::Ed25519Signer::new(sk))
    }
}

impl Drop for TestCell {
    fn drop(&mut self) {
        for c in &mut self.children {
            let _ = c.kill();
            let _ = c.wait();
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
