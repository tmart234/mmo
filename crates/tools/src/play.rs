// crates/tools/src/bin/play.rs
// Launch VS + GS (no --test-once), wait for GS TCP port, then run the Bevy client.
// Cleans up children on Bevy exit or Ctrl-C.

use anyhow::{Context, Result};
use ctrlc;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::{
    fs,
    net::TcpStream,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};

#[cfg(target_os = "windows")]
const BIN_EXT: &str = ".exe";
#[cfg(not(target_os = "windows"))]
const BIN_EXT: &str = "";

// Resolve path to target/{debug|release}/{bin}
fn bin_path(bin: &str, profile: &str) -> PathBuf {
    let tools_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = tools_dir
        .parent() // crates/
        .and_then(|p| p.parent()) // workspace root
        .expect("could not locate workspace root");

    workspace_root
        .join("target")
        .join(profile)
        .join(format!("{bin}{BIN_EXT}"))
}

// Ensure VS has signing keys so GS/clients can pin VS.
fn ensure_vs_keys() -> Result<()> {
    let skp = PathBuf::from("keys/vs_ed25519.pk8");
    let pkp = PathBuf::from("keys/vs_ed25519.pub");
    if skp.exists() && pkp.exists() {
        return Ok(());
    }
    fs::create_dir_all("keys").context("mkdir keys")?;
    let sk = SigningKey::generate(&mut OsRng);
    let pk = sk.verifying_key();
    fs::write(&skp, sk.to_bytes()).context("write vs_sk")?;
    fs::write(&pkp, pk.to_bytes()).context("write vs_pk")?;
    println!(
        "[PLAY] generated VS dev keys: {}, {}",
        skp.display(),
        pkp.display()
    );
    Ok(())
}

// Poll a TCP addr until it accepts or timeout.
fn wait_for_tcp(addr: &str, timeout_ms: u64) -> bool {
    let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);
    while std::time::Instant::now() < deadline {
        if TcpStream::connect(addr).is_ok() {
            return true;
        }
        thread::sleep(Duration::from_millis(50));
    }
    false
}

fn main() -> Result<()> {
    // Profile selector for child binaries (debug by default).
    // Use: PLAY_PROFILE=release make play-release
    let profile = std::env::var("PLAY_PROFILE").unwrap_or_else(|_| "debug".into());

    // Ctrl-C cancel flag
    let cancelled = Arc::new(AtomicBool::new(false));
    {
        let cancelled = cancelled.clone();
        ctrlc::set_handler(move || {
            cancelled.store(true, Ordering::SeqCst);
            eprintln!("\n[PLAY] Ctrl-C received — tearing down children…");
        })
        .context("install ctrl-c handler")?;
    }

    // 1) Keys for VS
    ensure_vs_keys()?;

    // 2) Paths to child binaries
    let vs_bin = bin_path("vs", &profile);
    let gs_sim_bin = bin_path("gs-sim", &profile);

    // 3) Spawn VS (QUIC on 127.0.0.1:4444)
    let mut vs_child = Command::new(&vs_bin)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("spawn {:?}", vs_bin))?;

    // Give VS a moment to bind
    thread::sleep(Duration::from_millis(200));

    // 4) Spawn GS (no --test-once so it runs indefinitely)
    let mut gs_child = Command::new(&gs_sim_bin)
        .arg("--vs")
        .arg("127.0.0.1:4444")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("spawn {:?}", gs_sim_bin))?;

    // Wait for GS client TCP port
    if !wait_for_tcp("127.0.0.1:50000", 8000) {
        eprintln!("[PLAY] timeout waiting for gs-sim client port at 127.0.0.1:50000");
        let _ = gs_child.kill();
        let _ = gs_child.wait();
        let _ = vs_child.kill();
        let _ = vs_child.wait();
        std::process::exit(1);
    }
    thread::sleep(Duration::from_millis(600));

    // 5) Resolve Bevy client launch plan
    let bevy_bin_candidates = [
        bin_path("client-bevy", &profile),
        bin_path("sanity3d", &profile),
    ];
    let bevy_path = bevy_bin_candidates.iter().find(|p| p.exists()).cloned();

    let mut bevy_child = if let Some(path) = bevy_path {
        println!("[PLAY] launching Bevy client: {}", path.display());
        Command::new(&path)
            .env("RUST_LOG", "client=info,bevy_winit=info,bevy_render=info")
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .with_context(|| format!("run {:?}", path))?
    } else {
        println!("[PLAY] Bevy binary not found at:");
        for p in &bevy_bin_candidates {
            println!("        - {}", p.display());
        }
        println!("[PLAY] falling back to: cargo run -p client-bevy");
        Command::new("cargo")
            .arg("run")
            .arg("-p")
            .arg("client-bevy")
            .env("RUST_LOG", "client=info,bevy_winit=info,bevy_render=info")
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .context("cargo run -p client-bevy")?
    };

    // 6) Wait for Bevy to exit OR Ctrl-C, then tear down servers
    //    Poll so Ctrl-C can interrupt while Bevy runs.
    loop {
        if cancelled.load(Ordering::SeqCst) {
            let _ = bevy_child.kill();
            break;
        }
        match bevy_child.try_wait() {
            Ok(Some(status)) => {
                // child exited
                if !status.success() {
                    eprintln!("[PLAY] Bevy exited with: {status:?}");
                }
                break;
            }
            Ok(None) => {
                thread::sleep(Duration::from_millis(100));
            }
            Err(e) => {
                eprintln!("[PLAY] error waiting for Bevy: {e:#}");
                break;
            }
        }
    }

    // Tear down VS/GS
    let _ = gs_child.kill();
    let _ = gs_child.wait();
    let _ = vs_child.kill();
    let _ = vs_child.wait();

    Ok(())
}
