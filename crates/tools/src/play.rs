// Launch a dev cell (Server Liveness, Verifier, Broker) and a GS (no
// --test-once), give the GS time to join, then run the Bevy client.
// Cleans up children on Bevy exit or Ctrl-C.

use anyhow::{Context, Result};
use std::{
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};
use tools::cell::{bin_path, ensure_dev_keys, Cell, Launch};

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

    // 1) Keys, and the cell
    ensure_dev_keys()?;
    let cell = Cell::start(&Launch::from_env(&profile))?;

    // 2) GS (no --test-once so it runs indefinitely)
    let gs_sim_bin = bin_path("gs-sim", &profile);
    let mut gs_child = Command::new(&gs_sim_bin)
        .args(["--liveness", "127.0.0.1:4444"])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("spawn {:?}", gs_sim_bin))?;

    // The game port is UDP (fpp-session): give the GS time to join Server
    // Liveness and sign its first Checkpoint before the client asks the Broker.
    thread::sleep(Duration::from_millis(2500));
    if let Ok(Some(status)) = gs_child.try_wait() {
        eprintln!("[PLAY] gs-sim exited early ({status})");
        drop(cell);
        std::process::exit(1);
    }

    // 3) Resolve Bevy client launch plan
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

    // 4) Wait for Bevy to exit OR Ctrl-C, then tear down servers
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

    // Tear down the GS and the cell
    let _ = gs_child.kill();
    let _ = gs_child.wait();
    drop(cell);

    Ok(())
}
