// CI-lite / `make ci` smoke test of the whole FPP prototype, with the trust
// plane as a cell of separate services (tools::cell; the Transparency Log
// and Revocation Feed run too, and `revocation_load` tests them):
//
// - Server Liveness: GS admission (challenge + JoinRequest), SAR chain,
//   Checkpoint verification, placement for the Broker (cell mutual TLS)
// - Verifier: the client's session key and evidence -> AR
// - Broker: AR + queue -> SAT for a slot on a live GS
// - GS: fpp-session game port, §7.2 admission, InputFrames, InputCommits,
//   signed Checkpoints, CheckpointHeads, SarUpdates
// - client: admission, join, play, SAR chain, tier floor of the `verified` queue
//
// 1. Ensure dev keys. 2. Start the cell and gather its key bundle.
// 3. Spawn gs-sim --test-once. 4. Run a client that must be refused the
//    `verified` queue, then client-sim --smoke-test. 5. Wait for gs-sim.
// 6. Failure domains: with Server Liveness stopped, the Verifier and Broker
//    still answer, and the Broker refuses (no live server) instead of
//    failing. Any failure fails the run (LENIENT_SMOKE=1 only warns).
//    Admission with a real TPM 2.0 is tested end to end against swtpm in
//    svc-liveness/src/tpm2.rs.
//
// SMOKE_BIN_DIR runs other builds of the services, SMOKE_WRAPPER runs them
// through a command (`make pi-cell-smoke`: the aarch64 services for a
// Raspberry Pi under qemu-aarch64-static), and SMOKE_STARTUP_MS waits
// longer for each.

use anyhow::{Context, Result};
use std::time::SystemTime;
use std::{fs, path::PathBuf, process::Command, time::Duration};
use tools::cell::{bin_path, ensure_dev_keys, Cell, Launch};

fn newest_ledger_file(dir: &str) -> anyhow::Result<PathBuf> {
    let mut newest: Option<(SystemTime, PathBuf)> = None;
    for ent in fs::read_dir(dir).context("read ledger dir")? {
        let ent = ent?;
        let p = ent.path();
        if p.extension().and_then(|e| e.to_str()) != Some("log") {
            continue;
        }
        let meta = ent.metadata().context("stat ledger entry")?;
        let mtime = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        if newest.as_ref().map(|(t, _)| mtime > *t).unwrap_or(true) {
            newest = Some((mtime, p));
        }
    }
    newest
        .map(|(_, p)| p)
        .context("no ledger/*.log files found")
}

fn assert_recent_ledger_has_move() -> anyhow::Result<()> {
    let path = newest_ledger_file("ledger")?;
    let meta = fs::metadata(&path).with_context(|| format!("stat {}", path.display()))?;
    anyhow::ensure!(meta.len() > 0, "ledger file is empty: {}", path.display());

    let mtime = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
    let age = match SystemTime::now().duration_since(mtime) {
        Ok(d) => d,
        Err(_) => Duration::from_secs(0),
    };
    anyhow::ensure!(
        age < Duration::from_secs(60),
        "newest ledger is too old: {}",
        path.display()
    );

    let body = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let last = body
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .context("ledger has no lines")?;
    anyhow::ensure!(
        last.starts_with('{') && last.ends_with('}'),
        "last ledger line not JSON-ish"
    );
    anyhow::ensure!(
        last.contains("\"op\":\"Move\""),
        "last ledger line missing op=Move"
    );

    println!(
        "[SMOKE] ledger OK: {} (last line has op=Move)",
        path.display()
    );
    Ok(())
}

/// Run the smoke pass: (clients ok, gs ok, failure domains ok).
fn run_smoke_pass() -> Result<(bool, bool, bool)> {
    println!("\n[SMOKE] ========== Starting smoke pass ==========");

    // 1. The cell: Server Liveness, Verifier, Broker; then the key bundle.
    let mut cell = Cell::start(&Launch::from_env("debug"))?;

    // 2. GS
    let gs_bin = bin_path("gs-sim", "debug");
    let mut gs_child = Command::new(&gs_bin)
        .args([
            "--liveness",
            "127.0.0.1:4444",
            "--test-once",
            "--test-secs",
            "12",
        ])
        .spawn()
        .with_context(|| format!("spawn {:?}", gs_bin))?;

    // Clients retry until the GS has joined and signed its first Checkpoint.
    std::thread::sleep(Duration::from_millis(500));

    // 3. Clients: one that must be refused the `verified` queue (tier floor
    //    D2; this device has no evidence), then the smoke client.
    let client_bin = bin_path("client-sim", "debug");
    let client = |args: &[&str]| {
        Command::new(&client_bin)
            .args(args)
            .status()
            .with_context(|| format!("run {:?}", client_bin))
    };
    let refused = client(&["--queue", "verified", "--expect-refused"])?;
    let played = client(&["--smoke-test"])?;
    let client_ok = played.success() && refused.success();
    println!(
        "[SMOKE] clients: smoke {:?}, verified-queue refusal {:?}",
        played.code(),
        refused.code()
    );

    // 4. GS
    let gs_status = gs_child.wait().context("wait gs-sim")?;
    println!("[SMOKE] gs-sim: {:?}", gs_status.code());

    // 5. Failure domains: Server Liveness down, the rest still serving.
    cell.stop("liveness");
    let without_liveness = client(&["--expect-refused"])?;
    let domains_ok = without_liveness.success() && cell.check_running().is_ok();
    println!(
        "[SMOKE] with Server Liveness stopped: Verifier and Broker {}",
        if domains_ok {
            "still answer (refused: no live server)"
        } else {
            "FAILED"
        }
    );
    drop(cell);

    Ok((client_ok, gs_status.success(), domains_ok))
}

fn main() -> Result<()> {
    ensure_dev_keys()?;
    let (client_ok, gs_ok, domains_ok) = run_smoke_pass()?;

    let strict = std::env::var("LENIENT_SMOKE").is_err();
    if let Err(e) = assert_recent_ledger_has_move() {
        if strict {
            anyhow::bail!("ledger check failed: {e:#}");
        }
        eprintln!("[SMOKE] ledger check warning: {e:#}");
    }

    let ok = |b: bool| if b { "OK" } else { "FAIL" };
    println!("\n[SMOKE] ========== Summary ==========");
    println!(
        "[SMOKE] client={}, gs={}, failure-domains={}",
        ok(client_ok),
        ok(gs_ok),
        ok(domains_ok)
    );
    if strict && !(client_ok && gs_ok && domains_ok) {
        std::process::exit(1);
    }
    println!("[SMOKE] done.");
    Ok(())
}
