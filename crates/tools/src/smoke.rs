// crates/tools/src/smoke.rs
//
// CI-lite / `make ci` smoke test of the whole FPP prototype:
//
// - VS: GS admission (challenge + JoinRequest), SAR chain, Checkpoint
//   verification, stub Verifier (AR) and Broker (SAT) for clients
// - GS: fpp-session game port, §7.2 admission, InputFrames, InputCommits,
//   signed Checkpoints, CheckpointHeads, SarUpdates
// - client: admission, join, play, SAR chain, tier floor of the `verified` queue
// - TPM: join quote bound to the VS challenge, re-attestation seeded by a SAR
//
// 1. Ensure dev keys exist. 2. Spawn VS. 3. Spawn gs-sim --test-once.
// 4. Run a client that must be refused the `verified` queue, then
//    client-sim --smoke-test. 5. Wait for gs-sim, kill VS. 6. Repeat with
//    the simulated TPM. Any failure fails the run (LENIENT_SMOKE=1 only warns).
//
// SMOKE_VS_BIN runs another VS binary, SMOKE_VS_WRAPPER runs it through a
// command (`make pi-vs-smoke`: the aarch64 VS for a Raspberry Pi under
// qemu-aarch64-static), and SMOKE_VS_STARTUP_MS waits longer for it.

use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::time::SystemTime;
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::Duration,
};

#[cfg(target_os = "windows")]
const BIN_EXT: &str = ".exe";
#[cfg(not(target_os = "windows"))]
const BIN_EXT: &str = "";

fn bin_path(bin: &str) -> PathBuf {
    let tools_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = tools_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("could not locate workspace root");

    workspace_root
        .join("target")
        .join("debug")
        .join(format!("{bin}{BIN_EXT}"))
}

fn ensure_vs_keys() -> Result<()> {
    let skp = PathBuf::from("keys/vs_ed25519.pk8");
    let pkp = PathBuf::from("keys/vs_ed25519.pub");

    if common::pki::ensure_dev_pki("keys").context("dev PKI")? {
        println!("[SMOKE] generated dev PKI under keys/");
    }

    if skp.exists() && pkp.exists() {
        return Ok(());
    }

    fs::create_dir_all("keys").context("mkdir keys")?;

    let sk = SigningKey::generate(&mut OsRng);
    let pk = sk.verifying_key();

    fs::write(&skp, sk.to_bytes()).context("write vs_sk")?;
    fs::write(&pkp, pk.to_bytes()).context("write vs_pk")?;

    println!(
        "[SMOKE] generated VS dev keys: {}, {}",
        skp.display(),
        pkp.display()
    );

    Ok(())
}

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

/// Run a single smoke test pass with optional TPM enabled.
fn run_smoke_pass(enable_tpm: bool) -> Result<(bool, bool)> {
    let pass_name = if enable_tpm {
        "TPM-enabled"
    } else {
        "standard"
    };
    println!(
        "\n[SMOKE] ========== Starting {} pass ==========",
        pass_name
    );

    // 1. Spawn VS (optionally another build, through a wrapper such as qemu)
    let vs_bin = std::env::var_os("SMOKE_VS_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| bin_path("vs"));
    let mut vs_cmd = match std::env::var_os("SMOKE_VS_WRAPPER") {
        Some(wrapper) => {
            let mut cmd = Command::new(wrapper);
            cmd.arg(&vs_bin);
            cmd
        }
        None => Command::new(&vs_bin),
    };
    let mut vs_child = vs_cmd
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("spawn {:?}", vs_bin))?;

    let startup_ms = std::env::var("SMOKE_VS_STARTUP_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(200);
    thread::sleep(Duration::from_millis(startup_ms));

    // 2. Spawn GS (with or without TPM)
    let gs_bin = bin_path("gs-sim");
    let mut gs_cmd = Command::new(&gs_bin);
    gs_cmd.args(["--vs", "127.0.0.1:4444", "--test-once", "--test-secs", "12"]);

    if enable_tpm {
        gs_cmd.arg("--enable-tpm");
    }

    let mut gs_child = gs_cmd
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("spawn {:?}", gs_bin))?;

    // Clients retry until the GS has joined and signed its first Checkpoint.
    thread::sleep(Duration::from_millis(500));

    // 3. Clients: one that must be refused the `verified` queue (tier floor
    //    D2; this device has no evidence), then the smoke client.
    let client_bin = bin_path("client-sim");
    let refused = Command::new(&client_bin)
        .args(["--queue", "verified", "--expect-refused"])
        .status()
        .with_context(|| format!("run {:?}", client_bin))?;
    let client_status = Command::new(&client_bin)
        .arg("--smoke-test")
        .status()
        .with_context(|| format!("run {:?}", client_bin))?;
    let client_ok = client_status.success() && refused.success();
    if client_ok {
        println!("[SMOKE] {pass_name} pass: clients completed successfully.");
    } else {
        println!(
            "[SMOKE] {pass_name} pass: client failed (smoke {:?}, verified-queue {:?})",
            client_status.code(),
            refused.code()
        );
    }

    // 4. Wait for GS
    let gs_status = gs_child.wait().context("wait gs-sim")?;
    if gs_status.success() {
        println!("[SMOKE] {} pass: gs-sim completed successfully.", pass_name);
    } else {
        println!(
            "[SMOKE] {} pass: gs-sim exited nonzero (status={:?})",
            pass_name,
            gs_status.code()
        );
    }

    // 5. Kill VS
    let _ = vs_child.kill();
    let _ = vs_child.wait();

    Ok((client_ok, gs_status.success()))
}

fn main() -> Result<()> {
    // 1. Make sure VS signing keys exist.
    ensure_vs_keys()?;

    // 2. Run standard smoke test (without TPM)
    let (client_ok, gs_ok) = run_smoke_pass(false)?;

    // 3. Check ledger
    match assert_recent_ledger_has_move() {
        Ok(_) => {}
        Err(e) => {
            if std::env::var("LENIENT_SMOKE").is_err() {
                anyhow::bail!("ledger check failed: {e:#}");
            } else {
                eprintln!("[SMOKE] ledger check warning: {e:#}");
            }
        }
    }

    // 4. Run TPM-enabled smoke test (unless SKIP_TPM_TEST is set)
    let (tpm_client_ok, tpm_gs_ok) = if std::env::var("SKIP_TPM_TEST").is_err() {
        // Small delay between passes
        thread::sleep(Duration::from_millis(500));
        run_smoke_pass(true)?
    } else {
        println!("[SMOKE] Skipping TPM test (SKIP_TPM_TEST is set)");
        (true, true)
    };

    // 5. Summary
    println!("\n[SMOKE] ========== Summary ==========");
    println!(
        "[SMOKE] Standard pass: client={}, gs={}",
        if client_ok { "OK" } else { "FAIL" },
        if gs_ok { "OK" } else { "FAIL" }
    );
    println!(
        "[SMOKE] TPM pass: client={}, gs={}",
        if tpm_client_ok { "OK" } else { "FAIL" },
        if tpm_gs_ok { "OK" } else { "FAIL" }
    );

    // 6. Exit policy
    let strict = std::env::var("LENIENT_SMOKE").is_err();
    let all_ok = client_ok && gs_ok && tpm_client_ok && tpm_gs_ok;

    if strict && !all_ok {
        std::process::exit(1);
    }

    println!("[SMOKE] done.");
    Ok(())
}
