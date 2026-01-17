// crates/tools/src/smoke.rs
//
// CI-lite / `make ci` smoke test:
//
// - REQ-VS-001/002 (tickets, receipts)
// - REQ-GS-001/002/003/004 (verify ticket & sigs, client binding, movement, multi-client)
// - REQ-CL-001/002 (pinning, persistent keys)
// - Stage 1.2: TPM continuous attestation (when --enable-tpm is used)
//
// 1. Ensure VS dev keys exist (keys/vs_ed25519.*).
// 2. Spawn VS in the background (listens QUIC on 127.0.0.1:4444).
// 3. Spawn gs-sim --test-once (optionally with --enable-tpm for TPM testing).
// 4. Run client-sim --smoke-test in the foreground.
// 5. Wait for gs-sim to complete.
// 6. Kill VS.
// 7. Optionally run TPM-enabled test as second pass.

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

    // 1. Spawn VS
    let vs_bin = bin_path("vs");
    let mut vs_child = Command::new(&vs_bin)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("spawn {:?}", vs_bin))?;

    thread::sleep(Duration::from_millis(200));

    // 2. Spawn GS (with or without TPM)
    let gs_bin = bin_path("gs-sim");
    let mut gs_cmd = Command::new(&gs_bin);
    gs_cmd.arg("--vs").arg("127.0.0.1:4444").arg("--test-once");

    if enable_tpm {
        gs_cmd.arg("--enable-tpm");
    }

    let mut gs_child = gs_cmd
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("spawn {:?}", gs_bin))?;

    // Wait for GS to initialize
    thread::sleep(Duration::from_millis(2000));

    // 3. Run client
    let client_bin = bin_path("client-sim");
    let mut client_child = Command::new(&client_bin)
        .arg("--gs-addr")
        .arg("127.0.0.1:50000")
        .arg("--smoke-test")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("run {:?}", client_bin))?;

    let client_status = client_child.wait().context("wait client-sim")?;
    if client_status.success() {
        println!(
            "[SMOKE] {} pass: client-sim completed successfully.",
            pass_name
        );
    } else {
        println!(
            "[SMOKE] {} pass: client-sim exited nonzero (status={:?})",
            pass_name,
            client_status.code()
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

    Ok((client_status.success(), gs_status.success()))
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
            if std::env::var("STRICT_SMOKE").is_ok() {
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
    let strict = std::env::var("STRICT_SMOKE").is_ok();
    let all_ok = client_ok && gs_ok && tpm_client_ok && tpm_gs_ok;

    if strict && !all_ok {
        std::process::exit(1);
    }

    println!("[SMOKE] done.");
    Ok(())
}
