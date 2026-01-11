// crates/tools/src/smoke.rs
//
// CI-lite / `make ci` smoke test:
//
// - REQ-VS-001/002 (tickets, receipts)
// - REQ-GS-001/002/003/004 (verify ticket & sigs, client binding, movement, multi-client)
// - REQ-CL-001/002 (pinning, persistent keys)
//
// 1. Ensure VS dev keys exist (keys/vs_ed25519.*). This matches what gs-sim
//    and client-sim expect for VS signatures.
// 2. Spawn VS in the background (listens QUIC on 127.0.0.1:4444).
// 3. Spawn gs-sim --test-once in the background. That will:
//      - connect to VS
//      - open its client port on 127.0.0.1:50000
//      - stream heartbeats
//      - receive PlayTickets
//      - accept a client connection
//      - exit after ~5s
// 4. Run client-sim --smoke-test in the foreground. That will:
//      - connect to gs-sim (QUIC 127.0.0.1:50000)
//      - verify the VS-signed PlayTicket
//      - send nonce-monotonic ClientInput stapled to that ticket
// 5. Wait for gs-sim to exit.
// 6. Kill VS.
// 7. By default exit 0 so local `make ci` doesn’t hard-fail your dev loop.
//    Set STRICT_SMOKE=1 to make the harness return nonzero on failures.
//
// Differences from older version:
//  - Resolve explicit paths to ./target/debug/{vs,gs-sim,client-sim} for Linux CI.
//  - Inherit stdout/stderr so CI prints all logs inline.
//  - Sleep to allow GS QUIC endpoint initialization before starting client-sim.

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

// Build an absolute/relative path to the compiled binary inside target/debug.
//
// Layout assumption:
//   workspace_root/
//     target/debug/vs(.exe)
//     target/debug/gs-sim(.exe)
//     target/debug/client-sim(.exe)
//     crates/tools/  <-- this file lives here
//
// CARGO_MANIFEST_DIR for this crate = <workspace_root>/crates/tools
fn bin_path(bin: &str) -> PathBuf {
    let tools_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = tools_dir
        .parent() // crates/
        .and_then(|p| p.parent()) // workspace root
        .expect("could not locate workspace root");

    workspace_root
        .join("target")
        .join("debug")
        .join(format!("{bin}{BIN_EXT}"))
}

// Ensure VS has an Ed25519 keypair on disk so it can sign tickets.
//
// keys/vs_ed25519.pk8  (priv)
// keys/vs_ed25519.pub  (pub)
//
// gs-sim/client-sim currently expect those to exist.
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

// ---------- Ledger E2E sanity checks (post-run) ----------

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

    // ensure it’s fresh (within the last 60s)
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

fn main() -> Result<()> {
    // 1. Make sure VS signing keys exist.
    ensure_vs_keys()?;

    // 2. Spawn VS in the background.
    //    We inherit stdout/stderr so GitHub Actions shows
    //    e.g. "[VS] listening on 127.0.0.1:4444".
    let vs_bin = bin_path("vs");
    let mut vs_child = Command::new(&vs_bin)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("spawn {:?}", vs_bin))?;

    // Give VS time to bind to 127.0.0.1:4444 (QUIC/UDP).
    thread::sleep(Duration::from_millis(200));

    // 3. Spawn gs-sim in the background.
    //
    //    --vs 127.0.0.1:4444       tells it where to find the validator server
    //    --test-once               tells it to:
    //                                - connect/join
    //                                - heartbeat
    //                                - run the QUIC "client port"
    //                                - accept one client handshake loop
    //                                - shut down after ~5s
    //
    let gs_bin = bin_path("gs-sim");
    let mut gs_child = Command::new(&gs_bin)
        .arg("--vs")
        .arg("127.0.0.1:4444")
        .arg("--test-once")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("spawn {:?}", gs_bin))?;

    // Wait for gs-sim to initialize its QUIC endpoint on 127.0.0.1:50000.
    // QUIC uses UDP, so we can't use TCP connection probing. Give it time to:
    // - Complete VS handshake
    // - Receive first ticket
    // - Start QUIC server
    thread::sleep(Duration::from_millis(2000));

    // 4. Run client-sim in the foreground.
    //
    //    --smoke-test: connect via QUIC, send a handful of ClientInput frames and exit
    //
    // We inherit stdout/stderr so we see:
    //   [CLIENT] tick=1 you=(1.00,0.00)
    //   [CLIENT] tick=2 you=(2.00,0.00)
    //
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
        println!("[SMOKE] client-sim completed successfully.");
    } else {
        println!(
            "[SMOKE] client-sim exited nonzero (status={:?})",
            client_status.code()
        );
    }

    // 5. Wait for gs-sim to complete its --test-once run.
    let gs_status = gs_child.wait().context("wait gs-sim")?;
    if gs_status.success() {
        println!("[SMOKE] gs-sim completed successfully.");
    } else {
        println!(
            "[SMOKE] gs-sim exited nonzero (status={:?})",
            gs_status.code()
        );
    }

    // 5b. Sanity-check that a recent ledger file exists and its last line has op=Move.
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

    // 6. Kill VS so it doesn't hang CI.
    let _ = vs_child.kill();
    let _ = vs_child.wait();

    // 7. Exit policy: default is success; STRICT_SMOKE=1 makes failures fatal.
    let strict = std::env::var("STRICT_SMOKE").is_ok();
    if strict && (!client_status.success() || !gs_status.success()) {
        std::process::exit(1);
    }

    println!("[SMOKE] done.");
    Ok(())
}
