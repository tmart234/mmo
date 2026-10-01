// Stage H5's exit test (docs/anticheat/08 §5, verified playlists), end to
// end on a dev cell of separate processes: a dedicated game server written
// in C against the SDK alone (`crates/fpp-ffi/tests/c/verified_host.c`,
// `make ffi-c-verified`) joins Server Liveness through `fpp_gs_link_*`,
// and players matched by the Verifier and the Broker join it.
//
// - Player A is admitted by its SAT and AR (`fpp_admission_admit`, with a
//   client-build list naming this client's build: finding H07), follows the
//   server's SAR chain and checks each Checkpoint it is sent under the
//   instance key the SAR certifies.
// - The server bans A's device (finding H08): A is kicked with REVOKED.
// - Player B is admitted; then the server leaves Server Liveness but keeps
//   serving, as a server that lost its blessing and ignores it. B's session
//   lapses on its own within one SAR lifetime (finding H09's mitigation:
//   only a blessed server keeps players).

use anyhow::{bail, ensure, Context, Result};
use client_core::{request_admission, ClientEvent, ClientTrust, GameClient, Services, SessionEnd};
use common::proto::ClientCmd;
use fpp_types::Reason;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tools::cell::{ensure_dev_keys, Cell, Launch};

const SAR_LIFETIME: Duration = Duration::from_secs(10);
const GAME_ADDR: &str = "127.0.0.1:50030";

struct Host {
    child: Child,
    /// Its lines, and when each was read.
    lines: Arc<Mutex<Vec<(Instant, String)>>>,
}

impl Host {
    /// When the host first printed a line containing `needle`.
    fn saw(&self, needle: &str) -> Option<Instant> {
        self.lines
            .lock()
            .expect("lines")
            .iter()
            .find(|(_, l)| l.contains(needle))
            .map(|(t, _)| *t)
    }
}

impl Host {
    /// [`Host::saw`], waiting up to a second for the line (the host's
    /// output can trail what its players already got).
    fn wait_for(&self, needle: &str) -> Option<Instant> {
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            match self.saw(needle) {
                Some(t) => return Some(t),
                None if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
                None => return None,
            }
        }
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_host() -> Result<Host> {
    let program = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/fpp-verified-host")
        .canonicalize()
        .context("target/fpp-verified-host missing: run `make ffi-c-verified`")?;
    let mut child = Command::new(program)
        .args([
            "127.0.0.1:4444",
            common::pki::DEFAULT_CA_CERT,
            common::keys::DEFAULT_BUNDLE,
            GAME_ADDR,
            "90",
            "--client-build",
            &hex::encode(client_core::client_build()),
            "--ban-after",
            "4",
            "--leave-after",
            "4",
        ])
        .stdout(Stdio::piped())
        .spawn()
        .context("spawn fpp-verified-host")?;
    let lines = Arc::new(Mutex::new(Vec::new()));
    let out = child.stdout.take().context("stdout")?;
    {
        let lines = lines.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(out).lines().map_while(Result::ok) {
                println!("[VERIFIED] {line}");
                lines.lock().expect("lines").push((Instant::now(), line));
            }
        });
    }
    Ok(Host { child, lines })
}

/// Ask the Verifier and the Broker for a place, until the server is up.
async fn matched(services: &Services, trust: &ClientTrust) -> Result<client_core::Credentials> {
    let mut tries = 0;
    loop {
        tries += 1;
        match request_admission(services, trust, "open").await {
            Ok(c) => return Ok(c),
            Err(e) if tries < 80 => {
                if let Some(SessionEnd::Refused(code)) = e.downcast_ref::<SessionEnd>() {
                    ensure!(*code == Reason::ServerDraining as u16, "refused ({code})");
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Play until the session ends; returns how it ended and the Checkpoint
/// heads seen (each verified by the client under the SAR's instance key).
async fn play_until_end(game: &mut GameClient, limit: Duration) -> Result<(SessionEnd, usize)> {
    let started = Instant::now();
    let mut heads = 0;
    loop {
        match game.step(&ClientCmd::Move { dx: 0.1, dy: 0.0 }).await {
            Ok(events) => {
                heads += events
                    .iter()
                    .filter(|e| matches!(e, ClientEvent::CheckpointHead { .. }))
                    .count();
                ensure!(started.elapsed() < limit, "still playing after {limit:?}");
            }
            Err(e) => {
                let end = *e
                    .downcast_ref::<SessionEnd>()
                    .context("not a session end")?;
                return Ok((end, heads));
            }
        }
    }
}

async fn run(host: &Host) -> Result<()> {
    let trust = ClientTrust::load_default()?;
    let services = Services::default();

    // Player A: admitted, plays, then its device is banned.
    let a = matched(&services, &trust).await?;
    let mut game = GameClient::connect(a, &trust, Duration::from_secs(10)).await?;
    println!("[VERIFIED] player A admitted to slot {}", game.slot());
    let (end, heads) = play_until_end(&mut game, Duration::from_secs(20)).await?;
    ensure!(
        end == SessionEnd::Kicked(Reason::Revoked as u16),
        "player A ended with {end:?}"
    );
    ensure!(
        heads >= 2,
        "player A verified only {heads} Checkpoint heads"
    );
    ensure!(
        host.wait_for("banned the device").is_some(),
        "the host did not ban A"
    );
    println!("[VERIFIED] player A: {heads} Checkpoints verified, then kicked (device banned, H08)");

    // Player B: admitted; then the server leaves Server Liveness.
    let b = matched(&services, &trust).await?;
    let mut game = GameClient::connect(b, &trust, Duration::from_secs(10)).await?;
    println!("[VERIFIED] player B admitted to slot {}", game.slot());
    let (end, heads) = play_until_end(&mut game, Duration::from_secs(30)).await?;
    let ended = Instant::now();
    let left = host
        .wait_for("leaving Server Liveness")
        .context("the host never left Server Liveness")?;
    ensure!(end == SessionEnd::SarLapsed, "player B ended with {end:?}");
    ensure!(
        heads >= 2,
        "player B verified only {heads} Checkpoint heads"
    );
    // The host still serves B; only B's own check of the SAR chain ends it.
    let lapsed = ended.saturating_duration_since(left);
    ensure!(lapsed <= SAR_LIFETIME, "{lapsed:?} > one SAR lifetime");
    println!(
        "[VERIFIED] player B: {heads} Checkpoints verified; the server left Server Liveness \
         and B's session lapsed on its own {lapsed:?} later"
    );
    if host.saw("admitted slot").is_none() {
        bail!("the host logged no admission");
    }
    Ok(())
}

fn main() -> Result<()> {
    ensure_dev_keys()?;
    let cell = Cell::start(&Launch::from_env("debug"))?;
    let host = spawn_host()?;
    let started = Instant::now();
    let result = tokio::runtime::Runtime::new()?.block_on(run(&host));
    drop(host);
    drop(cell);
    match &result {
        Ok(()) => println!(
            "[VERIFIED] verified-playlist exit test passed ({:?}; SAR lifetime {SAR_LIFETIME:?})",
            started.elapsed()
        ),
        Err(e) => println!("[VERIFIED] FAILED: {e:#}"),
    }
    result
}
