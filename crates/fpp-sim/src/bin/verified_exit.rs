//! Stage H5 exit test (verified playlists) against real `fppd`:
//! spawns the C dedicated host `target/fpp-verified-host` linked with
//! `libfpp.a --features gs-link`:
//! - Player A is admitted, verifies Checkpoints under the SAR's instance key,
//!   and is kicked with `REVOKED` when the host bans A's device (H08).
//! - Player B is admitted; the host leaves Server Liveness while continuing to
//!   serve; B's session lapses on its own within one SAR lifetime (H09).

use anyhow::{bail, ensure, Context, Result};
use fpp::types::Reason;
use fpp_sim::client::{
    client_build, request_admission, ClientEvent, ClientTrust, Credentials, GameClient, Services,
    SessionEnd,
};
use fpp_sim::game_wire::ClientCmd;
use fpp_sim::harness::TestCell;
use std::io::{BufRead, BufReader};
use std::net::UdpSocket;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const SAR_LIFETIME: Duration = Duration::from_secs(10);

struct Host {
    child: Child,
    lines: Arc<Mutex<Vec<(Instant, String)>>>,
}

impl Host {
    fn saw(&self, needle: &str) -> Option<Instant> {
        self.lines
            .lock()
            .expect("lines")
            .iter()
            .find(|(_, l)| l.contains(needle))
            .map(|(t, _)| *t)
    }

    fn wait_for(&self, needle: &str) -> Option<Instant> {
        let deadline = Instant::now() + Duration::from_secs(2);
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

fn pick_free_udp() -> Result<String> {
    let s = UdpSocket::bind("127.0.0.1:0")?;
    Ok(s.local_addr()?.to_string())
}

fn spawn_host(cell: &TestCell) -> Result<Host> {
    let program = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/fpp-verified-host")
        .canonicalize()
        .context("target/fpp-verified-host missing: run `make ffi-c-verified`")?;
    let game_addr = pick_free_udp()?;
    let mut child = Command::new(program)
        .args([
            &cell.addr.to_string(),
            "", // ca_cert unused under Noise_IK key-bundle pinning
            &cell.bundle_path.display().to_string(),
            &game_addr,
            "90",
            "--client-build",
            &hex::encode(client_build()),
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

async fn matched(services: &Services, trust: &ClientTrust) -> Result<Credentials> {
    let mut tries = 0;
    loop {
        tries += 1;
        match request_admission(services, trust, "open").await {
            Ok(c) => return Ok(c),
            Err(e) if tries < 80 => {
                if let Some(SessionEnd::Refused(code)) = e.downcast_ref::<SessionEnd>() {
                    ensure!(*code == Reason::ServerDraining as u16, "refused ({code})");
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            Err(e) => return Err(e),
        }
    }
}

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

async fn run(cell: &TestCell, host: &Host) -> Result<()> {
    let trust = ClientTrust::from_bundle(cell.bundle.clone());
    let services = Services::single(cell.addr);

    // Player A: admitted, plays, then its device is banned (H08).
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
        "host did not ban A"
    );
    println!("[VERIFIED] player A: {heads} Checkpoints verified, then kicked (device banned, H08)");

    // Player B: admitted; then host leaves Server Liveness (H09).
    let b = matched(&services, &trust).await?;
    let mut game = GameClient::connect(b, &trust, Duration::from_secs(10)).await?;
    println!("[VERIFIED] player B admitted to slot {}", game.slot());
    let (end, heads) = play_until_end(&mut game, Duration::from_secs(30)).await?;
    let ended = Instant::now();
    let left = host
        .wait_for("leaving Server Liveness")
        .context("host never left Server Liveness")?;
    ensure!(end == SessionEnd::SarLapsed, "player B ended with {end:?}");
    ensure!(
        heads >= 2,
        "player B verified only {heads} Checkpoint heads"
    );
    let lapsed = ended.saturating_duration_since(left);
    ensure!(lapsed <= SAR_LIFETIME, "{lapsed:?} > one SAR lifetime");
    println!(
        "[VERIFIED] player B: {heads} Checkpoints verified; host left Server Liveness and B lapsed {lapsed:?} later"
    );
    if host.saw("admitted slot").is_none() {
        bail!("host logged no admission");
    }
    Ok(())
}

fn main() -> Result<()> {
    let cell = TestCell::start("verified-exit", false, &[])?;
    let host = spawn_host(&cell)?;
    let started = Instant::now();
    let result = tokio::runtime::Runtime::new()?.block_on(run(&cell, &host));
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
