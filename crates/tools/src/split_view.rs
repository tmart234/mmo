// P2's exit test for client-verifiable transparency (EVD-02, EVD-03), end
// to end on a dev cell of separate processes:
//
// A rogue game server (`gs-sim --equivocate-from 3`) gives Server Liveness
// one Checkpoint per epoch and shows its player another from epoch 3 on.
// The player checks every Checkpoint it received against the Transparency
// Log (both halves of the log's hybrid signature, a witness cosignature,
// the inclusion proof): the epochs before 3 are proven logged; from epoch 3 the
// log proves a different Checkpoint, the player reports the one the server
// signed for it to Server Liveness, Server Liveness revokes the server, and
// the player's session lapses within one SAR lifetime.

use anyhow::{bail, ensure, Context, Result};
use client_core::transparency::{audit, HeadCheck};
use client_core::{request_admission, ClientTrust, GameClient, Services, SessionEnd};
use common::proto::{ClientCmd, ReportAnswer};
use fpp_types::Reason;
use std::process::{Child, Command};
use std::time::{Duration, Instant};
use tools::cell::{bin_path, ensure_dev_keys, Cell, Launch};

const SAR_LIFETIME: Duration = Duration::from_secs(10);
/// The first epoch the rogue server shows its player another Checkpoint.
const EQUIVOCATE_FROM: u32 = 3;

struct Gs(Child);

impl Drop for Gs {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn run() -> Result<()> {
    let trust = ClientTrust::load_default()?;
    let services = Services::default();
    let _gs = Gs(Command::new(bin_path("gs-sim", "debug"))
        .args([
            "--liveness",
            "127.0.0.1:4444",
            "--game-addr",
            "127.0.0.1:50020",
            "--equivocate-from",
            &EQUIVOCATE_FROM.to_string(),
        ])
        .spawn()
        .context("spawn gs-sim")?);

    let mut tries = 0;
    let creds = loop {
        tries += 1;
        match request_admission(&services, &trust, "open").await {
            Ok(c) => break c,
            Err(e) if tries < 60 => {
                if let Some(SessionEnd::Refused(code)) = e.downcast_ref::<SessionEnd>() {
                    ensure!(*code == Reason::ServerDraining as u16, "refused ({code})");
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            Err(e) => return Err(e),
        }
    };
    let mut game = GameClient::connect(creds, &trust, Duration::from_secs(10)).await?;
    let match_id = game.match_id();
    // play until the server has shown two Checkpoints of the split view
    // (the player may have joined after epoch 0)
    while game
        .heads
        .iter()
        .filter(|h| h.epoch >= EQUIVOCATE_FROM)
        .count()
        < 2
    {
        game.step(&ClientCmd::Move { dx: 0.1, dy: 0.0 }).await?;
    }
    let (honest, rogue): (Vec<_>, Vec<_>) = game
        .heads
        .iter()
        .cloned()
        .partition(|h| h.epoch < EQUIVOCATE_FROM);
    ensure!(!honest.is_empty(), "joined too late to see an honest epoch");

    // the honest epochs are proven logged; then the server is caught
    let checked = audit(
        &trust,
        services.log,
        services.liveness,
        match_id,
        &honest,
        Instant::now() + Duration::from_secs(30),
    )
    .await?;
    ensure!(
        checked.included == honest.len() && checked.split_views.is_empty(),
        "honest epochs: {checked:?}"
    );
    println!(
        "[SPLIT] epochs {:?}: proven logged (Ed25519 + ML-DSA, witness, inclusion)",
        honest.iter().map(|h| h.epoch).collect::<Vec<_>>()
    );
    let started = Instant::now();
    let caught = audit(
        &trust,
        services.log,
        services.liveness,
        match_id,
        &rogue[..1],
        Instant::now() + Duration::from_secs(30),
    )
    .await?;
    let [(epoch, Ok(ReportAnswer::Revoked))] = caught.split_views.as_slice() else {
        bail!("the split view was not caught and acted on: {caught:?}");
    };
    println!(
        "[SPLIT] epoch {epoch}: the log proves another Checkpoint; reported, Server Liveness revoked the server ({:?})",
        started.elapsed()
    );
    // a second report of the same split view is not a new revocation, but
    // still a proof
    let deadline = Instant::now() + Duration::from_secs(30);
    let again = loop {
        match client_core::transparency::check_head(&trust, services.log, match_id, &rogue[1])
            .await?
        {
            HeadCheck::Pending if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(250)).await
            }
            c => break c,
        }
    };
    ensure!(
        matches!(again, HeadCheck::SplitView { .. }),
        "epoch {}: {again:?}",
        rogue[1].epoch
    );

    // the player's session lapses within one SAR lifetime of the report
    let end = loop {
        match game.step(&ClientCmd::Move { dx: 0.1, dy: 0.0 }).await {
            Ok(_) => ensure!(started.elapsed() < SAR_LIFETIME * 2, "still playing"),
            Err(e) => {
                break e
                    .downcast_ref::<SessionEnd>()
                    .copied()
                    .context("not a session end")?
            }
        }
    };
    let lapsed = started.elapsed();
    ensure!(
        matches!(end, SessionEnd::SarLapsed | SessionEnd::Kicked(_)),
        "ended with {end:?}"
    );
    ensure!(lapsed <= SAR_LIFETIME, "{lapsed:?} > one SAR lifetime");
    println!("[SPLIT] the player's session ended ({end:?}) {lapsed:?} after the report");
    Ok(())
}

fn main() -> Result<()> {
    ensure_dev_keys()?;
    let cell = Cell::start(&Launch::from_env("debug"))?;
    let result = tokio::runtime::Runtime::new()?.block_on(run());
    drop(cell);
    match &result {
        Ok(()) => println!("[SPLIT] split-view exit test passed"),
        Err(e) => println!("[SPLIT] FAILED: {e:#}"),
    }
    result
}
