//! P2 client-verifiable transparency exit test (EVD-02, EVD-03) against real `fppd`:
//!
//! A rogue GS (`equivocate_from: Some(3)`) gives Server Liveness one Checkpoint
//! per epoch and shows its player another from epoch 3 on.
//! - Epochs < 3 are proven logged (Ed25519 + ML-DSA-65 + witness + Merkle inclusion).
//! - Epoch 3 proves a split view against the log; the player reports its signed
//!   Checkpoint to Server Liveness, which revokes the rogue GS.
//! - The player's session ends within one SAR lifetime (10s).

use anyhow::{bail, ensure, Context, Result};
use fpp::control::ReportAnswer;
use fpp::types::{DeviceTier, Reason};
use fpp_sim::client::{request_admission, ClientTrust, GameClient, Services, SessionEnd};
use fpp_sim::game_wire::ClientCmd;
use fpp_sim::harness::TestCell;
use fpp_sim::server::{spawn_server, ServerConfig};
use fpp_sim::transparency::{audit, check_head, HeadCheck};
use std::time::{Duration, Instant};

const SAR_LIFETIME: Duration = Duration::from_secs(10);
const EQUIVOCATE_FROM: u32 = 3;

async fn run() -> Result<()> {
    let cell = TestCell::start("split-view", true, &[])?;
    let trust = ClientTrust::from_bundle(cell.bundle.clone());
    let services = Services::single(cell.addr);

    let _gs = spawn_server(ServerConfig {
        liveness: cell.addr,
        bundle: cell.bundle.clone(),
        game_bind: "127.0.0.1:0".parse()?,
        gs_id: "split-view-gs".into(),
        min_tier: DeviceTier::D0Unknown,
        equivocate_from: Some(EQUIVOCATE_FROM),
        ignore_revocations: false,
        ledger_dir: None,
    })
    .await?;

    let mut tries = 0;
    let creds = loop {
        tries += 1;
        match request_admission(&services, &trust, "open").await {
            Ok(c) => break c,
            Err(e) if tries < 60 => {
                if let Some(SessionEnd::Refused(code)) = e.downcast_ref::<SessionEnd>() {
                    ensure!(*code == Reason::ServerDraining as u16, "refused ({code})");
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            Err(e) => return Err(e),
        }
    };

    let mut game = GameClient::connect(creds, &trust, Duration::from_secs(10)).await?;
    let match_id = game.match_id();
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
        "[SPLIT] epochs {:?}: proven logged (Ed25519 + ML-DSA-65, witness, inclusion)",
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
        bail!("split view was not caught and acted on: {caught:?}");
    };
    println!(
        "[SPLIT] epoch {epoch}: split view proven & reported; Server Liveness revoked the server ({:?})",
        started.elapsed()
    );

    let deadline = Instant::now() + Duration::from_secs(30);
    let again = loop {
        match check_head(&trust, services.log, match_id, &rogue[1]).await? {
            HeadCheck::Pending if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(200)).await
            }
            c => break c,
        }
    };
    ensure!(
        matches!(again, HeadCheck::SplitView { .. }),
        "epoch {}: {again:?}",
        rogue[1].epoch
    );

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
    println!("[SPLIT] player session ended ({end:?}) {lapsed:?} after report");
    drop(cell);
    println!("[SPLIT] split-view exit test passed");
    Ok(())
}

fn main() -> Result<()> {
    tokio::runtime::Runtime::new()?.block_on(run())
}
