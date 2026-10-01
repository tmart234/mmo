use anyhow::{bail, Result};
use clap::Parser;
use client_core::*;
use common::proto::ClientCmd;
use tokio::time::Duration;

#[derive(Parser, Debug)]
struct Opts {
    /// The Verifier's address.
    #[arg(long, default_value = "127.0.0.1:4445")]
    verifier: std::net::SocketAddr,
    /// The Broker's address.
    #[arg(long, default_value = "127.0.0.1:4446")]
    broker: std::net::SocketAddr,
    /// The Transparency Log's public address (gossip).
    #[arg(long, default_value = "127.0.0.1:4447")]
    log: std::net::SocketAddr,
    /// Server Liveness's address (split-view reports).
    #[arg(long, default_value = "127.0.0.1:4444")]
    liveness: std::net::SocketAddr,
    /// After the match, check every Checkpoint the server sent against the
    /// Transparency Log (waiting up to this many seconds for the last).
    #[arg(long)]
    check_log: Option<u64>,
    /// Queue to join: `open` (any device) or `verified` (tier D2+).
    #[arg(long, default_value = "open")]
    queue: String,
    /// Play a short scripted session and check the protocol worked, then exit.
    #[arg(long)]
    smoke_test: bool,
    /// Expect the Broker to refuse this queue (e.g. `verified` without evidence).
    #[arg(long)]
    expect_refused: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opts = Opts::parse();
    let trust = ClientTrust::load_default()?;
    let services = Services {
        verifier: opts.verifier,
        broker: opts.broker,
        log: opts.log,
        liveness: opts.liveness,
    };

    // The GS needs a moment to join Server Liveness and sign its first Checkpoint.
    let mut attempt = 0;
    let creds = loop {
        attempt += 1;
        match request_admission(&services, &trust, &opts.queue).await {
            Ok(c) => break c,
            Err(e) => {
                if let Some(SessionEnd::Refused(code)) = e.downcast_ref::<SessionEnd>() {
                    if opts.expect_refused {
                        println!("[CLIENT] refused by the Broker as expected (reason {code})");
                        return Ok(());
                    }
                    if *code != fpp_types::Reason::ServerDraining as u16 || attempt >= 20 {
                        bail!("admission refused (reason {code})");
                    }
                } else if attempt >= 20 {
                    return Err(e);
                }
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
        }
    };
    if opts.expect_refused {
        bail!("expected the Broker to refuse queue {}", opts.queue);
    }
    println!(
        "[CLIENT] admitted by the Broker: match {}.. slot {} on {}",
        hex::encode(&creds.sat_claims.match_id.0[..4]),
        creds.sat_claims.slot,
        creds.gs_addr
    );

    let mut game = GameClient::connect(creds, &trust, Duration::from_secs(10)).await?;
    println!("[CLIENT] joined the game server as slot {}", game.slot());

    let ticks = if opts.smoke_test { 150 } else { u32::MAX };
    let (mut last, mut snapshots, mut heads) = (None, 0u32, 0u32);
    for _ in 0..ticks {
        for ev in game.step(&ClientCmd::Move { dx: 0.5, dy: 0.0 }).await? {
            match ev {
                ClientEvent::Snapshot(s) => {
                    snapshots += 1;
                    last = Some(s);
                }
                ClientEvent::CheckpointHead { epoch, digest } => {
                    heads += 1;
                    println!(
                        "[CLIENT] checkpoint head epoch {epoch}: {}..",
                        hex::encode(&digest.0[..6])
                    );
                }
            }
        }
    }
    let sar_seq = game.sar_seq().unwrap_or(0);
    let (match_id, checked) = (game.match_id(), game.heads.clone());
    game.bye().await?;
    let x = last.as_ref().map_or(0.0, |s| s.you.0);
    println!(
        "[CLIENT] {snapshots} snapshots, {heads} checkpoint heads, SAR seq {sar_seq}, x = {x:.1}"
    );
    if opts.smoke_test {
        if snapshots < 50 || heads < 2 || sar_seq < 1 || x <= 10.0 {
            bail!(
                "smoke test failed: snapshots {snapshots}, heads {heads}, SAR seq {sar_seq}, x {x}"
            );
        }
        println!("[CLIENT] smoke test passed");
    }
    if let Some(wait) = opts.check_log {
        let deadline = std::time::Instant::now() + Duration::from_secs(wait);
        let audit = transparency::audit(
            &trust,
            opts.log,
            opts.liveness,
            match_id,
            &checked,
            deadline,
        )
        .await?;
        println!(
            "[CLIENT] Transparency Log: {} of {} Checkpoints proven logged (Ed25519 + ML-DSA, witness, inclusion); pending {:?}; split views {:?}",
            audit.included,
            checked.len(),
            audit.pending,
            audit.split_views
        );
        if audit.included != checked.len() {
            bail!("Checkpoints not proven logged");
        }
    }
    Ok(())
}
