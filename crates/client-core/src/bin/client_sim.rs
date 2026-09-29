use anyhow::{bail, Result};
use clap::Parser;
use client_core::*;
use common::proto::ClientCmd;
use tokio::time::Duration;

#[derive(Parser, Debug)]
struct Opts {
    /// VS control address (stub Verifier + Broker).
    #[arg(long, default_value = "127.0.0.1:4444")]
    vs: String,
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

    // The GS needs a moment to join the VS and sign its first Checkpoint.
    let mut attempt = 0;
    let creds = loop {
        attempt += 1;
        match request_admission(&opts.vs, &trust, &opts.queue).await {
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
    Ok(())
}
