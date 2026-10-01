//! `fpp-ticket`: a place in a verified playlist for a C game (stage H5 of
//! docs/anticheat/08). It makes a session key, proves it to the region's
//! Verifier (an Attestation Result) and asks the Broker for a match (a
//! Session Admission Token and the game server to join), then writes a
//! ticket file the game reads (the Halo port's `network.ticket_file`):
//!
//! ```text
//! fpp-ticket 1
//! session_seed <64 hex>      the session key (keep the file private)
//! gs_addr <ip:port>          the server to dial
//! gs_noise_static <64 hex>   its fpp_p2p host key (its SARs must name it)
//! sat <hex>
//! ar <hex>
//! ```
//!
//! The game joins with `fpp_signer_from_seed(session_seed)` and
//! `fpp_p2p_joiner_new(gs_noise_static, no invite secret, ...)`, checks the
//! server's SAR chain (`fpp_sar_chain_*`: it names `gs_noise_static` and the
//! SAT's audience) and sends `Admit{sat, ar}` (`fpp_control_admit`).
//!
//! This build has no platform evidence: its AR is tier D0, so it gets
//! places only in queues open to D0 (`open`).

use anyhow::{bail, Context, Result};
use clap::Parser;
use client_core::{request_admission_for_build, ClientTrust, Services, SessionEnd};
use ed25519_dalek::SigningKey;
use fpp_types::Reason;
use rand::RngCore;
use std::io::Write;
use std::path::PathBuf;
use tokio::time::Duration;

#[derive(Parser, Debug)]
struct Opts {
    /// The Verifier's address.
    #[arg(long, default_value = "127.0.0.1:4445")]
    verifier: std::net::SocketAddr,
    /// The Broker's address.
    #[arg(long, default_value = "127.0.0.1:4446")]
    broker: std::net::SocketAddr,
    /// Queue to join.
    #[arg(long, default_value = "open")]
    queue: String,
    /// The game's build (SHA-256, 64 hex digits), or
    #[arg(long, conflicts_with = "client_binary")]
    client_build: Option<String>,
    /// the game's executable, whose SHA-256 is its build. Neither: this
    /// tool's own build.
    #[arg(long)]
    client_binary: Option<PathBuf>,
    /// Keep asking this long while no server has a free place.
    #[arg(long, default_value_t = 30)]
    wait_secs: u64,
    /// Where to write the ticket.
    #[arg(long, default_value = "ticket.fpp")]
    out: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opts = Opts::parse();
    let trust = ClientTrust::load_default()?;
    let services = Services {
        verifier: opts.verifier,
        broker: opts.broker,
        ..Services::default()
    };
    let build = match (&opts.client_build, &opts.client_binary) {
        (Some(hex_build), _) => <[u8; 32]>::try_from(hex::decode(hex_build)?.as_slice())
            .map_err(|_| anyhow::anyhow!("--client-build: 64 hex digits"))?,
        (None, Some(path)) => {
            common::crypto::file_sha256(path).with_context(|| format!("read {}", path.display()))?
        }
        (None, None) => client_core::client_build(),
    };
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);

    let deadline = tokio::time::Instant::now() + Duration::from_secs(opts.wait_secs);
    let creds = loop {
        let session = Box::new(fpp_crypto::Ed25519Signer::new(SigningKey::from_bytes(
            &seed,
        )));
        match request_admission_for_build(&services, &trust, &opts.queue, session, None, build)
            .await
        {
            Ok(c) => break c,
            Err(e) => {
                // (no server with a free place yet: ask again)
                let waiting = matches!(
                    e.downcast_ref::<SessionEnd>(),
                    Some(SessionEnd::Refused(code)) if *code == Reason::ServerDraining as u16
                );
                if !waiting || tokio::time::Instant::now() >= deadline {
                    bail!("no place in queue {}: {e:#}", opts.queue);
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    };

    let text = format!(
        "fpp-ticket 1\nsession_seed {}\ngs_addr {}\ngs_noise_static {}\nsat {}\nar {}\n",
        hex::encode(seed),
        creds.gs_addr,
        hex::encode(creds.gs_noise_static),
        hex::encode(&creds.sat),
        hex::encode(&creds.ar),
    );
    let mut file = {
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create(true).truncate(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
        o.open(&opts.out)
            .with_context(|| format!("write {}", opts.out.display()))?
    };
    file.write_all(text.as_bytes())?;
    println!(
        "[ticket] {} in match {}.. slot {} on {} (queue {}, tier D{}): {}",
        hex::encode(&creds.sat_claims.sub[..4]),
        hex::encode(&creds.sat_claims.match_id.0[..4]),
        creds.sat_claims.slot,
        creds.gs_addr,
        creds.sat_claims.queue,
        creds.sat_claims.tier as u8,
        opts.out.display()
    );
    Ok(())
}
