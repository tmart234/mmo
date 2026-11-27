//! Headless reference game server built directly on the shared
//! `fpp::gs_link::GsLink` client (ZERO duplicated GS↔Liveness transport code).

use crate::game::{self, Match, MatchConfig, Outputs, SAR_GRACE_MS};
use crate::ledger::Ledger;
use anyhow::{anyhow, Context, Result};
use ed25519_dalek::SigningKey;
use fpp::bundle::KeyBundle;
use fpp::crypto::{self, sha256, Ed25519Signer};
use fpp::gs_link::{GsLink, GsLinkConfig, GsLinkEvent};
use fpp::session::{Host, HostConfig, StaticKeypair};
use fpp::types::{BuildId, DeviceTier, MatchId};
use fpp::wire::RevocationEvent;
use rand::rngs::OsRng;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};

pub struct ServerConfig {
    pub liveness: SocketAddr,
    pub bundle: KeyBundle,
    pub game_bind: SocketAddr,
    pub gs_id: String,
    pub min_tier: DeviceTier,
    pub equivocate_from: Option<u32>,
    pub ignore_revocations: bool,
    pub ledger_dir: Option<PathBuf>,
}

pub struct RunningServer {
    pub match_id: MatchId,
    pub game_addr: SocketAddr,
    pub ledger_path: Option<PathBuf>,
    stop: Arc<AtomicBool>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl RunningServer {
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    pub async fn wait(mut self) {
        if let Some(t) = self.task.take() {
            let _ = t.await;
        }
    }
}

impl Drop for RunningServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.task.take() {
            t.abort();
        }
    }
}

/// Spawn a headless reference game server joined to `cfg.liveness` through the
/// shared `fpp::gs_link::GsLink`.
pub async fn spawn_server(cfg: ServerConfig) -> Result<RunningServer> {
    let socket = UdpSocket::bind(cfg.game_bind)
        .await
        .with_context(|| format!("bind game UDP {}", cfg.game_bind))?;
    let game_addr = socket.local_addr()?;

    let gs_key = SigningKey::generate(&mut OsRng);
    let instance = Ed25519Signer::new(SigningKey::generate(&mut OsRng));
    let instance_pub = instance.verifying_key().to_bytes();
    let noise = StaticKeypair::generate();
    let noise_pub = noise.public;
    let sw_hash = sha256(b"fpp-sim-reference-gs");

    let bundle_clone = cfg.bundle.clone();
    let gs_id = cfg.gs_id.clone();
    let game_addr_str = game_addr.to_string();
    let liveness = cfg.liveness;
    let link = tokio::task::spawn_blocking(move || {
        GsLink::connect(GsLinkConfig {
            liveness,
            bundle: bundle_clone,
            gs_id,
            game_addr: game_addr_str,
            gs_key,
            instance_pub,
            noise_pub,
            sw_hash,
            tpm2: None,
            timeout: Duration::from_secs(10),
        })
    })
    .await
    .map_err(|e| anyhow!("gs_link join panic: {e}"))?
    .map_err(|e| anyhow!("gs_link join: {e}"))?;

    let match_id = MatchId(link.match_id());
    let keys = cfg.bundle.keyset();
    let (ledger, ledger_path) = match cfg.ledger_dir {
        Some(dir) => {
            let l = Ledger::open_in(&dir, &hex::encode(&match_id.0[..4]))?;
            let p = l.path.clone();
            (Some(l), Some(p))
        }
        None => (None, None),
    };

    let m = Match::new(
        MatchConfig {
            match_id,
            instance,
            build_id: BuildId(sw_hash),
            keys: keys.clone(),
            min_tier: cfg.min_tier,
            sar_grace_ms: SAR_GRACE_MS,
            equivocate_from: cfg.equivocate_from,
            ignore_revocations: cfg.ignore_revocations,
        },
        Host::new(HostConfig::new(noise)),
    );

    let (sar_tx, sar_rx) = watch::channel(None);
    let (rev_tx, rev_rx) = mpsc::unbounded_channel();
    let (cp_tx, mut cp_rx) = mpsc::unbounded_channel::<(u32, Vec<u8>)>();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_pump = stop.clone();
    let stop_game = stop.clone();

    let task = tokio::spawn(async move {
        let pump = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_millis(20));
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        if stop_pump.load(Ordering::Relaxed) {
                            break;
                        }
                        while let Some(ev) = link.poll_event() {
                            match ev {
                                GsLinkEvent::Sar(sar) => {
                                    let _ = sar_tx.send(Some(sar));
                                }
                                GsLinkEvent::Revocation(cose) => {
                                    if let Ok(v) = crypto::verify::<RevocationEvent>(&cose, &keys) {
                                        let _ = rev_tx.send(v.payload);
                                    }
                                }
                                GsLinkEvent::Closed(_) => {
                                    drop(sar_tx);
                                    return;
                                }
                            }
                        }
                    }
                    Some((_, cp)) = cp_rx.recv() => {
                        let _ = link.submit_checkpoint(cp);
                    }
                }
            }
            drop(link);
        });

        let _ = game::run(
            socket,
            m,
            sar_rx,
            rev_rx,
            Outputs {
                checkpoints: cp_tx,
                signals: None,
                ledger,
            },
            stop_game,
        )
        .await;
        pump.abort();
    });

    Ok(RunningServer {
        match_id,
        game_addr,
        ledger_path,
        stop,
        task: Some(task),
    })
}
