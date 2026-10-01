// P2's exit tests for revocation (docs/anticheat/07 §4), end to end on a
// dev cell of separate processes:
//
// 1. revocation -> kick: N players on an honest game server; Enforcement
//    kicks each by session key, one after another. Every kick must reach
//    its player within 5 s p99 (ENF-03), measured from the moment
//    Enforcement starts (record logged, event signed, published, relayed
//    by Server Liveness, applied by the GS, delivered to the client).
// 2. denied admission: an account Enforcement denied is refused by the
//    Broker.
// 3. SAR lapse: a rogue game server that ignores revocation events
//    (`gs-sim --ignore-revocations`) is revoked as an instance; Server
//    Liveness stops its SARs, and its players drop on their own within one
//    SAR lifetime.
//
// Options: REVOCATION_LOAD_PLAYERS (default 32), LOAD_PROFILE (the build
// to run, default debug), and tools::cell's SMOKE_BIN_DIR / SMOKE_WRAPPER /
// SMOKE_STARTUP_MS.

use anyhow::{bail, ensure, Context, Result};
use client_core::{
    request_admission, request_admission_with, ClientTrust, GameClient, Services, SessionEnd,
};
use common::proto::ClientCmd;
use fpp_types::Reason;
use fpp_wire::{Action, Scope, SubjectKind};
use std::process::{Child, Command};
use std::time::{Duration, Instant};
use svc_revocation::enforce::{Enforcer, Order};
use tokio::sync::mpsc;
use tools::cell::{bin_path, ensure_dev_keys, Cell, Launch, CELL_DIR, FEED_ADDR, LOG_ADDR};

/// Which build of the binaries to run (`LOAD_PROFILE`, default debug).
fn profile() -> String {
    std::env::var("LOAD_PROFILE").unwrap_or_else(|_| "debug".into())
}

const ENFORCEMENT_P99: Duration = Duration::from_secs(5);
/// One SAR lifetime (svc-liveness issues `exp = iat + 10 s`).
const SAR_LIFETIME: Duration = Duration::from_secs(10);

struct Gs(Child);

impl Drop for Gs {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start_gs(game_addr: &str, rogue: bool) -> Result<Gs> {
    let mut cmd = Command::new(bin_path("gs-sim", &profile()));
    cmd.args(["--liveness", "127.0.0.1:4444", "--game-addr", game_addr]);
    if rogue {
        cmd.arg("--ignore-revocations");
    }
    Ok(Gs(cmd.spawn().context("spawn gs-sim")?))
}

/// Admit a player (retrying while the GS joins and checkpoints) and join.
async fn join(trust: &ClientTrust) -> Result<(GameClient, [u8; 32], [u8; 32])> {
    let services = Services::default();
    let mut tries = 0;
    let creds = loop {
        tries += 1;
        match request_admission(&services, trust, "open").await {
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
    let session = fpp_crypto::session_key_id(&creds.session.session_key());
    let aud = creds.sat_claims.aud.0;
    let client = GameClient::connect(creds, trust, Duration::from_secs(10)).await?;
    Ok((client, session, aud))
}

/// Play until the session ends; report how and when.
fn play(
    mut c: GameClient,
    index: usize,
    ended: mpsc::UnboundedSender<(usize, SessionEnd, Instant)>,
) {
    tokio::spawn(async move {
        loop {
            if let Err(e) = c.step(&ClientCmd::Move { dx: 0.1, dy: 0.0 }).await {
                let end = e
                    .downcast_ref::<SessionEnd>()
                    .copied()
                    .unwrap_or(SessionEnd::Kicked(0));
                let _ = ended.send((index, end, Instant::now()));
                return;
            }
        }
    });
}

fn order(kind: SubjectKind, id: &[u8], action: Action, note: &str) -> Order {
    Order {
        subject_kind: kind,
        subject_id: id.to_vec(),
        action,
        scope: Scope::default(),
        reason: Reason::PolicyKick as u16,
        duration_s: Some(3600),
        note: note.into(),
    }
}

fn percentile(sorted: &[Duration], p: f64) -> Duration {
    let i = ((sorted.len() as f64 * p).ceil() as usize).clamp(1, sorted.len()) - 1;
    sorted[i]
}

async fn run(players: usize) -> Result<()> {
    let trust = ClientTrust::load_default()?;
    let enforcer = Enforcer::open(
        std::path::Path::new(CELL_DIR),
        FEED_ADDR.parse()?,
        Some(LOG_ADDR.parse()?),
    )?;

    // ---- 1. revocation -> kick
    let honest = start_gs("127.0.0.1:50010", false)?;
    let (ended_tx, mut ended) = mpsc::unbounded_channel();
    let mut sessions = Vec::new();
    let mut honest_instance = [0u8; 32];
    for i in 0..players {
        let (client, session, aud) = join(&trust).await.with_context(|| format!("player {i}"))?;
        honest_instance = aud;
        sessions.push(session);
        play(client, i, ended_tx.clone());
    }
    println!("[LOAD] {players} players on the honest GS; kicking each");
    tokio::time::sleep(Duration::from_secs(1)).await;
    let mut started = vec![None; players];
    for (i, s) in sessions.iter().enumerate() {
        started[i] = Some(Instant::now());
        enforcer
            .enforce(order(SubjectKind::Session, s, Action::Kick, "load test"))
            .await?;
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let mut latencies = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(30);
    while latencies.len() < players {
        let Ok(Some((i, end, at))) = tokio::time::timeout_at(deadline.into(), ended.recv()).await
        else {
            bail!("only {} of {players} players were kicked", latencies.len());
        };
        ensure!(
            end == SessionEnd::Kicked(Reason::PolicyKick as u16),
            "player {i} ended with {end:?}"
        );
        latencies.push(at - started[i].context("kicked before its order")?);
    }
    latencies.sort();
    let (p50, p99, max) = (
        percentile(&latencies, 0.50),
        percentile(&latencies, 0.99),
        *latencies.last().expect("players > 0"),
    );
    println!(
        "[LOAD] revocation -> kick over {players} players: p50 {p50:?}, p99 {p99:?}, max {max:?}"
    );
    ensure!(p99 <= ENFORCEMENT_P99, "p99 {p99:?} > {ENFORCEMENT_P99:?}");

    // ---- 2. denied admission at the Broker (the dev account id is derived
    //      from the session key, so the same key is the same account)
    let seed = [0x5au8; 32];
    let key = || fpp_crypto::Ed25519Signer::new(ed25519_dalek::SigningKey::from_bytes(&seed));
    let account = dev_account(&key().verifying_key().to_bytes());
    enforcer
        .enforce(order(
            SubjectKind::Account,
            &account,
            Action::DenyAdmission,
            "load test: denied account",
        ))
        .await?;
    let refused = async {
        let deadline = Instant::now() + ENFORCEMENT_P99;
        loop {
            let r =
                request_admission_with(&Services::default(), &trust, "open", Box::new(key())).await;
            let end = r
                .err()
                .and_then(|e| e.downcast_ref::<SessionEnd>().copied());
            if end == Some(SessionEnd::Refused(Reason::Revoked as u16)) || Instant::now() > deadline
            {
                return end;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    };
    let end = refused.await;
    ensure!(
        end == Some(SessionEnd::Refused(Reason::Revoked as u16)),
        "a denied account was not refused: {end:?}"
    );
    println!("[LOAD] a denied account is refused by the Broker");

    // The honest GS is retired as an instance (it obeys and ends its match).
    enforcer
        .enforce(order(
            SubjectKind::GsInstance,
            &honest_instance,
            Action::Kick,
            "retire",
        ))
        .await?;
    tokio::time::sleep(Duration::from_secs(1)).await;
    drop(honest);

    // ---- 3. SAR lapse: a rogue GS ignores its revocation
    let _rogue = start_gs("127.0.0.1:50011", true)?;
    let rogue_players = players.min(8);
    let (ended_tx, mut ended) = mpsc::unbounded_channel();
    let mut rogue_instance = [0u8; 32];
    for i in 0..rogue_players {
        let (client, _, aud) = join(&trust).await?;
        ensure!(aud != honest_instance, "placed on the retired server");
        rogue_instance = aud;
        play(client, i, ended_tx.clone());
    }
    tokio::time::sleep(Duration::from_secs(1)).await;
    let revoked_at = Instant::now();
    enforcer
        .enforce(order(
            SubjectKind::GsInstance,
            &rogue_instance,
            Action::Kick,
            "rogue GS",
        ))
        .await?;
    let mut worst = Duration::ZERO;
    for _ in 0..rogue_players {
        let Ok(Some((i, end, at))) = tokio::time::timeout(SAR_LIFETIME * 2, ended.recv()).await
        else {
            bail!("players of the rogue GS kept playing");
        };
        ensure!(
            end == SessionEnd::SarLapsed,
            "rogue player {i} ended with {end:?}"
        );
        worst = worst.max(at - revoked_at);
    }
    println!("[LOAD] rogue GS ignoring its revocation: all {rogue_players} players lapsed within {worst:?}");
    ensure!(
        worst <= SAR_LIFETIME,
        "{worst:?} > one SAR lifetime ({SAR_LIFETIME:?})"
    );
    Ok(())
}

/// The Broker's dev account id for a session key (`svc_broker::account_of`).
fn dev_account(session: &[u8; 32]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"mmo/dev-acct");
    h.update([0]);
    h.update(session);
    h.finalize().into()
}

fn main() -> Result<()> {
    let players = std::env::var("REVOCATION_LOAD_PLAYERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(32);
    ensure_dev_keys()?;
    let cell = Cell::start(&Launch::from_env(&profile()))?;
    let result = tokio::runtime::Runtime::new()?.block_on(run(players));
    drop(cell);
    match &result {
        Ok(()) => println!("[LOAD] revocation exit tests passed"),
        Err(e) => println!("[LOAD] FAILED: {e:#}"),
    }
    result
}
