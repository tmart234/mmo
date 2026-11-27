//! P2 revocation exit tests end-to-end against real `fppd`:
//! 1. Revocation -> kick: N players (default 32) on an honest GS; Enforcement
//!    kicks each by session key; p99 latency <= 5s (ENF-03).
//! 2. Denied admission: account denied by Enforcement is refused by Broker.
//! 3. SAR lapse: rogue GS ignoring revocations is revoked as an instance;
//!    Server Liveness stops its SARs and players drop on their own within one
//!    SAR lifetime (10s).

use anyhow::{bail, ensure, Context, Result};
use fpp::crypto::{session_key_id, Ed25519Signer};
use fpp::types::{DeviceTier, Reason};
use fpp::wire::{Action, Scope, SubjectKind};
use fpp_sim::client::{
    request_admission, request_admission_with, ClientTrust, GameClient, Services, SessionEnd,
};
use fpp_sim::game_wire::ClientCmd;
use fpp_sim::harness::TestCell;
use fpp_sim::server::{spawn_server, ServerConfig};
use fppd::broker::account_of;
use fppd::revocation::Order;
use fppd::rpc_enforce;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

const ENFORCEMENT_P99: Duration = Duration::from_secs(5);
const SAR_LIFETIME: Duration = Duration::from_secs(10);

async fn join(
    services: &Services,
    trust: &ClientTrust,
) -> Result<(GameClient, [u8; 32], [u8; 32])> {
    let mut tries = 0;
    let creds = loop {
        tries += 1;
        match request_admission(services, trust, "open").await {
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
    let session = session_key_id(&creds.session.session_key());
    let aud = creds.sat_claims.aud.0;
    let client = GameClient::connect(creds, trust, Duration::from_secs(10)).await?;
    Ok((client, session, aud))
}

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
    let cell = TestCell::start("revocation-load", false, &[])?;
    let trust = ClientTrust::from_bundle(cell.bundle.clone());
    let services = Services::single(cell.addr);
    let admin = cell.admin_key()?;
    let enf = cell.enforcement_signer()?;
    let pub_key = cell.bundle.transport_pub;

    // ---- 1. revocation -> kick
    let honest = spawn_server(ServerConfig {
        liveness: cell.addr,
        bundle: cell.bundle.clone(),
        game_bind: "127.0.0.1:0".parse()?,
        gs_id: "honest-gs".into(),
        min_tier: DeviceTier::D0Unknown,
        equivocate_from: None,
        ignore_revocations: false,
        ledger_dir: None,
    })
    .await?;

    let (ended_tx, mut ended) = mpsc::unbounded_channel();
    let mut sessions = Vec::new();
    let mut honest_instance = [0u8; 32];
    for i in 0..players {
        let (client, session, aud) = join(&services, &trust)
            .await
            .with_context(|| format!("player {i}"))?;
        honest_instance = aud;
        sessions.push(session);
        play(client, i, ended_tx.clone());
    }
    println!("[LOAD] {players} players on honest GS; kicking each");
    tokio::time::sleep(Duration::from_millis(500)).await;

    let mut started = vec![None; players];
    for (i, s) in sessions.iter().enumerate() {
        started[i] = Some(Instant::now());
        rpc_enforce(
            cell.addr,
            &pub_key,
            &admin,
            &enf,
            &order(SubjectKind::Session, s, Action::Kick, "load test"),
        )
        .await?;
        tokio::time::sleep(Duration::from_millis(40)).await;
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
        latencies.push(at - started[i].context("kicked before order")?);
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

    // ---- 2. denied admission at Broker
    let seed = [0x5au8; 32];
    let key = || Ed25519Signer::new(ed25519_dalek::SigningKey::from_bytes(&seed));
    let account = account_of(&fpp::crypto::SessionSigner::session_key(&key()));
    rpc_enforce(
        cell.addr,
        &pub_key,
        &admin,
        &enf,
        &order(
            SubjectKind::Account,
            &account,
            Action::DenyAdmission,
            "load test: denied account",
        ),
    )
    .await?;
    let deadline = Instant::now() + ENFORCEMENT_P99;
    let end = loop {
        let r = request_admission_with(&services, &trust, "open", Box::new(key())).await;
        let end = r
            .err()
            .and_then(|e| e.downcast_ref::<SessionEnd>().copied());
        if end == Some(SessionEnd::Refused(Reason::Revoked as u16)) || Instant::now() > deadline {
            break end;
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    };
    ensure!(
        end == Some(SessionEnd::Refused(Reason::Revoked as u16)),
        "denied account was not refused: {end:?}"
    );
    println!("[LOAD] denied account refused by Broker: OK");

    // Retire honest GS
    rpc_enforce(
        cell.addr,
        &pub_key,
        &admin,
        &enf,
        &order(
            SubjectKind::GsInstance,
            &honest_instance,
            Action::Kick,
            "retire",
        ),
    )
    .await?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    drop(honest);

    // ---- 3. SAR lapse: rogue GS ignores its revocation
    let _rogue = spawn_server(ServerConfig {
        liveness: cell.addr,
        bundle: cell.bundle.clone(),
        game_bind: "127.0.0.1:0".parse()?,
        gs_id: "rogue-gs".into(),
        min_tier: DeviceTier::D0Unknown,
        equivocate_from: None,
        ignore_revocations: true,
        ledger_dir: None,
    })
    .await?;

    let rogue_players = players.min(8);
    let (ended_tx, mut ended) = mpsc::unbounded_channel();
    let mut rogue_instance = [0u8; 32];
    for i in 0..rogue_players {
        let (client, _, aud) = join(&services, &trust).await?;
        ensure!(aud != honest_instance, "placed on retired server");
        rogue_instance = aud;
        play(client, i, ended_tx.clone());
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    let revoked_at = Instant::now();
    rpc_enforce(
        cell.addr,
        &pub_key,
        &admin,
        &enf,
        &order(
            SubjectKind::GsInstance,
            &rogue_instance,
            Action::Kick,
            "rogue GS",
        ),
    )
    .await?;

    let mut worst = Duration::ZERO;
    for _ in 0..rogue_players {
        let Ok(Some((i, end, at))) = tokio::time::timeout(SAR_LIFETIME * 2, ended.recv()).await
        else {
            bail!("players of rogue GS kept playing");
        };
        ensure!(
            end == SessionEnd::SarLapsed,
            "rogue player {i} ended with {end:?}"
        );
        worst = worst.max(at - revoked_at);
    }
    println!(
        "[LOAD] rogue GS ignoring its revocation: all {rogue_players} players lapsed within {worst:?}"
    );
    ensure!(
        worst <= SAR_LIFETIME,
        "{worst:?} > one SAR lifetime ({SAR_LIFETIME:?})"
    );
    drop(cell);
    println!("[LOAD] revocation exit tests passed");
    Ok(())
}

fn main() -> Result<()> {
    let players = std::env::var("REVOCATION_LOAD_PLAYERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(32);
    tokio::runtime::Runtime::new()?.block_on(run(players))
}
