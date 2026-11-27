//! End-to-end smoke test of the unified Fair-Play Protocol v1 stack:
//! - Real `fppd serve --no-witness` + separate `fppd role witness` processes
//! - Headless reference game server joined via shared `fpp::gs_link::GsLink`
//! - Unattested client refused from `verified` queue (D2 floor)
//! - Client with ES256 (P-256) session key plays 3 epochs, verifies every
//!   Checkpoint head against the Transparency Log (Ed25519 + ML-DSA-65 +
//!   external witness cosignature + Merkle inclusion proof)
//! - Authorized auditor reads back the match's Checkpoints from the Evidence
//!   Store over Noise_IK TCP and verifies an unbroken hash chain
//! - Match JSONL ledger check
//! - Failure-domain check: Verifier + Broker keep serving when Liveness is down

use anyhow::{ensure, Context, Result};
use fpp::crypto::{self, Ed25519Signer, P256Signer};
use fpp::types::{DeviceTier, Digest, Reason};
use fpp::wire::{cose, Checkpoint, Payload};
use fpp_sim::client::{
    request_admission, request_admission_with, ClientEvent, ClientTrust, GameClient, Services,
    SessionEnd,
};
use fpp_sim::game_wire::ClientCmd;
use fpp_sim::harness::TestCell;
use fpp_sim::server::{spawn_server, ServerConfig};
use fpp_sim::transparency;
use fppd::broker::{BrokerRole, Placer};
use fppd::verifier::{ClientAttestation, VerifierRole};
use fppd::{rpc_evidence_get, rpc_evidence_list, Authority};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;

async fn admit_retry(
    services: &Services,
    trust: &ClientTrust,
    queue: &str,
    session: Option<Box<dyn fpp::crypto::SessionSigner + Send + Sync>>,
) -> Result<fpp_sim::client::Credentials> {
    let mut session = session;
    for _ in 0..40 {
        let res = match session.take() {
            Some(s) => {
                // On retry, mint a fresh P-256 key if needed.
                let r = request_admission_with(services, trust, queue, s).await;
                if r.is_err() {
                    session = Some(Box::new(P256Signer::generate()));
                }
                r
            }
            None => request_admission(services, trust, queue).await,
        };
        match res {
            Ok(c) => return Ok(c),
            Err(e)
                if matches!(
                    e.downcast_ref::<SessionEnd>(),
                    Some(SessionEnd::Refused(c)) if *c == Reason::ServerDraining as u16
                ) =>
            {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            Err(e) => return Err(e),
        }
    }
    anyhow::bail!("timed out waiting for a live game server")
}

async fn run() -> Result<()> {
    println!("[SMOKE] starting fppd serve (--no-witness) + standalone fppd role witness");
    let cell = TestCell::start("smoke", true, &[])?;
    let trust = ClientTrust::from_bundle(cell.bundle.clone());
    let services = Services::single(cell.addr);

    let ledger_dir = cell.dir.join("ledger");
    let gs = spawn_server(ServerConfig {
        liveness: cell.addr,
        bundle: cell.bundle.clone(),
        game_bind: "127.0.0.1:0".parse()?,
        gs_id: "smoke-gs".into(),
        min_tier: DeviceTier::D0Unknown,
        equivocate_from: None,
        ignore_revocations: false,
        ledger_dir: Some(ledger_dir),
    })
    .await?;
    let match_id = gs.match_id.0;
    let ledger_path = gs.ledger_path.clone().context("ledger path")?;

    // 1) Unattested client MUST be refused the `verified` queue (tier floor D2).
    match request_admission(&services, &trust, "verified").await {
        Err(e)
            if matches!(
                e.downcast_ref::<SessionEnd>(),
                Some(SessionEnd::Refused(c)) if *c == Reason::TierInsufficient as u16
            ) =>
        {
            println!("[SMOKE] verified queue refused unattested client (TierInsufficient): OK");
        }
        other => anyhow::bail!(
            "expected TierInsufficient on verified queue, got {:?}",
            other.err()
        ),
    }

    // 2) Client with ES256 (P-256) session key joins `open` and plays through >= 3 epochs.
    let creds = admit_retry(
        &services,
        &trust,
        "open",
        Some(Box::new(P256Signer::generate())),
    )
    .await?;
    let mut client = GameClient::connect(creds, &trust, Duration::from_secs(10)).await?;
    let mut snapshots = 0usize;
    let mut x = 0.0f32;
    let deadline = Instant::now() + Duration::from_secs(15);
    while client.heads.len() < 3 {
        ensure!(
            Instant::now() < deadline,
            "did not receive 3 Checkpoint heads"
        );
        for ev in client.step(&ClientCmd::Move { dx: 2.0, dy: 0.0 }).await? {
            if let ClientEvent::Snapshot(s) = ev {
                snapshots += 1;
                x = s.you.0;
            }
        }
    }
    ensure!(snapshots > 10 && x > 10.0, "snapshots={snapshots}, x={x}");
    let heads = client.heads.clone();
    client.bye().await?;
    println!(
        "[SMOKE] P-256 client played ({snapshots} snapshots, x={x:.1}, {} Checkpoint heads)",
        heads.len()
    );

    // 3) Player verifies every Checkpoint head against Transparency Log (Ed25519 + ML-DSA-65 + external witness).
    let audit = transparency::audit(
        &trust,
        services.log,
        services.liveness,
        match_id,
        &heads,
        Instant::now() + Duration::from_secs(15),
    )
    .await?;
    ensure!(
        audit.included == heads.len() && audit.pending.is_empty() && audit.split_views.is_empty(),
        "transparency audit failed: {audit:?}"
    );
    println!(
        "[SMOKE] Transparency Log gossip verified {} heads (Ed25519 + ML-DSA-65 + external witness)",
        audit.included
    );

    // 4) Stop GS and verify match ledger has JSON Move line.
    gs.stop();
    gs.wait().await;
    let body = std::fs::read_to_string(&ledger_path).context("read ledger")?;
    let last = body
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .context("empty ledger")?;
    ensure!(
        last.starts_with('{') && last.ends_with('}') && last.contains("\"op\":\"Move\""),
        "unexpected ledger line: {last}"
    );
    println!("[SMOKE] ledger OK: {}", ledger_path.display());

    // 5) Auditor reads back all Checkpoints from Evidence Store over Noise_IK TCP and verifies chain.
    let admin = cell.admin_key()?;
    let digests =
        rpc_evidence_list(cell.addr, &cell.bundle.transport_pub, &admin, match_id).await?;
    ensure!(
        digests.len() >= 3,
        "expected >=3 Checkpoints, got {}",
        digests.len()
    );
    let mut prev = Digest::default();
    for (epoch, d) in digests.iter().enumerate() {
        let cose = rpc_evidence_get(cell.addr, &cell.bundle.transport_pub, &admin, *d)
            .await?
            .context("listed digest missing")?;
        let cp = Checkpoint::from_cbor(&cose::Sign1::decode(&cose)?.payload)?;
        ensure!(cp.match_id.0 == match_id, "Checkpoint of another match");
        ensure!(
            cp.epoch as usize == epoch && cp.prev == prev,
            "broken Checkpoint chain at epoch {epoch}"
        );
        prev = crypto::object_digest(&cose);
    }
    println!(
        "[SMOKE] Evidence Store OK: {} Checkpoints verified as one unbroken hash chain",
        digests.len()
    );

    // 6) Failure domain check: Verifier + Broker serving when remote Liveness is unreachable.
    let dead_liveness: std::net::SocketAddr = fpp_sim::harness::pick_free_port()?;
    let ver_sk = fppd::keys::load_ed25519(&cell.cell_dir(), "verifier")?;
    let brk_sk = fppd::keys::load_ed25519(&cell.cell_dir(), "broker")?;
    let transport = fpp::session::StaticKeypair::generate();
    let mut isolated_bundle = cell.bundle.clone();
    isolated_bundle.transport_pub = transport.public;
    let isolated_auth = Arc::new(Authority {
        transport: transport.clone(),
        admin_keys: vec![],
        deadline: Duration::from_secs(5),
        liveness: None,
        verifier: Some(Arc::new(VerifierRole {
            key: Ed25519Signer::new(ver_sk.clone()),
            did_key: [0x22; 32],
            policy: fppd::policy::AuthorityPolicy::default(),
            attestation: ClientAttestation::default(),
            deadline: Duration::from_secs(5),
        })),
        broker: Some(BrokerRole::new(
            Ed25519Signer::new(brk_sk),
            ver_sk.verifying_key(),
            Placer::Remote {
                addr: dead_liveness,
                server_pub: [0x11; 32],
                client_kp: transport,
            },
            None,
        )),
        revocation: None,
        evidence: None,
        log: None,
    });
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let iso_addr = listener.local_addr()?;
    let srv = tokio::spawn(async move { isolated_auth.serve(listener).await });
    let iso_trust = ClientTrust::from_bundle(isolated_bundle);
    let iso_services = Services::single(iso_addr);
    match request_admission(&iso_services, &iso_trust, "open").await {
        Err(e)
            if matches!(
                e.downcast_ref::<SessionEnd>(),
                Some(SessionEnd::Refused(c)) if *c == Reason::ServerDraining as u16
            ) =>
        {
            println!("[SMOKE] failure-domain check OK: Verifier+Broker answer cleanly when Liveness is down");
        }
        other => anyhow::bail!(
            "expected ServerDraining with Liveness down, got {:?}",
            other.err()
        ),
    }
    srv.abort();
    drop(cell);
    println!("[SMOKE] ALL CHECKS PASSED");
    Ok(())
}

fn main() -> Result<()> {
    tokio::runtime::Runtime::new()?.block_on(run())
}
