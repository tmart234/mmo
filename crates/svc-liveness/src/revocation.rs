//! Following the Revocation Feed (04 §9). A revoked game server instance
//! gets no more SARs: it and its players lapse within one SAR lifetime even
//! if it ignores everything else. Every event also goes to every game
//! server here, which checks the Enforcement signature and removes the
//! players it names (a GS must, within 5 s p99: ENF-03).

use common::framing::send_msg;
use common::proto::ToGameServer;
use fpp_crypto::{KeyRole, KeySet};
use fpp_tokens::instance_id;
use fpp_wire::{RevocationEvent, SubjectKind};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use crate::ctx::Ctx;

fn now_s() -> u64 {
    common::crypto::now_ms() / 1000
}

/// Push one event to one game server.
pub fn push(conn: &quinn::Connection, signed: Vec<u8>) {
    let conn = conn.clone();
    tokio::spawn(async move {
        let sent = async {
            let mut uni = conn.open_uni().await?;
            send_msg(&mut uni, &ToGameServer::Revocation(signed)).await
        };
        if let Err(e) = sent.await {
            eprintln!("[liveness] revocation push failed: {e:#}");
        }
    });
}

/// Apply one verified event (if it covers this region).
pub fn apply(ctx: &Ctx, event: RevocationEvent, signed: Vec<u8>) {
    if event.expires_at.is_some_and(|e| e <= now_s())
        || !event.scope.covers(Some(crate::liveness::REGION), None)
    {
        return;
    }
    if event.subject_kind == SubjectKind::GsInstance
        && (event.action.removes_players() || event.action.denies_admission())
    {
        let revoked: Vec<[u8; 16]> = ctx
            .sessions
            .iter()
            .filter(|s| instance_id(&s.instance_pub).0.as_slice() == event.subject_id)
            .map(|s| *s.key())
            .collect();
        for id in revoked {
            ctx.revoke(&id, &format!("revoked by Enforcement ({:?})", event.action));
        }
    }
    ctx.links.retain(|_, c| c.close_reason().is_none());
    for link in ctx.links.iter() {
        push(link.value(), signed.clone());
    }
    ctx.revocations
        .lock()
        .expect("revocations lock")
        .push((event, signed));
}

/// Events still in force, for a game server that just joined.
pub fn in_force(ctx: &Ctx) -> Vec<Vec<u8>> {
    let now = now_s();
    let mut all = ctx.revocations.lock().expect("revocations lock");
    all.retain(|(e, _)| e.expires_at.is_none_or(|x| x > now));
    all.iter().map(|(_, s)| s.clone()).collect()
}

/// Follow the feed at `feed` as this service, once Enforcement's key is
/// published in `cell`.
pub async fn follow(ctx: Ctx, cell: PathBuf, identity: fpp_svc::Identity, feed: SocketAddr) {
    let key = loop {
        match fpp_svc::PublicKeys::read(&cell, "enforcement")
            .ok()
            .and_then(|p| ed25519_dalek::VerifyingKey::from_bytes(&p.ed25519).ok())
        {
            Some(k) => break k,
            None => tokio::time::sleep(Duration::from_secs(1)).await,
        }
    };
    let mut keys = KeySet::default();
    keys.insert_ed25519(KeyRole::Enforcement, key);
    fpp_svc::follow::follow(identity, feed, keys, move |event, signed| {
        apply(&ctx, event, signed)
    })
    .await
}
