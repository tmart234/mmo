//! fpp-enforce: act on a subject, as Enforcement.
//!
//!     fpp-enforce init
//!     fpp-enforce kick session:<hex> [--reason 11] [--for 3600] [--note "..."]
//!     fpp-enforce deny-admission account:<hex>
//!     fpp-enforce ban device:<hex>
//!     fpp-enforce kick gs:<hex>            (a game server instance)
//!
//! Subjects: account, device, session, sat, gs, build (hex ids: 16 bytes
//! for a sat, 32 for the others).

use anyhow::{anyhow, bail, Result};
use clap::{Parser, Subcommand};
use fpp_wire::{Action, Scope, SubjectKind};
use std::path::PathBuf;
use svc_revocation::enforce::{Enforcer, Order};

#[derive(Parser)]
struct Opts {
    /// Cell directory: the Enforcement key is in `<cell>/enforcement/`.
    #[arg(long, default_value = "cell", global = true)]
    cell: PathBuf,
    /// The Revocation Feed.
    #[arg(long, default_value = "127.0.0.1:4460", global = true)]
    feed: std::net::SocketAddr,
    /// The Transparency Log, for the enforcement record.
    #[arg(long, global = true)]
    log: Option<std::net::SocketAddr>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(clap::Args)]
struct Act {
    /// `kind:hex`
    subject: String,
    /// `fpp_types::Reason` code (default: policy kick).
    #[arg(long, default_value_t = fpp_types::Reason::PolicyKick as u16)]
    reason: u16,
    /// Seconds it lasts (default: indefinitely).
    #[arg(long = "for")]
    duration_s: Option<u64>,
    /// Only in these regions.
    #[arg(long, value_delimiter = ',')]
    regions: Vec<String>,
    #[arg(long, default_value = "")]
    note: String,
}

#[derive(Subcommand)]
enum Cmd {
    /// Make the Enforcement key and publish its public half.
    Init,
    Kick(Act),
    DenyAdmission(Act),
    Suspend(Act),
    Ban(Act),
}

fn subject(s: &str) -> Result<(SubjectKind, Vec<u8>)> {
    let (kind, id) = s
        .split_once(':')
        .ok_or_else(|| anyhow!("subject is kind:hex"))?;
    let kind = match kind {
        "account" => SubjectKind::Account,
        "device" => SubjectKind::Device,
        "session" => SubjectKind::Session,
        "sat" => SubjectKind::Sat,
        "gs" => SubjectKind::GsInstance,
        "build" => SubjectKind::Build,
        other => bail!("unknown subject kind {other}"),
    };
    Ok((kind, hex::decode(id)?))
}

#[tokio::main]
async fn main() -> Result<()> {
    let o = Opts::parse();
    let (action, act) = match o.cmd {
        Cmd::Init => {
            let key = Enforcer::init(&o.cell)?;
            println!("enforcement key {}", hex::encode(key.to_bytes()));
            return Ok(());
        }
        Cmd::Kick(a) => (Action::Kick, a),
        Cmd::DenyAdmission(a) => (Action::DenyAdmission, a),
        Cmd::Suspend(a) => (Action::Suspend, a),
        Cmd::Ban(a) => (Action::Ban, a),
    };
    let (subject_kind, subject_id) = subject(&act.subject)?;
    let enforcer = Enforcer::open(&o.cell, o.feed, o.log)?;
    let done = enforcer
        .enforce(Order {
            subject_kind,
            subject_id,
            action,
            scope: Scope {
                regions: act.regions,
                ..Scope::default()
            },
            reason: act.reason,
            duration_s: act.duration_s,
            note: act.note,
        })
        .await?;
    println!(
        "published #{}: {:?} {:?}; record {}{}",
        done.seq,
        done.event.action,
        done.event.subject_kind,
        hex::encode(done.event.record.0),
        done.record_index
            .map(|i| format!(" (log index {i})"))
            .unwrap_or_default()
    );
    Ok(())
}
