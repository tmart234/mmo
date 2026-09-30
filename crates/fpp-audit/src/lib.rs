//! Audits the evidence of a player-hosted match (milestone M4, the
//! accounting audit; 04-protocol.md §8.5).
//!
//! A game writes one *bundle* per machine per match (the Halo fork's
//! `port/linux/src/p2p_evidence.c`): the player's own frames and signed
//! InputCommits and every Checkpoint package the host sent it, or the host's
//! received frames, the players' commits and its own Checkpoints. From a
//! single player's bundle this proves, without trusting the host:
//!
//! - its commits are its own, chained, and cover exactly its frames;
//! - the host's Checkpoints verify under the instance key the session's
//!   handshake announced, are chained, and their roots match their leaves;
//! - the host **acknowledged** each commit (its digest is in the Checkpoint of
//!   its epoch) and marked every frame applied (frames go on the reliable
//!   channel, so none may be "lost");
//! - the host **accounted** for every unit (a hit report) of every frame:
//!   each has an outcome event, applied or rejected with a reason.
//!
//! Given several bundles of one match, it also finds **equivocation**: two
//! players shown different Checkpoints for the same epoch.
//!
//! What it cannot show without replaying the game (the title's engine and
//! its data): that an outcome is *true* — a host that records a hit as
//! dealt and does not deal it, or rejects it for a false reason.

use ed25519_dalek::VerifyingKey;
use fpp_crypto::{KeyRole, KeySet};
use fpp_types::Digest;
use fpp_wire::{Checkpoint, InputCommit, InputLeaf};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;

pub const MAGIC: &[u8] = b"FPPB1\n";

pub const RECORD_META: u8 = 1;
pub const RECORD_FRAME: u8 = 2;
pub const RECORD_COMMIT: u8 = 3;
pub const RECORD_CHECKPOINT: u8 = 4;
pub const RECORD_RECEIVED_FRAME: u8 = 5;
pub const RECORD_ROSTER: u8 = 6;

pub const ROLE_HOST: u8 = 1;
pub const ROLE_PLAYER: u8 = 2;

/// An outcome event (04 §8.5): `'O' ‖ slot:u16 ‖ tick:u32 ‖ unit:u16 ‖ outcome:u8 ‖ reason:u8`.
pub const EVENT_OUTCOME: u8 = b'O';
pub const EVENT_SIZE: usize = 11;
pub const OUTCOME_APPLIED: u8 = 1;
pub const OUTCOME_REJECTED: u8 = 2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Meta {
    pub role: u8,
    pub match_id: [u8; 16],
    pub slot: u16,
    pub session_key: [u8; 32],
    pub instance_key: [u8; 32],
    pub epoch_ticks: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Leaf {
    pub slot: u16,
    pub commit: Option<[u8; 32]>,
    pub applied: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub slot: u16,
    pub tick: u32,
    pub unit: u16,
    pub outcome: u8,
    pub reason: u8,
}

/// A Checkpoint as the host sent it: the signed object and its leaves.
#[derive(Clone, Debug)]
pub struct Package {
    pub object: Vec<u8>,
    pub leaves: Vec<Leaf>,
    pub events: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Default)]
pub struct Bundle {
    pub meta: Option<Meta>,
    /// A player's own frames: (tick, payload).
    pub frames: Vec<(u32, Vec<u8>)>,
    pub commits: Vec<Vec<u8>>,
    pub checkpoints: Vec<Package>,
    /// The host's received frames: (slot, tick, payload).
    pub received: Vec<(u16, u32, Vec<u8>)>,
    /// The host's players: (slot, session key).
    pub roster: Vec<(u16, [u8; 32])>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParseError {
    Magic,
    Truncated,
    Record(u8),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Magic => write!(f, "not an evidence bundle"),
            ParseError::Truncated => write!(f, "truncated"),
            ParseError::Record(t) => write!(f, "malformed record of type {t}"),
        }
    }
}

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn fixed<const N: usize>(b: &[u8]) -> [u8; N] {
    b[..N].try_into().expect("length checked")
}

/// A Checkpoint package: `len:u32 ‖ signed ‖ n:u16 ‖ n × (slot:u16 ‖ acked:u8 ‖
/// digest:32 ‖ applied) ‖ m:u16 ‖ m × event`, with `applied` of
/// `ceil(epoch_ticks / 8)` bytes and events of [`EVENT_SIZE`].
pub fn parse_package(b: &[u8], epoch_ticks: u32) -> Option<Package> {
    let applied_size = epoch_ticks.div_ceil(8) as usize;
    let len = u32_at(b.get(..4)?, 0) as usize;
    let object = b.get(4..4 + len)?.to_vec();
    let mut at = 4 + len;
    let n = u16_at(b.get(at..at + 2)?, 0) as usize;
    at += 2;
    let mut leaves = Vec::with_capacity(n);
    for _ in 0..n {
        let leaf = b.get(at..at + 35 + applied_size)?;
        leaves.push(Leaf {
            slot: u16_at(leaf, 0),
            commit: (leaf[2] != 0).then(|| fixed(&leaf[3..35])),
            applied: leaf[35..].to_vec(),
        });
        at += 35 + applied_size;
    }
    let m = u16_at(b.get(at..at + 2)?, 0) as usize;
    at += 2;
    let mut events = Vec::with_capacity(m);
    for _ in 0..m {
        events.push(b.get(at..at + EVENT_SIZE)?.to_vec());
        at += EVENT_SIZE;
    }
    (at == b.len()).then_some(Package {
        object,
        leaves,
        events,
    })
}

pub fn parse_outcome(event: &[u8]) -> Option<Outcome> {
    (event.len() == EVENT_SIZE && event[0] == EVENT_OUTCOME).then(|| Outcome {
        slot: u16_at(event, 1),
        tick: u32_at(event, 3),
        unit: u16_at(event, 7),
        outcome: event[9],
        reason: event[10],
    })
}

pub fn parse(bytes: &[u8]) -> Result<Bundle, ParseError> {
    let rest = bytes.strip_prefix(MAGIC).ok_or(ParseError::Magic)?;
    let mut bundle = Bundle::default();
    let mut at = 0;
    while at < rest.len() {
        let header = rest.get(at..at + 5).ok_or(ParseError::Truncated)?;
        let (kind, len) = (header[0], u32_at(header, 1) as usize);
        let body = rest
            .get(at + 5..at + 5 + len)
            .ok_or(ParseError::Truncated)?;
        at += 5 + len;
        let bad = || ParseError::Record(kind);
        match kind {
            RECORD_META => {
                if body.len() < 88 || body[0] != 1 {
                    return Err(bad());
                }
                bundle.meta = Some(Meta {
                    role: body[1],
                    match_id: fixed(&body[2..18]),
                    slot: u16_at(body, 18),
                    session_key: fixed(&body[20..52]),
                    instance_key: fixed(&body[52..84]),
                    epoch_ticks: u32_at(body, 84),
                });
            }
            RECORD_FRAME => {
                if body.len() < 5 {
                    return Err(bad());
                }
                bundle.frames.push((u32_at(body, 0), body[4..].to_vec()));
            }
            RECORD_COMMIT => bundle.commits.push(body.to_vec()),
            RECORD_CHECKPOINT => {
                let ticks = bundle.meta.as_ref().ok_or_else(bad)?.epoch_ticks;
                bundle
                    .checkpoints
                    .push(parse_package(body, ticks).ok_or_else(bad)?);
            }
            RECORD_RECEIVED_FRAME => {
                if body.len() < 7 {
                    return Err(bad());
                }
                bundle
                    .received
                    .push((u16_at(body, 0), u32_at(body, 2), body[6..].to_vec()));
            }
            RECORD_ROSTER => {
                if body.len() != 34 {
                    return Err(bad());
                }
                bundle.roster.push((u16_at(body, 0), fixed(&body[2..34])));
            }
            _ => {} // (later record types: additive)
        }
    }
    Ok(bundle)
}

/// What an audit found. A finding means someone broke the protocol; a note
/// is expected at a match's edges (the last epoch before a machine left).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Finding {
    /// A signed object does not verify, or a chain or root does not hold.
    Invalid(String),
    /// The host's Checkpoint for an epoch does not carry the player's commit.
    CommitNotAcknowledged { epoch: u32 },
    /// A frame the player sent (reliably) is not marked applied.
    FrameDenied { tick: u32 },
    /// A unit (a hit report) the player sent has no outcome.
    Unaccounted { tick: u32, unit: u16 },
    /// Two Checkpoints for one epoch, differently signed (several bundles).
    Equivocation { epoch: u32 },
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Finding::Invalid(what) => write!(f, "invalid: {what}"),
            Finding::CommitNotAcknowledged { epoch } => {
                write!(
                    f,
                    "the host did not acknowledge the commit for epoch {epoch}"
                )
            }
            Finding::FrameDenied { tick } => {
                write!(f, "the host did not mark the frame of tick {tick} applied")
            }
            Finding::Unaccounted { tick, unit } => write!(
                f,
                "the host gave no outcome for unit {unit} of the frame of tick {tick}"
            ),
            Finding::Equivocation { epoch } => {
                write!(f, "the host signed two Checkpoints for epoch {epoch}")
            }
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Report {
    pub findings: Vec<Finding>,
    pub notes: Vec<String>,
    pub commits: usize,
    pub frames: usize,
    pub units: usize,
    pub checkpoints: usize,
    pub outcomes: usize,
}

impl Report {
    pub fn clean(&self) -> bool {
        self.findings.is_empty()
    }
}

fn keys(role: KeyRole, key: &[u8; 32]) -> Option<KeySet> {
    let mut set = KeySet::default();
    set.insert_ed25519(role, VerifyingKey::from_bytes(key).ok()?);
    Some(set)
}

fn leaf_data(leaf: &Leaf) -> Vec<u8> {
    InputLeaf {
        slot: leaf.slot,
        commit: leaf.commit.map(Digest),
        applied: leaf.applied.clone(),
    }
    .leaf_data()
}

/// The host's Checkpoints in a bundle, verified: by epoch.
fn checkpoints(
    meta: &Meta,
    bundle: &Bundle,
    report: &mut Report,
) -> BTreeMap<u32, (Checkpoint, Digest, Package)> {
    let mut by_epoch = BTreeMap::new();
    let Some(keyset) = keys(KeyRole::GsInstance, &meta.instance_key) else {
        report
            .findings
            .push(Finding::Invalid("the host's instance key".into()));
        return by_epoch;
    };
    let instance_id = VerifyingKey::from_bytes(&meta.instance_key)
        .map(|k| fpp_crypto::key_digest(&k))
        .ok();
    for package in &bundle.checkpoints {
        let verified = match fpp_crypto::verify::<Checkpoint>(&package.object, &keyset) {
            Ok(v) => v,
            Err(e) => {
                report.findings.push(Finding::Invalid(format!(
                    "a Checkpoint's signature ({e:?})"
                )));
                continue;
            }
        };
        let c = verified.payload;
        let epoch = c.epoch;
        if c.match_id.0 != meta.match_id || Some(c.gs_instance_id.0) != instance_id.map(|d| d.0) {
            report.findings.push(Finding::Invalid(format!(
                "the Checkpoint for epoch {epoch} names another match or host"
            )));
            continue;
        }
        let leaves: Vec<Vec<u8>> = package.leaves.iter().map(leaf_data).collect();
        if fpp_merkle::root(&leaves) != c.inputs_root || leaves.len() as u32 != c.inputs_n {
            report.findings.push(Finding::Invalid(format!(
                "the input leaves of the Checkpoint for epoch {epoch} are not its root"
            )));
            continue;
        }
        if fpp_merkle::root(&package.events) != c.events_root
            || package.events.len() as u32 != c.events_n
        {
            report.findings.push(Finding::Invalid(format!(
                "the events of the Checkpoint for epoch {epoch} are not its root"
            )));
            continue;
        }
        if let Some((_, digest, _)) = by_epoch.get(&epoch) {
            if *digest != verified.digest {
                report.findings.push(Finding::Equivocation { epoch });
            }
            continue;
        }
        by_epoch.insert(epoch, (c, verified.digest, package.clone()));
    }
    // (the chain: each Checkpoint names the one before it, where there is one)
    let mut previous: Option<(u32, Digest)> = None;
    for (epoch, (c, digest, _)) in &by_epoch {
        if let Some((prev_epoch, prev_digest)) = previous {
            if *epoch == prev_epoch + 1 && c.prev != prev_digest {
                report.findings.push(Finding::Invalid(format!(
                    "the Checkpoint for epoch {epoch} does not follow the one before it"
                )));
            } else if *epoch != prev_epoch + 1 {
                report.notes.push(format!(
                    "no Checkpoint between epochs {prev_epoch} and {epoch}"
                ));
            }
        }
        previous = Some((*epoch, *digest));
    }
    report.checkpoints = by_epoch.len();
    by_epoch
}

/// Audits a player's bundle.
pub fn audit_player(bundle: &Bundle) -> Report {
    let mut report = Report::default();
    let Some(meta) = bundle.meta.clone() else {
        report.findings.push(Finding::Invalid("no header".into()));
        return report;
    };
    let ticks = meta.epoch_ticks.max(1);
    let Some(session) = keys(KeyRole::Session, &meta.session_key) else {
        report
            .findings
            .push(Finding::Invalid("the session key".into()));
        return report;
    };
    // the player's own commits: its key, its match and slot, chained
    let mut commits: BTreeMap<u32, (InputCommit, Digest)> = BTreeMap::new();
    let mut prev = Digest([0; 32]);
    for object in &bundle.commits {
        match fpp_crypto::verify::<InputCommit>(object, &session) {
            Ok(v) => {
                let c = v.payload;
                if c.match_id.0 != meta.match_id || c.slot != meta.slot {
                    report.findings.push(Finding::Invalid(format!(
                        "the commit for epoch {} names another match",
                        c.epoch
                    )));
                } else if c.prev != prev {
                    report.findings.push(Finding::Invalid(format!(
                        "the commit for epoch {} does not follow the one before it",
                        c.epoch
                    )));
                }
                prev = v.digest;
                commits.insert(c.epoch, (c, v.digest));
            }
            Err(e) => report
                .findings
                .push(Finding::Invalid(format!("a commit's signature ({e:?})"))),
        }
    }
    report.commits = commits.len();
    // its frames, by epoch: exactly what each commit signed
    let mut frames: BTreeMap<u32, Vec<&(u32, Vec<u8>)>> = BTreeMap::new();
    for frame in &bundle.frames {
        frames.entry(frame.0 / ticks).or_default().push(frame);
    }
    report.frames = bundle.frames.len();
    for (epoch, list) in &frames {
        let leaves: Vec<Vec<u8>> = list
            .iter()
            .map(|(tick, payload)| fpp_wire::msg::frame_leaf_data(*tick, payload))
            .collect();
        match commits.get(epoch) {
            Some((c, _))
                if fpp_merkle::root(&leaves) == c.frames_root && c.n as usize == leaves.len() => {}
            Some(_) => report.findings.push(Finding::Invalid(format!(
                "the frames of epoch {epoch} are not the ones its commit signed"
            ))),
            None => report.notes.push(format!(
                "epoch {epoch}'s frames were never committed (the match ended)"
            )),
        }
    }
    let checkpoints = checkpoints(&meta, bundle, &mut report);
    let last_checkpoint = checkpoints.keys().next_back().copied();
    // acknowledgement: each commit in its epoch's Checkpoint, each frame applied
    for (epoch, (_, digest)) in &commits {
        let Some((_, _, package)) = checkpoints.get(epoch) else {
            if last_checkpoint.is_none_or(|last| *epoch > last) {
                report.notes.push(format!(
                    "no Checkpoint yet for epoch {epoch} (the match ended)"
                ));
            } else {
                report
                    .findings
                    .push(Finding::CommitNotAcknowledged { epoch: *epoch });
            }
            continue;
        };
        let leaf = package.leaves.iter().find(|l| l.slot == meta.slot);
        if leaf.and_then(|l| l.commit) != Some(digest.0) {
            report
                .findings
                .push(Finding::CommitNotAcknowledged { epoch: *epoch });
        }
        for (tick, _) in frames.get(epoch).into_iter().flatten() {
            let bit = (tick - epoch * ticks) as usize;
            let applied = leaf.is_some_and(|l| {
                l.applied
                    .get(bit / 8)
                    .is_some_and(|b| b & (1 << (bit % 8)) != 0)
            });
            if !applied {
                report.findings.push(Finding::FrameDenied { tick: *tick });
            }
        }
    }
    // accounting: every unit of every committed frame has an outcome
    let outcomes: BTreeSet<(u32, u16)> = checkpoints
        .values()
        .flat_map(|(_, _, p)| p.events.iter().filter_map(|e| parse_outcome(e)))
        .filter(|o| o.slot == meta.slot)
        .map(|o| (o.tick, o.unit))
        .collect();
    report.outcomes = outcomes.len();
    for (epoch, list) in &frames {
        let judged = checkpoints.keys().any(|e| e >= epoch);
        for (tick, payload) in list {
            let units = payload.first().copied().unwrap_or(0) as u16;
            report.units += units as usize;
            for unit in 0..units {
                if !outcomes.contains(&(*tick, unit)) {
                    if judged && commits.contains_key(epoch) {
                        report
                            .findings
                            .push(Finding::Unaccounted { tick: *tick, unit });
                    } else {
                        report.notes.push(format!(
                            "unit {unit} of tick {tick}: no Checkpoint after it yet"
                        ));
                    }
                }
            }
        }
    }
    report
}

/// Audits a host's own bundle: its players' commits verify under the keys
/// they proved, and its Checkpoints under its own key, chained.
pub fn audit_host(bundle: &Bundle) -> Report {
    let mut report = Report::default();
    let Some(meta) = bundle.meta.clone() else {
        report.findings.push(Finding::Invalid("no header".into()));
        return report;
    };
    let roster: HashMap<u16, [u8; 32]> = bundle.roster.iter().copied().collect();
    for object in &bundle.commits {
        let ok = roster.values().any(|key| {
            keys(KeyRole::Session, key)
                .is_some_and(|set| fpp_crypto::verify::<InputCommit>(object, &set).is_ok())
        });
        if !ok {
            report.findings.push(Finding::Invalid(
                "a player's commit under no admitted key".into(),
            ));
        }
    }
    report.commits = bundle.commits.len();
    report.frames = bundle.received.len();
    checkpoints(&meta, bundle, &mut report);
    report
}

/// Audits a bundle by its role.
pub fn audit(bundle: &Bundle) -> Report {
    match bundle.meta.as_ref().map(|m| m.role) {
        Some(ROLE_HOST) => audit_host(bundle),
        _ => audit_player(bundle),
    }
}

/// Across bundles of one match: every epoch's Checkpoint signed once.
pub fn equivocations(bundles: &[Bundle]) -> Vec<Finding> {
    let mut seen: BTreeMap<([u8; 16], u32), Digest> = BTreeMap::new();
    let mut findings = BTreeSet::new();
    for bundle in bundles {
        let Some(meta) = &bundle.meta else { continue };
        for package in &bundle.checkpoints {
            let digest = fpp_crypto::object_digest(&package.object);
            let Ok(s) = fpp_wire::cose::Sign1::decode(&package.object) else {
                continue;
            };
            let Ok(value) = fpp_wire::cbor::decode(&s.payload) else {
                continue;
            };
            let Ok(c) = <Checkpoint as fpp_wire::Payload>::from_value(&value) else {
                continue;
            };
            match seen.get(&(meta.match_id, c.epoch)) {
                Some(d) if *d != digest => {
                    findings.insert(c.epoch);
                }
                None => {
                    seen.insert((meta.match_id, c.epoch), digest);
                }
                _ => {}
            }
        }
    }
    findings
        .into_iter()
        .map(|epoch| Finding::Equivocation { epoch })
        .collect()
}
