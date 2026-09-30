//! The auditor against bundles made here with the same objects a game makes
//! (fpp-crypto signs them as the C SDK does): an honest match, and each way
//! a host can break the accounting.

use ed25519_dalek::SigningKey;
use fpp_audit::*;
use fpp_crypto::{sign, Ed25519Signer};
use fpp_types::{BuildId, Digest, GsInstanceId, MatchId};
use fpp_wire::msg::frame_leaf_data;
use fpp_wire::{Checkpoint, InputCommit, InputLeaf};

const TICKS: u32 = 150;
const APPLIED: usize = 19;
const MATCH: [u8; 16] = *b"match-0000000001";
const SLOT: u16 = 7;

fn key(seed: u8) -> Ed25519Signer {
    Ed25519Signer::new(SigningKey::from_bytes(&[seed; 32]))
}

fn public(k: &Ed25519Signer) -> [u8; 32] {
    k.verifying_key().to_bytes()
}

fn record(out: &mut Vec<u8>, kind: u8, body: &[u8]) {
    out.push(kind);
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(body);
}

fn outcome(slot: u16, tick: u32, unit: u16, result: u8) -> Vec<u8> {
    let mut e = vec![EVENT_OUTCOME];
    e.extend_from_slice(&slot.to_le_bytes());
    e.extend_from_slice(&tick.to_le_bytes());
    e.extend_from_slice(&unit.to_le_bytes());
    e.push(result);
    e.push(0);
    e
}

/// A match as a game records it, with knobs for a cheating host.
struct Match {
    session: Ed25519Signer,
    instance: Ed25519Signer,
    /// (tick, units) the player sent, epochs 0 and 1.
    frames: Vec<(u32, u8)>,
    /// outcomes the host leaves out: (tick, unit)
    omit: Vec<(u32, u16)>,
    /// epochs whose Checkpoint leaves the commit out
    unacknowledged: Vec<u32>,
    /// ticks the host marks not applied
    denied: Vec<u32>,
    /// a byte of the epoch-1 Checkpoint changed after signing
    tamper: bool,
}

impl Match {
    fn new() -> Self {
        Match {
            session: key(0x51),
            instance: key(0x61),
            frames: vec![(10, 1), (40, 2), (149, 0), (150, 1), (200, 3)],
            omit: vec![],
            unacknowledged: vec![],
            denied: vec![],
            tamper: false,
        }
    }

    fn frame_payload(tick: u32, units: u8) -> Vec<u8> {
        let mut p = vec![units];
        p.extend_from_slice(format!("hit reports of tick {tick}").as_bytes());
        p
    }

    /// The player's bundle; view_extra_event: the host's epoch-1 Checkpoint
    /// as another player got it (one more event).
    fn bundle(&self, view_extra_event: bool) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        let mut meta = vec![1, ROLE_PLAYER];
        meta.extend_from_slice(&MATCH);
        meta.extend_from_slice(&SLOT.to_le_bytes());
        meta.extend_from_slice(&public(&self.session));
        meta.extend_from_slice(&public(&self.instance));
        meta.extend_from_slice(&TICKS.to_le_bytes());
        record(&mut out, RECORD_META, &meta);
        let mut prev_commit = Digest([0; 32]);
        let mut prev_checkpoint = Digest([0; 32]);
        for epoch in 0..2u32 {
            let frames: Vec<(u32, Vec<u8>)> = self
                .frames
                .iter()
                .filter(|(t, _)| t / TICKS == epoch)
                .map(|(t, u)| (*t, Self::frame_payload(*t, *u)))
                .collect();
            for (tick, payload) in &frames {
                let mut body = tick.to_le_bytes().to_vec();
                body.extend_from_slice(payload);
                record(&mut out, RECORD_FRAME, &body);
            }
            let leaves: Vec<Vec<u8>> = frames.iter().map(|(t, p)| frame_leaf_data(*t, p)).collect();
            let commit = sign(
                &self.session,
                &InputCommit {
                    match_id: MatchId(MATCH),
                    slot: SLOT,
                    epoch,
                    first_tick: epoch * TICKS,
                    last_tick: epoch * TICKS + TICKS - 1,
                    n: leaves.len() as u32,
                    frames_root: fpp_merkle::root(&leaves),
                    prev: prev_commit,
                },
            );
            prev_commit = fpp_crypto::object_digest(&commit);
            record(&mut out, RECORD_COMMIT, &commit);
            // the host's Checkpoint for the epoch
            let mut applied = vec![0u8; APPLIED];
            for (tick, _) in &frames {
                if !self.denied.contains(tick) {
                    let bit = (tick - epoch * TICKS) as usize;
                    applied[bit / 8] |= 1 << (bit % 8);
                }
            }
            let acked = !self.unacknowledged.contains(&epoch);
            let leaf = InputLeaf {
                slot: SLOT,
                commit: acked.then_some(prev_commit),
                applied: applied.clone(),
            };
            let mut events: Vec<Vec<u8>> = frames
                .iter()
                .flat_map(|(tick, p)| (0..p[0] as u16).map(move |u| (*tick, u)))
                .filter(|tu| !self.omit.contains(tu))
                .map(|(tick, unit)| outcome(SLOT, tick, unit, OUTCOME_APPLIED))
                .collect();
            if view_extra_event && epoch == 1 {
                events.push(outcome(SLOT + 1, 199, 0, OUTCOME_REJECTED));
            }
            let checkpoint = sign(
                &self.instance,
                &Checkpoint {
                    match_id: MatchId(MATCH),
                    gs_instance_id: GsInstanceId(
                        fpp_crypto::key_digest(&self.instance.verifying_key()).0,
                    ),
                    build_id: BuildId([0; 32]),
                    policy_ver: 0,
                    epoch,
                    ticks: (epoch * TICKS, epoch * TICKS + TICKS - 1),
                    prev: prev_checkpoint,
                    inputs_root: fpp_merkle::root(&[leaf.leaf_data()]),
                    inputs_n: 1,
                    events_root: fpp_merkle::root(&events),
                    events_n: events.len() as u32,
                    state_root: Digest([0; 32]),
                    rng_root: fpp_merkle::root::<Vec<u8>>(&[]),
                    rng_n: 0,
                    roster_root: fpp_merkle::root::<Vec<u8>>(&[]),
                    roster_n: 0,
                },
            );
            prev_checkpoint = fpp_crypto::object_digest(&checkpoint);
            let mut object = checkpoint.clone();
            if self.tamper && epoch == 1 {
                let at = object.len() / 2;
                object[at] ^= 1;
            }
            let mut package = (object.len() as u32).to_le_bytes().to_vec();
            package.extend_from_slice(&object);
            package.extend_from_slice(&1u16.to_le_bytes());
            package.extend_from_slice(&SLOT.to_le_bytes());
            package.push(acked as u8);
            package.extend_from_slice(if acked { &prev_commit.0 } else { &[0u8; 32] });
            package.extend_from_slice(&applied);
            package.extend_from_slice(&(events.len() as u16).to_le_bytes());
            for e in &events {
                package.extend_from_slice(e);
            }
            record(&mut out, RECORD_CHECKPOINT, &package);
        }
        out
    }

    fn audit(&self) -> Report {
        audit(&parse(&self.bundle(false)).expect("parses"))
    }
}

#[test]
fn an_honest_match_is_clean() {
    let report = Match::new().audit();
    assert!(report.clean(), "{:?}", report.findings);
    assert_eq!(
        (
            report.commits,
            report.frames,
            report.units,
            report.checkpoints
        ),
        (2, 5, 7, 2)
    );
    assert_eq!(report.outcomes, 7);
}

#[test]
fn a_host_that_leaves_out_an_outcome_is_caught() {
    let mut m = Match::new();
    m.omit = vec![(40, 1), (200, 2)];
    let report = m.audit();
    assert_eq!(
        report.findings,
        vec![
            Finding::Unaccounted { tick: 40, unit: 1 },
            Finding::Unaccounted { tick: 200, unit: 2 },
        ]
    );
}

#[test]
fn a_host_that_ignores_a_commit_or_a_frame_is_caught() {
    let mut m = Match::new();
    m.unacknowledged = vec![1];
    m.denied = vec![10];
    let report = m.audit();
    assert!(report
        .findings
        .contains(&Finding::CommitNotAcknowledged { epoch: 1 }));
    assert!(report.findings.contains(&Finding::FrameDenied { tick: 10 }));
    assert_eq!(report.findings.len(), 2, "{:?}", report.findings);
}

#[test]
fn a_changed_checkpoint_does_not_verify() {
    let mut m = Match::new();
    m.tamper = true;
    let report = m.audit();
    assert!(report
        .findings
        .iter()
        .any(|f| matches!(f, Finding::Invalid(what) if what.contains("signature"))));
}

#[test]
fn two_players_shown_different_checkpoints_is_equivocation() {
    let m = Match::new();
    let one = parse(&m.bundle(false)).unwrap();
    let other = parse(&m.bundle(true)).unwrap();
    // each is consistent alone...
    assert!(audit(&one).clean());
    assert!(audit(&other).clean());
    // ...but the host signed two different Checkpoints for epoch 1
    assert_eq!(
        equivocations(&[one, other]),
        vec![Finding::Equivocation { epoch: 1 }]
    );
}

#[test]
fn rejects_what_is_not_a_bundle() {
    assert_eq!(parse(b"hello").unwrap_err(), ParseError::Magic);
    let mut truncated = Match::new().bundle(false);
    truncated.truncate(truncated.len() - 3);
    assert_eq!(parse(&truncated).unwrap_err(), ParseError::Truncated);
}
