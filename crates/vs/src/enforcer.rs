use anyhow::{anyhow, Result};
use common::{
    crypto::{now_ms, sha256},
    proto::{Heartbeat, TranscriptDigest},
};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// How fast a player can legally move, in "world units per second".
/// Pick something safely above your GS clamp * inputs-per-second.
/// Smoke client: 1.0 per input @ 5 Hz ⇒ ~5 u/s. We allow 10 u/s for headroom.
const MAX_SPEED_UNITS_PER_SEC: f32 = 10.0;

/// Ignore pathological deltas where dt is too tiny (clock skew / first sample).
const MIN_DT_MS_FOR_SPEED: u64 = 50;

/// Priority 4 (Heartbeat time bounding): maximum allowed drift between the VS
/// wall-clock and the GS-reported gs_time_ms.  A GS claiming a time more than
/// this far in the past or future is either misconfigured or actively trying to
/// inflate dt_ms to bypass the speed calculation.  10 s absorbs normal NTP
/// divergence and network jitter while blocking day/year-scale manipulation.
const MAX_ALLOWED_DRIFT_MS: u64 = 10_000;

/// VS enforces per-session invariants.
#[derive(Default)]
pub struct Enforcer {
    sessions: HashMap<[u8; 16], SessionPhysics>,
}

#[derive(Clone)]
struct SessionPhysics {
    expected_sw_hash: [u8; 32],
    revoked: bool,

    // last finalized heartbeat tick (time and positions), after a TranscriptDigest
    last_hb_time_ms: Option<u64>,
    last_positions: HashMap<[u8; 32], (f32, f32)>,

    // staged time from the current Heartbeat (before TranscriptDigest arrives)
    pending_hb_time_ms: Option<u64>,

    /// Priority 2 (Ghost Snapshot fix): the receipt_tip the GS signed in the
    /// most recent heartbeat.  on_transcript() cross-checks that the
    /// TranscriptDigest carries the *same* receipt_tip, so the VS never runs
    /// physics checks on a positions array that is disconnected from the
    /// committed transcript hash.
    pending_hb_receipt_tip: Option<[u8; 32]>,
}

impl Enforcer {
    pub fn new() -> Self {
        Self::default()
    }

    /// VS recorded that a new session was admitted with this sw_hash.
    pub fn note_join(&mut self, session_id: [u8; 16], expected_sw_hash: [u8; 32]) {
        self.sessions.insert(
            session_id,
            SessionPhysics {
                expected_sw_hash,
                revoked: false,
                last_hb_time_ms: None,
                last_positions: HashMap::new(),
                pending_hb_time_ms: None,
                pending_hb_receipt_tip: None,
            },
        );
    }

    pub fn is_revoked(&self, session_id: [u8; 16]) -> bool {
        self.sessions
            .get(&session_id)
            .map(|s| s.revoked)
            .unwrap_or(false)
    }

    /// Called right after VS verifies Heartbeat signature.
    /// - Pins `sw_hash` to the one seen at Join.
    /// - Stages the current heartbeat time for speed checks on TranscriptDigest.
    /// - Priority 4: Rejects heartbeats whose gs_time_ms is more than
    ///   MAX_ALLOWED_DRIFT_MS away from the VS wall-clock to prevent a rogue
    ///   GS from inflating dt_ms and bypassing the speed calculation.
    pub fn on_heartbeat(&mut self, session_id: [u8; 16], hb: &Heartbeat) -> Result<()> {
        let sess = self
            .sessions
            .get_mut(&session_id)
            .ok_or_else(|| anyhow!("unknown session in on_heartbeat"))?;

        if sess.revoked {
            return Err(anyhow!("session already revoked"));
        }

        // Priority 4: Bound the reported GS time against the VS wall-clock.
        // We still use hb.gs_time_ms for the internal dt_ms speed math (so
        // legitimate GS clocks with minor skew keep working), but we reject
        // anything that is wildly off to prevent day/year-scale manipulation.
        let vs_now = now_ms();
        let drift = vs_now.abs_diff(hb.gs_time_ms);
        if drift > MAX_ALLOWED_DRIFT_MS {
            sess.revoked = true;
            eprintln!(
                "[VS] REVOKE session {}.. reason=heartbeat_time_drift \
                 (vs_now={}, gs_time={}, drift={}ms, max={}ms)",
                hex4(&session_id),
                vs_now,
                hb.gs_time_ms,
                drift,
                MAX_ALLOWED_DRIFT_MS,
            );
            return Err(anyhow!(
                "heartbeat gs_time_ms drift too large: {drift}ms (max {MAX_ALLOWED_DRIFT_MS}ms)"
            ));
        }

        if hb.sw_hash != sess.expected_sw_hash {
            sess.revoked = true;
            eprintln!(
                "[VS] REVOKE session {}.. reason=sw_hash_mismatch (join={}, hb={})",
                hex4(&session_id),
                hex32(&sess.expected_sw_hash),
                hex32(&hb.sw_hash),
            );
            return Err(anyhow!("sw_hash mismatch"));
        }

        // Stage time and receipt_tip of this heartbeat; speed check + cross-
        // validation will be done when TranscriptDigest arrives.
        sess.pending_hb_time_ms = Some(hb.gs_time_ms);
        sess.pending_hb_receipt_tip = Some(hb.receipt_tip);
        Ok(())
    }

    /// Called right after VS receives TranscriptDigest for the same gs_counter as the heartbeat.
    ///
    /// Priority 2 (Ghost Snapshot fix):
    ///   1. Verify `td.receipt_tip` matches the receipt_tip the GS claimed in the
    ///      matching Heartbeat.  This closes the gap where a rogue GS could send a
    ///      legally-looking `positions` array that is completely unrelated to the
    ///      actual committed game state.
    ///   2. Verify `sha256(positions_bytes) == td.snapshot_root`.  The GS already
    ///      folded snapshot_root into receipt_tip before signing the Heartbeat, so
    ///      the two checks together prove the positions are part of the signed chain.
    ///
    /// Then uses last finalized (positions, time) to compute speed; revokes on violation.
    pub fn on_transcript(&mut self, session_id: [u8; 16], td: &TranscriptDigest) -> Result<()> {
        let sess = self
            .sessions
            .get_mut(&session_id)
            .ok_or_else(|| anyhow!("unknown session in on_transcript"))?;

        if sess.revoked {
            return Err(anyhow!("session already revoked"));
        }

        // -----------------------------------------------------------------------
        // Priority 2, check 1: receipt_tip cross-validation.
        // The TranscriptDigest must carry the same receipt_tip the GS signed in
        // its Heartbeat for this counter.  If they differ the GS is operating a
        // split-brain: an honest state committed in the heartbeat vs. a fabricated
        // positions array fed to the speed checker.
        // -----------------------------------------------------------------------
        if let Some(expected_tip) = sess.pending_hb_receipt_tip {
            if td.receipt_tip != expected_tip {
                sess.revoked = true;
                eprintln!(
                    "[VS] REVOKE session {}.. reason=receipt_tip_mismatch \
                     (heartbeat={}, transcript={})",
                    hex4(&session_id),
                    hex32(&expected_tip),
                    hex32(&td.receipt_tip),
                );
                return Err(anyhow!(
                    "receipt_tip in TranscriptDigest does not match Heartbeat"
                ));
            }
        }
        // Clear the staged tip regardless (consumed by this digest).
        sess.pending_hb_receipt_tip = None;

        // -----------------------------------------------------------------------
        // Priority 2, check 2: snapshot_root integrity.
        // Recompute sha256(positions) and compare against the claimed root.
        // Because the GS folded snapshot_root into receipt_tip (which was signed),
        // a rogue GS cannot swap in a different positions array post-signature.
        // -----------------------------------------------------------------------
        let positions_bytes =
            bincode::serialize(&td.positions).expect("serialize positions for snapshot_root check");
        let computed_root = sha256(&positions_bytes);
        if computed_root != td.snapshot_root {
            sess.revoked = true;
            eprintln!(
                "[VS] REVOKE session {}.. reason=snapshot_root_mismatch \
                 (computed={}, claimed={})",
                hex4(&session_id),
                hex32(&computed_root),
                hex32(&td.snapshot_root),
            );
            return Err(anyhow!(
                "snapshot_root does not match sha256(positions): positions array was tampered"
            ));
        }

        let cur_time_ms = match sess.pending_hb_time_ms.take() {
            Some(t) => t,
            None => {
                // Only warn if this is NOT our very first finalized sample.
                if sess.last_hb_time_ms.is_some() {
                    eprintln!(
                        "[VS] warn: transcript without staged heartbeat time (session {}.., ctr={})",
                        hex4(&session_id),
                        td.gs_counter
                    );
                }
                // Can't do speed; just finalize positions so next round has a baseline.
                let new_pos = vec_to_map(&td.positions);
                sess.last_positions = new_pos;
                return Ok(());
            }
        };

        // First sample: establish baseline, no enforcement yet.
        if sess.last_hb_time_ms.is_none() {
            sess.last_hb_time_ms = Some(cur_time_ms);
            sess.last_positions = vec_to_map(&td.positions);
            return Ok(());
        }

        let prev_time = sess.last_hb_time_ms.unwrap();
        let dt_ms = cur_time_ms.saturating_sub(prev_time);
        if dt_ms < MIN_DT_MS_FOR_SPEED {
            sess.last_hb_time_ms = Some(cur_time_ms);
            sess.last_positions = vec_to_map(&td.positions);
            return Ok(());
        }

        let prev = &sess.last_positions;
        let cur = vec_to_map(&td.positions);

        let dt_s = dt_ms as f32 / 1000.0;
        for (who, (x2, y2)) in cur.iter() {
            if let Some((x1, y1)) = prev.get(who) {
                let dx = x2 - x1;
                let dy = y2 - y1;
                let dist = (dx * dx + dy * dy).sqrt();
                let speed = dist / dt_s;

                if speed > MAX_SPEED_UNITS_PER_SEC {
                    sess.revoked = true;
                    eprintln!(
                        "[VS] REVOKE session {}.. reason=speed_violation player={} speed={:.2}u/s dt={:.0}ms",
                        hex4(&session_id),
                        hex8(who),
                        speed,
                        dt_ms
                    );
                    return Err(anyhow!("speed violation: {:.2} u/s", speed));
                }
            }
        }

        // Passed checks; finalize this snapshot.
        sess.last_hb_time_ms = Some(cur_time_ms);
        sess.last_positions = cur;
        Ok(())
    }
}

/// Global enforcer (no external deps). Use `enforcer()` to access.
static ENFORCER: OnceLock<Mutex<Enforcer>> = OnceLock::new();

pub fn enforcer() -> &'static Mutex<Enforcer> {
    ENFORCER.get_or_init(|| Mutex::new(Enforcer::new()))
}

fn vec_to_map(v: &[([u8; 32], f32, f32)]) -> HashMap<[u8; 32], (f32, f32)> {
    let mut m = HashMap::with_capacity(v.len());
    for (k, x, y) in v.iter() {
        m.insert(*k, (*x, *y));
    }
    m
}

fn hex4(id: &[u8; 16]) -> String {
    hex::encode(&id[..4])
}

fn hex8(pk: &[u8; 32]) -> String {
    hex::encode(&pk[..8])
}

fn hex32(h: &[u8; 32]) -> String {
    hex::encode(h)
}
