// crates/gs-sim/src/game.rs
//! The game port: one match, served over fpp-session (ADR-002).
//!
//! Per client:
//! 1. Noise handshake (fpp-session) proves the client's session key.
//! 2. We send the current SAR (`SarUpdate`); the client checks it names the
//!    key it dialled and answers `Admit{SAT, AR}`.
//! 3. `fpp_tokens::admission::admit` runs the 04 §7.2 checks; the player is
//!    `Admitted{slot}` or `Reject`ed and disconnected.
//! 4. Inputs arrive as unreliable `InputFrame`s (intent only); per epoch the
//!    client commits to them with a signed `InputCommit` (reliable).
//! 5. Every tick: apply intents (clamped), send each player a snapshot.
//!    Every epoch: sign a Checkpoint over what was applied and decided, send
//!    it to Server Liveness, and its digest (`CheckpointHead`) to every player.
//! 6. New SARs are forwarded (`SarUpdate`). If they stop, the server has lost
//!    its blessing: every player is kicked with `SAR_LAPSED`.
//!
//! [`Match`] is sans-I/O (tests drive it directly); [`run`] adds the socket
//! and the clock.

use common::proto::{ClientCmd, WorldSnapshot};
use fpp_crypto::{Ed25519Signer, KeyResolver, KeyRole, KeySet};
use fpp_session::{Host, HostEvent, Transmit};
use fpp_tokens::admission::{admit, AdmissionPolicy, Revocations};
use fpp_tokens::control::Control;
use fpp_types::{BuildId, DeviceTier, Digest, GsInstanceId, MatchId, Reason};
use fpp_wire::msg::frame_leaf_data;
use fpp_wire::{Checkpoint, InputCommit, InputFrame, InputLeaf};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, HashMap};

/// Unreliable payload kinds (first byte).
pub const SNAPSHOT: u8 = 0x10;

pub const TICK_HZ: u32 = 30;
pub const TICKS_PER_EPOCH: u32 = 30;
/// Inputs are accepted this many ticks late (rewind window) or early (jitter).
pub const REWIND_TICKS: u32 = 15;
pub const JITTER_TICKS: u32 = 5;
/// Largest move per tick a client may ask for (world units).
pub const MAX_STEP: f32 = 1.0;
/// No SAR for this long: the server is no longer blessed.
pub const SAR_GRACE_MS: u64 = 6_000;

/// A security-relevant observation (feeds detection later, DET-01).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Signal {
    InputEquivocation { slot: u16, tick: u32 },
    CommitMismatch { slot: u16, epoch: u32 },
    CommitInvalid { slot: u16 },
    Rejected { peer: u32, reason: Reason },
}

struct Player {
    peer: u32,
    session_key: [u8; 32],
    x: f32,
    y: f32,
    /// Received intents by tick (current and previous epoch).
    frames: BTreeMap<u32, Vec<u8>>,
    /// Ticks whose intent was applied in time.
    applied: BTreeMap<u32, ()>,
    /// Digest of the player's verified InputCommit per epoch.
    commits: HashMap<u32, Digest>,
    roster_leaf: Vec<u8>,
}

pub struct MatchConfig {
    pub match_id: MatchId,
    pub instance: Ed25519Signer,
    pub build_id: BuildId,
    /// Regional key bundle (Verifier, Broker, Liveness keys).
    pub keys: KeySet,
    pub min_tier: DeviceTier,
    /// No SAR for this long: kick everyone (default [`SAR_GRACE_MS`]).
    pub sar_grace_ms: u64,
}

pub struct Match {
    cfg: MatchConfig,
    pub host: Host<Vec<u8>>,
    tick: u32,
    /// Joined but not yet admitted: peer → session key.
    pending: HashMap<u32, [u8; 32]>,
    players: BTreeMap<u16, Player>,
    slot_of: HashMap<u32, u16>,
    sar: Option<Vec<u8>>,
    last_sar_ms: Option<u64>,
    revoked: bool,
    revocations: Revocations,
    prev_checkpoint: Digest,
    next_checkpoint_epoch: u32,
    /// State digest at the end of each epoch not yet checkpointed.
    epoch_state: BTreeMap<u32, Digest>,
    pub signals: Vec<Signal>,
    /// Signed Checkpoints not yet taken by the caller (for Server Liveness).
    pub checkpoints_out: Vec<(u32, Vec<u8>)>,
    /// Ledger lines (JSON) not yet taken by the caller.
    pub ledger_out: Vec<String>,
    /// SpendCoins idempotency per (session key, op_id).
    runtime: crate::state::PlayerRuntime,
}

fn state_digest(tick: u32, players: &BTreeMap<u16, Player>) -> Digest {
    let mut h = Sha256::new();
    h.update(tick.to_le_bytes());
    for (slot, p) in players {
        h.update(slot.to_le_bytes());
        h.update(p.x.to_le_bytes());
        h.update(p.y.to_le_bytes());
    }
    Digest(h.finalize().into())
}

impl Match {
    pub fn new(cfg: MatchConfig, host: Host<Vec<u8>>) -> Self {
        Self {
            cfg,
            host,
            tick: 0,
            pending: HashMap::new(),
            players: BTreeMap::new(),
            slot_of: HashMap::new(),
            sar: None,
            last_sar_ms: None,
            revoked: false,
            revocations: Revocations::default(),
            prev_checkpoint: Digest::default(),
            next_checkpoint_epoch: 0,
            epoch_state: BTreeMap::new(),
            signals: Vec::new(),
            checkpoints_out: Vec::new(),
            ledger_out: Vec::new(),
            runtime: crate::state::PlayerRuntime::new(),
        }
    }

    pub fn instance_id(&self) -> GsInstanceId {
        fpp_tokens::instance_id(&self.cfg.instance.verifying_key().to_bytes())
    }

    pub fn tick(&self) -> u32 {
        self.tick
    }

    pub fn revoked(&self) -> bool {
        self.revoked
    }

    pub fn player_count(&self) -> usize {
        self.players.len()
    }

    fn control(&mut self, peer: u32, msg: &Control) {
        let _ = self.host.send_reliable(peer, &msg.encode());
    }

    fn reject(&mut self, peer: u32, reason: Reason) {
        self.signals.push(Signal::Rejected { peer, reason });
        self.control(
            peer,
            &Control::Reject {
                code: reason as u16,
            },
        );
        let _ = self.host.tick(0);
        let _ = self.host.disconnect(peer, reason as u16);
        self.pending.remove(&peer);
    }

    /// A new SAR from the liveness service (already chain-verified by the caller).
    pub fn on_sar(&mut self, sar: Vec<u8>, now_ms: u64) {
        if self.revoked {
            return;
        }
        self.last_sar_ms = Some(now_ms);
        let peers: Vec<u32> = self
            .pending
            .keys()
            .copied()
            .chain(self.players.values().map(|p| p.peer))
            .collect();
        let update = Control::SarUpdate { sar: sar.clone() };
        for peer in peers {
            self.control(peer, &update);
        }
        self.sar = Some(sar);
    }

    /// Feed one datagram from the socket.
    pub fn on_datagram(&mut self, from: Vec<u8>, datagram: &[u8]) {
        if self.host.recv(from, datagram).is_err() {
            return;
        }
        while let Some(ev) = self.host.poll_event() {
            self.on_event(ev);
        }
    }

    fn on_event(&mut self, ev: HostEvent) {
        match ev {
            HostEvent::PeerJoined {
                peer, session_key, ..
            } => {
                if self.revoked {
                    let _ = self.host.disconnect(peer, Reason::SarLapsed as u16);
                    return;
                }
                self.pending.insert(peer, session_key);
                if let Some(sar) = self.sar.clone() {
                    self.control(peer, &Control::SarUpdate { sar });
                }
            }
            HostEvent::Message { peer, payload } => match Control::decode(&payload) {
                Ok(Control::Admit { sat, ar, .. }) => self.on_admit(peer, &sat, &ar),
                Ok(Control::InputCommit { commit }) => self.on_commit(peer, &commit),
                Ok(Control::Bye) => self.remove_peer(peer),
                _ => {}
            },
            HostEvent::Data { peer, payload } => self.on_input(peer, &payload),
            HostEvent::PeerLeft { peer, .. } => self.remove_peer(peer),
            HostEvent::PeerMigrated { .. } => {}
        }
    }

    fn remove_peer(&mut self, peer: u32) {
        self.pending.remove(&peer);
        if let Some(slot) = self.slot_of.remove(&peer) {
            self.players.remove(&slot);
        }
    }

    fn on_admit(&mut self, peer: u32, sat: &[u8], ar: &[u8]) {
        let Some(session_key) = self.pending.get(&peer).copied() else {
            return;
        };
        let policy = AdmissionPolicy {
            gs_instance_id: self.instance_id(),
            matches: vec![self.cfg.match_id],
            min_tier: self.cfg.min_tier,
        };
        let admitted = admit(
            sat,
            ar,
            &session_key,
            &self.cfg.keys,
            &policy,
            &self.revocations,
            // Token times are wall-clock; `now_ms` is the match clock.
            common::crypto::now_ms() / 1000,
        );
        let a = match admitted {
            Ok(a) => a,
            Err((token, e)) => {
                eprintln!("[GS] admission refused for peer {peer}: {token:?} {e}");
                return self.reject(peer, e.reason(token));
            }
        };
        let slot = a.sat.slot;
        if self.players.contains_key(&slot) {
            return self.reject(peer, Reason::SatInvalid);
        }
        // A SAT is single-use per match: revoke its cti here once admitted.
        self.revocations.token_ctis.insert(a.sat.cti);
        self.pending.remove(&peer);
        let mut roster_leaf = slot.to_le_bytes().to_vec();
        roster_leaf.extend_from_slice(&a.sat.cti);
        roster_leaf.extend_from_slice(&a.sat.did.0);
        self.players.insert(
            slot,
            Player {
                peer,
                session_key,
                x: 0.0,
                y: 0.0,
                frames: BTreeMap::new(),
                applied: BTreeMap::new(),
                commits: HashMap::new(),
                roster_leaf,
            },
        );
        self.slot_of.insert(peer, slot);
        println!(
            "[GS] admitted slot {slot} (tier D{}, platform {})",
            a.ar.tier as u8, a.ar.platform
        );
        self.control(
            peer,
            &Control::Admitted {
                slot,
                start_tick: self.tick,
            },
        );
    }

    fn on_input(&mut self, peer: u32, payload: &[u8]) {
        let Some(&slot) = self.slot_of.get(&peer) else {
            return;
        };
        let Ok(frame) = InputFrame::decode(payload) else {
            return;
        };
        if frame.slot != slot {
            return;
        }
        let lo = self.tick.saturating_sub(REWIND_TICKS);
        let hi = self.tick + JITTER_TICKS;
        let p = self.players.get_mut(&slot).expect("slot of admitted peer");
        for (t, bytes) in frame.frames {
            if t < lo || t > hi {
                continue;
            }
            match p.frames.get(&t) {
                None => {
                    p.frames.insert(t, bytes);
                }
                Some(have) if *have != bytes => {
                    self.signals
                        .push(Signal::InputEquivocation { slot, tick: t });
                }
                Some(_) => {}
            }
        }
    }

    fn epoch_root(p: &Player, epoch: u32) -> (u32, Digest) {
        let first = epoch * TICKS_PER_EPOCH;
        let leaves: Vec<Vec<u8>> = p
            .frames
            .range(first..first + TICKS_PER_EPOCH)
            .map(|(t, b)| frame_leaf_data(*t, b))
            .collect();
        (leaves.len() as u32, fpp_merkle::root(&leaves))
    }

    fn on_commit(&mut self, peer: u32, commit: &[u8]) {
        let Some(&slot) = self.slot_of.get(&peer) else {
            return;
        };
        let p = self.players.get_mut(&slot).expect("slot of admitted peer");
        let mut keys = KeySet::default();
        let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&p.session_key) else {
            return;
        };
        keys.insert_ed25519(KeyRole::Session, vk);
        let v = match fpp_crypto::verify::<InputCommit>(commit, &keys) {
            Ok(v) if v.payload.match_id == self.cfg.match_id && v.payload.slot == slot => v,
            _ => {
                self.signals.push(Signal::CommitInvalid { slot });
                return;
            }
        };
        let epoch = v.payload.epoch;
        let (n, root) = Self::epoch_root(p, epoch);
        if n != v.payload.n || root != v.payload.frames_root {
            // Frames were lost or differ: the commit is still evidence
            // (BackfillRequest would fetch the missing ones, §7.4).
            self.signals.push(Signal::CommitMismatch { slot, epoch });
        }
        p.commits.insert(epoch, v.digest);
    }

    /// Advance one simulation tick. Call at `TICK_HZ`.
    pub fn step(&mut self, now_ms: u64) {
        if !self.revoked
            && self
                .last_sar_ms
                .is_some_and(|t| now_ms.saturating_sub(t) > self.cfg.sar_grace_ms)
        {
            self.lapse();
        }
        if self.revoked {
            let _ = self.host.tick(now_ms);
            return;
        }
        let tick = self.tick;
        for (&slot, p) in self.players.iter_mut() {
            let Some(bytes) = p.frames.get(&tick) else {
                continue;
            };
            p.applied.insert(tick, ());
            match bincode::deserialize::<ClientCmd>(bytes) {
                Ok(ClientCmd::Move { dx, dy }) if dx.is_finite() && dy.is_finite() => {
                    // Intent is clamped: a client asks, the server decides (AUTH-01).
                    p.x += dx.clamp(-MAX_STEP, MAX_STEP);
                    p.y += dy.clamp(-MAX_STEP, MAX_STEP);
                    self.ledger_out.push(format!(
                        "{{\"tick\":{tick},\"slot\":{slot},\"op\":\"Move\",\"x\":{:.3},\"y\":{:.3}}}",
                        p.x, p.y
                    ));
                }
                // Idempotent: a retried op_id is applied once (ECO-01).
                Ok(ClientCmd::SpendCoins(sc))
                    if self
                        .runtime
                        .check_idempotency(&p.session_key, &sc.op_id)
                        .is_none() =>
                {
                    self.runtime.record_op(
                        p.session_key,
                        sc.op_id,
                        crate::state::OpResult {
                            processed_at_ms: now_ms,
                            success: true,
                        },
                    );
                    self.ledger_out.push(format!(
                            "{{\"tick\":{tick},\"slot\":{slot},\"op\":\"SpendCoins\",\"op_id\":\"{}\",\"amount\":{}}}",
                            hex::encode(sc.op_id),
                            sc.amount
                        ));
                }
                _ => {}
            }
        }
        // Snapshots (unreliable; latest wins).
        let all: Vec<(u16, f32, f32)> = self.players.iter().map(|(s, p)| (*s, p.x, p.y)).collect();
        for (&slot, p) in &self.players {
            let snap = WorldSnapshot {
                tick: u64::from(tick),
                you: (p.x, p.y),
                others: all.iter().copied().filter(|o| o.0 != slot).collect(),
            };
            let mut bytes = vec![SNAPSHOT];
            bytes.extend(bincode::serialize(&snap).expect("snapshot"));
            let _ = self.host.send(p.peer, &bytes);
        }
        // Epoch end: remember the state; checkpoint the epoch before it,
        // whose InputCommits have had a full epoch to arrive.
        if tick % TICKS_PER_EPOCH == TICKS_PER_EPOCH - 1 {
            let epoch = tick / TICKS_PER_EPOCH;
            self.epoch_state
                .insert(epoch, state_digest(tick, &self.players));
            if epoch >= 1 {
                self.checkpoint(epoch - 1);
            }
        }
        self.tick += 1;
        let _ = self.host.tick(now_ms);
    }

    fn checkpoint(&mut self, epoch: u32) {
        if epoch < self.next_checkpoint_epoch {
            return;
        }
        let first = epoch * TICKS_PER_EPOCH;
        let last = first + TICKS_PER_EPOCH - 1;
        let mut inputs = Vec::new();
        let mut roster = Vec::new();
        for (&slot, p) in &self.players {
            let mut applied = vec![0u8; (TICKS_PER_EPOCH as usize).div_ceil(8)];
            for (&t, _) in p.applied.range(first..=last) {
                let i = (t - first) as usize;
                applied[i / 8] |= 1 << (i % 8);
            }
            inputs.push(
                InputLeaf {
                    slot,
                    commit: p.commits.get(&epoch).copied(),
                    applied,
                }
                .leaf_data(),
            );
            roster.push(p.roster_leaf.clone());
        }
        let cp = Checkpoint {
            match_id: self.cfg.match_id,
            gs_instance_id: self.instance_id(),
            build_id: self.cfg.build_id,
            policy_ver: 1,
            epoch,
            ticks: (first, last),
            prev: self.prev_checkpoint,
            inputs_root: fpp_merkle::root(&inputs),
            inputs_n: inputs.len() as u32,
            events_root: fpp_merkle::root::<Vec<u8>>(&[]),
            events_n: 0,
            state_root: self.epoch_state.remove(&epoch).unwrap_or_default(),
            rng_root: fpp_merkle::root::<Vec<u8>>(&[]),
            rng_n: 0,
            roster_root: fpp_merkle::root(&roster),
            roster_n: roster.len() as u32,
        };
        let signed = fpp_crypto::sign(&self.cfg.instance, &cp);
        let digest = fpp_crypto::object_digest(&signed);
        self.prev_checkpoint = digest;
        self.next_checkpoint_epoch = epoch + 1;
        let head = Control::CheckpointHead {
            match_id: self.cfg.match_id,
            epoch,
            digest,
        };
        let peers: Vec<u32> = self.players.values().map(|p| p.peer).collect();
        for peer in peers {
            self.control(peer, &head);
        }
        // Forget what is now committed.
        for p in self.players.values_mut() {
            p.frames = p.frames.split_off(&(last + 1).saturating_sub(REWIND_TICKS));
            p.applied = p.applied.split_off(&(last + 1));
            p.commits.retain(|e, _| *e > epoch);
        }
        self.checkpoints_out.push((epoch, signed));
    }

    /// SARs stopped: kick everyone and refuse new joins.
    pub fn lapse(&mut self) {
        if self.revoked {
            return;
        }
        self.revoked = true;
        eprintln!("[GS] SAR chain lapsed: no longer blessed; kicking all players");
        let peers: Vec<u32> = self
            .players
            .values()
            .map(|p| p.peer)
            .chain(self.pending.keys().copied())
            .collect();
        for peer in peers {
            self.control(peer, &Control::kick(Reason::SarLapsed));
            let _ = self.host.tick(0);
            let _ = self.host.disconnect(peer, Reason::SarLapsed as u16);
        }
        self.players.clear();
        self.pending.clear();
        self.slot_of.clear();
    }

    pub fn poll_transmit(&mut self) -> Option<Transmit<Vec<u8>>> {
        self.host.poll_transmit()
    }
}

/// Address blobs for fpp-session: the socket address as text.
pub fn addr_bytes(a: &std::net::SocketAddr) -> Vec<u8> {
    a.to_string().into_bytes()
}

pub fn parse_addr(b: &[u8]) -> Option<std::net::SocketAddr> {
    std::str::from_utf8(b).ok()?.parse().ok()
}

/// Is every key a resolver needs present? (Guards against an empty bundle.)
pub fn bundle_complete(keys: &impl KeyResolver, bundle: &common::keys::KeyBundle) -> bool {
    [
        bundle.verifier_ar,
        bundle.broker_sat,
        bundle.server_liveness,
    ]
    .iter()
    .all(|k| keys.resolve(&fpp_crypto::kid(k)).is_some())
}

/// Next SAR from the watch channel; `None` once, when its sender is gone
/// (after that, never resolves).
async fn sar_changed(
    rx: &mut Option<tokio::sync::watch::Receiver<Option<Vec<u8>>>>,
) -> Option<Vec<u8>> {
    loop {
        let Some(r) = rx.as_mut() else {
            return std::future::pending().await;
        };
        if r.changed().await.is_err() {
            *rx = None;
            return None;
        }
        if let Some(sar) = r.borrow_and_update().clone() {
            return Some(sar);
        }
    }
}

/// Serve the match on `socket` until `stop` is set or the SAR chain lapses
/// (then a few more ticks so kicks go out).
pub async fn run(
    socket: tokio::net::UdpSocket,
    mut m: Match,
    sar_rx: tokio::sync::watch::Receiver<Option<Vec<u8>>>,
    cp_tx: tokio::sync::mpsc::UnboundedSender<(u32, Vec<u8>)>,
    mut ledger: Option<crate::ledger::Ledger>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> anyhow::Result<()> {
    use std::sync::atomic::Ordering;
    let start = std::time::Instant::now();
    let now = || start.elapsed().as_millis() as u64;
    let mut ticker =
        tokio::time::interval(std::time::Duration::from_millis(1000 / u64::from(TICK_HZ)));
    let mut buf = vec![0u8; 2048];
    let mut drain_ticks = 0u32;
    let mut sar_rx = Some(sar_rx);
    loop {
        tokio::select! {
            r = socket.recv_from(&mut buf) => {
                if let Ok((n, from)) = r {
                    m.on_datagram(addr_bytes(&from), &buf[..n]);
                }
            }
            changed = sar_changed(&mut sar_rx) => {
                match changed {
                    // The Server Liveness link is gone: SARs will not come back.
                    None => m.lapse(),
                    Some(sar) => m.on_sar(sar, now()),
                }
            }
            _ = ticker.tick() => {
                m.step(now());
                for (epoch, cp) in m.checkpoints_out.drain(..) {
                    let _ = cp_tx.send((epoch, cp));
                }
                if let Some(l) = ledger.as_mut() {
                    for line in m.ledger_out.drain(..) {
                        l.append_line(&line);
                    }
                } else {
                    m.ledger_out.clear();
                }
                if m.revoked() || stop.load(Ordering::Relaxed) {
                    drain_ticks += 1;
                }
            }
        }
        while let Some(t) = m.poll_transmit() {
            if let Some(to) = parse_addr(&t.to) {
                let _ = socket.send_to(&t.packet, to).await;
            }
        }
        if drain_ticks > 10 {
            return Ok(());
        }
    }
}
