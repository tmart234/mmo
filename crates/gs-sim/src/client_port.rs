// crates/gs-sim/src/client_port.rs
use anyhow::anyhow;
use anyhow::Context;
use common::{
    crypto::{client_input_sign_bytes, now_ms, receipt_tip_update},
    proto::{AuthoritativeEvent, ClientCmd, ClientToGs, PlayTicket, ServerHello, WorldSnapshot},
};
use ed25519_dalek::{Signature, VerifyingKey};
use std::{
    collections::VecDeque,
    convert::TryFrom,
    net::SocketAddr,
    sync::{Arc, Mutex},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::watch,
    time::{sleep, Duration},
};

use crate::ledger::LedgerEvent;
use crate::state::{PlayerState, Shared};
use std::io::ErrorKind;

const MAX_CLIENT_MSG: usize = 1024; // small and safe; raise if needed
const NONCE_WINDOW: u64 = 4; // allow nonce jumps up to +4
const TICKET_RING_MAX: usize = 32;

/// Send a length-prefixed bincode message over a TCP stream.
async fn send_bin_tcp<T: serde::Serialize>(sock: &mut TcpStream, msg: &T) -> anyhow::Result<()> {
    let bytes = bincode::serialize(msg).context("serialize send_bin_tcp")?;
    let len_le = (bytes.len() as u32).to_le_bytes();

    sock.write_all(&len_le).await.context("write len")?;
    sock.write_all(&bytes).await.context("write body")?;

    Ok(())
}

/// Receive a length-prefixed bincode message from a TCP stream.
async fn recv_bin_tcp<T: serde::de::DeserializeOwned>(sock: &mut TcpStream) -> anyhow::Result<T> {
    let mut len_buf = [0u8; 4];
    sock.read_exact(&mut len_buf).await.context("read len")?;
    let len = u32::from_le_bytes(len_buf) as usize;

    // Reject-before-parse: length sanity
    if len == 0 || len > MAX_CLIENT_MSG {
        // Act like a DDoS guard: drop without parsing
        return Err(anyhow!("frame too large or zero (len={})", len));
    }

    let mut buf = vec![0u8; len];
    sock.read_exact(&mut buf).await.context("read body")?;

    let msg = bincode::deserialize(&buf).context("bincode::deserialize")?;
    Ok(msg)
}

/// Local TCP listener that talks to a client instance (client-sim / client-bevy).
///
/// Security properties per client socket:
///  - client must staple a fresh VS-signed PlayTicket
///  - ticket must match our session / be within time window
///  - ticket.client_binding must match client_pub (if bound)
///  - client input must be signed with client_pub
///  - nonce must strictly increase per client_pub
///  - dx/dy is clamped server-side (anti-speedhack)
///  - we update per-player world state in shared memory
///  - we fold BOTH the ClientInput and an AuthoritativeEvent into receipt_tip
///  - we respond with a WorldSnapshot including you + others
///
/// When VS revokes us (or we miss tickets), we disconnect everyone.
pub async fn client_port_task(
    shared: Shared,
    revoke_rx: watch::Receiver<bool>,
    ticket_rx: watch::Receiver<Option<PlayTicket>>,
) -> anyhow::Result<()> {
    // Bind a local port for clients to connect (client-sim / client-bevy).
    let listener = TcpListener::bind("127.0.0.1:50000")
        .await
        .context("bind 127.0.0.1:50000")?;

    // Outer accept loop: one spawned task per client connection.
    'accept_loop: loop {
        let (mut socket, peer_addr): (TcpStream, SocketAddr) =
            listener.accept().await.context("accept client")?;
        println!("[GS] client connected from {}", peer_addr);

        // If we've already been revoked, just refuse immediately.
        if *revoke_rx.borrow() {
            eprintln!(
                "[GS] refusing client {}: session already revoked",
                peer_addr
            );
            continue 'accept_loop;
        }

        // Snapshot session_id and vs_pub exactly once for this client.
        let (session_id, vs_pub_bytes) = {
            let guard = shared.lock().unwrap();
            (guard.session_id, guard.vs_pub.to_bytes())
        };

        // Clone a local watch receiver for tickets so this client follows updates.
        // Wait until we have the first ticket, then seed a background "ticket ring" updater.
        let mut local_ticket_rx = ticket_rx.clone();
        let first_ticket: PlayTicket = loop {
            if let Some(t) = local_ticket_rx.borrow().clone() {
                break t;
            }
            if local_ticket_rx.changed().await.is_err() {
                eprintln!("[GS] ticket_rx closed; shutting client_port_task listener");
                return Ok(());
            }
        };

        // === Ticket ring so we accept recently rolled tickets even when client idles ===
        let ring: Arc<Mutex<VecDeque<PlayTicket>>> = Arc::new(Mutex::new(VecDeque::new()));
        {
            let mut r = ring.lock().unwrap();
            r.push_back(first_ticket.clone());
        }
        // Watcher that pushes every new ticket into the ring (cap = TICKET_RING_MAX)
        {
            let mut rx = local_ticket_rx.clone();
            let ring_for_watcher = ring.clone();
            tokio::spawn(async move {
                while rx.changed().await.is_ok() {
                    if let Some(t) = rx.borrow().clone() {
                        let mut r = ring_for_watcher.lock().unwrap();
                        if r.back().map(|p| p.counter) != Some(t.counter) {
                            r.push_back(t);
                            while r.len() > TICKET_RING_MAX {
                                r.pop_front();
                            }
                        }
                    }
                }
            });
        }

        // Send initial ServerHello with the first ticket.
        let hello = ServerHello {
            session_id,
            ticket: first_ticket.clone(),
            vs_pub: vs_pub_bytes,
        };

        if let Err(e) = send_bin_tcp(&mut socket, &hello).await {
            // Early client drop during startup is normal with retrying clients.
            if let Some(ioe) = e.downcast_ref::<std::io::Error>() {
                match ioe.kind() {
                    ErrorKind::ConnectionAborted
                    | ErrorKind::ConnectionReset
                    | ErrorKind::BrokenPipe => {
                        eprintln!("[GS] client {peer_addr} dropped before Hello; will retry");
                    }
                    _ => eprintln!("[GS] send ServerHello to {peer_addr} failed: {e:?}"),
                }
            } else {
                eprintln!("[GS] send ServerHello to {peer_addr} failed: {e:?}");
            }
            continue 'accept_loop;
        }

        // Each client gets its own async task so we can go back to accept()
        let shared_cloned = shared.clone();
        let revoke_rx_client = revoke_rx.clone();
        let session_id_for_client = session_id;
        let ring_for_client = ring.clone();

        tokio::spawn(async move {
            // per-connection tick counter for snapshots
            let mut tick: u64 = 0;
            let mut socket = socket;

            loop {
                // Hard revoke? Kill client immediately.
                if *revoke_rx_client.borrow() {
                    eprintln!("[GS] closing client {} (revoked)", peer_addr);
                    break;
                }

                // Receive exactly one client message.
                let msg_res = recv_bin_tcp::<ClientToGs>(&mut socket).await;
                let ci = match msg_res {
                    Ok(ClientToGs::Input(ci)) => Some(*ci), // enum carries Box<ClientInput>
                    Ok(ClientToGs::Bye) => {
                        println!("[GS] client {} said Bye; closing gracefully", peer_addr);
                        break;
                    }
                    Err(e) => {
                        eprintln!("[GS] recv ClientInput error from {peer_addr}: {e:?}");
                        break;
                    }
                };

                // If we didn’t get an Input (i.e., was Bye), end the loop.
                let ci = match ci {
                    Some(ci) => ci,
                    None => break,
                };

                let now_ms_val = now_ms();

                // === Everything that touches shared state lives in this block ===
                // We do NOT hold the mutex across an .await.
                let step_res: Result<WorldSnapshot, ()> = (|| {
                    // Snapshot GS-shared info we need BEFORE we await anything else.
                    let mut guard = shared_cloned.lock().unwrap();

                    // Phase 0: read current per-player state.
                    let (prev_x, prev_y, prev_nonce) = match guard.players.get(&ci.client_pub) {
                        Some(ps) => (ps.x, ps.y, ps.last_nonce),
                        None => (0.0, 0.0, 0),
                    };
                    let prev_tip = guard.receipt_tip;

                    // === Ticket-ring validation (newest → oldest) ===
                    let ring_snapshot: Vec<PlayTicket> = {
                        let r = ring_for_client.lock().unwrap();
                        r.iter().cloned().collect()
                    };

                    let ticket_matches = |pt: &PlayTicket| -> bool {
                        if now_ms_val < pt.not_before_ms || now_ms_val > pt.not_after_ms {
                            return false;
                        }
                        if pt.session_id != session_id_for_client {
                            return false;
                        }
                        if pt.client_binding != [0u8; 32] && pt.client_binding != ci.client_pub {
                            return false;
                        }
                        if ci.ticket_counter != pt.counter {
                            return false;
                        }
                        if ci.ticket_sig_vs != pt.sig_vs {
                            return false;
                        }
                        true
                    };

                    let mut used_recent = false;
                    for pt in ring_snapshot.iter().rev() {
                        if ticket_matches(pt) {
                            used_recent = true;
                            break;
                        }
                    }
                    if !used_recent {
                        eprintln!(
                            "[GS] ticket mismatch from {peer_addr} (not in recent ring of {} tickets)",
                            ring_snapshot.len()
                        );
                        return Err(());
                    }

                    // ---- 2) anti-replay / ordering via monotonically increasing client_nonce ----
                    if ci.client_nonce <= prev_nonce {
                        eprintln!(
                            "[GS] client_nonce non-monotonic from {peer_addr} (got {}, last {})",
                            ci.client_nonce, prev_nonce
                        );
                        return Err(());
                    }
                    if ci.client_nonce > prev_nonce.saturating_add(NONCE_WINDOW) {
                        eprintln!(
                            "[GS] client_nonce jump too large from {peer_addr} (got {}, last {}, window {})",
                            ci.client_nonce, prev_nonce, NONCE_WINDOW
                        );
                        return Err(());
                    }

                    // ---- 2a) rate-limit per-cmd using TokenBucket (runtime buckets) ----
                    let rt = guard
                        .runtime
                        .get_or_insert_with(|| crate::state::PlayerRuntime {
                            buckets: std::collections::HashMap::new(),
                        });

                    let key = (ci.client_pub, crate::state::CmdKey::Move);
                    match rt.buckets.entry(key) {
                        std::collections::hash_map::Entry::Occupied(mut o) => {
                            if !o.get_mut().take(1.0, now_ms_val) {
                                eprintln!("[GS] rate limit: too many Move ops from {peer_addr}");
                                return Err(());
                            }
                        }
                        std::collections::hash_map::Entry::Vacant(v) => {
                            let mut b = crate::state::TokenBucket::new(10.0, 10.0, now_ms_val); // cap=10, 10/sec
                            let _ = b.take(1.0, now_ms_val); // spend the first token
                            v.insert(b);
                        }
                    }

                    // ---- 3) verify client's signature over canonical tuple ----
                    let sign_bytes = client_input_sign_bytes(
                        &ci.session_id,
                        ci.ticket_counter,
                        &ci.ticket_sig_vs,
                        ci.client_nonce,
                        &ci.cmd,
                    );

                    let client_vk = match VerifyingKey::from_bytes(&ci.client_pub) {
                        Ok(vk) => vk,
                        Err(e) => {
                            eprintln!("[GS] bad client_pub from {peer_addr}: {e:?}");
                            return Err(());
                        }
                    };

                    let sig = match Signature::try_from(&ci.client_sig[..]) {
                        Ok(s) => s,
                        Err(_) => {
                            eprintln!("[GS] malformed client_sig from {peer_addr}");
                            return Err(());
                        }
                    };

                    if client_vk.verify_strict(&sign_bytes, &sig).is_err() {
                        eprintln!("[GS] client_sig verification failed from {peer_addr}");
                        return Err(());
                    }

                    // ---- 4) simulation / command handling ----
                    let (new_x, new_y) = match ci.cmd {
                        ClientCmd::Move { mut dx, mut dy } => {
                            // per-tick displacement cap (anti-speedhack / anti-teleport)
                            const MAX_STEP: f32 = 1.0;
                            let mag2 = dx * dx + dy * dy;
                            if mag2 > (MAX_STEP * MAX_STEP) {
                                let mag = (mag2 as f64).sqrt() as f32;
                                if mag > 0.0 {
                                    let scale = MAX_STEP / mag;
                                    dx *= scale;
                                    dy *= scale;
                                }
                            }

                            let nx = prev_x + dx;
                            let ny = prev_y + dy;

                            println!(
                                "[GS] accepted Move {{ dx: {:.3}, dy: {:.3} }} \
                                 (nonce={}, ticket_ctr={}, used_recent={}) from {peer_addr}",
                                dx, dy, ci.client_nonce, ci.ticket_counter, used_recent
                            );

                            (nx, ny)
                        }
                        ClientCmd::SpendCoins(_) => {
                            eprintln!(
                                "[GS] SpendCoins not implemented; rejecting from {}",
                                peer_addr
                            );
                            return Err(());
                        }
                    };

                    // advance world tick
                    let new_tick = tick + 1;

                    // write back player state
                    {
                        let entry = guard.players.entry(ci.client_pub).or_insert(PlayerState {
                            x: 0.0,
                            y: 0.0,
                            last_nonce: 0,
                        });
                        entry.x = new_x;
                        entry.y = new_y;
                        entry.last_nonce = ci.client_nonce;
                    }

                    // Build an authoritative event for the transcript.
                    let ev = AuthoritativeEvent::MoveResolved {
                        who: ci.client_pub,
                        x: new_x,
                        y: new_y,
                        tick: new_tick,
                    };

                    // ---- 5) update rolling transcript tip + save it in shared ----
                    let ci_bytes = bincode::serialize(&ci).expect("serialize ClientInput in GS");
                    let ev_bytes =
                        bincode::serialize(&ev).expect("serialize AuthoritativeEvent in GS");

                    let new_tip = receipt_tip_update(&prev_tip, &ci_bytes, &ev_bytes);
                    guard.receipt_tip = new_tip;

                    // Append to ledger if enabled (copy values first to avoid borrow conflicts)
                    let session_id_copy = guard.session_id;
                    let client_pub_copy = ci.client_pub;
                    if let Some(ledger) = guard.ledger.as_mut() {
                        let mut op_id16 = [0u8; 16];
                        op_id16.copy_from_slice(&ci.client_sig[..16]);
                        let log_ev = LedgerEvent {
                            t_unix_ms: now_ms_val,
                            session_id: &session_id_copy,
                            client_pub: &client_pub_copy,
                            op: "Move",
                            op_id: &op_id16,
                            delta: 0,
                            balance_before: 0,
                            balance_after: 0,
                            receipt_tip: &new_tip,
                        };
                        if let Err(e) = ledger.append(&log_ev) {
                            eprintln!("[GS] ledger append failed: {e:?}");
                        }
                    }

                    // update local tick counter
                    tick = new_tick;

                    // ---- 6) prepare WorldSnapshot ----
                    let mut others: Vec<([u8; 32], f32, f32)> =
                        Vec::with_capacity(guard.players.len().saturating_sub(1));

                    for (pubkey, st) in guard.players.iter() {
                        if *pubkey != ci.client_pub {
                            others.push((*pubkey, st.x, st.y));
                        }
                    }

                    let snapshot = WorldSnapshot {
                        tick,
                        you: (new_x, new_y),
                        others,
                    };

                    Ok(snapshot)
                })(); // drop mutex guard here

                // If validation or sim failed, kill client.
                let snapshot = match step_res {
                    Ok(s) => s,
                    Err(()) => {
                        break;
                    }
                };

                // Respond with an updated WorldSnapshot back to this client
                if let Err(e) = send_bin_tcp(&mut socket, &snapshot).await {
                    eprintln!("[GS] send WorldSnapshot to {peer_addr} failed: {e:?}");
                    break;
                }

                // tiny breather so a spammy client doesn't 100% busy-loop us
                sleep(Duration::from_millis(5)).await;
            }

            println!("[GS] client {} disconnected / recv error", peer_addr);
        });
    }
}
