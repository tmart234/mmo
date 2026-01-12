// crates/gs-sim/src/client_port.rs
use common::{
    crypto::{client_input_sign_bytes, now_ms, receipt_tip_update},
    framing::{recv_msg, send_msg},
    proto::{AuthoritativeEvent, ClientCmd, ClientToGs, PlayTicket, ServerHello, WorldSnapshot},
};
use ed25519_dalek::{Signature, VerifyingKey};
use quinn::{Endpoint, ServerConfig};
use std::{
    collections::VecDeque,
    convert::TryFrom,
    sync::{Arc, Mutex},
};
use tokio::{
    sync::watch,
    time::{sleep, Duration},
};

use crate::ledger::LedgerEvent;
use crate::state::{PlayerState, Shared};

const NONCE_WINDOW: u64 = 4; // allow nonce jumps up to +4
const TICKET_RING_MAX: usize = 32;

/// Configure QUIC server for GS client port.
fn configure_quic_server() -> anyhow::Result<ServerConfig> {
    // Generate self-signed certificate for local dev/testing
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let cert_der = cert.serialize_der()?;
    let priv_key = cert.serialize_private_key_der();

    let cert_chain = vec![rustls::pki_types::CertificateDer::from(cert_der)];
    let key_der = rustls::pki_types::PrivateKeyDer::try_from(priv_key)
        .map_err(|e| anyhow::anyhow!("Failed to parse private key: {}", e))?;

    let mut server_config = ServerConfig::with_single_cert(cert_chain, key_der)?;

    // Performance tuning for MMO
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_concurrent_bidi_streams(100_u32.into());
    transport_config.max_concurrent_uni_streams(100_u32.into());
    transport_config.keep_alive_interval(Some(Duration::from_secs(5)));

    server_config.transport = Arc::new(transport_config);
    Ok(server_config)
}

/// QUIC listener that talks to client instances (client-sim / client-bevy).
///
/// Security properties per client connection:
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
    // Configure and start QUIC server
    let server_config = configure_quic_server()?;
    let endpoint = Endpoint::server(server_config, "127.0.0.1:50000".parse()?)?;
    println!("[GS] QUIC client port listening on 127.0.0.1:50000");

    // Outer accept loop: one spawned task per client connection.
    let loop_start = std::time::Instant::now();
    let mut conn_counter = 0u32;

    'accept_loop: loop {
        println!(
            "[GS] {:?} [ACCEPT LOOP] waiting for connection #{}",
            loop_start.elapsed(),
            conn_counter + 1
        );

        let Some(connecting) = endpoint.accept().await else {
            eprintln!("[GS] QUIC endpoint closed");
            return Ok(());
        };

        println!(
            "[GS] {:?} [ACCEPT LOOP] incoming connection detected, starting handshake...",
            loop_start.elapsed()
        );

        let conn = match connecting.await {
            Ok(c) => {
                conn_counter += 1;
                println!(
                    "[GS] {:?} [ACCEPT LOOP] ✓ Connection #{} handshake complete",
                    loop_start.elapsed(),
                    conn_counter
                );
                c
            }
            Err(e) => {
                eprintln!(
                    "[GS] {:?} [ACCEPT LOOP] ✗ handshake failed: {e:?}",
                    loop_start.elapsed()
                );
                continue 'accept_loop;
            }
        };

        let peer_addr = conn.remote_address();
        let conn_id = conn.stable_id();
        println!(
            "[GS] {:?} [CONN #{}] peer={} conn_id={} ACCEPTED",
            loop_start.elapsed(),
            conn_counter,
            peer_addr,
            conn_id
        );

        // Verify ticket exists before spawning task
        if ticket_rx.borrow().is_none() {
            eprintln!(
                "[GS] {:?} no ticket available for client {}, rejecting",
                loop_start.elapsed(),
                peer_addr
            );
            continue 'accept_loop;
        }

        println!(
            "[GS] {:?} spawning handler task for {}",
            loop_start.elapsed(),
            peer_addr
        );

        // Spawn task IMMEDIATELY without blocking the main loop.
        // The task will accept the bi-stream, not the main loop.
        let shared_for_task = shared.clone();
        let revoke_rx_for_task = revoke_rx.clone();
        let ticket_rx_for_task = ticket_rx.clone();

        tokio::spawn(async move {
            let task_start = std::time::Instant::now();
            println!(
                "[GS] {:?} handler task started for {}",
                task_start.elapsed(),
                peer_addr
            );
            if let Err(e) = handle_client_connection(
                conn,
                peer_addr,
                shared_for_task,
                revoke_rx_for_task,
                ticket_rx_for_task,
            )
            .await
            {
                eprintln!("[GS] client {} error: {e:?}", peer_addr);
            }
        });
    }
}

/// Handle a single client connection: accept bi-stream, send ServerHello, then process inputs.
async fn handle_client_connection(
    conn: quinn::Connection,
    peer_addr: std::net::SocketAddr,
    shared: Shared,
    revoke_rx: watch::Receiver<bool>,
    ticket_rx: watch::Receiver<Option<PlayTicket>>,
) -> anyhow::Result<()> {
    use anyhow::{bail, Context};

    let task_start = std::time::Instant::now();
    let conn_id = conn.stable_id();

    println!(
        "[GS] {:?} [TASK {}] calling accept_bi() on conn_id={}...",
        task_start.elapsed(),
        peer_addr,
        conn_id
    );

    // Accept bi-stream from client
    let (mut send_stream, mut recv_stream) = conn
        .accept_bi()
        .await
        .context("accept bi-stream from client")?;

    println!(
        "[GS] {:?} [TASK {}] ✓ accept_bi() succeeded on conn_id={}",
        task_start.elapsed(),
        peer_addr,
        conn_id
    );

    // If we've already been revoked, refuse this client.
    if *revoke_rx.borrow() {
        bail!("session already revoked");
    }

    // Snapshot session_id and vs_pub exactly once for this client.
    let (session_id, vs_pub_bytes) = {
        let guard = shared.lock().unwrap();
        (guard.session_id, guard.vs_pub.to_bytes())
    };

    // Get the current ticket (should already be available since we checked in main loop).
    let local_ticket_rx = ticket_rx.clone();
    let first_ticket: PlayTicket = match local_ticket_rx.borrow().clone() {
        Some(t) => t,
        None => bail!("no ticket available"),
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

    println!("[GS] {} sending ServerHello...", peer_addr);
    let send_start = std::time::Instant::now();
    send_msg(&mut send_stream, &hello)
        .await
        .context("send ServerHello")?;
    println!(
        "[GS] {} ServerHello sent in {:?}",
        peer_addr,
        send_start.elapsed()
    );

    // Now handle client input loop
    let mut tick: u64 = 0;

    loop {
        // Hard revoke? Kill client immediately.
        if *revoke_rx.borrow() {
            eprintln!("[GS] closing client {} (revoked)", peer_addr);
            break;
        }

        // Receive exactly one client message.
        let msg_res = recv_msg::<ClientToGs>(&mut recv_stream).await;
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

        // If we didn't get an Input (i.e., was Bye), end the loop.
        let ci = match ci {
            Some(ci) => ci,
            None => break,
        };

        let now_ms_val = now_ms();

        // === Everything that touches shared state lives in this block ===
        // We do NOT hold the mutex across an .await.
        let step_res: Result<WorldSnapshot, ()> = (|| {
            // Snapshot GS-shared info we need BEFORE we await anything else.
            let mut guard = shared.lock().unwrap();

            // Phase 0: read current per-player state.
            let (prev_x, prev_y, prev_nonce) = match guard.players.get(&ci.client_pub) {
                Some(ps) => (ps.x, ps.y, ps.last_nonce),
                None => (0.0, 0.0, 0),
            };
            let prev_tip = guard.receipt_tip;

            // === Ticket-ring validation (newest → oldest) ===
            let ring_snapshot: Vec<PlayTicket> = {
                let r = ring.lock().unwrap();
                r.iter().cloned().collect()
            };

            let ticket_matches = |pt: &PlayTicket| -> bool {
                if now_ms_val < pt.not_before_ms || now_ms_val > pt.not_after_ms {
                    return false;
                }
                if pt.session_id != session_id {
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
            let ev_bytes = bincode::serialize(&ev).expect("serialize AuthoritativeEvent in GS");

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
        if let Err(e) = send_msg(&mut send_stream, &snapshot).await {
            eprintln!("[GS] send WorldSnapshot to {peer_addr} failed: {e:?}");
            break;
        }

        // tiny breather so a spammy client doesn't 100% busy-loop us
        sleep(Duration::from_millis(5)).await;
    }

    println!("[GS] client {} disconnected / recv error", peer_addr);
    Ok(())
}
