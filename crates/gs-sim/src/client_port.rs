// crates/gs-sim/src/client_port.rs
use common::{
    crypto::{client_input_sign_bytes, now_ms, receipt_tip_update},
    framing::{recv_msg, send_msg_continue},
    proto::{
        AuthoritativeEvent, ClientCmd, ClientHello, ClientToGs, GsToClient, PlayTicket,
        ServerHello, TicketUpdate, WorldSnapshot,
    },
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
    time::{sleep, timeout, Duration},
};

use crate::ledger::LedgerEvent;
use crate::state::{CmdKey, OpResult, PlayerState, Shared, TokenBucket};

const NONCE_WINDOW: u64 = 4; // allow nonce jumps up to +4
const TICKET_RING_MAX: usize = 32;
const CLIENT_HELLO_TIMEOUT_SECS: u64 = 10;
/// Grace period (ms) for ticket expiration to handle clock skew and race conditions.
/// A ticket that expired within this window is still accepted if it's in the ring.
const TICKET_EXPIRY_GRACE_MS: u64 = 2000;

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
///  - client must send ClientHello first (materializes QUIC stream)
///  - client must staple a fresh VS-signed PlayTicket
///  - ticket must match our session / be within time window
///  - ticket.client_binding must match client_pub (if bound)
///  - client input must be signed with client_pub
///  - nonce must strictly increase per client_pub
///  - dx/dy is clamped server-side (anti-speedhack)
///  - we update per-player world state in shared memory
///  - we fold BOTH the ClientInput and an AuthoritativeEvent into receipt_tip
///  - we respond with a WorldSnapshot including you + others
///  - Stage 1.1: SpendCoins operations are idempotent via op_id LRU cache
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

/// Handle a single client connection: accept bi-stream, receive ClientHello,
/// send ServerHello, then process inputs.
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

    // =========================================================================
    // Step 1: Accept bi-stream from client
    // =========================================================================
    println!(
        "[GS] {:?} [TASK {}] calling accept_bi() on conn_id={} \
         (waiting for client to send data)...",
        task_start.elapsed(),
        peer_addr,
        conn_id
    );

    let accept_timeout = Duration::from_secs(CLIENT_HELLO_TIMEOUT_SECS);
    let (mut send_stream, mut recv_stream) = timeout(accept_timeout, conn.accept_bi())
        .await
        .map_err(|_| {
            eprintln!(
                "[GS] {:?} [TASK {}] TIMEOUT waiting for client to open bi-stream after {}s",
                task_start.elapsed(),
                peer_addr,
                CLIENT_HELLO_TIMEOUT_SECS
            );
            anyhow::anyhow!("timeout waiting for client bi-stream")
        })?
        .context("accept bi-stream from client")?;

    println!(
        "[GS] {:?} [TASK {}] ✓ accept_bi() succeeded on conn_id={}",
        task_start.elapsed(),
        peer_addr,
        conn_id
    );

    // =========================================================================
    // Step 2: Receive ClientHello
    // =========================================================================
    println!(
        "[GS] {:?} [TASK {}] waiting for ClientHello (timeout={}s)...",
        task_start.elapsed(),
        peer_addr,
        CLIENT_HELLO_TIMEOUT_SECS
    );

    let client_hello: ClientHello = timeout(
        Duration::from_secs(CLIENT_HELLO_TIMEOUT_SECS),
        recv_msg(&mut recv_stream),
    )
    .await
    .map_err(|_| {
        eprintln!(
            "[GS] {:?} [TASK {}] TIMEOUT waiting for ClientHello after {}s",
            task_start.elapsed(),
            peer_addr,
            CLIENT_HELLO_TIMEOUT_SECS
        );
        anyhow::anyhow!("timeout waiting for ClientHello")
    })?
    .context("recv ClientHello")?;

    println!(
        "[GS] {:?} [TASK {}] ✓ ClientHello received (client_pub={}, proto_v={})",
        task_start.elapsed(),
        peer_addr,
        hex::encode(&client_hello.client_pub[..4]),
        client_hello.protocol_version
    );

    // Validate protocol version
    if client_hello.protocol_version != ClientHello::CURRENT_PROTOCOL_VERSION {
        eprintln!(
            "[GS] {:?} [TASK {}] protocol version mismatch: client={}, server={}",
            task_start.elapsed(),
            peer_addr,
            client_hello.protocol_version,
            ClientHello::CURRENT_PROTOCOL_VERSION
        );
    }

    // If we've already been revoked, refuse this client.
    if *revoke_rx.borrow() {
        bail!("session already revoked");
    }

    // Snapshot session_id and vs_pub exactly once for this client.
    let (session_id, vs_pub_bytes) = {
        let guard = shared.lock().unwrap();
        (guard.session_id, guard.vs_pub.to_bytes())
    };

    // Get the current ticket
    let local_ticket_rx = ticket_rx.clone();
    let first_ticket: PlayTicket = match local_ticket_rx.borrow().clone() {
        Some(t) => t,
        None => bail!("no ticket available"),
    };

    // === Ticket ring so we accept recently rolled tickets even when client idles ===
    let ring: Arc<Mutex<VecDeque<PlayTicket>>> = Arc::new(Mutex::new(VecDeque::new()));
    let latest_sent_counter: Arc<std::sync::atomic::AtomicU64> =
        Arc::new(std::sync::atomic::AtomicU64::new(first_ticket.counter));
    {
        let mut r = ring.lock().unwrap();
        r.push_back(first_ticket.clone());
    }
    // Watcher that pushes every new ticket into the ring
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

    // =========================================================================
    // Step 3: Send ServerHello back to client
    // =========================================================================
    let hello = ServerHello {
        session_id,
        ticket: first_ticket.clone(),
        vs_pub: vs_pub_bytes,
    };

    println!(
        "[GS] {:?} [TASK {}] sending ServerHello (session={}, ticket_ctr={})...",
        task_start.elapsed(),
        peer_addr,
        hex::encode(&session_id[..4]),
        first_ticket.counter
    );

    let send_start = std::time::Instant::now();
    send_msg_continue(&mut send_stream, &hello)
        .await
        .context("send ServerHello")?;

    println!(
        "[GS] {:?} [TASK {}] ✓ ServerHello sent in {:?}",
        task_start.elapsed(),
        peer_addr,
        send_start.elapsed()
    );

    // =========================================================================
    // Step 4: Main input loop - process ClientInput messages
    // =========================================================================
    let mut tick: u64 = 0;
    let expected_client_pub = client_hello.client_pub;

    loop {
        // Hard revoke? Kill client immediately.
        if *revoke_rx.borrow() {
            eprintln!("[GS] closing client {} (revoked)", peer_addr);
            break;
        }

        // Receive exactly one client message.
        let msg_res = recv_msg::<ClientToGs>(&mut recv_stream).await;
        let ci = match msg_res {
            Ok(ClientToGs::Input(ci)) => Some(*ci),
            Ok(ClientToGs::Bye) => {
                println!("[GS] client {} said Bye; closing gracefully", peer_addr);
                break;
            }
            Err(e) => {
                eprintln!("[GS] recv ClientInput error from {peer_addr}: {e:?}");
                break;
            }
        };

        let ci = match ci {
            Some(ci) => ci,
            None => break,
        };

        // Verify client_pub matches what they declared in ClientHello
        if ci.client_pub != expected_client_pub {
            eprintln!(
                "[GS] client_pub mismatch from {}: expected {}, got {}",
                peer_addr,
                hex::encode(&expected_client_pub[..4]),
                hex::encode(&ci.client_pub[..4])
            );
            break;
        }

        let now_ms_val = now_ms();

        // === Everything that touches shared state lives in this block ===
        let step_res: Result<WorldSnapshot, ()> = (|| {
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
                if now_ms_val < pt.not_before_ms
                    || now_ms_val > pt.not_after_ms.saturating_add(TICKET_EXPIRY_GRACE_MS)
                {
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
                    "[GS] client_nonce jump too large from {peer_addr} \
                     (got {}, last {}, window {})",
                    ci.client_nonce, prev_nonce, NONCE_WINDOW
                );
                return Err(());
            }

            // ---- 2a) rate-limit per-cmd using TokenBucket ----
            let rt = guard.runtime_mut();

            let key = (ci.client_pub, CmdKey::Move);
            match rt.buckets.entry(key) {
                std::collections::hash_map::Entry::Occupied(mut o) => {
                    if !o.get_mut().take(1.0, now_ms_val) {
                        eprintln!("[GS] rate limit: too many Move ops from {peer_addr}");
                        return Err(());
                    }
                }
                std::collections::hash_map::Entry::Vacant(v) => {
                    let mut b = TokenBucket::new(10.0, 10.0, now_ms_val);
                    let _ = b.take(1.0, now_ms_val);
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
            let (new_x, new_y) = match &ci.cmd {
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
                ClientCmd::SpendCoins(sc) => {
                    // =========================================================
                    // Stage 1.1: Economy Idempotency Check
                    //
                    // Before processing any economy operation, check if we've
                    // already processed this (client_pub, op_id) pair.
                    // If yes, this is a replay - ignore but don't error.
                    // If no, process and cache the result.
                    // =========================================================

                    let rt = guard.runtime_mut();

                    // Check idempotency: have we already processed this op?
                    if let Some(cached_result) = rt.check_idempotency(&ci.client_pub, &sc.op_id) {
                        println!(
                            "[GS] SpendCoins replay detected from {peer_addr} \
                             (op_id={}, processed_at={}ms ago, success={})",
                            hex::encode(&sc.op_id[..4]),
                            now_ms_val.saturating_sub(cached_result.processed_at_ms),
                            cached_result.success
                        );
                        // Return current position - don't change state
                        return Ok(WorldSnapshot {
                            tick,
                            you: (prev_x, prev_y),
                            others: guard
                                .players
                                .iter()
                                .filter(|(pk, _)| **pk != ci.client_pub)
                                .map(|(pk, ps)| (*pk, ps.x, ps.y))
                                .collect(),
                        });
                    }

                    // Not a replay - process the operation
                    // TODO: Implement actual economy logic here
                    // For now, just log and record the operation

                    println!(
                        "[GS] SpendCoins NEW op from {peer_addr}: op_id={}, amount={}",
                        hex::encode(&sc.op_id[..4]),
                        sc.amount
                    );

                    // Record the operation in the idempotency cache
                    // Re-borrow runtime since we dropped it in the check
                    let rt = guard.runtime_mut();
                    rt.record_op(
                        ci.client_pub,
                        sc.op_id,
                        OpResult {
                            processed_at_ms: now_ms_val,
                            success: true, // Would be based on actual operation result
                            balance_after: Some(0), // Would be actual balance
                        },
                    );

                    // SpendCoins doesn't change position
                    (prev_x, prev_y)
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

            // Priority 1 (DA Black Hole fix): buffer the raw signed ClientInput bytes
            // so the heartbeat loop can ship them to VS as da_payload, guaranteeing
            // the VS can durably store them before signing the ProtectedReceipt.
            guard.da_buffer.push(ci_bytes);

            // Append to ledger if enabled
            let session_id_copy = guard.session_id;
            let client_pub_copy = ci.client_pub;
            if let Some(ledger) = guard.ledger.as_mut() {
                let mut op_id16 = [0u8; 16];
                op_id16.copy_from_slice(&ci.client_sig[..16]);
                let log_ev = LedgerEvent {
                    t_unix_ms: now_ms_val,
                    session_id: &session_id_copy,
                    client_pub: &client_pub_copy,
                    op: match &ci.cmd {
                        ClientCmd::Move { .. } => "Move",
                        ClientCmd::SpendCoins(_) => "SpendCoins",
                    },
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
        })();

        // If validation or sim failed, kill client.
        let snapshot = match step_res {
            Ok(s) => s,
            Err(()) => {
                break;
            }
        };

        // Check if there's a newer ticket to send to this client
        let maybe_ticket_update: Option<(GsToClient, u64)> = {
            use std::sync::atomic::Ordering;
            let ring_guard = ring.lock().unwrap();
            if let Some(newest) = ring_guard.back() {
                let last_sent = latest_sent_counter.load(Ordering::SeqCst);
                if newest.counter > last_sent {
                    let new_counter = newest.counter;
                    let update = GsToClient::TicketUpdate(TicketUpdate {
                        ticket: newest.clone(),
                    });
                    Some((update, new_counter))
                } else {
                    None
                }
            } else {
                None
            }
        };

        // Send ticket update if we have one
        if let Some((update, new_counter)) = maybe_ticket_update {
            use std::sync::atomic::Ordering;
            if let Err(e) = send_msg_continue(&mut send_stream, &update).await {
                eprintln!("[GS] send TicketUpdate to {peer_addr} failed: {e:?}");
                break;
            }
            latest_sent_counter.store(new_counter, Ordering::SeqCst);
        }

        // Respond with an updated WorldSnapshot back to this client
        let ws_msg = GsToClient::WorldSnapshot(snapshot);
        if let Err(e) = send_msg_continue(&mut send_stream, &ws_msg).await {
            eprintln!("[GS] send WorldSnapshot to {peer_addr} failed: {e:?}");
            break;
        }

        // tiny breather
        sleep(Duration::from_millis(5)).await;
    }

    println!("[GS] client {} disconnected / recv error", peer_addr);
    Ok(())
}
