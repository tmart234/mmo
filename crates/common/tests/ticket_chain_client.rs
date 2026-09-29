//! F03: the client verifies every ticket and stops when the GS loses its blessing.

use common::{
    crypto::{sign, ticket_body_bytes},
    proto::PlayTicket,
    tickets::{ticket_body_hash, TicketChain, TICKET_MAX_SKEW_MS},
};
use ed25519_dalek::SigningKey;

const SESSION: [u8; 16] = *b"0123456789ABCDEF";
const CLIENT: [u8; 32] = [0xC1; 32];
const T0: u64 = 1_000_000;
const LIFETIME: u64 = 2_000;

fn vs_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn ticket(vs: &SigningKey, counter: u64, prev: [u8; 32], issued_at: u64) -> PlayTicket {
    let (nb, na) = (issued_at, issued_at + LIFETIME);
    let body = ticket_body_bytes(&SESSION, &[0u8; 32], counter, nb, na, &prev);
    PlayTicket {
        session_id: SESSION,
        client_binding: [0u8; 32],
        counter,
        not_before_ms: nb,
        not_after_ms: na,
        prev_ticket_hash: prev,
        sig_vs: sign(vs, &body),
    }
}

fn start(vs: &SigningKey) -> TicketChain {
    TicketChain::start(
        vs.verifying_key(),
        SESSION,
        CLIENT,
        ticket(vs, 1, [0; 32], T0),
        T0,
    )
    .expect("genuine first ticket")
}

fn err(r: anyhow::Result<()>) -> String {
    format!("{:#}", r.expect_err("must be rejected"))
}

#[test]
fn follows_a_genuine_chain() {
    let vs = vs_key(1);
    let mut chain = start(&vs);
    let t2 = ticket(&vs, 2, ticket_body_hash(chain.current()), T0 + 2_000);
    chain.advance(t2, T0 + 2_100).unwrap();
    let t3 = ticket(&vs, 3, ticket_body_hash(chain.current()), T0 + 4_000);
    chain.advance(t3, T0 + 4_100).unwrap();
    assert_eq!(chain.current().counter, 3);
    chain.ensure_fresh(T0 + 4_100).unwrap();
}

#[test]
fn rejects_first_ticket_not_signed_by_pinned_vs() {
    let pinned = vs_key(1);
    let attacker = vs_key(2);
    let forged = ticket(&attacker, 1, [0; 32], T0);
    let r = TicketChain::start(pinned.verifying_key(), SESSION, CLIENT, forged, T0);
    assert!(err(r.map(|_| ())).contains("did not verify"));
}

#[test]
fn rejects_first_ticket_for_other_session_or_client() {
    let vs = vs_key(1);
    let t = ticket(&vs, 1, [0; 32], T0);
    let r = TicketChain::start(vs.verifying_key(), [9; 16], CLIENT, t.clone(), T0);
    assert!(err(r.map(|_| ())).contains("session mismatch"));

    let mut bound = t;
    bound.client_binding = [0xEE; 32];
    let body = ticket_body_bytes(
        &SESSION,
        &bound.client_binding,
        1,
        bound.not_before_ms,
        bound.not_after_ms,
        &bound.prev_ticket_hash,
    );
    bound.sig_vs = sign(&vs, &body);
    let r = TicketChain::start(vs.verifying_key(), SESSION, CLIENT, bound, T0);
    assert!(err(r.map(|_| ())).contains("client_binding mismatch"));
}

#[test]
fn rejects_expired_first_ticket() {
    let vs = vs_key(1);
    let stale = ticket(&vs, 1, [0; 32], T0);
    let later = T0 + LIFETIME + TICKET_MAX_SKEW_MS + 1;
    let r = TicketChain::start(vs.verifying_key(), SESSION, CLIENT, stale, later);
    assert!(err(r.map(|_| ())).contains("expired"));
}

#[test]
fn rejects_forged_update() {
    // Correct counter and prev hash, but signed by someone other than the VS:
    // what a GS would have to do to keep a session going after revocation.
    let vs = vs_key(1);
    let mut chain = start(&vs);
    let forged = ticket(&vs_key(2), 2, ticket_body_hash(chain.current()), T0 + 2_000);
    assert!(err(chain.advance(forged, T0 + 2_100)).contains("did not verify"));
    assert_eq!(
        chain.current().counter,
        1,
        "chain unchanged after rejection"
    );
}

#[test]
fn rejects_replayed_skipped_and_forked_updates() {
    let vs = vs_key(1);
    let mut chain = start(&vs);
    let h1 = ticket_body_hash(chain.current());

    let replay = ticket(&vs, 1, [0; 32], T0);
    assert!(err(chain.advance(replay, T0 + 100)).contains("gap or replay"));

    let skip = ticket(&vs, 3, h1, T0 + 4_000);
    assert!(err(chain.advance(skip, T0 + 4_100)).contains("gap or replay"));

    let fork = ticket(&vs, 2, [0xAB; 32], T0 + 2_000);
    assert!(err(chain.advance(fork, T0 + 2_100)).contains("fork"));
}

#[test]
fn stops_trusting_gs_when_tickets_stop() {
    // Revocation = the VS stops issuing tickets. Whatever the GS does, the
    // client's current ticket runs out and it must stop sending inputs.
    let vs = vs_key(1);
    let chain = start(&vs);
    chain.ensure_fresh(T0 + LIFETIME).unwrap();
    chain
        .ensure_fresh(T0 + LIFETIME + TICKET_MAX_SKEW_MS)
        .unwrap();
    let e = err(chain.ensure_fresh(T0 + LIFETIME + TICKET_MAX_SKEW_MS + 1));
    assert!(e.contains("no longer blessed"), "{e}");
}

#[test]
fn rejects_update_that_is_already_expired() {
    let vs = vs_key(1);
    let mut chain = start(&vs);
    let t2 = ticket(&vs, 2, ticket_body_hash(chain.current()), T0 + 2_000);
    let too_late = T0 + 2_000 + LIFETIME + TICKET_MAX_SKEW_MS + 1;
    assert!(err(chain.advance(t2, too_late)).contains("expired"));
}
