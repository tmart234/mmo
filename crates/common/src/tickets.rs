use crate::crypto::{ticket_body_bytes, ticket_hash_next, verify_ticket_sig};
use crate::proto::PlayTicket;
use anyhow::{bail, Result};
use ed25519_dalek::VerifyingKey;

/// Coarse skew allowance for ticket times.
pub const TICKET_MAX_SKEW_MS: u64 = 1_500;

/// Is the ticket valid "now", in a coarse time window?
#[inline]
pub fn ticket_is_fresh(now_ms: u64, not_before_ms: u64, not_after_ms: u64) -> bool {
    let nb = not_before_ms.saturating_sub(TICKET_MAX_SKEW_MS);
    let na = not_after_ms.saturating_add(TICKET_MAX_SKEW_MS);
    now_ms >= nb && now_ms <= na
}

/// Hash of a ticket's signed body; the next ticket's `prev_ticket_hash`.
pub fn ticket_body_hash(t: &PlayTicket) -> [u8; 32] {
    ticket_hash_next(&ticket_body_bytes(
        &t.session_id,
        &t.client_binding,
        t.counter,
        t.not_before_ms,
        t.not_after_ms,
        &t.prev_ticket_hash,
    ))
}

/// A client's view of the VS ticket chain for one GS session.
///
/// The client trusts a GS only while it holds a fresh ticket signed by the
/// pinned VS, and every later ticket must extend the same chain. When the VS
/// stops issuing tickets (revocation), the current ticket expires and
/// `ensure_fresh` fails, whatever the GS keeps sending.
pub struct TicketChain {
    vs: VerifyingKey,
    session_id: [u8; 16],
    client_pub: [u8; 32],
    current: PlayTicket,
    current_hash: [u8; 32],
}

impl TicketChain {
    /// Start from the ticket in ServerHello.
    pub fn start(
        vs: VerifyingKey,
        session_id: [u8; 16],
        client_pub: [u8; 32],
        first: PlayTicket,
        now_ms: u64,
    ) -> Result<Self> {
        check_ticket(&vs, &session_id, &client_pub, &first, now_ms)?;
        Ok(Self {
            vs,
            session_id,
            client_pub,
            current_hash: ticket_body_hash(&first),
            current: first,
        })
    }

    pub fn current(&self) -> &PlayTicket {
        &self.current
    }

    /// Accept the next ticket: exactly one counter ahead and linked by hash.
    pub fn advance(&mut self, next: PlayTicket, now_ms: u64) -> Result<()> {
        if next.counter != self.current.counter + 1 {
            bail!(
                "ticket chain gap or replay: got #{}, expected #{}",
                next.counter,
                self.current.counter + 1
            );
        }
        if next.prev_ticket_hash != self.current_hash {
            bail!(
                "ticket chain fork: #{} does not extend #{}",
                next.counter,
                self.current.counter
            );
        }
        check_ticket(&self.vs, &self.session_id, &self.client_pub, &next, now_ms)?;
        self.current_hash = ticket_body_hash(&next);
        self.current = next;
        Ok(())
    }

    /// Fails once the current ticket has expired: the VS has stopped blessing the GS.
    pub fn ensure_fresh(&self, now_ms: u64) -> Result<()> {
        let t = &self.current;
        if !ticket_is_fresh(now_ms, t.not_before_ms, t.not_after_ms) {
            bail!(
                "ticket #{} expired: GS is no longer blessed by the VS",
                t.counter
            );
        }
        Ok(())
    }
}

fn check_ticket(
    vs: &VerifyingKey,
    session_id: &[u8; 16],
    client_pub: &[u8; 32],
    t: &PlayTicket,
    now_ms: u64,
) -> Result<()> {
    if t.session_id != *session_id {
        bail!("ServerHello session mismatch between GS and ticket");
    }
    if t.client_binding != [0u8; 32] && t.client_binding != *client_pub {
        bail!("ticket client_binding mismatch: this ticket isn't for our client_pub");
    }
    if !verify_ticket_sig(vs, t) {
        bail!("VS signature on PlayTicket did not verify");
    }
    if !ticket_is_fresh(now_ms, t.not_before_ms, t.not_after_ms) {
        bail!("ticket #{} is expired or not yet valid", t.counter);
    }
    Ok(())
}
