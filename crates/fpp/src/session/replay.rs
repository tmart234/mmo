//! Sliding anti-replay window over packet counters (RFC 6479 style).

/// Counters older than this many below the highest seen are rejected.
pub const WINDOW: u64 = 2048;
const WORDS: usize = (WINDOW / 64) as usize;

#[derive(Clone, Debug)]
pub(crate) struct ReplayWindow {
    /// Highest counter accepted so far, plus one (0: none yet).
    next: u64,
    bits: [u64; WORDS],
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self {
            next: 0,
            bits: [0; WORDS],
        }
    }
}

impl ReplayWindow {
    fn bit(n: u64) -> (usize, u64) {
        let i = n % WINDOW;
        ((i / 64) as usize, 1 << (i % 64))
    }

    /// Whether `n` is new and inside the window. Call before decrypting; call
    /// [`mark`](Self::mark) only once the packet authenticated.
    pub fn check(&self, n: u64) -> bool {
        if n >= self.next {
            return true;
        }
        if self.next - n > WINDOW {
            return false;
        }
        let (w, m) = Self::bit(n);
        self.bits[w] & m == 0
    }

    pub fn mark(&mut self, n: u64) {
        if n >= self.next {
            if n - self.next >= WINDOW {
                self.bits = [0; WORDS];
            } else {
                for skipped in self.next..n {
                    let (w, m) = Self::bit(skipped);
                    self.bits[w] &= !m;
                }
            }
            self.next = n + 1;
        }
        let (w, m) = Self::bit(n);
        self.bits[w] |= m;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_each_counter_once_in_any_order() {
        let mut w = ReplayWindow::default();
        for n in [0, 2, 1, 5, 3, 4, 100, 99] {
            assert!(w.check(n), "{n} first time");
            w.mark(n);
            assert!(!w.check(n), "{n} replayed");
        }
        assert!(w.check(6) && w.check(98));
    }

    #[test]
    fn rejects_counters_older_than_the_window() {
        let mut w = ReplayWindow::default();
        w.mark(10_000);
        assert!(!w.check(10_000 - WINDOW - 1));
        assert!(w.check(10_000 - WINDOW + 1));
        w.mark(10_000 - WINDOW + 1);
        assert!(!w.check(10_000 - WINDOW + 1));
    }

    #[test]
    fn a_large_jump_clears_stale_bits() {
        let mut w = ReplayWindow::default();
        for n in 0..WINDOW {
            w.mark(n);
        }
        w.mark(3 * WINDOW);
        // Everything in the new window except 3*WINDOW itself is unseen.
        assert!(w.check(2 * WINDOW + 1));
        assert!(!w.check(3 * WINDOW));
        // Slots reused modulo WINDOW must not carry old marks.
        w.mark(3 * WINDOW + 5);
        assert!(w.check(3 * WINDOW + 4));
    }
}
