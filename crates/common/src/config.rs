//! Network robustness configuration for distributed MMO protocol.
//!
//! Provides configurable timeouts, retry policies, and graceful degradation
//! for real-world network conditions (high latency, packet loss, geographic distribution).

use std::time::Duration;

/// Where a game server's binary is installed by default (`deploy/`).
pub const DEFAULT_GS_PROGRAM_PATH: &str = "/opt/fpp/gs-sim";

/// Network robustness configuration for VS (Validation Server).
#[derive(Debug, Clone)]
pub struct VsConfig {
    /// Maximum time skew allowed for JoinRequest timestamp (default: 30s for cross-region).
    pub join_max_skew_ms: u64,

    /// Revoke a game server after this long without a verified Checkpoint
    /// (default: 30 s; Checkpoints arrive once per epoch, about every second).
    pub checkpoint_timeout_ms: u64,

    /// Deadline for a new connection to finish the QUIC handshake, the
    /// challenge and its request (default: 10s). Idle connections are dropped.
    pub admission_timeout_ms: u64,

    /// Priority 3 (TOFU/TPM fix): allowlist of approved GS binary hashes (sw_hash).
    /// Each entry is a sha256 digest of an approved GS build.
    /// If the vec is **empty** the VS operates in TOFU/dev mode and accepts any hash.
    /// In production, populate this with the sha256 hashes of vetted GS releases.
    pub sw_hash_allowlist: Vec<[u8; 32]>,

    /// Priority 3 (TOFU/TPM fix): required PCR values that must be present in any
    /// TPM attestation quote.  Keys are PCR indices (0-7 cover firmware + OS +
    /// Secure Boot policy on most TPM 2.0 platforms).
    /// If the map is **empty** the VS operates in TOFU mode: the first quote from
    /// each GS establishes the baseline and subsequent quotes must match it.
    /// In production, fill this with known-good measurements for the approved OS
    /// and firmware stack so a compromised hypervisor cannot pass attestation.
    pub required_pcr_baselines: std::collections::BTreeMap<u8, [u8; 32]>,

    /// Enrolled TPM attestation keys (Ed25519 AK public keys) allowed to sign
    /// quotes. A quote carries its own AK, so without enrollment anyone can
    /// sign a "quote" for any PCR values with a key they made up. If the vec
    /// is **empty** (dev mode) any AK is accepted at join and then pinned for
    /// the session. Production replaces this with EK-certificate chains and
    /// credential activation in the Verifier (roadmap P3).
    pub trusted_ak_keys: Vec<[u8; 32]>,

    /// Reject a JoinRequest that carries no TPM quote (default: false).
    pub require_tpm_quote: bool,

    /// TPM manufacturers' root certificates (DER): a game server's TPM 2.0
    /// evidence counts only with an EK certificate chaining to one.
    pub tpm_ek_roots: Vec<Vec<u8>>,

    /// Build Registry: SHA-256 of the GS builds CI made (with signed
    /// provenance), and a label for each. Non-empty: a game server is
    /// admitted only with TPM 2.0 evidence whose IMA log shows the kernel
    /// ran one of these at `gs_program_path` (F06).
    pub build_registry: Vec<([u8; 32], String)>,

    /// Where the GS binary is installed, as the kernel names it in its IMA
    /// log.
    pub gs_program_path: String,

    /// Require the measured-boot log to show Secure Boot on.
    pub require_secure_boot: bool,
}

impl Default for VsConfig {
    fn default() -> Self {
        Self {
            join_max_skew_ms: 30_000, // 30s (was 10s)
            checkpoint_timeout_ms: 30_000,
            admission_timeout_ms: 10_000,
            sw_hash_allowlist: Vec::new(),
            required_pcr_baselines: std::collections::BTreeMap::new(),
            trusted_ak_keys: Vec::new(),
            require_tpm_quote: false,
            tpm_ek_roots: Vec::new(),
            build_registry: Vec::new(),
            gs_program_path: DEFAULT_GS_PROGRAM_PATH.to_string(),
            require_secure_boot: false,
        }
    }
}

/// Exponential backoff retry configuration.
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum retry attempts (default: 5).
    pub max_attempts: u32,

    /// Initial backoff duration (default: 100ms).
    pub initial_backoff_ms: u64,

    /// Maximum backoff duration (default: 5s).
    pub max_backoff_ms: u64,

    /// Backoff multiplier (default: 2.0 for exponential).
    pub backoff_multiplier: f64,

    /// Add random jitter to prevent thundering herd (default: 0.2 = ±20%).
    pub jitter_factor: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            initial_backoff_ms: 100,
            max_backoff_ms: 5_000,
            backoff_multiplier: 2.0,
            jitter_factor: 0.2,
        }
    }
}

impl RetryConfig {
    /// Calculate backoff duration for attempt N (0-indexed).
    /// Applies exponential backoff with jitter.
    pub fn backoff_duration(&self, attempt: u32) -> Duration {
        let base_ms = (self.initial_backoff_ms as f64
            * self.backoff_multiplier.powi(attempt as i32))
        .min(self.max_backoff_ms as f64);

        // Add jitter: ±(jitter_factor * base_ms)
        let jitter_range = base_ms * self.jitter_factor;
        let jitter = (rand::random::<f64>() * 2.0 - 1.0) * jitter_range;
        let final_ms = (base_ms + jitter).max(0.0) as u64;

        Duration::from_millis(final_ms)
    }

    /// Check if we should retry based on attempt number.
    pub fn should_retry(&self, attempt: u32) -> bool {
        attempt < self.max_attempts
    }
}

/// Helper to determine if an error is transient (should retry).
pub fn is_transient_error(e: &anyhow::Error) -> bool {
    let msg = format!("{:?}", e).to_lowercase();

    // Network-related transient errors
    msg.contains("timeout")
        || msg.contains("connection refused")
        || msg.contains("connection reset")
        || msg.contains("broken pipe")
        || msg.contains("would block")
        || msg.contains("try again")
        || msg.contains("temporarily unavailable")
        || msg.contains("network unreachable")
        || msg.contains("host unreachable")
        || msg.contains("connection aborted")
        || msg.contains("timed out")
        // QUIC-specific errors
        || msg.contains("application closed")
        || msg.contains("idle timeout")
        || msg.contains("locally closed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_retry_backoff() {
        let cfg = RetryConfig::default();

        // Attempt 0: ~100ms
        let d0 = cfg.backoff_duration(0);
        assert!(d0.as_millis() >= 80 && d0.as_millis() <= 120);

        // Attempt 1: ~200ms
        let d1 = cfg.backoff_duration(1);
        assert!(d1.as_millis() >= 160 && d1.as_millis() <= 240);

        // Attempt 10: capped at max_backoff_ms (5s)
        let d10 = cfg.backoff_duration(10);
        assert!(d10.as_millis() <= 6000); // 5s + jitter
    }

    #[test]
    fn test_should_retry() {
        let cfg = RetryConfig {
            max_attempts: 3,
            ..Default::default()
        };
        assert!(cfg.should_retry(0));
        assert!(cfg.should_retry(1));
        assert!(cfg.should_retry(2));
        assert!(!cfg.should_retry(3));
    }

    #[test]
    fn test_transient_error() {
        let e = anyhow::anyhow!("connection timeout");
        assert!(is_transient_error(&e));

        let e2 = anyhow::anyhow!("invalid signature");
        assert!(!is_transient_error(&e2));
    }
}
