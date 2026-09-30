//! The VS's configuration.

/// Where a game server's binary is installed by default (`deploy/`).
pub const DEFAULT_GS_PROGRAM_PATH: &str = "/opt/fpp/gs-sim";

#[derive(Debug, Clone)]
pub struct VsConfig {
    /// Maximum time skew allowed for JoinRequest timestamp (default: 30 s,
    /// for cross-region clocks).
    pub join_max_skew_ms: u64,

    /// Revoke a game server after this long without a verified Checkpoint
    /// (default: 30 s; Checkpoints arrive once per epoch, about every second).
    pub checkpoint_timeout_ms: u64,

    /// Deadline for a new connection to finish the QUIC handshake, the
    /// challenge and its request (default: 10s). Idle connections are dropped.
    pub admission_timeout_ms: u64,

    /// TPM manufacturers' root certificates (DER): a game server's TPM 2.0
    /// evidence counts only with an EK certificate chaining to one.
    pub tpm_ek_roots: Vec<Vec<u8>>,

    /// Build Registry: SHA-256 of the GS builds CI made (with signed
    /// provenance), and a label for each. Non-empty: a game server is
    /// admitted only with TPM 2.0 evidence whose IMA log shows the kernel
    /// ran one of these at `gs_program_path` (F06). Empty: development,
    /// where a GS's build is only what it says.
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
            join_max_skew_ms: 30_000,
            checkpoint_timeout_ms: 30_000,
            admission_timeout_ms: 10_000,
            tpm_ek_roots: Vec::new(),
            build_registry: Vec::new(),
            gs_program_path: DEFAULT_GS_PROGRAM_PATH.to_string(),
            require_secure_boot: false,
        }
    }
}
