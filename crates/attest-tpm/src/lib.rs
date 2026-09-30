//! Verifier appraisal of TPM 2.0 evidence (10 §5 step 4; findings F05,
//! F06, F21), in Rust with no TPM library: the Verifier parses and checks
//! what a TPM produced, it does not talk to one.
//!
//! - [`public`]: `TPMT_PUBLIC`, key attributes and Names.
//! - [`quote`]: `TPMS_ATTEST` quotes and `TPMT_SIGNATURE` (RSA-SSA, RSA-PSS,
//!   ECDSA P-256/P-384), the nonce, and the PCR digest.
//! - [`ek`]: EK certificates to a pinned manufacturer root.
//! - [`credential`]: `TPM2_MakeCredential` in software, which ties an AK to
//!   the EK (credential activation).
//! - [`eventlog`]: the measured-boot log, replayed, and Secure Boot's state.
//! - [`ima`]: the kernel's IMA log, replayed into PCR 10.
//! - [`appraise`]: all of it with a policy and a Build Registry: the
//!   program a machine runs, as the kernel measured it, is a registered
//!   build (F06).
//!
//! Tested against a real TPM 2.0 implementation (swtpm, with tpm2-tools):
//! `tests/swtpm.rs`.

pub mod appraise;
pub mod credential;
pub mod ek;
pub mod eventlog;
pub mod ima;
mod marshal;
pub mod public;
pub mod quote;

pub use appraise::{appraise, Appraisal, Evidence, Policy, Registry};
pub use credential::{make_credential, CredentialChallenge};
pub use ek::{verify_ek, Endorsement};
pub use public::Public;
pub use quote::{verify_quote, Pcrs, Quote};

/// `TPM_ALG_ID` values (TPM 2.0 Part 2, 6.3) and `TPM_ECC_CURVE` (6.4).
pub mod alg {
    pub const RSA: u16 = 0x0001;
    pub const SHA1: u16 = 0x0004;
    pub const AES: u16 = 0x0006;
    pub const SHA256: u16 = 0x000b;
    pub const SHA384: u16 = 0x000c;
    pub const SHA512: u16 = 0x000d;
    pub const NULL: u16 = 0x0010;
    pub const RSASSA: u16 = 0x0014;
    pub const RSAES: u16 = 0x0015;
    pub const RSAPSS: u16 = 0x0016;
    pub const OAEP: u16 = 0x0017;
    pub const ECDSA: u16 = 0x0018;
    pub const ECDH: u16 = 0x0019;
    pub const ECDAA: u16 = 0x001a;
    pub const ECC: u16 = 0x0023;
    pub const CFB: u16 = 0x0043;
    pub const NIST_P256: u16 = 0x0003;
    pub const NIST_P384: u16 = 0x0004;
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TpmError {
    #[error("malformed TPM structure: {0}")]
    Malformed(&'static str),
    #[error("unsupported: {0}")]
    Unsupported(&'static str),
    #[error("signature does not verify")]
    BadSignature,
    #[error("the quote is not over this nonce")]
    NonceMismatch,
    #[error("PCR values do not match the quoted digest")]
    PcrDigestMismatch,
    #[error("EK certificate: {0}")]
    Certificate(attest_core::AttestError),
    #[error("policy: {0}")]
    Policy(&'static str),
    #[error("cryptographic operation failed")]
    Crypto,
}
