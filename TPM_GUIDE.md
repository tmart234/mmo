# TPM (Trusted Platform Module) Integration Guide

> **Status (2026-09):** this guide describes the prototype. It is out of date in
> one direction and optimistic in another. The VS *does* call `verify_quote`
> today, but the check is not a real attestation: the quote's nonce is chosen by
> the GS, there is no EK certificate chain or AK credential activation, only
> simulated Ed25519 AKs verify, and `sw_hash` is self-reported (findings F04–F06
> in [docs/anticheat/07-gap-analysis-and-roadmap.md](docs/anticheat/07-gap-analysis-and-roadmap.md)).
> The replacement is Verifier-side appraisal of platform evidence
> ([docs/anticheat/03-architecture.md](docs/anticheat/03-architecture.md) §5.1).

This guide explains how to use TPM attestation in the MMO protocol for hardware-rooted trust.

## Overview

TPM provides **hardware-based attestation** that proves:
1. **Code Integrity:** The GS binary hasn't been modified
2. **Configuration Integrity:** The GS configuration is authentic
3. **Runtime Integrity:** The GS hasn't been tampered with during execution

## Architecture

### **PCR (Platform Configuration Register) Usage:**

| PCR | Purpose | Measurement |
|-----|---------|-------------|
| 0 | Code Measurement | SHA256(GS binary) |
| 1 | Configuration | SHA256(GS ID string) |
| 2-23 | Reserved | Future use (DLC hashes, player data, etc.) |

### **Attestation Flow:**

```text
┌─────────────┐                    ┌──────────────┐
│     GS      │                    │      VS      │
└──────┬──────┘                    └──────┬───────┘
       │                                  │
       │ 1. Boot: Extend PCRs             │
       │    PCR[0] = SHA256(binary)       │
       │    PCR[1] = SHA256(gs_id)        │
       │                                  │
       │ 2. JoinRequest + TpmQuote        │
       ├─────────────────────────────────>│
       │    {pcr_values, nonce, sig}      │
       │                                  │
       │                         3. Verify:│
       │                       - Signature │
       │                       - PCR[0]    │
       │                       - PCR[1]    │
       │                       - Nonce     │
       │                                  │
       │ 4. JoinAccept (if valid)         │
       │<─────────────────────────────────┤
       │                                  │
       │ 5. Heartbeat (every 2s)          │
       │    + TpmQuote (every 10th)       │
       ├─────────────────────────────────>│
       │                                  │
```

## Usage

### **Development (Simulated TPM):**

```bash
# Start GS with simulated TPM
cargo run --bin gs-sim -- --enable-tpm

# Output:
# [GS] initializing simulated TPM for attestation
# [GS] generating TPM attestation quote (PCRs 0,1)
```

**Simulated TPM features:**
- ✅ Full PCR bank (0-23)
- ✅ Ed25519 signing (software key)
- ✅ Quote generation
- ⚠️ No hardware root of trust (testing only!)

### **Production (Hardware TPM 2.0):**

**Prerequisites:**
```bash
# Install TPM 2.0 tools
sudo apt-get install tpm2-tools tpm2-abrmd

# Verify TPM is available
tpm2_pcrread

# Check EK certificate
tpm2_nvread 0x1c00002
```

**Hardware TPM integration** (TODO):
```rust
// Future implementation using tpm2-tss
use tpm2_tss::*;

pub struct HardwareTpm {
    context: ESYS_CONTEXT,
    ak_handle: ESYS_TR,
}

impl TpmProvider for HardwareTpm {
    fn quote(&self, pcr_indices: &[PcrIndex], nonce: &[u8; 32]) -> Result<TpmQuote> {
        // Call TPM2_Quote() via tpm2-tss
        // ...
    }
}
```

## TPM Quote Structure

```rust
pub struct TpmQuote {
    /// PCR values at time of quote
    pub pcr_values: HashMap<PcrIndex, PcrValue>,

    /// Nonce from verifier (prevents replay)
    pub nonce: [u8; 32],

    /// TPM signature over (pcr_values || nonce)
    /// Simulated: Ed25519 (64 bytes)
    /// Hardware: RSA-2048 or ECC-P256
    pub signature: Vec<u8>,

    /// Attestation Key public key
    pub ak_pub: Vec<u8>,

    /// Endorsement Key certificate (hardware only)
    pub ek_cert: Option<Vec<u8>>,
}
```

## Verification (VS Side)

**Current Status:** ⏳ Not yet implemented (VS accepts quotes but doesn't verify)

**Planned Verification Steps:**

```rust
// crates/vs/src/admission.rs
fn verify_join_request_tpm(jr: &JoinRequest) -> Result<()> {
    let Some(ref quote) = jr.tpm_quote else {
        return Ok(()); // TPM optional
    };

    // 1. Verify signature
    let ak_pub = parse_attestation_key(&quote.ak_pub)?;
    let message = bincode::serialize(&(&quote.pcr_values, &quote.nonce))?;
    verify_signature(&ak_pub, &message, &quote.signature)?;

    // 2. Check nonce matches JoinRequest nonce
    let mut expected_nonce = [0u8; 32];
    expected_nonce[..16].copy_from_slice(&jr.nonce);
    if quote.nonce != expected_nonce {
        bail!("TPM quote nonce mismatch");
    }

    // 3. Verify PCR[0] matches sw_hash
    let pcr0 = quote.pcr_values.get(&0)
        .ok_or_else(|| anyhow!("PCR[0] missing from quote"))?;

    // PCR[0] should be: SHA256(0 || sw_hash)
    // (because PCRs start at 0, first extend is SHA256(0^32 || data))
    let expected_pcr0 = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update([0u8; 32]); // Initial PCR value
        hasher.update(jr.sw_hash);
        let result: [u8; 32] = hasher.finalize().into();
        result
    };

    if pcr0 != &expected_pcr0 {
        bail!("PCR[0] mismatch: binary hash doesn't match TPM measurement");
    }

    // 4. Verify EK certificate chain (hardware TPM only)
    if let Some(ref ek_cert) = quote.ek_cert {
        verify_ek_certificate_chain(ek_cert)?;
    }

    Ok(())
}
```

## Testing

### **Test Simulated TPM:**

```bash
# Run tests
cargo test -p common tpm

# Expected output:
# test tpm::tests::test_simulated_tpm_quote ... ok
# test tpm::tests::test_pcr_extension ... ok
# test tpm::tests::test_deterministic_tpm ... ok
```

### **Test Quote Generation:**

```rust
use common::tpm::{SimulatedTpm, TpmProvider};

let mut tpm = SimulatedTpm::new();

// Extend PCR 0 with binary hash
let binary_hash = [0x42; 32];
tpm.extend_pcr(0, &binary_hash).unwrap();

// Generate quote
let nonce = [0x99; 32];
let quote = tpm.quote(&[0, 1], &nonce).unwrap();

assert_eq!(quote.nonce, nonce);
assert!(quote.pcr_values.contains_key(&0));
assert!(!quote.signature.is_empty());
```

### **Test Quote Verification:**

```rust
use common::tpm::verify_quote;

// Verify quote matches expected values
let expected_pcrs = HashMap::from([(0, pcr0_value)]);
verify_quote(&quote, &nonce, Some(&expected_pcrs)).unwrap();
```

## Security Considerations

### **Simulated TPM (Development):**
- ⚠️ **NO hardware root of trust**
- ⚠️ Software key can be extracted
- ⚠️ PCRs can be manipulated
- ✅ Good for protocol testing
- ✅ CI/CD integration

### **Hardware TPM (Production):**
- ✅ Hardware-protected signing key
- ✅ Tamper-resistant PCRs
- ✅ EK certificate from manufacturer
- ✅ Secure boot chain verification
- ⚠️ Requires physical TPM chip

### **Attack Mitigations:**

| Attack | Mitigation |
|--------|-----------|
| **Replay Attack** | Nonce in quote (VS generates fresh nonce) |
| **Binary Modification** | PCR[0] verification against sw_hash |
| **Configuration Tampering** | PCR[1] verification against expected GS ID |
| **Quote Forgery** | Signature verification with AK public key |
| **AK Key Substitution** | EK certificate chain validation (hardware) |

## Roadmap

### **Phase 1: Foundation** ✅
- [x] TPM abstraction layer (`TpmProvider` trait)
- [x] Simulated TPM implementation
- [x] Protocol integration (JoinRequest, Heartbeat)
- [x] GS sends TPM quotes

### **Phase 2: Verification** ⏳
- [ ] VS quote signature verification
- [ ] PCR value validation
- [ ] Nonce checking
- [ ] Integration tests

### **Phase 3: Hardware** 📅
- [ ] Hardware TPM implementation (tpm2-tss)
- [ ] EK certificate chain validation
- [ ] Sealed storage for GS secrets
- [ ] Performance benchmarking

### **Phase 4: Advanced** 📅
- [ ] Client-side TPM attestation
- [ ] Multi-PCR policies (require PCRs 0+1+2)
- [ ] TPM-based key derivation
- [ ] Remote attestation protocol (RATS)

## Performance

### **Simulated TPM:**
- Quote generation: ~100 μs
- PCR extend: ~50 μs
- Memory: ~4 KB (24 PCRs × 32 bytes + keys)

### **Hardware TPM 2.0:**
- Quote generation: ~50-200 ms (hardware dependent)
- PCR extend: ~10-50 ms
- Memory: Minimal (handled by TPM chip)

**Recommendation:** Generate TPM quotes **only when needed**:
- Always in JoinRequest
- Every 10th heartbeat (not every heartbeat)
- On configuration change

## Troubleshooting

### **"TPM not available"**
```bash
# Check TPM device
ls -l /dev/tpm*

# Check kernel module
lsmod | grep tpm

# Load module if needed
sudo modprobe tpm_tis
```

### **"PCR read failed"**
```bash
# Check TPM resource manager
sudo systemctl status tpm2-abrmd

# Direct PCR read
tpm2_pcrread sha256:0,1
```

### **"Quote verification failed"**
- Check nonce matches
- Verify PCR values are extended in correct order
- Ensure AK public key format is correct

## References

- TPM 2.0 Spec: https://trustedcomputinggroup.org/resource/tpm-library-specification/
- tpm2-tss library: https://github.com/tpm2-software/tpm2-tss
- Remote Attestation: https://datatracker.ietf.org/doc/draft-ietf-rats-architecture/

---

**Status:** ✅ Simulated TPM ready for testing | ⏳ Hardware TPM pending | ⏳ VS verification pending
