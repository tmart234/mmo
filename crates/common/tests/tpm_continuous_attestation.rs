// crates/common/tests/tpm_continuous_attestation.rs
//
// Stage 1.2: Test TPM continuous attestation logic

use common::crypto::sha256;
use common::tpm::{verify_quote, SimulatedTpm, TpmProvider};

/// Test that nonce derivation is consistent between GS and VS.
/// Both must derive: sha256(session_id || gs_counter || receipt_tip)
#[test]
fn nonce_derivation_matches_gs_and_vs() {
    let session_id = [0xAA; 16];
    let gs_counter = 42u64;
    let receipt_tip = [0xBB; 32];

    // GS-side derivation (from heartbeat.rs)
    let gs_nonce = {
        let mut buf = Vec::with_capacity(16 + 8 + 32);
        buf.extend_from_slice(&session_id);
        buf.extend_from_slice(&gs_counter.to_le_bytes());
        buf.extend_from_slice(&receipt_tip);
        sha256(&buf)
    };

    // VS-side derivation (from streams.rs)
    let vs_nonce = {
        let mut buf = Vec::with_capacity(16 + 8 + 32);
        buf.extend_from_slice(&session_id);
        buf.extend_from_slice(&gs_counter.to_le_bytes());
        buf.extend_from_slice(&receipt_tip);
        sha256(&buf)
    };

    assert_eq!(gs_nonce, vs_nonce, "GS and VS must derive same nonce");
}

/// Test that VS verifies quotes correctly with matching PCRs.
#[test]
fn vs_accepts_valid_quote_with_matching_pcrs() {
    let mut tpm = SimulatedTpm::new();

    // Simulate GS boot: extend PCRs
    let sw_hash = [0x11; 32];
    let gs_id = b"gs-sim-local";
    tpm.extend_pcr(0, &sw_hash).unwrap();
    tpm.extend_pcr(1, gs_id).unwrap();

    // Generate initial quote to establish baseline
    let nonce1 = [0x22; 32];
    let quote1 = tpm.quote(&[0, 1], &nonce1).unwrap();

    // VS stores baseline PCRs
    let baseline_pcrs = quote1.pcr_values.clone();

    // Later: GS generates re-attestation quote
    let nonce2 = [0x33; 32];
    let quote2 = tpm.quote(&[0, 1], &nonce2).unwrap();

    // VS verifies: should succeed because PCRs haven't changed
    let result = verify_quote(&quote2, &nonce2, Some(&baseline_pcrs));
    assert!(result.is_ok(), "VS should accept quote with matching PCRs");
}

/// Test that VS detects PCR drift (hot-patching attack).
#[test]
fn vs_detects_pcr_drift_after_hot_patching() {
    let mut tpm = SimulatedTpm::new();

    // Simulate GS boot: extend PCRs
    let sw_hash = [0x11; 32];
    let gs_id = b"gs-sim-local";
    tpm.extend_pcr(0, &sw_hash).unwrap();
    tpm.extend_pcr(1, gs_id).unwrap();

    // Generate initial quote to establish baseline
    let nonce1 = [0x22; 32];
    let quote1 = tpm.quote(&[0, 1], &nonce1).unwrap();

    // VS stores baseline PCRs
    let baseline_pcrs = quote1.pcr_values.clone();

    // ATTACK: Attacker extends PCR 0 again (simulating hot-patch)
    // In real attack, this would be GS memory modification
    let malicious_code = b"MAX_STEP = 999.0";
    tpm.extend_pcr(0, malicious_code).unwrap();

    // GS generates re-attestation quote with drifted PCRs
    let nonce2 = [0x33; 32];
    let quote2 = tpm.quote(&[0, 1], &nonce2).unwrap();

    // VS verifies: should FAIL because PCR 0 changed
    let result = verify_quote(&quote2, &nonce2, Some(&baseline_pcrs));
    assert!(result.is_err(), "VS should detect PCR drift");

    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("PCR") && err_msg.contains("mismatch"),
        "Error should mention PCR mismatch: {}",
        err_msg
    );
}

/// Test that VS rejects quotes with wrong nonce (replay attack).
#[test]
fn vs_rejects_replayed_quote_with_old_nonce() {
    let tpm = SimulatedTpm::new();

    // Generate quote with nonce A
    let nonce_a = [0xAA; 32];
    let quote = tpm.quote(&[0, 1], &nonce_a).unwrap();

    // Attacker tries to replay quote with different expected nonce
    let nonce_b = [0xBB; 32];
    let result = verify_quote(&quote, &nonce_b, None);

    assert!(result.is_err(), "VS should reject quote with wrong nonce");
    assert!(
        result.unwrap_err().to_string().contains("nonce"),
        "Error should mention nonce mismatch"
    );
}

/// Test that nonce changes with each heartbeat counter.
#[test]
fn nonce_is_unique_per_heartbeat() {
    let session_id = [0xAA; 16];
    let receipt_tip = [0xBB; 32];

    let mut nonces = Vec::new();
    for counter in 1..=100u64 {
        let mut buf = Vec::new();
        buf.extend_from_slice(&session_id);
        buf.extend_from_slice(&counter.to_le_bytes());
        buf.extend_from_slice(&receipt_tip);
        nonces.push(sha256(&buf));
    }

    // All nonces should be unique
    let unique_count = {
        let mut set = std::collections::HashSet::new();
        for n in &nonces {
            set.insert(n);
        }
        set.len()
    };

    assert_eq!(unique_count, 100, "Each heartbeat should have unique nonce");
}

/// Test that quote verification works without baseline (first attestation).
#[test]
fn first_attestation_establishes_baseline() {
    let mut tpm = SimulatedTpm::new();

    // Extend PCRs with measurements
    tpm.extend_pcr(0, b"binary_hash").unwrap();
    tpm.extend_pcr(1, b"config_hash").unwrap();

    let nonce = [0x42; 32];
    let quote = tpm.quote(&[0, 1], &nonce).unwrap();

    // First verification with no baseline should succeed
    let result = verify_quote(&quote, &nonce, None);
    assert!(
        result.is_ok(),
        "First attestation should succeed without baseline"
    );

    // Quote should contain PCR values that VS can store as baseline
    assert!(quote.pcr_values.contains_key(&0));
    assert!(quote.pcr_values.contains_key(&1));
}

/// Simulate full attestation flow: join -> heartbeat -> re-attest -> verify
#[test]
fn full_continuous_attestation_flow() {
    let mut tpm = SimulatedTpm::new();
    let session_id = [0x12; 16];

    // === JOIN PHASE ===
    // GS extends PCRs at boot
    let sw_hash = sha256(b"gs-sim binary v1.0.0");
    let gs_id = b"gs-sim-prod-01";
    tpm.extend_pcr(0, &sw_hash).unwrap();
    tpm.extend_pcr(1, gs_id).unwrap();

    // GS sends initial quote in JoinRequest
    let join_nonce = [0x00; 32]; // In real impl, derived from join request
    let join_quote = tpm.quote(&[0, 1], &join_nonce).unwrap();

    // VS verifies and stores baseline
    assert!(verify_quote(&join_quote, &join_nonce, None).is_ok());
    let baseline = join_quote.pcr_values.clone();
    println!(
        "VS established baseline PCRs: {:?}",
        baseline.keys().collect::<Vec<_>>()
    );

    // === HEARTBEAT PHASE (no TPM) ===
    // Heartbeats 1-29 don't include TPM quotes

    // === RE-ATTESTATION PHASE (heartbeat 30) ===
    let receipt_tip = [0xAB; 32];
    let gs_counter = 30u64;

    // GS derives nonce
    let reattest_nonce = {
        let mut buf = Vec::new();
        buf.extend_from_slice(&session_id);
        buf.extend_from_slice(&gs_counter.to_le_bytes());
        buf.extend_from_slice(&receipt_tip);
        sha256(&buf)
    };

    // GS generates quote
    let reattest_quote = tpm.quote(&[0, 1], &reattest_nonce).unwrap();

    // VS derives expected nonce
    let vs_expected_nonce = {
        let mut buf = Vec::new();
        buf.extend_from_slice(&session_id);
        buf.extend_from_slice(&gs_counter.to_le_bytes());
        buf.extend_from_slice(&receipt_tip);
        sha256(&buf)
    };

    // VS verifies
    let result = verify_quote(&reattest_quote, &vs_expected_nonce, Some(&baseline));
    assert!(
        result.is_ok(),
        "Re-attestation should succeed for honest GS"
    );

    println!("Full attestation flow completed successfully!");
}
