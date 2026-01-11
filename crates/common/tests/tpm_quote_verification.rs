// Test TPM quote verification logic

use common::tpm::{SimulatedTpm, TpmProvider, verify_quote};
use std::collections::HashMap;

#[test]
fn test_tpm_quote_verification_success() {
    let mut tpm = SimulatedTpm::new();

    // Extend some PCRs
    tpm.extend_pcr(0, b"bootloader").unwrap();
    tpm.extend_pcr(1, b"kernel").unwrap();

    // Generate a quote
    let nonce = [42u8; 32];
    let quote = tpm.quote(&[0, 1], &nonce).unwrap();

    // Verify the quote (should succeed)
    assert!(verify_quote(&quote, &nonce, None).is_ok());
}

#[test]
fn test_tpm_quote_verification_wrong_nonce() {
    let tpm = SimulatedTpm::new();

    let nonce = [42u8; 32];
    let quote = tpm.quote(&[0], &nonce).unwrap();

    // Try to verify with wrong nonce
    let wrong_nonce = [43u8; 32];
    let result = verify_quote(&quote, &wrong_nonce, None);

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("nonce mismatch"));
}

#[test]
fn test_tpm_quote_verification_pcr_check() {
    let mut tpm = SimulatedTpm::new();

    // Extend PCR 0
    tpm.extend_pcr(0, b"measurement").unwrap();
    let expected_pcr0 = tpm.read_pcr(0).unwrap();

    // Generate quote
    let nonce = [42u8; 32];
    let quote = tpm.quote(&[0], &nonce).unwrap();

    // Verify with correct expected PCR values
    let mut expected_pcrs = HashMap::new();
    expected_pcrs.insert(0, expected_pcr0);
    assert!(verify_quote(&quote, &nonce, Some(&expected_pcrs)).is_ok());

    // Verify with wrong expected PCR values
    let mut wrong_pcrs = HashMap::new();
    wrong_pcrs.insert(0, [0u8; 32]); // Wrong value
    let result = verify_quote(&quote, &nonce, Some(&wrong_pcrs));
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("PCR[0] mismatch"));
}

#[test]
fn test_tpm_quote_verification_invalid_signature() {
    let tpm = SimulatedTpm::new();

    let nonce = [42u8; 32];
    let mut quote = tpm.quote(&[0], &nonce).unwrap();

    // Corrupt the signature
    quote.signature[0] ^= 0xFF;

    let result = verify_quote(&quote, &nonce, None);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("verification failed"));
}

#[tokio::test]
async fn test_tpm_quote_with_timeout() {
    use tokio::time::{timeout, Duration};

    let tpm = SimulatedTpm::new();
    let nonce = [42u8; 32];

    // Generate quote with timeout
    let quote_result = timeout(Duration::from_secs(1), async {
        tpm.quote(&[0, 1, 2], &nonce)
    }).await;

    assert!(quote_result.is_ok(), "TPM quote generation should complete within timeout");
    let quote = quote_result.unwrap().unwrap();

    // Verify quote with timeout
    let verify_result = timeout(Duration::from_secs(1), async {
        verify_quote(&quote, &nonce, None)
    }).await;

    assert!(verify_result.is_ok(), "TPM quote verification should complete within timeout");
    assert!(verify_result.unwrap().is_ok());
}
