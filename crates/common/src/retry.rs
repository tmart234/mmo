//! Retry utilities with exponential backoff for network operations.

use crate::config::{is_transient_error, RetryConfig};
use anyhow::Result;
use std::future::Future;
use tokio::time::sleep;

/// Retry an async operation with exponential backoff.
///
/// # Arguments
/// * `config` - Retry configuration
/// * `operation_name` - Name for logging
/// * `f` - Async closure that returns Result<T>
///
/// # Returns
/// Result from the operation, or last error if all retries exhausted.
pub async fn retry_with_backoff<F, Fut, T>(
    config: &RetryConfig,
    operation_name: &str,
    mut f: F,
) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let mut attempt = 0;

    loop {
        match f().await {
            Ok(result) => {
                if attempt > 0 {
                    println!(
                        "[RETRY] {} succeeded after {} attempt(s)",
                        operation_name,
                        attempt + 1
                    );
                }
                return Ok(result);
            }
            Err(e) => {
                // Check if error is transient and we should retry
                let is_transient = is_transient_error(&e);
                let can_retry = config.should_retry(attempt);

                if !is_transient {
                    eprintln!(
                        "[RETRY] {} failed with non-transient error (attempt {}): {:?}",
                        operation_name,
                        attempt + 1,
                        e
                    );
                    return Err(e);
                }

                if !can_retry {
                    eprintln!(
                        "[RETRY] {} exhausted all {} attempts, giving up: {:?}",
                        operation_name, config.max_attempts, e
                    );
                    return Err(e);
                }

                let backoff = config.backoff_duration(attempt);
                eprintln!(
                    "[RETRY] {} failed (attempt {}), retrying in {:?}: {:?}",
                    operation_name,
                    attempt + 1,
                    backoff,
                    e
                );

                sleep(backoff).await;
                attempt += 1;
            }
        }
    }
}

/// Retry an async operation with custom retry logic.
///
/// # Arguments
/// * `config` - Retry configuration
/// * `operation_name` - Name for logging
/// * `should_retry_fn` - Custom function to determine if error is retryable
/// * `f` - Async closure that returns Result<T>
pub async fn retry_with_custom<F, Fut, T, R>(
    config: &RetryConfig,
    operation_name: &str,
    should_retry_fn: R,
    mut f: F,
) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T>>,
    R: Fn(&anyhow::Error) -> bool,
{
    let mut attempt = 0;

    loop {
        match f().await {
            Ok(result) => {
                if attempt > 0 {
                    println!(
                        "[RETRY] {} succeeded after {} attempt(s)",
                        operation_name,
                        attempt + 1
                    );
                }
                return Ok(result);
            }
            Err(e) => {
                let should_retry = should_retry_fn(&e);
                let can_retry = config.should_retry(attempt);

                if !should_retry {
                    eprintln!(
                        "[RETRY] {} failed with non-retryable error (attempt {}): {:?}",
                        operation_name,
                        attempt + 1,
                        e
                    );
                    return Err(e);
                }

                if !can_retry {
                    eprintln!(
                        "[RETRY] {} exhausted all {} attempts: {:?}",
                        operation_name, config.max_attempts, e
                    );
                    return Err(e);
                }

                let backoff = config.backoff_duration(attempt);
                eprintln!(
                    "[RETRY] {} failed (attempt {}), retrying in {:?}: {:?}",
                    operation_name,
                    attempt + 1,
                    backoff,
                    e
                );

                sleep(backoff).await;
                attempt += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    #[tokio::test]
    async fn test_retry_succeeds_after_failures() {
        let config = RetryConfig {
            max_attempts: 3,
            initial_backoff_ms: 10,
            max_backoff_ms: 100,
            ..Default::default()
        };

        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = counter.clone();

        let result = retry_with_backoff(&config, "test_op", || {
            let counter = counter_clone.clone();
            async move {
                let count = counter.fetch_add(1, Ordering::SeqCst);
                if count < 2 {
                    Err(anyhow::anyhow!("connection timeout"))
                } else {
                    Ok(42)
                }
            }
        })
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
        assert_eq!(counter.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_retry_fails_on_non_transient() {
        let config = RetryConfig {
            max_attempts: 3,
            initial_backoff_ms: 10,
            ..Default::default()
        };

        let result: Result<()> = retry_with_backoff(&config, "test_op", || async {
            Err(anyhow::anyhow!("invalid signature"))
        })
        .await;

        assert!(result.is_err());
    }
}
