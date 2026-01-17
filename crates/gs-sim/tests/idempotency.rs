// crates/gs-sim/tests/idempotency.rs
//
// Stage 1.1: Test economy operation idempotency

use common::proto::OpId;
use gs_sim::state::{OpResult, PlayerRuntime};

#[test]
fn spend_coins_idempotency_detects_replay() {
    let mut runtime = PlayerRuntime::new();
    let client_pub = [0xAA; 32];
    let op_id: OpId = [0xBB; 16];

    // First operation: should be new
    assert!(
        runtime.check_idempotency(&client_pub, &op_id).is_none(),
        "First operation should not be detected as replay"
    );

    // Record the operation
    runtime.record_op(
        client_pub,
        op_id,
        OpResult {
            processed_at_ms: 1000,
            success: true,
            balance_after: Some(90),
        },
    );

    // Second operation with same op_id: should be replay
    let cached = runtime.check_idempotency(&client_pub, &op_id);
    assert!(
        cached.is_some(),
        "Second operation should be detected as replay"
    );
    assert_eq!(cached.unwrap().processed_at_ms, 1000);
    assert!(cached.unwrap().success);
}

#[test]
fn different_clients_can_use_same_op_id() {
    let mut runtime = PlayerRuntime::new();
    let client_a = [0xAA; 32];
    let client_b = [0xBB; 32];
    let op_id: OpId = [0xCC; 16]; // Same op_id for both

    // Client A records an operation
    runtime.record_op(
        client_a,
        op_id,
        OpResult {
            processed_at_ms: 1000,
            success: true,
            balance_after: Some(100),
        },
    );

    // Client A's second attempt should be blocked
    assert!(runtime.check_idempotency(&client_a, &op_id).is_some());

    // Client B should NOT be blocked by Client A's op_id
    assert!(
        runtime.check_idempotency(&client_b, &op_id).is_none(),
        "Different client should not be blocked by same op_id"
    );
}

#[test]
fn lru_eviction_allows_reuse_after_many_ops() {
    let mut runtime = PlayerRuntime::new();
    let client_pub = [0xAA; 32];

    // Record many operations to trigger LRU eviction
    // OP_CACHE_SIZE is 6000, so we need more than that
    for i in 0..6100u64 {
        let mut op_id: OpId = [0; 16];
        op_id[..8].copy_from_slice(&i.to_le_bytes());

        runtime.record_op(
            client_pub,
            op_id,
            OpResult {
                processed_at_ms: i,
                success: true,
                balance_after: None,
            },
        );
    }

    // The first op_id should have been evicted
    let first_op_id: OpId = [0; 16]; // i=0
    assert!(
        runtime
            .check_idempotency(&client_pub, &first_op_id)
            .is_none(),
        "Old op_id should be evicted after LRU limit"
    );

    // A recent op_id should still be cached
    let recent_op_id: OpId = {
        let mut id = [0; 16];
        id[..8].copy_from_slice(&6050u64.to_le_bytes());
        id
    };
    assert!(
        runtime
            .check_idempotency(&client_pub, &recent_op_id)
            .is_some(),
        "Recent op_id should still be in cache"
    );
}

#[test]
fn failed_operations_are_also_cached() {
    let mut runtime = PlayerRuntime::new();
    let client_pub = [0xAA; 32];
    let op_id: OpId = [0xBB; 16];

    // Record a failed operation
    runtime.record_op(
        client_pub,
        op_id,
        OpResult {
            processed_at_ms: 1000,
            success: false, // Operation failed
            balance_after: None,
        },
    );

    // Retry should still be detected (we don't retry failed ops)
    let cached = runtime.check_idempotency(&client_pub, &op_id);
    assert!(cached.is_some(), "Failed operations should also be cached");
    assert!(
        !cached.unwrap().success,
        "Should remember that operation failed"
    );
}
