//! Economy operation idempotency tests for `fpp_sim::state::PlayerRuntime`.

use fpp_sim::game_wire::OpId;
use fpp_sim::state::{OpResult, PlayerRuntime};

#[test]
fn spend_coins_idempotency_detects_replay() {
    let mut runtime = PlayerRuntime::new();
    let client_pub = [0xAA; 32];
    let op_id: OpId = [0xBB; 16];

    assert!(runtime.check_idempotency(&client_pub, &op_id).is_none());
    runtime.record_op(
        client_pub,
        op_id,
        OpResult {
            processed_at_ms: 1000,
            success: true,
        },
    );

    let cached = runtime.check_idempotency(&client_pub, &op_id);
    assert!(cached.is_some());
    assert_eq!(cached.unwrap().processed_at_ms, 1000);
    assert!(cached.unwrap().success);
}

#[test]
fn different_clients_can_use_same_op_id() {
    let mut runtime = PlayerRuntime::new();
    let client_a = [0xAA; 32];
    let client_b = [0xBB; 32];
    let op_id: OpId = [0xCC; 16];

    runtime.record_op(
        client_a,
        op_id,
        OpResult {
            processed_at_ms: 1000,
            success: true,
        },
    );
    assert!(runtime.check_idempotency(&client_a, &op_id).is_some());
    assert!(runtime.check_idempotency(&client_b, &op_id).is_none());
}

#[test]
fn bounded_eviction_allows_reuse_after_many_ops() {
    let mut runtime = PlayerRuntime::new();
    let client_pub = [0xAA; 32];

    for i in 0..6100u64 {
        let mut op_id: OpId = [0; 16];
        op_id[..8].copy_from_slice(&i.to_le_bytes());
        runtime.record_op(
            client_pub,
            op_id,
            OpResult {
                processed_at_ms: i,
                success: true,
            },
        );
    }

    let first_op_id: OpId = [0; 16];
    assert!(runtime
        .check_idempotency(&client_pub, &first_op_id)
        .is_none());

    let mut recent_op_id: OpId = [0; 16];
    recent_op_id[..8].copy_from_slice(&6050u64.to_le_bytes());
    assert!(runtime
        .check_idempotency(&client_pub, &recent_op_id)
        .is_some());
}

#[test]
fn failed_operations_are_also_cached() {
    let mut runtime = PlayerRuntime::new();
    let client_pub = [0xAA; 32];
    let op_id: OpId = [0xBB; 16];

    runtime.record_op(
        client_pub,
        op_id,
        OpResult {
            processed_at_ms: 1000,
            success: false,
        },
    );

    let cached = runtime.check_idempotency(&client_pub, &op_id);
    assert!(cached.is_some());
    assert!(!cached.unwrap().success);
}
