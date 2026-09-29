use fpp_types::{ctx, BuildId, Digest, GsInstanceId, Kid, MatchId, FPP_VERSION};
use fpp_wire::cbor::{self, text_map, Value};
use fpp_wire::cose::{alg, ProtectedHeader, Sign1};
use fpp_wire::{Checkpoint, InputCommit, InputLeaf, Payload, WireError};

fn commit() -> InputCommit {
    InputCommit {
        match_id: MatchId([1; 16]),
        slot: 3,
        epoch: 7,
        first_tick: 448,
        last_tick: 511,
        n: 64,
        frames_root: Digest([0xAA; 32]),
        prev: Digest([0xBB; 32]),
    }
}

fn checkpoint() -> Checkpoint {
    Checkpoint {
        match_id: MatchId([1; 16]),
        gs_instance_id: GsInstanceId([2; 32]),
        build_id: BuildId([3; 32]),
        policy_ver: 42,
        epoch: 7,
        ticks: (448, 511),
        prev: Digest([4; 32]),
        inputs_root: Digest([5; 32]),
        inputs_n: 10,
        events_root: Digest([6; 32]),
        events_n: 120,
        state_root: Digest([7; 32]),
        rng_root: Digest([8; 32]),
        rng_n: 3,
        roster_root: Digest([9; 32]),
        roster_n: 10,
    }
}

#[test]
fn payloads_roundtrip() {
    assert_eq!(
        InputCommit::from_cbor(&commit().to_cbor()).unwrap(),
        commit()
    );
    assert_eq!(
        Checkpoint::from_cbor(&checkpoint().to_cbor()).unwrap(),
        checkpoint()
    );
    let leaf = InputLeaf {
        slot: 2,
        commit: None,
        applied: vec![0xff, 0x7f],
    };
    assert_eq!(
        InputLeaf::from_value(&cbor::decode(&leaf.leaf_data()).unwrap()).unwrap(),
        leaf
    );
}

#[test]
fn payloads_are_bound_to_their_context() {
    assert_eq!(InputCommit::CTX, ctx::INPUT_COMMIT);
    assert_eq!(Checkpoint::CTX, ctx::CHECKPOINT);
}

#[test]
fn schema_errors_are_reported_not_panicked() {
    // Missing field.
    let mut v = commit().to_value();
    if let Value::Map(m) = &mut v {
        m.retain(|(k, _)| k.as_text() != Some("prev"));
    }
    assert_eq!(
        InputCommit::from_value(&v),
        Err(WireError::Schema("InputCommit", "prev"))
    );
    // Wrong width.
    let bad = text_map([("slot", Value::Unsigned(70_000))]);
    assert!(InputCommit::from_value(&bad).is_err());
    // Inverted tick range.
    let mut c = commit();
    c.first_tick = 600;
    assert!(InputCommit::from_cbor(&c.to_cbor()).is_err());
    let mut cp = checkpoint();
    cp.ticks = (9, 8);
    assert!(Checkpoint::from_cbor(&cp.to_cbor()).is_err());
}

#[test]
fn unknown_payload_fields_are_ignored() {
    // 04-protocol.md §12: signed objects may add fields.
    let mut v = commit().to_value();
    if let Value::Map(m) = &mut v {
        m.push((Value::text("zz_future"), Value::Unsigned(1)));
    }
    let bytes = cbor::encode(&v).unwrap();
    assert_eq!(InputCommit::from_cbor(&bytes).unwrap(), commit());
}

fn header() -> ProtectedHeader {
    ProtectedHeader {
        alg: alg::EDDSA,
        content_type: InputCommit::CONTENT_TYPE.into(),
        kid: Kid([0x11; 16]),
        ctx: InputCommit::CTX.into(),
        version: FPP_VERSION,
    }
}

#[test]
fn sign1_roundtrip_and_sig_structure() {
    let mut s = Sign1::new(header(), commit().to_cbor()).unwrap();
    s.signature = vec![0x55; 64];
    let bytes = s.encode();
    assert_eq!(Sign1::decode(&bytes).unwrap(), s);
    // Sig_structure: ["Signature1", protected, h'', payload]
    let tbs = cbor::decode(&s.to_be_signed()).unwrap();
    let parts = tbs.as_array().unwrap();
    assert_eq!(parts[0], Value::text("Signature1"));
    assert_eq!(parts[1], Value::bytes(s.protected_raw.clone()));
    assert_eq!(parts[2], Value::bytes(vec![]));
    assert_eq!(parts[3], Value::bytes(s.payload.clone()));
}

fn sign1_with(protected: Value, unprotected: Value, payload: Value) -> Vec<u8> {
    cbor::encode(&Value::Array(vec![
        Value::bytes(cbor::encode(&protected).unwrap()),
        unprotected,
        payload,
        Value::bytes(vec![0; 64]),
    ]))
    .unwrap()
}

#[test]
fn sign1_header_rules() {
    let ok = header().to_value();
    let empty = Value::Map(vec![]);
    let payload = Value::bytes(commit().to_cbor());
    assert!(Sign1::decode(&sign1_with(ok.clone(), empty.clone(), payload.clone())).is_ok());

    // Unprotected header must be empty.
    let unprot = Value::Map(vec![(Value::Unsigned(4), Value::bytes(vec![0; 16]))]);
    assert!(matches!(
        Sign1::decode(&sign1_with(ok.clone(), unprot, payload.clone())),
        Err(WireError::Header(_))
    ));
    // Detached payload (nil) is not allowed.
    assert!(matches!(
        Sign1::decode(&sign1_with(ok.clone(), empty.clone(), Value::Null)),
        Err(WireError::Header(_))
    ));
    // crit is not allowed.
    let mut with_crit = ok.clone();
    if let Value::Map(m) = &mut with_crit {
        m.push((Value::Unsigned(2), Value::Array(vec![Value::int(-65537)])));
    }
    assert!(matches!(
        Sign1::decode(&sign1_with(with_crit, empty.clone(), payload.clone())),
        Err(WireError::Header(_))
    ));
    // Unknown header parameters are not allowed.
    let mut unknown = ok.clone();
    if let Value::Map(m) = &mut unknown {
        m.push((Value::Unsigned(33), Value::Null));
    }
    assert!(Sign1::decode(&sign1_with(unknown, empty.clone(), payload.clone())).is_err());
    // kid must be exactly 16 bytes.
    let mut short_kid = ok;
    if let Value::Map(m) = &mut short_kid {
        for (k, v) in m.iter_mut() {
            if k.as_i64() == Some(4) {
                *v = Value::bytes(vec![0; 8]);
            }
        }
    }
    assert!(Sign1::decode(&sign1_with(short_kid, empty, payload)).is_err());
}

#[test]
fn sign1_rejects_trailing_and_non_canonical_protected_header() {
    let mut s = Sign1::new(header(), commit().to_cbor()).unwrap();
    s.signature = vec![0; 64];
    let mut bytes = s.encode();
    bytes.push(0x00);
    assert_eq!(Sign1::decode(&bytes), Err(WireError::TrailingBytes));

    // Protected header with a non-minimal integer (alg -8 as 0x38 0x07).
    let raw = hex::decode("a5013807").unwrap();
    let outer = cbor::encode(&Value::Array(vec![
        Value::bytes(raw),
        Value::Map(vec![]),
        Value::bytes(vec![]),
        Value::bytes(vec![]),
    ]))
    .unwrap();
    assert!(Sign1::decode(&outer).is_err());
}
