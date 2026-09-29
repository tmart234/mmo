use fpp_wire::cbor::{decode, encode, Value, MAX_DEPTH};
use fpp_wire::WireError;
use proptest::prelude::*;

fn enc(v: &Value) -> String {
    hex::encode(encode(v).unwrap())
}

fn dec(h: &str) -> Result<Value, WireError> {
    decode(&hex::decode(h).unwrap())
}

fn arr(items: Vec<Value>) -> Value {
    Value::Array(items)
}

/// RFC 8949 Appendix A examples within FPP's subset.
#[test]
fn rfc8949_appendix_a() {
    let u = Value::Unsigned;
    let cases: Vec<(Value, &str)> = vec![
        (u(0), "00"),
        (u(1), "01"),
        (u(10), "0a"),
        (u(23), "17"),
        (u(24), "1818"),
        (u(25), "1819"),
        (u(100), "1864"),
        (u(1000), "1903e8"),
        (u(1_000_000), "1a000f4240"),
        (u(1_000_000_000_000), "1b000000e8d4a51000"),
        (u(u64::MAX), "1bffffffffffffffff"),
        (Value::int(-1), "20"),
        (Value::int(-10), "29"),
        (Value::int(-100), "3863"),
        (Value::int(-1000), "3903e7"),
        (Value::Negative(u64::MAX), "3bffffffffffffffff"),
        (Value::Bool(false), "f4"),
        (Value::Bool(true), "f5"),
        (Value::Null, "f6"),
        (Value::bytes(vec![]), "40"),
        (Value::bytes(vec![1, 2, 3, 4]), "4401020304"),
        (Value::text(""), "60"),
        (Value::text("a"), "6161"),
        (Value::text("IETF"), "6449455446"),
        (Value::text("\"\\"), "62225c"),
        (Value::text("\u{00fc}"), "62c3bc"),
        (Value::text("\u{6c34}"), "63e6b0b4"),
        (arr(vec![]), "80"),
        (arr(vec![u(1), u(2), u(3)]), "83010203"),
        (
            arr(vec![u(1), arr(vec![u(2), u(3)]), arr(vec![u(4), u(5)])]),
            "8301820203820405",
        ),
        (
            arr((1..=25).map(u).collect()),
            "98190102030405060708090a0b0c0d0e0f101112131415161718181819",
        ),
        (Value::Map(vec![]), "a0"),
        (Value::Map(vec![(u(1), u(2)), (u(3), u(4))]), "a201020304"),
        (
            Value::Map(vec![
                (Value::text("a"), u(1)),
                (Value::text("b"), arr(vec![u(2), u(3)])),
            ]),
            "a26161016162820203",
        ),
        (
            arr(vec![
                Value::text("a"),
                Value::Map(vec![(Value::text("b"), Value::text("c"))]),
            ]),
            "826161a161626163",
        ),
    ];
    for (v, want) in cases {
        assert_eq!(enc(&v), want, "encode {v:?}");
        assert_eq!(dec(want).unwrap(), v, "decode {want}");
    }
}

/// RFC 8949 §4.2.1: keys sort by their encoded bytes (10, 100, -1, "z", "aa").
#[test]
fn map_keys_sort_by_encoding() {
    let v = Value::Map(vec![
        (Value::text("aa"), Value::Null),
        (Value::int(-1), Value::Null),
        (Value::text("z"), Value::Null),
        (Value::Unsigned(100), Value::Null),
        (Value::Unsigned(10), Value::Null),
    ]);
    assert_eq!(enc(&v), "a50af61864f620f6617af6626161f6");
}

#[test]
fn encoder_rejects_duplicate_and_unsupported_keys() {
    let dup = Value::Map(vec![
        (Value::Unsigned(1), Value::Null),
        (Value::Unsigned(1), Value::Null),
    ]);
    assert_eq!(encode(&dup), Err(WireError::UnsortedOrDuplicateKey));
    let bad = Value::Map(vec![(Value::bytes(vec![0]), Value::Null)]);
    assert_eq!(encode(&bad), Err(WireError::UnsupportedKey));
}

#[test]
fn rejects_non_deterministic_and_unsupported_input() {
    use WireError::*;
    let cases = [
        ("1817", NonCanonical),
        ("190017", NonCanonical),
        ("1a0000ffff", NonCanonical),
        ("1b00000000ffffffff", NonCanonical),
        ("3817", NonCanonical),
        ("5817", NonCanonical),
        ("5f4101ff", IndefiniteLength),
        ("9f01ff", IndefiniteLength),
        ("bf0102ff", IndefiniteLength),
        ("1c", Reserved),
        ("a203040102", UnsortedOrDuplicateKey),
        ("a201020103", UnsortedOrDuplicateKey),
        ("c11a514b67b0", Unsupported),
        ("f93c00", Unsupported),
        ("fb3ff0000000000000", Unsupported),
        ("f7", Unsupported),
        ("f0", Unsupported),
        ("62c328", InvalidUtf8),
        ("0101", TrailingBytes),
        ("44010203", Truncated),
        ("a1410001", UnsupportedKey),
        ("a1f401", UnsupportedKey),
        ("", Truncated),
    ];
    for (h, want) in cases {
        assert_eq!(dec(h), Err(want), "{h}");
    }
}

#[test]
fn huge_declared_lengths_fail_without_allocating() {
    // Lengths near u64::MAX must be rejected by comparison, not by allocation.
    for h in [
        "5bffffffffffffffff",
        "7bffffffffffffffff",
        "9b7fffffffffffffff",
        "bb7fffffffffffffff",
    ] {
        assert_eq!(dec(h), Err(WireError::Truncated), "{h}");
    }
}

#[test]
fn nesting_is_bounded() {
    let nested = |depth: usize| {
        let mut v = Value::Unsigned(0);
        for _ in 0..depth {
            v = Value::Array(vec![v]);
        }
        encode(&v).unwrap()
    };
    assert!(decode(&nested(MAX_DEPTH)).is_ok());
    assert_eq!(decode(&nested(MAX_DEPTH + 1)), Err(WireError::TooDeep));
}

fn arb_value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        any::<u64>().prop_map(Value::Unsigned),
        any::<u64>().prop_map(Value::Negative),
        proptest::collection::vec(any::<u8>(), 0..40).prop_map(Value::Bytes),
        ".{0,12}".prop_map(Value::Text),
        any::<bool>().prop_map(Value::Bool),
        Just(Value::Null),
    ];
    leaf.prop_recursive(4, 64, 8, |inner| {
        prop_oneof![
            proptest::collection::vec(inner.clone(), 0..8).prop_map(Value::Array),
            proptest::collection::btree_map(".{0,6}", inner, 0..8).prop_map(|m| {
                Value::Map(m.into_iter().map(|(k, v)| (Value::Text(k), v)).collect())
            }),
        ]
    })
}

proptest! {
    /// There is exactly one accepted encoding: whatever decodes re-encodes to
    /// the identical bytes.
    #[test]
    fn accepted_bytes_are_canonical(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
        if let Ok(v) = decode(&bytes) {
            prop_assert_eq!(encode(&v).unwrap(), bytes);
        }
    }

    #[test]
    fn values_roundtrip(v in arb_value()) {
        let bytes = encode(&v).unwrap();
        let back = decode(&bytes).unwrap();
        prop_assert_eq!(encode(&back).unwrap(), bytes);
    }
}
