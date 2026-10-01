//! The log and witness on disk: proofs across tile boundaries, reopening,
//! storage tampering, receipts, and the witness refusing a split view.

use ed25519_dalek::SigningKey;
use fpp_crypto::hybrid::{verify_hybrid, HybridSigner};
use fpp_crypto::{KeyRole, KeySet};
use fpp_log::note::{Checkpoint, Note};
use fpp_log::{Log, LogError, Witness};
use fpp_merkle::{verify_consistency, verify_inclusion};
use fpp_types::Digest;
use fpp_wire::LogReceipt;

const ORIGIN: &str = "fpp.test/log";

fn dir(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("fpp-log-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

/// A hybrid log key.
fn key(seed: u8) -> HybridSigner {
    HybridSigner::from_seeds(&[seed; 32], &[seed ^ 0x55; 32]).unwrap()
}

/// A witness key (Ed25519).
fn wkey(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn entries(from: usize, n: usize) -> Vec<Vec<u8>> {
    (from..from + n)
        .map(|i| format!("entry {i}").into_bytes())
        .collect()
}

fn checkpoint(log: &Log) -> Checkpoint {
    Checkpoint::parse(&Note::parse(&log.checkpoint()).unwrap().text).unwrap()
}

#[test]
fn proofs_across_tiles_and_reopening() {
    let d = dir("proofs");
    let mut log = Log::open(&d, ORIGIN, key(1), 60).unwrap();
    assert_eq!(log.size(), 0);
    let mut sizes = vec![0u64];
    // batches that end inside, on and past tile boundaries (256)
    for n in [1, 254, 1, 300, 256, 70_000 - 812] {
        let from = log.size() as usize;
        // (receipts for the small batches; a bulk import for the large one)
        if n < 1000 {
            let appended = log.append(&entries(from, n), 1_000).unwrap();
            assert_eq!(appended.len(), n);
            assert_eq!(appended[0].index, from as u64);
        } else {
            assert_eq!(
                log.append_without_receipts(&entries(from, n)).unwrap(),
                (from + n) as u64
            );
        }
        sizes.push(log.size());
    }
    assert_eq!(log.size(), 70_000);
    let head = checkpoint(&log);
    assert_eq!(head.size, 70_000);
    let root = Digest(head.root);

    for index in [0u64, 255, 256, 511, 65_535, 65_536, 69_999] {
        let proof = log.inclusion_proof(index, 70_000).unwrap();
        let leaf = fpp_merkle::leaf_hash(format!("entry {index}").as_bytes());
        assert!(verify_inclusion(&leaf, index, 70_000, &proof, &root));
    }
    let roots: Vec<Digest> = sizes
        .iter()
        .map(|s| fpp_merkle::root(&entries(0, *s as usize)))
        .collect();
    for (i, old) in sizes.iter().enumerate().skip(1) {
        let proof = log.consistency_proof(*old, 70_000).unwrap();
        assert!(verify_consistency(*old, 70_000, &roots[i], &root, &proof) || *old == 70_000);
    }
    assert!(log.inclusion_proof(70_000, 70_000).is_err());
    assert!(log.consistency_proof(10, 70_001).is_err());

    // the level-1 tile exists: 70000 leaves = 273 full level-0 tiles
    // 70000 leaves: 273 full level-0 tiles and a partial; 273 level-1
    // hashes (one full level-1 tile, a partial of 17); one level-2 hash
    assert!(d.join("tile/1/000").exists());
    assert!(d.join("tile/1/001.p/17").exists());
    assert!(d.join("tile/2/000.p/1").exists());
    assert!(d.join("tile/0/272").exists());
    assert!(d.join("tile/0/273.p/112").exists());
    assert!(d.join("tile/entries/273.p/112").exists());

    // reopened from disk: the same tree, and appending continues
    drop(log);
    let mut log = Log::open(&d, ORIGIN, key(1), 60).unwrap();
    assert_eq!(log.size(), 70_000);
    assert_eq!(log.root(), root);
    log.append(&entries(70_000, 5), 1_001).unwrap();
    assert_eq!(log.root(), fpp_merkle::root(&entries(0, 70_005)));
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn storage_tampering_is_found_on_open() {
    let d = dir("tamper");
    let mut log = Log::open(&d, ORIGIN, key(1), 60).unwrap();
    log.append(&entries(0, 300), 1).unwrap();
    drop(log);
    // an entry rewritten in place
    let path = d.join("tile/entries/000");
    let mut bytes = std::fs::read(&path).unwrap();
    let at = bytes.len() / 2;
    bytes[at] ^= 1;
    std::fs::write(&path, bytes).unwrap();
    assert!(matches!(
        Log::open(&d, ORIGIN, key(1), 60),
        Err(LogError::Storage(_))
    ));
    // a checkpoint signed by another key
    let d2 = dir("tamper2");
    Log::open(&d2, ORIGIN, key(1), 60).unwrap();
    assert!(Log::open(&d2, ORIGIN, key(2), 60).is_err());
    let _ = std::fs::remove_dir_all(&d);
    let _ = std::fs::remove_dir_all(&d2);
}

#[test]
fn receipts_are_signed_by_the_log_key() {
    let d = dir("receipts");
    let mut log = Log::open(&d, ORIGIN, key(1), 60).unwrap();
    let appended = log.append(&entries(0, 2), 1_700_000_000).unwrap();
    let k = key(1);
    let mut keys = KeySet::default();
    keys.insert_hybrid(KeyRole::Log, k.ed25519_public(), k.ml_dsa_public().to_vec());
    let receipt: LogReceipt = verify_hybrid(&appended[1].receipt, &keys).unwrap().payload;
    assert_eq!(receipt.leaf_hash, fpp_merkle::leaf_hash(b"entry 1"));
    assert_eq!(receipt.log_id, Log::log_id(&key(1)));
    assert_eq!((receipt.timestamp, receipt.mmd_s), (1_700_000_000, 60));
    // (not a receipt under any other role, nor with only one half of the key)
    let mut other = KeySet::default();
    other.insert_hybrid(
        KeyRole::BuildSigning,
        k.ed25519_public(),
        k.ml_dsa_public().to_vec(),
    );
    assert!(verify_hybrid::<LogReceipt>(&appended[1].receipt, &other).is_err());
    let mut ed_only = KeySet::default();
    ed_only.insert_ed25519(KeyRole::Log, k.ed25519_public());
    assert!(verify_hybrid::<LogReceipt>(&appended[1].receipt, &ed_only).is_err());
    // and an Ed25519-only COSE_Sign1 by the log's key is refused (S1H is required)
    let single = fpp_crypto::sign(
        &fpp_crypto::Ed25519Signer::new(k.ed25519().clone()),
        &receipt,
    );
    assert!(matches!(
        fpp_crypto::verify::<LogReceipt>(&single, &ed_only),
        Err(fpp_crypto::VerifyError::HybridRequired(KeyRole::Log))
    ));
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn witness_cosigns_one_history_only() {
    let d = dir("witness");
    let mut log = Log::open(d.join("log"), ORIGIN, key(1), 60).unwrap();
    let log_pub = log.public_key();
    let log_ml = log.ml_dsa_public_key().to_vec();
    let mut witness = Witness::open(
        "witness.test",
        wkey(9),
        ORIGIN,
        log_pub,
        log_ml.clone(),
        d.join("witness-state"),
    )
    .unwrap();
    log.set_witnesses(vec![("witness.test".into(), witness.public_key())]);

    log.append(&entries(0, 10), 1).unwrap();
    let line = witness.cosign(&log.checkpoint(), &[], 100).unwrap();
    let text = Note::parse(&log.checkpoint()).unwrap().text;
    log.add_cosignature(&text, &line).unwrap();
    let published = Note::parse(&log.checkpoint()).unwrap();
    published.verify_hybrid(ORIGIN, &log_pub, &log_ml).unwrap();
    assert_eq!(
        published
            .verify_cosignature("witness.test", &witness.public_key())
            .unwrap(),
        100
    );

    // growth with a consistency proof: cosigned
    log.append(&entries(10, 20), 2).unwrap();
    let proof = log.consistency_proof(10, 30).unwrap();
    witness.cosign(&log.checkpoint(), &proof, 101).unwrap();

    // the same key signing a different history (an entry hidden, another in
    // its place): refused, at the same size and when grown
    let mut fork = Log::open(d.join("fork"), ORIGIN, key(1), 60).unwrap();
    let mut other = entries(0, 30);
    other[3] = b"a different entry".to_vec();
    fork.append(&other, 3).unwrap();
    assert!(matches!(
        witness.cosign(&fork.checkpoint(), &[], 102),
        Err(LogError::SplitView)
    ));
    fork.append(&entries(30, 5), 4).unwrap();
    let fork_proof = fork.consistency_proof(30, 35).unwrap();
    assert!(matches!(
        witness.cosign(&fork.checkpoint(), &fork_proof, 103),
        Err(LogError::SplitView)
    ));

    // a smaller tree than already cosigned (a rollback)
    let mut small = Log::open(d.join("small"), ORIGIN, key(1), 60).unwrap();
    small.append(&entries(0, 5), 5).unwrap();
    assert!(matches!(
        witness.cosign(&small.checkpoint(), &[], 104),
        Err(LogError::Rollback)
    ));

    // the witness remembers across restarts
    drop(witness);
    let mut witness = Witness::open(
        "witness.test",
        wkey(9),
        ORIGIN,
        log_pub,
        log_ml.clone(),
        d.join("witness-state"),
    )
    .unwrap();
    assert_eq!(witness.last_size(), 30);
    assert!(matches!(
        witness.cosign(&fork.checkpoint(), &fork_proof, 105),
        Err(LogError::SplitView)
    ));

    // a checkpoint the log did not sign
    let forged = fpp_log::note::sign_hybrid(
        &Checkpoint {
            origin: ORIGIN.into(),
            size: 31,
            root: [0; 32],
        }
        .text(),
        ORIGIN,
        &key(7),
    )
    .unwrap();
    assert!(witness.cosign(&forged, &[], 106).is_err());
    // one signed with the log's Ed25519 half only (the ML-DSA line missing)
    let ed_only = fpp_log::note::sign(
        &Checkpoint {
            origin: ORIGIN.into(),
            size: 30,
            root: checkpoint(&log).root,
        }
        .text(),
        ORIGIN,
        key(1).ed25519(),
    )
    .unwrap();
    assert!(witness.cosign(&ed_only, &[], 106).is_err());

    // the log accepts cosignatures only from its witnesses, over its current checkpoint
    let stranger = Witness::open(
        "stranger",
        wkey(8),
        ORIGIN,
        log_pub,
        log_ml.clone(),
        d.join("stranger-state"),
    );
    let line = stranger
        .unwrap()
        .cosign(&log.checkpoint(), &[], 107)
        .unwrap();
    let text = Note::parse(&log.checkpoint()).unwrap().text;
    assert!(log.add_cosignature(&text, &line).is_err());
    assert!(matches!(
        log.add_cosignature("old\n", &line),
        Err(LogError::Stale)
    ));
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn the_cosigned_checkpoint_outlives_appends_and_reopening() {
    let d = dir("cosigned");
    let mut log = Log::open(&d, ORIGIN, key(1), 60).unwrap();
    let mut witness = Witness::open(
        "witness.test",
        wkey(9),
        ORIGIN,
        log.public_key(),
        log.ml_dsa_public_key().to_vec(),
        d.join("w"),
    )
    .unwrap();
    log.set_witnesses(vec![("witness.test".into(), witness.public_key())]);
    assert_eq!(log.cosigned_checkpoint(), None);
    log.append(&entries(0, 300), 1).unwrap();
    let line = witness.cosign(&log.checkpoint(), &[], 10).unwrap();
    log.add_cosignature(&Note::parse(&log.checkpoint()).unwrap().text, &line)
        .unwrap();
    let cosigned = log.cosigned_checkpoint().unwrap();
    log.append(&entries(300, 5), 2).unwrap();
    // the published checkpoint moved on; the cosigned one did not
    assert_ne!(log.checkpoint(), cosigned);
    assert_eq!(
        log.cosigned_checkpoint().as_deref(),
        Some(cosigned.as_str())
    );
    let c = Checkpoint::parse(&Note::parse(&cosigned).unwrap().text).unwrap();
    assert_eq!(c.size, 300);
    // and entries read back from disk, from anywhere
    assert_eq!(log.entries(0).unwrap(), entries(0, 305));
    assert_eq!(log.entries(299).unwrap(), entries(299, 6));
    // a cosignature for a checkpoint the log has since moved past still
    // counts (re-signed), and the published checkpoint is left alone
    let older = log.checkpoint();
    log.append(&entries(305, 3), 3).unwrap();
    let proof = log.consistency_proof(300, 305).unwrap();
    let line = witness.cosign(&older, &proof, 11).unwrap();
    let published = log.checkpoint();
    log.add_cosignature(&Note::parse(&older).unwrap().text, &line)
        .unwrap();
    assert_eq!(log.checkpoint(), published);
    let now = Note::parse(&log.cosigned_checkpoint().unwrap()).unwrap();
    assert_eq!(Checkpoint::parse(&now.text).unwrap().size, 305);
    now.verify_hybrid(ORIGIN, &log.public_key(), log.ml_dsa_public_key())
        .unwrap();
    now.verify_cosignature("witness.test", &witness.public_key())
        .unwrap();
    // but not one for a tree this log never had
    let mut fork = Log::open(d.join("fork"), ORIGIN, key(1), 60).unwrap();
    fork.append(&entries(1, 5), 1).unwrap();
    let forged = Note::parse(&fork.checkpoint()).unwrap().text;
    assert!(matches!(
        log.add_cosignature(&forged, &line),
        Err(LogError::Stale)
    ));
    let cosigned = log.cosigned_checkpoint().unwrap();
    drop(log);
    let log = Log::open(&d, ORIGIN, key(1), 60).unwrap();
    assert_eq!(
        log.cosigned_checkpoint().as_deref(),
        Some(cosigned.as_str())
    );
    let _ = std::fs::remove_dir_all(&d);
}
