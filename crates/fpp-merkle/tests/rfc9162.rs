use fpp_merkle::*;
use fpp_types::Digest;
use proptest::prelude::*;

/// Certificate Transparency's reference test tree (RFC 6962 hashing, identical
/// in RFC 9162): leaf inputs and the tree hash of the first n leaves.
const CT_LEAVES: [&str; 8] = [
    "",
    "00",
    "10",
    "2021",
    "3031",
    "40414243",
    "5051525354555657",
    "606162636465666768696a6b6c6d6e6f",
];
const CT_ROOTS: [&str; 8] = [
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
    "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
    "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
    "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
    "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
    "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
    "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
];

fn ct_leaf_data() -> Vec<Vec<u8>> {
    CT_LEAVES.iter().map(|h| hex::decode(h).unwrap()).collect()
}

#[test]
fn empty_tree_is_sha256_of_nothing() {
    let empty: [&[u8]; 0] = [];
    assert_eq!(
        hex::encode(root(&empty).0),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn matches_ct_reference_roots() {
    let data = ct_leaf_data();
    for n in 1..=8 {
        assert_eq!(hex::encode(root(&data[..n]).0), CT_ROOTS[n - 1], "size {n}");
    }
}

fn leaves(n: usize) -> Vec<Digest> {
    (0..n)
        .map(|i| leaf_hash(&(i as u32).to_le_bytes()))
        .collect()
}

#[test]
fn every_inclusion_proof_verifies_up_to_40_leaves() {
    for n in 1..=40usize {
        let l = leaves(n);
        let r = root_from_leaf_hashes(&l);
        for i in 0..n {
            let p = inclusion_proof(&l, i).unwrap();
            assert!(
                verify_inclusion(&l[i], i as u64, n as u64, &p, &r),
                "n={n} i={i}"
            );
            // Wrong index, size, leaf or root must fail.
            if n > 1 {
                assert!(!verify_inclusion(
                    &l[i],
                    ((i + 1) % n) as u64,
                    n as u64,
                    &p,
                    &r
                ));
                assert!(!verify_inclusion(
                    &l[(i + 1) % n],
                    i as u64,
                    n as u64,
                    &p,
                    &r
                ));
            }
            assert!(!verify_inclusion(
                &l[i],
                i as u64,
                n as u64,
                &p,
                &leaf_hash(b"x")
            ));
            // Tampering with any proof element must fail.
            for j in 0..p.len() {
                let mut bad = p.clone();
                bad[j].0[0] ^= 1;
                assert!(!verify_inclusion(&l[i], i as u64, n as u64, &bad, &r));
            }
        }
        assert!(inclusion_proof(&l, n).is_none());
    }
}

/// RFC 9162 inclusion verification does not authenticate the tree size: for
/// leaf 0, trees of 3 and 4 leaves have the same proof shape, so a size-3
/// proof also "verifies" as size 4 against the same root. The size must come
/// from a signature over (size, root), which is why every FPP root is signed
/// together with its leaf count (Checkpoint `*_n`, InputCommit `n`,
/// HostBatch `count`, tree heads).
#[test]
fn tree_size_must_be_authenticated_with_the_root() {
    let l = leaves(3);
    let r = root_from_leaf_hashes(&l);
    let p = inclusion_proof(&l, 0).unwrap();
    assert!(verify_inclusion(&l[0], 0, 3, &p, &r));
    assert!(verify_inclusion(&l[0], 0, 4, &p, &r));
}

#[test]
fn every_consistency_proof_verifies_up_to_40_leaves() {
    for n in 1..=40usize {
        let l = leaves(n);
        let rn = root_from_leaf_hashes(&l);
        for m in 1..=n {
            let rm = root_from_leaf_hashes(&l[..m]);
            let p = consistency_proof(&l, m).unwrap();
            assert!(
                verify_consistency(m as u64, n as u64, &rm, &rn, &p),
                "m={m} n={n}"
            );
            if m < n {
                // A forked history (different old root) must not be provably consistent.
                assert!(!verify_consistency(
                    m as u64,
                    n as u64,
                    &leaf_hash(b"fork"),
                    &rn,
                    &p
                ));
                assert!(!verify_consistency(
                    m as u64,
                    n as u64,
                    &rm,
                    &leaf_hash(b"fork"),
                    &p
                ));
                for j in 0..p.len() {
                    let mut bad = p.clone();
                    bad[j].0[31] ^= 0x80;
                    assert!(!verify_consistency(m as u64, n as u64, &rm, &rn, &bad));
                }
            }
        }
        assert!(consistency_proof(&l, 0).is_none());
        assert!(consistency_proof(&l, n + 1).is_none());
        assert!(!verify_consistency(0, n as u64, &rn, &rn, &[]));
    }
}

proptest! {
    #[test]
    fn arbitrary_proofs_are_rejected(
        n in 1u64..64,
        i in 0u64..64,
        proof in proptest::collection::vec(any::<[u8; 32]>(), 0..8),
    ) {
        let l = leaves(n as usize);
        let r = root_from_leaf_hashes(&l);
        let proof: Vec<Digest> = proof.into_iter().map(Digest).collect();
        let idx = i % n;
        // Random proofs essentially never verify; genuine ones always do.
        let genuine = inclusion_proof(&l, idx as usize).unwrap();
        if proof != genuine {
            prop_assert!(!verify_inclusion(&l[idx as usize], idx, n, &proof, &r));
        }
    }
}
