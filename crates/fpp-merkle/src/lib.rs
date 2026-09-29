//! RFC 9162 (Certificate Transparency v2) Merkle trees: tree hashes,
//! inclusion proofs and consistency proofs (04-protocol.md §2, §8).
//!
//! `leaf = SHA-256(0x00 ‖ data)`, `node = SHA-256(0x01 ‖ left ‖ right)`; the
//! empty tree hashes to `SHA-256("")`. Proof generation follows the recursive
//! definitions in RFC 9162 §2.1.3.1 / §2.1.4.1 and verification follows the
//! iterative algorithms in §2.1.3.2 / §2.1.4.2 exactly.

#![forbid(unsafe_code)]

use fpp_types::Digest;
use sha2::{Digest as _, Sha256};

pub fn leaf_hash(data: &[u8]) -> Digest {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(data);
    Digest(h.finalize().into())
}

pub fn node_hash(left: &Digest, right: &Digest) -> Digest {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(left.0);
    h.update(right.0);
    Digest(h.finalize().into())
}

/// Largest power of two strictly less than `n` (n >= 2).
fn split(n: usize) -> usize {
    debug_assert!(n >= 2);
    let mut k = 1;
    while k << 1 < n {
        k <<= 1;
    }
    k
}

/// Merkle Tree Hash over already-hashed leaves.
pub fn root_from_leaf_hashes(leaves: &[Digest]) -> Digest {
    match leaves.len() {
        0 => Digest(Sha256::digest([]).into()),
        1 => leaves[0],
        n => {
            let k = split(n);
            node_hash(
                &root_from_leaf_hashes(&leaves[..k]),
                &root_from_leaf_hashes(&leaves[k..]),
            )
        }
    }
}

/// Merkle Tree Hash over leaf data.
pub fn root<T: AsRef<[u8]>>(leaves: &[T]) -> Digest {
    let hashes: Vec<Digest> = leaves.iter().map(|d| leaf_hash(d.as_ref())).collect();
    root_from_leaf_hashes(&hashes)
}

/// Inclusion proof (audit path) for leaf `index`; `None` if out of range.
pub fn inclusion_proof(leaves: &[Digest], index: usize) -> Option<Vec<Digest>> {
    if index >= leaves.len() {
        return None;
    }
    fn path(m: usize, d: &[Digest], out: &mut Vec<Digest>) {
        if d.len() <= 1 {
            return;
        }
        let k = split(d.len());
        if m < k {
            path(m, &d[..k], out);
            out.push(root_from_leaf_hashes(&d[k..]));
        } else {
            path(m - k, &d[k..], out);
            out.push(root_from_leaf_hashes(&d[..k]));
        }
    }
    let mut out = Vec::new();
    path(index, leaves, &mut out);
    Some(out)
}

/// RFC 9162 §2.1.3.2.
pub fn verify_inclusion(
    leaf: &Digest,
    index: u64,
    tree_size: u64,
    proof: &[Digest],
    root: &Digest,
) -> bool {
    if index >= tree_size {
        return false;
    }
    let (mut fn_, mut sn) = (index, tree_size - 1);
    let mut r = *leaf;
    for p in proof {
        if sn == 0 {
            return false;
        }
        if fn_ & 1 == 1 || fn_ == sn {
            r = node_hash(p, &r);
            if fn_ & 1 == 0 {
                while fn_ & 1 == 0 && fn_ != 0 {
                    fn_ >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            r = node_hash(&r, p);
        }
        fn_ >>= 1;
        sn >>= 1;
    }
    sn == 0 && r == *root
}

/// Consistency proof between the first `m` leaves and all of `leaves`.
/// `None` if `m` is 0 or greater than the tree size.
pub fn consistency_proof(leaves: &[Digest], m: usize) -> Option<Vec<Digest>> {
    if m == 0 || m > leaves.len() {
        return None;
    }
    fn subproof(m: usize, d: &[Digest], complete: bool, out: &mut Vec<Digest>) {
        let n = d.len();
        if m == n {
            if !complete {
                out.push(root_from_leaf_hashes(d));
            }
            return;
        }
        let k = split(n);
        if m <= k {
            subproof(m, &d[..k], complete, out);
            out.push(root_from_leaf_hashes(&d[k..]));
        } else {
            subproof(m - k, &d[k..], false, out);
            out.push(root_from_leaf_hashes(&d[..k]));
        }
    }
    let mut out = Vec::new();
    subproof(m, leaves, true, &mut out);
    Some(out)
}

/// RFC 9162 §2.1.4.2, for `0 < first <= second`. `first == second` requires
/// an empty proof and equal roots.
pub fn verify_consistency(
    first: u64,
    second: u64,
    first_root: &Digest,
    second_root: &Digest,
    proof: &[Digest],
) -> bool {
    if first == 0 || first > second {
        return false;
    }
    if first == second {
        return proof.is_empty() && first_root == second_root;
    }
    if proof.is_empty() {
        return false;
    }
    let mut path: Vec<Digest> = Vec::with_capacity(proof.len() + 1);
    if first.is_power_of_two() {
        path.push(*first_root);
    }
    path.extend_from_slice(proof);

    let (mut fn_, mut sn) = (first - 1, second - 1);
    while fn_ & 1 == 1 {
        fn_ >>= 1;
        sn >>= 1;
    }
    let (mut fr, mut sr) = (path[0], path[0]);
    for c in &path[1..] {
        if sn == 0 {
            return false;
        }
        if fn_ & 1 == 1 || fn_ == sn {
            fr = node_hash(c, &fr);
            sr = node_hash(c, &sr);
            if fn_ & 1 == 0 {
                while fn_ & 1 == 0 && fn_ != 0 {
                    fn_ >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            sr = node_hash(&sr, c);
        }
        fn_ >>= 1;
        sn >>= 1;
    }
    fr == *first_root && sr == *second_root && sn == 0
}
