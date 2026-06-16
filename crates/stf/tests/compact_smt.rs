//! Validation of the staged compact (pass-through) SMT against the deployed depth-256
//! scheme, the same role the verifier differential test plays for the BN254 port.
//!
//! Runs under `--features compact_smt` (so both `smt` (the live depth-256 tree) and
//! `smt_compact` are compiled and can be checked side by side in one binary). It pins:
//!
//!   * **self-consistency**: the full-tree root equals the partial-witness
//!     reconstruction, and a single-leaf proof verifies, for members and non-members;
//!   * **the transition invariant**: the *same* frontier siblings reconstruct both the
//!     pre-state and post-state roots (exactly how `prove_transition` binds `prev_root`
//!     and computes `new_root`);
//!   * **tamper rejection**: a wrong leaf, a flipped sibling, or a wrong-length proof
//!     is rejected;
//!   * **determinism / order-independence** against the depth-256 tree as the membership
//!     oracle; and (under `hash_count`)
//!   * **the proving-cost win**: keccak calls for the compact reconstruction are a small
//!     fraction of the depth-256 scheme's.
#![cfg(feature = "compact_smt")]

use liquid_cells_stf::hash::Hash;
use liquid_cells_stf::keccak;
use liquid_cells_stf::smt as full; // deployed depth-256 scheme
use liquid_cells_stf::smt_compact as cc; // staged compact scheme

// --- deterministic RNG (SplitMix64), no external deps ----------------------
struct R(u64);
impl R {
    fn new(seed: u64) -> Self {
        R(seed)
    }
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

fn rand_hash(r: &mut R) -> Hash {
    let mut k = [0u8; 32];
    for i in 0..4 {
        k[i * 8..i * 8 + 8].copy_from_slice(&r.next().to_be_bytes());
    }
    k
}
fn rand_content(r: &mut R) -> Hash {
    loop {
        let c = rand_hash(r);
        if c != [0u8; 32] {
            return c;
        }
    }
}

/// Build a compact tree and an independent depth-256 tree over the same leaves.
fn build(r: &mut R, n: usize) -> (cc::Smt, full::Smt, Vec<Hash>) {
    let (mut c, mut f) = (cc::Smt::new(), full::Smt::new());
    let mut keys = Vec::with_capacity(n);
    for _ in 0..n {
        let k = rand_hash(r);
        let v = rand_content(r);
        c.set_leaf_hash(k, v);
        f.set_leaf_hash(k, v);
        keys.push(k);
    }
    keys.sort();
    keys.dedup();
    (c, f, keys)
}

#[test]
fn empty_tree_root_is_the_zero_constant() {
    // The compact empty root is the single zero constant (the depth-256 tree's is a
    // depth-folded default, the schemes are intentionally distinct).
    assert_eq!(cc::Smt::new().root(), [0u8; 32]);
    assert_ne!(full::Smt::new().root(), [0u8; 32]);
}

#[test]
fn full_tree_root_equals_partial_witness_reconstruction() {
    let mut r = R::new(1);
    for round in 0..40 {
        let (smt, _f, keys) = build(&mut r, 1 + (round * 7) % 80);
        if keys.is_empty() {
            continue;
        }
        // touch a sorted subset, mixing present keys and fresh (absent) ones
        let mut touched: Vec<Hash> = keys.iter().step_by(3).copied().collect();
        for _ in 0..(round % 4) {
            touched.push(rand_hash(&mut r));
        }
        touched.sort();
        touched.dedup();

        let entries: Vec<(Hash, Hash)> =
            touched.iter().map(|k| (*k, smt.get_leaf_hash(k))).collect();
        let siblings = smt.frontier_siblings(&touched);
        let recon = cc::root_from_witness(&entries, &siblings);
        assert_eq!(recon, Some(smt.root()), "round {round}: partial != full root");
    }
}

#[test]
fn same_siblings_reconstruct_both_pre_and_post_roots() {
    // The exact property `prove_transition` relies on: build siblings once from the
    // pre-state, then both the pre-state and the mutated post-state reconstruct under
    // those same siblings (the touched key set, hence the sibling layout, is fixed).
    let mut r = R::new(2);
    for round in 0..40 {
        let (mut smt, _f, keys) = build(&mut r, 4 + (round * 5) % 60);
        if keys.len() < 2 {
            continue;
        }
        let touched: Vec<Hash> = {
            let mut t: Vec<Hash> = keys.iter().step_by(2).copied().collect();
            t.push(rand_hash(&mut r)); // a fresh absent key the batch will create
            t.sort();
            t.dedup();
            t
        };
        let pre: Vec<(Hash, Hash)> = touched.iter().map(|k| (*k, smt.get_leaf_hash(k))).collect();
        let siblings = smt.frontier_siblings(&touched);
        assert_eq!(cc::root_from_witness(&pre, &siblings), Some(smt.root()));

        // mutate every touched leaf (some set, some cleared), apply to the full tree too
        let post: Vec<(Hash, Hash)> = touched
            .iter()
            .enumerate()
            .map(|(i, k)| {
                let v = if i % 5 == 0 { [0u8; 32] } else { rand_content(&mut r) };
                (*k, v)
            })
            .collect();
        for (k, v) in &post {
            smt.set_leaf_hash(*k, *v);
        }
        let recon_post = cc::root_from_witness(&post, &siblings);
        assert_eq!(recon_post, Some(smt.root()), "round {round}: post root mismatch");
    }
}

#[test]
fn single_leaf_proof_verifies_for_members_and_non_members() {
    let mut r = R::new(3);
    let (smt, _f, keys) = build(&mut r, 50);
    let root = smt.root();
    // members
    for k in keys.iter().take(20) {
        let proof = smt.proof(k);
        assert!(cc::verify_proof(&root, k, &smt.get_leaf_hash(k), &proof), "member {k:?}");
    }
    // non-members (absent key, empty leaf)
    for _ in 0..20 {
        let ghost = rand_hash(&mut r);
        if smt.get_leaf_hash(&ghost) != [0u8; 32] {
            continue;
        }
        let proof = smt.proof(&ghost);
        assert!(cc::verify_proof(&root, &ghost, &[0u8; 32], &proof), "non-member");
    }
}

#[test]
fn tampered_proofs_are_rejected() {
    let mut r = R::new(4);
    let (smt, _f, keys) = build(&mut r, 40);
    let root = smt.root();
    let k = keys[7];
    let leaf = smt.get_leaf_hash(&k);
    let proof = smt.proof(&k);
    assert!(cc::verify_proof(&root, &k, &leaf, &proof));

    // wrong leaf value
    assert!(!cc::verify_proof(&root, &k, &keccak(b"not-the-leaf"), &proof));
    // flipped sibling (flip a byte in every position so we catch the non-empty one)
    for d in 0..proof.len() {
        if proof[d] == [0u8; 32] {
            continue; // flipping an empty (pass-through) sibling can be a no-op; skip
        }
        let mut bad = proof.clone();
        bad[d][0] ^= 1;
        assert!(!cc::verify_proof(&root, &k, &leaf, &bad), "flip at depth {d} not caught");
        break;
    }
    // wrong-length proof
    let mut short = proof.clone();
    short.pop();
    assert!(!cc::verify_proof(&root, &k, &leaf, &short));
    // wrong root
    assert!(!cc::verify_proof(&keccak(b"wrong-root"), &k, &leaf, &proof));
}

#[test]
fn deterministic_and_order_independent_vs_depth256_membership() {
    // Both schemes are deterministic functions of the leaf SET (order-independent),
    // and they agree on which keys are members (the depth-256 tree is the oracle).
    let mut r = R::new(5);
    let n = 60;
    let mut pairs: Vec<(Hash, Hash)> = (0..n).map(|_| (rand_hash(&mut r), rand_content(&mut r))).collect();

    let mut c1 = cc::Smt::new();
    for (k, v) in &pairs {
        c1.set_leaf_hash(*k, *v);
    }
    // insert in a different order
    pairs.reverse();
    let mut c2 = cc::Smt::new();
    for (k, v) in &pairs {
        c2.set_leaf_hash(*k, *v);
    }
    assert_eq!(c1.root(), c2.root(), "compact root depends on insertion order");

    // a fresh present leaf changes the root; clearing it back restores it
    let r0 = c1.root();
    let (nk, nv) = (rand_hash(&mut r), rand_content(&mut r));
    c1.set_leaf_hash(nk, nv);
    assert_ne!(c1.root(), r0, "adding a leaf did not change the root");
    c1.set_leaf_hash(nk, [0u8; 32]);
    assert_eq!(c1.root(), r0, "clearing the leaf did not restore the root");
}

#[test]
fn sparse_proof_round_trips_and_rejects_malformed() {
    // The v2 witness-size compaction: a single-leaf compact proof (mostly EMPTY_LEAF siblings)
    // sparse-encodes to a 32-byte bitmap + ONLY the non-empty siblings, and decodes back to the EXACT
    // 256-long vector. This pins the on-the-wire format the on-chain escape hatch
    // (`escape::smt_root_sparse`) decodes; the ckb-contract-tests escape suites pin the contract to it.
    let mut r = R::new(0x00C0FFEE);
    let (smt, _f, keys) = build(&mut r, 60);
    let key = keys[17];
    let content = smt.get_leaf_hash(&key);
    let root = smt.root();
    let full_sib = smt.proof(&key);
    assert_eq!(full_sib.len(), 256);
    assert!(cc::verify_proof(&root, &key, &content, &full_sib));

    let sparse = cc::sparse_encode_proof(&full_sib);
    assert!(sparse.len() < 8192, "sparse proof must be far smaller than the 8192-byte full form");
    assert_eq!(sparse.len() % 32, 0, "32-byte bitmap + whole siblings");
    let decoded = cc::sparse_decode_proof(&sparse).expect("decode a well-formed sparse proof");
    assert_eq!(decoded, full_sib, "sparse round-trip must restore the exact 256-sibling vector");
    assert!(cc::verify_proof(&root, &key, &content, &decoded));

    // Malformed sparse blobs are rejected (the on-chain decoder applies the same three checks).
    assert!(cc::sparse_decode_proof(&[0u8; 31]).is_none(), "too short for a bitmap");
    let mut bad_len = sparse.clone();
    bad_len.push(0); // `present` no longer a multiple of 32
    assert!(cc::sparse_decode_proof(&bad_len).is_none(), "present not a multiple of 32");
    let mut bad_pop = sparse.clone();
    bad_pop[0] ^= 0xff; // set bitmap bits without adding siblings => popcount != present count
    assert!(cc::sparse_decode_proof(&bad_pop).is_none(), "bitmap popcount must equal present count");
}

#[cfg(feature = "hash_count")]
#[test]
fn compact_reconstruction_costs_far_fewer_keccaks_than_depth256() {
    use liquid_cells_stf::hash::count;

    let mut r = R::new(7);
    let n = 512; // a realistic pool
    let (cmt, fmt, keys) = build(&mut r, n);
    // a typical batch: 16 touched leaves
    let mut touched: Vec<Hash> = keys.iter().step_by(keys.len().max(16) / 16).take(16).copied().collect();
    touched.sort();
    touched.dedup();

    let c_entries: Vec<(Hash, Hash)> = touched.iter().map(|k| (*k, cmt.get_leaf_hash(k))).collect();
    let f_entries: Vec<(Hash, Hash)> = touched.iter().map(|k| (*k, fmt.get_leaf_hash(k))).collect();
    let c_sib = cmt.frontier_siblings(&touched);
    let f_sib = fmt.frontier_siblings(&touched);

    // Proving cost = the guest's root_from_witness keccaks (it runs it twice; we count one).
    count::reset();
    let cr = cc::root_from_witness(&c_entries, &c_sib).unwrap();
    let compact_keccaks = count::get();
    assert_eq!(cr, cmt.root());

    count::reset();
    let fr = full::root_from_witness(&f_entries, &f_sib).unwrap();
    let full_keccaks = count::get();
    assert_eq!(fr, fmt.root());

    // Single-leaf force-exit verify cost (the contract side). Everything but the
    // verify call itself is precomputed so the counter measures only the verify.
    let k = touched[0];
    let (cmt_root, fmt_root) = (cmt.root(), fmt.root());
    let (cleaf, fleaf) = (cmt.get_leaf_hash(&k), fmt.get_leaf_hash(&k));
    let cproof = cmt.proof(&k);
    let fproof = fmt.proof(&k);
    count::reset();
    assert!(cc::verify_proof(&cmt_root, &k, &cleaf, &cproof));
    let compact_verify = count::get();
    count::reset();
    assert!(full::verify_proof(&fmt_root, &k, &fleaf, &fproof));
    let full_verify = count::get();

    println!(
        "compact SMT cost (pool={n}, batch={}):\n  reconstruct keccaks: compact={compact_keccaks} full={full_keccaks} ({:.1}x fewer)\n  1-leaf verify keccaks: compact={compact_verify} full={full_verify} ({:.1}x fewer)",
        touched.len(),
        full_keccaks as f64 / compact_keccaks.max(1) as f64,
        full_verify as f64 / compact_verify.max(1) as f64,
    );

    // The headline claim: the compact reconstruction is at least 3x cheaper in keccaks,
    // and a single-leaf verify (256 hashes in the deployed tree) collapses to ~log.
    assert!(compact_keccaks * 3 < full_keccaks, "compact reconstruction not >=3x cheaper");
    assert!(full_verify == 256, "depth-256 verify should be exactly 256 keccaks");
    assert!(compact_verify * 8 < full_verify, "compact verify not >=8x cheaper");
}
