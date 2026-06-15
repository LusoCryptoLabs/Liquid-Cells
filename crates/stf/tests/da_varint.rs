//! Validates the staged `da_varint` DA-blob compression. Runs under `--features da_varint`.
//!
//! Checks the varint codec round-trips (so reconstruction from L1 still works), reconstructs
//! the same tree the fixed layout would, shrinks the blob for typical micro-payment amounts,
//! and never panics on a malformed blob.
#![cfg(feature = "da_varint")]

use liquid_cells_stf::{encode_da_blob, parse_da_blob, reconstruct, Hash, Leaf, Smt};

fn key(seed: u8) -> Hash {
    let mut k = [0u8; 32];
    k[0] = seed;
    k[31] = seed;
    k
}

#[test]
fn round_trips_and_reconstructs_the_same_tree() {
    // sorted ascending by key (key(1) < key(2) < ...), spanning tiny to maximal amounts
    let post: Vec<(Hash, Leaf)> = vec![
        (key(1), Leaf { balance: 0, nonce: 0 }),
        (key(2), Leaf { balance: 1, nonce: 1 }),
        (key(3), Leaf { balance: 100_000, nonce: 7 }),
        (key(4), Leaf { balance: 1u128 << 70, nonce: 1u64 << 40 }),
        (key(5), Leaf { balance: u128::MAX, nonce: u64::MAX }),
    ];

    let blob = encode_da_blob(&post);
    let parsed = parse_da_blob(&blob).expect("varint blob parses");
    assert_eq!(parsed.len(), post.len());
    for (rec, (k, leaf)) in parsed.iter().zip(post.iter()) {
        assert_eq!(&rec.key, k);
        assert_eq!(rec.leaf, *leaf, "varint round-trip must preserve balance/nonce exactly");
    }

    // reconstruction (the force-exit recovery path) rebuilds the exact tree
    let recon = reconstruct(&[blob]).expect("reconstruct from varint blob");
    let mut direct = Smt::new();
    for (k, leaf) in &post {
        direct.set_leaf_hash(*k, leaf.hash());
    }
    assert_eq!(recon.root(), direct.root(), "reconstructed root must match the direct tree");
}

#[test]
fn smaller_than_the_fixed_layout_for_typical_values() {
    // a realistic micro-payment post-state: small balances and nonces
    let post: Vec<(Hash, Leaf)> = (0..64u8)
        .map(|i| (key(i.wrapping_add(1)), Leaf { balance: (i as u128) * 1000 + 1, nonce: i as u64 }))
        .collect();
    let varint = encode_da_blob(&post).len();
    let fixed = post.len() * 56; // key(32) + balance(16) + nonce(8)
    println!(
        "DA blob (n={}): fixed={fixed}B varint={varint}B ({:.0}% smaller)",
        post.len(),
        100.0 * (1.0 - varint as f64 / fixed as f64)
    );
    assert!(varint < fixed, "varint blob must be smaller than the fixed layout for small amounts");
    // 32-byte key dominates; the 24 amount bytes collapse to ~2-4, so expect ~35% off
    assert!(varint < fixed * 3 / 4, "expected at least ~25% smaller");
}

#[test]
fn malformed_blobs_do_not_panic() {
    assert!(parse_da_blob(&[0u8; 10]).is_none(), "a partial key must fail to parse");
    let mut unterminated = vec![0u8; 32];
    unterminated.extend_from_slice(&[0x80, 0x80, 0x80]); // varint continuation that never ends
    assert!(parse_da_blob(&unterminated).is_none(), "an unterminated varint must fail to parse");
}
