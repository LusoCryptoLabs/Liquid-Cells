//! Regression for the escape-hatch core (what `lc-exit` does, sans RPC): folding the published DA
//! blob of the live type-id'd pool (Pudge checkpoint 0x332e49ff…, seq 1) must rebuild the exact
//! on-chain anchor root and the depositor's leaf, proving a user can recover from L1 data alone.
use liquid_cells_client::{proof_from_da, reconstruct_tree};

fn blob() -> Vec<u8> {
    std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures/typeid/da_blob.bin")).unwrap()
}
fn anchor() -> Vec<u8> {
    std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures/typeid/new_anchor.bin")).unwrap()
}

#[test]
fn reconstruct_typeid_pool_root_matches_onchain_anchor() {
    let blobs = vec![blob()];
    let root = reconstruct_tree(&blobs).expect("reconstruct").root();
    // new_anchor = root(32) ‖ seq(8) ‖ ... ; the reconstructed root must equal the on-chain anchor's.
    assert_eq!(&root[..], &anchor()[0..32], "reconstructed root != on-chain anchor root");
}

#[test]
fn depositor_leaf_recovered_from_da_alone() {
    let blobs = vec![blob()];
    let mut my_key = [0u8; 32];
    my_key.copy_from_slice(
        &hex::decode("61da078bba9223fb5955014bd3a9fa814d210e89add2c31039a1cf04eb598536").unwrap(),
    );
    let (leaf, siblings) = proof_from_da(&blobs, &my_key).expect("proof");
    assert_eq!(leaf.balance, 19_998_900_000, "balance (200 CKB − 0.01 transfer − 0.001 fee)");
    assert_eq!(leaf.nonce, 1);
    assert_eq!(siblings.len(), 256);
}
