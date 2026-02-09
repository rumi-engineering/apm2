//! Criterion benchmark for verifier cache amortization (TCK-00359).
//!
//! Demonstrates that cache reuse measurably reduces repeated identity
//! verification cost (definition-of-done criterion for REQ-0013).
//!
//! - **cached**: Admit head once, verify N identity proofs against it.
//! - **uncached**: Re-admit head before each verification (simulates no cache).

#![allow(missing_docs)]

use apm2_daemon::identity::{
    AlgorithmTag, CellGenesisV1, CellIdV1, DirectoryEntryStatus, DirectoryKindV1,
    DirectoryProofKindV1, DirectoryProofV1, HolonDirectoryHeadV1, HolonGenesisV1, HolonIdV1,
    IdentityProofProfileV1, IdentityProofV1, LedgerAnchorV1, PolicyRootId, PublicKeyIdV1,
    SiblingNode, VerifiedHeadCache, derive_directory_key,
};
use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};

const HASH_BYTES: usize = 32;

// Domain separators replicated from directory_proof.rs for root computation.
const DIRECTORY_LEAF_DOMAIN_SEPARATOR: &[u8] = b"apm2:dir_leaf:v1\0";
const DIRECTORY_NODE_DOMAIN_SEPARATOR: &[u8] = b"apm2:dir_node:v1\0";

fn hash_directory_leaf(
    key: &[u8; HASH_BYTES],
    value_hash: &[u8; HASH_BYTES],
    entry_status: DirectoryEntryStatus,
) -> [u8; HASH_BYTES] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DIRECTORY_LEAF_DOMAIN_SEPARATOR);
    hasher.update(key);
    hasher.update(value_hash);
    hasher.update(&[entry_status.to_byte()]);
    *hasher.finalize().as_bytes()
}

fn hash_directory_node(left: &[u8; HASH_BYTES], right: &[u8; HASH_BYTES]) -> [u8; HASH_BYTES] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DIRECTORY_NODE_DOMAIN_SEPARATOR);
    hasher.update(left);
    hasher.update(right);
    *hasher.finalize().as_bytes()
}

const fn key_bit_at_depth(key: &[u8; HASH_BYTES], depth: usize) -> u8 {
    let byte = key[depth / 8];
    let shift = 7 - (depth % 8);
    (byte >> shift) & 0x01
}

fn compute_root_from_proof(proof: &DirectoryProofV1) -> [u8; HASH_BYTES] {
    let mut current = hash_directory_leaf(proof.key(), proof.value_hash(), proof.entry_status());
    for (depth, sibling) in proof.siblings().iter().enumerate() {
        let bit = key_bit_at_depth(proof.key(), depth);
        current = if bit == 0 {
            hash_directory_node(&current, sibling.hash())
        } else {
            hash_directory_node(sibling.hash(), &current)
        };
    }
    current
}

fn make_public_key_id(fill: u8) -> PublicKeyIdV1 {
    PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[fill; 32])
}

/// Builds a valid fixture triple for benchmarking.
fn build_fixture() -> ([u8; HASH_BYTES], HolonDirectoryHeadV1, IdentityProofV1) {
    let genesis = CellGenesisV1::new(
        [0x01; 32],
        PolicyRootId::Single(make_public_key_id(0xAA)),
        "bench.cell.internal",
    )
    .unwrap();
    let cell_id = CellIdV1::from_genesis(&genesis);

    let holon_genesis = HolonGenesisV1::new(
        cell_id.clone(),
        make_public_key_id(0xBB),
        vec![0xBB; 32],
        None,
        None,
    )
    .unwrap();
    let holon_id = HolonIdV1::from_genesis(&holon_genesis);
    let key = derive_directory_key(&holon_id);

    let siblings = vec![
        SiblingNode::new([0x10; HASH_BYTES]),
        SiblingNode::new([0x11; HASH_BYTES]),
        SiblingNode::new([0x12; HASH_BYTES]),
        SiblingNode::new([0x13; HASH_BYTES]),
    ];

    let proof = DirectoryProofV1::new(
        DirectoryProofKindV1::Smt256CompressedV1,
        key,
        [0xAB; HASH_BYTES],
        DirectoryEntryStatus::Active,
        siblings,
    )
    .unwrap();

    let root = compute_root_from_proof(&proof);

    let profile_hash = IdentityProofProfileV1::baseline_smt_10e12()
        .content_hash()
        .expect("baseline profile hash");
    let head = HolonDirectoryHeadV1::new(
        cell_id,
        12,
        LedgerAnchorV1::ConsensusIndex { index: 99 },
        root,
        DirectoryKindV1::Smt256V1,
        1,
        8192,
        profile_hash,
        [0x62; HASH_BYTES],
        [0x63; HASH_BYTES],
        None,
    )
    .unwrap();

    let head_hash = head.content_hash().unwrap();

    let identity_proof = IdentityProofV1::new(
        Some([0xCC; HASH_BYTES]),
        [0xDD; HASH_BYTES],
        head_hash,
        proof,
        100,
    )
    .unwrap();

    (head_hash, head, identity_proof)
}

fn bench_verifier_cache(c: &mut Criterion) {
    let (head_hash, head, identity_proof) = build_fixture();

    let mut group = c.benchmark_group("verifier_cache");

    for n in [1, 10, 100] {
        // Cached path: admit once, verify N times.
        group.bench_with_input(BenchmarkId::new("cached_verify", n), &n, |b, &n| {
            b.iter_batched(
                || {
                    let mut cache = VerifiedHeadCache::new(64);
                    cache.admit_head(head_hash, head.clone()).unwrap();
                    cache
                },
                |cache| {
                    for _ in 0..n {
                        let status = cache
                            .verify_identity(black_box(&head_hash), black_box(&identity_proof))
                            .unwrap();
                        black_box(status);
                    }
                },
                criterion::BatchSize::SmallInput,
            );
        });

        // Uncached path: re-admit + verify each time.
        group.bench_with_input(
            BenchmarkId::new("uncached_readmit_verify", n),
            &n,
            |b, &n| {
                b.iter(|| {
                    for _ in 0..n {
                        let mut cache = VerifiedHeadCache::new(64);
                        cache
                            .admit_head(black_box(head_hash), black_box(head.clone()))
                            .unwrap();
                        let status = cache
                            .verify_identity(black_box(&head_hash), black_box(&identity_proof))
                            .unwrap();
                        black_box(status);
                    }
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_verifier_cache);
criterion_main!(benches);
