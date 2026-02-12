//! TCK-00472: RFC-0029 REQ-0003 integration tests for verification
//! amortization and proof-cache discipline.

use apm2_core::context::proof_cache::{
    DEFAULT_MAX_TTL_TICKS, MAX_PROOF_CACHE_ENTRIES, ProofCache, ProofCacheDefect,
    ProofCacheDefectCode, ProofCacheError, ProofCacheMetrics, ProofCachePolicy, VerificationInput,
    VerificationResult,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const fn default_policy() -> ProofCachePolicy {
    ProofCachePolicy {
        max_entries: 1_000,
        max_ttl_ticks: 100,
        revocation_generation: 0,
        allow_reuse: true,
    }
}

fn make_input(id: u8) -> VerificationInput {
    let mut key = [0u8; 32];
    key[0] = id;
    VerificationInput {
        proof_key: key,
        payload: vec![id],
    }
}

fn make_input_from_usize(id: usize) -> VerificationInput {
    let bytes = id.to_le_bytes();
    let mut key = [0u8; 32];
    for (i, b) in bytes.iter().enumerate() {
        if i < 32 {
            key[i] = *b;
        }
    }
    VerificationInput {
        proof_key: key,
        payload: bytes.to_vec(),
    }
}

const fn pass_verifier(_input: &VerificationInput) -> VerificationResult {
    VerificationResult::Pass
}

fn assert_defect_code(err: ProofCacheError, expected: ProofCacheDefectCode) {
    match err {
        ProofCacheError::Defect(d) => {
            assert_eq!(d.code, expected);
        },
        _ => panic!("expected ProofCacheError::Defect, got {err:?}"),
    }
}

// ---------------------------------------------------------------------------
// cache_hit_reuses_proof
// ---------------------------------------------------------------------------

#[test]
fn cache_hit_reuses_proof() {
    let mut cache = ProofCache::new(default_policy()).expect("cache creation");
    let input = make_input(1);

    // First batch: miss and compute.
    let results = cache
        .verify_batch(std::slice::from_ref(&input), 0, pass_verifier)
        .expect("batch 1");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0], VerificationResult::Pass);
    assert_eq!(cache.metrics().cache_misses, 1);
    assert_eq!(cache.metrics().cache_hits, 0);

    // Second batch: hit from cache (no recompute).
    let mut compute_count = 0u64;
    let results = cache
        .verify_batch(std::slice::from_ref(&input), 1, |inp| {
            compute_count += 1;
            pass_verifier(inp)
        })
        .expect("batch 2");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0], VerificationResult::Pass);
    assert_eq!(compute_count, 0, "verifier must NOT be called on cache hit");
    assert_eq!(cache.metrics().cache_hits, 1);
}

// ---------------------------------------------------------------------------
// stale_cache_entry_denied
// ---------------------------------------------------------------------------

#[test]
fn stale_cache_entry_denied() {
    let policy = ProofCachePolicy {
        max_ttl_ticks: 10,
        ..default_policy()
    };
    let mut cache = ProofCache::new(policy).expect("cache creation");
    let key = [0xAA; 32];
    cache
        .insert(key, VerificationResult::Pass, 5)
        .expect("insert");

    // Lookup at tick 5 + 10 + 1 = 16 (age 11 > TTL 10).
    let err = cache.lookup(&key, 16).expect_err("stale must deny");
    assert_defect_code(err, ProofCacheDefectCode::StaleCacheEntry);
}

// ---------------------------------------------------------------------------
// revoked_generation_denied
// ---------------------------------------------------------------------------

#[test]
fn revoked_generation_denied() {
    let mut cache = ProofCache::new(default_policy()).expect("cache creation");
    let key = [0xBB; 32];
    cache
        .insert(key, VerificationResult::Pass, 0)
        .expect("insert");

    // Bump revocation generation.
    cache.invalidate_generation();

    let err = cache.lookup(&key, 0).expect_err("revoked must deny");
    assert_defect_code(err, ProofCacheDefectCode::RevokedCacheEntry);
}

// ---------------------------------------------------------------------------
// cache_overflow_denied
// ---------------------------------------------------------------------------

#[test]
fn cache_overflow_denied() {
    let policy = ProofCachePolicy {
        max_entries: 3,
        ..default_policy()
    };
    let mut cache = ProofCache::new(policy).expect("cache creation");

    for i in 0u8..3 {
        let mut key = [0u8; 32];
        key[0] = i;
        cache
            .insert(key, VerificationResult::Pass, 0)
            .expect("insert within bounds");
    }

    // Fourth insert should fail.
    let err = cache
        .insert([0xFF; 32], VerificationResult::Pass, 0)
        .expect_err("overflow must deny");
    assert_defect_code(err, ProofCacheDefectCode::CacheCapacityExceeded);
}

// ---------------------------------------------------------------------------
// batch_dedup_reduces_work
// ---------------------------------------------------------------------------

#[test]
fn batch_dedup_reduces_work() {
    let mut cache = ProofCache::new(default_policy()).expect("cache creation");
    let mut compute_count = 0u64;

    let input = make_input(42);
    // 5 identical inputs, but only 1 unique proof key.
    let inputs = vec![
        input.clone(),
        input.clone(),
        input.clone(),
        input.clone(),
        input,
    ];

    let results = cache
        .verify_batch(&inputs, 0, |inp| {
            compute_count += 1;
            pass_verifier(inp)
        })
        .expect("batch");
    assert_eq!(results.len(), 5);
    assert_eq!(
        compute_count, 1,
        "verifier called once for 5 identical inputs"
    );
    assert_eq!(
        cache.metrics().batch_dedup_count,
        4,
        "4 duplicates eliminated"
    );
    assert_eq!(cache.metrics().total_verifications, 5);
}

// ---------------------------------------------------------------------------
// sub_linear_workload_growth
// ---------------------------------------------------------------------------

#[test]
#[allow(clippy::cast_precision_loss)]
fn sub_linear_workload_growth() {
    let mut cache = ProofCache::new(default_policy()).expect("cache creation");

    // Create a workload with 50 unique keys, each repeated 10 times = 500
    // total inputs, but only 50 unique computations needed.
    let unique_count: usize = 50;
    let repeat_count: usize = 10;
    let total_inputs = unique_count * repeat_count;

    let mut inputs = Vec::with_capacity(total_inputs);
    for _r in 0..repeat_count {
        for u in 0..unique_count {
            inputs.push(make_input_from_usize(u));
        }
    }

    let mut compute_count = 0u64;
    let results = cache
        .verify_batch(&inputs, 0, |inp| {
            compute_count += 1;
            pass_verifier(inp)
        })
        .expect("batch");

    assert_eq!(results.len(), total_inputs);
    assert_eq!(
        compute_count, unique_count as u64,
        "only unique keys computed"
    );
    assert!(
        (compute_count as f64) < (total_inputs as f64),
        "workload must be sub-linear: {compute_count} computations < {total_inputs} inputs"
    );

    let ratio = cache.metrics().amortization_ratio();
    // With 50 misses out of 500 total: ratio = 1 - 50/500 = 0.9
    assert!(
        ratio > 0.8,
        "amortization ratio {ratio} must be >0.8 for this correlated workload"
    );
}

// ---------------------------------------------------------------------------
// cache_disabled_always_computes
// ---------------------------------------------------------------------------

#[test]
fn cache_disabled_always_computes() {
    let policy = ProofCachePolicy {
        allow_reuse: false,
        ..default_policy()
    };
    let mut cache = ProofCache::new(policy).expect("cache creation");
    let input = make_input(99);

    // First batch.
    let _ = cache
        .verify_batch(std::slice::from_ref(&input), 0, pass_verifier)
        .expect("batch 1");

    // Second batch with same input — should recompute.
    let mut compute_count = 0u64;
    let results = cache
        .verify_batch(std::slice::from_ref(&input), 1, |inp| {
            compute_count += 1;
            pass_verifier(inp)
        })
        .expect("batch 2");
    assert_eq!(results.len(), 1);
    assert_eq!(
        compute_count, 1,
        "verifier must be called when reuse is disabled"
    );
}

// ---------------------------------------------------------------------------
// verify_batch_preserves_input_order
// ---------------------------------------------------------------------------

#[test]
fn verify_batch_preserves_input_order() {
    let mut cache = ProofCache::new(default_policy()).expect("cache creation");

    let inputs = vec![make_input(10), make_input(20), make_input(30)];
    let results = cache
        .verify_batch(&inputs, 0, |input| {
            if input.proof_key[0] == 20 {
                VerificationResult::Deny(ProofCacheDefect {
                    code: ProofCacheDefectCode::UnresolvedCacheBinding,
                    message: "deliberately denied for test".into(),
                    proof_key_hex: Some(hex::encode(input.proof_key)),
                })
            } else {
                VerificationResult::Pass
            }
        })
        .expect("batch");

    assert_eq!(results.len(), 3);
    assert_eq!(results[0], VerificationResult::Pass);
    assert!(matches!(results[1], VerificationResult::Deny(_)));
    assert_eq!(results[2], VerificationResult::Pass);
}

// ---------------------------------------------------------------------------
// Additional negative tests
// ---------------------------------------------------------------------------

#[test]
fn stale_entry_in_batch_produces_deny_result() {
    let policy = ProofCachePolicy {
        max_ttl_ticks: 5,
        ..default_policy()
    };
    let mut cache = ProofCache::new(policy).expect("cache creation");
    let input = make_input(1);

    // Populate cache at tick 0.
    let _ = cache
        .verify_batch(std::slice::from_ref(&input), 0, pass_verifier)
        .expect("first batch");

    // Query at tick 10 — entry is stale (age 10 > TTL 5).
    let results = cache
        .verify_batch(std::slice::from_ref(&input), 10, pass_verifier)
        .expect("second batch");
    assert_eq!(results.len(), 1);
    match &results[0] {
        VerificationResult::Deny(d) => {
            assert_eq!(d.code, ProofCacheDefectCode::StaleCacheEntry);
        },
        VerificationResult::Pass => panic!("stale entry must produce Deny"),
    }
}

#[test]
fn revocation_race_in_batch_produces_deny_result() {
    let mut cache = ProofCache::new(default_policy()).expect("cache creation");
    let input = make_input(1);

    // Populate cache at generation 0.
    let _ = cache
        .verify_batch(std::slice::from_ref(&input), 0, pass_verifier)
        .expect("first batch");

    // Bump generation (simulates revocation event).
    cache.invalidate_generation();

    // Query again — entry is revoked.
    let results = cache
        .verify_batch(std::slice::from_ref(&input), 1, pass_verifier)
        .expect("second batch");
    assert_eq!(results.len(), 1);
    match &results[0] {
        VerificationResult::Deny(d) => {
            assert_eq!(d.code, ProofCacheDefectCode::RevokedCacheEntry);
        },
        VerificationResult::Pass => panic!("revoked entry must produce Deny"),
    }
}

#[test]
fn capacity_exceeded_in_batch_produces_deny_for_overflow_input() {
    let policy = ProofCachePolicy {
        max_entries: 2,
        ..default_policy()
    };
    let mut cache = ProofCache::new(policy).expect("cache creation");

    // Pre-fill to capacity.
    cache
        .insert([0x01; 32], VerificationResult::Pass, 0)
        .expect("insert 1");
    cache
        .insert([0x02; 32], VerificationResult::Pass, 0)
        .expect("insert 2");

    // New input that would exceed capacity.
    let new_input = make_input(0xFF);
    let results = cache
        .verify_batch(std::slice::from_ref(&new_input), 0, pass_verifier)
        .expect("batch with overflow");
    assert_eq!(results.len(), 1);
    match &results[0] {
        VerificationResult::Deny(d) => {
            assert_eq!(d.code, ProofCacheDefectCode::CacheCapacityExceeded);
        },
        VerificationResult::Pass => panic!("overflow input must produce Deny"),
    }
}

// ---------------------------------------------------------------------------
// Policy max_entries > hard limit denied at construction
// ---------------------------------------------------------------------------

#[test]
fn policy_exceeding_hard_limit_denied() {
    let policy = ProofCachePolicy {
        max_entries: MAX_PROOF_CACHE_ENTRIES + 1,
        ..default_policy()
    };
    let err = ProofCache::new(policy).expect_err("should deny");
    assert_defect_code(err, ProofCacheDefectCode::UnresolvedCacheBinding);
}

// ---------------------------------------------------------------------------
// Default constants are sane
// ---------------------------------------------------------------------------

#[test]
fn default_constants_are_reasonable() {
    assert_ne!(MAX_PROOF_CACHE_ENTRIES, 0);
    assert_ne!(DEFAULT_MAX_TTL_TICKS, 0);

    let default = ProofCachePolicy::default();
    assert_eq!(default.max_entries, MAX_PROOF_CACHE_ENTRIES);
    assert_eq!(default.max_ttl_ticks, DEFAULT_MAX_TTL_TICKS);
    assert!(default.allow_reuse);
    assert_eq!(default.revocation_generation, 0);
}

// ---------------------------------------------------------------------------
// Metrics amortization ratio evidence
// ---------------------------------------------------------------------------

#[test]
fn metrics_amortization_evidence() {
    let m = ProofCacheMetrics {
        cache_hits: 950,
        cache_misses: 50,
        batch_dedup_count: 0,
        total_verifications: 1000,
    };
    let ratio = m.amortization_ratio();
    assert!(
        (ratio - 0.95).abs() < 0.001,
        "expected 0.95 amortization ratio, got {ratio}"
    );
}

#[test]
fn metrics_zero_verifications_safe() {
    let m = ProofCacheMetrics::default();
    assert!((m.amortization_ratio() - 0.0).abs() < f64::EPSILON);
}

// ---------------------------------------------------------------------------
// Second-call batch with mixed hit/miss
// ---------------------------------------------------------------------------

#[test]
fn mixed_hit_miss_batch() {
    let mut cache = ProofCache::new(default_policy()).expect("cache creation");

    // Populate with input 1.
    let input1 = make_input(1);
    let _ = cache
        .verify_batch(std::slice::from_ref(&input1), 0, pass_verifier)
        .expect("initial batch");

    // Second batch: input 1 (hit) + input 2 (miss).
    let input2 = make_input(2);
    let mut compute_count = 0u64;
    let batch = [input1, input2];
    let results = cache
        .verify_batch(&batch, 1, |inp| {
            compute_count += 1;
            pass_verifier(inp)
        })
        .expect("mixed batch");

    assert_eq!(results.len(), 2);
    assert_eq!(results[0], VerificationResult::Pass);
    assert_eq!(results[1], VerificationResult::Pass);
    assert_eq!(compute_count, 1, "only input 2 should be computed");
    assert_eq!(cache.metrics().cache_hits, 1);
}
