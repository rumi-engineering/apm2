//! RFC-0029 REQ-0003: Verification amortization and proof-cache discipline.
//!
//! Implements bounded, policy-gated proof-cache reuse with batching,
//! deduplicated proof paths, and deterministic cache invalidation that
//! preserves freshness and revocation correctness.
//!
//! # Design
//!
//! - [`ProofCache`]: bounded LRU-free cache mapping proof keys to cached
//!   verification results. Overflow denies (never evicts silently).
//! - [`ProofCachePolicy`]: governs reuse, TTL, revocation generation, and
//!   capacity.
//! - [`ProofCache::verify_batch`]: batch-verifies inputs, deduplicating by
//!   proof key and serving cache hits where policy permits.
//!
//! # Fail-Closed Semantics
//!
//! Every ambiguous or stale state produces a deterministic deny:
//!
//! - Stale entry (expired TTL) -> [`ProofCacheDefectCode::StaleCacheEntry`]
//! - Revoked generation -> [`ProofCacheDefectCode::RevokedCacheEntry`]
//! - Cache overflow -> [`ProofCacheDefectCode::CacheCapacityExceeded`]
//! - Unresolved binding -> [`ProofCacheDefectCode::UnresolvedCacheBinding`]
//!
//! # Security
//!
//! Cache artifacts never bypass revocation or freshness constraints. Any
//! revocation event bumps the global generation counter, invalidating all
//! entries minted under older generations.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Hard upper bound on proof cache entries to prevent memory denial of service.
pub const MAX_PROOF_CACHE_ENTRIES: usize = 100_000;

/// Default TTL for cached proof entries (in ticks).
pub const DEFAULT_MAX_TTL_TICKS: u64 = 1_000;

// ---------------------------------------------------------------------------
// Defect taxonomy
// ---------------------------------------------------------------------------

/// Machine-readable defect codes for proof-cache violations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ProofCacheDefectCode {
    /// Cached entry has exceeded its TTL — freshness violated.
    StaleCacheEntry,
    /// Cached entry was minted under an older revocation generation.
    RevokedCacheEntry,
    /// Cache is at capacity and cannot accept new entries.
    CacheCapacityExceeded,
    /// Cache binding could not be resolved — fail closed.
    UnresolvedCacheBinding,
}

/// Structured defect for proof-cache violations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofCacheDefect {
    /// Machine-readable defect code.
    pub code: ProofCacheDefectCode,
    /// Human-readable detail.
    pub message: String,
    /// Proof key (hex) when available.
    pub proof_key_hex: Option<String>,
}

/// Errors for proof-cache operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ProofCacheError {
    /// A proof-cache defect was detected.
    #[error("proof cache defect: {0:?}")]
    Defect(ProofCacheDefect),
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

/// Policy governing proof-cache reuse, freshness, and capacity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofCachePolicy {
    /// Maximum number of cache entries. Must be <= [`MAX_PROOF_CACHE_ENTRIES`].
    /// Overflow produces a deny — never evicts silently.
    pub max_entries: usize,
    /// Maximum TTL in ticks. Entries older than this are stale.
    pub max_ttl_ticks: u64,
    /// Current revocation generation. Bumped on any revocation event. Entries
    /// with an older generation are stale.
    pub revocation_generation: u64,
    /// Master switch: if `false`, cache lookups always miss.
    pub allow_reuse: bool,
}

impl Default for ProofCachePolicy {
    fn default() -> Self {
        Self {
            max_entries: MAX_PROOF_CACHE_ENTRIES,
            max_ttl_ticks: DEFAULT_MAX_TTL_TICKS,
            revocation_generation: 0,
            allow_reuse: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Cached entry
// ---------------------------------------------------------------------------

/// A cached verification result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedProofEntry {
    /// The verification result.
    pub result: VerificationResult,
    /// Tick at which this entry was created.
    pub creation_tick: u64,
    /// Revocation generation at creation time.
    pub revocation_generation: u64,
}

// ---------------------------------------------------------------------------
// Verification I/O types
// ---------------------------------------------------------------------------

/// Input to a single verification operation. The proof key is the BLAKE3 hash
/// of the serialised admission inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationInput {
    /// BLAKE3 hash of the admission inputs — the cache key.
    pub proof_key: [u8; 32],
    /// Opaque payload forwarded to the verifier on cache miss.
    pub payload: Vec<u8>,
}

/// Result of a single verification operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationResult {
    /// Verification passed.
    Pass,
    /// Verification denied with a structured defect.
    Deny(ProofCacheDefect),
}

/// Verdict returned by cache lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheVerdict {
    /// Cache hit — result is usable.
    Hit(VerificationResult),
    /// Cache miss — must compute.
    Miss,
}

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

/// Aggregated proof-cache metrics.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProofCacheMetrics {
    /// Number of cache hits served.
    pub cache_hits: u64,
    /// Number of cache misses requiring computation.
    pub cache_misses: u64,
    /// Number of duplicate inputs eliminated in batch dedup.
    pub batch_dedup_count: u64,
    /// Total verification inputs processed.
    pub total_verifications: u64,
}

impl ProofCacheMetrics {
    /// Amortization ratio: `1.0 - (misses / total)`. Returns `0.0` when no
    /// verifications have been processed.
    #[must_use]
    #[allow(clippy::cast_precision_loss)] // u64→f64 precision loss is acceptable for metrics ratios
    pub fn amortization_ratio(&self) -> f64 {
        if self.total_verifications == 0 {
            return 0.0;
        }
        1.0 - (self.cache_misses as f64 / self.total_verifications as f64)
    }
}

// ---------------------------------------------------------------------------
// ProofCache
// ---------------------------------------------------------------------------

/// Bounded, policy-gated proof cache.
///
/// # Synchronization Protocol
///
/// `ProofCache` is **not** internally synchronised. It is intended to be owned
/// by a single verification pipeline thread or wrapped externally in a
/// `Mutex`/`RwLock` if shared access is required. All mutations occur through
/// `&mut self` methods, which the Rust borrow checker enforces at compile time.
///
/// The `entries` `HashMap` is bounded by `policy.max_entries` (hard cap <=
/// [`MAX_PROOF_CACHE_ENTRIES`]). Insert returns `Err` on overflow — never
/// evicts silently.
#[derive(Debug)]
pub struct ProofCache {
    /// Cache storage.
    ///
    /// Bounded: `len <= policy.max_entries <= MAX_PROOF_CACHE_ENTRIES`.
    /// Overflow returns `Err(ProofCacheError::Defect(CacheCapacityExceeded))`.
    entries: HashMap<[u8; 32], CachedProofEntry>,
    /// Governing policy.
    policy: ProofCachePolicy,
    /// Aggregated metrics.
    metrics: ProofCacheMetrics,
}

impl ProofCache {
    /// Creates a new proof cache with the given policy.
    ///
    /// # Errors
    ///
    /// Returns [`ProofCacheError::Defect`] with
    /// [`ProofCacheDefectCode::UnresolvedCacheBinding`] if
    /// `policy.max_entries` exceeds [`MAX_PROOF_CACHE_ENTRIES`].
    pub fn new(policy: ProofCachePolicy) -> Result<Self, ProofCacheError> {
        if policy.max_entries > MAX_PROOF_CACHE_ENTRIES {
            return Err(ProofCacheError::Defect(ProofCacheDefect {
                code: ProofCacheDefectCode::UnresolvedCacheBinding,
                message: format!(
                    "policy max_entries {} exceeds hard limit {}",
                    policy.max_entries, MAX_PROOF_CACHE_ENTRIES,
                ),
                proof_key_hex: None,
            }));
        }
        Ok(Self {
            entries: HashMap::new(),
            policy,
            metrics: ProofCacheMetrics::default(),
        })
    }

    /// Returns a reference to the current policy.
    #[must_use]
    pub const fn policy(&self) -> &ProofCachePolicy {
        &self.policy
    }

    /// Returns a snapshot of the current metrics.
    #[must_use]
    pub const fn metrics(&self) -> &ProofCacheMetrics {
        &self.metrics
    }

    /// Returns the number of entries currently in the cache.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the cache contains no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Looks up a proof key in the cache, validating freshness and revocation.
    ///
    /// Returns [`CacheVerdict::Hit`] when the entry is valid, or
    /// [`CacheVerdict::Miss`] when no usable entry exists.
    ///
    /// # Errors
    ///
    /// Returns [`ProofCacheError::Defect`] with the appropriate code when an
    /// entry exists but is stale or revoked.
    pub fn lookup(
        &self,
        proof_key: &[u8; 32],
        current_tick: u64,
    ) -> Result<CacheVerdict, ProofCacheError> {
        if !self.policy.allow_reuse {
            return Ok(CacheVerdict::Miss);
        }

        let Some(entry) = self.entries.get(proof_key) else {
            return Ok(CacheVerdict::Miss);
        };

        let key_hex = hex::encode(proof_key);

        // Freshness check: tick-based TTL.
        let age = current_tick.saturating_sub(entry.creation_tick);
        if age > self.policy.max_ttl_ticks {
            return Err(ProofCacheError::Defect(ProofCacheDefect {
                code: ProofCacheDefectCode::StaleCacheEntry,
                message: format!(
                    "cache entry age {age} ticks exceeds max TTL {}",
                    self.policy.max_ttl_ticks,
                ),
                proof_key_hex: Some(key_hex),
            }));
        }

        // Revocation check: generation counter.
        if entry.revocation_generation < self.policy.revocation_generation {
            return Err(ProofCacheError::Defect(ProofCacheDefect {
                code: ProofCacheDefectCode::RevokedCacheEntry,
                message: format!(
                    "cache entry generation {} < current revocation generation {}",
                    entry.revocation_generation, self.policy.revocation_generation,
                ),
                proof_key_hex: Some(key_hex),
            }));
        }

        Ok(CacheVerdict::Hit(entry.result.clone()))
    }

    /// Inserts a verification result into the cache.
    ///
    /// # Errors
    ///
    /// Returns [`ProofCacheError::Defect`] with
    /// [`ProofCacheDefectCode::CacheCapacityExceeded`] if the cache is at
    /// capacity and the key is not already present.
    pub fn insert(
        &mut self,
        proof_key: [u8; 32],
        result: VerificationResult,
        current_tick: u64,
    ) -> Result<(), ProofCacheError> {
        // If the key is already present, update in-place (no capacity change).
        if self.entries.contains_key(&proof_key) {
            self.entries.insert(
                proof_key,
                CachedProofEntry {
                    result,
                    creation_tick: current_tick,
                    revocation_generation: self.policy.revocation_generation,
                },
            );
            return Ok(());
        }

        // Capacity check before insertion.
        if self.entries.len() >= self.policy.max_entries {
            return Err(ProofCacheError::Defect(ProofCacheDefect {
                code: ProofCacheDefectCode::CacheCapacityExceeded,
                message: format!(
                    "cache at capacity {} — cannot insert new entry",
                    self.policy.max_entries,
                ),
                proof_key_hex: Some(hex::encode(proof_key)),
            }));
        }

        self.entries.insert(
            proof_key,
            CachedProofEntry {
                result,
                creation_tick: current_tick,
                revocation_generation: self.policy.revocation_generation,
            },
        );
        Ok(())
    }

    /// Bumps the revocation generation, invalidating all cache entries minted
    /// under older generations. Subsequent lookups for those entries will
    /// return [`ProofCacheDefectCode::RevokedCacheEntry`].
    pub const fn invalidate_generation(&mut self) {
        self.policy.revocation_generation = self.policy.revocation_generation.saturating_add(1);
    }

    /// Batch-verifies a set of inputs with deduplication and cache reuse.
    ///
    /// 1. Deduplicates inputs by proof key (same admission inputs -> same
    ///    result).
    /// 2. Looks up the cache first, validating freshness + revocation.
    /// 3. Computes only for cache misses using `verifier_fn`.
    /// 4. Inserts results into the cache.
    /// 5. Returns results **in input order** (deterministic).
    ///
    /// # Verifier function
    ///
    /// `verifier_fn` is called exactly once per unique cache-miss proof key
    /// with the corresponding [`VerificationInput`]. It must return a
    /// [`VerificationResult`].
    ///
    /// # Errors
    ///
    /// Returns [`ProofCacheError`] if a cache operation (insert, lookup) fails
    /// in a way that cannot be associated with a single input (e.g., capacity
    /// exceeded mid-batch).
    pub fn verify_batch<F>(
        &mut self,
        inputs: &[VerificationInput],
        current_tick: u64,
        mut verifier_fn: F,
    ) -> Result<Vec<VerificationResult>, ProofCacheError>
    where
        F: FnMut(&VerificationInput) -> VerificationResult,
    {
        self.metrics.total_verifications = self
            .metrics
            .total_verifications
            .saturating_add(inputs.len() as u64);

        // Collect unique proof keys (preserving first-seen input for verifier).
        let mut unique_results: HashMap<[u8; 32], VerificationResult> = HashMap::new();
        let mut seen_count: usize = 0;

        for input in inputs {
            if unique_results.contains_key(&input.proof_key) {
                // Already resolved in this batch.
                continue;
            }
            seen_count = seen_count.saturating_add(1);

            // Try cache lookup.
            match self.lookup(&input.proof_key, current_tick) {
                Ok(CacheVerdict::Hit(result)) => {
                    self.metrics.cache_hits = self.metrics.cache_hits.saturating_add(1);
                    unique_results.insert(input.proof_key, result);
                },
                Ok(CacheVerdict::Miss) => {
                    // Compute.
                    self.metrics.cache_misses = self.metrics.cache_misses.saturating_add(1);
                    let result = verifier_fn(input);
                    // Insert into cache (best-effort — capacity exceeded is
                    // surfaced as a deny for this input).
                    match self.insert(input.proof_key, result.clone(), current_tick) {
                        Ok(()) => {},
                        Err(ProofCacheError::Defect(defect))
                            if defect.code == ProofCacheDefectCode::CacheCapacityExceeded =>
                        {
                            // Record as deny for this key; do not propagate as
                            // batch-level error — the input still gets a
                            // deterministic deny.
                            unique_results
                                .insert(input.proof_key, VerificationResult::Deny(defect));
                            continue;
                        },
                        Err(e) => return Err(e),
                    }
                    unique_results.insert(input.proof_key, result);
                },
                Err(ProofCacheError::Defect(defect)) => {
                    // Stale/revoked — deterministic deny for this key.
                    self.metrics.cache_misses = self.metrics.cache_misses.saturating_add(1);
                    unique_results.insert(input.proof_key, VerificationResult::Deny(defect));
                },
            }
        }

        // Compute dedup savings.
        let dedup_count = inputs.len().saturating_sub(seen_count);
        self.metrics.batch_dedup_count = self
            .metrics
            .batch_dedup_count
            .saturating_add(dedup_count as u64);

        // Build results in input order.
        let results: Vec<VerificationResult> = inputs
            .iter()
            .map(|input| {
                unique_results
                    .get(&input.proof_key)
                    .cloned()
                    .unwrap_or_else(|| {
                        // Unreachable by construction: every input's key was
                        // inserted into unique_results above. Fail closed.
                        VerificationResult::Deny(ProofCacheDefect {
                            code: ProofCacheDefectCode::UnresolvedCacheBinding,
                            message: "proof key not resolved during batch verification".into(),
                            proof_key_hex: Some(hex::encode(input.proof_key)),
                        })
                    })
            })
            .collect();

        Ok(results)
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn default_policy() -> ProofCachePolicy {
        ProofCachePolicy {
            max_entries: 100,
            max_ttl_ticks: 50,
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

    fn pass_verifier(_input: &VerificationInput) -> VerificationResult {
        VerificationResult::Pass
    }

    // --- Construction ---

    #[test]
    fn new_with_valid_policy() {
        let cache = ProofCache::new(default_policy());
        assert!(cache.is_ok());
        let cache = cache.expect("valid policy");
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn new_exceeding_hard_limit_denied() {
        let policy = ProofCachePolicy {
            max_entries: MAX_PROOF_CACHE_ENTRIES + 1,
            ..default_policy()
        };
        let err = ProofCache::new(policy).expect_err("should deny");
        match err {
            ProofCacheError::Defect(d) => {
                assert_eq!(d.code, ProofCacheDefectCode::UnresolvedCacheBinding);
            },
        }
    }

    // --- Lookup ---

    #[test]
    fn lookup_miss_on_empty() {
        let cache = ProofCache::new(default_policy()).expect("ok");
        let key = [0u8; 32];
        let verdict = cache.lookup(&key, 0).expect("no error");
        assert_eq!(verdict, CacheVerdict::Miss);
    }

    #[test]
    fn lookup_hit_after_insert() {
        let mut cache = ProofCache::new(default_policy()).expect("ok");
        let key = [1u8; 32];
        cache
            .insert(key, VerificationResult::Pass, 10)
            .expect("insert ok");
        let verdict = cache.lookup(&key, 10).expect("no error");
        assert_eq!(verdict, CacheVerdict::Hit(VerificationResult::Pass));
    }

    #[test]
    fn lookup_stale_entry_denied() {
        let mut cache = ProofCache::new(default_policy()).expect("ok");
        let key = [2u8; 32];
        cache
            .insert(key, VerificationResult::Pass, 10)
            .expect("insert ok");
        // Lookup at tick 10 + TTL + 1 = 10 + 50 + 1 = 61
        let err = cache.lookup(&key, 61).expect_err("stale must deny");
        match err {
            ProofCacheError::Defect(d) => {
                assert_eq!(d.code, ProofCacheDefectCode::StaleCacheEntry);
                assert!(d.proof_key_hex.is_some());
            },
        }
    }

    #[test]
    fn lookup_revoked_entry_denied() {
        let mut cache = ProofCache::new(default_policy()).expect("ok");
        let key = [3u8; 32];
        cache
            .insert(key, VerificationResult::Pass, 10)
            .expect("insert ok");
        cache.invalidate_generation();
        let err = cache.lookup(&key, 10).expect_err("revoked must deny");
        match err {
            ProofCacheError::Defect(d) => {
                assert_eq!(d.code, ProofCacheDefectCode::RevokedCacheEntry);
            },
        }
    }

    #[test]
    fn lookup_miss_when_reuse_disabled() {
        let policy = ProofCachePolicy {
            allow_reuse: false,
            ..default_policy()
        };
        let mut cache = ProofCache::new(policy).expect("ok");
        let key = [4u8; 32];
        cache
            .insert(key, VerificationResult::Pass, 10)
            .expect("insert ok");
        let verdict = cache.lookup(&key, 10).expect("no error");
        assert_eq!(verdict, CacheVerdict::Miss);
    }

    // --- Insert ---

    #[test]
    fn insert_overflow_denied() {
        let policy = ProofCachePolicy {
            max_entries: 2,
            ..default_policy()
        };
        let mut cache = ProofCache::new(policy).expect("ok");
        cache
            .insert([1u8; 32], VerificationResult::Pass, 0)
            .expect("insert 1");
        cache
            .insert([2u8; 32], VerificationResult::Pass, 0)
            .expect("insert 2");
        let err = cache
            .insert([3u8; 32], VerificationResult::Pass, 0)
            .expect_err("overflow");
        match err {
            ProofCacheError::Defect(d) => {
                assert_eq!(d.code, ProofCacheDefectCode::CacheCapacityExceeded);
            },
        }
    }

    #[test]
    fn insert_update_existing_key_no_capacity_change() {
        let policy = ProofCachePolicy {
            max_entries: 1,
            ..default_policy()
        };
        let mut cache = ProofCache::new(policy).expect("ok");
        let key = [5u8; 32];
        cache
            .insert(key, VerificationResult::Pass, 0)
            .expect("first insert");
        // Updating same key should succeed even at capacity.
        cache
            .insert(key, VerificationResult::Pass, 1)
            .expect("update same key");
        assert_eq!(cache.len(), 1);
    }

    // --- Batch ---

    #[test]
    fn verify_batch_basic() {
        let mut cache = ProofCache::new(default_policy()).expect("ok");
        let inputs = vec![make_input(1), make_input(2)];
        let results = cache
            .verify_batch(&inputs, 0, pass_verifier)
            .expect("batch ok");
        assert_eq!(results.len(), 2);
        assert_eq!(results[0], VerificationResult::Pass);
        assert_eq!(results[1], VerificationResult::Pass);
    }

    #[test]
    fn verify_batch_dedup_reduces_work() {
        let mut cache = ProofCache::new(default_policy()).expect("ok");
        let mut call_count = 0u64;
        let inputs = vec![make_input(1), make_input(1), make_input(1)];
        let results = cache
            .verify_batch(&inputs, 0, |input| {
                call_count += 1;
                pass_verifier(input)
            })
            .expect("batch ok");
        assert_eq!(results.len(), 3);
        assert_eq!(call_count, 1, "verifier called once for deduped batch");
        assert_eq!(cache.metrics().batch_dedup_count, 2);
    }

    #[test]
    fn verify_batch_preserves_input_order() {
        let mut cache = ProofCache::new(default_policy()).expect("ok");
        let inputs = vec![make_input(3), make_input(1), make_input(2)];
        let results = cache
            .verify_batch(&inputs, 0, |input| {
                if input.proof_key[0] == 2 {
                    VerificationResult::Deny(ProofCacheDefect {
                        code: ProofCacheDefectCode::UnresolvedCacheBinding,
                        message: "test deny".into(),
                        proof_key_hex: None,
                    })
                } else {
                    VerificationResult::Pass
                }
            })
            .expect("batch ok");
        assert_eq!(results.len(), 3);
        assert_eq!(results[0], VerificationResult::Pass); // input 3
        assert_eq!(results[1], VerificationResult::Pass); // input 1
        assert!(matches!(results[2], VerificationResult::Deny(_))); // input 2
    }

    #[test]
    fn verify_batch_cache_hit_on_second_call() {
        let mut cache = ProofCache::new(default_policy()).expect("ok");
        let inputs = vec![make_input(1)];
        let _ = cache
            .verify_batch(&inputs, 0, pass_verifier)
            .expect("first batch");
        assert_eq!(cache.metrics().cache_misses, 1);
        assert_eq!(cache.metrics().cache_hits, 0);

        let _ = cache
            .verify_batch(&inputs, 1, pass_verifier)
            .expect("second batch");
        assert_eq!(cache.metrics().cache_hits, 1);
        assert_eq!(cache.metrics().cache_misses, 1);
    }

    #[test]
    fn verify_batch_empty_input() {
        let mut cache = ProofCache::new(default_policy()).expect("ok");
        let results = cache.verify_batch(&[], 0, pass_verifier).expect("empty ok");
        assert!(results.is_empty());
    }

    // --- Metrics ---

    #[test]
    fn amortization_ratio_zero_on_no_verifications() {
        let m = ProofCacheMetrics::default();
        assert!((m.amortization_ratio() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn amortization_ratio_correct() {
        let m = ProofCacheMetrics {
            cache_hits: 8,
            cache_misses: 2,
            batch_dedup_count: 0,
            total_verifications: 10,
        };
        assert!((m.amortization_ratio() - 0.8).abs() < f64::EPSILON);
    }

    // --- Invalidation ---

    #[test]
    fn invalidate_generation_increments() {
        let mut cache = ProofCache::new(default_policy()).expect("ok");
        assert_eq!(cache.policy().revocation_generation, 0);
        cache.invalidate_generation();
        assert_eq!(cache.policy().revocation_generation, 1);
        cache.invalidate_generation();
        assert_eq!(cache.policy().revocation_generation, 2);
    }

    #[test]
    fn invalidate_generation_saturates() {
        let policy = ProofCachePolicy {
            revocation_generation: u64::MAX,
            ..default_policy()
        };
        let mut cache = ProofCache::new(policy).expect("ok");
        cache.invalidate_generation();
        assert_eq!(cache.policy().revocation_generation, u64::MAX);
    }
}
