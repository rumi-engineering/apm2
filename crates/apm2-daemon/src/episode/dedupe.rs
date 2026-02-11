//! Dedupe cache for idempotent tool replay.
//!
//! This module implements the `DedupeCache` for caching tool results to enable
//! idempotent replay per CTR-DAEMON-004. When a tool request matches a cached
//! result, the broker returns the cached result instead of re-executing.
//!
//! # Architecture
//!
//! ```text
//! DedupeCache
//!     ├── entries: HashMap<DedupeKey, CacheEntry>
//!     ├── lru_order: VecDeque<(DedupeKey, Instant)>  // For TTL and LRU
//!     ├── by_episode: HashMap<EpisodeId, HashSet<DedupeKey>>
//!     └── config: DedupeCacheConfig
//!
//! Cache Entry:
//!     ├── result: ToolResult
//!     ├── policy_hash: Hash
//!     ├── inserted_at_ns: u64  // For TTL (RSK-1304)
//!     └── access_count: u64
//! ```
//!
//! # Security Model
//!
//! Per CTR-1303 and RSK-1304:
//! - Maximum entries is bounded by `MAX_DEDUPE_ENTRIES`
//! - LRU eviction prevents unbounded growth
//! - TTL-based eviction uses timestamps (not just keys) per RSK-1304
//! - Episode-scoped eviction for isolation
//!
//! # LRU Queue Memory Considerations (F08)
//!
//! The `lru_order` `VecDeque` may contain "ghost keys" - entries that remain in
//! the queue after their corresponding cache entries are evicted (e.g., via
//! TTL or episode eviction). These ghost keys are detected and skipped during
//! LRU eviction using timestamp comparison per RSK-1304.
//!
//! **Memory bound:** The queue length is bounded by `O(N * K)` where:
//! - `N` = `MAX_DEDUPE_ENTRIES` (maximum cache entries)
//! - `K` = average number of times a key is re-inserted before reaching the
//!   queue front
//!
//! In practice, `K` is typically 1-2 because:
//! 1. Re-insertion of the same key with a new timestamp only happens when the
//!    key is updated
//! 2. Ghost keys are cleaned up as they reach the front during LRU eviction
//! 3. The queue is FIFO, so older ghost keys are processed first
//!
//! With `MAX_DEDUPE_ENTRIES = 100,000` and each `LruEntry` being approximately
//! 80 bytes (64 bytes for `DedupeKey` + 8 bytes for `u64` timestamp +
//! overhead), worst-case memory is bounded at approximately 16-32 MB for the
//! LRU queue, which is acceptable given the overall cache memory budget of 100
//! MB.
//!
//! # Contract References
//!
//! - CTR-DAEMON-004: `ToolBroker` structure with dedupe cache
//! - CTR-1303: Bounded collections with MAX_* constants
//! - RSK-1304: Ghost key prevention in TTL queues

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, trace};

use super::decision::{DedupeKey, ToolResult};
use super::error::EpisodeId;
use super::runtime::Hash;

// =============================================================================
// Limits (CTR-1303)
// =============================================================================

/// Maximum number of entries in the dedupe cache.
pub const MAX_DEDUPE_ENTRIES: usize = 100_000;

/// Default TTL for cache entries (1 hour).
pub const DEFAULT_TTL_SECS: u64 = 3600;

/// Maximum TTL for cache entries (24 hours).
pub const MAX_TTL_SECS: u64 = 86400;

/// Default maximum total bytes for the dedupe cache (100 MB).
///
/// This provides a memory safety bound independent of entry count.
/// With a 10MB max output per entry, even 100k entries could theoretically
/// consume 1TB of RAM without this limit.
pub const DEFAULT_MAX_TOTAL_BYTES: usize = 100 * 1024 * 1024;

/// Minimum allowed value for `max_total_bytes` (1 MB).
///
/// This prevents misconfiguration that could cause constant eviction.
pub const MIN_MAX_TOTAL_BYTES: usize = 1024 * 1024;

// =============================================================================
// DedupeCacheConfig
// =============================================================================

/// Configuration for the dedupe cache.
///
/// # Memory Safety
///
/// The cache enforces two independent bounds to prevent resource exhaustion:
/// 1. `max_entries` - Maximum number of cached entries (default: 100,000)
/// 2. `max_total_bytes` - Maximum aggregate memory for cached outputs (default:
///    100 MB)
///
/// Both limits trigger LRU eviction when exceeded. The memory limit is critical
/// because individual tool outputs can be up to 10 MB each (per
/// `MAX_TOOL_OUTPUT_SIZE`), meaning 100k entries could theoretically consume 1
/// TB of RAM without it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DedupeCacheConfig {
    /// Maximum number of entries in the cache.
    pub max_entries: usize,

    /// Maximum total bytes for all cached outputs combined.
    ///
    /// When inserting would exceed this limit, entries are evicted in LRU order
    /// until the new entry fits. This provides memory safety independent of
    /// entry count.
    ///
    /// Default: 100 MB (`DEFAULT_MAX_TOTAL_BYTES`)
    /// Minimum: 1 MB (`MIN_MAX_TOTAL_BYTES`)
    pub max_total_bytes: usize,

    /// Time-to-live for cache entries in seconds.
    pub ttl_secs: u64,

    /// Whether to track per-episode entries for bulk eviction.
    pub track_episodes: bool,
}

impl Default for DedupeCacheConfig {
    fn default() -> Self {
        Self {
            max_entries: MAX_DEDUPE_ENTRIES,
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
            ttl_secs: DEFAULT_TTL_SECS,
            track_episodes: true,
        }
    }
}

impl DedupeCacheConfig {
    /// Creates a config with custom max entries.
    #[must_use]
    pub const fn with_max_entries(mut self, max: usize) -> Self {
        self.max_entries = max;
        self
    }

    /// Creates a config with custom max total bytes.
    ///
    /// Values below `MIN_MAX_TOTAL_BYTES` (1 MB) are clamped to the minimum.
    #[must_use]
    pub const fn with_max_total_bytes(mut self, max_bytes: usize) -> Self {
        self.max_total_bytes = if max_bytes < MIN_MAX_TOTAL_BYTES {
            MIN_MAX_TOTAL_BYTES
        } else {
            max_bytes
        };
        self
    }

    /// Creates a config with custom TTL.
    #[must_use]
    pub const fn with_ttl_secs(mut self, ttl: u64) -> Self {
        self.ttl_secs = if ttl > MAX_TTL_SECS {
            MAX_TTL_SECS
        } else {
            ttl
        };
        self
    }

    /// Disables episode tracking.
    #[must_use]
    pub const fn without_episode_tracking(mut self) -> Self {
        self.track_episodes = false;
        self
    }
}

// =============================================================================
// CacheEntry
// =============================================================================

/// Entry in the dedupe cache.
///
/// Per RSK-1304, entries store timestamps (not just keys) for TTL-based
/// eviction to prevent ghost key attacks.
#[derive(Debug, Clone)]
struct CacheEntry {
    /// The cached tool result.
    result: ToolResult,

    /// Policy digest admitted for the request that populated this entry.
    policy_hash: Hash,

    /// Timestamp when this entry was inserted (nanoseconds since epoch).
    ///
    /// Per RSK-1304: TTL queues must store timestamps to detect stale entries.
    inserted_at_ns: u64,

    /// Episode this entry belongs to.
    episode_id: EpisodeId,

    /// Number of times this entry has been accessed.
    access_count: u64,

    /// Size of the cached output in bytes.
    ///
    /// Used for memory-based eviction to prevent resource exhaustion.
    output_size: usize,
}

impl CacheEntry {
    /// Checks if this entry has expired based on the given current time.
    fn is_expired(&self, current_ns: u64, ttl_ns: u64) -> bool {
        // Use checked arithmetic per RSK-2504
        current_ns
            .checked_sub(self.inserted_at_ns)
            .is_some_and(|age| age > ttl_ns)
    }
}

/// Entry in the LRU queue.
///
/// Per RSK-1304, we store both the key and the insertion timestamp to
/// detect ghost keys (keys that were removed but still exist in the queue).
#[derive(Debug, Clone)]
struct LruEntry {
    /// The dedupe key.
    key: DedupeKey,

    /// Timestamp when this entry was inserted (nanoseconds since epoch).
    ///
    /// This allows detecting ghost keys: if the entry in the main map
    /// has a different timestamp, this queue entry is stale.
    inserted_at_ns: u64,
}

// =============================================================================
// DedupeCache
// =============================================================================

/// Cache for idempotent tool replay.
///
/// The cache maps dedupe keys to tool results, enabling repeated requests
/// to return cached results instead of re-executing. This provides
/// idempotency for tool operations within an episode.
///
/// # Thread Safety
///
/// `DedupeCache` is `Send + Sync` via internal `RwLock` protection.
/// All operations are async and may block waiting for the lock.
///
/// # Eviction Strategies
///
/// 1. **LRU**: Least-recently-inserted entries are evicted when at capacity
/// 2. **TTL**: Entries expire after the configured TTL
/// 3. **Episode**: All entries for an episode can be evicted at once
///
/// # Example
///
/// ```rust,ignore
/// use apm2_daemon::episode::dedupe::{DedupeCache, DedupeCacheConfig};
///
/// let cache = DedupeCache::new(DedupeCacheConfig::default());
///
/// // Insert a result
/// cache.insert(episode_id, key.clone(), result.clone(), timestamp_ns).await;
///
/// // Lookup returns the cached result
/// let cached = cache.get(&key, timestamp_ns).await;
/// assert!(cached.is_some());
/// ```
pub struct DedupeCache {
    /// Configuration.
    config: DedupeCacheConfig,

    /// Cache entries indexed by dedupe key.
    entries: RwLock<HashMap<DedupeKey, CacheEntry>>,

    /// LRU order for eviction.
    ///
    /// Per RSK-1304, entries include timestamps to detect ghost keys.
    ///
    /// **Memory consideration (F08):** This queue may contain ghost keys after
    /// entries are evicted via TTL or episode eviction. Ghost keys are detected
    /// and cleaned up during LRU eviction using timestamp comparison. The queue
    /// length is bounded by `O(MAX_DEDUPE_ENTRIES * K)` where `K` is typically
    /// 1-2. See module documentation for detailed analysis.
    lru_order: RwLock<VecDeque<LruEntry>>,

    /// Index of dedupe keys by episode ID for bulk eviction.
    by_episode: RwLock<HashMap<String, HashSet<DedupeKey>>>,

    /// Total bytes currently cached.
    ///
    /// This tracks the aggregate size of all cached outputs for memory-based
    /// eviction. When inserting would exceed `config.max_total_bytes`, entries
    /// are evicted in LRU order until the new entry fits.
    total_bytes: RwLock<usize>,
}

impl DedupeCache {
    /// Creates a new dedupe cache with the given configuration.
    #[must_use]
    pub fn new(config: DedupeCacheConfig) -> Self {
        Self {
            config,
            entries: RwLock::new(HashMap::new()),
            lru_order: RwLock::new(VecDeque::new()),
            by_episode: RwLock::new(HashMap::new()),
            total_bytes: RwLock::new(0),
        }
    }

    /// Creates a new dedupe cache with default configuration.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(DedupeCacheConfig::default())
    }

    /// Returns the current number of entries.
    pub async fn len(&self) -> usize {
        self.entries.read().await.len()
    }

    /// Returns `true` if the cache is empty.
    pub async fn is_empty(&self) -> bool {
        self.entries.read().await.is_empty()
    }

    /// Returns the current total bytes cached.
    pub async fn total_bytes(&self) -> usize {
        *self.total_bytes.read().await
    }

    /// Looks up a cached result by dedupe key for a specific episode.
    ///
    /// Returns `None` if:
    /// - The key is not in the cache
    /// - The entry has expired based on TTL
    /// - The entry belongs to a different episode (cross-episode isolation)
    ///
    /// # Arguments
    ///
    /// * `episode_id` - The episode making the request (for isolation)
    /// * `key` - The dedupe key to lookup
    /// * `current_ns` - Current timestamp in nanoseconds (for TTL check)
    ///
    /// # Security
    ///
    /// Per AD-TOOL-002, cache entries are isolated by episode. An entry is
    /// only returned if its stored `episode_id` matches the requesting
    /// episode's ID. This prevents cross-episode information leakage.
    pub async fn get(
        &self,
        episode_id: &EpisodeId,
        key: &DedupeKey,
        current_ns: u64,
    ) -> Option<ToolResult> {
        self.get_with_policy(episode_id, key, current_ns)
            .await
            .map(|(result, _)| result)
    }

    /// Looks up a cached result and its admitted policy digest.
    ///
    /// Returns `None` under the same conditions as [`Self::get`].
    pub async fn get_with_policy(
        &self,
        episode_id: &EpisodeId,
        key: &DedupeKey,
        current_ns: u64,
    ) -> Option<(ToolResult, Hash)> {
        let ttl_ns = self.config.ttl_secs * 1_000_000_000;

        let mut entries = self.entries.write().await;
        let entry = entries.get_mut(key)?;

        // SECURITY: Verify episode_id matches to prevent cross-episode information
        // leakage
        if entry.episode_id != *episode_id {
            trace!(
                key = %key,
                cached_episode = %entry.episode_id,
                requesting_episode = %episode_id,
                "cache miss: episode mismatch"
            );
            return None;
        }

        // Check TTL
        if entry.is_expired(current_ns, ttl_ns) {
            trace!(key = %key, "cache entry expired");
            // Don't remove here - let cleanup handle it
            return None;
        }

        // Increment access count
        entry.access_count += 1;

        trace!(key = %key, access_count = entry.access_count, "cache hit");
        Some((entry.result.clone(), entry.policy_hash))
    }

    /// Inserts a result into the cache.
    ///
    /// If the cache is at entry count or memory capacity, the oldest entries
    /// are evicted first (LRU eviction).
    ///
    /// # Arguments
    ///
    /// * `episode_id` - Episode this result belongs to
    /// * `key` - The dedupe key
    /// * `result` - The tool result to cache
    /// * `current_ns` - Current timestamp in nanoseconds
    pub async fn insert(
        &self,
        episode_id: EpisodeId,
        key: DedupeKey,
        result: ToolResult,
        current_ns: u64,
    ) {
        self.insert_with_policy(episode_id, key, result, [0u8; 32], current_ns)
            .await;
    }

    /// Inserts a result and admitted policy digest into the cache.
    pub async fn insert_with_policy(
        &self,
        episode_id: EpisodeId,
        key: DedupeKey,
        result: ToolResult,
        policy_hash: Hash,
        current_ns: u64,
    ) {
        let output_size = result.output.len();

        // Evict expired entries first
        self.evict_expired(current_ns).await;

        // Evict LRU if at entry count capacity
        while self.len().await >= self.config.max_entries {
            if !self.evict_lru().await {
                break;
            }
        }

        // Evict LRU if inserting would exceed memory limit
        while self.total_bytes().await.saturating_add(output_size) > self.config.max_total_bytes {
            if !self.evict_lru().await {
                // No more entries to evict but still over limit
                // This can happen if output_size alone exceeds max_total_bytes
                // In this case, we still insert (the single-entry case)
                break;
            }
        }

        let entry = CacheEntry {
            result,
            policy_hash,
            inserted_at_ns: current_ns,
            episode_id: episode_id.clone(),
            access_count: 0,
            output_size,
        };

        let lru_entry = LruEntry {
            key: key.clone(),
            inserted_at_ns: current_ns,
        };

        // Insert entry and update total bytes
        {
            let mut entries = self.entries.write().await;
            // If replacing an existing entry, subtract its size first
            if let Some(old_entry) = entries.get(&key) {
                let mut total = self.total_bytes.write().await;
                *total = total.saturating_sub(old_entry.output_size);
            }
            entries.insert(key.clone(), entry);

            let mut total = self.total_bytes.write().await;
            *total = total.saturating_add(output_size);
        }

        // Add to LRU order
        {
            let mut lru = self.lru_order.write().await;
            lru.push_back(lru_entry);
        }

        // Track by episode
        if self.config.track_episodes {
            let mut by_ep = self.by_episode.write().await;
            by_ep
                .entry(episode_id.as_str().to_string())
                .or_default()
                .insert(key.clone());
        }

        debug!(key = %key, output_size, "inserted into dedupe cache");
    }

    /// Evicts all entries for a specific episode.
    ///
    /// This is called when an episode terminates to clean up its cache entries.
    ///
    /// # Returns
    ///
    /// The number of entries evicted.
    pub async fn evict_by_episode(&self, episode_id: &EpisodeId) -> usize {
        if !self.config.track_episodes {
            return 0;
        }

        // Get keys for this episode
        let keys: Vec<DedupeKey> = {
            let mut by_ep = self.by_episode.write().await;
            by_ep
                .remove(episode_id.as_str())
                .map(|s| s.into_iter().collect())
                .unwrap_or_default()
        };

        if keys.is_empty() {
            return 0;
        }

        // Remove entries and track freed bytes
        let mut entries = self.entries.write().await;
        let mut total = self.total_bytes.write().await;
        let mut evicted = 0;
        let mut freed_bytes = 0usize;
        for key in keys {
            if let Some(entry) = entries.remove(&key) {
                freed_bytes = freed_bytes.saturating_add(entry.output_size);
                evicted += 1;
            }
        }
        *total = total.saturating_sub(freed_bytes);

        // Note: We don't remove from LRU order - ghost key detection handles it
        debug!(episode_id = %episode_id, evicted, freed_bytes, "evicted episode cache entries");
        evicted
    }

    /// Evicts expired entries based on TTL.
    ///
    /// # Returns
    ///
    /// The number of entries evicted.
    pub async fn evict_expired(&self, current_ns: u64) -> usize {
        let ttl_ns = self.config.ttl_secs * 1_000_000_000;

        let mut entries = self.entries.write().await;
        let mut total = self.total_bytes.write().await;
        let before = entries.len();
        let mut freed_bytes = 0usize;

        entries.retain(|key, entry| {
            let expired = entry.is_expired(current_ns, ttl_ns);
            if expired {
                freed_bytes = freed_bytes.saturating_add(entry.output_size);
                trace!(key = %key, "evicting expired entry");
            }
            !expired
        });

        *total = total.saturating_sub(freed_bytes);
        let evicted = before - entries.len();
        if evicted > 0 {
            debug!(evicted, freed_bytes, "evicted expired cache entries");
        }
        evicted
    }

    /// Evicts the least-recently-inserted entry.
    ///
    /// Per RSK-1304, this uses timestamp comparison to detect ghost keys.
    ///
    /// # Returns
    ///
    /// `true` if an entry was evicted, `false` if the queue was empty.
    async fn evict_lru(&self) -> bool {
        loop {
            // Pop from LRU queue
            let lru_entry = {
                let mut lru = self.lru_order.write().await;
                lru.pop_front()
            };

            let Some(lru_entry) = lru_entry else {
                return false;
            };

            // Check if this is a ghost key (RSK-1304)
            let mut entries = self.entries.write().await;
            if let Some(entry) = entries.get(&lru_entry.key) {
                // Verify timestamp matches - if not, this is a ghost key
                if entry.inserted_at_ns == lru_entry.inserted_at_ns {
                    // Valid entry - evict it
                    if let Some(evicted) = entries.remove(&lru_entry.key) {
                        // Update total bytes
                        {
                            let mut total = self.total_bytes.write().await;
                            *total = total.saturating_sub(evicted.output_size);
                        }
                        // Clean up episode index
                        if self.config.track_episodes {
                            let mut by_ep = self.by_episode.write().await;
                            if let Some(keys) = by_ep.get_mut(evicted.episode_id.as_str()) {
                                keys.remove(&lru_entry.key);
                            }
                        }
                        trace!(key = %lru_entry.key, output_size = evicted.output_size, "evicted LRU entry");
                        return true;
                    }
                }
                // Ghost key - timestamp mismatch, continue to next entry
                trace!(key = %lru_entry.key, "skipped ghost key in LRU");
            }
            // Key not found (already removed) - continue to next entry
        }
    }

    /// Clears all entries from the cache.
    pub async fn clear(&self) {
        let mut entries = self.entries.write().await;
        let mut lru = self.lru_order.write().await;
        let mut by_ep = self.by_episode.write().await;
        let mut total = self.total_bytes.write().await;

        entries.clear();
        lru.clear();
        by_ep.clear();
        *total = 0;

        debug!("cleared dedupe cache");
    }

    /// Returns cache statistics.
    pub async fn stats(&self) -> DedupeCacheStats {
        let entries = self.entries.read().await;
        let lru = self.lru_order.read().await;
        let by_ep = self.by_episode.read().await;
        let total = self.total_bytes.read().await;

        DedupeCacheStats {
            entry_count: entries.len(),
            lru_queue_len: lru.len(),
            episode_count: by_ep.len(),
            max_entries: self.config.max_entries,
            max_total_bytes: self.config.max_total_bytes,
            total_bytes: *total,
            ttl_secs: self.config.ttl_secs,
        }
    }
}

impl std::fmt::Debug for DedupeCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DedupeCache")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

// =============================================================================
// DedupeCacheStats
// =============================================================================

/// Statistics about the dedupe cache.
#[derive(Debug, Clone, Copy)]
pub struct DedupeCacheStats {
    /// Current number of entries.
    pub entry_count: usize,

    /// Length of the LRU queue (may include ghost entries).
    pub lru_queue_len: usize,

    /// Number of episodes with cached entries.
    pub episode_count: usize,

    /// Maximum entries allowed.
    pub max_entries: usize,

    /// Maximum total bytes allowed.
    pub max_total_bytes: usize,

    /// Current total bytes cached.
    pub total_bytes: usize,

    /// TTL in seconds.
    pub ttl_secs: u64,
}

// =============================================================================
// SharedDedupeCache
// =============================================================================

/// Shared reference to a dedupe cache.
pub type SharedDedupeCache = Arc<DedupeCache>;

/// Creates a new shared dedupe cache.
#[must_use]
pub fn new_shared_cache(config: DedupeCacheConfig) -> SharedDedupeCache {
    Arc::new(DedupeCache::new(config))
}

#[cfg(test)]
mod tests {
    use std::time::Duration as StdDuration;

    use super::*;
    use crate::episode::decision::BudgetDelta;

    fn test_episode_id() -> EpisodeId {
        EpisodeId::new("ep-test-001").unwrap()
    }

    fn test_dedupe_key(suffix: &str) -> DedupeKey {
        DedupeKey::new(format!("test-key-{suffix}"))
    }

    fn test_result(request_id: &str) -> ToolResult {
        ToolResult::success(
            request_id,
            b"test output".to_vec(),
            BudgetDelta::single_call(),
            StdDuration::from_millis(100),
            1_000_000_000,
        )
    }

    fn timestamp_ns(secs: u64) -> u64 {
        secs * 1_000_000_000
    }

    #[tokio::test]
    async fn test_cache_insert_and_get() {
        let cache = DedupeCache::with_defaults();
        let key = test_dedupe_key("1");
        let result = test_result("req-1");
        let episode = test_episode_id();

        cache
            .insert(
                episode.clone(),
                key.clone(),
                result.clone(),
                timestamp_ns(0),
            )
            .await;

        let cached = cache.get(&episode, &key, timestamp_ns(0)).await;
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().request_id, "req-1");
    }

    #[tokio::test]
    async fn test_cache_miss() {
        let cache = DedupeCache::with_defaults();
        let key = test_dedupe_key("nonexistent");
        let episode = test_episode_id();

        let cached = cache.get(&episode, &key, timestamp_ns(0)).await;
        assert!(cached.is_none());
    }

    #[tokio::test]
    async fn test_cache_ttl_expiration() {
        let config = DedupeCacheConfig::default().with_ttl_secs(10);
        let cache = DedupeCache::new(config);
        let key = test_dedupe_key("ttl");
        let result = test_result("req-ttl");
        let episode = test_episode_id();

        // Insert at time 0
        cache
            .insert(episode.clone(), key.clone(), result, timestamp_ns(0))
            .await;

        // Should be available at time 5
        let cached = cache.get(&episode, &key, timestamp_ns(5)).await;
        assert!(cached.is_some());

        // Should be expired at time 15 (TTL is 10 seconds)
        let cached = cache.get(&episode, &key, timestamp_ns(15)).await;
        assert!(cached.is_none());
    }

    #[tokio::test]
    async fn test_cache_lru_eviction() {
        let config = DedupeCacheConfig::default().with_max_entries(3);
        let cache = DedupeCache::new(config);
        let episode = test_episode_id();

        // Insert 3 entries
        for i in 0..3 {
            let key = test_dedupe_key(&format!("{i}"));
            let result = test_result(&format!("req-{i}"));
            cache
                .insert(episode.clone(), key, result, timestamp_ns(i))
                .await;
        }

        assert_eq!(cache.len().await, 3);

        // Insert 4th entry - should evict the oldest (key-0)
        let key = test_dedupe_key("3");
        let result = test_result("req-3");
        cache
            .insert(episode.clone(), key, result, timestamp_ns(3))
            .await;

        assert_eq!(cache.len().await, 3);

        // key-0 should be evicted
        let cached = cache
            .get(&episode, &test_dedupe_key("0"), timestamp_ns(3))
            .await;
        assert!(cached.is_none());

        // key-1 should still be there
        let cached = cache
            .get(&episode, &test_dedupe_key("1"), timestamp_ns(3))
            .await;
        assert!(cached.is_some());
    }

    #[tokio::test]
    async fn test_cache_evict_by_episode() {
        let cache = DedupeCache::with_defaults();
        let episode1 = EpisodeId::new("ep-1").unwrap();
        let episode2 = EpisodeId::new("ep-2").unwrap();

        // Insert entries for episode 1
        for i in 0..3 {
            let key = test_dedupe_key(&format!("ep1-{i}"));
            let result = test_result(&format!("req-ep1-{i}"));
            cache
                .insert(episode1.clone(), key, result, timestamp_ns(i))
                .await;
        }

        // Insert entries for episode 2
        for i in 0..2 {
            let key = test_dedupe_key(&format!("ep2-{i}"));
            let result = test_result(&format!("req-ep2-{i}"));
            cache
                .insert(episode2.clone(), key, result, timestamp_ns(i))
                .await;
        }

        assert_eq!(cache.len().await, 5);

        // Evict episode 1 entries
        let evicted = cache.evict_by_episode(&episode1).await;
        assert_eq!(evicted, 3);
        assert_eq!(cache.len().await, 2);

        // Episode 2 entries should still be there
        let cached = cache
            .get(&episode2, &test_dedupe_key("ep2-0"), timestamp_ns(0))
            .await;
        assert!(cached.is_some());
    }

    #[tokio::test]
    async fn test_cache_evict_expired() {
        let config = DedupeCacheConfig::default().with_ttl_secs(100);
        let cache = DedupeCache::new(config);

        // Insert entries all at the same time to avoid eviction during insertion
        // (insert calls evict_expired with current_ns which could evict old entries)
        let base_time = timestamp_ns(0);
        for i in 0..5 {
            let key = test_dedupe_key(&format!("{i}"));
            let result = test_result(&format!("req-{i}"));
            cache
                .insert(test_episode_id(), key, result, base_time)
                .await;
        }

        assert_eq!(cache.len().await, 5);

        // Evict expired at time 150s (TTL is 100s)
        // All entries at time 0 have age=150s which is > 100s (expired)
        let evicted = cache.evict_expired(timestamp_ns(150)).await;
        assert_eq!(evicted, 5);
        assert_eq!(cache.len().await, 0);
    }

    #[tokio::test]
    async fn test_cache_clear() {
        let cache = DedupeCache::with_defaults();

        for i in 0..5 {
            let key = test_dedupe_key(&format!("{i}"));
            let result = test_result(&format!("req-{i}"));
            cache
                .insert(test_episode_id(), key, result, timestamp_ns(0))
                .await;
        }

        assert_eq!(cache.len().await, 5);

        cache.clear().await;

        assert!(cache.is_empty().await);
    }

    #[tokio::test]
    async fn test_cache_stats() {
        let config = DedupeCacheConfig::default()
            .with_max_entries(1000)
            .with_max_total_bytes(50 * 1024 * 1024) // 50 MB
            .with_ttl_secs(3600);
        let cache = DedupeCache::new(config);

        let stats = cache.stats().await;
        assert_eq!(stats.entry_count, 0);
        assert_eq!(stats.max_entries, 1000);
        assert_eq!(stats.max_total_bytes, 50 * 1024 * 1024);
        assert_eq!(stats.total_bytes, 0);
        assert_eq!(stats.ttl_secs, 3600);
    }

    #[tokio::test]
    async fn test_cache_ghost_key_prevention() {
        // This test verifies RSK-1304: ghost key prevention
        let config = DedupeCacheConfig::default().with_max_entries(3);
        let cache = DedupeCache::new(config);
        let episode = test_episode_id();

        // Insert an entry
        let key = test_dedupe_key("ghost-test");
        let result1 = test_result("req-1");
        cache
            .insert(episode.clone(), key.clone(), result1, timestamp_ns(0))
            .await;

        // Remove it by inserting a new entry with the same key but different timestamp
        // This simulates re-insertion after manual removal
        let result2 = test_result("req-2");
        cache
            .insert(episode.clone(), key.clone(), result2, timestamp_ns(10))
            .await;

        // The LRU queue now has two entries for the same key with different timestamps
        // When we hit capacity and evict, the ghost key (timestamp 0) should be skipped

        // Fill to capacity
        for i in 0..2 {
            let k = test_dedupe_key(&format!("fill-{i}"));
            let r = test_result(&format!("fill-{i}"));
            cache
                .insert(episode.clone(), k, r, timestamp_ns(20 + i))
                .await;
        }

        assert_eq!(cache.len().await, 3);

        // The original key should still have the updated value
        let cached = cache.get(&episode, &key, timestamp_ns(25)).await;
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().request_id, "req-2");
    }

    #[tokio::test]
    async fn test_cache_access_count() {
        let cache = DedupeCache::with_defaults();
        let key = test_dedupe_key("access");
        let result = test_result("req-access");
        let episode = test_episode_id();

        cache
            .insert(episode.clone(), key.clone(), result, timestamp_ns(0))
            .await;

        // Access multiple times
        for _ in 0..5 {
            let _ = cache.get(&episode, &key, timestamp_ns(0)).await;
        }

        // Access count should be tracked (internal, verified via debug)
        let entries = cache.entries.read().await;
        let entry = entries.get(&key).unwrap();
        assert_eq!(entry.access_count, 5);
    }

    #[tokio::test]
    async fn test_shared_cache() {
        let cache = new_shared_cache(DedupeCacheConfig::default());

        let key = test_dedupe_key("shared");
        let result = test_result("req-shared");
        let episode = test_episode_id();

        cache
            .insert(episode.clone(), key.clone(), result, timestamp_ns(0))
            .await;

        // Can be cloned and used from multiple places
        let cloned_cache = Arc::clone(&cache);
        let result = cloned_cache.get(&episode, &key, timestamp_ns(0)).await;
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn test_config_max_ttl_clamped() {
        let config = DedupeCacheConfig::default().with_ttl_secs(MAX_TTL_SECS + 1000);
        assert_eq!(config.ttl_secs, MAX_TTL_SECS);
    }

    #[tokio::test]
    async fn test_config_min_max_total_bytes_clamped() {
        // Values below MIN_MAX_TOTAL_BYTES should be clamped
        let config = DedupeCacheConfig::default().with_max_total_bytes(100);
        assert_eq!(config.max_total_bytes, MIN_MAX_TOTAL_BYTES);

        // Values at or above MIN_MAX_TOTAL_BYTES should be accepted
        let config = DedupeCacheConfig::default().with_max_total_bytes(MIN_MAX_TOTAL_BYTES);
        assert_eq!(config.max_total_bytes, MIN_MAX_TOTAL_BYTES);

        let config = DedupeCacheConfig::default().with_max_total_bytes(10 * 1024 * 1024);
        assert_eq!(config.max_total_bytes, 10 * 1024 * 1024);
    }

    fn make_large_result(request_id: &str, output: Vec<u8>) -> ToolResult {
        ToolResult::success(
            request_id,
            output,
            BudgetDelta::single_call(),
            StdDuration::from_millis(100),
            1_000_000_000,
        )
    }

    #[tokio::test]
    async fn test_cache_memory_limit_eviction() {
        // Set a small memory limit (1KB) to test eviction
        let config = DedupeCacheConfig::default()
            .with_max_entries(100) // High entry limit
            .with_max_total_bytes(MIN_MAX_TOTAL_BYTES); // Use minimum (1 MB)
        let cache = DedupeCache::new(config);

        // Create results with ~100KB output each
        let large_output = vec![0u8; 100 * 1024];

        // Insert 5 entries (500KB total, well under 1MB limit)
        for i in 0..5 {
            let key = test_dedupe_key(&format!("mem-{i}"));
            let result = make_large_result(&format!("req-mem-{i}"), large_output.clone());
            cache
                .insert(test_episode_id(), key, result, timestamp_ns(i))
                .await;
        }

        assert_eq!(cache.len().await, 5);
        assert_eq!(cache.total_bytes().await, 5 * 100 * 1024);

        // Now insert entries until we exceed the 1MB limit
        // Each entry is 100KB, so after ~10 entries we'll hit 1MB
        for i in 5..15 {
            let key = test_dedupe_key(&format!("mem-{i}"));
            let result = make_large_result(&format!("req-mem-{i}"), large_output.clone());
            cache
                .insert(test_episode_id(), key, result, timestamp_ns(i))
                .await;
        }

        // Total bytes should be at or under the limit (1 MB = 1,048,576 bytes)
        let total_bytes = cache.total_bytes().await;
        assert!(
            total_bytes <= MIN_MAX_TOTAL_BYTES,
            "total_bytes ({total_bytes}) should be <= MIN_MAX_TOTAL_BYTES ({MIN_MAX_TOTAL_BYTES})"
        );

        // Early entries should have been evicted
        let cached = cache
            .get(
                &test_episode_id(),
                &test_dedupe_key("mem-0"),
                timestamp_ns(20),
            )
            .await;
        assert!(cached.is_none(), "oldest entry should have been evicted");
    }

    #[tokio::test]
    async fn test_cache_total_bytes_tracking() {
        let config = DedupeCacheConfig::default().with_max_total_bytes(10 * 1024 * 1024); // 10 MB
        let cache = DedupeCache::new(config);

        assert_eq!(cache.total_bytes().await, 0);

        // Insert entry with 1000 byte output
        let result = ToolResult::success(
            "req-1",
            vec![0u8; 1000],
            BudgetDelta::single_call(),
            StdDuration::from_millis(100),
            1_000_000_000,
        );
        cache
            .insert(
                test_episode_id(),
                test_dedupe_key("bytes-1"),
                result,
                timestamp_ns(0),
            )
            .await;

        assert_eq!(cache.total_bytes().await, 1000);

        // Insert another entry with 2000 byte output
        let result2 = ToolResult::success(
            "req-2",
            vec![0u8; 2000],
            BudgetDelta::single_call(),
            StdDuration::from_millis(100),
            1_000_000_000,
        );
        cache
            .insert(
                test_episode_id(),
                test_dedupe_key("bytes-2"),
                result2,
                timestamp_ns(1),
            )
            .await;

        assert_eq!(cache.total_bytes().await, 3000);

        // Clear should reset total bytes
        cache.clear().await;
        assert_eq!(cache.total_bytes().await, 0);
    }

    #[tokio::test]
    async fn test_cache_evict_by_episode_updates_total_bytes() {
        let cache = DedupeCache::with_defaults();
        let episode1 = EpisodeId::new("ep-bytes-1").unwrap();

        // Insert entries with known sizes
        for i in 0..3 {
            let result = ToolResult::success(
                format!("req-{i}"),
                vec![0u8; 1000], // 1KB each
                BudgetDelta::single_call(),
                StdDuration::from_millis(100),
                1_000_000_000,
            );
            cache
                .insert(
                    episode1.clone(),
                    test_dedupe_key(&format!("ep-bytes-{i}")),
                    result,
                    timestamp_ns(i),
                )
                .await;
        }

        assert_eq!(cache.total_bytes().await, 3000);

        // Evict episode should update total bytes
        let evicted = cache.evict_by_episode(&episode1).await;
        assert_eq!(evicted, 3);
        assert_eq!(cache.total_bytes().await, 0);
    }

    #[tokio::test]
    async fn test_cache_without_episode_tracking() {
        let config = DedupeCacheConfig::default().without_episode_tracking();
        let cache = DedupeCache::new(config);
        let episode = test_episode_id();

        let key = test_dedupe_key("no-track");
        let result = test_result("req-no-track");

        cache
            .insert(episode.clone(), key.clone(), result, timestamp_ns(0))
            .await;

        // Evict by episode should do nothing
        let evicted = cache.evict_by_episode(&episode).await;
        assert_eq!(evicted, 0);

        // Entry should still be there
        let cached = cache.get(&episode, &key, timestamp_ns(0)).await;
        assert!(cached.is_some());
    }

    // =========================================================================
    // Security Tests
    // =========================================================================

    #[tokio::test]
    async fn test_cross_episode_isolation() {
        // This test verifies that cache entries are isolated by episode.
        // An episode cannot read another episode's cached results.
        let cache = DedupeCache::with_defaults();
        let episode1 = EpisodeId::new("ep-security-1").unwrap();
        let episode2 = EpisodeId::new("ep-security-2").unwrap();

        // Insert a result for episode 1
        let key = test_dedupe_key("secret-data");
        let result = test_result("req-secret");
        cache
            .insert(episode1.clone(), key.clone(), result, timestamp_ns(0))
            .await;

        // Episode 1 can read its own data
        let cached = cache.get(&episode1, &key, timestamp_ns(0)).await;
        assert!(
            cached.is_some(),
            "episode 1 should be able to read its own cache entry"
        );

        // Episode 2 CANNOT read episode 1's data (cross-episode isolation)
        let cached = cache.get(&episode2, &key, timestamp_ns(0)).await;
        assert!(
            cached.is_none(),
            "episode 2 must NOT be able to read episode 1's cache entry"
        );
    }

    #[tokio::test]
    async fn test_same_key_different_episodes() {
        // This test verifies that the same dedupe key can exist independently
        // for different episodes without leaking data.
        let cache = DedupeCache::with_defaults();
        let episode1 = EpisodeId::new("ep-key-1").unwrap();
        let episode2 = EpisodeId::new("ep-key-2").unwrap();

        // Both episodes use the same dedupe key
        let key = test_dedupe_key("shared-key");

        // Insert result for episode 1
        let result1 = ToolResult::success(
            "req-ep1",
            b"episode 1 secret data".to_vec(),
            BudgetDelta::single_call(),
            StdDuration::from_millis(100),
            1_000_000_000,
        );
        cache
            .insert(episode1.clone(), key.clone(), result1, timestamp_ns(0))
            .await;

        // Insert result for episode 2 with the same key
        let result2 = ToolResult::success(
            "req-ep2",
            b"episode 2 secret data".to_vec(),
            BudgetDelta::single_call(),
            StdDuration::from_millis(100),
            2_000_000_000,
        );
        cache
            .insert(episode2.clone(), key.clone(), result2, timestamp_ns(1))
            .await;

        // Episode 1 should get episode 1's data (latest insert overwrote)
        // Note: Since we use the same key, the second insert replaces the first
        // But episode 1 should NOT get episode 2's data
        let cached1 = cache.get(&episode1, &key, timestamp_ns(2)).await;
        let cached2 = cache.get(&episode2, &key, timestamp_ns(2)).await;

        // The cache should only return the entry to the episode that owns it
        // Episode 2's insert overwrote the entry, so only episode 2 should see it
        assert!(
            cached1.is_none(),
            "episode 1 should not get cached entry after episode 2 overwrote it"
        );
        assert!(
            cached2.is_some(),
            "episode 2 should be able to read its own cache entry"
        );
        assert_eq!(
            cached2.unwrap().output,
            b"episode 2 secret data",
            "episode 2 should get its own data"
        );
    }
}
