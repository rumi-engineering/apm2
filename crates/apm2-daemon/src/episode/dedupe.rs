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
//! # Contract References
//!
//! - CTR-DAEMON-004: `ToolBroker` structure with dedupe cache
//! - CTR-1303: Bounded collections with MAX_* constants
//! - RSK-1304: Ghost key prevention in TTL queues

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use tokio::sync::RwLock;
use tracing::{debug, trace};

use super::decision::{DedupeKey, ToolResult};
use super::error::EpisodeId;

// =============================================================================
// Limits (CTR-1303)
// =============================================================================

/// Maximum number of entries in the dedupe cache.
pub const MAX_DEDUPE_ENTRIES: usize = 100_000;

/// Default TTL for cache entries (1 hour).
pub const DEFAULT_TTL_SECS: u64 = 3600;

/// Maximum TTL for cache entries (24 hours).
pub const MAX_TTL_SECS: u64 = 86400;

// =============================================================================
// DedupeCacheConfig
// =============================================================================

/// Configuration for the dedupe cache.
#[derive(Debug, Clone)]
pub struct DedupeCacheConfig {
    /// Maximum number of entries in the cache.
    pub max_entries: usize,

    /// Time-to-live for cache entries in seconds.
    pub ttl_secs: u64,

    /// Whether to track per-episode entries for bulk eviction.
    pub track_episodes: bool,
}

impl Default for DedupeCacheConfig {
    fn default() -> Self {
        Self {
            max_entries: MAX_DEDUPE_ENTRIES,
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

    /// Timestamp when this entry was inserted (nanoseconds since epoch).
    ///
    /// Per RSK-1304: TTL queues must store timestamps to detect stale entries.
    inserted_at_ns: u64,

    /// Episode this entry belongs to.
    episode_id: EpisodeId,

    /// Number of times this entry has been accessed.
    access_count: u64,
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
    lru_order: RwLock<VecDeque<LruEntry>>,

    /// Index of dedupe keys by episode ID for bulk eviction.
    by_episode: RwLock<HashMap<String, HashSet<DedupeKey>>>,
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

    /// Looks up a cached result by dedupe key.
    ///
    /// Returns `None` if:
    /// - The key is not in the cache
    /// - The entry has expired based on TTL
    ///
    /// # Arguments
    ///
    /// * `key` - The dedupe key to lookup
    /// * `current_ns` - Current timestamp in nanoseconds (for TTL check)
    pub async fn get(&self, key: &DedupeKey, current_ns: u64) -> Option<ToolResult> {
        let ttl_ns = self.config.ttl_secs * 1_000_000_000;

        let mut entries = self.entries.write().await;
        let entry = entries.get_mut(key)?;

        // Check TTL
        if entry.is_expired(current_ns, ttl_ns) {
            trace!(key = %key, "cache entry expired");
            // Don't remove here - let cleanup handle it
            return None;
        }

        // Increment access count
        entry.access_count += 1;

        trace!(key = %key, access_count = entry.access_count, "cache hit");
        Some(entry.result.clone())
    }

    /// Inserts a result into the cache.
    ///
    /// If the cache is at capacity, the oldest entry is evicted first.
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
        // Evict expired entries first
        self.evict_expired(current_ns).await;

        // Evict LRU if at capacity
        while self.len().await >= self.config.max_entries {
            if !self.evict_lru().await {
                break;
            }
        }

        let entry = CacheEntry {
            result,
            inserted_at_ns: current_ns,
            episode_id: episode_id.clone(),
            access_count: 0,
        };

        let lru_entry = LruEntry {
            key: key.clone(),
            inserted_at_ns: current_ns,
        };

        // Insert entry
        {
            let mut entries = self.entries.write().await;
            entries.insert(key.clone(), entry);
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

        debug!(key = %key, "inserted into dedupe cache");
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

        // Remove entries
        let mut entries = self.entries.write().await;
        let mut evicted = 0;
        for key in keys {
            if entries.remove(&key).is_some() {
                evicted += 1;
            }
        }

        // Note: We don't remove from LRU order - ghost key detection handles it
        debug!(episode_id = %episode_id, evicted, "evicted episode cache entries");
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
        let before = entries.len();

        entries.retain(|key, entry| {
            let expired = entry.is_expired(current_ns, ttl_ns);
            if expired {
                trace!(key = %key, "evicting expired entry");
            }
            !expired
        });

        let evicted = before - entries.len();
        if evicted > 0 {
            debug!(evicted, "evicted expired cache entries");
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
                        // Clean up episode index
                        if self.config.track_episodes {
                            let mut by_ep = self.by_episode.write().await;
                            if let Some(keys) = by_ep.get_mut(evicted.episode_id.as_str()) {
                                keys.remove(&lru_entry.key);
                            }
                        }
                        trace!(key = %lru_entry.key, "evicted LRU entry");
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

        entries.clear();
        lru.clear();
        by_ep.clear();

        debug!("cleared dedupe cache");
    }

    /// Returns cache statistics.
    pub async fn stats(&self) -> DedupeCacheStats {
        let entries = self.entries.read().await;
        let lru = self.lru_order.read().await;
        let by_ep = self.by_episode.read().await;

        DedupeCacheStats {
            entry_count: entries.len(),
            lru_queue_len: lru.len(),
            episode_count: by_ep.len(),
            max_entries: self.config.max_entries,
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

        cache
            .insert(
                test_episode_id(),
                key.clone(),
                result.clone(),
                timestamp_ns(0),
            )
            .await;

        let cached = cache.get(&key, timestamp_ns(0)).await;
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().request_id, "req-1");
    }

    #[tokio::test]
    async fn test_cache_miss() {
        let cache = DedupeCache::with_defaults();
        let key = test_dedupe_key("nonexistent");

        let cached = cache.get(&key, timestamp_ns(0)).await;
        assert!(cached.is_none());
    }

    #[tokio::test]
    async fn test_cache_ttl_expiration() {
        let config = DedupeCacheConfig::default().with_ttl_secs(10);
        let cache = DedupeCache::new(config);
        let key = test_dedupe_key("ttl");
        let result = test_result("req-ttl");

        // Insert at time 0
        cache
            .insert(test_episode_id(), key.clone(), result, timestamp_ns(0))
            .await;

        // Should be available at time 5
        let cached = cache.get(&key, timestamp_ns(5)).await;
        assert!(cached.is_some());

        // Should be expired at time 15 (TTL is 10 seconds)
        let cached = cache.get(&key, timestamp_ns(15)).await;
        assert!(cached.is_none());
    }

    #[tokio::test]
    async fn test_cache_lru_eviction() {
        let config = DedupeCacheConfig::default().with_max_entries(3);
        let cache = DedupeCache::new(config);

        // Insert 3 entries
        for i in 0..3 {
            let key = test_dedupe_key(&format!("{i}"));
            let result = test_result(&format!("req-{i}"));
            cache
                .insert(test_episode_id(), key, result, timestamp_ns(i))
                .await;
        }

        assert_eq!(cache.len().await, 3);

        // Insert 4th entry - should evict the oldest (key-0)
        let key = test_dedupe_key("3");
        let result = test_result("req-3");
        cache
            .insert(test_episode_id(), key, result, timestamp_ns(3))
            .await;

        assert_eq!(cache.len().await, 3);

        // key-0 should be evicted
        let cached = cache.get(&test_dedupe_key("0"), timestamp_ns(3)).await;
        assert!(cached.is_none());

        // key-1 should still be there
        let cached = cache.get(&test_dedupe_key("1"), timestamp_ns(3)).await;
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
        let cached = cache.get(&test_dedupe_key("ep2-0"), timestamp_ns(0)).await;
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
            .with_ttl_secs(3600);
        let cache = DedupeCache::new(config);

        let stats = cache.stats().await;
        assert_eq!(stats.entry_count, 0);
        assert_eq!(stats.max_entries, 1000);
        assert_eq!(stats.ttl_secs, 3600);
    }

    #[tokio::test]
    async fn test_cache_ghost_key_prevention() {
        // This test verifies RSK-1304: ghost key prevention
        let config = DedupeCacheConfig::default().with_max_entries(3);
        let cache = DedupeCache::new(config);

        // Insert an entry
        let key = test_dedupe_key("ghost-test");
        let result1 = test_result("req-1");
        cache
            .insert(test_episode_id(), key.clone(), result1, timestamp_ns(0))
            .await;

        // Remove it by inserting a new entry with the same key but different timestamp
        // This simulates re-insertion after manual removal
        let result2 = test_result("req-2");
        cache
            .insert(test_episode_id(), key.clone(), result2, timestamp_ns(10))
            .await;

        // The LRU queue now has two entries for the same key with different timestamps
        // When we hit capacity and evict, the ghost key (timestamp 0) should be skipped

        // Fill to capacity
        for i in 0..2 {
            let k = test_dedupe_key(&format!("fill-{i}"));
            let r = test_result(&format!("fill-{i}"));
            cache
                .insert(test_episode_id(), k, r, timestamp_ns(20 + i))
                .await;
        }

        assert_eq!(cache.len().await, 3);

        // The original key should still have the updated value
        let cached = cache.get(&key, timestamp_ns(25)).await;
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().request_id, "req-2");
    }

    #[tokio::test]
    async fn test_cache_access_count() {
        let cache = DedupeCache::with_defaults();
        let key = test_dedupe_key("access");
        let result = test_result("req-access");

        cache
            .insert(test_episode_id(), key.clone(), result, timestamp_ns(0))
            .await;

        // Access multiple times
        for _ in 0..5 {
            let _ = cache.get(&key, timestamp_ns(0)).await;
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

        cache
            .insert(test_episode_id(), key.clone(), result, timestamp_ns(0))
            .await;

        // Can be cloned and used from multiple places
        let cloned_cache = Arc::clone(&cache);
        let result = cloned_cache.get(&key, timestamp_ns(0)).await;
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn test_config_max_ttl_clamped() {
        let config = DedupeCacheConfig::default().with_ttl_secs(MAX_TTL_SECS + 1000);
        assert_eq!(config.ttl_secs, MAX_TTL_SECS);
    }

    #[tokio::test]
    async fn test_cache_without_episode_tracking() {
        let config = DedupeCacheConfig::default().without_episode_tracking();
        let cache = DedupeCache::new(config);

        let key = test_dedupe_key("no-track");
        let result = test_result("req-no-track");

        cache
            .insert(test_episode_id(), key.clone(), result, timestamp_ns(0))
            .await;

        // Evict by episode should do nothing
        let evicted = cache.evict_by_episode(&test_episode_id()).await;
        assert_eq!(evicted, 0);

        // Entry should still be there
        let cached = cache.get(&key, timestamp_ns(0)).await;
        assert!(cached.is_some());
    }
}
