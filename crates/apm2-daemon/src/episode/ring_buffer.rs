//! Fixed-size ring buffer for flight recorder.
//!
//! This module provides a generic `RingBuffer<T>` that maintains a fixed
//! capacity, evicting the oldest items when full. It is used for the
//! flight recorder to retain recent PTY output.
//!
//! # Invariants
//!
//! - [INV-RB001] Capacity is fixed at construction time
//! - [INV-RB002] `push()` evicts oldest item when at capacity
//! - [INV-RB003] Items are returned in insertion order (oldest first)
//! - [INV-RB004] `len()` <= `capacity()` is always true
//!
//! # Security Considerations
//!
//! This is SCP (Security-Critical Path) code. The ring buffer:
//! - Uses bounded memory to prevent resource exhaustion
//! - Provides deterministic behavior for evidence collection
//! - Does not use `Instant::now()` per HARD-TIME principle

use std::collections::VecDeque;

/// A fixed-size ring buffer that evicts oldest items on overflow.
///
/// # Type Parameters
///
/// * `T` - The type of items stored in the buffer
///
/// # Example
///
/// ```rust,ignore
/// use apm2_daemon::episode::ring_buffer::RingBuffer;
///
/// let mut buffer: RingBuffer<u32> = RingBuffer::new(3);
/// buffer.push(1);
/// buffer.push(2);
/// buffer.push(3);
/// buffer.push(4); // Evicts 1
///
/// let items: Vec<u32> = buffer.drain().collect();
/// assert_eq!(items, vec![2, 3, 4]);
/// ```
#[derive(Debug, Clone)]
pub struct RingBuffer<T> {
    /// Internal storage.
    buffer: VecDeque<T>,
    /// Maximum capacity.
    capacity: usize,
}

impl<T> RingBuffer<T> {
    /// Creates a new ring buffer with the specified capacity.
    ///
    /// # Arguments
    ///
    /// * `capacity` - Maximum number of items to retain
    ///
    /// # Panics
    ///
    /// Panics if `capacity` is 0 (fail-closed behavior).
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "RingBuffer capacity must be > 0");
        Self {
            buffer: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    /// Returns the maximum capacity of the buffer.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Returns the current number of items in the buffer.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Returns `true` if the buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Returns `true` if the buffer is at capacity.
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.buffer.len() >= self.capacity
    }

    /// Pushes an item to the buffer, evicting the oldest if at capacity.
    ///
    /// # Arguments
    ///
    /// * `item` - The item to push
    ///
    /// # Returns
    ///
    /// Returns `Some(evicted)` if an item was evicted, `None` otherwise.
    pub fn push(&mut self, item: T) -> Option<T> {
        let evicted = if self.is_full() {
            self.buffer.pop_front()
        } else {
            None
        };
        self.buffer.push_back(item);
        evicted
    }

    /// Drains all items from the buffer in insertion order (oldest first).
    ///
    /// This consumes all items, leaving the buffer empty.
    pub fn drain(&mut self) -> impl Iterator<Item = T> + '_ {
        self.buffer.drain(..)
    }

    /// Clears all items from the buffer.
    pub fn clear(&mut self) {
        self.buffer.clear();
    }

    /// Returns an iterator over references to items in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.buffer.iter()
    }

    /// Returns the oldest item without removing it.
    #[must_use]
    pub fn front(&self) -> Option<&T> {
        self.buffer.front()
    }

    /// Returns the newest item without removing it.
    #[must_use]
    pub fn back(&self) -> Option<&T> {
        self.buffer.back()
    }
}

impl<T> Default for RingBuffer<T> {
    /// Creates a ring buffer with a default capacity of 1024.
    fn default() -> Self {
        Self::new(1024)
    }
}

/// Default ring buffer capacities by risk tier.
///
/// **IMPORTANT**: `RingBuffer<T>` is item-count based, not byte-based.
/// These constants specify the maximum number of `PtyOutput` items to retain.
///
/// # Aggregate Memory Consideration
///
/// With a maximum of 10,000 concurrent episodes, aggregate memory usage must
/// be bounded. Using conservative capacity limits:
///
/// - Tier 1: 64 items * 4KB avg = ~256KB per episode
/// - Tier 2: 256 items * 4KB avg = ~1MB per episode
/// - Tier 3+: 1024 items * 4KB avg = ~4MB per episode
///
/// Worst case (all 10,000 episodes at Tier 3+): 10,000 * 4MB = 40GB
/// This is a reasonable upper bound for server deployments while still
/// providing adequate flight recorder retention for debugging purposes.
///
/// The capacity values are derived from the estimated average output chunk
/// size. Since PTY output typically arrives in chunks of 1-8KB
/// (`READ_BUFFER_SIZE` = 8KB max), we use 4KB as the average chunk size.
pub mod tier_defaults {
    /// Estimated average chunk size for capacity calculations (4 KB).
    ///
    /// This is a conservative estimate based on typical terminal output
    /// patterns. `READ_BUFFER_SIZE` is 8KB, so chunks can be up to 8KB, but
    /// most are smaller.
    pub const ESTIMATED_AVG_CHUNK_SIZE: usize = 4 * 1024;

    /// Tier 1 ring buffer capacity (item count, ~256KB equivalent).
    ///
    /// 64 items * 4KB avg = ~256KB of output data retained.
    pub const TIER_1_CAPACITY: usize = 64;

    /// Tier 2 ring buffer capacity (item count, ~1MB equivalent).
    ///
    /// 256 items * 4KB avg = ~1MB of output data retained.
    pub const TIER_2_CAPACITY: usize = 256;

    /// Tier 3+ ring buffer capacity (item count, ~4MB equivalent).
    ///
    /// 1024 items * 4KB avg = ~4MB of output data retained.
    pub const TIER_3_PLUS_CAPACITY: usize = 1024;

    /// Returns the default ring buffer capacity (item count) for the given risk
    /// tier.
    ///
    /// # Arguments
    ///
    /// * `tier` - Risk tier (0-4)
    ///
    /// # Returns
    ///
    /// Buffer capacity as item count. Tier 0 returns 1 (minimal capacity for
    /// read-only/experimental operations). This ensures `RingBuffer::new()`
    /// never receives 0, which would panic.
    ///
    /// # Example
    ///
    /// ```
    /// use apm2_daemon::episode::ring_buffer::tier_defaults::buffer_capacity_for_tier;
    ///
    /// assert_eq!(buffer_capacity_for_tier(0), 1);
    /// assert_eq!(buffer_capacity_for_tier(1), 64);
    /// assert_eq!(buffer_capacity_for_tier(2), 256);
    /// assert_eq!(buffer_capacity_for_tier(3), 1024);
    /// ```
    #[must_use]
    pub const fn buffer_capacity_for_tier(tier: u8) -> usize {
        match tier {
            0 => 1, // Minimal capacity for Tier 0 (read-only/experimental)
            1 => TIER_1_CAPACITY,
            2 => TIER_2_CAPACITY,
            _ => TIER_3_PLUS_CAPACITY, // Tier 3, 4, and any future tiers
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // UT-00161-02: Ring buffer overflow test
    // ========================================================================

    /// UT-00161-02: Test that ring buffer evicts oldest items on overflow.
    #[test]
    fn test_ring_buffer_overflow_eviction() {
        let mut buffer: RingBuffer<u32> = RingBuffer::new(3);

        // Fill the buffer
        assert!(buffer.push(1).is_none());
        assert!(buffer.push(2).is_none());
        assert!(buffer.push(3).is_none());
        assert_eq!(buffer.len(), 3);

        // Overflow - should evict 1
        let evicted = buffer.push(4);
        assert_eq!(evicted, Some(1));
        assert_eq!(buffer.len(), 3);

        // Overflow again - should evict 2
        let evicted = buffer.push(5);
        assert_eq!(evicted, Some(2));
        assert_eq!(buffer.len(), 3);

        // Verify order (oldest first)
        let items: Vec<u32> = buffer.drain().collect();
        assert_eq!(items, vec![3, 4, 5]);
    }

    #[test]
    fn test_ring_buffer_new() {
        let buffer: RingBuffer<u32> = RingBuffer::new(10);
        assert_eq!(buffer.capacity(), 10);
        assert_eq!(buffer.len(), 0);
        assert!(buffer.is_empty());
        assert!(!buffer.is_full());
    }

    #[test]
    #[should_panic(expected = "capacity must be > 0")]
    fn test_ring_buffer_zero_capacity_panics() {
        let _buffer: RingBuffer<u32> = RingBuffer::new(0);
    }

    #[test]
    fn test_ring_buffer_push_no_overflow() {
        let mut buffer: RingBuffer<u32> = RingBuffer::new(5);

        assert!(buffer.push(1).is_none());
        assert!(buffer.push(2).is_none());
        assert!(buffer.push(3).is_none());

        assert_eq!(buffer.len(), 3);
        assert!(!buffer.is_full());
    }

    #[test]
    fn test_ring_buffer_is_full() {
        let mut buffer: RingBuffer<u32> = RingBuffer::new(2);

        assert!(!buffer.is_full());
        buffer.push(1);
        assert!(!buffer.is_full());
        buffer.push(2);
        assert!(buffer.is_full());
    }

    #[test]
    fn test_ring_buffer_drain() {
        let mut buffer: RingBuffer<String> = RingBuffer::new(3);
        buffer.push("a".to_string());
        buffer.push("b".to_string());
        buffer.push("c".to_string());

        let items: Vec<String> = buffer.drain().collect();
        assert_eq!(items, vec!["a", "b", "c"]);
        assert!(buffer.is_empty());
    }

    #[test]
    fn test_ring_buffer_clear() {
        let mut buffer: RingBuffer<u32> = RingBuffer::new(5);
        buffer.push(1);
        buffer.push(2);
        buffer.push(3);

        assert_eq!(buffer.len(), 3);
        buffer.clear();
        assert!(buffer.is_empty());
        assert_eq!(buffer.capacity(), 5); // Capacity unchanged
    }

    #[test]
    fn test_ring_buffer_iter() {
        let mut buffer: RingBuffer<u32> = RingBuffer::new(3);
        buffer.push(1);
        buffer.push(2);
        buffer.push(3);

        let items: Vec<&u32> = buffer.iter().collect();
        assert_eq!(items, vec![&1, &2, &3]);

        // Buffer still contains items
        assert_eq!(buffer.len(), 3);
    }

    #[test]
    fn test_ring_buffer_front_back() {
        let mut buffer: RingBuffer<u32> = RingBuffer::new(3);

        assert!(buffer.front().is_none());
        assert!(buffer.back().is_none());

        buffer.push(1);
        assert_eq!(buffer.front(), Some(&1));
        assert_eq!(buffer.back(), Some(&1));

        buffer.push(2);
        assert_eq!(buffer.front(), Some(&1));
        assert_eq!(buffer.back(), Some(&2));

        buffer.push(3);
        assert_eq!(buffer.front(), Some(&1));
        assert_eq!(buffer.back(), Some(&3));

        buffer.push(4); // Evicts 1
        assert_eq!(buffer.front(), Some(&2));
        assert_eq!(buffer.back(), Some(&4));
    }

    #[test]
    fn test_ring_buffer_default() {
        let buffer: RingBuffer<u32> = RingBuffer::default();
        assert_eq!(buffer.capacity(), 1024);
        assert!(buffer.is_empty());
    }

    #[test]
    fn test_ring_buffer_clone() {
        let mut buffer: RingBuffer<u32> = RingBuffer::new(3);
        buffer.push(1);
        buffer.push(2);

        let cloned = buffer.clone();
        assert_eq!(cloned.len(), 2);
        assert_eq!(cloned.capacity(), 3);
    }

    #[test]
    fn test_ring_buffer_single_capacity() {
        let mut buffer: RingBuffer<u32> = RingBuffer::new(1);

        assert!(buffer.push(1).is_none());
        assert!(buffer.is_full());

        let evicted = buffer.push(2);
        assert_eq!(evicted, Some(1));
        assert_eq!(buffer.front(), Some(&2));
    }

    #[test]
    fn test_ring_buffer_large_overflow() {
        let mut buffer: RingBuffer<u32> = RingBuffer::new(3);

        // Push many items
        for i in 0..100 {
            buffer.push(i);
        }

        // Should contain only last 3 items
        assert_eq!(buffer.len(), 3);
        let items: Vec<u32> = buffer.drain().collect();
        assert_eq!(items, vec![97, 98, 99]);
    }

    // ========================================================================
    // Tier defaults tests
    // ========================================================================

    #[test]
    fn test_tier_defaults_capacities() {
        use tier_defaults::*;

        // Verify the capacity constants are reasonable item counts (not huge byte
        // values). These are conservative to bound aggregate memory usage:
        // 10,000 episodes * 4MB max = 40GB worst case.
        assert_eq!(TIER_1_CAPACITY, 64);
        assert_eq!(TIER_2_CAPACITY, 256);
        assert_eq!(TIER_3_PLUS_CAPACITY, 1024);

        // Verify estimated chunk size is reasonable
        assert_eq!(ESTIMATED_AVG_CHUNK_SIZE, 4 * 1024);
    }

    #[test]
    fn test_buffer_capacity_for_tier() {
        use tier_defaults::*;

        // Tier 0 returns 1 (minimal capacity) to avoid RingBuffer::new(0) panic
        assert_eq!(buffer_capacity_for_tier(0), 1);
        assert_eq!(buffer_capacity_for_tier(1), TIER_1_CAPACITY);
        assert_eq!(buffer_capacity_for_tier(2), TIER_2_CAPACITY);
        assert_eq!(buffer_capacity_for_tier(3), TIER_3_PLUS_CAPACITY);
        assert_eq!(buffer_capacity_for_tier(4), TIER_3_PLUS_CAPACITY);
        assert_eq!(buffer_capacity_for_tier(255), TIER_3_PLUS_CAPACITY); // Future tiers
    }

    /// Test that Tier 0 capacity creates a valid `RingBuffer`.
    ///
    /// This ensures that spawning a Tier 0 episode will not panic due to
    /// `RingBuffer::new(0)`.
    #[test]
    fn test_tier_0_capacity_creates_valid_ring_buffer() {
        use tier_defaults::*;

        let capacity = buffer_capacity_for_tier(0);
        // This must not panic
        let mut rb: RingBuffer<u32> = RingBuffer::new(capacity);
        assert_eq!(rb.capacity(), 1);

        // Verify it works as expected - single item capacity
        assert!(rb.push(1).is_none());
        assert!(rb.is_full());
        assert_eq!(rb.push(2), Some(1)); // Evicts 1
        assert_eq!(rb.front(), Some(&2));
    }

    /// Verify that tier capacities are reasonable for creating `RingBuffer`s.
    /// This ensures we don't accidentally pass byte values to the item-count
    /// `RingBuffer`.
    #[test]
    fn test_tier_capacities_are_usable() {
        use tier_defaults::*;

        // Tier 0 is special - no buffer
        // Tiers 1-3+ should all create valid ring buffers with reasonable capacities
        let rb1: RingBuffer<u32> = RingBuffer::new(TIER_1_CAPACITY);
        let rb2: RingBuffer<u32> = RingBuffer::new(TIER_2_CAPACITY);
        let rb3: RingBuffer<u32> = RingBuffer::new(TIER_3_PLUS_CAPACITY);

        // Verify capacities are what we expect (conservative for aggregate memory)
        assert_eq!(rb1.capacity(), 64);
        assert_eq!(rb2.capacity(), 256);
        assert_eq!(rb3.capacity(), 1024);
    }
}
