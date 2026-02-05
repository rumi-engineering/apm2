//! `TestDaemon` helper for E2E episode tests.
//!
//! This module provides the `TestDaemon` struct that creates an isolated
//! test environment with an `EpisodeRuntime` instance for E2E testing.
//!
//! # Architecture
//!
//! Unlike full daemon integration tests that spawn processes over UDS,
//! these E2E tests focus on the episode lifecycle and budget enforcement
//! by directly interacting with `EpisodeRuntime`. This approach:
//!
//! 1. Avoids unnecessary process spawning overhead
//! 2. Enables deterministic timing tests (HARD-TIME)
//! 3. Focuses on the episode lifecycle state machine
//!
//! # Contract References
//!
//! - TCK-00175: E2E lifecycle and budget tests
//! - AD-EPISODE-002: Episode state machine
//! - AD-LAYER-001: `EpisodeRuntime` as plant controller

use std::sync::Arc;

use apm2_daemon::episode::{
    BudgetDelta, BudgetSnapshot, BudgetTracker, EpisodeBudget, EpisodeEvent, EpisodeId,
    EpisodeRuntime, EpisodeRuntimeConfig, EpisodeState, QuarantineReason, SessionHandle,
    StopSignal, TerminationClass,
};
use tempfile::TempDir;

/// Test timestamp base: 2024-01-01 00:00:00 UTC in nanoseconds.
pub const TEST_TIMESTAMP_NS: u64 = 1_704_067_200_000_000_000;

/// One second in nanoseconds.
pub const ONE_SEC_NS: u64 = 1_000_000_000;

/// One millisecond in nanoseconds.
pub const ONE_MS_NS: u64 = 1_000_000;

/// Test helper for E2E episode lifecycle tests.
///
/// `TestDaemon` provides an isolated test environment with an `EpisodeRuntime`
/// instance. It manages a temporary directory for any file operations and
/// provides convenient methods for common test operations.
///
/// # Example
///
/// ```rust,ignore
/// use crate::common::TestDaemon;
///
/// #[tokio::test]
/// async fn test_episode_lifecycle() {
///     let daemon = TestDaemon::start();
///
///     // Create an episode
///     let episode_id = daemon.create_episode().await.unwrap();
///
///     // Start the episode
///     let handle = daemon.start_episode(&episode_id).await.unwrap();
///
///     // Stop the episode
///     daemon.stop_episode(&episode_id, TerminationClass::Success).await.unwrap();
/// }
/// ```
#[derive(Debug)]
pub struct TestDaemon {
    /// The episode runtime instance.
    runtime: Arc<EpisodeRuntime>,
    /// Temporary directory for test isolation.
    #[allow(dead_code)]
    temp_dir: TempDir,
    /// Monotonic timestamp counter for deterministic timing.
    current_timestamp_ns: std::sync::atomic::AtomicU64,
    /// Episode sequence number for unique test envelopes.
    episode_seq: std::sync::atomic::AtomicU64,
}

#[allow(dead_code)]
impl TestDaemon {
    /// Creates a new test daemon with default configuration.
    ///
    /// This creates an isolated test environment with:
    /// - An `EpisodeRuntime` with default configuration
    /// - A temporary directory for file operations
    /// - Deterministic timestamp generation
    #[must_use]
    pub fn start() -> Self {
        Self::with_config(EpisodeRuntimeConfig::default())
    }

    /// Creates a new test daemon with custom configuration.
    #[must_use]
    pub fn with_config(config: EpisodeRuntimeConfig) -> Self {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let runtime = Arc::new(EpisodeRuntime::new(config));

        Self {
            runtime,
            temp_dir,
            current_timestamp_ns: std::sync::atomic::AtomicU64::new(TEST_TIMESTAMP_NS),
            episode_seq: std::sync::atomic::AtomicU64::new(1),
        }
    }

    /// Creates a test daemon with a limited number of concurrent episodes.
    ///
    /// Useful for testing limit enforcement.
    #[must_use]
    pub fn with_max_episodes(max: usize) -> Self {
        let config = EpisodeRuntimeConfig::default()
            .with_max_concurrent_episodes(max)
            .with_emit_events(true);
        Self::with_config(config)
    }

    /// Returns the current test timestamp in nanoseconds.
    #[must_use]
    pub fn current_timestamp_ns(&self) -> u64 {
        self.current_timestamp_ns
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Advances the test timestamp by the given duration in nanoseconds.
    ///
    /// Returns the new timestamp.
    pub fn advance_time_ns(&self, delta_ns: u64) -> u64 {
        self.current_timestamp_ns
            .fetch_add(delta_ns, std::sync::atomic::Ordering::Relaxed)
            + delta_ns
    }

    /// Advances the test timestamp by the given duration in milliseconds.
    ///
    /// Returns the new timestamp.
    pub fn advance_time_ms(&self, delta_ms: u64) -> u64 {
        self.advance_time_ns(delta_ms * ONE_MS_NS)
    }

    /// Advances the test timestamp by one second.
    ///
    /// Returns the new timestamp.
    pub fn advance_one_second(&self) -> u64 {
        self.advance_time_ns(ONE_SEC_NS)
    }

    /// Generates a unique test envelope hash.
    ///
    /// The hash incorporates a sequence number to ensure uniqueness.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn test_envelope_hash(&self) -> [u8; 32] {
        let seq = self
            .episode_seq
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut hash = [0u8; 32];
        hash[0..8].copy_from_slice(&seq.to_le_bytes());
        // Fill remaining bytes with a pattern for easier debugging
        // Truncation is safe: i ranges from 8..32, fitting in u8
        for (i, byte) in hash.iter_mut().enumerate().skip(8) {
            *byte = (i as u8).wrapping_mul(17);
        }
        hash
    }

    /// Creates a new episode with a unique envelope hash.
    ///
    /// Returns the episode ID on success.
    ///
    /// # Errors
    ///
    /// Returns an error if the runtime rejects the creation (e.g., limit
    /// reached).
    pub async fn create_episode(&self) -> Result<EpisodeId, apm2_daemon::episode::EpisodeError> {
        let envelope_hash = self.test_envelope_hash();
        let timestamp = self.current_timestamp_ns();
        self.runtime.create(envelope_hash, timestamp).await
    }

    /// Starts an episode with a generated lease ID.
    ///
    /// Advances the timestamp by 1ms before starting.
    ///
    /// Returns the session handle on success.
    ///
    /// # TCK-00336: Deprecated Method Usage
    ///
    /// This test helper uses the deprecated `start` method intentionally.
    /// Production code should use `start_with_workspace` for proper isolation.
    #[allow(deprecated)]
    pub async fn start_episode(
        &self,
        episode_id: &EpisodeId,
    ) -> Result<SessionHandle, apm2_daemon::episode::EpisodeError> {
        let timestamp = self.advance_time_ms(1);
        let lease_id = format!("lease-{}", self.current_timestamp_ns());
        self.runtime.start(episode_id, lease_id, timestamp).await
    }

    /// Starts an episode with a specific lease ID.
    ///
    /// Advances the timestamp by 1ms before starting.
    ///
    /// # TCK-00336: Deprecated Method Usage
    ///
    /// This test helper uses the deprecated `start` method intentionally.
    /// Production code should use `start_with_workspace` for proper isolation.
    #[allow(deprecated)]
    pub async fn start_episode_with_lease(
        &self,
        episode_id: &EpisodeId,
        lease_id: impl Into<String>,
    ) -> Result<SessionHandle, apm2_daemon::episode::EpisodeError> {
        let timestamp = self.advance_time_ms(1);
        self.runtime.start(episode_id, lease_id, timestamp).await
    }

    /// Stops an episode with the specified termination class.
    ///
    /// Advances the timestamp by 1ms before stopping.
    pub async fn stop_episode(
        &self,
        episode_id: &EpisodeId,
        termination_class: TerminationClass,
    ) -> Result<(), apm2_daemon::episode::EpisodeError> {
        let timestamp = self.advance_time_ms(1);
        self.runtime
            .stop(episode_id, termination_class, timestamp)
            .await
    }

    /// Quarantines an episode with the specified reason.
    ///
    /// Advances the timestamp by 1ms before quarantining.
    pub async fn quarantine_episode(
        &self,
        episode_id: &EpisodeId,
        reason: QuarantineReason,
    ) -> Result<(), apm2_daemon::episode::EpisodeError> {
        let timestamp = self.advance_time_ms(1);
        self.runtime.quarantine(episode_id, reason, timestamp).await
    }

    /// Signals a running episode.
    pub async fn signal_episode(
        &self,
        episode_id: &EpisodeId,
        signal: StopSignal,
    ) -> Result<(), apm2_daemon::episode::EpisodeError> {
        self.runtime.signal(episode_id, signal).await
    }

    /// Observes the current state of an episode.
    pub async fn observe_episode(
        &self,
        episode_id: &EpisodeId,
    ) -> Result<EpisodeState, apm2_daemon::episode::EpisodeError> {
        self.runtime.observe(episode_id).await
    }

    /// Drains all emitted events from the runtime.
    pub async fn drain_events(&self) -> Vec<EpisodeEvent> {
        self.runtime.drain_events().await
    }

    /// Returns the count of active (non-terminal) episodes.
    pub async fn active_count(&self) -> usize {
        self.runtime.active_count().await
    }

    /// Returns the total count of tracked episodes.
    pub async fn total_count(&self) -> usize {
        self.runtime.total_count().await
    }

    /// Cleans up terminal episodes from tracking.
    pub async fn cleanup_terminal(&self) -> usize {
        self.runtime.cleanup_terminal().await
    }

    /// Creates a budget tracker with the specified limits.
    #[must_use]
    pub fn create_budget_tracker(budget: EpisodeBudget) -> BudgetTracker {
        BudgetTracker::from_envelope(budget)
    }

    /// Creates a budget tracker with default test limits.
    ///
    /// Default limits:
    /// - `tokens`: 10,000
    /// - `tool_calls`: 100
    /// - `wall_ms`: 60,000 (1 minute)
    /// - `cpu_ms`: 30,000 (30 seconds)
    /// - `bytes_io`: 1,000,000 (1 MB)
    /// - `evidence_bytes`: 100,000 (100 KB)
    #[must_use]
    pub fn create_test_budget_tracker() -> BudgetTracker {
        let budget = EpisodeBudget::builder()
            .tokens(10_000)
            .tool_calls(100)
            .wall_ms(60_000)
            .cpu_ms(30_000)
            .bytes_io(1_000_000)
            .evidence_bytes(100_000)
            .build();
        BudgetTracker::from_envelope(budget)
    }

    /// Charges a budget delta to the tracker and returns the result.
    ///
    /// This is a convenience method for budget exhaustion tests.
    pub fn charge_budget(
        tracker: &BudgetTracker,
        delta: &BudgetDelta,
    ) -> Result<(), apm2_daemon::episode::BudgetExhaustedError> {
        tracker.charge(delta)
    }

    /// Returns a snapshot of consumed resources from the tracker.
    #[must_use]
    pub fn consumed_budget(tracker: &BudgetTracker) -> BudgetSnapshot {
        tracker.consumed()
    }

    /// Returns the remaining budget from the tracker.
    #[must_use]
    pub fn remaining_budget(tracker: &BudgetTracker) -> EpisodeBudget {
        tracker.remaining()
    }

    /// Checks if the tracker's budget is exhausted.
    #[must_use]
    pub fn is_budget_exhausted(tracker: &BudgetTracker) -> bool {
        tracker.is_exhausted()
    }
}

impl Default for TestDaemon {
    fn default() -> Self {
        Self::start()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_daemon_creation() {
        let daemon = TestDaemon::start();
        assert_eq!(daemon.active_count().await, 0);
        assert_eq!(daemon.total_count().await, 0);
    }

    #[tokio::test]
    async fn test_daemon_timestamp_advancement() {
        let daemon = TestDaemon::start();
        let initial = daemon.current_timestamp_ns();

        daemon.advance_one_second();
        assert_eq!(daemon.current_timestamp_ns(), initial + ONE_SEC_NS);

        daemon.advance_time_ms(500);
        assert_eq!(
            daemon.current_timestamp_ns(),
            initial + ONE_SEC_NS + 500 * ONE_MS_NS
        );
    }

    #[tokio::test]
    async fn test_daemon_unique_envelope_hashes() {
        let daemon = TestDaemon::start();

        let hash1 = daemon.test_envelope_hash();
        let hash2 = daemon.test_envelope_hash();
        let hash3 = daemon.test_envelope_hash();

        // All hashes should be unique
        assert_ne!(hash1, hash2);
        assert_ne!(hash2, hash3);
        assert_ne!(hash1, hash3);
    }

    #[tokio::test]
    async fn test_daemon_episode_lifecycle() {
        let daemon = TestDaemon::start();

        // Create
        let episode_id = daemon.create_episode().await.unwrap();
        assert_eq!(daemon.active_count().await, 1);

        // Start
        let handle = daemon.start_episode(&episode_id).await.unwrap();
        assert!(!handle.should_stop());

        // Stop
        daemon
            .stop_episode(&episode_id, TerminationClass::Success)
            .await
            .unwrap();
        assert_eq!(daemon.active_count().await, 0);
    }

    #[tokio::test]
    async fn test_daemon_budget_tracker() {
        let tracker = TestDaemon::create_test_budget_tracker();

        assert!(!TestDaemon::is_budget_exhausted(&tracker));

        let delta = BudgetDelta::single_call().with_tokens(5_000);
        TestDaemon::charge_budget(&tracker, &delta).unwrap();

        let remaining = TestDaemon::remaining_budget(&tracker);
        assert_eq!(remaining.tokens(), 5_000);
    }
}
