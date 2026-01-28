//! `TelemetryCollector` implementation for frame streaming.
//!
//! This module implements the `TelemetryCollector` per CTR-DAEMON-005,
//! providing periodic resource metric collection with ring buffer storage
//! and budget integration.
//!
//! # Architecture
//!
//! ```text
//! TelemetryCollector
//!     |
//!     +-- start(episode_id, pid) --> TelemetryHandle
//!     |
//!     +-- collect(handle) --> TelemetryFrame
//!     |
//!     +-- apply_policy(policy) --> updates collection parameters
//!     |
//!     +-- spawn_collection_loop() --> async task for periodic collection
//! ```
//!
//! # Collection Loop
//!
//! The collector spawns an async task that:
//! 1. Sleeps for `sample_interval`
//! 2. Reads metrics from `CgroupReader`
//! 3. Computes deltas from previous sample
//! 4. Pushes frame to ring buffer
//! 5. Reports consumption to `BudgetTracker`
//!
//! # Budget Integration
//!
//! Per CTR-DAEMON-005, the collector integrates with budget accounting:
//! - Reports `cpu_ms` from telemetry to budget tracker
//! - Reports `bytes_io` from telemetry to budget tracker
//! - Checks limits and triggers stop if exhausted
//!
//! # Contract References
//!
//! - CTR-DAEMON-005: `TelemetryCollector` and frame streaming

use std::sync::Arc;

use nix::unistd::Pid;
use thiserror::Error;
use tokio::sync::mpsc;
use tokio::time::{Duration, sleep};
use tracing::{debug, warn};

use super::cgroup::CgroupReader;
use super::frame::{O11yFlags, TelemetryFrame};
use super::handle::TelemetryHandle;
use super::policy::TelemetryPolicy;
use crate::episode::{BudgetDelta, BudgetExhaustedError, BudgetTracker, EpisodeId};

/// Error type for telemetry collection operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TelemetryError {
    /// Collection is stopped.
    #[error("telemetry collection is stopped for episode {episode_id}")]
    Stopped {
        /// Episode identifier.
        episode_id: String,
    },

    /// Budget exhausted during collection.
    #[error("budget exhausted during telemetry collection: {source}")]
    BudgetExhausted {
        /// The budget exhaustion error.
        #[source]
        source: BudgetExhaustedError,
    },

    /// Cgroup reader failed.
    #[error("cgroup reader unavailable for episode {episode_id}")]
    CgroupUnavailable {
        /// Episode identifier.
        episode_id: String,
    },

    /// Invalid configuration.
    #[error("invalid telemetry configuration: {reason}")]
    InvalidConfig {
        /// Reason for the error.
        reason: String,
    },
}

/// Result type for telemetry operations.
pub type TelemetryResult<T> = Result<T, TelemetryError>;

/// Telemetry collector for episode resource monitoring.
///
/// Per CTR-DAEMON-005, this collector:
/// - Collects resource metrics at configurable intervals
/// - Stores frames in a ring buffer
/// - Reports consumption to budget tracker
/// - Supports high-frequency mode when budget nearing exhaustion
///
/// # Example
///
/// ```rust,ignore
/// use apm2_daemon::telemetry::{TelemetryCollector, TelemetryPolicy};
/// use apm2_daemon::episode::EpisodeId;
/// use nix::unistd::Pid;
///
/// let collector = TelemetryCollector::new(TelemetryPolicy::default());
/// let handle = collector.start(
///     EpisodeId::new("ep-001")?,
///     Pid::from_raw(1234),
/// )?;
///
/// // Collection happens asynchronously...
///
/// // Get current frame manually
/// let frame = collector.collect(&handle)?;
///
/// // Stop collection
/// let frames = handle.stop();
/// ```
#[derive(Debug)]
pub struct TelemetryCollector {
    /// Collection policy.
    policy: TelemetryPolicy,
}

impl TelemetryCollector {
    /// Creates a new telemetry collector with the given policy.
    #[must_use]
    pub const fn new(policy: TelemetryPolicy) -> Self {
        Self { policy }
    }

    /// Creates a new telemetry collector with default policy.
    #[must_use]
    pub fn with_default_policy() -> Self {
        Self::new(TelemetryPolicy::default())
    }

    /// Returns the current policy.
    #[must_use]
    pub const fn policy(&self) -> &TelemetryPolicy {
        &self.policy
    }

    /// Applies a new policy.
    ///
    /// Note: This only affects new collection sessions. Existing handles
    /// continue with their original policy.
    pub const fn apply_policy(&mut self, policy: TelemetryPolicy) {
        self.policy = policy;
    }

    /// Starts telemetry collection for an episode.
    ///
    /// # Arguments
    ///
    /// * `episode_id` - Episode identifier
    /// * `pid` - Process ID to monitor
    ///
    /// # Returns
    ///
    /// A handle for the active collection session.
    #[must_use]
    pub fn start(&self, episode_id: EpisodeId, pid: Pid) -> TelemetryHandle {
        TelemetryHandle::new(episode_id, pid, self.policy.ring_buffer_capacity())
    }

    /// Collects a single telemetry frame.
    ///
    /// This manually collects a frame using the provided cgroup reader.
    /// For automatic periodic collection, use `spawn_collection_loop`.
    ///
    /// # Arguments
    ///
    /// * `handle` - Active collection handle
    /// * `reader` - Cgroup reader for metrics
    /// * `o11y_flags` - Observability flags for this frame
    ///
    /// # Errors
    ///
    /// Returns an error if collection is stopped.
    pub fn collect(
        &self,
        handle: &TelemetryHandle,
        reader: &CgroupReader,
        o11y_flags: O11yFlags,
    ) -> TelemetryResult<TelemetryFrame> {
        if handle.is_stopped() {
            return Err(TelemetryError::Stopped {
                episode_id: handle.episode_id().to_string(),
            });
        }

        // Read current stats
        let stats = reader.read_all();

        // Create frame
        handle
            .next_frame(stats, o11y_flags)
            .ok_or_else(|| TelemetryError::Stopped {
                episode_id: handle.episode_id().to_string(),
            })
    }

    /// Collects a frame and reports consumption to the budget tracker.
    ///
    /// # Arguments
    ///
    /// * `handle` - Active collection handle
    /// * `reader` - Cgroup reader for metrics
    /// * `budget_tracker` - Budget tracker for consumption reporting
    /// * `o11y_flags` - Observability flags for this frame
    ///
    /// # Returns
    ///
    /// Returns `Ok(Some(frame))` if collection succeeded.
    /// Returns `Ok(None)` if budget is exhausted (caller should stop episode).
    /// Returns `Err` if collection failed for other reasons.
    ///
    /// # Errors
    ///
    /// Returns an error if collection is stopped.
    pub fn collect_with_budget(
        &self,
        handle: &TelemetryHandle,
        reader: &CgroupReader,
        budget_tracker: &BudgetTracker,
        o11y_flags: O11yFlags,
    ) -> TelemetryResult<Option<TelemetryFrame>> {
        if handle.is_stopped() {
            return Err(TelemetryError::Stopped {
                episode_id: handle.episode_id().to_string(),
            });
        }

        // Read current stats
        let stats = reader.read_all();

        // Compute delta from previous
        let (cpu_delta_ns, io_delta_bytes) = handle.compute_delta(&stats);

        // Convert nanoseconds to milliseconds for budget
        let budget_delta = BudgetDelta {
            tokens: 0,
            tool_calls: 0,
            wall_ms: 0,
            cpu_ms: cpu_delta_ns / 1_000_000,
            bytes_io: io_delta_bytes,
        };

        // Try to charge the budget
        if let Err(e) = budget_tracker.charge(&budget_delta) {
            debug!(
                episode_id = %handle.episode_id(),
                error = %e,
                "budget exhausted during telemetry collection"
            );
            return Ok(None);
        }

        // Create frame
        let frame =
            handle
                .next_frame(stats, o11y_flags)
                .ok_or_else(|| TelemetryError::Stopped {
                    episode_id: handle.episode_id().to_string(),
                })?;

        // Check high-frequency mode threshold
        self.update_high_freq_mode(handle, budget_tracker);

        Ok(Some(frame))
    }

    /// Updates high-frequency mode based on budget consumption.
    fn update_high_freq_mode(&self, handle: &TelemetryHandle, budget_tracker: &BudgetTracker) {
        if !self.policy.high_freq_enabled() {
            return;
        }

        let limits = budget_tracker.limits();
        let consumed = budget_tracker.consumed();

        // Check CPU budget consumption
        let cpu_percent = if limits.cpu_ms() > 0 {
            (consumed.cpu_ms * 100) / limits.cpu_ms()
        } else {
            0
        };

        // Check I/O budget consumption
        let io_percent = if limits.bytes_io() > 0 {
            (consumed.bytes_io * 100) / limits.bytes_io()
        } else {
            0
        };

        // Enable high-frequency mode if either threshold exceeded
        let threshold = u64::from(self.policy.high_freq_threshold_percent());
        let should_enable = cpu_percent >= threshold || io_percent >= threshold;

        if should_enable != handle.is_high_freq_active() {
            handle.set_high_freq_active(should_enable);
            debug!(
                episode_id = %handle.episode_id(),
                high_freq = should_enable,
                cpu_percent,
                io_percent,
                "telemetry high-frequency mode changed"
            );
        }
    }

    /// Spawns an async collection loop for periodic telemetry gathering.
    ///
    /// This spawns a Tokio task that:
    /// 1. Sleeps for `sample_interval` (adjusted for high-freq mode)
    /// 2. Reads metrics from `CgroupReader`
    /// 3. Reports consumption to `BudgetTracker`
    /// 4. Pushes frame to the handle's ring buffer
    /// 5. Sends frame to the output channel
    ///
    /// The loop terminates when:
    /// - The handle is stopped
    /// - Budget is exhausted
    /// - The output channel is closed
    ///
    /// # Arguments
    ///
    /// * `handle` - Active collection handle (wrapped in Arc for sharing)
    /// * `reader` - Cgroup reader (wrapped in Arc for sharing)
    /// * `budget_tracker` - Budget tracker (wrapped in Arc for sharing)
    /// * `output_tx` - Channel for sending frames
    ///
    /// # Returns
    ///
    /// A `JoinHandle` for the spawned task.
    pub fn spawn_collection_loop(
        &self,
        handle: Arc<TelemetryHandle>,
        reader: Arc<CgroupReader>,
        budget_tracker: Arc<BudgetTracker>,
        output_tx: mpsc::Sender<TelemetryFrame>,
    ) -> tokio::task::JoinHandle<()> {
        let policy = self.policy.clone();

        tokio::spawn(async move {
            let mut is_first = true;

            loop {
                // Check if stopped
                if handle.is_stopped() {
                    debug!(
                        episode_id = %handle.episode_id(),
                        "telemetry collection loop stopped"
                    );
                    break;
                }

                // Determine sample interval
                let sample_ms = policy.effective_sample_period_ms(handle.is_high_freq_active());
                let sleep_duration = Duration::from_millis(sample_ms);

                // Sleep for the interval
                sleep(sleep_duration).await;

                // Check again after sleep
                if handle.is_stopped() {
                    break;
                }

                // Read current stats
                let stats = reader.read_all();

                // Compute delta
                let (cpu_delta_ns, io_delta_bytes) = handle.compute_delta(&stats);

                // Try to charge budget
                let budget_delta = BudgetDelta {
                    tokens: 0,
                    tool_calls: 0,
                    wall_ms: 0,
                    cpu_ms: cpu_delta_ns / 1_000_000,
                    bytes_io: io_delta_bytes,
                };

                if let Err(e) = budget_tracker.charge(&budget_delta) {
                    warn!(
                        episode_id = %handle.episode_id(),
                        error = %e,
                        "budget exhausted in telemetry loop, stopping"
                    );
                    break;
                }

                // Build flags
                let mut o11y_flags = O11yFlags::new();
                if is_first {
                    o11y_flags = o11y_flags.with_initial();
                    is_first = false;
                }
                if handle.is_high_freq_active() {
                    o11y_flags = o11y_flags.with_high_frequency();
                }
                if stats.has_degraded_source() {
                    o11y_flags = o11y_flags.with_degraded();
                }

                // Create frame
                let Some(frame) = handle.next_frame(stats, o11y_flags) else {
                    break;
                };

                // Send to output channel
                if output_tx.send(frame).await.is_err() {
                    debug!(
                        episode_id = %handle.episode_id(),
                        "output channel closed, stopping telemetry loop"
                    );
                    break;
                }

                // Update high-frequency mode
                update_high_freq_mode_internal(&policy, &handle, &budget_tracker);
            }
        })
    }
}

/// Internal function to update high-frequency mode.
fn update_high_freq_mode_internal(
    policy: &TelemetryPolicy,
    handle: &TelemetryHandle,
    budget_tracker: &BudgetTracker,
) {
    if !policy.high_freq_enabled() {
        return;
    }

    let limits = budget_tracker.limits();
    let consumed = budget_tracker.consumed();

    let cpu_percent = if limits.cpu_ms() > 0 {
        (consumed.cpu_ms * 100) / limits.cpu_ms()
    } else {
        0
    };

    let io_percent = if limits.bytes_io() > 0 {
        (consumed.bytes_io * 100) / limits.bytes_io()
    } else {
        0
    };

    let threshold = u64::from(policy.high_freq_threshold_percent());
    let should_enable = cpu_percent >= threshold || io_percent >= threshold;

    if should_enable != handle.is_high_freq_active() {
        handle.set_high_freq_active(should_enable);
    }
}

impl Default for TelemetryCollector {
    fn default() -> Self {
        Self::with_default_policy()
    }
}

impl Clone for TelemetryCollector {
    fn clone(&self) -> Self {
        Self {
            policy: self.policy.clone(),
        }
    }
}

/// Creates a shared telemetry collector wrapped in `Arc`.
#[must_use]
pub fn new_shared_collector(policy: TelemetryPolicy) -> Arc<TelemetryCollector> {
    Arc::new(TelemetryCollector::new(policy))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::episode::EpisodeBudget;

    fn test_episode_id() -> EpisodeId {
        EpisodeId::new("test-episode-001").expect("valid episode ID")
    }

    // =========================================================================
    // UT-00169-01: Frame collection tests
    // =========================================================================

    #[test]
    fn test_telemetry_collector_new() {
        let policy = TelemetryPolicy::default();
        let collector = TelemetryCollector::new(policy.clone());

        assert_eq!(
            collector.policy().sample_period_ms(),
            policy.sample_period_ms()
        );
    }

    #[test]
    fn test_telemetry_collector_start() {
        let collector = TelemetryCollector::with_default_policy();
        let handle = collector.start(test_episode_id(), Pid::from_raw(1234));

        assert_eq!(handle.episode_id().as_str(), "test-episode-001");
        assert_eq!(handle.pid().as_raw(), 1234);
        assert!(!handle.is_stopped());
    }

    #[test]
    fn test_telemetry_collector_apply_policy() {
        let mut collector = TelemetryCollector::with_default_policy();

        let new_policy = TelemetryPolicy::builder().sample_period_ms(500).build();

        collector.apply_policy(new_policy);

        assert_eq!(collector.policy().sample_period_ms(), 500);
    }

    #[test]
    fn test_telemetry_collector_default() {
        let collector = TelemetryCollector::default();
        assert_eq!(
            collector.policy().sample_period_ms(),
            TelemetryPolicy::default().sample_period_ms()
        );
    }

    #[test]
    fn test_telemetry_collector_clone() {
        let collector =
            TelemetryCollector::new(TelemetryPolicy::builder().sample_period_ms(500).build());
        let cloned = collector.clone();

        assert_eq!(
            collector.policy().sample_period_ms(),
            cloned.policy().sample_period_ms()
        );
    }

    #[test]
    fn test_new_shared_collector() {
        let collector = new_shared_collector(TelemetryPolicy::default());
        assert_eq!(Arc::strong_count(&collector), 1);
    }

    // =========================================================================
    // UT-00169-02: Sample interval tests
    // =========================================================================

    #[test]
    fn test_telemetry_policy_effective_sample_period() {
        let policy = TelemetryPolicy::builder()
            .sample_period_ms(1000)
            .high_freq_enabled(true)
            .build();

        assert_eq!(policy.effective_sample_period_ms(false), 1000);
        assert_eq!(policy.effective_sample_period_ms(true), 250);
    }

    #[test]
    fn test_telemetry_handle_high_freq_mode() {
        let collector = TelemetryCollector::with_default_policy();
        let handle = collector.start(test_episode_id(), Pid::from_raw(1234));

        assert!(!handle.is_high_freq_active());
        handle.set_high_freq_active(true);
        assert!(handle.is_high_freq_active());
    }

    // =========================================================================
    // IT-00169-01: Budget integration tests
    // =========================================================================

    #[test]
    fn test_budget_delta_from_telemetry() {
        // Simulate telemetry delta conversion
        let cpu_ns: u64 = 1_500_000_000; // 1.5 seconds
        let io_bytes: u64 = 1_048_576; // 1 MiB

        let budget_delta = BudgetDelta {
            tokens: 0,
            tool_calls: 0,
            wall_ms: 0,
            cpu_ms: cpu_ns / 1_000_000,
            bytes_io: io_bytes,
        };

        assert_eq!(budget_delta.cpu_ms, 1500);
        assert_eq!(budget_delta.bytes_io, 1_048_576);
    }

    #[test]
    fn test_budget_tracker_charge_from_telemetry() {
        let budget = EpisodeBudget::builder()
            .cpu_ms(10_000)
            .bytes_io(10_000_000)
            .build();

        let tracker = BudgetTracker::from_envelope(budget);

        // Simulate telemetry charging
        let delta = BudgetDelta {
            tokens: 0,
            tool_calls: 0,
            wall_ms: 0,
            cpu_ms: 1000,
            bytes_io: 1_000_000,
        };

        assert!(tracker.charge(&delta).is_ok());

        let remaining = tracker.remaining();
        assert_eq!(remaining.cpu_ms(), 9000);
        assert_eq!(remaining.bytes_io(), 9_000_000);
    }

    #[test]
    fn test_budget_exhaustion_detection() {
        let budget = EpisodeBudget::builder().cpu_ms(100).bytes_io(1000).build();

        let tracker = BudgetTracker::from_envelope(budget);

        // First charge succeeds
        let delta1 = BudgetDelta {
            tokens: 0,
            tool_calls: 0,
            wall_ms: 0,
            cpu_ms: 50,
            bytes_io: 500,
        };
        assert!(tracker.charge(&delta1).is_ok());

        // Second charge exceeds budget
        let delta2 = BudgetDelta {
            tokens: 0,
            tool_calls: 0,
            wall_ms: 0,
            cpu_ms: 100, // Would exceed
            bytes_io: 100,
        };
        assert!(tracker.charge(&delta2).is_err());
    }

    #[test]
    fn test_high_freq_threshold_calculation() {
        let budget = EpisodeBudget::builder()
            .cpu_ms(1000)
            .bytes_io(10_000)
            .build();

        let tracker = BudgetTracker::from_envelope(budget);

        // Charge 80% of CPU budget
        let delta = BudgetDelta {
            tokens: 0,
            tool_calls: 0,
            wall_ms: 0,
            cpu_ms: 800,
            bytes_io: 0,
        };
        tracker.charge(&delta).unwrap();

        let consumed = tracker.consumed();
        let limits = tracker.limits();

        let cpu_percent = (consumed.cpu_ms * 100) / limits.cpu_ms();
        assert_eq!(cpu_percent, 80);

        // With threshold at 80%, high-freq should be enabled
        let threshold = 80_u64;
        assert!(cpu_percent >= threshold);
    }

    // =========================================================================
    // Error type tests
    // =========================================================================

    #[test]
    fn test_telemetry_error_display() {
        let err = TelemetryError::Stopped {
            episode_id: "test-ep".to_string(),
        };
        assert!(err.to_string().contains("test-ep"));

        let err = TelemetryError::CgroupUnavailable {
            episode_id: "test-ep".to_string(),
        };
        assert!(err.to_string().contains("cgroup reader unavailable"));

        let err = TelemetryError::InvalidConfig {
            reason: "bad config".to_string(),
        };
        assert!(err.to_string().contains("bad config"));
    }
}
