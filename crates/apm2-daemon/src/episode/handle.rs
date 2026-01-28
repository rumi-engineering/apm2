//! Session handle for running episodes.
//!
//! This module provides the `SessionHandle` type that represents an active
//! episode session. It encapsulates the runtime state needed to manage
//! a running episode.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::watch;

use super::error::EpisodeId;
use super::state::TerminationClass;

/// Maximum session ID length.
pub const MAX_SESSION_ID_LEN: usize = 128;

/// Shared inner state for `SessionHandle`.
///
/// This is wrapped in `Arc` to allow cloning handles while sharing
/// the same stop signal channel.
#[derive(Debug)]
struct SessionHandleInner {
    /// Episode identifier.
    episode_id: EpisodeId,
    /// Session identifier (unique within the episode).
    session_id: String,
    /// Lease ID authorizing this session.
    lease_id: String,
    /// When this session started (nanoseconds since epoch).
    ///
    /// This is deterministic, set by the caller per HARD-TIME (M05).
    started_at_ns: u64,
    /// Sender for stop signals.
    stop_sender: watch::Sender<StopSignal>,
}

/// Handle to a running episode session.
///
/// This handle provides methods to interact with a running episode,
/// including stop condition checking and budget tracking.
///
/// # Design
///
/// The `SessionHandle` is designed to be held by the caller while an
/// episode is running. It provides:
///
/// - Episode and session identifiers for correlation
/// - Stop signal receiver for graceful shutdown
/// - Timing information for budget enforcement
///
/// # Cloning
///
/// `SessionHandle` is `Clone`. All clones share the same underlying
/// stop signal channel, so signals sent via any clone are received
/// by all clones. This is essential for the runtime to signal the
/// caller's handle.
///
/// # Invariants
///
/// - [INV-SH001] Session IDs are unique within an episode
/// - [INV-SH002] Start timestamp is immutable after creation
/// - [INV-SH003] All clones share the same stop signal channel
/// - [INV-SH004] All timing is deterministic via caller-supplied timestamps
///   (HARD-TIME)
#[derive(Debug, Clone)]
pub struct SessionHandle {
    /// Shared inner state.
    inner: Arc<SessionHandleInner>,
    /// Receiver for stop signals (cloned from shared sender).
    stop_receiver: watch::Receiver<StopSignal>,
}

impl SessionHandle {
    /// Creates a new session handle.
    ///
    /// # Arguments
    ///
    /// * `episode_id` - The episode this session belongs to
    /// * `session_id` - Unique session identifier
    /// * `lease_id` - Lease authorizing this session
    /// * `started_at_ns` - Start timestamp in nanoseconds since epoch
    ///   (deterministic, per HARD-TIME)
    pub fn new(
        episode_id: EpisodeId,
        session_id: impl Into<String>,
        lease_id: impl Into<String>,
        started_at_ns: u64,
    ) -> Self {
        let (stop_sender, stop_receiver) = watch::channel(StopSignal::None);
        let inner = SessionHandleInner {
            episode_id,
            session_id: session_id.into(),
            lease_id: lease_id.into(),
            started_at_ns,
            stop_sender,
        };
        Self {
            inner: Arc::new(inner),
            stop_receiver,
        }
    }

    /// Returns the episode ID.
    #[must_use]
    pub fn episode_id(&self) -> &EpisodeId {
        &self.inner.episode_id
    }

    /// Returns the session ID.
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.inner.session_id
    }

    /// Returns the lease ID.
    #[must_use]
    pub fn lease_id(&self) -> &str {
        &self.inner.lease_id
    }

    /// Returns the elapsed time in nanoseconds since this session started.
    ///
    /// # Arguments
    ///
    /// * `current_ns` - Current timestamp in nanoseconds since epoch
    ///
    /// # Returns
    ///
    /// Elapsed time in nanoseconds. Returns 0 if `current_ns < started_at_ns`
    /// (fail-closed behavior for clock skew).
    ///
    /// This method is deterministic per HARD-TIME (M05) - timing is computed
    /// from caller-supplied timestamps, not from `Instant::now()`.
    #[must_use]
    pub fn elapsed_ns(&self, current_ns: u64) -> u64 {
        current_ns.saturating_sub(self.inner.started_at_ns)
    }

    /// Returns the start timestamp in nanoseconds since epoch.
    ///
    /// This is the deterministic timestamp provided at session creation.
    #[must_use]
    pub fn started_at_ns(&self) -> u64 {
        self.inner.started_at_ns
    }

    /// Signals the session to stop with the given reason.
    ///
    /// This sends a stop signal that can be observed via `should_stop()`.
    /// Because all clones of this handle share the same channel, the signal
    /// is received by all holders of the handle.
    pub fn signal_stop(&self, signal: StopSignal) {
        // send() only fails if there are no receivers, which can't happen
        // since we hold a receiver ourselves.
        let _ = self.inner.stop_sender.send(signal);
    }

    /// Returns the current stop signal, if any.
    #[must_use]
    pub fn current_stop_signal(&self) -> StopSignal {
        self.stop_receiver.borrow().clone()
    }

    /// Returns `true` if the session should stop.
    #[must_use]
    pub fn should_stop(&self) -> bool {
        !matches!(*self.stop_receiver.borrow(), StopSignal::None)
    }

    /// Returns a receiver for stop signals.
    ///
    /// This can be used in `tokio::select!` to wait for stop signals.
    #[must_use]
    pub fn stop_receiver(&self) -> watch::Receiver<StopSignal> {
        self.stop_receiver.clone()
    }

    /// Creates a snapshot of the current handle state.
    ///
    /// # Arguments
    ///
    /// * `current_ns` - Current timestamp in nanoseconds since epoch
    ///
    /// This method is deterministic per HARD-TIME (M05) - elapsed time is
    /// computed from the caller-supplied timestamp.
    #[must_use]
    #[allow(clippy::similar_names)] // elapsed_ns and elapsed_ms are intentionally similar
    pub fn snapshot(&self, current_ns: u64) -> SessionSnapshot {
        // Convert elapsed nanoseconds to milliseconds
        let elapsed_ns = self.elapsed_ns(current_ns);
        let elapsed_ms = elapsed_ns / 1_000_000;
        SessionSnapshot {
            episode_id: self.inner.episode_id.as_str().to_string(),
            session_id: self.inner.session_id.clone(),
            lease_id: self.inner.lease_id.clone(),
            elapsed_ms,
            stop_signal: self.current_stop_signal(),
        }
    }
}

/// A stop signal sent to a running session.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum StopSignal {
    /// No stop signal - continue running.
    #[default]
    None,
    /// Graceful stop requested - finish current work and terminate.
    Graceful {
        /// Reason for the stop.
        reason: String,
    },
    /// Immediate stop - terminate as soon as possible.
    Immediate {
        /// Reason for the stop.
        reason: String,
    },
    /// Budget exhausted - stop due to resource limits.
    BudgetExhausted {
        /// Which resource was exhausted.
        resource: String,
    },
    /// External signal - stop due to external event.
    External {
        /// Signal type (e.g., "SIGTERM", "SIGINT").
        signal: String,
    },
    /// Quarantine requested - stop and quarantine the episode.
    Quarantine {
        /// Reason for quarantine.
        reason: String,
    },
}

impl StopSignal {
    /// Returns the termination class for this stop signal.
    #[must_use]
    pub fn termination_class(&self) -> Option<TerminationClass> {
        match self {
            Self::None => None,
            Self::Graceful { .. } => Some(TerminationClass::Success),
            Self::BudgetExhausted { .. } => Some(TerminationClass::BudgetExhausted),
            Self::External { signal } if signal == "SIGKILL" => Some(TerminationClass::Killed),
            Self::Immediate { .. } | Self::External { .. } => Some(TerminationClass::Cancelled),
            Self::Quarantine { .. } => Some(TerminationClass::Crashed),
        }
    }

    /// Returns `true` if this signal requires quarantine instead of normal
    /// termination.
    #[must_use]
    pub const fn requires_quarantine(&self) -> bool {
        matches!(self, Self::Quarantine { .. })
    }
}

/// Snapshot of a session's state at a point in time.
///
/// This is a serializable representation of a session handle's state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionSnapshot {
    /// Episode identifier.
    pub episode_id: String,
    /// Session identifier.
    pub session_id: String,
    /// Lease identifier.
    pub lease_id: String,
    /// Elapsed time in milliseconds.
    pub elapsed_ms: u64,
    /// Current stop signal.
    pub stop_signal: StopSignal,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_episode_id() -> EpisodeId {
        EpisodeId::new("ep-test-123").unwrap()
    }

    /// Test timestamp: 2024-01-01 00:00:00 UTC in nanoseconds.
    fn test_timestamp() -> u64 {
        1_704_067_200_000_000_000
    }

    #[test]
    fn test_session_handle_new() {
        let handle =
            SessionHandle::new(test_episode_id(), "session-1", "lease-1", test_timestamp());
        assert_eq!(handle.episode_id().as_str(), "ep-test-123");
        assert_eq!(handle.session_id(), "session-1");
        assert_eq!(handle.lease_id(), "lease-1");
        assert_eq!(handle.started_at_ns(), test_timestamp());
    }

    #[test]
    fn test_session_handle_elapsed_ns() {
        let start_ns = test_timestamp();
        let handle = SessionHandle::new(test_episode_id(), "session-1", "lease-1", start_ns);

        // At start time, elapsed should be 0
        assert_eq!(handle.elapsed_ns(start_ns), 0);

        // 1 second later
        let one_sec_ns = 1_000_000_000;
        assert_eq!(handle.elapsed_ns(start_ns + one_sec_ns), one_sec_ns);

        // Fail-closed: if current_ns < started_at_ns (clock skew), return 0
        assert_eq!(handle.elapsed_ns(start_ns - 1), 0);
    }

    #[test]
    fn test_session_handle_stop_signal() {
        let handle =
            SessionHandle::new(test_episode_id(), "session-1", "lease-1", test_timestamp());

        // Initially no stop signal
        assert!(!handle.should_stop());
        assert_eq!(handle.current_stop_signal(), StopSignal::None);

        // Signal stop
        handle.signal_stop(StopSignal::Graceful {
            reason: "test".to_string(),
        });

        // Now should stop
        assert!(handle.should_stop());
        assert!(matches!(
            handle.current_stop_signal(),
            StopSignal::Graceful { .. }
        ));
    }

    #[test]
    fn test_session_handle_snapshot() {
        let start_ns = test_timestamp();
        let handle = SessionHandle::new(test_episode_id(), "session-1", "lease-1", start_ns);
        // Snapshot taken 500ms after start
        let current_ns = start_ns + 500_000_000;
        let snapshot = handle.snapshot(current_ns);

        assert_eq!(snapshot.episode_id, "ep-test-123");
        assert_eq!(snapshot.session_id, "session-1");
        assert_eq!(snapshot.lease_id, "lease-1");
        assert_eq!(snapshot.elapsed_ms, 500);
        assert_eq!(snapshot.stop_signal, StopSignal::None);
    }

    // Stop signal tests

    #[test]
    fn test_stop_signal_termination_class() {
        assert_eq!(StopSignal::None.termination_class(), None);
        assert_eq!(
            StopSignal::Graceful {
                reason: "x".to_string()
            }
            .termination_class(),
            Some(TerminationClass::Success)
        );
        assert_eq!(
            StopSignal::Immediate {
                reason: "x".to_string()
            }
            .termination_class(),
            Some(TerminationClass::Cancelled)
        );
        assert_eq!(
            StopSignal::BudgetExhausted {
                resource: "tokens".to_string()
            }
            .termination_class(),
            Some(TerminationClass::BudgetExhausted)
        );
        assert_eq!(
            StopSignal::External {
                signal: "SIGKILL".to_string()
            }
            .termination_class(),
            Some(TerminationClass::Killed)
        );
        assert_eq!(
            StopSignal::External {
                signal: "SIGTERM".to_string()
            }
            .termination_class(),
            Some(TerminationClass::Cancelled)
        );
    }

    #[test]
    fn test_stop_signal_requires_quarantine() {
        assert!(!StopSignal::None.requires_quarantine());
        assert!(
            !StopSignal::Graceful {
                reason: "x".to_string()
            }
            .requires_quarantine()
        );
        assert!(
            StopSignal::Quarantine {
                reason: "x".to_string()
            }
            .requires_quarantine()
        );
    }

    #[test]
    fn test_stop_signal_serialization() {
        let signals = vec![
            StopSignal::None,
            StopSignal::Graceful {
                reason: "test".to_string(),
            },
            StopSignal::Immediate {
                reason: "urgent".to_string(),
            },
            StopSignal::BudgetExhausted {
                resource: "tokens".to_string(),
            },
        ];

        for signal in signals {
            let json = serde_json::to_string(&signal).unwrap();
            let deserialized: StopSignal = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, signal);
        }
    }

    /// SECURITY TEST: Verify `SessionSnapshot` rejects unknown fields.
    #[test]
    fn test_snapshot_rejects_unknown_fields() {
        let json = r#"{
            "episode_id": "ep-1",
            "session_id": "s-1",
            "lease_id": "l-1",
            "elapsed_ms": 100,
            "stop_signal": {"type": "NONE"},
            "malicious": "value"
        }"#;

        let result: Result<SessionSnapshot, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "SessionSnapshot should reject unknown fields"
        );
    }

    /// Test that `SessionHandle` implements `Clone` and clones share the
    /// channel.
    #[test]
    fn test_session_handle_is_clone() {
        let handle1 =
            SessionHandle::new(test_episode_id(), "session-1", "lease-1", test_timestamp());
        let handle2 = handle1.clone();

        // Both handles should have the same identifiers
        assert_eq!(handle1.episode_id().as_str(), handle2.episode_id().as_str());
        assert_eq!(handle1.session_id(), handle2.session_id());
        assert_eq!(handle1.lease_id(), handle2.lease_id());

        // Initially neither should have a stop signal
        assert!(!handle1.should_stop());
        assert!(!handle2.should_stop());

        // Signal through handle1
        handle1.signal_stop(StopSignal::Graceful {
            reason: "clone-test".to_string(),
        });

        // Both handles should see the signal (shared channel - INV-SH003)
        assert!(handle1.should_stop());
        assert!(handle2.should_stop());
        assert!(matches!(
            handle2.current_stop_signal(),
            StopSignal::Graceful { reason } if reason == "clone-test"
        ));
    }

    /// Test that multiple clones all share the same channel.
    #[test]
    fn test_session_handle_multiple_clones_share_channel() {
        let handle1 =
            SessionHandle::new(test_episode_id(), "session-1", "lease-1", test_timestamp());
        let handle2 = handle1.clone();
        let handle3 = handle2.clone();
        let handle4 = handle1.clone();

        // Signal through handle3
        handle3.signal_stop(StopSignal::BudgetExhausted {
            resource: "tokens".to_string(),
        });

        // All handles should see the signal
        assert!(handle1.should_stop());
        assert!(handle2.should_stop());
        assert!(handle3.should_stop());
        assert!(handle4.should_stop());
    }
}
