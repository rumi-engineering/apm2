//! Session handle for running episodes.
//!
//! This module provides the `SessionHandle` type that represents an active
//! episode session. It encapsulates the runtime state needed to manage
//! a running episode.

use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::watch;

use super::error::EpisodeId;
use super::state::TerminationClass;

/// Maximum session ID length.
pub const MAX_SESSION_ID_LEN: usize = 128;

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
/// # Invariants
///
/// - [INV-SH001] Session IDs are unique within an episode
/// - [INV-SH002] Start instant is immutable after creation
#[derive(Debug)]
pub struct SessionHandle {
    /// Episode identifier.
    episode_id: EpisodeId,
    /// Session identifier (unique within the episode).
    session_id: String,
    /// Lease ID authorizing this session.
    lease_id: String,
    /// When this session started.
    started_at: Instant,
    /// Receiver for stop signals.
    stop_receiver: watch::Receiver<StopSignal>,
    /// Sender for stop signals (held internally for signaling).
    stop_sender: Arc<watch::Sender<StopSignal>>,
}

impl SessionHandle {
    /// Creates a new session handle.
    ///
    /// # Arguments
    ///
    /// * `episode_id` - The episode this session belongs to
    /// * `session_id` - Unique session identifier
    /// * `lease_id` - Lease authorizing this session
    pub fn new(
        episode_id: EpisodeId,
        session_id: impl Into<String>,
        lease_id: impl Into<String>,
    ) -> Self {
        let (stop_sender, stop_receiver) = watch::channel(StopSignal::None);
        Self {
            episode_id,
            session_id: session_id.into(),
            lease_id: lease_id.into(),
            started_at: Instant::now(),
            stop_receiver,
            stop_sender: Arc::new(stop_sender),
        }
    }

    /// Returns the episode ID.
    #[must_use]
    pub const fn episode_id(&self) -> &EpisodeId {
        &self.episode_id
    }

    /// Returns the session ID.
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Returns the lease ID.
    #[must_use]
    pub fn lease_id(&self) -> &str {
        &self.lease_id
    }

    /// Returns the duration since this session started.
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.started_at.elapsed()
    }

    /// Returns the start instant.
    #[must_use]
    pub const fn started_at(&self) -> Instant {
        self.started_at
    }

    /// Signals the session to stop with the given reason.
    ///
    /// This sends a stop signal that can be observed via `should_stop()`.
    pub fn signal_stop(&self, signal: StopSignal) {
        // send() only fails if there are no receivers, which can't happen
        // since we hold a receiver ourselves.
        let _ = self.stop_sender.send(signal);
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
    #[must_use]
    pub fn snapshot(&self) -> SessionSnapshot {
        SessionSnapshot {
            episode_id: self.episode_id.as_str().to_string(),
            session_id: self.session_id.clone(),
            lease_id: self.lease_id.clone(),
            // Saturate to u64::MAX for durations exceeding ~584 million years
            elapsed_ms: u64::try_from(self.elapsed().as_millis()).unwrap_or(u64::MAX),
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

    #[test]
    fn test_session_handle_new() {
        let handle = SessionHandle::new(test_episode_id(), "session-1", "lease-1");
        assert_eq!(handle.episode_id().as_str(), "ep-test-123");
        assert_eq!(handle.session_id(), "session-1");
        assert_eq!(handle.lease_id(), "lease-1");
    }

    #[test]
    fn test_session_handle_elapsed() {
        let handle = SessionHandle::new(test_episode_id(), "session-1", "lease-1");
        // Elapsed time should be very small (essentially 0)
        assert!(handle.elapsed().as_millis() < 100);
    }

    #[test]
    fn test_session_handle_stop_signal() {
        let handle = SessionHandle::new(test_episode_id(), "session-1", "lease-1");

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
        let handle = SessionHandle::new(test_episode_id(), "session-1", "lease-1");
        let snapshot = handle.snapshot();

        assert_eq!(snapshot.episode_id, "ep-test-123");
        assert_eq!(snapshot.session_id, "session-1");
        assert_eq!(snapshot.lease_id, "lease-1");
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
}
