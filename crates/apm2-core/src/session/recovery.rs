//! Session state recovery from ledger.
//!
//! This module provides functions for recovering session state from the
//! ledger after a crash, enabling sessions to resume from their last
//! known good state.

use std::collections::HashMap;

use crate::ledger::EventRecord;

/// Error type for recovery operations.
#[derive(Debug, thiserror::Error)]
pub enum RecoveryError {
    /// The session was not found in the ledger.
    #[error("session {session_id} not found in ledger")]
    SessionNotFound {
        /// The session ID that was not found.
        session_id: String,
    },

    /// The recovery point is invalid.
    #[error("invalid recovery point: seq_id {seq_id} for session {session_id}")]
    InvalidRecoveryPoint {
        /// The sequence ID that was invalid.
        seq_id: u64,
        /// The session ID.
        session_id: String,
    },

    /// Failed to decode event data.
    #[error("failed to decode event: {0}")]
    DecodeError(String),
}

/// Finds the last ledger sequence ID for a session by scanning events.
///
/// Returns the sequence ID of the most recent event for the given session,
/// or an error if no events are found.
///
/// # Errors
///
/// Returns `RecoveryError::SessionNotFound` if no events exist for the session.
pub fn find_last_session_cursor(
    events: &[EventRecord],
    session_id: &str,
) -> Result<u64, RecoveryError> {
    events
        .iter()
        .filter(|e| e.session_id == session_id && e.seq_id.is_some())
        .filter_map(|e| e.seq_id)
        .max()
        .ok_or_else(|| RecoveryError::SessionNotFound {
            session_id: session_id.to_string(),
        })
}

/// Finds the sequence ID of the last progress event for a session.
///
/// Progress events are good recovery points as they represent
/// successfully completed work.
///
/// # Errors
///
/// Returns `RecoveryError::SessionNotFound` if no progress events exist.
pub fn find_last_progress_cursor(
    events: &[EventRecord],
    session_id: &str,
) -> Result<u64, RecoveryError> {
    events
        .iter()
        .filter(|e| {
            e.session_id == session_id && e.event_type == "session.progress" && e.seq_id.is_some()
        })
        .filter_map(|e| e.seq_id)
        .max()
        .ok_or_else(|| RecoveryError::SessionNotFound {
            session_id: session_id.to_string(),
        })
}

/// Replays session state from ledger events.
///
/// This function processes events in order to reconstruct the session's
/// state at a given point. Returns a map of session metadata.
///
/// Note: This is a simplified implementation. A full implementation would
/// use the `SessionReducer` to replay events.
///
/// # Errors
///
/// Returns `RecoveryError::SessionNotFound` if no events exist for the session.
pub fn replay_session_state(
    events: &[EventRecord],
    session_id: &str,
    up_to_seq_id: Option<u64>,
) -> Result<SessionRecoveryState, RecoveryError> {
    let mut state = SessionRecoveryState::default();
    let mut found = false;

    for event in events {
        // Stop at seq_id if specified
        if let (Some(limit), Some(event_seq)) = (up_to_seq_id, event.seq_id) {
            if event_seq > limit {
                break;
            }
        }

        // Only process events for this session
        if event.session_id != session_id {
            continue;
        }

        found = true;
        if let Some(seq) = event.seq_id {
            state.last_seq_id = seq;
        }
        state.last_timestamp_ns = event.timestamp_ns;
        state.event_count += 1;

        match event.event_type.as_str() {
            "session.started" => {
                state.started_at = Some(event.timestamp_ns);
                state.started_seq_id = event.seq_id;
            },
            "session.progress" => {
                state.progress_count += 1;
                state.last_progress_seq_id = event.seq_id;
            },
            "session.terminated" => {
                state.terminated = true;
            },
            "session.quarantined" => {
                state.quarantined = true;
            },
            _ => {},
        }
    }

    if !found {
        return Err(RecoveryError::SessionNotFound {
            session_id: session_id.to_string(),
        });
    }

    Ok(state)
}

/// Validates that a recovery point is valid for a session.
///
/// A recovery point is valid if:
/// 1. The sequence ID exists in the ledger
/// 2. The sequence ID belongs to the specified session
/// 3. The session was not terminated before this sequence ID
///
/// # Errors
///
/// Returns `RecoveryError::SessionNotFound` if the session doesn't exist,
/// or `RecoveryError::InvalidRecoveryPoint` if the sequence ID is not found.
pub fn validate_recovery_point(
    events: &[EventRecord],
    seq_id: u64,
    session_id: &str,
) -> Result<bool, RecoveryError> {
    let mut session_started = false;
    let mut session_terminated = false;
    let mut seq_id_found = false;

    for event in events {
        if event.session_id == session_id {
            if event.event_type == "session.started" {
                session_started = true;
            }
            if event.seq_id == Some(seq_id) {
                seq_id_found = true;
            }
            if event.event_type == "session.terminated" {
                if let Some(event_seq) = event.seq_id {
                    if event_seq < seq_id {
                        session_terminated = true;
                    }
                }
            }
        }
    }

    if !session_started {
        return Err(RecoveryError::SessionNotFound {
            session_id: session_id.to_string(),
        });
    }

    if !seq_id_found {
        return Err(RecoveryError::InvalidRecoveryPoint {
            seq_id,
            session_id: session_id.to_string(),
        });
    }

    // Valid if session exists, seq_id found, and not terminated before seq_id
    Ok(!session_terminated)
}

/// Counts the number of events for a session since a given sequence ID.
#[must_use]
pub fn count_events_since(events: &[EventRecord], session_id: &str, since_seq_id: u64) -> usize {
    events
        .iter()
        .filter(|e| e.session_id == session_id && e.seq_id.is_some_and(|seq| seq > since_seq_id))
        .count()
}

/// Recovered session state from ledger replay.
#[derive(Debug, Default, Clone)]
pub struct SessionRecoveryState {
    /// When the session started (nanoseconds since epoch).
    pub started_at: Option<u64>,
    /// Sequence ID where the session started.
    pub started_seq_id: Option<u64>,
    /// Last sequence ID processed.
    pub last_seq_id: u64,
    /// Last timestamp processed.
    pub last_timestamp_ns: u64,
    /// Total events processed.
    pub event_count: u64,
    /// Progress events processed.
    pub progress_count: u64,
    /// Sequence ID of last progress event.
    pub last_progress_seq_id: Option<u64>,
    /// Whether the session was terminated.
    pub terminated: bool,
    /// Whether the session was quarantined.
    pub quarantined: bool,
}

impl SessionRecoveryState {
    /// Returns whether the session is still active (not
    /// terminated/quarantined).
    #[must_use]
    pub const fn is_active(&self) -> bool {
        !self.terminated && !self.quarantined
    }

    /// Returns the best sequence ID to resume from.
    ///
    /// Prefers the last progress sequence ID if available, otherwise uses the
    /// last sequence ID.
    #[must_use]
    pub fn resume_cursor(&self) -> u64 {
        self.last_progress_seq_id.unwrap_or(self.last_seq_id)
    }
}

/// Collects session sequence IDs from events into a format suitable for
/// `restart_coordinator::find_last_session_cursor`.
#[must_use]
pub fn collect_session_cursors(events: &[EventRecord]) -> Vec<(u64, String)> {
    events
        .iter()
        .filter_map(|e| e.seq_id.map(|seq| (seq, e.session_id.clone())))
        .collect()
}

/// Groups events by session ID.
#[must_use]
pub fn group_by_session(events: &[EventRecord]) -> HashMap<String, Vec<&EventRecord>> {
    let mut groups: HashMap<String, Vec<&EventRecord>> = HashMap::new();
    for event in events {
        groups
            .entry(event.session_id.clone())
            .or_default()
            .push(event);
    }
    groups
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(
        seq_id: u64,
        session_id: &str,
        event_type: &str,
        timestamp_ns: u64,
    ) -> EventRecord {
        EventRecord::with_timestamp(event_type, session_id, "test-actor", vec![], timestamp_ns)
            .with_seq_id(seq_id)
    }

    #[test]
    fn test_find_last_session_cursor() {
        let events = vec![
            make_event(1, "session-1", "session.started", 1000),
            make_event(2, "session-1", "session.progress", 2000),
            make_event(3, "session-2", "session.started", 3000),
            make_event(4, "session-1", "session.progress", 4000),
        ];

        assert_eq!(find_last_session_cursor(&events, "session-1").unwrap(), 4);
        assert_eq!(find_last_session_cursor(&events, "session-2").unwrap(), 3);
        assert!(find_last_session_cursor(&events, "session-3").is_err());
    }

    #[test]
    fn test_find_last_progress_cursor() {
        let events = vec![
            make_event(1, "session-1", "session.started", 1000),
            make_event(2, "session-1", "session.progress", 2000),
            make_event(3, "session-1", "tool.request", 3000),
            make_event(4, "session-1", "session.progress", 4000),
            make_event(5, "session-1", "tool.response", 5000),
        ];

        assert_eq!(find_last_progress_cursor(&events, "session-1").unwrap(), 4);
    }

    #[test]
    fn test_replay_session_state() {
        let events = vec![
            make_event(1, "session-1", "session.started", 1_000_000),
            make_event(2, "session-1", "session.progress", 2_000_000),
            make_event(3, "session-1", "session.progress", 3_000_000),
            make_event(4, "session-1", "session.progress", 4_000_000),
        ];

        let state = replay_session_state(&events, "session-1", None).unwrap();
        assert_eq!(state.started_at, Some(1_000_000));
        assert_eq!(state.started_seq_id, Some(1));
        assert_eq!(state.last_seq_id, 4);
        assert_eq!(state.event_count, 4);
        assert_eq!(state.progress_count, 3);
        assert_eq!(state.last_progress_seq_id, Some(4));
        assert!(!state.terminated);
        assert!(state.is_active());
    }

    #[test]
    fn test_replay_session_state_up_to_seq_id() {
        let events = vec![
            make_event(1, "session-1", "session.started", 1_000_000),
            make_event(2, "session-1", "session.progress", 2_000_000),
            make_event(3, "session-1", "session.progress", 3_000_000),
            make_event(4, "session-1", "session.terminated", 4_000_000),
        ];

        // Replay only up to seq_id 2
        let state = replay_session_state(&events, "session-1", Some(2)).unwrap();
        assert_eq!(state.last_seq_id, 2);
        assert_eq!(state.progress_count, 1);
        assert!(!state.terminated);
    }

    #[test]
    fn test_replay_terminated_session() {
        let events = vec![
            make_event(1, "session-1", "session.started", 1_000_000),
            make_event(2, "session-1", "session.progress", 2_000_000),
            make_event(3, "session-1", "session.terminated", 3_000_000),
        ];

        let state = replay_session_state(&events, "session-1", None).unwrap();
        assert!(state.terminated);
        assert!(!state.is_active());
    }

    #[test]
    fn test_replay_quarantined_session() {
        let events = vec![
            make_event(1, "session-1", "session.started", 1_000_000),
            make_event(2, "session-1", "session.quarantined", 2_000_000),
        ];

        let state = replay_session_state(&events, "session-1", None).unwrap();
        assert!(state.quarantined);
        assert!(!state.is_active());
    }

    #[test]
    fn test_validate_recovery_point_valid() {
        let events = vec![
            make_event(1, "session-1", "session.started", 1_000_000),
            make_event(2, "session-1", "session.progress", 2_000_000),
            make_event(3, "session-1", "session.progress", 3_000_000),
        ];

        assert!(validate_recovery_point(&events, 2, "session-1").unwrap());
        assert!(validate_recovery_point(&events, 3, "session-1").unwrap());
    }

    #[test]
    fn test_validate_recovery_point_after_termination() {
        let events = vec![
            make_event(1, "session-1", "session.started", 1_000_000),
            make_event(2, "session-1", "session.terminated", 2_000_000),
            make_event(3, "session-1", "session.progress", 3_000_000),
        ];

        // Seq_id 3 is invalid because session was terminated at seq_id 2
        assert!(!validate_recovery_point(&events, 3, "session-1").unwrap());
    }

    #[test]
    fn test_validate_recovery_point_session_not_found() {
        let events = vec![make_event(1, "session-1", "session.started", 1_000_000)];

        assert!(validate_recovery_point(&events, 1, "session-2").is_err());
    }

    #[test]
    fn test_validate_recovery_point_seq_id_not_found() {
        let events = vec![
            make_event(1, "session-1", "session.started", 1_000_000),
            make_event(2, "session-1", "session.progress", 2_000_000),
        ];

        assert!(validate_recovery_point(&events, 99, "session-1").is_err());
    }

    #[test]
    fn test_count_events_since() {
        let events = vec![
            make_event(1, "session-1", "session.started", 1_000_000),
            make_event(2, "session-1", "session.progress", 2_000_000),
            make_event(3, "session-1", "session.progress", 3_000_000),
            make_event(4, "session-2", "session.started", 4_000_000),
            make_event(5, "session-1", "session.progress", 5_000_000),
        ];

        assert_eq!(count_events_since(&events, "session-1", 0), 4);
        assert_eq!(count_events_since(&events, "session-1", 2), 2);
        assert_eq!(count_events_since(&events, "session-1", 5), 0);
        assert_eq!(count_events_since(&events, "session-2", 0), 1);
    }

    #[test]
    fn test_resume_cursor() {
        let state = SessionRecoveryState {
            last_seq_id: 10,
            last_progress_seq_id: Some(8),
            ..Default::default()
        };
        assert_eq!(state.resume_cursor(), 8);

        let state_no_progress = SessionRecoveryState {
            last_seq_id: 10,
            last_progress_seq_id: None,
            ..Default::default()
        };
        assert_eq!(state_no_progress.resume_cursor(), 10);
    }

    #[test]
    fn test_collect_session_cursors() {
        let events = vec![
            make_event(1, "session-1", "session.started", 1_000_000),
            make_event(2, "session-2", "session.started", 2_000_000),
            make_event(3, "session-1", "session.progress", 3_000_000),
        ];

        let cursors = collect_session_cursors(&events);
        assert_eq!(cursors.len(), 3);
        assert!(cursors.contains(&(1, "session-1".to_string())));
        assert!(cursors.contains(&(2, "session-2".to_string())));
        assert!(cursors.contains(&(3, "session-1".to_string())));
    }

    #[test]
    fn test_group_by_session() {
        let events = vec![
            make_event(1, "session-1", "session.started", 1_000_000),
            make_event(2, "session-2", "session.started", 2_000_000),
            make_event(3, "session-1", "session.progress", 3_000_000),
        ];

        let groups = group_by_session(&events);
        assert_eq!(groups.len(), 2);
        assert_eq!(groups.get("session-1").unwrap().len(), 2);
        assert_eq!(groups.get("session-2").unwrap().len(), 1);
    }
}
