//! Ledger observation traits and composite cursor helpers.

use crate::orchestrator_kernel::types::CompositeCursor;

/// Trait for event types that can be ordered by composite cursor.
pub trait CursorEvent {
    /// Event timestamp in nanoseconds since Unix epoch.
    fn timestamp_ns(&self) -> u64;
    /// Stable event identifier used as tie-breaker within equal timestamps.
    fn event_id(&self) -> &str;
}

/// Returns `true` when `event` is strictly after `cursor`.
#[must_use]
pub fn is_after_cursor<E: CursorEvent>(event: &E, cursor: &CompositeCursor) -> bool {
    event.timestamp_ns() > cursor.timestamp_ns
        || (event.timestamp_ns() == cursor.timestamp_ns
            && event.event_id() > cursor.event_id.as_str())
}

/// Returns the next cursor obtained by advancing with `event`.
#[must_use]
pub fn advance_cursor_with_event<E: CursorEvent>(
    cursor: &CompositeCursor,
    event: &E,
) -> CompositeCursor {
    if is_after_cursor(event, cursor) {
        CompositeCursor {
            timestamp_ns: event.timestamp_ns(),
            event_id: event.event_id().to_string(),
        }
    } else {
        cursor.clone()
    }
}

/// Deterministically sorts events by `(timestamp_ns, event_id)` and truncates
/// to `limit`.
#[must_use]
pub fn sort_and_truncate_events<E: CursorEvent>(mut events: Vec<E>, limit: usize) -> Vec<E> {
    events.sort_by(|a, b| {
        a.timestamp_ns()
            .cmp(&b.timestamp_ns())
            .then_with(|| a.event_id().cmp(b.event_id()))
    });
    events.truncate(limit);
    events
}

/// Read-only ledger poll contract for kernel Observe phase.
#[allow(async_fn_in_trait)]
pub trait LedgerReader<Event>: Send + Sync {
    /// Reader-specific error type.
    type Error;

    /// Polls events strictly after `cursor`, bounded by `limit`.
    async fn poll(&self, cursor: &CompositeCursor, limit: usize)
    -> Result<Vec<Event>, Self::Error>;
}

/// Durable cursor storage contract.
#[allow(async_fn_in_trait)]
pub trait CursorStore: Send + Sync {
    /// Store-specific error type.
    type Error;

    /// Loads the latest durable cursor.
    async fn load(&self) -> Result<CompositeCursor, Self::Error>;

    /// Saves the latest durable cursor.
    async fn save(&self, cursor: &CompositeCursor) -> Result<(), Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct TestEvent {
        timestamp_ns: u64,
        event_id: &'static str,
    }

    impl CursorEvent for TestEvent {
        fn timestamp_ns(&self) -> u64 {
            self.timestamp_ns
        }

        fn event_id(&self) -> &str {
            self.event_id
        }
    }

    #[test]
    fn composite_cursor_disambiguates_timestamp_collisions() {
        let cursor = CompositeCursor {
            timestamp_ns: 100,
            event_id: "evt-010".to_string(),
        };
        let prior = TestEvent {
            timestamp_ns: 100,
            event_id: "evt-009",
        };
        let equal = TestEvent {
            timestamp_ns: 100,
            event_id: "evt-010",
        };
        let next = TestEvent {
            timestamp_ns: 100,
            event_id: "evt-011",
        };
        let later_ts = TestEvent {
            timestamp_ns: 101,
            event_id: "evt-001",
        };

        assert!(!is_after_cursor(&prior, &cursor));
        assert!(!is_after_cursor(&equal, &cursor));
        assert!(is_after_cursor(&next, &cursor));
        assert!(is_after_cursor(&later_ts, &cursor));
    }

    #[test]
    fn sort_and_truncate_preserves_zero_padded_lexical_order() {
        let events = vec![
            TestEvent {
                timestamp_ns: 50,
                event_id: "canonical-00000000000000000010",
            },
            TestEvent {
                timestamp_ns: 50,
                event_id: "legacy-zzz",
            },
            TestEvent {
                timestamp_ns: 50,
                event_id: "canonical-00000000000000000002",
            },
            TestEvent {
                timestamp_ns: 49,
                event_id: "legacy-aaa",
            },
        ];

        let sorted = sort_and_truncate_events(events, 3);
        let ids: Vec<&str> = sorted.iter().map(CursorEvent::event_id).collect();
        assert_eq!(
            ids,
            vec![
                "legacy-aaa",
                "canonical-00000000000000000002",
                "canonical-00000000000000000010",
            ]
        );
    }
}
