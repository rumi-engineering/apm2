//! Ledger observation traits and cursor-generic helpers.
//!
//! Cursors are ledger-specific.  The kernel requires only [`Ord`] to compare
//! and advance cursors; the concrete cursor type is chosen by each
//! [`LedgerReader`] implementation.
//! [`CompositeCursor`](super::types::CompositeCursor) remains the default for
//! timestamp + event-id ledgers.

use crate::orchestrator_kernel::types::KernelCursor;

/// Trait for event types that expose a cursor for ordering.
///
/// The cursor type `C` must implement [`KernelCursor`] and its total order
/// must be consistent with the ledger reader's returned event order.
pub trait CursorEvent<C: KernelCursor> {
    /// Returns the cursor position of this event.
    fn cursor(&self) -> C;
}

/// Returns `true` when `event` is strictly after `cursor` using `Ord`.
#[must_use]
pub fn is_after_cursor<C: KernelCursor, E: CursorEvent<C>>(event: &E, cursor: &C) -> bool {
    event.cursor() > *cursor
}

/// Returns the next cursor obtained by advancing with `event`.
///
/// Takes the maximum of the current cursor and the event's cursor.
#[must_use]
pub fn advance_cursor_with_event<C: KernelCursor, E: CursorEvent<C>>(cursor: &C, event: &E) -> C {
    let event_cursor = event.cursor();
    if event_cursor > *cursor {
        event_cursor
    } else {
        cursor.clone()
    }
}

/// Deterministically sorts events by cursor order and truncates to `limit`.
#[must_use]
pub fn sort_and_truncate_events<C: KernelCursor, E: CursorEvent<C>>(
    mut events: Vec<E>,
    limit: usize,
) -> Vec<E> {
    events.sort_by_key(CursorEvent::cursor);
    events.truncate(limit);
    events
}

/// Read-only ledger poll contract for kernel Observe phase.
///
/// The associated `Cursor` type determines the cursor used for ordering
/// and checkpointing.
#[allow(async_fn_in_trait)]
pub trait LedgerReader<Event>: Send + Sync {
    /// Cursor type for this ledger.
    type Cursor: KernelCursor;

    /// Reader-specific error type.
    type Error;

    /// Polls events strictly after `cursor`, bounded by `limit`.
    async fn poll(&self, cursor: &Self::Cursor, limit: usize) -> Result<Vec<Event>, Self::Error>;
}

/// Durable cursor storage contract.
///
/// The cursor type `C` must implement [`KernelCursor`] for serialization
/// and ordering guarantees.
#[allow(async_fn_in_trait)]
pub trait CursorStore<C: KernelCursor>: Send + Sync {
    /// Store-specific error type.
    type Error;

    /// Loads the latest durable cursor.
    async fn load(&self) -> Result<C, Self::Error>;

    /// Saves the latest durable cursor.
    async fn save(&self, cursor: &C) -> Result<(), Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orchestrator_kernel::types::CompositeCursor;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct TestEvent {
        timestamp_ns: u64,
        event_id: &'static str,
    }

    impl CursorEvent<CompositeCursor> for TestEvent {
        fn cursor(&self) -> CompositeCursor {
            CompositeCursor {
                timestamp_ns: self.timestamp_ns,
                event_id: self.event_id.to_string(),
            }
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
        let ids: Vec<String> = sorted.iter().map(|e| e.cursor().event_id).collect();
        assert_eq!(
            ids,
            vec![
                "legacy-aaa",
                "canonical-00000000000000000002",
                "canonical-00000000000000000010",
            ]
        );
    }

    /// Verify that `CompositeCursor`'s derived `Ord` is consistent with the
    /// legacy manual `(timestamp_ns, event_id)` comparison.
    #[test]
    fn composite_cursor_ord_is_consistent_with_legacy_manual_comparison() {
        let a = CompositeCursor {
            timestamp_ns: 100,
            event_id: "evt-001".to_string(),
        };
        let b = CompositeCursor {
            timestamp_ns: 100,
            event_id: "evt-002".to_string(),
        };
        let c = CompositeCursor {
            timestamp_ns: 101,
            event_id: "evt-000".to_string(),
        };

        assert!(a < b, "same ts, smaller event_id should be less");
        assert!(b < c, "smaller ts should be less regardless of event_id");
        assert!(a < c);
    }

    /// Verify `advance_cursor_with_event` takes the maximum cursor.
    #[test]
    fn advance_cursor_takes_max() {
        let cursor = CompositeCursor {
            timestamp_ns: 50,
            event_id: "evt-005".to_string(),
        };
        let earlier = TestEvent {
            timestamp_ns: 49,
            event_id: "evt-999",
        };
        let same = TestEvent {
            timestamp_ns: 50,
            event_id: "evt-005",
        };
        let later = TestEvent {
            timestamp_ns: 50,
            event_id: "evt-006",
        };

        assert_eq!(advance_cursor_with_event(&cursor, &earlier), cursor);
        assert_eq!(advance_cursor_with_event(&cursor, &same), cursor);
        let advanced = advance_cursor_with_event(&cursor, &later);
        assert_eq!(advanced.timestamp_ns, 50);
        assert_eq!(advanced.event_id, "evt-006");
    }
}
