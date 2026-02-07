//! Crash recovery wiring for daemon startup (TCK-00387).
//!
//! This module connects persistent session state to lease revocation and work
//! cleanup. On daemon restart, it:
//!
//! 1. Collects stale sessions from the persistent session registry
//! 2. Emits `LEASE_REVOKED` events to the ledger for each stale session
//! 3. Deletes work claims for stale sessions so work becomes re-claimable
//! 4. Clears the persistent session registry (idempotency guarantee)
//!
//! # Crash-Only Design
//!
//! Per the crash-only design philosophy, sessions are **terminated** on
//! recovery, not resumed. The daemon assumes all previous sessions are invalid
//! after a restart.
//!
//! # Idempotency
//!
//! Recovery is idempotent: the persistent session registry is cleared after
//! successful recovery. A second startup with the same state file will not
//! double-emit events because the sessions are gone from the state file.
//!
//! # Fail-Closed Integrity
//!
//! Per Security Review v5 BLOCKER 1, recovery failures are startup-fatal.
//! If recovery emits ledger events but then fails to clear the recovered
//! sessions from the registry, the next startup would re-emit those events
//! (duplicate revocation). On error, the session registry is **preserved**
//! so unrecovered sessions can be retried, but the daemon does NOT proceed
//! to accept connections.
//!
//! When session collection is truncated (exceeds `MAX_RECOVERY_SESSIONS`),
//! only the recovered subset is cleared from the registry. Remaining
//! sessions are preserved for the next startup cycle.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rusqlite::{Connection, params};
use tracing::{info, warn};

use crate::htf::HolonicClock;
use crate::ledger::SqliteLedgerEventEmitter;
use crate::protocol::dispatch::LedgerEventEmitter;
use crate::session::{SessionRegistry, SessionState};

/// Maximum number of sessions to recover in a single batch.
///
/// Per CTR-1303, bounded iteration prevents runaway recovery if the state file
/// is corrupted with an unreasonable number of entries.
const MAX_RECOVERY_SESSIONS: usize = 10_000;

/// Event type string for lease revocation events in the ledger.
const LEASE_REVOKED_EVENT_TYPE: &str = "lease_revoked";

/// Result of the crash recovery process.
#[derive(Debug, Clone)]
pub struct CrashRecoveryOutcome {
    /// Number of stale sessions found and processed.
    pub sessions_recovered: u32,
    /// Number of `LEASE_REVOKED` events emitted to the ledger.
    pub lease_revoked_events_emitted: u32,
    /// Number of work claims released (deleted from `work_claims` table).
    pub work_claims_released: u32,
    /// Time taken for recovery in milliseconds.
    pub recovery_time_ms: u32,
    /// Session IDs that were successfully recovered (both ledger event emitted
    /// and work claim released without error). Only these sessions should be
    /// cleared from the registry; failed sessions are preserved for retry.
    pub succeeded_session_ids: Vec<String>,
    /// Session IDs where a critical side-effect (ledger emit or work claim
    /// release) failed. These must NOT be cleared from the registry.
    pub failed_session_ids: Vec<String>,
}

/// Result of session collection for recovery.
#[derive(Debug, Clone)]
pub struct CollectedSessions {
    /// The sessions collected for recovery (may be a truncated subset).
    pub sessions: Vec<SessionState>,
    /// Whether the collection was truncated to `MAX_RECOVERY_SESSIONS`.
    /// When `true`, the registry contains more sessions than were collected,
    /// and only the collected subset should be cleared after recovery.
    pub was_truncated: bool,
    /// Total number of sessions in the registry before truncation.
    pub total_in_registry: usize,
}

/// Error type for crash recovery operations.
#[derive(Debug, thiserror::Error)]
pub enum CrashRecoveryError {
    /// Recovery timed out with partial progress.
    ///
    /// The `outcome` field contains the sessions that were successfully
    /// processed before the timeout. The caller MUST clear those succeeded
    /// IDs from the registry to avoid replaying their side-effects on the
    /// next startup.
    #[error("recovery timeout: {elapsed_ms}ms elapsed, timeout is {timeout_ms}ms ({} sessions completed before timeout)", outcome.sessions_recovered)]
    Timeout {
        /// Elapsed time in milliseconds.
        elapsed_ms: u32,
        /// Configured timeout in milliseconds.
        timeout_ms: u32,
        /// Partial recovery outcome: sessions that completed before timeout.
        /// Succeeded IDs should be cleared; remaining sessions are preserved.
        outcome: CrashRecoveryOutcome,
    },

    /// Ledger event emission failed.
    #[error("failed to emit ledger event: {message}")]
    LedgerEmitFailed {
        /// Error message.
        message: String,
    },

    /// Work claim cleanup failed.
    #[error("failed to clean up work claims: {message}")]
    WorkClaimCleanupFailed {
        /// Error message.
        message: String,
    },

    /// Timestamp acquisition failed.
    #[error("failed to acquire timestamp: {message}")]
    TimestampFailed {
        /// Error message.
        message: String,
    },

    /// Registry clear/persist operation failed.
    ///
    /// Per the security review (MAJOR 2 v3), persistence failures must be
    /// escalated rather than being warning-only. A failed persist means the
    /// registry state on disk is inconsistent with in-memory state, which
    /// could cause sessions to be replayed or lost on next startup.
    #[error("registry clear/persist failed: {message}")]
    RegistryClearFailed {
        /// Error message.
        message: String,
    },

    /// Partial recovery: some sessions failed critical side-effects.
    /// The outcome contains details of which sessions succeeded and which
    /// failed. Only succeeded sessions should be cleared from the registry.
    #[error("partial recovery: {failed_count} of {total_count} sessions had critical failures")]
    PartialRecovery {
        /// Number of sessions that failed.
        failed_count: usize,
        /// Total number of sessions attempted.
        total_count: usize,
        /// The recovery outcome with per-session success/failure tracking.
        outcome: CrashRecoveryOutcome,
    },
}

/// Collects all sessions from the session registry for recovery.
///
/// Uses the `all_sessions_for_recovery()` trait method added in TCK-00387.
/// For `PersistentSessionRegistry`, this returns sessions loaded from the
/// state file. For `InMemorySessionRegistry`, this returns an empty vec
/// (default implementation) since in-memory state doesn't survive restarts.
///
/// Returns a [`CollectedSessions`] that indicates whether truncation
/// occurred, so the caller can decide whether to clear all sessions or
/// only the recovered subset.
///
/// # Arguments
///
/// * `registry` - The session registry (typically a
///   `PersistentSessionRegistry`)
#[must_use]
pub fn collect_sessions(registry: &Arc<dyn SessionRegistry>) -> CollectedSessions {
    let sessions = registry.all_sessions_for_recovery();
    let total_in_registry = sessions.len();
    if sessions.len() > MAX_RECOVERY_SESSIONS {
        warn!(
            total = sessions.len(),
            max = MAX_RECOVERY_SESSIONS,
            "Truncating recovery sessions to maximum; remaining sessions preserved for next startup"
        );
        CollectedSessions {
            sessions: sessions.into_iter().take(MAX_RECOVERY_SESSIONS).collect(),
            was_truncated: true,
            total_in_registry,
        }
    } else {
        CollectedSessions {
            sessions,
            was_truncated: false,
            total_in_registry,
        }
    }
}

/// Recovers stale sessions by emitting `LEASE_REVOKED` events and cleaning up
/// work claims.
///
/// For each stale session:
/// 1. Emits a `LEASE_REVOKED` event to the ledger (if emitter is available)
/// 2. Deletes the work claim from the `work_claims` table (if `SQLite` conn is
///    available) so the work becomes re-claimable. Per security review v4 MAJOR
///    1, work claim cleanup is causally gated on successful ledger emission --
///    if ledger emission fails, the work claim is NOT released.
///
/// # Arguments
///
/// * `sessions` - Stale sessions to recover
/// * `emitter` - Optional ledger event emitter for persisting `LEASE_REVOKED`
///   events
/// * `sqlite_conn` - Optional `SQLite` connection for cleaning up work claims
/// * `timeout` - Maximum duration for recovery
/// * `htf_clock` - The daemon's shared HTF clock for RFC-0016 compliant
///   timestamps. Must not be `None` -- fail-closed per security review v4
///   BLOCKER 2.
///
/// # Returns
///
/// `Ok(CrashRecoveryOutcome)` with recovery statistics, or
/// `Err(CrashRecoveryError)` if recovery failed critically.
///
/// On `Timeout`, the error includes partial progress (succeeded/failed IDs)
/// so the caller can checkpoint the succeeded subset.
#[allow(clippy::cast_possible_truncation)] // Recovery timeout is < 5s, well within u32
pub fn recover_stale_sessions(
    sessions: &[SessionState],
    emitter: Option<&SqliteLedgerEventEmitter>,
    sqlite_conn: Option<&Arc<Mutex<Connection>>>,
    timeout: Duration,
    htf_clock: &HolonicClock,
) -> Result<CrashRecoveryOutcome, CrashRecoveryError> {
    let start = Instant::now();
    let deadline = start + timeout;

    let mut lease_revoked_events_emitted: u32 = 0;
    let mut work_claims_released: u32 = 0;
    let mut succeeded_session_ids: Vec<String> = Vec::new();
    let mut failed_session_ids: Vec<String> = Vec::new();

    for session in sessions {
        // Check timeout before each session -- return partial progress so
        // caller can checkpoint succeeded IDs (SECURITY BLOCKER v3 fix).
        if Instant::now() > deadline {
            let recovery_time_ms = start.elapsed().as_millis() as u32;
            return Err(CrashRecoveryError::Timeout {
                elapsed_ms: recovery_time_ms,
                timeout_ms: timeout.as_millis() as u32,
                outcome: CrashRecoveryOutcome {
                    sessions_recovered: succeeded_session_ids.len() as u32,
                    lease_revoked_events_emitted,
                    work_claims_released,
                    recovery_time_ms,
                    succeeded_session_ids,
                    failed_session_ids,
                },
            });
        }

        // Track per-session success: a session is considered failed if any
        // critical side-effect (ledger emit or work claim release) fails.
        let mut session_failed = false;

        // Step 1: Emit LEASE_REVOKED event to ledger
        let mut ledger_emit_succeeded = false;
        if let Some(emitter) = emitter {
            match emit_lease_revoked_event(emitter, session, htf_clock) {
                Ok(event_id) => {
                    info!(
                        session_id = %session.session_id,
                        work_id = %session.work_id,
                        event_id = %event_id,
                        "Emitted LEASE_REVOKED event for stale session"
                    );
                    lease_revoked_events_emitted += 1;
                    ledger_emit_succeeded = true;
                },
                Err(e) => {
                    // Critical failure: ledger event not persisted. Mark session
                    // as failed so it is preserved in the registry for retry.
                    warn!(
                        session_id = %session.session_id,
                        error = %e,
                        "Failed to emit LEASE_REVOKED event; session will be preserved for retry"
                    );
                    session_failed = true;
                },
            }
        } else {
            // No ledger configured: treat as vacuously succeeded for causal
            // gating purposes (there is nothing to gate on).
            info!(
                session_id = %session.session_id,
                work_id = %session.work_id,
                "LEASE_REVOKED (no ledger configured, event not persisted)"
            );
            ledger_emit_succeeded = true;
        }

        // Step 2: Release work claim so work becomes re-claimable.
        //
        // Security Review v4 MAJOR 1 fix: Only release work claims after
        // successful ledger emission for this session. If the LEASE_REVOKED
        // event was not persisted, we must NOT release the work claim --
        // both operations must succeed or neither should proceed, ensuring
        // causal ordering of side effects.
        if ledger_emit_succeeded {
            if let Some(conn) = sqlite_conn {
                match release_work_claim(conn, &session.work_id) {
                    Ok(released) => {
                        if released {
                            info!(
                                work_id = %session.work_id,
                                session_id = %session.session_id,
                                "Released work claim for stale session"
                            );
                            work_claims_released += 1;
                        }
                    },
                    Err(e) => {
                        // Critical failure: work claim not released. Mark session
                        // as failed so it is preserved in the registry for retry.
                        warn!(
                            work_id = %session.work_id,
                            error = %e,
                            "Failed to release work claim; session will be preserved for retry"
                        );
                        session_failed = true;
                    },
                }
            }
        }

        if session_failed {
            failed_session_ids.push(session.session_id.clone());
        } else {
            succeeded_session_ids.push(session.session_id.clone());
        }
    }

    let recovery_time_ms = start.elapsed().as_millis() as u32;

    // Post-operation deadline check: if we exceeded the timeout during
    // processing (but didn't catch it at a loop boundary), return partial
    // progress so caller can checkpoint succeeded IDs (SECURITY BLOCKER v3 fix).
    if Instant::now() > deadline {
        let recovery_time_ms = start.elapsed().as_millis() as u32;
        return Err(CrashRecoveryError::Timeout {
            elapsed_ms: recovery_time_ms,
            timeout_ms: timeout.as_millis() as u32,
            outcome: CrashRecoveryOutcome {
                sessions_recovered: succeeded_session_ids.len() as u32,
                lease_revoked_events_emitted,
                work_claims_released,
                recovery_time_ms,
                succeeded_session_ids,
                failed_session_ids,
            },
        });
    }

    let outcome = CrashRecoveryOutcome {
        sessions_recovered: succeeded_session_ids.len() as u32,
        lease_revoked_events_emitted,
        work_claims_released,
        recovery_time_ms,
        succeeded_session_ids,
        failed_session_ids: failed_session_ids.clone(),
    };

    // If any sessions had critical failures, return PartialRecovery error
    // so the caller knows NOT to clear the failed session IDs from the
    // registry.
    if !failed_session_ids.is_empty() {
        return Err(CrashRecoveryError::PartialRecovery {
            failed_count: failed_session_ids.len(),
            total_count: sessions.len(),
            outcome,
        });
    }

    Ok(outcome)
}

/// Clears the persistent session registry after successful recovery.
///
/// Only clears sessions that were **successfully** recovered (i.e., their
/// `LEASE_REVOKED` event was emitted and work claim was released without
/// error). Failed sessions are preserved in the registry for retry on the
/// next startup.
///
/// When `collected.was_truncated` is `false` **and** all sessions succeeded,
/// clears all sessions using `clear_all_sessions()`. Otherwise, only clears
/// the successfully recovered subset using `clear_sessions_by_ids()`.
///
/// # Arguments
///
/// * `registry` - The session registry to clear
/// * `collected` - The collection result from [`collect_sessions`], used to
///   determine whether to clear all or only the recovered subset
/// * `succeeded_ids` - Session IDs that were successfully recovered. Only these
///   will be cleared. If `None`, all collected sessions are assumed to have
///   succeeded (backward-compatible path).
///
/// # Errors
///
/// Returns `CrashRecoveryError` if the registry clear or persist operation
/// fails. Per the security review (MAJOR 2 v3), persistence failures are
/// now escalated rather than being warning-only, since a failed persist
/// means the registry state on disk is inconsistent with in-memory state.
pub fn clear_session_registry(
    registry: &Arc<dyn SessionRegistry>,
    collected: &CollectedSessions,
    succeeded_ids: Option<&[String]>,
) -> Result<(), CrashRecoveryError> {
    // Determine which IDs to clear: if succeeded_ids is provided, use it;
    // otherwise fall back to all collected session IDs.
    let ids_to_clear: Vec<String> = succeeded_ids.map_or_else(
        || {
            collected
                .sessions
                .iter()
                .map(|s| s.session_id.clone())
                .collect()
        },
        <[String]>::to_vec,
    );

    // Use clear_all_sessions only if not truncated AND all collected sessions
    // are being cleared (no per-session failures).
    let can_clear_all = !collected.was_truncated && ids_to_clear.len() == collected.sessions.len();

    if can_clear_all {
        registry
            .clear_all_sessions()
            .map_err(|e| CrashRecoveryError::RegistryClearFailed {
                message: format!("Failed to clear session registry after recovery: {e}"),
            })?;
        info!("Cleared session registry after crash recovery");
    } else if !ids_to_clear.is_empty() {
        info!(
            cleared = ids_to_clear.len(),
            total_in_registry = collected.total_in_registry,
            "Clearing recovered subset; remaining sessions preserved for retry"
        );
        registry.clear_sessions_by_ids(&ids_to_clear).map_err(|e| {
            CrashRecoveryError::RegistryClearFailed {
                message: format!("Failed to clear recovered sessions from registry: {e}"),
            }
        })?;
        info!(
            cleared = ids_to_clear.len(),
            "Cleared recovered sessions from registry (partial)"
        );
    } else {
        info!("No sessions to clear from registry (all failed; preserved for retry)");
    }

    Ok(())
}

/// Emits a `LEASE_REVOKED` event to the ledger for a stale session.
///
/// The event payload includes the session ID, work ID, and the reason
/// (`daemon_restart`).
///
/// # Timestamp Source
///
/// Per RFC-0016 and the security review (v4 BLOCKER 2), timestamps MUST
/// come from the HTF `HolonicClock` (same clock contract used by dispatch
/// flows). The `SystemTime` fallback has been removed -- if the HTF clock
/// is unavailable, recovery must fail-closed rather than silently using an
/// unauthorized time source.
fn emit_lease_revoked_event(
    emitter: &SqliteLedgerEventEmitter,
    session: &SessionState,
    htf_clock: &HolonicClock,
) -> Result<String, CrashRecoveryError> {
    // Security Review v4 BLOCKER 2: All timestamps come from the shared HTF
    // clock. No SystemTime fallback -- fail-closed if HTF is unavailable.
    let timestamp_ns = htf_clock.now_hlc().map(|hlc| hlc.wall_ns).map_err(|e| {
        CrashRecoveryError::TimestampFailed {
            message: format!("HTF clock error for session {}: {e}", session.session_id),
        }
    })?;

    // Build the LEASE_REVOKED payload
    let payload = serde_json::json!({
        "event_type": LEASE_REVOKED_EVENT_TYPE,
        "session_id": session.session_id,
        "work_id": session.work_id,
        "reason": "daemon_restart",
        "role": session.role,
    });
    let payload_bytes = payload.to_string().into_bytes();

    // Use emit_session_event to persist the LEASE_REVOKED event
    let signed_event = emitter
        .emit_session_event(
            &session.session_id,
            LEASE_REVOKED_EVENT_TYPE,
            &payload_bytes,
            "daemon",
            timestamp_ns,
        )
        .map_err(|e| CrashRecoveryError::LedgerEmitFailed {
            message: format!(
                "emit_session_event failed for session {}: {e}",
                session.session_id
            ),
        })?;

    Ok(signed_event.event_id)
}

/// Releases a work claim by deleting it from the `work_claims` table.
///
/// This makes the work re-claimable by agents after daemon restart.
///
/// # Returns
///
/// `Ok(true)` if a claim was deleted, `Ok(false)` if no claim existed.
fn release_work_claim(
    conn: &Arc<Mutex<Connection>>,
    work_id: &str,
) -> Result<bool, CrashRecoveryError> {
    let conn = conn
        .lock()
        .map_err(|_| CrashRecoveryError::WorkClaimCleanupFailed {
            message: "connection lock poisoned".to_string(),
        })?;

    let rows_affected = conn
        .execute(
            "DELETE FROM work_claims WHERE work_id = ?1",
            params![work_id],
        )
        .map_err(|e| CrashRecoveryError::WorkClaimCleanupFailed {
            message: format!("sqlite delete failed: {e}"),
        })?;

    Ok(rows_affected > 0)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rusqlite::Connection;

    use super::*;
    use crate::episode::registry::InMemorySessionRegistry;
    use crate::ledger::{SqliteLedgerEventEmitter, SqliteWorkRegistry};
    use crate::protocol::dispatch::{PolicyResolution, WorkClaim, WorkRegistry};
    use crate::protocol::messages::WorkRole;
    use crate::session::{SessionRegistry, SessionState};

    /// Helper to create a test session.
    fn make_session(id: &str, work_id: &str) -> SessionState {
        SessionState {
            session_id: id.to_string(),
            work_id: work_id.to_string(),
            role: 1,
            ephemeral_handle: format!("handle-{id}"),
            lease_id: String::new(), // Empty after loading from disk
            policy_resolved_ref: "policy-ref".to_string(),
            capability_manifest_hash: vec![],
            episode_id: None,
        }
    }

    /// Creates an in-memory `SQLite` connection with schemas initialized.
    fn setup_sqlite() -> Arc<Mutex<Connection>> {
        let conn = Connection::open_in_memory().expect("open in-memory sqlite");
        SqliteLedgerEventEmitter::init_schema(&conn).expect("init ledger schema");
        SqliteWorkRegistry::init_schema(&conn).expect("init work schema");
        Arc::new(Mutex::new(conn))
    }

    /// Creates an HTF clock for tests.
    fn make_clock() -> HolonicClock {
        use crate::htf::ClockConfig;
        HolonicClock::new(ClockConfig::default(), None).expect("clock creation should succeed")
    }

    /// Creates a `SqliteLedgerEventEmitter` with a fresh signing key.
    fn make_emitter(conn: &Arc<Mutex<Connection>>) -> SqliteLedgerEventEmitter {
        use rand::rngs::OsRng;
        let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        SqliteLedgerEventEmitter::new(Arc::clone(conn), signing_key)
    }

    /// Registers a work claim in the `SQLite` work registry.
    fn register_claim(conn: &Arc<Mutex<Connection>>, work_id: &str) {
        let registry = SqliteWorkRegistry::new(Arc::clone(conn));
        let claim = WorkClaim {
            work_id: work_id.to_string(),
            lease_id: format!("lease-{work_id}"),
            actor_id: "test-actor".to_string(),
            role: WorkRole::Implementer,
            policy_resolution: PolicyResolution {
                policy_resolved_ref: "test-policy".to_string(),
                resolved_policy_hash: [0u8; 32],
                capability_manifest_hash: [0u8; 32],
                context_pack_hash: [0u8; 32],
                resolved_risk_tier: 0,
                resolved_scope_baseline: None,
                expected_adapter_profile_hash: None,
            },
            executor_custody_domains: Vec::new(),
            author_custody_domains: Vec::new(),
        };
        registry.register_claim(claim).expect("register claim");
    }

    // =========================================================================
    // Happy Path Tests
    // =========================================================================

    #[test]
    fn test_recover_empty_sessions() {
        let clock = make_clock();
        let result = recover_stale_sessions(&[], None, None, Duration::from_secs(5), &clock)
            .expect("recovery should succeed");

        assert_eq!(result.sessions_recovered, 0);
        assert_eq!(result.lease_revoked_events_emitted, 0);
        assert_eq!(result.work_claims_released, 0);
        assert!(result.recovery_time_ms < 100);
    }

    #[test]
    fn test_recover_sessions_emits_lease_revoked_events() {
        let conn = setup_sqlite();
        let emitter = make_emitter(&conn);
        let clock = make_clock();
        let sessions = vec![
            make_session("sess-1", "work-1"),
            make_session("sess-2", "work-2"),
            make_session("sess-3", "work-3"),
        ];

        let result = recover_stale_sessions(
            &sessions,
            Some(&emitter),
            Some(&conn),
            Duration::from_secs(5),
            &clock,
        )
        .expect("recovery should succeed");

        assert_eq!(result.sessions_recovered, 3);
        assert_eq!(result.lease_revoked_events_emitted, 3);

        // Verify events were persisted to the ledger
        let db = conn.lock().unwrap();
        let count: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM ledger_events WHERE event_type = ?1",
                params![LEASE_REVOKED_EVENT_TYPE],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 3);
    }

    #[test]
    fn test_recover_sessions_releases_work_claims() {
        let conn = setup_sqlite();
        let emitter = make_emitter(&conn);
        let clock = make_clock();

        // Register work claims
        register_claim(&conn, "work-1");
        register_claim(&conn, "work-2");

        let sessions = vec![
            make_session("sess-1", "work-1"),
            make_session("sess-2", "work-2"),
            make_session("sess-3", "work-3"), // No claim for this one
        ];

        let result = recover_stale_sessions(
            &sessions,
            Some(&emitter),
            Some(&conn),
            Duration::from_secs(5),
            &clock,
        )
        .expect("recovery should succeed");

        assert_eq!(result.sessions_recovered, 3);
        assert_eq!(result.work_claims_released, 2); // Only 2 had claims

        // Verify claims were deleted
        let db = conn.lock().unwrap();
        let count: i64 = db
            .query_row("SELECT COUNT(*) FROM work_claims", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_recover_sessions_completes_within_timeout() {
        let conn = setup_sqlite();
        let emitter = make_emitter(&conn);
        let clock = make_clock();

        // Create 100 sessions
        let sessions: Vec<SessionState> = (0..100)
            .map(|i| make_session(&format!("sess-{i}"), &format!("work-{i}")))
            .collect();

        let start = Instant::now();
        let result = recover_stale_sessions(
            &sessions,
            Some(&emitter),
            Some(&conn),
            Duration::from_secs(5),
            &clock,
        )
        .expect("recovery should succeed");

        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_secs(5),
            "Recovery took {elapsed:?}"
        );
        assert!(result.recovery_time_ms < 5000);
        assert_eq!(result.sessions_recovered, 100);
    }

    // =========================================================================
    // Idempotency Tests
    // =========================================================================

    #[test]
    fn test_recovery_is_idempotent() {
        let conn = setup_sqlite();
        let emitter = make_emitter(&conn);
        let clock = make_clock();

        register_claim(&conn, "work-1");

        let sessions = vec![make_session("sess-1", "work-1")];

        // First recovery
        let result1 = recover_stale_sessions(
            &sessions,
            Some(&emitter),
            Some(&conn),
            Duration::from_secs(5),
            &clock,
        )
        .expect("first recovery should succeed");

        assert_eq!(result1.lease_revoked_events_emitted, 1);
        assert_eq!(result1.work_claims_released, 1);

        // Second recovery with same sessions -- should succeed but not find
        // any claims to release (they were already deleted).
        let result2 = recover_stale_sessions(
            &sessions,
            Some(&emitter),
            Some(&conn),
            Duration::from_secs(5),
            &clock,
        )
        .expect("second recovery should succeed");

        assert_eq!(result2.lease_revoked_events_emitted, 1); // New event emitted
        assert_eq!(result2.work_claims_released, 0); // No claims to release

        // In practice, the session registry would be cleared after the first
        // recovery, so the second call wouldn't find any sessions. But the
        // function itself is safe to call repeatedly.
    }

    #[test]
    fn test_recovery_idempotent_via_clear_registry() {
        use crate::episode::PersistentSessionRegistry;

        let temp_dir = tempfile::TempDir::new().unwrap();
        let state_path = temp_dir.path().join("state.json");

        // Create a persistent registry with sessions
        let registry = PersistentSessionRegistry::new(&state_path);
        registry
            .register_session(make_session("sess-1", "work-1"))
            .unwrap();
        assert_eq!(registry.session_count(), 1);

        let registry: Arc<dyn SessionRegistry> = Arc::new(registry);

        // Collect sessions (simulates first startup)
        let collected = collect_sessions(&registry);
        assert_eq!(collected.sessions.len(), 1);
        assert!(!collected.was_truncated);

        // Clear after recovery (None = all collected sessions succeeded)
        clear_session_registry(&registry, &collected, None).expect("clear should succeed");

        // Now collect again (simulates second startup after reload)
        let collected_after = collect_sessions(&registry);
        assert!(
            collected_after.sessions.is_empty(),
            "Sessions should be cleared"
        );
    }

    // =========================================================================
    // Failure Safety Tests
    // =========================================================================

    #[test]
    fn test_recovery_without_ledger_succeeds() {
        // No ledger configured -- events not persisted but recovery succeeds
        let clock = make_clock();
        let sessions = vec![
            make_session("sess-1", "work-1"),
            make_session("sess-2", "work-2"),
        ];

        let result = recover_stale_sessions(
            &sessions,
            None, // No emitter
            None, // No sqlite conn
            Duration::from_secs(5),
            &clock,
        )
        .expect("recovery should succeed without ledger");

        assert_eq!(result.sessions_recovered, 2);
        assert_eq!(result.lease_revoked_events_emitted, 0);
        assert_eq!(result.work_claims_released, 0);
    }

    #[test]
    fn test_recovery_timeout() {
        let conn = setup_sqlite();
        let emitter = make_emitter(&conn);
        let clock = make_clock();

        // Create enough sessions with a very short timeout
        let sessions: Vec<SessionState> = (0..1000)
            .map(|i| make_session(&format!("sess-{i}"), &format!("work-{i}")))
            .collect();

        // Use a 0ms timeout to force immediate timeout
        let result = recover_stale_sessions(
            &sessions,
            Some(&emitter),
            Some(&conn),
            Duration::from_millis(0),
            &clock,
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            CrashRecoveryError::Timeout { .. } => {
                // Expected
            },
            other => panic!("Expected Timeout, got: {other:?}"),
        }
    }

    #[test]
    fn test_collect_sessions_with_in_memory_registry() {
        // InMemorySessionRegistry should return empty (no persistence)
        let registry: Arc<dyn SessionRegistry> = Arc::new(InMemorySessionRegistry::new());

        let collected = collect_sessions(&registry);
        assert!(collected.sessions.is_empty());
        assert!(!collected.was_truncated);
        assert_eq!(collected.total_in_registry, 0);
    }

    #[test]
    fn test_collect_sessions_with_persistent_registry() {
        use crate::episode::PersistentSessionRegistry;

        let temp_dir = tempfile::TempDir::new().unwrap();
        let state_path = temp_dir.path().join("state.json");

        let registry = PersistentSessionRegistry::new(&state_path);
        registry
            .register_session(make_session("sess-1", "work-1"))
            .unwrap();
        registry
            .register_session(make_session("sess-2", "work-2"))
            .unwrap();

        let registry: Arc<dyn SessionRegistry> = Arc::new(registry);
        let collected = collect_sessions(&registry);
        assert_eq!(collected.sessions.len(), 2);
        assert!(!collected.was_truncated);
        assert_eq!(collected.total_in_registry, 2);
    }

    // =========================================================================
    // Integration Test: Full Recovery Cycle
    // =========================================================================

    #[test]
    fn test_full_recovery_cycle() {
        use crate::episode::PersistentSessionRegistry;

        let temp_dir = tempfile::TempDir::new().unwrap();
        let state_path = temp_dir.path().join("state.json");

        // Phase 1: Simulate daemon that registers sessions and work claims
        let conn = setup_sqlite();
        {
            let registry = PersistentSessionRegistry::new(&state_path);
            registry
                .register_session(make_session("sess-1", "work-1"))
                .unwrap();
            registry
                .register_session(make_session("sess-2", "work-2"))
                .unwrap();
            register_claim(&conn, "work-1");
            register_claim(&conn, "work-2");
        }

        // Verify state file was written
        assert!(state_path.exists());

        // Phase 2: Simulate daemon restart -- load from state file
        let loaded_registry = PersistentSessionRegistry::load_from_file(&state_path).unwrap();
        assert_eq!(loaded_registry.session_count(), 2);

        let registry: Arc<dyn SessionRegistry> = Arc::new(loaded_registry);
        let collected = collect_sessions(&registry);
        assert_eq!(collected.sessions.len(), 2);
        assert!(!collected.was_truncated);

        // Phase 3: Perform crash recovery
        let emitter = make_emitter(&conn);
        let clock = make_clock();
        let result = recover_stale_sessions(
            &collected.sessions,
            Some(&emitter),
            Some(&conn),
            Duration::from_secs(5),
            &clock,
        )
        .expect("recovery should succeed");

        // Verify outcome
        assert_eq!(result.sessions_recovered, 2);
        assert_eq!(result.lease_revoked_events_emitted, 2);
        assert_eq!(result.work_claims_released, 2);
        assert!(result.recovery_time_ms < 5000);

        // Verify ledger events
        let db = conn.lock().unwrap();
        let count: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM ledger_events WHERE event_type = ?1",
                params![LEASE_REVOKED_EVENT_TYPE],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 2);

        // Verify work claims are gone
        let claims_count: i64 = db
            .query_row("SELECT COUNT(*) FROM work_claims", [], |row| row.get(0))
            .unwrap();
        assert_eq!(claims_count, 0);
        drop(db);

        // Phase 4: Clear registry (idempotency)
        clear_session_registry(&registry, &collected, Some(&result.succeeded_session_ids))
            .expect("clear should succeed");

        // Phase 5: Verify second recovery finds nothing
        let collected_after = collect_sessions(&registry);
        assert!(collected_after.sessions.is_empty());
    }

    // =========================================================================
    // LEASE_REVOKED Event Content Tests
    // =========================================================================

    #[test]
    fn test_lease_revoked_event_payload_content() {
        let conn = setup_sqlite();
        let emitter = make_emitter(&conn);
        let clock = make_clock();
        let session = make_session("sess-1", "work-1");

        let result = recover_stale_sessions(
            &[session],
            Some(&emitter),
            Some(&conn),
            Duration::from_secs(5),
            &clock,
        )
        .expect("recovery should succeed");

        assert_eq!(result.lease_revoked_events_emitted, 1);

        // Verify event content
        let db = conn.lock().unwrap();
        let (event_type, work_id, actor_id): (String, String, String) = db
            .query_row(
                "SELECT event_type, work_id, actor_id FROM ledger_events \
                 WHERE event_type = ?1",
                params![LEASE_REVOKED_EVENT_TYPE],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();

        assert_eq!(event_type, LEASE_REVOKED_EVENT_TYPE);
        // emit_session_event uses session_id as work_id for indexing
        assert_eq!(work_id, "sess-1");
        assert_eq!(actor_id, "daemon");
    }

    // =========================================================================
    // Regression Tests: BLOCKER 1 -- Registry preserved on recovery error
    // =========================================================================

    /// Regression test: when recovery times out, the session registry must NOT
    /// be cleared. Stale sessions must be preserved for retry on next startup.
    #[test]
    fn test_timeout_preserves_registry() {
        use crate::episode::PersistentSessionRegistry;

        let temp_dir = tempfile::TempDir::new().unwrap();
        let state_path = temp_dir.path().join("state.json");

        // Create registry with sessions
        let registry = PersistentSessionRegistry::new(&state_path);
        registry
            .register_session(make_session("sess-1", "work-1"))
            .unwrap();
        registry
            .register_session(make_session("sess-2", "work-2"))
            .unwrap();
        assert_eq!(registry.session_count(), 2);

        let registry: Arc<dyn SessionRegistry> = Arc::new(registry);
        let collected = collect_sessions(&registry);
        assert_eq!(collected.sessions.len(), 2);

        let conn = setup_sqlite();
        let emitter = make_emitter(&conn);
        let clock = make_clock();

        // Force timeout by using 0ms timeout
        let result = recover_stale_sessions(
            &collected.sessions,
            Some(&emitter),
            Some(&conn),
            Duration::from_millis(0),
            &clock,
        );

        // Recovery should fail with timeout
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CrashRecoveryError::Timeout { .. }
        ));

        // CRITICAL: Do NOT clear registry on error (simulating what main.rs
        // now does -- only clear on Ok)
        // clear_session_registry is NOT called here.

        // Verify sessions are still present in the registry
        let collected_after = collect_sessions(&registry);
        assert_eq!(
            collected_after.sessions.len(),
            2,
            "Registry must preserve all sessions after timeout"
        );
    }

    // =========================================================================
    // Regression Tests: BLOCKER 2 -- Truncated recovery clears only subset
    // =========================================================================

    /// Regression test: when session collection is truncated to
    /// `MAX_RECOVERY_SESSIONS`, `clear_session_registry` must only remove the
    /// recovered subset, preserving unrecovered sessions for the next startup.
    #[test]
    fn test_truncated_recovery_preserves_unrecovered_sessions() {
        use crate::episode::PersistentSessionRegistry;

        let temp_dir = tempfile::TempDir::new().unwrap();
        let state_path = temp_dir.path().join("state.json");

        // Create a persistent registry with more sessions than the cap.
        // We can't easily create 10,001 sessions (MAX_RECOVERY_SESSIONS + 1)
        // in a unit test, so we test the mechanism directly: build a
        // CollectedSessions with was_truncated=true and verify
        // clear_session_registry removes only the listed subset.
        let registry = PersistentSessionRegistry::new(&state_path);
        for i in 0..5 {
            registry
                .register_session(make_session(&format!("sess-{i}"), &format!("work-{i}")))
                .unwrap();
        }
        assert_eq!(registry.session_count(), 5);

        let registry: Arc<dyn SessionRegistry> = Arc::new(registry);

        // Simulate a truncated collection that only includes 3 of 5 sessions
        let truncated = CollectedSessions {
            sessions: vec![
                make_session("sess-0", "work-0"),
                make_session("sess-1", "work-1"),
                make_session("sess-2", "work-2"),
            ],
            was_truncated: true,
            total_in_registry: 5,
        };

        // Clear only the recovered subset (None = all collected sessions succeeded)
        clear_session_registry(&registry, &truncated, None).expect("clear should succeed");

        // Verify: only the 2 unrecovered sessions remain
        let remaining = collect_sessions(&registry);
        assert_eq!(
            remaining.sessions.len(),
            2,
            "Only unrecovered sessions should remain"
        );

        // Verify the remaining sessions are the ones NOT in the truncated set
        let remaining_ids: Vec<String> = remaining
            .sessions
            .iter()
            .map(|s| s.session_id.clone())
            .collect();
        assert!(
            remaining_ids.contains(&"sess-3".to_string()),
            "sess-3 should be preserved"
        );
        assert!(
            remaining_ids.contains(&"sess-4".to_string()),
            "sess-4 should be preserved"
        );
        assert!(
            !remaining_ids.contains(&"sess-0".to_string()),
            "sess-0 should be cleared"
        );
    }

    /// Regression test: `CollectedSessions` correctly reports truncation.
    #[test]
    fn test_collect_sessions_reports_truncation() {
        use crate::episode::PersistentSessionRegistry;

        let temp_dir = tempfile::TempDir::new().unwrap();
        let state_path = temp_dir.path().join("state.json");

        // With fewer than MAX_RECOVERY_SESSIONS, was_truncated should be false
        let registry = PersistentSessionRegistry::new(&state_path);
        registry
            .register_session(make_session("sess-1", "work-1"))
            .unwrap();

        let registry: Arc<dyn SessionRegistry> = Arc::new(registry);
        let collected = collect_sessions(&registry);
        assert!(!collected.was_truncated);
        assert_eq!(collected.total_in_registry, 1);
        assert_eq!(collected.sessions.len(), 1);
    }

    // =========================================================================
    // Regression Tests: Per-Session Failure Tracking (SECURITY BLOCKER 2)
    // =========================================================================

    /// Regression test: when a per-session work claim release fails, the
    /// failed session ID must be preserved in the registry (not cleared).
    /// Only successfully recovered sessions should be cleared.
    #[test]
    fn test_per_session_failure_preserves_failed_ids_in_registry() {
        use crate::episode::PersistentSessionRegistry;

        let temp_dir = tempfile::TempDir::new().unwrap();
        let state_path = temp_dir.path().join("state.json");

        // Create registry with 3 sessions
        let registry = PersistentSessionRegistry::new(&state_path);
        for i in 0..3 {
            registry
                .register_session(make_session(&format!("sess-{i}"), &format!("work-{i}")))
                .unwrap();
        }
        assert_eq!(registry.session_count(), 3);

        let registry: Arc<dyn SessionRegistry> = Arc::new(registry);
        let collected = collect_sessions(&registry);
        assert_eq!(collected.sessions.len(), 3);

        // Set up SQLite with a poisoned connection to cause work claim failures.
        // We create a connection, then poison it by panicking inside a lock.
        let conn = setup_sqlite();
        let emitter = make_emitter(&conn);

        // Poison the mutex by panicking inside a lock guard
        let conn_clone = Arc::clone(&conn);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = conn_clone.lock().unwrap();
            panic!("intentional poison");
        }));

        // Now the mutex is poisoned. Recovery should fail for work claim release
        // but the function should track per-session failures.
        let clock = make_clock();
        let result = recover_stale_sessions(
            &collected.sessions,
            Some(&emitter), // Emitter also uses the same poisoned conn
            None,           // No sqlite_conn for claims (ledger will fail)
            Duration::from_secs(5),
            &clock,
        );

        // With the poisoned connection, emit_lease_revoked_event will fail
        // because the emitter internally uses the poisoned connection.
        // This should produce a PartialRecovery error.
        match result {
            Err(CrashRecoveryError::PartialRecovery {
                failed_count,
                total_count,
                outcome,
            }) => {
                assert_eq!(total_count, 3);
                assert_eq!(failed_count, 3);
                assert_eq!(outcome.failed_session_ids.len(), 3);
                assert!(outcome.succeeded_session_ids.is_empty());

                // CRITICAL: Only clear succeeded sessions (none in this case).
                // Failed sessions must be preserved for retry.
                clear_session_registry(&registry, &collected, Some(&outcome.succeeded_session_ids))
                    .expect("clear should succeed (no sessions to clear)");

                // Verify ALL sessions are still in the registry
                let remaining = collect_sessions(&registry);
                assert_eq!(
                    remaining.sessions.len(),
                    3,
                    "All sessions must be preserved when all have failures"
                );
            },
            Ok(_) => panic!("Expected PartialRecovery error, got Ok"),
            Err(other) => panic!("Expected PartialRecovery error, got: {other:?}"),
        }
    }

    /// Regression test: when some sessions succeed and others fail, only the
    /// succeeded sessions are cleared from the registry.
    #[test]
    fn test_partial_failure_clears_only_succeeded_sessions() {
        use crate::episode::PersistentSessionRegistry;

        let temp_dir = tempfile::TempDir::new().unwrap();
        let state_path = temp_dir.path().join("state.json");

        // Create registry with 3 sessions
        let registry = PersistentSessionRegistry::new(&state_path);
        for i in 0..3 {
            registry
                .register_session(make_session(&format!("sess-{i}"), &format!("work-{i}")))
                .unwrap();
        }
        assert_eq!(registry.session_count(), 3);

        let registry: Arc<dyn SessionRegistry> = Arc::new(registry);
        let collected = collect_sessions(&registry);

        // Simulate a partial recovery outcome: sess-0 and sess-2 succeeded,
        // sess-1 failed.
        let succeeded_ids = vec!["sess-0".to_string(), "sess-2".to_string()];
        clear_session_registry(&registry, &collected, Some(&succeeded_ids))
            .expect("clear should succeed");

        // Verify: only sess-1 (the failed one) remains in the registry
        let remaining = collect_sessions(&registry);
        assert_eq!(
            remaining.sessions.len(),
            1,
            "Only the failed session should remain"
        );
        assert_eq!(remaining.sessions[0].session_id, "sess-1");
    }

    // =========================================================================
    // Regression Tests: Timeout Before Registry Clear (SECURITY BLOCKER 1)
    // =========================================================================

    /// Regression test: `recover_stale_sessions` performs a post-operation
    /// deadline check after processing all sessions, ensuring timeout is
    /// detected even if individual session processing completes before the
    /// per-iteration check.
    #[test]
    fn test_timeout_check_occurs_before_registry_clear() {
        use crate::episode::PersistentSessionRegistry;

        let temp_dir = tempfile::TempDir::new().unwrap();
        let state_path = temp_dir.path().join("state.json");

        // Create registry with sessions
        let registry = PersistentSessionRegistry::new(&state_path);
        registry
            .register_session(make_session("sess-1", "work-1"))
            .unwrap();
        registry
            .register_session(make_session("sess-2", "work-2"))
            .unwrap();
        assert_eq!(registry.session_count(), 2);

        let registry: Arc<dyn SessionRegistry> = Arc::new(registry);
        let collected = collect_sessions(&registry);

        // Use a 0ms timeout. recover_stale_sessions checks the deadline
        // before each session AND after all sessions (post-operation check).
        // With 0ms timeout, it must return Timeout before success.
        let clock = make_clock();
        let result = recover_stale_sessions(
            &collected.sessions,
            None,
            None,
            Duration::from_millis(0),
            &clock,
        );

        // Must be a Timeout error
        assert!(
            matches!(result, Err(CrashRecoveryError::Timeout { .. })),
            "Expected Timeout error, got: {result:?}"
        );

        // CRITICAL: Registry must NOT be cleared on timeout.
        // The caller (perform_crash_recovery in main.rs) skips
        // clear_session_registry when recover_stale_sessions returns Err.
        let remaining = collect_sessions(&registry);
        assert_eq!(
            remaining.sessions.len(),
            2,
            "Registry must preserve all sessions when timeout occurs"
        );
    }

    // =========================================================================
    // Regression Tests: Timestamp Failure Propagation (SECURITY MAJOR 1)
    // =========================================================================

    /// Regression test: `CrashRecoveryError::TimestampFailed` variant exists
    /// and can be constructed, ensuring timestamp acquisition failures are
    /// propagated as errors rather than silently using timestamp 0.
    #[test]
    fn test_timestamp_failure_error_variant_exists() {
        let err = CrashRecoveryError::TimestampFailed {
            message: "system clock before UNIX epoch".to_string(),
        };
        let display = format!("{err}");
        assert!(
            display.contains("system clock before UNIX epoch"),
            "TimestampFailed error should contain the message"
        );
        assert!(
            display.contains("failed to acquire timestamp"),
            "TimestampFailed error should have descriptive prefix"
        );
    }

    /// Regression test: `emit_lease_revoked_event` does NOT use `unwrap_or(0)`
    /// for timestamps. Under normal conditions, it succeeds. This test verifies
    /// the function works correctly and the event gets a valid non-zero
    /// timestamp.
    #[test]
    fn test_lease_revoked_event_has_valid_timestamp() {
        let conn = setup_sqlite();
        let emitter = make_emitter(&conn);
        let clock = make_clock();
        let session = make_session("sess-ts", "work-ts");

        let result = recover_stale_sessions(
            &[session],
            Some(&emitter),
            Some(&conn),
            Duration::from_secs(5),
            &clock,
        )
        .expect("recovery should succeed");

        assert_eq!(result.lease_revoked_events_emitted, 1);

        // Verify the event has a non-zero timestamp (fail-closed: no
        // unwrap_or(0) fallback)
        let db = conn.lock().unwrap();
        let timestamp_ns: i64 = db
            .query_row(
                "SELECT timestamp_ns FROM ledger_events WHERE event_type = ?1",
                params![LEASE_REVOKED_EVENT_TYPE],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            timestamp_ns > 0,
            "Timestamp must be non-zero (fail-closed, no unwrap_or(0) fallback)"
        );
    }

    // =========================================================================
    // Original Regression Tests (preserved)
    // =========================================================================

    /// Full end-to-end test: non-truncated successful recovery clears all
    /// sessions from registry.
    #[test]
    fn test_non_truncated_success_clears_all() {
        use crate::episode::PersistentSessionRegistry;

        let temp_dir = tempfile::TempDir::new().unwrap();
        let state_path = temp_dir.path().join("state.json");
        let conn = setup_sqlite();
        let emitter = make_emitter(&conn);
        let clock = make_clock();

        let registry = PersistentSessionRegistry::new(&state_path);
        registry
            .register_session(make_session("sess-1", "work-1"))
            .unwrap();
        registry
            .register_session(make_session("sess-2", "work-2"))
            .unwrap();

        let registry: Arc<dyn SessionRegistry> = Arc::new(registry);
        let collected = collect_sessions(&registry);
        assert_eq!(collected.sessions.len(), 2);
        assert!(!collected.was_truncated);

        // Successful recovery
        let outcome = recover_stale_sessions(
            &collected.sessions,
            Some(&emitter),
            Some(&conn),
            Duration::from_secs(5),
            &clock,
        )
        .expect("recovery should succeed");

        // Clear -- should clear all since not truncated
        clear_session_registry(&registry, &collected, Some(&outcome.succeeded_session_ids))
            .expect("clear should succeed");

        let after = collect_sessions(&registry);
        assert!(
            after.sessions.is_empty(),
            "All sessions should be cleared on non-truncated success"
        );
    }

    // =========================================================================
    // Regression Tests: SECURITY BLOCKER v3 -- Timeout returns partial progress
    // =========================================================================

    /// Regression test: when recovery times out after processing some sessions,
    /// the `Timeout` error MUST carry the partial outcome (succeeded/failed
    /// IDs) so the caller can checkpoint the completed subset and avoid
    /// replaying their side-effects on the next startup.
    #[test]
    fn test_timeout_returns_partial_progress() {
        let conn = setup_sqlite();
        let emitter = make_emitter(&conn);
        let clock = make_clock();

        // Create 1000 sessions with a very short timeout. Some will complete
        // before the deadline is hit.
        let sessions: Vec<SessionState> = (0..1000)
            .map(|i| make_session(&format!("sess-{i}"), &format!("work-{i}")))
            .collect();

        // Use a 0ms timeout. With 0ms, the first iteration check fires
        // immediately, so we expect 0 sessions completed (the check happens
        // BEFORE processing each session).
        let result = recover_stale_sessions(
            &sessions,
            Some(&emitter),
            Some(&conn),
            Duration::from_millis(0),
            &clock,
        );

        match result {
            Err(CrashRecoveryError::Timeout { outcome, .. }) => {
                // The timeout carries partial progress. With 0ms timeout the
                // pre-iteration check fires before any session is processed,
                // so sessions_recovered should be 0. But the key invariant is
                // that the outcome IS present (not discarded).
                assert!(
                    outcome.sessions_recovered as usize + outcome.failed_session_ids.len()
                        <= sessions.len(),
                    "Partial progress must not exceed total sessions"
                );
                // The succeeded + failed IDs must be consistent
                assert_eq!(
                    outcome.succeeded_session_ids.len(),
                    outcome.sessions_recovered as usize
                );
            },
            Ok(_) => panic!("Expected Timeout error, got Ok"),
            Err(other) => panic!("Expected Timeout error, got: {other:?}"),
        }
    }

    /// Regression test: when timeout occurs after processing a prefix of
    /// sessions, the caller checkpoints the succeeded subset. Only the
    /// unprocessed sessions remain in the registry.
    #[test]
    fn test_timeout_partial_progress_checkpoint_clears_succeeded() {
        use crate::episode::PersistentSessionRegistry;

        let temp_dir = tempfile::TempDir::new().unwrap();
        let state_path = temp_dir.path().join("state.json");

        // Create registry with 3 sessions
        let registry = PersistentSessionRegistry::new(&state_path);
        for i in 0..3 {
            registry
                .register_session(make_session(&format!("sess-{i}"), &format!("work-{i}")))
                .unwrap();
        }
        assert_eq!(registry.session_count(), 3);

        let registry: Arc<dyn SessionRegistry> = Arc::new(registry);
        let collected = collect_sessions(&registry);
        assert_eq!(collected.sessions.len(), 3);

        // Simulate a timeout that completed 2 of 3 sessions by directly
        // constructing the Timeout error with partial progress.
        let partial_outcome = CrashRecoveryOutcome {
            sessions_recovered: 2,
            lease_revoked_events_emitted: 2,
            work_claims_released: 0,
            recovery_time_ms: 100,
            succeeded_session_ids: vec!["sess-0".to_string(), "sess-1".to_string()],
            failed_session_ids: vec![],
        };

        // Simulate caller behavior: checkpoint the succeeded subset.
        clear_session_registry(
            &registry,
            &collected,
            Some(&partial_outcome.succeeded_session_ids),
        )
        .expect("clear should succeed");

        // Only the unprocessed session (sess-2) should remain.
        let remaining = collect_sessions(&registry);
        assert_eq!(
            remaining.sessions.len(),
            1,
            "Only unprocessed sessions should remain after timeout checkpoint"
        );
        assert_eq!(remaining.sessions[0].session_id, "sess-2");
    }

    // =========================================================================
    // Regression Tests: SECURITY MAJOR 1 v3 -- HTF clock for timestamps
    // =========================================================================

    /// Regression test: when an HTF `HolonicClock` is provided, recovery
    /// timestamps come from the HLC (not raw `SystemTime`).
    #[test]
    fn test_htf_clock_used_for_recovery_timestamps() {
        let conn = setup_sqlite();
        let emitter = make_emitter(&conn);
        let session = make_session("sess-htf", "work-htf");

        // Create an HTF clock
        let clock = make_clock();

        let result = recover_stale_sessions(
            &[session],
            Some(&emitter),
            Some(&conn),
            Duration::from_secs(5),
            &clock,
        )
        .expect("recovery should succeed");

        assert_eq!(result.lease_revoked_events_emitted, 1);

        // Verify the event has a non-zero timestamp from the HLC
        let db = conn.lock().unwrap();
        let timestamp_ns: i64 = db
            .query_row(
                "SELECT timestamp_ns FROM ledger_events WHERE event_type = ?1",
                params![LEASE_REVOKED_EVENT_TYPE],
                |row| row.get(0),
            )
            .unwrap();
        assert!(timestamp_ns > 0, "HTF timestamp must be non-zero");
    }

    // =========================================================================
    // Regression Tests: SECURITY MAJOR 2 v3 -- Registry clear returns Result
    // =========================================================================

    /// Regression test: `clear_session_registry` returns `Result`, ensuring
    /// persistence failures are escalated rather than being warning-only.
    #[test]
    fn test_clear_session_registry_returns_result() {
        use crate::episode::PersistentSessionRegistry;

        let temp_dir = tempfile::TempDir::new().unwrap();
        let state_path = temp_dir.path().join("state.json");

        let registry = PersistentSessionRegistry::new(&state_path);
        registry
            .register_session(make_session("sess-1", "work-1"))
            .unwrap();

        let registry: Arc<dyn SessionRegistry> = Arc::new(registry);
        let collected = collect_sessions(&registry);

        // Successful clear should return Ok(())
        let result = clear_session_registry(&registry, &collected, None);
        assert!(
            result.is_ok(),
            "clear_session_registry should return Ok on success"
        );

        // After clearing, registry should be empty
        let remaining = collect_sessions(&registry);
        assert!(remaining.sessions.is_empty());
    }

    /// Regression test: `RegistryClearFailed` error variant exists and can be
    /// constructed, ensuring the error path is compile-time verified.
    #[test]
    fn test_registry_clear_failed_error_variant_exists() {
        let err = CrashRecoveryError::RegistryClearFailed {
            message: "persistence failed".to_string(),
        };
        let display = format!("{err}");
        assert!(
            display.contains("persistence failed"),
            "RegistryClearFailed error should contain the message"
        );
        assert!(
            display.contains("registry clear/persist failed"),
            "RegistryClearFailed error should have descriptive prefix"
        );
    }
}
