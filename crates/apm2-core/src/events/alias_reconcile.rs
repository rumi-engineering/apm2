//! Alias reconciliation schema, observation window controls, and
//! snapshot-emitter sunset.
//!
//! This module implements ticket-alias observation windows, reconciliation
//! gates between ticket-alias projections and canonical work-id projections,
//! promotion gates that block on unresolved defects, and snapshot-emitter
//! sunset evaluation.
//!
//! # Design Principles
//!
//! - **`ticket_alias` is operator-facing only** and never authority-bearing.
//!   Authority remains with `work_id` on the ledger/CAS.
//! - **Fail-closed**: promotion gates return `false` on any ambiguous state.
//! - **Non-authoritative overlays**: observation windows are advisory metadata
//!   that do not affect canonical identity semantics.
//!
//! # Contracts
//!
//! - [CTR-ALIAS-001] `ticket_alias` fields are for cognition/traceability only.
//! - [CTR-ALIAS-002] Promotion gates require zero unresolved alias/`work_id`
//!   mismatches.
//! - [CTR-ALIAS-003] Snapshot emitters are sunset only after criteria pass with
//!   historical trace preserved.
//!
//! # Invariants
//!
//! - [INV-ALIAS-001] `reconcile_aliases` produces a defect for every binding
//!   that does not match the canonical projection.
//! - [INV-ALIAS-002] `promotion_gate` returns `false` if any defect exists
//!   (fail-closed).
//! - [INV-ALIAS-003] `evaluate_sunset` returns `Active` on ambiguous inputs
//!   (fail-closed).

use std::collections::HashMap;
use std::hash::BuildHasher;

// ============================================================================
// Alias Binding Schema
// ============================================================================

/// A binding between a human-readable ticket alias and a canonical work ID.
///
/// This is a non-authoritative overlay for operator cognition and traceability.
/// The canonical identity is always the `work_id` hash on the ledger/CAS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TicketAliasBinding {
    /// Human-readable ticket alias (e.g., "TCK-00420").
    pub ticket_alias: String,

    /// Canonical work ID hash this alias is bound to.
    pub canonical_work_id: Hash,

    /// HTF tick at which this binding was first observed.
    pub observed_at_tick: u64,

    /// Start of the observation window (inclusive).
    pub observation_window_start: u64,

    /// End of the observation window (inclusive).
    pub observation_window_end: u64,
}

/// Opaque hash type representing a canonical work ID.
///
/// Uses a 32-byte array for compatibility with Ed25519/SHA-256 hashes
/// used elsewhere in the kernel.
pub type Hash = [u8; 32];

// ============================================================================
// Reconciliation Defects
// ============================================================================

/// Classification of alias reconciliation defects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefectClass {
    /// The alias was not found in canonical projections.
    NotFound,

    /// The alias maps to a different `work_id` than expected.
    Mismatch,

    /// The alias binding is stale (last seen tick exceeds staleness threshold).
    Stale,

    /// The alias maps to multiple canonical `work_id` values (ambiguous).
    Ambiguous,
}

impl std::fmt::Display for DefectClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "not_found"),
            Self::Mismatch => write!(f, "mismatch"),
            Self::Stale => write!(f, "stale"),
            Self::Ambiguous => write!(f, "ambiguous"),
        }
    }
}

/// A defect detected during alias reconciliation.
///
/// Each defect represents a discrepancy between the operator-facing alias
/// binding and the canonical `work_id` projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AliasReconciliationDefect {
    /// The ticket alias that produced the defect.
    pub ticket_alias: String,

    /// The `work_id` the alias was expected to resolve to.
    pub expected_work_id: Hash,

    /// The `work_id` the alias actually resolved to (zero hash if not found).
    pub actual_work_id: Hash,

    /// Classification of the defect.
    pub defect_class: DefectClass,

    /// HTF tick at which the defect was detected.
    pub detected_at_tick: u64,
}

/// Result of a reconciliation pass over a set of alias bindings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AliasReconciliationResult {
    /// Number of aliases that resolved correctly.
    pub resolved_count: usize,

    /// Defects for aliases that did not resolve correctly.
    pub unresolved_defects: Vec<AliasReconciliationDefect>,
}

// ============================================================================
// Observation Window
// ============================================================================

/// Observation window controls for alias bindings.
///
/// Defines a tick-based window during which alias bindings are considered
/// valid, plus a staleness threshold for detecting bindings that have not
/// been refreshed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservationWindow {
    /// Start tick of the window (inclusive).
    pub start_tick: u64,

    /// End tick of the window (inclusive).
    pub end_tick: u64,

    /// Maximum number of ticks since last observation before a binding
    /// is considered stale.
    pub max_staleness_ticks: u64,
}

impl ObservationWindow {
    /// Returns `true` if the given tick falls within the observation window
    /// (inclusive on both bounds).
    #[must_use]
    pub const fn is_within_window(&self, tick: u64) -> bool {
        tick >= self.start_tick && tick <= self.end_tick
    }

    /// Returns `true` if a binding last seen at `last_seen_tick` is stale
    /// relative to `current_tick`.
    ///
    /// A binding is stale when the gap between `current_tick` and
    /// `last_seen_tick` exceeds `max_staleness_ticks`.
    ///
    /// **Fail-closed on temporal inversion**: if `current_tick <
    /// last_seen_tick` (tick regression / temporal anomaly), the binding is
    /// treated as stale. This prevents a regressed clock from silently
    /// bypassing staleness detection ([INV-ALIAS-004]).
    #[must_use]
    pub const fn is_stale(&self, last_seen_tick: u64, current_tick: u64) -> bool {
        // Fail-closed: tick regression is always stale (temporal anomaly).
        if current_tick < last_seen_tick {
            return true;
        }
        current_tick.saturating_sub(last_seen_tick) > self.max_staleness_ticks
    }
}

// ============================================================================
// Reconciliation Gate
// ============================================================================

/// Zero hash used as sentinel for "not found" in defect reporting.
pub const ZERO_HASH: Hash = [0u8; 32];

/// Reconciles a set of alias bindings against canonical `work_id` projections.
///
/// For each binding, checks whether the alias exists in the canonical
/// projections and whether the `work_id` matches. Produces defects for:
///
/// - **`NotFound`**: alias not present in canonical projections
/// - **`Mismatch`**: alias present but maps to a different `work_id`
/// - **`Ambiguous`**: alias maps to multiple distinct `work_id` values
///
/// The `canonical_projections` map uses `Vec<Hash>` values to preserve
/// multiplicity. When an alias maps to more than one distinct `work_id`,
/// the reconciliation emits a `DefectClass::Ambiguous` defect and the
/// `promotion_gate` will block (fail-closed).
///
/// Staleness checks are not performed here; use [`ObservationWindow::is_stale`]
/// separately if needed.
///
/// # Arguments
///
/// * `bindings` - The alias bindings to reconcile.
/// * `canonical_projections` - Map from ticket alias to one or more canonical
///   `work_id` hashes. Multiple entries indicate ambiguity.
/// * `current_tick` - The current HTF tick for defect timestamping.
///
/// # Returns
///
/// An [`AliasReconciliationResult`] with counts and any defects found.
#[must_use]
pub fn reconcile_aliases<S: BuildHasher>(
    bindings: &[TicketAliasBinding],
    canonical_projections: &HashMap<String, Vec<Hash>, S>,
    current_tick: u64,
) -> AliasReconciliationResult {
    let mut resolved_count = 0usize;
    let mut unresolved_defects = Vec::new();

    for binding in bindings {
        match canonical_projections.get(&binding.ticket_alias) {
            Some(canonical_ids) => {
                if canonical_ids.len() > 1 {
                    // Multiple distinct work_ids for the same alias => ambiguous.
                    unresolved_defects.push(AliasReconciliationDefect {
                        ticket_alias: binding.ticket_alias.clone(),
                        expected_work_id: binding.canonical_work_id,
                        actual_work_id: ZERO_HASH,
                        defect_class: DefectClass::Ambiguous,
                        detected_at_tick: current_tick,
                    });
                } else if let Some(canonical_id) = canonical_ids.first() {
                    if *canonical_id == binding.canonical_work_id {
                        resolved_count += 1;
                    } else {
                        unresolved_defects.push(AliasReconciliationDefect {
                            ticket_alias: binding.ticket_alias.clone(),
                            expected_work_id: binding.canonical_work_id,
                            actual_work_id: *canonical_id,
                            defect_class: DefectClass::Mismatch,
                            detected_at_tick: current_tick,
                        });
                    }
                } else {
                    // Empty vec => treat as not found (fail-closed).
                    unresolved_defects.push(AliasReconciliationDefect {
                        ticket_alias: binding.ticket_alias.clone(),
                        expected_work_id: binding.canonical_work_id,
                        actual_work_id: ZERO_HASH,
                        defect_class: DefectClass::NotFound,
                        detected_at_tick: current_tick,
                    });
                }
            },
            None => {
                unresolved_defects.push(AliasReconciliationDefect {
                    ticket_alias: binding.ticket_alias.clone(),
                    expected_work_id: binding.canonical_work_id,
                    actual_work_id: ZERO_HASH,
                    defect_class: DefectClass::NotFound,
                    detected_at_tick: current_tick,
                });
            },
        }
    }

    AliasReconciliationResult {
        resolved_count,
        unresolved_defects,
    }
}

/// Promotion gate: returns `true` only if zero unresolved defects exist.
///
/// This is a fail-closed gate ([INV-ALIAS-002]): any ambiguity or defect
/// blocks promotion.
#[must_use]
pub fn promotion_gate(result: &AliasReconciliationResult) -> bool {
    result.unresolved_defects.is_empty()
}

// ============================================================================
// Snapshot Emitter Sunset
// ============================================================================

/// Status of a snapshot emitter in the sunset lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotEmitterStatus {
    /// Emitter is actively producing snapshots.
    Active,

    /// Emitter has met partial sunset criteria but is not yet fully sunset.
    SunsetPending,

    /// Emitter is fully sunset and should no longer produce snapshots.
    /// Historical trace fields are preserved.
    Sunset,
}

impl std::fmt::Display for SnapshotEmitterStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::SunsetPending => write!(f, "sunset_pending"),
            Self::Sunset => write!(f, "sunset"),
        }
    }
}

/// Criteria for sunsetting a snapshot emitter.
///
/// Both criteria must be met for the emitter to be considered for sunset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotSunsetCriteria {
    /// Minimum number of consecutive clean reconciliation ticks required.
    pub min_reconciled_ticks: u64,

    /// Whether zero defects are required for sunset.
    pub zero_defects_required: bool,
}

/// Evaluates whether a snapshot emitter should be sunset based on criteria.
///
/// # Returns
///
/// - [`SnapshotEmitterStatus::Sunset`] if all criteria are met.
/// - [`SnapshotEmitterStatus::SunsetPending`] if some but not all criteria are
///   met.
/// - [`SnapshotEmitterStatus::Active`] if no criteria are met or inputs are
///   ambiguous.
///
/// Fail-closed ([INV-ALIAS-003]): returns `Active` on ambiguous state.
#[must_use]
pub const fn evaluate_sunset(
    criteria: &SnapshotSunsetCriteria,
    consecutive_clean_ticks: u64,
    has_defects: bool,
) -> SnapshotEmitterStatus {
    let ticks_met = consecutive_clean_ticks >= criteria.min_reconciled_ticks;
    let defects_met = !criteria.zero_defects_required || !has_defects;

    match (ticks_met, defects_met) {
        (true, true) => SnapshotEmitterStatus::Sunset,
        (true, false) | (false, true) => SnapshotEmitterStatus::SunsetPending,
        (false, false) => SnapshotEmitterStatus::Active,
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_hash(byte: u8) -> Hash {
        [byte; 32]
    }

    fn make_binding(alias: &str, work_id_byte: u8) -> TicketAliasBinding {
        TicketAliasBinding {
            ticket_alias: alias.to_string(),
            canonical_work_id: make_hash(work_id_byte),
            observed_at_tick: 100,
            observation_window_start: 90,
            observation_window_end: 110,
        }
    }

    mod reconciliation_tests {
        use super::*;

        #[test]
        fn all_aliases_matching() {
            let bindings = vec![
                make_binding("TCK-001", 0x01),
                make_binding("TCK-002", 0x02),
                make_binding("TCK-003", 0x03),
            ];

            let mut projections = HashMap::new();
            projections.insert("TCK-001".to_string(), vec![make_hash(0x01)]);
            projections.insert("TCK-002".to_string(), vec![make_hash(0x02)]);
            projections.insert("TCK-003".to_string(), vec![make_hash(0x03)]);

            let result = reconcile_aliases(&bindings, &projections, 100);

            assert_eq!(result.resolved_count, 3);
            assert!(result.unresolved_defects.is_empty());
            assert!(promotion_gate(&result));
        }

        #[test]
        fn mismatch_produces_defect() {
            let bindings = vec![make_binding("TCK-001", 0x01), make_binding("TCK-002", 0x02)];

            let mut projections = HashMap::new();
            projections.insert("TCK-001".to_string(), vec![make_hash(0x01)]);
            // TCK-002 maps to a different hash in canonical projections
            projections.insert("TCK-002".to_string(), vec![make_hash(0xFF)]);

            let result = reconcile_aliases(&bindings, &projections, 100);

            assert_eq!(result.resolved_count, 1);
            assert_eq!(result.unresolved_defects.len(), 1);

            let defect = &result.unresolved_defects[0];
            assert_eq!(defect.ticket_alias, "TCK-002");
            assert_eq!(defect.expected_work_id, make_hash(0x02));
            assert_eq!(defect.actual_work_id, make_hash(0xFF));
            assert_eq!(defect.defect_class, DefectClass::Mismatch);
            assert_eq!(defect.detected_at_tick, 100);

            assert!(!promotion_gate(&result));
        }

        #[test]
        fn not_found_produces_defect() {
            let bindings = vec![make_binding("TCK-001", 0x01)];

            let projections = HashMap::new(); // empty

            let result = reconcile_aliases(&bindings, &projections, 50);

            assert_eq!(result.resolved_count, 0);
            assert_eq!(result.unresolved_defects.len(), 1);

            let defect = &result.unresolved_defects[0];
            assert_eq!(defect.ticket_alias, "TCK-001");
            assert_eq!(defect.defect_class, DefectClass::NotFound);
            assert_eq!(defect.actual_work_id, ZERO_HASH);
            assert_eq!(defect.detected_at_tick, 50);

            assert!(!promotion_gate(&result));
        }

        #[test]
        fn empty_bindings_passes() {
            let projections: HashMap<String, Vec<Hash>> = HashMap::new();
            let result = reconcile_aliases(&[], &projections, 0);

            assert_eq!(result.resolved_count, 0);
            assert!(result.unresolved_defects.is_empty());
            assert!(promotion_gate(&result));
        }

        #[test]
        fn mixed_resolved_and_unresolved() {
            let bindings = vec![
                make_binding("TCK-001", 0x01),
                make_binding("TCK-002", 0x02),
                make_binding("TCK-003", 0x03),
            ];

            let mut projections = HashMap::new();
            projections.insert("TCK-001".to_string(), vec![make_hash(0x01)]); // match
            projections.insert("TCK-002".to_string(), vec![make_hash(0xAA)]); // mismatch
            // TCK-003 not in projections -> not found

            let result = reconcile_aliases(&bindings, &projections, 200);

            assert_eq!(result.resolved_count, 1);
            assert_eq!(result.unresolved_defects.len(), 2);

            let classes: Vec<DefectClass> = result
                .unresolved_defects
                .iter()
                .map(|d| d.defect_class)
                .collect();
            assert!(classes.contains(&DefectClass::Mismatch));
            assert!(classes.contains(&DefectClass::NotFound));

            assert!(!promotion_gate(&result));
        }

        #[test]
        fn ambiguous_alias_produces_defect() {
            let bindings = vec![make_binding("TCK-001", 0x01)];

            let mut projections = HashMap::new();
            // Two distinct work_ids for the same alias => ambiguous
            projections.insert(
                "TCK-001".to_string(),
                vec![make_hash(0x01), make_hash(0x02)],
            );

            let result = reconcile_aliases(&bindings, &projections, 100);

            assert_eq!(result.resolved_count, 0);
            assert_eq!(result.unresolved_defects.len(), 1);

            let defect = &result.unresolved_defects[0];
            assert_eq!(defect.ticket_alias, "TCK-001");
            assert_eq!(defect.defect_class, DefectClass::Ambiguous);
            assert_eq!(defect.actual_work_id, ZERO_HASH);
            assert_eq!(defect.detected_at_tick, 100);

            // Ambiguity MUST block promotion (fail-closed)
            assert!(!promotion_gate(&result));
        }

        #[test]
        fn empty_vec_projection_produces_not_found() {
            let bindings = vec![make_binding("TCK-001", 0x01)];

            let mut projections = HashMap::new();
            projections.insert("TCK-001".to_string(), vec![]);

            let result = reconcile_aliases(&bindings, &projections, 100);

            assert_eq!(result.resolved_count, 0);
            assert_eq!(result.unresolved_defects.len(), 1);
            assert_eq!(
                result.unresolved_defects[0].defect_class,
                DefectClass::NotFound
            );
            assert!(!promotion_gate(&result));
        }
    }

    mod observation_window_tests {
        use super::*;

        #[test]
        fn within_window() {
            let window = ObservationWindow {
                start_tick: 100,
                end_tick: 200,
                max_staleness_ticks: 50,
            };

            assert!(window.is_within_window(100)); // start boundary
            assert!(window.is_within_window(150)); // middle
            assert!(window.is_within_window(200)); // end boundary
        }

        #[test]
        fn outside_window() {
            let window = ObservationWindow {
                start_tick: 100,
                end_tick: 200,
                max_staleness_ticks: 50,
            };

            assert!(!window.is_within_window(99)); // before start
            assert!(!window.is_within_window(201)); // after end
            assert!(!window.is_within_window(0)); // well before
        }

        #[test]
        fn staleness_detection() {
            let window = ObservationWindow {
                start_tick: 0,
                end_tick: 1000,
                max_staleness_ticks: 10,
            };

            // Not stale: within threshold
            assert!(!window.is_stale(90, 100)); // gap = 10, threshold = 10
            assert!(!window.is_stale(95, 100)); // gap = 5

            // Stale: exceeds threshold
            assert!(window.is_stale(89, 100)); // gap = 11 > 10
            assert!(window.is_stale(0, 100)); // gap = 100 > 10
        }

        #[test]
        fn staleness_with_zero_threshold() {
            let window = ObservationWindow {
                start_tick: 0,
                end_tick: 1000,
                max_staleness_ticks: 0,
            };

            // With max_staleness_ticks = 0, any gap > 0 is stale
            assert!(!window.is_stale(100, 100)); // gap = 0, not stale
            assert!(window.is_stale(99, 100)); // gap = 1 > 0
        }

        #[test]
        fn tick_regression_is_stale_fail_closed() {
            let window = ObservationWindow {
                start_tick: 0,
                end_tick: 1000,
                max_staleness_ticks: 10,
            };

            // Fail-closed: temporal inversion (current_tick < last_seen_tick)
            // MUST be treated as stale. A regressed clock is a temporal anomaly
            // that blocks promotion ([INV-ALIAS-004]).
            assert!(window.is_stale(100, 50));
            assert!(window.is_stale(200, 100));
            assert!(window.is_stale(1, 0));
        }
    }

    mod promotion_gate_tests {
        use super::*;

        #[test]
        fn blocks_on_unresolved_defects() {
            let result = AliasReconciliationResult {
                resolved_count: 5,
                unresolved_defects: vec![AliasReconciliationDefect {
                    ticket_alias: "TCK-001".to_string(),
                    expected_work_id: make_hash(0x01),
                    actual_work_id: make_hash(0x02),
                    defect_class: DefectClass::Mismatch,
                    detected_at_tick: 100,
                }],
            };

            assert!(!promotion_gate(&result));
        }

        #[test]
        fn passes_on_zero_defects() {
            let result = AliasReconciliationResult {
                resolved_count: 5,
                unresolved_defects: vec![],
            };

            assert!(promotion_gate(&result));
        }

        #[test]
        fn fail_closed_on_ambiguous_state() {
            // Even a single Ambiguous defect should block promotion
            let result = AliasReconciliationResult {
                resolved_count: 10,
                unresolved_defects: vec![AliasReconciliationDefect {
                    ticket_alias: "TCK-AMBIG".to_string(),
                    expected_work_id: make_hash(0x01),
                    actual_work_id: ZERO_HASH,
                    defect_class: DefectClass::Ambiguous,
                    detected_at_tick: 50,
                }],
            };

            assert!(!promotion_gate(&result));
        }
    }

    mod snapshot_sunset_tests {
        use super::*;

        #[test]
        fn full_sunset_when_all_criteria_met() {
            let criteria = SnapshotSunsetCriteria {
                min_reconciled_ticks: 10,
                zero_defects_required: true,
            };

            let status = evaluate_sunset(&criteria, 10, false);
            assert_eq!(status, SnapshotEmitterStatus::Sunset);
        }

        #[test]
        fn sunset_pending_when_ticks_met_but_defects_present() {
            let criteria = SnapshotSunsetCriteria {
                min_reconciled_ticks: 10,
                zero_defects_required: true,
            };

            let status = evaluate_sunset(&criteria, 10, true);
            assert_eq!(status, SnapshotEmitterStatus::SunsetPending);
        }

        #[test]
        fn sunset_pending_when_defects_clear_but_ticks_insufficient() {
            let criteria = SnapshotSunsetCriteria {
                min_reconciled_ticks: 10,
                zero_defects_required: true,
            };

            let status = evaluate_sunset(&criteria, 5, false);
            assert_eq!(status, SnapshotEmitterStatus::SunsetPending);
        }

        #[test]
        fn active_when_no_criteria_met() {
            let criteria = SnapshotSunsetCriteria {
                min_reconciled_ticks: 10,
                zero_defects_required: true,
            };

            let status = evaluate_sunset(&criteria, 5, true);
            assert_eq!(status, SnapshotEmitterStatus::Active);
        }

        #[test]
        fn sunset_without_defect_requirement() {
            let criteria = SnapshotSunsetCriteria {
                min_reconciled_ticks: 10,
                zero_defects_required: false,
            };

            // Even with defects, if zero_defects_required is false,
            // ticks alone suffice.
            let status = evaluate_sunset(&criteria, 10, true);
            assert_eq!(status, SnapshotEmitterStatus::Sunset);
        }

        #[test]
        fn zero_min_ticks_sunset_immediately() {
            let criteria = SnapshotSunsetCriteria {
                min_reconciled_ticks: 0,
                zero_defects_required: false,
            };

            let status = evaluate_sunset(&criteria, 0, false);
            assert_eq!(status, SnapshotEmitterStatus::Sunset);
        }

        #[test]
        fn display_implementations() {
            assert_eq!(format!("{}", SnapshotEmitterStatus::Active), "active");
            assert_eq!(
                format!("{}", SnapshotEmitterStatus::SunsetPending),
                "sunset_pending"
            );
            assert_eq!(format!("{}", SnapshotEmitterStatus::Sunset), "sunset");
        }

        #[test]
        fn defect_class_display() {
            assert_eq!(format!("{}", DefectClass::NotFound), "not_found");
            assert_eq!(format!("{}", DefectClass::Mismatch), "mismatch");
            assert_eq!(format!("{}", DefectClass::Stale), "stale");
            assert_eq!(format!("{}", DefectClass::Ambiguous), "ambiguous");
        }
    }
}
