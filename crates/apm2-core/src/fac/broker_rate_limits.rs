// AGENT-AUTHORED
//! Broker rate limits and quotas for control-plane actions.
//!
//! Implements TCK-00568: RFC-0029 budget admission applied to control-plane
//! actions — token issuance rate, queue enqueue rate + maximum queue bytes,
//! and bundle export bytes.
//!
//! # Design
//!
//! The broker maintains a [`ControlPlaneBudget`] that tracks cumulative usage
//! counters for three control-plane dimensions:
//!
//! - **Token issuance**: number of `ChannelContextToken` tokens issued
//! - **Queue enqueue**: number of enqueue operations AND total bytes enqueued
//! - **Bundle export**: total bytes exported via bundle export operations
//!
//! Each dimension has a hard cap configured via [`ControlPlaneLimits`]. When a
//! request would exceed any cap, the broker denies with a structured
//! [`ControlPlaneDenialReceipt`] containing evidence of the exceeded dimension,
//! current usage, and the configured limit.
//!
//! # Fail-Closed Semantics
//!
//! - Missing or zero limits deny all operations for that dimension.
//! - Arithmetic overflow on counter advancement denies fail-closed.
//! - All denial paths produce a receipt with stable reason codes.
//!
//! # Thread Safety
//!
//! `ControlPlaneBudget` is **not** internally synchronized. Callers must hold
//! the same external lock that guards `&mut FacBroker` access (consistent with
//! `QueueSchedulerState` and `AntiEntropyBudget` patterns).
//!
//! # Security Invariants
//!
//! - [INV-CPRL-001] Fail-closed: missing, zero, or overflowed budget state
//!   denies the operation.
//! - [INV-CPRL-002] Budget check occurs BEFORE any state mutation (admission
//!   before mutation ordering).
//! - [INV-CPRL-003] Denial receipts include the exceeded dimension, current
//!   usage, limit, and stable reason code for audit.
//! - [INV-CPRL-004] Counter arithmetic uses `checked_add`; overflow returns Err
//!   (not wrapping).
//! - [INV-CPRL-005] All string fields in receipts are bounded.

use serde::{Deserialize, Serialize};

// ============================================================================
// Constants
// ============================================================================

/// Maximum tokens issued per budget window (hard cap).
pub const MAX_TOKEN_ISSUANCE_LIMIT: u64 = 1_000_000;

/// Maximum queue enqueue operations per budget window (hard cap).
pub const MAX_QUEUE_ENQUEUE_LIMIT: u64 = 1_000_000;

/// Maximum queue bytes per budget window (hard cap, 64 GiB).
pub const MAX_QUEUE_BYTES_LIMIT: u64 = 68_719_476_736;

/// Maximum bundle export bytes per budget window (hard cap, 64 GiB).
pub const MAX_BUNDLE_EXPORT_BYTES_LIMIT: u64 = 68_719_476_736;

/// Maximum length for denial reason strings.
const MAX_DENIAL_REASON_LENGTH: usize = 256;

// Stable denial reason codes
/// Token issuance rate exceeded.
pub const DENY_REASON_TOKEN_ISSUANCE_EXCEEDED: &str = "broker_token_issuance_rate_exceeded";
/// Queue enqueue rate exceeded.
pub const DENY_REASON_QUEUE_ENQUEUE_RATE_EXCEEDED: &str = "broker_queue_enqueue_rate_exceeded";
/// Queue bytes limit exceeded.
pub const DENY_REASON_QUEUE_BYTES_EXCEEDED: &str = "broker_queue_bytes_exceeded";
/// Bundle export bytes limit exceeded.
pub const DENY_REASON_BUNDLE_EXPORT_BYTES_EXCEEDED: &str = "broker_bundle_export_bytes_exceeded";
/// Counter overflow (terminal condition).
pub const DENY_REASON_COUNTER_OVERFLOW: &str = "broker_rate_limit_counter_overflow";

// ============================================================================
// Errors
// ============================================================================

/// Errors from control-plane budget evaluation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ControlPlaneBudgetError {
    /// The requested operation would exceed the configured limit.
    #[error("control-plane budget exceeded: {reason}")]
    BudgetExceeded {
        /// Stable denial reason code.
        reason: String,
        /// Structured denial receipt.
        receipt: ControlPlaneDenialReceipt,
    },

    /// Counter arithmetic overflowed (terminal condition).
    ///
    /// INV-CPRL-004: overflow produces a denial receipt with the same
    /// structured evidence as `BudgetExceeded` so auditors can retrieve
    /// machine-readable denial evidence for all denial paths.
    #[error("control-plane budget counter overflow: {dimension}")]
    CounterOverflow {
        /// Which dimension overflowed.
        dimension: String,
        /// Structured denial receipt (INV-CPRL-004).
        receipt: ControlPlaneDenialReceipt,
    },

    /// Limits are invalid (e.g., exceed hard caps).
    #[error("invalid control-plane limits: {detail}")]
    InvalidLimits {
        /// Detail about the validation failure.
        detail: String,
    },
}

// ============================================================================
// Configuration
// ============================================================================

/// Control-plane rate limits and quotas.
///
/// Configures hard caps for each control-plane dimension. A limit of `0` means
/// the dimension is disabled (all operations denied — fail-closed per
/// INV-CPRL-001).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlPlaneLimits {
    /// Maximum number of tokens that may be issued per budget window.
    pub max_token_issuance: u64,
    /// Maximum number of queue enqueue operations per budget window.
    pub max_queue_enqueue_ops: u64,
    /// Maximum total queue bytes per budget window.
    pub max_queue_bytes: u64,
    /// Maximum total bundle export bytes per budget window.
    pub max_bundle_export_bytes: u64,
}

impl Default for ControlPlaneLimits {
    fn default() -> Self {
        Self {
            max_token_issuance: 10_000,
            max_queue_enqueue_ops: 100_000,
            max_queue_bytes: 10_737_418_240,         // 10 GiB
            max_bundle_export_bytes: 10_737_418_240, // 10 GiB
        }
    }
}

impl ControlPlaneLimits {
    /// Validates that limits do not exceed hard caps.
    ///
    /// # Errors
    ///
    /// Returns [`ControlPlaneBudgetError::InvalidLimits`] if any limit
    /// exceeds its hard cap.
    pub fn validate(&self) -> Result<(), ControlPlaneBudgetError> {
        if self.max_token_issuance > MAX_TOKEN_ISSUANCE_LIMIT {
            return Err(ControlPlaneBudgetError::InvalidLimits {
                detail: format!(
                    "max_token_issuance {} exceeds hard cap {MAX_TOKEN_ISSUANCE_LIMIT}",
                    self.max_token_issuance
                ),
            });
        }
        if self.max_queue_enqueue_ops > MAX_QUEUE_ENQUEUE_LIMIT {
            return Err(ControlPlaneBudgetError::InvalidLimits {
                detail: format!(
                    "max_queue_enqueue_ops {} exceeds hard cap {MAX_QUEUE_ENQUEUE_LIMIT}",
                    self.max_queue_enqueue_ops
                ),
            });
        }
        if self.max_queue_bytes > MAX_QUEUE_BYTES_LIMIT {
            return Err(ControlPlaneBudgetError::InvalidLimits {
                detail: format!(
                    "max_queue_bytes {} exceeds hard cap {MAX_QUEUE_BYTES_LIMIT}",
                    self.max_queue_bytes
                ),
            });
        }
        if self.max_bundle_export_bytes > MAX_BUNDLE_EXPORT_BYTES_LIMIT {
            return Err(ControlPlaneBudgetError::InvalidLimits {
                detail: format!(
                    "max_bundle_export_bytes {} exceeds hard cap {MAX_BUNDLE_EXPORT_BYTES_LIMIT}",
                    self.max_bundle_export_bytes
                ),
            });
        }
        Ok(())
    }
}

// ============================================================================
// Budget tracker
// ============================================================================

/// Control-plane budget tracker.
///
/// Tracks cumulative usage counters for rate-limited control-plane dimensions.
/// Counters are monotonically increasing within a budget window. The budget
/// window is reset by calling [`Self::reset()`].
///
/// # Synchronization
///
/// Not internally synchronized. Callers must hold the same external lock that
/// guards `&mut FacBroker` access.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlPlaneBudget {
    /// Configured limits for this budget window.
    limits: ControlPlaneLimits,
    /// Cumulative tokens issued in the current window.
    tokens_issued: u64,
    /// Cumulative queue enqueue operations in the current window.
    queue_enqueue_ops: u64,
    /// Cumulative queue bytes enqueued in the current window.
    queue_bytes: u64,
    /// Cumulative bundle export bytes in the current window.
    bundle_export_bytes: u64,
}

impl ControlPlaneBudget {
    /// Creates a new budget tracker with the given limits.
    ///
    /// # Errors
    ///
    /// Returns an error if limits exceed hard caps.
    pub fn new(limits: ControlPlaneLimits) -> Result<Self, ControlPlaneBudgetError> {
        limits.validate()?;
        Ok(Self {
            limits,
            tokens_issued: 0,
            queue_enqueue_ops: 0,
            queue_bytes: 0,
            bundle_export_bytes: 0,
        })
    }

    /// Resets all counters to zero for a new budget window.
    pub const fn reset(&mut self) {
        self.tokens_issued = 0;
        self.queue_enqueue_ops = 0;
        self.queue_bytes = 0;
        self.bundle_export_bytes = 0;
    }

    /// Returns the configured limits.
    #[must_use]
    pub const fn limits(&self) -> &ControlPlaneLimits {
        &self.limits
    }

    /// Returns the current token issuance count.
    #[must_use]
    pub const fn tokens_issued(&self) -> u64 {
        self.tokens_issued
    }

    /// Returns the current queue enqueue operation count.
    #[must_use]
    pub const fn queue_enqueue_ops(&self) -> u64 {
        self.queue_enqueue_ops
    }

    /// Returns the current queue bytes count.
    #[must_use]
    pub const fn queue_bytes(&self) -> u64 {
        self.queue_bytes
    }

    /// Returns the current bundle export bytes count.
    #[must_use]
    pub const fn bundle_export_bytes(&self) -> u64 {
        self.bundle_export_bytes
    }

    // -----------------------------------------------------------------------
    // Admission checks (check BEFORE mutation — INV-CPRL-002)
    // -----------------------------------------------------------------------

    /// Checks and records a token issuance against the budget.
    ///
    /// INV-CPRL-002: Budget check occurs before counter mutation.
    /// INV-CPRL-004: Uses checked arithmetic.
    ///
    /// # Errors
    ///
    /// Returns [`ControlPlaneBudgetError::BudgetExceeded`] if the issuance
    /// would exceed the configured limit, or
    /// [`ControlPlaneBudgetError::CounterOverflow`] if counter arithmetic
    /// overflows.
    pub fn admit_token_issuance(&mut self) -> Result<(), ControlPlaneBudgetError> {
        // INV-CPRL-001: Zero limit means disabled (fail-closed).
        if self.limits.max_token_issuance == 0 {
            return Err(self.deny_token_issuance());
        }

        // Check BEFORE mutate (INV-CPRL-002).
        let next = self.tokens_issued.checked_add(1).ok_or_else(|| {
            ControlPlaneBudgetError::CounterOverflow {
                dimension: "tokens_issued".to_string(),
                receipt: ControlPlaneDenialReceipt {
                    dimension: ControlPlaneDimension::TokenIssuance,
                    current_usage: self.tokens_issued,
                    limit: self.limits.max_token_issuance,
                    requested_increment: 1,
                    reason: truncate_reason(DENY_REASON_COUNTER_OVERFLOW),
                },
            }
        })?;

        if next > self.limits.max_token_issuance {
            return Err(self.deny_token_issuance());
        }

        // Admission passed — commit the counter.
        self.tokens_issued = next;
        Ok(())
    }

    /// Checks and records a queue enqueue operation against the budget.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Size in bytes of the enqueued item.
    ///
    /// # Errors
    ///
    /// Returns [`ControlPlaneBudgetError::BudgetExceeded`] if the enqueue
    /// would exceed either the operation count or byte limit.
    pub fn admit_queue_enqueue(&mut self, bytes: u64) -> Result<(), ControlPlaneBudgetError> {
        // INV-CPRL-001: Zero limit means disabled.
        if self.limits.max_queue_enqueue_ops == 0 {
            return Err(self.deny_queue_enqueue_rate());
        }
        if self.limits.max_queue_bytes == 0 {
            return Err(self.deny_queue_bytes(bytes));
        }

        // Check BEFORE mutate (INV-CPRL-002).
        let next_ops = self.queue_enqueue_ops.checked_add(1).ok_or_else(|| {
            ControlPlaneBudgetError::CounterOverflow {
                dimension: "queue_enqueue_ops".to_string(),
                receipt: ControlPlaneDenialReceipt {
                    dimension: ControlPlaneDimension::QueueEnqueueOps,
                    current_usage: self.queue_enqueue_ops,
                    limit: self.limits.max_queue_enqueue_ops,
                    requested_increment: 1,
                    reason: truncate_reason(DENY_REASON_COUNTER_OVERFLOW),
                },
            }
        })?;
        let next_bytes = self.queue_bytes.checked_add(bytes).ok_or_else(|| {
            ControlPlaneBudgetError::CounterOverflow {
                dimension: "queue_bytes".to_string(),
                receipt: ControlPlaneDenialReceipt {
                    dimension: ControlPlaneDimension::QueueBytes,
                    current_usage: self.queue_bytes,
                    limit: self.limits.max_queue_bytes,
                    requested_increment: bytes,
                    reason: truncate_reason(DENY_REASON_COUNTER_OVERFLOW),
                },
            }
        })?;

        if next_ops > self.limits.max_queue_enqueue_ops {
            return Err(self.deny_queue_enqueue_rate());
        }
        if next_bytes > self.limits.max_queue_bytes {
            return Err(self.deny_queue_bytes(bytes));
        }

        // Admission passed — commit both counters atomically.
        self.queue_enqueue_ops = next_ops;
        self.queue_bytes = next_bytes;
        Ok(())
    }

    /// Checks and records a bundle export against the budget.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Size in bytes of the exported bundle.
    ///
    /// # Errors
    ///
    /// Returns [`ControlPlaneBudgetError::BudgetExceeded`] if the export
    /// would exceed the byte limit.
    pub fn admit_bundle_export(&mut self, bytes: u64) -> Result<(), ControlPlaneBudgetError> {
        // INV-CPRL-001: Zero limit means disabled.
        if self.limits.max_bundle_export_bytes == 0 {
            return Err(self.deny_bundle_export(bytes));
        }

        // Check BEFORE mutate (INV-CPRL-002).
        let next = self.bundle_export_bytes.checked_add(bytes).ok_or_else(|| {
            ControlPlaneBudgetError::CounterOverflow {
                dimension: "bundle_export_bytes".to_string(),
                receipt: ControlPlaneDenialReceipt {
                    dimension: ControlPlaneDimension::BundleExportBytes,
                    current_usage: self.bundle_export_bytes,
                    limit: self.limits.max_bundle_export_bytes,
                    requested_increment: bytes,
                    reason: truncate_reason(DENY_REASON_COUNTER_OVERFLOW),
                },
            }
        })?;

        if next > self.limits.max_bundle_export_bytes {
            return Err(self.deny_bundle_export(bytes));
        }

        // Admission passed — commit the counter.
        self.bundle_export_bytes = next;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Denial receipt builders (INV-CPRL-003)
    // -----------------------------------------------------------------------

    fn deny_token_issuance(&self) -> ControlPlaneBudgetError {
        ControlPlaneBudgetError::BudgetExceeded {
            reason: DENY_REASON_TOKEN_ISSUANCE_EXCEEDED.to_string(),
            receipt: ControlPlaneDenialReceipt {
                dimension: ControlPlaneDimension::TokenIssuance,
                current_usage: self.tokens_issued,
                limit: self.limits.max_token_issuance,
                requested_increment: 1,
                reason: truncate_reason(DENY_REASON_TOKEN_ISSUANCE_EXCEEDED),
            },
        }
    }

    fn deny_queue_enqueue_rate(&self) -> ControlPlaneBudgetError {
        ControlPlaneBudgetError::BudgetExceeded {
            reason: DENY_REASON_QUEUE_ENQUEUE_RATE_EXCEEDED.to_string(),
            receipt: ControlPlaneDenialReceipt {
                dimension: ControlPlaneDimension::QueueEnqueueOps,
                current_usage: self.queue_enqueue_ops,
                limit: self.limits.max_queue_enqueue_ops,
                requested_increment: 1,
                reason: truncate_reason(DENY_REASON_QUEUE_ENQUEUE_RATE_EXCEEDED),
            },
        }
    }

    fn deny_queue_bytes(&self, requested_bytes: u64) -> ControlPlaneBudgetError {
        ControlPlaneBudgetError::BudgetExceeded {
            reason: DENY_REASON_QUEUE_BYTES_EXCEEDED.to_string(),
            receipt: ControlPlaneDenialReceipt {
                dimension: ControlPlaneDimension::QueueBytes,
                current_usage: self.queue_bytes,
                limit: self.limits.max_queue_bytes,
                requested_increment: requested_bytes,
                reason: truncate_reason(DENY_REASON_QUEUE_BYTES_EXCEEDED),
            },
        }
    }

    fn deny_bundle_export(&self, requested_bytes: u64) -> ControlPlaneBudgetError {
        ControlPlaneBudgetError::BudgetExceeded {
            reason: DENY_REASON_BUNDLE_EXPORT_BYTES_EXCEEDED.to_string(),
            receipt: ControlPlaneDenialReceipt {
                dimension: ControlPlaneDimension::BundleExportBytes,
                current_usage: self.bundle_export_bytes,
                limit: self.limits.max_bundle_export_bytes,
                requested_increment: requested_bytes,
                reason: truncate_reason(DENY_REASON_BUNDLE_EXPORT_BYTES_EXCEEDED),
            },
        }
    }
}

// ============================================================================
// Denial receipts
// ============================================================================

/// Control-plane dimension that was exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlPlaneDimension {
    /// Token issuance count.
    TokenIssuance,
    /// Queue enqueue operation count.
    QueueEnqueueOps,
    /// Queue bytes total.
    QueueBytes,
    /// Bundle export bytes total.
    BundleExportBytes,
}

/// Structured denial receipt for control-plane budget violations.
///
/// Contains evidence of the exceeded dimension, current usage, the configured
/// limit, and a stable reason code for audit (INV-CPRL-003).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlPlaneDenialReceipt {
    /// Which control-plane dimension was exceeded.
    pub dimension: ControlPlaneDimension,
    /// Current usage counter at the time of denial.
    pub current_usage: u64,
    /// Configured limit for this dimension.
    pub limit: u64,
    /// The increment that was requested (and denied).
    pub requested_increment: u64,
    /// Stable denial reason code.
    pub reason: String,
}

// ============================================================================
// Helpers
// ============================================================================

/// Truncates a reason string to the maximum allowed length (UTF-8 safe).
///
/// Uses `char_indices` to find a safe truncation boundary, ensuring we never
/// split a multi-byte UTF-8 character (INV-CPRL-005, RSK-2406 panic safety).
fn truncate_reason(reason: &str) -> String {
    if reason.len() <= MAX_DENIAL_REASON_LENGTH {
        reason.to_string()
    } else {
        // Find the last char boundary at or before MAX_DENIAL_REASON_LENGTH.
        let boundary = reason
            .char_indices()
            .take_while(|&(i, _)| i <= MAX_DENIAL_REASON_LENGTH)
            .last()
            .map_or(0, |(i, _)| i);
        reason[..boundary].to_string()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn default_limits() -> ControlPlaneLimits {
        ControlPlaneLimits {
            max_token_issuance: 5,
            max_queue_enqueue_ops: 3,
            max_queue_bytes: 100,
            max_bundle_export_bytes: 200,
        }
    }

    // -----------------------------------------------------------------------
    // ControlPlaneLimits validation
    // -----------------------------------------------------------------------

    #[test]
    fn default_limits_pass_validation() {
        let limits = ControlPlaneLimits::default();
        assert!(limits.validate().is_ok());
    }

    #[test]
    fn limits_exceeding_hard_caps_rejected() {
        let limits = ControlPlaneLimits {
            max_token_issuance: MAX_TOKEN_ISSUANCE_LIMIT + 1,
            ..ControlPlaneLimits::default()
        };
        let err = limits.validate().unwrap_err();
        assert!(
            matches!(err, ControlPlaneBudgetError::InvalidLimits { .. }),
            "expected InvalidLimits, got {err:?}"
        );
    }

    #[test]
    fn queue_ops_exceeding_hard_cap_rejected() {
        let limits = ControlPlaneLimits {
            max_queue_enqueue_ops: MAX_QUEUE_ENQUEUE_LIMIT + 1,
            ..ControlPlaneLimits::default()
        };
        assert!(matches!(
            limits.validate(),
            Err(ControlPlaneBudgetError::InvalidLimits { .. })
        ));
    }

    #[test]
    fn queue_bytes_exceeding_hard_cap_rejected() {
        let limits = ControlPlaneLimits {
            max_queue_bytes: MAX_QUEUE_BYTES_LIMIT + 1,
            ..ControlPlaneLimits::default()
        };
        assert!(matches!(
            limits.validate(),
            Err(ControlPlaneBudgetError::InvalidLimits { .. })
        ));
    }

    #[test]
    fn bundle_bytes_exceeding_hard_cap_rejected() {
        let limits = ControlPlaneLimits {
            max_bundle_export_bytes: MAX_BUNDLE_EXPORT_BYTES_LIMIT + 1,
            ..ControlPlaneLimits::default()
        };
        assert!(matches!(
            limits.validate(),
            Err(ControlPlaneBudgetError::InvalidLimits { .. })
        ));
    }

    // -----------------------------------------------------------------------
    // Token issuance admission
    // -----------------------------------------------------------------------

    #[test]
    fn token_issuance_within_limit_succeeds() {
        let mut budget = ControlPlaneBudget::new(default_limits()).unwrap();
        for _ in 0..5 {
            assert!(budget.admit_token_issuance().is_ok());
        }
        assert_eq!(budget.tokens_issued(), 5);
    }

    #[test]
    fn token_issuance_exceeding_limit_denied_with_receipt() {
        let mut budget = ControlPlaneBudget::new(default_limits()).unwrap();
        for _ in 0..5 {
            budget.admit_token_issuance().unwrap();
        }

        let err = budget.admit_token_issuance().unwrap_err();
        match err {
            ControlPlaneBudgetError::BudgetExceeded { reason, receipt } => {
                assert_eq!(reason, DENY_REASON_TOKEN_ISSUANCE_EXCEEDED);
                assert_eq!(receipt.dimension, ControlPlaneDimension::TokenIssuance);
                assert_eq!(receipt.current_usage, 5);
                assert_eq!(receipt.limit, 5);
                assert_eq!(receipt.requested_increment, 1);
            },
            other => panic!("expected BudgetExceeded, got {other:?}"),
        }
        // Counter must NOT advance past the limit.
        assert_eq!(budget.tokens_issued(), 5);
    }

    #[test]
    fn token_issuance_zero_limit_denied_immediately() {
        let limits = ControlPlaneLimits {
            max_token_issuance: 0,
            ..default_limits()
        };
        let mut budget = ControlPlaneBudget::new(limits).unwrap();
        let err = budget.admit_token_issuance().unwrap_err();
        assert!(matches!(
            err,
            ControlPlaneBudgetError::BudgetExceeded { .. }
        ));
        assert_eq!(budget.tokens_issued(), 0);
    }

    // -----------------------------------------------------------------------
    // Queue enqueue admission
    // -----------------------------------------------------------------------

    #[test]
    fn queue_enqueue_within_limits_succeeds() {
        let mut budget = ControlPlaneBudget::new(default_limits()).unwrap();
        assert!(budget.admit_queue_enqueue(30).is_ok());
        assert!(budget.admit_queue_enqueue(30).is_ok());
        assert_eq!(budget.queue_enqueue_ops(), 2);
        assert_eq!(budget.queue_bytes(), 60);
    }

    #[test]
    fn queue_enqueue_ops_exceeded_denied() {
        let mut budget = ControlPlaneBudget::new(default_limits()).unwrap();
        for _ in 0..3 {
            budget.admit_queue_enqueue(10).unwrap();
        }

        let err = budget.admit_queue_enqueue(10).unwrap_err();
        match err {
            ControlPlaneBudgetError::BudgetExceeded { reason, receipt } => {
                assert_eq!(reason, DENY_REASON_QUEUE_ENQUEUE_RATE_EXCEEDED);
                assert_eq!(receipt.dimension, ControlPlaneDimension::QueueEnqueueOps);
                assert_eq!(receipt.current_usage, 3);
                assert_eq!(receipt.limit, 3);
            },
            other => panic!("expected BudgetExceeded, got {other:?}"),
        }
        // Counters must NOT advance.
        assert_eq!(budget.queue_enqueue_ops(), 3);
        assert_eq!(budget.queue_bytes(), 30);
    }

    #[test]
    fn queue_bytes_exceeded_denied() {
        let mut budget = ControlPlaneBudget::new(default_limits()).unwrap();
        budget.admit_queue_enqueue(90).unwrap();

        let err = budget.admit_queue_enqueue(20).unwrap_err();
        match err {
            ControlPlaneBudgetError::BudgetExceeded { reason, receipt } => {
                assert_eq!(reason, DENY_REASON_QUEUE_BYTES_EXCEEDED);
                assert_eq!(receipt.dimension, ControlPlaneDimension::QueueBytes);
                assert_eq!(receipt.current_usage, 90);
                assert_eq!(receipt.limit, 100);
                assert_eq!(receipt.requested_increment, 20);
            },
            other => panic!("expected BudgetExceeded, got {other:?}"),
        }
        // Only 1 op counted, bytes at 90.
        assert_eq!(budget.queue_enqueue_ops(), 1);
        assert_eq!(budget.queue_bytes(), 90);
    }

    #[test]
    fn queue_enqueue_zero_ops_limit_denied() {
        let limits = ControlPlaneLimits {
            max_queue_enqueue_ops: 0,
            ..default_limits()
        };
        let mut budget = ControlPlaneBudget::new(limits).unwrap();
        assert!(matches!(
            budget.admit_queue_enqueue(10),
            Err(ControlPlaneBudgetError::BudgetExceeded { .. })
        ));
    }

    #[test]
    fn queue_enqueue_zero_bytes_limit_denied() {
        let limits = ControlPlaneLimits {
            max_queue_bytes: 0,
            ..default_limits()
        };
        let mut budget = ControlPlaneBudget::new(limits).unwrap();
        assert!(matches!(
            budget.admit_queue_enqueue(10),
            Err(ControlPlaneBudgetError::BudgetExceeded { .. })
        ));
    }

    // -----------------------------------------------------------------------
    // Bundle export admission
    // -----------------------------------------------------------------------

    #[test]
    fn bundle_export_within_limit_succeeds() {
        let mut budget = ControlPlaneBudget::new(default_limits()).unwrap();
        assert!(budget.admit_bundle_export(100).is_ok());
        assert!(budget.admit_bundle_export(50).is_ok());
        assert_eq!(budget.bundle_export_bytes(), 150);
    }

    #[test]
    fn bundle_export_exceeding_limit_denied_with_receipt() {
        let mut budget = ControlPlaneBudget::new(default_limits()).unwrap();
        budget.admit_bundle_export(150).unwrap();

        let err = budget.admit_bundle_export(60).unwrap_err();
        match err {
            ControlPlaneBudgetError::BudgetExceeded { reason, receipt } => {
                assert_eq!(reason, DENY_REASON_BUNDLE_EXPORT_BYTES_EXCEEDED);
                assert_eq!(receipt.dimension, ControlPlaneDimension::BundleExportBytes);
                assert_eq!(receipt.current_usage, 150);
                assert_eq!(receipt.limit, 200);
                assert_eq!(receipt.requested_increment, 60);
            },
            other => panic!("expected BudgetExceeded, got {other:?}"),
        }
        assert_eq!(budget.bundle_export_bytes(), 150);
    }

    #[test]
    fn bundle_export_zero_limit_denied() {
        let limits = ControlPlaneLimits {
            max_bundle_export_bytes: 0,
            ..default_limits()
        };
        let mut budget = ControlPlaneBudget::new(limits).unwrap();
        assert!(matches!(
            budget.admit_bundle_export(1),
            Err(ControlPlaneBudgetError::BudgetExceeded { .. })
        ));
    }

    // -----------------------------------------------------------------------
    // Reset
    // -----------------------------------------------------------------------

    #[test]
    fn reset_clears_all_counters() {
        let mut budget = ControlPlaneBudget::new(default_limits()).unwrap();
        budget.admit_token_issuance().unwrap();
        budget.admit_queue_enqueue(50).unwrap();
        budget.admit_bundle_export(100).unwrap();

        budget.reset();

        assert_eq!(budget.tokens_issued(), 0);
        assert_eq!(budget.queue_enqueue_ops(), 0);
        assert_eq!(budget.queue_bytes(), 0);
        assert_eq!(budget.bundle_export_bytes(), 0);
    }

    // -----------------------------------------------------------------------
    // Counter overflow
    // -----------------------------------------------------------------------

    #[test]
    fn token_issuance_counter_overflow_denied() {
        let limits = ControlPlaneLimits {
            max_token_issuance: MAX_TOKEN_ISSUANCE_LIMIT,
            ..default_limits()
        };
        let mut budget = ControlPlaneBudget::new(limits).unwrap();
        // Force counter to near-max.
        budget.tokens_issued = u64::MAX;
        let err = budget.admit_token_issuance().unwrap_err();
        assert!(
            matches!(err, ControlPlaneBudgetError::CounterOverflow { .. }),
            "expected CounterOverflow, got {err:?}"
        );
    }

    #[test]
    fn queue_bytes_counter_overflow_denied() {
        let limits = ControlPlaneLimits {
            max_queue_bytes: MAX_QUEUE_BYTES_LIMIT,
            max_queue_enqueue_ops: MAX_QUEUE_ENQUEUE_LIMIT,
            ..default_limits()
        };
        let mut budget = ControlPlaneBudget::new(limits).unwrap();
        budget.queue_bytes = u64::MAX - 10;
        let err = budget.admit_queue_enqueue(20).unwrap_err();
        assert!(
            matches!(err, ControlPlaneBudgetError::CounterOverflow { .. }),
            "expected CounterOverflow, got {err:?}"
        );
    }

    #[test]
    fn bundle_export_counter_overflow_denied() {
        let limits = ControlPlaneLimits {
            max_bundle_export_bytes: MAX_BUNDLE_EXPORT_BYTES_LIMIT,
            ..default_limits()
        };
        let mut budget = ControlPlaneBudget::new(limits).unwrap();
        budget.bundle_export_bytes = u64::MAX - 10;
        let err = budget.admit_bundle_export(20).unwrap_err();
        assert!(
            matches!(err, ControlPlaneBudgetError::CounterOverflow { .. }),
            "expected CounterOverflow, got {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Serialization round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn budget_serialization_round_trip() {
        let mut budget = ControlPlaneBudget::new(default_limits()).unwrap();
        budget.admit_token_issuance().unwrap();
        budget.admit_queue_enqueue(42).unwrap();
        budget.admit_bundle_export(99).unwrap();

        let json = serde_json::to_string(&budget).expect("serialize");
        let loaded: ControlPlaneBudget = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(budget, loaded);
    }

    #[test]
    fn denial_receipt_serialization_round_trip() {
        let receipt = ControlPlaneDenialReceipt {
            dimension: ControlPlaneDimension::TokenIssuance,
            current_usage: 42,
            limit: 100,
            requested_increment: 1,
            reason: DENY_REASON_TOKEN_ISSUANCE_EXCEEDED.to_string(),
        };
        let json = serde_json::to_string(&receipt).expect("serialize");
        let loaded: ControlPlaneDenialReceipt = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(receipt, loaded);
    }

    // -----------------------------------------------------------------------
    // Flooding test (Definition of Done)
    // -----------------------------------------------------------------------

    #[test]
    fn flooding_token_requests_hits_deny_not_collapse() {
        let limits = ControlPlaneLimits {
            max_token_issuance: 100,
            ..default_limits()
        };
        let mut budget = ControlPlaneBudget::new(limits).unwrap();
        let mut denied = 0usize;
        for _ in 0..1_000 {
            if budget.admit_token_issuance().is_err() {
                denied += 1;
            }
        }
        // Exactly 900 should be denied (100 allowed, 900 denied).
        assert_eq!(denied, 900);
        assert_eq!(budget.tokens_issued(), 100);
    }

    #[test]
    fn flooding_enqueue_requests_hits_deny_not_collapse() {
        let limits = ControlPlaneLimits {
            max_queue_enqueue_ops: 50,
            max_queue_bytes: 500,
            ..default_limits()
        };
        let mut budget = ControlPlaneBudget::new(limits).unwrap();
        let mut denied = 0usize;
        for _ in 0..200 {
            if budget.admit_queue_enqueue(5).is_err() {
                denied += 1;
            }
        }
        // 50 ops allowed, 150 denied.
        assert_eq!(denied, 150);
        assert_eq!(budget.queue_enqueue_ops(), 50);
        assert_eq!(budget.queue_bytes(), 250);
    }

    // -----------------------------------------------------------------------
    // Counter overflow produces denial receipt (INV-CPRL-004)
    // -----------------------------------------------------------------------

    #[test]
    fn counter_overflow_produces_receipt_token_issuance() {
        let limits = ControlPlaneLimits {
            max_token_issuance: MAX_TOKEN_ISSUANCE_LIMIT,
            ..default_limits()
        };
        let mut budget = ControlPlaneBudget::new(limits).unwrap();
        budget.tokens_issued = u64::MAX;
        let err = budget.admit_token_issuance().unwrap_err();
        match err {
            ControlPlaneBudgetError::CounterOverflow { dimension, receipt } => {
                assert_eq!(dimension, "tokens_issued");
                assert_eq!(receipt.dimension, ControlPlaneDimension::TokenIssuance);
                assert_eq!(receipt.current_usage, u64::MAX);
                assert_eq!(receipt.limit, MAX_TOKEN_ISSUANCE_LIMIT);
                assert_eq!(receipt.requested_increment, 1);
                assert_eq!(receipt.reason, DENY_REASON_COUNTER_OVERFLOW);
            },
            other => panic!("expected CounterOverflow with receipt, got {other:?}"),
        }
    }

    #[test]
    fn counter_overflow_produces_receipt_bundle_export() {
        let limits = ControlPlaneLimits {
            max_bundle_export_bytes: MAX_BUNDLE_EXPORT_BYTES_LIMIT,
            ..default_limits()
        };
        let mut budget = ControlPlaneBudget::new(limits).unwrap();
        budget.bundle_export_bytes = u64::MAX - 10;
        let err = budget.admit_bundle_export(20).unwrap_err();
        match err {
            ControlPlaneBudgetError::CounterOverflow { dimension, receipt } => {
                assert_eq!(dimension, "bundle_export_bytes");
                assert_eq!(receipt.dimension, ControlPlaneDimension::BundleExportBytes);
                assert_eq!(receipt.current_usage, u64::MAX - 10);
                assert_eq!(receipt.requested_increment, 20);
                assert_eq!(receipt.reason, DENY_REASON_COUNTER_OVERFLOW);
            },
            other => panic!("expected CounterOverflow with receipt, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // UTF-8-safe truncation
    // -----------------------------------------------------------------------

    #[test]
    fn truncate_reason_utf8_safe() {
        // Build a string with multi-byte chars that would panic with naive
        // byte slicing at MAX_DENIAL_REASON_LENGTH.
        let multi_byte = "\u{1F600}"; // 4-byte emoji
        let long_reason = multi_byte.repeat(100); // 400 bytes > MAX_DENIAL_REASON_LENGTH
        // Should NOT panic.
        let truncated = truncate_reason(&long_reason);
        assert!(truncated.len() <= MAX_DENIAL_REASON_LENGTH);
        // Verify the truncated string is valid UTF-8.
        let _ = truncated.as_str();
    }

    #[test]
    fn truncate_reason_short_string_unchanged() {
        let short = "hello";
        assert_eq!(truncate_reason(short), "hello");
    }
}
