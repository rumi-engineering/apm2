//! Budget tracking for episode resource management.
//!
//! This module implements the `BudgetTracker` per TCK-00165. The tracker
//! manages resource consumption during episode execution, enforcing limits
//! from the episode envelope.
//!
//! # Architecture
//!
//! ```text
//! EpisodeEnvelope
//!     │
//!     └── budget: EpisodeBudget (immutable limits)
//!               │
//!               ▼
//!         BudgetTracker
//!               │
//!               ├── charge(delta) ──► Updates consumed counters atomically
//!               ├── reconcile(estimate, actual) ──► Adjusts for actual usage
//!               ├── remaining() ──► Returns available budget
//!               └── is_exhausted() ──► Checks if any limit exceeded
//! ```
//!
//! # Security Model
//!
//! - Budget checks are **fail-closed**: if any limit is exceeded, the operation
//!   is denied
//! - All arithmetic uses checked operations to prevent overflow
//! - Zero in budget means unlimited for that resource
//! - Atomic CAS loops ensure race-condition-free budget charging
//! - Counter overflow is detected and rejected (fail-closed)
//!
//! # Contract References
//!
//! - TCK-00165: Tool execution and budget charging
//! - AD-EPISODE-001: Immutable episode envelope with budget
//! - CTR-2504: Defensive time handling

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::budget::EpisodeBudget;
use super::decision::BudgetDelta;

// =============================================================================
// BudgetExhaustedError
// =============================================================================

/// Error indicating budget exhaustion.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum BudgetExhaustedError {
    /// Token budget exceeded.
    #[error("token budget exceeded: requested {requested}, remaining {remaining}")]
    Tokens {
        /// Tokens requested.
        requested: u64,
        /// Tokens remaining.
        remaining: u64,
    },

    /// Tool calls budget exceeded.
    #[error("tool calls budget exceeded: requested {requested}, remaining {remaining}")]
    ToolCalls {
        /// Tool calls requested.
        requested: u32,
        /// Tool calls remaining.
        remaining: u32,
    },

    /// Wall clock time budget exceeded.
    #[error("wall time budget exceeded: requested {requested}ms, remaining {remaining}ms")]
    WallTime {
        /// Milliseconds requested.
        requested: u64,
        /// Milliseconds remaining.
        remaining: u64,
    },

    /// CPU time budget exceeded.
    #[error("CPU time budget exceeded: requested {requested}ms, remaining {remaining}ms")]
    CpuTime {
        /// Milliseconds requested.
        requested: u64,
        /// Milliseconds remaining.
        remaining: u64,
    },

    /// I/O bytes budget exceeded.
    #[error("I/O bytes budget exceeded: requested {requested}, remaining {remaining}")]
    BytesIo {
        /// Bytes requested.
        requested: u64,
        /// Bytes remaining.
        remaining: u64,
    },

    /// Evidence bytes budget exceeded.
    #[error("evidence bytes budget exceeded: requested {requested}, remaining {remaining}")]
    EvidenceBytes {
        /// Bytes requested.
        requested: u64,
        /// Bytes remaining.
        remaining: u64,
    },

    /// Counter overflow would occur.
    #[error("{resource} counter overflow: current {current}, adding {adding}")]
    Overflow {
        /// Resource type that would overflow.
        resource: &'static str,
        /// Current counter value.
        current: u64,
        /// Amount being added.
        adding: u64,
    },

    /// Actual usage exceeded estimate (reconciliation failure).
    #[error("{resource} actual usage {actual} exceeded estimate {estimate}")]
    ActualExceededEstimate {
        /// Resource type that exceeded.
        resource: &'static str,
        /// Estimated amount that was charged.
        estimate: u64,
        /// Actual amount consumed.
        actual: u64,
    },
}

impl BudgetExhaustedError {
    /// Returns the resource type that was exhausted.
    #[must_use]
    pub const fn resource(&self) -> &'static str {
        match self {
            Self::Tokens { .. } => "tokens",
            Self::ToolCalls { .. } => "tool_calls",
            Self::WallTime { .. } => "wall_time",
            Self::CpuTime { .. } => "cpu_time",
            Self::BytesIo { .. } => "bytes_io",
            Self::EvidenceBytes { .. } => "evidence_bytes",
            Self::Overflow { resource, .. } | Self::ActualExceededEstimate { resource, .. } => {
                resource
            },
        }
    }
}

// =============================================================================
// BudgetTracker
// =============================================================================

/// Thread-safe budget tracker for episode resource management.
///
/// The tracker maintains atomic counters for consumed resources and enforces
/// limits from the episode envelope. All operations are thread-safe.
///
/// # Invariants
///
/// - [INV-BT001] Consumed values never exceed limit values (enforced by
///   `charge`)
/// - [INV-BT002] Original limits are immutable after construction
/// - [INV-BT003] Zero limit means unlimited (no enforcement)
///
/// # Example
///
/// ```rust
/// use apm2_daemon::episode::{BudgetDelta, BudgetTracker, EpisodeBudget};
///
/// let budget = EpisodeBudget::builder()
///     .tokens(10_000)
///     .tool_calls(100)
///     .build();
///
/// let tracker = BudgetTracker::from_envelope(budget);
///
/// // Charge a tool call
/// let delta = BudgetDelta::single_call().with_tokens(500);
/// tracker.charge(&delta).expect("budget available");
///
/// // Check remaining
/// let remaining = tracker.remaining();
/// assert_eq!(remaining.tokens(), 9_500);
/// assert_eq!(remaining.tool_calls(), 99);
/// ```
#[derive(Debug)]
pub struct BudgetTracker {
    /// Original budget limits (immutable).
    limits: EpisodeBudget,

    /// Tokens consumed.
    tokens_consumed: AtomicU64,

    /// Tool calls consumed.
    tool_calls_consumed: AtomicU32,

    /// Wall clock time consumed (milliseconds).
    wall_ms_consumed: AtomicU64,

    /// CPU time consumed (milliseconds).
    cpu_ms_consumed: AtomicU64,

    /// I/O bytes consumed.
    bytes_io_consumed: AtomicU64,

    /// Evidence bytes consumed.
    evidence_bytes_consumed: AtomicU64,
}

impl BudgetTracker {
    /// Creates a new budget tracker from an episode envelope budget.
    ///
    /// # Arguments
    ///
    /// * `budget` - The budget limits from the episode envelope
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // AtomicU64::new is not const in stable
    pub fn from_envelope(budget: EpisodeBudget) -> Self {
        Self {
            limits: budget,
            tokens_consumed: AtomicU64::new(0),
            tool_calls_consumed: AtomicU32::new(0),
            wall_ms_consumed: AtomicU64::new(0),
            cpu_ms_consumed: AtomicU64::new(0),
            bytes_io_consumed: AtomicU64::new(0),
            evidence_bytes_consumed: AtomicU64::new(0),
        }
    }

    /// Creates an unlimited budget tracker.
    ///
    /// This is useful for testing or when budget enforcement is disabled.
    #[must_use]
    pub fn unlimited() -> Self {
        Self::from_envelope(EpisodeBudget::unlimited())
    }

    /// Charges the given budget delta, consuming resources.
    ///
    /// This atomically checks and updates all resource counters using CAS
    /// loops. If any limit would be exceeded or overflow would occur, no
    /// resources are consumed and an error is returned.
    ///
    /// # Arguments
    ///
    /// * `delta` - The resources to consume
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Any budget limit would be exceeded
    /// - Any counter would overflow
    ///
    /// # Thread Safety
    ///
    /// This method is fully thread-safe. Each resource is atomically checked
    /// and updated using compare-and-swap loops, preventing race conditions
    /// where concurrent calls could exceed limits.
    ///
    /// # Atomicity
    ///
    /// Note: While each individual resource is updated atomically, the overall
    /// operation across multiple resources is not transactional. Under high
    /// contention, some resources may be charged before a later resource fails.
    /// However, this is acceptable because:
    /// 1. Over-charging is safe (fail-closed behavior)
    /// 2. The executor performs reconciliation after execution
    pub fn charge(&self, delta: &BudgetDelta) -> Result<(), BudgetExhaustedError> {
        // Atomically charge each resource using CAS loops
        // Order matters: we charge in order and don't roll back on failure
        // (fail-closed: over-charging is safe)
        self.atomic_charge_u64(
            &self.tokens_consumed,
            delta.tokens,
            self.limits.tokens(),
            "tokens",
            |req, rem| BudgetExhaustedError::Tokens {
                requested: req,
                remaining: rem,
            },
        )?;

        self.atomic_charge_u32(
            &self.tool_calls_consumed,
            delta.tool_calls,
            self.limits.tool_calls(),
            "tool_calls",
            |req, rem| BudgetExhaustedError::ToolCalls {
                requested: req,
                remaining: rem,
            },
        )?;

        self.atomic_charge_u64(
            &self.wall_ms_consumed,
            delta.wall_ms,
            self.limits.wall_ms(),
            "wall_ms",
            |req, rem| BudgetExhaustedError::WallTime {
                requested: req,
                remaining: rem,
            },
        )?;

        self.atomic_charge_u64(
            &self.cpu_ms_consumed,
            delta.cpu_ms,
            self.limits.cpu_ms(),
            "cpu_ms",
            |req, rem| BudgetExhaustedError::CpuTime {
                requested: req,
                remaining: rem,
            },
        )?;

        self.atomic_charge_u64(
            &self.bytes_io_consumed,
            delta.bytes_io,
            self.limits.bytes_io(),
            "bytes_io",
            |req, rem| BudgetExhaustedError::BytesIo {
                requested: req,
                remaining: rem,
            },
        )?;

        Ok(())
    }

    /// Reconciles an estimated charge with actual consumption.
    ///
    /// After tool execution completes, this method adjusts the budget based on
    /// the difference between the estimated charge and actual consumption.
    ///
    /// # Arguments
    ///
    /// * `estimate` - The estimated delta that was pre-charged
    /// * `actual` - The actual delta consumed during execution
    ///
    /// # Errors
    ///
    /// Returns an error if actual consumption exceeds the estimate for any
    /// resource (fail-closed). In this case, the budget remains at the higher
    /// charged amount.
    ///
    /// # Behavior
    ///
    /// - If `actual < estimate`: Refunds the difference (subtracts from
    ///   consumed)
    /// - If `actual > estimate`: Returns error (fail-closed, no automatic
    ///   charge)
    /// - If `actual == estimate`: No change needed
    pub fn reconcile(
        &self,
        estimate: &BudgetDelta,
        actual: &BudgetDelta,
    ) -> Result<(), BudgetExhaustedError> {
        // Check for any overages first (fail-closed)
        if actual.tokens > estimate.tokens {
            return Err(BudgetExhaustedError::ActualExceededEstimate {
                resource: "tokens",
                estimate: estimate.tokens,
                actual: actual.tokens,
            });
        }
        if actual.tool_calls > estimate.tool_calls {
            return Err(BudgetExhaustedError::ActualExceededEstimate {
                resource: "tool_calls",
                estimate: u64::from(estimate.tool_calls),
                actual: u64::from(actual.tool_calls),
            });
        }
        if actual.wall_ms > estimate.wall_ms {
            return Err(BudgetExhaustedError::ActualExceededEstimate {
                resource: "wall_ms",
                estimate: estimate.wall_ms,
                actual: actual.wall_ms,
            });
        }
        if actual.cpu_ms > estimate.cpu_ms {
            return Err(BudgetExhaustedError::ActualExceededEstimate {
                resource: "cpu_ms",
                estimate: estimate.cpu_ms,
                actual: actual.cpu_ms,
            });
        }
        if actual.bytes_io > estimate.bytes_io {
            return Err(BudgetExhaustedError::ActualExceededEstimate {
                resource: "bytes_io",
                estimate: estimate.bytes_io,
                actual: actual.bytes_io,
            });
        }

        // All checks passed - refund the differences
        // Using fetch_sub with saturating semantics via the difference
        let tokens_refund = estimate.tokens - actual.tokens;
        if tokens_refund > 0 {
            self.tokens_consumed
                .fetch_sub(tokens_refund, Ordering::Relaxed);
        }

        let tool_calls_refund = estimate.tool_calls - actual.tool_calls;
        if tool_calls_refund > 0 {
            self.tool_calls_consumed
                .fetch_sub(tool_calls_refund, Ordering::Relaxed);
        }

        let wall_ms_refund = estimate.wall_ms - actual.wall_ms;
        if wall_ms_refund > 0 {
            self.wall_ms_consumed
                .fetch_sub(wall_ms_refund, Ordering::Relaxed);
        }

        let cpu_ms_refund = estimate.cpu_ms - actual.cpu_ms;
        if cpu_ms_refund > 0 {
            self.cpu_ms_consumed
                .fetch_sub(cpu_ms_refund, Ordering::Relaxed);
        }

        let bytes_io_refund = estimate.bytes_io - actual.bytes_io;
        if bytes_io_refund > 0 {
            self.bytes_io_consumed
                .fetch_sub(bytes_io_refund, Ordering::Relaxed);
        }

        Ok(())
    }

    /// Charges evidence bytes separately from the main delta.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The evidence bytes to charge
    ///
    /// # Errors
    ///
    /// Returns an error if the evidence bytes budget would be exceeded or
    /// if overflow would occur.
    ///
    /// # Thread Safety
    ///
    /// This method is fully thread-safe using atomic CAS operations.
    pub fn charge_evidence(&self, bytes: u64) -> Result<(), BudgetExhaustedError> {
        self.atomic_charge_u64(
            &self.evidence_bytes_consumed,
            bytes,
            self.limits.evidence_bytes(),
            "evidence_bytes",
            |req, rem| BudgetExhaustedError::EvidenceBytes {
                requested: req,
                remaining: rem,
            },
        )
    }

    /// Returns the remaining budget.
    ///
    /// For unlimited resources (limit = 0), the remaining value is also 0.
    #[must_use]
    pub fn remaining(&self) -> EpisodeBudget {
        EpisodeBudget::builder()
            .tokens(self.remaining_tokens())
            .tool_calls(self.remaining_tool_calls())
            .wall_ms(self.remaining_wall_ms())
            .cpu_ms(self.remaining_cpu_ms())
            .bytes_io(self.remaining_bytes_io())
            .evidence_bytes(self.remaining_evidence_bytes())
            .build()
    }

    /// Returns the consumed resources as a snapshot.
    #[must_use]
    pub fn consumed(&self) -> BudgetSnapshot {
        BudgetSnapshot {
            tokens: self.tokens_consumed.load(Ordering::Relaxed),
            tool_calls: self.tool_calls_consumed.load(Ordering::Relaxed),
            wall_ms: self.wall_ms_consumed.load(Ordering::Relaxed),
            cpu_ms: self.cpu_ms_consumed.load(Ordering::Relaxed),
            bytes_io: self.bytes_io_consumed.load(Ordering::Relaxed),
            evidence_bytes: self.evidence_bytes_consumed.load(Ordering::Relaxed),
        }
    }

    /// Returns the original budget limits.
    #[must_use]
    pub const fn limits(&self) -> &EpisodeBudget {
        &self.limits
    }

    /// Returns `true` if any budget limit is exhausted.
    #[must_use]
    pub fn is_exhausted(&self) -> bool {
        self.is_tokens_exhausted()
            || self.is_tool_calls_exhausted()
            || self.is_wall_time_exhausted()
            || self.is_cpu_time_exhausted()
            || self.is_bytes_io_exhausted()
            || self.is_evidence_bytes_exhausted()
    }

    /// Returns `true` if the token budget is exhausted.
    #[must_use]
    pub fn is_tokens_exhausted(&self) -> bool {
        let limit = self.limits.tokens();
        limit > 0 && self.tokens_consumed.load(Ordering::Relaxed) >= limit
    }

    /// Returns `true` if the tool calls budget is exhausted.
    #[must_use]
    pub fn is_tool_calls_exhausted(&self) -> bool {
        let limit = self.limits.tool_calls();
        limit > 0 && self.tool_calls_consumed.load(Ordering::Relaxed) >= limit
    }

    /// Returns `true` if the wall time budget is exhausted.
    #[must_use]
    pub fn is_wall_time_exhausted(&self) -> bool {
        let limit = self.limits.wall_ms();
        limit > 0 && self.wall_ms_consumed.load(Ordering::Relaxed) >= limit
    }

    /// Returns `true` if the CPU time budget is exhausted.
    #[must_use]
    pub fn is_cpu_time_exhausted(&self) -> bool {
        let limit = self.limits.cpu_ms();
        limit > 0 && self.cpu_ms_consumed.load(Ordering::Relaxed) >= limit
    }

    /// Returns `true` if the I/O bytes budget is exhausted.
    #[must_use]
    pub fn is_bytes_io_exhausted(&self) -> bool {
        let limit = self.limits.bytes_io();
        limit > 0 && self.bytes_io_consumed.load(Ordering::Relaxed) >= limit
    }

    /// Returns `true` if the evidence bytes budget is exhausted.
    #[must_use]
    pub fn is_evidence_bytes_exhausted(&self) -> bool {
        let limit = self.limits.evidence_bytes();
        limit > 0 && self.evidence_bytes_consumed.load(Ordering::Relaxed) >= limit
    }

    // =========================================================================
    // Private helpers
    // =========================================================================

    fn remaining_tokens(&self) -> u64 {
        let limit = self.limits.tokens();
        if limit == 0 {
            return 0; // Unlimited
        }
        limit.saturating_sub(self.tokens_consumed.load(Ordering::Relaxed))
    }

    fn remaining_tool_calls(&self) -> u32 {
        let limit = self.limits.tool_calls();
        if limit == 0 {
            return 0; // Unlimited
        }
        limit.saturating_sub(self.tool_calls_consumed.load(Ordering::Relaxed))
    }

    fn remaining_wall_ms(&self) -> u64 {
        let limit = self.limits.wall_ms();
        if limit == 0 {
            return 0; // Unlimited
        }
        limit.saturating_sub(self.wall_ms_consumed.load(Ordering::Relaxed))
    }

    fn remaining_cpu_ms(&self) -> u64 {
        let limit = self.limits.cpu_ms();
        if limit == 0 {
            return 0; // Unlimited
        }
        limit.saturating_sub(self.cpu_ms_consumed.load(Ordering::Relaxed))
    }

    fn remaining_bytes_io(&self) -> u64 {
        let limit = self.limits.bytes_io();
        if limit == 0 {
            return 0; // Unlimited
        }
        limit.saturating_sub(self.bytes_io_consumed.load(Ordering::Relaxed))
    }

    fn remaining_evidence_bytes(&self) -> u64 {
        let limit = self.limits.evidence_bytes();
        if limit == 0 {
            return 0; // Unlimited
        }
        limit.saturating_sub(self.evidence_bytes_consumed.load(Ordering::Relaxed))
    }

    /// Atomically charges a u64 counter using compare-and-swap.
    ///
    /// This ensures thread-safe charging that cannot exceed limits even under
    /// concurrent access, and prevents counter overflow.
    ///
    /// # Arguments
    ///
    /// * `counter` - The atomic counter to update
    /// * `amount` - The amount to charge
    /// * `limit` - The budget limit (0 = unlimited)
    /// * `resource_name` - Name for error reporting
    /// * `make_exceeded_err` - Closure to create the exceeded error
    #[allow(clippy::unused_self)] // Keep &self for API consistency with struct methods
    fn atomic_charge_u64<F>(
        &self,
        counter: &AtomicU64,
        amount: u64,
        limit: u64,
        resource_name: &'static str,
        make_exceeded_err: F,
    ) -> Result<(), BudgetExhaustedError>
    where
        F: Fn(u64, u64) -> BudgetExhaustedError,
    {
        // Fast path: nothing to charge
        if amount == 0 {
            return Ok(());
        }

        // Fast path: unlimited budget (limit == 0)
        if limit == 0 {
            // Still need to check for overflow
            loop {
                let current = counter.load(Ordering::Relaxed);
                let Some(new_value) = current.checked_add(amount) else {
                    return Err(BudgetExhaustedError::Overflow {
                        resource: resource_name,
                        current,
                        adding: amount,
                    });
                };

                if counter
                    .compare_exchange_weak(current, new_value, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
                {
                    return Ok(());
                }
                // CAS failed, retry
            }
        }

        // Limited budget: CAS loop with limit and overflow checks
        loop {
            let current = counter.load(Ordering::Relaxed);
            let remaining = limit.saturating_sub(current);

            // Check if we would exceed the limit
            if amount > remaining {
                return Err(make_exceeded_err(amount, remaining));
            }

            // Check for overflow (even though we check remaining, be defensive)
            let Some(new_value) = current.checked_add(amount) else {
                return Err(BudgetExhaustedError::Overflow {
                    resource: resource_name,
                    current,
                    adding: amount,
                });
            };

            // Atomically update if current value hasn't changed
            if counter
                .compare_exchange_weak(current, new_value, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return Ok(());
            }
            // CAS failed, another thread modified it, retry
        }
    }

    /// Atomically charges a u32 counter using compare-and-swap.
    ///
    /// Same as `atomic_charge_u64` but for u32 counters (`tool_calls`).
    #[allow(clippy::unused_self)] // Keep &self for API consistency with struct methods
    fn atomic_charge_u32<F>(
        &self,
        counter: &AtomicU32,
        amount: u32,
        limit: u32,
        resource_name: &'static str,
        make_exceeded_err: F,
    ) -> Result<(), BudgetExhaustedError>
    where
        F: Fn(u32, u32) -> BudgetExhaustedError,
    {
        // Fast path: nothing to charge
        if amount == 0 {
            return Ok(());
        }

        // Fast path: unlimited budget (limit == 0)
        if limit == 0 {
            // Still need to check for overflow
            loop {
                let current = counter.load(Ordering::Relaxed);
                let Some(new_value) = current.checked_add(amount) else {
                    return Err(BudgetExhaustedError::Overflow {
                        resource: resource_name,
                        current: u64::from(current),
                        adding: u64::from(amount),
                    });
                };

                if counter
                    .compare_exchange_weak(current, new_value, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
                {
                    return Ok(());
                }
                // CAS failed, retry
            }
        }

        // Limited budget: CAS loop with limit and overflow checks
        loop {
            let current = counter.load(Ordering::Relaxed);
            let remaining = limit.saturating_sub(current);

            // Check if we would exceed the limit
            if amount > remaining {
                return Err(make_exceeded_err(amount, remaining));
            }

            // Check for overflow (even though we check remaining, be defensive)
            let Some(new_value) = current.checked_add(amount) else {
                return Err(BudgetExhaustedError::Overflow {
                    resource: resource_name,
                    current: u64::from(current),
                    adding: u64::from(amount),
                });
            };

            // Atomically update if current value hasn't changed
            if counter
                .compare_exchange_weak(current, new_value, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return Ok(());
            }
            // CAS failed, another thread modified it, retry
        }
    }
}

// =============================================================================
// BudgetSnapshot
// =============================================================================

/// Snapshot of consumed budget resources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetSnapshot {
    /// Tokens consumed.
    pub tokens: u64,

    /// Tool calls consumed.
    pub tool_calls: u32,

    /// Wall clock time consumed (milliseconds).
    pub wall_ms: u64,

    /// CPU time consumed (milliseconds).
    pub cpu_ms: u64,

    /// I/O bytes consumed.
    pub bytes_io: u64,

    /// Evidence bytes consumed.
    pub evidence_bytes: u64,
}

impl BudgetSnapshot {
    /// Returns `true` if all values are zero.
    #[must_use]
    pub const fn is_zero(&self) -> bool {
        self.tokens == 0
            && self.tool_calls == 0
            && self.wall_ms == 0
            && self.cpu_ms == 0
            && self.bytes_io == 0
            && self.evidence_bytes == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_budget() -> EpisodeBudget {
        EpisodeBudget::builder()
            .tokens(10_000)
            .tool_calls(100)
            .wall_ms(60_000)
            .cpu_ms(30_000)
            .bytes_io(1_000_000)
            .evidence_bytes(100_000)
            .build()
    }

    #[test]
    fn test_budget_tracker_charge_success() {
        let tracker = BudgetTracker::from_envelope(test_budget());

        let delta = BudgetDelta::single_call()
            .with_tokens(500)
            .with_wall_ms(100)
            .with_bytes_io(1000);

        assert!(tracker.charge(&delta).is_ok());

        let consumed = tracker.consumed();
        assert_eq!(consumed.tokens, 500);
        assert_eq!(consumed.tool_calls, 1);
        assert_eq!(consumed.wall_ms, 100);
        assert_eq!(consumed.bytes_io, 1000);
    }

    #[test]
    fn test_budget_tracker_charge_tokens_exceeded() {
        let tracker = BudgetTracker::from_envelope(test_budget());

        let delta = BudgetDelta::single_call().with_tokens(10_001);

        let result = tracker.charge(&delta);
        assert!(matches!(result, Err(BudgetExhaustedError::Tokens { .. })));
    }

    #[test]
    fn test_budget_tracker_charge_tool_calls_exceeded() {
        let budget = EpisodeBudget::builder().tool_calls(2).build();
        let tracker = BudgetTracker::from_envelope(budget);

        // First two charges succeed
        assert!(tracker.charge(&BudgetDelta::single_call()).is_ok());
        assert!(tracker.charge(&BudgetDelta::single_call()).is_ok());

        // Third charge fails
        let result = tracker.charge(&BudgetDelta::single_call());
        assert!(matches!(
            result,
            Err(BudgetExhaustedError::ToolCalls { .. })
        ));
    }

    #[test]
    fn test_budget_tracker_remaining() {
        let tracker = BudgetTracker::from_envelope(test_budget());

        let delta = BudgetDelta::single_call().with_tokens(3000);
        tracker.charge(&delta).unwrap();

        let remaining = tracker.remaining();
        assert_eq!(remaining.tokens(), 7000);
        assert_eq!(remaining.tool_calls(), 99);
    }

    #[test]
    fn test_budget_tracker_is_exhausted() {
        let budget = EpisodeBudget::builder().tokens(100).build();
        let tracker = BudgetTracker::from_envelope(budget);

        assert!(!tracker.is_exhausted());
        assert!(!tracker.is_tokens_exhausted());

        let delta = BudgetDelta::single_call().with_tokens(100);
        tracker.charge(&delta).unwrap();

        assert!(tracker.is_exhausted());
        assert!(tracker.is_tokens_exhausted());
    }

    #[test]
    fn test_budget_tracker_unlimited() {
        let tracker = BudgetTracker::unlimited();

        // Large charges should succeed with unlimited budget
        let delta = BudgetDelta::single_call()
            .with_tokens(1_000_000_000)
            .with_bytes_io(1_000_000_000);

        assert!(tracker.charge(&delta).is_ok());
        assert!(!tracker.is_exhausted());
    }

    #[test]
    fn test_budget_tracker_unlimited_remaining() {
        let tracker = BudgetTracker::unlimited();

        // Remaining is 0 for unlimited (not u64::MAX)
        let remaining = tracker.remaining();
        assert_eq!(remaining.tokens(), 0);
        assert!(remaining.is_unlimited());
    }

    #[test]
    fn test_budget_tracker_charge_evidence() {
        let tracker = BudgetTracker::from_envelope(test_budget());

        assert!(tracker.charge_evidence(50_000).is_ok());
        assert!(tracker.charge_evidence(50_000).is_ok());

        // Next charge exceeds limit
        let result = tracker.charge_evidence(1);
        assert!(matches!(
            result,
            Err(BudgetExhaustedError::EvidenceBytes { .. })
        ));
    }

    #[test]
    fn test_budget_tracker_partial_charge_is_safe() {
        // With atomic CAS-based charging, each resource is charged independently.
        // If one resource fails, earlier resources may already be charged.
        // This is intentional: fail-closed means over-charging is safe.
        let budget = EpisodeBudget::builder()
            .tokens(1000)
            .tool_calls(1) // Will fail on second call
            .build();
        let tracker = BudgetTracker::from_envelope(budget);

        // First charge succeeds
        tracker.charge(&BudgetDelta::single_call()).unwrap();

        // Second charge fails due to tool_calls being exhausted
        // Tokens are charged FIRST (before tool_calls check), so they will be consumed
        let delta = BudgetDelta::single_call().with_tokens(500);
        let result = tracker.charge(&delta);
        assert!(result.is_err());

        // Tokens were charged before tool_calls failed (this is safe - over-charging)
        let consumed = tracker.consumed();
        assert_eq!(consumed.tokens, 500); // Tokens were charged
        assert_eq!(consumed.tool_calls, 1); // Tool calls at limit

        // Importantly, the overall charge failed, so caller knows the operation
        // should not proceed. The slight over-charge is acceptable for
        // security.
    }

    #[test]
    fn test_budget_exhausted_error_resource() {
        assert_eq!(
            BudgetExhaustedError::Tokens {
                requested: 0,
                remaining: 0
            }
            .resource(),
            "tokens"
        );
        assert_eq!(
            BudgetExhaustedError::ToolCalls {
                requested: 0,
                remaining: 0
            }
            .resource(),
            "tool_calls"
        );
        assert_eq!(
            BudgetExhaustedError::WallTime {
                requested: 0,
                remaining: 0
            }
            .resource(),
            "wall_time"
        );
    }

    #[test]
    fn test_budget_snapshot_is_zero() {
        let snapshot = BudgetSnapshot::default();
        assert!(snapshot.is_zero());

        let snapshot = BudgetSnapshot {
            tokens: 1,
            ..Default::default()
        };
        assert!(!snapshot.is_zero());
    }

    #[test]
    fn test_budget_tracker_multiple_charges() {
        let tracker = BudgetTracker::from_envelope(test_budget());

        for _ in 0..10 {
            let delta = BudgetDelta::single_call()
                .with_tokens(100)
                .with_bytes_io(10_000);
            tracker.charge(&delta).unwrap();
        }

        let consumed = tracker.consumed();
        assert_eq!(consumed.tokens, 1000);
        assert_eq!(consumed.tool_calls, 10);
        assert_eq!(consumed.bytes_io, 100_000);
    }

    #[test]
    fn test_budget_tracker_limits_accessor() {
        let budget = test_budget();
        let tracker = BudgetTracker::from_envelope(budget);

        assert_eq!(tracker.limits().tokens(), 10_000);
        assert_eq!(tracker.limits().tool_calls(), 100);
    }

    // =========================================================================
    // Budget charging tests (UT-00165-01)
    // =========================================================================

    #[test]
    fn test_budget_charge_decrements_correctly() {
        let tracker = BudgetTracker::from_envelope(test_budget());

        let delta = BudgetDelta {
            tokens: 1000,
            tool_calls: 5,
            wall_ms: 500,
            cpu_ms: 100,
            bytes_io: 5000,
        };

        tracker.charge(&delta).unwrap();

        let remaining = tracker.remaining();
        assert_eq!(remaining.tokens(), 9000);
        assert_eq!(remaining.tool_calls(), 95);
        assert_eq!(remaining.wall_ms(), 59_500);
        assert_eq!(remaining.cpu_ms(), 29_900);
        assert_eq!(remaining.bytes_io(), 995_000);
    }

    // =========================================================================
    // Budget exhaustion tests (UT-00165-03)
    // =========================================================================

    #[test]
    fn test_budget_exhaustion_detected() {
        let budget = EpisodeBudget::builder()
            .tokens(100)
            .tool_calls(5)
            .wall_ms(1000)
            .build();
        let tracker = BudgetTracker::from_envelope(budget);

        // Exhaust tokens
        tracker
            .charge(&BudgetDelta::single_call().with_tokens(100))
            .unwrap();
        assert!(tracker.is_tokens_exhausted());

        // Exhaust tool calls
        for _ in 0..4 {
            tracker.charge(&BudgetDelta::single_call()).unwrap();
        }
        assert!(tracker.is_tool_calls_exhausted());

        // Overall exhaustion
        assert!(tracker.is_exhausted());
    }

    // =========================================================================
    // Budget reconciliation tests (TCK-00165 Security Fix)
    // =========================================================================

    #[test]
    fn test_budget_reconcile_refund() {
        let tracker = BudgetTracker::from_envelope(test_budget());

        // Pre-charge an estimate
        let estimate = BudgetDelta::single_call()
            .with_tokens(1000)
            .with_bytes_io(5000);
        tracker.charge(&estimate).unwrap();

        // Verify the estimate was charged
        let consumed_before = tracker.consumed();
        assert_eq!(consumed_before.tokens, 1000);
        assert_eq!(consumed_before.bytes_io, 5000);
        assert_eq!(consumed_before.tool_calls, 1);

        // Actual usage was less
        let actual = BudgetDelta::single_call()
            .with_tokens(500)
            .with_bytes_io(2000);

        // Reconcile should refund the difference
        tracker.reconcile(&estimate, &actual).unwrap();

        // Verify refund was applied
        let consumed_after = tracker.consumed();
        assert_eq!(consumed_after.tokens, 500);
        assert_eq!(consumed_after.bytes_io, 2000);
        assert_eq!(consumed_after.tool_calls, 1); // tool_calls unchanged
    }

    #[test]
    fn test_budget_reconcile_exact_match() {
        let tracker = BudgetTracker::from_envelope(test_budget());

        // Pre-charge an estimate
        let estimate = BudgetDelta::single_call().with_tokens(500);
        tracker.charge(&estimate).unwrap();

        // Actual usage matches estimate exactly
        let actual = BudgetDelta::single_call().with_tokens(500);

        // Reconcile should succeed with no change
        tracker.reconcile(&estimate, &actual).unwrap();

        let consumed = tracker.consumed();
        assert_eq!(consumed.tokens, 500);
    }

    #[test]
    fn test_budget_reconcile_actual_exceeds_estimate_fails() {
        let tracker = BudgetTracker::from_envelope(test_budget());

        // Pre-charge an estimate
        let estimate = BudgetDelta::single_call().with_tokens(500);
        tracker.charge(&estimate).unwrap();

        // Actual usage exceeds estimate - this should FAIL (fail-closed)
        let actual = BudgetDelta::single_call().with_tokens(600);

        let result = tracker.reconcile(&estimate, &actual);
        assert!(matches!(
            result,
            Err(BudgetExhaustedError::ActualExceededEstimate {
                resource: "tokens",
                ..
            })
        ));

        // Budget should remain at the charged amount (not refunded)
        let consumed = tracker.consumed();
        assert_eq!(consumed.tokens, 500);
    }

    #[test]
    fn test_budget_reconcile_multiple_resources() {
        let tracker = BudgetTracker::from_envelope(test_budget());

        let estimate = BudgetDelta {
            tokens: 1000,
            tool_calls: 1,
            wall_ms: 500,
            cpu_ms: 200,
            bytes_io: 10_000,
        };
        tracker.charge(&estimate).unwrap();

        let actual = BudgetDelta {
            tokens: 800,
            tool_calls: 1,
            wall_ms: 300,
            cpu_ms: 150,
            bytes_io: 8000,
        };

        tracker.reconcile(&estimate, &actual).unwrap();

        let consumed = tracker.consumed();
        assert_eq!(consumed.tokens, 800);
        assert_eq!(consumed.tool_calls, 1);
        assert_eq!(consumed.wall_ms, 300);
        assert_eq!(consumed.cpu_ms, 150);
        assert_eq!(consumed.bytes_io, 8000);
    }

    // =========================================================================
    // Counter overflow tests (TCK-00165 Security Fix)
    // =========================================================================

    #[test]
    fn test_budget_overflow_rejected() {
        // Use unlimited budget to test overflow detection without limit checks
        let tracker = BudgetTracker::unlimited();

        // First, charge a large amount
        let large_delta = BudgetDelta::single_call().with_tokens(u64::MAX - 100);
        tracker.charge(&large_delta).unwrap();

        // Now try to charge an amount that would overflow
        let overflow_delta = BudgetDelta::single_call().with_tokens(200);
        let result = tracker.charge(&overflow_delta);

        assert!(
            matches!(
                result,
                Err(BudgetExhaustedError::Overflow {
                    resource: "tokens",
                    ..
                })
            ),
            "Expected overflow error, got: {result:?}"
        );
    }

    #[test]
    fn test_budget_tool_calls_overflow_rejected() {
        // Use unlimited budget to test overflow detection in tool_calls
        let tracker = BudgetTracker::unlimited();

        // Charge a very large amount first
        let delta = BudgetDelta {
            tokens: 0,
            tool_calls: u32::MAX - 10,
            wall_ms: 0,
            cpu_ms: 0,
            bytes_io: 0,
        };
        tracker.charge(&delta).unwrap();

        // Now try to charge more - this should cause overflow
        let overflow_delta = BudgetDelta {
            tokens: 0,
            tool_calls: 20, // Would overflow u32
            wall_ms: 0,
            cpu_ms: 0,
            bytes_io: 0,
        };
        let result = tracker.charge(&overflow_delta);

        // Should fail with overflow error
        assert!(
            matches!(
                result,
                Err(BudgetExhaustedError::Overflow {
                    resource: "tool_calls",
                    ..
                })
            ),
            "Expected overflow error, got: {result:?}"
        );
    }

    #[test]
    fn test_budget_is_exhausted_does_not_wrap_around() {
        // Verify that even if counter somehow got very large, is_exhausted
        // still reports correctly (using saturating arithmetic)
        let budget = EpisodeBudget::builder().tokens(100).build();
        let tracker = BudgetTracker::from_envelope(budget);

        // Exhaust the budget
        tracker
            .charge(&BudgetDelta::single_call().with_tokens(100))
            .unwrap();

        assert!(tracker.is_exhausted());
        assert!(tracker.is_tokens_exhausted());

        // remaining() should be 0, not wrap around
        assert_eq!(tracker.remaining().tokens(), 0);
    }

    // =========================================================================
    // Concurrent access tests (TCK-00165 Security Fix)
    // =========================================================================

    #[test]
    fn test_budget_concurrent_charges_respect_limits() {
        use std::sync::Arc;
        use std::thread;

        let budget = EpisodeBudget::builder().tool_calls(100).build();
        let tracker = Arc::new(BudgetTracker::from_envelope(budget));

        // Spawn multiple threads that each try to charge
        let mut handles = vec![];
        for _ in 0..20 {
            let tracker_clone = Arc::clone(&tracker);
            let handle = thread::spawn(move || {
                let mut successes = 0;
                for _ in 0..10 {
                    if tracker_clone.charge(&BudgetDelta::single_call()).is_ok() {
                        successes += 1;
                    }
                }
                successes
            });
            handles.push(handle);
        }

        // Collect results
        let total_successes: u32 = handles.into_iter().map(|h| h.join().unwrap()).sum();

        // Total successes should be exactly equal to the limit
        assert_eq!(
            total_successes, 100,
            "Expected exactly 100 successful charges, got {total_successes}"
        );

        // Verify consumed equals limit
        let consumed = tracker.consumed();
        assert_eq!(consumed.tool_calls, 100);
    }

    #[test]
    fn test_budget_concurrent_charges_no_overcount() {
        use std::sync::Arc;
        use std::thread;

        let budget = EpisodeBudget::builder().tokens(10_000).build();
        let tracker = Arc::new(BudgetTracker::from_envelope(budget));

        // Spawn threads that charge small amounts concurrently
        let mut handles = vec![];
        for _ in 0..10 {
            let tracker_clone = Arc::clone(&tracker);
            let handle = thread::spawn(move || {
                for _ in 0..100 {
                    let _ = tracker_clone.charge(&BudgetDelta::single_call().with_tokens(10));
                }
            });
            handles.push(handle);
        }

        // Wait for all threads
        for h in handles {
            h.join().unwrap();
        }

        // Total consumed should not exceed limit
        let consumed = tracker.consumed();
        assert!(
            consumed.tokens <= 10_000,
            "Consumed {} tokens but limit is 10_000",
            consumed.tokens
        );
    }

    // =========================================================================
    // Error variant tests
    // =========================================================================

    #[test]
    fn test_overflow_error_resource() {
        let err = BudgetExhaustedError::Overflow {
            resource: "tokens",
            current: 100,
            adding: 200,
        };
        assert_eq!(err.resource(), "tokens");
    }

    #[test]
    fn test_actual_exceeded_estimate_error_resource() {
        let err = BudgetExhaustedError::ActualExceededEstimate {
            resource: "bytes_io",
            estimate: 100,
            actual: 200,
        };
        assert_eq!(err.resource(), "bytes_io");
    }
}
