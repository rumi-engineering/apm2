//! Coordination state types and structures.
//!
//! This module defines the core state types for the coordination layer:
//! - [`CoordinationState`]: The reducer projection containing all coordinations
//! - [`CoordinationSession`]: Individual coordination tracking state
//! - [`BindingInfo`]: Session-to-work binding information
//! - [`CoordinationBudget`]: Budget constraints for a coordination
//! - [`BudgetUsage`]: Current budget consumption tracking
//! - [`CoordinationStatus`]: Lifecycle status of a coordination
//! - [`StopCondition`]: Why a coordination stopped
//!
//! Types follow patterns established in [`crate::session::state`].

use std::collections::HashMap;
use std::fmt;
use std::marker::PhantomData;

use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, de};

/// Maximum number of work items allowed in a coordination queue.
///
/// This limit prevents denial-of-service attacks through unbounded allocation
/// when deserializing coordination events from JSON. The limit is enforced both
/// in constructors and during deserialization.
pub const MAX_WORK_QUEUE_SIZE: usize = 1000;

/// Maximum number of items allowed in coordination `HashMap`s.
///
/// This limit prevents denial-of-service attacks through unbounded allocation
/// when deserializing coordination state from untrusted JSON.
pub const MAX_HASHMAP_SIZE: usize = 10_000;

/// Maximum number of session IDs allowed per work item.
///
/// This limit prevents denial-of-service attacks through unbounded allocation
/// when deserializing `WorkItemTracking` from untrusted JSON. The limit is
/// set conservatively since each session generates at most one entry.
pub const MAX_SESSION_IDS_PER_WORK: usize = 100;

/// Custom deserializer for `work_queue` that enforces [`MAX_WORK_QUEUE_SIZE`].
///
/// This uses a streaming visitor pattern that enforces limits DURING
/// deserialization, preventing OOM attacks by rejecting oversized arrays
/// before full allocation occurs.
fn deserialize_bounded_work_queue<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    struct BoundedVecVisitor;

    impl<'de> Visitor<'de> for BoundedVecVisitor {
        type Value = Vec<String>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            write!(
                formatter,
                "a sequence of at most {MAX_WORK_QUEUE_SIZE} strings"
            )
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            // Use size hint but cap at MAX_WORK_QUEUE_SIZE to prevent pre-allocation
            // attacks
            let capacity = seq.size_hint().unwrap_or(0).min(MAX_WORK_QUEUE_SIZE);
            let mut items = Vec::with_capacity(capacity);

            while let Some(item) = seq.next_element()? {
                if items.len() >= MAX_WORK_QUEUE_SIZE {
                    return Err(de::Error::custom(format!(
                        "work_queue exceeds maximum size: {} > {}",
                        items.len() + 1,
                        MAX_WORK_QUEUE_SIZE
                    )));
                }
                items.push(item);
            }
            Ok(items)
        }
    }

    deserializer.deserialize_seq(BoundedVecVisitor)
}

/// Custom deserializer for `session_ids` that enforces
/// [`MAX_SESSION_IDS_PER_WORK`].
///
/// This uses a streaming visitor pattern that enforces limits DURING
/// deserialization, preventing OOM attacks by rejecting oversized arrays
/// before full allocation occurs.
fn deserialize_bounded_session_ids<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    struct BoundedVecVisitor;

    impl<'de> Visitor<'de> for BoundedVecVisitor {
        type Value = Vec<String>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            write!(
                formatter,
                "a sequence of at most {MAX_SESSION_IDS_PER_WORK} strings"
            )
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            // Use size hint but cap at MAX_SESSION_IDS_PER_WORK to prevent pre-allocation
            // attacks
            let capacity = seq.size_hint().unwrap_or(0).min(MAX_SESSION_IDS_PER_WORK);
            let mut items = Vec::with_capacity(capacity);

            while let Some(item) = seq.next_element()? {
                if items.len() >= MAX_SESSION_IDS_PER_WORK {
                    return Err(de::Error::custom(format!(
                        "session_ids exceeds maximum size: {} > {}",
                        items.len() + 1,
                        MAX_SESSION_IDS_PER_WORK
                    )));
                }
                items.push(item);
            }
            Ok(items)
        }
    }

    deserializer.deserialize_seq(BoundedVecVisitor)
}

/// Custom deserializer for `work_tracking` `HashMap` that enforces
/// [`MAX_HASHMAP_SIZE`].
///
/// This uses a streaming visitor pattern that enforces limits DURING
/// deserialization, preventing OOM attacks by rejecting oversized maps
/// before full allocation occurs.
fn deserialize_bounded_work_tracking<'de, D>(
    deserializer: D,
) -> Result<HashMap<String, WorkItemTracking>, D::Error>
where
    D: Deserializer<'de>,
{
    struct BoundedMapVisitor;

    impl<'de> Visitor<'de> for BoundedMapVisitor {
        type Value = HashMap<String, WorkItemTracking>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            write!(formatter, "a map of at most {MAX_HASHMAP_SIZE} entries")
        }

        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            // Use size hint but cap at MAX_HASHMAP_SIZE to prevent pre-allocation attacks
            let capacity = map.size_hint().unwrap_or(0).min(MAX_HASHMAP_SIZE);
            let mut items = HashMap::with_capacity(capacity);

            while let Some((key, value)) = map.next_entry()? {
                if items.len() >= MAX_HASHMAP_SIZE {
                    return Err(de::Error::custom(format!(
                        "work_tracking exceeds maximum size: {} > {}",
                        items.len() + 1,
                        MAX_HASHMAP_SIZE
                    )));
                }
                items.insert(key, value);
            }
            Ok(items)
        }
    }

    deserializer.deserialize_map(BoundedMapVisitor)
}

/// Custom deserializer for a bounded `HashMap` with generic value type.
///
/// This uses a streaming visitor pattern that enforces limits DURING
/// deserialization, preventing OOM attacks by rejecting oversized maps
/// before full allocation occurs.
fn deserialize_bounded_hashmap<'de, D, V>(deserializer: D) -> Result<HashMap<String, V>, D::Error>
where
    D: Deserializer<'de>,
    V: Deserialize<'de>,
{
    struct BoundedHashMapVisitor<V> {
        marker: PhantomData<V>,
    }

    impl<'de, V> Visitor<'de> for BoundedHashMapVisitor<V>
    where
        V: Deserialize<'de>,
    {
        type Value = HashMap<String, V>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            write!(formatter, "a map of at most {MAX_HASHMAP_SIZE} entries")
        }

        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            // Use size hint but cap at MAX_HASHMAP_SIZE to prevent pre-allocation attacks
            let capacity = map.size_hint().unwrap_or(0).min(MAX_HASHMAP_SIZE);
            let mut items = HashMap::with_capacity(capacity);

            while let Some((key, value)) = map.next_entry()? {
                if items.len() >= MAX_HASHMAP_SIZE {
                    return Err(de::Error::custom(format!(
                        "hashmap exceeds maximum size: {} > {}",
                        items.len() + 1,
                        MAX_HASHMAP_SIZE
                    )));
                }
                items.insert(key, value);
            }
            Ok(items)
        }
    }

    deserializer.deserialize_map(BoundedHashMapVisitor {
        marker: PhantomData,
    })
}

/// Custom deserializer for `coordinations` `HashMap`.
fn deserialize_bounded_coordinations<'de, D>(
    deserializer: D,
) -> Result<HashMap<String, CoordinationSession>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_hashmap(deserializer)
}

/// Custom deserializer for `bindings` `HashMap`.
fn deserialize_bounded_bindings<'de, D>(
    deserializer: D,
) -> Result<HashMap<String, BindingInfo>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_hashmap(deserializer)
}

/// Errors that can occur during coordination operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoordinationError {
    /// Work queue size exceeds the maximum allowed limit.
    WorkQueueSizeExceeded {
        /// The actual size that was provided.
        actual: usize,
        /// The maximum allowed size.
        max: usize,
    },
    /// Budget values must be positive (non-zero).
    ///
    /// Per RFC-0012/TB-COORD-004: `max_episodes` and `max_duration_ticks` are
    /// required positive integers.
    InvalidBudget {
        /// Description of which budget field is invalid.
        field: &'static str,
    },
    /// Tick rate mismatch during budget tracking.
    ///
    /// Once a `BudgetUsage` is initialized with a tick rate, all subsequent
    /// updates must use the same rate to ensure `elapsed_ticks` semantics
    /// remain valid.
    TickRateMismatch {
        /// The tick rate that was previously set.
        expected: u64,
        /// The tick rate that was attempted.
        actual: u64,
    },
    /// Clock regression detected during elapsed time update.
    ///
    /// The current tick value is less than the start tick, indicating a
    /// clock regression or discontinuity. Per fail-closed policy, this
    /// error must be handled rather than silently ignored.
    ClockRegression {
        /// The tick value when coordination started.
        start_tick: u64,
        /// The current tick value that is less than start.
        current_tick: u64,
    },
}

impl fmt::Display for CoordinationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WorkQueueSizeExceeded { actual, max } => {
                write!(f, "work queue size {actual} exceeds maximum allowed {max}")
            },
            Self::InvalidBudget { field } => {
                write!(
                    f,
                    "budget field '{field}' must be a positive (non-zero) value"
                )
            },
            Self::TickRateMismatch { expected, actual } => {
                write!(
                    f,
                    "tick rate mismatch: initialized with {expected} Hz, attempted update with {actual} Hz"
                )
            },
            Self::ClockRegression {
                start_tick,
                current_tick,
            } => {
                write!(
                    f,
                    "clock regression detected: current tick {current_tick} < start tick {start_tick}"
                )
            },
        }
    }
}

/// Default tick rate for legacy deserialization (1kHz = 1ms per tick).
///
/// Used when deserializing legacy JSON where `max_duration_ms` or `elapsed_ms`
/// were provided without an explicit `tick_rate_hz`. Preserves the semantic
/// value of the legacy fields (milliseconds).
const fn default_legacy_tick_rate() -> u64 {
    1000
}

/// Budget constraints for a coordination.
///
/// Per AD-COORD-004: `max_episodes` and `max_duration_ticks` are required.
/// `max_tokens` is optional but recommended.
///
/// # HTF Compliance (RFC-0016::REQ-0003)
///
/// Duration budgets use tick-based tracking for replay stability. The tick
/// rate is carried alongside the budget to enable conversion when needed.
/// See RFC-0016 for the HTF time model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoordinationBudget {
    /// Maximum number of session episodes (required).
    pub max_episodes: u32,

    /// Maximum duration in ticks (required).
    ///
    /// Ticks are node-local monotonic units; the interpretation depends on
    /// `tick_rate_hz`. This field replaces the wall-clock based
    /// `max_duration_ms` for replay stability.
    ///
    /// # Backward Compatibility
    ///
    /// The alias `max_duration_ms` is supported for deserializing legacy data.
    #[serde(alias = "max_duration_ms")]
    pub max_duration_ticks: u64,

    /// Tick rate in Hz (ticks per second) for interpreting duration.
    ///
    /// Must match the system's HTF tick rate. Common values:
    /// - `1_000_000` (1MHz): 1 tick = 1 microsecond
    /// - `1_000_000_000` (1GHz): 1 tick = 1 nanosecond
    ///
    /// # Backward Compatibility
    ///
    /// Defaults to 1kHz (1ms) if missing, to support legacy data where
    /// `max_duration_ms` was used.
    #[serde(default = "default_legacy_tick_rate")]
    pub tick_rate_hz: u64,

    /// Maximum token consumption (optional).
    ///
    /// When `None`, token consumption is tracked but not enforced.
    pub max_tokens: Option<u64>,
}

impl CoordinationBudget {
    /// Creates a new coordination budget with tick-based duration.
    ///
    /// # Arguments
    ///
    /// * `max_episodes` - Maximum number of session episodes (must be >= 1)
    /// * `max_duration_ticks` - Maximum duration in ticks (must be >= 1)
    /// * `tick_rate_hz` - Tick rate in Hz (must be >= 1)
    /// * `max_tokens` - Optional maximum token consumption
    ///
    /// # Errors
    ///
    /// Returns [`CoordinationError::InvalidBudget`] if:
    /// - `max_episodes` is zero
    /// - `max_duration_ticks` is zero
    /// - `tick_rate_hz` is zero
    ///
    /// Per RFC-0012/TB-COORD-004 and RFC-0016::REQ-0003: Budget constraints use
    /// tick-based durations for replay stability.
    pub const fn new(
        max_episodes: u32,
        max_duration_ticks: u64,
        tick_rate_hz: u64,
        max_tokens: Option<u64>,
    ) -> Result<Self, CoordinationError> {
        if max_episodes == 0 {
            return Err(CoordinationError::InvalidBudget {
                field: "max_episodes",
            });
        }
        if max_duration_ticks == 0 {
            return Err(CoordinationError::InvalidBudget {
                field: "max_duration_ticks",
            });
        }
        if tick_rate_hz == 0 {
            return Err(CoordinationError::InvalidBudget {
                field: "tick_rate_hz",
            });
        }
        Ok(Self {
            max_episodes,
            max_duration_ticks,
            tick_rate_hz,
            max_tokens,
        })
    }

    /// Creates a new coordination budget without validation.
    ///
    /// This is intended for use in deserialization where the values come from
    /// a trusted source or will be validated separately.
    #[must_use]
    pub const fn new_unchecked(
        max_episodes: u32,
        max_duration_ticks: u64,
        tick_rate_hz: u64,
        max_tokens: Option<u64>,
    ) -> Self {
        Self {
            max_episodes,
            max_duration_ticks,
            tick_rate_hz,
            max_tokens,
        }
    }

    /// Returns the tick rate in Hz.
    #[must_use]
    pub const fn tick_rate_hz(&self) -> u64 {
        self.tick_rate_hz
    }
}

/// Current budget consumption tracking.
///
/// All counters are monotonically non-decreasing within a coordination.
///
/// # HTF Compliance (RFC-0016::REQ-0003)
///
/// Elapsed time is tracked in ticks rather than wall-clock milliseconds
/// for replay stability. The tick rate is stored alongside for conversion.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetUsage {
    /// Number of episodes (sessions) consumed.
    pub consumed_episodes: u32,

    /// Elapsed time in ticks since coordination started.
    ///
    /// Ticks are node-local monotonic units. This replaces `elapsed_ms`
    /// for replay stability per RFC-0016::REQ-0003.
    ///
    /// # Backward Compatibility
    ///
    /// The alias `elapsed_ms` is supported for deserializing legacy data.
    #[serde(alias = "elapsed_ms")]
    pub elapsed_ticks: u64,

    /// Tick rate in Hz for interpreting `elapsed_ticks`.
    ///
    /// Should match the budget's tick rate and system HTF configuration.
    ///
    /// # Backward Compatibility
    ///
    /// Defaults to 1kHz (1ms) if missing, to support legacy data where
    /// `elapsed_ms` was used.
    #[serde(default = "default_legacy_tick_rate")]
    pub tick_rate_hz: u64,

    /// Total tokens consumed across all sessions.
    ///
    /// Aggregated from session `final_entropy` per AD-COORD-011.
    pub consumed_tokens: u64,
}

impl BudgetUsage {
    /// Creates a new empty budget usage tracker.
    ///
    /// # Note
    ///
    /// The `tick_rate_hz` defaults to 0 and should be set via `with_tick_rate`
    /// or by calling `update_elapsed_ticks`.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            consumed_episodes: 0,
            elapsed_ticks: 0,
            tick_rate_hz: 0,
            consumed_tokens: 0,
        }
    }

    /// Creates a new budget usage tracker with specified tick rate.
    ///
    /// # Arguments
    ///
    /// * `tick_rate_hz` - The tick rate in Hz for this coordination
    #[must_use]
    pub const fn with_tick_rate(tick_rate_hz: u64) -> Self {
        Self {
            consumed_episodes: 0,
            elapsed_ticks: 0,
            tick_rate_hz,
            consumed_tokens: 0,
        }
    }

    // =========================================================================
    // Budget Tracking Helper Methods (RFC-0032::REQ-0051, RFC-0016::REQ-0003)
    // =========================================================================

    /// Checks if the episode budget is exhausted.
    ///
    /// Per AD-COORD-004: Returns `true` when `consumed_episodes >=
    /// max_episodes`.
    ///
    /// # Arguments
    ///
    /// * `budget` - The budget constraints to check against
    ///
    /// # Returns
    ///
    /// `true` if episode budget is exhausted, `false` otherwise.
    #[must_use]
    pub const fn is_episode_budget_exhausted(&self, budget: &CoordinationBudget) -> bool {
        self.consumed_episodes >= budget.max_episodes
    }

    /// Checks if the duration budget is exhausted.
    ///
    /// Per AD-COORD-004 and RFC-0016::REQ-0003: Returns `true` when
    /// `elapsed_ticks >= max_duration_ticks`.
    ///
    /// # Arguments
    ///
    /// * `budget` - The budget constraints to check against
    ///
    /// # Returns
    ///
    /// `true` if duration budget is exhausted, `false` otherwise.
    #[must_use]
    pub const fn is_duration_budget_exhausted(&self, budget: &CoordinationBudget) -> bool {
        self.elapsed_ticks >= budget.max_duration_ticks
    }

    /// Checks if the token budget is exhausted.
    ///
    /// Per AD-COORD-004: Returns `true` when `max_tokens` is set AND
    /// `consumed_tokens >= max_tokens`.
    ///
    /// # Arguments
    ///
    /// * `budget` - The budget constraints to check against
    ///
    /// # Returns
    ///
    /// `true` if token budget is exhausted, `false` otherwise.
    /// Always returns `false` if `max_tokens` is `None`.
    #[must_use]
    pub const fn is_token_budget_exhausted(&self, budget: &CoordinationBudget) -> bool {
        match budget.max_tokens {
            Some(max) => self.consumed_tokens >= max,
            None => false,
        }
    }

    /// Checks if any budget constraint is exhausted.
    ///
    /// Per AD-COORD-013 priority ordering, checks:
    /// 1. Duration budget (highest priority among budgets)
    /// 2. Token budget (if set)
    /// 3. Episode budget (lowest priority among budgets)
    ///
    /// # Arguments
    ///
    /// * `budget` - The budget constraints to check against
    ///
    /// # Returns
    ///
    /// `Some(BudgetType)` for the highest-priority exhausted budget, or `None`.
    #[must_use]
    pub const fn check_budget_exhausted(&self, budget: &CoordinationBudget) -> Option<BudgetType> {
        // Per AD-COORD-013: Duration > Tokens > Episodes priority
        if self.is_duration_budget_exhausted(budget) {
            return Some(BudgetType::Duration);
        }
        if self.is_token_budget_exhausted(budget) {
            return Some(BudgetType::Tokens);
        }
        if self.is_episode_budget_exhausted(budget) {
            return Some(BudgetType::Episodes);
        }
        None
    }

    /// Aggregates token consumption from a session outcome.
    ///
    /// Per AD-COORD-011: Token consumption is aggregated from session
    /// `final_entropy` values. This method safely saturates to prevent
    /// overflow.
    ///
    /// # Arguments
    ///
    /// * `tokens` - Tokens consumed by the session (from `final_entropy`)
    pub const fn aggregate_tokens(&mut self, tokens: u64) {
        self.consumed_tokens = self.consumed_tokens.saturating_add(tokens);
    }

    /// Increments the consumed episodes counter.
    ///
    /// Safely saturates to prevent overflow.
    pub const fn increment_episodes(&mut self) {
        self.consumed_episodes = self.consumed_episodes.saturating_add(1);
    }

    /// Updates the elapsed time from tick values.
    ///
    /// Per RFC-0016::REQ-0003: Uses tick-based tracking for replay stability.
    /// This replaces the wall-clock based `update_elapsed_from`.
    ///
    /// # Arguments
    ///
    /// * `start_tick` - The tick value when coordination started
    /// * `current_tick` - The current tick value
    /// * `tick_rate_hz` - The tick rate in Hz
    ///
    /// # Errors
    ///
    /// Returns [`CoordinationError::TickRateMismatch`] if `tick_rate_hz`
    /// differs from the previously set rate (when `self.tick_rate_hz > 0`).
    /// This prevents temporal confusion where `elapsed_ticks` would become
    /// semantically invalid due to rate changes.
    ///
    /// Returns [`CoordinationError::ClockRegression`] if `current_tick <
    /// start_tick`, indicating a clock regression or discontinuity. Per
    /// fail-closed policy, callers must handle this error explicitly rather
    /// than silently continuing.
    pub const fn update_elapsed_ticks(
        &mut self,
        start_tick: u64,
        current_tick: u64,
        tick_rate_hz: u64,
    ) -> Result<(), CoordinationError> {
        // Enforce rate immutability once initialized (RFC-0016::REQ-0003)
        // A rate of 0 indicates uninitialized state (from Default or new())
        if self.tick_rate_hz != 0 && self.tick_rate_hz != tick_rate_hz {
            return Err(CoordinationError::TickRateMismatch {
                expected: self.tick_rate_hz,
                actual: tick_rate_hz,
            });
        }

        // Detect clock regression (fail-closed per RFC-0016::REQ-0003)
        // Instead of saturating to 0 which allows indefinite coordination,
        // we fail explicitly to prevent security bypass.
        if current_tick < start_tick {
            return Err(CoordinationError::ClockRegression {
                start_tick,
                current_tick,
            });
        }

        self.elapsed_ticks = current_tick - start_tick;
        self.tick_rate_hz = tick_rate_hz;
        Ok(())
    }

    /// Returns the remaining episodes before budget exhaustion.
    ///
    /// # Arguments
    ///
    /// * `budget` - The budget constraints
    ///
    /// # Returns
    ///
    /// Number of episodes remaining, or 0 if budget is exhausted.
    #[must_use]
    pub const fn remaining_episodes(&self, budget: &CoordinationBudget) -> u32 {
        budget.max_episodes.saturating_sub(self.consumed_episodes)
    }

    /// Returns the remaining duration in ticks before budget exhaustion.
    ///
    /// Per RFC-0016::REQ-0003: Duration tracking uses ticks for replay
    /// stability.
    ///
    /// # Arguments
    ///
    /// * `budget` - The budget constraints
    ///
    /// # Returns
    ///
    /// Remaining duration in ticks, or 0 if budget is exhausted.
    #[must_use]
    pub const fn remaining_duration_ticks(&self, budget: &CoordinationBudget) -> u64 {
        budget.max_duration_ticks.saturating_sub(self.elapsed_ticks)
    }

    /// Returns the remaining tokens before budget exhaustion, if a token limit
    /// is set.
    ///
    /// # Arguments
    ///
    /// * `budget` - The budget constraints
    ///
    /// # Returns
    ///
    /// `Some(remaining)` if token budget is set, `None` otherwise.
    #[must_use]
    pub const fn remaining_tokens(&self, budget: &CoordinationBudget) -> Option<u64> {
        match budget.max_tokens {
            Some(max) => Some(max.saturating_sub(self.consumed_tokens)),
            None => None,
        }
    }

    /// Returns the tick rate in Hz.
    #[must_use]
    pub const fn tick_rate_hz(&self) -> u64 {
        self.tick_rate_hz
    }
}

/// The type of budget that was exhausted.
///
/// Used in [`StopCondition::BudgetExhausted`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BudgetType {
    /// Duration budget exhausted.
    Duration,
    /// Token budget exhausted.
    Tokens,
    /// Episode budget exhausted.
    Episodes,
}

impl BudgetType {
    /// Returns the string representation of this budget type.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Duration => "DURATION",
            Self::Tokens => "TOKENS",
            Self::Episodes => "EPISODES",
        }
    }
}

/// Why a coordination stopped.
///
/// Stop conditions have a priority ordering per AD-COORD-013:
/// 1. `CircuitBreakerTriggered` (highest - safety critical)
/// 2. `BudgetExhausted(Duration)` (runtime limit)
/// 3. `BudgetExhausted(Tokens)` (resource limit)
/// 4. `BudgetExhausted(Episodes)` (session count limit)
/// 5. `MaxAttemptsExceeded` (work-level failure)
/// 6. `WorkCompleted` (lowest - success)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum StopCondition {
    /// All work items completed successfully.
    WorkCompleted,

    /// A work item exhausted its retry attempts.
    MaxAttemptsExceeded {
        /// The work item that exhausted retries.
        work_id: String,
    },

    /// A budget ceiling was reached.
    BudgetExhausted(BudgetType),

    /// Circuit breaker triggered due to consecutive failures.
    ///
    /// Per AD-COORD-005: Triggered after 3 consecutive session failures
    /// across different work items.
    CircuitBreakerTriggered {
        /// Number of consecutive failures when triggered.
        consecutive_failures: u32,
    },
}

impl StopCondition {
    /// Returns the priority of this stop condition (lower = higher priority).
    ///
    /// Per AD-COORD-013 priority ordering.
    #[must_use]
    pub const fn priority(&self) -> u8 {
        match self {
            Self::CircuitBreakerTriggered { .. } => 0,
            Self::BudgetExhausted(BudgetType::Duration) => 1,
            Self::BudgetExhausted(BudgetType::Tokens) => 2,
            Self::BudgetExhausted(BudgetType::Episodes) => 3,
            Self::MaxAttemptsExceeded { .. } => 4,
            Self::WorkCompleted => 5,
        }
    }

    /// Returns `true` if this is a success condition.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        matches!(self, Self::WorkCompleted)
    }

    /// Returns the string representation of this stop condition.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::WorkCompleted => "WORK_COMPLETED",
            Self::MaxAttemptsExceeded { .. } => "MAX_ATTEMPTS_EXCEEDED",
            Self::BudgetExhausted(BudgetType::Duration) => "BUDGET_EXHAUSTED_DURATION",
            Self::BudgetExhausted(BudgetType::Tokens) => "BUDGET_EXHAUSTED_TOKENS",
            Self::BudgetExhausted(BudgetType::Episodes) => "BUDGET_EXHAUSTED_EPISODES",
            Self::CircuitBreakerTriggered { .. } => "CIRCUIT_BREAKER_TRIGGERED",
        }
    }
}

/// Why a coordination was aborted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum AbortReason {
    /// Coordination was manually cancelled.
    Cancelled {
        /// Reason for cancellation.
        reason: String,
    },

    /// Coordination encountered an unrecoverable error.
    Error {
        /// Error message.
        message: String,
    },

    /// No eligible work items in the queue.
    NoEligibleWork,
}

impl AbortReason {
    /// Returns the string representation of this abort reason.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Cancelled { .. } => "CANCELLED",
            Self::Error { .. } => "ERROR",
            Self::NoEligibleWork => "NO_ELIGIBLE_WORK",
        }
    }
}

/// Lifecycle status of a coordination.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum CoordinationStatus {
    /// Coordination is initializing.
    Initializing,

    /// Coordination is actively running.
    Running,

    /// Coordination completed (may be success or failure).
    Completed(StopCondition),

    /// Coordination was aborted.
    Aborted(AbortReason),
}

impl CoordinationStatus {
    /// Returns `true` if the coordination is in a terminal state.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed(_) | Self::Aborted(_))
    }

    /// Returns `true` if the coordination is actively running.
    #[must_use]
    pub const fn is_running(&self) -> bool {
        matches!(self, Self::Running)
    }

    /// Returns the string representation of this status.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Initializing => "INITIALIZING",
            Self::Running => "RUNNING",
            Self::Completed(_) => "COMPLETED",
            Self::Aborted(_) => "ABORTED",
        }
    }
}

/// Outcome of a session for a work item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionOutcome {
    /// Session completed successfully.
    Success,
    /// Session failed.
    Failure,
}

impl SessionOutcome {
    /// Returns the string representation of this outcome.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Success => "SUCCESS",
            Self::Failure => "FAILURE",
        }
    }

    /// Returns `true` if this is a success outcome.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        matches!(self, Self::Success)
    }
}

/// Information about a session-to-work binding.
///
/// Per AD-COORD-003: Binding events bracket session lifecycle.
/// `coordination.session_bound` MUST be emitted before `session.started`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindingInfo {
    /// Session ID bound to the work item.
    pub session_id: String,

    /// Work item ID being processed.
    pub work_id: String,

    /// Attempt number for this work item (1-indexed).
    pub attempt_number: u32,

    /// Timestamp when binding was created (nanoseconds since epoch).
    pub bound_at: u64,
}

impl BindingInfo {
    /// Creates a new binding info.
    #[must_use]
    pub const fn new(
        session_id: String,
        work_id: String,
        attempt_number: u32,
        bound_at: u64,
    ) -> Self {
        Self {
            session_id,
            work_id,
            attempt_number,
            bound_at,
        }
    }
}

/// Tracking state for an individual work item within a coordination.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkItemTracking {
    /// Work item ID.
    pub work_id: String,

    /// Number of attempts made for this work item.
    pub attempt_count: u32,

    /// Session IDs used for this work item.
    ///
    /// Limited to [`MAX_SESSION_IDS_PER_WORK`] entries during deserialization.
    #[serde(deserialize_with = "deserialize_bounded_session_ids")]
    pub session_ids: Vec<String>,

    /// Final outcome (set when work item processing is complete).
    pub final_outcome: Option<WorkItemOutcome>,
}

/// Final outcome for a work item in a coordination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkItemOutcome {
    /// Work item completed successfully.
    Succeeded,
    /// Work item failed (retries exhausted).
    Failed,
    /// Work item was skipped (e.g., stale state).
    Skipped,
}

impl WorkItemOutcome {
    /// Returns the string representation of this outcome.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Succeeded => "SUCCEEDED",
            Self::Failed => "FAILED",
            Self::Skipped => "SKIPPED",
        }
    }
}

impl WorkItemTracking {
    /// Creates a new work item tracking entry.
    #[must_use]
    pub const fn new(work_id: String) -> Self {
        Self {
            work_id,
            attempt_count: 0,
            session_ids: Vec::new(),
            final_outcome: None,
        }
    }
}

/// Individual coordination tracking state.
///
/// Represents a single coordination (work queue processing session).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoordinationSession {
    /// Unique identifier for this coordination.
    pub coordination_id: String,

    /// Work queue (list of work item IDs to process).
    ///
    /// Limited to [`MAX_WORK_QUEUE_SIZE`] items. This limit is enforced both
    /// in [`CoordinationSession::new`] and during deserialization.
    #[serde(deserialize_with = "deserialize_bounded_work_queue")]
    pub work_queue: Vec<String>,

    /// Current index in work queue (0-indexed).
    pub work_index: usize,

    /// Per-work tracking information.
    ///
    /// Limited to [`MAX_HASHMAP_SIZE`] entries during deserialization.
    #[serde(deserialize_with = "deserialize_bounded_work_tracking")]
    pub work_tracking: HashMap<String, WorkItemTracking>,

    /// Budget constraints.
    pub budget: CoordinationBudget,

    /// Current budget usage.
    pub budget_usage: BudgetUsage,

    /// Consecutive session failures (for circuit breaker).
    ///
    /// Per AD-COORD-005: Reset to 0 on any success.
    pub consecutive_failures: u32,

    /// Current status.
    pub status: CoordinationStatus,

    /// Timestamp when coordination started (nanoseconds since epoch).
    pub started_at: u64,

    /// Timestamp when coordination completed (nanoseconds since epoch).
    ///
    /// `None` until coordination reaches terminal state.
    pub completed_at: Option<u64>,

    /// Maximum attempts per work item.
    pub max_attempts_per_work: u32,
}

impl CoordinationSession {
    /// Creates a new coordination session.
    ///
    /// # Errors
    ///
    /// Returns [`CoordinationError::WorkQueueSizeExceeded`] if the work queue
    /// contains more than [`MAX_WORK_QUEUE_SIZE`] items.
    pub fn new(
        coordination_id: String,
        work_queue: Vec<String>,
        budget: CoordinationBudget,
        max_attempts_per_work: u32,
        started_at: u64,
    ) -> Result<Self, CoordinationError> {
        if work_queue.len() > MAX_WORK_QUEUE_SIZE {
            return Err(CoordinationError::WorkQueueSizeExceeded {
                actual: work_queue.len(),
                max: MAX_WORK_QUEUE_SIZE,
            });
        }

        let work_tracking = work_queue
            .iter()
            .map(|id| (id.clone(), WorkItemTracking::new(id.clone())))
            .collect();

        Ok(Self {
            coordination_id,
            work_queue,
            work_index: 0,
            work_tracking,
            budget,
            budget_usage: BudgetUsage::new(),
            consecutive_failures: 0,
            status: CoordinationStatus::Initializing,
            started_at,
            completed_at: None,
            max_attempts_per_work,
        })
    }

    /// Returns `true` if the coordination is in a terminal state.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        self.status.is_terminal()
    }

    /// Returns `true` if the coordination is actively running.
    #[must_use]
    pub const fn is_running(&self) -> bool {
        self.status.is_running()
    }

    /// Returns the current work ID being processed, if any.
    #[must_use]
    pub fn current_work_id(&self) -> Option<&str> {
        self.work_queue.get(self.work_index).map(String::as_str)
    }

    /// Returns `true` if all work items have been processed.
    #[must_use]
    pub fn is_work_queue_exhausted(&self) -> bool {
        self.work_index >= self.work_queue.len()
    }
}

/// The coordination reducer state projection.
///
/// Contains all active and completed coordinations.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoordinationState {
    /// Map of coordination ID to coordination session state.
    ///
    /// Limited to [`MAX_HASHMAP_SIZE`] entries during deserialization.
    #[serde(deserialize_with = "deserialize_bounded_coordinations", default)]
    pub coordinations: HashMap<String, CoordinationSession>,

    /// Map of session ID to binding info for active bindings.
    ///
    /// Per AD-COORD-003: Bindings are created on `session_bound` and
    /// removed on `session_unbound`.
    ///
    /// Limited to [`MAX_HASHMAP_SIZE`] entries during deserialization.
    #[serde(deserialize_with = "deserialize_bounded_bindings", default)]
    pub bindings: HashMap<String, BindingInfo>,
}

impl CoordinationState {
    /// Creates a new empty coordination state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            coordinations: HashMap::new(),
            bindings: HashMap::new(),
        }
    }

    /// Gets a coordination session by ID.
    #[must_use]
    pub fn get(&self, coordination_id: &str) -> Option<&CoordinationSession> {
        self.coordinations.get(coordination_id)
    }

    /// Gets a mutable reference to a coordination session by ID.
    #[must_use]
    pub fn get_mut(&mut self, coordination_id: &str) -> Option<&mut CoordinationSession> {
        self.coordinations.get_mut(coordination_id)
    }

    /// Gets a binding by session ID.
    #[must_use]
    pub fn get_binding(&self, session_id: &str) -> Option<&BindingInfo> {
        self.bindings.get(session_id)
    }

    /// Returns the number of coordinations.
    #[must_use]
    pub fn len(&self) -> usize {
        self.coordinations.len()
    }

    /// Returns `true` if there are no coordinations.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.coordinations.is_empty()
    }

    /// Returns the number of active bindings.
    #[must_use]
    pub fn binding_count(&self) -> usize {
        self.bindings.len()
    }

    /// Returns the number of active (non-terminal) coordinations.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.coordinations
            .values()
            .filter(|c| !c.is_terminal())
            .count()
    }

    /// Returns the number of completed coordinations.
    #[must_use]
    pub fn completed_count(&self) -> usize {
        self.coordinations
            .values()
            .filter(|c| matches!(c.status, CoordinationStatus::Completed(_)))
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test tick rate: 1MHz (1 tick = 1 microsecond)
    const TEST_TICK_RATE_HZ: u64 = 1_000_000;

    // ========================================================================
    // CoordinationBudget Tests (RFC-0016::REQ-0003: tick-based)
    // ========================================================================

    #[test]
    fn test_coordination_budget_new() {
        // 10 episodes, 60_000_000 ticks (60 seconds at 1MHz), 100_000 tokens
        let budget =
            CoordinationBudget::new(10, 60_000_000, TEST_TICK_RATE_HZ, Some(100_000)).unwrap();
        assert_eq!(budget.max_episodes, 10);
        assert_eq!(budget.max_duration_ticks, 60_000_000);
        assert_eq!(budget.tick_rate_hz, TEST_TICK_RATE_HZ);
        assert_eq!(budget.max_tokens, Some(100_000));
    }

    #[test]
    fn test_coordination_budget_no_tokens() {
        let budget = CoordinationBudget::new(5, 30_000_000, TEST_TICK_RATE_HZ, None).unwrap();
        assert_eq!(budget.max_episodes, 5);
        assert_eq!(budget.max_duration_ticks, 30_000_000);
        assert_eq!(budget.tick_rate_hz, TEST_TICK_RATE_HZ);
        assert_eq!(budget.max_tokens, None);
    }

    #[test]
    fn test_coordination_budget_serde_roundtrip() {
        let budget =
            CoordinationBudget::new(10, 60_000_000, TEST_TICK_RATE_HZ, Some(100_000)).unwrap();
        let json = serde_json::to_string(&budget).unwrap();
        let restored: CoordinationBudget = serde_json::from_str(&json).unwrap();
        assert_eq!(budget, restored);
    }

    /// RFC-0032::REQ-0048, RFC-0016::REQ-0003: Test that zero budget values are
    /// rejected.
    ///
    /// Per RFC-0012/TB-COORD-004 and RFC-0016::REQ-0003: `max_episodes`,
    /// `max_duration_ticks`, and `tick_rate_hz` are required positive integers.
    #[test]
    fn test_coordination_budget_requires_positive() {
        // Zero max_episodes should fail
        let result = CoordinationBudget::new(0, 60_000_000, TEST_TICK_RATE_HZ, None);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CoordinationError::InvalidBudget {
                field: "max_episodes"
            }
        ));

        // Zero max_duration_ticks should fail
        let result = CoordinationBudget::new(10, 0, TEST_TICK_RATE_HZ, None);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CoordinationError::InvalidBudget {
                field: "max_duration_ticks"
            }
        ));

        // Zero tick_rate_hz should fail
        let result = CoordinationBudget::new(10, 60_000_000, 0, None);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CoordinationError::InvalidBudget {
                field: "tick_rate_hz"
            }
        ));

        // Valid positive values should succeed
        let result = CoordinationBudget::new(1, 1, 1, None);
        assert!(result.is_ok());
    }

    // ========================================================================
    // BudgetUsage Tests (RFC-0016::REQ-0003: tick-based)
    // ========================================================================

    #[test]
    fn test_budget_usage_new() {
        let usage = BudgetUsage::new();
        assert_eq!(usage.consumed_episodes, 0);
        assert_eq!(usage.elapsed_ticks, 0);
        assert_eq!(usage.tick_rate_hz, 0);
        assert_eq!(usage.consumed_tokens, 0);
    }

    #[test]
    fn test_budget_usage_with_tick_rate() {
        let usage = BudgetUsage::with_tick_rate(TEST_TICK_RATE_HZ);
        assert_eq!(usage.consumed_episodes, 0);
        assert_eq!(usage.elapsed_ticks, 0);
        assert_eq!(usage.tick_rate_hz, TEST_TICK_RATE_HZ);
        assert_eq!(usage.consumed_tokens, 0);
    }

    #[test]
    fn test_budget_usage_default() {
        let usage = BudgetUsage::default();
        assert_eq!(usage, BudgetUsage::new());
    }

    #[test]
    fn test_budget_usage_serde_roundtrip() {
        let usage = BudgetUsage {
            consumed_episodes: 5,
            elapsed_ticks: 30_000_000,
            tick_rate_hz: TEST_TICK_RATE_HZ,
            consumed_tokens: 50_000,
        };
        let json = serde_json::to_string(&usage).unwrap();
        let restored: BudgetUsage = serde_json::from_str(&json).unwrap();
        assert_eq!(usage, restored);
    }

    // ========================================================================
    // StopCondition Tests
    // ========================================================================

    #[test]
    fn test_stop_condition_priority_ordering() {
        // Per AD-COORD-013: CircuitBreaker > Duration > Tokens > Episodes > MaxAttempts
        // > WorkCompleted
        let circuit_breaker = StopCondition::CircuitBreakerTriggered {
            consecutive_failures: 3,
        };
        let budget_duration = StopCondition::BudgetExhausted(BudgetType::Duration);
        let budget_tokens = StopCondition::BudgetExhausted(BudgetType::Tokens);
        let budget_episodes = StopCondition::BudgetExhausted(BudgetType::Episodes);
        let max_attempts = StopCondition::MaxAttemptsExceeded {
            work_id: "work-1".to_string(),
        };
        let work_completed = StopCondition::WorkCompleted;

        assert!(circuit_breaker.priority() < budget_duration.priority());
        assert!(budget_duration.priority() < budget_tokens.priority());
        assert!(budget_tokens.priority() < budget_episodes.priority());
        assert!(budget_episodes.priority() < max_attempts.priority());
        assert!(max_attempts.priority() < work_completed.priority());
    }

    #[test]
    fn test_stop_condition_is_success() {
        assert!(StopCondition::WorkCompleted.is_success());
        assert!(
            !StopCondition::CircuitBreakerTriggered {
                consecutive_failures: 3
            }
            .is_success()
        );
        assert!(!StopCondition::BudgetExhausted(BudgetType::Duration).is_success());
    }

    #[test]
    fn test_stop_condition_serde_roundtrip() {
        let conditions = vec![
            StopCondition::WorkCompleted,
            StopCondition::MaxAttemptsExceeded {
                work_id: "work-123".to_string(),
            },
            StopCondition::BudgetExhausted(BudgetType::Duration),
            StopCondition::BudgetExhausted(BudgetType::Tokens),
            StopCondition::BudgetExhausted(BudgetType::Episodes),
            StopCondition::CircuitBreakerTriggered {
                consecutive_failures: 3,
            },
        ];

        for condition in conditions {
            let json = serde_json::to_string(&condition).unwrap();
            let restored: StopCondition = serde_json::from_str(&json).unwrap();
            assert_eq!(condition, restored);
        }
    }

    // ========================================================================
    // CoordinationStatus Tests
    // ========================================================================

    #[test]
    fn test_coordination_status_is_terminal() {
        assert!(!CoordinationStatus::Initializing.is_terminal());
        assert!(!CoordinationStatus::Running.is_terminal());
        assert!(CoordinationStatus::Completed(StopCondition::WorkCompleted).is_terminal());
        assert!(CoordinationStatus::Aborted(AbortReason::NoEligibleWork).is_terminal());
    }

    #[test]
    fn test_coordination_status_is_running() {
        assert!(!CoordinationStatus::Initializing.is_running());
        assert!(CoordinationStatus::Running.is_running());
        assert!(!CoordinationStatus::Completed(StopCondition::WorkCompleted).is_running());
        assert!(!CoordinationStatus::Aborted(AbortReason::NoEligibleWork).is_running());
    }

    #[test]
    fn test_coordination_status_serde_roundtrip() {
        let statuses = vec![
            CoordinationStatus::Initializing,
            CoordinationStatus::Running,
            CoordinationStatus::Completed(StopCondition::WorkCompleted),
            CoordinationStatus::Aborted(AbortReason::Cancelled {
                reason: "test".to_string(),
            }),
        ];

        for status in statuses {
            let json = serde_json::to_string(&status).unwrap();
            let restored: CoordinationStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(status, restored);
        }
    }

    // ========================================================================
    // BindingInfo Tests
    // ========================================================================

    #[test]
    fn test_binding_info_new() {
        let binding = BindingInfo::new(
            "session-123".to_string(),
            "work-456".to_string(),
            1,
            1_000_000_000,
        );
        assert_eq!(binding.session_id, "session-123");
        assert_eq!(binding.work_id, "work-456");
        assert_eq!(binding.attempt_number, 1);
        assert_eq!(binding.bound_at, 1_000_000_000);
    }

    #[test]
    fn test_binding_info_serde_roundtrip() {
        let binding = BindingInfo::new(
            "session-123".to_string(),
            "work-456".to_string(),
            2,
            2_000_000_000,
        );
        let json = serde_json::to_string(&binding).unwrap();
        let restored: BindingInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(binding, restored);
    }

    // ========================================================================
    // CoordinationSession Tests
    // ========================================================================

    #[test]
    fn test_coordination_session_new() {
        let budget = CoordinationBudget::new(10, 60_000_000, TEST_TICK_RATE_HZ, None).unwrap();
        let work_queue = vec!["work-1".to_string(), "work-2".to_string()];
        let session = CoordinationSession::new(
            "coord-123".to_string(),
            work_queue,
            budget,
            3,
            1_000_000_000,
        )
        .unwrap();

        assert_eq!(session.coordination_id, "coord-123");
        assert_eq!(session.work_queue.len(), 2);
        assert_eq!(session.work_index, 0);
        assert_eq!(session.consecutive_failures, 0);
        assert_eq!(session.max_attempts_per_work, 3);
        assert!(matches!(session.status, CoordinationStatus::Initializing));
        assert!(!session.is_terminal());
        assert!(!session.is_running());
    }

    #[test]
    fn test_coordination_session_current_work_id() {
        let budget = CoordinationBudget::new(10, 60_000_000, TEST_TICK_RATE_HZ, None).unwrap();
        let work_queue = vec!["work-1".to_string(), "work-2".to_string()];
        let mut session = CoordinationSession::new(
            "coord-123".to_string(),
            work_queue,
            budget,
            3,
            1_000_000_000,
        )
        .unwrap();

        assert_eq!(session.current_work_id(), Some("work-1"));
        session.work_index = 1;
        assert_eq!(session.current_work_id(), Some("work-2"));
        session.work_index = 2;
        assert_eq!(session.current_work_id(), None);
    }

    #[test]
    fn test_coordination_session_work_queue_exhausted() {
        let budget = CoordinationBudget::new(10, 60_000_000, TEST_TICK_RATE_HZ, None).unwrap();
        let work_queue = vec!["work-1".to_string()];
        let mut session = CoordinationSession::new(
            "coord-123".to_string(),
            work_queue,
            budget,
            3,
            1_000_000_000,
        )
        .unwrap();

        assert!(!session.is_work_queue_exhausted());
        session.work_index = 1;
        assert!(session.is_work_queue_exhausted());
    }

    #[test]
    fn test_coordination_session_serde_roundtrip() {
        let budget =
            CoordinationBudget::new(10, 60_000_000, TEST_TICK_RATE_HZ, Some(100_000)).unwrap();
        let work_queue = vec!["work-1".to_string(), "work-2".to_string()];
        let session = CoordinationSession::new(
            "coord-123".to_string(),
            work_queue,
            budget,
            3,
            1_000_000_000,
        )
        .unwrap();

        let json = serde_json::to_string(&session).unwrap();
        let restored: CoordinationSession = serde_json::from_str(&json).unwrap();
        assert_eq!(session, restored);
    }

    // ========================================================================
    // CoordinationState Tests
    // ========================================================================

    #[test]
    fn test_coordination_state_new() {
        let state = CoordinationState::new();
        assert!(state.is_empty());
        assert_eq!(state.len(), 0);
        assert_eq!(state.binding_count(), 0);
    }

    #[test]
    fn test_coordination_state_get() {
        let mut state = CoordinationState::new();
        let budget = CoordinationBudget::new(10, 60_000_000, TEST_TICK_RATE_HZ, None).unwrap();
        let work_queue = vec!["work-1".to_string()];
        let session = CoordinationSession::new(
            "coord-123".to_string(),
            work_queue,
            budget,
            3,
            1_000_000_000,
        )
        .unwrap();

        state.coordinations.insert("coord-123".to_string(), session);

        assert!(state.get("coord-123").is_some());
        assert!(state.get("nonexistent").is_none());
    }

    #[test]
    fn test_coordination_state_counts() {
        let mut state = CoordinationState::new();
        let budget = CoordinationBudget::new(10, 60_000_000, TEST_TICK_RATE_HZ, None).unwrap();

        // Add an active coordination
        let mut active =
            CoordinationSession::new("coord-1".to_string(), vec![], budget.clone(), 3, 1_000)
                .unwrap();
        active.status = CoordinationStatus::Running;
        state.coordinations.insert("coord-1".to_string(), active);

        // Add a completed coordination
        let mut completed =
            CoordinationSession::new("coord-2".to_string(), vec![], budget, 3, 1_000).unwrap();
        completed.status = CoordinationStatus::Completed(StopCondition::WorkCompleted);
        state.coordinations.insert("coord-2".to_string(), completed);

        assert_eq!(state.len(), 2);
        assert_eq!(state.active_count(), 1);
        assert_eq!(state.completed_count(), 1);
    }

    #[test]
    fn test_coordination_state_serde_roundtrip() {
        let mut state = CoordinationState::new();
        let budget = CoordinationBudget::new(10, 60_000_000, TEST_TICK_RATE_HZ, None).unwrap();
        let work_queue = vec!["work-1".to_string()];
        let session = CoordinationSession::new(
            "coord-123".to_string(),
            work_queue,
            budget,
            3,
            1_000_000_000,
        )
        .unwrap();
        state.coordinations.insert("coord-123".to_string(), session);

        let binding = BindingInfo::new(
            "session-456".to_string(),
            "work-1".to_string(),
            1,
            2_000_000_000,
        );
        state.bindings.insert("session-456".to_string(), binding);

        let json = serde_json::to_string(&state).unwrap();
        let restored: CoordinationState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, restored);
    }

    // ========================================================================
    // RFC-0032::REQ-0048 Specific Tests (Serde Round-Trip)
    // ========================================================================

    /// RFC-0032::REQ-0048: Verify all types serialize and deserialize
    /// correctly.
    #[test]
    fn tck_00148_serde_roundtrip_all_types() {
        // CoordinationBudget
        let budget =
            CoordinationBudget::new(10, 60_000_000, TEST_TICK_RATE_HZ, Some(100_000)).unwrap();
        let json = serde_json::to_string(&budget).unwrap();
        assert_eq!(budget, serde_json::from_str(&json).unwrap());

        // BudgetUsage
        let usage = BudgetUsage {
            consumed_episodes: 5,
            elapsed_ticks: 30_000_000,
            tick_rate_hz: TEST_TICK_RATE_HZ,
            consumed_tokens: 50_000,
        };
        let json = serde_json::to_string(&usage).unwrap();
        assert_eq!(usage, serde_json::from_str(&json).unwrap());

        // StopCondition (all variants)
        for condition in [
            StopCondition::WorkCompleted,
            StopCondition::MaxAttemptsExceeded {
                work_id: "w".to_string(),
            },
            StopCondition::BudgetExhausted(BudgetType::Duration),
            StopCondition::BudgetExhausted(BudgetType::Tokens),
            StopCondition::BudgetExhausted(BudgetType::Episodes),
            StopCondition::CircuitBreakerTriggered {
                consecutive_failures: 3,
            },
        ] {
            let json = serde_json::to_string(&condition).unwrap();
            assert_eq!(condition, serde_json::from_str(&json).unwrap());
        }

        // CoordinationStatus (all variants)
        for status in [
            CoordinationStatus::Initializing,
            CoordinationStatus::Running,
            CoordinationStatus::Completed(StopCondition::WorkCompleted),
            CoordinationStatus::Aborted(AbortReason::NoEligibleWork),
        ] {
            let json = serde_json::to_string(&status).unwrap();
            assert_eq!(status, serde_json::from_str(&json).unwrap());
        }

        // BindingInfo
        let binding = BindingInfo::new("s".to_string(), "w".to_string(), 1, 1000);
        let json = serde_json::to_string(&binding).unwrap();
        assert_eq!(binding, serde_json::from_str(&json).unwrap());

        // CoordinationSession
        let session =
            CoordinationSession::new("c".to_string(), vec!["w".to_string()], budget, 3, 1000)
                .unwrap();
        let json = serde_json::to_string(&session).unwrap();
        assert_eq!(session, serde_json::from_str(&json).unwrap());

        // CoordinationState
        let mut state = CoordinationState::new();
        state.coordinations.insert("c".to_string(), session);
        state.bindings.insert("s".to_string(), binding);
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(state, serde_json::from_str(&json).unwrap());
    }

    // ========================================================================
    // Security Tests (RFC-0032::REQ-0048)
    // ========================================================================

    /// RFC-0032::REQ-0048: Test that work queue size limit is enforced.
    #[test]
    fn test_coordination_session_queue_limit() {
        let budget = CoordinationBudget::new(10, 60_000_000, TEST_TICK_RATE_HZ, None).unwrap();

        // Create a work queue that exceeds the limit
        let oversized_queue: Vec<String> = (0..=MAX_WORK_QUEUE_SIZE)
            .map(|i| format!("work-{i}"))
            .collect();
        assert_eq!(oversized_queue.len(), MAX_WORK_QUEUE_SIZE + 1);

        let result = CoordinationSession::new(
            "coord-123".to_string(),
            oversized_queue,
            budget.clone(),
            3,
            1_000_000_000,
        );

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(
            err,
            CoordinationError::WorkQueueSizeExceeded {
                actual,
                max
            } if actual == MAX_WORK_QUEUE_SIZE + 1 && max == MAX_WORK_QUEUE_SIZE
        ));

        // Verify exact limit works
        let exact_queue: Vec<String> = (0..MAX_WORK_QUEUE_SIZE)
            .map(|i| format!("work-{i}"))
            .collect();
        assert_eq!(exact_queue.len(), MAX_WORK_QUEUE_SIZE);

        let result = CoordinationSession::new(
            "coord-124".to_string(),
            exact_queue,
            budget,
            3,
            1_000_000_000,
        );
        assert!(result.is_ok());
    }

    /// RFC-0032::REQ-0048: Test that `work_queue` size limit is enforced during
    /// deserialization, preventing denial-of-service via oversized JSON
    /// payloads.
    #[test]
    fn test_coordination_session_queue_limit_serde() {
        // Build a JSON string with MAX_WORK_QUEUE_SIZE + 1 work items
        let oversized_queue: Vec<String> = (0..=MAX_WORK_QUEUE_SIZE)
            .map(|i| format!("work-{i}"))
            .collect();
        assert_eq!(oversized_queue.len(), MAX_WORK_QUEUE_SIZE + 1);

        // Build work_tracking HashMap for the oversized queue
        let work_tracking: std::collections::HashMap<String, serde_json::Value> = oversized_queue
            .iter()
            .map(|id| {
                (
                    id.clone(),
                    serde_json::json!({
                        "work_id": id,
                        "attempt_count": 0,
                        "session_ids": [],
                        "final_outcome": null
                    }),
                )
            })
            .collect();

        let json = serde_json::json!({
            "coordination_id": "coord-123",
            "work_queue": oversized_queue,
            "work_index": 0,
            "work_tracking": work_tracking,
            "budget": {
                "max_episodes": 10,
                "max_duration_ticks": 60000,
                "tick_rate_hz": 1_000_000,
                "max_tokens": null
            },
            "budget_usage": {
                "consumed_episodes": 0,
                "elapsed_ticks": 0,
                "tick_rate_hz": 1_000_000,
                "consumed_tokens": 0
            },
            "consecutive_failures": 0,
            "status": "Initializing",
            "started_at": 1_000_000_000_u64,
            "completed_at": null,
            "max_attempts_per_work": 3
        });

        let result: Result<CoordinationSession, _> = serde_json::from_value(json);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("work_queue exceeds maximum size"),
            "Expected error about work_queue size limit, got: {err}"
        );
    }

    /// RFC-0032::REQ-0048: Test that `HashMap` size limits are enforced during
    /// deserialization for `work_tracking`.
    #[test]
    fn test_work_tracking_hashmap_limit_serde() {
        // Build an oversized work_tracking HashMap
        let oversized_tracking: std::collections::HashMap<String, serde_json::Value> = (0
            ..=MAX_HASHMAP_SIZE)
            .map(|i| {
                (
                    format!("work-{i}"),
                    serde_json::json!({
                        "work_id": format!("work-{i}"),
                        "attempt_count": 0,
                        "session_ids": [],
                        "final_outcome": null
                    }),
                )
            })
            .collect();
        assert_eq!(oversized_tracking.len(), MAX_HASHMAP_SIZE + 1);

        let json = serde_json::json!({
            "coordination_id": "coord-123",
            "work_queue": ["work-0"],
            "work_index": 0,
            "work_tracking": oversized_tracking,
            "budget": {
                "max_episodes": 10,
                "max_duration_ticks": 60000,
                "tick_rate_hz": 1_000_000,
                "max_tokens": null
            },
            "budget_usage": {
                "consumed_episodes": 0,
                "elapsed_ticks": 0,
                "tick_rate_hz": 1_000_000,
                "consumed_tokens": 0
            },
            "consecutive_failures": 0,
            "status": "Initializing",
            "started_at": 1_000_000_000_u64,
            "completed_at": null,
            "max_attempts_per_work": 3
        });

        let result: Result<CoordinationSession, _> = serde_json::from_value(json);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("work_tracking exceeds maximum size"),
            "Expected error about work_tracking size limit, got: {err}"
        );
    }

    /// RFC-0032::REQ-0048: Test that `HashMap` size limits are enforced during
    /// deserialization for `coordinations` in `CoordinationState`.
    #[test]
    fn test_coordinations_hashmap_limit_serde() {
        // Build an oversized coordinations HashMap
        // For efficiency, we use minimal valid coordination session objects
        let budget_json = serde_json::json!({
            "max_episodes": 10,
            "max_duration_ticks": 60000,
            "tick_rate_hz": 1_000_000,
            "max_tokens": null
        });

        let oversized_coordinations: std::collections::HashMap<String, serde_json::Value> = (0
            ..=MAX_HASHMAP_SIZE)
            .map(|i| {
                (
                    format!("coord-{i}"),
                    serde_json::json!({
                        "coordination_id": format!("coord-{i}"),
                        "work_queue": [],
                        "work_index": 0,
                        "work_tracking": {},
                        "budget": budget_json,
                        "budget_usage": {
                            "consumed_episodes": 0,
                            "elapsed_ticks": 0,
                            "tick_rate_hz": 1_000_000,
                            "consumed_tokens": 0
                        },
                        "consecutive_failures": 0,
                        "status": "Initializing",
                        "started_at": 1_000_000_000_u64,
                        "completed_at": null,
                        "max_attempts_per_work": 3
                    }),
                )
            })
            .collect();
        assert_eq!(oversized_coordinations.len(), MAX_HASHMAP_SIZE + 1);

        let json = serde_json::json!({
            "coordinations": oversized_coordinations,
            "bindings": {}
        });

        let result: Result<CoordinationState, _> = serde_json::from_value(json);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("hashmap exceeds maximum size"),
            "Expected error about hashmap size limit, got: {err}"
        );
    }

    /// RFC-0032::REQ-0048: Test that `HashMap` size limits are enforced during
    /// deserialization for `bindings` in `CoordinationState`.
    #[test]
    fn test_bindings_hashmap_limit_serde() {
        // Build an oversized bindings HashMap
        let oversized_bindings: std::collections::HashMap<String, serde_json::Value> = (0
            ..=MAX_HASHMAP_SIZE)
            .map(|i| {
                (
                    format!("session-{i}"),
                    serde_json::json!({
                        "session_id": format!("session-{i}"),
                        "work_id": format!("work-{i}"),
                        "attempt_number": 1,
                        "bound_at": 1_000_000_000_u64
                    }),
                )
            })
            .collect();
        assert_eq!(oversized_bindings.len(), MAX_HASHMAP_SIZE + 1);

        let json = serde_json::json!({
            "coordinations": {},
            "bindings": oversized_bindings
        });

        let result: Result<CoordinationState, _> = serde_json::from_value(json);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("hashmap exceeds maximum size"),
            "Expected error about hashmap size limit, got: {err}"
        );
    }

    /// RFC-0032::REQ-0048: Verify streaming deserializer rejects oversized
    /// arrays without attempting full allocation.
    ///
    /// This test documents that the streaming visitor pattern prevents OOM
    /// by checking bounds during iteration rather than after full allocation.
    /// The test verifies the error message indicates the failure occurs at
    /// the boundary, not after allocating 1001 items.
    #[test]
    fn test_streaming_deserializer_bounds_check() {
        // Create JSON with exactly MAX_WORK_QUEUE_SIZE + 1 items
        let oversized_queue: Vec<String> = (0..=MAX_WORK_QUEUE_SIZE)
            .map(|i| format!("work-{i}"))
            .collect();

        let json = serde_json::json!({
            "coordination_id": "coord-test",
            "work_ids": oversized_queue,
            "budget": {
                "max_episodes": 10,
                "max_duration_ticks": 60000,
                "tick_rate_hz": 1_000_000,
                "max_tokens": null
            },
            "max_attempts_per_work": 3,
            "started_at": 1_000_000_000_u64
        });

        let result: Result<super::super::events::CoordinationStarted, _> =
            serde_json::from_value(json);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();

        // The error message should indicate the exact boundary where rejection occurred
        // (MAX_WORK_QUEUE_SIZE + 1 = 1001)
        assert!(
            err.contains(&format!(
                "work_ids exceeds maximum size: {} > {}",
                MAX_WORK_QUEUE_SIZE + 1,
                MAX_WORK_QUEUE_SIZE
            )),
            "Expected error at boundary {}, got: {err}",
            MAX_WORK_QUEUE_SIZE + 1
        );
    }

    /// RFC-0032::REQ-0048: Test that `session_ids` size limit is enforced
    /// during deserialization, preventing denial-of-service via oversized
    /// JSON payloads in `WorkItemTracking`.
    #[test]
    fn test_work_tracking_session_ids_limit_serde() {
        // Build a session_ids array that exceeds the limit
        let oversized_session_ids: Vec<String> = (0..=MAX_SESSION_IDS_PER_WORK)
            .map(|i| format!("session-{i}"))
            .collect();
        assert_eq!(oversized_session_ids.len(), MAX_SESSION_IDS_PER_WORK + 1);

        let json = serde_json::json!({
            "work_id": "work-123",
            "attempt_count": 0,
            "session_ids": oversized_session_ids,
            "final_outcome": null
        });

        let result: Result<WorkItemTracking, _> = serde_json::from_value(json);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("session_ids exceeds maximum size"),
            "Expected error about session_ids size limit, got: {err}"
        );

        // Verify exact limit works
        let exact_session_ids: Vec<String> = (0..MAX_SESSION_IDS_PER_WORK)
            .map(|i| format!("session-{i}"))
            .collect();
        assert_eq!(exact_session_ids.len(), MAX_SESSION_IDS_PER_WORK);

        let json = serde_json::json!({
            "work_id": "work-123",
            "attempt_count": 0,
            "session_ids": exact_session_ids,
            "final_outcome": null
        });

        let result: Result<WorkItemTracking, _> = serde_json::from_value(json);
        assert!(
            result.is_ok(),
            "Expected exact limit to work, got: {result:?}"
        );
    }

    // ========================================================================
    // RFC-0032::REQ-0051: Budget Enforcement Helper Tests
    // ========================================================================

    /// RFC-0032::REQ-0051: Test episode budget exhaustion detection.
    ///
    /// Verification: Coordination stops at `max_episodes`.
    #[test]
    fn tck_00151_episode_budget_exhausted() {
        let budget = CoordinationBudget::new(5, 60_000_000, TEST_TICK_RATE_HZ, None).unwrap();
        let mut usage = BudgetUsage::new();

        // Not exhausted initially
        assert!(!usage.is_episode_budget_exhausted(&budget));
        assert_eq!(usage.remaining_episodes(&budget), 5);

        // Consume 4 episodes - still not exhausted
        usage.consumed_episodes = 4;
        assert!(!usage.is_episode_budget_exhausted(&budget));
        assert_eq!(usage.remaining_episodes(&budget), 1);

        // Consume 5th episode - now exhausted
        usage.consumed_episodes = 5;
        assert!(usage.is_episode_budget_exhausted(&budget));
        assert_eq!(usage.remaining_episodes(&budget), 0);

        // Over budget - still exhausted
        usage.consumed_episodes = 10;
        assert!(usage.is_episode_budget_exhausted(&budget));
        assert_eq!(usage.remaining_episodes(&budget), 0);
    }

    /// RFC-0032::REQ-0051: Test duration budget exhaustion detection.
    ///
    /// Verification: Coordination stops at `max_duration_ticks`.
    #[test]
    fn tck_00151_duration_budget_exhausted() {
        let budget = CoordinationBudget::new(10, 30_000_000, TEST_TICK_RATE_HZ, None).unwrap();
        let mut usage = BudgetUsage::new();

        // Not exhausted initially
        assert!(!usage.is_duration_budget_exhausted(&budget));
        assert_eq!(usage.remaining_duration_ticks(&budget), 30_000_000);

        // Consume 29 seconds (29M ticks) - still not exhausted
        usage.elapsed_ticks = 29_000_000;
        assert!(!usage.is_duration_budget_exhausted(&budget));
        assert_eq!(usage.remaining_duration_ticks(&budget), 1_000_000);

        // Consume exactly 30 seconds (30M ticks) - now exhausted
        usage.elapsed_ticks = 30_000_000;
        assert!(usage.is_duration_budget_exhausted(&budget));
        assert_eq!(usage.remaining_duration_ticks(&budget), 0);

        // Over budget - still exhausted
        usage.elapsed_ticks = 45_000_000;
        assert!(usage.is_duration_budget_exhausted(&budget));
        assert_eq!(usage.remaining_duration_ticks(&budget), 0);
    }

    /// RFC-0032::REQ-0051: Test token budget exhaustion detection.
    ///
    /// Verification: Coordination stops at `max_tokens` (when set).
    #[test]
    fn tck_00151_token_budget_exhausted() {
        // With token limit set
        let budget_with_tokens =
            CoordinationBudget::new(10, 60_000_000, TEST_TICK_RATE_HZ, Some(100_000)).unwrap();
        let mut usage = BudgetUsage::new();

        // Not exhausted initially
        assert!(!usage.is_token_budget_exhausted(&budget_with_tokens));
        assert_eq!(usage.remaining_tokens(&budget_with_tokens), Some(100_000));

        // Consume 99,999 tokens - still not exhausted
        usage.consumed_tokens = 99_999;
        assert!(!usage.is_token_budget_exhausted(&budget_with_tokens));
        assert_eq!(usage.remaining_tokens(&budget_with_tokens), Some(1));

        // Consume exactly 100,000 tokens - now exhausted
        usage.consumed_tokens = 100_000;
        assert!(usage.is_token_budget_exhausted(&budget_with_tokens));
        assert_eq!(usage.remaining_tokens(&budget_with_tokens), Some(0));

        // Over budget - still exhausted
        usage.consumed_tokens = 150_000;
        assert!(usage.is_token_budget_exhausted(&budget_with_tokens));
        assert_eq!(usage.remaining_tokens(&budget_with_tokens), Some(0));

        // Without token limit - never exhausted
        let budget_no_tokens =
            CoordinationBudget::new(10, 60_000_000, TEST_TICK_RATE_HZ, None).unwrap();
        assert!(!usage.is_token_budget_exhausted(&budget_no_tokens));
        assert_eq!(usage.remaining_tokens(&budget_no_tokens), None);
    }

    /// RFC-0032::REQ-0051: Test budget exhaustion priority ordering.
    ///
    /// Per AD-COORD-013: Duration > Tokens > Episodes priority.
    #[test]
    fn tck_00151_budget_exhaustion_priority() {
        let budget =
            CoordinationBudget::new(5, 10_000_000, TEST_TICK_RATE_HZ, Some(50_000)).unwrap();
        let mut usage = BudgetUsage::new();

        // No budget exhausted
        assert_eq!(usage.check_budget_exhausted(&budget), None);

        // Only episode budget exhausted - returns Episodes
        usage.consumed_episodes = 5;
        assert_eq!(
            usage.check_budget_exhausted(&budget),
            Some(BudgetType::Episodes)
        );

        // Token and episode exhausted - returns Tokens (higher priority)
        usage.consumed_tokens = 50_000;
        assert_eq!(
            usage.check_budget_exhausted(&budget),
            Some(BudgetType::Tokens)
        );

        // All three exhausted - returns Duration (highest priority)
        usage.elapsed_ticks = 10_000_000;
        assert_eq!(
            usage.check_budget_exhausted(&budget),
            Some(BudgetType::Duration)
        );

        // Reset and test duration alone
        usage.consumed_episodes = 0;
        usage.consumed_tokens = 0;
        usage.elapsed_ticks = 10_000_000;
        assert_eq!(
            usage.check_budget_exhausted(&budget),
            Some(BudgetType::Duration)
        );
    }

    /// RFC-0032::REQ-0051: Test token aggregation from session outcomes.
    ///
    /// Verification: `consumed_tokens` reflects session `final_entropy`.
    #[test]
    fn tck_00151_token_aggregation() {
        let mut usage = BudgetUsage::new();

        // Initial state
        assert_eq!(usage.consumed_tokens, 0);

        // Aggregate first session tokens
        usage.aggregate_tokens(1000);
        assert_eq!(usage.consumed_tokens, 1000);

        // Aggregate second session tokens
        usage.aggregate_tokens(2500);
        assert_eq!(usage.consumed_tokens, 3500);

        // Aggregate third session tokens
        usage.aggregate_tokens(500);
        assert_eq!(usage.consumed_tokens, 4000);

        // Verify saturation behavior (no overflow)
        usage.consumed_tokens = u64::MAX - 100;
        usage.aggregate_tokens(200);
        assert_eq!(usage.consumed_tokens, u64::MAX);
    }

    /// RFC-0032::REQ-0051: Test episode increment helper.
    #[test]
    fn tck_00151_episode_increment() {
        let mut usage = BudgetUsage::new();

        assert_eq!(usage.consumed_episodes, 0);

        usage.increment_episodes();
        assert_eq!(usage.consumed_episodes, 1);

        usage.increment_episodes();
        assert_eq!(usage.consumed_episodes, 2);

        // Verify saturation behavior (no overflow)
        usage.consumed_episodes = u32::MAX;
        usage.increment_episodes();
        assert_eq!(usage.consumed_episodes, u32::MAX);
    }

    /// RFC-0032::REQ-0051: Test remaining budget calculations at boundary
    /// conditions.
    #[test]
    fn tck_00151_remaining_budget_boundaries() {
        let budget =
            CoordinationBudget::new(10, 60_000_000, TEST_TICK_RATE_HZ, Some(100_000)).unwrap();

        // Test at exactly budget limit
        let usage_at_limit = BudgetUsage {
            consumed_episodes: 10,
            elapsed_ticks: 60_000_000,
            tick_rate_hz: TEST_TICK_RATE_HZ,
            consumed_tokens: 100_000,
        };
        assert_eq!(usage_at_limit.remaining_episodes(&budget), 0);
        assert_eq!(usage_at_limit.remaining_duration_ticks(&budget), 0);
        assert_eq!(usage_at_limit.remaining_tokens(&budget), Some(0));

        // Test over budget (should saturate to 0, not underflow)
        let usage_over_limit = BudgetUsage {
            consumed_episodes: 15,
            elapsed_ticks: 90_000_000,
            tick_rate_hz: TEST_TICK_RATE_HZ,
            consumed_tokens: 150_000,
        };
        assert_eq!(usage_over_limit.remaining_episodes(&budget), 0);
        assert_eq!(usage_over_limit.remaining_duration_ticks(&budget), 0);
        assert_eq!(usage_over_limit.remaining_tokens(&budget), Some(0));
    }

    /// RFC-0032::REQ-0051: Test budget usage with large values (near
    /// `u64::MAX`).
    #[test]
    fn tck_00151_budget_large_values() {
        // Create budget with large values
        let budget = CoordinationBudget::new_unchecked(
            u32::MAX,
            u64::MAX,
            TEST_TICK_RATE_HZ,
            Some(u64::MAX),
        );
        let mut usage = BudgetUsage::new();

        // Not exhausted with large budget
        assert!(!usage.is_episode_budget_exhausted(&budget));
        assert!(!usage.is_duration_budget_exhausted(&budget));
        assert!(!usage.is_token_budget_exhausted(&budget));

        // Consume large amounts - still not exhausted
        usage.consumed_episodes = u32::MAX - 1;
        usage.elapsed_ticks = u64::MAX - 1;
        usage.consumed_tokens = u64::MAX - 1;
        assert!(!usage.is_episode_budget_exhausted(&budget));
        assert!(!usage.is_duration_budget_exhausted(&budget));
        assert!(!usage.is_token_budget_exhausted(&budget));

        // At max - now exhausted
        usage.consumed_episodes = u32::MAX;
        usage.elapsed_ticks = u64::MAX;
        usage.consumed_tokens = u64::MAX;
        assert!(usage.is_episode_budget_exhausted(&budget));
        assert!(usage.is_duration_budget_exhausted(&budget));
        assert!(usage.is_token_budget_exhausted(&budget));
    }

    /// RFC-0032::REQ-0051: Test budget usage serde roundtrip preserves helper
    /// behavior.
    #[test]
    fn tck_00151_budget_usage_serde_roundtrip() {
        let budget =
            CoordinationBudget::new(10, 60_000_000, TEST_TICK_RATE_HZ, Some(100_000)).unwrap();
        let usage = BudgetUsage {
            consumed_episodes: 5,
            elapsed_ticks: 30_000_000,
            tick_rate_hz: TEST_TICK_RATE_HZ,
            consumed_tokens: 50_000,
        };

        // Serialize and deserialize
        let json = serde_json::to_string(&usage).unwrap();
        let restored: BudgetUsage = serde_json::from_str(&json).unwrap();

        // Verify helper methods work identically
        assert_eq!(
            usage.is_episode_budget_exhausted(&budget),
            restored.is_episode_budget_exhausted(&budget)
        );
        assert_eq!(
            usage.is_duration_budget_exhausted(&budget),
            restored.is_duration_budget_exhausted(&budget)
        );
        assert_eq!(
            usage.is_token_budget_exhausted(&budget),
            restored.is_token_budget_exhausted(&budget)
        );
        assert_eq!(
            usage.check_budget_exhausted(&budget),
            restored.check_budget_exhausted(&budget)
        );
        assert_eq!(
            usage.remaining_episodes(&budget),
            restored.remaining_episodes(&budget)
        );
        assert_eq!(
            usage.remaining_duration_ticks(&budget),
            restored.remaining_duration_ticks(&budget)
        );
        assert_eq!(
            usage.remaining_tokens(&budget),
            restored.remaining_tokens(&budget)
        );
    }

    // =========================================================================
    // RFC-0016::REQ-0003: BudgetUsage Tick Rate Validation Tests
    // =========================================================================

    /// RFC-0016::REQ-0003: `BudgetUsage` allows first tick rate assignment.
    ///
    /// When `tick_rate_hz` is 0 (default/uninitialized), any rate can be set.
    #[test]
    fn tck_00242_budget_usage_allows_first_tick_rate() {
        let mut usage = BudgetUsage::new();
        assert_eq!(usage.tick_rate_hz, 0);

        // First assignment should work
        usage.update_elapsed_ticks(0, 1000, 1_000_000).unwrap();

        assert_eq!(usage.elapsed_ticks, 1000);
        assert_eq!(usage.tick_rate_hz, 1_000_000);
    }

    /// RFC-0016::REQ-0003: `BudgetUsage` allows same tick rate on subsequent
    /// updates.
    ///
    /// When the same rate is used, updates should succeed.
    #[test]
    fn tck_00242_budget_usage_allows_same_tick_rate() {
        let mut usage = BudgetUsage::with_tick_rate(1_000_000);

        // First update
        usage.update_elapsed_ticks(0, 1000, 1_000_000).unwrap();
        assert_eq!(usage.elapsed_ticks, 1000);

        // Second update with same rate should work
        usage.update_elapsed_ticks(0, 2000, 1_000_000).unwrap();
        assert_eq!(usage.elapsed_ticks, 2000);
    }

    /// RFC-0016::REQ-0003: `BudgetUsage` returns error on tick rate mismatch.
    ///
    /// Once initialized with a non-zero rate, attempting to use a different
    /// rate should return an error to prevent temporal confusion.
    #[test]
    fn tck_00242_budget_usage_errors_on_rate_mismatch() {
        let mut usage = BudgetUsage::with_tick_rate(1_000_000);

        // First update with correct rate
        usage.update_elapsed_ticks(0, 1000, 1_000_000).unwrap();

        // Second update with different rate should return error
        let result = usage.update_elapsed_ticks(0, 2000, 1_000_000_000);
        assert!(matches!(
            result,
            Err(CoordinationError::TickRateMismatch {
                expected: 1_000_000,
                actual: 1_000_000_000
            })
        ));
    }

    /// RFC-0016::REQ-0003: `BudgetUsage` from Default still allows rate
    /// assignment.
    ///
    /// Default-constructed `BudgetUsage` has `tick_rate_hz` = 0, allowing
    /// first-time assignment.
    #[test]
    fn tck_00242_budget_usage_default_allows_rate_assignment() {
        let mut usage = BudgetUsage::default();
        assert_eq!(usage.tick_rate_hz, 0);

        // Should be able to set rate
        usage.update_elapsed_ticks(100, 500, 1_000_000).unwrap();

        assert_eq!(usage.elapsed_ticks, 400);
        assert_eq!(usage.tick_rate_hz, 1_000_000);
    }

    /// RFC-0016::REQ-0003: `BudgetUsage` detects clock regression.
    ///
    /// When `current_tick` < `start_tick`, the method should return an error
    /// rather than silently saturating to 0.
    #[test]
    fn tck_00242_budget_usage_detects_clock_regression() {
        let mut usage = BudgetUsage::new();

        // Clock regression: current tick is before start tick
        let result = usage.update_elapsed_ticks(1000, 500, 1_000_000);
        assert!(matches!(
            result,
            Err(CoordinationError::ClockRegression {
                start_tick: 1000,
                current_tick: 500
            })
        ));
    }

    // =========================================================================
    // RFC-0016::REQ-0003: Legacy JSON Deserialization Tests
    // =========================================================================

    /// RFC-0016::REQ-0003: Verify legacy JSON deserialization works by
    /// defaulting `tick_rate_hz` to 1000.
    #[test]
    fn tck_00242_legacy_json_deserialization() {
        // Legacy Budget JSON (missing tick_rate_hz)
        let legacy_budget_json = serde_json::json!({
            "max_episodes": 10,
            "max_duration_ms": 60000, // 60 seconds in ms
            "max_tokens": 1000
        });

        let budget: CoordinationBudget = serde_json::from_value(legacy_budget_json).unwrap();
        assert_eq!(budget.max_duration_ticks, 60000);
        assert_eq!(budget.tick_rate_hz, 1000); // Defaulted to 1kHz

        // Legacy BudgetUsage JSON (missing tick_rate_hz)
        let legacy_usage_json = serde_json::json!({
            "consumed_episodes": 5,
            "elapsed_ms": 30000, // 30 seconds in ms
            "consumed_tokens": 500
        });

        let usage: BudgetUsage = serde_json::from_value(legacy_usage_json).unwrap();
        assert_eq!(usage.elapsed_ticks, 30000);
        assert_eq!(usage.tick_rate_hz, 1000); // Defaulted to 1kHz
    }
}
