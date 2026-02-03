//! Resource governance and backpressure/drop policy for HEF Pulse Plane
//! (RFC-0018, TCK-00303).
//!
//! This module implements resource governance for the Holonic Event Fabric
//! (HEF) pulse subscription system. It enforces limits on subscriptions,
//! patterns, rates, queue depths, and bytes in-flight to prevent
//! denial-of-service and ensure daemon stability.
//!
//! # Resource Governance Limits (DD-HEF-0005)
//!
//! Per RFC-0018 `resource_governance.limits`:
//!
//! | Limit                            | Value    | Purpose                       |
//! |----------------------------------|----------|-------------------------------|
//! | `max_subscriptions_per_connection` | 16       | Subscription count cap        |
//! | `max_patterns_per_subscription`  | 16       | Patterns per subscription     |
//! | `max_total_patterns_per_connection` | 64     | Total patterns per connection |
//! | `max_pulses_per_sec_per_subscriber` | 100    | Rate limit (token bucket)     |
//! | `max_burst_pulses_per_subscriber` | 200     | Burst capacity                |
//! | `max_queue_depth_per_subscriber` | 256      | Queue depth limit             |
//! | `max_bytes_in_flight_per_subscriber` | 1048576 | 1 MiB bytes in-flight       |
//! | `max_pulse_payload_bytes`        | 2048     | Individual pulse size limit   |
//!
//! # Drop Policy (DD-HEF-0005)
//!
//! Under backpressure, pulses are dropped in priority order (lowest priority
//! first):
//!
//! 1. `episode.<episode_id>.io` - Stream output (highest drop priority)
//! 2. `episode.<episode_id>.tool` - Tool events
//! 3. `episode.<episode_id>.lifecycle` - Lifecycle events
//! 4. `work.<work_id>.events` - Work events
//! 5. `gate.<work_id>.<changeset_digest>.<gate_id>` - Gate receipts
//! 6. `ledger.head` - Ledger head (lowest drop priority, most important)
//!
//! # Error Handling
//!
//! Oversubscription and limit violations return `HEF_ERROR_RESOURCE_LIMIT`
//! without crashing the daemon.
//!
//! # Security Invariants
//!
//! - [INV-RG-001] Connection-level limits prevent single-connection DoS
//! - [INV-RG-002] Rate limiting prevents pulse flood attacks
//! - [INV-RG-003] Queue bounds prevent memory exhaustion
//! - [INV-RG-004] Drop policy ensures critical pulses survive backpressure
//! - [INV-RG-005] All limit violations return errors, never panic

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Instant;

use super::messages::HefErrorCode;
use super::pulse_topic::TopicPattern;

// ============================================================================
// Constants (DD-HEF-0005: Resource Governance)
// ============================================================================

/// Maximum subscriptions per connection.
/// Per RFC-0018: `max_subscriptions_per_connection: 16`
pub const MAX_SUBSCRIPTIONS_PER_CONNECTION: usize = 16;

/// Maximum patterns per subscription.
/// Per RFC-0018: `max_patterns_per_subscription: 16`
pub const MAX_PATTERNS_PER_SUBSCRIPTION: usize = 16;

/// Maximum total patterns per connection.
/// Per RFC-0018: `max_total_patterns_per_connection: 64`
pub const MAX_TOTAL_PATTERNS_PER_CONNECTION: usize = 64;

/// Maximum pulses per second per subscriber (rate limit).
/// Per RFC-0018: `max_pulses_per_sec_per_subscriber: 100`
pub const MAX_PULSES_PER_SEC_PER_SUBSCRIBER: u64 = 100;

/// Maximum burst pulses per subscriber.
/// Per RFC-0018: `max_burst_pulses_per_subscriber: 200`
pub const MAX_BURST_PULSES_PER_SUBSCRIBER: u64 = 200;

/// Maximum queue depth per subscriber.
/// Per RFC-0018: `max_queue_depth_per_subscriber: 256`
pub const MAX_QUEUE_DEPTH_PER_SUBSCRIBER: usize = 256;

/// Maximum bytes in-flight per subscriber.
/// Per RFC-0018: `max_bytes_in_flight_per_subscriber: 1048576` (1 MiB)
pub const MAX_BYTES_IN_FLIGHT_PER_SUBSCRIBER: usize = 1_048_576;

/// Maximum pulse payload size in bytes.
/// Per RFC-0018: `max_pulse_payload_bytes: 2048`
pub const MAX_PULSE_PAYLOAD_BYTES: usize = 2048;

// ============================================================================
// Error Types (CTR-0703: Structured Error Types)
// ============================================================================

/// Error type for resource governance violations.
///
/// Per CTR-0703, error types must be structured when callers branch on cause.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceError {
    /// Maximum subscriptions per connection exceeded.
    TooManySubscriptions {
        /// Current subscription count.
        current: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Maximum patterns per subscription exceeded.
    TooManyPatternsInSubscription {
        /// Requested pattern count.
        requested: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Maximum total patterns per connection exceeded.
    TooManyTotalPatterns {
        /// Current total pattern count.
        current: usize,
        /// Requested additional patterns.
        requested: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Rate limit exceeded.
    RateLimitExceeded {
        /// Current rate (pulses/sec).
        current_rate: u64,
        /// Maximum allowed rate.
        max_rate: u64,
    },

    /// Queue depth limit exceeded.
    QueueFull {
        /// Current queue depth.
        current: usize,
        /// Maximum allowed depth.
        max: usize,
    },

    /// Bytes in-flight limit exceeded.
    BytesInFlightExceeded {
        /// Current bytes in-flight.
        current: usize,
        /// Requested additional bytes.
        requested: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Pulse payload too large.
    PayloadTooLarge {
        /// Actual size in bytes.
        size: usize,
        /// Maximum allowed size.
        max: usize,
    },

    /// Subscription not found.
    SubscriptionNotFound {
        /// The subscription ID that was not found.
        subscription_id: String,
    },

    /// Connection not found.
    ConnectionNotFound {
        /// The connection ID that was not found.
        connection_id: String,
    },

    /// Maximum connections exceeded.
    TooManyConnections {
        /// Current connection count.
        current: usize,
        /// Maximum allowed.
        max: usize,
    },
}

impl std::fmt::Display for ResourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooManySubscriptions { current, max } => {
                write!(f, "subscription limit exceeded: {current} >= maximum {max}")
            },
            Self::TooManyPatternsInSubscription { requested, max } => {
                write!(
                    f,
                    "patterns per subscription limit exceeded: {requested} > maximum {max}"
                )
            },
            Self::TooManyTotalPatterns {
                current,
                requested,
                max,
            } => {
                write!(
                    f,
                    "total patterns limit exceeded: {current} + {requested} > maximum {max}"
                )
            },
            Self::RateLimitExceeded {
                current_rate,
                max_rate,
            } => {
                write!(
                    f,
                    "rate limit exceeded: {current_rate} pulses/sec > maximum {max_rate}"
                )
            },
            Self::QueueFull { current, max } => {
                write!(f, "queue full: {current} >= maximum {max}")
            },
            Self::BytesInFlightExceeded {
                current,
                requested,
                max,
            } => {
                write!(
                    f,
                    "bytes in-flight limit exceeded: {current} + {requested} > maximum {max}"
                )
            },
            Self::PayloadTooLarge { size, max } => {
                write!(f, "pulse payload too large: {size} bytes > maximum {max}")
            },
            Self::SubscriptionNotFound { subscription_id } => {
                write!(f, "subscription not found: {subscription_id}")
            },
            Self::ConnectionNotFound { connection_id } => {
                write!(f, "connection not found: {connection_id}")
            },
            Self::TooManyConnections { current, max } => {
                write!(f, "connection limit exceeded: {current} >= maximum {max}")
            },
        }
    }
}

impl std::error::Error for ResourceError {}

impl ResourceError {
    /// Returns the corresponding `HefErrorCode` for this error.
    #[must_use]
    #[allow(clippy::match_same_arms)]
    pub const fn to_hef_error_code(&self) -> HefErrorCode {
        match self {
            Self::TooManySubscriptions { .. }
            | Self::TooManyPatternsInSubscription { .. }
            | Self::TooManyTotalPatterns { .. }
            | Self::RateLimitExceeded { .. }
            | Self::QueueFull { .. }
            | Self::BytesInFlightExceeded { .. }
            | Self::PayloadTooLarge { .. }
            | Self::TooManyConnections { .. } => HefErrorCode::HefErrorResourceLimit,
            Self::SubscriptionNotFound { .. } => HefErrorCode::HefErrorSubscriptionNotFound,
            // ConnectionNotFound maps to ResourceLimit as it's a governance issue.
            // Kept as separate match arm for explicit documentation.
            Self::ConnectionNotFound { .. } => HefErrorCode::HefErrorResourceLimit,
        }
    }
}

// ============================================================================
// Resource Quota Configuration
// ============================================================================

/// Configuration for resource governance limits.
///
/// This struct encapsulates all configurable limits for resource governance.
/// Default values match RFC-0018 specifications.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceQuotaConfig {
    /// Maximum subscriptions per connection.
    pub max_subscriptions_per_connection: usize,
    /// Maximum patterns per subscription.
    pub max_patterns_per_subscription: usize,
    /// Maximum total patterns per connection.
    pub max_total_patterns_per_connection: usize,
    /// Maximum pulses per second per subscriber.
    pub max_pulses_per_sec: u64,
    /// Maximum burst pulses per subscriber.
    pub max_burst_pulses: u64,
    /// Maximum queue depth per subscriber.
    pub max_queue_depth: usize,
    /// Maximum bytes in-flight per subscriber.
    pub max_bytes_in_flight: usize,
    /// Maximum pulse payload size in bytes.
    pub max_pulse_payload_bytes: usize,
    /// Maximum total connections to the registry.
    /// Default: 100.
    pub max_connections: usize,
}

/// Default maximum connections to the registry.
pub const MAX_CONNECTIONS: usize = 100;

impl Default for ResourceQuotaConfig {
    fn default() -> Self {
        Self {
            max_subscriptions_per_connection: MAX_SUBSCRIPTIONS_PER_CONNECTION,
            max_patterns_per_subscription: MAX_PATTERNS_PER_SUBSCRIPTION,
            max_total_patterns_per_connection: MAX_TOTAL_PATTERNS_PER_CONNECTION,
            max_pulses_per_sec: MAX_PULSES_PER_SEC_PER_SUBSCRIBER,
            max_burst_pulses: MAX_BURST_PULSES_PER_SUBSCRIBER,
            max_queue_depth: MAX_QUEUE_DEPTH_PER_SUBSCRIBER,
            max_bytes_in_flight: MAX_BYTES_IN_FLIGHT_PER_SUBSCRIBER,
            max_pulse_payload_bytes: MAX_PULSE_PAYLOAD_BYTES,
            max_connections: MAX_CONNECTIONS,
        }
    }
}

impl ResourceQuotaConfig {
    /// Creates a configuration for testing with relaxed limits.
    #[must_use]
    pub const fn for_testing() -> Self {
        Self {
            max_subscriptions_per_connection: 4,
            max_patterns_per_subscription: 4,
            max_total_patterns_per_connection: 8,
            max_pulses_per_sec: 10,
            max_burst_pulses: 20,
            max_queue_depth: 16,
            max_bytes_in_flight: 16384,
            max_pulse_payload_bytes: 512,
            max_connections: 10,
        }
    }
}

// ============================================================================
// Drop Priority (DD-HEF-0005: Drop Policy)
// ============================================================================

/// Drop priority levels for pulse topics.
///
/// Lower values = higher drop priority (dropped first under backpressure).
/// Per DD-HEF-0005 drop policy order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum DropPriority {
    /// Unknown topic category - unclassified topics are dropped first.
    Unknown          = 0,
    /// `episode.<episode_id>.io` - Stream output, dropped early.
    EpisodeIo        = 1,
    /// `episode.<episode_id>.tool` - Tool events.
    EpisodeTool      = 2,
    /// `episode.<episode_id>.lifecycle` - Lifecycle events.
    EpisodeLifecycle = 3,
    /// `work.<work_id>.events` - Work events.
    WorkEvents       = 4,
    /// `gate.<work_id>.<changeset_digest>.<gate_id>` - Gate receipts.
    Gate             = 5,
    /// `ledger.head` - System ledger head, dropped last (most important).
    LedgerHead       = 6,
}

impl DropPriority {
    /// Determines the drop priority for a topic string.
    ///
    /// # Arguments
    ///
    /// * `topic` - The topic string to classify
    ///
    /// # Returns
    ///
    /// The drop priority for the topic.
    #[must_use]
    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    pub fn from_topic(topic: &str) -> Self {
        // Check topic prefixes in order.
        // Note: Case-sensitive comparison is intentional per RFC-0018 topic grammar
        // which requires ASCII lowercase topic names.
        if topic.starts_with("episode.") {
            // Check specific episode subtopics
            if topic.ends_with(".io") || topic.contains(".io.") {
                return Self::EpisodeIo;
            }
            if topic.ends_with(".tool") || topic.contains(".tool.") {
                return Self::EpisodeTool;
            }
            if topic.ends_with(".lifecycle") || topic.contains(".lifecycle.") {
                return Self::EpisodeLifecycle;
            }
            // Default episode topics to tool priority
            return Self::EpisodeTool;
        }
        if topic.starts_with("work.") {
            return Self::WorkEvents;
        }
        if topic.starts_with("gate.") {
            return Self::Gate;
        }
        if topic == "ledger.head" || topic.starts_with("ledger.") {
            return Self::LedgerHead;
        }
        if topic.starts_with("defect.") {
            // Defect topics are important, similar to gate
            return Self::Gate;
        }

        Self::Unknown
    }

    /// Returns the numeric priority value.
    ///
    /// Lower = dropped first under backpressure.
    #[must_use]
    pub const fn value(self) -> u8 {
        self as u8
    }
}

// ============================================================================
// Rate Limiter (Token Bucket)
// ============================================================================

/// Token bucket rate limiter for pulse delivery.
///
/// Implements a simple token bucket algorithm:
/// - Tokens are replenished at `rate` tokens per second
/// - Maximum tokens is `burst` capacity
/// - Each pulse consumes one token
/// - When tokens are exhausted, pulses are rate-limited
///
/// # Thread Safety
///
/// Uses a Mutex to protect both tokens and `last_refill` timestamp together,
/// ensuring atomic read-modify-write operations and preventing race conditions
/// between concurrent refill and `try_acquire` operations.
#[derive(Debug)]
pub struct RateLimiter {
    /// Protected state: (tokens scaled by 1000, last refill timestamp).
    /// Using Mutex ensures atomic updates to both fields together.
    state: std::sync::Mutex<RateLimiterState>,
    /// Tokens per second (rate).
    rate: u64,
    /// Maximum tokens (burst capacity).
    burst: u64,
}

/// Internal state for the rate limiter, protected by Mutex.
#[derive(Debug)]
struct RateLimiterState {
    /// Current token count (scaled by 1000 for sub-token precision).
    tokens: u64,
    /// Last refill timestamp.
    last_refill: Instant,
}

impl RateLimiter {
    /// Creates a new rate limiter with the given rate and burst capacity.
    ///
    /// # Arguments
    ///
    /// * `rate` - Tokens per second
    /// * `burst` - Maximum token capacity
    #[must_use]
    pub fn new(rate: u64, burst: u64) -> Self {
        Self {
            state: std::sync::Mutex::new(RateLimiterState {
                // Start with full burst capacity (scaled by 1000)
                tokens: burst * 1000,
                last_refill: Instant::now(),
            }),
            rate,
            burst,
        }
    }

    /// Creates a rate limiter from configuration.
    #[must_use]
    pub fn from_config(config: &ResourceQuotaConfig) -> Self {
        Self::new(config.max_pulses_per_sec, config.max_burst_pulses)
    }

    /// Attempts to acquire a token for sending a pulse.
    ///
    /// This method atomically refills tokens based on elapsed time and then
    /// attempts to consume one token. The Mutex ensures no race conditions
    /// between concurrent refill and acquire operations.
    ///
    /// # Returns
    ///
    /// `Ok(())` if a token was acquired,
    /// `Err(ResourceError::RateLimitExceeded)` if rate limit is exceeded.
    #[allow(clippy::cast_possible_truncation)]
    pub fn try_acquire(&self) -> Result<(), ResourceError> {
        let mut state = self.state.lock().expect("lock poisoned");

        // Refill tokens based on elapsed time (done atomically with acquire)
        let now = Instant::now();
        let elapsed = now.duration_since(state.last_refill);
        // Truncation is intentional: milliseconds since last refill will never
        // exceed u64::MAX in practice (would require ~584 million years).
        let elapsed_ms = elapsed.as_millis() as u64;

        if elapsed_ms > 0 {
            // Calculate tokens to add (rate is per second, elapsed_ms is in
            // milliseconds). The formula: tokens = (elapsed_ms / 1000) * rate
            // Rearranged to avoid float: tokens = elapsed_ms * rate / 1000
            // But we store scaled tokens (by 1000), so we just use:
            // scaled_tokens_to_add = elapsed_ms * rate
            let tokens_to_add = elapsed_ms * self.rate;
            let max_tokens = self.burst * 1000;
            state.tokens = (state.tokens + tokens_to_add).min(max_tokens);
            state.last_refill = now;
        }

        // Try to consume one token (1000 scaled units)
        if state.tokens < 1000 {
            return Err(ResourceError::RateLimitExceeded {
                current_rate: self.rate,
                max_rate: self.rate,
            });
        }

        state.tokens -= 1000;
        Ok(())
    }

    /// Returns the current token count (for testing/monitoring).
    ///
    /// This also performs a refill based on elapsed time.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn available_tokens(&self) -> u64 {
        let mut state = self.state.lock().expect("lock poisoned");

        // Refill tokens based on elapsed time
        let now = Instant::now();
        let elapsed = now.duration_since(state.last_refill);
        let elapsed_ms = elapsed.as_millis() as u64;

        if elapsed_ms > 0 {
            // Same formula as try_acquire: scaled_tokens_to_add = elapsed_ms * rate
            let tokens_to_add = elapsed_ms * self.rate;
            let max_tokens = self.burst * 1000;
            state.tokens = (state.tokens + tokens_to_add).min(max_tokens);
            state.last_refill = now;
        }

        state.tokens / 1000
    }
}

// ============================================================================
// Subscription State
// ============================================================================

/// State for a single subscription.
#[derive(Debug)]
pub struct SubscriptionState {
    /// Subscription ID.
    pub subscription_id: String,
    /// Client subscription ID (optional, for client correlation).
    pub client_sub_id: String,
    /// Patterns associated with this subscription.
    pub patterns: Vec<TopicPattern>,
    /// Ledger cursor for resume semantics.
    pub since_cursor: u64,
}

impl SubscriptionState {
    /// Creates a new subscription state.
    #[must_use]
    pub fn new(
        subscription_id: impl Into<String>,
        client_sub_id: impl Into<String>,
        patterns: Vec<TopicPattern>,
        since_cursor: u64,
    ) -> Self {
        Self {
            subscription_id: subscription_id.into(),
            client_sub_id: client_sub_id.into(),
            patterns,
            since_cursor,
        }
    }

    /// Returns the number of patterns in this subscription.
    #[must_use]
    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }
}

// ============================================================================
// Connection State
// ============================================================================

/// Resource governance state for a single connection.
#[derive(Debug)]
pub struct ConnectionState {
    /// Connection ID.
    pub connection_id: String,
    /// Session ID (for session connections).
    pub session_id: Option<String>,
    /// Active subscriptions keyed by subscription ID.
    subscriptions: HashMap<String, SubscriptionState>,
    /// Rate limiter for this connection.
    rate_limiter: RateLimiter,
    /// Current queue depth.
    queue_depth: AtomicUsize,
    /// Current bytes in-flight.
    bytes_in_flight: AtomicUsize,
    /// Configuration for quota limits.
    config: ResourceQuotaConfig,
}

impl ConnectionState {
    /// Creates a new connection state.
    #[must_use]
    pub fn new(connection_id: impl Into<String>, config: ResourceQuotaConfig) -> Self {
        Self {
            connection_id: connection_id.into(),
            session_id: None,
            subscriptions: HashMap::new(),
            rate_limiter: RateLimiter::from_config(&config),
            queue_depth: AtomicUsize::new(0),
            bytes_in_flight: AtomicUsize::new(0),
            config,
        }
    }

    /// Sets the session ID for this connection.
    pub fn set_session_id(&mut self, session_id: impl Into<String>) {
        self.session_id = Some(session_id.into());
    }

    /// Returns the number of active subscriptions.
    #[must_use]
    pub fn subscription_count(&self) -> usize {
        self.subscriptions.len()
    }

    /// Returns the total number of patterns across all subscriptions.
    #[must_use]
    pub fn total_pattern_count(&self) -> usize {
        self.subscriptions
            .values()
            .map(SubscriptionState::pattern_count)
            .sum()
    }

    /// Checks if adding a subscription with the given patterns would exceed
    /// limits.
    ///
    /// # Arguments
    ///
    /// * `pattern_count` - Number of patterns in the new subscription
    ///
    /// # Errors
    ///
    /// Returns `ResourceError` if limits would be exceeded.
    pub fn check_subscription_limits(&self, pattern_count: usize) -> Result<(), ResourceError> {
        // Check subscription count
        if self.subscription_count() >= self.config.max_subscriptions_per_connection {
            return Err(ResourceError::TooManySubscriptions {
                current: self.subscription_count(),
                max: self.config.max_subscriptions_per_connection,
            });
        }

        // Check patterns per subscription
        if pattern_count > self.config.max_patterns_per_subscription {
            return Err(ResourceError::TooManyPatternsInSubscription {
                requested: pattern_count,
                max: self.config.max_patterns_per_subscription,
            });
        }

        // Check total patterns
        let current_total = self.total_pattern_count();
        if current_total + pattern_count > self.config.max_total_patterns_per_connection {
            return Err(ResourceError::TooManyTotalPatterns {
                current: current_total,
                requested: pattern_count,
                max: self.config.max_total_patterns_per_connection,
            });
        }

        Ok(())
    }

    /// Adds a subscription to this connection.
    ///
    /// # Arguments
    ///
    /// * `subscription` - The subscription state to add
    ///
    /// # Errors
    ///
    /// Returns `ResourceError` if limits would be exceeded.
    pub fn add_subscription(
        &mut self,
        subscription: SubscriptionState,
    ) -> Result<(), ResourceError> {
        self.check_subscription_limits(subscription.pattern_count())?;
        self.subscriptions
            .insert(subscription.subscription_id.clone(), subscription);
        Ok(())
    }

    /// Removes a subscription by ID.
    ///
    /// # Returns
    ///
    /// The removed subscription state, or `None` if not found.
    pub fn remove_subscription(&mut self, subscription_id: &str) -> Option<SubscriptionState> {
        self.subscriptions.remove(subscription_id)
    }

    /// Gets a subscription by ID.
    #[must_use]
    pub fn get_subscription(&self, subscription_id: &str) -> Option<&SubscriptionState> {
        self.subscriptions.get(subscription_id)
    }

    /// Returns an iterator over all subscriptions.
    pub fn subscriptions(&self) -> impl Iterator<Item = &SubscriptionState> {
        self.subscriptions.values()
    }

    /// Atomically checks all delivery limits and reserves queue slot if
    /// allowed.
    ///
    /// This method combines check and reservation into a single atomic
    /// operation to prevent TOCTOU vulnerabilities. It also ensures rate
    /// limit tokens are only consumed after all other checks pass to
    /// prevent token leaks.
    ///
    /// # Arguments
    ///
    /// * `payload_size` - Size of the pulse payload in bytes
    ///
    /// # Errors
    ///
    /// Returns `ResourceError` if any limit would be exceeded.
    ///
    /// # Thread Safety
    ///
    /// Uses CAS loops to atomically reserve queue depth and bytes in-flight,
    /// preventing race conditions where multiple threads could pass the check
    /// simultaneously before any increment occurs.
    ///
    /// # TCK-00304: Wiring Note
    ///
    /// This method is called by the pulse publisher (TCK-00304) when delivering
    /// pulses to subscribers. It enforces rate limits, queue depth, and bytes
    /// in-flight limits per subscriber. Currently implemented but wiring into
    /// the pulse delivery path is out of scope for TCK-00303 (registry only)
    /// and will be completed in TCK-00304 (outbox + pulse publisher).
    pub fn try_reserve_enqueue(&self, payload_size: usize) -> Result<(), ResourceError> {
        // Check payload size first (stateless check, no reservation needed)
        if payload_size > self.config.max_pulse_payload_bytes {
            return Err(ResourceError::PayloadTooLarge {
                size: payload_size,
                max: self.config.max_pulse_payload_bytes,
            });
        }

        // Atomically reserve queue depth slot using CAS loop
        loop {
            let current_depth = self.queue_depth.load(Ordering::Acquire);
            if current_depth >= self.config.max_queue_depth {
                return Err(ResourceError::QueueFull {
                    current: current_depth,
                    max: self.config.max_queue_depth,
                });
            }

            if self
                .queue_depth
                .compare_exchange_weak(
                    current_depth,
                    current_depth + 1,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                break;
            }
            // CAS failed, retry
        }

        // Atomically reserve bytes in-flight using CAS loop
        loop {
            let current_bytes = self.bytes_in_flight.load(Ordering::Acquire);
            if current_bytes + payload_size > self.config.max_bytes_in_flight {
                // Rollback queue depth reservation
                self.queue_depth.fetch_sub(1, Ordering::Release);
                return Err(ResourceError::BytesInFlightExceeded {
                    current: current_bytes,
                    requested: payload_size,
                    max: self.config.max_bytes_in_flight,
                });
            }

            if self
                .bytes_in_flight
                .compare_exchange_weak(
                    current_bytes,
                    current_bytes + payload_size,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                break;
            }
            // CAS failed, retry
        }

        // Only consume rate limit token AFTER all other checks pass and
        // reservations are made. This prevents token leak on queue rejection.
        if let Err(e) = self.rate_limiter.try_acquire() {
            // Rollback reservations on rate limit failure
            self.queue_depth.fetch_sub(1, Ordering::Release);
            self.bytes_in_flight
                .fetch_sub(payload_size, Ordering::Release);
            return Err(e);
        }

        Ok(())
    }

    /// Checks delivery limits without reserving (for read-only validation).
    ///
    /// NOTE: This is a TOCTOU-prone check. For actual enqueue operations,
    /// use `try_reserve_enqueue` which atomically checks AND reserves.
    /// This method is only for pre-validation or monitoring purposes.
    ///
    /// # Arguments
    ///
    /// * `payload_size` - Size of the pulse payload in bytes
    ///
    /// # Errors
    ///
    /// Returns `ResourceError` if any limit would be exceeded.
    #[allow(dead_code)]
    pub fn check_delivery_limits(&self, payload_size: usize) -> Result<(), ResourceError> {
        // Check payload size
        if payload_size > self.config.max_pulse_payload_bytes {
            return Err(ResourceError::PayloadTooLarge {
                size: payload_size,
                max: self.config.max_pulse_payload_bytes,
            });
        }

        // Check queue depth (non-reserving check)
        let current_depth = self.queue_depth.load(Ordering::Acquire);
        if current_depth >= self.config.max_queue_depth {
            return Err(ResourceError::QueueFull {
                current: current_depth,
                max: self.config.max_queue_depth,
            });
        }

        // Check bytes in-flight (non-reserving check)
        let current_bytes = self.bytes_in_flight.load(Ordering::Acquire);
        if current_bytes + payload_size > self.config.max_bytes_in_flight {
            return Err(ResourceError::BytesInFlightExceeded {
                current: current_bytes,
                requested: payload_size,
                max: self.config.max_bytes_in_flight,
            });
        }

        Ok(())
    }

    /// Records that a pulse was enqueued (for use after `try_reserve_enqueue`).
    ///
    /// NOTE: This method is now a no-op since `try_reserve_enqueue` atomically
    /// reserves the slot. It is kept for API compatibility but callers should
    /// use `try_reserve_enqueue` directly.
    #[deprecated(
        since = "0.1.0",
        note = "Use try_reserve_enqueue which atomically reserves. This is now a no-op."
    )]
    #[allow(clippy::missing_const_for_fn)]
    pub fn record_enqueue(&self, _payload_size: usize) {
        // No-op: try_reserve_enqueue already performed the reservation
        // atomically. This method is kept for backwards compatibility
        // during migration.
    }

    /// Records that a pulse was delivered/dequeued.
    ///
    /// # Arguments
    ///
    /// * `payload_size` - Size of the pulse payload in bytes
    pub fn record_dequeue(&self, payload_size: usize) {
        // Use Release ordering to ensure the dequeue is visible to other threads
        // that may be checking available capacity with Acquire ordering.
        self.queue_depth.fetch_sub(1, Ordering::Release);
        self.bytes_in_flight
            .fetch_sub(payload_size, Ordering::Release);
    }

    /// Returns current queue depth.
    #[must_use]
    pub fn queue_depth(&self) -> usize {
        self.queue_depth.load(Ordering::Relaxed)
    }

    /// Returns current bytes in-flight.
    #[must_use]
    pub fn bytes_in_flight(&self) -> usize {
        self.bytes_in_flight.load(Ordering::Relaxed)
    }
}

// ============================================================================
// Subscription Registry
// ============================================================================

/// Registry tracking all subscriptions across connections.
///
/// This is the central registry for managing HEF subscriptions with resource
/// governance. It tracks per-connection state and enforces global limits.
///
/// # Thread Safety
///
/// Uses `RwLock` for concurrent access to connection state.
#[derive(Debug)]
pub struct SubscriptionRegistry {
    /// Per-connection state keyed by connection ID.
    connections: RwLock<HashMap<String, ConnectionState>>,
    /// Default quota configuration.
    config: ResourceQuotaConfig,
}

impl SubscriptionRegistry {
    /// Creates a new subscription registry.
    #[must_use]
    pub fn new(config: ResourceQuotaConfig) -> Self {
        Self {
            connections: RwLock::new(HashMap::new()),
            config,
        }
    }

    /// Creates a registry with default configuration.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(ResourceQuotaConfig::default())
    }

    /// Registers a new connection.
    ///
    /// # Arguments
    ///
    /// * `connection_id` - Unique identifier for the connection
    ///
    /// # Errors
    ///
    /// Returns `ResourceError::TooManyConnections` if the global connection
    /// limit would be exceeded.
    pub fn register_connection(
        &self,
        connection_id: impl Into<String>,
    ) -> Result<(), ResourceError> {
        let connection_id = connection_id.into();
        let mut connections = self.connections.write().expect("lock poisoned");

        // Check if already exists - idempotent success
        if connections.contains_key(&connection_id) {
            return Ok(());
        }

        // Check global connection limit
        if connections.len() >= self.config.max_connections {
            return Err(ResourceError::TooManyConnections {
                current: connections.len(),
                max: self.config.max_connections,
            });
        }

        connections.insert(
            connection_id.clone(),
            ConnectionState::new(connection_id, self.config),
        );
        Ok(())
    }

    /// Sets the session ID for a connection.
    ///
    /// # Arguments
    ///
    /// * `connection_id` - Connection identifier
    /// * `session_id` - Session identifier
    ///
    /// # Errors
    ///
    /// Returns `ResourceError::ConnectionNotFound` if the connection doesn't
    /// exist.
    pub fn set_session_id(
        &self,
        connection_id: &str,
        session_id: impl Into<String>,
    ) -> Result<(), ResourceError> {
        let mut connections = self.connections.write().expect("lock poisoned");
        let conn = connections.get_mut(connection_id).ok_or_else(|| {
            ResourceError::ConnectionNotFound {
                connection_id: connection_id.to_string(),
            }
        })?;
        conn.set_session_id(session_id);
        Ok(())
    }

    /// Unregisters a connection and all its subscriptions.
    ///
    /// # Arguments
    ///
    /// * `connection_id` - Connection identifier
    pub fn unregister_connection(&self, connection_id: &str) {
        let mut connections = self.connections.write().expect("lock poisoned");
        connections.remove(connection_id);
    }

    /// Adds a subscription for a connection.
    ///
    /// # Arguments
    ///
    /// * `connection_id` - Connection identifier
    /// * `subscription` - Subscription state to add
    ///
    /// # Errors
    ///
    /// Returns `ResourceError` if limits would be exceeded or connection not
    /// found.
    pub fn add_subscription(
        &self,
        connection_id: &str,
        subscription: SubscriptionState,
    ) -> Result<(), ResourceError> {
        let mut connections = self.connections.write().expect("lock poisoned");
        let conn = connections.get_mut(connection_id).ok_or_else(|| {
            ResourceError::ConnectionNotFound {
                connection_id: connection_id.to_string(),
            }
        })?;
        conn.add_subscription(subscription)
    }

    /// Removes a subscription.
    ///
    /// # Arguments
    ///
    /// * `connection_id` - Connection identifier
    /// * `subscription_id` - Subscription identifier
    ///
    /// # Errors
    ///
    /// Returns `ResourceError::SubscriptionNotFound` if the subscription
    /// doesn't exist.
    pub fn remove_subscription(
        &self,
        connection_id: &str,
        subscription_id: &str,
    ) -> Result<SubscriptionState, ResourceError> {
        let mut connections = self.connections.write().expect("lock poisoned");
        let conn = connections.get_mut(connection_id).ok_or_else(|| {
            ResourceError::ConnectionNotFound {
                connection_id: connection_id.to_string(),
            }
        })?;
        conn.remove_subscription(subscription_id).ok_or_else(|| {
            ResourceError::SubscriptionNotFound {
                subscription_id: subscription_id.to_string(),
            }
        })
    }

    /// Checks if a subscription can be added without exceeding limits.
    ///
    /// # Arguments
    ///
    /// * `connection_id` - Connection identifier
    /// * `pattern_count` - Number of patterns in the proposed subscription
    ///
    /// # Errors
    ///
    /// Returns `ResourceError` if limits would be exceeded.
    pub fn check_subscription_limits(
        &self,
        connection_id: &str,
        pattern_count: usize,
    ) -> Result<(), ResourceError> {
        let connections = self.connections.read().expect("lock poisoned");
        let conn =
            connections
                .get(connection_id)
                .ok_or_else(|| ResourceError::ConnectionNotFound {
                    connection_id: connection_id.to_string(),
                })?;
        conn.check_subscription_limits(pattern_count)
    }

    /// Atomically checks delivery limits and reserves queue slot for a pulse.
    ///
    /// This method combines check and reservation into a single atomic
    /// operation to prevent TOCTOU vulnerabilities. Rate limit tokens are
    /// only consumed after all other checks pass to prevent token leaks.
    ///
    /// # Arguments
    ///
    /// * `connection_id` - Connection identifier
    /// * `payload_size` - Size of the pulse payload
    ///
    /// # Errors
    ///
    /// Returns `ResourceError` if limits would be exceeded.
    pub fn try_reserve_enqueue(
        &self,
        connection_id: &str,
        payload_size: usize,
    ) -> Result<(), ResourceError> {
        let connections = self.connections.read().expect("lock poisoned");
        let conn =
            connections
                .get(connection_id)
                .ok_or_else(|| ResourceError::ConnectionNotFound {
                    connection_id: connection_id.to_string(),
                })?;
        conn.try_reserve_enqueue(payload_size)
    }

    /// Checks delivery limits for a pulse (non-reserving).
    ///
    /// NOTE: This is a TOCTOU-prone check. For actual enqueue operations,
    /// use `try_reserve_enqueue` which atomically checks AND reserves.
    /// This method is only for pre-validation or monitoring purposes.
    ///
    /// # Arguments
    ///
    /// * `connection_id` - Connection identifier
    /// * `payload_size` - Size of the pulse payload
    ///
    /// # Errors
    ///
    /// Returns `ResourceError` if limits would be exceeded.
    #[allow(dead_code)]
    pub fn check_delivery_limits(
        &self,
        connection_id: &str,
        payload_size: usize,
    ) -> Result<(), ResourceError> {
        let connections = self.connections.read().expect("lock poisoned");
        let conn =
            connections
                .get(connection_id)
                .ok_or_else(|| ResourceError::ConnectionNotFound {
                    connection_id: connection_id.to_string(),
                })?;
        conn.check_delivery_limits(payload_size)
    }

    /// Records that a pulse was enqueued for a connection.
    ///
    /// NOTE: This method is now a no-op since `try_reserve_enqueue` atomically
    /// reserves the slot. It is kept for API compatibility but callers should
    /// use `try_reserve_enqueue` directly.
    #[deprecated(
        since = "0.1.0",
        note = "Use try_reserve_enqueue which atomically reserves. This is now a no-op."
    )]
    #[allow(clippy::missing_const_for_fn)]
    pub fn record_enqueue(&self, _connection_id: &str, _payload_size: usize) {
        // No-op: try_reserve_enqueue already performed the reservation
        // atomically. This method is kept for backwards compatibility
        // during migration.
    }

    /// Records that a pulse was delivered for a connection.
    ///
    /// # Arguments
    ///
    /// * `connection_id` - Connection identifier
    /// * `payload_size` - Size of the pulse payload
    pub fn record_dequeue(&self, connection_id: &str, payload_size: usize) {
        let connections = self.connections.read().expect("lock poisoned");
        if let Some(conn) = connections.get(connection_id) {
            conn.record_dequeue(payload_size);
        }
    }

    /// Returns statistics for a connection.
    #[must_use]
    pub fn connection_stats(&self, connection_id: &str) -> Option<ConnectionStats> {
        let connections = self.connections.read().expect("lock poisoned");
        connections.get(connection_id).map(|conn| ConnectionStats {
            subscription_count: conn.subscription_count(),
            total_pattern_count: conn.total_pattern_count(),
            queue_depth: conn.queue_depth(),
            bytes_in_flight: conn.bytes_in_flight(),
        })
    }

    /// Returns the number of registered connections.
    #[must_use]
    pub fn connection_count(&self) -> usize {
        self.connections.read().expect("lock poisoned").len()
    }

    /// Finds all subscriptions that match a topic.
    ///
    /// Returns a list of `(connection_id, subscription_id)` pairs.
    ///
    /// # Performance
    ///
    /// This method pre-splits the topic string once and reuses the segments
    /// across all pattern matches, avoiding O(N*M) string splitting overhead
    /// where N is the number of patterns and M is the topic segment count.
    #[must_use]
    pub fn find_matching_subscriptions(&self, topic: &str) -> Vec<(String, String)> {
        // Quick ASCII check (invalid topics never match any pattern)
        if !topic.is_ascii() {
            return Vec::new();
        }

        // Pre-split the topic once to avoid O(N*M) splitting overhead
        let topic_segments: Vec<&str> = topic.split('.').collect();

        let connections = self.connections.read().expect("lock poisoned");
        let mut matches = Vec::new();

        for (conn_id, conn) in connections.iter() {
            for sub in conn.subscriptions() {
                for pattern in &sub.patterns {
                    if pattern.matches_segments(&topic_segments) {
                        matches.push((conn_id.clone(), sub.subscription_id.clone()));
                        break; // Don't add same subscription twice
                    }
                }
            }
        }

        matches
    }
}

impl Default for SubscriptionRegistry {
    fn default() -> Self {
        Self::with_defaults()
    }
}

// ============================================================================
// Connection Statistics
// ============================================================================

/// Statistics for a connection's resource usage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionStats {
    /// Number of active subscriptions.
    pub subscription_count: usize,
    /// Total number of patterns across all subscriptions.
    pub total_pattern_count: usize,
    /// Current queue depth.
    pub queue_depth: usize,
    /// Current bytes in-flight.
    pub bytes_in_flight: usize,
}

// ============================================================================
// Queued Pulse Entry
// ============================================================================

/// A pulse entry in the delivery queue.
#[derive(Debug)]
pub struct QueuedPulse {
    /// Topic this pulse was published to.
    pub topic: String,
    /// Encoded pulse envelope.
    pub payload: Vec<u8>,
    /// Drop priority for backpressure.
    pub priority: DropPriority,
    /// Timestamp when enqueued.
    pub enqueued_at: Instant,
}

impl QueuedPulse {
    /// Creates a new queued pulse.
    #[must_use]
    pub fn new(topic: impl Into<String>, payload: Vec<u8>) -> Self {
        let topic = topic.into();
        let priority = DropPriority::from_topic(&topic);
        Self {
            topic,
            payload,
            priority,
            enqueued_at: Instant::now(),
        }
    }

    /// Returns the payload size in bytes.
    #[must_use]
    pub fn payload_size(&self) -> usize {
        self.payload.len()
    }
}

// ============================================================================
// Thread-Safe Shared Types
// ============================================================================

/// Thread-safe shared subscription registry.
pub type SharedSubscriptionRegistry = Arc<SubscriptionRegistry>;

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Drop Priority Tests
    // ========================================================================

    mod drop_priority {
        use super::*;

        #[test]
        fn unknown_has_highest_drop_priority() {
            assert_eq!(
                DropPriority::from_topic("unknown.topic"),
                DropPriority::Unknown
            );
            // Unknown topics are dropped first (value = 0)
            assert_eq!(DropPriority::Unknown.value(), 0);
        }

        #[test]
        fn episode_io_has_high_drop_priority() {
            assert_eq!(
                DropPriority::from_topic("episode.EP-001.io"),
                DropPriority::EpisodeIo
            );
            assert_eq!(DropPriority::EpisodeIo.value(), 1);
        }

        #[test]
        fn episode_tool_priority() {
            assert_eq!(
                DropPriority::from_topic("episode.EP-001.tool"),
                DropPriority::EpisodeTool
            );
        }

        #[test]
        fn episode_lifecycle_priority() {
            assert_eq!(
                DropPriority::from_topic("episode.EP-001.lifecycle"),
                DropPriority::EpisodeLifecycle
            );
        }

        #[test]
        fn work_events_priority() {
            assert_eq!(
                DropPriority::from_topic("work.W-123.events"),
                DropPriority::WorkEvents
            );
        }

        #[test]
        fn gate_priority() {
            assert_eq!(
                DropPriority::from_topic("gate.W-123.CS-abc.G-001"),
                DropPriority::Gate
            );
        }

        #[test]
        fn ledger_head_has_lowest_drop_priority() {
            assert_eq!(
                DropPriority::from_topic("ledger.head"),
                DropPriority::LedgerHead
            );
            // LedgerHead should be higher than all others (dropped last)
            assert!(DropPriority::LedgerHead > DropPriority::EpisodeIo);
            assert!(DropPriority::LedgerHead > DropPriority::Gate);
        }

        #[test]
        fn drop_order_is_correct() {
            // Verify ordering: Unknown < EpisodeIo < EpisodeTool < EpisodeLifecycle <
            // WorkEvents < Gate < LedgerHead
            assert!(DropPriority::Unknown < DropPriority::EpisodeIo);
            assert!(DropPriority::EpisodeIo < DropPriority::EpisodeTool);
            assert!(DropPriority::EpisodeTool < DropPriority::EpisodeLifecycle);
            assert!(DropPriority::EpisodeLifecycle < DropPriority::WorkEvents);
            assert!(DropPriority::WorkEvents < DropPriority::Gate);
            assert!(DropPriority::Gate < DropPriority::LedgerHead);
        }

        #[test]
        fn unknown_topic_dropped_first() {
            assert_eq!(
                DropPriority::from_topic("unknown.topic"),
                DropPriority::Unknown
            );
            // Unknown has lowest priority value (dropped first under backpressure)
            assert!(DropPriority::Unknown < DropPriority::EpisodeIo);
            assert!(DropPriority::Unknown < DropPriority::LedgerHead);
        }
    }

    // ========================================================================
    // Rate Limiter Tests
    // ========================================================================

    mod rate_limiter {
        use super::*;

        #[test]
        fn new_limiter_has_burst_capacity() {
            let limiter = RateLimiter::new(100, 200);
            assert_eq!(limiter.available_tokens(), 200);
        }

        #[test]
        fn acquire_consumes_token() {
            let limiter = RateLimiter::new(100, 10);
            assert!(limiter.try_acquire().is_ok());
            assert_eq!(limiter.available_tokens(), 9);
        }

        #[test]
        fn exhausted_limiter_returns_error() {
            let limiter = RateLimiter::new(100, 1);
            assert!(limiter.try_acquire().is_ok());
            let result = limiter.try_acquire();
            assert!(matches!(
                result,
                Err(ResourceError::RateLimitExceeded { .. })
            ));
        }

        #[test]
        fn from_config_uses_config_values() {
            let config = ResourceQuotaConfig {
                max_pulses_per_sec: 50,
                max_burst_pulses: 75,
                ..ResourceQuotaConfig::default()
            };
            let limiter = RateLimiter::from_config(&config);
            assert_eq!(limiter.available_tokens(), 75);
        }
    }

    // ========================================================================
    // Connection State Tests
    // ========================================================================

    mod connection_state {
        use super::*;

        fn test_pattern(s: &str) -> TopicPattern {
            TopicPattern::parse(s).expect("valid pattern")
        }

        #[test]
        fn new_connection_is_empty() {
            let conn = ConnectionState::new("conn-1", ResourceQuotaConfig::for_testing());
            assert_eq!(conn.subscription_count(), 0);
            assert_eq!(conn.total_pattern_count(), 0);
        }

        #[test]
        fn add_subscription_success() {
            let mut conn = ConnectionState::new("conn-1", ResourceQuotaConfig::for_testing());
            let sub = SubscriptionState::new(
                "sub-1",
                "client-sub-1",
                vec![test_pattern("work.*.events")],
                0,
            );
            assert!(conn.add_subscription(sub).is_ok());
            assert_eq!(conn.subscription_count(), 1);
            assert_eq!(conn.total_pattern_count(), 1);
        }

        #[test]
        fn add_subscription_exceeds_limit() {
            let config = ResourceQuotaConfig {
                max_subscriptions_per_connection: 1,
                ..ResourceQuotaConfig::for_testing()
            };
            let mut conn = ConnectionState::new("conn-1", config);

            // First subscription should succeed
            let sub1 = SubscriptionState::new("sub-1", "", vec![test_pattern("work.*.events")], 0);
            assert!(conn.add_subscription(sub1).is_ok());

            // Second should fail
            let sub2 = SubscriptionState::new("sub-2", "", vec![test_pattern("ledger.head")], 0);
            let result = conn.add_subscription(sub2);
            assert!(matches!(
                result,
                Err(ResourceError::TooManySubscriptions { .. })
            ));
        }

        #[test]
        fn add_subscription_too_many_patterns() {
            let config = ResourceQuotaConfig {
                max_patterns_per_subscription: 2,
                ..ResourceQuotaConfig::for_testing()
            };
            let mut conn = ConnectionState::new("conn-1", config);

            let sub = SubscriptionState::new(
                "sub-1",
                "",
                vec![
                    test_pattern("work.*.events"),
                    test_pattern("ledger.head"),
                    test_pattern("defect.new"), // Third pattern exceeds limit
                ],
                0,
            );
            let result = conn.add_subscription(sub);
            assert!(matches!(
                result,
                Err(ResourceError::TooManyPatternsInSubscription { .. })
            ));
        }

        #[test]
        fn add_subscription_exceeds_total_patterns() {
            let config = ResourceQuotaConfig {
                max_subscriptions_per_connection: 10,
                max_patterns_per_subscription: 10,
                max_total_patterns_per_connection: 3,
                ..ResourceQuotaConfig::for_testing()
            };
            let mut conn = ConnectionState::new("conn-1", config);

            // Add first subscription with 2 patterns
            let sub1 = SubscriptionState::new(
                "sub-1",
                "",
                vec![test_pattern("work.*.events"), test_pattern("ledger.head")],
                0,
            );
            assert!(conn.add_subscription(sub1).is_ok());

            // Try to add second with 2 more patterns (would total 4, exceeds 3)
            let sub2 = SubscriptionState::new(
                "sub-2",
                "",
                vec![test_pattern("defect.new"), test_pattern("gate.*.*.G-001")],
                0,
            );
            let result = conn.add_subscription(sub2);
            assert!(matches!(
                result,
                Err(ResourceError::TooManyTotalPatterns { .. })
            ));
        }

        #[test]
        fn remove_subscription_success() {
            let mut conn = ConnectionState::new("conn-1", ResourceQuotaConfig::for_testing());
            let sub = SubscriptionState::new("sub-1", "", vec![test_pattern("work.*.events")], 0);
            conn.add_subscription(sub).unwrap();

            let removed = conn.remove_subscription("sub-1");
            assert!(removed.is_some());
            assert_eq!(conn.subscription_count(), 0);
        }

        #[test]
        fn payload_size_limit() {
            let config = ResourceQuotaConfig {
                max_pulse_payload_bytes: 100,
                ..ResourceQuotaConfig::for_testing()
            };
            let conn = ConnectionState::new("conn-1", config);

            // Small payload should pass
            assert!(conn.check_delivery_limits(50).is_ok());

            // Large payload should fail
            let result = conn.check_delivery_limits(150);
            assert!(matches!(result, Err(ResourceError::PayloadTooLarge { .. })));
        }

        #[test]
        fn queue_and_bytes_tracking() {
            let conn = ConnectionState::new("conn-1", ResourceQuotaConfig::for_testing());

            // Use try_reserve_enqueue which atomically reserves
            conn.try_reserve_enqueue(100).unwrap();
            assert_eq!(conn.queue_depth(), 1);
            assert_eq!(conn.bytes_in_flight(), 100);

            conn.try_reserve_enqueue(200).unwrap();
            assert_eq!(conn.queue_depth(), 2);
            assert_eq!(conn.bytes_in_flight(), 300);

            conn.record_dequeue(100);
            assert_eq!(conn.queue_depth(), 1);
            assert_eq!(conn.bytes_in_flight(), 200);
        }

        #[test]
        fn try_reserve_enqueue_enforces_queue_limit() {
            let config = ResourceQuotaConfig {
                max_queue_depth: 2,
                max_bytes_in_flight: 10000,
                max_burst_pulses: 100,
                ..ResourceQuotaConfig::for_testing()
            };
            let conn = ConnectionState::new("conn-1", config);

            // First two should succeed
            assert!(conn.try_reserve_enqueue(50).is_ok());
            assert!(conn.try_reserve_enqueue(50).is_ok());
            assert_eq!(conn.queue_depth(), 2);

            // Third should fail with QueueFull
            let result = conn.try_reserve_enqueue(50);
            assert!(matches!(result, Err(ResourceError::QueueFull { .. })));
            // Queue depth should still be 2 (no reservation made)
            assert_eq!(conn.queue_depth(), 2);
        }

        #[test]
        fn try_reserve_enqueue_enforces_bytes_limit() {
            let config = ResourceQuotaConfig {
                max_queue_depth: 100,
                max_bytes_in_flight: 150,
                max_burst_pulses: 100,
                ..ResourceQuotaConfig::for_testing()
            };
            let conn = ConnectionState::new("conn-1", config);

            // First should succeed
            assert!(conn.try_reserve_enqueue(100).is_ok());
            assert_eq!(conn.bytes_in_flight(), 100);

            // Second should fail (100 + 100 > 150)
            let result = conn.try_reserve_enqueue(100);
            assert!(matches!(
                result,
                Err(ResourceError::BytesInFlightExceeded { .. })
            ));
            // Queue depth should be rolled back
            assert_eq!(conn.queue_depth(), 1);
            assert_eq!(conn.bytes_in_flight(), 100);
        }

        #[test]
        fn try_reserve_enqueue_no_token_leak_on_queue_full() {
            let config = ResourceQuotaConfig {
                max_queue_depth: 1,
                max_bytes_in_flight: 10000,
                max_burst_pulses: 2, // Only 2 tokens
                max_pulses_per_sec: 1,
                ..ResourceQuotaConfig::for_testing()
            };
            let conn = ConnectionState::new("conn-1", config);

            // First enqueue should succeed (uses 1 token)
            assert!(conn.try_reserve_enqueue(50).is_ok());

            // Second should fail due to queue full (NOT rate limit)
            // and should NOT consume a token
            let result = conn.try_reserve_enqueue(50);
            assert!(matches!(result, Err(ResourceError::QueueFull { .. })));

            // Dequeue the first item
            conn.record_dequeue(50);

            // Now we should still be able to enqueue because the token wasn't
            // consumed on the failed attempt
            assert!(conn.try_reserve_enqueue(50).is_ok());
        }
    }

    // ========================================================================
    // Subscription Registry Tests
    // ========================================================================

    mod subscription_registry {
        use super::*;

        fn test_pattern(s: &str) -> TopicPattern {
            TopicPattern::parse(s).expect("valid pattern")
        }

        #[test]
        fn register_and_unregister_connection() {
            let registry = SubscriptionRegistry::new(ResourceQuotaConfig::for_testing());

            registry.register_connection("conn-1").unwrap();
            assert_eq!(registry.connection_count(), 1);

            registry.unregister_connection("conn-1");
            assert_eq!(registry.connection_count(), 0);
        }

        #[test]
        fn register_connection_exceeds_limit() {
            let config = ResourceQuotaConfig {
                max_connections: 2,
                ..ResourceQuotaConfig::for_testing()
            };
            let registry = SubscriptionRegistry::new(config);

            // First two should succeed
            assert!(registry.register_connection("conn-1").is_ok());
            assert!(registry.register_connection("conn-2").is_ok());
            assert_eq!(registry.connection_count(), 2);

            // Third should fail
            let result = registry.register_connection("conn-3");
            assert!(matches!(
                result,
                Err(ResourceError::TooManyConnections { current: 2, max: 2 })
            ));
            assert_eq!(registry.connection_count(), 2);
        }

        #[test]
        fn add_subscription_through_registry() {
            let registry = SubscriptionRegistry::new(ResourceQuotaConfig::for_testing());
            registry.register_connection("conn-1").unwrap();

            let sub = SubscriptionState::new("sub-1", "", vec![test_pattern("work.*.events")], 0);
            assert!(registry.add_subscription("conn-1", sub).is_ok());

            let stats = registry.connection_stats("conn-1").unwrap();
            assert_eq!(stats.subscription_count, 1);
        }

        #[test]
        fn add_subscription_connection_not_found() {
            let registry = SubscriptionRegistry::new(ResourceQuotaConfig::for_testing());

            let sub = SubscriptionState::new("sub-1", "", vec![], 0);
            let result = registry.add_subscription("nonexistent", sub);
            assert!(matches!(
                result,
                Err(ResourceError::ConnectionNotFound { .. })
            ));
        }

        #[test]
        fn find_matching_subscriptions() {
            let registry = SubscriptionRegistry::new(ResourceQuotaConfig::for_testing());

            registry.register_connection("conn-1").unwrap();
            let sub1 = SubscriptionState::new("sub-1", "", vec![test_pattern("work.*.events")], 0);
            registry.add_subscription("conn-1", sub1).unwrap();

            registry.register_connection("conn-2").unwrap();
            let sub2 = SubscriptionState::new("sub-2", "", vec![test_pattern("ledger.head")], 0);
            registry.add_subscription("conn-2", sub2).unwrap();

            // Should match sub-1
            let matches = registry.find_matching_subscriptions("work.W-123.events");
            assert_eq!(matches.len(), 1);
            assert_eq!(matches[0], ("conn-1".to_string(), "sub-1".to_string()));

            // Should match sub-2
            let matches = registry.find_matching_subscriptions("ledger.head");
            assert_eq!(matches.len(), 1);
            assert_eq!(matches[0], ("conn-2".to_string(), "sub-2".to_string()));

            // Should match nothing
            let matches = registry.find_matching_subscriptions("unknown.topic");
            assert!(matches.is_empty());
        }

        #[test]
        fn try_reserve_enqueue_through_registry() {
            let registry = SubscriptionRegistry::new(ResourceQuotaConfig::for_testing());
            registry.register_connection("conn-1").unwrap();

            // Should succeed for reasonable payload and atomically reserve
            assert!(registry.try_reserve_enqueue("conn-1", 100).is_ok());

            // Stats should reflect usage (reservation is atomic)
            let stats = registry.connection_stats("conn-1").unwrap();
            assert_eq!(stats.queue_depth, 1);
            assert_eq!(stats.bytes_in_flight, 100);

            // Add another
            assert!(registry.try_reserve_enqueue("conn-1", 50).is_ok());
            let stats = registry.connection_stats("conn-1").unwrap();
            assert_eq!(stats.queue_depth, 2);
            assert_eq!(stats.bytes_in_flight, 150);
        }

        #[test]
        fn remove_subscription_through_registry() {
            let registry = SubscriptionRegistry::new(ResourceQuotaConfig::for_testing());
            registry.register_connection("conn-1").unwrap();

            let sub = SubscriptionState::new("sub-1", "", vec![test_pattern("work.*.events")], 0);
            registry.add_subscription("conn-1", sub).unwrap();

            let removed = registry.remove_subscription("conn-1", "sub-1");
            assert!(removed.is_ok());

            let stats = registry.connection_stats("conn-1").unwrap();
            assert_eq!(stats.subscription_count, 0);
        }

        #[test]
        fn remove_nonexistent_subscription() {
            let registry = SubscriptionRegistry::new(ResourceQuotaConfig::for_testing());
            registry.register_connection("conn-1").unwrap();

            let result = registry.remove_subscription("conn-1", "nonexistent");
            assert!(matches!(
                result,
                Err(ResourceError::SubscriptionNotFound { .. })
            ));
        }
    }

    // ========================================================================
    // Resource Error Tests
    // ========================================================================

    mod resource_error {
        use super::*;

        #[test]
        fn error_codes_are_correct() {
            assert_eq!(
                ResourceError::TooManySubscriptions {
                    current: 16,
                    max: 16
                }
                .to_hef_error_code(),
                HefErrorCode::HefErrorResourceLimit
            );

            assert_eq!(
                ResourceError::RateLimitExceeded {
                    current_rate: 100,
                    max_rate: 100
                }
                .to_hef_error_code(),
                HefErrorCode::HefErrorResourceLimit
            );

            assert_eq!(
                ResourceError::SubscriptionNotFound {
                    subscription_id: "sub-1".to_string()
                }
                .to_hef_error_code(),
                HefErrorCode::HefErrorSubscriptionNotFound
            );
        }

        #[test]
        fn error_display_is_descriptive() {
            let err = ResourceError::TooManySubscriptions {
                current: 16,
                max: 16,
            };
            let msg = err.to_string();
            assert!(msg.contains("subscription limit"));
            assert!(msg.contains("16"));
        }
    }

    // ========================================================================
    // Queued Pulse Tests
    // ========================================================================

    mod queued_pulse {
        use super::*;

        #[test]
        fn new_pulse_has_correct_priority() {
            let pulse = QueuedPulse::new("episode.EP-001.io", vec![1, 2, 3]);
            assert_eq!(pulse.priority, DropPriority::EpisodeIo);
            assert_eq!(pulse.payload_size(), 3);
        }
    }

    // ========================================================================
    // Configuration Tests
    // ========================================================================

    mod config {
        use super::*;

        #[test]
        fn default_config_matches_rfc() {
            let config = ResourceQuotaConfig::default();
            assert_eq!(config.max_subscriptions_per_connection, 16);
            assert_eq!(config.max_patterns_per_subscription, 16);
            assert_eq!(config.max_total_patterns_per_connection, 64);
            assert_eq!(config.max_pulses_per_sec, 100);
            assert_eq!(config.max_burst_pulses, 200);
            assert_eq!(config.max_queue_depth, 256);
            assert_eq!(config.max_bytes_in_flight, 1_048_576);
            assert_eq!(config.max_pulse_payload_bytes, 2048);
        }

        #[test]
        fn testing_config_has_smaller_limits() {
            let config = ResourceQuotaConfig::for_testing();
            assert!(config.max_subscriptions_per_connection < 16);
            assert!(config.max_queue_depth < 256);
        }
    }
}
