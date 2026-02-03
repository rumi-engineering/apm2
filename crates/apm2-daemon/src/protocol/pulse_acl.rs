//! ACL evaluation for HEF Pulse Plane subscriptions (RFC-0018, TCK-00302).
//!
//! This module implements Access Control List (ACL) evaluation for pulse topic
//! subscriptions, enforcing the default-deny security posture specified in
//! DD-HEF-0004 and REQ-HEF-0003.
//!
//! # Security Model
//!
//! Per RFC-0018 and DD-HEF-0004:
//! - **Operator sockets** (`operator.sock`): May subscribe to the full topic
//!   taxonomy. No wildcard restrictions.
//! - **Session sockets** (`session.sock`): Default-deny. Can only subscribe to
//!   topics explicitly enumerated in the capability manifest/lease. Phase 1
//!   forbids wildcard patterns.
//! - **Publish prohibition**: Sessions may NEVER publish pulse topics.
//!
//! # Phase 1 Restrictions
//!
//! Per the ticket scope:
//! - Session wildcard patterns are rejected (Phase 1 limitation)
//! - Session subscriptions require exact topic matches against allowlist
//! - No subscription persistence across daemon restarts (out of scope)
//!
//! # Security Invariants
//!
//! - [INV-ACL-001] Session subscriptions are deny-by-default
//! - [INV-ACL-002] Session wildcards rejected in Phase 1
//! - [INV-ACL-003] Sessions cannot publish pulse topics
//! - [INV-ACL-004] Empty allowlist means no topics allowed (fail-closed)
//! - [INV-ACL-005] All topic validation uses the pulse_topic module grammar

use std::collections::HashSet;

use super::pulse_topic::{PatternError, TopicPattern, validate_topic};

// ============================================================================
// Constants (CTR-1303: Bounded Collections)
// ============================================================================

/// Maximum number of topics in a session's allowlist.
///
/// Per CTR-1303, all allowlists must have bounded sizes to prevent `DoS`.
/// This limit aligns with the resource governance limits in RFC-0018
/// (`max_total_patterns_per_connection: 64`).
pub const MAX_TOPIC_ALLOWLIST: usize = 64;

/// Maximum length for a subscription ID.
///
/// Per REQ-HEF-0002 and INV-HEF-003: All string IDs are length-bounded.
pub const MAX_SUBSCRIPTION_ID_LEN: usize = 64;

/// Maximum length for a client subscription ID.
pub const MAX_CLIENT_SUB_ID_LEN: usize = 64;

// ============================================================================
// Error Types (CTR-0703: Structured Error Types)
// ============================================================================

/// Error type for ACL evaluation failures.
///
/// Per CTR-0703, error types must be structured when callers branch on cause.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AclError {
    /// Topic is not in the session's allowlist.
    TopicNotAllowed {
        /// The topic that was denied.
        topic: String,
    },

    /// Wildcard pattern not allowed for session subscriptions (Phase 1).
    WildcardNotAllowed {
        /// The pattern that contains wildcards.
        pattern: String,
    },

    /// Session attempted to publish a pulse (forbidden).
    PublishNotAllowed,

    /// Topic pattern validation failed.
    InvalidPattern {
        /// The invalid pattern.
        pattern: String,
        /// The underlying error.
        error: PatternError,
    },

    /// Topic validation failed.
    InvalidTopic {
        /// The invalid topic.
        topic: String,
        /// The reason for failure.
        reason: String,
    },

    /// Allowlist exceeds maximum size.
    AllowlistTooLarge {
        /// Actual size.
        count: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Subscription ID exceeds maximum length.
    SubscriptionIdTooLong {
        /// Actual length.
        len: usize,
        /// Maximum allowed.
        max: usize,
    },
}

impl std::fmt::Display for AclError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TopicNotAllowed { topic } => {
                write!(f, "topic not in allowlist: {topic}")
            },
            Self::WildcardNotAllowed { pattern } => {
                write!(
                    f,
                    "wildcard patterns not allowed for session subscriptions (Phase 1): {pattern}"
                )
            },
            Self::PublishNotAllowed => {
                write!(f, "sessions cannot publish pulse topics")
            },
            Self::InvalidPattern { pattern, error } => {
                write!(f, "invalid pattern '{pattern}': {error}")
            },
            Self::InvalidTopic { topic, reason } => {
                write!(f, "invalid topic '{topic}': {reason}")
            },
            Self::AllowlistTooLarge { count, max } => {
                write!(f, "allowlist too large: {count} exceeds maximum {max}")
            },
            Self::SubscriptionIdTooLong { len, max } => {
                write!(
                    f,
                    "subscription ID too long: {len} characters exceeds maximum {max}"
                )
            },
        }
    }
}

impl std::error::Error for AclError {}

// ============================================================================
// ACL Decision
// ============================================================================

/// Result of an ACL check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AclDecision {
    /// Request is allowed.
    Allow,
    /// Request is denied with reason.
    Deny(AclError),
}

impl AclDecision {
    /// Returns `true` if this is an Allow decision.
    #[must_use]
    pub const fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow)
    }

    /// Returns `true` if this is a Deny decision.
    #[must_use]
    pub const fn is_denied(&self) -> bool {
        matches!(self, Self::Deny(_))
    }

    /// Converts to a Result for easier chaining.
    ///
    /// # Errors
    ///
    /// Returns `Err(AclError)` if the decision is `Deny`.
    pub fn into_result(self) -> Result<(), AclError> {
        match self {
            Self::Allow => Ok(()),
            Self::Deny(err) => Err(err),
        }
    }
}

// ============================================================================
// Session Topic Allowlist
// ============================================================================

/// A validated topic allowlist for session subscriptions.
///
/// This struct represents a set of exact topics that a session is allowed to
/// subscribe to. Per Phase 1 restrictions, all topics must be exact matches
/// (no wildcards).
///
/// # Security Contract (INV-ACL-004)
///
/// An empty allowlist means no topics are allowed (fail-closed).
#[derive(Debug, Clone, Default)]
pub struct TopicAllowlist {
    /// Set of allowed topics (exact matches only).
    topics: HashSet<String>,
}

impl TopicAllowlist {
    /// Creates a new empty allowlist.
    ///
    /// # Security Note (INV-ACL-004)
    ///
    /// An empty allowlist denies all subscription requests (fail-closed).
    #[must_use]
    pub fn new() -> Self {
        Self {
            topics: HashSet::new(),
        }
    }

    /// Creates an allowlist from an iterator of topics.
    ///
    /// # Arguments
    ///
    /// * `topics` - Iterator of topic strings to allow
    ///
    /// # Errors
    ///
    /// Returns `AclError::AllowlistTooLarge` if more than `MAX_TOPIC_ALLOWLIST`
    /// topics are provided.
    ///
    /// Returns `AclError::InvalidTopic` if any topic fails validation.
    pub fn try_from_iter<I, S>(topics: I) -> Result<Self, AclError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut allowlist = Self::new();
        let mut count = 0;

        for topic in topics {
            count += 1;
            if count > MAX_TOPIC_ALLOWLIST {
                return Err(AclError::AllowlistTooLarge {
                    count,
                    max: MAX_TOPIC_ALLOWLIST,
                });
            }

            let topic_str = topic.as_ref();

            // Validate topic format
            validate_topic(topic_str).map_err(|e| AclError::InvalidTopic {
                topic: topic_str.to_string(),
                reason: e.to_string(),
            })?;

            allowlist.topics.insert(topic_str.to_string());
        }

        Ok(allowlist)
    }

    /// Adds a topic to the allowlist.
    ///
    /// # Arguments
    ///
    /// * `topic` - The topic to allow
    ///
    /// # Errors
    ///
    /// Returns `AclError::AllowlistTooLarge` if the allowlist is full.
    /// Returns `AclError::InvalidTopic` if the topic is invalid.
    pub fn add(&mut self, topic: &str) -> Result<(), AclError> {
        if self.topics.len() >= MAX_TOPIC_ALLOWLIST {
            return Err(AclError::AllowlistTooLarge {
                count: self.topics.len() + 1,
                max: MAX_TOPIC_ALLOWLIST,
            });
        }

        // Validate topic format
        validate_topic(topic).map_err(|e| AclError::InvalidTopic {
            topic: topic.to_string(),
            reason: e.to_string(),
        })?;

        self.topics.insert(topic.to_string());
        Ok(())
    }

    /// Checks if a topic is in the allowlist.
    #[must_use]
    pub fn contains(&self, topic: &str) -> bool {
        self.topics.contains(topic)
    }

    /// Returns the number of topics in the allowlist.
    #[must_use]
    pub fn len(&self) -> usize {
        self.topics.len()
    }

    /// Returns `true` if the allowlist is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.topics.is_empty()
    }

    /// Returns an iterator over the allowed topics.
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.topics.iter().map(String::as_str)
    }
}

// ============================================================================
// ACL Evaluator
// ============================================================================

/// Connection type for ACL evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionType {
    /// Operator connection (privileged, full access).
    Operator,
    /// Session connection (restricted, allowlist-based).
    Session,
}

/// ACL evaluator for pulse subscriptions.
///
/// This struct encapsulates the ACL evaluation logic for both operator and
/// session connections, enforcing the security model specified in DD-HEF-0004.
///
/// # Usage
///
/// ```rust,ignore
/// let evaluator = PulseAclEvaluator::for_session(topic_allowlist);
///
/// // Check if subscription is allowed
/// match evaluator.check_subscribe(&pattern) {
///     AclDecision::Allow => { /* proceed */ },
///     AclDecision::Deny(err) => { /* reject with error */ },
/// }
/// ```
#[derive(Debug, Clone)]
pub struct PulseAclEvaluator {
    /// Type of connection being evaluated.
    connection_type: ConnectionType,

    /// Topic allowlist for session connections.
    /// `None` for operator connections (full access).
    allowlist: Option<TopicAllowlist>,
}

impl PulseAclEvaluator {
    /// Creates an evaluator for operator connections.
    ///
    /// Operator connections have full access to the topic taxonomy.
    #[must_use]
    pub const fn for_operator() -> Self {
        Self {
            connection_type: ConnectionType::Operator,
            allowlist: None,
        }
    }

    /// Creates an evaluator for session connections.
    ///
    /// Session connections are restricted to the provided allowlist.
    ///
    /// # Arguments
    ///
    /// * `allowlist` - The topics this session is allowed to subscribe to
    #[must_use]
    pub const fn for_session(allowlist: TopicAllowlist) -> Self {
        Self {
            connection_type: ConnectionType::Session,
            allowlist: Some(allowlist),
        }
    }

    /// Returns the connection type.
    #[must_use]
    pub const fn connection_type(&self) -> ConnectionType {
        self.connection_type
    }

    /// Checks if a subscription pattern is allowed.
    ///
    /// # Arguments
    ///
    /// * `pattern_str` - The pattern string from the subscribe request
    ///
    /// # Returns
    ///
    /// `AclDecision::Allow` if the pattern is allowed.
    /// `AclDecision::Deny(error)` if the pattern is denied.
    ///
    /// # Security
    ///
    /// For session connections:
    /// - Wildcards are rejected (Phase 1)
    /// - Only exact matches against allowlist are permitted
    /// - Empty allowlist denies all requests
    ///
    /// For operator connections:
    /// - All valid patterns are allowed
    #[must_use]
    pub fn check_subscribe(&self, pattern_str: &str) -> AclDecision {
        // First, validate the pattern syntax
        let pattern = match TopicPattern::parse(pattern_str) {
            Ok(p) => p,
            Err(e) => {
                return AclDecision::Deny(AclError::InvalidPattern {
                    pattern: pattern_str.to_string(),
                    error: e,
                });
            },
        };

        match self.connection_type {
            ConnectionType::Operator => {
                // Operators can subscribe to any valid pattern
                AclDecision::Allow
            },
            ConnectionType::Session => {
                // Phase 1: Reject wildcards for sessions
                if !pattern.is_exact() {
                    return AclDecision::Deny(AclError::WildcardNotAllowed {
                        pattern: pattern_str.to_string(),
                    });
                }

                // Check against allowlist (fail-closed: no allowlist = deny all)
                self.allowlist.as_ref().map_or_else(
                    || {
                        AclDecision::Deny(AclError::TopicNotAllowed {
                            topic: pattern_str.to_string(),
                        })
                    },
                    |allowlist| {
                        if allowlist.contains(pattern_str) {
                            AclDecision::Allow
                        } else {
                            AclDecision::Deny(AclError::TopicNotAllowed {
                                topic: pattern_str.to_string(),
                            })
                        }
                    },
                )
            },
        }
    }

    /// Checks if a batch of subscription patterns is allowed.
    ///
    /// Returns a list of patterns that were denied, along with their errors.
    /// If the returned list is empty, all patterns are allowed.
    ///
    /// # Arguments
    ///
    /// * `patterns` - Iterator of pattern strings to check
    ///
    /// # Returns
    ///
    /// A vector of `(pattern, error)` pairs for denied patterns.
    pub fn check_subscribe_batch<'a, I>(&self, patterns: I) -> Vec<(String, AclError)>
    where
        I: IntoIterator<Item = &'a str>,
    {
        let mut denied = Vec::new();

        for pattern in patterns {
            if let AclDecision::Deny(err) = self.check_subscribe(pattern) {
                denied.push((pattern.to_string(), err));
            }
        }

        denied
    }

    /// Checks if publishing is allowed (always denied for sessions).
    ///
    /// Per DD-HEF-0004: "Sessions never publish pulse topics; daemon-only
    /// publish from outbox after ledger commit."
    #[must_use]
    pub const fn check_publish(&self) -> AclDecision {
        match self.connection_type {
            ConnectionType::Operator => {
                // Note: Even operators don't publish directly in the current
                // design. The daemon publishes from the outbox after ledger
                // commit. However, we allow it for operators to support
                // potential future use cases.
                AclDecision::Allow
            },
            ConnectionType::Session => AclDecision::Deny(AclError::PublishNotAllowed),
        }
    }
}

// ============================================================================
// Validation Helpers
// ============================================================================

/// Validates a subscription ID.
///
/// # Errors
///
/// Returns `AclError::SubscriptionIdTooLong` if the ID exceeds the maximum
/// length.
pub const fn validate_subscription_id(sub_id: &str) -> Result<(), AclError> {
    if sub_id.len() > MAX_SUBSCRIPTION_ID_LEN {
        return Err(AclError::SubscriptionIdTooLong {
            len: sub_id.len(),
            max: MAX_SUBSCRIPTION_ID_LEN,
        });
    }
    Ok(())
}

/// Validates a client subscription ID.
///
/// # Errors
///
/// Returns `AclError::SubscriptionIdTooLong` if the ID exceeds the maximum
/// length.
pub const fn validate_client_sub_id(client_sub_id: &str) -> Result<(), AclError> {
    if client_sub_id.len() > MAX_CLIENT_SUB_ID_LEN {
        return Err(AclError::SubscriptionIdTooLong {
            len: client_sub_id.len(),
            max: MAX_CLIENT_SUB_ID_LEN,
        });
    }
    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // TopicAllowlist Tests
    // ========================================================================

    mod allowlist {
        use super::*;

        #[test]
        fn empty_allowlist_denies_all() {
            let allowlist = TopicAllowlist::new();
            assert!(allowlist.is_empty());
            assert!(!allowlist.contains("work.W-123.events"));
        }

        #[test]
        fn allowlist_from_valid_topics() {
            let topics = ["work.W-123.events", "episode.EP-001.lifecycle"];
            let allowlist = TopicAllowlist::try_from_iter(topics).unwrap();

            assert_eq!(allowlist.len(), 2);
            assert!(allowlist.contains("work.W-123.events"));
            assert!(allowlist.contains("episode.EP-001.lifecycle"));
            assert!(!allowlist.contains("other.topic"));
        }

        #[test]
        fn allowlist_rejects_invalid_topic() {
            let topics = ["valid.topic", "invalid..topic"];
            let result = TopicAllowlist::try_from_iter(topics);

            assert!(result.is_err());
            if let Err(AclError::InvalidTopic { topic, .. }) = result {
                assert_eq!(topic, "invalid..topic");
            } else {
                panic!("Expected InvalidTopic error");
            }
        }

        #[test]
        fn allowlist_rejects_too_many_topics() {
            // Create more than MAX_TOPIC_ALLOWLIST topics
            let topics: Vec<String> = (0..=MAX_TOPIC_ALLOWLIST)
                .map(|i| format!("topic.{i}"))
                .collect();

            let result = TopicAllowlist::try_from_iter(&topics);
            assert!(matches!(result, Err(AclError::AllowlistTooLarge { .. })));
        }

        #[test]
        fn add_to_allowlist() {
            let mut allowlist = TopicAllowlist::new();
            allowlist.add("work.W-123.events").unwrap();
            assert!(allowlist.contains("work.W-123.events"));
        }

        #[test]
        fn add_invalid_topic_fails() {
            let mut allowlist = TopicAllowlist::new();
            let result = allowlist.add("");
            assert!(matches!(result, Err(AclError::InvalidTopic { .. })));
        }
    }

    // ========================================================================
    // Operator ACL Tests
    // ========================================================================

    mod operator_acl {
        use super::*;

        #[test]
        fn operator_allows_all_valid_patterns() {
            let evaluator = PulseAclEvaluator::for_operator();

            // Exact topics
            assert!(evaluator.check_subscribe("work.W-123.events").is_allowed());
            assert!(evaluator.check_subscribe("ledger.head").is_allowed());

            // Wildcard patterns
            assert!(evaluator.check_subscribe("work.*.events").is_allowed());
            assert!(evaluator.check_subscribe("episode.EP-001.>").is_allowed());
        }

        #[test]
        fn operator_rejects_invalid_patterns() {
            let evaluator = PulseAclEvaluator::for_operator();

            // Invalid patterns should still be rejected
            assert!(evaluator.check_subscribe("").is_denied());
            assert!(evaluator.check_subscribe("invalid..topic").is_denied());
            assert!(evaluator.check_subscribe("regex.[a-z]").is_denied());
        }

        #[test]
        fn operator_can_publish() {
            let evaluator = PulseAclEvaluator::for_operator();
            assert!(evaluator.check_publish().is_allowed());
        }
    }

    // ========================================================================
    // Session ACL Tests
    // ========================================================================

    mod session_acl {
        use super::*;

        fn session_evaluator_with_topics(topics: &[&str]) -> PulseAclEvaluator {
            let allowlist = TopicAllowlist::try_from_iter(topics.iter().copied()).unwrap();
            PulseAclEvaluator::for_session(allowlist)
        }

        #[test]
        fn session_allows_allowlisted_topic() {
            let evaluator =
                session_evaluator_with_topics(&["work.W-123.events", "episode.EP-001.lifecycle"]);

            assert!(evaluator.check_subscribe("work.W-123.events").is_allowed());
            assert!(
                evaluator
                    .check_subscribe("episode.EP-001.lifecycle")
                    .is_allowed()
            );
        }

        #[test]
        fn session_denies_non_allowlisted_topic() {
            let evaluator = session_evaluator_with_topics(&["work.W-123.events"]);

            let decision = evaluator.check_subscribe("work.W-456.events");
            assert!(decision.is_denied());

            if let AclDecision::Deny(AclError::TopicNotAllowed { topic }) = decision {
                assert_eq!(topic, "work.W-456.events");
            } else {
                panic!("Expected TopicNotAllowed error");
            }
        }

        #[test]
        fn session_denies_wildcard_patterns() {
            let evaluator =
                session_evaluator_with_topics(&["work.W-123.events", "work.W-456.events"]);

            // Even if all matching topics are in the allowlist, wildcards are denied
            let decision = evaluator.check_subscribe("work.*.events");
            assert!(decision.is_denied());

            if let AclDecision::Deny(AclError::WildcardNotAllowed { pattern }) = decision {
                assert_eq!(pattern, "work.*.events");
            } else {
                panic!("Expected WildcardNotAllowed error");
            }
        }

        #[test]
        fn session_denies_terminal_wildcard() {
            let evaluator = session_evaluator_with_topics(&["episode.EP-001.lifecycle"]);

            let decision = evaluator.check_subscribe("episode.EP-001.>");
            assert!(decision.is_denied());
            assert!(matches!(
                decision,
                AclDecision::Deny(AclError::WildcardNotAllowed { .. })
            ));
        }

        #[test]
        fn session_cannot_publish() {
            let evaluator = session_evaluator_with_topics(&["work.W-123.events"]);

            let decision = evaluator.check_publish();
            assert!(decision.is_denied());
            assert!(matches!(
                decision,
                AclDecision::Deny(AclError::PublishNotAllowed)
            ));
        }

        #[test]
        fn empty_allowlist_denies_all_topics() {
            let evaluator = PulseAclEvaluator::for_session(TopicAllowlist::new());

            let decision = evaluator.check_subscribe("work.W-123.events");
            assert!(decision.is_denied());
            assert!(matches!(
                decision,
                AclDecision::Deny(AclError::TopicNotAllowed { .. })
            ));
        }

        #[test]
        fn session_rejects_invalid_patterns() {
            let evaluator = session_evaluator_with_topics(&["valid.topic"]);

            let decision = evaluator.check_subscribe("invalid..topic");
            assert!(decision.is_denied());
            assert!(matches!(
                decision,
                AclDecision::Deny(AclError::InvalidPattern { .. })
            ));
        }
    }

    // ========================================================================
    // Batch Validation Tests
    // ========================================================================

    mod batch_validation {
        use super::*;

        #[test]
        fn batch_check_all_allowed() {
            let evaluator = PulseAclEvaluator::for_operator();
            let patterns = ["work.W-123.events", "ledger.head"];

            let denied = evaluator.check_subscribe_batch(patterns.iter().copied());
            assert!(denied.is_empty());
        }

        #[test]
        fn batch_check_some_denied() {
            let allowlist = TopicAllowlist::try_from_iter(["work.W-123.events"]).unwrap();
            let evaluator = PulseAclEvaluator::for_session(allowlist);
            let patterns = ["work.W-123.events", "work.W-456.events"];

            let denied = evaluator.check_subscribe_batch(patterns.iter().copied());
            assert_eq!(denied.len(), 1);
            assert_eq!(denied[0].0, "work.W-456.events");
        }
    }

    // ========================================================================
    // Validation Helper Tests
    // ========================================================================

    mod validation_helpers {
        use super::*;

        #[test]
        fn valid_subscription_id() {
            assert!(validate_subscription_id("sub-123").is_ok());
            assert!(validate_subscription_id("").is_ok()); // Empty is OK (optional field)
        }

        #[test]
        fn subscription_id_too_long() {
            let long_id = "a".repeat(MAX_SUBSCRIPTION_ID_LEN + 1);
            let result = validate_subscription_id(&long_id);
            assert!(matches!(
                result,
                Err(AclError::SubscriptionIdTooLong { .. })
            ));
        }

        #[test]
        fn valid_client_sub_id() {
            assert!(validate_client_sub_id("client-sub-123").is_ok());
        }

        #[test]
        fn client_sub_id_too_long() {
            let long_id = "a".repeat(MAX_CLIENT_SUB_ID_LEN + 1);
            let result = validate_client_sub_id(&long_id);
            assert!(matches!(
                result,
                Err(AclError::SubscriptionIdTooLong { .. })
            ));
        }
    }

    // ========================================================================
    // Security Tests
    // ========================================================================

    mod security {
        use super::*;

        /// INV-ACL-001: Session subscriptions are deny-by-default
        #[test]
        fn deny_by_default() {
            let evaluator = PulseAclEvaluator::for_session(TopicAllowlist::new());
            assert!(evaluator.check_subscribe("any.topic").is_denied());
        }

        /// INV-ACL-002: Session wildcards rejected in Phase 1
        #[test]
        fn wildcards_rejected_for_session() {
            let allowlist = TopicAllowlist::try_from_iter(["work.W-123.events"]).unwrap();
            let evaluator = PulseAclEvaluator::for_session(allowlist);

            // Single wildcard
            assert!(matches!(
                evaluator.check_subscribe("work.*.events"),
                AclDecision::Deny(AclError::WildcardNotAllowed { .. })
            ));

            // Terminal wildcard
            assert!(matches!(
                evaluator.check_subscribe("work.W-123.>"),
                AclDecision::Deny(AclError::WildcardNotAllowed { .. })
            ));
        }

        /// INV-ACL-003: Sessions cannot publish pulse topics
        #[test]
        fn session_publish_denied() {
            let evaluator = PulseAclEvaluator::for_session(TopicAllowlist::new());
            assert!(matches!(
                evaluator.check_publish(),
                AclDecision::Deny(AclError::PublishNotAllowed)
            ));
        }

        /// INV-ACL-004: Empty allowlist means no topics allowed (fail-closed)
        #[test]
        fn empty_allowlist_fail_closed() {
            let evaluator = PulseAclEvaluator::for_session(TopicAllowlist::new());
            // Even valid topics are denied
            assert!(evaluator.check_subscribe("work.W-123.events").is_denied());
            assert!(evaluator.check_subscribe("ledger.head").is_denied());
        }
    }
}
