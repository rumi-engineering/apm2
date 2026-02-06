//! Trigger conditions for flight recorder persistence.
//!
//! This module defines `PersistTrigger` per AD-EVID-001, specifying the
//! conditions under which the flight recorder should persist its buffers
//! to the content-addressed store.
//!
//! # Architecture
//!
//! ```text
//! PersistTrigger (enum)
//!     |
//!     +-- GateFailure { gate_id, reason }
//!     +-- PolicyViolation { rule_id, violation }
//!     +-- BudgetExhausted { resource }
//!     +-- ProcessCrash { exit_code, signal }
//!     +-- ProcessKilled { signal }
//!     +-- ExplicitPin { actor, reason }
//!     +-- QuarantineEntry { reason }
//! ```
//!
//! # Trigger Categories
//!
//! Per AD-EVID-001, persistence is triggered on:
//!
//! 1. **Gate failures**: Security gate rejects an operation
//! 2. **Policy violations**: Runtime policy check fails
//! 3. **Budget exhaustion**: Episode exceeds resource limits
//! 4. **Process abnormality**: Crash, signal, or forced termination
//! 5. **Explicit pins**: Human or system requests evidence retention
//! 6. **Quarantine entry**: Episode enters quarantine state
//!
//! # Security Model
//!
//! - Triggers are fail-closed: any unexpected termination preserves evidence
//! - Normal completion does NOT trigger persistence (evidence is discarded)
//! - All trigger events are recorded in the ledger for audit
//!
//! # Invariants
//!
//! - [INV-PT001] All trigger variants include sufficient context for audit
//! - [INV-PT002] String fields are bounded by MAX_* constants
//! - [INV-PT003] Triggers are serializable for ledger storage
//!
//! # Contract References
//!
//! - AD-EVID-001: Flight recorder and evidence persistence
//! - CTR-1303: Bounded string lengths

use serde::{Deserialize, Serialize};

// =============================================================================
// Constants (CTR-1303)
// =============================================================================

/// Maximum length for gate ID.
pub const MAX_GATE_ID_LEN: usize = 128;

/// Maximum length for rule ID.
pub const MAX_RULE_ID_LEN: usize = 256;

/// Maximum length for reason strings.
pub const MAX_REASON_LEN: usize = 1024;

/// Maximum length for resource names.
pub const MAX_RESOURCE_LEN: usize = 64;

/// Maximum length for actor IDs.
pub const MAX_ACTOR_LEN: usize = 256;

/// Maximum length for violation descriptions.
pub const MAX_VIOLATION_LEN: usize = 2048;

// =============================================================================
// PersistTrigger
// =============================================================================

/// Trigger condition for flight recorder persistence.
///
/// These triggers determine when evidence should be persisted to the CAS
/// rather than discarded. Per AD-EVID-001, evidence is retained on abnormal
/// terminations to support debugging and incident investigation.
///
/// # Example
///
/// ```rust,ignore
/// use apm2_daemon::evidence::trigger::PersistTrigger;
///
/// let trigger = PersistTrigger::gate_failure("pre-exec-gate", "capability denied");
///
/// assert!(trigger.is_security_related());
/// assert_eq!(trigger.category(), TriggerCategory::Security);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum PersistTrigger {
    /// Security gate rejected an operation.
    ///
    /// Gates are synchronous checkpoints that must pass before execution
    /// continues. Gate failures indicate a security boundary was enforced.
    GateFailure {
        /// Identifier of the gate that failed.
        gate_id: String,
        /// Human-readable reason for failure.
        reason: String,
    },

    /// Runtime policy check failed.
    ///
    /// Policy violations occur when a tool request violates runtime rules.
    /// These are distinct from capability checks (pre-authorization) and
    /// indicate runtime behavior exceeded policy bounds.
    PolicyViolation {
        /// Identifier of the rule that was violated.
        rule_id: String,
        /// Description of the violation.
        violation: String,
    },

    /// Episode resource budget was exhausted.
    ///
    /// Budget exhaustion triggers when an episode exceeds its allocated
    /// resources (tokens, tool calls, wall time, I/O bytes).
    BudgetExhausted {
        /// Name of the exhausted resource.
        resource: String,
        /// Amount consumed when exhaustion occurred.
        consumed: u64,
        /// Limit that was exceeded.
        limit: u64,
    },

    /// Process terminated abnormally (crash).
    ///
    /// Crashes include non-zero exit codes and signal terminations.
    ProcessCrash {
        /// Exit code if process exited.
        exit_code: Option<i32>,
        /// Signal number if process was signaled.
        signal: Option<i32>,
        /// Signal name (e.g., "SIGSEGV") if available.
        signal_name: Option<String>,
    },

    /// Process was forcibly killed.
    ///
    /// Distinct from crashes - this indicates intentional termination
    /// by the system (e.g., SIGKILL from OOM killer or budget enforcement).
    ProcessKilled {
        /// Signal number used to kill the process.
        signal: i32,
        /// Signal name (e.g., "SIGKILL").
        signal_name: String,
        /// Reason for the kill (if known).
        reason: Option<String>,
    },

    /// Explicit pin request from human or system.
    ///
    /// Allows manual evidence retention for debugging or investigation.
    ExplicitPin {
        /// Actor requesting the pin (human ID or system component).
        actor: String,
        /// Reason for pinning.
        reason: String,
    },

    /// Episode entered quarantine state.
    ///
    /// Quarantine is a terminal state for episodes that encountered
    /// security-relevant anomalies requiring investigation.
    QuarantineEntry {
        /// Reason for quarantine.
        reason: String,
    },

    /// Watchdog timeout detected unresponsive episode.
    ///
    /// The episode failed to respond to health checks within the
    /// configured timeout period.
    WatchdogTimeout {
        /// How long the episode was unresponsive (milliseconds).
        unresponsive_ms: u64,
        /// Configured timeout threshold (milliseconds).
        threshold_ms: u64,
    },

    /// Internal error occurred during episode execution.
    ///
    /// These are daemon-internal errors, not application errors.
    InternalError {
        /// Error message.
        message: String,
        /// Error code if available.
        code: Option<String>,
    },

    /// Taint flow policy denied an untrusted content flow (TCK-00339).
    ///
    /// Emitted when untrusted or adversarial content attempts to flow into
    /// a restricted target context (receipt, high-authority prompt, etc.)
    /// and the taint policy denies the flow. This is a security trigger
    /// that requires immediate attention.
    TaintFlowDenied {
        /// Source type of the tainted content.
        source: String,
        /// Taint level classification.
        taint_level: String,
        /// Target context that was protected.
        target_context: String,
        /// Policy rule that triggered the denial.
        rule_id: String,
    },
}

impl PersistTrigger {
    // =========================================================================
    // Constructors
    // =========================================================================

    /// Creates a gate failure trigger.
    #[must_use]
    pub fn gate_failure(gate_id: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::GateFailure {
            gate_id: truncate_string(gate_id.into(), MAX_GATE_ID_LEN),
            reason: truncate_string(reason.into(), MAX_REASON_LEN),
        }
    }

    /// Creates a policy violation trigger.
    #[must_use]
    pub fn policy_violation(rule_id: impl Into<String>, violation: impl Into<String>) -> Self {
        Self::PolicyViolation {
            rule_id: truncate_string(rule_id.into(), MAX_RULE_ID_LEN),
            violation: truncate_string(violation.into(), MAX_VIOLATION_LEN),
        }
    }

    /// Creates a budget exhausted trigger.
    #[must_use]
    pub fn budget_exhausted(resource: impl Into<String>, consumed: u64, limit: u64) -> Self {
        Self::BudgetExhausted {
            resource: truncate_string(resource.into(), MAX_RESOURCE_LEN),
            consumed,
            limit,
        }
    }

    /// Creates a process crash trigger from an exit code.
    #[must_use]
    pub const fn from_exit_code(code: i32) -> Self {
        Self::ProcessCrash {
            exit_code: Some(code),
            signal: None,
            signal_name: None,
        }
    }

    /// Creates a process crash trigger from a signal.
    #[must_use]
    pub fn from_signal(signal: i32) -> Self {
        Self::ProcessCrash {
            exit_code: None,
            signal: Some(signal),
            signal_name: signal_name(signal),
        }
    }

    /// Creates a process killed trigger.
    #[must_use]
    pub fn process_killed(signal: i32, reason: Option<String>) -> Self {
        Self::ProcessKilled {
            signal,
            signal_name: signal_name(signal).unwrap_or_else(|| format!("SIG{signal}")),
            reason: reason.map(|r| truncate_string(r, MAX_REASON_LEN)),
        }
    }

    /// Creates an explicit pin trigger.
    #[must_use]
    pub fn explicit_pin(actor: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::ExplicitPin {
            actor: truncate_string(actor.into(), MAX_ACTOR_LEN),
            reason: truncate_string(reason.into(), MAX_REASON_LEN),
        }
    }

    /// Creates a quarantine entry trigger.
    #[must_use]
    pub fn quarantine(reason: impl Into<String>) -> Self {
        Self::QuarantineEntry {
            reason: truncate_string(reason.into(), MAX_REASON_LEN),
        }
    }

    /// Creates a watchdog timeout trigger.
    #[must_use]
    pub const fn watchdog_timeout(unresponsive_ms: u64, threshold_ms: u64) -> Self {
        Self::WatchdogTimeout {
            unresponsive_ms,
            threshold_ms,
        }
    }

    /// Creates an internal error trigger.
    #[must_use]
    pub fn internal_error(message: impl Into<String>, code: Option<String>) -> Self {
        Self::InternalError {
            message: truncate_string(message.into(), MAX_REASON_LEN),
            code: code.map(|c| truncate_string(c, MAX_GATE_ID_LEN)),
        }
    }

    /// Creates a taint flow denied trigger from a `TaintViolation` (TCK-00339).
    #[must_use]
    pub fn taint_flow_denied(
        source: impl Into<String>,
        taint_level: impl Into<String>,
        target_context: impl Into<String>,
        rule_id: impl Into<String>,
    ) -> Self {
        Self::TaintFlowDenied {
            source: truncate_string(source.into(), MAX_RESOURCE_LEN),
            taint_level: truncate_string(taint_level.into(), MAX_RESOURCE_LEN),
            target_context: truncate_string(target_context.into(), MAX_RESOURCE_LEN),
            rule_id: truncate_string(rule_id.into(), MAX_RULE_ID_LEN),
        }
    }

    // =========================================================================
    // Accessors
    // =========================================================================

    /// Returns the trigger category.
    #[must_use]
    pub const fn category(&self) -> TriggerCategory {
        match self {
            Self::GateFailure { .. }
            | Self::PolicyViolation { .. }
            | Self::QuarantineEntry { .. }
            | Self::TaintFlowDenied { .. } => TriggerCategory::Security,
            Self::BudgetExhausted { .. } | Self::WatchdogTimeout { .. } => {
                TriggerCategory::Resource
            },
            Self::ProcessCrash { .. } | Self::ProcessKilled { .. } => TriggerCategory::Process,
            Self::ExplicitPin { .. } => TriggerCategory::Manual,
            Self::InternalError { .. } => TriggerCategory::Internal,
        }
    }

    /// Returns `true` if this trigger is security-related.
    #[must_use]
    pub const fn is_security_related(&self) -> bool {
        matches!(self.category(), TriggerCategory::Security)
    }

    /// Returns `true` if this trigger requires immediate investigation.
    ///
    /// High-severity triggers that should be escalated.
    #[must_use]
    pub const fn requires_immediate_attention(&self) -> bool {
        matches!(
            self,
            Self::GateFailure { .. }
                | Self::PolicyViolation { .. }
                | Self::QuarantineEntry { .. }
                | Self::ProcessKilled { .. }
                | Self::TaintFlowDenied { .. }
        )
    }

    /// Returns the trigger type as a string identifier.
    #[must_use]
    pub const fn trigger_type(&self) -> &'static str {
        match self {
            Self::GateFailure { .. } => "gate_failure",
            Self::PolicyViolation { .. } => "policy_violation",
            Self::BudgetExhausted { .. } => "budget_exhausted",
            Self::ProcessCrash { .. } => "process_crash",
            Self::ProcessKilled { .. } => "process_killed",
            Self::ExplicitPin { .. } => "explicit_pin",
            Self::QuarantineEntry { .. } => "quarantine_entry",
            Self::WatchdogTimeout { .. } => "watchdog_timeout",
            Self::InternalError { .. } => "internal_error",
            Self::TaintFlowDenied { .. } => "taint_flow_denied",
        }
    }

    /// Returns a human-readable summary of the trigger.
    #[must_use]
    pub fn summary(&self) -> String {
        match self {
            Self::GateFailure { gate_id, reason } => {
                format!("Gate '{gate_id}' failed: {reason}")
            },
            Self::PolicyViolation { rule_id, violation } => {
                format!("Policy rule '{rule_id}' violated: {violation}")
            },
            Self::BudgetExhausted {
                resource,
                consumed,
                limit,
            } => {
                format!("Budget exhausted: {resource} ({consumed}/{limit})")
            },
            Self::ProcessCrash {
                exit_code,
                signal,
                signal_name,
            } => match (signal, exit_code) {
                (Some(sig), _) => {
                    let name = signal_name.as_deref().unwrap_or("unknown");
                    format!("Process crashed with signal {sig} ({name})")
                },
                (None, Some(code)) => format!("Process crashed with exit code {code}"),
                (None, None) => "Process crashed".to_string(),
            },
            Self::ProcessKilled {
                signal,
                signal_name,
                reason,
            } => {
                let reason_str = reason.as_deref().unwrap_or("no reason provided");
                format!("Process killed with signal {signal} ({signal_name}): {reason_str}")
            },
            Self::ExplicitPin { actor, reason } => {
                format!("Explicitly pinned by '{actor}': {reason}")
            },
            Self::QuarantineEntry { reason } => {
                format!("Entered quarantine: {reason}")
            },
            Self::WatchdogTimeout {
                unresponsive_ms,
                threshold_ms,
            } => {
                format!(
                    "Watchdog timeout: unresponsive for {unresponsive_ms}ms (threshold: {threshold_ms}ms)"
                )
            },
            Self::InternalError { message, code } => code.as_ref().map_or_else(
                || format!("Internal error: {message}"),
                |c| format!("Internal error [{c}]: {message}"),
            ),
            Self::TaintFlowDenied {
                source,
                taint_level,
                target_context,
                rule_id,
            } => {
                format!(
                    "Taint flow denied: {taint_level} content from {source} \
                     blocked from {target_context} (rule: {rule_id})"
                )
            },
        }
    }
}

// =============================================================================
// TriggerCategory
// =============================================================================

/// Category of persistence trigger.
///
/// Used for filtering and prioritization of triggers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum TriggerCategory {
    /// Security-related triggers (gates, policies, quarantine).
    Security,

    /// Resource-related triggers (budget, watchdog).
    Resource,

    /// Process-related triggers (crash, kill).
    Process,

    /// Manual triggers (explicit pins).
    Manual,

    /// Internal daemon errors.
    Internal,
}

impl TriggerCategory {
    /// Returns the category name as a string.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Security => "security",
            Self::Resource => "resource",
            Self::Process => "process",
            Self::Manual => "manual",
            Self::Internal => "internal",
        }
    }
}

impl std::fmt::Display for TriggerCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Truncates a string to the maximum length, preserving valid UTF-8.
fn truncate_string(s: String, max_len: usize) -> String {
    if s.len() <= max_len {
        return s;
    }

    // Find a valid UTF-8 boundary
    let mut end = max_len;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }

    s[..end].to_string()
}

/// Returns the signal name for common signals.
fn signal_name(signal: i32) -> Option<String> {
    let name = match signal {
        1 => "SIGHUP",
        2 => "SIGINT",
        3 => "SIGQUIT",
        4 => "SIGILL",
        5 => "SIGTRAP",
        6 => "SIGABRT",
        7 => "SIGBUS",
        8 => "SIGFPE",
        9 => "SIGKILL",
        10 => "SIGUSR1",
        11 => "SIGSEGV",
        12 => "SIGUSR2",
        13 => "SIGPIPE",
        14 => "SIGALRM",
        15 => "SIGTERM",
        _ => return None,
    };
    Some(name.to_string())
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gate_failure_trigger() {
        let trigger = PersistTrigger::gate_failure("auth-gate", "invalid token");

        assert_eq!(trigger.trigger_type(), "gate_failure");
        assert_eq!(trigger.category(), TriggerCategory::Security);
        assert!(trigger.is_security_related());
        assert!(trigger.requires_immediate_attention());
        assert!(trigger.summary().contains("auth-gate"));
    }

    #[test]
    fn test_policy_violation_trigger() {
        let trigger = PersistTrigger::policy_violation("no-network", "attempted DNS lookup");

        assert_eq!(trigger.trigger_type(), "policy_violation");
        assert_eq!(trigger.category(), TriggerCategory::Security);
        assert!(trigger.is_security_related());
    }

    #[test]
    fn test_budget_exhausted_trigger() {
        let trigger = PersistTrigger::budget_exhausted("tokens", 10000, 5000);

        assert_eq!(trigger.trigger_type(), "budget_exhausted");
        assert_eq!(trigger.category(), TriggerCategory::Resource);
        assert!(!trigger.is_security_related());
        assert!(trigger.summary().contains("10000"));
        assert!(trigger.summary().contains("5000"));
    }

    #[test]
    fn test_process_crash_exit_code() {
        let trigger = PersistTrigger::from_exit_code(1);

        assert_eq!(trigger.trigger_type(), "process_crash");
        assert_eq!(trigger.category(), TriggerCategory::Process);
        assert!(trigger.summary().contains("exit code 1"));
    }

    #[test]
    fn test_process_crash_signal() {
        let trigger = PersistTrigger::from_signal(11); // SIGSEGV

        assert_eq!(trigger.trigger_type(), "process_crash");
        assert!(trigger.summary().contains("SIGSEGV"));
    }

    #[test]
    fn test_process_killed_trigger() {
        let trigger = PersistTrigger::process_killed(9, Some("OOM killer".to_string()));

        assert_eq!(trigger.trigger_type(), "process_killed");
        assert!(trigger.requires_immediate_attention());
        assert!(trigger.summary().contains("SIGKILL"));
        assert!(trigger.summary().contains("OOM killer"));
    }

    #[test]
    fn test_explicit_pin_trigger() {
        let trigger = PersistTrigger::explicit_pin("user@example.com", "investigating issue");

        assert_eq!(trigger.trigger_type(), "explicit_pin");
        assert_eq!(trigger.category(), TriggerCategory::Manual);
        assert!(!trigger.is_security_related());
    }

    #[test]
    fn test_quarantine_trigger() {
        let trigger = PersistTrigger::quarantine("suspicious network activity");

        assert_eq!(trigger.trigger_type(), "quarantine_entry");
        assert!(trigger.is_security_related());
        assert!(trigger.requires_immediate_attention());
    }

    #[test]
    fn test_watchdog_timeout_trigger() {
        let trigger = PersistTrigger::watchdog_timeout(30000, 10000);

        assert_eq!(trigger.trigger_type(), "watchdog_timeout");
        assert_eq!(trigger.category(), TriggerCategory::Resource);
        assert!(trigger.summary().contains("30000ms"));
    }

    #[test]
    fn test_internal_error_trigger() {
        let trigger =
            PersistTrigger::internal_error("database connection failed", Some("E001".to_string()));

        assert_eq!(trigger.trigger_type(), "internal_error");
        assert_eq!(trigger.category(), TriggerCategory::Internal);
        assert!(trigger.summary().contains("E001"));
    }

    #[test]
    fn test_trigger_serialization() {
        let trigger = PersistTrigger::gate_failure("test-gate", "test reason");
        let json = serde_json::to_string(&trigger).unwrap();
        let deserialized: PersistTrigger = serde_json::from_str(&json).unwrap();

        assert_eq!(trigger, deserialized);
    }

    #[test]
    fn test_trigger_json_format() {
        let trigger = PersistTrigger::gate_failure("test-gate", "test reason");
        let json = serde_json::to_string_pretty(&trigger).unwrap();

        assert!(json.contains("\"type\": \"gate_failure\""));
        assert!(json.contains("\"gate_id\": \"test-gate\""));
    }

    /// SECURITY: Verify unknown fields are rejected.
    #[test]
    fn test_trigger_rejects_unknown_fields() {
        let json = r#"{
            "type": "gate_failure",
            "gate_id": "test",
            "reason": "test",
            "malicious": "attack"
        }"#;

        let result: Result<PersistTrigger, _> = serde_json::from_str(json);
        assert!(result.is_err(), "should reject unknown fields");
    }

    #[test]
    fn test_string_truncation() {
        let long_string = "a".repeat(MAX_REASON_LEN * 2);
        let trigger = PersistTrigger::gate_failure("gate", &long_string);

        if let PersistTrigger::GateFailure { reason, .. } = trigger {
            assert!(reason.len() <= MAX_REASON_LEN);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn test_trigger_category_display() {
        assert_eq!(TriggerCategory::Security.to_string(), "security");
        assert_eq!(TriggerCategory::Resource.to_string(), "resource");
        assert_eq!(TriggerCategory::Process.to_string(), "process");
        assert_eq!(TriggerCategory::Manual.to_string(), "manual");
        assert_eq!(TriggerCategory::Internal.to_string(), "internal");
    }

    #[test]
    fn test_all_trigger_types_have_summaries() {
        let triggers = vec![
            PersistTrigger::gate_failure("gate", "reason"),
            PersistTrigger::policy_violation("rule", "violation"),
            PersistTrigger::budget_exhausted("resource", 100, 50),
            PersistTrigger::from_exit_code(1),
            PersistTrigger::from_signal(9),
            PersistTrigger::process_killed(9, None),
            PersistTrigger::explicit_pin("actor", "reason"),
            PersistTrigger::quarantine("reason"),
            PersistTrigger::watchdog_timeout(1000, 500),
            PersistTrigger::internal_error("message", None),
            PersistTrigger::taint_flow_denied(
                "DIFF",
                "UNTRUSTED",
                "RECEIPT",
                "DEFAULT_TRUST_CHECK",
            ),
        ];

        for trigger in triggers {
            let summary = trigger.summary();
            assert!(!summary.is_empty(), "trigger {trigger:?} has empty summary");
        }
    }

    #[test]
    fn test_taint_flow_denied_trigger() {
        let trigger = PersistTrigger::taint_flow_denied(
            "DIFF",
            "UNTRUSTED",
            "RECEIPT",
            "DEFAULT_TRUST_CHECK",
        );

        assert_eq!(trigger.trigger_type(), "taint_flow_denied");
        assert_eq!(trigger.category(), TriggerCategory::Security);
        assert!(trigger.is_security_related());
        assert!(trigger.requires_immediate_attention());
        assert!(trigger.summary().contains("UNTRUSTED"));
        assert!(trigger.summary().contains("DIFF"));
        assert!(trigger.summary().contains("RECEIPT"));
    }

    #[test]
    fn test_taint_flow_denied_trigger_serialization() {
        let trigger = PersistTrigger::taint_flow_denied(
            "WEB_CONTENT",
            "ADVERSARIAL",
            "HIGH_AUTHORITY_PROMPT",
            "RULE_001",
        );
        let json = serde_json::to_string(&trigger).unwrap();
        let deserialized: PersistTrigger = serde_json::from_str(&json).unwrap();
        assert_eq!(trigger, deserialized);
    }
}
