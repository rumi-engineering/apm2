// AGENT-AUTHORED (TCK-00268)
//! Prometheus metrics for daemon health observability.
//!
//! This module provides Prometheus metrics for the APM2 daemon as specified
//! in RFC-0017 REQ-DCP-0012 (Daemon Health Metrics).
//!
//! # Metrics Families
//!
//! Per `05_rollout_and_ops.yaml`
//! `operational_considerations.monitoring.metrics`:
//!
//! | Metric | Type | Description | Labels |
//! |--------|------|-------------|--------|
//! | `apm2_daemon_sessions_active` | Gauge | Active sessions | `role` |
//! | `apm2_daemon_tool_mediation_latency_seconds` | Histogram | Tool mediation latency | `tool_id`, `decision` |
//! | `apm2_daemon_ipc_requests_total` | Counter | IPC requests | `endpoint`, `status` |
//! | `apm2_daemon_capability_grants_total` | Counter | Capability grants | `role`, `capability_type` |
//! | `apm2_daemon_context_firewall_denials_total` | Counter | Firewall denials | `rule_id` |
//! | `apm2_daemon_session_terminations_total` | Counter | Session terminations | `rationale` |
//!
//! # Usage
//!
//! ```rust,ignore
//! use apm2_daemon::metrics::{DaemonMetrics, MetricsRegistry};
//!
//! // Create metrics registry
//! let registry = MetricsRegistry::new();
//! let metrics = registry.daemon_metrics();
//!
//! // Record events
//! metrics.session_spawned("implementer");
//! metrics.ipc_request_completed("ClaimWork", "success");
//! metrics.record_tool_mediation_latency("file_read", "allow", 0.003);
//!
//! // Export for scraping
//! let output = registry.encode_text()?;
//! ```
//!
//! # Contract References
//!
//! - REQ-DCP-0012: Daemon Health Metrics
//! - RFC-0017 `05_rollout_and_ops.yaml`: Metric definitions

use std::sync::Arc;

use prometheus::{
    CounterVec, Encoder, GaugeVec, HistogramOpts, HistogramVec, Opts, Registry, TextEncoder,
};
use thiserror::Error;

/// Maximum length for label values to prevent denial-of-service via unbounded
/// labels.
pub const MAX_LABEL_VALUE_LEN: usize = 64;

/// Default histogram buckets for tool mediation latency (in seconds).
/// Per RFC-0017: [0.001, 0.005, 0.01, 0.025, 0.05, 0.1]
pub const TOOL_MEDIATION_BUCKETS: &[f64] = &[0.001, 0.005, 0.01, 0.025, 0.05, 0.1];

/// Errors that can occur during metrics operations.
#[derive(Debug, Error)]
pub enum MetricsError {
    /// Failed to register a metric with Prometheus.
    #[error("failed to register metric: {0}")]
    RegistrationFailed(#[from] prometheus::Error),

    /// Failed to encode metrics output.
    #[error("failed to encode metrics: {0}")]
    EncodingFailed(String),
}

/// Result type for metrics operations.
pub type MetricsResult<T> = Result<T, MetricsError>;

/// Daemon health metrics per REQ-DCP-0012.
///
/// This struct holds all Prometheus metrics for the daemon. Metrics are
/// registered with a shared registry and can be exported in Prometheus
/// text format for scraping.
///
/// # Thread Safety
///
/// All metrics use interior mutability and are safe to share across threads.
/// The struct is `Clone`, `Send`, and `Sync`.
#[derive(Clone)]
pub struct DaemonMetrics {
    /// Number of currently active sessions, labeled by role.
    sessions_active: GaugeVec,

    /// Latency of tool mediation (excluding execution), labeled by `tool_id`
    /// and `decision`.
    tool_mediation_latency: HistogramVec,

    /// Total IPC requests by `endpoint` and `status`.
    ipc_requests_total: CounterVec,

    /// Total capability grants issued, labeled by `role` and `capability_type`.
    capability_grants_total: CounterVec,

    /// Total context firewall denials, labeled by `rule_id`.
    context_firewall_denials_total: CounterVec,

    /// Total session terminations by rationale.
    session_terminations_total: CounterVec,

    /// Total contract mismatches during handshake, labeled by `risk_tier`
    /// and `outcome` (TCK-00348).
    ///
    /// Per RFC-0020 section 11.4, this counter tracks:
    /// - `outcome="waived"`: mismatch detected but session allowed
    ///   (Tier0/Tier1)
    /// - `outcome="denied"`: mismatch detected and session denied (Tier2+)
    contract_mismatch_total: CounterVec,
}

impl DaemonMetrics {
    /// Creates new daemon metrics and registers them with the given registry.
    ///
    /// # Errors
    ///
    /// Returns an error if any metric fails to register (e.g., duplicate name).
    pub fn new(registry: &Registry) -> MetricsResult<Self> {
        // Sessions active gauge
        let sessions_active = GaugeVec::new(
            Opts::new(
                "apm2_daemon_sessions_active",
                "Number of currently active sessions",
            ),
            &["role"],
        )?;
        registry.register(Box::new(sessions_active.clone()))?;

        // Tool mediation latency histogram
        let tool_mediation_latency = HistogramVec::new(
            HistogramOpts::new(
                "apm2_daemon_tool_mediation_latency_seconds",
                "Latency of tool mediation (excluding execution)",
            )
            .buckets(TOOL_MEDIATION_BUCKETS.to_vec()),
            &["tool_id", "decision"],
        )?;
        registry.register(Box::new(tool_mediation_latency.clone()))?;

        // IPC requests counter
        let ipc_requests_total = CounterVec::new(
            Opts::new(
                "apm2_daemon_ipc_requests_total",
                "Total IPC requests by endpoint",
            ),
            &["endpoint", "status"],
        )?;
        registry.register(Box::new(ipc_requests_total.clone()))?;

        // Capability grants counter
        let capability_grants_total = CounterVec::new(
            Opts::new(
                "apm2_daemon_capability_grants_total",
                "Total capability grants issued",
            ),
            &["role", "capability_type"],
        )?;
        registry.register(Box::new(capability_grants_total.clone()))?;

        // Context firewall denials counter
        let context_firewall_denials_total = CounterVec::new(
            Opts::new(
                "apm2_daemon_context_firewall_denials_total",
                "Total context firewall denials",
            ),
            &["rule_id"],
        )?;
        registry.register(Box::new(context_firewall_denials_total.clone()))?;

        // Session terminations counter
        let session_terminations_total = CounterVec::new(
            Opts::new(
                "apm2_daemon_session_terminations_total",
                "Total session terminations by rationale",
            ),
            &["rationale"],
        )?;
        registry.register(Box::new(session_terminations_total.clone()))?;

        // TCK-00348: Contract mismatch counter per RFC-0020 section 11.4
        let contract_mismatch_total = CounterVec::new(
            Opts::new(
                "apm2_daemon_contract_mismatch_total",
                "Total contract mismatches during handshake",
            ),
            &["risk_tier", "outcome"],
        )?;
        registry.register(Box::new(contract_mismatch_total.clone()))?;

        Ok(Self {
            sessions_active,
            tool_mediation_latency,
            ipc_requests_total,
            capability_grants_total,
            context_firewall_denials_total,
            session_terminations_total,
            contract_mismatch_total,
        })
    }

    // ========================================================================
    // Session Metrics
    // ========================================================================

    /// Increments the active sessions gauge when a session is spawned.
    ///
    /// # Arguments
    ///
    /// * `role` - The role of the session (e.g., `implementer`,
    ///   `gate_executor`, `reviewer`)
    pub fn session_spawned(&self, role: &str) {
        let role = truncate_label(role);
        self.sessions_active.with_label_values(&[role]).inc();
    }

    /// Decrements the active sessions gauge when a session terminates.
    ///
    /// # Arguments
    ///
    /// * `role` - The role of the session
    pub fn session_ended(&self, role: &str) {
        let role = truncate_label(role);
        self.sessions_active.with_label_values(&[role]).dec();
    }

    /// Returns the current number of active sessions for a given role.
    ///
    /// This is primarily useful for testing.
    #[must_use]
    pub fn active_sessions(&self, role: &str) -> f64 {
        let role = truncate_label(role);
        self.sessions_active.with_label_values(&[role]).get()
    }

    // ========================================================================
    // Tool Mediation Metrics
    // ========================================================================

    /// Records tool mediation latency.
    ///
    /// # Arguments
    ///
    /// * `tool_id` - The tool identifier (e.g., `file_read`, `execute`)
    /// * `decision` - The mediation decision (e.g., `allow`, `deny`)
    /// * `latency_secs` - The latency in seconds
    pub fn record_tool_mediation_latency(&self, tool_id: &str, decision: &str, latency_secs: f64) {
        let tool_id = truncate_label(tool_id);
        let decision = truncate_label(decision);
        self.tool_mediation_latency
            .with_label_values(&[tool_id, decision])
            .observe(latency_secs);
    }

    // ========================================================================
    // IPC Request Metrics
    // ========================================================================

    /// Records an IPC request completion.
    ///
    /// # Arguments
    ///
    /// * `endpoint` - The endpoint name (e.g., `ClaimWork`, `SpawnEpisode`,
    ///   `RequestTool`)
    /// * `status` - The request status (e.g., `success`, `error`,
    ///   `unauthorized`)
    pub fn ipc_request_completed(&self, endpoint: &str, status: &str) {
        let endpoint = truncate_label(endpoint);
        let status = truncate_label(status);
        self.ipc_requests_total
            .with_label_values(&[endpoint, status])
            .inc();
    }

    /// Returns the total IPC requests for testing purposes.
    #[must_use]
    pub fn ipc_request_count(&self, endpoint: &str, status: &str) -> f64 {
        let endpoint = truncate_label(endpoint);
        let status = truncate_label(status);
        self.ipc_requests_total
            .with_label_values(&[endpoint, status])
            .get()
    }

    // ========================================================================
    // Capability Grant Metrics
    // ========================================================================

    /// Records a capability grant.
    ///
    /// # Arguments
    ///
    /// * `role` - The role receiving the capability
    /// * `capability_type` - The type of capability granted (e.g., `file_read`,
    ///   `execute`)
    pub fn capability_granted(&self, role: &str, capability_type: &str) {
        let role = truncate_label(role);
        let capability_type = truncate_label(capability_type);
        self.capability_grants_total
            .with_label_values(&[role, capability_type])
            .inc();
    }

    // ========================================================================
    // Context Firewall Metrics
    // ========================================================================

    /// Records a context firewall denial.
    ///
    /// # Arguments
    ///
    /// * `rule_id` - The firewall rule that triggered the denial
    pub fn context_firewall_denied(&self, rule_id: &str) {
        let rule_id = truncate_label(rule_id);
        self.context_firewall_denials_total
            .with_label_values(&[rule_id])
            .inc();
    }

    /// Returns the total context firewall denials for testing purposes.
    #[must_use]
    pub fn firewall_denial_count(&self, rule_id: &str) -> f64 {
        let rule_id = truncate_label(rule_id);
        self.context_firewall_denials_total
            .with_label_values(&[rule_id])
            .get()
    }

    // ========================================================================
    // Session Termination Metrics
    // ========================================================================

    /// Records a session termination.
    ///
    /// # Arguments
    ///
    /// * `rationale` - The termination rationale (e.g., `normal`,
    ///   `context_firewall_violation`, `budget_exhausted`, `daemon_restart`)
    pub fn session_terminated(&self, rationale: &str) {
        let rationale = truncate_label(rationale);
        self.session_terminations_total
            .with_label_values(&[rationale])
            .inc();
    }

    /// Returns the total session terminations for testing purposes.
    #[must_use]
    pub fn termination_count(&self, rationale: &str) -> f64 {
        let rationale = truncate_label(rationale);
        self.session_terminations_total
            .with_label_values(&[rationale])
            .get()
    }

    // ========================================================================
    // Contract Mismatch Metrics (TCK-00348)
    // ========================================================================

    /// Records a contract mismatch event during handshake.
    ///
    /// Per RFC-0020 section 11.4, this counter is incremented whenever the
    /// mismatch policy evaluation produces a waiver or denial.
    ///
    /// # Arguments
    ///
    /// * `risk_tier` - The risk tier label (e.g., `"tier0"`, `"tier2"`)
    /// * `outcome` - The mismatch outcome (e.g., `"waived"`, `"denied"`)
    pub fn contract_mismatch(&self, risk_tier: &str, outcome: &str) {
        let risk_tier = truncate_label(risk_tier);
        let outcome = truncate_label(outcome);
        self.contract_mismatch_total
            .with_label_values(&[risk_tier, outcome])
            .inc();
    }

    /// Returns the total contract mismatches for testing purposes.
    #[must_use]
    pub fn contract_mismatch_count(&self, risk_tier: &str, outcome: &str) -> f64 {
        let risk_tier = truncate_label(risk_tier);
        let outcome = truncate_label(outcome);
        self.contract_mismatch_total
            .with_label_values(&[risk_tier, outcome])
            .get()
    }
}

/// Metrics registry wrapper that holds the Prometheus registry and daemon
/// metrics.
///
/// This is the main entry point for metrics in the daemon. It creates and
/// manages all daemon metrics and provides methods for exporting metrics
/// in Prometheus text format.
#[derive(Clone)]
pub struct MetricsRegistry {
    /// The Prometheus registry.
    registry: Registry,
    /// Daemon metrics registered with this registry.
    daemon_metrics: DaemonMetrics,
}

impl MetricsRegistry {
    /// Creates a new metrics registry with all daemon metrics registered.
    ///
    /// # Errors
    ///
    /// Returns an error if metric registration fails.
    pub fn new() -> MetricsResult<Self> {
        let registry = Registry::new();
        let daemon_metrics = DaemonMetrics::new(&registry)?;
        Ok(Self {
            registry,
            daemon_metrics,
        })
    }

    /// Returns a reference to the daemon metrics.
    #[must_use]
    pub const fn daemon_metrics(&self) -> &DaemonMetrics {
        &self.daemon_metrics
    }

    /// Encodes all metrics in Prometheus text format.
    ///
    /// This is the format expected by Prometheus scrapers and can be
    /// returned directly from the `/metrics` HTTP endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error if encoding fails.
    pub fn encode_text(&self) -> MetricsResult<String> {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        encoder
            .encode(&metric_families, &mut buffer)
            .map_err(|e| MetricsError::EncodingFailed(e.to_string()))?;
        String::from_utf8(buffer).map_err(|e| MetricsError::EncodingFailed(e.to_string()))
    }

    /// Returns the underlying Prometheus registry.
    ///
    /// This is useful for registering additional custom metrics.
    #[must_use]
    pub const fn prometheus_registry(&self) -> &Registry {
        &self.registry
    }
}

/// Shared metrics registry for use across the daemon.
pub type SharedMetricsRegistry = Arc<MetricsRegistry>;

/// Creates a new shared metrics registry.
///
/// # Errors
///
/// Returns an error if metric registration fails.
pub fn new_shared_registry() -> MetricsResult<SharedMetricsRegistry> {
    Ok(Arc::new(MetricsRegistry::new()?))
}

/// Truncates a label value to prevent denial-of-service via unbounded labels.
///
/// This function is UTF-8 safe and will not panic on multi-byte characters.
/// It finds the last valid character boundary at or before
/// `MAX_LABEL_VALUE_LEN` bytes and truncates there.
fn truncate_label(value: &str) -> &str {
    if value.len() <= MAX_LABEL_VALUE_LEN {
        value
    } else {
        // Find the last valid UTF-8 character boundary at or before
        // MAX_LABEL_VALUE_LEN. This prevents panics when truncating multi-byte
        // UTF-8 characters.
        let end = value
            .char_indices()
            .map(|(i, _)| i)
            .take_while(|&i| i <= MAX_LABEL_VALUE_LEN)
            .last()
            .unwrap_or(0);
        &value[..end]
    }
}

#[cfg(test)]
#[allow(clippy::float_cmp)] // Prometheus counters/gauges return exact integer values as f64
mod tests {
    use super::*;

    #[test]
    fn test_metrics_registry_creation() {
        let registry = MetricsRegistry::new().expect("registry creation should succeed");
        assert!(registry.encode_text().is_ok());
    }

    #[test]
    fn test_sessions_active_gauge() {
        let registry = MetricsRegistry::new().unwrap();
        let metrics = registry.daemon_metrics();

        // Initial state
        assert_eq!(metrics.active_sessions("implementer"), 0.0);

        // Spawn sessions
        metrics.session_spawned("implementer");
        assert_eq!(metrics.active_sessions("implementer"), 1.0);

        metrics.session_spawned("implementer");
        assert_eq!(metrics.active_sessions("implementer"), 2.0);

        // End session
        metrics.session_ended("implementer");
        assert_eq!(metrics.active_sessions("implementer"), 1.0);
    }

    #[test]
    fn test_ipc_requests_counter() {
        let registry = MetricsRegistry::new().unwrap();
        let metrics = registry.daemon_metrics();

        // Record requests
        metrics.ipc_request_completed("ClaimWork", "success");
        metrics.ipc_request_completed("ClaimWork", "success");
        metrics.ipc_request_completed("ClaimWork", "error");

        assert_eq!(metrics.ipc_request_count("ClaimWork", "success"), 2.0);
        assert_eq!(metrics.ipc_request_count("ClaimWork", "error"), 1.0);
    }

    #[test]
    fn test_tool_mediation_histogram() {
        let registry = MetricsRegistry::new().unwrap();
        let metrics = registry.daemon_metrics();

        // Record latencies
        metrics.record_tool_mediation_latency("file_read", "allow", 0.003);
        metrics.record_tool_mediation_latency("file_read", "allow", 0.007);
        metrics.record_tool_mediation_latency("file_read", "deny", 0.001);

        // Just verify encoding works (histogram values are harder to test)
        let output = registry.encode_text().unwrap();
        assert!(output.contains("apm2_daemon_tool_mediation_latency_seconds"));
    }

    #[test]
    fn test_context_firewall_denials() {
        let registry = MetricsRegistry::new().unwrap();
        let metrics = registry.daemon_metrics();

        metrics.context_firewall_denied("path_traversal");
        metrics.context_firewall_denied("path_traversal");
        metrics.context_firewall_denied("unauthorized_network");

        assert_eq!(metrics.firewall_denial_count("path_traversal"), 2.0);
        assert_eq!(metrics.firewall_denial_count("unauthorized_network"), 1.0);
    }

    #[test]
    fn test_session_terminations() {
        let registry = MetricsRegistry::new().unwrap();
        let metrics = registry.daemon_metrics();

        metrics.session_terminated("normal");
        metrics.session_terminated("context_firewall_violation");
        metrics.session_terminated("normal");

        assert_eq!(metrics.termination_count("normal"), 2.0);
        assert_eq!(metrics.termination_count("context_firewall_violation"), 1.0);
    }

    #[test]
    fn test_capability_grants() {
        let registry = MetricsRegistry::new().unwrap();
        let metrics = registry.daemon_metrics();

        metrics.capability_granted("implementer", "file_read");
        metrics.capability_granted("implementer", "execute");
        metrics.capability_granted("gate_executor", "file_read");

        // Verify encoding works
        let output = registry.encode_text().unwrap();
        assert!(output.contains("apm2_daemon_capability_grants_total"));
    }

    #[test]
    fn test_metrics_text_encoding() {
        let registry = MetricsRegistry::new().unwrap();
        let metrics = registry.daemon_metrics();

        // Record metrics for all 7 families to ensure they appear in output.
        // Prometheus only outputs metrics that have been observed.
        metrics.session_spawned("implementer");
        metrics.ipc_request_completed("Ping", "success");
        metrics.record_tool_mediation_latency("file_read", "allow", 0.005);
        metrics.capability_granted("implementer", "file_read");
        metrics.context_firewall_denied("path_traversal");
        metrics.session_terminated("normal");
        metrics.contract_mismatch("tier0", "waived");

        let output = registry.encode_text().unwrap();

        // Verify all 7 metric families are present
        assert!(
            output.contains("apm2_daemon_sessions_active"),
            "missing sessions_active"
        );
        assert!(
            output.contains("apm2_daemon_tool_mediation_latency_seconds"),
            "missing tool_mediation_latency"
        );
        assert!(
            output.contains("apm2_daemon_ipc_requests_total"),
            "missing ipc_requests_total"
        );
        assert!(
            output.contains("apm2_daemon_capability_grants_total"),
            "missing capability_grants_total"
        );
        assert!(
            output.contains("apm2_daemon_context_firewall_denials_total"),
            "missing context_firewall_denials_total"
        );
        assert!(
            output.contains("apm2_daemon_session_terminations_total"),
            "missing session_terminations_total"
        );
        assert!(
            output.contains("apm2_daemon_contract_mismatch_total"),
            "missing contract_mismatch_total"
        );
    }

    #[test]
    fn test_label_truncation() {
        let registry = MetricsRegistry::new().unwrap();
        let metrics = registry.daemon_metrics();

        // Create a very long label value
        let long_label = "a".repeat(200);
        metrics.session_spawned(&long_label);

        // Should not panic and encoding should work
        let output = registry.encode_text().unwrap();
        assert!(output.contains("apm2_daemon_sessions_active"));
    }

    #[test]
    fn test_label_truncation_utf8_safety() {
        // Test that truncation is UTF-8 safe and does not panic on multi-byte
        // characters at the boundary. This is a regression test for CRASH-001.
        let registry = MetricsRegistry::new().unwrap();
        let metrics = registry.daemon_metrics();

        // Create a string with multi-byte UTF-8 characters that crosses the
        // 64-byte boundary. Each emoji is 4 bytes, so 16 emojis = 64 bytes.
        // Adding one more character would cross the boundary.
        let emoji_label = "\u{1F600}".repeat(20); // 80 bytes of emojis
        assert!(emoji_label.len() > MAX_LABEL_VALUE_LEN);

        // This should NOT panic - it should truncate at a character boundary
        metrics.session_spawned(&emoji_label);

        // Verify encoding works
        let output = registry.encode_text().unwrap();
        assert!(output.contains("apm2_daemon_sessions_active"));

        // Test with mixed ASCII and multi-byte characters near the boundary
        // 60 ASCII bytes + 2 emojis (8 bytes) = 68 bytes
        let mixed_label = format!("{}{}", "a".repeat(60), "\u{1F600}\u{1F600}");
        assert!(mixed_label.len() > MAX_LABEL_VALUE_LEN);

        // This should NOT panic
        metrics.session_spawned(&mixed_label);
        let output = registry.encode_text().unwrap();
        assert!(output.contains("apm2_daemon_sessions_active"));

        // Test boundary case: exactly at boundary with multi-byte char
        // 63 ASCII bytes + 1 emoji (4 bytes) = 67 bytes, truncation happens
        // mid-emoji which must not panic
        let boundary_label = format!("{}{}", "b".repeat(63), "\u{1F600}");
        assert!(boundary_label.len() > MAX_LABEL_VALUE_LEN);

        // This should NOT panic - should truncate before the emoji
        metrics.session_spawned(&boundary_label);
        let output = registry.encode_text().unwrap();
        assert!(output.contains("apm2_daemon_sessions_active"));
    }

    #[test]
    fn test_truncate_label_direct() {
        // Direct unit tests for the truncate_label function

        // Short string - no truncation
        let short = "hello";
        assert_eq!(truncate_label(short), "hello");

        // Exactly at limit - no truncation
        let exact = "a".repeat(MAX_LABEL_VALUE_LEN);
        assert_eq!(truncate_label(&exact), exact);

        // ASCII over limit - truncated to limit
        let long_ascii = "a".repeat(100);
        assert_eq!(truncate_label(&long_ascii).len(), MAX_LABEL_VALUE_LEN);

        // Multi-byte at boundary - must truncate before incomplete char
        // 63 'a' chars + one 4-byte emoji = 67 bytes
        let boundary = format!("{}{}", "a".repeat(63), "\u{1F600}");
        let truncated = truncate_label(&boundary);
        // Should truncate to 63 bytes (before the emoji)
        assert_eq!(truncated.len(), 63);
        assert_eq!(truncated, "a".repeat(63));

        // All multi-byte characters - should truncate at char boundary
        let emojis = "\u{1F600}".repeat(20); // 80 bytes
        let truncated = truncate_label(&emojis);
        // Should be 64 bytes or less, at a char boundary (so divisible by 4)
        assert!(truncated.len() <= MAX_LABEL_VALUE_LEN);
        assert_eq!(truncated.len() % 4, 0); // emoji is 4 bytes
        assert_eq!(truncated.len(), 64); // exactly 16 emojis fit
    }

    #[test]
    fn test_contract_mismatch_counter() {
        let registry = MetricsRegistry::new().unwrap();
        let metrics = registry.daemon_metrics();

        // Initial state
        assert_eq!(metrics.contract_mismatch_count("tier0", "waived"), 0.0);
        assert_eq!(metrics.contract_mismatch_count("tier2", "denied"), 0.0);

        // Record mismatches
        metrics.contract_mismatch("tier0", "waived");
        metrics.contract_mismatch("tier0", "waived");
        metrics.contract_mismatch("tier2", "denied");
        metrics.contract_mismatch("tier3", "denied");

        assert_eq!(metrics.contract_mismatch_count("tier0", "waived"), 2.0);
        assert_eq!(metrics.contract_mismatch_count("tier2", "denied"), 1.0);
        assert_eq!(metrics.contract_mismatch_count("tier3", "denied"), 1.0);
    }

    #[test]
    fn test_shared_registry() {
        let registry = new_shared_registry().unwrap();
        let metrics = registry.daemon_metrics();

        metrics.session_spawned("test");
        assert_eq!(metrics.active_sessions("test"), 1.0);
    }
}
