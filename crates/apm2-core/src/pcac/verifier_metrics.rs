// AGENT-AUTHORED
//! Verifier economics metrics surface for PCAC operations.
//!
//! This crate emits structured tracing events for verifier metrics. Prometheus
//! registry wiring can consume these events in downstream runtime surfaces.

use super::VerifierOperation;

/// Emits a verifier-economics sample.
pub fn record_verifier_metrics(operation: VerifierOperation, elapsed_us: u64, proof_checks: u64) {
    tracing::info!(
        target: "pcac_verifier_economics",
        operation = %operation,
        elapsed_us,
        proof_checks,
        "pcac verifier economics sample"
    );
}

/// Emits anti-entropy throughput metrics separately from proof-check metrics.
pub fn record_anti_entropy_event_metrics(event_count: u64) {
    tracing::info!(
        target: "pcac_verifier_economics",
        operation = %VerifierOperation::AntiEntropy,
        event_count,
        "pcac anti-entropy event throughput sample"
    );
}
