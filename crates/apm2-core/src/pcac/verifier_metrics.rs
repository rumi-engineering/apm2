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
