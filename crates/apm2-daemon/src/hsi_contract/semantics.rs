//! Per-route semantics annotations for HSI contract manifest.
//!
//! This module defines the semantics annotation structure for each route in
//! the dispatch registry. Per RFC-0020 section 3.1, every route MUST have
//! a semantics annotation describing whether it is authoritative vs advisory,
//! its idempotency requirement, and its receipt obligation.
//!
//! # Authoritative Routes and Receipts
//!
//! Per RFC-0020 section 1.3, ALL authoritative routes MUST require receipts
//! for proof-carrying-effects/accountability. Side-effectful local operations
//! (e.g., daemon shutdown, credential mutations) are classified as
//! authoritative with `receipt_required: true` because they produce
//! observable state changes requiring accountability. Only truly read-only
//! query routes are classified as advisory.
//!
//! # Fail-closed Build Enforcement
//!
//! The `annotate_route` function returns `Option<HsiRouteSemantics>`. When
//! building the manifest via `build_manifest()`, any route missing a semantics
//! annotation causes the build to fail. This is enforced at manifest
//! construction time so that new routes added to the dispatcher without
//! annotations are caught immediately.
//!
//! # Contract References
//!
//! - RFC-0020 section 3.1: Missing annotations MUST fail the build
//! - RFC-0020 section 1.3: Authoritative routes MUST produce receipts
//! - REQ-0001: `Missing route semantics annotation fails CI/build`

use super::manifest::{HsiRouteSemantics, IdempotencyRequirement};

/// Authoritative + idempotency-required + receipt-required semantics.
///
/// Used for core state-mutating routes that produce world effects.
const AUTH_IDEMPOTENT_RECEIPT: HsiRouteSemantics = HsiRouteSemantics {
    authoritative: true,
    idempotency: IdempotencyRequirement::Required,
    receipt_required: true,
};

/// Authoritative + best-effort idempotency + receipt-required semantics.
///
/// Used for lifecycle operations (stop, restart, reload, end session).
const AUTH_BESTEFFORT_RECEIPT: HsiRouteSemantics = HsiRouteSemantics {
    authoritative: true,
    idempotency: IdempotencyRequirement::BestEffort,
    receipt_required: true,
};

/// Advisory (read-only) semantics: no idempotency, no receipts.
const ADVISORY: HsiRouteSemantics = HsiRouteSemantics {
    authoritative: false,
    idempotency: IdempotencyRequirement::NotRequired,
    receipt_required: false,
};

/// Authoritative + best-effort idempotency + receipt-required semantics
/// for side-effectful local operations.
///
/// Used for daemon shutdown and credential mutation operations that perform
/// real side effects (shutdown flag flip, credential store mutation). These
/// MUST be authoritative with receipts per RFC-0020 section 1.3, since they
/// produce observable state changes requiring accountability.
const AUTH_BESTEFFORT_RECEIPT_LOCAL: HsiRouteSemantics = HsiRouteSemantics {
    authoritative: true,
    idempotency: IdempotencyRequirement::BestEffort,
    receipt_required: true,
};

/// Authoritative + idempotency-required + receipt-required semantics
/// for side-effectful local operations with idempotent semantics.
///
/// Used for credential add operations (idempotent by key) that still
/// mutate the credential store and therefore require receipts for
/// accountability per RFC-0020 section 1.3.
const AUTH_IDEMPOTENT_RECEIPT_LOCAL: HsiRouteSemantics = HsiRouteSemantics {
    authoritative: true,
    idempotency: IdempotencyRequirement::Required,
    receipt_required: true,
};

/// Returns the semantics annotation for a given route string.
///
/// Every route in the daemon/CLI dispatch registry MUST have an entry here.
/// Adding a new route to the dispatcher without adding a corresponding
/// annotation will cause `build_manifest()` to return an error, which
/// fails the build per RFC-0020 section 3.1.1.
///
/// # Authoritative and Receipts Invariant
///
/// Per RFC-0020 section 1.3, all authoritative routes MUST have
/// `receipt_required: true`. Side-effectful local operations (daemon
/// shutdown, credential mutations) are classified as authoritative with
/// receipts because they produce observable state changes. Only read-only
/// query routes are classified as advisory.
///
/// # Fail-closed
///
/// Returns `None` for unknown routes. The caller MUST treat `None` as a
/// build failure.
#[must_use]
pub fn annotate_route(route: &str) -> Option<HsiRouteSemantics> {
    match route {
        // =================================================================
        // Authoritative + idempotent + receipt-required
        // Core state-mutating operations with world effects.
        // =================================================================
        "hsi.work.claim"
        | "hsi.episode.spawn"
        | "hsi.capability.issue"
        | "hsi.process.start"
        | "hsi.review.ingest_receipt"
        | "hsi.changeset.publish"
        | "hsi.sublease.delegate"
        | "hsi.tool.request"
        | "hsi.event.emit"
        | "hsi.evidence.publish" => Some(AUTH_IDEMPOTENT_RECEIPT),

        // =================================================================
        // Authoritative + best-effort idempotency + receipt-required
        // Lifecycle operations that may retry but track effects.
        // =================================================================
        "hsi.process.stop" | "hsi.process.restart" | "hsi.process.reload" | "hsi.session.end" => {
            Some(AUTH_BESTEFFORT_RECEIPT)
        },

        // =================================================================
        // Authoritative + best-effort idempotency + receipt-required
        // Side-effectful local operations (daemon shutdown, credential
        // mutations). These perform real state changes (shutdown flag flip,
        // credential store mutation) and MUST be authoritative with receipts
        // per RFC-0020 section 1.3.
        // =================================================================
        "hsi.daemon.shutdown"
        | "hsi.credential.remove"
        | "hsi.credential.refresh"
        | "hsi.credential.switch"
        | "hsi.credential.login" => Some(AUTH_BESTEFFORT_RECEIPT_LOCAL),

        // =================================================================
        // Authoritative + idempotent + receipt-required
        // Credential add is idempotent by key but still mutates the
        // credential store, requiring receipts for accountability.
        // =================================================================
        "hsi.credential.add" => Some(AUTH_IDEMPOTENT_RECEIPT_LOCAL),

        // =================================================================
        // Advisory (read-only) endpoints
        // No state mutation, no receipts required.
        // =================================================================
        "hsi.process.list"
        | "hsi.process.status"
        | "hsi.consensus.status"
        | "hsi.consensus.validators"
        | "hsi.consensus.byzantine_evidence"
        | "hsi.consensus.metrics"
        | "hsi.work.status"
        | "hsi.credential.list"
        | "hsi.pulse.subscribe"
        | "hsi.pulse.unsubscribe"
        | "hsi.telemetry.stream"
        | "hsi.logs.stream"
        | "hsi.session.status" => Some(ADVISORY),

        // Unknown route: fail-closed
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_routes_have_annotations() {
        // Verify a representative sample of routes have annotations
        let known_routes = [
            "hsi.work.claim",
            "hsi.episode.spawn",
            "hsi.capability.issue",
            "hsi.daemon.shutdown",
            "hsi.tool.request",
            "hsi.event.emit",
            "hsi.evidence.publish",
            "hsi.session.status",
            "hsi.changeset.publish",
        ];
        for route in &known_routes {
            assert!(
                annotate_route(route).is_some(),
                "route {route} must have semantics annotation"
            );
        }
    }

    #[test]
    fn unknown_route_returns_none() {
        assert!(annotate_route("hsi.nonexistent.route").is_none());
        assert!(annotate_route("").is_none());
        assert!(annotate_route("invalid").is_none());
    }

    #[test]
    fn authoritative_routes_always_require_receipts() {
        // Exhaustively verify ALL annotated routes: if authoritative, must
        // require receipts.
        let all_routes = [
            "hsi.work.claim",
            "hsi.episode.spawn",
            "hsi.capability.issue",
            "hsi.process.start",
            "hsi.review.ingest_receipt",
            "hsi.changeset.publish",
            "hsi.tool.request",
            "hsi.event.emit",
            "hsi.evidence.publish",
            "hsi.process.stop",
            "hsi.process.restart",
            "hsi.process.reload",
            "hsi.session.end",
            "hsi.daemon.shutdown",
            "hsi.credential.remove",
            "hsi.credential.refresh",
            "hsi.credential.switch",
            "hsi.credential.login",
            "hsi.credential.add",
            "hsi.process.list",
            "hsi.process.status",
            "hsi.consensus.status",
            "hsi.consensus.validators",
            "hsi.consensus.byzantine_evidence",
            "hsi.consensus.metrics",
            "hsi.work.status",
            "hsi.credential.list",
            "hsi.pulse.subscribe",
            "hsi.pulse.unsubscribe",
            "hsi.telemetry.stream",
            "hsi.logs.stream",
            "hsi.session.status",
        ];
        for route in &all_routes {
            let sem = annotate_route(route).unwrap();
            if sem.authoritative {
                assert!(
                    sem.receipt_required,
                    "authoritative route {route} must require receipts"
                );
            }
        }
    }

    #[test]
    fn advisory_routes_do_not_require_receipts() {
        let advisory_routes = [
            "hsi.process.list",
            "hsi.process.status",
            "hsi.consensus.status",
            "hsi.work.status",
            "hsi.telemetry.stream",
            "hsi.session.status",
        ];
        for route in &advisory_routes {
            let sem = annotate_route(route).unwrap();
            assert!(!sem.authoritative, "route {route} must be advisory");
            assert!(
                !sem.receipt_required,
                "advisory route {route} must not require receipts"
            );
        }
    }

    #[test]
    fn side_effectful_local_routes_are_authoritative_with_receipts() {
        // Shutdown and credential mutation routes perform real side effects
        // (shutdown flag flip, credential store mutation). Per RFC-0020
        // section 1.3, they MUST be authoritative with receipt_required.
        let side_effectful_routes = [
            "hsi.daemon.shutdown",
            "hsi.credential.add",
            "hsi.credential.remove",
            "hsi.credential.refresh",
            "hsi.credential.switch",
            "hsi.credential.login",
        ];
        for route in &side_effectful_routes {
            let sem = annotate_route(route).unwrap();
            assert!(
                sem.authoritative,
                "side-effectful route {route} must be authoritative"
            );
            assert!(
                sem.receipt_required,
                "side-effectful route {route} must require receipts"
            );
        }
    }

    /// Invariant: all side-effectful handlers (those that mutate state or
    /// perform real external effects) MUST NOT be classified as advisory.
    /// Advisory classification is reserved for read-only/query routes only.
    #[test]
    fn side_effectful_handlers_cannot_be_advisory() {
        // Exhaustive list of routes that perform real side effects.
        // If a new side-effectful route is added, it MUST be added here.
        let side_effectful_routes = [
            // Core state-mutating operations
            "hsi.work.claim",
            "hsi.episode.spawn",
            "hsi.capability.issue",
            "hsi.process.start",
            "hsi.review.ingest_receipt",
            "hsi.changeset.publish",
            "hsi.tool.request",
            "hsi.event.emit",
            "hsi.evidence.publish",
            // Lifecycle operations
            "hsi.process.stop",
            "hsi.process.restart",
            "hsi.process.reload",
            "hsi.session.end",
            // Side-effectful local operations
            "hsi.daemon.shutdown",
            "hsi.credential.add",
            "hsi.credential.remove",
            "hsi.credential.refresh",
            "hsi.credential.switch",
            "hsi.credential.login",
        ];
        for route in &side_effectful_routes {
            let sem = annotate_route(route)
                .unwrap_or_else(|| panic!("side-effectful route {route} must have annotation"));
            assert!(
                sem.authoritative,
                "side-effectful route {route} must be authoritative, not advisory"
            );
            assert!(
                sem.receipt_required,
                "side-effectful route {route} must require receipts"
            );
        }
    }
}
