//! HSI Contract Manifest registry builder.
//!
//! This module builds an `HSIContractManifestV1` from the daemon and CLI
//! dispatch registry. Every route in `PrivilegedMessageType` and
//! `SessionMessageType` is mapped to an HSI route entry with semantics
//! annotations.
//!
//! # Mechanically Derived from Dispatch Enums
//!
//! Route descriptors are derived directly from `PrivilegedMessageType` and
//! `SessionMessageType` via their `all_request_variants()`, `hsi_route()`,
//! `hsi_route_id()`, `hsi_request_schema()`, and `hsi_response_schema()`
//! methods. Adding a new dispatch variant without updating these methods
//! causes a build failure (missing match arm) or a manifest completeness
//! test failure.
//!
//! # Fail-closed Build Enforcement
//!
//! Per RFC-0020 section 3.1.1, if any route is missing a semantics
//! annotation, `build_manifest()` returns an error. This ensures that
//! new routes added to the dispatcher cannot be deployed without
//! explicit semantics documentation.
//!
//! # Contract References
//!
//! - RFC-0020 section 3.1.1: Generation and determinism
//! - REQ-0001: Missing route semantics annotation fails CI/build

use super::manifest::{
    CliVersion, HsiContractManifestV1, HsiRouteEntry, SCHEMA_ID, SCHEMA_VERSION, StabilityClass,
};
use super::semantics::annotate_route;
use crate::protocol::dispatch::PrivilegedMessageType;
use crate::protocol::session_dispatch::SessionMessageType;

/// Error returned when manifest generation fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestBuildError {
    /// One or more routes are missing semantics annotations.
    ///
    /// Per RFC-0020 section 3.1.1: "Missing annotations MUST fail the build."
    MissingSemantics {
        /// Routes that are missing annotations.
        routes: Vec<String>,
    },

    /// A route appears in both privileged and session registries with
    /// conflicting descriptors (differing id, `request_schema`,
    /// `response_schema`, or stability).
    ///
    /// Shared routes MUST have identical metadata in both registries to
    /// ensure manifest determinism regardless of which registry provides
    /// the winning entry.
    ConflictingSharedRoute {
        /// The route path that has conflicting descriptors.
        route: String,
        /// Human-readable description of the conflict.
        detail: String,
    },
}

impl std::fmt::Display for ManifestBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingSemantics { routes } => {
                write!(
                    f,
                    "HSI contract manifest build failed: missing semantics annotations for {} route(s): {}",
                    routes.len(),
                    routes.join(", ")
                )
            },
            Self::ConflictingSharedRoute { route, detail } => {
                write!(
                    f,
                    "HSI contract manifest build failed: conflicting shared route '{route}': {detail}"
                )
            },
        }
    }
}

impl std::error::Error for ManifestBuildError {}

/// Route descriptor used to build the manifest from dispatch registries.
///
/// Each entry maps a dispatcher message type to an HSI route with its
/// schema bindings.
struct RouteDescriptor {
    /// Route identifier (e.g., `CLAIM_WORK`).
    id: &'static str,
    /// Canonical route path (e.g., `hsi.work.claim`).
    route: &'static str,
    /// Stability classification.
    stability: StabilityClass,
    /// Request schema identifier.
    request_schema: &'static str,
    /// Response schema identifier.
    response_schema: &'static str,
}

/// Returns all route descriptors from the privileged (operator) dispatch
/// registry, derived mechanically from `PrivilegedMessageType`.
///
/// Route metadata (ID, route path, schemas) comes directly from the enum
/// methods, so adding a new variant without updating the match arms in
/// `PrivilegedMessageType` causes a compile-time error.
fn privileged_routes() -> Vec<RouteDescriptor> {
    PrivilegedMessageType::all_request_variants()
        .iter()
        .map(|v| RouteDescriptor {
            id: v.hsi_route_id(),
            route: v.hsi_route(),
            stability: StabilityClass::Stable,
            request_schema: v.hsi_request_schema(),
            response_schema: v.hsi_response_schema(),
        })
        .collect()
}

/// Returns all route descriptors from the session-scoped dispatch registry,
/// derived mechanically from `SessionMessageType`.
fn session_routes() -> Vec<RouteDescriptor> {
    SessionMessageType::all_request_variants()
        .iter()
        .map(|v| RouteDescriptor {
            id: v.hsi_route_id(),
            route: v.hsi_route(),
            stability: StabilityClass::Stable,
            request_schema: v.hsi_request_schema(),
            response_schema: v.hsi_response_schema(),
        })
        .collect()
}

/// Builds an `HSIContractManifestV1` from the daemon and CLI dispatch
/// registries.
///
/// # Arguments
///
/// * `cli_version` - The CLI version metadata to embed in the manifest.
///
/// # Errors
///
/// Returns `ManifestBuildError::MissingSemantics` if any route lacks a
/// semantics annotation. Per RFC-0020 section 3.1.1, this MUST fail the
/// build.
///
/// Returns `ManifestBuildError::ConflictingSharedRoute` if a route appears
/// in both privileged and session registries with differing metadata.
///
/// # Determinism
///
/// The returned manifest is deterministic: routes are sorted
/// lexicographically by `route` field, and all fields are populated from
/// compile-time constants.
pub fn build_manifest(
    cli_version: CliVersion,
) -> Result<HsiContractManifestV1, ManifestBuildError> {
    let all_routes: Vec<RouteDescriptor> = {
        let mut routes = privileged_routes();
        routes.extend(session_routes());
        routes
    };

    build_manifest_from_descriptors(cli_version, &all_routes)
}

/// Internal: builds a manifest from an explicit list of route descriptors.
///
/// This function contains the core build logic shared by `build_manifest()`
/// and test helpers. It is not public because production callers should use
/// `build_manifest()` which derives descriptors from the dispatch enums.
fn build_manifest_from_descriptors(
    cli_version: CliVersion,
    all_routes: &[RouteDescriptor],
) -> Result<HsiContractManifestV1, ManifestBuildError> {
    let mut missing = Vec::new();
    let mut entries = Vec::with_capacity(all_routes.len());
    let mut seen_routes: std::collections::HashMap<&str, &RouteDescriptor> =
        std::collections::HashMap::new();

    for desc in all_routes {
        // Deduplicate routes that appear in both privileged and session
        // dispatch registries (e.g., SubscribePulse, UnsubscribePulse).
        // On duplicate detection, verify that the full descriptor tuple
        // (id, request_schema, response_schema, stability) matches. If
        // they differ, return an error to prevent silent metadata loss.
        if let Some(prev) = seen_routes.get(desc.route) {
            if prev.id != desc.id
                || prev.request_schema != desc.request_schema
                || prev.response_schema != desc.response_schema
                || prev.stability != desc.stability
            {
                return Err(ManifestBuildError::ConflictingSharedRoute {
                    route: desc.route.to_string(),
                    detail: format!(
                        "privileged descriptor (id={}, req={}, resp={}, stability={:?}) \
                         vs session descriptor (id={}, req={}, resp={}, stability={:?})",
                        prev.id,
                        prev.request_schema,
                        prev.response_schema,
                        prev.stability,
                        desc.id,
                        desc.request_schema,
                        desc.response_schema,
                        desc.stability,
                    ),
                });
            }
            continue;
        }
        seen_routes.insert(desc.route, desc);
        match annotate_route(desc.route) {
            Some(semantics) => {
                entries.push(HsiRouteEntry {
                    id: desc.id.to_string(),
                    route: desc.route.to_string(),
                    stability: desc.stability,
                    request_schema: desc.request_schema.to_string(),
                    response_schema: desc.response_schema.to_string(),
                    semantics,
                });
            },
            None => {
                missing.push(desc.route.to_string());
            },
        }
    }

    // Fail-closed: missing annotations MUST fail the build
    if !missing.is_empty() {
        return Err(ManifestBuildError::MissingSemantics { routes: missing });
    }

    // Sort routes lexicographically by route field for determinism
    entries.sort_by(|a, b| a.route.cmp(&b.route));

    Ok(HsiContractManifestV1 {
        schema: SCHEMA_ID.to_string(),
        schema_version: SCHEMA_VERSION.to_string(),
        cli_version,
        routes: entries,
    })
}

/// Expected number of privileged routes.
///
/// This constant MUST be updated when routes are added to or removed from
/// `PrivilegedMessageType::all_request_variants()`. The
/// `test_privileged_route_count` test enforces this.
pub const EXPECTED_PRIVILEGED_ROUTE_COUNT: usize = 37;

/// Expected number of session routes.
///
/// This constant MUST be updated when routes are added to or removed from
/// `SessionMessageType::all_request_variants()`. The
/// `test_session_route_count` test enforces this.
pub const EXPECTED_SESSION_ROUTE_COUNT: usize = 8;

/// Number of routes that appear in both privileged and session dispatch
/// registries (e.g., `SubscribePulse`, `UnsubscribePulse`). These are
/// deduplicated during manifest construction.
pub const EXPECTED_SHARED_ROUTE_COUNT: usize = 2;

/// Expected total route count for the manifest (after deduplication).
pub const EXPECTED_TOTAL_ROUTE_COUNT: usize =
    EXPECTED_PRIVILEGED_ROUTE_COUNT + EXPECTED_SESSION_ROUTE_COUNT - EXPECTED_SHARED_ROUTE_COUNT;

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cli_version() -> CliVersion {
        CliVersion {
            semver: "0.9.0".to_string(),
            build_hash: "blake3:0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
        }
    }

    #[test]
    fn build_manifest_succeeds() {
        let manifest = build_manifest(test_cli_version()).expect("manifest build must succeed");
        assert_eq!(manifest.schema, SCHEMA_ID);
        assert_eq!(manifest.schema_version, SCHEMA_VERSION);
        assert!(!manifest.routes.is_empty());
    }

    #[test]
    fn build_manifest_routes_are_sorted() {
        let manifest = build_manifest(test_cli_version()).expect("manifest build must succeed");
        for i in 1..manifest.routes.len() {
            assert!(
                manifest.routes[i - 1].route <= manifest.routes[i].route,
                "routes not sorted: '{}' before '{}'",
                manifest.routes[i - 1].route,
                manifest.routes[i].route,
            );
        }
    }

    #[test]
    fn build_manifest_deterministic_across_builds() {
        let m1 = build_manifest(test_cli_version()).expect("build 1");
        let m2 = build_manifest(test_cli_version()).expect("build 2");
        assert_eq!(
            m1.canonical_bytes().expect("canonical bytes 1"),
            m2.canonical_bytes().expect("canonical bytes 2"),
        );
        assert_eq!(
            m1.content_hash().expect("hash 1"),
            m2.content_hash().expect("hash 2"),
        );
    }

    #[test]
    fn build_manifest_hash_changes_on_version_change() {
        let m1 = build_manifest(test_cli_version()).expect("build 1");
        let m2 = build_manifest(CliVersion {
            semver: "0.10.0".to_string(),
            build_hash: "blake3:0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
        })
        .expect("build 2");
        assert_ne!(
            m1.content_hash().expect("hash 1"),
            m2.content_hash().expect("hash 2"),
        );
    }

    #[test]
    fn build_manifest_validates_clean() {
        let manifest = build_manifest(test_cli_version()).expect("manifest build must succeed");
        let errors = manifest.validate();
        assert!(errors.is_empty(), "validation errors: {errors:?}");
    }

    #[test]
    fn privileged_route_count() {
        let routes = privileged_routes();
        assert_eq!(
            routes.len(),
            EXPECTED_PRIVILEGED_ROUTE_COUNT,
            "privileged route count mismatch: expected {EXPECTED_PRIVILEGED_ROUTE_COUNT}, got {}. \
             Update EXPECTED_PRIVILEGED_ROUTE_COUNT when adding/removing privileged routes.",
            routes.len()
        );
    }

    #[test]
    fn session_route_count() {
        let routes = session_routes();
        assert_eq!(
            routes.len(),
            EXPECTED_SESSION_ROUTE_COUNT,
            "session route count mismatch: expected {EXPECTED_SESSION_ROUTE_COUNT}, got {}. \
             Update EXPECTED_SESSION_ROUTE_COUNT when adding/removing session routes.",
            routes.len()
        );
    }

    #[test]
    fn total_route_count() {
        let manifest = build_manifest(test_cli_version()).expect("manifest build must succeed");
        assert_eq!(
            manifest.routes.len(),
            EXPECTED_TOTAL_ROUTE_COUNT,
            "total route count mismatch"
        );
    }

    #[test]
    fn all_routes_have_unique_ids() {
        let manifest = build_manifest(test_cli_version()).expect("manifest build must succeed");
        let mut ids: Vec<&str> = manifest.routes.iter().map(|r| r.id.as_str()).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(
            ids.len(),
            manifest.routes.len(),
            "duplicate route IDs found"
        );
    }

    #[test]
    fn all_routes_have_unique_routes() {
        let manifest = build_manifest(test_cli_version()).expect("manifest build must succeed");
        let mut routes: Vec<&str> = manifest.routes.iter().map(|r| r.route.as_str()).collect();
        routes.sort_unstable();
        routes.dedup();
        assert_eq!(
            routes.len(),
            manifest.routes.len(),
            "duplicate route paths found"
        );
    }

    /// Verifies that ALL authoritative routes require receipts.
    ///
    /// Per RFC-0020 section 1.3, authoritative routes MUST produce receipts
    /// for proof-carrying-effects/accountability. No exceptions.
    #[test]
    fn all_authoritative_routes_require_receipts() {
        let manifest = build_manifest(test_cli_version()).expect("manifest build must succeed");
        for entry in &manifest.routes {
            if entry.semantics.authoritative {
                assert!(
                    entry.semantics.receipt_required,
                    "authoritative route '{}' must require receipts — \
                     reclassify as advisory if receipts are not needed",
                    entry.route
                );
            }
        }
    }

    /// Verifies that `build_manifest_from_descriptors()` returns
    /// `MissingSemantics` when a route has no semantics annotation.
    ///
    /// This test injects a fake route descriptor with no corresponding
    /// `annotate_route` entry and calls the production build pipeline,
    /// asserting that the fail-closed `MissingSemantics` error is returned.
    ///
    /// EVID-0301: concrete failing-path test for `MissingSemantics` via the
    /// real build function.
    #[test]
    fn missing_semantics_error_path_triggers_via_build() {
        let descriptors = vec![RouteDescriptor {
            id: "FAKE_MISSING",
            route: "hsi.nonexistent.test_only_route",
            stability: StabilityClass::Stable,
            request_schema: "apm2.fake.v1",
            response_schema: "apm2.fake.v1",
        }];
        let result = super::build_manifest_from_descriptors(test_cli_version(), &descriptors);
        match result {
            Err(ManifestBuildError::MissingSemantics { routes }) => {
                assert_eq!(routes.len(), 1);
                assert_eq!(routes[0], "hsi.nonexistent.test_only_route");
                let msg = ManifestBuildError::MissingSemantics { routes }.to_string();
                assert!(
                    msg.contains("missing semantics annotations"),
                    "error message must mention missing semantics: {msg}"
                );
                assert!(
                    msg.contains("hsi.nonexistent.test_only_route"),
                    "error message must contain the failing route: {msg}"
                );
            },
            Ok(_) => panic!("build_manifest_from_descriptors must fail for unknown routes"),
            Err(other) => panic!("expected MissingSemantics, got: {other:?}"),
        }
    }

    /// Verifies that shared routes with conflicting descriptors cause
    /// `ConflictingSharedRoute` error.
    ///
    /// When a route path appears in both privileged and session registries
    /// with differing metadata (id, schemas, or stability), the builder
    /// MUST reject it to prevent silent metadata loss.
    #[test]
    fn conflicting_shared_route_causes_build_error() {
        let descriptors = vec![
            RouteDescriptor {
                id: "PULSE_SUBSCRIBE",
                route: "hsi.pulse.subscribe",
                stability: StabilityClass::Stable,
                request_schema: "apm2.subscribe_pulse_request.v1",
                response_schema: "apm2.subscribe_pulse_response.v1",
            },
            // Same route but with a different request_schema
            RouteDescriptor {
                id: "PULSE_SUBSCRIBE",
                route: "hsi.pulse.subscribe",
                stability: StabilityClass::Stable,
                request_schema: "apm2.subscribe_pulse_request.v2_CONFLICT",
                response_schema: "apm2.subscribe_pulse_response.v1",
            },
        ];
        let result = super::build_manifest_from_descriptors(test_cli_version(), &descriptors);
        match result {
            Err(ManifestBuildError::ConflictingSharedRoute { route, detail }) => {
                assert_eq!(route, "hsi.pulse.subscribe");
                assert!(
                    detail.contains("v2_CONFLICT"),
                    "detail must describe the conflict: {detail}"
                );
            },
            Ok(_) => panic!("build must fail for conflicting shared routes"),
            Err(other) => panic!("expected ConflictingSharedRoute, got: {other:?}"),
        }
    }

    /// Verifies that shared routes with identical descriptors are
    /// deduplicated without error.
    #[test]
    fn identical_shared_route_deduplicates_cleanly() {
        let descriptors = vec![
            RouteDescriptor {
                id: "WORK_CLAIM",
                route: "hsi.work.claim",
                stability: StabilityClass::Stable,
                request_schema: "apm2.claim_work_request.v1",
                response_schema: "apm2.claim_work_response.v1",
            },
            // Exact duplicate — should be silently deduplicated
            RouteDescriptor {
                id: "WORK_CLAIM",
                route: "hsi.work.claim",
                stability: StabilityClass::Stable,
                request_schema: "apm2.claim_work_request.v1",
                response_schema: "apm2.claim_work_response.v1",
            },
        ];
        let manifest = super::build_manifest_from_descriptors(test_cli_version(), &descriptors)
            .expect("identical shared routes must deduplicate cleanly");
        assert_eq!(manifest.routes.len(), 1);
        assert_eq!(manifest.routes[0].route, "hsi.work.claim");
    }

    /// Verifies that every dispatchable request variant from both dispatch
    /// enums appears in the built manifest. This catches variants that are
    /// declared in the enum but omitted from `all_request_variants()`.
    #[test]
    fn every_dispatchable_variant_appears_in_manifest() {
        let manifest = build_manifest(test_cli_version()).expect("manifest build must succeed");
        let manifest_routes: std::collections::HashSet<&str> =
            manifest.routes.iter().map(|r| r.route.as_str()).collect();

        // Check all privileged variants
        for v in PrivilegedMessageType::all_request_variants() {
            assert!(
                manifest_routes.contains(v.hsi_route()),
                "PrivilegedMessageType::{:?} (route '{}') is dispatchable but missing from manifest",
                v,
                v.hsi_route()
            );
        }

        // Check all session variants
        for v in SessionMessageType::all_request_variants() {
            assert!(
                manifest_routes.contains(v.hsi_route()),
                "SessionMessageType::{:?} (route '{}') is dispatchable but missing from manifest",
                v,
                v.hsi_route()
            );
        }
    }

    /// Verifies that `PrivilegedMessageType::all_request_variants()` covers
    /// all request-bearing dispatch variants.
    ///
    /// This test asserts that the route descriptors derived from the enum
    /// match the expected count, and that every variant's route appears in
    /// the built manifest. If a new variant is added to the enum but not
    /// to `all_request_variants()`, this test will fail.
    #[test]
    fn privileged_routes_cover_dispatch_types() {
        let variants = PrivilegedMessageType::all_request_variants();
        assert_eq!(
            variants.len(),
            EXPECTED_PRIVILEGED_ROUTE_COUNT,
            "PrivilegedMessageType::all_request_variants() count mismatch — \
             a new variant was added without updating all_request_variants()"
        );
        let manifest = build_manifest(test_cli_version()).expect("manifest build must succeed");
        let manifest_routes: Vec<&str> = manifest.routes.iter().map(|r| r.route.as_str()).collect();
        for v in variants {
            assert!(
                manifest_routes.contains(&v.hsi_route()),
                "missing route in manifest for {:?}: {}",
                v,
                v.hsi_route()
            );
        }
    }

    /// Verifies that `SessionMessageType::all_request_variants()` covers
    /// all request-bearing session dispatch variants.
    #[test]
    fn session_routes_cover_dispatch_types() {
        let variants = SessionMessageType::all_request_variants();
        assert_eq!(
            variants.len(),
            EXPECTED_SESSION_ROUTE_COUNT,
            "SessionMessageType::all_request_variants() count mismatch — \
             a new variant was added without updating all_request_variants()"
        );
        let manifest = build_manifest(test_cli_version()).expect("manifest build must succeed");
        let manifest_routes: Vec<&str> = manifest.routes.iter().map(|r| r.route.as_str()).collect();
        for v in variants {
            assert!(
                manifest_routes.contains(&v.hsi_route()),
                "missing route in manifest for {:?}: {}",
                v,
                v.hsi_route()
            );
        }
    }

    // ====================================================================
    // Independent tag-scan completeness tests (non-self-referential)
    //
    // These tests derive the set of client-request variants by scanning
    // all decodable tags (0..=255) via `from_tag()` and filtering with
    // `is_client_request()`. This is an independently-derived source of
    // truth. If a new variant is added to `from_tag()` but omitted from
    // `all_request_variants()`, the set-equality assertion fails.
    //
    // `is_client_request()` uses exhaustive match arms (no `_ =>` wildcard),
    // so adding a new enum variant causes a compile error until it is
    // classified — making this a non-self-referential completeness guard.
    // ====================================================================

    /// Derives `PrivilegedMessageType` client-request variants by scanning
    /// all u8 tags through `from_tag()` + `is_client_request()`, and
    /// asserts set equality with `all_request_variants()`.
    #[test]
    fn privileged_tag_scan_matches_all_request_variants() {
        let tag_scanned: std::collections::HashSet<PrivilegedMessageType> = (0..=255u8)
            .filter_map(PrivilegedMessageType::from_tag)
            .filter(|v| v.is_client_request())
            .collect();

        let declared: std::collections::HashSet<PrivilegedMessageType> =
            PrivilegedMessageType::all_request_variants()
                .iter()
                .copied()
                .collect();

        // Variants found by tag scan but missing from all_request_variants()
        let missing_from_declared: Vec<_> = tag_scanned.difference(&declared).collect();
        assert!(
            missing_from_declared.is_empty(),
            "Tag-scan found client-request variants missing from \
             PrivilegedMessageType::all_request_variants(): {missing_from_declared:?}. \
             Add them to all_request_variants()."
        );

        // Variants declared in all_request_variants() but not found by tag scan
        let extra_in_declared: Vec<_> = declared.difference(&tag_scanned).collect();
        assert!(
            extra_in_declared.is_empty(),
            "PrivilegedMessageType::all_request_variants() contains variants \
             not found by tag scan or not classified as client requests: \
             {extra_in_declared:?}. Update is_client_request() or from_tag()."
        );

        // Binding evidence: at least one variant was scanned.
        assert!(
            !tag_scanned.is_empty(),
            "tag scan must find at least one client-request variant"
        );
    }

    /// Derives `SessionMessageType` client-request variants by scanning
    /// all u8 tags through `from_tag()` + `is_client_request()`, and
    /// asserts set equality with `all_request_variants()`.
    #[test]
    fn session_tag_scan_matches_all_request_variants() {
        let tag_scanned: std::collections::HashSet<SessionMessageType> = (0..=255u8)
            .filter_map(SessionMessageType::from_tag)
            .filter(|v| v.is_client_request())
            .collect();

        let declared: std::collections::HashSet<SessionMessageType> =
            SessionMessageType::all_request_variants()
                .iter()
                .copied()
                .collect();

        // Variants found by tag scan but missing from all_request_variants()
        let missing_from_declared: Vec<_> = tag_scanned.difference(&declared).collect();
        assert!(
            missing_from_declared.is_empty(),
            "Tag-scan found client-request variants missing from \
             SessionMessageType::all_request_variants(): {missing_from_declared:?}. \
             Add them to all_request_variants()."
        );

        // Variants declared in all_request_variants() but not found by tag scan
        let extra_in_declared: Vec<_> = declared.difference(&tag_scanned).collect();
        assert!(
            extra_in_declared.is_empty(),
            "SessionMessageType::all_request_variants() contains variants \
             not found by tag scan or not classified as client requests: \
             {extra_in_declared:?}. Update is_client_request() or from_tag()."
        );

        // Binding evidence: at least one variant was scanned.
        assert!(
            !tag_scanned.is_empty(),
            "tag scan must find at least one client-request variant"
        );
    }

    /// Verifies that `PrivilegedMessageType::is_client_request()` returns
    /// `false` for all non-request variants (server-to-client notifications).
    #[test]
    fn privileged_non_request_variants_excluded_by_tag_scan() {
        let non_request: Vec<PrivilegedMessageType> = (0..=255u8)
            .filter_map(PrivilegedMessageType::from_tag)
            .filter(|v| !v.is_client_request())
            .collect();

        // PulseEvent is the only non-request variant today.
        assert!(
            !non_request.is_empty(),
            "there must be at least one non-request variant (e.g., PulseEvent)"
        );
        for v in &non_request {
            assert!(
                !PrivilegedMessageType::all_request_variants().contains(v),
                "non-request variant {v:?} must NOT appear in all_request_variants()"
            );
        }
    }

    /// Verifies that `SessionMessageType::is_client_request()` returns
    /// `false` for all non-request variants (server-to-client notifications).
    #[test]
    fn session_non_request_variants_excluded_by_tag_scan() {
        let non_request: Vec<SessionMessageType> = (0..=255u8)
            .filter_map(SessionMessageType::from_tag)
            .filter(|v| !v.is_client_request())
            .collect();

        // PulseEvent is the only non-request variant today.
        assert!(
            !non_request.is_empty(),
            "there must be at least one non-request variant (e.g., PulseEvent)"
        );
        for v in &non_request {
            assert!(
                !SessionMessageType::all_request_variants().contains(v),
                "non-request variant {v:?} must NOT appear in all_request_variants()"
            );
        }
    }
}
