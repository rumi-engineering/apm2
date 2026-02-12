// AGENT-AUTHORED (TCK-00507)
//! Continuity profile and sink snapshot resolution for economics gate
//! input assembly.
//!
//! This module implements [`ContinuityProfileResolver`], a trait that
//! resolves projection sink continuity profiles, sink identity snapshots,
//! and continuity windows from a backing store. The initial implementation
//! ([`ConfigBackedResolver`]) loads profiles from the daemon TOML
//! configuration at startup and serves them from memory.
//!
//! # Fail-Closed Semantics
//!
//! When no profile is found for a sink, the resolver returns `None`.
//! Callers MUST treat `None` as DENY (fail-closed). The resolver never
//! synthesizes default profiles for unknown sinks.
//!
//! # Security
//!
//! Trusted signer keys are validated at config parse time (see
//! [`apm2_core::config::ProjectionConfig::validate_sink_profiles`]).
//! By the time a `ConfigBackedResolver` is constructed, all keys are
//! guaranteed to be valid Ed25519 public keys. This module does NOT
//! perform lazy key validation.
//!
//! # Future Extension
//!
//! The [`ContinuityProfileResolver`] trait boundary supports future
//! ledger-backed dynamic profile resolution without changing callers.

use std::collections::HashMap;

use apm2_core::config::ProjectionSinkProfileConfig;
use apm2_core::crypto::{EventHasher, Hash};
use apm2_core::economics::{MultiSinkIdentitySnapshotV1, SinkIdentityEntry};

/// Maximum number of resolved profiles (references config bound).
pub const MAX_RESOLVED_PROFILES: usize = apm2_core::config::MAX_PROJECTION_SINKS;

// ============================================================================
// ContinuityProfileResolver trait
// ============================================================================

/// Resolves projection sink continuity profiles for economics gate input
/// assembly.
///
/// Implementors provide access to per-sink continuity profiles, sink
/// identity snapshots, and continuity windows. The trait is
/// `Send + Sync` to support concurrent access from the projection
/// worker and gate evaluator.
///
/// # Fail-Closed Contract
///
/// All methods return `Option`. Callers MUST interpret `None` as a
/// DENY signal -- the resolver never synthesizes defaults for unknown
/// or unconfigured sinks.
pub trait ContinuityProfileResolver: Send + Sync {
    /// Resolves the continuity profile for the given sink identifier.
    ///
    /// Returns `None` when no profile is configured for `sink_id`.
    /// Callers must treat `None` as DENY.
    fn resolve_continuity_profile(&self, sink_id: &str) -> Option<ResolvedContinuityProfile>;

    /// Resolves the sink identity snapshot for the given sink identifier.
    ///
    /// Returns `None` when no snapshot is available for `sink_id`.
    /// Callers must treat `None` as DENY.
    fn resolve_sink_snapshot(&self, sink_id: &str) -> Option<MultiSinkIdentitySnapshotV1>;

    /// Resolves the continuity window for the given boundary identifier.
    ///
    /// Returns `None` when no window is declared for `boundary_id`.
    /// Callers must treat `None` as DENY.
    fn resolve_continuity_window(&self, boundary_id: &str) -> Option<ResolvedContinuityWindow>;
}

// ============================================================================
// Resolved value types (pre-validated, ready for economics gate input)
// ============================================================================

/// A resolved continuity profile derived from configuration.
///
/// Contains the pre-validated fields that map directly to
/// [`apm2_core::economics::ProjectionSinkContinuityProfileV1`] input
/// fields without lossy conversion. The actual signed
/// `ProjectionSinkContinuityProfileV1` is constructed downstream by
/// the economics gate assembler which has access to a
/// [`Signer`](apm2_core::crypto::Signer).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedContinuityProfile {
    /// Sink identifier (e.g., "github-primary").
    pub sink_id: String,
    /// Outage window duration in HTF ticks.
    pub outage_window_ticks: u64,
    /// Replay window duration in HTF ticks.
    pub replay_window_ticks: u64,
    /// Churn tolerance count.
    pub churn_tolerance: u32,
    /// Partition tolerance count.
    pub partition_tolerance: u32,
    /// Pre-validated Ed25519 public keys of trusted signers (32 bytes each).
    pub trusted_signer_keys: Vec<[u8; 32]>,
}

/// A resolved continuity window derived from configuration.
///
/// Contains the pre-validated fields that map directly to
/// [`apm2_core::economics::ProjectionContinuityWindowV1`] input fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedContinuityWindow {
    /// Boundary identifier this window is scoped to.
    pub boundary_id: String,
    /// Outage window duration in HTF ticks.
    pub outage_window_ticks: u64,
    /// Replay window duration in HTF ticks.
    pub replay_window_ticks: u64,
}

// ============================================================================
// ConfigBackedResolver
// ============================================================================

/// Config-backed continuity profile resolver (TCK-00507).
///
/// Loads projection sink profiles from daemon TOML configuration at
/// construction time. All trusted signer keys are pre-decoded and
/// validated before the resolver is made available.
///
/// # Invariants
///
/// - [INV-CR01] All stored `trusted_signer_keys` are valid 32-byte Ed25519
///   public keys (validated at construction time).
/// - [INV-CR02] The resolver is immutable after construction -- no runtime
///   mutations.
/// - [INV-CR03] Missing sink returns `None` (caller enforces DENY).
///
/// # Contracts
///
/// - [CTR-CR01] Construction fails if any trusted signer hex is invalid,
///   preventing daemon startup.
/// - [CTR-CR02] `resolve_*` methods are `O(1)` hash map lookups.
/// - [CTR-CR03] The resolver is `Send + Sync` for concurrent access.
pub struct ConfigBackedResolver {
    /// Pre-resolved profiles keyed by sink identifier.
    profiles: HashMap<String, ResolvedContinuityProfile>,
    /// Pre-resolved sink identity snapshots keyed by sink identifier.
    snapshots: HashMap<String, MultiSinkIdentitySnapshotV1>,
    /// Pre-resolved continuity windows keyed by boundary identifier.
    ///
    /// For config-backed resolution, each sink ID also serves as a
    /// boundary ID for its continuity window.
    windows: HashMap<String, ResolvedContinuityWindow>,
}

impl ConfigBackedResolver {
    /// Creates a new `ConfigBackedResolver` from validated sink profile
    /// configurations.
    ///
    /// This constructor decodes hex-encoded trusted signer keys and
    /// builds the internal lookup maps. It assumes that
    /// [`apm2_core::config::ProjectionConfig::validate_sink_profiles`] has
    /// already been called during config parsing (which happens at daemon
    /// startup).
    ///
    /// # Errors
    ///
    /// Returns an error if hex decoding or key parsing fails. In
    /// practice this should not happen if config validation passed,
    /// but we maintain fail-closed semantics by propagating errors
    /// rather than silently ignoring them.
    pub fn from_config(
        sinks: &HashMap<String, ProjectionSinkProfileConfig>,
    ) -> Result<Self, ConfigResolverError> {
        let mut profiles = HashMap::with_capacity(sinks.len());
        let mut windows = HashMap::with_capacity(sinks.len());

        // Collect per-sink decoded key material so we can build the
        // aggregate snapshot deterministically across ALL sinks.
        let mut decoded_keys: Vec<(String, Vec<[u8; 32]>)> = Vec::with_capacity(sinks.len());

        for (sink_id, config) in sinks {
            // Decode trusted signer keys (already validated at config
            // parse time, but we still propagate errors for defense in
            // depth).
            let mut trusted_signer_keys = Vec::with_capacity(config.trusted_signers.len());
            for (i, hex_key) in config.trusted_signers.iter().enumerate() {
                let bytes =
                    hex::decode(hex_key).map_err(|e| ConfigResolverError::InvalidSignerKey {
                        sink_id: sink_id.clone(),
                        index: i,
                        reason: format!("hex decode: {e}"),
                    })?;
                let key_bytes: [u8; 32] =
                    bytes
                        .try_into()
                        .map_err(|_| ConfigResolverError::InvalidSignerKey {
                            sink_id: sink_id.clone(),
                            index: i,
                            reason: "decoded key is not 32 bytes".to_string(),
                        })?;
                trusted_signer_keys.push(key_bytes);
            }

            let profile = ResolvedContinuityProfile {
                sink_id: sink_id.clone(),
                outage_window_ticks: config.outage_window_ticks,
                replay_window_ticks: config.replay_window_ticks,
                churn_tolerance: config.churn_tolerance,
                partition_tolerance: config.partition_tolerance,
                trusted_signer_keys: trusted_signer_keys.clone(),
            };

            // Build a continuity window for this sink using the sink ID
            // as the boundary ID.
            let window = ResolvedContinuityWindow {
                boundary_id: sink_id.clone(),
                outage_window_ticks: config.outage_window_ticks,
                replay_window_ticks: config.replay_window_ticks,
            };

            decoded_keys.push((sink_id.clone(), trusted_signer_keys));
            profiles.insert(sink_id.clone(), profile);
            windows.insert(sink_id.clone(), window);
        }

        // Build the aggregate multi-sink identity snapshot containing
        // ALL configured sinks, sorted deterministically by sink_id.
        // RFC-0029 REQ-0009 requires at least 2 distinct sinks for
        // meaningful multi-sink continuity scenarios. Each per-sink
        // resolution returns this same complete snapshot.
        decoded_keys.sort_by(|(a, _), (b, _)| a.cmp(b));
        let mut all_entries: Vec<SinkIdentityEntry> = Vec::with_capacity(decoded_keys.len());
        for (sink_id, keys) in &decoded_keys {
            let identity_digest = compute_sink_identity_digest(sink_id, keys);
            all_entries.push(SinkIdentityEntry {
                sink_id: sink_id.clone(),
                identity_digest,
            });
        }
        let mut aggregate_snapshot = MultiSinkIdentitySnapshotV1 {
            sink_identities: all_entries,
            snapshot_digest: [0u8; 32],
        };
        aggregate_snapshot.snapshot_digest = aggregate_snapshot.compute_digest();

        // Store the same aggregate snapshot for every sink key so that
        // resolve_sink_snapshot(any_configured_sink_id) returns the
        // complete multi-sink snapshot.
        let mut snapshots = HashMap::with_capacity(decoded_keys.len());
        for (sink_id, _) in &decoded_keys {
            snapshots.insert(sink_id.clone(), aggregate_snapshot.clone());
        }

        Ok(Self {
            profiles,
            snapshots,
            windows,
        })
    }

    /// Returns the number of configured sink profiles.
    #[must_use]
    pub fn sink_count(&self) -> usize {
        self.profiles.len()
    }
}

impl ContinuityProfileResolver for ConfigBackedResolver {
    fn resolve_continuity_profile(&self, sink_id: &str) -> Option<ResolvedContinuityProfile> {
        self.profiles.get(sink_id).cloned()
    }

    fn resolve_sink_snapshot(&self, sink_id: &str) -> Option<MultiSinkIdentitySnapshotV1> {
        self.snapshots.get(sink_id).cloned()
    }

    fn resolve_continuity_window(&self, boundary_id: &str) -> Option<ResolvedContinuityWindow> {
        self.windows.get(boundary_id).cloned()
    }
}

// ============================================================================
// Error types
// ============================================================================

/// Errors from `ConfigBackedResolver` construction.
#[derive(Debug, thiserror::Error)]
pub enum ConfigResolverError {
    /// A trusted signer key failed to decode or validate.
    #[error("invalid trusted signer key for sink '{sink_id}' at index {index}: {reason}")]
    InvalidSignerKey {
        /// Sink identifier.
        sink_id: String,
        /// Index within the `trusted_signers` list.
        index: usize,
        /// Descriptive reason for the failure.
        reason: String,
    },
}

// ============================================================================
// Helpers
// ============================================================================

/// Computes a deterministic identity digest for a sink based on its ID
/// and trusted signer key material.
///
/// The digest is a Blake3 hash over:
/// - 4-byte big-endian length prefix of `sink_id`
/// - UTF-8 bytes of `sink_id`
/// - 4-byte big-endian count of trusted signer keys
/// - Each 32-byte signer key in order
///
/// This provides a content-addressed binding between a sink's identity
/// and its trust configuration.
#[allow(clippy::cast_possible_truncation)]
fn compute_sink_identity_digest(sink_id: &str, trusted_signer_keys: &[[u8; 32]]) -> Hash {
    let mut canonical = Vec::new();
    canonical.extend_from_slice(&(sink_id.len() as u32).to_be_bytes());
    canonical.extend_from_slice(sink_id.as_bytes());
    canonical.extend_from_slice(&(trusted_signer_keys.len() as u32).to_be_bytes());
    for key in trusted_signer_keys {
        canonical.extend_from_slice(key);
    }
    EventHasher::hash_content(&canonical)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// A valid Ed25519 public key for testing (the public key from the
    /// well-known test vector seed of all-zeros).
    fn valid_test_key_hex() -> String {
        // Generate a real key pair for testing.
        let signer = apm2_core::crypto::Signer::generate();
        hex::encode(signer.public_key_bytes())
    }

    /// Returns a second distinct valid key for multi-signer tests.
    fn valid_test_key_hex_2() -> String {
        let signer = apm2_core::crypto::Signer::generate();
        hex::encode(signer.public_key_bytes())
    }

    fn make_sink_config(
        outage: u64,
        replay: u64,
        churn: u32,
        partition: u32,
        signers: Vec<String>,
    ) -> ProjectionSinkProfileConfig {
        ProjectionSinkProfileConfig {
            outage_window_ticks: outage,
            replay_window_ticks: replay,
            churn_tolerance: churn,
            partition_tolerance: partition,
            trusted_signers: signers,
        }
    }

    // ===================================================================
    // ConfigBackedResolver: config present -> valid resolution
    // ===================================================================

    /// UT-00507-01: Resolver returns profile for a configured sink.
    #[test]
    fn resolver_returns_profile_for_configured_sink() {
        let key_hex = valid_test_key_hex();
        let mut sinks = HashMap::new();
        sinks.insert(
            "github-primary".to_string(),
            make_sink_config(3_600_000_000, 7_200_000_000, 3, 2, vec![key_hex.clone()]),
        );

        let resolver =
            ConfigBackedResolver::from_config(&sinks).expect("resolver construction must succeed");
        assert_eq!(resolver.sink_count(), 1);

        let profile = resolver
            .resolve_continuity_profile("github-primary")
            .expect("profile must be present");
        assert_eq!(profile.sink_id, "github-primary");
        assert_eq!(profile.outage_window_ticks, 3_600_000_000);
        assert_eq!(profile.replay_window_ticks, 7_200_000_000);
        assert_eq!(profile.churn_tolerance, 3);
        assert_eq!(profile.partition_tolerance, 2);
        assert_eq!(profile.trusted_signer_keys.len(), 1);

        let expected_key_bytes = hex::decode(&key_hex).unwrap();
        assert_eq!(
            profile.trusted_signer_keys[0],
            expected_key_bytes.as_slice()
        );
    }

    /// UT-00507-02: Resolver returns sink snapshot for a configured sink.
    #[test]
    fn resolver_returns_snapshot_for_configured_sink() {
        let key_hex = valid_test_key_hex();
        let mut sinks = HashMap::new();
        sinks.insert(
            "github-primary".to_string(),
            make_sink_config(1_000_000, 2_000_000, 1, 1, vec![key_hex]),
        );

        let resolver =
            ConfigBackedResolver::from_config(&sinks).expect("resolver construction must succeed");

        let snapshot = resolver
            .resolve_sink_snapshot("github-primary")
            .expect("snapshot must be present");
        assert_eq!(snapshot.sink_identities.len(), 1);
        assert_eq!(snapshot.sink_identities[0].sink_id, "github-primary");
        // Snapshot digest must be non-zero.
        assert_ne!(snapshot.snapshot_digest, [0u8; 32]);
        // Digest must verify.
        assert!(snapshot.verify_digest().is_ok());
    }

    /// UT-00507-03: Resolver returns continuity window for a configured sink.
    #[test]
    fn resolver_returns_window_for_configured_sink() {
        let key_hex = valid_test_key_hex();
        let mut sinks = HashMap::new();
        sinks.insert(
            "github-primary".to_string(),
            make_sink_config(3_600_000, 7_200_000, 2, 1, vec![key_hex]),
        );

        let resolver =
            ConfigBackedResolver::from_config(&sinks).expect("resolver construction must succeed");

        let window = resolver
            .resolve_continuity_window("github-primary")
            .expect("window must be present");
        assert_eq!(window.boundary_id, "github-primary");
        assert_eq!(window.outage_window_ticks, 3_600_000);
        assert_eq!(window.replay_window_ticks, 7_200_000);
    }

    /// UT-00507-04: Profile fields map directly to economics module input
    /// types without lossy conversion (u64 ticks, u32 tolerances, [u8;32]
    /// keys).
    #[test]
    fn profile_fields_map_to_economics_types() {
        let key_hex = valid_test_key_hex();
        let key_bytes: [u8; 32] = hex::decode(&key_hex).unwrap().try_into().unwrap();
        let mut sinks = HashMap::new();
        sinks.insert(
            "github-primary".to_string(),
            make_sink_config(
                u64::MAX,
                u64::MAX - 1,
                u32::MAX,
                u32::MAX - 1,
                vec![key_hex],
            ),
        );

        let resolver =
            ConfigBackedResolver::from_config(&sinks).expect("resolver construction must succeed");
        let profile = resolver
            .resolve_continuity_profile("github-primary")
            .expect("profile must be present");

        // Verify no truncation or lossy conversion occurred.
        assert_eq!(profile.outage_window_ticks, u64::MAX);
        assert_eq!(profile.replay_window_ticks, u64::MAX - 1);
        assert_eq!(profile.churn_tolerance, u32::MAX);
        assert_eq!(profile.partition_tolerance, u32::MAX - 1);
        assert_eq!(profile.trusted_signer_keys[0], key_bytes);
    }

    /// UT-00507-05: Multiple trusted signers are preserved in order.
    #[test]
    fn multiple_trusted_signers_preserved_in_order() {
        let key1 = valid_test_key_hex();
        let key2 = valid_test_key_hex_2();
        let mut sinks = HashMap::new();
        sinks.insert(
            "github-primary".to_string(),
            make_sink_config(100, 200, 1, 1, vec![key1.clone(), key2.clone()]),
        );

        let resolver =
            ConfigBackedResolver::from_config(&sinks).expect("resolver construction must succeed");
        let profile = resolver
            .resolve_continuity_profile("github-primary")
            .expect("profile must be present");

        assert_eq!(profile.trusted_signer_keys.len(), 2);
        let expected_key1: [u8; 32] = hex::decode(&key1).unwrap().try_into().unwrap();
        let expected_key2: [u8; 32] = hex::decode(&key2).unwrap().try_into().unwrap();
        assert_eq!(profile.trusted_signer_keys[0], expected_key1);
        assert_eq!(profile.trusted_signer_keys[1], expected_key2);
    }

    // ===================================================================
    // ConfigBackedResolver: config missing -> None (fail-closed)
    // ===================================================================

    /// UT-00507-06: Missing sink config returns None for profile.
    #[test]
    fn missing_sink_returns_none_for_profile() {
        let resolver =
            ConfigBackedResolver::from_config(&HashMap::new()).expect("empty config is valid");
        assert!(resolver.resolve_continuity_profile("nonexistent").is_none());
    }

    /// UT-00507-07: Missing sink config returns None for snapshot.
    #[test]
    fn missing_sink_returns_none_for_snapshot() {
        let resolver =
            ConfigBackedResolver::from_config(&HashMap::new()).expect("empty config is valid");
        assert!(resolver.resolve_sink_snapshot("nonexistent").is_none());
    }

    /// UT-00507-08: Missing sink config returns None for window.
    #[test]
    fn missing_sink_returns_none_for_window() {
        let resolver =
            ConfigBackedResolver::from_config(&HashMap::new()).expect("empty config is valid");
        assert!(resolver.resolve_continuity_window("nonexistent").is_none());
    }

    /// UT-00507-09: Resolver with one sink returns None for a different
    /// sink ID.
    #[test]
    fn wrong_sink_id_returns_none() {
        let key_hex = valid_test_key_hex();
        let mut sinks = HashMap::new();
        sinks.insert(
            "github-primary".to_string(),
            make_sink_config(100, 200, 1, 1, vec![key_hex]),
        );

        let resolver =
            ConfigBackedResolver::from_config(&sinks).expect("resolver construction must succeed");
        assert!(
            resolver
                .resolve_continuity_profile("gitlab-secondary")
                .is_none()
        );
        assert!(resolver.resolve_sink_snapshot("gitlab-secondary").is_none());
        assert!(
            resolver
                .resolve_continuity_window("gitlab-secondary")
                .is_none()
        );
    }

    // ===================================================================
    // Config validation: malformed config fails at startup
    // ===================================================================

    /// UT-00507-10: Valid hex key passes config validation.
    #[test]
    fn config_valid_hex_key_passes() {
        let key_hex = valid_test_key_hex();
        let config = apm2_core::config::ProjectionConfig {
            sinks: {
                let mut m = HashMap::new();
                m.insert(
                    "github-primary".to_string(),
                    make_sink_config(100, 200, 1, 1, vec![key_hex]),
                );
                m
            },
            ..Default::default()
        };
        assert!(config.validate_sink_profiles().is_ok());
    }

    /// UT-00507-11: Odd-length hex fails config validation at startup.
    #[test]
    fn config_odd_length_hex_fails() {
        let config = apm2_core::config::ProjectionConfig {
            sinks: {
                let mut m = HashMap::new();
                m.insert(
                    "github-primary".to_string(),
                    make_sink_config(100, 200, 1, 1, vec!["abc".to_string()]),
                );
                m
            },
            ..Default::default()
        };
        let err = config.validate_sink_profiles().expect_err("must fail");
        assert!(err.contains("odd-length hex"), "error: {err}");
    }

    /// UT-00507-12: Non-hex characters fail config validation at startup.
    #[test]
    fn config_non_hex_chars_fails() {
        let config = apm2_core::config::ProjectionConfig {
            sinks: {
                let mut m = HashMap::new();
                m.insert(
                    "github-primary".to_string(),
                    make_sink_config(
                        100,
                        200,
                        1,
                        1,
                        vec![
                            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
                                .to_string(),
                        ],
                    ),
                );
                m
            },
            ..Default::default()
        };
        let err = config.validate_sink_profiles().expect_err("must fail");
        assert!(err.contains("invalid hex"), "error: {err}");
    }

    /// UT-00507-13: Wrong key length (not 32 bytes) fails config
    /// validation at startup.
    #[test]
    fn config_wrong_key_length_fails() {
        // 16 bytes = 32 hex chars (not 64 hex = 32 bytes).
        let short_key = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4";
        assert_eq!(short_key.len(), 32); // 32 hex chars = 16 bytes
        let config = apm2_core::config::ProjectionConfig {
            sinks: {
                let mut m = HashMap::new();
                m.insert(
                    "github-primary".to_string(),
                    make_sink_config(100, 200, 1, 1, vec![short_key.to_string()]),
                );
                m
            },
            ..Default::default()
        };
        let err = config.validate_sink_profiles().expect_err("must fail");
        assert!(err.contains("16 bytes, expected 32"), "error: {err}");
    }

    /// UT-00507-14: Empty trusted signers list fails config validation
    /// at startup.
    #[test]
    fn config_empty_signers_fails() {
        let config = apm2_core::config::ProjectionConfig {
            sinks: {
                let mut m = HashMap::new();
                m.insert(
                    "github-primary".to_string(),
                    make_sink_config(100, 200, 1, 1, vec![]),
                );
                m
            },
            ..Default::default()
        };
        let err = config.validate_sink_profiles().expect_err("must fail");
        assert!(err.contains("must not be empty"), "error: {err}");
    }

    /// UT-00507-15: Zero `outage_window_ticks` fails validation.
    #[test]
    fn config_zero_outage_window_ticks_fails() {
        let key_hex = valid_test_key_hex();
        let config = apm2_core::config::ProjectionConfig {
            sinks: {
                let mut m = HashMap::new();
                m.insert(
                    "github-primary".to_string(),
                    make_sink_config(0, 200, 1, 1, vec![key_hex]),
                );
                m
            },
            ..Default::default()
        };
        let err = config.validate_sink_profiles().expect_err("must fail");
        assert!(
            err.contains("outage_window_ticks must be > 0"),
            "error: {err}"
        );
    }

    /// UT-00507-16: Zero `replay_window_ticks` fails validation.
    #[test]
    fn config_zero_replay_window_ticks_fails() {
        let key_hex = valid_test_key_hex();
        let config = apm2_core::config::ProjectionConfig {
            sinks: {
                let mut m = HashMap::new();
                m.insert(
                    "github-primary".to_string(),
                    make_sink_config(100, 0, 1, 1, vec![key_hex]),
                );
                m
            },
            ..Default::default()
        };
        let err = config.validate_sink_profiles().expect_err("must fail");
        assert!(
            err.contains("replay_window_ticks must be > 0"),
            "error: {err}"
        );
    }

    // ===================================================================
    // TOML integration: full round-trip through EcosystemConfig
    // ===================================================================

    /// UT-00507-17: Sink profile parsed from TOML and resolved correctly.
    #[test]
    fn toml_sink_profile_round_trip() {
        let key_hex = valid_test_key_hex();
        let toml_str = format!(
            r#"
            [daemon]
            operator_socket = "/tmp/apm2/operator.sock"
            session_socket = "/tmp/apm2/session.sock"

            [daemon.projection.sinks.github-primary]
            outage_window_ticks = 3600000000
            replay_window_ticks = 7200000000
            churn_tolerance = 3
            partition_tolerance = 2
            trusted_signers = ["{key_hex}"]

            [[processes]]
            name = "test"
            command = "echo"
            "#,
        );

        let config = apm2_core::config::EcosystemConfig::from_toml(&toml_str)
            .expect("config must parse and validate");

        assert_eq!(config.daemon.projection.sinks.len(), 1);
        let sink = config
            .daemon
            .projection
            .sinks
            .get("github-primary")
            .expect("sink must be present");
        assert_eq!(sink.outage_window_ticks, 3_600_000_000);
        assert_eq!(sink.replay_window_ticks, 7_200_000_000);
        assert_eq!(sink.churn_tolerance, 3);
        assert_eq!(sink.partition_tolerance, 2);
        assert_eq!(sink.trusted_signers.len(), 1);
        assert_eq!(sink.trusted_signers[0], key_hex);

        // Now verify the resolver works with this config.
        let resolver = ConfigBackedResolver::from_config(&config.daemon.projection.sinks)
            .expect("resolver must construct");
        assert!(
            resolver
                .resolve_continuity_profile("github-primary")
                .is_some()
        );
    }

    /// UT-00507-18: Malformed hex key in TOML causes startup failure.
    #[test]
    fn toml_malformed_key_fails_at_parse_time() {
        let toml_str = r#"
            [daemon]
            operator_socket = "/tmp/apm2/operator.sock"
            session_socket = "/tmp/apm2/session.sock"

            [daemon.projection.sinks.github-primary]
            outage_window_ticks = 3600000000
            replay_window_ticks = 7200000000
            churn_tolerance = 3
            partition_tolerance = 2
            trusted_signers = ["not_valid_hex_at_all!!"]

            [[processes]]
            name = "test"
            command = "echo"
        "#;

        let err = apm2_core::config::EcosystemConfig::from_toml(toml_str)
            .expect_err("must fail with invalid key");
        match err {
            apm2_core::config::ConfigError::Validation(msg) => {
                assert!(msg.contains("invalid hex"), "error: {msg}");
            },
            other => panic!("expected ConfigError::Validation, got: {other:?}"),
        }
    }

    /// UT-00507-19: Empty sinks map in TOML is accepted (no sinks
    /// configured).
    #[test]
    fn toml_empty_sinks_accepted() {
        let toml_str = r#"
            [daemon]
            operator_socket = "/tmp/apm2/operator.sock"
            session_socket = "/tmp/apm2/session.sock"

            [[processes]]
            name = "test"
            command = "echo"
        "#;

        let config =
            apm2_core::config::EcosystemConfig::from_toml(toml_str).expect("config must parse");
        assert!(config.daemon.projection.sinks.is_empty());
    }

    /// UT-00507-20: Snapshot digest is deterministic for the same input.
    #[test]
    fn snapshot_digest_deterministic() {
        let key_hex = valid_test_key_hex();
        let mut sinks = HashMap::new();
        sinks.insert(
            "github-primary".to_string(),
            make_sink_config(100, 200, 1, 1, vec![key_hex]),
        );

        let resolver1 = ConfigBackedResolver::from_config(&sinks).unwrap();
        let resolver2 = ConfigBackedResolver::from_config(&sinks).unwrap();

        let snap1 = resolver1.resolve_sink_snapshot("github-primary").unwrap();
        let snap2 = resolver2.resolve_sink_snapshot("github-primary").unwrap();

        assert_eq!(snap1.snapshot_digest, snap2.snapshot_digest);
        assert_eq!(snap1.sink_identities, snap2.sink_identities);
    }

    /// UT-00507-21: Identity digest changes when trusted signers change.
    #[test]
    fn identity_digest_changes_with_signers() {
        let key1 = valid_test_key_hex();
        let key2 = valid_test_key_hex_2();

        let mut sinks1 = HashMap::new();
        sinks1.insert(
            "github-primary".to_string(),
            make_sink_config(100, 200, 1, 1, vec![key1]),
        );

        let mut sinks2 = HashMap::new();
        sinks2.insert(
            "github-primary".to_string(),
            make_sink_config(100, 200, 1, 1, vec![key2]),
        );

        let resolver1 = ConfigBackedResolver::from_config(&sinks1).unwrap();
        let resolver2 = ConfigBackedResolver::from_config(&sinks2).unwrap();

        let snap1 = resolver1.resolve_sink_snapshot("github-primary").unwrap();
        let snap2 = resolver2.resolve_sink_snapshot("github-primary").unwrap();

        // Different signers must produce different identity digests.
        assert_ne!(
            snap1.sink_identities[0].identity_digest,
            snap2.sink_identities[0].identity_digest
        );
        assert_ne!(snap1.snapshot_digest, snap2.snapshot_digest);
    }

    // ===================================================================
    // Multi-sink aggregate snapshot (BLOCKER fix verification)
    // ===================================================================

    /// UT-00507-22: Aggregate snapshot contains ALL configured sinks,
    /// sorted deterministically by `sink_id`.
    #[test]
    fn multi_sink_aggregate_snapshot_contains_all_sinks_sorted() {
        let key1 = valid_test_key_hex();
        let key2 = valid_test_key_hex_2();
        let mut sinks = HashMap::new();
        // Insert in non-sorted order to verify deterministic sorting.
        sinks.insert(
            "zeta-sink".to_string(),
            make_sink_config(100, 200, 1, 1, vec![key1]),
        );
        sinks.insert(
            "alpha-sink".to_string(),
            make_sink_config(300, 400, 2, 2, vec![key2]),
        );

        let resolver =
            ConfigBackedResolver::from_config(&sinks).expect("resolver construction must succeed");
        assert_eq!(resolver.sink_count(), 2);

        // Both sinks resolve to the SAME aggregate snapshot.
        let snap_alpha = resolver
            .resolve_sink_snapshot("alpha-sink")
            .expect("snapshot must be present");
        let snap_zeta = resolver
            .resolve_sink_snapshot("zeta-sink")
            .expect("snapshot must be present");

        // Same snapshot for both lookups.
        assert_eq!(snap_alpha, snap_zeta);

        // Contains all sinks in sorted order.
        assert_eq!(snap_alpha.sink_identities.len(), 2);
        assert_eq!(snap_alpha.sink_identities[0].sink_id, "alpha-sink");
        assert_eq!(snap_alpha.sink_identities[1].sink_id, "zeta-sink");

        // Digest is non-zero and verifies.
        assert_ne!(snap_alpha.snapshot_digest, [0u8; 32]);
        assert!(snap_alpha.verify_digest().is_ok());

        // Satisfies multi-sink validation (>= 2 distinct sinks).
        assert!(snap_alpha.validate().is_ok());
    }

    /// UT-00507-23: Single-sink snapshot still has one entry but the
    /// snapshot is the complete aggregate (which happens to be 1 sink).
    #[test]
    fn single_sink_snapshot_is_complete_aggregate() {
        let key_hex = valid_test_key_hex();
        let mut sinks = HashMap::new();
        sinks.insert(
            "only-sink".to_string(),
            make_sink_config(100, 200, 1, 1, vec![key_hex]),
        );

        let resolver =
            ConfigBackedResolver::from_config(&sinks).expect("resolver construction must succeed");

        let snapshot = resolver
            .resolve_sink_snapshot("only-sink")
            .expect("snapshot must be present");
        assert_eq!(snapshot.sink_identities.len(), 1);
        assert_eq!(snapshot.sink_identities[0].sink_id, "only-sink");
        assert!(snapshot.verify_digest().is_ok());
    }

    /// UT-00507-24: Aggregate snapshot digest is deterministic across
    /// multiple constructions with the same config (`HashMap` iteration
    /// order independence).
    #[test]
    fn aggregate_snapshot_deterministic_across_constructions() {
        let key1 = valid_test_key_hex();
        let key2 = valid_test_key_hex_2();
        let mut sinks = HashMap::new();
        sinks.insert(
            "sink-b".to_string(),
            make_sink_config(100, 200, 1, 1, vec![key1]),
        );
        sinks.insert(
            "sink-a".to_string(),
            make_sink_config(300, 400, 2, 2, vec![key2]),
        );

        let resolver1 = ConfigBackedResolver::from_config(&sinks).unwrap();
        let resolver2 = ConfigBackedResolver::from_config(&sinks).unwrap();

        let snap1 = resolver1.resolve_sink_snapshot("sink-a").unwrap();
        let snap2 = resolver2.resolve_sink_snapshot("sink-a").unwrap();

        assert_eq!(snap1.snapshot_digest, snap2.snapshot_digest);
        assert_eq!(snap1.sink_identities, snap2.sink_identities);
    }
}
