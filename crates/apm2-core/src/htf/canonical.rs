// AGENT-AUTHORED
//! Canonicalization logic for HTF types.
//!
//! This module implements the canonicalization strategy for HTF artifacts
//! ([`ClockProfile`](crate::htf::ClockProfile),
//! [`TimeEnvelope`](crate::htf::TimeEnvelope), etc.) to ensure deterministic
//! hashing and signing.
//!
//! # Strategy
//!
//! We follow the RFC 8785 (JSON Canonicalization Scheme) principles:
//! 1. Keys are sorted lexicographically.
//! 2. No insignificant whitespace.
//! 3. Deterministic number formatting.
//!
//! Implementation relies on `serde_json::Value` (which uses `BTreeMap` for
//! objects, ensuring sorted keys) and `serde_json::to_vec` (which produces
//! compact JSON).

use serde::Serialize;
use thiserror::Error;

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during canonicalization.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CanonicalizationError {
    /// Serialization failed.
    #[error("serialization failed: {0}")]
    Serialization(String),
}

// =============================================================================
// Canonicalizable Trait
// =============================================================================

/// Trait for types that can be canonicalized to a deterministic byte sequence.
pub trait Canonicalizable {
    /// Returns the canonical byte representation of the object.
    ///
    /// # Errors
    ///
    /// Returns [`CanonicalizationError`] if serialization fails.
    fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalizationError>;

    /// Returns the BLAKE3 hash of the canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CanonicalizationError`] if canonicalization fails.
    fn canonical_hash(&self) -> Result<[u8; 32], CanonicalizationError> {
        let bytes = self.canonical_bytes()?;
        Ok(blake3::hash(&bytes).into())
    }
}

// Blanket implementation for any Serialize type.
// We use `serde_json::Value` to ensure key sorting.
impl<T: Serialize> Canonicalizable for T {
    fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalizationError> {
        // Convert to serde_json::Value to force key sorting (BTreeMap)
        let value = serde_json::to_value(self)
            .map_err(|e| CanonicalizationError::Serialization(e.to_string()))?;

        // Serialize the Value to compact JSON (no whitespace)
        serde_json::to_vec(&value).map_err(|e| CanonicalizationError::Serialization(e.to_string()))
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::htf::{
        BoundedWallInterval, ClockProfile, Hlc, LedgerTime, MonotonicReading, MonotonicSource,
        TimeEnvelope, WallTimeSource,
    };

    #[test]
    fn test_canonical_sorts_keys() {
        #[derive(Serialize)]
        struct TestStruct {
            z: i32,
            a: i32,
        }

        let s = TestStruct { z: 1, a: 2 };
        let bytes = s.canonical_bytes().unwrap();
        let json = String::from_utf8(bytes).unwrap();

        // Should be {"a":2,"z":1} not {"z":1,"a":2}
        assert_eq!(json, r#"{"a":2,"z":1}"#);
    }

    #[test]
    fn test_clock_profile_canonicalization() {
        let profile = ClockProfile {
            profile_policy_id: "test-policy".to_string(),
            tick_rate_hz: 1_000_000,
            monotonic_source: MonotonicSource::ClockMonotonicRaw,
            hlc_enabled: true,
            wall_time_source: WallTimeSource::AuthenticatedNts,
            max_wall_uncertainty_ns: 1_000_000,
            build_fingerprint: "sha256:abcd...".to_string(),
            attestation: None,
        };

        let bytes = profile.canonical_bytes().unwrap();
        let json = String::from_utf8(bytes).unwrap();

        // Verify keys are sorted
        // expected: build_fingerprint, hlc_enabled, max_wall_uncertainty_ns,
        // monotonic_source, profile_policy_id, tick_rate_hz, wall_time_source
        // Note: attestation is skipped (None)

        let expected = r#"{"build_fingerprint":"sha256:abcd...","hlc_enabled":true,"max_wall_uncertainty_ns":1000000,"monotonic_source":"CLOCK_MONOTONIC_RAW","profile_policy_id":"test-policy","tick_rate_hz":1000000,"wall_time_source":"AUTHENTICATED_NTS"}"#;

        assert_eq!(json, expected);
    }

    #[test]
    fn test_time_envelope_canonicalization() {
        let env = TimeEnvelope {
            clock_profile_hash: "hash-123".to_string(),
            hlc: Hlc {
                logical: 10,
                wall_ns: 2000,
            },
            ledger_anchor: LedgerTime::new("ledger-1", 1, 100),
            mono: MonotonicReading {
                start_tick: 500,
                end_tick: Some(600),
                tick_rate_hz: 1000,
                source: MonotonicSource::ClockMonotonic,
            },
            wall: BoundedWallInterval::new(1000, 2000, WallTimeSource::Roughtime, "high").unwrap(),
            notes: Some("test note".to_string()),
        };

        let bytes = env.canonical_bytes().unwrap();
        let json = String::from_utf8(bytes).unwrap();

        // Verify structure and sorting
        // Keys: clock_profile_hash, hlc, ledger_anchor, mono, notes, wall
        // ledger_anchor keys: epoch, ledger_id, seq
        // wall keys: confidence, source, t_max_utc_ns, t_min_utc_ns

        assert!(json.contains(r#""clock_profile_hash":"hash-123""#));
        assert!(json.contains(r#""epoch":1,"ledger_id":"ledger-1","seq":100"#)); // LedgerTime sorted
        assert!(json.contains(
            r#""confidence":"high","source":"ROUGHTIME","t_max_utc_ns":2000,"t_min_utc_ns":1000"#
        )); // Wall sorted
    }

    #[test]
    #[cfg(feature = "test_vectors")]
    fn verify_vectors() {
        use std::fs;
        use std::path::PathBuf;

        // Helper to load vectors
        fn load_vectors<T: serde::de::DeserializeOwned>(name: &str) -> Vec<VectorCase<T>> {
            let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .parent() // crates
                .unwrap()
                .parent() // workspace
                .unwrap()
                .to_path_buf();

            let path = root.join("evidence/htf/vectors").join(name);
            let content = fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("failed to read vector file {}: {}", path.display(), e));

            serde_json::from_str(&content).expect("failed to parse vectors")
        }

        #[derive(serde::Deserialize)]
        struct VectorCase<T> {
            description: String,
            input: T,
            canonical_json: String,
            canonical_hash_hex: String,
        }

        // Verify ClockProfile
        let cases: Vec<VectorCase<ClockProfile>> = load_vectors("clock_profile_v1.json");
        for case in cases {
            let bytes = case.input.canonical_bytes().expect("canonicalize failed");
            let json = String::from_utf8(bytes.clone()).expect("utf8");
            assert_eq!(
                json, case.canonical_json,
                "JSON mismatch for {}",
                case.description
            );

            let hash = blake3::hash(&bytes);
            assert_eq!(
                hash.to_hex().as_str(),
                case.canonical_hash_hex,
                "Hash mismatch for {}",
                case.description
            );
        }

        // Verify TimeEnvelope
        let cases: Vec<VectorCase<TimeEnvelope>> = load_vectors("time_envelope_v1.json");
        for case in cases {
            let bytes = case.input.canonical_bytes().expect("canonicalize failed");
            let json = String::from_utf8(bytes.clone()).expect("utf8");
            assert_eq!(
                json, case.canonical_json,
                "JSON mismatch for {}",
                case.description
            );

            let hash = blake3::hash(&bytes);
            assert_eq!(
                hash.to_hex().as_str(),
                case.canonical_hash_hex,
                "Hash mismatch for {}",
                case.description
            );
        }
    }
}
