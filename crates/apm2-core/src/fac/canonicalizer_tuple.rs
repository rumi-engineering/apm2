use std::convert::TryFrom;

use serde::{Deserialize, Serialize};

use crate::determinism::{CANONICALIZER_ID, CANONICALIZER_VERSION, MAX_DEPTH, canonicalize_json};

/// Schema identifier for canonicalizer tuple artifacts.
pub const CANONICALIZER_TUPLE_SCHEMA: &str = "apm2.canonicalizer_tuple.v1";

/// Canonicalization semantics used for digest computation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CanonicalizerTupleV1 {
    /// Schema identifier.
    pub schema: String,

    /// Canonicalizer identifier.
    pub canonicalizer_id: String,

    /// Canonicalizer version.
    pub canonicalizer_version: String,

    /// Hash algorithm name.
    pub hash_algorithm: String,

    /// Digest format used for canonicalized output.
    pub digest_format: String,

    /// Maximum JSON nesting depth.
    pub max_depth: u32,
}

impl CanonicalizerTupleV1 {
    /// Build from current codebase constants.
    ///
    /// # Panics
    ///
    /// Panics if `MAX_DEPTH` cannot be represented as `u32` (in practice,
    /// this is only possible if `MAX_DEPTH` is misconfigured).
    #[must_use]
    pub fn from_current() -> Self {
        let max_depth = u32::try_from(MAX_DEPTH)
            .unwrap_or_else(|_| panic!("MAX_DEPTH must fit into u32: {MAX_DEPTH}"));
        Self {
            schema: CANONICALIZER_TUPLE_SCHEMA.to_string(),
            canonicalizer_id: CANONICALIZER_ID.to_string(),
            canonicalizer_version: CANONICALIZER_VERSION.to_string(),
            hash_algorithm: "blake3".to_string(),
            digest_format: "b3-256".to_string(),
            max_depth,
        }
    }

    /// Compute canonical, content-addressed digest of this tuple.
    ///
    /// # Panics
    ///
    /// Panics if serialization/canonicalization fails unexpectedly.
    #[must_use]
    pub fn compute_digest(&self) -> String {
        let json = serde_json::to_string(self).expect("tuple serializable");
        let canonical = canonicalize_json(&json).expect("tuple canonical");
        let hash = crate::fac::job_spec::compute_digest_bytes(
            CANONICALIZER_TUPLE_SCHEMA,
            canonical.as_bytes(),
        );
        crate::fac::job_spec::format_b3_256_digest(&hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalizer_tuple_roundtrip_serialize_deserialize() {
        let tuple = CanonicalizerTupleV1::from_current();
        let bytes = serde_json::to_vec_pretty(&tuple).expect("serialize tuple");
        let restored: CanonicalizerTupleV1 =
            serde_json::from_slice(&bytes).expect("deserialize tuple");

        assert_eq!(restored, tuple);
    }

    #[test]
    fn canonicalizer_tuple_digest_is_stable() {
        let tuple = CanonicalizerTupleV1::from_current();
        let first = tuple.compute_digest();
        let second = tuple.compute_digest();

        assert_eq!(first, second);
    }

    #[test]
    fn canonicalizer_tuple_digest_changes_with_version() {
        let mut tuple = CanonicalizerTupleV1::from_current();
        let first = tuple.compute_digest();

        tuple.canonicalizer_version.push_str("-modified");
        let second = tuple.compute_digest();

        assert_ne!(first, second);
        assert_ne!(first, tuple.compute_digest());
    }
}
