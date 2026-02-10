//! Canonical economics profile model for RFC-0029 REQ-0001.
//!
//! Profiles are hash-addressed, fail-closed budget matrices keyed by
//! `(RiskTier, BoundaryIntentClass)`. Canonical profile hashing uses:
//!
//! `BLAKE3(b"apm2-economics-profile-v1" || canonical_profile_json_bytes)`

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::determinism::canonicalize_json;
use crate::events::Canonicalize;
use crate::evidence::{CasError, ContentAddressedStore};
use crate::pcac::{BoundaryIntentClass, RiskTier};

const PROFILE_SCHEMA: &str = "apm2.economics_constraint_profile.v1";
const PROFILE_SCHEMA_VERSION: &str = "1.0.0";
const RISK_TIER_VARIANT_COUNT: usize = 3;
const BOUNDARY_INTENT_CLASS_VARIANT_COUNT: usize = 5;
const MAX_BUDGET_ENTRIES: usize = RISK_TIER_VARIANT_COUNT * BOUNDARY_INTENT_CLASS_VARIANT_COUNT;

/// Domain separator for deterministic economics profile hashing.
pub const ECONOMICS_PROFILE_HASH_DOMAIN: &[u8] = b"apm2-economics-profile-v1";

/// Lifecycle-stage cost vector from RFC-0029.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleCostVector {
    /// Join-stage cost (`C_join`).
    pub c_join: u64,
    /// Revalidate-stage cost (`C_revalidate`).
    pub c_revalidate: u64,
    /// Consume-stage cost (`C_consume`).
    pub c_consume: u64,
    /// Effect-stage cost (`C_effect`).
    pub c_effect: u64,
    /// Replay-stage cost (`C_replay`).
    pub c_replay: u64,
    /// Recovery-stage cost (`C_recovery`).
    pub c_recovery: u64,
}

/// Per-cell budget limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetEntry {
    /// Maximum tokens allowed.
    pub max_tokens: u64,
    /// Maximum tool calls allowed.
    pub max_tool_calls: u32,
    /// Maximum execution time in milliseconds.
    pub max_time_ms: u64,
    /// Maximum I/O bytes allowed.
    pub max_io_bytes: u64,
}

/// Profile state for economics inputs used to derive the active matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum EconomicsProfileInputState {
    /// Inputs are resolved and current.
    Current,
    /// Inputs are resolved but stale for authority-bearing use.
    Stale,
    /// Inputs are unresolved or ambiguous.
    Unresolved,
}

/// Canonical economics profile keyed by `(RiskTier, BoundaryIntentClass)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EconomicsProfile {
    /// Lifecycle-stage cost vector bound to this profile.
    pub lifecycle_cost_vector: LifecycleCostVector,
    /// Input freshness state for fail-closed admission.
    pub input_state: EconomicsProfileInputState,
    /// Budget matrix keyed by `(RiskTier, BoundaryIntentClass)`.
    pub budget_matrix: BTreeMap<(RiskTier, BoundaryIntentClass), BudgetEntry>,
}

impl Canonicalize for EconomicsProfile {
    fn canonicalize(&mut self) {
        // `BTreeMap` preserves deterministic key ordering.
    }
}

/// Errors for economics profile serialization, hashing, and CAS operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum EconomicsProfileError {
    /// Schema identifier mismatch.
    #[error("invalid economics profile schema: expected {expected}, got {actual}")]
    InvalidSchema {
        /// Expected schema identifier.
        expected: String,
        /// Actual schema identifier.
        actual: String,
    },

    /// Schema version mismatch.
    #[error("invalid economics profile schema version: expected {expected}, got {actual}")]
    InvalidSchemaVersion {
        /// Expected schema version.
        expected: String,
        /// Actual schema version.
        actual: String,
    },

    /// Duplicate budget key found while decoding profile wire bytes.
    #[error("duplicate budget entry for tier '{tier}' and intent class '{intent_class}'")]
    DuplicateBudgetEntry {
        /// Duplicate risk tier.
        tier: String,
        /// Duplicate boundary intent class.
        intent_class: String,
    },

    /// Budget entry count exceeds the finite matrix key space.
    #[error("budget entry count {count} exceeds maximum {max}")]
    BudgetEntriesTooLarge {
        /// Observed entry count.
        count: usize,
        /// Maximum supported entry count.
        max: usize,
    },

    /// Serialization or canonicalization failed.
    #[error("economics profile serialization failed: {message}")]
    Serialization {
        /// Error message.
        message: String,
    },

    /// Framed profile bytes are malformed.
    #[error("invalid economics profile frame: missing domain prefix")]
    InvalidFrame,

    /// CAS operation failed.
    #[error("CAS error: {0}")]
    Cas(#[from] CasError),

    /// Recomputed profile hash does not match expected hash.
    #[error("economics profile hash mismatch: expected {expected}, got {actual}")]
    HashMismatch {
        /// Expected hash (hex-encoded).
        expected: String,
        /// Actual hash (hex-encoded).
        actual: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EconomicsProfileWire {
    schema: String,
    schema_version: String,
    lifecycle_cost_vector: LifecycleCostVector,
    input_state: EconomicsProfileInputState,
    budget_entries: Vec<BudgetCell>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BudgetCell {
    risk_tier: RiskTier,
    intent_class: BoundaryIntentClass,
    budget: BudgetEntry,
}

impl EconomicsProfile {
    /// Creates a validated economics profile.
    ///
    /// # Errors
    ///
    /// Returns an error if profile validation fails.
    pub fn new(
        lifecycle_cost_vector: LifecycleCostVector,
        input_state: EconomicsProfileInputState,
        budget_matrix: BTreeMap<(RiskTier, BoundaryIntentClass), BudgetEntry>,
    ) -> Result<Self, EconomicsProfileError> {
        let profile = Self {
            lifecycle_cost_vector,
            input_state,
            budget_matrix,
        };
        profile.validate()?;
        Ok(profile)
    }

    /// Returns the budget entry for a `(tier, intent_class)` key.
    #[must_use]
    pub fn budget_entry(
        &self,
        tier: RiskTier,
        intent_class: BoundaryIntentClass,
    ) -> Option<&BudgetEntry> {
        self.budget_matrix.get(&(tier, intent_class))
    }

    /// Validates profile invariants.
    ///
    /// # Errors
    ///
    /// Returns an error if schema or structure checks fail.
    pub fn validate(&self) -> Result<(), EconomicsProfileError> {
        self.to_wire().validate()
    }

    /// Returns canonical profile JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization or canonicalization fails.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EconomicsProfileError> {
        let mut canonical = self.clone();
        canonical.canonicalize();

        let wire = canonical.to_wire();
        wire.validate()?;

        let json =
            serde_json::to_string(&wire).map_err(|error| EconomicsProfileError::Serialization {
                message: error.to_string(),
            })?;
        let canonical_json =
            canonicalize_json(&json).map_err(|error| EconomicsProfileError::Serialization {
                message: error.to_string(),
            })?;
        Ok(canonical_json.into_bytes())
    }

    /// Returns framed bytes used for CAS storage.
    ///
    /// The frame is `ECONOMICS_PROFILE_HASH_DOMAIN || canonical_bytes`.
    ///
    /// # Errors
    ///
    /// Returns an error if canonicalization fails.
    pub fn framed_bytes(&self) -> Result<Vec<u8>, EconomicsProfileError> {
        let canonical_bytes = self.canonical_bytes()?;
        let mut framed =
            Vec::with_capacity(ECONOMICS_PROFILE_HASH_DOMAIN.len() + canonical_bytes.len());
        framed.extend_from_slice(ECONOMICS_PROFILE_HASH_DOMAIN);
        framed.extend_from_slice(&canonical_bytes);
        Ok(framed)
    }

    /// Computes the canonical profile hash.
    ///
    /// # Errors
    ///
    /// Returns an error if canonicalization fails.
    pub fn profile_hash(&self) -> Result<[u8; 32], EconomicsProfileError> {
        let canonical_bytes = self.canonical_bytes()?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(ECONOMICS_PROFILE_HASH_DOMAIN);
        hasher.update(&canonical_bytes);
        Ok(*hasher.finalize().as_bytes())
    }

    /// Stores this profile in CAS and returns its profile hash.
    ///
    /// # Errors
    ///
    /// Returns an error if canonicalization, hash computation, or CAS storage
    /// fails.
    pub fn store_in_cas(
        &self,
        cas: &dyn ContentAddressedStore,
    ) -> Result<[u8; 32], EconomicsProfileError> {
        let framed = self.framed_bytes()?;
        let expected_hash = self.profile_hash()?;
        let stored = cas.store(&framed)?;
        if stored.hash != expected_hash {
            return Err(EconomicsProfileError::HashMismatch {
                expected: hex::encode(expected_hash),
                actual: hex::encode(stored.hash),
            });
        }
        Ok(stored.hash)
    }

    /// Loads and validates an economics profile from CAS.
    ///
    /// # Errors
    ///
    /// Returns an error if CAS retrieval fails, bytes are malformed, decoding
    /// fails, or recomputed hash differs from the provided hash.
    pub fn load_from_cas(
        cas: &dyn ContentAddressedStore,
        profile_hash: &[u8; 32],
    ) -> Result<Self, EconomicsProfileError> {
        let bytes = cas.retrieve(profile_hash)?;
        let profile = Self::from_framed_bytes(&bytes)?;
        let computed_hash = profile.profile_hash()?;
        if computed_hash != *profile_hash {
            return Err(EconomicsProfileError::HashMismatch {
                expected: hex::encode(profile_hash),
                actual: hex::encode(computed_hash),
            });
        }
        Ok(profile)
    }

    /// Decodes a framed profile payload.
    ///
    /// # Errors
    ///
    /// Returns an error if framing, deserialization, or validation fails.
    pub fn from_framed_bytes(bytes: &[u8]) -> Result<Self, EconomicsProfileError> {
        if !bytes.starts_with(ECONOMICS_PROFILE_HASH_DOMAIN) {
            return Err(EconomicsProfileError::InvalidFrame);
        }

        let payload = &bytes[ECONOMICS_PROFILE_HASH_DOMAIN.len()..];
        let wire: EconomicsProfileWire = serde_json::from_slice(payload).map_err(|error| {
            EconomicsProfileError::Serialization {
                message: error.to_string(),
            }
        })?;
        Self::from_wire(wire)
    }

    fn to_wire(&self) -> EconomicsProfileWire {
        let budget_entries = self
            .budget_matrix
            .iter()
            .map(|(&(risk_tier, intent_class), &budget)| BudgetCell {
                risk_tier,
                intent_class,
                budget,
            })
            .collect();

        EconomicsProfileWire {
            schema: PROFILE_SCHEMA.to_string(),
            schema_version: PROFILE_SCHEMA_VERSION.to_string(),
            lifecycle_cost_vector: self.lifecycle_cost_vector,
            input_state: self.input_state,
            budget_entries,
        }
    }

    fn from_wire(wire: EconomicsProfileWire) -> Result<Self, EconomicsProfileError> {
        wire.validate()?;

        if wire.budget_entries.len() > MAX_BUDGET_ENTRIES {
            return Err(EconomicsProfileError::BudgetEntriesTooLarge {
                count: wire.budget_entries.len(),
                max: MAX_BUDGET_ENTRIES,
            });
        }

        let mut budget_matrix = BTreeMap::new();
        for entry in wire.budget_entries {
            let key = (entry.risk_tier, entry.intent_class);
            if budget_matrix.insert(key, entry.budget).is_some() {
                return Err(EconomicsProfileError::DuplicateBudgetEntry {
                    tier: entry.risk_tier.to_string(),
                    intent_class: entry.intent_class.to_string(),
                });
            }
        }

        Ok(Self {
            lifecycle_cost_vector: wire.lifecycle_cost_vector,
            input_state: wire.input_state,
            budget_matrix,
        })
    }
}

impl EconomicsProfileWire {
    fn validate(&self) -> Result<(), EconomicsProfileError> {
        if self.schema != PROFILE_SCHEMA {
            return Err(EconomicsProfileError::InvalidSchema {
                expected: PROFILE_SCHEMA.to_string(),
                actual: self.schema.clone(),
            });
        }
        if self.schema_version != PROFILE_SCHEMA_VERSION {
            return Err(EconomicsProfileError::InvalidSchemaVersion {
                expected: PROFILE_SCHEMA_VERSION.to_string(),
                actual: self.schema_version.clone(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{
        BudgetCell, BudgetEntry, ECONOMICS_PROFILE_HASH_DOMAIN, EconomicsProfile,
        EconomicsProfileError, EconomicsProfileInputState, EconomicsProfileWire,
        LifecycleCostVector, MAX_BUDGET_ENTRIES, PROFILE_SCHEMA, PROFILE_SCHEMA_VERSION,
    };
    use crate::evidence::MemoryCas;
    use crate::pcac::{BoundaryIntentClass, RiskTier};

    fn lifecycle_costs() -> LifecycleCostVector {
        LifecycleCostVector {
            c_join: 1,
            c_revalidate: 2,
            c_consume: 3,
            c_effect: 4,
            c_replay: 5,
            c_recovery: 6,
        }
    }

    fn budget_entry(base: u64) -> BudgetEntry {
        BudgetEntry {
            max_tokens: base,
            max_tool_calls: u32::try_from(base).expect("test value should fit in u32"),
            max_time_ms: base * 10,
            max_io_bytes: base * 100,
        }
    }

    #[test]
    fn deterministic_hash_is_construction_order_independent() {
        let mut matrix_a = BTreeMap::new();
        matrix_a.insert(
            (RiskTier::Tier0, BoundaryIntentClass::Observe),
            budget_entry(10),
        );
        matrix_a.insert(
            (RiskTier::Tier1, BoundaryIntentClass::Assert),
            budget_entry(20),
        );
        matrix_a.insert(
            (RiskTier::Tier2Plus, BoundaryIntentClass::Actuate),
            budget_entry(30),
        );

        let mut matrix_b = BTreeMap::new();
        matrix_b.insert(
            (RiskTier::Tier2Plus, BoundaryIntentClass::Actuate),
            budget_entry(30),
        );
        matrix_b.insert(
            (RiskTier::Tier1, BoundaryIntentClass::Assert),
            budget_entry(20),
        );
        matrix_b.insert(
            (RiskTier::Tier0, BoundaryIntentClass::Observe),
            budget_entry(10),
        );

        let profile_a = EconomicsProfile::new(
            lifecycle_costs(),
            EconomicsProfileInputState::Current,
            matrix_a,
        )
        .expect("profile A should be valid");
        let profile_b = EconomicsProfile::new(
            lifecycle_costs(),
            EconomicsProfileInputState::Current,
            matrix_b,
        )
        .expect("profile B should be valid");

        let hash_a = profile_a
            .profile_hash()
            .expect("profile A hash should compute");
        let hash_b = profile_b
            .profile_hash()
            .expect("profile B hash should compute");

        assert_eq!(hash_a, hash_b);
    }

    #[test]
    fn cas_round_trip_loads_identical_profile() {
        let mut matrix = BTreeMap::new();
        matrix.insert(
            (RiskTier::Tier0, BoundaryIntentClass::Observe),
            budget_entry(10),
        );
        matrix.insert(
            (RiskTier::Tier1, BoundaryIntentClass::Assert),
            budget_entry(20),
        );

        let profile = EconomicsProfile::new(
            lifecycle_costs(),
            EconomicsProfileInputState::Current,
            matrix,
        )
        .expect("profile should be valid");
        let cas = MemoryCas::new();

        let profile_hash = profile
            .store_in_cas(&cas)
            .expect("profile should store in CAS");
        let loaded =
            EconomicsProfile::load_from_cas(&cas, &profile_hash).expect("profile should load");

        assert_eq!(profile, loaded);
    }

    #[test]
    fn from_framed_bytes_rejects_budget_entries_above_maximum() {
        let wire = EconomicsProfileWire {
            schema: PROFILE_SCHEMA.to_string(),
            schema_version: PROFILE_SCHEMA_VERSION.to_string(),
            lifecycle_cost_vector: lifecycle_costs(),
            input_state: EconomicsProfileInputState::Current,
            budget_entries: vec![
                BudgetCell {
                    risk_tier: RiskTier::Tier0,
                    intent_class: BoundaryIntentClass::Observe,
                    budget: budget_entry(10),
                };
                MAX_BUDGET_ENTRIES + 1
            ],
        };
        let payload = serde_json::to_vec(&wire).expect("wire should serialize");
        let mut framed = Vec::from(ECONOMICS_PROFILE_HASH_DOMAIN);
        framed.extend_from_slice(&payload);

        let error = EconomicsProfile::from_framed_bytes(&framed)
            .expect_err("oversized budget entries should fail closed");
        assert!(matches!(
            error,
            EconomicsProfileError::BudgetEntriesTooLarge { count, max }
                if count == MAX_BUDGET_ENTRIES + 1 && max == MAX_BUDGET_ENTRIES
        ));
    }
}
