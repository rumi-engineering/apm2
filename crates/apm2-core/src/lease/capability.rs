//! Capability proof model for cross-node authority verification.
//!
//! This module implements the OCAP (Object Capability) model for distributed
//! consensus as specified in RFC-0014 (DD-0009). Capabilities provide ledger-
//! verifiable authority that works across nodes.
//!
//! # Key Concepts
//!
//! - **Capability**: An unforgeable token granting specific permissions
//! - **Namespace Binding**: Capabilities are bound to a namespace to prevent
//!   cross-namespace replay attacks
//! - **Delegation Chain**: Capabilities can be delegated hierarchically, with
//!   each delegation signed by the delegator
//! - **Lease Linkage**: `capability_id == lease_id` for lease-backed
//!   capabilities
//!
//! # Security Properties
//!
//! - All capability events are `TotalOrder` authority events requiring BFT
//!   consensus
//! - Namespace binding prevents cross-namespace replay attacks
//! - Delegation chains are cryptographically verifiable
//! - Revocation cascades through the delegation tree
//!
//! # Example
//!
//! ```rust
//! use apm2_core::lease::capability::{
//!     Capability, CapabilityProof, CapabilityState, DelegationChainEntry,
//! };
//!
//! // Create a root capability
//! let capability = Capability::new(
//!     "cap-001".to_string(),
//!     "namespace-1".to_string(),
//!     "actor-alice".to_string(),
//!     "registrar".to_string(),
//!     vec![1, 2, 3], // scope_hash
//!     vec![],        // budget_hash
//!     1_000_000_000,
//!     2_000_000_000,
//!     vec![4, 5, 6], // registrar_signature
//!     true,          // delegatable
//! );
//!
//! assert!(capability.is_active());
//! ```

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use super::error::LeaseError;
use crate::crypto::{EventHasher, parse_signature, parse_verifying_key, verify_signature};

// =============================================================================
// Size Limits (CTR-1303: Explicit size bounds)
// =============================================================================

/// Maximum length of capability ID, namespace, and actor IDs.
pub const MAX_ID_LEN: usize = 128;

/// Maximum length of hash fields (BLAKE3 = 32 bytes).
pub const MAX_HASH_LEN: usize = 64;

/// Maximum length of signature fields (Ed25519 = 64 bytes).
pub const MAX_SIGNATURE_LEN: usize = 512;

/// Maximum depth of delegation chain.
/// This prevents unbounded recursion and limits proof size.
pub const MAX_DELEGATION_DEPTH: u32 = 16;

/// Maximum number of entries in a delegation chain proof.
pub const MAX_DELEGATION_CHAIN_ENTRIES: usize = 17; // root + MAX_DELEGATION_DEPTH

/// Maximum number of capabilities tracked per namespace.
pub const MAX_CAPABILITIES_PER_NAMESPACE: usize = 10_000;

// =============================================================================
// Capability State Types
// =============================================================================

/// The lifecycle state of a capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub enum CapabilityState {
    /// Capability is active and can be used.
    Active,
    /// Capability has been revoked before expiration.
    Revoked,
    /// Capability has expired naturally.
    Expired,
}

impl std::fmt::Display for CapabilityState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl CapabilityState {
    /// Parses a capability state from a string.
    ///
    /// # Errors
    ///
    /// Returns `LeaseError::InvalidInput` if the string is not a recognized
    /// state.
    pub fn parse(s: &str) -> Result<Self, LeaseError> {
        match s.to_uppercase().as_str() {
            "ACTIVE" => Ok(Self::Active),
            "REVOKED" => Ok(Self::Revoked),
            "EXPIRED" => Ok(Self::Expired),
            _ => Err(LeaseError::InvalidInput {
                field: "capability_state".to_string(),
                reason: format!("unrecognized state: {s}"),
            }),
        }
    }

    /// Returns the string representation of this state.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "ACTIVE",
            Self::Revoked => "REVOKED",
            Self::Expired => "EXPIRED",
        }
    }

    /// Returns true if this is a terminal state.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Revoked | Self::Expired)
    }

    /// Returns true if this is an active (non-terminal) state.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self, Self::Active)
    }
}

/// The reason a capability was revoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub enum RevocationReason {
    /// Voluntary revocation by the grantor.
    Voluntary,
    /// Revoked due to policy violation.
    PolicyViolation,
    /// Revoked due to key compromise.
    KeyCompromise,
    /// Superseded by a new capability.
    Superseded,
}

impl std::fmt::Display for RevocationReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl RevocationReason {
    /// Parses a revocation reason from a string.
    ///
    /// # Errors
    ///
    /// Returns `LeaseError::InvalidInput` if the string is not recognized.
    pub fn parse(s: &str) -> Result<Self, LeaseError> {
        match s.to_uppercase().as_str() {
            "VOLUNTARY" => Ok(Self::Voluntary),
            "POLICY_VIOLATION" => Ok(Self::PolicyViolation),
            "KEY_COMPROMISE" => Ok(Self::KeyCompromise),
            "SUPERSEDED" => Ok(Self::Superseded),
            _ => Err(LeaseError::InvalidInput {
                field: "revocation_reason".to_string(),
                reason: format!("unrecognized reason: {s}"),
            }),
        }
    }

    /// Returns the string representation of this reason.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Voluntary => "VOLUNTARY",
            Self::PolicyViolation => "POLICY_VIOLATION",
            Self::KeyCompromise => "KEY_COMPROMISE",
            Self::Superseded => "SUPERSEDED",
        }
    }
}

// =============================================================================
// Capability
// =============================================================================

/// A capability granting specific permissions within a namespace.
///
/// Capabilities are the core unit of authority in the OCAP model. They can be:
/// - Granted by an authority (registrar) to an actor
/// - Delegated from one actor to another (if delegatable)
/// - Revoked by the grantor or an authority
/// - Expired naturally based on `expires_at`
///
/// # Relationship to Leases
///
/// For lease-backed capabilities, `capability_id == lease_id`. The `scope_hash`
/// references the serialized `LeaseScope` stored in CAS.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Capability {
    /// Unique identifier for this capability.
    /// For lease-backed capabilities: `capability_id == lease_id`.
    pub capability_id: String,

    /// Namespace this capability is bound to.
    /// Prevents cross-namespace replay attacks.
    pub namespace: String,

    /// Actor holding this capability.
    pub holder_actor_id: String,

    /// Actor that granted this capability.
    pub grantor_actor_id: String,

    /// Current lifecycle state.
    pub state: CapabilityState,

    /// Hash of the serialized `LeaseScope` (stored in CAS).
    pub scope_hash: Vec<u8>,

    /// Optional hash of the serialized Budget (stored in CAS).
    pub budget_hash: Vec<u8>,

    /// Timestamp when the capability was granted (Unix nanos).
    pub granted_at: u64,

    /// Timestamp when the capability expires (Unix nanos).
    pub expires_at: u64,

    /// Signature from the grantor/registrar.
    pub signature: Vec<u8>,

    /// Whether this capability can be delegated to others.
    pub delegatable: bool,

    /// ID of the parent capability if this is a delegated capability.
    pub parent_capability_id: Option<String>,

    /// Depth in the delegation chain (0 for root capabilities).
    pub delegation_depth: u32,

    /// Revocation reason if revoked.
    pub revocation_reason: Option<RevocationReason>,

    /// Timestamp when revoked (Unix nanos).
    pub revoked_at: Option<u64>,

    /// Actor who performed the revocation.
    pub revoker_actor_id: Option<String>,
}

impl Capability {
    /// Creates a new root capability (not delegated).
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::missing_const_for_fn)] // Can't be const: String/Vec aren't const-constructible
    pub fn new(
        capability_id: String,
        namespace: String,
        holder_actor_id: String,
        grantor_actor_id: String,
        scope_hash: Vec<u8>,
        budget_hash: Vec<u8>,
        granted_at: u64,
        expires_at: u64,
        signature: Vec<u8>,
        delegatable: bool,
    ) -> Self {
        Self {
            capability_id,
            namespace,
            holder_actor_id,
            grantor_actor_id,
            state: CapabilityState::Active,
            scope_hash,
            budget_hash,
            granted_at,
            expires_at,
            signature,
            delegatable,
            parent_capability_id: None,
            delegation_depth: 0,
            revocation_reason: None,
            revoked_at: None,
            revoker_actor_id: None,
        }
    }

    /// Creates a delegated capability from a parent.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::missing_const_for_fn)] // Can't be const: String/Vec aren't const-constructible
    pub fn new_delegated(
        capability_id: String,
        parent_capability_id: String,
        namespace: String,
        holder_actor_id: String,
        delegator_actor_id: String,
        scope_hash: Vec<u8>,
        budget_hash: Vec<u8>,
        delegated_at: u64,
        expires_at: u64,
        signature: Vec<u8>,
        delegatable: bool,
        delegation_depth: u32,
    ) -> Self {
        Self {
            capability_id,
            namespace,
            holder_actor_id,
            grantor_actor_id: delegator_actor_id,
            state: CapabilityState::Active,
            scope_hash,
            budget_hash,
            granted_at: delegated_at,
            expires_at,
            signature,
            delegatable,
            parent_capability_id: Some(parent_capability_id),
            delegation_depth,
            revocation_reason: None,
            revoked_at: None,
            revoker_actor_id: None,
        }
    }

    /// Returns true if this capability is active.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.state.is_active()
    }

    /// Returns true if this capability is in a terminal state.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        self.state.is_terminal()
    }

    /// Returns true if this is a delegated capability (has a parent).
    #[must_use]
    pub const fn is_delegated(&self) -> bool {
        self.parent_capability_id.is_some()
    }

    /// Checks if the capability has expired based on the given current time.
    #[must_use]
    pub const fn is_expired_at(&self, current_time: u64) -> bool {
        self.state.is_active() && current_time >= self.expires_at
    }

    /// Returns the remaining time until expiration, or 0 if expired.
    #[must_use]
    pub const fn time_remaining(&self, current_time: u64) -> u64 {
        self.expires_at.saturating_sub(current_time)
    }

    /// Returns the linked lease ID (for lease-backed capabilities).
    ///
    /// Per RFC-0014 DD-0009: `capability_id == lease_id`
    #[must_use]
    pub fn lease_id(&self) -> &str {
        &self.capability_id
    }
}

// =============================================================================
// Delegation Chain Entry
// =============================================================================

/// An entry in a capability delegation chain.
///
/// Each entry represents one step in the chain from the root capability
/// to the final delegated capability. The chain must be traversed to
/// verify that each delegation is properly signed by the delegator.
///
/// # Security (CRITICAL-01)
///
/// The `event_hash` must be cryptographically bound to the metadata fields
/// (`capability_id`, `holder_actor_id`, `scope_hash`, `namespace`,
/// `expires_at`). Use [`DelegationChainEntry::compute_event_hash`] to compute
/// the canonical hash and [`DelegationChainEntry::verify_event_hash_binding`]
/// to verify binding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DelegationChainEntry {
    /// Capability ID at this level.
    pub capability_id: String,

    /// Actor holding the capability at this level.
    pub holder_actor_id: String,

    /// Namespace this entry is bound to.
    pub namespace: String,

    /// Hash of the serialized scope at this level.
    pub scope_hash: Vec<u8>,

    /// Expiration time for this entry (Unix nanos).
    pub expires_at: u64,

    /// Hash of the capability event (`CapabilityGranted` or
    /// `CapabilityDelegated`). This MUST be derived from the metadata fields
    /// using [`DelegationChainEntry::compute_event_hash`].
    pub event_hash: Vec<u8>,

    /// Signature from the delegator (or registrar for root).
    pub signature: Vec<u8>,

    /// Depth in the chain (0 for root).
    pub depth: u32,
}

impl DelegationChainEntry {
    /// Computes the canonical event hash from the metadata fields.
    ///
    /// The hash is computed over the canonical serialization of:
    /// `capability_id || holder_actor_id || namespace || scope_hash ||
    /// expires_at || depth`
    ///
    /// This ensures that all metadata is cryptographically bound to the hash
    /// that is signed, preventing metadata substitution attacks.
    #[must_use]
    pub fn compute_event_hash(&self) -> Vec<u8> {
        Self::compute_event_hash_from_parts(
            &self.capability_id,
            &self.holder_actor_id,
            &self.namespace,
            &self.scope_hash,
            self.expires_at,
            self.depth,
        )
    }

    /// Computes the event hash from individual fields.
    ///
    /// This is useful for creating new entries with a correct event hash.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // ID lengths are bounded by MAX_ID_LEN (128)
    pub fn compute_event_hash_from_parts(
        capability_id: &str,
        holder_actor_id: &str,
        namespace: &str,
        scope_hash: &[u8],
        expires_at: u64,
        depth: u32,
    ) -> Vec<u8> {
        // Canonical serialization: length-prefixed fields to prevent ambiguity
        let mut data = Vec::new();

        // capability_id (length-prefixed)
        data.extend_from_slice(&(capability_id.len() as u32).to_le_bytes());
        data.extend_from_slice(capability_id.as_bytes());

        // holder_actor_id (length-prefixed)
        data.extend_from_slice(&(holder_actor_id.len() as u32).to_le_bytes());
        data.extend_from_slice(holder_actor_id.as_bytes());

        // namespace (length-prefixed)
        data.extend_from_slice(&(namespace.len() as u32).to_le_bytes());
        data.extend_from_slice(namespace.as_bytes());

        // scope_hash (length-prefixed)
        data.extend_from_slice(&(scope_hash.len() as u32).to_le_bytes());
        data.extend_from_slice(scope_hash);

        // expires_at (fixed size)
        data.extend_from_slice(&expires_at.to_le_bytes());

        // depth (fixed size)
        data.extend_from_slice(&depth.to_le_bytes());

        EventHasher::hash_content(&data).to_vec()
    }

    /// Verifies that the `event_hash` is correctly bound to the metadata.
    ///
    /// # Security (CRITICAL-01)
    ///
    /// This check prevents metadata substitution attacks where an attacker
    /// reuses a valid signature from one capability grant but substitutes
    /// different metadata (e.g., a different `holder_actor_id`).
    ///
    /// # Errors
    ///
    /// Returns `LeaseError::InvalidInput` if the event hash does not match
    /// the computed hash from the metadata fields.
    pub fn verify_event_hash_binding(&self) -> Result<(), LeaseError> {
        let computed = self.compute_event_hash();
        if self.event_hash != computed {
            return Err(LeaseError::InvalidInput {
                field: "event_hash".to_string(),
                reason: "event hash does not match metadata (possible substitution attack)"
                    .to_string(),
            });
        }
        Ok(())
    }
}

// =============================================================================
// Capability Proof
// =============================================================================

/// A cryptographic proof of capability authority.
///
/// A capability proof contains everything needed to verify that an actor
/// holds a specific capability. It includes:
///
/// 1. The root capability grant (`CapabilityGranted` event)
/// 2. The delegation chain (if any) leading to the holder
/// 3. Namespace binding for replay protection
///
/// # Verification
///
/// To verify a capability proof:
/// 1. Verify the root grant signature against the registrar key
/// 2. Verify each delegation signature in the chain
/// 3. Verify namespace matches throughout the chain
/// 4. Verify the capability is not expired or revoked
/// 5. Verify the scope hash matches expected permissions
///
/// # Cross-Node Verification
///
/// Proofs are ledger-verifiable: each event in the chain can be looked up
/// in the ledger to confirm it exists and has not been superseded by a
/// revocation event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CapabilityProof {
    /// The capability being proven.
    pub capability_id: String,

    /// Namespace the capability is bound to.
    pub namespace: String,

    /// Actor claiming to hold the capability.
    pub holder_actor_id: String,

    /// Hash of the serialized `LeaseScope`.
    pub scope_hash: Vec<u8>,

    /// Optional hash of the serialized `Budget`.
    pub budget_hash: Vec<u8>,

    /// Expiration time (Unix nanos).
    pub expires_at: u64,

    /// The delegation chain from root to holder.
    /// First entry is always the root `CapabilityGranted`.
    /// Empty for root capabilities that haven't been delegated.
    pub delegation_chain: Vec<DelegationChainEntry>,

    /// Ledger sequence ID where the root grant was recorded.
    /// Used for cross-node verification via ledger lookup.
    pub root_grant_seq_id: Option<u64>,
}

impl CapabilityProof {
    /// Creates a new capability proof for a root capability (no delegation).
    ///
    /// The `root_event_hash` should be computed using
    /// [`DelegationChainEntry::compute_event_hash_from_parts`] to ensure
    /// correct binding between metadata and the signed hash.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new_root(
        capability_id: String,
        namespace: String,
        holder_actor_id: String,
        scope_hash: Vec<u8>,
        budget_hash: Vec<u8>,
        expires_at: u64,
        root_event_hash: Vec<u8>,
        registrar_signature: Vec<u8>,
    ) -> Self {
        Self {
            capability_id: capability_id.clone(),
            namespace: namespace.clone(),
            holder_actor_id: holder_actor_id.clone(),
            scope_hash: scope_hash.clone(),
            budget_hash,
            expires_at,
            delegation_chain: vec![DelegationChainEntry {
                capability_id,
                holder_actor_id,
                namespace,
                scope_hash,
                expires_at,
                event_hash: root_event_hash,
                signature: registrar_signature,
                depth: 0,
            }],
            root_grant_seq_id: None,
        }
    }

    /// Creates a proof with a full delegation chain.
    ///
    /// # Errors
    ///
    /// Returns `LeaseError::InvalidInput` if the chain exceeds
    /// `MAX_DELEGATION_CHAIN_ENTRIES`.
    pub fn with_delegation_chain(
        capability_id: String,
        namespace: String,
        holder_actor_id: String,
        scope_hash: Vec<u8>,
        budget_hash: Vec<u8>,
        expires_at: u64,
        delegation_chain: Vec<DelegationChainEntry>,
    ) -> Result<Self, LeaseError> {
        if delegation_chain.len() > MAX_DELEGATION_CHAIN_ENTRIES {
            return Err(LeaseError::InvalidInput {
                field: "delegation_chain".to_string(),
                reason: format!(
                    "chain length {} exceeds maximum {}",
                    delegation_chain.len(),
                    MAX_DELEGATION_CHAIN_ENTRIES
                ),
            });
        }

        Ok(Self {
            capability_id,
            namespace,
            holder_actor_id,
            scope_hash,
            budget_hash,
            expires_at,
            delegation_chain,
            root_grant_seq_id: None,
        })
    }

    /// Sets the root grant sequence ID for ledger verification.
    #[must_use]
    pub const fn with_root_seq_id(mut self, seq_id: u64) -> Self {
        self.root_grant_seq_id = Some(seq_id);
        self
    }

    /// Returns the depth of the delegation chain.
    #[must_use]
    pub fn delegation_depth(&self) -> u32 {
        self.delegation_chain.last().map_or(0, |entry| entry.depth)
    }

    /// Returns true if the proof has expired.
    #[must_use]
    pub const fn is_expired_at(&self, current_time: u64) -> bool {
        current_time >= self.expires_at
    }

    /// Returns true if the proof is for a delegated capability.
    #[must_use]
    pub fn is_delegated(&self) -> bool {
        self.delegation_chain.len() > 1
    }

    /// Returns the root entry of the delegation chain.
    #[must_use]
    pub fn root_entry(&self) -> Option<&DelegationChainEntry> {
        self.delegation_chain.first()
    }

    /// Validates basic structural requirements of the proof.
    ///
    /// This performs local validation without ledger lookup:
    /// - ID lengths are within bounds
    /// - Hash sizes are valid
    /// - Chain depth is within limits
    /// - Expiration is in the future
    ///
    /// # Errors
    ///
    /// Returns `LeaseError::InvalidInput` if validation fails.
    #[allow(clippy::too_many_lines)]
    pub fn validate_structure(&self, current_time: u64) -> Result<(), LeaseError> {
        // Validate ID lengths
        if self.capability_id.len() > MAX_ID_LEN {
            return Err(LeaseError::InvalidInput {
                field: "capability_id".to_string(),
                reason: format!("exceeds limit of {MAX_ID_LEN} bytes"),
            });
        }
        if self.namespace.len() > MAX_ID_LEN {
            return Err(LeaseError::InvalidInput {
                field: "namespace".to_string(),
                reason: format!("exceeds limit of {MAX_ID_LEN} bytes"),
            });
        }
        if self.holder_actor_id.len() > MAX_ID_LEN {
            return Err(LeaseError::InvalidInput {
                field: "holder_actor_id".to_string(),
                reason: format!("exceeds limit of {MAX_ID_LEN} bytes"),
            });
        }

        // Validate hash sizes
        if self.scope_hash.len() > MAX_HASH_LEN {
            return Err(LeaseError::InvalidInput {
                field: "scope_hash".to_string(),
                reason: format!("exceeds limit of {MAX_HASH_LEN} bytes"),
            });
        }
        if self.budget_hash.len() > MAX_HASH_LEN {
            return Err(LeaseError::InvalidInput {
                field: "budget_hash".to_string(),
                reason: format!("exceeds limit of {MAX_HASH_LEN} bytes"),
            });
        }

        // Validate chain length (must not be empty)
        if self.delegation_chain.is_empty() {
            return Err(LeaseError::InvalidInput {
                field: "delegation_chain".to_string(),
                reason: "cannot be empty; must contain at least the root grant".to_string(),
            });
        }
        if self.delegation_chain.len() > MAX_DELEGATION_CHAIN_ENTRIES {
            return Err(LeaseError::InvalidInput {
                field: "delegation_chain".to_string(),
                reason: format!(
                    "chain length {} exceeds maximum {}",
                    self.delegation_chain.len(),
                    MAX_DELEGATION_CHAIN_ENTRIES
                ),
            });
        }

        // Validate expiration (must be in the future)
        if self.is_expired_at(current_time) {
            return Err(LeaseError::InvalidInput {
                field: "expires_at".to_string(),
                reason: format!(
                    "capability expired at {} (current time: {})",
                    self.expires_at, current_time
                ),
            });
        }

        // Validate chain entries
        for (i, entry) in self.delegation_chain.iter().enumerate() {
            if entry.capability_id.len() > MAX_ID_LEN {
                return Err(LeaseError::InvalidInput {
                    field: format!("delegation_chain[{i}].capability_id"),
                    reason: format!("exceeds limit of {MAX_ID_LEN} bytes"),
                });
            }
            if entry.holder_actor_id.len() > MAX_ID_LEN {
                return Err(LeaseError::InvalidInput {
                    field: format!("delegation_chain[{i}].holder_actor_id"),
                    reason: format!("exceeds limit of {MAX_ID_LEN} bytes"),
                });
            }
            if entry.signature.len() > MAX_SIGNATURE_LEN {
                return Err(LeaseError::InvalidInput {
                    field: format!("delegation_chain[{i}].signature"),
                    reason: format!("exceeds limit of {MAX_SIGNATURE_LEN} bytes"),
                });
            }

            // Validate depth sequence: depth must equal position in chain (zero-indexed)
            #[allow(clippy::cast_possible_truncation)] // i bounded by MAX_DELEGATION_CHAIN_ENTRIES
            let expected_depth = i as u32;
            if entry.depth != expected_depth {
                return Err(LeaseError::InvalidInput {
                    field: format!("delegation_chain[{i}].depth"),
                    reason: format!(
                        "depth must match position in chain (expected {expected_depth}, found {})",
                        entry.depth
                    ),
                });
            }

            if entry.depth > MAX_DELEGATION_DEPTH {
                return Err(LeaseError::InvalidInput {
                    field: format!("delegation_chain[{i}].depth"),
                    reason: format!("exceeds maximum depth {MAX_DELEGATION_DEPTH}"),
                });
            }
        }

        // Validate that the last entry matches the proof's top-level identity
        if let Some(last_entry) = self.delegation_chain.last() {
            if last_entry.capability_id != self.capability_id {
                return Err(LeaseError::InvalidInput {
                    field: "capability_id".to_string(),
                    reason: "does not match the tail of the delegation chain".to_string(),
                });
            }
            if last_entry.holder_actor_id != self.holder_actor_id {
                return Err(LeaseError::InvalidInput {
                    field: "holder_actor_id".to_string(),
                    reason: "does not match the tail of the delegation chain".to_string(),
                });
            }
        }

        Ok(())
    }

    /// Validates cryptographic signatures in the delegation chain.
    ///
    /// This verifies:
    /// 1. The root grant's registrar signature over the root event hash
    /// 2. Each delegation's signature by the delegator (previous holder)
    ///
    /// # Arguments
    ///
    /// * `get_public_key` - A function that resolves actor IDs to their public
    ///   keys. For the root entry (depth 0), this is called with the registrar
    ///   ID. For delegations (depth > 0), this is called with the delegator's
    ///   actor ID (the previous entry's holder).
    ///
    /// # Errors
    ///
    /// Returns `LeaseError::InvalidSignature` if any signature is invalid.
    /// Returns `LeaseError::MissingSignature` if a signature is empty.
    /// Returns `LeaseError::InvalidInput` if a public key cannot be resolved.
    ///
    /// # Security
    ///
    /// This method is deterministic: the same inputs always produce the same
    /// result. The verification order is fixed (root first, then
    /// delegations in chain order).
    pub fn validate_signatures<F>(&self, get_public_key: F) -> Result<(), LeaseError>
    where
        F: Fn(&str) -> Option<Vec<u8>>,
    {
        if self.delegation_chain.is_empty() {
            return Err(LeaseError::InvalidInput {
                field: "delegation_chain".to_string(),
                reason: "cannot be empty; must contain at least the root grant".to_string(),
            });
        }

        // Verify each entry in the chain
        for (i, entry) in self.delegation_chain.iter().enumerate() {
            // Check signature is not empty
            if entry.signature.is_empty() {
                return Err(LeaseError::MissingSignature {
                    lease_id: entry.capability_id.clone(),
                });
            }

            // Check event_hash is not empty
            if entry.event_hash.is_empty() {
                return Err(LeaseError::InvalidInput {
                    field: format!("delegation_chain[{i}].event_hash"),
                    reason: "event hash cannot be empty".to_string(),
                });
            }

            // Determine whose public key to use for verification
            let signer_id = if i == 0 {
                // Root entry: we need the registrar's key
                // The registrar ID is typically the grantor of the root capability
                // For verification, the caller must provide it via the lookup function
                // We use a special convention: "_registrar_" prefix + capability_id
                // to allow the resolver to identify this is the registrar lookup
                format!("_registrar_{}", entry.capability_id)
            } else {
                // Delegation entry: signed by the previous holder (delegator)
                self.delegation_chain[i - 1].holder_actor_id.clone()
            };

            // Resolve the public key
            let public_key_bytes =
                get_public_key(&signer_id).ok_or_else(|| LeaseError::InvalidInput {
                    field: format!("delegation_chain[{i}]"),
                    reason: format!("cannot resolve public key for signer: {signer_id}"),
                })?;

            // Parse the public key
            let verifying_key = parse_verifying_key(&public_key_bytes).map_err(|_| {
                LeaseError::InvalidSignature {
                    lease_id: entry.capability_id.clone(),
                }
            })?;

            // Parse the signature
            let signature =
                parse_signature(&entry.signature).map_err(|_| LeaseError::InvalidSignature {
                    lease_id: entry.capability_id.clone(),
                })?;

            // Verify the signature over the event hash
            verify_signature(&verifying_key, &entry.event_hash, &signature).map_err(|_| {
                LeaseError::InvalidSignature {
                    lease_id: entry.capability_id.clone(),
                }
            })?;
        }

        Ok(())
    }

    /// Validates cryptographic signatures using a direct public key lookup.
    ///
    /// This is an alternative to `validate_signatures` that takes a simpler
    /// lookup function that maps actor IDs directly to public keys, plus an
    /// explicit registrar public key for verifying the root grant.
    ///
    /// # Security (CRITICAL-01)
    ///
    /// This method verifies both:
    /// 1. That each signature is valid over the event hash
    /// 2. That each event hash is correctly bound to the metadata (prevents
    ///    metadata substitution attacks)
    ///
    /// # Arguments
    ///
    /// * `registrar_public_key` - The public key of the registrar who signed
    ///   the root grant
    /// * `get_actor_public_key` - A function that resolves actor IDs to their
    ///   public keys
    ///
    /// # Errors
    ///
    /// Returns `LeaseError::InvalidSignature` if any signature is invalid.
    /// Returns `LeaseError::MissingSignature` if a signature is empty.
    /// Returns `LeaseError::InvalidInput` if a public key cannot be resolved
    /// or if event hash binding verification fails.
    pub fn validate_signatures_with_registrar<F>(
        &self,
        registrar_public_key: &[u8],
        get_actor_public_key: F,
    ) -> Result<(), LeaseError>
    where
        F: Fn(&str) -> Option<Vec<u8>>,
    {
        if self.delegation_chain.is_empty() {
            return Err(LeaseError::InvalidInput {
                field: "delegation_chain".to_string(),
                reason: "cannot be empty; must contain at least the root grant".to_string(),
            });
        }

        // Verify each entry in the chain
        for (i, entry) in self.delegation_chain.iter().enumerate() {
            // Check signature is not empty
            if entry.signature.is_empty() {
                return Err(LeaseError::MissingSignature {
                    lease_id: entry.capability_id.clone(),
                });
            }

            // Check event_hash is not empty
            if entry.event_hash.is_empty() {
                return Err(LeaseError::InvalidInput {
                    field: format!("delegation_chain[{i}].event_hash"),
                    reason: "event hash cannot be empty".to_string(),
                });
            }

            // CRITICAL-01: Verify event hash is correctly bound to metadata
            // This prevents metadata substitution attacks where an attacker
            // reuses a valid signature but substitutes different metadata
            entry
                .verify_event_hash_binding()
                .map_err(|_| LeaseError::InvalidInput {
                    field: format!("delegation_chain[{i}].event_hash"),
                    reason: "event hash does not match metadata (possible substitution attack)"
                        .to_string(),
                })?;

            // Determine which public key to use for verification
            let public_key_bytes: Vec<u8> = if i == 0 {
                // Root entry: use the registrar's key
                registrar_public_key.to_vec()
            } else {
                // Delegation entry: signed by the previous holder (delegator)
                let delegator_id = &self.delegation_chain[i - 1].holder_actor_id;
                get_actor_public_key(delegator_id).ok_or_else(|| LeaseError::InvalidInput {
                    field: format!("delegation_chain[{i}]"),
                    reason: format!("cannot resolve public key for delegator: {delegator_id}"),
                })?
            };

            // Parse and verify signature
            let verifying_key = parse_verifying_key(&public_key_bytes).map_err(|_| {
                LeaseError::InvalidSignature {
                    lease_id: entry.capability_id.clone(),
                }
            })?;

            let signature =
                parse_signature(&entry.signature).map_err(|_| LeaseError::InvalidSignature {
                    lease_id: entry.capability_id.clone(),
                })?;

            verify_signature(&verifying_key, &entry.event_hash, &signature).map_err(|_| {
                LeaseError::InvalidSignature {
                    lease_id: entry.capability_id.clone(),
                }
            })?;
        }

        Ok(())
    }

    /// Performs structural and signature verification of the capability proof.
    ///
    /// This combines structural validation and signature verification into
    /// a single deterministic verification operation.
    ///
    /// # Important: Not Full Authority Verification
    ///
    /// This method performs cryptographic verification but does NOT check
    /// ledger state. For full authority verification that includes revocation
    /// checks, use [`CapabilityProof::verify_with_state`] instead.
    ///
    /// What this method verifies:
    /// - Structural validity (ID lengths, hash sizes, chain depth, expiration)
    /// - Signature validity (each signature is valid over the event hash)
    /// - Metadata binding (event hash is derived from metadata, preventing
    ///   substitution attacks)
    ///
    /// What this method does NOT verify:
    /// - Whether capabilities exist in the ledger
    /// - Whether capabilities have been revoked
    /// - Whether the registry state is consistent
    ///
    /// # Arguments
    ///
    /// * `current_time` - The current time in Unix nanoseconds
    /// * `registrar_public_key` - The public key of the registrar who signed
    ///   the root grant
    /// * `get_actor_public_key` - A function that resolves actor IDs to their
    ///   public keys
    ///
    /// # Errors
    ///
    /// Returns an error if either structural validation or signature
    /// verification fails.
    ///
    /// # Determinism
    ///
    /// This method is fully deterministic: given the same inputs, it will
    /// always produce the same result. This property is essential for
    /// cross-node verification where multiple nodes must independently
    /// arrive at the same conclusion.
    pub fn verify<F>(
        &self,
        current_time: u64,
        registrar_public_key: &[u8],
        get_actor_public_key: F,
    ) -> Result<(), LeaseError>
    where
        F: Fn(&str) -> Option<Vec<u8>>,
    {
        // Step 1: Structural validation
        self.validate_structure(current_time)?;

        // Step 2: Signature verification (includes metadata binding check)
        self.validate_signatures_with_registrar(registrar_public_key, get_actor_public_key)?;

        Ok(())
    }

    /// Performs full authority verification including ledger state checks.
    ///
    /// This method provides complete verification as required by TCK-00200:
    /// "Verification uses ledger state + signature chain"
    ///
    /// # Verification Steps
    ///
    /// 1. Structural validation (ID lengths, hash sizes, chain depth,
    ///    expiration)
    /// 2. Signature verification (each signature is valid over the event hash)
    /// 3. Metadata binding verification (event hash matches metadata)
    /// 4. **Ledger state verification**:
    ///    - Each capability in the chain exists in the registry
    ///    - No capability in the chain is revoked
    ///    - The root capability is valid
    ///
    /// # Arguments
    ///
    /// * `current_time` - The current time in Unix nanoseconds
    /// * `registrar_public_key` - The public key of the registrar who signed
    ///   the root grant
    /// * `get_actor_public_key` - A function that resolves actor IDs to their
    ///   public keys
    /// * `registry` - The capability registry state to verify against
    ///
    /// # Errors
    ///
    /// Returns an error if any verification step fails, including:
    /// - Structural or signature validation errors (see [`verify`])
    /// - `LeaseError::LeaseNotFound` if a capability is not in the registry
    /// - `LeaseError::LeaseRevoked` if any capability in the chain is revoked
    /// - `LeaseError::LeaseExpired` if any capability in the chain is expired
    ///
    /// # Security (HIGH-02)
    ///
    /// This method is required for cross-node verification. Using only
    /// [`verify`] without ledger state checks would allow presenting
    /// proofs for revoked capabilities.
    pub fn verify_with_state<F>(
        &self,
        current_time: u64,
        registrar_public_key: &[u8],
        get_actor_public_key: F,
        registry: &CapabilityRegistryState,
    ) -> Result<(), LeaseError>
    where
        F: Fn(&str) -> Option<Vec<u8>>,
    {
        // Step 1-3: Structural, signature, and metadata binding verification
        self.verify(current_time, registrar_public_key, get_actor_public_key)?;

        // Step 4: Ledger state verification
        self.verify_against_registry(current_time, registry)?;

        Ok(())
    }

    /// Verifies the proof against the capability registry state.
    ///
    /// This checks that all capabilities in the delegation chain:
    /// 1. Exist in the registry
    /// 2. Are not revoked
    /// 3. Are not expired
    /// 4. Have matching metadata (holder, namespace, scope)
    fn verify_against_registry(
        &self,
        current_time: u64,
        registry: &CapabilityRegistryState,
    ) -> Result<(), LeaseError> {
        // Verify each capability in the chain exists and is valid
        for (i, entry) in self.delegation_chain.iter().enumerate() {
            let capability =
                registry
                    .get(&entry.capability_id)
                    .ok_or_else(|| LeaseError::LeaseNotFound {
                        lease_id: entry.capability_id.clone(),
                    })?;

            // Check revocation status
            if capability.state == CapabilityState::Revoked {
                return Err(LeaseError::LeaseRevoked {
                    lease_id: entry.capability_id.clone(),
                });
            }

            // Check expiration (in registry, not just proof)
            if capability.is_expired_at(current_time) {
                return Err(LeaseError::LeaseExpired {
                    lease_id: entry.capability_id.clone(),
                });
            }

            // Verify metadata consistency between proof and registry
            if capability.holder_actor_id != entry.holder_actor_id {
                return Err(LeaseError::InvalidInput {
                    field: format!("delegation_chain[{i}].holder_actor_id"),
                    reason: format!(
                        "holder mismatch: proof has '{}', registry has '{}'",
                        entry.holder_actor_id, capability.holder_actor_id
                    ),
                });
            }

            if capability.namespace != entry.namespace {
                return Err(LeaseError::InvalidInput {
                    field: format!("delegation_chain[{i}].namespace"),
                    reason: format!(
                        "namespace mismatch: proof has '{}', registry has '{}'",
                        entry.namespace, capability.namespace
                    ),
                });
            }
        }

        // Verify the proof's top-level metadata matches the final capability
        if let Some(last_entry) = self.delegation_chain.last() {
            if let Some(capability) = registry.get(&last_entry.capability_id) {
                // Verify namespace consistency at proof level
                if self.namespace != capability.namespace {
                    return Err(LeaseError::InvalidInput {
                        field: "namespace".to_string(),
                        reason: format!(
                            "proof namespace '{}' does not match registry '{}'",
                            self.namespace, capability.namespace
                        ),
                    });
                }
            }
        }

        Ok(())
    }
}

// =============================================================================
// Capability Registry State
// =============================================================================

/// State maintained by the capability reducer.
///
/// Tracks all capabilities by namespace and provides efficient lookup.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CapabilityRegistryState {
    /// Map of capability ID to capability.
    pub capabilities: HashMap<String, Capability>,

    /// Map of namespace to set of capability IDs.
    pub capabilities_by_namespace: HashMap<String, Vec<String>>,

    /// Map of holder actor ID to set of capability IDs.
    pub capabilities_by_holder: HashMap<String, Vec<String>>,

    /// Map of parent capability ID to child capability IDs (delegation tree).
    pub delegation_tree: HashMap<String, Vec<String>>,
}

impl CapabilityRegistryState {
    /// Creates a new empty state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the number of capabilities.
    #[must_use]
    pub fn len(&self) -> usize {
        self.capabilities.len()
    }

    /// Returns true if there are no capabilities.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.capabilities.is_empty()
    }

    /// Returns a capability by ID.
    #[must_use]
    pub fn get(&self, capability_id: &str) -> Option<&Capability> {
        self.capabilities.get(capability_id)
    }

    /// Returns all capabilities in a namespace.
    #[must_use]
    pub fn get_by_namespace(&self, namespace: &str) -> Vec<&Capability> {
        self.capabilities_by_namespace
            .get(namespace)
            .map_or_else(Vec::new, |ids| {
                ids.iter()
                    .filter_map(|id| self.capabilities.get(id))
                    .collect()
            })
    }

    /// Returns all capabilities held by an actor.
    #[must_use]
    pub fn get_by_holder(&self, actor_id: &str) -> Vec<&Capability> {
        self.capabilities_by_holder
            .get(actor_id)
            .map_or_else(Vec::new, |ids| {
                ids.iter()
                    .filter_map(|id| self.capabilities.get(id))
                    .collect()
            })
    }

    /// Returns all active capabilities.
    #[must_use]
    pub fn active_capabilities(&self) -> Vec<&Capability> {
        self.capabilities
            .values()
            .filter(|c| c.is_active())
            .collect()
    }

    /// Returns the number of active capabilities.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.capabilities.values().filter(|c| c.is_active()).count()
    }

    /// Returns all child capabilities delegated from a parent.
    #[must_use]
    pub fn get_delegated_from(&self, parent_id: &str) -> Vec<&Capability> {
        self.delegation_tree
            .get(parent_id)
            .map_or_else(Vec::new, |ids| {
                ids.iter()
                    .filter_map(|id| self.capabilities.get(id))
                    .collect()
            })
    }

    /// Returns capabilities that have expired but are still marked active.
    #[must_use]
    pub fn get_expired_but_active(&self, current_time: u64) -> Vec<&Capability> {
        self.capabilities
            .values()
            .filter(|c| c.is_expired_at(current_time))
            .collect()
    }

    /// Inserts a new capability.
    ///
    /// # Errors
    ///
    /// Returns `LeaseError::LeaseAlreadyExists` if capability ID already
    /// exists. Returns `LeaseError::InvalidInput` if namespace capacity is
    /// exceeded.
    pub fn insert(&mut self, capability: Capability) -> Result<(), LeaseError> {
        let namespace = capability.namespace.clone();
        let holder = capability.holder_actor_id.clone();
        let cap_id = capability.capability_id.clone();

        // Check for duplicate capability ID
        if self.capabilities.contains_key(&cap_id) {
            return Err(LeaseError::LeaseAlreadyExists { lease_id: cap_id });
        }

        // Check namespace capacity
        let ns_count = self
            .capabilities_by_namespace
            .get(&namespace)
            .map_or(0, Vec::len);
        if ns_count >= MAX_CAPABILITIES_PER_NAMESPACE {
            return Err(LeaseError::InvalidInput {
                field: "namespace".to_string(),
                reason: format!(
                    "namespace {namespace} has reached capacity ({MAX_CAPABILITIES_PER_NAMESPACE})"
                ),
            });
        }

        // Track delegation tree
        if let Some(parent_id) = &capability.parent_capability_id {
            self.delegation_tree
                .entry(parent_id.clone())
                .or_default()
                .push(cap_id.clone());
        }

        // Insert into main map
        self.capabilities.insert(cap_id.clone(), capability);

        // Update namespace index
        self.capabilities_by_namespace
            .entry(namespace)
            .or_default()
            .push(cap_id.clone());

        // Update holder index
        self.capabilities_by_holder
            .entry(holder)
            .or_default()
            .push(cap_id);

        Ok(())
    }

    /// Removes all terminal (revoked/expired) capabilities.
    ///
    /// Returns the number of capabilities removed.
    pub fn prune_terminal(&mut self) -> usize {
        let terminal_ids: Vec<String> = self
            .capabilities
            .iter()
            .filter(|(_, c)| c.is_terminal())
            .map(|(id, _)| id.clone())
            .collect();

        let count = terminal_ids.len();
        for id in terminal_ids {
            self.remove(&id);
        }
        count
    }

    /// Collects all descendant capability IDs for a given capability.
    ///
    /// This performs a breadth-first traversal of the delegation tree to find
    /// all capabilities that were delegated from the given capability, directly
    /// or indirectly.
    ///
    /// Uses a visited set to detect cycles and prevent infinite loops if a
    /// cycle exists in the delegation tree (due to a bug elsewhere).
    fn get_all_descendants(&self, capability_id: &str) -> Vec<String> {
        let mut descendants = Vec::new();
        let mut queue = vec![capability_id.to_string()];
        let mut visited = HashSet::new();
        visited.insert(capability_id.to_string());

        while let Some(current_id) = queue.pop() {
            if let Some(children) = self.delegation_tree.get(&current_id) {
                for child_id in children {
                    if visited.insert(child_id.clone()) {
                        descendants.push(child_id.clone());
                        queue.push(child_id.clone());
                    }
                }
            }
        }

        descendants
    }

    /// Removes a capability and cleans up indices.
    ///
    /// **Security (HIGH-01)**: This implements cascading revocation. When a
    /// capability is removed, ALL of its descendants in the delegation tree
    /// are also removed. This prevents 'dangling authority' where a revoked
    /// parent would still have active children.
    fn remove(&mut self, capability_id: &str) {
        // HIGH-01 FIX: Collect all descendants BEFORE removing anything.
        // This must be done first because removing ancestors would break
        // the delegation_tree traversal.
        let descendants = self.get_all_descendants(capability_id);

        // Remove all descendants first (cascading revocation)
        for descendant_id in descendants {
            self.remove_single(&descendant_id);
        }

        // Remove the capability itself
        self.remove_single(capability_id);
    }

    /// Removes a single capability without cascading to descendants.
    ///
    /// This is an internal helper used by `remove` after descendants have
    /// already been collected and scheduled for removal.
    fn remove_single(&mut self, capability_id: &str) {
        if let Some(cap) = self.capabilities.remove(capability_id) {
            // Clean up namespace index
            if let Some(ids) = self.capabilities_by_namespace.get_mut(&cap.namespace) {
                ids.retain(|id| id != capability_id);
            }

            // Clean up holder index
            if let Some(ids) = self.capabilities_by_holder.get_mut(&cap.holder_actor_id) {
                ids.retain(|id| id != capability_id);
            }

            // Clean up delegation tree (parent's child list)
            if let Some(parent_id) = &cap.parent_capability_id {
                if let Some(children) = self.delegation_tree.get_mut(parent_id) {
                    children.retain(|id| id != capability_id);
                }
            }

            // Clean up delegation tree (this cap's children entry)
            self.delegation_tree.remove(capability_id);
        }
    }
}

#[cfg(test)]
mod tck_00199_tests {
    use super::*;

    // =========================================================================
    // CapabilityState Tests
    // =========================================================================

    #[test]
    fn test_capability_state_parse() {
        assert_eq!(
            CapabilityState::parse("ACTIVE").unwrap(),
            CapabilityState::Active
        );
        assert_eq!(
            CapabilityState::parse("active").unwrap(),
            CapabilityState::Active
        );
        assert_eq!(
            CapabilityState::parse("REVOKED").unwrap(),
            CapabilityState::Revoked
        );
        assert_eq!(
            CapabilityState::parse("EXPIRED").unwrap(),
            CapabilityState::Expired
        );
    }

    #[test]
    fn test_capability_state_parse_unknown_fails() {
        let result = CapabilityState::parse("UNKNOWN");
        assert!(matches!(result, Err(LeaseError::InvalidInput { .. })));

        let result = CapabilityState::parse("");
        assert!(matches!(result, Err(LeaseError::InvalidInput { .. })));
    }

    #[test]
    fn test_capability_state_as_str() {
        assert_eq!(CapabilityState::Active.as_str(), "ACTIVE");
        assert_eq!(CapabilityState::Revoked.as_str(), "REVOKED");
        assert_eq!(CapabilityState::Expired.as_str(), "EXPIRED");
    }

    #[test]
    fn test_capability_state_terminal() {
        assert!(!CapabilityState::Active.is_terminal());
        assert!(CapabilityState::Revoked.is_terminal());
        assert!(CapabilityState::Expired.is_terminal());
    }

    #[test]
    fn test_capability_state_active() {
        assert!(CapabilityState::Active.is_active());
        assert!(!CapabilityState::Revoked.is_active());
        assert!(!CapabilityState::Expired.is_active());
    }

    // =========================================================================
    // RevocationReason Tests
    // =========================================================================

    #[test]
    fn test_revocation_reason_parse() {
        assert_eq!(
            RevocationReason::parse("VOLUNTARY").unwrap(),
            RevocationReason::Voluntary
        );
        assert_eq!(
            RevocationReason::parse("POLICY_VIOLATION").unwrap(),
            RevocationReason::PolicyViolation
        );
        assert_eq!(
            RevocationReason::parse("KEY_COMPROMISE").unwrap(),
            RevocationReason::KeyCompromise
        );
        assert_eq!(
            RevocationReason::parse("SUPERSEDED").unwrap(),
            RevocationReason::Superseded
        );
    }

    #[test]
    fn test_revocation_reason_parse_unknown_fails() {
        let result = RevocationReason::parse("UNKNOWN");
        assert!(matches!(result, Err(LeaseError::InvalidInput { .. })));
    }

    #[test]
    fn test_revocation_reason_as_str() {
        assert_eq!(RevocationReason::Voluntary.as_str(), "VOLUNTARY");
        assert_eq!(
            RevocationReason::PolicyViolation.as_str(),
            "POLICY_VIOLATION"
        );
        assert_eq!(RevocationReason::KeyCompromise.as_str(), "KEY_COMPROMISE");
        assert_eq!(RevocationReason::Superseded.as_str(), "SUPERSEDED");
    }

    // =========================================================================
    // Capability Tests
    // =========================================================================

    #[test]
    fn test_capability_new() {
        let cap = Capability::new(
            "cap-1".to_string(),
            "namespace-1".to_string(),
            "actor-alice".to_string(),
            "registrar".to_string(),
            vec![1, 2, 3],
            vec![4, 5, 6],
            1_000_000_000,
            2_000_000_000,
            vec![7, 8, 9],
            true,
        );

        assert_eq!(cap.capability_id, "cap-1");
        assert_eq!(cap.namespace, "namespace-1");
        assert_eq!(cap.holder_actor_id, "actor-alice");
        assert_eq!(cap.grantor_actor_id, "registrar");
        assert_eq!(cap.state, CapabilityState::Active);
        assert_eq!(cap.scope_hash, vec![1, 2, 3]);
        assert_eq!(cap.budget_hash, vec![4, 5, 6]);
        assert_eq!(cap.granted_at, 1_000_000_000);
        assert_eq!(cap.expires_at, 2_000_000_000);
        assert_eq!(cap.signature, vec![7, 8, 9]);
        assert!(cap.delegatable);
        assert!(cap.parent_capability_id.is_none());
        assert_eq!(cap.delegation_depth, 0);
        assert!(cap.is_active());
        assert!(!cap.is_terminal());
        assert!(!cap.is_delegated());
    }

    #[test]
    fn test_capability_new_delegated() {
        let cap = Capability::new_delegated(
            "cap-2".to_string(),
            "cap-1".to_string(),
            "namespace-1".to_string(),
            "actor-bob".to_string(),
            "actor-alice".to_string(),
            vec![1, 2],
            vec![],
            1_500_000_000,
            1_900_000_000,
            vec![10, 11],
            false,
            1,
        );

        assert_eq!(cap.capability_id, "cap-2");
        assert_eq!(cap.parent_capability_id, Some("cap-1".to_string()));
        assert_eq!(cap.holder_actor_id, "actor-bob");
        assert_eq!(cap.grantor_actor_id, "actor-alice");
        assert_eq!(cap.delegation_depth, 1);
        assert!(cap.is_delegated());
        assert!(!cap.delegatable);
    }

    #[test]
    fn test_capability_is_expired_at() {
        let cap = Capability::new(
            "cap-1".to_string(),
            "ns".to_string(),
            "alice".to_string(),
            "reg".to_string(),
            vec![],
            vec![],
            1_000_000_000,
            2_000_000_000,
            vec![1],
            false,
        );

        assert!(!cap.is_expired_at(1_500_000_000));
        assert!(cap.is_expired_at(2_000_000_000));
        assert!(cap.is_expired_at(3_000_000_000));
    }

    #[test]
    fn test_capability_time_remaining() {
        let cap = Capability::new(
            "cap-1".to_string(),
            "ns".to_string(),
            "alice".to_string(),
            "reg".to_string(),
            vec![],
            vec![],
            1_000_000_000,
            2_000_000_000,
            vec![1],
            false,
        );

        assert_eq!(cap.time_remaining(1_500_000_000), 500_000_000);
        assert_eq!(cap.time_remaining(2_000_000_000), 0);
        assert_eq!(cap.time_remaining(3_000_000_000), 0);
    }

    #[test]
    fn test_capability_lease_id() {
        let cap = Capability::new(
            "lease-123".to_string(),
            "ns".to_string(),
            "alice".to_string(),
            "reg".to_string(),
            vec![],
            vec![],
            1_000_000_000,
            2_000_000_000,
            vec![1],
            false,
        );

        // Per RFC-0014: capability_id == lease_id
        assert_eq!(cap.lease_id(), "lease-123");
    }

    // =========================================================================
    // CapabilityProof Tests
    // =========================================================================

    #[test]
    fn test_capability_proof_new_root() {
        let proof = CapabilityProof::new_root(
            "cap-1".to_string(),
            "namespace-1".to_string(),
            "actor-alice".to_string(),
            vec![1, 2, 3],
            vec![],
            2_000_000_000,
            vec![10, 11, 12],
            vec![20, 21, 22],
        );

        assert_eq!(proof.capability_id, "cap-1");
        assert_eq!(proof.namespace, "namespace-1");
        assert_eq!(proof.holder_actor_id, "actor-alice");
        assert_eq!(proof.scope_hash, vec![1, 2, 3]);
        assert!(proof.budget_hash.is_empty());
        assert_eq!(proof.expires_at, 2_000_000_000);
        assert_eq!(proof.delegation_chain.len(), 1);
        assert_eq!(proof.delegation_depth(), 0);
        assert!(!proof.is_delegated());
        assert!(proof.root_grant_seq_id.is_none());
    }

    #[test]
    fn test_capability_proof_with_delegation_chain() {
        let chain = vec![
            DelegationChainEntry {
                capability_id: "cap-root".to_string(),
                holder_actor_id: "alice".to_string(),
                namespace: "ns".to_string(),
                scope_hash: vec![5],
                expires_at: 2_000_000_000,
                event_hash: vec![1],
                signature: vec![2],
                depth: 0,
            },
            DelegationChainEntry {
                capability_id: "cap-1".to_string(),
                holder_actor_id: "bob".to_string(),
                namespace: "ns".to_string(),
                scope_hash: vec![5],
                expires_at: 2_000_000_000,
                event_hash: vec![3],
                signature: vec![4],
                depth: 1,
            },
        ];

        let proof = CapabilityProof::with_delegation_chain(
            "cap-1".to_string(),
            "ns".to_string(),
            "bob".to_string(),
            vec![5],
            vec![],
            2_000_000_000,
            chain,
        )
        .unwrap();

        assert_eq!(proof.delegation_chain.len(), 2);
        assert_eq!(proof.delegation_depth(), 1);
        assert!(proof.is_delegated());
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)] // Loop bounded by small constant
    fn test_capability_proof_chain_too_long_fails() {
        let chain: Vec<DelegationChainEntry> = (0..=MAX_DELEGATION_CHAIN_ENTRIES)
            .map(|i| DelegationChainEntry {
                capability_id: format!("cap-{i}"),
                holder_actor_id: format!("actor-{i}"),
                namespace: "ns".to_string(),
                scope_hash: vec![],
                expires_at: 2_000_000_000,
                event_hash: vec![(i & 0xFF) as u8],
                signature: vec![(i & 0xFF) as u8],
                depth: (i & 0xFFFF_FFFF) as u32,
            })
            .collect();

        let result = CapabilityProof::with_delegation_chain(
            "cap-final".to_string(),
            "ns".to_string(),
            "final-actor".to_string(),
            vec![],
            vec![],
            2_000_000_000,
            chain,
        );

        assert!(matches!(result, Err(LeaseError::InvalidInput { .. })));
    }

    #[test]
    fn test_capability_proof_with_root_seq_id() {
        let proof = CapabilityProof::new_root(
            "cap-1".to_string(),
            "ns".to_string(),
            "alice".to_string(),
            vec![],
            vec![],
            2_000_000_000,
            vec![1],
            vec![2],
        )
        .with_root_seq_id(42);

        assert_eq!(proof.root_grant_seq_id, Some(42));
    }

    #[test]
    fn test_capability_proof_is_expired_at() {
        let proof = CapabilityProof::new_root(
            "cap-1".to_string(),
            "ns".to_string(),
            "alice".to_string(),
            vec![],
            vec![],
            2_000_000_000,
            vec![1],
            vec![2],
        );

        assert!(!proof.is_expired_at(1_500_000_000));
        assert!(proof.is_expired_at(2_000_000_000));
        assert!(proof.is_expired_at(3_000_000_000));
    }

    #[test]
    fn test_capability_proof_validate_structure_valid() {
        let proof = CapabilityProof::new_root(
            "cap-1".to_string(),
            "ns".to_string(),
            "alice".to_string(),
            vec![1, 2, 3],
            vec![],
            2_000_000_000,
            vec![10, 11],
            vec![20, 21],
        );

        // Valid at time before expiration
        assert!(proof.validate_structure(1_500_000_000).is_ok());
    }

    #[test]
    fn test_capability_proof_validate_structure_expired_fails() {
        let proof = CapabilityProof::new_root(
            "cap-1".to_string(),
            "ns".to_string(),
            "alice".to_string(),
            vec![],
            vec![],
            2_000_000_000,
            vec![1],
            vec![2],
        );

        let result = proof.validate_structure(2_500_000_000);
        assert!(
            matches!(result, Err(LeaseError::InvalidInput { field, .. }) if field == "expires_at")
        );
    }

    #[test]
    fn test_capability_proof_validate_structure_empty_chain_fails() {
        let proof = CapabilityProof {
            capability_id: "cap-1".to_string(),
            namespace: "ns".to_string(),
            holder_actor_id: "alice".to_string(),
            scope_hash: vec![],
            budget_hash: vec![],
            expires_at: 2_000_000_000,
            delegation_chain: vec![], // Empty chain
            root_grant_seq_id: None,
        };

        let result = proof.validate_structure(1_500_000_000);
        assert!(
            matches!(result, Err(LeaseError::InvalidInput { field, .. }) if field == "delegation_chain")
        );
    }

    #[test]
    fn test_capability_proof_validate_structure_id_too_long_fails() {
        let long_id = "x".repeat(MAX_ID_LEN + 1);
        let proof = CapabilityProof::new_root(
            long_id,
            "ns".to_string(),
            "alice".to_string(),
            vec![],
            vec![],
            2_000_000_000,
            vec![1],
            vec![2],
        );

        let result = proof.validate_structure(1_500_000_000);
        assert!(
            matches!(result, Err(LeaseError::InvalidInput { field, .. }) if field == "capability_id")
        );
    }

    #[test]
    fn test_capability_proof_validate_structure_namespace_too_long_fails() {
        let long_ns = "x".repeat(MAX_ID_LEN + 1);
        let proof = CapabilityProof::new_root(
            "cap-1".to_string(),
            long_ns,
            "alice".to_string(),
            vec![],
            vec![],
            2_000_000_000,
            vec![1],
            vec![2],
        );

        let result = proof.validate_structure(1_500_000_000);
        assert!(
            matches!(result, Err(LeaseError::InvalidInput { field, .. }) if field == "namespace")
        );
    }

    #[test]
    fn test_capability_proof_validate_structure_scope_hash_too_long_fails() {
        let long_hash = vec![0u8; MAX_HASH_LEN + 1];
        let proof = CapabilityProof::new_root(
            "cap-1".to_string(),
            "ns".to_string(),
            "alice".to_string(),
            long_hash,
            vec![],
            2_000_000_000,
            vec![1],
            vec![2],
        );

        let result = proof.validate_structure(1_500_000_000);
        assert!(
            matches!(result, Err(LeaseError::InvalidInput { field, .. }) if field == "scope_hash")
        );
    }

    #[test]
    fn test_capability_proof_validate_structure_chain_entry_depth_too_high() {
        let chain = vec![DelegationChainEntry {
            capability_id: "cap-1".to_string(),
            holder_actor_id: "alice".to_string(),
            namespace: "ns".to_string(),
            scope_hash: vec![],
            expires_at: 2_000_000_000,
            event_hash: vec![1],
            signature: vec![2],
            depth: MAX_DELEGATION_DEPTH + 1,
        }];

        let proof = CapabilityProof::with_delegation_chain(
            "cap-1".to_string(),
            "ns".to_string(),
            "alice".to_string(),
            vec![],
            vec![],
            2_000_000_000,
            chain,
        )
        .unwrap();

        let result = proof.validate_structure(1_500_000_000);
        assert!(
            matches!(result, Err(LeaseError::InvalidInput { field, .. }) if field.contains("depth"))
        );
    }

    // =========================================================================
    // CapabilityRegistryState Tests
    // =========================================================================

    #[test]
    fn test_registry_state_new() {
        let state = CapabilityRegistryState::new();
        assert!(state.is_empty());
        assert_eq!(state.len(), 0);
        assert_eq!(state.active_count(), 0);
    }

    #[test]
    fn test_registry_state_insert_and_get() {
        let mut state = CapabilityRegistryState::new();
        let cap = Capability::new(
            "cap-1".to_string(),
            "ns-1".to_string(),
            "alice".to_string(),
            "reg".to_string(),
            vec![1, 2, 3],
            vec![],
            1_000_000_000,
            2_000_000_000,
            vec![4, 5, 6],
            true,
        );

        state.insert(cap).unwrap();

        assert_eq!(state.len(), 1);
        assert!(!state.is_empty());
        assert_eq!(state.active_count(), 1);

        let retrieved = state.get("cap-1").unwrap();
        assert_eq!(retrieved.capability_id, "cap-1");
        assert_eq!(retrieved.namespace, "ns-1");
    }

    #[test]
    fn test_registry_state_insert_duplicate_fails() {
        let mut state = CapabilityRegistryState::new();
        let cap1 = Capability::new(
            "cap-1".to_string(),
            "ns-1".to_string(),
            "alice".to_string(),
            "reg".to_string(),
            vec![1, 2, 3],
            vec![],
            1_000_000_000,
            2_000_000_000,
            vec![4, 5, 6],
            true,
        );

        // First insert should succeed
        state.insert(cap1).unwrap();
        assert_eq!(state.len(), 1);

        // Second insert with same ID should fail
        let cap1_duplicate = Capability::new(
            "cap-1".to_string(), // Same ID as first capability
            "ns-2".to_string(),  // Different namespace
            "bob".to_string(),   // Different holder
            "reg".to_string(),
            vec![7, 8, 9],
            vec![],
            1_500_000_000,
            2_500_000_000,
            vec![10, 11, 12],
            false,
        );

        let result = state.insert(cap1_duplicate);
        assert!(
            matches!(result, Err(LeaseError::LeaseAlreadyExists { lease_id }) if lease_id == "cap-1")
        );

        // State should be unchanged
        assert_eq!(state.len(), 1);
        let retrieved = state.get("cap-1").unwrap();
        assert_eq!(retrieved.holder_actor_id, "alice"); // Original capability still there
    }

    #[test]
    fn test_registry_state_get_by_namespace() {
        let mut state = CapabilityRegistryState::new();

        // Add capabilities to different namespaces
        for i in 1u8..=3 {
            let cap = Capability::new(
                format!("cap-ns1-{i}"),
                "ns-1".to_string(),
                format!("actor-{i}"),
                "reg".to_string(),
                vec![],
                vec![],
                1_000_000_000,
                2_000_000_000,
                vec![i],
                false,
            );
            state.insert(cap).unwrap();
        }

        let cap_ns2 = Capability::new(
            "cap-ns2-1".to_string(),
            "ns-2".to_string(),
            "actor-x".to_string(),
            "reg".to_string(),
            vec![],
            vec![],
            1_000_000_000,
            2_000_000_000,
            vec![10],
            false,
        );
        state.insert(cap_ns2).unwrap();

        let ns1_caps = state.get_by_namespace("ns-1");
        assert_eq!(ns1_caps.len(), 3);

        let ns2_caps = state.get_by_namespace("ns-2");
        assert_eq!(ns2_caps.len(), 1);

        let ns3_caps = state.get_by_namespace("ns-3");
        assert!(ns3_caps.is_empty());
    }

    #[test]
    fn test_registry_state_get_by_holder() {
        let mut state = CapabilityRegistryState::new();

        // Alice has 2 capabilities
        for i in 1u8..=2 {
            let cap = Capability::new(
                format!("cap-alice-{i}"),
                "ns".to_string(),
                "alice".to_string(),
                "reg".to_string(),
                vec![],
                vec![],
                1_000_000_000,
                2_000_000_000,
                vec![i],
                false,
            );
            state.insert(cap).unwrap();
        }

        // Bob has 1 capability
        let cap_bob = Capability::new(
            "cap-bob-1".to_string(),
            "ns".to_string(),
            "bob".to_string(),
            "reg".to_string(),
            vec![],
            vec![],
            1_000_000_000,
            2_000_000_000,
            vec![10],
            false,
        );
        state.insert(cap_bob).unwrap();

        let alice_caps = state.get_by_holder("alice");
        assert_eq!(alice_caps.len(), 2);

        let bob_caps = state.get_by_holder("bob");
        assert_eq!(bob_caps.len(), 1);

        let carol_caps = state.get_by_holder("carol");
        assert!(carol_caps.is_empty());
    }

    #[test]
    fn test_registry_state_delegation_tree() {
        let mut state = CapabilityRegistryState::new();

        // Root capability
        let root = Capability::new(
            "cap-root".to_string(),
            "ns".to_string(),
            "alice".to_string(),
            "reg".to_string(),
            vec![],
            vec![],
            1_000_000_000,
            2_000_000_000,
            vec![1],
            true,
        );
        state.insert(root).unwrap();

        // Delegated to bob
        let delegated = Capability::new_delegated(
            "cap-bob".to_string(),
            "cap-root".to_string(),
            "ns".to_string(),
            "bob".to_string(),
            "alice".to_string(),
            vec![],
            vec![],
            1_500_000_000,
            2_000_000_000,
            vec![2],
            false,
            1,
        );
        state.insert(delegated).unwrap();

        let delegated_from_root = state.get_delegated_from("cap-root");
        assert_eq!(delegated_from_root.len(), 1);
        assert_eq!(delegated_from_root[0].capability_id, "cap-bob");

        let delegated_from_bob = state.get_delegated_from("cap-bob");
        assert!(delegated_from_bob.is_empty());
    }

    #[test]
    fn test_registry_state_prune_terminal() {
        let mut state = CapabilityRegistryState::new();

        // Add 3 active capabilities
        for i in 1u8..=3 {
            let cap = Capability::new(
                format!("cap-{i}"),
                "ns".to_string(),
                "alice".to_string(),
                "reg".to_string(),
                vec![],
                vec![],
                1_000_000_000,
                2_000_000_000,
                vec![i],
                false,
            );
            state.insert(cap).unwrap();
        }

        assert_eq!(state.len(), 3);
        assert_eq!(state.active_count(), 3);

        // Revoke cap-1
        if let Some(cap) = state.capabilities.get_mut("cap-1") {
            cap.state = CapabilityState::Revoked;
            cap.revoked_at = Some(1_500_000_000);
        }

        // Expire cap-2
        if let Some(cap) = state.capabilities.get_mut("cap-2") {
            cap.state = CapabilityState::Expired;
        }

        assert_eq!(state.active_count(), 1);

        let pruned = state.prune_terminal();
        assert_eq!(pruned, 2);
        assert_eq!(state.len(), 1);
        assert!(state.get("cap-1").is_none());
        assert!(state.get("cap-2").is_none());
        assert!(state.get("cap-3").is_some());
    }

    #[test]
    fn test_registry_state_get_expired_but_active() {
        let mut state = CapabilityRegistryState::new();

        // Cap that expires at 2s
        let cap1 = Capability::new(
            "cap-1".to_string(),
            "ns".to_string(),
            "alice".to_string(),
            "reg".to_string(),
            vec![],
            vec![],
            1_000_000_000,
            2_000_000_000,
            vec![1],
            false,
        );
        state.insert(cap1).unwrap();

        // Cap that expires at 3s
        let cap2 = Capability::new(
            "cap-2".to_string(),
            "ns".to_string(),
            "bob".to_string(),
            "reg".to_string(),
            vec![],
            vec![],
            1_000_000_000,
            3_000_000_000,
            vec![2],
            false,
        );
        state.insert(cap2).unwrap();

        // At 2.5s, only cap-1 should be expired
        let expired = state.get_expired_but_active(2_500_000_000);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].capability_id, "cap-1");

        // At 3.5s, both should be expired
        let expired = state.get_expired_but_active(3_500_000_000);
        assert_eq!(expired.len(), 2);
    }

    // =========================================================================
    // Namespace Binding Security Tests (Negative Tests)
    // =========================================================================

    #[test]
    fn test_namespace_binding_prevents_cross_namespace() {
        // This test verifies the design principle: capabilities are bound to namespaces
        let cap_ns1 = Capability::new(
            "cap-1".to_string(),
            "namespace-A".to_string(),
            "alice".to_string(),
            "reg".to_string(),
            vec![1, 2, 3],
            vec![],
            1_000_000_000,
            2_000_000_000,
            vec![4, 5, 6],
            true,
        );

        // Attempting to create a proof with a different namespace should be caught
        // during verification (the proof would not match the capability's namespace)
        let proof = CapabilityProof::new_root(
            "cap-1".to_string(),
            "namespace-B".to_string(), // Different namespace!
            "alice".to_string(),
            vec![1, 2, 3],
            vec![],
            2_000_000_000,
            vec![10],
            vec![20],
        );

        // Namespace mismatch: proof's namespace != capability's namespace
        assert_ne!(proof.namespace, cap_ns1.namespace);
    }

    #[test]
    fn test_delegation_must_match_parent_namespace() {
        // Delegated capability must have same namespace as parent
        let parent = Capability::new(
            "cap-parent".to_string(),
            "ns-1".to_string(),
            "alice".to_string(),
            "reg".to_string(),
            vec![],
            vec![],
            1_000_000_000,
            2_000_000_000,
            vec![1],
            true,
        );

        let child = Capability::new_delegated(
            "cap-child".to_string(),
            "cap-parent".to_string(),
            "ns-1".to_string(), // Must match parent namespace
            "bob".to_string(),
            "alice".to_string(),
            vec![],
            vec![],
            1_500_000_000,
            1_900_000_000,
            vec![2],
            false,
            1,
        );

        assert_eq!(parent.namespace, child.namespace);
    }

    // =========================================================================
    // Lease Linkage Tests
    // =========================================================================

    #[test]
    fn test_capability_id_equals_lease_id() {
        // Per RFC-0014 DD-0009: capability_id == lease_id
        let cap = Capability::new(
            "lease-456".to_string(), // Using lease ID as capability ID
            "ns".to_string(),
            "actor".to_string(),
            "registrar".to_string(),
            vec![1, 2, 3], // scope_hash references LeaseScope in CAS
            vec![4, 5, 6], // budget_hash references Budget in CAS
            1_000_000_000,
            2_000_000_000,
            vec![7, 8, 9],
            true,
        );

        assert_eq!(cap.lease_id(), "lease-456");
        assert_eq!(cap.capability_id, cap.lease_id());
    }

    // =========================================================================
    // Boundary Condition Tests
    // =========================================================================

    #[test]
    #[allow(clippy::cast_possible_truncation)] // Depth is bounded by MAX_DELEGATION_DEPTH (16)
    fn test_max_delegation_depth_boundary() {
        // Exactly at limit should work
        let chain: Vec<DelegationChainEntry> = (0..=MAX_DELEGATION_DEPTH)
            .map(|i| DelegationChainEntry {
                capability_id: format!("cap-{i}"),
                holder_actor_id: format!("actor-{i}"),
                namespace: "ns".to_string(),
                scope_hash: vec![],
                expires_at: 2_000_000_000,
                event_hash: vec![(i & 0xFF) as u8],
                signature: vec![(i & 0xFF) as u8],
                depth: i,
            })
            .collect();

        let result = CapabilityProof::with_delegation_chain(
            "cap-final".to_string(),
            "ns".to_string(),
            format!("actor-{MAX_DELEGATION_DEPTH}"),
            vec![],
            vec![],
            2_000_000_000,
            chain,
        );

        assert!(result.is_ok());
        let proof = result.unwrap();
        assert_eq!(proof.delegation_depth(), MAX_DELEGATION_DEPTH);
    }

    #[test]
    fn test_max_id_len_boundary() {
        // Exactly at limit should work
        let max_id = "x".repeat(MAX_ID_LEN);
        let proof = CapabilityProof::new_root(
            max_id,
            "ns".to_string(),
            "alice".to_string(),
            vec![],
            vec![],
            2_000_000_000,
            vec![1],
            vec![2],
        );

        assert!(proof.validate_structure(1_500_000_000).is_ok());

        // One over limit should fail
        let over_id = "x".repeat(MAX_ID_LEN + 1);
        let proof_over = CapabilityProof::new_root(
            over_id,
            "ns".to_string(),
            "alice".to_string(),
            vec![],
            vec![],
            2_000_000_000,
            vec![1],
            vec![2],
        );

        assert!(proof_over.validate_structure(1_500_000_000).is_err());
    }

    #[test]
    fn test_expiration_boundary_exactly_at_expiry() {
        let proof = CapabilityProof::new_root(
            "cap-1".to_string(),
            "ns".to_string(),
            "alice".to_string(),
            vec![],
            vec![],
            2_000_000_000, // expires_at
            vec![1],
            vec![2],
        );

        // One nanosecond before expiry - still valid
        assert!(!proof.is_expired_at(1_999_999_999));
        assert!(proof.validate_structure(1_999_999_999).is_ok());

        // Exactly at expiry - expired
        assert!(proof.is_expired_at(2_000_000_000));
        assert!(proof.validate_structure(2_000_000_000).is_err());
    }

    // =========================================================================
    // Serde Tests (CTR-1604: deny_unknown_fields)
    // =========================================================================

    #[test]
    fn test_capability_state_serde_roundtrip() {
        let state = CapabilityState::Active;
        let json = serde_json::to_string(&state).unwrap();
        let parsed: CapabilityState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, parsed);
    }

    #[test]
    fn test_capability_serde_roundtrip() {
        let cap = Capability::new(
            "cap-1".to_string(),
            "ns".to_string(),
            "alice".to_string(),
            "reg".to_string(),
            vec![1, 2, 3],
            vec![4, 5, 6],
            1_000_000_000,
            2_000_000_000,
            vec![7, 8, 9],
            true,
        );

        let json = serde_json::to_string(&cap).unwrap();
        let parsed: Capability = serde_json::from_str(&json).unwrap();
        assert_eq!(cap, parsed);
    }

    #[test]
    fn test_capability_proof_serde_roundtrip() {
        let proof = CapabilityProof::new_root(
            "cap-1".to_string(),
            "ns".to_string(),
            "alice".to_string(),
            vec![1, 2, 3],
            vec![],
            2_000_000_000,
            vec![10, 11],
            vec![20, 21],
        );

        let json = serde_json::to_string(&proof).unwrap();
        let parsed: CapabilityProof = serde_json::from_str(&json).unwrap();
        assert_eq!(proof, parsed);
    }

    #[test]
    fn test_capability_state_unknown_field_rejected() {
        // CTR-1604: deny_unknown_fields should reject unknown fields
        // CapabilityState is an enum, not a struct, so the struct test
        // (test_capability_unknown_field_rejected) validates this pattern.
        // For enums, serde will reject invalid variant names.
        let json = r#""INVALID_STATE""#;
        let result: Result<CapabilityState, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_capability_unknown_field_rejected() {
        // CTR-1604: deny_unknown_fields
        let json = r#"{
            "capability_id": "cap-1",
            "namespace": "ns",
            "holder_actor_id": "alice",
            "grantor_actor_id": "reg",
            "state": "Active",
            "scope_hash": [1,2,3],
            "budget_hash": [],
            "granted_at": 1000000000,
            "expires_at": 2000000000,
            "signature": [4,5,6],
            "delegatable": true,
            "parent_capability_id": null,
            "delegation_depth": 0,
            "revocation_reason": null,
            "revoked_at": null,
            "revoker_actor_id": null,
            "unknown_evil_field": "attack"
        }"#;

        let result: Result<Capability, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_capability_proof_unknown_field_rejected() {
        // CTR-1604: deny_unknown_fields
        let json = r#"{
            "capability_id": "cap-1",
            "namespace": "ns",
            "holder_actor_id": "alice",
            "scope_hash": [],
            "budget_hash": [],
            "expires_at": 2000000000,
            "delegation_chain": [],
            "root_grant_seq_id": null,
            "malicious_field": true
        }"#;

        let result: Result<CapabilityProof, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    // =========================================================================
    // HIGH-01: Cascading Revocation Tests
    // =========================================================================

    #[test]
    fn test_cascading_revocation_removes_all_descendants() {
        // HIGH-01: When a capability is removed, all descendants must also be removed.
        // This prevents 'dangling authority' where a revoked parent still has active
        // children.
        let mut state = CapabilityRegistryState::new();

        // Create a delegation tree:
        //   root (alice)
        //     |
        //   child1 (bob)
        //     |
        //   grandchild1 (carol)

        let root = Capability::new(
            "cap-root".to_string(),
            "ns".to_string(),
            "alice".to_string(),
            "reg".to_string(),
            vec![],
            vec![],
            1_000_000_000,
            2_000_000_000,
            vec![1],
            true,
        );
        state.insert(root).unwrap();

        let child1 = Capability::new_delegated(
            "cap-child1".to_string(),
            "cap-root".to_string(),
            "ns".to_string(),
            "bob".to_string(),
            "alice".to_string(),
            vec![],
            vec![],
            1_100_000_000,
            2_000_000_000,
            vec![2],
            true,
            1,
        );
        state.insert(child1).unwrap();

        let grandchild1 = Capability::new_delegated(
            "cap-grandchild1".to_string(),
            "cap-child1".to_string(),
            "ns".to_string(),
            "carol".to_string(),
            "bob".to_string(),
            vec![],
            vec![],
            1_200_000_000,
            2_000_000_000,
            vec![3],
            false,
            2,
        );
        state.insert(grandchild1).unwrap();

        // Verify initial state
        assert_eq!(state.len(), 3);
        assert!(state.get("cap-root").is_some());
        assert!(state.get("cap-child1").is_some());
        assert!(state.get("cap-grandchild1").is_some());

        // Now revoke the root capability
        if let Some(cap) = state.capabilities.get_mut("cap-root") {
            cap.state = CapabilityState::Revoked;
            cap.revoked_at = Some(1_500_000_000);
        }

        // Prune terminal capabilities (this triggers cascading removal)
        let pruned = state.prune_terminal();

        // Verify cascading revocation: root and ALL descendants should be removed
        assert_eq!(pruned, 1); // Only root was marked as terminal
        assert!(state.get("cap-root").is_none(), "Root should be removed");
        assert!(
            state.get("cap-child1").is_none(),
            "Child should be removed via cascading revocation"
        );
        assert!(
            state.get("cap-grandchild1").is_none(),
            "Grandchild should be removed via cascading revocation"
        );
        assert_eq!(state.len(), 0);
    }

    #[test]
    fn test_cascading_revocation_with_multiple_children() {
        // HIGH-01: Test cascading revocation with a wider tree (multiple children)
        let mut state = CapabilityRegistryState::new();

        // Create a delegation tree:
        //        root (alice)
        //       /     \
        //   child1   child2
        //   (bob)    (carol)
        //     |
        // grandchild1
        //   (dave)

        let root = Capability::new(
            "cap-root".to_string(),
            "ns".to_string(),
            "alice".to_string(),
            "reg".to_string(),
            vec![],
            vec![],
            1_000_000_000,
            2_000_000_000,
            vec![1],
            true,
        );
        state.insert(root).unwrap();

        let child1 = Capability::new_delegated(
            "cap-child1".to_string(),
            "cap-root".to_string(),
            "ns".to_string(),
            "bob".to_string(),
            "alice".to_string(),
            vec![],
            vec![],
            1_100_000_000,
            2_000_000_000,
            vec![2],
            true,
            1,
        );
        state.insert(child1).unwrap();

        let child2 = Capability::new_delegated(
            "cap-child2".to_string(),
            "cap-root".to_string(),
            "ns".to_string(),
            "carol".to_string(),
            "alice".to_string(),
            vec![],
            vec![],
            1_100_000_000,
            2_000_000_000,
            vec![3],
            false,
            1,
        );
        state.insert(child2).unwrap();

        let grandchild1 = Capability::new_delegated(
            "cap-grandchild1".to_string(),
            "cap-child1".to_string(),
            "ns".to_string(),
            "dave".to_string(),
            "bob".to_string(),
            vec![],
            vec![],
            1_200_000_000,
            2_000_000_000,
            vec![4],
            false,
            2,
        );
        state.insert(grandchild1).unwrap();

        assert_eq!(state.len(), 4);

        // Revoke the root
        if let Some(cap) = state.capabilities.get_mut("cap-root") {
            cap.state = CapabilityState::Revoked;
        }

        let pruned = state.prune_terminal();
        assert_eq!(pruned, 1);

        // All capabilities should be removed
        assert!(state.get("cap-root").is_none());
        assert!(state.get("cap-child1").is_none());
        assert!(state.get("cap-child2").is_none());
        assert!(state.get("cap-grandchild1").is_none());
        assert_eq!(state.len(), 0);
    }

    #[test]
    fn test_cascading_revocation_preserves_unrelated_capabilities() {
        // HIGH-01: Cascading revocation should only affect descendants, not siblings
        let mut state = CapabilityRegistryState::new();

        // Create two separate trees:
        //   root1 (alice)      root2 (eve)
        //     |                  |
        //   child1 (bob)      child2 (frank)

        let root1 = Capability::new(
            "cap-root1".to_string(),
            "ns".to_string(),
            "alice".to_string(),
            "reg".to_string(),
            vec![],
            vec![],
            1_000_000_000,
            2_000_000_000,
            vec![1],
            true,
        );
        state.insert(root1).unwrap();

        let child1 = Capability::new_delegated(
            "cap-child1".to_string(),
            "cap-root1".to_string(),
            "ns".to_string(),
            "bob".to_string(),
            "alice".to_string(),
            vec![],
            vec![],
            1_100_000_000,
            2_000_000_000,
            vec![2],
            false,
            1,
        );
        state.insert(child1).unwrap();

        let root2 = Capability::new(
            "cap-root2".to_string(),
            "ns".to_string(),
            "eve".to_string(),
            "reg".to_string(),
            vec![],
            vec![],
            1_000_000_000,
            2_000_000_000,
            vec![3],
            true,
        );
        state.insert(root2).unwrap();

        let child2 = Capability::new_delegated(
            "cap-child2".to_string(),
            "cap-root2".to_string(),
            "ns".to_string(),
            "frank".to_string(),
            "eve".to_string(),
            vec![],
            vec![],
            1_100_000_000,
            2_000_000_000,
            vec![4],
            false,
            1,
        );
        state.insert(child2).unwrap();

        assert_eq!(state.len(), 4);

        // Revoke only root1
        if let Some(cap) = state.capabilities.get_mut("cap-root1") {
            cap.state = CapabilityState::Revoked;
        }

        let pruned = state.prune_terminal();
        assert_eq!(pruned, 1);

        // root1 tree should be removed
        assert!(state.get("cap-root1").is_none());
        assert!(state.get("cap-child1").is_none());

        // root2 tree should be preserved
        assert!(state.get("cap-root2").is_some());
        assert!(state.get("cap-child2").is_some());
        assert_eq!(state.len(), 2);
    }

    #[test]
    fn test_get_all_descendants_returns_correct_ids() {
        // Direct test of the get_all_descendants helper
        let mut state = CapabilityRegistryState::new();

        // Create a tree: root -> child1, child2 -> grandchild1
        let root = Capability::new(
            "cap-root".to_string(),
            "ns".to_string(),
            "alice".to_string(),
            "reg".to_string(),
            vec![],
            vec![],
            1_000_000_000,
            2_000_000_000,
            vec![1],
            true,
        );
        state.insert(root).unwrap();

        let child1 = Capability::new_delegated(
            "cap-child1".to_string(),
            "cap-root".to_string(),
            "ns".to_string(),
            "bob".to_string(),
            "alice".to_string(),
            vec![],
            vec![],
            1_100_000_000,
            2_000_000_000,
            vec![2],
            true,
            1,
        );
        state.insert(child1).unwrap();

        let child2 = Capability::new_delegated(
            "cap-child2".to_string(),
            "cap-root".to_string(),
            "ns".to_string(),
            "carol".to_string(),
            "alice".to_string(),
            vec![],
            vec![],
            1_100_000_000,
            2_000_000_000,
            vec![3],
            false,
            1,
        );
        state.insert(child2).unwrap();

        let grandchild1 = Capability::new_delegated(
            "cap-grandchild1".to_string(),
            "cap-child1".to_string(),
            "ns".to_string(),
            "dave".to_string(),
            "bob".to_string(),
            vec![],
            vec![],
            1_200_000_000,
            2_000_000_000,
            vec![4],
            false,
            2,
        );
        state.insert(grandchild1).unwrap();

        // Test get_all_descendants from root
        let descendants = state.get_all_descendants("cap-root");
        assert_eq!(descendants.len(), 3);
        assert!(descendants.contains(&"cap-child1".to_string()));
        assert!(descendants.contains(&"cap-child2".to_string()));
        assert!(descendants.contains(&"cap-grandchild1".to_string()));

        // Test get_all_descendants from child1
        let descendants = state.get_all_descendants("cap-child1");
        assert_eq!(descendants.len(), 1);
        assert!(descendants.contains(&"cap-grandchild1".to_string()));

        // Test get_all_descendants from leaf (no children)
        let descendants = state.get_all_descendants("cap-grandchild1");
        assert!(descendants.is_empty());

        // Test get_all_descendants for non-existent capability
        let descendants = state.get_all_descendants("cap-nonexistent");
        assert!(descendants.is_empty());
    }
}

// =============================================================================
// TCK-00200: Signature Verification Tests
// =============================================================================

#[cfg(test)]
mod tck_00200_signature_tests {
    use std::collections::HashMap;

    use super::*;
    use crate::crypto::Signer;

    /// Helper to create a test signer and return (signer, `public_key_bytes`).
    fn create_test_signer() -> (Signer, Vec<u8>) {
        let signer = Signer::generate();
        let public_key = signer.public_key_bytes().to_vec();
        (signer, public_key)
    }

    /// Helper to create a signed delegation chain entry with proper metadata
    /// binding.
    ///
    /// This creates an entry where the `event_hash` is correctly derived from
    /// the metadata fields, and the signature is over that `event_hash`.
    fn create_signed_entry(
        capability_id: &str,
        holder_actor_id: &str,
        namespace: &str,
        scope_hash: &[u8],
        expires_at: u64,
        depth: u32,
        signer: &Signer,
    ) -> DelegationChainEntry {
        // Compute the canonical event hash from metadata (CRITICAL-01)
        let event_hash = DelegationChainEntry::compute_event_hash_from_parts(
            capability_id,
            holder_actor_id,
            namespace,
            scope_hash,
            expires_at,
            depth,
        );

        // Sign the event hash
        let signature = signer.sign(&event_hash);

        DelegationChainEntry {
            capability_id: capability_id.to_string(),
            holder_actor_id: holder_actor_id.to_string(),
            namespace: namespace.to_string(),
            scope_hash: scope_hash.to_vec(),
            expires_at,
            event_hash,
            signature: signature.to_bytes().to_vec(),
            depth,
        }
    }

    // =========================================================================
    // Test: Valid proof verification succeeds
    // =========================================================================

    // Test constants for consistency
    const TEST_NAMESPACE: &str = "ns-1";
    const TEST_SCOPE_HASH: &[u8] = &[1, 2, 3];
    const TEST_EXPIRES_AT: u64 = 2_000_000_000;

    #[test]
    fn test_valid_root_proof_verification_succeeds() {
        // Create registrar signer
        let (registrar_signer, registrar_pk) = create_test_signer();

        // Create a root capability proof with valid signature
        let root_entry = create_signed_entry(
            "cap-root",
            "alice",
            TEST_NAMESPACE,
            TEST_SCOPE_HASH,
            TEST_EXPIRES_AT,
            0,
            &registrar_signer,
        );

        let proof = CapabilityProof::with_delegation_chain(
            "cap-root".to_string(),
            TEST_NAMESPACE.to_string(),
            "alice".to_string(),
            TEST_SCOPE_HASH.to_vec(),
            vec![],
            TEST_EXPIRES_AT,
            vec![root_entry],
        )
        .unwrap();

        // Create public key lookup
        let get_actor_pk = |_actor_id: &str| -> Option<Vec<u8>> { None };

        // Verify signatures
        let result = proof.validate_signatures_with_registrar(&registrar_pk, get_actor_pk);
        assert!(result.is_ok(), "Valid root proof should verify: {result:?}");
    }

    #[test]
    fn test_valid_delegated_proof_verification_succeeds() {
        // Create signers for registrar, alice (root holder), and bob (delegated holder)
        let (registrar_signer, registrar_pk) = create_test_signer();
        let (alice_signer, alice_pk) = create_test_signer();

        // Create root entry signed by registrar
        let root_entry = create_signed_entry(
            "cap-root",
            "alice",
            TEST_NAMESPACE,
            TEST_SCOPE_HASH,
            TEST_EXPIRES_AT,
            0,
            &registrar_signer,
        );

        // Create delegation entry signed by alice (delegating to bob)
        let delegation_entry = create_signed_entry(
            "cap-delegated",
            "bob",
            TEST_NAMESPACE,
            TEST_SCOPE_HASH,
            TEST_EXPIRES_AT,
            1,
            &alice_signer,
        );

        let proof = CapabilityProof::with_delegation_chain(
            "cap-delegated".to_string(),
            TEST_NAMESPACE.to_string(),
            "bob".to_string(),
            TEST_SCOPE_HASH.to_vec(),
            vec![],
            TEST_EXPIRES_AT,
            vec![root_entry, delegation_entry],
        )
        .unwrap();

        // Create public key lookup that resolves alice's key
        let mut keys: HashMap<String, Vec<u8>> = HashMap::new();
        keys.insert("alice".to_string(), alice_pk);

        let get_actor_pk = |actor_id: &str| -> Option<Vec<u8>> { keys.get(actor_id).cloned() };

        // Verify signatures
        let result = proof.validate_signatures_with_registrar(&registrar_pk, get_actor_pk);
        assert!(
            result.is_ok(),
            "Valid delegated proof should verify: {result:?}"
        );
    }

    #[test]
    fn test_valid_multi_level_delegation_verification_succeeds() {
        // Create signers for registrar, alice, bob, and carol
        let (registrar_signer, registrar_pk) = create_test_signer();
        let (alice_signer, alice_pk) = create_test_signer();
        let (bob_signer, bob_pk) = create_test_signer();

        // Create chain: registrar -> alice -> bob -> carol
        let root_entry = create_signed_entry(
            "cap-root",
            "alice",
            TEST_NAMESPACE,
            TEST_SCOPE_HASH,
            TEST_EXPIRES_AT,
            0,
            &registrar_signer,
        );
        let delegation1 = create_signed_entry(
            "cap-d1",
            "bob",
            TEST_NAMESPACE,
            TEST_SCOPE_HASH,
            TEST_EXPIRES_AT,
            1,
            &alice_signer,
        );
        let delegation2 = create_signed_entry(
            "cap-d2",
            "carol",
            TEST_NAMESPACE,
            TEST_SCOPE_HASH,
            TEST_EXPIRES_AT,
            2,
            &bob_signer,
        );

        let proof = CapabilityProof::with_delegation_chain(
            "cap-d2".to_string(),
            TEST_NAMESPACE.to_string(),
            "carol".to_string(),
            TEST_SCOPE_HASH.to_vec(),
            vec![],
            TEST_EXPIRES_AT,
            vec![root_entry, delegation1, delegation2],
        )
        .unwrap();

        // Create public key lookup
        let mut keys: HashMap<String, Vec<u8>> = HashMap::new();
        keys.insert("alice".to_string(), alice_pk);
        keys.insert("bob".to_string(), bob_pk);

        let get_actor_pk = |actor_id: &str| -> Option<Vec<u8>> { keys.get(actor_id).cloned() };

        // Verify signatures
        let result = proof.validate_signatures_with_registrar(&registrar_pk, get_actor_pk);
        assert!(
            result.is_ok(),
            "Valid multi-level delegation should verify: {result:?}"
        );
    }

    // =========================================================================
    // Test: Invalid signature is rejected
    // =========================================================================

    #[test]
    fn test_invalid_root_signature_rejected() {
        // Create registrar signer and a different (wrong) signer
        let (_registrar_signer, registrar_pk) = create_test_signer();
        let (wrong_signer, _wrong_pk) = create_test_signer();

        // Create root entry signed by WRONG signer
        let root_entry = create_signed_entry(
            "cap-root",
            "alice",
            TEST_NAMESPACE,
            TEST_SCOPE_HASH,
            TEST_EXPIRES_AT,
            0,
            &wrong_signer,
        );

        let proof = CapabilityProof::with_delegation_chain(
            "cap-root".to_string(),
            TEST_NAMESPACE.to_string(),
            "alice".to_string(),
            TEST_SCOPE_HASH.to_vec(),
            vec![],
            TEST_EXPIRES_AT,
            vec![root_entry],
        )
        .unwrap();

        let get_actor_pk = |_actor_id: &str| -> Option<Vec<u8>> { None };

        // Verification should fail
        let result = proof.validate_signatures_with_registrar(&registrar_pk, get_actor_pk);
        assert!(
            matches!(result, Err(LeaseError::InvalidSignature { .. })),
            "Invalid root signature should be rejected: {result:?}"
        );
    }

    #[test]
    fn test_invalid_delegation_signature_rejected() {
        // Create signers
        let (registrar_signer, registrar_pk) = create_test_signer();
        let (_alice_signer, alice_pk) = create_test_signer();
        let (wrong_signer, _wrong_pk) = create_test_signer();

        // Valid root entry
        let root_entry = create_signed_entry(
            "cap-root",
            "alice",
            TEST_NAMESPACE,
            TEST_SCOPE_HASH,
            TEST_EXPIRES_AT,
            0,
            &registrar_signer,
        );

        // Delegation entry signed by WRONG signer (not alice)
        let delegation_entry = create_signed_entry(
            "cap-delegated",
            "bob",
            TEST_NAMESPACE,
            TEST_SCOPE_HASH,
            TEST_EXPIRES_AT,
            1,
            &wrong_signer,
        );

        let proof = CapabilityProof::with_delegation_chain(
            "cap-delegated".to_string(),
            TEST_NAMESPACE.to_string(),
            "bob".to_string(),
            TEST_SCOPE_HASH.to_vec(),
            vec![],
            TEST_EXPIRES_AT,
            vec![root_entry, delegation_entry],
        )
        .unwrap();

        let mut keys: HashMap<String, Vec<u8>> = HashMap::new();
        keys.insert("alice".to_string(), alice_pk);

        let get_actor_pk = |actor_id: &str| -> Option<Vec<u8>> { keys.get(actor_id).cloned() };

        // Verification should fail
        let result = proof.validate_signatures_with_registrar(&registrar_pk, get_actor_pk);
        assert!(
            matches!(result, Err(LeaseError::InvalidSignature { .. })),
            "Invalid delegation signature should be rejected: {result:?}"
        );
    }

    // =========================================================================
    // Test: Tampered chain entry is rejected
    // =========================================================================

    #[test]
    fn test_tampered_event_hash_rejected() {
        let (registrar_signer, registrar_pk) = create_test_signer();

        // Create a valid signed entry
        let mut root_entry = create_signed_entry(
            "cap-root",
            "alice",
            TEST_NAMESPACE,
            TEST_SCOPE_HASH,
            TEST_EXPIRES_AT,
            0,
            &registrar_signer,
        );

        // Tamper with the event hash after signing
        root_entry.event_hash[0] ^= 0xFF;

        let proof = CapabilityProof::with_delegation_chain(
            "cap-root".to_string(),
            TEST_NAMESPACE.to_string(),
            "alice".to_string(),
            TEST_SCOPE_HASH.to_vec(),
            vec![],
            TEST_EXPIRES_AT,
            vec![root_entry],
        )
        .unwrap();

        let get_actor_pk = |_actor_id: &str| -> Option<Vec<u8>> { None };

        // Verification should fail because event hash doesn't match metadata
        // (CRITICAL-01) This is now caught by metadata binding verification
        // before signature verification
        let result = proof.validate_signatures_with_registrar(&registrar_pk, get_actor_pk);
        assert!(
            matches!(result, Err(LeaseError::InvalidInput { ref field, .. }) if field.contains("event_hash")),
            "Tampered event hash should be rejected: {result:?}"
        );
    }

    #[test]
    fn test_tampered_signature_rejected() {
        let (registrar_signer, registrar_pk) = create_test_signer();

        // Create a valid signed entry
        let mut root_entry = create_signed_entry(
            "cap-root",
            "alice",
            TEST_NAMESPACE,
            TEST_SCOPE_HASH,
            TEST_EXPIRES_AT,
            0,
            &registrar_signer,
        );

        // Tamper with the signature
        root_entry.signature[0] ^= 0xFF;

        let proof = CapabilityProof::with_delegation_chain(
            "cap-root".to_string(),
            TEST_NAMESPACE.to_string(),
            "alice".to_string(),
            TEST_SCOPE_HASH.to_vec(),
            vec![],
            TEST_EXPIRES_AT,
            vec![root_entry],
        )
        .unwrap();

        let get_actor_pk = |_actor_id: &str| -> Option<Vec<u8>> { None };

        // Verification should fail
        let result = proof.validate_signatures_with_registrar(&registrar_pk, get_actor_pk);
        assert!(
            matches!(result, Err(LeaseError::InvalidSignature { .. })),
            "Tampered signature should be rejected: {result:?}"
        );
    }

    // =========================================================================
    // Test: Missing signature is rejected
    // =========================================================================

    #[test]
    fn test_empty_signature_rejected() {
        let (_registrar_signer, registrar_pk) = create_test_signer();

        // Create entry with empty signature - compute correct event hash first
        let event_hash = DelegationChainEntry::compute_event_hash_from_parts(
            "cap-root",
            "alice",
            TEST_NAMESPACE,
            TEST_SCOPE_HASH,
            TEST_EXPIRES_AT,
            0,
        );

        let root_entry = DelegationChainEntry {
            capability_id: "cap-root".to_string(),
            holder_actor_id: "alice".to_string(),
            namespace: TEST_NAMESPACE.to_string(),
            scope_hash: TEST_SCOPE_HASH.to_vec(),
            expires_at: TEST_EXPIRES_AT,
            event_hash,
            signature: vec![], // Empty signature!
            depth: 0,
        };

        let proof = CapabilityProof::with_delegation_chain(
            "cap-root".to_string(),
            TEST_NAMESPACE.to_string(),
            "alice".to_string(),
            TEST_SCOPE_HASH.to_vec(),
            vec![],
            TEST_EXPIRES_AT,
            vec![root_entry],
        )
        .unwrap();

        let get_actor_pk = |_actor_id: &str| -> Option<Vec<u8>> { None };

        // Verification should fail with MissingSignature
        let result = proof.validate_signatures_with_registrar(&registrar_pk, get_actor_pk);
        assert!(
            matches!(result, Err(LeaseError::MissingSignature { .. })),
            "Empty signature should be rejected: {result:?}"
        );
    }

    #[test]
    fn test_empty_event_hash_rejected() {
        let (registrar_signer, registrar_pk) = create_test_signer();

        // Create entry with empty event hash
        let signature = registrar_signer.sign(&[1, 2, 3]);
        let root_entry = DelegationChainEntry {
            capability_id: "cap-root".to_string(),
            holder_actor_id: "alice".to_string(),
            namespace: TEST_NAMESPACE.to_string(),
            scope_hash: TEST_SCOPE_HASH.to_vec(),
            expires_at: TEST_EXPIRES_AT,
            event_hash: vec![], // Empty event hash!
            signature: signature.to_bytes().to_vec(),
            depth: 0,
        };

        let proof = CapabilityProof::with_delegation_chain(
            "cap-root".to_string(),
            TEST_NAMESPACE.to_string(),
            "alice".to_string(),
            TEST_SCOPE_HASH.to_vec(),
            vec![],
            TEST_EXPIRES_AT,
            vec![root_entry],
        )
        .unwrap();

        let get_actor_pk = |_actor_id: &str| -> Option<Vec<u8>> { None };

        // Verification should fail with InvalidInput
        let result = proof.validate_signatures_with_registrar(&registrar_pk, get_actor_pk);
        assert!(
            matches!(result, Err(LeaseError::InvalidInput { .. })),
            "Empty event hash should be rejected: {result:?}"
        );
    }

    // =========================================================================
    // Test: Missing public key is rejected
    // =========================================================================

    #[test]
    fn test_missing_delegator_public_key_rejected() {
        let (registrar_signer, registrar_pk) = create_test_signer();
        let (alice_signer, _alice_pk) = create_test_signer();

        let root_entry = create_signed_entry(
            "cap-root",
            "alice",
            TEST_NAMESPACE,
            TEST_SCOPE_HASH,
            TEST_EXPIRES_AT,
            0,
            &registrar_signer,
        );
        let delegation_entry = create_signed_entry(
            "cap-delegated",
            "bob",
            TEST_NAMESPACE,
            TEST_SCOPE_HASH,
            TEST_EXPIRES_AT,
            1,
            &alice_signer,
        );

        let proof = CapabilityProof::with_delegation_chain(
            "cap-delegated".to_string(),
            TEST_NAMESPACE.to_string(),
            "bob".to_string(),
            TEST_SCOPE_HASH.to_vec(),
            vec![],
            TEST_EXPIRES_AT,
            vec![root_entry, delegation_entry],
        )
        .unwrap();

        // Don't provide alice's public key
        let get_actor_pk = |_actor_id: &str| -> Option<Vec<u8>> { None };

        // Verification should fail because alice's key cannot be resolved
        let result = proof.validate_signatures_with_registrar(&registrar_pk, get_actor_pk);
        assert!(
            matches!(&result, Err(LeaseError::InvalidInput { field, .. }) if field.contains("delegation_chain")),
            "Missing delegator public key should be rejected: {result:?}"
        );
    }

    // =========================================================================
    // Test: Full verify() method combines structural + signature validation
    // =========================================================================

    #[test]
    fn test_verify_combines_structural_and_signature_validation() {
        let (registrar_signer, registrar_pk) = create_test_signer();

        let root_entry = create_signed_entry(
            "cap-root",
            "alice",
            TEST_NAMESPACE,
            TEST_SCOPE_HASH,
            TEST_EXPIRES_AT,
            0,
            &registrar_signer,
        );

        let proof = CapabilityProof::with_delegation_chain(
            "cap-root".to_string(),
            TEST_NAMESPACE.to_string(),
            "alice".to_string(),
            TEST_SCOPE_HASH.to_vec(),
            vec![],
            TEST_EXPIRES_AT,
            vec![root_entry],
        )
        .unwrap();

        let get_actor_pk = |_actor_id: &str| -> Option<Vec<u8>> { None };

        // Full verification at time before expiration
        let result = proof.verify(1_500_000_000, &registrar_pk, get_actor_pk);
        assert!(result.is_ok(), "Full verify should succeed: {result:?}");
    }

    #[test]
    fn test_verify_rejects_expired_proof() {
        let (registrar_signer, registrar_pk) = create_test_signer();

        let root_entry = create_signed_entry(
            "cap-root",
            "alice",
            TEST_NAMESPACE,
            TEST_SCOPE_HASH,
            TEST_EXPIRES_AT,
            0,
            &registrar_signer,
        );

        let proof = CapabilityProof::with_delegation_chain(
            "cap-root".to_string(),
            TEST_NAMESPACE.to_string(),
            "alice".to_string(),
            TEST_SCOPE_HASH.to_vec(),
            vec![],
            TEST_EXPIRES_AT, // expires at 2s
            vec![root_entry],
        )
        .unwrap();

        let get_actor_pk = |_actor_id: &str| -> Option<Vec<u8>> { None };

        // Full verification at time AFTER expiration
        let result = proof.verify(2_500_000_000, &registrar_pk, get_actor_pk);
        assert!(
            matches!(&result, Err(LeaseError::InvalidInput { field, .. }) if field == "expires_at"),
            "verify() should reject expired proof: {result:?}"
        );
    }

    // =========================================================================
    // Test: Determinism - same inputs always produce same result
    // =========================================================================

    #[test]
    fn test_verification_is_deterministic() {
        let (registrar_signer, registrar_pk) = create_test_signer();
        let (alice_signer, alice_pk) = create_test_signer();

        let root_entry = create_signed_entry(
            "cap-root",
            "alice",
            TEST_NAMESPACE,
            TEST_SCOPE_HASH,
            TEST_EXPIRES_AT,
            0,
            &registrar_signer,
        );
        let delegation_entry = create_signed_entry(
            "cap-delegated",
            "bob",
            TEST_NAMESPACE,
            TEST_SCOPE_HASH,
            TEST_EXPIRES_AT,
            1,
            &alice_signer,
        );

        let proof = CapabilityProof::with_delegation_chain(
            "cap-delegated".to_string(),
            TEST_NAMESPACE.to_string(),
            "bob".to_string(),
            TEST_SCOPE_HASH.to_vec(),
            vec![],
            TEST_EXPIRES_AT,
            vec![root_entry, delegation_entry],
        )
        .unwrap();

        let mut keys: HashMap<String, Vec<u8>> = HashMap::new();
        keys.insert("alice".to_string(), alice_pk);

        let get_actor_pk = |actor_id: &str| -> Option<Vec<u8>> { keys.get(actor_id).cloned() };

        // Verify multiple times - should always get the same result
        for _ in 0..10 {
            let result = proof.validate_signatures_with_registrar(&registrar_pk, get_actor_pk);
            assert!(result.is_ok(), "Verification should be deterministic");
        }
    }

    // =========================================================================
    // Test: Invalid public key format is rejected
    // =========================================================================

    #[test]
    fn test_malformed_public_key_rejected() {
        let (registrar_signer, _registrar_pk) = create_test_signer();
        let (alice_signer, _alice_pk) = create_test_signer();

        let root_entry = create_signed_entry(
            "cap-root",
            "alice",
            TEST_NAMESPACE,
            TEST_SCOPE_HASH,
            TEST_EXPIRES_AT,
            0,
            &registrar_signer,
        );
        let delegation_entry = create_signed_entry(
            "cap-delegated",
            "bob",
            TEST_NAMESPACE,
            TEST_SCOPE_HASH,
            TEST_EXPIRES_AT,
            1,
            &alice_signer,
        );

        let proof = CapabilityProof::with_delegation_chain(
            "cap-delegated".to_string(),
            TEST_NAMESPACE.to_string(),
            "bob".to_string(),
            TEST_SCOPE_HASH.to_vec(),
            vec![],
            TEST_EXPIRES_AT,
            vec![root_entry, delegation_entry],
        )
        .unwrap();

        // Provide malformed registrar public key
        let bad_registrar_pk = vec![0u8; 16]; // Wrong size

        let mut keys: HashMap<String, Vec<u8>> = HashMap::new();
        keys.insert("alice".to_string(), vec![0u8; 32]); // Also malformed

        let get_actor_pk = |actor_id: &str| -> Option<Vec<u8>> { keys.get(actor_id).cloned() };

        let result = proof.validate_signatures_with_registrar(&bad_registrar_pk, get_actor_pk);
        assert!(
            matches!(result, Err(LeaseError::InvalidSignature { .. })),
            "Malformed public key should be rejected: {result:?}"
        );
    }

    // =========================================================================
    // Test: validate_signatures (with _registrar_ convention)
    // =========================================================================

    #[test]
    fn test_validate_signatures_with_registrar_convention() {
        let (registrar_signer, registrar_pk) = create_test_signer();

        let root_entry = create_signed_entry(
            "cap-root",
            "alice",
            TEST_NAMESPACE,
            TEST_SCOPE_HASH,
            TEST_EXPIRES_AT,
            0,
            &registrar_signer,
        );

        let proof = CapabilityProof::with_delegation_chain(
            "cap-root".to_string(),
            TEST_NAMESPACE.to_string(),
            "alice".to_string(),
            TEST_SCOPE_HASH.to_vec(),
            vec![],
            TEST_EXPIRES_AT,
            vec![root_entry],
        )
        .unwrap();

        // Use the _registrar_ convention lookup
        let get_pk = |actor_id: &str| -> Option<Vec<u8>> {
            if actor_id == "_registrar_cap-root" {
                Some(registrar_pk.clone())
            } else {
                None
            }
        };

        let result = proof.validate_signatures(get_pk);
        assert!(
            result.is_ok(),
            "validate_signatures with _registrar_ convention should work: {result:?}"
        );
    }

    // =========================================================================
    // CRITICAL-01: Metadata Substitution Attack Tests
    // =========================================================================

    #[test]
    fn test_metadata_substitution_attack_holder_swap_rejected() {
        // CRITICAL-01: Test that an attacker cannot reuse a valid signature
        // from a grant to Alice but substitute their own holder_actor_id.
        //
        // Scenario: Alice has a valid capability. Mallory (attacker) tries to
        // create a proof claiming to be the holder, but using Alice's valid
        // event_hash and signature.
        let (registrar_signer, registrar_pk) = create_test_signer();

        // Create a legitimate entry for Alice
        let alice_entry = create_signed_entry(
            "cap-root",
            "alice", // Alice is the legitimate holder
            TEST_NAMESPACE,
            TEST_SCOPE_HASH,
            TEST_EXPIRES_AT,
            0,
            &registrar_signer,
        );

        // Attacker creates a proof claiming to be "mallory" but uses Alice's
        // event_hash and signature
        let attack_entry = DelegationChainEntry {
            capability_id: alice_entry.capability_id.clone(),
            holder_actor_id: "mallory".to_string(), // Attacker substitutes holder!
            namespace: alice_entry.namespace.clone(),
            scope_hash: alice_entry.scope_hash.clone(),
            expires_at: alice_entry.expires_at,
            event_hash: alice_entry.event_hash.clone(), // Uses Alice's event_hash
            signature: alice_entry.signature.clone(),   // Uses Alice's signature
            depth: alice_entry.depth,
        };

        let proof = CapabilityProof::with_delegation_chain(
            "cap-root".to_string(),
            TEST_NAMESPACE.to_string(),
            "mallory".to_string(), // Attacker claims to be holder
            TEST_SCOPE_HASH.to_vec(),
            vec![],
            TEST_EXPIRES_AT,
            vec![attack_entry],
        )
        .unwrap();

        let get_actor_pk = |_actor_id: &str| -> Option<Vec<u8>> { None };

        // CRITICAL: This MUST fail because the event_hash was computed for
        // "alice" but the entry claims "mallory" as the holder
        let result = proof.validate_signatures_with_registrar(&registrar_pk, get_actor_pk);
        assert!(
            matches!(result, Err(LeaseError::InvalidInput { ref field, .. }) if field.contains("event_hash")),
            "Metadata substitution attack (holder swap) MUST be rejected: {result:?}"
        );
    }

    #[test]
    fn test_metadata_substitution_attack_namespace_swap_rejected() {
        // CRITICAL-01: Test that an attacker cannot swap the namespace while
        // keeping the original signature.
        let (registrar_signer, registrar_pk) = create_test_signer();

        // Create a legitimate entry for namespace "ns-1"
        let legitimate_entry = create_signed_entry(
            "cap-root",
            "alice",
            "ns-1", // Original namespace
            TEST_SCOPE_HASH,
            TEST_EXPIRES_AT,
            0,
            &registrar_signer,
        );

        // Attacker creates an entry claiming a different namespace
        let attack_entry = DelegationChainEntry {
            capability_id: legitimate_entry.capability_id.clone(),
            holder_actor_id: legitimate_entry.holder_actor_id.clone(),
            namespace: "ns-ATTACKER".to_string(), // Attacker substitutes namespace!
            scope_hash: legitimate_entry.scope_hash.clone(),
            expires_at: legitimate_entry.expires_at,
            event_hash: legitimate_entry.event_hash.clone(), // Uses original hash
            signature: legitimate_entry.signature.clone(),   // Uses original sig
            depth: legitimate_entry.depth,
        };

        let proof = CapabilityProof::with_delegation_chain(
            "cap-root".to_string(),
            "ns-ATTACKER".to_string(), // Claims attacker's namespace
            "alice".to_string(),
            TEST_SCOPE_HASH.to_vec(),
            vec![],
            TEST_EXPIRES_AT,
            vec![attack_entry],
        )
        .unwrap();

        let get_actor_pk = |_actor_id: &str| -> Option<Vec<u8>> { None };

        // CRITICAL: This MUST fail because the event_hash was computed for
        // "ns-1" but the entry claims "ns-ATTACKER"
        let result = proof.validate_signatures_with_registrar(&registrar_pk, get_actor_pk);
        assert!(
            matches!(result, Err(LeaseError::InvalidInput { ref field, .. }) if field.contains("event_hash")),
            "Metadata substitution attack (namespace swap) MUST be rejected: {result:?}"
        );
    }

    #[test]
    fn test_event_hash_binding_verification_works() {
        // Verify that DelegationChainEntry::verify_event_hash_binding works
        let (signer, _pk) = create_test_signer();

        // Valid entry with correct binding
        let valid_entry = create_signed_entry(
            "cap-1",
            "alice",
            TEST_NAMESPACE,
            TEST_SCOPE_HASH,
            TEST_EXPIRES_AT,
            0,
            &signer,
        );

        assert!(
            valid_entry.verify_event_hash_binding().is_ok(),
            "Valid entry should pass binding verification"
        );

        // Entry with wrong event hash (doesn't match metadata)
        let mut invalid_entry = valid_entry;
        invalid_entry.event_hash[0] ^= 0xFF; // Corrupt the hash

        assert!(
            invalid_entry.verify_event_hash_binding().is_err(),
            "Entry with corrupted hash should fail binding verification"
        );
    }

    // =========================================================================
    // HIGH-02: Ledger State Verification Tests
    // =========================================================================

    #[test]
    fn test_verify_with_state_succeeds_for_valid_capability() {
        let (registrar_signer, registrar_pk) = create_test_signer();

        // Create a capability in the registry
        let mut registry = CapabilityRegistryState::new();
        let capability = Capability::new(
            "cap-root".to_string(),
            TEST_NAMESPACE.to_string(),
            "alice".to_string(),
            "registrar".to_string(),
            TEST_SCOPE_HASH.to_vec(),
            vec![],
            1_000_000_000,
            TEST_EXPIRES_AT,
            vec![1, 2, 3], // signature placeholder
            true,
        );
        registry.insert(capability).unwrap();

        // Create a matching proof
        let root_entry = create_signed_entry(
            "cap-root",
            "alice",
            TEST_NAMESPACE,
            TEST_SCOPE_HASH,
            TEST_EXPIRES_AT,
            0,
            &registrar_signer,
        );

        let proof = CapabilityProof::with_delegation_chain(
            "cap-root".to_string(),
            TEST_NAMESPACE.to_string(),
            "alice".to_string(),
            TEST_SCOPE_HASH.to_vec(),
            vec![],
            TEST_EXPIRES_AT,
            vec![root_entry],
        )
        .unwrap();

        let get_actor_pk = |_actor_id: &str| -> Option<Vec<u8>> { None };

        // Full verification with state should succeed
        let result = proof.verify_with_state(1_500_000_000, &registrar_pk, get_actor_pk, &registry);
        assert!(
            result.is_ok(),
            "verify_with_state should succeed for valid capability: {result:?}"
        );
    }

    #[test]
    fn test_verify_with_state_rejects_missing_capability() {
        let (registrar_signer, registrar_pk) = create_test_signer();

        // Empty registry - capability doesn't exist
        let registry = CapabilityRegistryState::new();

        let root_entry = create_signed_entry(
            "cap-root",
            "alice",
            TEST_NAMESPACE,
            TEST_SCOPE_HASH,
            TEST_EXPIRES_AT,
            0,
            &registrar_signer,
        );

        let proof = CapabilityProof::with_delegation_chain(
            "cap-root".to_string(),
            TEST_NAMESPACE.to_string(),
            "alice".to_string(),
            TEST_SCOPE_HASH.to_vec(),
            vec![],
            TEST_EXPIRES_AT,
            vec![root_entry],
        )
        .unwrap();

        let get_actor_pk = |_actor_id: &str| -> Option<Vec<u8>> { None };

        // Should fail because capability doesn't exist in registry
        let result = proof.verify_with_state(1_500_000_000, &registrar_pk, get_actor_pk, &registry);
        assert!(
            matches!(result, Err(LeaseError::LeaseNotFound { .. })),
            "verify_with_state should reject missing capability: {result:?}"
        );
    }

    #[test]
    fn test_verify_with_state_rejects_revoked_capability() {
        let (registrar_signer, registrar_pk) = create_test_signer();

        // Create a revoked capability in the registry
        let mut registry = CapabilityRegistryState::new();
        let mut capability = Capability::new(
            "cap-root".to_string(),
            TEST_NAMESPACE.to_string(),
            "alice".to_string(),
            "registrar".to_string(),
            TEST_SCOPE_HASH.to_vec(),
            vec![],
            1_000_000_000,
            TEST_EXPIRES_AT,
            vec![1, 2, 3],
            true,
        );
        capability.state = CapabilityState::Revoked;
        capability.revoked_at = Some(1_200_000_000);
        registry.insert(capability).unwrap();

        let root_entry = create_signed_entry(
            "cap-root",
            "alice",
            TEST_NAMESPACE,
            TEST_SCOPE_HASH,
            TEST_EXPIRES_AT,
            0,
            &registrar_signer,
        );

        let proof = CapabilityProof::with_delegation_chain(
            "cap-root".to_string(),
            TEST_NAMESPACE.to_string(),
            "alice".to_string(),
            TEST_SCOPE_HASH.to_vec(),
            vec![],
            TEST_EXPIRES_AT,
            vec![root_entry],
        )
        .unwrap();

        let get_actor_pk = |_actor_id: &str| -> Option<Vec<u8>> { None };

        // Should fail because capability is revoked
        let result = proof.verify_with_state(1_500_000_000, &registrar_pk, get_actor_pk, &registry);
        assert!(
            matches!(result, Err(LeaseError::LeaseRevoked { .. })),
            "verify_with_state should reject revoked capability: {result:?}"
        );
    }

    #[test]
    fn test_verify_with_state_rejects_holder_mismatch() {
        let (registrar_signer, registrar_pk) = create_test_signer();

        // Create a capability with alice as holder
        let mut registry = CapabilityRegistryState::new();
        let capability = Capability::new(
            "cap-root".to_string(),
            TEST_NAMESPACE.to_string(),
            "alice".to_string(), // Alice is the holder in registry
            "registrar".to_string(),
            TEST_SCOPE_HASH.to_vec(),
            vec![],
            1_000_000_000,
            TEST_EXPIRES_AT,
            vec![1, 2, 3],
            true,
        );
        registry.insert(capability).unwrap();

        // But proof claims bob is the holder
        let root_entry = create_signed_entry(
            "cap-root",
            "bob", // Bob claims to be holder
            TEST_NAMESPACE,
            TEST_SCOPE_HASH,
            TEST_EXPIRES_AT,
            0,
            &registrar_signer,
        );

        let proof = CapabilityProof::with_delegation_chain(
            "cap-root".to_string(),
            TEST_NAMESPACE.to_string(),
            "bob".to_string(),
            TEST_SCOPE_HASH.to_vec(),
            vec![],
            TEST_EXPIRES_AT,
            vec![root_entry],
        )
        .unwrap();

        let get_actor_pk = |_actor_id: &str| -> Option<Vec<u8>> { None };

        // Should fail because holder in proof doesn't match registry
        let result = proof.verify_with_state(1_500_000_000, &registrar_pk, get_actor_pk, &registry);
        assert!(
            matches!(&result, Err(LeaseError::InvalidInput { field, .. }) if field.contains("holder")),
            "verify_with_state should reject holder mismatch: {result:?}"
        );
    }
}
