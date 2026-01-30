//! Forge Admission Cycle (FAC) module.
//!
//! This module implements the core types and validation logic for the Forge
//! Admission Cycle, which governs how changes flow through quality gates
//! before merge.
//!
//! # Components
//!
//! - **Domain Separators**: Cryptographic prefixes preventing signature replay
//! - **Gate Leases**: Authorization tokens binding executors to changesets
//! - **Policy Resolution**: Anchor events locking policy decisions for
//!   changesets
//! - **Gate Receipts**: Versioned envelopes for gate execution results
//!
//! # Security Model
//!
//! The FAC implements a capability-based security model where:
//!
//! 1. **Gate leases** are cryptographically signed authorizations
//! 2. **Domain separation** prevents cross-protocol signature replay
//! 3. **Policy resolution** locks policy decisions before lease issuance
//! 4. **Time envelopes** enforce temporal authority bounds
//! 5. **Gate receipts** provide cryptographic proof of gate execution
//!
//! # Ordering Invariant
//!
//! **CRITICAL**: A `PolicyResolvedForChangeSet` event MUST exist before any
//! `GateLeaseIssued` event for the same `work_id`/changeset. This ensures all
//! leases operate under a locked policy configuration.
//!
//! # Example
//!
//! ```rust
//! use apm2_core::crypto::Signer;
//! use apm2_core::fac::{
//!     GATE_LEASE_ISSUED_PREFIX, GateLease, GateLeaseBuilder,
//!     PolicyResolvedForChangeSet, PolicyResolvedForChangeSetBuilder,
//! };
//!
//! // First, resolve the policy for the changeset
//! let resolver = Signer::generate();
//! let resolution =
//!     PolicyResolvedForChangeSetBuilder::new("work-001", [0x42; 32])
//!         .resolved_risk_tier(1)
//!         .resolved_determinism_class(0)
//!         .resolver_actor_id("resolver-001")
//!         .resolver_version("1.0.0")
//!         .build_and_sign(&resolver);
//!
//! // Then issue a gate lease referencing the resolved policy
//! let issuer = Signer::generate();
//! let lease = GateLeaseBuilder::new("lease-001", "work-001", "gate-build")
//!     .changeset_digest([0x42; 32])
//!     .executor_actor_id("executor-001")
//!     .issued_at(1704067200000)
//!     .expires_at(1704070800000)
//!     .policy_hash(resolution.resolved_policy_hash())
//!     .issuer_actor_id("issuer-001")
//!     .time_envelope_ref("htf:tick:12345")
//!     .build_and_sign(&issuer);
//!
//! // Verify the lease matches the policy resolution
//! assert!(resolution.verify_lease_match(&lease).is_ok());
//! ```

mod domain_separator;
mod key_policy;
mod lease;
mod policy_resolution;
mod receipt;

// Re-export domain separator constants and functions
pub use domain_separator::{
    AAT_RESULT_REUSED_PREFIX, CI_IMPORT_ATTESTATION_PREFIX, GATE_LEASE_ISSUED_PREFIX,
    GATE_RECEIPT_PREFIX, GATE_RUN_COMPLETED_PREFIX, INTERVENTION_FREEZE_PREFIX,
    INTERVENTION_UNFREEZE_PREFIX, LEASE_REVOKED_PREFIX, MERGE_RECEIPT_PREFIX,
    POLICY_RESOLVED_PREFIX, PROJECTION_RECEIPT_PREFIX, QUARANTINE_EVENT_PREFIX, sign_with_domain,
    verify_with_domain,
};
// Re-export key policy types
pub use key_policy::{
    CoiEnforcementLevel, CoiRule, CustodyDomain, DelegationRule, KeyBinding, KeyPolicy,
    KeyPolicyBuilder, KeyPolicyError, MAX_COI_RULES, MAX_CUSTODY_DOMAINS, MAX_DELEGATION_RULES,
    MAX_KEY_BINDINGS, SUPPORTED_SCHEMA_VERSIONS,
};
// Re-export lease types
pub use lease::{AatLeaseExtension, GateLease, GateLeaseBuilder, LeaseError};
// Re-export policy resolution types
pub use policy_resolution::{
    DeterminismClass, MAX_RCP_PROFILES, MAX_STRING_LENGTH, MAX_VERIFIER_POLICIES,
    PolicyResolutionError, PolicyResolvedForChangeSet, PolicyResolvedForChangeSetBuilder,
    PolicyResolvedForChangeSetProto, RiskTier,
};
// Re-export receipt types
pub use receipt::{
    GateReceipt, GateReceiptBuilder, GateReceiptProto, ReceiptError, SUPPORTED_PAYLOAD_KINDS,
    SUPPORTED_PAYLOAD_SCHEMA_VERSIONS, SUPPORTED_RECEIPT_VERSIONS,
};
