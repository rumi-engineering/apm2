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
//!
//! # Security Model
//!
//! The FAC implements a capability-based security model where:
//!
//! 1. **Gate leases** are cryptographically signed authorizations
//! 2. **Domain separation** prevents cross-protocol signature replay
//! 3. **Scope subset rules** prevent privilege escalation
//! 4. **Time envelopes** enforce temporal authority bounds
//!
//! # Example
//!
//! ```rust
//! use apm2_core::crypto::Signer;
//! use apm2_core::fac::{
//!     GATE_LEASE_ISSUED_PREFIX, GateLease, GateLeaseBuilder,
//! };
//!
//! // Create an issuer
//! let issuer = Signer::generate();
//!
//! // Issue a gate lease
//! let lease = GateLeaseBuilder::new("lease-001", "work-001", "gate-build")
//!     .changeset_digest([0x42; 32])
//!     .executor_actor_id("executor-001")
//!     .issued_at(1704067200000)
//!     .expires_at(1704070800000)
//!     .policy_hash([0xab; 32])
//!     .issuer_actor_id("issuer-001")
//!     .time_envelope_ref("htf:tick:12345")
//!     .build_and_sign(&issuer);
//!
//! // Verify the lease
//! assert!(lease.validate_signature(&issuer.verifying_key()).is_ok());
//! ```

mod domain_separator;
mod lease;

// Re-export domain separator constants
pub use domain_separator::{
    AAT_RESULT_REUSED_PREFIX, CI_IMPORT_ATTESTATION_PREFIX, GATE_LEASE_ISSUED_PREFIX,
    GATE_RECEIPT_PREFIX, GATE_RUN_COMPLETED_PREFIX, LEASE_REVOKED_PREFIX, MERGE_RECEIPT_PREFIX,
    POLICY_RESOLVED_PREFIX, PROJECTION_RECEIPT_PREFIX, QUARANTINE_EVENT_PREFIX, sign_with_domain,
    verify_with_domain,
};
// Re-export lease types
pub use lease::{
    AatLeaseExtension, AatLeaseExtensionProto, GateLease, GateLeaseBuilder, GateLeaseProto,
    GateLeaseScope, LeaseError,
};
