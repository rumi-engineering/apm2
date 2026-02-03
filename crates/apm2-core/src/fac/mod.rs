//! Forge Admission Cycle (FAC) module.
//!
//! This module implements the core types and validation logic for the Forge
//! Admission Cycle, which governs how changes flow through quality gates
//! before merge.
//!
//! # Components
//!
//! - **CI Attestation**: Types representing CI evidence trustworthiness levels
//! - **Domain Separators**: Cryptographic prefixes preventing signature replay
//! - **Gate Leases**: Authorization tokens binding executors to changesets
//! - **Policy Resolution**: Anchor events locking policy decisions for
//!   changesets
//! - **Gate Receipts**: Versioned envelopes for gate execution results
//! - **Terminal Verifiers**: Machine-checkable predicates for AAT outcomes
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

mod aat_receipt;
pub mod aat_reuse;
mod aat_spec;
pub mod anti_downgrade;
mod artifact_manifest;
mod changeset_bundle;
mod ci_attestation;
mod ci_import;
pub mod determinism;
mod domain_separator;
pub mod echo_trap;
pub mod flake_class;
pub mod harness_sandbox;
mod key_policy;
mod lease;
pub mod merge_receipt;
mod policy_resolution;
pub mod quarantine;
mod receipt;
pub mod retry_manager;
mod review_blocked;
pub mod risk_tier;
pub mod selection_policy;
mod terminal_verifier;
pub mod transcript_binding;

// Re-export AAT receipt types
pub use aat_receipt::{
    AatAttestation, AatGateReceipt, AatGateReceiptBuilder, AatReceiptError, AatVerdict,
    DeterminismStatus, FlakeClass, MAX_RUN_RECEIPT_HASHES,
    MAX_STRING_LENGTH as MAX_AAT_STRING_LENGTH, MAX_TERMINAL_VERIFIER_OUTPUTS,
    MAX_TOOLCHAIN_DIGESTS, TerminalVerifierOutput,
};
// Re-export AAT reuse types
pub use aat_reuse::{
    AATResultReused, AATResultReusedProto, AatProvenanceTuple, AatProvenanceTupleProto, ReuseError,
    can_reuse_aat_result,
};
// Re-export AAT spec types
pub use aat_spec::{
    AatSpec, AatSpecBuilder, AatSpecError, AatStep, AatStepBuilder, Invariant, InvariantBuilder,
    MAX_ACTION_LENGTH, MAX_INVARIANTS, MAX_STATEMENT_LENGTH, MAX_STEPS,
};
// Re-export artifact manifest types
pub use artifact_manifest::{
    ArtifactDigest, ArtifactManifest, ArtifactManifestBuilder, ArtifactManifestError, ArtifactType,
    DataClassification, HygieneError, MAX_ARTIFACTS,
    MAX_STRING_LENGTH as MAX_ARTIFACT_STRING_LENGTH, validate_evidence_hygiene_for_admission,
};
// Re-export changeset bundle types
pub use changeset_bundle::{
    ChangeKind, ChangeSetBundleError, ChangeSetBundleV1, ChangeSetBundleV1Builder,
    ChangeSetPublished, ChangeSetPublishedProto, FileChange, GitObjectRef, HashAlgo,
    MAX_CHANGESET_ID_LENGTH, MAX_FILE_MANIFEST_SIZE, MAX_PATH_LENGTH, SCHEMA_IDENTIFIER,
    SCHEMA_VERSION,
};
// Re-export CI attestation types
pub use ci_attestation::{
    CiAttestation, CiAttestationBuilder, CiAttestationError, CiAttestationLevel,
    MAX_DOWNLOADED_ARTIFACT_HASHES, MAX_STRING_LENGTH as MAX_CI_ATTESTATION_STRING_LENGTH,
};
// Re-export CI import types
pub use ci_import::{
    CiEvidenceImport, CiEvidenceImportBuilder, CiImportAttestation, CiImportAttestationBuilder,
    CiImportError, CiImportPolicy, MAX_ARTIFACT_DIGESTS, MAX_IMPORT_ID_LENGTH,
    MAX_WORKFLOW_RUN_ID_LENGTH, can_transition_to_ready_for_review, validate_ci_import,
};
// Re-export determinism types
pub use determinism::{
    DeterminismEnvelope, DeterminismEnvelopeBuilder, DeterminismError,
    MAX_RUN_COUNT as MAX_DETERMINISM_RUN_COUNT,
    MAX_RUN_RECEIPT_HASHES as MAX_DETERMINISM_RUN_HASHES, REQUIRED_RUNS_DEFAULT,
    REQUIRED_RUNS_HIGH, REQUIRED_RUNS_LOW, REQUIRED_RUNS_MED, REQUIRED_RUNS_TIER0,
    REQUIRED_RUNS_TIER1, REQUIRED_RUNS_TIER2, REQUIRED_RUNS_TIER3, REQUIRED_RUNS_TIER4,
    RISK_TIER_HIGH, RISK_TIER_LOW, RISK_TIER_MED, check_stability, compute_stability_digest,
    required_run_count,
};
// Re-export domain separator constants and functions
pub use domain_separator::{
    AAT_RESULT_REUSED_PREFIX, CHANGESET_PUBLISHED_PREFIX, CI_IMPORT_ATTESTATION_PREFIX,
    GATE_LEASE_ISSUED_PREFIX, GATE_RECEIPT_PREFIX, GATE_RUN_COMPLETED_PREFIX,
    INTERVENTION_FREEZE_PREFIX, INTERVENTION_UNFREEZE_PREFIX, LEASE_REVOKED_PREFIX,
    LEDGER_EVENT_PREFIX, MERGE_RECEIPT_PREFIX, POLICY_RESOLVED_PREFIX, PROJECTION_RECEIPT_PREFIX,
    QUARANTINE_EVENT_PREFIX, REVIEW_BLOCKED_RECORDED_PREFIX, sign_with_domain, verify_with_domain,
};
// Re-export echo-trap detection types
pub use echo_trap::{
    ECHO_TRAP_THRESHOLD, EchoTrapDetector, EchoTrapError, EchoTrapEvent, FindingSignature,
    MAX_SIGNATURE_LENGTH, MAX_SIGNATURES as MAX_ECHO_TRAP_SIGNATURES, SessionTermination,
    TerminationRationale,
};
// Re-export flake classification routing types
pub use flake_class::FlakeRouting;
// Re-export harness sandbox types
pub use harness_sandbox::{
    EgressRule, HarnessSandboxError, MAX_EGRESS_RULES, MAX_HOST_LENGTH,
    MAX_STRING_LENGTH as MAX_HARNESS_SANDBOX_STRING_LENGTH, NetworkPolicyProfile,
    NetworkPolicyProfileBuilder, Protocol,
};
// Re-export key policy types
pub use key_policy::{
    CoiEnforcementLevel, CoiRule, CustodyDomain, DelegationRule, KeyBinding, KeyPolicy,
    KeyPolicyBuilder, KeyPolicyError, MAX_COI_RULES, MAX_CUSTODY_DOMAINS, MAX_DELEGATION_RULES,
    MAX_KEY_BINDINGS, SUPPORTED_SCHEMA_VERSIONS,
};
// Re-export lease types
pub use lease::{
    AatLeaseExtension, GateLease, GateLeaseBuilder, LeaseError, validate_custody_for_aat_lease,
    validate_custody_for_aat_lease_by_actor,
};
// Re-export merge receipt types
pub use merge_receipt::{
    MAX_GATE_RECEIPTS as MAX_MERGE_GATE_RECEIPTS, MergeReceipt, MergeReceiptError,
    MergeReceiptProto,
};
// Re-export policy resolution types
pub use policy_resolution::{
    DeterminismClass, MAX_RCP_PROFILES, MAX_STRING_LENGTH, MAX_VERIFIER_POLICIES,
    PolicyResolutionError, PolicyResolvedForChangeSet, PolicyResolvedForChangeSetBuilder,
    PolicyResolvedForChangeSetProto, RiskTier,
};
// Re-export quarantine types
pub use quarantine::{
    AATSpecQuarantined, AATSpecQuarantinedProto, MAX_EVIDENCE_REFS, MAX_QUARANTINED_ITEMS,
    MAX_STRING_LENGTH as MAX_QUARANTINE_STRING_LENGTH, QuarantineCleared, QuarantineClearedProto,
    QuarantineError, QuarantineEvent, QuarantineProjection, RunnerPoolQuarantined,
    RunnerPoolQuarantinedProto,
};
// Re-export receipt types
pub use receipt::{
    GateReceipt, GateReceiptBuilder, GateReceiptProto, ReceiptError, SUPPORTED_PAYLOAD_KINDS,
    SUPPORTED_PAYLOAD_SCHEMA_VERSIONS, SUPPORTED_RECEIPT_VERSIONS,
};
// Re-export retry manager types
pub use retry_manager::{
    MAX_GATE_ATTEMPTS, MAX_GLOBAL_EPISODES, MAX_TRACKED_GATES, RetryError, RetryManager,
};
// Re-export review blocked types
pub use review_blocked::{
    MAX_BLOCKED_ID_LENGTH, MAX_STRING_LENGTH as MAX_REVIEW_BLOCKED_STRING_LENGTH, ReasonCode,
    ReviewBlockedError, ReviewBlockedRecorded, ReviewBlockedRecordedBuilder,
    ReviewBlockedRecordedProto, SCHEMA_IDENTIFIER as REVIEW_BLOCKED_SCHEMA_IDENTIFIER,
    SCHEMA_VERSION as REVIEW_BLOCKED_SCHEMA_VERSION,
};
// Re-export risk tier classification types
pub use risk_tier::{
    CRITICAL_MODULES, ChangeSet, DEPENDENCY_FANOUT_THRESHOLD, FILES_CHANGED_THRESHOLD,
    LINES_CHANGED_THRESHOLD, RiskTierClass, RiskTierError, SENSITIVE_PATTERNS, classify_risk,
};
// Re-export selection policy types
pub use selection_policy::{
    AatRequirement, DEFAULT_LOW_TIER_SAMPLE_RATE, MAX_DOMAIN_LENGTH, MAX_POLICY_ID_LENGTH,
    MAX_POLICY_SIZE, MAX_WORK_ID_LENGTH, SENSITIVE_DOMAINS, SelectionContext, SelectionPolicy,
    SelectionPolicyBuilder, SelectionPolicyError, TierConfig,
};
// Re-export terminal verifier types
pub use terminal_verifier::{
    CheckResult, MAX_ALLOWED_VERIFIER_KINDS, MAX_OUTPUT_VALUES, MAX_PREDICATE_DEPTH,
    MAX_PREDICATE_NODES, MAX_REQUIRED_OUTPUTS, Predicate, PredicateOp, TerminalVerifier,
    VerifierError, VerifierKind, VerifierOutput, VerifierOutputBuilder, VerifierPolicy,
    VerifierPolicyBuilder, evaluate_predicate,
};
// Re-export transcript binding types
pub use transcript_binding::{
    AatTranscriptBinding, MAX_CHUNK_CONTENT_BYTES, MAX_RUN_TRANSCRIPT_HASHES,
    MAX_TRANSCRIPT_CHUNKS, TranscriptBindingError, TranscriptChunk,
};
