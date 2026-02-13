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
//! - **Policy Inheritance**: Multi-holon policy inheritance enforcement and
//!   attestation ratcheting (TCK-00340)
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
//!     GATE_LEASE_ISSUED_PREFIX, GateLease, GateLeaseBuilder, PolicyResolvedForChangeSet,
//!     PolicyResolvedForChangeSetBuilder,
//! };
//!
//! // First, resolve the policy for the changeset
//! let resolver = Signer::generate();
//! let resolution = PolicyResolvedForChangeSetBuilder::new("work-001", [0x42; 32])
//!     .resolved_risk_tier(1)
//!     .resolved_determinism_class(0)
//!     .resolver_actor_id("resolver-001")
//!     .resolver_version("1.0.0")
//!     .build_and_sign(&resolver);
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
pub mod adapter_selection;
mod agent_adapter_profile;
pub mod anti_downgrade;
mod artifact_manifest;
pub mod broker;
pub mod broker_health;
pub mod builtin_profiles;
pub mod builtin_roles;
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
pub mod policy_inheritance;
mod policy_resolution;
pub mod projection;
pub mod projection_compromise;
pub mod projection_receipt_recorded;
pub mod quarantine;
mod receipt;
pub mod retry_manager;
pub mod review_blocked;
pub mod review_receipt;
pub mod risk_tier;
pub mod role_conformance;
mod role_spec;
mod role_spec_v2;
pub mod selection_policy;
pub mod serde_helpers;
pub mod taint;
mod terminal_verifier;
pub mod transcript_binding;

// Re-export broker types (TCK-00510)
// Re-export taint tracking types (TCK-00339)
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
// Re-export adapter selection policy types (TCK-00400)
pub use adapter_selection::{
    AdapterSelectionError, AdapterSelectionPolicy, AdapterSelectionStrategy, ProfileWeight,
    SelectionDecision, SelectionWeightSnapshot, monotonic_secs,
};
// Re-export agent adapter profile types (TCK-00328)
pub use agent_adapter_profile::{
    AGENT_ADAPTER_PROFILE_V1_SCHEMA, AdapterMode, AgentAdapterProfileError, AgentAdapterProfileV1,
    AgentAdapterProfileV1Builder, BudgetDefaults, EvidencePolicy, HealthChecks, InputMode,
    MAX_ARG_LENGTH, MAX_ARGS_COUNT, MAX_CAPABILITY_MAP_COUNT, MAX_CAPABILITY_MAP_KEY_LENGTH,
    MAX_CAPABILITY_MAP_VALUE_LENGTH, MAX_COMMAND_LENGTH, MAX_CWD_LENGTH, MAX_ENV_COUNT,
    MAX_ENV_KEY_LENGTH, MAX_ENV_VALUE_LENGTH, MAX_PERMISSION_MODE_FLAG_LENGTH,
    MAX_PERMISSION_MODE_FLAGS_COUNT, MAX_PERMISSION_MODE_KEY_LENGTH, MAX_PERMISSION_MODE_MAP_COUNT,
    MAX_PROFILE_ID_LENGTH, MAX_VERSION_PROBE_COMMAND_LENGTH, MAX_VERSION_PROBE_REGEX_LENGTH,
    OutputMode, ToolBridgeConfig, VersionProbe,
};
// Re-export artifact manifest types
pub use artifact_manifest::{
    ArtifactDigest, ArtifactManifest, ArtifactManifestBuilder, ArtifactManifestError, ArtifactType,
    DataClassification, HygieneError, MAX_ARTIFACTS,
    MAX_STRING_LENGTH as MAX_ARTIFACT_STRING_LENGTH, validate_evidence_hygiene_for_admission,
};
pub use broker::{
    BrokerError, BrokerSignatureVerifier, BrokerState, DEFAULT_ENVELOPE_TTL_TICKS, FacBroker,
    MAX_ADMITTED_POLICY_DIGESTS, MAX_AUTHORITY_CLOCK_LENGTH, MAX_BOUNDARY_ID_LENGTH,
    MAX_CONVERGENCE_RECEIPTS, MAX_ENVELOPE_TTL_TICKS,
};
// Re-export broker health types (TCK-00585)
pub use broker_health::{
    BrokerHealthChecker, BrokerHealthStatus, HEALTH_RECEIPT_SCHEMA_ID,
    HEALTH_RECEIPT_SCHEMA_VERSION, HealthCheckInput, HealthReceiptV1, InvariantCheckResult,
    MAX_HEALTH_FINDINGS, MAX_HEALTH_HISTORY, MAX_HEALTH_REQUIRED_AUTHORITY_SETS,
    WorkerHealthGateError, WorkerHealthPolicy, evaluate_worker_health_gate,
};
// Re-export builtin profile types (TCK-00329)
pub use builtin_profiles::{
    CLAUDE_CODE_PROFILE_ID, CODEX_CLI_PROFILE_ID, GEMINI_CLI_PROFILE_ID,
    LOCAL_INFERENCE_PROFILE_ID, all_builtin_profiles, claude_code_profile, codex_cli_profile,
    gemini_cli_profile, get_builtin_profile, local_inference_profile,
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
    LEDGER_EVENT_PREFIX, MERGE_RECEIPT_PREFIX, POLICY_RESOLVED_PREFIX,
    PROJECTION_ADMISSION_RECEIPT_PREFIX, PROJECTION_COMPROMISE_SIGNAL_PREFIX,
    PROJECTION_RECEIPT_PREFIX, PROJECTION_RECEIPT_RECORDED_PREFIX,
    PROJECTION_REPLAY_RECEIPT_PREFIX, QUARANTINE_EVENT_PREFIX, REVIEW_BLOCKED_RECORDED_PREFIX,
    REVIEW_RECEIPT_RECORDED_PREFIX, sign_with_domain, verify_with_domain,
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
// Re-export policy inheritance types (TCK-00340)
pub use policy_inheritance::{
    AttestationLevel, AttestationRequirements, MAX_ACTOR_ID_LENGTH, MAX_REASON_LENGTH,
    MAX_SUBLEASE_BATCH_SIZE, PolicyInheritanceError, PolicyInheritanceValidator,
    ReceiptAttestation, ReceiptKind, validate_receipt_attestation,
};
// Re-export policy resolution types
pub use policy_resolution::{
    DeterminismClass, MAX_RCP_PROFILES, MAX_STRING_LENGTH, MAX_VERIFIER_POLICIES,
    PolicyResolutionError, PolicyResolvedForChangeSet, PolicyResolvedForChangeSetBuilder,
    PolicyResolvedForChangeSetProto, RiskTier,
};
// Re-export projection contract types (TCK-00452).
pub use projection::{
    AuditorLaunchProjectionV1, OrchestratorLaunchProjectionV1, ProjectionContractError,
    ProjectionDigestEnvelopeV1, ProjectionUncertainty, canonical_projection_json,
    compute_projection_digest, digest_first_projection,
};
// Re-export projection compromise controls (RFC-0028 REQ-0009).
pub use projection_compromise::{
    AuthorityKeyBindingV1, ChannelIdentitySnapshotV1, DivergenceEvidence, ProjectionChannel,
    ProjectionCompromiseError, ProjectionCompromiseSignalV1, ProjectionDivergence,
    ProjectionReplayReceiptV1, ProjectionSurfaceType, QuarantineStatus,
    ReconstructedProjectionState, ReplaySequenceBoundsV1, SourceTrustSnapshotV1,
    detect_projection_divergence, quarantine_channel, reconstruct_projection_state,
};
// Re-export projection receipt recorded types
pub use projection_receipt_recorded::{
    MAX_RECEIPT_ID_LENGTH as MAX_PROJECTION_RECEIPT_ID_LENGTH,
    MAX_STRING_LENGTH as MAX_PROJECTION_RECEIPT_STRING_LENGTH,
    MAX_WORK_ID_LENGTH as MAX_PROJECTION_WORK_ID_LENGTH, ProjectedStatusCode,
    ProjectionArtifactBundleV1, ProjectionArtifactBundleV1Builder, ProjectionMetadata,
    ProjectionReceiptRecorded, ProjectionReceiptRecordedBuilder, ProjectionReceiptRecordedError,
    ProjectionReceiptRecordedProto, SCHEMA_IDENTIFIER as PROJECTION_ARTIFACT_SCHEMA_IDENTIFIER,
    SCHEMA_VERSION as PROJECTION_ARTIFACT_SCHEMA_VERSION,
    validate_changeset_binding as validate_projection_changeset_binding,
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
// Re-export review receipt types
pub use review_receipt::{
    MAX_RECEIPT_ID_LENGTH as MAX_REVIEW_RECEIPT_ID_LENGTH, MAX_REVIEW_ID_LENGTH,
    MAX_STRING_LENGTH as MAX_REVIEW_RECEIPT_STRING_LENGTH, MAX_TOOL_LOG_HASHES,
    ReviewArtifactBundleV1, ReviewArtifactBundleV1Builder, ReviewMetadata, ReviewReceiptError,
    ReviewReceiptRecorded, ReviewReceiptRecordedBuilder, ReviewReceiptRecordedProto, ReviewVerdict,
    SCHEMA_IDENTIFIER as REVIEW_ARTIFACT_SCHEMA_IDENTIFIER,
    SCHEMA_VERSION as REVIEW_ARTIFACT_SCHEMA_VERSION, validate_changeset_binding,
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
pub use taint::{
    FlowRule, MAX_FLOW_RULES, MAX_POLICY_RULE_ID_LEN, MAX_SOURCE_DESCRIPTION_LEN, MAX_TAINT_TAGS,
    MAX_VIOLATION_DESCRIPTION_LEN, TaintAggregator, TaintFlowDecision, TaintLevel, TaintPolicy,
    TaintSource, TaintTag, TaintViolation, TargetContext,
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
pub mod summary_receipt;
pub mod tool_execution_receipt;
pub mod tool_log_index;
pub mod view_commitment;
// Re-export view commitment types
// Re-export summary receipt types (TCK-00327)
// Re-export builtin role types (TCK-00331)
pub use builtin_roles::{
    CODE_QUALITY_REVIEWER_ROLE_ID, FAC_WORKOBJECT_IMPLEMENTOR_V2_ROLE_ID, IMPLEMENTER_ROLE_ID,
    ORCHESTRATOR_ROLE_ID, SECURITY_REVIEWER_ROLE_ID, all_builtin_role_contracts_v2,
    all_builtin_roles, builtin_role_contract_hash_registry_v2, code_quality_reviewer_role,
    fac_workobject_implementor_v2_role_contract, get_builtin_role, get_builtin_role_contract_v2,
    implementer_role, orchestrator_role, security_reviewer_role,
    seed_builtin_role_contracts_v2_in_cas,
};
// Re-export role conformance harness types (TCK-00331)
pub use role_conformance::{
    ConformanceError, ConformanceResult, ConformanceViolation, RoleConformanceHarness,
    ViolationType,
};
// Re-export role spec types (TCK-00331)
pub use role_spec::{
    FORBIDDEN_DIRECT_GITHUB_CAPABILITY_CLASSES,
    MAX_CAPABILITY_ID_LENGTH as MAX_ROLE_CAPABILITY_ID_LENGTH,
    MAX_DESCRIPTION_LENGTH as MAX_ROLE_DESCRIPTION_LENGTH,
    MAX_OUTPUT_SCHEMA_LENGTH as MAX_ROLE_OUTPUT_SCHEMA_LENGTH,
    MAX_REQUIRED_OUTPUT_SCHEMAS as MAX_ROLE_OUTPUT_SCHEMAS, MAX_ROLE_ID_LENGTH,
    MAX_ROLE_NAME_LENGTH, MAX_TOOL_BUDGETS, MAX_TOOL_CLASS_LENGTH, MAX_TOOLS_IN_ALLOWLIST,
    ROLE_SPEC_V1_SCHEMA, RequiredOutputSchema, RoleBudgets, RoleSpecError, RoleSpecV1,
    RoleSpecV1Builder, RoleType, ToolAllowlist, ToolBudget,
    forbidden_direct_github_capability_class,
};
pub use role_spec_v2::{
    DenyCondition, DenyReason, DenyReasonCode, MAX_V2_DENY_REASON_MESSAGE_LENGTH,
    MAX_V2_DENY_TAXONOMY_ENTRIES, MAX_V2_OUTPUT_FIELD_NAME_LENGTH, MAX_V2_OUTPUT_SCHEMA_FIELDS,
    MAX_V2_REQUIRED_CAPABILITIES, MAX_V2_TOOL_BUDGETS, MAX_V2_TOOLS_IN_ALLOWLISTS, OutputFieldType,
    OutputSchemaField, OutputSchemaV2, ROLE_SPEC_V2_SCHEMA, RoleSpecV2, RoleSpecV2Error,
    ToolBudgetV2,
};
pub use summary_receipt::{
    LossProfile, MAX_REVIEW_ID_LENGTH as MAX_SUMMARY_RECEIPT_REVIEW_ID_LENGTH,
    MAX_SELECTOR_TAG_LENGTH, MAX_SELECTOR_TAGS, MAX_SUMMARY_TEXT_LENGTH, ReviewOutcome,
    SUMMARY_RECEIPT_PREFIX, SUMMARY_RECEIPT_SCHEMA, SUMMARY_RECEIPT_VERSION, SummaryReceipt,
    SummaryReceiptBuilder, SummaryReceiptError,
};
// Re-export tool execution receipt types (TCK-00327)
pub use tool_execution_receipt::{
    MAX_CAPABILITY_ID_LENGTH as MAX_TOOL_RECEIPT_CAPABILITY_ID_LENGTH,
    MAX_EPISODE_ID_LENGTH as MAX_TOOL_RECEIPT_EPISODE_ID_LENGTH,
    MAX_REQUEST_ID_LENGTH as MAX_TOOL_RECEIPT_REQUEST_ID_LENGTH,
    MAX_TOOL_CLASS_LENGTH as MAX_TOOL_RECEIPT_TOOL_CLASS_LENGTH, TOOL_EXECUTION_RECEIPT_PREFIX,
    TOOL_EXECUTION_RECEIPT_SCHEMA, TOOL_EXECUTION_RECEIPT_VERSION, ToolExecutionReceipt,
    ToolExecutionReceiptBuilder, ToolExecutionReceiptError,
};
// Re-export tool log index types (TCK-00327)
pub use tool_log_index::{
    MAX_CONTINUATION_HASHES, MAX_EPISODE_ID_LENGTH as MAX_TOOL_LOG_INDEX_EPISODE_ID_LENGTH,
    MAX_RECEIPT_HASHES_PER_INDEX, TOOL_LOG_INDEX_V1_SCHEMA, TOOL_LOG_INDEX_V1_VERSION,
    ToolLogCounts, ToolLogIndexError, ToolLogIndexV1, ToolLogIndexV1Builder,
};
pub use view_commitment::{
    MAX_POLICY_REF_LENGTH as MAX_VIEW_COMMITMENT_POLICY_REF_LENGTH,
    MAX_WORK_ID_LENGTH as MAX_VIEW_COMMITMENT_WORK_ID_LENGTH, VIEW_COMMITMENT_V1_SCHEMA,
    ViewCommitmentError, ViewCommitmentV1, ViewCommitmentV1Builder,
};
/// Role routing and classification logic for work allocation.
///
/// This module provides heuristics for routing work to specialist roles
/// based on diff analysis and issue labels. It is designed to be called
/// by the Orchestrator or daemon when allocating work to determine whether
/// a specialist (e.g., `TestFlakeFixer`, `RustCompileErrorFixer`) or a
/// generalist (`Implementer`) role should handle the task.
///
/// # Integration Point
///
/// The primary entry point is [`classify_changeset`], which analyzes:
/// - Issue labels (strongest signal)
/// - Issue title keywords (medium signal)
/// - Changed file patterns (heuristic signal)
///
/// And returns a [`RoutingDecision`] indicating which role to use.
///
/// # Example
///
/// ```rust
/// use apm2_core::fac::role_routing::{RoutingDecision, classify_changeset};
///
/// let decision = classify_changeset(
///     &["Cargo.toml".to_string()],
///     &["dependencies".to_string()],
///     "Bump serde to 1.0.200",
/// );
///
/// match decision {
///     RoutingDecision::Specialist(role) => {
///         println!("Route to specialist: {}", role.role_id);
///     },
///     RoutingDecision::Generalist(role) => {
///         println!("Route to generalist: {}", role.role_id);
///     },
/// }
/// ```
pub mod role_routing;
// Re-export role routing types for convenient access
pub use role_routing::{RoutingDecision, classify_changeset};
/// Efficiency primitives for context deltas, caching, and summary-first
/// iteration.
///
/// This module implements TCK-00335 with:
/// - **Context Deltas**: Capture minimal state changes between iterations (N ->
///   N+1)
/// - **Tool Output Caching**: CAS-backed caches for Search/FileRead outputs
///   when safe
/// - **Summary-first Iteration**: Use summary receipts as iteration interfaces
///
/// # Budget Enforcement
///
/// The primitives ensure a 20-iteration loop stays within a fixed context
/// budget envelope through:
/// - Delta-based context injection (not full history)
/// - Tool output deduplication via CAS caching
/// - Automatic compaction when budget is exceeded
///
/// # Example
///
/// ```rust
/// use apm2_core::fac::efficiency_primitives::{
///     ContextBudgetEnvelope, ContextDeltaBuilder, IterationContextBuilder,
/// };
///
/// let mut envelope = ContextBudgetEnvelope::for_twenty_iterations();
///
/// for i in 0..20 {
///     let delta = ContextDeltaBuilder::new(i, i + 1)
///         .add_changed_file("/src/main.rs", [0x42; 32])
///         .unwrap()
///         .tokens_consumed(1000)
///         .build()
///         .unwrap();
///
///     let ctx = IterationContextBuilder::new("work-123", i + 1)
///         .add_delta(delta)
///         .build()
///         .unwrap();
///
///     envelope
///         .record_iteration(ctx.estimated_size_bytes())
///         .unwrap();
/// }
///
/// assert_eq!(envelope.iterations_completed, 20);
/// ```
pub mod efficiency_primitives;
// Re-export efficiency primitives for convenient access (TCK-00335)
pub use efficiency_primitives::{
    CacheKey, CacheStats, ChangeType, ChangedFile, ContextBudgetEnvelope, ContextDelta,
    ContextDeltaBuilder, DEFAULT_CACHE_TTL_SECS, DEFAULT_CONTEXT_BUDGET_BYTES,
    EFFICIENCY_PRIMITIVES_SCHEMA, EFFICIENCY_PRIMITIVES_VERSION, EfficiencyError, Finding,
    IterationContext, IterationContextBuilder, MAX_CACHE_ENTRIES, MAX_CHANGED_FILES,
    MAX_CONTEXT_BUDGET_BYTES, MAX_DELTAS, MAX_FINDINGS, MAX_TOOL_OUTPUTS, MAX_ZOOM_SELECTORS,
    ToolOutputCache, ToolOutputCacheConfig, ToolOutputRef, ZoomSelector, ZoomSelectorType,
};
