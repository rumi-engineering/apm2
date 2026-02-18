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
//! # Control-Lane Exception (Audited)
//!
//! `stop_revoke` jobs bypass the standard RFC-0028 channel context token and
//! RFC-0029 queue admission flow.  This is an **explicit, audited policy
//! exception** marked by [`CONTROL_LANE_EXCEPTION_AUDITED`].
//!
//! **Justification**: Control-lane cancellation originates from the local
//! operator (same trust domain as the queue owner) and requires
//! filesystem-level access proof (queue directory write capability).  A
//! broker-issued token would add no additional authority beyond what
//! filesystem capability already proves.  All structural and digest
//! validation is still enforced; only the token requirement is waived.
//!
//! See [`job_spec::validate_job_spec_control_lane`] for the full policy
//! exception documentation.
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
/// Content-addressed blob store for FAC patch data.
pub mod blob_store;
pub mod broker;
pub mod broker_health;
pub mod broker_health_ipc;
pub mod broker_rate_limits;
pub mod builtin_profiles;
pub mod builtin_roles;
mod canonicalizer_tuple;
mod changeset_bundle;
mod ci_attestation;
mod ci_import;
/// Containment verification: cgroup membership checks for child processes
/// (TCK-00548).
pub mod containment;
/// Credential gate for FAC workflows: fail-fast checks for GitHub-facing
/// commands and typed credential mount descriptors (TCK-00596).
pub mod credential_gate;
pub mod determinism;
mod domain_separator;
pub mod echo_trap;
/// Economics profile adoption protocol: broker-admitted economics_profile_hash
/// rotation with rollback and durable receipts (TCK-00584).
pub mod economics_adoption;
/// Evidence bundle export/import with RFC-0028 boundary validation and RFC-0029
/// receipt validation (TCK-00527).
pub mod evidence_bundle;
/// Execution backend selection for FAC jobs (system-mode and user-mode).
pub mod execution_backend;
pub mod flake_class;
mod flock_util;
/// Garbage-collection planner and execution primitives.
#[allow(missing_docs)]
pub mod gc;
/// Garbage-collection receipt schema and persistence helpers.
#[allow(missing_docs)]
pub mod gc_receipt;
/// Non-interactive, lane-scoped GitHub CLI command builder (TCK-00597).
pub mod gh_cli;
/// Git safety hardening for lane workspaces (TCK-00580).
pub mod git_hardening;
pub mod harness_sandbox;
pub mod job_spec;
mod key_policy;
pub mod lane;
mod lease;
pub mod merge_receipt;
mod node_identity;
/// Patch injection hardening: path traversal rejection, safe apply mode,
/// and patch provenance receipts (TCK-00581).
pub mod patch_hardening;
pub mod policy;
/// Policy adoption protocol: broker-admitted `FacPolicyHash` rotation with
/// receipts and rollback (TCK-00561).
pub mod policy_adoption;
pub mod policy_inheritance;
mod policy_resolution;
/// Disk preflight and auto-GC escalation policy.
#[allow(missing_docs)]
pub mod preflight;
pub mod projection;
pub mod projection_compromise;
pub mod projection_receipt_recorded;
pub mod quarantine;
/// Queue bounds and backpressure: max pending jobs/bytes with denial receipts
/// (TCK-00578).
pub mod queue_bounds;
mod receipt;
/// Non-authoritative, rebuildable receipt index for fast job/receipt lookup.
pub mod receipt_index;
/// Receipt stream merge: set-union merge with deterministic ordering and
/// conflict audit report (TCK-00543).
pub mod receipt_merge;
/// Atomic receipt write pipeline for crash-safe job completion (TCK-00564).
pub mod receipt_pipeline;
/// Crash recovery and reconciliation for queue/lane state on worker startup
/// (TCK-00534).
pub mod reconcile;
mod repo_mirror;
pub mod retry_manager;
pub mod review_blocked;
pub mod review_receipt;
pub mod risk_tier;
pub mod role_conformance;
mod role_spec;
mod role_spec_v2;
pub mod safe_rmtree;
pub mod scheduler_state;
pub mod sd_notify;
pub mod selection_policy;
pub mod serde_helpers;
pub mod signed_receipt;
mod systemd_properties;
pub mod taint;
mod terminal_verifier;
pub mod transcript_binding;
pub mod warm;
pub mod worker_heartbeat;

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
pub use blob_store::{BLOB_DIR, BlobStore, BlobStoreError, MAX_BLOB_SIZE};
pub use broker::{
    BrokerError, BrokerSignatureVerifier, BrokerState, DEFAULT_ENVELOPE_TTL_TICKS, FacBroker,
    MAX_ADMITTED_POLICY_DIGESTS, MAX_AUTHORITY_CLOCK_LENGTH, MAX_BOUNDARY_ID_LENGTH,
    MAX_CONVERGENCE_RECEIPTS, MAX_ENVELOPE_TTL_TICKS,
};
// Re-export broker health types (TCK-00585)
pub use broker_health::{
    BrokerHealthChecker, BrokerHealthError, BrokerHealthStatus, HEALTH_RECEIPT_SCHEMA_ID,
    HEALTH_RECEIPT_SCHEMA_VERSION, HealthCheckInput, HealthReceiptV1, InvariantCheckResult,
    MAX_HEALTH_FINDINGS, MAX_HEALTH_HISTORY, MAX_HEALTH_REQUIRED_AUTHORITY_SETS,
    WorkerHealthGateError, WorkerHealthPolicy, compute_eval_window_hash,
    evaluate_worker_health_gate,
};
// Re-export broker rate limits types (TCK-00568)
pub use broker_rate_limits::{
    ControlPlaneBudget, ControlPlaneBudgetError, ControlPlaneDenialReceipt, ControlPlaneDimension,
    ControlPlaneLimits, DENY_REASON_BUNDLE_EXPORT_BYTES_EXCEEDED, DENY_REASON_COUNTER_OVERFLOW,
    DENY_REASON_QUEUE_BYTES_EXCEEDED, DENY_REASON_QUEUE_ENQUEUE_RATE_EXCEEDED,
    DENY_REASON_TOKEN_ISSUANCE_EXCEEDED, MAX_BUNDLE_EXPORT_BYTES_LIMIT, MAX_QUEUE_BYTES_LIMIT,
    MAX_QUEUE_ENQUEUE_LIMIT, MAX_TOKEN_ISSUANCE_LIMIT,
};
// Re-export builtin profile types (TCK-00329)
pub use builtin_profiles::{
    CLAUDE_CODE_PROFILE_ID, CODEX_CLI_PROFILE_ID, GEMINI_CLI_PROFILE_ID,
    LOCAL_INFERENCE_PROFILE_ID, all_builtin_profiles, claude_code_profile, codex_cli_profile,
    gemini_cli_profile, get_builtin_profile, local_inference_profile,
};
// Re-export canonicalizer tuple types
pub use canonicalizer_tuple::{CANONICALIZER_TUPLE_SCHEMA, CanonicalizerTupleV1};
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
// Re-export containment verification types (TCK-00548)
pub use containment::{
    ContainmentError, ContainmentMismatch, ContainmentTrace, ContainmentVerdict,
    MAX_CHILD_PROCESSES, MAX_CONTAINMENT_MISMATCHES, MAX_PROC_READ_SIZE, MAX_PROC_SCAN_ENTRIES,
    check_sccache_containment, check_sccache_containment_with_proc, discover_children,
    discover_children_from_proc, is_cgroup_contained, read_cgroup_path, read_cgroup_path_from_proc,
    verify_containment, verify_containment_with_proc,
};
// Re-export credential gate types (TCK-00596)
pub use credential_gate::{
    CREDENTIAL_MOUNT_SCHEMA_ID, CredentialGateError, CredentialMountV1, CredentialPosture,
    CredentialSource, EnvMount, FileMountDescriptor, MAX_ENV_MOUNTS, MAX_ENV_NAME_LENGTH,
    MAX_FILE_MOUNTS, MAX_FILE_PATH_LENGTH, apply_credential_mount_to_env,
    build_github_credential_mount, check_github_credential_posture, require_github_credentials,
    validate_credential_mount,
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
    GATE_CACHE_RECEIPT_PREFIX, GATE_LEASE_ISSUED_PREFIX, GATE_RECEIPT_PREFIX,
    GATE_RUN_COMPLETED_PREFIX, INTERVENTION_FREEZE_PREFIX, INTERVENTION_UNFREEZE_PREFIX,
    LEASE_REVOKED_PREFIX, LEDGER_EVENT_PREFIX, MERGE_RECEIPT_PREFIX, POLICY_RESOLVED_PREFIX,
    PROJECTION_ADMISSION_RECEIPT_PREFIX, PROJECTION_COMPROMISE_SIGNAL_PREFIX,
    PROJECTION_RECEIPT_PREFIX, PROJECTION_RECEIPT_RECORDED_PREFIX,
    PROJECTION_REPLAY_RECEIPT_PREFIX, QUARANTINE_EVENT_PREFIX, REVIEW_BLOCKED_RECORDED_PREFIX,
    REVIEW_RECEIPT_RECORDED_PREFIX, SIGNED_RECEIPT_ENVELOPE_PREFIX, sign_with_domain,
    verify_with_domain,
};
// Re-export echo-trap detection types
pub use echo_trap::{
    ECHO_TRAP_THRESHOLD, EchoTrapDetector, EchoTrapError, EchoTrapEvent, FindingSignature,
    MAX_SIGNATURE_LENGTH, MAX_SIGNATURES as MAX_ECHO_TRAP_SIGNATURES, SessionTermination,
    TerminationRationale,
};
// Re-export economics adoption types (TCK-00584)
pub use economics_adoption::{
    ADMITTED_ECONOMICS_PROFILE_SCHEMA, AdmittedEconomicsProfileRootV1,
    ECONOMICS_ADOPTION_RECEIPT_SCHEMA, EconomicsAdoptionAction, EconomicsAdoptionError,
    EconomicsAdoptionReceiptV1, adopt_economics_profile, adopt_economics_profile_by_hash,
    is_economics_profile_hash_admitted, load_admitted_economics_profile_root, looks_like_digest,
    rollback_economics_profile, validate_digest_string, validate_economics_profile_bytes,
};
// Re-export flake classification routing types
pub use flake_class::FlakeRouting;
pub use gc::{GcPlan, GcPlanError, GcTarget, execute_gc, plan_gc, plan_quarantine_prune};
pub use gc_receipt::{
    DEFAULT_MIN_FREE_BYTES, GC_RECEIPT_SCHEMA, GcAction, GcActionKind, GcError, GcReceiptV1,
    MAX_GC_ACTIONS, MAX_GC_RECEIPT_SIZE, persist_gc_receipt,
};
// Re-export gh_cli (TCK-00597)
pub use gh_cli::{GhCommand, gh_command};
pub use git_hardening::{
    GIT_HARDENING_RECEIPT_SCHEMA, GitHardeningError, GitHardeningOutcome, GitHardeningReceipt,
};
// Re-export harness sandbox types
pub use harness_sandbox::{
    EgressRule, HarnessSandboxError, MAX_EGRESS_RULES, MAX_HOST_LENGTH,
    MAX_STRING_LENGTH as MAX_HARNESS_SANDBOX_STRING_LENGTH, NetworkPolicyProfile,
    NetworkPolicyProfileBuilder, Protocol,
};
// Re-export job spec types (TCK-00512, TCK-00579)
pub use job_spec::{
    Actuation, CONTROL_LANE_EXCEPTION_AUDITED, FacJobSpecV1, FacJobSpecV1Builder,
    JOB_SPEC_SCHEMA_ID, JobConstraints, JobSource, JobSpecError, JobSpecValidationPolicy,
    LaneRequirements, MAX_CHANNEL_CONTEXT_TOKEN_LENGTH, MAX_DECODED_SOURCE_LENGTH,
    MAX_HEAD_SHA_LENGTH, MAX_JOB_ID_LENGTH, MAX_JOB_SPEC_SIZE, MAX_KIND_LENGTH,
    MAX_LEASE_ID_LENGTH, MAX_QUEUE_LANE_LENGTH, MAX_REPO_ALLOWLIST_SIZE, MAX_REPO_ID_LENGTH,
    MAX_REQUEST_ID_LENGTH, MAX_SOURCE_KIND_LENGTH, VALID_PATCH_BYTES_BACKENDS,
    deserialize_job_spec, parse_b3_256_digest, validate_job_spec, validate_job_spec_control_lane,
    validate_job_spec_control_lane_with_policy, validate_job_spec_with_policy,
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
// Re-export patch hardening types (TCK-00581)
pub use patch_hardening::{
    MAX_PATCH_CONTENT_SIZE, MAX_PATCH_FILE_ENTRIES, MAX_REFUSALS, PATCH_APPLY_RECEIPT_SCHEMA_ID,
    PATCH_APPLY_RECEIPT_SCHEMA_VERSION, PATCH_FORMAT_GIT_DIFF_V1, PatchApplyReceiptV1,
    PatchRefusal, PatchValidationError, PatchValidationResult, validate_for_apply,
    validate_patch_content,
};
#[cfg(unix)]
pub use policy::verify_dir_permissions;
pub use policy::{
    EnvSetEntry, FacPolicyError, FacPolicyV1, LANE_ENV_DIR_HOME, LANE_ENV_DIR_TMP,
    LANE_ENV_DIR_XDG_CACHE, LANE_ENV_DIR_XDG_CONFIG, LANE_ENV_DIRS, POLICY_SCHEMA_ID,
    apply_lane_env_overrides, build_job_environment, compute_policy_hash, deserialize_policy,
    ensure_lane_env_dirs, parse_policy_hash, persist_policy,
};
// Re-export policy adoption types (TCK-00561)
pub use policy_adoption::{
    ADMITTED_POLICY_ROOT_SCHEMA, AdmittedPolicyRootV1, POLICY_ADOPTION_RECEIPT_SCHEMA,
    PolicyAdoptionAction, PolicyAdoptionError, PolicyAdoptionReceiptV1, adopt_policy,
    deserialize_adoption_receipt, is_policy_hash_admitted, load_admitted_policy_root,
    rollback_policy, validate_policy_bytes,
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
    BudgetAdmissionTrace, ChannelBoundaryTrace, DenialReasonCode, FAC_LANE_CLEANUP_RECEIPT_SCHEMA,
    FacJobOutcome, FacJobReceiptError, FacJobReceiptV1, FacJobReceiptV1Builder, GateReceipt,
    GateReceiptBuilder, GateReceiptProto, LANE_CLEANUP_RECEIPT_SCHEMA, LaneCleanupReceiptError,
    LaneCleanupReceiptV1, MAX_JOB_RECEIPT_SIZE, MAX_LANE_CLEANUP_RECEIPT_SIZE, QueueAdmissionTrace,
    ReceiptError, SUPPORTED_PAYLOAD_KINDS, SUPPORTED_PAYLOAD_SCHEMA_VERSIONS,
    SUPPORTED_RECEIPT_VERSIONS, compute_job_receipt_content_hash,
    compute_job_receipt_content_hash_v2, deserialize_job_receipt,
    persist_content_addressed_receipt, persist_content_addressed_receipt_v2,
};
// Re-export receipt index types (TCK-00560)
pub use receipt_index::{
    INDEX_FILE_NAME, INDEX_SUBDIR, MAX_INDEX_ENTRIES, MAX_INDEX_FILE_SIZE, MAX_JOB_INDEX_ENTRIES,
    MAX_REBUILD_SCAN_FILES, RECEIPT_INDEX_SCHEMA, ReceiptHeaderV1, ReceiptIndexError,
    ReceiptIndexV1, find_receipt_for_job, has_receipt_for_job, list_receipt_headers,
    lookup_job_receipt,
};
// Re-export receipt merge types (TCK-00543)
pub use receipt_merge::{
    JobIdMismatch, MAX_JOB_ID_MISMATCHES, MAX_MERGE_SCAN_FILES as MAX_RECEIPT_MERGE_SCAN_FILES,
    MAX_PARSE_FAILURES, MergeAuditReport, MergedReceiptHeader, ParseFailure, ReceiptMergeError,
    merge_receipt_dirs,
};
// Re-export receipt pipeline types (TCK-00564)
pub use receipt_pipeline::{
    CommitResult, RECOVERY_RECEIPT_SCHEMA, ReceiptPipelineError, ReceiptWritePipeline,
    RecoveryReceiptV1, TerminalState, move_job_to_terminal, outcome_to_terminal_state,
    receipt_exists_for_job, rename_noreplace,
};
// Re-export reconcile types (TCK-00534)
pub use reconcile::{
    LaneRecoveryAction, MAX_CLAIMED_SCAN_ENTRIES, MAX_LANE_RECOVERY_ACTIONS,
    MAX_QUEUE_RECOVERY_ACTIONS, OrphanedJobPolicy, QueueRecoveryAction, RECONCILE_RECEIPT_SCHEMA,
    ReconcileError, ReconcileReceiptV1, reconcile_on_startup,
};
pub use repo_mirror::{
    CheckoutOutcome, DEFAULT_CLONE_TIMEOUT_SECS, DEFAULT_FETCH_TIMEOUT_SECS,
    MAX_ALLOWED_URL_PATTERNS, MAX_MIRROR_DIR_NAME, MAX_PATCH_SIZE, MAX_RECEIPT_REFS,
    MIRROR_LOCK_TIMEOUT_SECS, MIRROR_UPDATE_RECEIPT_SCHEMA, MirrorPolicy, MirrorUpdateReceiptV1,
    PatchOutcome, REPO_MIRROR_SCHEMA, RepoMirrorError, RepoMirrorManager,
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
// Re-export signed receipt types (TCK-00576)
pub use signed_receipt::{
    MAX_SIGNED_ENVELOPE_SIZE, SIGNED_RECEIPT_ENVELOPE_SCHEMA, SIGNED_RECEIPT_PREFIX,
    SignedReceiptEnvelopeV1, SignedReceiptError, deserialize_signed_envelope,
    load_and_verify_receipt_signature, load_signed_envelope, persist_signed_envelope, sign_receipt,
    signed_envelope_path, verify_receipt_signature,
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
// Re-export execution backend types (TCK-00529)
pub use execution_backend::{
    DEFAULT_SERVICE_USER, EXECUTION_BACKEND_ENV_VAR, ExecutionBackend, ExecutionBackendError,
    SERVICE_USER_ENV_VAR, SystemModeConfig, SystemdRunCommand, build_systemd_run_command,
    probe_user_bus, select_and_validate_backend, select_backend,
};
// Re-export lane types (TCK-00515)
pub use lane::{
    DEFAULT_LANE_COUNT, LANE_CORRUPT_MARKER_SCHEMA, LANE_COUNT_ENV_VAR, LANE_ID_PREFIX,
    LANE_INIT_RECEIPT_SCHEMA, LANE_LEASE_V1_SCHEMA, LANE_LOCK_TIMEOUT, LANE_PROFILE_V1_SCHEMA,
    LANE_RECONCILE_RECEIPT_SCHEMA, LaneCleanupError, LaneCleanupOutcome, LaneCorruptMarkerV1,
    LaneError, LaneInitProfileEntry, LaneInitReceiptV1, LaneLeaseV1, LaneLockGuard, LaneManager,
    LanePolicy, LaneProfileV1, LaneReconcileAction, LaneReconcileOutcome, LaneReconcileReceiptV1,
    LaneState, LaneStatusV1, LaneTimeouts, MAX_LANE_COUNT, MAX_LANE_ID_LENGTH, MAX_LEASE_FILE_SIZE,
    MAX_MEMORY_MAX_BYTES, MAX_PROFILE_FILE_SIZE, MAX_STRING_LENGTH as MAX_LANE_STRING_LENGTH,
    MAX_TEST_TIMEOUT_SECONDS, ResourceProfile, compute_test_env_for_parallelism,
    create_dir_restricted, resolve_host_test_parallelism,
};
// Re-export node identity types (TCK-00556).
pub use node_identity::{
    DEFAULT_BOUNDARY_ID, MAX_BOUNDARY_ID_LENGTH as NODE_IDENTITY_MAX_BOUNDARY_ID_LENGTH,
    NODE_IDENTITY_SCHEMA_ID, NodeIdentityError, derive_node_fingerprint,
    load_or_default_boundary_id, load_or_derive_node_fingerprint, read_boundary_id,
};
pub use preflight::{PreflightError, PreflightStatus, check_disk_space, run_preflight};
// Re-export safe rmtree types (TCK-00516)
pub use safe_rmtree::{
    MAX_DIR_ENTRIES, MAX_TRAVERSAL_DEPTH, RefusedDeleteReceipt, SafeRmtreeError, SafeRmtreeOutcome,
    safe_rmtree_v1,
};
pub use systemd_properties::{
    NetworkPolicy, SandboxHardeningProfile, SystemdUnitProperties, resolve_network_policy,
};
pub use warm::{
    DEFAULT_WARM_PHASES, MAX_WARM_PHASES, MAX_WARM_RECEIPT_SIZE, MAX_WARM_STRING_LENGTH,
    WARM_RECEIPT_SCHEMA, WarmContainment, WarmError, WarmPhase, WarmPhaseResult, WarmReceiptV1,
    WarmToolVersions, collect_tool_versions, execute_warm, execute_warm_phase,
};
