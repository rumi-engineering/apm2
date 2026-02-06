//! Episode runtime module.
//!
//! This module manages bounded execution episodes for agent processes,
//! providing lifecycle management, state machine transitions, and
//! envelope construction for episode context.
//!
//! # Architecture
//!
//! Per AD-EPISODE-001 and AD-LAYER-001, the episode module provides:
//!
//! - **`EpisodeEnvelope`**: Immutable episode configuration, referenced by
//!   digest and bound into all receipts.
//! - **`EpisodeBudget`**: Resource limits (tokens, tool calls, time, I/O).
//! - **`PinnedSnapshot`**: Reproducibility digests (repo, lockfile, policy).
//! - **`StopConditions`**: Termination predicates.
//! - **`RiskTier`**: Security tier determining gates and evidence strength.
//! - **`DeterminismClass`**: Declared reproducibility level.
//! - **`EpisodeRuntime`**: Daemon-layer runtime managing episode lifecycle.
//!
//! The episode module implements the daemon-layer episode runtime per
//! AD-LAYER-001. It operates as the authoritative plant controller,
//! managing process lifetime, state machines, and event emission.
//!
//! # State Machine
//!
//! Episodes follow the state machine defined in AD-EPISODE-002:
//!
//! ```text
//! CREATED ──────► RUNNING ──────► TERMINATED
//!                    │
//!                    └──────────► QUARANTINED
//! ```
//!
//! - **CREATED**: Envelope accepted, resources not yet allocated
//! - **RUNNING**: Harness process spawned, I/O streaming active
//! - **TERMINATED**: Normal completion, evidence finalized
//! - **QUARANTINED**: Abnormal termination, evidence pinned for investigation
//!
//! # Canonicalization
//!
//! Per AD-VERIFY-001, all types support deterministic serialization:
//!
//! ```rust,ignore
//! use apm2_daemon::episode::EpisodeEnvelope;
//!
//! let envelope = EpisodeEnvelope::builder()
//!     .episode_id("ep-001")
//!     // ... other required fields
//!     .build()?;
//!
//! let bytes = envelope.canonical_bytes();
//! let digest = envelope.digest();
//! ```
//!
//! # Invariants
//!
//! - [INV-EP001] All state transitions emit events
//! - [INV-EP002] Terminal states (TERMINATED, QUARANTINED) have no outgoing
//!   transitions
//! - [INV-EP003] RUNNING requires valid lease
//! - [INV-EP004] Episode IDs are unique within the runtime
//! - [INV-EP005] Maximum concurrent episodes is bounded (CTR-1303)
//!
//! # Modules
//!
//! - [`adapter`]: `HarnessAdapter` trait and event types for normalizing
//!   harness behavior
//! - [`registry`]: `AdapterRegistry` for managing harness adapters
//! - [`raw_adapter`]: Raw adapter implementation for unstructured output
//! - [`budget`]: Episode budget and resource limits
//! - [`envelope`]: Episode envelope and configuration
//! - [`snapshot`]: Pinned snapshot for reproducibility
//! - [`capability`]: Capability manifest and validation (AD-TOOL-002)
//! - [`scope`]: Capability scope with path, size, and network restrictions
//! - [`tool_class`]: Tool class enumeration for capability categorization
//! - [`broker`]: `ToolBroker` for capability-validated tool execution
//!   (CTR-DAEMON-004)
//! - [`decision`]: Tool request, decision, and result types
//! - [`dedupe`]: `DedupeCache` for idempotent tool replay
//! - [`budget_tracker`]: `BudgetTracker` for episode resource management
//! - [`executor`]: `ToolExecutor` for budget-enforced tool execution
//! - [`tool_handler`]: `ToolHandler` trait for tool implementations
//! - [`handlers`]: Stub implementations of core tool handlers
//!
//! # Key Types
//!
//! - [`EpisodeError`]: Episode error types
//! - [`EpisodeState`]: State machine and transitions
//! - [`SessionHandle`]: Session handle for running episodes
//! - [`EpisodeRuntime`]: Episode runtime implementation
//!
//! # Contract References
//!
//! - AD-EPISODE-001: Immutable episode envelope
//! - AD-EPISODE-002: Session state machine
//! - AD-VERIFY-001: Deterministic Protobuf serialization
//! - AD-LAYER-001: `EpisodeRuntime` extends `EpisodeController`
//! - REQ-EPISODE-001: Episode envelope requirements

// TCK-00159: Envelope and budget types
pub mod budget;
pub mod envelope;
pub mod golden_vectors;
pub mod snapshot;

// TCK-00160: Runtime and state machine
mod error;
mod handle;
mod runtime;
mod state;

// TCK-00161: PTY spawning and output capture
pub mod output;
pub mod pty;
pub mod ring_buffer;

// TCK-00162: Harness adapter and registry
pub mod adapter;
pub mod raw_adapter;
pub mod registry;

// TCK-00173: Claude Code harness adapter
pub mod claude_code;
pub mod claude_parser;

// TCK-00163: Capability manifest and validation
pub mod capability;
pub mod reviewer_manifest;
pub mod scope;
pub mod tool_class;

// TCK-00164: Tool broker with dedupe cache
pub mod broker;
pub mod decision;
pub mod dedupe;

// TCK-00165: Tool execution and budget charging
pub mod budget_tracker;
pub mod executor;
pub mod handlers;
pub mod tool_handler;

// TCK-00311: Workspace snapshot and apply
pub mod workspace;

// Re-export envelope types (TCK-00159)
// Re-export adapter types (TCK-00162)
pub use adapter::{
    AdapterError, AdapterResult, AdapterType, HarnessAdapter, HarnessConfig, HarnessEvent,
    HarnessEventStream, HarnessHandle, OutputKind, TerminationClassification,
};
// Re-export broker types (TCK-00164, TCK-00292, TCK-00293)
pub use broker::{
    BrokerError, BrokerPolicyEngine, NO_POLICY_RATIONALE, NO_POLICY_RULE_ID, PolicyDecision,
    SharedToolBroker, StubContentAddressedStore, ToolBroker, ToolBrokerConfig, new_shared_broker,
    new_shared_broker_with_cas,
};
pub use budget::{EpisodeBudget, EpisodeBudgetBuilder};
// Re-export tool execution types (TCK-00165)
pub use budget_tracker::{BudgetExhaustedError, BudgetSnapshot, BudgetTracker};
// Re-export capability types (TCK-00163, TCK-00254, TCK-00258, TCK-00317)
pub use capability::{
    Capability, CapabilityBuilder, CapabilityDecision, CapabilityError, CapabilityManifest,
    CapabilityManifestBuilder, CapabilityValidator, CustodyDomainError, CustodyDomainId,
    DenyReason, InMemoryCasManifestLoader, MAX_ACTOR_ID_LEN, MAX_CAPABILITIES,
    MAX_CAPABILITY_ID_LEN, MAX_CUSTODY_DOMAINS_PER_REQUEST, MAX_MANIFEST_ID_LEN,
    MAX_SHELL_ALLOWLIST, MAX_SHELL_PATTERN_LEN, MAX_WRITE_ALLOWLIST, ManifestLoader, ToolRequest,
    validate_custody_domain_overlap,
};
// Re-export Claude Code adapter types (TCK-00173)
pub use claude_code::{
    ClaudeCodeAdapter, ClaudeCodeHolon, ClaudeCodeOutput, ClaudeCodeState, SharedClaudeCodeState,
};
pub use claude_parser::{
    ClaudeCodeParser, DEFAULT_RATE_LIMIT_PER_SEC, MAX_BUFFER_SIZE,
    MAX_TOOL_ARGS_SIZE as CLAUDE_MAX_TOOL_ARGS_SIZE, MAX_TOOL_NAME_LEN, ParseResult,
    ParsedToolCall, ParserDefect, ParserState, strip_ansi,
};
pub use decision::{
    BrokerToolRequest, BudgetDelta, DedupeKey, DedupeKeyError, MAX_DEDUPE_KEY_LEN,
    MAX_ERROR_MESSAGE_LEN, MAX_HOST_LEN, MAX_INLINE_ARGS_SIZE, MAX_INLINE_RESULT_SIZE,
    MAX_REQUEST_ID_LEN, MAX_RULE_ID_LEN, MAX_TOOL_OUTPUT_SIZE, RequestValidationError,
    SessionContext, ToolDecision, ToolResult,
};
pub use dedupe::{
    DEFAULT_TTL_SECS, DedupeCache, DedupeCacheConfig, DedupeCacheStats, MAX_DEDUPE_ENTRIES,
    MAX_TTL_SECS, SharedDedupeCache, new_shared_cache,
};
pub use envelope::{
    ContextRefs, DeterminismClass, EnvelopeError, EpisodeEnvelope, EpisodeEnvelopeBuilder,
    RiskTier, StopConditions,
};
// Re-export runtime types (TCK-00160)
pub use error::{EpisodeError, EpisodeId, MAX_EPISODE_ID_LEN};
pub use executor::{
    ContentAddressedStore, ExecutionContext, ExecutorError, SharedToolExecutor, ToolExecutor,
    new_shared_executor,
};
pub use handle::{MAX_SESSION_ID_LEN, SessionHandle, SessionSnapshot, StopSignal};
// TCK-00319: register_stub_handlers is test-only (insecure CWD rooting)
#[cfg(test)]
#[allow(deprecated)]
pub use handlers::register_stub_handlers;
// Re-export handler types (TCK-00291, TCK-00315, TCK-00319, TCK-00338)
pub use handlers::{
    ArtifactFetchHandler, ExecuteHandler, GitOperationHandler, ListFilesHandler, ReadFileHandler,
    SandboxConfig, SearchHandler, WriteFileHandler, register_handlers_with_root,
};
// Re-export PTY types (TCK-00161)
pub use output::{MAX_CHUNK_SIZE, PtyOutput, PtyOutputRecord, SequenceGenerator, StreamKind};
pub use pty::{ExitStatus, PtyConfig, PtyError, PtyRunner};
pub use raw_adapter::{
    RawAdapter, RawAdapterHolon, RawAdapterOutput, RawAdapterState, SharedAdapterState,
};
// Re-export registry types (TCK-00162, TCK-00328: profile-based selection, TCK-00385: TTL)
pub use registry::{
    AdapterRegistry, AdapterRegistryError, InMemorySessionRegistry, PersistentRegistryError,
    PersistentSessionRegistry, TERMINATED_SESSION_TTL_SECS,
};
// Re-export reviewer manifest types (TCK-00317)
pub use reviewer_manifest::{
    DAEMON_DELEGATOR_ID, REVIEWER_V0_MANIFEST_ID, build_reviewer_v0_manifest,
    build_reviewer_v0_manifest_dynamic, is_reviewer_v0_manifest_hash, reviewer_v0_manifest,
    reviewer_v0_manifest_hash,
};
pub use ring_buffer::{RingBuffer, tier_defaults};
pub use runtime::{
    EpisodeEvent, EpisodeRuntime, EpisodeRuntimeConfig, Hash, LeaseIssueDenialReason,
    MAX_CONCURRENT_EPISODES, MAX_EVENTS_BUFFER_SIZE, MAX_RESULT_HASHES_PER_EPISODE,
    RootedHandlerFactory, new_shared_runtime, new_shared_runtime_with_clock,
    new_shared_runtime_with_clock_initialized,
};
pub use scope::{
    CapabilityScope, CapabilityScopeBuilder, MAX_ALLOWED_PATTERNS, MAX_NETWORK_HOSTS,
    MAX_NETWORK_PORTS, MAX_PATH_LEN, MAX_PATTERN_LEN, MAX_ROOT_PATHS, NetworkPolicy, ScopeError,
    SizeLimits,
};
pub use snapshot::{PinnedSnapshot, PinnedSnapshotBuilder};
pub use state::{EpisodeState, QuarantineReason, TerminationClass, validate_transition};
pub use tool_class::{MAX_TOOL_ALLOWLIST, MAX_TOOL_CLASS_NAME_LEN, ToolClass, ToolClassExt};
pub use tool_handler::{
    ARTIFACT_FETCH_MAX_BYTES, ArtifactArgs, ExecuteArgs, GIT_DIFF_MAX_BYTES, GIT_DIFF_MAX_LINES,
    GIT_STATUS_MAX_BYTES, GIT_STATUS_MAX_LINES, GitArgs, InferenceArgs, MAX_HANDLERS,
    MAX_RESULT_MESSAGE_LEN, MAX_TOOL_ARGS_SIZE, NetworkArgs, RawArgs, ReadArgs, ResultMetadata,
    ToolArgs, ToolHandler, ToolHandlerError, ToolResultData, WriteArgs,
};
// Re-export workspace types (TCK-00311, TCK-00312, TCK-00318)
pub use workspace::{
    ApplyResult, MAX_FILE_SIZE, MAX_GIT_LINE_LEN, MAX_PATH_DEPTH, MAX_RETRY_ATTEMPTS,
    MAX_WORKSPACE_FILES, RetryContext, ReviewCompletionResult, ReviewCompletionResultBuilder,
    WorkspaceError, WorkspaceManager, WorkspaceSnapshot, create_artifact_bundle,
    create_blocked_event, create_receipt_event, validate_file_changes, validate_path,
    validate_path_filesystem_aware, validate_path_with_symlink_check,
};
