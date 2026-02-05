//! TCK-00313: FAC v0 E2E Harness - Full End-to-End Verification
//!
//! This test module provides comprehensive end-to-end verification of the FAC
//! v0 reviewer harness against the acceptance criteria for:
//!
//! - **REQ-HEF-0009**: FAC v0 diff observability via `ChangeSetBundle`
//!   - CAS storage of `ChangeSetBundleV1`
//!   - `ChangeSetPublished` ledger event with anchoring
//!   - No GitHub reads for truth (ledger + CAS only)
//!
//! - **REQ-HEF-0010**: Reviewer viability
//!   - Workspace snapshot/apply with real validation
//!   - Tool profile enforcement via `CapabilityValidator`
//!   - Tool logs stored in CAS, referenced by `ReviewReceipt`
//!   - Tool output bounds enforced (`GitOperation`, `ArtifactFetch`)
//!
//! - **REQ-HEF-0011**: `ReviewBlocked` liveness semantics
//!   - Ledger-anchored `ReviewBlockedRecorded` with reason codes
//!   - CAS log hash binding for blocked outcomes
//!   - Reason codes for various failure paths
//!
//! - **EVID-HEF-0012**: Evidence artifact constraints
//!   - `GITHUB_TOKEN` / `GH_TOKEN` must be unset
//!   - Ledger-only truth source (no external reads)
//!   - Local projection sink (no network writes)
//!
//! # Verification Commands
//!
//! ```bash
//! # Run all FAC v0 E2E tests
//! cargo test -p apm2-daemon --test hef_fac_v0_e2e -- --nocapture
//!
//! # Run the full E2E flow
//! cargo test -p apm2-daemon --test hef_fac_v0_e2e test_fac_v0_full_e2e_autonomous_flow
//!
//! # Run ledger anchoring tests
//! cargo test -p apm2-daemon --test hef_fac_v0_e2e test_changeset_published_ledger_anchoring
//! cargo test -p apm2-daemon --test hef_fac_v0_e2e test_review_receipt_ledger_anchoring
//! cargo test -p apm2-daemon --test hef_fac_v0_e2e test_review_blocked_ledger_anchoring
//! ```

use std::ffi::{OsStr, OsString};
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};

use apm2_core::crypto::Signer;
use apm2_core::events::{
    CHANGESET_PUBLISHED_DOMAIN_PREFIX, ChangeSetPublished, REVIEW_BLOCKED_RECORDED_DOMAIN_PREFIX,
    REVIEW_RECEIPT_RECORDED_DOMAIN_PREFIX, ReviewBlockedRecorded, ReviewReceiptRecorded,
};
use apm2_core::fac::{
    ChangeKind, ChangeSetBundleV1, FileChange, GitObjectRef, HashAlgo, ReasonCode,
    ReviewArtifactBundleV1, ReviewMetadata, ReviewVerdict, sign_with_domain,
};
use apm2_core::htf::Canonicalizable;
use apm2_core::ledger::{EventRecord, Ledger};
use apm2_daemon::cas::{DurableCas, DurableCasConfig};
use apm2_daemon::episode::executor::ContentAddressedStore;
use apm2_daemon::episode::tool_handler::{ArtifactArgs, GitArgs, ReadArgs, ToolArgs};
use apm2_daemon::episode::workspace::validate_file_changes;
use apm2_daemon::episode::{
    ArtifactFetchHandler, BudgetTracker, Capability, CapabilityManifestBuilder, CapabilityScope,
    CapabilityValidator, EpisodeBudget, ExecutionContext, GitOperationHandler, ReadFileHandler,
    RiskTier, ToolClass, ToolExecutor, ToolRequest, WorkspaceError, WorkspaceManager,
    create_artifact_bundle,
};
use apm2_daemon::projection::{
    GitHubAdapterConfig, GitHubProjectionAdapter, ProjectedStatus, ProjectionAdapter,
};
use prost::Message;
use tempfile::TempDir;

// =============================================================================
// EVID-HEF-0012 Constraints
// =============================================================================

/// Enforces EVID-HEF-0012 environment constraints.
///
/// Per EVID-HEF-0012, the E2E harness must run without GitHub tokens to ensure
/// no external reads occur. This function panics if tokens are present.
fn enforce_evid_hef_0012_env_constraints() {
    assert!(
        std::env::var_os("GITHUB_TOKEN").is_none(),
        "EVID-HEF-0012 constraint: GITHUB_TOKEN must not be set during evidence runs"
    );
    assert!(
        std::env::var_os("GH_TOKEN").is_none(),
        "EVID-HEF-0012 constraint: GH_TOKEN must not be set during evidence runs"
    );
}

// =============================================================================
// Environment Guard
// =============================================================================

struct EnvVarGuard {
    key: &'static str,
    previous: Option<OsString>,
}

static GIT_TEST_MUTEX: Mutex<()> = Mutex::new(());

impl EnvVarGuard {
    #[allow(unsafe_code)]
    fn set(key: &'static str, value: impl AsRef<OsStr>) -> Self {
        let previous = std::env::var_os(key);
        // SAFETY: Tests control env mutation scope; guard restores on drop.
        unsafe {
            std::env::set_var(key, value);
        }
        Self { key, previous }
    }
}

impl Drop for EnvVarGuard {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        match self.previous.as_ref() {
            Some(value) => unsafe {
                // SAFETY: Tests control env mutation scope; guard restores on drop.
                std::env::set_var(self.key, value);
            },
            None => unsafe {
                // SAFETY: Tests control env mutation scope; guard restores on drop.
                std::env::remove_var(self.key);
            },
        }
    }
}

// =============================================================================
// Test Harness
// =============================================================================

/// FAC v0 E2E test harness with real components including ledger.
struct FacV0TestHarness {
    /// Workspace manager for snapshot/apply operations.
    workspace_manager: WorkspaceManager,
    /// Capability validator for tool profile enforcement.
    capability_validator: CapabilityValidator,
    /// Content-addressed store for evidence.
    cas: Arc<dyn ContentAddressedStore>,
    /// Tool executor with real handlers.
    tool_executor: ToolExecutor,
    /// Signer for cryptographic operations.
    signer: Signer,
    /// Ledger for event anchoring.
    ledger: Ledger,
    /// Temporary directory for workspace.
    _temp_dir: TempDir,
    /// Current timestamp for event ordering.
    current_timestamp_ms: u64,
}

impl FacV0TestHarness {
    /// Creates a new test harness with real components.
    fn new() -> Self {
        // Create temporary workspace directory
        let temp_dir = TempDir::new().expect("create temp dir");
        let workspace_root = temp_dir.path().to_path_buf();

        // Create workspace manager
        let workspace_manager = WorkspaceManager::new(workspace_root.clone());

        // Create reviewer capability manifest with Read allowed
        let reviewer_manifest = create_reviewer_capability_manifest();
        let capability_validator =
            CapabilityValidator::new(reviewer_manifest).expect("valid capability validator");

        // Create CAS
        let cas_dir = temp_dir.path().join("cas");
        std::fs::create_dir_all(&cas_dir).expect("create cas dir");
        let cas_config = DurableCasConfig::new(&cas_dir);
        let cas: Arc<dyn ContentAddressedStore> =
            Arc::new(DurableCas::new(cas_config).expect("create cas"));

        // Create ledger (in-memory for tests)
        let ledger = Ledger::in_memory().expect("create ledger");

        // Create budget tracker for tool execution
        let budget = EpisodeBudget::builder()
            .tokens(10_000)
            .tool_calls(100)
            .wall_ms(300_000)
            .bytes_io(10_000_000)
            .build();
        let budget_tracker = Arc::new(BudgetTracker::from_envelope(budget));

        // Create executor with real handlers rooted at workspace
        let mut executor = ToolExecutor::new(budget_tracker, cas.clone());
        executor
            .register_handler(Box::new(ReadFileHandler::with_root(workspace_root)))
            .expect("register ReadFileHandler");
        executor
            .register_handler(Box::new(GitOperationHandler::with_root(
                temp_dir.path().to_path_buf(),
            )))
            .expect("register GitOperationHandler");
        executor
            .register_handler(Box::new(ArtifactFetchHandler::new(cas.clone())))
            .expect("register ArtifactFetchHandler");

        // Create signer
        let signer = Signer::generate();

        Self {
            workspace_manager,
            capability_validator,
            cas,
            tool_executor: executor,
            signer,
            ledger,
            _temp_dir: temp_dir,
            current_timestamp_ms: 1_704_067_200_000, // 2024-01-01T00:00:00Z
        }
    }

    /// Returns the workspace root path.
    const fn workspace_root(&self) -> &PathBuf {
        &self.workspace_manager.workspace_root
    }

    /// Advances the current timestamp.
    const fn advance_time(&mut self, ms: u64) {
        self.current_timestamp_ms += ms;
    }

    /// Returns the current timestamp in nanoseconds for HTF compliance.
    const fn current_time_ns(&self) -> u64 {
        self.current_timestamp_ms * 1_000_000
    }

    /// Returns the actor ID derived from the signer's verifying key.
    fn actor_id(&self) -> String {
        hex::encode(self.signer.verifying_key().as_bytes())
    }

    /// Creates an execution context for tool calls.
    fn execution_context(&self, request_id: &str) -> ExecutionContext {
        ExecutionContext::new(
            apm2_daemon::episode::EpisodeId::new("ep-fac-v0-e2e").expect("valid episode id"),
            request_id,
            self.current_timestamp_ms * 1_000_000, // Convert to nanoseconds
        )
    }

    /// Initializes a git repository in the workspace for `GitOperation` tests.
    fn init_git_repo(&self) {
        let git_dir = self.workspace_root().join(".git");
        if git_dir.exists() {
            return;
        }

        self.run_git(&["init"]);
        self.run_git(&["config", "user.email", "fac-v0@example.com"]);
        self.run_git(&["config", "user.name", "FAC V0 Harness"]);
    }

    /// Commits all current changes in the workspace.
    fn git_commit_all(&self, message: &str) {
        self.run_git(&["add", "."]);
        let status = Command::new("git")
            .arg("-C")
            .arg(self.workspace_root())
            .args(["commit", "-m", message])
            .env("GIT_AUTHOR_NAME", "FAC V0 Harness")
            .env("GIT_AUTHOR_EMAIL", "fac-v0@example.com")
            .env("GIT_COMMITTER_NAME", "FAC V0 Harness")
            .env("GIT_COMMITTER_EMAIL", "fac-v0@example.com")
            .status()
            .expect("git commit");
        assert!(status.success(), "git commit failed");
    }

    fn run_git(&self, args: &[&str]) {
        let status = Command::new("git")
            .arg("-C")
            .arg(self.workspace_root())
            .args(args)
            .status()
            .expect("git command");
        assert!(status.success(), "git {args:?} failed");
    }

    /// Creates a signed ledger event for `ChangeSetPublished`.
    fn create_changeset_published_event(
        &self,
        work_id: &str,
        changeset_digest: [u8; 32],
        cas_hash: [u8; 32],
    ) -> EventRecord {
        let event = ChangeSetPublished {
            work_id: work_id.to_string(),
            changeset_digest: changeset_digest.to_vec(),
            cas_hash: cas_hash.to_vec(),
            published_at: self.current_timestamp_ms,
            publisher_actor_id: self.actor_id(),
            publisher_signature: vec![], // Set below
            time_envelope_ref: None,
        };

        let payload = event.encode_to_vec();

        // Sign with ledger domain prefix (not FAC prefix)
        let signature = sign_with_domain(&self.signer, CHANGESET_PUBLISHED_DOMAIN_PREFIX, &payload);

        let prev_hash = self.ledger.last_event_hash().expect("get prev_hash");

        let mut record = EventRecord::new("changeset_published", work_id, self.actor_id(), payload);
        record.prev_hash = Some(prev_hash);
        record.signature = Some(signature.to_bytes().to_vec());
        record
    }

    /// Creates a signed ledger event for `ReviewReceiptRecorded`.
    fn create_review_receipt_event(
        &self,
        receipt_id: &str,
        changeset_digest: [u8; 32],
        artifact_bundle_hash: [u8; 32],
    ) -> EventRecord {
        let event = ReviewReceiptRecorded {
            receipt_id: receipt_id.to_string(),
            changeset_digest: changeset_digest.to_vec(),
            artifact_bundle_hash: artifact_bundle_hash.to_vec(),
            time_envelope_ref: None,
            reviewer_actor_id: self.actor_id(),
            reviewer_signature: vec![], // Set below
            // TCK-00326: Authority binding fields
            capability_manifest_hash: vec![0x55; 32],
            context_pack_hash: vec![0x66; 32],
        };

        let payload = event.encode_to_vec();

        // Sign with ledger domain prefix
        let signature = sign_with_domain(
            &self.signer,
            REVIEW_RECEIPT_RECORDED_DOMAIN_PREFIX,
            &payload,
        );

        let prev_hash = self.ledger.last_event_hash().expect("get prev_hash");

        let mut record = EventRecord::new(
            "review_receipt_recorded",
            receipt_id,
            self.actor_id(),
            payload,
        );
        record.prev_hash = Some(prev_hash);
        record.signature = Some(signature.to_bytes().to_vec());
        record
    }

    /// Creates a signed ledger event for `ReviewBlockedRecorded`.
    fn create_review_blocked_event(
        &self,
        blocked_id: &str,
        changeset_digest: [u8; 32],
        reason_code: ReasonCode,
        cas_log_hash: [u8; 32],
    ) -> EventRecord {
        let event = ReviewBlockedRecorded {
            blocked_id: blocked_id.to_string(),
            changeset_digest: changeset_digest.to_vec(),
            reason_code: i32::from(reason_code.to_code()),
            blocked_log_hash: cas_log_hash.to_vec(),
            time_envelope_ref: None,
            recorder_actor_id: self.actor_id(),
            recorder_signature: vec![], // Set below
            // TCK-00326: Authority binding fields
            capability_manifest_hash: vec![0x55; 32],
            context_pack_hash: vec![0x66; 32],
        };

        let payload = event.encode_to_vec();

        // Sign with ledger domain prefix
        let signature = sign_with_domain(
            &self.signer,
            REVIEW_BLOCKED_RECORDED_DOMAIN_PREFIX,
            &payload,
        );

        let prev_hash = self.ledger.last_event_hash().expect("get prev_hash");

        let mut record = EventRecord::new(
            "review_blocked_recorded",
            blocked_id,
            self.actor_id(),
            payload,
        );
        record.prev_hash = Some(prev_hash);
        record.signature = Some(signature.to_bytes().to_vec());
        record
    }
}

/// Creates a reviewer capability manifest for FAC v0.
///
/// Per REQ-HEF-0010, the reviewer profile allows:
/// - Read: File reading for code review
/// - Git: Diff/status for workspace inspection
/// - Artifact: Fetch review artifacts from CAS
/// - Denies: Write, Execute, Network (safety constraints)
fn create_reviewer_capability_manifest() -> apm2_daemon::episode::CapabilityManifest {
    CapabilityManifestBuilder::new("reviewer-fac-v0-manifest")
        .delegator("fac-v0-orchestrator")
        .capability(
            Capability::builder("cap-reviewer-read", ToolClass::Read)
                .scope(CapabilityScope::allow_all())
                .build()
                .expect("valid read capability"),
        )
        .capability(
            Capability::builder("cap-reviewer-git", ToolClass::Git)
                .scope(CapabilityScope::allow_all())
                .build()
                .expect("valid git capability"),
        )
        .capability(
            Capability::builder("cap-reviewer-artifact", ToolClass::Artifact)
                .scope(CapabilityScope::allow_all())
                .build()
                .expect("valid artifact capability"),
        )
        .tool_allowlist(vec![ToolClass::Read, ToolClass::Git, ToolClass::Artifact])
        .build()
        .expect("valid manifest")
}

/// Creates a read-only capability manifest (for negative enforcement tests).
fn create_read_only_capability_manifest() -> apm2_daemon::episode::CapabilityManifest {
    CapabilityManifestBuilder::new("reviewer-read-only-manifest")
        .delegator("fac-v0-orchestrator")
        .capability(
            Capability::builder("cap-reviewer-read", ToolClass::Read)
                .scope(CapabilityScope::allow_all())
                .build()
                .expect("valid read capability"),
        )
        .tool_allowlist(vec![ToolClass::Read])
        .build()
        .expect("valid manifest")
}

/// Creates a test changeset bundle.
fn create_test_changeset_bundle(files: Vec<(&str, ChangeKind)>) -> ChangeSetBundleV1 {
    let file_manifest: Vec<FileChange> = files
        .into_iter()
        .map(|(path, kind)| FileChange {
            path: path.to_string(),
            change_kind: kind,
            old_path: None,
        })
        .collect();

    ChangeSetBundleV1::builder()
        .changeset_id("cs-test-001")
        .base(GitObjectRef {
            algo: HashAlgo::Sha1,
            object_kind: "commit".to_string(),
            object_id: "a".repeat(40),
        })
        .diff_hash([0x42; 32])
        .file_manifest(file_manifest)
        .binary_detected(false)
        .build()
        .expect("valid changeset bundle")
}

// =============================================================================
// IT-00313-01: ChangeSetPublished Ledger Anchoring (REQ-HEF-0009)
// =============================================================================

/// Tests `ChangeSetPublished` ledger anchoring with CAS storage.
///
/// Verifies:
/// - `ChangeSetBundleV1` is stored in CAS
/// - `ChangeSetPublished` event is appended to ledger via `append_verified`
/// - Event can be read back and decoded
/// - `changeset_digest` and `cas_hash` match
#[tokio::test]
async fn test_changeset_published_ledger_anchoring() {
    enforce_evid_hef_0012_env_constraints();

    let harness = FacV0TestHarness::new();

    // Create changeset bundle
    let bundle = create_test_changeset_bundle(vec![
        ("src/lib.rs", ChangeKind::Modify),
        ("tests/integration.rs", ChangeKind::Add),
    ]);

    // Store bundle in CAS
    let bundle_bytes = bundle.canonical_bytes().expect("serialize bundle");
    let cas_hash = harness.cas.store(&bundle_bytes);

    // Verify CAS storage
    let retrieved = harness.cas.retrieve(&cas_hash);
    assert!(retrieved.is_some(), "Bundle should be retrievable from CAS");
    assert_eq!(retrieved.unwrap(), bundle_bytes, "CAS content should match");

    // Create and append ChangeSetPublished event
    let event = harness.create_changeset_published_event(
        "work-fac-v0-test",
        bundle.changeset_digest,
        cas_hash,
    );

    let seq_id = harness
        .ledger
        .append_verified(&event, &harness.signer.verifying_key())
        .expect("append_verified should succeed");

    assert_eq!(seq_id, 1, "First event should have seq_id 1");

    // Read back and verify
    let stored = harness.ledger.read_one(seq_id).expect("read_one");
    assert_eq!(stored.event_type, "changeset_published");

    // Decode payload
    let decoded =
        ChangeSetPublished::decode(stored.payload.as_slice()).expect("decode ChangeSetPublished");
    assert_eq!(decoded.work_id, "work-fac-v0-test");
    assert_eq!(decoded.changeset_digest, bundle.changeset_digest.to_vec());
    assert_eq!(decoded.cas_hash, cas_hash.to_vec());

    // Verify ledger chain integrity
    assert!(stored.event_hash.is_some(), "event_hash should be computed");
    assert!(stored.prev_hash.is_some(), "prev_hash should be set");
}

// =============================================================================
// IT-00313-02: ReviewReceiptRecorded Ledger Anchoring (REQ-HEF-0011)
// =============================================================================

/// Tests `ReviewReceiptRecorded` ledger anchoring with artifact bundle.
///
/// Verifies:
/// - `ReviewArtifactBundle` is stored in CAS
/// - `ReviewReceiptRecorded` event is appended to ledger
/// - `changeset_digest` and `artifact_bundle_hash` are correctly bound
#[tokio::test]
#[allow(clippy::await_holding_lock)] // Test-only: serial execution via mutex is intentional
async fn test_review_receipt_ledger_anchoring() {
    enforce_evid_hef_0012_env_constraints();

    let mut harness = FacV0TestHarness::new();
    let _git_lock = GIT_TEST_MUTEX
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    // First, establish context with ChangeSetPublished
    let bundle = create_test_changeset_bundle(vec![("src/lib.rs", ChangeKind::Modify)]);
    let bundle_bytes = bundle.canonical_bytes().expect("serialize bundle");
    let cas_hash = harness.cas.store(&bundle_bytes);

    let cs_event = harness.create_changeset_published_event(
        "work-review-test",
        bundle.changeset_digest,
        cas_hash,
    );
    harness
        .ledger
        .append_verified(&cs_event, &harness.signer.verifying_key())
        .expect("append changeset_published");

    harness.advance_time(100);

    // Create review artifact bundle
    let review_text = "LGTM - Code changes look good.";
    let review_text_hash = harness.cas.store(review_text.as_bytes());

    let tool_log = r#"{"tool": "FileRead", "success": true}"#;
    let tool_log_hash = harness.cas.store(tool_log.as_bytes());

    let metadata = ReviewMetadata::new()
        .with_reviewer_actor_id("reviewer-fac-v0-test")
        .with_verdict(ReviewVerdict::Approve)
        .with_started_at(harness.current_timestamp_ms * 1_000_000)
        .with_completed_at((harness.current_timestamp_ms + 1) * 1_000_000);

    let artifact_bundle = create_artifact_bundle(
        "review-receipt-test".to_string(),
        bundle.changeset_digest,
        review_text_hash,
        vec![tool_log_hash],
        [0u8; 32],
        None,
        None,
        Some(metadata),
    )
    .expect("build artifact bundle");

    artifact_bundle.validate().expect("artifact bundle valid");
    let artifact_bundle_bytes =
        serde_json::to_vec(&artifact_bundle).expect("serialize artifact bundle");
    let artifact_bundle_hash = harness.cas.store(&artifact_bundle_bytes);

    // Create and append ReviewReceiptRecorded
    let receipt_event = harness.create_review_receipt_event(
        "RR-fac-v0-001",
        bundle.changeset_digest,
        artifact_bundle_hash,
    );

    let seq_id = harness
        .ledger
        .append_verified(&receipt_event, &harness.signer.verifying_key())
        .expect("append_verified should succeed");

    assert_eq!(seq_id, 2, "Second event should have seq_id 2");

    // Read back and verify
    let stored = harness.ledger.read_one(seq_id).expect("read_one");
    assert_eq!(stored.event_type, "review_receipt_recorded");

    // Decode and verify binding
    let decoded = ReviewReceiptRecorded::decode(stored.payload.as_slice())
        .expect("decode ReviewReceiptRecorded");
    assert_eq!(decoded.receipt_id, "RR-fac-v0-001");
    assert_eq!(decoded.changeset_digest, bundle.changeset_digest.to_vec());
    assert_eq!(decoded.artifact_bundle_hash, artifact_bundle_hash.to_vec());

    // Verify artifact bundle can be retrieved and decoded
    let retrieved_bundle = harness
        .cas
        .retrieve(&artifact_bundle_hash)
        .expect("retrieve artifact bundle");
    let parsed: ReviewArtifactBundleV1 =
        serde_json::from_slice(&retrieved_bundle).expect("parse artifact bundle");
    assert_eq!(parsed.review_text_hash, hex::encode(review_text_hash));
    assert_eq!(parsed.tool_log_hashes.len(), 1);
    assert_eq!(parsed.tool_log_hashes[0], hex::encode(tool_log_hash));
}

// =============================================================================
// IT-00313-03: ReviewBlockedRecorded Ledger Anchoring (REQ-HEF-0011)
// =============================================================================

/// Tests `ReviewBlockedRecorded` ledger anchoring for binary file rejection.
#[tokio::test]
async fn test_review_blocked_binary_unsupported() {
    enforce_evid_hef_0012_env_constraints();

    let harness = FacV0TestHarness::new();

    // Create bundle with binary file
    let bundle = ChangeSetBundleV1::builder()
        .changeset_id("cs-binary-test")
        .base(GitObjectRef {
            algo: HashAlgo::Sha1,
            object_kind: "commit".to_string(),
            object_id: "b".repeat(40),
        })
        .diff_hash([0x43; 32])
        .file_manifest(vec![FileChange {
            path: "image.png".to_string(),
            change_kind: ChangeKind::Add,
            old_path: None,
        }])
        .binary_detected(true)
        .build()
        .expect("valid bundle");

    // Validate should fail
    let validation_result = validate_file_changes(&bundle, harness.workspace_root());
    assert!(
        matches!(validation_result, Err(WorkspaceError::BinaryUnsupported(_))),
        "Should reject binary files"
    );

    // Store error log in CAS
    let error_log = format!(
        r#"{{"error": "BinaryUnsupported", "path": "image.png", "changeset_digest": "{}"}}"#,
        hex::encode(bundle.changeset_digest)
    );
    let cas_log_hash = harness.cas.store(error_log.as_bytes());

    // Create and append ReviewBlockedRecorded
    let blocked_event = harness.create_review_blocked_event(
        "BLK-binary-001",
        bundle.changeset_digest,
        ReasonCode::BinaryUnsupported,
        cas_log_hash,
    );

    let seq_id = harness
        .ledger
        .append_verified(&blocked_event, &harness.signer.verifying_key())
        .expect("append_verified should succeed");

    // Read back and verify
    let stored = harness.ledger.read_one(seq_id).expect("read_one");
    let decoded = ReviewBlockedRecorded::decode(stored.payload.as_slice())
        .expect("decode ReviewBlockedRecorded");

    assert_eq!(decoded.blocked_id, "BLK-binary-001");
    assert_eq!(
        decoded.reason_code,
        i32::from(ReasonCode::BinaryUnsupported.to_code())
    );
    assert_eq!(decoded.blocked_log_hash, cas_log_hash.to_vec());
}

/// Tests `ReviewBlockedRecorded` ledger anchoring for path traversal rejection.
#[tokio::test]
async fn test_review_blocked_path_traversal() {
    enforce_evid_hef_0012_env_constraints();

    let harness = FacV0TestHarness::new();

    // Create bundle with path traversal
    let bundle = ChangeSetBundleV1::builder()
        .changeset_id("cs-traversal-test")
        .base(GitObjectRef {
            algo: HashAlgo::Sha1,
            object_kind: "commit".to_string(),
            object_id: "c".repeat(40),
        })
        .diff_hash([0x44; 32])
        .file_manifest(vec![FileChange {
            path: "../etc/passwd".to_string(),
            change_kind: ChangeKind::Modify,
            old_path: None,
        }])
        .binary_detected(false)
        .build()
        .expect("valid bundle");

    // Validate should fail
    let validation_result = validate_file_changes(&bundle, harness.workspace_root());
    assert!(
        matches!(validation_result, Err(WorkspaceError::PathTraversal(_))),
        "Should reject path traversal"
    );

    // Store error log in CAS
    let error_log = format!(
        r#"{{"error": "PathTraversal", "path": "../etc/passwd", "changeset_digest": "{}"}}"#,
        hex::encode(bundle.changeset_digest)
    );
    let cas_log_hash = harness.cas.store(error_log.as_bytes());

    // Create and append ReviewBlockedRecorded
    let blocked_event = harness.create_review_blocked_event(
        "BLK-traversal-001",
        bundle.changeset_digest,
        ReasonCode::InvalidBundle,
        cas_log_hash,
    );

    let seq_id = harness
        .ledger
        .append_verified(&blocked_event, &harness.signer.verifying_key())
        .expect("append_verified should succeed");

    // Read back and verify
    let stored = harness.ledger.read_one(seq_id).expect("read_one");
    let decoded = ReviewBlockedRecorded::decode(stored.payload.as_slice())
        .expect("decode ReviewBlockedRecorded");

    assert_eq!(
        decoded.reason_code,
        i32::from(ReasonCode::InvalidBundle.to_code())
    );
}

/// Tests `ReviewBlockedRecorded` for apply failure mapping.
#[tokio::test]
async fn test_review_blocked_apply_failed() {
    enforce_evid_hef_0012_env_constraints();

    let harness = FacV0TestHarness::new();
    let bundle = create_test_changeset_bundle(vec![("src/apply.rs", ChangeKind::Modify)]);

    let bundle_bytes = bundle.canonical_bytes().expect("serialize bundle");
    let cas_hash = harness.cas.store(&bundle_bytes);
    let cs_event = harness.create_changeset_published_event(
        "work-apply-failed",
        bundle.changeset_digest,
        cas_hash,
    );
    harness
        .ledger
        .append_verified(&cs_event, &harness.signer.verifying_key())
        .expect("append changeset_published");

    let error = WorkspaceError::ApplyFailed("apply failed".into());
    let error_log = serde_json::json!({
        "error": error.to_string(),
        "changeset_digest": hex::encode(bundle.changeset_digest),
    });
    let cas_log_hash = harness.cas.store(error_log.to_string().as_bytes());

    let blocked_event = harness.create_review_blocked_event(
        "BLK-apply-001",
        bundle.changeset_digest,
        error.reason_code(),
        cas_log_hash,
    );

    let seq_id = harness
        .ledger
        .append_verified(&blocked_event, &harness.signer.verifying_key())
        .expect("append review_blocked_recorded");

    let stored = harness.ledger.read_one(seq_id).expect("read_one");
    let decoded = ReviewBlockedRecorded::decode(stored.payload.as_slice())
        .expect("decode ReviewBlockedRecorded");

    assert_eq!(
        decoded.reason_code,
        i32::from(ReasonCode::ApplyFailed.to_code())
    );
    assert_eq!(decoded.blocked_log_hash, cas_log_hash.to_vec());
}

/// Tests `ReviewBlockedRecorded` for tool failure on `GitOperation` bounds.
#[tokio::test]
#[allow(clippy::await_holding_lock)] // Test-only: serial execution via mutex is intentional
async fn test_review_blocked_tool_failure_on_git_bounds() {
    enforce_evid_hef_0012_env_constraints();

    let harness = FacV0TestHarness::new();
    let _git_lock = GIT_TEST_MUTEX
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let bundle = create_test_changeset_bundle(vec![("big.txt", ChangeKind::Modify)]);

    let bundle_bytes = bundle.canonical_bytes().expect("serialize bundle");
    let cas_hash = harness.cas.store(&bundle_bytes);
    let cs_event = harness.create_changeset_published_event(
        "work-tool-failed",
        bundle.changeset_digest,
        cas_hash,
    );
    harness
        .ledger
        .append_verified(&cs_event, &harness.signer.verifying_key())
        .expect("append changeset_published");

    let big_path = harness.workspace_root().join("big.txt");
    std::fs::write(&big_path, b"base\n").expect("write base file");
    harness.init_git_repo();
    harness.git_commit_all("init-big");

    let line_count = apm2_daemon::episode::GIT_DIFF_MAX_LINES + 10;
    let mut large = String::new();
    for _ in 0..line_count {
        large.push_str("line\n");
    }
    std::fs::write(&big_path, large.as_bytes()).expect("write large diff");

    let ctx = harness.execution_context("req-git-bounds");
    let git_args = ToolArgs::Git(GitArgs {
        operation: "diff".to_string(),
        args: vec!["big.txt".to_string()],
        repo_path: None,
    });

    let result = harness
        .tool_executor
        .execute(&ctx, &git_args, None)
        .await
        .expect("execute git diff");
    assert!(
        !result.success,
        "git diff should fail when output exceeds bounds"
    );

    let error_message = result
        .error_message
        .unwrap_or_else(|| "git diff failed".to_string());
    let error_log = serde_json::json!({
        "error": error_message,
        "operation": "diff",
        "changeset_digest": hex::encode(bundle.changeset_digest),
    });
    let cas_log_hash = harness.cas.store(error_log.to_string().as_bytes());

    let blocked_event = harness.create_review_blocked_event(
        "BLK-tool-001",
        bundle.changeset_digest,
        ReasonCode::ToolFailed,
        cas_log_hash,
    );

    let seq_id = harness
        .ledger
        .append_verified(&blocked_event, &harness.signer.verifying_key())
        .expect("append review_blocked_recorded");

    let stored = harness.ledger.read_one(seq_id).expect("read_one");
    let decoded = ReviewBlockedRecorded::decode(stored.payload.as_slice())
        .expect("decode ReviewBlockedRecorded");

    assert_eq!(
        decoded.reason_code,
        i32::from(ReasonCode::ToolFailed.to_code())
    );
}

/// Tests `ReviewBlockedRecorded` for tool failure on `git status` bounds.
#[tokio::test]
#[allow(clippy::await_holding_lock)] // Test-only: serial execution via mutex is intentional
async fn test_review_blocked_tool_failure_on_git_status_bounds() {
    enforce_evid_hef_0012_env_constraints();

    let harness = FacV0TestHarness::new();
    let _git_lock = GIT_TEST_MUTEX
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let bundle = create_test_changeset_bundle(vec![("status.txt", ChangeKind::Modify)]);

    let bundle_bytes = bundle.canonical_bytes().expect("serialize bundle");
    let cas_hash = harness.cas.store(&bundle_bytes);
    let cs_event = harness.create_changeset_published_event(
        "work-status-bounds",
        bundle.changeset_digest,
        cas_hash,
    );
    harness
        .ledger
        .append_verified(&cs_event, &harness.signer.verifying_key())
        .expect("append changeset_published");

    harness.init_git_repo();

    let file_count = apm2_daemon::episode::GIT_STATUS_MAX_LINES + 25;
    let mut tracked_paths = Vec::with_capacity(file_count);
    for idx in 0..file_count {
        let path = harness
            .workspace_root()
            .join("status")
            .join(format!("file_{idx:04}.txt"));
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create status dir");
        }
        std::fs::write(&path, b"x").expect("write status file");
        tracked_paths.push(path);
    }

    harness.git_commit_all("init-status");
    for path in tracked_paths {
        std::fs::write(&path, b"updated\n").expect("update status file");
    }

    let ctx = harness.execution_context("req-git-status-bounds");
    let git_args = ToolArgs::Git(GitArgs {
        operation: "status".to_string(),
        args: vec![],
        repo_path: None,
    });

    let result = harness
        .tool_executor
        .execute(&ctx, &git_args, None)
        .await
        .expect("execute git status");
    assert!(
        !result.success,
        "git status should fail when output exceeds bounds"
    );

    let error_message = result
        .error_message
        .unwrap_or_else(|| "git status failed".to_string());
    let error_log = serde_json::json!({
        "error": error_message,
        "operation": "status",
        "changeset_digest": hex::encode(bundle.changeset_digest),
    });
    let cas_log_hash = harness.cas.store(error_log.to_string().as_bytes());

    let blocked_event = harness.create_review_blocked_event(
        "BLK-tool-status-001",
        bundle.changeset_digest,
        ReasonCode::ToolFailed,
        cas_log_hash,
    );

    let seq_id = harness
        .ledger
        .append_verified(&blocked_event, &harness.signer.verifying_key())
        .expect("append review_blocked_recorded");

    let stored = harness.ledger.read_one(seq_id).expect("read_one");
    let decoded = ReviewBlockedRecorded::decode(stored.payload.as_slice())
        .expect("decode ReviewBlockedRecorded");

    assert_eq!(
        decoded.reason_code,
        i32::from(ReasonCode::ToolFailed.to_code())
    );
}

/// Tests git environment isolation (`GIT_DIR`/`GIT_WORK_TREE` ignored).
#[tokio::test]
#[allow(clippy::await_holding_lock)] // Test-only: serial execution via mutex is intentional
async fn test_git_operation_ignores_env_overrides() {
    enforce_evid_hef_0012_env_constraints();

    let harness = FacV0TestHarness::new();
    let _git_lock = GIT_TEST_MUTEX
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let file_path = harness.workspace_root().join("env_isolation.txt");
    std::fs::write(&file_path, b"base\n").expect("write base file");
    harness.init_git_repo();
    harness.git_commit_all("init-env");
    std::fs::write(&file_path, b"changed\n").expect("write change");

    let _git_dir_guard = EnvVarGuard::set("GIT_DIR", harness.workspace_root().join("not-a-repo"));
    let _git_work_tree_guard = EnvVarGuard::set("GIT_WORK_TREE", "/tmp");

    let ctx = harness.execution_context("req-git-env-override");
    let git_args = ToolArgs::Git(GitArgs {
        operation: "diff".to_string(),
        args: vec!["env_isolation.txt".to_string()],
        repo_path: None,
    });

    let result = harness
        .tool_executor
        .execute(&ctx, &git_args, None)
        .await
        .expect("execute git diff");

    assert!(
        result.success,
        "git diff should succeed despite env overrides"
    );
    assert!(
        String::from_utf8_lossy(&result.output).contains("changed"),
        "git diff should reflect workspace content"
    );
}

/// Tests `ReviewBlockedRecorded` for missing artifact fetch.
#[tokio::test]
async fn test_review_blocked_missing_artifact() {
    enforce_evid_hef_0012_env_constraints();

    let harness = FacV0TestHarness::new();
    let bundle = create_test_changeset_bundle(vec![("src/missing.rs", ChangeKind::Modify)]);

    let bundle_bytes = bundle.canonical_bytes().expect("serialize bundle");
    let cas_hash = harness.cas.store(&bundle_bytes);
    let cs_event = harness.create_changeset_published_event(
        "work-missing-artifact",
        bundle.changeset_digest,
        cas_hash,
    );
    harness
        .ledger
        .append_verified(&cs_event, &harness.signer.verifying_key())
        .expect("append changeset_published");

    let missing_hash = [0x11; 32];
    let ctx = harness.execution_context("req-missing-artifact");
    let artifact_args = ToolArgs::Artifact(ArtifactArgs {
        stable_id: None,
        content_hash: Some(missing_hash),
        expected_hash: None,
        max_bytes: 1024,
        format: None,
    });
    let result = harness
        .tool_executor
        .execute(&ctx, &artifact_args, None)
        .await
        .expect("execute artifact fetch");
    assert!(
        !result.success,
        "artifact fetch should fail for missing content"
    );

    let error_message = result
        .error_message
        .unwrap_or_else(|| "missing artifact".to_string());
    let error_log = serde_json::json!({
        "error": error_message,
        "content_hash": hex::encode(missing_hash),
    });
    let cas_log_hash = harness.cas.store(error_log.to_string().as_bytes());

    let blocked_event = harness.create_review_blocked_event(
        "BLK-missing-001",
        bundle.changeset_digest,
        ReasonCode::MissingArtifact,
        cas_log_hash,
    );
    let seq_id = harness
        .ledger
        .append_verified(&blocked_event, &harness.signer.verifying_key())
        .expect("append review_blocked_recorded");

    let stored = harness.ledger.read_one(seq_id).expect("read_one");
    let decoded = ReviewBlockedRecorded::decode(stored.payload.as_slice())
        .expect("decode ReviewBlockedRecorded");
    assert_eq!(
        decoded.reason_code,
        i32::from(ReasonCode::MissingArtifact.to_code())
    );
}

/// Tests `ReviewBlockedRecorded` for artifact fetch `max_bytes` enforcement.
#[tokio::test]
async fn test_review_blocked_artifact_fetch_max_bytes() {
    enforce_evid_hef_0012_env_constraints();

    let harness = FacV0TestHarness::new();
    let bundle = create_test_changeset_bundle(vec![("artifact.txt", ChangeKind::Add)]);

    let bundle_bytes = bundle.canonical_bytes().expect("serialize bundle");
    let cas_hash = harness.cas.store(&bundle_bytes);
    let cs_event = harness.create_changeset_published_event(
        "work-artifact-max-bytes",
        bundle.changeset_digest,
        cas_hash,
    );
    harness
        .ledger
        .append_verified(&cs_event, &harness.signer.verifying_key())
        .expect("append changeset_published");

    let content = vec![b'a'; 2048];
    let content_hash = harness.cas.store(&content);

    let ctx = harness.execution_context("req-artifact-max-bytes");
    let artifact_args = ToolArgs::Artifact(ArtifactArgs {
        stable_id: None,
        content_hash: Some(content_hash),
        expected_hash: None,
        max_bytes: 512,
        format: None,
    });
    let result = harness
        .tool_executor
        .execute(&ctx, &artifact_args, None)
        .await
        .expect("execute artifact fetch");
    assert!(
        !result.success,
        "artifact fetch should fail when max_bytes is exceeded"
    );

    let error_message = result
        .error_message
        .unwrap_or_else(|| "artifact fetch failed".to_string());
    let error_log = serde_json::json!({
        "error": error_message,
        "content_hash": hex::encode(content_hash),
        "max_bytes": 512,
    });
    let cas_log_hash = harness.cas.store(error_log.to_string().as_bytes());

    let blocked_event = harness.create_review_blocked_event(
        "BLK-artifact-max-bytes-001",
        bundle.changeset_digest,
        ReasonCode::ToolFailed,
        cas_log_hash,
    );
    let seq_id = harness
        .ledger
        .append_verified(&blocked_event, &harness.signer.verifying_key())
        .expect("append review_blocked_recorded");

    let stored = harness.ledger.read_one(seq_id).expect("read_one");
    let decoded = ReviewBlockedRecorded::decode(stored.payload.as_slice())
        .expect("decode ReviewBlockedRecorded");
    assert_eq!(
        decoded.reason_code,
        i32::from(ReasonCode::ToolFailed.to_code())
    );
}

/// Tests `ReviewBlockedRecorded` for invalid bundle validation.
#[tokio::test]
async fn test_review_blocked_invalid_bundle() {
    enforce_evid_hef_0012_env_constraints();

    let harness = FacV0TestHarness::new();
    let mut invalid_bundle =
        create_test_changeset_bundle(vec![("src/invalid.rs", ChangeKind::Modify)]);
    let expected_digest = invalid_bundle.changeset_digest;
    invalid_bundle.changeset_digest = [0u8; 32];
    let validation = invalid_bundle.validate();
    assert!(validation.is_err(), "invalid bundle should fail validation");

    let error_log = serde_json::json!({
        "error": validation.err().unwrap().to_string(),
        "changeset_digest": hex::encode(expected_digest),
    });
    let cas_log_hash = harness.cas.store(error_log.to_string().as_bytes());

    let blocked_event = harness.create_review_blocked_event(
        "BLK-invalid-001",
        expected_digest,
        ReasonCode::InvalidBundle,
        cas_log_hash,
    );
    let seq_id = harness
        .ledger
        .append_verified(&blocked_event, &harness.signer.verifying_key())
        .expect("append review_blocked_recorded");

    let stored = harness.ledger.read_one(seq_id).expect("read_one");
    let decoded = ReviewBlockedRecorded::decode(stored.payload.as_slice())
        .expect("decode ReviewBlockedRecorded");
    assert_eq!(
        decoded.reason_code,
        i32::from(ReasonCode::InvalidBundle.to_code())
    );
}

/// Tests `ReviewBlockedRecorded` for timeout mapping.
#[tokio::test]
async fn test_review_blocked_timeout() {
    enforce_evid_hef_0012_env_constraints();

    let harness = FacV0TestHarness::new();
    let bundle = create_test_changeset_bundle(vec![("src/timeout.rs", ChangeKind::Modify)]);

    let bundle_bytes = bundle.canonical_bytes().expect("serialize bundle");
    let cas_hash = harness.cas.store(&bundle_bytes);
    let cs_event =
        harness.create_changeset_published_event("work-timeout", bundle.changeset_digest, cas_hash);
    harness
        .ledger
        .append_verified(&cs_event, &harness.signer.verifying_key())
        .expect("append changeset_published");

    let error = WorkspaceError::Timeout("tool timeout".into());
    let error_log = serde_json::json!({
        "error": error.to_string(),
        "changeset_digest": hex::encode(bundle.changeset_digest),
    });
    let cas_log_hash = harness.cas.store(error_log.to_string().as_bytes());

    let blocked_event = harness.create_review_blocked_event(
        "BLK-timeout-001",
        bundle.changeset_digest,
        error.reason_code(),
        cas_log_hash,
    );
    let seq_id = harness
        .ledger
        .append_verified(&blocked_event, &harness.signer.verifying_key())
        .expect("append review_blocked_recorded");

    let stored = harness.ledger.read_one(seq_id).expect("read_one");
    let decoded = ReviewBlockedRecorded::decode(stored.payload.as_slice())
        .expect("decode ReviewBlockedRecorded");
    assert_eq!(
        decoded.reason_code,
        i32::from(ReasonCode::Timeout.to_code())
    );
}

// =============================================================================
// IT-00313-04: Domain Separation Security Test
// =============================================================================

/// Tests that FAC-prefix signatures are rejected by ledger (domain separation).
///
/// This is a critical security test: the ledger must reject signatures created
/// with FAC-level domain prefixes and only accept ledger-specific prefixes.
#[tokio::test]
async fn test_domain_separation_rejects_fac_prefix() {
    enforce_evid_hef_0012_env_constraints();

    let harness = FacV0TestHarness::new();

    // Create a valid ReviewReceiptRecorded event
    let event_proto = ReviewReceiptRecorded {
        receipt_id: "RR-domain-test".to_string(),
        changeset_digest: vec![0x42; 32],
        artifact_bundle_hash: vec![0xAB; 32],
        time_envelope_ref: None,
        reviewer_actor_id: harness.actor_id(),
        reviewer_signature: vec![],
        // TCK-00326: Authority binding fields
        capability_manifest_hash: vec![0x55; 32],
        context_pack_hash: vec![0x66; 32],
    };
    let payload = event_proto.encode_to_vec();

    // Sign with FAC prefix (NOT ledger prefix) - this should be rejected
    let fac_prefix = apm2_core::fac::REVIEW_RECEIPT_RECORDED_PREFIX;
    let wrong_signature = sign_with_domain(&harness.signer, fac_prefix, &payload);

    let prev_hash = harness.ledger.last_event_hash().expect("get prev_hash");

    let mut event = EventRecord::new(
        "review_receipt_recorded",
        "RR-domain-test",
        harness.actor_id(),
        payload,
    );
    event.prev_hash = Some(prev_hash);
    event.signature = Some(wrong_signature.to_bytes().to_vec());

    // Append with verification should FAIL (wrong domain prefix)
    let result = harness
        .ledger
        .append_verified(&event, &harness.signer.verifying_key());

    assert!(
        result.is_err(),
        "Ledger should reject FAC-prefix signatures"
    );
}

// =============================================================================
// IT-00313-05: Full E2E Autonomous Flow
// =============================================================================

/// Tests the full FAC v0 autonomous reviewer flow with ledger anchoring.
///
/// This test exercises the complete flow:
/// 1. EVID-HEF-0012 env constraints
/// 2. CAS storage of `ChangeSetBundleV1`
/// 3. `ChangeSetPublished` ledger anchoring
/// 4. Workspace snapshot and apply
/// 5. Real tool execution via `ToolExecutor`
/// 6. CAS storage of tool outputs
/// 7. `ReviewReceiptRecorded` ledger anchoring
/// 8. Ledger-only truth verification
#[tokio::test]
#[allow(clippy::await_holding_lock)] // Test-only: serial execution via mutex is intentional
async fn test_fac_v0_full_e2e_autonomous_flow() {
    // =========================================================================
    // Step 0: EVID-HEF-0012 Environment Constraints
    // =========================================================================
    enforce_evid_hef_0012_env_constraints();

    let _git_lock = GIT_TEST_MUTEX
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut harness = FacV0TestHarness::new();

    // =========================================================================
    // Step 1: Create and validate changeset bundle
    // =========================================================================
    let bundle = create_test_changeset_bundle(vec![
        ("src/lib.rs", ChangeKind::Modify),
        ("tests/integration.rs", ChangeKind::Add),
    ]);

    bundle.validate().expect("changeset should be valid");
    assert!(!bundle.binary_detected, "no binary files in test bundle");

    // =========================================================================
    // Step 2: Store bundle in CAS (REQ-HEF-0009)
    // =========================================================================
    let bundle_bytes = bundle.canonical_bytes().expect("serialize bundle");
    let bundle_cas_hash = harness.cas.store(&bundle_bytes);

    // Verify CAS-only diff source (no GitHub reads)
    let retrieved_bundle = harness.cas.retrieve(&bundle_cas_hash);
    assert!(
        retrieved_bundle.is_some(),
        "Bundle should be retrievable from CAS"
    );

    // =========================================================================
    // Step 3: Anchor ChangeSetPublished to ledger (REQ-HEF-0009)
    // =========================================================================
    let cs_event = harness.create_changeset_published_event(
        "work-fac-v0-e2e",
        bundle.changeset_digest,
        bundle_cas_hash,
    );

    let cs_seq_id = harness
        .ledger
        .append_verified(&cs_event, &harness.signer.verifying_key())
        .expect("append changeset_published");

    // Verify ledger-only truth
    let cs_stored = harness.ledger.read_one(cs_seq_id).expect("read_one");
    let cs_decoded = ChangeSetPublished::decode(cs_stored.payload.as_slice())
        .expect("decode ChangeSetPublished");
    assert_eq!(
        cs_decoded.changeset_digest,
        bundle.changeset_digest.to_vec()
    );

    harness.advance_time(50);

    // =========================================================================
    // Step 4: Workspace snapshot and apply
    // =========================================================================
    let snapshot_ts = harness.current_time_ns();
    let snapshot = harness
        .workspace_manager
        .snapshot("work-fac-v0-e2e", snapshot_ts)
        .expect("workspace snapshot");

    assert_eq!(snapshot.work_id, "work-fac-v0-e2e");

    let apply_ts = harness.current_time_ns();
    let apply_result = harness
        .workspace_manager
        .apply_with_timestamp(&bundle, apply_ts)
        .expect("apply should succeed");

    assert_eq!(apply_result.changeset_digest, bundle.changeset_digest);
    harness.advance_time(100);

    // =========================================================================
    // Step 5: Create test file, initialize git repo, and validate tool requests
    // =========================================================================
    let test_file_path = harness.workspace_root().join("src/lib.rs");
    std::fs::create_dir_all(test_file_path.parent().unwrap()).expect("create workspace dirs");
    let initial_contents =
        b"// Test file for FAC v0 E2E\nfn main() { println!(\"Hello, FAC!\"); }\n";
    std::fs::write(&test_file_path, initial_contents).expect("create test file");

    harness.init_git_repo();
    harness.git_commit_all("init-fac-v0-e2e");

    // Modify file to produce a diff for GitOperation
    let updated_contents = b"// Test file for FAC v0 E2E\nfn main() { println!(\"Hello, FAC!\"); }\n// follow-up change\n";
    std::fs::write(&test_file_path, updated_contents).expect("update test file");

    let read_request = ToolRequest::new(ToolClass::Read, RiskTier::default())
        .with_path(test_file_path.clone())
        .with_size(4096);
    let git_request = ToolRequest::new(ToolClass::Git, RiskTier::default())
        .with_path(harness.workspace_root().clone());
    let artifact_request =
        ToolRequest::new(ToolClass::Artifact, RiskTier::default()).with_size(4096);

    let decision = harness.capability_validator.validate(&read_request);
    assert!(
        decision.is_allowed(),
        "Read tool should be allowed: {decision:?}"
    );
    let git_decision = harness.capability_validator.validate(&git_request);
    assert!(
        git_decision.is_allowed(),
        "Git tool should be allowed: {git_decision:?}"
    );
    let artifact_decision = harness.capability_validator.validate(&artifact_request);
    assert!(
        artifact_decision.is_allowed(),
        "Artifact tool should be allowed: {artifact_decision:?}"
    );

    // =========================================================================
    // Step 6: Execute real tools via ToolExecutor (Read + Git)
    // =========================================================================
    let ctx = harness.execution_context("req-read-001");
    let read_args = ToolArgs::Read(ReadArgs {
        path: PathBuf::from("src/lib.rs"),
        offset: None,
        limit: Some(4096),
    });

    let read_result = harness
        .tool_executor
        .execute(&ctx, &read_args, None)
        .await
        .expect("tool execution");

    assert!(read_result.success, "read execution should succeed");
    assert!(
        String::from_utf8_lossy(&read_result.output).contains("FAC v0 E2E"),
        "output should contain test file content"
    );

    let git_args = ToolArgs::Git(GitArgs {
        operation: "diff".to_string(),
        args: vec!["src/lib.rs".to_string()],
        repo_path: None,
    });
    let git_result = harness
        .tool_executor
        .execute(&ctx, &git_args, None)
        .await
        .expect("git operation");

    assert!(git_result.success, "git operation should succeed");
    assert!(
        String::from_utf8_lossy(&git_result.output).contains("follow-up change"),
        "git diff should include updated line"
    );

    harness.advance_time(50);

    // =========================================================================
    // Step 7: Store tool outputs in CAS
    // =========================================================================
    #[allow(clippy::cast_possible_truncation)]
    let read_duration_ms = read_result.duration.as_millis() as u64;
    let read_log = serde_json::json!({
        "tool": "FileRead",
        "path": "src/lib.rs",
        "success": read_result.success,
        "bytes_read": read_result.output.len(),
        "duration_ms": read_duration_ms,
    });
    let read_log_hash = harness.cas.store(read_log.to_string().as_bytes());

    #[allow(clippy::cast_possible_truncation)]
    let git_duration_ms = git_result.duration.as_millis() as u64;
    let git_log = serde_json::json!({
        "tool": "GitOperation",
        "operation": "diff",
        "pathspecs": ["src/lib.rs"],
        "success": git_result.success,
        "bytes_output": git_result.output.len(),
        "duration_ms": git_duration_ms,
    });
    let git_log_hash = harness.cas.store(git_log.to_string().as_bytes());

    // Verify CAS storage
    assert!(harness.cas.retrieve(&read_log_hash).is_some());
    assert!(harness.cas.retrieve(&git_log_hash).is_some());

    harness.advance_time(25);

    // =========================================================================
    // Step 8: Execute ArtifactFetch and store log in CAS
    // =========================================================================
    let review_text = "LGTM - Code changes look good. No security issues found.";
    let review_text_hash = harness.cas.store(review_text.as_bytes());

    let artifact_args = ToolArgs::Artifact(ArtifactArgs {
        stable_id: None,
        content_hash: Some(review_text_hash),
        expected_hash: None,
        max_bytes: 4096,
        format: None,
    });
    let artifact_result = harness
        .tool_executor
        .execute(&ctx, &artifact_args, None)
        .await
        .expect("artifact fetch");

    assert!(artifact_result.success, "artifact fetch should succeed");
    assert_eq!(artifact_result.output, review_text.as_bytes());

    #[allow(clippy::cast_possible_truncation)]
    let artifact_duration_ms = artifact_result.duration.as_millis() as u64;
    let artifact_log = serde_json::json!({
        "tool": "ArtifactFetch",
        "success": artifact_result.success,
        "bytes_output": artifact_result.output.len(),
        "duration_ms": artifact_duration_ms,
    });
    let artifact_log_hash = harness.cas.store(artifact_log.to_string().as_bytes());

    // =========================================================================
    // Step 9: Create review artifact bundle
    // =========================================================================
    let metadata = ReviewMetadata::new()
        .with_reviewer_actor_id("reviewer-fac-v0-e2e")
        .with_verdict(ReviewVerdict::Approve)
        .with_started_at((harness.current_timestamp_ms - 225) * 1_000_000)
        .with_completed_at(harness.current_timestamp_ms * 1_000_000);

    let artifact_bundle = create_artifact_bundle(
        "review-fac-v0-e2e".to_string(),
        bundle.changeset_digest,
        review_text_hash,
        vec![read_log_hash, git_log_hash, artifact_log_hash],
        [0u8; 32],
        None, // view_commitment_hash
        None, // policy_resolved_ref
        Some(metadata),
    )
    .expect("build artifact bundle");

    let artifact_bundle_bytes =
        serde_json::to_vec(&artifact_bundle).expect("serialize artifact bundle");
    let artifact_bundle_hash = harness.cas.store(&artifact_bundle_bytes);

    // =========================================================================
    // Step 10: Anchor ReviewReceiptRecorded to ledger (REQ-HEF-0011)
    // =========================================================================
    let rr_event = harness.create_review_receipt_event(
        "RR-fac-v0-e2e-001",
        bundle.changeset_digest,
        artifact_bundle_hash,
    );

    let rr_seq_id = harness
        .ledger
        .append_verified(&rr_event, &harness.signer.verifying_key())
        .expect("append review_receipt_recorded");

    // Verify ledger anchoring
    let rr_stored = harness.ledger.read_one(rr_seq_id).expect("read_one");
    let rr_decoded = ReviewReceiptRecorded::decode(rr_stored.payload.as_slice())
        .expect("decode ReviewReceiptRecorded");

    assert_eq!(rr_decoded.receipt_id, "RR-fac-v0-e2e-001");
    assert_eq!(
        rr_decoded.changeset_digest,
        bundle.changeset_digest.to_vec()
    );
    assert_eq!(
        rr_decoded.artifact_bundle_hash,
        artifact_bundle_hash.to_vec()
    );

    // =========================================================================
    // Step 11: Verify ledger chain integrity
    // =========================================================================
    let stats = harness.ledger.stats().expect("get stats");
    assert_eq!(stats.event_count, 2, "Should have 2 ledger events");
    assert_eq!(stats.max_seq_id, 2, "Max seq_id should be 2");

    // Verify all events have correct hash chain
    let events = harness.ledger.read_from(1, 10).expect("read_from");
    assert_eq!(events.len(), 2);

    // First event should have genesis prev_hash
    assert!(events[0].prev_hash.is_some());
    let genesis_hash = vec![0u8; 32];
    assert_eq!(events[0].prev_hash.as_ref().unwrap(), &genesis_hash);

    // Second event should link to first
    assert!(events[1].prev_hash.is_some());
    assert_eq!(
        events[1].prev_hash.as_ref().unwrap(),
        events[0].event_hash.as_ref().unwrap()
    );

    // =========================================================================
    // Verification Summary: All acceptance criteria met
    // =========================================================================
    // REQ-HEF-0009: ✅ ChangeSetBundleV1 in CAS, ChangeSetPublished in ledger
    // REQ-HEF-0010: ✅ Workspace apply, tool execution, CAS logging, capability
    //               enforcement
    // REQ-HEF-0011: ✅ ReviewReceiptRecorded in ledger with artifact binding
    // EVID-HEF-0012: ✅ No GitHub tokens, ledger-only truth source
}

// =============================================================================
// IT-00313-06: Blocked Path E2E Flow
// =============================================================================

/// Tests the blocked path flow with ledger anchoring.
#[tokio::test]
async fn test_fac_v0_e2e_blocked_path() {
    enforce_evid_hef_0012_env_constraints();

    let harness = FacV0TestHarness::new();

    // Create bundle that will fail validation
    let bundle = ChangeSetBundleV1::builder()
        .changeset_id("cs-blocked-test")
        .base(GitObjectRef {
            algo: HashAlgo::Sha1,
            object_kind: "commit".to_string(),
            object_id: "d".repeat(40),
        })
        .diff_hash([0x45; 32])
        .file_manifest(vec![FileChange {
            path: "binary.exe".to_string(),
            change_kind: ChangeKind::Add,
            old_path: None,
        }])
        .binary_detected(true)
        .build()
        .expect("valid bundle");

    // Store bundle in CAS
    let bundle_bytes = bundle.canonical_bytes().expect("serialize bundle");
    let bundle_cas_hash = harness.cas.store(&bundle_bytes);

    // Anchor ChangeSetPublished
    let cs_event = harness.create_changeset_published_event(
        "work-blocked-test",
        bundle.changeset_digest,
        bundle_cas_hash,
    );
    harness
        .ledger
        .append_verified(&cs_event, &harness.signer.verifying_key())
        .expect("append changeset_published");

    // Attempt to apply - should fail
    let validation_result = validate_file_changes(&bundle, harness.workspace_root());
    assert!(validation_result.is_err());

    // Store error log
    let error_log = serde_json::json!({
        "error": "BinaryUnsupported",
        "path": "binary.exe",
        "changeset_digest": hex::encode(bundle.changeset_digest),
    });
    let cas_log_hash = harness.cas.store(error_log.to_string().as_bytes());

    // Anchor ReviewBlockedRecorded
    let blocked_event = harness.create_review_blocked_event(
        "BLK-e2e-001",
        bundle.changeset_digest,
        ReasonCode::BinaryUnsupported,
        cas_log_hash,
    );

    let blk_seq_id = harness
        .ledger
        .append_verified(&blocked_event, &harness.signer.verifying_key())
        .expect("append review_blocked_recorded");

    // Verify chain
    let stats = harness.ledger.stats().expect("get stats");
    assert_eq!(stats.event_count, 2);

    let blk_stored = harness.ledger.read_one(blk_seq_id).expect("read_one");
    let blk_decoded = ReviewBlockedRecorded::decode(blk_stored.payload.as_slice())
        .expect("decode ReviewBlockedRecorded");

    assert_eq!(
        blk_decoded.reason_code,
        i32::from(ReasonCode::BinaryUnsupported.to_code())
    );
    assert_eq!(blk_decoded.blocked_log_hash, cas_log_hash.to_vec());
}

// =============================================================================
// IT-00313-07: Workspace Apply Tests
// =============================================================================

/// Tests workspace apply produces correct result structure.
#[test]
fn test_workspace_apply_produces_correct_result() {
    let temp_dir = TempDir::new().expect("create temp dir");
    let workspace_manager = WorkspaceManager::new(temp_dir.path().to_path_buf());

    let bundle = create_test_changeset_bundle(vec![
        ("src/main.rs", ChangeKind::Add),
        ("Cargo.toml", ChangeKind::Modify),
        ("README.md", ChangeKind::Delete),
    ]);

    // BLOCKER 2 FIX: timestamp_ns is now required (u64, not Option<u64>)
    let timestamp_ns = 1_234_567_890_123_456_789_u64;
    let result = workspace_manager
        .apply_with_timestamp(&bundle, timestamp_ns)
        .expect("apply should succeed");

    assert_eq!(result.changeset_digest, bundle.changeset_digest);
    assert_eq!(result.files_modified, 3);
    assert_eq!(result.applied_at_ns, timestamp_ns);
}

// =============================================================================
// IT-00313-08: Capability Validator Tests
// =============================================================================

/// Tests capability validator enforces the tool profile.
#[test]
fn test_capability_validator_enforces_tool_profile() {
    let manifest = create_reviewer_capability_manifest();
    let validator = CapabilityValidator::new(manifest).expect("valid validator");

    // Read should be allowed
    let read_request = ToolRequest::new(ToolClass::Read, RiskTier::default())
        .with_path(PathBuf::from("/workspace/src/lib.rs"));
    assert!(
        validator.validate(&read_request).is_allowed(),
        "Read should be allowed"
    );

    // Git should be allowed
    let git_request = ToolRequest::new(ToolClass::Git, RiskTier::default());
    assert!(
        validator.validate(&git_request).is_allowed(),
        "Git should be allowed"
    );

    // Artifact should be allowed
    let artifact_request = ToolRequest::new(ToolClass::Artifact, RiskTier::default());
    assert!(
        validator.validate(&artifact_request).is_allowed(),
        "Artifact should be allowed"
    );

    // Write should be denied
    let write_request = ToolRequest::new(ToolClass::Write, RiskTier::default())
        .with_path(PathBuf::from("/workspace/src/lib.rs"));
    assert!(
        !validator.validate(&write_request).is_allowed(),
        "Write should be denied"
    );

    // Execute should be denied
    let execute_request = ToolRequest::new(ToolClass::Execute, RiskTier::default());
    assert!(
        !validator.validate(&execute_request).is_allowed(),
        "Execute should be denied"
    );

    // Network should be denied
    let network_request =
        ToolRequest::new(ToolClass::Network, RiskTier::default()).with_network("example.com", 443);
    assert!(
        !validator.validate(&network_request).is_allowed(),
        "Network should be denied"
    );
}

// =============================================================================
// IT-00313-09: CAS Storage Tests
// =============================================================================

/// Tests that tool outputs are correctly stored in CAS.
#[tokio::test]
async fn test_tool_output_stored_in_cas() {
    let harness = FacV0TestHarness::new();

    // Create test file
    let test_file = harness.workspace_root().join("test_cas.txt");
    std::fs::write(&test_file, b"Content for CAS storage test").expect("write test file");

    // Execute tool
    let ctx = harness.execution_context("req-cas-test");
    let args = ToolArgs::Read(ReadArgs {
        path: PathBuf::from("test_cas.txt"),
        offset: None,
        limit: None,
    });

    let result = harness
        .tool_executor
        .execute(&ctx, &args, None)
        .await
        .expect("execute");

    assert!(result.success);

    // Store result in CAS
    let result_json = serde_json::to_vec(&result.output).expect("serialize");
    let hash = harness.cas.store(&result_json);

    // Verify retrieval
    let retrieved = harness.cas.retrieve(&hash).expect("retrieve");
    assert_eq!(retrieved, result_json);
}

// =============================================================================
// IT-00313-10: Tool Executor Tests
// =============================================================================

/// Tests that tool executor respects budget constraints.
#[tokio::test]
async fn test_tool_executor_respects_budget() {
    let temp_dir = TempDir::new().expect("create temp dir");
    let workspace_root = temp_dir.path().to_path_buf();

    let cas: Arc<dyn ContentAddressedStore> =
        Arc::new(apm2_daemon::episode::StubContentAddressedStore::new());

    // Create very limited budget (1 tool call)
    let budget = EpisodeBudget::builder().tool_calls(1).build();
    let budget_tracker = Arc::new(BudgetTracker::from_envelope(budget));

    let mut executor = ToolExecutor::new(budget_tracker.clone(), cas);
    executor
        .register_handler(Box::new(ReadFileHandler::with_root(&workspace_root)))
        .expect("register handler");

    std::fs::write(workspace_root.join("budget_test.txt"), b"test").expect("write file");

    let ctx = ExecutionContext::new(
        apm2_daemon::episode::EpisodeId::new("ep-budget-test").expect("valid id"),
        "req-budget-1",
        0,
    );
    let args = ToolArgs::Read(ReadArgs {
        path: PathBuf::from("budget_test.txt"),
        offset: None,
        limit: None,
    });

    // First call should succeed
    let result1 = executor.execute(&ctx, &args, None).await;
    assert!(result1.is_ok(), "first call should succeed");

    // Second call should fail due to budget
    let result2 = executor.execute(&ctx, &args, None).await;
    assert!(
        result2.is_err(),
        "second call should fail due to budget exhaustion"
    );
}

/// Tests that tool executor validates arguments (path traversal).
#[tokio::test]
async fn test_tool_executor_validates_arguments() {
    let temp_dir = TempDir::new().expect("create temp dir");
    let workspace_root = temp_dir.path().to_path_buf();

    let cas: Arc<dyn ContentAddressedStore> =
        Arc::new(apm2_daemon::episode::StubContentAddressedStore::new());

    let budget = EpisodeBudget::builder().tool_calls(100).build();
    let budget_tracker = Arc::new(BudgetTracker::from_envelope(budget));

    let mut executor = ToolExecutor::new(budget_tracker, cas);
    executor
        .register_handler(Box::new(ReadFileHandler::with_root(&workspace_root)))
        .expect("register handler");

    let ctx = ExecutionContext::new(
        apm2_daemon::episode::EpisodeId::new("ep-validate-test").expect("valid id"),
        "req-validate",
        0,
    );

    // Path traversal should be rejected
    let args = ToolArgs::Read(ReadArgs {
        path: PathBuf::from("../etc/passwd"),
        offset: None,
        limit: None,
    });

    let result = executor.execute(&ctx, &args, None).await;
    assert!(
        result.is_err(),
        "path traversal should be rejected: {result:?}"
    );
}

// =============================================================================
// IT-00313-11: Snapshot Tests
// =============================================================================

/// Tests workspace snapshot captures state correctly.
#[test]
fn test_workspace_snapshot_captures_state() {
    let temp_dir = TempDir::new().expect("create temp dir");
    let workspace_manager = WorkspaceManager::new(temp_dir.path().to_path_buf());
    let timestamp_ns = 1_234_567_890_123_456_789_u64;

    let snapshot1 = workspace_manager
        .snapshot("work-001", timestamp_ns)
        .expect("first snapshot");
    let snapshot2 = workspace_manager
        .snapshot("work-002", timestamp_ns)
        .expect("second snapshot");

    // Different work IDs should produce different hashes
    assert_ne!(
        snapshot1.snapshot_hash, snapshot2.snapshot_hash,
        "different work IDs should have different hashes"
    );

    // Same work ID should produce same hash (deterministic)
    let snapshot1_again = workspace_manager
        .snapshot("work-001", timestamp_ns)
        .expect("snapshot again");
    assert_eq!(
        snapshot1.snapshot_hash, snapshot1_again.snapshot_hash,
        "same work ID should have same hash"
    );
}

// =============================================================================
// IT-00313-12: Git/Artifact Tool Class Enforcement (REQ-HEF-0010)
// =============================================================================

/// Tests that Git and Artifact tool classes are properly enforced.
///
/// This test verifies that a read-only manifest rejects Git and Artifact
/// tool classes when they are not explicitly granted.
#[test]
fn test_git_artifact_tool_class_enforcement() {
    // Create a reviewer manifest that only allows Read
    let manifest = create_read_only_capability_manifest();
    let validator = CapabilityValidator::new(manifest).expect("valid validator");

    // Git tool class should be denied (not in reviewer profile)
    let git_request = ToolRequest::new(ToolClass::Git, RiskTier::default());
    assert!(
        !validator.validate(&git_request).is_allowed(),
        "Git should be denied for reviewer profile"
    );

    // Artifact tool class should be denied (not in reviewer profile)
    let artifact_request = ToolRequest::new(ToolClass::Artifact, RiskTier::default());
    assert!(
        !validator.validate(&artifact_request).is_allowed(),
        "Artifact should be denied for reviewer profile"
    );

    // Inference tool class should be denied
    let inference_request = ToolRequest::new(ToolClass::Inference, RiskTier::default());
    assert!(
        !validator.validate(&inference_request).is_allowed(),
        "Inference should be denied for reviewer profile"
    );

    // Verify allowed classes still work
    let read_request = ToolRequest::new(ToolClass::Read, RiskTier::default())
        .with_path(PathBuf::from("/workspace/src/lib.rs"));
    assert!(
        validator.validate(&read_request).is_allowed(),
        "Read should still be allowed"
    );
}

/// Tests that an expanded capability manifest can grant Git operations.
///
/// This demonstrates that the capability system supports different tool
/// profiles for different reviewer types.
#[test]
fn test_git_capability_can_be_granted() {
    // Create a manifest that includes Git capability
    let manifest = CapabilityManifestBuilder::new("git-reviewer-manifest")
        .delegator("fac-orchestrator")
        .capability(
            Capability::builder("cap-read", ToolClass::Read)
                .scope(CapabilityScope::allow_all())
                .build()
                .expect("valid read capability"),
        )
        .capability(
            Capability::builder("cap-git", ToolClass::Git)
                .scope(CapabilityScope::allow_all())
                .build()
                .expect("valid git capability"),
        )
        .tool_allowlist(vec![ToolClass::Read, ToolClass::Git])
        .build()
        .expect("valid manifest");

    let validator = CapabilityValidator::new(manifest).expect("valid validator");

    // Git should now be allowed when granted via capability
    let git_request = ToolRequest::new(ToolClass::Git, RiskTier::default())
        .with_path(PathBuf::from("/workspace/src/lib.rs"));
    assert!(
        validator.validate(&git_request).is_allowed(),
        "Git should be allowed when capability is granted"
    );
}

// =============================================================================
// IT-00313-13: GateReceipt → Projection Flow (EVID-HEF-0012)
// =============================================================================

/// Tests that a successful review can be projected via the mock adapter.
///
/// Per EVID-HEF-0012, after ledger anchoring the `ReviewReceiptRecorded`,
/// the status should be projected to the local sink (mock adapter in tests).
/// This demonstrates the complete flow from ledger event to projection receipt.
#[tokio::test]
async fn test_gate_receipt_projection_flow() {
    enforce_evid_hef_0012_env_constraints();

    let harness = FacV0TestHarness::new();

    // Step 1: Create the changeset bundle
    let bundle = ChangeSetBundleV1::builder()
        .changeset_id("cs-projection-test")
        .base(GitObjectRef {
            algo: HashAlgo::Sha1,
            object_kind: "commit".to_string(),
            object_id: "e".repeat(40),
        })
        .diff_hash([0x99; 32])
        .file_manifest(vec![FileChange {
            path: "src/projection.rs".to_string(),
            change_kind: ChangeKind::Add,
            old_path: None,
        }])
        .binary_detected(false)
        .build()
        .expect("valid bundle");

    // Store bundle in CAS
    let bundle_bytes = bundle.canonical_bytes().expect("serialize bundle");
    let bundle_cas_hash = harness.cas.store(&bundle_bytes);

    // Step 2: Anchor ChangeSetPublished
    let cs_event = harness.create_changeset_published_event(
        "work-projection-test",
        bundle.changeset_digest,
        bundle_cas_hash,
    );
    harness
        .ledger
        .append_verified(&cs_event, &harness.signer.verifying_key())
        .expect("append changeset_published");

    // Step 3: Simulate successful review (store artifact)
    let review_result = serde_json::json!({
        "verdict": "approved",
        "review_text": "Projection test review",
        "changeset_digest": hex::encode(bundle.changeset_digest),
    });
    let artifact_hash = harness.cas.store(review_result.to_string().as_bytes());

    // Step 4: Anchor ReviewReceiptRecorded
    let rr_event = harness.create_review_receipt_event(
        "RR-projection-001",
        bundle.changeset_digest,
        artifact_hash,
    );
    let rr_seq_id = harness
        .ledger
        .append_verified(&rr_event, &harness.signer.verifying_key())
        .expect("append review_receipt_recorded");

    // Verify ledger anchoring
    let rr_stored = harness.ledger.read_one(rr_seq_id).expect("read_one");
    assert_eq!(rr_stored.event_type, "review_receipt_recorded");

    // Step 5: Create projection adapter (mock mode)
    let projection_signer = Signer::generate();
    let projection_config =
        GitHubAdapterConfig::new("https://api.github.com", "test-owner", "test-repo")
            .expect("valid config")
            .with_context("apm2/fac-test")
            .expect("valid context");

    let adapter = GitHubProjectionAdapter::new_mock(projection_signer, projection_config)
        .expect("create adapter");

    // Step 6: Project the status
    let ledger_head_vec = harness.ledger.last_event_hash().expect("get ledger head");
    let ledger_head: [u8; 32] = ledger_head_vec
        .try_into()
        .expect("ledger head should be 32 bytes");

    let receipt = adapter
        .project_status(
            "work-projection-test",
            bundle.changeset_digest,
            ledger_head,
            ProjectedStatus::Success,
        )
        .await
        .expect("project status");

    // Step 7: Verify projection receipt
    assert!(
        receipt.validate_signature(&adapter.verifying_key()).is_ok(),
        "Projection receipt should have valid signature"
    );
    assert_eq!(receipt.work_id, "work-projection-test");
    assert_eq!(receipt.changeset_digest, bundle.changeset_digest);
    assert_eq!(receipt.projected_status, ProjectedStatus::Success);

    // Verify idempotency key
    let idempotency_key = receipt.idempotency_key();
    assert_eq!(idempotency_key.work_id, "work-projection-test");
    assert_eq!(idempotency_key.changeset_digest, bundle.changeset_digest);
}

/// Tests projection flow for blocked reviews.
///
/// When a review is blocked, the projection status should be `Failure`.
#[tokio::test]
async fn test_blocked_review_projection_flow() {
    enforce_evid_hef_0012_env_constraints();

    let harness = FacV0TestHarness::new();

    // Create blocked bundle
    let bundle = ChangeSetBundleV1::builder()
        .changeset_id("cs-blocked-projection")
        .base(GitObjectRef {
            algo: HashAlgo::Sha1,
            object_kind: "commit".to_string(),
            object_id: "f".repeat(40),
        })
        .diff_hash([0xAA; 32])
        .file_manifest(vec![FileChange {
            path: "exploit.exe".to_string(),
            change_kind: ChangeKind::Add,
            old_path: None,
        }])
        .binary_detected(true)
        .build()
        .expect("valid bundle");

    // Store and anchor
    let bundle_bytes = bundle.canonical_bytes().expect("serialize bundle");
    let bundle_cas_hash = harness.cas.store(&bundle_bytes);

    let cs_event = harness.create_changeset_published_event(
        "work-blocked-projection",
        bundle.changeset_digest,
        bundle_cas_hash,
    );
    harness
        .ledger
        .append_verified(&cs_event, &harness.signer.verifying_key())
        .expect("append changeset_published");

    // Anchor blocked event
    let error_log = b"Binary file not supported";
    let log_hash = harness.cas.store(error_log);

    let blocked_event = harness.create_review_blocked_event(
        "BLK-projection-001",
        bundle.changeset_digest,
        ReasonCode::BinaryUnsupported,
        log_hash,
    );
    harness
        .ledger
        .append_verified(&blocked_event, &harness.signer.verifying_key())
        .expect("append review_blocked_recorded");

    // Project failure status
    let projection_signer = Signer::generate();
    let projection_config =
        GitHubAdapterConfig::new("https://api.github.com", "test-owner", "test-repo")
            .expect("valid config");

    let adapter = GitHubProjectionAdapter::new_mock(projection_signer, projection_config)
        .expect("create adapter");

    let ledger_head_vec = harness.ledger.last_event_hash().expect("get ledger head");
    let ledger_head: [u8; 32] = ledger_head_vec
        .try_into()
        .expect("ledger head should be 32 bytes");

    let receipt = adapter
        .project_status(
            "work-blocked-projection",
            bundle.changeset_digest,
            ledger_head,
            ProjectedStatus::Failure,
        )
        .await
        .expect("project status");

    // Verify
    assert!(receipt.validate_signature(&adapter.verifying_key()).is_ok());
    assert_eq!(receipt.projected_status, ProjectedStatus::Failure);
}
