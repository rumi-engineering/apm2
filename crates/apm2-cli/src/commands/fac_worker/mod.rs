// AGENT-AUTHORED (TCK-00511)
//! FAC Worker: queue consumer with RFC-0028 authorization + RFC-0029 admission
//! gating.
//!
//! Implements the `apm2 fac worker` runtime entrypoint. The worker is
//! wake-driven on queue filesystem signals (`pending` + `claimed`) and uses a
//! bounded degraded safety nudge interval when watcher delivery is unavailable.
//!
//! Claimed-queue runtime reconcile is claimed-only and lane-safe; startup and
//! doctor remain the broad remediation paths.
//!
//! # Processing Pipeline
//!
//! ```text
//! scan ~/.apm2/queue/pending/*.json
//!   -> sort by (priority ASC, enqueue_time ASC, job_id ASC)
//!   -> for each:
//!     1. Bounded deserialize (64KB) -> on fail: quarantine + receipt
//!     2. Validate job_spec_digest   -> on fail: quarantine + receipt
//!     3. Validate RFC-0028 token    -> on fail: deny + receipt
//!     4. Evaluate RFC-0029 admission -> on fail: deny + receipt
//!     5. Atomic claim: rename pending/X.json -> claimed/X.json
//!     6. Acquire lane lease via LaneManager::try_lock
//!     7. Execute job under containment
//!     8. Emit completion receipt, move to completed/
//! ```
//!
//! # Security Model
//!
//! - All queue reads bounded to 64KB (RSK-1601).
//! - Token decode failures -> DENY + receipt.
//! - Admission failures -> DENY + receipt.
//! - Digest mismatch -> QUARANTINE.
//! - Malformed/oversize files -> QUARANTINE + receipt (never silently dropped).
//! - No secrets in receipts/logs.
//! - Atomic rename prevents double-execution.
//! - Collision-safe target names prevent clobbering (timestamp-nanos suffix).
//!
//! # Broker Key Sharing (Default Mode)
//!
//! In default mode, the worker and broker share a single process. The same
//! `FacBroker` instance that issues tokens also provides the verifying key
//! used to decode them. This is a documented limitation of default-mode
//! operation: distributed workers would need to load the broker's persisted
//! state or receive the verifying key via a secure channel. The broker
//! issues a time authority envelope and populates freshness/revocation/
//! convergence state so that the RFC-0029 admission path can reach `Allow`.
//!
//! # Invariants
//!
//! - [INV-WRK-001] All file reads are bounded to `MAX_JOB_SPEC_SIZE`.
//! - [INV-WRK-002] Fail-closed: any validation failure results in
//!   deny/quarantine.
//! - [INV-WRK-003] Atomic claim via rename prevents double-execution.
//! - [INV-WRK-004] No secrets appear in receipts or log output.
//! - [INV-WRK-005] Deterministic ordering: priority ASC, `enqueue_time` ASC,
//!   `job_id` ASC.
//! - [INV-WRK-006] In-memory collections are bounded by
//!   `MAX_PENDING_SCAN_ENTRIES`.
//! - [INV-WRK-007] Malformed/unreadable/oversize files are quarantined with
//!   receipts, never silently dropped.
//! - [INV-WRK-008] Lane lease is acquired before job execution; jobs that
//!   cannot acquire a lane are moved back to pending.

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::time::{Duration, Instant};

use apm2_core::channel::{
    ChannelBoundaryDefect, ExpectedTokenBinding, decode_channel_context_token_with_binding,
    validate_channel_boundary,
};
use apm2_core::crypto::Signer;
use apm2_core::economics::admission::{
    BudgetAdmissionEvaluator, BudgetAdmissionTrace as EconomicsBudgetAdmissionTrace,
    BudgetAdmissionVerdict, ObservedUsage,
};
use apm2_core::economics::profile::EconomicsProfile;
use apm2_core::economics::queue_admission::{
    HtfEvaluationWindow, QueueAdmissionDecision, QueueAdmissionRequest, QueueAdmissionVerdict,
    QueueLane, QueueSchedulerState, evaluate_queue_admission,
};
use apm2_core::evidence::MemoryCas;
use apm2_core::fac::broker::{BrokerError, BrokerSignatureVerifier, FacBroker};
use apm2_core::fac::broker_health::WorkerHealthPolicy;
use apm2_core::fac::job_spec::{
    FacJobSpecV1, JobSpecError, MAX_JOB_SPEC_SIZE, deserialize_job_spec, job_kind_to_budget_key,
    parse_b3_256_digest, validate_job_spec_control_lane_with_policy, validate_job_spec_with_policy,
};
use apm2_core::fac::lane::{
    LaneLeaseV1, LaneLockGuard, LaneManager, LaneState, ProcessIdentity, current_time_iso8601,
    verify_pid_identity,
};
use apm2_core::fac::queue_bounds::{QueueBoundsPolicy, check_queue_bounds};
use apm2_core::fac::scan_lock::{ScanLockResult, check_stuck_scan_lock, try_acquire_scan_lock};
use apm2_core::fac::scheduler_state::{load_scheduler_state, persist_scheduler_state};
use apm2_core::fac::{
    BlobStore, BudgetAdmissionTrace as FacBudgetAdmissionTrace, CanonicalizerTupleV1,
    ChannelBoundaryTrace, DenialReasonCode, EXECUTION_BACKEND_ENV_VAR, ExecutionBackend,
    ExecutionBackendError, FAC_LANE_CLEANUP_RECEIPT_SCHEMA, FacJobOutcome, FacJobReceiptV1,
    FacJobReceiptV1Builder, FacPolicyV1, FacUnitLiveness, GateReceipt, GateReceiptBuilder,
    LANE_CORRUPT_MARKER_SCHEMA, LaneCleanupOutcome, LaneCleanupReceiptV1, LaneCorruptMarkerV1,
    LaneProfileV1, LogRetentionConfig, MAX_POLICY_SIZE, ORPHANED_SYSTEMD_UNIT_REASON_CODE,
    OrphanedJobPolicy, PATCH_FORMAT_GIT_DIFF_V1, QueueAdmissionTrace as JobQueueAdmissionTrace,
    QueueReconcileLimits, ReceiptPipelineError, ReceiptWritePipeline, RepoMirrorManager,
    RuntimeQueueReconcileConfig, RuntimeQueueReconcileStatus, SystemModeConfig,
    SystemdUnitProperties, TOOLCHAIN_MAX_CACHE_FILE_BYTES, apply_credential_mount_to_env,
    build_github_credential_mount, build_job_environment, check_fac_unit_liveness,
    compute_policy_hash, deserialize_policy, fingerprint_short_hex, load_or_default_boundary_id,
    move_job_to_terminal, outcome_to_terminal_state, parse_policy_hash,
    persist_content_addressed_receipt, persist_policy, probe_user_bus, reconcile_claimed_runtime,
    rename_noreplace, resolve_toolchain_fingerprint_cached, run_preflight,
    select_and_validate_backend, serialize_cache, toolchain_cache_dir, toolchain_cache_file_path,
};
use apm2_core::github::{parse_github_remote_url, resolve_apm2_home};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chrono::{SecondsFormat, Utc};
use fs2::FileExt;
#[cfg(target_os = "linux")]
use nix::sys::inotify::{AddWatchFlags, InitFlags, Inotify};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use super::fac_gates_job::{GATES_JOB_OPTIONS_SCHEMA, GatesJobOptionsV1};
use super::{fac_key_material, fac_queue_lifecycle_dual_write, fac_secure_io};
#[cfg(not(test))]
use crate::commands::fac_review as fac_review_api;
#[cfg(test)]
mod fac_review_api {
    use std::cell::RefCell;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum GateThroughputProfile {
        Throughput,
        Balanced,
        Conservative,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct LocalGatesRunResult {
        pub exit_code: u8,
        pub failure_summary: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct RunGatesLocalWorkerInvocation {
        pub lease_job_id: Option<String>,
        pub lease_toolchain_fingerprint: Option<String>,
    }

    thread_local! {
        static RUN_GATES_LOCAL_WORKER_OVERRIDE: RefCell<Option<Result<LocalGatesRunResult, String>>> =
            const { RefCell::new(None) };
        static GATE_LIFECYCLE_OVERRIDE: RefCell<Option<Result<usize, String>>> =
            const { RefCell::new(None) };
        static LAST_RUN_GATES_LOCAL_WORKER_INVOCATION: RefCell<Option<RunGatesLocalWorkerInvocation>> =
            const { RefCell::new(None) };
    }

    pub fn set_run_gates_local_worker_override(
        result: Option<Result<LocalGatesRunResult, String>>,
    ) {
        RUN_GATES_LOCAL_WORKER_OVERRIDE.with(|slot| {
            *slot.borrow_mut() = result;
        });
    }

    pub fn set_gate_lifecycle_override(result: Option<Result<usize, String>>) {
        GATE_LIFECYCLE_OVERRIDE.with(|slot| {
            *slot.borrow_mut() = result;
        });
    }

    pub fn take_last_run_gates_local_worker_invocation() -> Option<RunGatesLocalWorkerInvocation> {
        LAST_RUN_GATES_LOCAL_WORKER_INVOCATION.with(|slot| slot.borrow_mut().take())
    }

    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::unnecessary_wraps)]
    pub fn run_gates_local_worker(
        _force: bool,
        _quick: bool,
        _timeout_seconds: u64,
        _memory_max: &str,
        _pids_max: u64,
        _cpu_quota: &str,
        _gate_profile: GateThroughputProfile,
        _workspace_root: &std::path::Path,
        _bounded_unit_base: Option<&str>,
        lease_job_id: Option<&str>,
        lease_toolchain_fingerprint: Option<&str>,
    ) -> Result<LocalGatesRunResult, String> {
        LAST_RUN_GATES_LOCAL_WORKER_INVOCATION.with(|slot| {
            *slot.borrow_mut() = Some(RunGatesLocalWorkerInvocation {
                lease_job_id: lease_job_id.map(std::string::ToString::to_string),
                lease_toolchain_fingerprint: lease_toolchain_fingerprint
                    .map(std::string::ToString::to_string),
            });
        });
        if let Some(override_result) =
            RUN_GATES_LOCAL_WORKER_OVERRIDE.with(|slot| slot.borrow().clone())
        {
            return override_result;
        }
        Ok(LocalGatesRunResult {
            exit_code: crate::exit_codes::codes::GENERIC_ERROR,
            failure_summary: None,
        })
    }

    /// Test stub: no-op rebinding (v2).
    pub fn rebind_gate_cache_after_receipt(
        _sha: &str,
        _receipts_dir: &std::path::Path,
        _job_id: &str,
        _signer: &apm2_core::crypto::Signer,
    ) {
    }

    /// Test stub: no-op rebinding (v3).
    pub fn rebind_v3_gate_cache_after_receipt(
        _sha: &str,
        _policy_hash: &str,
        _sbx_hash: &str,
        _net_hash: &str,
        _receipts_dir: &std::path::Path,
        _job_id: &str,
        _signer: &apm2_core::crypto::Signer,
    ) {
    }

    #[allow(clippy::unnecessary_wraps)]
    pub fn apply_gate_result_lifecycle_for_repo_sha(
        owner_repo: &str,
        head_sha: &str,
        _passed: bool,
    ) -> Result<usize, String> {
        if let Some(override_result) = GATE_LIFECYCLE_OVERRIDE.with(|slot| slot.borrow().clone()) {
            return override_result;
        }
        // Test shim: enforce non-empty routing inputs and return a non-zero
        // applied count so worker unit tests do not silently mask no-op behavior.
        if owner_repo.trim().is_empty() {
            return Err("owner_repo is empty".to_string());
        }
        if head_sha.trim().is_empty() {
            return Err("head_sha is empty".to_string());
        }
        Ok(1)
    }
}

#[cfg(test)]
mod fac_permissions {
    use std::path::Path;
    use std::{fs, io};

    pub fn ensure_dir_with_mode(path: &Path) -> Result<(), io::Error> {
        fs::create_dir_all(path)
    }

    /// Test-mode stub for atomic file write with restricted permissions.
    /// In test mode, simply writes directly without permission enforcement.
    pub fn write_fac_file_with_mode(path: &Path, data: &[u8]) -> Result<(), io::Error> {
        fs::write(path, data)
    }

    /// Test-mode stub: always passes.  Integration tests for real
    /// owner+mode enforcement live in `fac_permissions::tests`.
    pub fn validate_directory(path: &Path, _expected_uid: u32) -> Result<(), io::Error> {
        if !path.exists() {
            fs::create_dir_all(path)?;
        }
        Ok(())
    }
}
#[cfg(not(test))]
use crate::commands::fac_permissions;
use crate::exit_codes::codes as exit_codes;

mod commit_ops;
mod error;
mod execution_ops;
mod lane_ops;
mod orchestrator;
mod queue_ops;
mod types;
mod worker_loop;

#[allow(clippy::wildcard_imports)]
use commit_ops::*;
#[allow(clippy::wildcard_imports)]
use error::*;
#[allow(clippy::wildcard_imports)]
use execution_ops::*;
#[allow(clippy::wildcard_imports)]
use lane_ops::*;
#[allow(clippy::wildcard_imports)]
use orchestrator::*;
#[allow(clippy::wildcard_imports)]
use queue_ops::*;
#[allow(clippy::wildcard_imports)]
use types::*;
// Re-export worker_loop items needed by the tests module.
#[cfg(test)]
#[allow(clippy::wildcard_imports)]
use worker_loop::*;

#[cfg(test)]
pub fn env_var_test_lock() -> &'static crate::commands::EnvVarTestLock {
    crate::commands::env_var_test_lock()
}

pub fn run_fac_worker(once: bool, max_jobs: u64, json_output: bool, print_unit: bool) -> u8 {
    worker_loop::run_fac_worker_impl(once, max_jobs, json_output, print_unit)
}

#[allow(dead_code)] // Public API consumed by fac_queue_submit and fac_warm; unused in test harness.
pub fn load_token_ledger_pub(
    current_tick: u64,
) -> Result<Option<apm2_core::fac::token_ledger::TokenUseLedger>, String> {
    commit_ops::load_token_ledger_pub_impl(current_tick)
}

#[allow(dead_code)] // Public API consumed by fac_warm and fac_review; unused in test harness.
pub fn append_token_ledger_wal_pub(wal_bytes: &[u8]) -> Result<(), String> {
    commit_ops::append_token_ledger_wal_pub_impl(wal_bytes)
}

#[cfg(test)]
mod tests;
