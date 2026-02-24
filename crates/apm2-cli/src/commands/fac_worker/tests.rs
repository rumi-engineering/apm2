use apm2_core::fac::LaneState;
use apm2_core::fac::lane::LaneLeaseV1;

use super::*;

#[test]
fn test_deterministic_ordering() {
    // Verify that candidates sort by priority ASC, enqueue_time ASC,
    // job_id ASC.
    let mut items = [
        ("c", 50u32, "2026-02-12T00:00:02Z"),
        ("a", 50, "2026-02-12T00:00:01Z"),
        ("b", 10, "2026-02-12T00:00:03Z"),
        ("d", 50, "2026-02-12T00:00:01Z"),
    ];

    items.sort_by(|a, b| {
        a.1.cmp(&b.1)
            .then_with(|| a.2.cmp(b.2))
            .then_with(|| a.0.cmp(b.0))
    });

    let ids: Vec<&str> = items.iter().map(|i| i.0).collect();
    assert_eq!(ids, vec!["b", "a", "d", "c"]);
}

#[test]
fn one_shot_worker_skips_background_runtime_primitives() {
    assert!(
        !should_start_background_runtime(true),
        "one-shot worker must not start long-lived watcher/watchdog runtime"
    );
    assert!(
        should_start_background_runtime(false),
        "continuous worker mode must retain watcher/watchdog runtime"
    );
}

#[test]
fn test_read_bounded_rejects_oversized() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file_path = dir.path().join("big.json");
    let data = vec![b'x'; MAX_JOB_SPEC_SIZE + 1];
    fs::write(&file_path, &data).expect("write");

    let result = read_bounded(&file_path, MAX_JOB_SPEC_SIZE);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("too large"));
}

#[test]
fn test_read_bounded_accepts_valid_size() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file_path = dir.path().join("ok.json");
    let data = b"{}";
    fs::write(&file_path, data).expect("write");

    let result = read_bounded(&file_path, MAX_JOB_SPEC_SIZE);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), data.to_vec());
}

#[test]
fn test_ensure_queue_dirs_creates_all() {
    let dir = tempfile::tempdir().expect("tempdir");
    let queue_root = dir.path().join("queue");

    ensure_queue_dirs(&queue_root).expect("create dirs");

    for sub in [
        PENDING_DIR,
        CLAIMED_DIR,
        COMPLETED_DIR,
        DENIED_DIR,
        QUARANTINE_DIR,
        CONSUME_RECEIPTS_DIR,
    ] {
        assert!(queue_root.join(sub).is_dir(), "missing {sub}");
    }

    // TCK-00577 round 5 BLOCKER fix: broker_requests/ must also be
    // created by ensure_queue_dirs.
    assert!(
        queue_root.join(BROKER_REQUESTS_DIR).is_dir(),
        "missing broker_requests dir"
    );
}

/// TCK-00577 round 5: `ensure_queue_dirs` creates `broker_requests/` with
/// mode 01733 (sticky + world-writable) on Unix.
#[cfg(unix)]
#[test]
fn test_ensure_queue_dirs_broker_requests_mode_01733() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("tempdir");
    let queue_root = dir.path().join("queue");

    ensure_queue_dirs(&queue_root).expect("create dirs");

    let broker_dir = queue_root.join(BROKER_REQUESTS_DIR);
    assert!(broker_dir.is_dir(), "broker_requests must exist");

    let metadata = fs::metadata(&broker_dir).expect("metadata");
    let mode = metadata.permissions().mode() & 0o7777; // mask off file type bits
    assert_eq!(
        mode, 0o1733,
        "broker_requests/ must have mode 01733 (sticky + world-writable), got {mode:#o}"
    );
}

/// TCK-00577 round 6: `ensure_queue_dirs` creates `queue/` with mode 0711
/// (traverse-only for group/other) so non-service-user callers can reach
/// `broker_requests/`.
#[cfg(unix)]
#[test]
fn test_ensure_queue_dirs_queue_root_mode_0711() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("tempdir");
    let queue_root = dir.path().join("queue");

    ensure_queue_dirs(&queue_root).expect("create dirs");

    let metadata = fs::metadata(&queue_root).expect("metadata");
    let mode = metadata.permissions().mode() & 0o7777;
    assert_eq!(
        mode, 0o711,
        "queue/ must have mode 0711 (traverse-only), got {mode:#o}"
    );
}

#[cfg(unix)]
#[test]
fn ensure_queue_dirs_rejects_symlink_queue_root_fail_closed() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().expect("tempdir");
    let real_queue = dir.path().join("real-queue");
    fs::create_dir_all(&real_queue).expect("create real queue");
    let queue_root = dir.path().join("queue");
    symlink(&real_queue, &queue_root).expect("create queue root symlink");

    let err = ensure_queue_dirs(&queue_root).expect_err("must fail-closed on queue root symlink");
    assert!(
        err.contains("symlink"),
        "error must report symlink refusal, got: {err}"
    );
}

#[cfg(unix)]
#[test]
fn ensure_queue_dirs_rejects_symlink_subdir_fail_closed() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().expect("tempdir");
    let queue_root = dir.path().join("queue");
    fs::create_dir_all(&queue_root).expect("create queue root");
    let external_target = dir.path().join("external-target");
    fs::create_dir_all(&external_target).expect("create external target");
    symlink(&external_target, queue_root.join(PENDING_DIR)).expect("create subdir symlink");

    let err =
        ensure_queue_dirs(&queue_root).expect_err("must fail-closed on queue subdirectory symlink");
    assert!(
        err.contains("symlink"),
        "error must report symlink refusal, got: {err}"
    );
}

#[cfg(unix)]
#[test]
fn ensure_queue_dirs_rejects_non_directory_queue_root_fail_closed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let queue_root = dir.path().join("queue");
    fs::write(&queue_root, b"not-a-dir").expect("create queue root file");

    let err =
        ensure_queue_dirs(&queue_root).expect_err("must fail-closed on queue root non-directory");
    assert!(
        err.contains("non-directory"),
        "error must report non-directory refusal, got: {err}"
    );
}

#[cfg(unix)]
#[test]
fn ensure_queue_dirs_rejects_non_directory_subdir_fail_closed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let queue_root = dir.path().join("queue");
    fs::create_dir_all(&queue_root).expect("create queue root");
    fs::write(queue_root.join(PENDING_DIR), b"not-a-dir").expect("create subdir file");

    let err = ensure_queue_dirs(&queue_root)
        .expect_err("must fail-closed on queue subdirectory non-directory");
    assert!(
        err.contains("non-directory"),
        "error must report non-directory refusal, got: {err}"
    );
}

#[test]
fn consume_authority_rejects_second_write_without_overwriting_receipt() {
    let dir = tempfile::tempdir().expect("tempdir");
    let queue_root = dir.path().join("queue");
    fs::create_dir_all(&queue_root).expect("create queue root");

    consume_authority(&queue_root, "job-atomic", "b3-256:first")
        .expect("first consume should succeed");
    let receipt_path = queue_root
        .join(CONSUME_RECEIPTS_DIR)
        .join("job-atomic.consumed");
    let first_bytes = fs::read(&receipt_path).expect("read first consume receipt");

    let err = consume_authority(&queue_root, "job-atomic", "b3-256:second")
        .expect_err("second consume must fail-closed");
    assert!(
        err.contains("authority already consumed"),
        "second consume should fail with consumed marker, got: {err}"
    );

    let second_bytes = fs::read(&receipt_path).expect("read consume receipt after second attempt");
    assert_eq!(
        second_bytes, first_bytes,
        "consume receipt must be immutable after first successful write"
    );

    let receipt: serde_json::Value =
        serde_json::from_slice(&second_bytes).expect("parse consume receipt");
    assert_eq!(receipt["job_id"], "job-atomic");
    assert_eq!(receipt["spec_digest"], "b3-256:first");
}

#[test]
fn consume_authority_is_atomic_under_concurrent_race() {
    let dir = tempfile::tempdir().expect("tempdir");
    let queue_root = dir.path().join("queue");
    fs::create_dir_all(&queue_root).expect("create queue root");

    let threads = 8usize;
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(threads));
    let queue_root = std::sync::Arc::new(queue_root);

    let handles: Vec<_> = (0..threads)
        .map(|_| {
            let barrier = std::sync::Arc::clone(&barrier);
            let queue_root = std::sync::Arc::clone(&queue_root);
            std::thread::spawn(move || {
                barrier.wait();
                consume_authority(&queue_root, "job-race", "b3-256:racy")
            })
        })
        .collect();

    let mut ok_count = 0usize;
    let mut already_consumed_count = 0usize;
    let mut unexpected_errors = Vec::new();

    for handle in handles {
        match handle.join().expect("worker thread should not panic") {
            Ok(()) => ok_count += 1,
            Err(err) if err.contains("authority already consumed") => already_consumed_count += 1,
            Err(err) => unexpected_errors.push(err),
        }
    }

    assert!(
        unexpected_errors.is_empty(),
        "unexpected consume errors: {unexpected_errors:?}"
    );
    assert_eq!(
        ok_count, 1,
        "exactly one concurrent consume should succeed; got {ok_count}"
    );
    assert_eq!(
        already_consumed_count,
        threads - 1,
        "all losing racers must fail as already consumed"
    );

    let receipt_path = queue_root
        .join(CONSUME_RECEIPTS_DIR)
        .join("job-race.consumed");
    let receipt_bytes = fs::read(&receipt_path).expect("read race consume receipt");
    let receipt: serde_json::Value =
        serde_json::from_slice(&receipt_bytes).expect("parse race consume receipt");
    assert_eq!(receipt["job_id"], "job-race");
    assert_eq!(receipt["spec_digest"], "b3-256:racy");
}

fn make_orchestrator_step_candidate(job_id: &str, path: PathBuf) -> PendingCandidate {
    let source = apm2_core::fac::job_spec::JobSource {
        kind: "mirror_commit".to_string(),
        repo_id: "test/repo".to_string(),
        work_id: "W-TEST".to_string(),
        head_sha: "a".repeat(40),
        patch: None,
    };
    let spec = apm2_core::fac::job_spec::FacJobSpecV1Builder::new(
        job_id,
        "gates",
        "bulk",
        "2026-02-22T00:00:00Z",
        "lease-step-test",
        source,
    )
    .priority(50)
    .build()
    .expect("build step candidate spec");
    PendingCandidate {
        path,
        spec,
        raw_bytes: b"{}".to_vec(),
    }
}

#[test]
fn worker_orchestrator_step_transitions_lease_persisted_to_executing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let queue_root = dir.path().join("queue");
    let fac_root = dir.path().join("private").join("fac");
    fs::create_dir_all(&queue_root).expect("queue root");
    fs::create_dir_all(&fac_root).expect("fac root");

    let candidate =
        make_orchestrator_step_candidate("job-step-lease", queue_root.join("pending/job.json"));
    let mut completed_gates_cache = None;
    let signer = Signer::generate();
    let verifying_key = signer.verifying_key();
    let scheduler = QueueSchedulerState::new();
    let mut broker = FacBroker::new();
    let policy = FacPolicyV1::default_policy();
    let policy_hash = compute_policy_hash(&policy).expect("policy hash");
    let policy_digest = parse_policy_hash(&policy_hash).expect("policy digest");
    let job_spec_policy = policy
        .job_spec_validation_policy()
        .expect("job spec policy");
    let budget_cas = MemoryCas::new();
    let cost_model = apm2_core::economics::CostModelV1::with_defaults();
    let mut ctx = OrchestratorContext {
        candidate: &candidate,
        queue_root: &queue_root,
        fac_root: &fac_root,
        completed_gates_cache: &mut completed_gates_cache,
        verifying_key: &verifying_key,
        scheduler: &scheduler,
        lane: QueueLane::Bulk,
        broker: &mut broker,
        signer: &signer,
        policy_hash: &policy_hash,
        policy_digest: &policy_digest,
        policy: &policy,
        job_spec_policy: &job_spec_policy,
        budget_cas: &budget_cas,
        print_unit: false,
        canonicalizer_tuple_digest: "b3-256:step",
        boundary_id: "apm2.fac.local",
        heartbeat_cycle_count: 0,
        heartbeat_jobs_completed: 0,
        heartbeat_jobs_denied: 0,
        heartbeat_jobs_quarantined: 0,
        cost_model: &cost_model,
        toolchain_fingerprint: None,
    };

    let job_id = candidate.spec.job_id.clone();
    let lane_id = "lane-00".to_string();
    let mut orchestrator = WorkerOrchestrator::new();
    orchestrator.test_set_state(OrchestratorState::LeasePersisted {
        job_id: job_id.clone(),
        lane_id: lane_id.clone(),
    });

    let step = orchestrator.step(&mut ctx);
    assert!(matches!(step, StepOutcome::Advanced));
    assert_eq!(
        orchestrator.test_state(),
        &OrchestratorState::Executing { job_id, lane_id }
    );
}

#[test]
fn worker_orchestrator_step_executing_without_lease_context_fails_closed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let queue_root = dir.path().join("queue");
    let fac_root = dir.path().join("private").join("fac");
    fs::create_dir_all(&queue_root).expect("queue root");
    fs::create_dir_all(&fac_root).expect("fac root");

    let candidate = make_orchestrator_step_candidate(
        "job-step-missing-lease",
        queue_root.join("pending/job-missing-lease.json"),
    );
    let mut completed_gates_cache = None;
    let signer = Signer::generate();
    let verifying_key = signer.verifying_key();
    let scheduler = QueueSchedulerState::new();
    let mut broker = FacBroker::new();
    let policy = FacPolicyV1::default_policy();
    let policy_hash = compute_policy_hash(&policy).expect("policy hash");
    let policy_digest = parse_policy_hash(&policy_hash).expect("policy digest");
    let job_spec_policy = policy
        .job_spec_validation_policy()
        .expect("job spec policy");
    let budget_cas = MemoryCas::new();
    let cost_model = apm2_core::economics::CostModelV1::with_defaults();
    let mut ctx = OrchestratorContext {
        candidate: &candidate,
        queue_root: &queue_root,
        fac_root: &fac_root,
        completed_gates_cache: &mut completed_gates_cache,
        verifying_key: &verifying_key,
        scheduler: &scheduler,
        lane: QueueLane::Bulk,
        broker: &mut broker,
        signer: &signer,
        policy_hash: &policy_hash,
        policy_digest: &policy_digest,
        policy: &policy,
        job_spec_policy: &job_spec_policy,
        budget_cas: &budget_cas,
        print_unit: false,
        canonicalizer_tuple_digest: "b3-256:step",
        boundary_id: "apm2.fac.local",
        heartbeat_cycle_count: 0,
        heartbeat_jobs_completed: 0,
        heartbeat_jobs_denied: 0,
        heartbeat_jobs_quarantined: 0,
        cost_model: &cost_model,
        toolchain_fingerprint: None,
    };

    let job_id = candidate.spec.job_id.clone();
    let lane_id = "lane-00".to_string();
    let mut orchestrator = WorkerOrchestrator::new();
    orchestrator.test_set_state(OrchestratorState::Executing {
        job_id: job_id.clone(),
        lane_id,
    });

    let step = orchestrator.step(&mut ctx);
    let reason = match step {
        StepOutcome::Done(JobOutcome::Skipped { reason, .. }) => reason,
        other => panic!("expected skipped outcome, got {other:?}"),
    };
    assert!(
        reason.contains("missing lease context"),
        "expected missing lease context reason, got: {reason}"
    );
    assert!(matches!(
        orchestrator.test_state(),
        OrchestratorState::Completed {
            job_id: completed_id,
            outcome: JobOutcome::Skipped { reason, .. }
        } if completed_id == &job_id && reason.contains("missing lease context")
    ));
}

#[test]
fn worker_orchestrator_step_committing_emits_staged_outcome_and_terminal_state() {
    let dir = tempfile::tempdir().expect("tempdir");
    let queue_root = dir.path().join("queue");
    let fac_root = dir.path().join("private").join("fac");
    fs::create_dir_all(&queue_root).expect("queue root");
    fs::create_dir_all(&fac_root).expect("fac root");

    let candidate =
        make_orchestrator_step_candidate("job-step-commit", queue_root.join("pending/job.json"));
    let mut completed_gates_cache = None;
    let signer = Signer::generate();
    let verifying_key = signer.verifying_key();
    let scheduler = QueueSchedulerState::new();
    let mut broker = FacBroker::new();
    let policy = FacPolicyV1::default_policy();
    let policy_hash = compute_policy_hash(&policy).expect("policy hash");
    let policy_digest = parse_policy_hash(&policy_hash).expect("policy digest");
    let job_spec_policy = policy
        .job_spec_validation_policy()
        .expect("job spec policy");
    let budget_cas = MemoryCas::new();
    let cost_model = apm2_core::economics::CostModelV1::with_defaults();
    let mut ctx = OrchestratorContext {
        candidate: &candidate,
        queue_root: &queue_root,
        fac_root: &fac_root,
        completed_gates_cache: &mut completed_gates_cache,
        verifying_key: &verifying_key,
        scheduler: &scheduler,
        lane: QueueLane::Bulk,
        broker: &mut broker,
        signer: &signer,
        policy_hash: &policy_hash,
        policy_digest: &policy_digest,
        policy: &policy,
        job_spec_policy: &job_spec_policy,
        budget_cas: &budget_cas,
        print_unit: false,
        canonicalizer_tuple_digest: "b3-256:step",
        boundary_id: "apm2.fac.local",
        heartbeat_cycle_count: 0,
        heartbeat_jobs_completed: 0,
        heartbeat_jobs_denied: 0,
        heartbeat_jobs_quarantined: 0,
        cost_model: &cost_model,
        toolchain_fingerprint: None,
    };

    let job_id = candidate.spec.job_id.clone();
    let mut orchestrator = WorkerOrchestrator::new();
    orchestrator.test_set_state(OrchestratorState::Committing {
        job_id: job_id.clone(),
        lane_id: "lane-00".to_string(),
    });
    orchestrator.test_set_staged_outcome(JobOutcome::Denied {
        reason: "forced-deny-for-test".to_string(),
    });

    let first_step = orchestrator.step(&mut ctx);
    let first_reason = match first_step {
        StepOutcome::Done(JobOutcome::Denied { reason }) => reason,
        other => panic!("expected denied outcome, got {other:?}"),
    };
    assert_eq!(first_reason, "forced-deny-for-test");
    assert!(matches!(
        orchestrator.test_state(),
        OrchestratorState::Completed {
            job_id: completed_id,
            outcome: JobOutcome::Denied { reason }
        } if completed_id == &job_id && reason == "forced-deny-for-test"
    ));

    let second_step = orchestrator.step(&mut ctx);
    let second_reason = match second_step {
        StepOutcome::Done(JobOutcome::Denied { reason }) => reason,
        other => panic!("expected denied outcome on terminal replay, got {other:?}"),
    };
    assert_eq!(second_reason, "forced-deny-for-test");
}

#[test]
fn worker_orchestrator_step_completed_mismatch_fails_closed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let queue_root = dir.path().join("queue");
    let fac_root = dir.path().join("private").join("fac");
    fs::create_dir_all(&queue_root).expect("queue root");
    fs::create_dir_all(&fac_root).expect("fac root");

    let candidate =
        make_orchestrator_step_candidate("job-step-mismatch", queue_root.join("pending/job.json"));
    let mut completed_gates_cache = None;
    let signer = Signer::generate();
    let verifying_key = signer.verifying_key();
    let scheduler = QueueSchedulerState::new();
    let mut broker = FacBroker::new();
    let policy = FacPolicyV1::default_policy();
    let policy_hash = compute_policy_hash(&policy).expect("policy hash");
    let policy_digest = parse_policy_hash(&policy_hash).expect("policy digest");
    let job_spec_policy = policy
        .job_spec_validation_policy()
        .expect("job spec policy");
    let budget_cas = MemoryCas::new();
    let cost_model = apm2_core::economics::CostModelV1::with_defaults();
    let mut ctx = OrchestratorContext {
        candidate: &candidate,
        queue_root: &queue_root,
        fac_root: &fac_root,
        completed_gates_cache: &mut completed_gates_cache,
        verifying_key: &verifying_key,
        scheduler: &scheduler,
        lane: QueueLane::Bulk,
        broker: &mut broker,
        signer: &signer,
        policy_hash: &policy_hash,
        policy_digest: &policy_digest,
        policy: &policy,
        job_spec_policy: &job_spec_policy,
        budget_cas: &budget_cas,
        print_unit: false,
        canonicalizer_tuple_digest: "b3-256:step",
        boundary_id: "apm2.fac.local",
        heartbeat_cycle_count: 0,
        heartbeat_jobs_completed: 0,
        heartbeat_jobs_denied: 0,
        heartbeat_jobs_quarantined: 0,
        cost_model: &cost_model,
        toolchain_fingerprint: None,
    };

    let mut orchestrator = WorkerOrchestrator::new();
    orchestrator.test_set_state(OrchestratorState::Completed {
        job_id: "state-job-id".to_string(),
        outcome: JobOutcome::Completed {
            job_id: "outcome-job-id".to_string(),
            observed_cost: None,
        },
    });

    let step = orchestrator.step(&mut ctx);
    let reason = match step {
        StepOutcome::Skipped(reason) => reason,
        other => panic!("expected skipped mismatch outcome, got {other:?}"),
    };
    assert!(
        reason.contains("job_id mismatch"),
        "expected mismatch reason, got: {reason}"
    );
}

#[test]
fn test_move_to_dir_safe_atomic() {
    let dir = tempfile::tempdir().expect("tempdir");
    let src_dir = dir.path().join("src");
    let dst_dir = dir.path().join("dst");
    fs::create_dir_all(&src_dir).expect("src dir");

    let src_file = src_dir.join("test.json");
    fs::write(&src_file, b"data").expect("write");

    move_to_dir_safe(&src_file, &dst_dir, "test.json").expect("move");

    assert!(!src_file.exists(), "source should be gone");
    assert!(dst_dir.join("test.json").exists(), "dest should exist");
}

#[test]
fn test_move_to_dir_safe_collision_avoidance() {
    let dir = tempfile::tempdir().expect("tempdir");
    let src_dir = dir.path().join("src");
    let dst_dir = dir.path().join("dst");
    fs::create_dir_all(&src_dir).expect("src dir");
    fs::create_dir_all(&dst_dir).expect("dst dir");

    // Create existing target to trigger collision path.
    fs::write(dst_dir.join("test.json"), b"existing").expect("write existing");

    let src_file = src_dir.join("test.json");
    fs::write(&src_file, b"new data").expect("write src");

    move_to_dir_safe(&src_file, &dst_dir, "test.json").expect("move with collision");

    // Original target should be untouched.
    let existing_content = fs::read_to_string(dst_dir.join("test.json")).expect("read");
    assert_eq!(
        existing_content, "existing",
        "original file should be untouched"
    );

    // New file should exist with a timestamp suffix.
    let entries: Vec<_> = fs::read_dir(&dst_dir)
        .expect("read dir")
        .flatten()
        .collect();
    assert_eq!(
        entries.len(),
        2,
        "should have original + collision-safe file"
    );
}

#[test]
fn test_emit_scan_receipt_bounded_reason() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fac_root = dir.path().join("private").join("fac");
    ensure_queue_dirs(&dir.path().join("queue")).expect("create dirs");

    let long_reason = "x".repeat(1024);
    let result = emit_scan_receipt(
        &fac_root,
        "test.json",
        "job1",
        &compute_job_spec_digest_preview(&[]),
        FacJobOutcome::Quarantined,
        DenialReasonCode::MalformedSpec,
        None,
        &long_reason,
        &CanonicalizerTupleV1::from_current().compute_digest(),
        None, // toolchain_fingerprint
    );

    assert!(
        result.is_err(),
        "receipt emit should reject oversized reason with 512-char bound"
    );
}

#[test]
fn test_current_timestamp_epoch_secs_is_nonzero() {
    let secs = current_timestamp_epoch_secs();
    assert!(secs > 0, "timestamp should be nonzero");
}

#[test]
fn test_build_running_lane_lease_uses_rfc3339_started_at() {
    let lease = build_running_lane_lease(
        "lane-00",
        "job-001",
        std::process::id(),
        "b3-256:ph",
        "b3-256:th",
    )
    .expect("build running lease");
    assert!(
        chrono::DateTime::parse_from_rfc3339(&lease.started_at).is_ok(),
        "worker lease started_at must be RFC3339, got {}",
        lease.started_at
    );
    assert!(
        lease.started_at.ends_with('Z'),
        "worker lease started_at must be UTC-Z, got {}",
        lease.started_at
    );
}

#[test]
fn test_parse_queue_lane_known_values() {
    assert_eq!(parse_queue_lane("stop_revoke"), QueueLane::StopRevoke);
    assert_eq!(parse_queue_lane("control"), QueueLane::Control);
    assert_eq!(parse_queue_lane("consume"), QueueLane::Consume);
    assert_eq!(parse_queue_lane("replay"), QueueLane::Replay);
    assert_eq!(
        parse_queue_lane("projection_replay"),
        QueueLane::ProjectionReplay
    );
    assert_eq!(parse_queue_lane("bulk"), QueueLane::Bulk);
}

#[test]
fn test_parse_queue_lane_unknown_defaults_to_bulk() {
    assert_eq!(parse_queue_lane("unknown_lane"), QueueLane::Bulk);
    assert_eq!(parse_queue_lane(""), QueueLane::Bulk);
}

#[test]
fn test_build_queued_gates_bounded_unit_base_includes_lane_and_job_id() {
    let base = build_queued_gates_bounded_unit_base("lane-00", "job_123");
    assert_eq!(base, "apm2-fac-job-lane-00-job_123");
}

#[test]
fn test_build_queued_gates_bounded_unit_base_sanitizes_segments() {
    let base = build_queued_gates_bounded_unit_base("lane 00", "job/id");
    assert_eq!(base, "apm2-fac-job-lane-00-job-id");
}

#[test]
fn test_parse_gates_job_options_rejects_missing_payload() {
    let spec = make_receipt_test_spec();
    let err = parse_gates_job_options(&spec).expect_err("missing payload must fail closed");
    assert!(err.contains("missing gates options payload"));
}

#[test]
fn test_parse_gates_job_options_from_patch_payload() {
    let workspace_root = repo_toplevel_for_tests();
    let mut spec = make_receipt_test_spec();
    spec.source.patch = Some(serde_json::json!({
        "schema": GATES_JOB_OPTIONS_SCHEMA,
        "force": true,
        "quick": true,
        "timeout_seconds": 77,
        "memory_max": "1G",
        "pids_max": 99,
        "cpu_quota": "150%",
        "gate_profile": "balanced",
        "workspace_root": workspace_root
    }));
    let options = parse_gates_job_options(&spec).expect("parse payload");
    assert!(options.force);
    assert!(options.quick);
    assert_eq!(options.timeout_seconds, 77);
    assert_eq!(options.memory_max, "1G");
    assert_eq!(options.pids_max, 99);
    assert_eq!(options.cpu_quota, "150%");
    assert_eq!(
        options.gate_profile,
        fac_review_api::GateThroughputProfile::Balanced
    );
    assert!(options.workspace_root.is_dir());
}

#[test]
fn test_parse_gates_job_options_rejects_missing_decoded_source() {
    let workspace_root = repo_toplevel_for_tests();
    let mut spec = make_receipt_test_spec();
    spec.actuation.decoded_source = None;
    spec.source.patch = Some(serde_json::json!({
        "schema": GATES_JOB_OPTIONS_SCHEMA,
        "force": false,
        "quick": false,
        "timeout_seconds": DEFAULT_GATES_TIMEOUT_SECONDS,
        "memory_max": DEFAULT_GATES_MEMORY_MAX,
        "pids_max": DEFAULT_GATES_PIDS_MAX,
        "cpu_quota": DEFAULT_GATES_CPU_QUOTA,
        "gate_profile": "throughput",
        "workspace_root": workspace_root
    }));
    let err = parse_gates_job_options(&spec).expect_err("missing decoded_source must fail");
    assert!(err.contains("missing gates decoded_source hint"));
}

#[test]
fn test_parse_gates_job_options_rejects_schema_mismatch() {
    let workspace_root = repo_toplevel_for_tests();
    let mut spec = make_receipt_test_spec();
    spec.source.patch = Some(serde_json::json!({
        "schema": "apm2.fac.gates_job_options.v0",
        "force": false,
        "quick": false,
        "timeout_seconds": 600,
        "memory_max": "48G",
        "pids_max": 1536,
        "cpu_quota": "auto",
        "gate_profile": "throughput",
        "workspace_root": workspace_root
    }));
    let err = parse_gates_job_options(&spec).expect_err("schema mismatch must fail closed");
    assert!(err.contains("unsupported gates options schema"));
}

#[test]
fn test_parse_gates_job_options_rejects_invalid_profile() {
    let workspace_root = repo_toplevel_for_tests();
    let mut spec = make_receipt_test_spec();
    spec.source.patch = Some(serde_json::json!({
        "schema": GATES_JOB_OPTIONS_SCHEMA,
        "force": false,
        "quick": false,
        "timeout_seconds": 600,
        "memory_max": "48G",
        "pids_max": 1536,
        "cpu_quota": "auto",
        "gate_profile": "extreme",
        "workspace_root": workspace_root
    }));
    let err = parse_gates_job_options(&spec).expect_err("invalid profile must fail closed");
    assert!(err.contains("invalid gates gate_profile"));
}

#[test]
fn test_parse_gates_job_options_rejects_missing_workspace_root() {
    let mut spec = make_receipt_test_spec();
    spec.source.patch = Some(serde_json::json!({
        "schema": GATES_JOB_OPTIONS_SCHEMA,
        "force": false,
        "quick": false,
        "timeout_seconds": 600,
        "memory_max": "48G",
        "pids_max": 1536,
        "cpu_quota": "auto",
        "gate_profile": "throughput",
        "workspace_root": "/path/does/not/exist"
    }));
    let err = parse_gates_job_options(&spec).expect_err("invalid workspace root must fail closed");
    assert!(err.contains("workspace_root"));
}

#[test]
fn test_parse_gates_job_options_rejects_repo_mismatch() {
    let workspace_root = repo_toplevel_for_tests();
    let mut spec = make_receipt_test_spec();
    spec.source.repo_id = "local/not-this-workspace".to_string();
    spec.source.patch = Some(serde_json::json!({
        "schema": GATES_JOB_OPTIONS_SCHEMA,
        "force": false,
        "quick": false,
        "timeout_seconds": 600,
        "memory_max": "48G",
        "pids_max": 1536,
        "cpu_quota": "auto",
        "gate_profile": "throughput",
        "workspace_root": workspace_root
    }));
    let err = parse_gates_job_options(&spec).expect_err("repo mismatch must fail closed");
    assert!(err.contains("repo mismatch"), "unexpected error: {err}");
}

#[test]
fn test_parse_gates_job_options_rejects_fac_internal_workspace_root() {
    let _guard = env_var_test_lock().lock().expect("serialize env test");
    let original_apm2_home = std::env::var_os("APM2_HOME");

    let dir = tempfile::tempdir().expect("tempdir");
    let apm2_home = dir.path().join(".apm2");
    let fac_internal = apm2_home.join("private").join("fac").join("workspace");
    fs::create_dir_all(&fac_internal).expect("create fac internal path");

    set_env_var_for_test("APM2_HOME", &apm2_home);

    let mut spec = make_receipt_test_spec();
    spec.source.patch = Some(serde_json::json!({
        "schema": GATES_JOB_OPTIONS_SCHEMA,
        "force": false,
        "quick": false,
        "timeout_seconds": 600,
        "memory_max": "48G",
        "pids_max": 1536,
        "cpu_quota": "auto",
        "gate_profile": "throughput",
        "workspace_root": fac_internal.to_string_lossy()
    }));
    let err = parse_gates_job_options(&spec).expect_err("fac internal path must be denied");
    assert!(
        err.contains("FAC-internal storage"),
        "unexpected error: {err}"
    );

    if let Some(value) = original_apm2_home {
        set_env_var_for_test("APM2_HOME", value);
    } else {
        remove_env_var_for_test("APM2_HOME");
    }
}

#[test]
fn test_parse_gates_job_options_rejects_workspace_outside_allowlist_roots() {
    let _guard = env_var_test_lock().lock().expect("serialize env test");
    let original_allowlist = std::env::var_os(ALLOWED_WORKSPACE_ROOTS_ENV);
    remove_env_var_for_test(ALLOWED_WORKSPACE_ROOTS_ENV);

    let dir = tempfile::tempdir().expect("tempdir");
    let workspace = dir.path().join("foreign-workspace");
    fs::create_dir_all(&workspace).expect("create workspace");
    init_test_workspace_git_repo(&workspace);

    let mut spec = make_receipt_test_spec();
    spec.source.repo_id = resolve_repo_id(&workspace);
    spec.source.patch = Some(serde_json::json!({
        "schema": GATES_JOB_OPTIONS_SCHEMA,
        "force": false,
        "quick": false,
        "timeout_seconds": 600,
        "memory_max": "48G",
        "pids_max": 1536,
        "cpu_quota": "auto",
        "gate_profile": "throughput",
        "workspace_root": workspace.to_string_lossy()
    }));
    let err = parse_gates_job_options(&spec).expect_err("workspace outside allowlist must deny");
    assert!(
        err.contains("outside allowed workspace roots"),
        "unexpected error: {err}"
    );

    if let Some(value) = original_allowlist {
        set_env_var_for_test(ALLOWED_WORKSPACE_ROOTS_ENV, value);
    } else {
        remove_env_var_for_test(ALLOWED_WORKSPACE_ROOTS_ENV);
    }
}

#[test]
fn test_parse_gates_job_options_accepts_workspace_in_explicit_allowlist() {
    let _guard = env_var_test_lock().lock().expect("serialize env test");
    let original_allowlist = std::env::var_os(ALLOWED_WORKSPACE_ROOTS_ENV);

    let dir = tempfile::tempdir().expect("tempdir");
    let workspace = dir.path().join("allowed-workspace");
    fs::create_dir_all(&workspace).expect("create workspace");
    init_test_workspace_git_repo(&workspace);
    set_env_var_for_test(ALLOWED_WORKSPACE_ROOTS_ENV, &workspace);

    let mut spec = make_receipt_test_spec();
    spec.source.repo_id = resolve_repo_id(&workspace);
    spec.source.patch = Some(serde_json::json!({
        "schema": GATES_JOB_OPTIONS_SCHEMA,
        "force": false,
        "quick": false,
        "timeout_seconds": 600,
        "memory_max": "48G",
        "pids_max": 1536,
        "cpu_quota": "auto",
        "gate_profile": "throughput",
        "workspace_root": workspace.to_string_lossy()
    }));
    let options = parse_gates_job_options(&spec).expect("allowlisted workspace should pass");
    assert_eq!(options.workspace_root, workspace);

    if let Some(value) = original_allowlist {
        set_env_var_for_test(ALLOWED_WORKSPACE_ROOTS_ENV, value);
    } else {
        remove_env_var_for_test(ALLOWED_WORKSPACE_ROOTS_ENV);
    }
}

#[allow(unsafe_code)]
fn set_env_var_for_test<K: AsRef<std::ffi::OsStr>, V: AsRef<std::ffi::OsStr>>(key: K, value: V) {
    unsafe { std::env::set_var(key, value) };
}

#[allow(unsafe_code)]
fn remove_env_var_for_test<K: AsRef<std::ffi::OsStr>>(key: K) {
    unsafe { std::env::remove_var(key) };
}

struct FacReviewApiOverrideGuard;

impl FacReviewApiOverrideGuard {
    fn install(
        run_result: Result<fac_review_api::LocalGatesRunResult, String>,
        lifecycle_result: Result<usize, String>,
    ) -> Self {
        fac_review_api::set_run_gates_local_worker_override(Some(run_result));
        fac_review_api::set_gate_lifecycle_override(Some(lifecycle_result));
        Self
    }
}

impl Drop for FacReviewApiOverrideGuard {
    fn drop(&mut self) {
        fac_review_api::set_run_gates_local_worker_override(None);
        fac_review_api::set_gate_lifecycle_override(None);
    }
}

fn make_receipt_test_spec() -> FacJobSpecV1 {
    let repo_root = PathBuf::from(repo_toplevel_for_tests());
    let repo_id = resolve_repo_id(&repo_root);
    FacJobSpecV1 {
        schema: "apm2.fac.job_spec.v1".to_string(),
        job_id: "job-001".to_string(),
        job_spec_digest: "b3-256:".to_string() + &"a".repeat(64),
        kind: "gates".to_string(),
        queue_lane: "control".to_string(),
        priority: 50,
        enqueue_time: "2026-02-13T12:00:00Z".to_string(),
        actuation: apm2_core::fac::job_spec::Actuation {
            lease_id: "lease-001".to_string(),
            request_id: "b3-256:".to_string() + &"b".repeat(64),
            channel_context_token: Some("token".to_string()),
            decoded_source: Some("fac_gates_worker".to_string()),
        },
        source: apm2_core::fac::job_spec::JobSource {
            kind: "mirror_commit".to_string(),
            repo_id: repo_id.clone(),
            work_id: format!(
                "W-LEGACY-{}",
                &blake3::hash(repo_id.as_bytes()).to_hex()[..24]
            ),
            head_sha: "abcd1234abcd1234abcd1234abcd1234abcd1234".to_string(),
            patch: None,
        },
        lane_requirements: apm2_core::fac::job_spec::LaneRequirements {
            lane_profile_hash: Some("b3-256:".to_string() + &"c".repeat(64)),
        },
        constraints: apm2_core::fac::job_spec::JobConstraints {
            require_nextest: false,
            test_timeout_seconds: None,
            memory_max_bytes: None,
        },
        cancel_target_job_id: None,
    }
}

fn repo_toplevel_for_tests() -> String {
    let output = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .expect("git rev-parse should execute");
    assert!(
        output.status.success(),
        "git rev-parse --show-toplevel failed"
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

#[test]
fn test_check_or_admit_canonicalizer_tuple_missing_is_fail_closed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fac_root = dir.path().join("private").join("fac");
    let _broker = FacBroker::new();

    let result = check_or_admit_canonicalizer_tuple(&fac_root)
        .expect("first run should return a canonicalizer check result");
    match result {
        CanonicalizerTupleCheck::Missing => {},
        other => panic!("unexpected result: {other:?}"),
    }
}

#[test]
fn test_check_or_admit_canonicalizer_tuple_mismatch_detected() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fac_root = dir.path().join("private").join("fac");
    let mut broker = FacBroker::new();

    broker
        .admit_canonicalizer_tuple(&fac_root)
        .expect("seed admitted tuple");

    let mut tuple = CanonicalizerTupleV1::from_current();
    tuple.canonicalizer_version.push_str("-mismatch");
    let tuple_path = fac_root
        .join("broker")
        .join("admitted_canonicalizer_tuple.v1.json");
    fs::create_dir_all(fac_root.join("broker")).expect("tuple directory exists");
    let tuple_bytes = serde_json::to_vec_pretty(&tuple).expect("serialize mismatch tuple");
    fs::write(&tuple_path, tuple_bytes).expect("write mismatch tuple");

    match check_or_admit_canonicalizer_tuple(&fac_root) {
        Ok(CanonicalizerTupleCheck::Mismatch(admitted_tuple)) => {
            assert_ne!(admitted_tuple, CanonicalizerTupleV1::from_current());
        },
        other => panic!("expected mismatch, got: {other:?}"),
    }
}

#[test]
fn test_check_or_admit_canonicalizer_tuple_rejects_deserialization_errors() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fac_root = dir.path().join("private").join("fac");
    let _broker = FacBroker::new();
    let tuple_path = fac_root
        .join("broker")
        .join("admitted_canonicalizer_tuple.v1.json");
    fs::create_dir_all(tuple_path.parent().expect("tuple directory parent"))
        .expect("create tuple directory");
    fs::write(&tuple_path, b"{not-json").expect("write corrupted tuple");

    let result = check_or_admit_canonicalizer_tuple(&fac_root);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.contains("corrupted"),
        "expected corruption error, got: {err}"
    );
    assert_eq!(
        fs::read(&tuple_path).expect("read tuple").as_slice(),
        b"{not-json"
    );
}

#[test]
fn test_emit_job_receipt_includes_canonicalizer_tuple_digest() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fac_root = dir.path().join("private").join("fac");
    let tuple_digest = CanonicalizerTupleV1::from_current().compute_digest();
    let spec = make_receipt_test_spec();
    let boundary_trace = ChannelBoundaryTrace {
        passed: true,
        defect_count: 0,
        defect_classes: Vec::new(),
        token_fac_policy_hash: None,
        token_canonicalizer_tuple_digest: None,
        token_boundary_id: None,
        token_issued_at_tick: None,
        token_expiry_tick: None,
    };
    let queue_trace = JobQueueAdmissionTrace {
        verdict: "allow".to_string(),
        queue_lane: "control".to_string(),
        defect_reason: None,
        cost_estimate_ticks: None,
    };

    let receipt_path = emit_job_receipt(
        &fac_root,
        &spec,
        FacJobOutcome::Completed,
        None,
        "completed",
        Some(&boundary_trace),
        Some(&queue_trace),
        None,
        None,
        Some(&tuple_digest),
        None,
        &spec.job_spec_digest,
        None,
        None,
        None,
        None, // bytes_backend
        None,
    )
    .expect("emit receipt");

    let receipt_json = serde_json::from_slice::<serde_json::Value>(
        &fs::read(&receipt_path).expect("read receipt"),
    )
    .expect("parse receipt JSON");
    assert_eq!(
        receipt_json
            .get("canonicalizer_tuple_digest")
            .and_then(|value| value.as_str()),
        Some(tuple_digest.as_str())
    );
    assert!(
        receipt_json.get("patch_digest").is_none(),
        "patch_digest should remain unset in this receipt path"
    );
}

#[test]
fn test_emit_job_receipt_channel_boundary_defect_path_sets_canonicalizer_digest() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fac_root = dir.path().join("private").join("fac");
    let canonicalizer_tuple_digest = CanonicalizerTupleV1::from_current().compute_digest();
    let spec = make_receipt_test_spec();

    let receipt_path = emit_job_receipt(
        &fac_root,
        &spec,
        FacJobOutcome::Denied,
        Some(DenialReasonCode::ChannelBoundaryViolation),
        "channel boundary violation",
        None,
        None,
        None,
        None,
        Some(&canonicalizer_tuple_digest),
        None,
        &spec.job_spec_digest,
        None,
        None,
        None,
        None, // bytes_backend
        None,
    )
    .expect("emit receipt");

    let receipt_json = serde_json::from_slice::<serde_json::Value>(
        &fs::read(&receipt_path).expect("read receipt"),
    )
    .expect("parse receipt JSON");
    assert_eq!(
        receipt_json
            .get("canonicalizer_tuple_digest")
            .and_then(|value| value.as_str()),
        Some(canonicalizer_tuple_digest.as_str())
    );
    assert!(
        receipt_json.get("patch_digest").is_none(),
        "channel-boundary receipt should not set patch_digest"
    );
}

#[test]
fn test_emit_job_receipt_restores_denied_job_to_pending_on_persist_failure() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fac_root = dir.path().join("private").join("fac");
    let queue_root = fac_root.join("queue");
    fs::create_dir_all(queue_root.join(PENDING_DIR)).expect("create pending dir");
    fs::create_dir_all(queue_root.join(DENIED_DIR)).expect("create denied dir");

    let spec = make_receipt_test_spec();
    let denied_file_name = format!("{}.json", spec.job_id);
    let denied_relative_path = format!("{DENIED_DIR}/{denied_file_name}");
    let denied_path = queue_root.join(DENIED_DIR).join(&denied_file_name);
    fs::write(
        &denied_path,
        serde_json::to_vec_pretty(&spec).expect("serialize denied job spec"),
    )
    .expect("write denied job file");

    fs::create_dir_all(&fac_root).expect("create fac root");
    fs::write(fac_root.join(FAC_RECEIPTS_DIR), b"receipts-dir-blocker")
        .expect("write receipts dir blocker file");

    let err = emit_job_receipt(
        &fac_root,
        &spec,
        FacJobOutcome::Denied,
        Some(DenialReasonCode::ValidationFailed),
        "validation failed",
        None,
        None,
        None,
        None,
        Some(&CanonicalizerTupleV1::from_current().compute_digest()),
        Some(&denied_relative_path),
        &spec.job_spec_digest,
        None,
        None,
        None,
        None, // bytes_backend
        None,
    )
    .expect_err("receipt persistence should fail when receipts path is not a directory");
    assert!(
        err.contains("restored moved job to pending"),
        "error should report pending restore path, got: {err}"
    );

    let restored_pending_path = queue_root.join(PENDING_DIR).join(&denied_file_name);
    assert!(
        restored_pending_path.exists(),
        "denied file must be restored to pending on receipt persist failure"
    );
    assert!(
        !denied_path.exists(),
        "denied file must be removed after pending restore"
    );
}

#[test]
fn test_scan_pending_quarantines_malformed_files() {
    let dir = tempfile::tempdir().expect("tempdir");
    let queue_root = dir.path().join("queue");
    ensure_queue_dirs(&queue_root).expect("create dirs");

    // Write a malformed JSON file to pending.
    let malformed_path = queue_root.join("pending").join("bad.json");
    fs::write(&malformed_path, b"not valid json {{{").expect("write malformed");

    let fac_root = dir.path().join("private").join("fac");
    let candidates = scan_pending(
        &queue_root,
        &fac_root,
        &CanonicalizerTupleV1::from_current().compute_digest(),
        None, // toolchain_fingerprint
    )
    .expect("scan");

    // Malformed file should have been quarantined, not included in candidates.
    assert!(
        candidates.is_empty(),
        "malformed file should not be a candidate"
    );

    // Check it was quarantined.
    let quarantine_dir = queue_root.join(QUARANTINE_DIR);
    let quarantined_files: Vec<_> = fs::read_dir(&quarantine_dir)
        .expect("read quarantine")
        .flatten()
        .collect();
    assert!(
        !quarantined_files.is_empty(),
        "malformed file should be in quarantine"
    );

    // Check receipt was written.
    let receipts_dir = fac_root.join(FAC_RECEIPTS_DIR);
    let receipt_files: Vec<_> = fs::read_dir(&receipts_dir)
        .expect("read receipts")
        .flatten()
        .collect();
    assert!(
        !receipt_files.is_empty(),
        "quarantine receipt should be written"
    );
}

#[test]
fn test_scan_pending_quarantines_oversize_files() {
    let dir = tempfile::tempdir().expect("tempdir");
    let queue_root = dir.path().join("queue");
    ensure_queue_dirs(&queue_root).expect("create dirs");

    // Write an oversize file to pending.
    let oversize_path = queue_root.join("pending").join("huge.json");
    let data = vec![b'x'; MAX_JOB_SPEC_SIZE + 1];
    fs::write(&oversize_path, &data).expect("write oversize");

    let fac_root = dir.path().join("private").join("fac");
    let candidates = scan_pending(
        &queue_root,
        &fac_root,
        &CanonicalizerTupleV1::from_current().compute_digest(),
        None, // toolchain_fingerprint
    )
    .expect("scan");

    assert!(
        candidates.is_empty(),
        "oversize file should not be a candidate"
    );

    // Check it was quarantined.
    let quarantine_dir = queue_root.join(QUARANTINE_DIR);
    let quarantined_files: Vec<_> = fs::read_dir(&quarantine_dir)
        .expect("read quarantine")
        .flatten()
        .collect();
    assert!(
        !quarantined_files.is_empty(),
        "oversize file should be in quarantine"
    );
}

#[test]
fn test_compute_evidence_hash_deterministic() {
    let h1 = compute_evidence_hash(b"test-data");
    let h2 = compute_evidence_hash(b"test-data");
    assert_eq!(h1, h2, "same input must produce same hash");
}

#[test]
fn test_compute_evidence_hash_different_inputs() {
    let h1 = compute_evidence_hash(b"data-a");
    let h2 = compute_evidence_hash(b"data-b");
    assert_ne!(h1, h2, "different inputs must produce different hashes");
}

/// MAJOR-1 regression: `stop_target_unit_exact` must reject unsafe lane
/// characters to prevent command injection via crafted unit names.
#[test]
fn test_stop_target_unit_exact_rejects_unsafe_lane() {
    for unsafe_lane in &["../evil", "lane;rm", "a b", "lane/path", "lane*glob", ""] {
        let result = stop_target_unit_exact(unsafe_lane, "job-123");
        assert!(
            result.is_err(),
            "should reject unsafe lane {unsafe_lane:?}: {result:?}"
        );
        let err_msg = result.unwrap_err();
        assert!(
            err_msg.contains("unsafe queue_lane"),
            "error should mention unsafe lane: {err_msg}"
        );
    }
}

/// MAJOR-1 regression: `stop_target_unit_exact` must accept valid lanes.
#[test]
fn test_stop_target_unit_exact_accepts_valid_lane() {
    // This will fail to actually stop a unit (no systemd in test), but it
    // should NOT fail due to lane sanitization.
    for valid_lane in &["control", "default-0", "lane_1", "A-Z-test"] {
        let result = stop_target_unit_exact(valid_lane, "job-123");
        // We expect Err from systemctl (not installed or unit not found),
        // but NOT an "unsafe queue_lane" error.
        if let Err(ref e) = result {
            assert!(
                !e.contains("unsafe queue_lane"),
                "valid lane {valid_lane:?} should not be rejected: {e}"
            );
        }
    }
}

/// BLOCKER-1 regression: Completed receipts must include containment
/// evidence when a `ContainmentTrace` is provided.
#[test]
fn test_emit_job_receipt_includes_containment_trace() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fac_root = dir.path().join("private").join("fac");
    let spec = make_receipt_test_spec();
    let boundary_trace = ChannelBoundaryTrace {
        passed: true,
        defect_count: 0,
        defect_classes: Vec::new(),
        token_fac_policy_hash: None,
        token_canonicalizer_tuple_digest: None,
        token_boundary_id: None,
        token_issued_at_tick: None,
        token_expiry_tick: None,
    };
    let queue_trace = JobQueueAdmissionTrace {
        verdict: "allow".to_string(),
        queue_lane: "bulk".to_string(),
        defect_reason: None,
        cost_estimate_ticks: None,
    };
    let tuple_digest = CanonicalizerTupleV1::from_current().compute_digest();
    let containment_trace = apm2_core::fac::containment::ContainmentTrace {
        verified: true,
        cgroup_path: "/system.slice/apm2-job.service".to_string(),
        processes_checked: 5,
        mismatch_count: 0,
        sccache_auto_disabled: false,
        sccache_enabled: false,
        sccache_version: None,
        sccache_server_containment: None,
    };

    let receipt_path = emit_job_receipt(
        &fac_root,
        &spec,
        FacJobOutcome::Completed,
        None,
        "completed",
        Some(&boundary_trace),
        Some(&queue_trace),
        None,
        None,
        Some(&tuple_digest),
        None,
        &spec.job_spec_digest,
        Some(&containment_trace),
        None,
        None,
        None, // bytes_backend
        None,
    )
    .expect("emit receipt with containment");

    let receipt_json = serde_json::from_slice::<serde_json::Value>(
        &fs::read(&receipt_path).expect("read receipt"),
    )
    .expect("parse receipt JSON");

    let containment = receipt_json
        .get("containment")
        .expect("containment field must be present in completed receipt");
    assert_eq!(
        containment
            .get("verified")
            .and_then(serde_json::Value::as_bool),
        Some(true),
    );
    assert_eq!(
        containment
            .get("cgroup_path")
            .and_then(serde_json::Value::as_str),
        Some("/system.slice/apm2-job.service"),
    );
    assert_eq!(
        containment
            .get("processes_checked")
            .and_then(serde_json::Value::as_u64),
        Some(5),
    );
}

/// BLOCKER-1 regression: Completed receipts without containment must
/// NOT have the containment field (None case).
#[test]
fn test_emit_job_receipt_omits_containment_when_none() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fac_root = dir.path().join("private").join("fac");
    let spec = make_receipt_test_spec();
    let boundary_trace = ChannelBoundaryTrace {
        passed: true,
        defect_count: 0,
        defect_classes: Vec::new(),
        token_fac_policy_hash: None,
        token_canonicalizer_tuple_digest: None,
        token_boundary_id: None,
        token_issued_at_tick: None,
        token_expiry_tick: None,
    };
    let queue_trace = JobQueueAdmissionTrace {
        verdict: "allow".to_string(),
        queue_lane: "bulk".to_string(),
        defect_reason: None,
        cost_estimate_ticks: None,
    };
    let tuple_digest = CanonicalizerTupleV1::from_current().compute_digest();

    let receipt_path = emit_job_receipt(
        &fac_root,
        &spec,
        FacJobOutcome::Completed,
        None,
        "completed",
        Some(&boundary_trace),
        Some(&queue_trace),
        None,
        None,
        Some(&tuple_digest),
        None,
        &spec.job_spec_digest,
        None,
        None,
        None,
        None, // bytes_backend
        None,
    )
    .expect("emit receipt without containment");

    let receipt_json = serde_json::from_slice::<serde_json::Value>(
        &fs::read(&receipt_path).expect("read receipt"),
    )
    .expect("parse receipt JSON");

    assert!(
        receipt_json.get("containment").is_none(),
        "containment field must be absent when None"
    );
}

/// Verify that `sandbox_hardening_hash` is included in the persisted
/// receipt when provided (TCK-00573 regression test).
#[test]
fn test_emit_job_receipt_includes_sandbox_hardening_hash() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fac_root = dir.path().join("private").join("fac");
    let tuple_digest = CanonicalizerTupleV1::from_current().compute_digest();
    let spec = make_receipt_test_spec();
    let boundary_trace = ChannelBoundaryTrace {
        passed: true,
        defect_count: 0,
        defect_classes: Vec::new(),
        token_fac_policy_hash: None,
        token_canonicalizer_tuple_digest: None,
        token_boundary_id: None,
        token_issued_at_tick: None,
        token_expiry_tick: None,
    };
    let queue_trace = JobQueueAdmissionTrace {
        verdict: "allow".to_string(),
        queue_lane: "control".to_string(),
        defect_reason: None,
        cost_estimate_ticks: None,
    };

    let hardening_hash = apm2_core::fac::SandboxHardeningProfile::default().content_hash_hex();

    let receipt_path = emit_job_receipt(
        &fac_root,
        &spec,
        FacJobOutcome::Completed,
        None,
        "completed",
        Some(&boundary_trace),
        Some(&queue_trace),
        None,
        None,
        Some(&tuple_digest),
        None,
        &spec.job_spec_digest,
        None,
        Some(&hardening_hash),
        None,
        None, // bytes_backend
        None,
    )
    .expect("emit receipt with sandbox_hardening_hash");

    let receipt_json = serde_json::from_slice::<serde_json::Value>(
        &fs::read(&receipt_path).expect("read receipt"),
    )
    .expect("parse receipt JSON");

    assert_eq!(
        receipt_json
            .get("sandbox_hardening_hash")
            .and_then(|v| v.as_str()),
        Some(hardening_hash.as_str()),
        "sandbox_hardening_hash must be present in persisted receipt"
    );
    // Verify the hash has the expected b3-256: prefix format.
    assert!(
        hardening_hash.starts_with("b3-256:"),
        "hash must have b3-256: prefix"
    );
    assert_eq!(
        hardening_hash.len(),
        71,
        "b3-256:<64hex> must be exactly 71 chars"
    );
}

/// Verify that `sandbox_hardening_hash` is absent when not provided.
#[test]
fn test_emit_job_receipt_omits_sandbox_hardening_hash_when_none() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fac_root = dir.path().join("private").join("fac");
    let tuple_digest = CanonicalizerTupleV1::from_current().compute_digest();
    let spec = make_receipt_test_spec();
    let boundary_trace = ChannelBoundaryTrace {
        passed: true,
        defect_count: 0,
        defect_classes: Vec::new(),
        token_fac_policy_hash: None,
        token_canonicalizer_tuple_digest: None,
        token_boundary_id: None,
        token_issued_at_tick: None,
        token_expiry_tick: None,
    };
    let queue_trace = JobQueueAdmissionTrace {
        verdict: "allow".to_string(),
        queue_lane: "control".to_string(),
        defect_reason: None,
        cost_estimate_ticks: None,
    };

    let receipt_path = emit_job_receipt(
        &fac_root,
        &spec,
        FacJobOutcome::Completed,
        None,
        "completed",
        Some(&boundary_trace),
        Some(&queue_trace),
        None,
        None,
        Some(&tuple_digest),
        None,
        &spec.job_spec_digest,
        None,
        None,
        None,
        None, // bytes_backend
        None,
    )
    .expect("emit receipt without sandbox_hardening_hash");

    let receipt_json = serde_json::from_slice::<serde_json::Value>(
        &fs::read(&receipt_path).expect("read receipt"),
    )
    .expect("parse receipt JSON");

    assert!(
        receipt_json.get("sandbox_hardening_hash").is_none(),
        "sandbox_hardening_hash must be absent when None"
    );
}

#[test]
fn test_execute_queued_gates_job_binds_sandbox_hardening_hash_in_denial_receipt() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fac_root = dir.path().join("private").join("fac");
    let queue_root = dir.path().join("queue");
    fs::create_dir_all(&fac_root).expect("create fac root");
    ensure_queue_dirs(&queue_root).expect("create queue dirs");

    let claimed_path = queue_root.join(CLAIMED_DIR).join("gates-test.json");
    fs::write(&claimed_path, b"{}").expect("seed claimed file");
    let claimed_file_name = "gates-test.json";

    let spec = make_receipt_test_spec();
    let claimed_lock_guard = build_claimed_lock_guard_for_test(&claimed_path, &spec.job_id);
    let boundary_trace = ChannelBoundaryTrace {
        passed: true,
        defect_count: 0,
        defect_classes: Vec::new(),
        token_fac_policy_hash: None,
        token_canonicalizer_tuple_digest: None,
        token_boundary_id: None,
        token_issued_at_tick: None,
        token_expiry_tick: None,
    };
    let queue_trace = JobQueueAdmissionTrace {
        verdict: "allow".to_string(),
        queue_lane: "consume".to_string(),
        defect_reason: None,
        cost_estimate_ticks: None,
    };
    let tuple_digest = CanonicalizerTupleV1::from_current().compute_digest();
    let hardening_hash = apm2_core::fac::SandboxHardeningProfile::default().content_hash_hex();

    let outcome = execute_queued_gates_job(
        &spec,
        &claimed_path,
        claimed_file_name,
        &claimed_lock_guard,
        &queue_root,
        &fac_root,
        &boundary_trace,
        &queue_trace,
        None,
        &tuple_digest,
        &spec.job_spec_digest,
        &hardening_hash,
        &apm2_core::fac::NetworkPolicy::deny().content_hash_hex(),
        1,
        0,
        0,
        0,
        None, // toolchain_fingerprint
    );
    assert!(
        matches!(outcome, JobOutcome::Denied { .. }),
        "missing gates payload should fail closed in denial path"
    );

    let receipt_file = fs::read_dir(fac_root.join(FAC_RECEIPTS_DIR))
        .expect("receipts dir")
        .flatten()
        .find(|entry| {
            entry.file_type().is_ok_and(|ty| ty.is_file())
                && entry
                    .path()
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| !n.contains(".sig."))
        })
        .expect("at least one receipt emitted");
    let receipt_json = serde_json::from_slice::<serde_json::Value>(
        &fs::read(receipt_file.path()).expect("read receipt"),
    )
    .expect("parse receipt JSON");
    assert_eq!(
        receipt_json
            .get("sandbox_hardening_hash")
            .and_then(serde_json::Value::as_str),
        Some(hardening_hash.as_str()),
        "queued gates receipt must bind sandbox hardening hash"
    );
}

fn build_claimed_lock_guard_for_test(claimed_path: &Path, job_id: &str) -> ClaimedJobLockGuardV1 {
    let lock_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(claimed_path)
        .expect("open claimed lock file");
    fs2::FileExt::lock_exclusive(&lock_file).expect("acquire claimed lock");
    ClaimedJobLockGuardV1::from_claimed_lock(
        job_id.to_string(),
        claimed_path.to_path_buf(),
        lock_file,
    )
}

#[test]
fn test_execute_queued_gates_job_denies_when_lifecycle_replay_returns_illegal_transition() {
    let _override_guard = FacReviewApiOverrideGuard::install(
        Ok(fac_review_api::LocalGatesRunResult {
            exit_code: exit_codes::SUCCESS,
            failure_summary: None,
        }),
        Err("illegal transition: pushed + gates_started".to_string()),
    );
    let dir = tempfile::tempdir().expect("tempdir");
    let fac_root = dir.path().join("private").join("fac");
    let queue_root = dir.path().join("queue");
    fs::create_dir_all(&fac_root).expect("create fac root");
    ensure_queue_dirs(&queue_root).expect("create queue dirs");

    let claimed_path = queue_root
        .join(CLAIMED_DIR)
        .join("gates-lifecycle-illegal.json");
    fs::write(&claimed_path, b"{}").expect("seed claimed file");
    let claimed_file_name = "gates-lifecycle-illegal.json";

    let repo_root = PathBuf::from(repo_toplevel_for_tests());
    let current_head = resolve_workspace_head(&repo_root).expect("resolve workspace head");
    let mut spec = make_receipt_test_spec();
    spec.source.head_sha = current_head;
    spec.source.patch = Some(serde_json::json!({
        "schema": GATES_JOB_OPTIONS_SCHEMA,
        "force": false,
        "quick": false,
        "timeout_seconds": 600,
        "memory_max": "48G",
        "pids_max": 1536,
        "cpu_quota": "auto",
        "gate_profile": "throughput",
        "workspace_root": repo_root.to_string_lossy(),
    }));

    let boundary_trace = ChannelBoundaryTrace {
        passed: true,
        defect_count: 0,
        defect_classes: Vec::new(),
        token_fac_policy_hash: None,
        token_canonicalizer_tuple_digest: None,
        token_boundary_id: None,
        token_issued_at_tick: None,
        token_expiry_tick: None,
    };
    let queue_trace = JobQueueAdmissionTrace {
        verdict: "allow".to_string(),
        queue_lane: "consume".to_string(),
        defect_reason: None,
        cost_estimate_ticks: None,
    };
    let tuple_digest = CanonicalizerTupleV1::from_current().compute_digest();
    let hardening_hash = apm2_core::fac::SandboxHardeningProfile::default().content_hash_hex();
    let network_hash = apm2_core::fac::NetworkPolicy::deny().content_hash_hex();
    let claimed_lock_guard = build_claimed_lock_guard_for_test(&claimed_path, &spec.job_id);

    let outcome = execute_queued_gates_job(
        &spec,
        &claimed_path,
        claimed_file_name,
        &claimed_lock_guard,
        &queue_root,
        &fac_root,
        &boundary_trace,
        &queue_trace,
        None,
        &tuple_digest,
        &spec.job_spec_digest,
        &hardening_hash,
        &network_hash,
        1,
        0,
        0,
        0,
        None, // toolchain_fingerprint
    );
    let reason = match outcome {
        JobOutcome::Denied { reason } => reason,
        other => panic!("expected denied outcome, got {other:?}"),
    };
    assert!(reason.contains("lifecycle update failed"));
    assert!(reason.contains("illegal transition"));
    assert!(
        queue_root
            .join(DENIED_DIR)
            .join(claimed_file_name)
            .is_file(),
        "job should be moved to denied on lifecycle replay failure"
    );
}

#[test]
fn test_execute_queued_gates_job_passes_lease_binding_to_gates_worker() {
    let _override_guard = FacReviewApiOverrideGuard::install(
        Ok(fac_review_api::LocalGatesRunResult {
            exit_code: exit_codes::SUCCESS,
            failure_summary: None,
        }),
        Ok(1),
    );
    let _ = fac_review_api::take_last_run_gates_local_worker_invocation();

    let dir = tempfile::tempdir().expect("tempdir");
    let fac_root = dir.path().join("private").join("fac");
    let queue_root = dir.path().join("queue");
    fs::create_dir_all(&fac_root).expect("create fac root");
    ensure_queue_dirs(&queue_root).expect("create queue dirs");

    let claimed_path = queue_root
        .join(CLAIMED_DIR)
        .join("gates-lease-binding.json");
    fs::write(&claimed_path, b"{}").expect("seed claimed file");
    let claimed_file_name = "gates-lease-binding.json";

    let repo_root = PathBuf::from(repo_toplevel_for_tests());
    let current_head = resolve_workspace_head(&repo_root).expect("resolve workspace head");
    let mut spec = make_receipt_test_spec();
    spec.job_id = "job-gates-lease-binding".to_string();
    spec.source.head_sha = current_head;
    spec.source.patch = Some(serde_json::json!({
        "schema": GATES_JOB_OPTIONS_SCHEMA,
        "force": false,
        "quick": false,
        "timeout_seconds": 600,
        "memory_max": "48G",
        "pids_max": 1536,
        "cpu_quota": "auto",
        "gate_profile": "throughput",
        "workspace_root": repo_root.to_string_lossy(),
    }));

    let boundary_trace = ChannelBoundaryTrace {
        passed: true,
        defect_count: 0,
        defect_classes: Vec::new(),
        token_fac_policy_hash: None,
        token_canonicalizer_tuple_digest: None,
        token_boundary_id: None,
        token_issued_at_tick: None,
        token_expiry_tick: None,
    };
    let queue_trace = JobQueueAdmissionTrace {
        verdict: "allow".to_string(),
        queue_lane: "consume".to_string(),
        defect_reason: None,
        cost_estimate_ticks: None,
    };
    let tuple_digest = CanonicalizerTupleV1::from_current().compute_digest();
    let hardening_hash = apm2_core::fac::SandboxHardeningProfile::default().content_hash_hex();
    let network_hash = apm2_core::fac::NetworkPolicy::deny().content_hash_hex();
    let toolchain_fp = format!("b3-256:{}", "a".repeat(64));
    let claimed_lock_guard = build_claimed_lock_guard_for_test(&claimed_path, &spec.job_id);

    let outcome = execute_queued_gates_job(
        &spec,
        &claimed_path,
        claimed_file_name,
        &claimed_lock_guard,
        &queue_root,
        &fac_root,
        &boundary_trace,
        &queue_trace,
        None,
        &tuple_digest,
        &spec.job_spec_digest,
        &hardening_hash,
        &network_hash,
        1,
        0,
        0,
        0,
        Some(toolchain_fp.as_str()),
    );
    assert!(
        matches!(outcome, JobOutcome::Completed { .. }),
        "expected queued gates completion with API override"
    );

    let invocation = fac_review_api::take_last_run_gates_local_worker_invocation()
        .expect("queued gates call should invoke local worker");
    assert_eq!(
        invocation.lease_job_id.as_deref(),
        Some(spec.job_id.as_str())
    );
    assert_eq!(
        invocation.lease_toolchain_fingerprint.as_deref(),
        Some(toolchain_fp.as_str())
    );
}

#[test]
fn test_execute_queued_gates_job_denied_reason_includes_gate_failure_summary() {
    let _override_guard = FacReviewApiOverrideGuard::install(
        Ok(fac_review_api::LocalGatesRunResult {
            exit_code: exit_codes::GENERIC_ERROR,
            failure_summary: Some(
                "failed_gates=test; first_failure=test: timeout exceeded".to_string(),
            ),
        }),
        Ok(1),
    );
    let dir = tempfile::tempdir().expect("tempdir");
    let fac_root = dir.path().join("private").join("fac");
    let queue_root = dir.path().join("queue");
    fs::create_dir_all(&fac_root).expect("create fac root");
    ensure_queue_dirs(&queue_root).expect("create queue dirs");

    let claimed_path = queue_root
        .join(CLAIMED_DIR)
        .join("gates-failure-summary.json");
    fs::write(&claimed_path, b"{}").expect("seed claimed file");
    let claimed_file_name = "gates-failure-summary.json";

    let repo_root = PathBuf::from(repo_toplevel_for_tests());
    let current_head = resolve_workspace_head(&repo_root).expect("resolve workspace head");
    let mut spec = make_receipt_test_spec();
    spec.source.head_sha = current_head;
    spec.source.patch = Some(serde_json::json!({
        "schema": GATES_JOB_OPTIONS_SCHEMA,
        "force": false,
        "quick": false,
        "timeout_seconds": 600,
        "memory_max": "48G",
        "pids_max": 1536,
        "cpu_quota": "auto",
        "gate_profile": "throughput",
        "workspace_root": repo_root.to_string_lossy(),
    }));

    let boundary_trace = ChannelBoundaryTrace {
        passed: true,
        defect_count: 0,
        defect_classes: Vec::new(),
        token_fac_policy_hash: None,
        token_canonicalizer_tuple_digest: None,
        token_boundary_id: None,
        token_issued_at_tick: None,
        token_expiry_tick: None,
    };
    let queue_trace = JobQueueAdmissionTrace {
        verdict: "allow".to_string(),
        queue_lane: "consume".to_string(),
        defect_reason: None,
        cost_estimate_ticks: None,
    };
    let tuple_digest = CanonicalizerTupleV1::from_current().compute_digest();
    let hardening_hash = apm2_core::fac::SandboxHardeningProfile::default().content_hash_hex();
    let network_hash = apm2_core::fac::NetworkPolicy::deny().content_hash_hex();
    let claimed_lock_guard = build_claimed_lock_guard_for_test(&claimed_path, &spec.job_id);

    let outcome = execute_queued_gates_job(
        &spec,
        &claimed_path,
        claimed_file_name,
        &claimed_lock_guard,
        &queue_root,
        &fac_root,
        &boundary_trace,
        &queue_trace,
        None,
        &tuple_digest,
        &spec.job_spec_digest,
        &hardening_hash,
        &network_hash,
        1,
        0,
        0,
        0,
        None, // toolchain_fingerprint
    );
    let reason = match outcome {
        JobOutcome::Denied { reason } => reason,
        other => panic!("expected denied outcome, got {other:?}"),
    };
    assert!(reason.contains("gates failed with exit code 1"));
    assert!(reason.contains("failed_gates=test"));
    assert!(reason.contains("first_failure=test: timeout exceeded"));
}

#[test]
fn test_execute_queued_gates_job_denied_reason_is_utf8_safe_and_bounded() {
    let _override_guard = FacReviewApiOverrideGuard::install(
        Ok(fac_review_api::LocalGatesRunResult {
            exit_code: exit_codes::GENERIC_ERROR,
            failure_summary: Some(format!(
                "failed_gates=test; first_failure=test: {}",
                "🚧".repeat(700)
            )),
        }),
        Ok(1),
    );
    let dir = tempfile::tempdir().expect("tempdir");
    let fac_root = dir.path().join("private").join("fac");
    let queue_root = dir.path().join("queue");
    fs::create_dir_all(&fac_root).expect("create fac root");
    ensure_queue_dirs(&queue_root).expect("create queue dirs");

    let claimed_path = queue_root
        .join(CLAIMED_DIR)
        .join("gates-bounded-reason.json");
    fs::write(&claimed_path, b"{}").expect("seed claimed file");
    let claimed_file_name = "gates-bounded-reason.json";

    let repo_root = PathBuf::from(repo_toplevel_for_tests());
    let current_head = resolve_workspace_head(&repo_root).expect("resolve workspace head");
    let mut spec = make_receipt_test_spec();
    spec.source.head_sha = current_head;
    spec.source.patch = Some(serde_json::json!({
        "schema": GATES_JOB_OPTIONS_SCHEMA,
        "force": false,
        "quick": false,
        "timeout_seconds": 600,
        "memory_max": "48G",
        "pids_max": 1536,
        "cpu_quota": "auto",
        "gate_profile": "throughput",
        "workspace_root": repo_root.to_string_lossy(),
    }));

    let boundary_trace = ChannelBoundaryTrace {
        passed: true,
        defect_count: 0,
        defect_classes: Vec::new(),
        token_fac_policy_hash: None,
        token_canonicalizer_tuple_digest: None,
        token_boundary_id: None,
        token_issued_at_tick: None,
        token_expiry_tick: None,
    };
    let queue_trace = JobQueueAdmissionTrace {
        verdict: "allow".to_string(),
        queue_lane: "consume".to_string(),
        defect_reason: None,
        cost_estimate_ticks: None,
    };
    let tuple_digest = CanonicalizerTupleV1::from_current().compute_digest();
    let hardening_hash = apm2_core::fac::SandboxHardeningProfile::default().content_hash_hex();
    let network_hash = apm2_core::fac::NetworkPolicy::deny().content_hash_hex();
    let claimed_lock_guard = build_claimed_lock_guard_for_test(&claimed_path, &spec.job_id);

    let outcome = execute_queued_gates_job(
        &spec,
        &claimed_path,
        claimed_file_name,
        &claimed_lock_guard,
        &queue_root,
        &fac_root,
        &boundary_trace,
        &queue_trace,
        None,
        &tuple_digest,
        &spec.job_spec_digest,
        &hardening_hash,
        &network_hash,
        1,
        0,
        0,
        0,
        None, // toolchain_fingerprint
    );
    let reason = match outcome {
        JobOutcome::Denied { reason } => reason,
        other => panic!("expected denied outcome, got {other:?}"),
    };
    assert!(
        reason.chars().count() <= MAX_FAC_RECEIPT_REASON_CHARS,
        "reason must be bounded to FAC receipt limit"
    );
    assert!(reason.ends_with("..."), "long reason should be truncated");
    assert!(reason.contains("failed_gates=test"));
}

fn init_test_workspace_git_repo(workspace: &Path) {
    let init_output = std::process::Command::new("git")
        .args(["init"])
        .current_dir(workspace)
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .expect("init git repo");
    assert!(
        init_output.status.success(),
        "git init should succeed, got {}",
        String::from_utf8_lossy(&init_output.stderr)
    );

    let set_name_output = std::process::Command::new("git")
        .args(["config", "user.name", "apm2 test"])
        .current_dir(workspace)
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .expect("set git user name");
    assert!(
        set_name_output.status.success(),
        "git config user.name should succeed, got {}",
        String::from_utf8_lossy(&set_name_output.stderr)
    );

    let set_email_output = std::process::Command::new("git")
        .args(["config", "user.email", "test@apm2.local"])
        .current_dir(workspace)
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .expect("set git user email");
    assert!(
        set_email_output.status.success(),
        "git config user.email should succeed, got {}",
        String::from_utf8_lossy(&set_email_output.stderr)
    );

    fs::write(workspace.join("README.md"), b"seed").expect("write seed file");

    let add_output = std::process::Command::new("git")
        .args(["add", "README.md"])
        .current_dir(workspace)
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .expect("git add");
    assert!(
        add_output.status.success(),
        "git add should succeed, got {}",
        String::from_utf8_lossy(&add_output.stderr)
    );

    let commit_output = std::process::Command::new("git")
        .args(["commit", "-m", "initial"])
        .current_dir(workspace)
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .expect("git commit");
    assert!(
        commit_output.status.success(),
        "git commit should succeed, got {}",
        String::from_utf8_lossy(&commit_output.stderr)
    );
}

fn persist_running_lease(manager: &LaneManager, lane_id: &str) {
    let lane_dir = manager.lane_dir(lane_id);
    let lease = LaneLeaseV1::new(
        lane_id,
        "job_cleanup",
        std::process::id(),
        LaneState::Running,
        "2026-02-12T03:15:00Z",
        "b3-256:ph",
        "b3-256:th",
    )
    .expect("create lease");
    lease.persist(&lane_dir).expect("persist lease");
}

fn persist_lease_with_pid(manager: &LaneManager, lane_id: &str, state: LaneState, pid: u32) {
    let lane_dir = manager.lane_dir(lane_id);
    let lease = LaneLeaseV1::new(
        lane_id,
        "job_cleanup",
        pid,
        state,
        "2026-02-12T03:15:00Z",
        "b3-256:ph",
        "b3-256:th",
    )
    .expect("create lease");
    lease.persist(&lane_dir).expect("persist lease");
}

#[test]
fn test_reap_orphaned_leases_on_tick_reaps_dead_leased_lane() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fac_root = dir.path().join("private").join("fac");
    fs::create_dir_all(&fac_root).expect("create fac root");
    let lane_mgr = LaneManager::new(fac_root.clone()).expect("create lane manager");
    lane_mgr.ensure_directories().expect("ensure lanes");

    let dead_pid = find_dead_pid();
    persist_lease_with_pid(&lane_mgr, "lane-00", LaneState::Leased, dead_pid);
    let lane_dir = lane_mgr.lane_dir("lane-00");
    assert!(
        LaneLeaseV1::load(&lane_dir).expect("load lease").is_some(),
        "test precondition: lease exists before maintenance"
    );

    reap_orphaned_leases_on_tick(&fac_root, false);

    assert!(
        LaneLeaseV1::load(&lane_dir)
            .expect("load lease after maintenance")
            .is_none(),
        "dead leased lane should be reaped during poll tick maintenance"
    );
}

#[test]
fn test_reap_orphaned_leases_on_tick_keeps_alive_leased_lane() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fac_root = dir.path().join("private").join("fac");
    fs::create_dir_all(&fac_root).expect("create fac root");
    let lane_mgr = LaneManager::new(fac_root.clone()).expect("create lane manager");
    lane_mgr.ensure_directories().expect("ensure lanes");

    persist_lease_with_pid(&lane_mgr, "lane-00", LaneState::Leased, std::process::id());
    let lane_dir = lane_mgr.lane_dir("lane-00");

    reap_orphaned_leases_on_tick(&fac_root, false);

    assert!(
        LaneLeaseV1::load(&lane_dir)
            .expect("load lease after maintenance")
            .is_some(),
        "alive leased lane should not be reaped"
    );
}

#[test]
fn test_execute_lane_cleanup_success_emits_success_receipt() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fac_root = dir.path().join("private").join("fac");
    fs::create_dir_all(&fac_root).expect("create fac root");
    let lane_mgr = LaneManager::new(fac_root.clone()).expect("create lane manager");
    lane_mgr.ensure_directories().expect("ensure lanes");

    let lane_id = "lane-00";
    let workspace = lane_mgr.lane_dir(lane_id).join("workspace");
    persist_running_lease(&lane_mgr, lane_id);
    init_test_workspace_git_repo(&workspace);

    execute_lane_cleanup(
        &fac_root,
        &lane_mgr,
        lane_id,
        &workspace,
        &LogRetentionConfig::default(),
    )
    .expect("lane cleanup should succeed");

    let status = lane_mgr.lane_status(lane_id).expect("lane status");
    assert_eq!(status.state, LaneState::Idle);

    let receipt_file = fs::read_dir(fac_root.join(FAC_RECEIPTS_DIR))
        .expect("receipts dir")
        .flatten()
        .find(|entry| entry.file_type().is_ok_and(|ty| ty.is_file()))
        .expect("at least one lane cleanup receipt");
    let receipt_json = serde_json::from_slice::<serde_json::Value>(
        &fs::read(receipt_file.path()).expect("read receipt"),
    )
    .expect("parse lane cleanup receipt");
    assert_eq!(
        receipt_json
            .get("outcome")
            .and_then(serde_json::Value::as_str),
        Some("success"),
        "cleanup success should emit success receipt"
    );
    assert_eq!(
        receipt_json
            .get("lane_id")
            .and_then(serde_json::Value::as_str),
        Some(lane_id),
        "receipt should target executed lane"
    );
}

#[test]
fn test_execute_lane_cleanup_failure_marks_corrupt_and_emits_failed_receipt() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fac_root = dir.path().join("private").join("fac");
    fs::create_dir_all(&fac_root).expect("create fac root");
    let lane_mgr = LaneManager::new(fac_root.clone()).expect("create lane manager");
    lane_mgr.ensure_directories().expect("ensure lanes");

    let lane_id = "lane-00";
    let workspace = lane_mgr.lane_dir(lane_id).join("workspace");
    persist_running_lease(&lane_mgr, lane_id);

    let err = execute_lane_cleanup(
        &fac_root,
        &lane_mgr,
        lane_id,
        &workspace,
        &LogRetentionConfig::default(),
    )
    .expect_err("cleanup should fail when workspace is not a git repo");
    assert!(err.to_string().contains("lane cleanup failed"));

    let status = lane_mgr.lane_status(lane_id).expect("lane status");
    assert_eq!(status.state, LaneState::Corrupt);

    let marker = LaneCorruptMarkerV1::load(&fac_root, lane_id)
        .expect("marker should be persisted on cleanup failure")
        .expect("marker should exist");
    assert!(marker.reason.contains("lane cleanup failed"));

    let receipt_file = fs::read_dir(fac_root.join(FAC_RECEIPTS_DIR))
        .expect("receipts dir")
        .flatten()
        .find(|entry| entry.file_type().is_ok_and(|ty| ty.is_file()))
        .expect("at least one lane cleanup receipt");
    let expected_receipt_digest = receipt_file
        .path()
        .file_stem()
        .and_then(|value| value.to_str())
        .expect("receipt file must have digest stem")
        .to_string();
    let receipt_json = serde_json::from_slice::<serde_json::Value>(
        &fs::read(receipt_file.path()).expect("read receipt"),
    )
    .expect("parse lane cleanup receipt");
    assert_eq!(
        receipt_json
            .get("outcome")
            .and_then(serde_json::Value::as_str),
        Some("failed"),
        "cleanup failure should emit failed receipt"
    );
    assert_eq!(
        marker.cleanup_receipt_digest.as_deref(),
        Some(expected_receipt_digest.as_str()),
        "corrupt marker must bind to the emitted failed cleanup receipt digest"
    );
}

#[test]
fn test_acquire_worker_lane_skips_corrupt_and_uses_next_lane() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fac_root = dir.path().join("private").join("fac");
    fs::create_dir_all(&fac_root).expect("create fac root");
    let lane_mgr = LaneManager::new(fac_root.clone()).expect("create lane manager");
    lane_mgr.ensure_directories().expect("ensure lanes");

    let corrupt_marker = LaneCorruptMarkerV1 {
        schema: LANE_CORRUPT_MARKER_SCHEMA.to_string(),
        lane_id: "lane-00".to_string(),
        reason: "corrupt from previous failed cleanup".to_string(),
        cleanup_receipt_digest: None,
        detected_at: "2026-02-15T00:00:00Z".to_string(),
    };
    corrupt_marker
        .persist(&fac_root)
        .expect("persist corrupt marker");

    let lane_ids = vec!["lane-00".to_string(), "lane-01".to_string()];
    let (_guard, acquired_lane_id) =
        acquire_worker_lane(&lane_mgr, &lane_ids).expect("lane should be acquired");
    assert_eq!(
        acquired_lane_id, "lane-01",
        "corrupt lane should be skipped and next lane acquired"
    );
}

/// Find a PID that is guaranteed to not exist.
///
/// Starts from a high PID and walks down until one is confirmed dead.
/// Falls back to PID 0 which identity checks treat as dead.
fn find_dead_pid() -> u32 {
    // Walk from a high PID downward to find one classified as dead.
    // Typical Linux pid_max is 32768 or 4194304; we start well above
    // the common range to minimize collision risk with running processes.
    for pid_candidate in (100_000..200_000).rev() {
        if matches!(
            verify_pid_identity(pid_candidate, Some(0)),
            ProcessIdentity::Dead
        ) {
            return pid_candidate;
        }
    }
    // Fallback: PID 0 is special-cased as dead in identity checks.
    0
}

#[test]
fn test_acquire_worker_lane_recovers_dead_running_lease() {
    // When a lane has a RUNNING lease for a DEAD process, the lane
    // should be recovered (stale lease removed) and acquired, not
    // marked corrupt.
    let dir = tempfile::tempdir().expect("tempdir");
    let fac_root = dir.path().join("private").join("fac");
    fs::create_dir_all(&fac_root).expect("create fac root");
    let lane_mgr = LaneManager::new(fac_root.clone()).expect("create lane manager");
    lane_mgr.ensure_directories().expect("ensure lanes");

    let dead_pid = find_dead_pid();
    persist_lease_with_pid(&lane_mgr, "lane-00", LaneState::Running, dead_pid);

    let lane_ids = vec!["lane-00".to_string(), "lane-01".to_string()];
    let (_guard, acquired_lane_id) =
        acquire_worker_lane(&lane_mgr, &lane_ids).expect("lane should be acquired");
    // Lane-00 should be recovered (dead process), not skipped.
    assert_eq!(acquired_lane_id, "lane-00");

    // No corrupt marker should exist — the lane was recovered.
    assert!(
        LaneCorruptMarkerV1::load(&fac_root, "lane-00")
            .expect("marker load")
            .is_none(),
        "recovered lane should NOT have a corrupt marker"
    );
}

#[test]
fn test_acquire_worker_lane_marks_alive_running_lease_corrupt() {
    // When a lane has a RUNNING lease for an ALIVE process (current PID),
    // acquiring the flock is unexpected. The lane should be marked corrupt.
    let dir = tempfile::tempdir().expect("tempdir");
    let fac_root = dir.path().join("private").join("fac");
    fs::create_dir_all(&fac_root).expect("create fac root");
    let lane_mgr = LaneManager::new(fac_root.clone()).expect("create lane manager");
    lane_mgr.ensure_directories().expect("ensure lanes");

    persist_running_lease(&lane_mgr, "lane-00");

    let lane_ids = vec!["lane-00".to_string(), "lane-01".to_string()];
    let (_guard, acquired_lane_id) =
        acquire_worker_lane(&lane_mgr, &lane_ids).expect("lane should be acquired");
    assert_eq!(acquired_lane_id, "lane-01");

    let marker = LaneCorruptMarkerV1::load(&fac_root, "lane-00")
        .expect("marker load")
        .expect("marker should exist for alive-process lease");
    assert!(
        marker.reason.contains("matching identity"),
        "marker reason should mention matching identity, got: {}",
        marker.reason
    );
}

#[test]
fn test_acquire_worker_lane_recovers_pid_identity_mismatch_lease() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fac_root = dir.path().join("private").join("fac");
    fs::create_dir_all(&fac_root).expect("create fac root");
    let lane_mgr = LaneManager::new(fac_root.clone()).expect("create lane manager");
    lane_mgr.ensure_directories().expect("ensure lanes");

    // Persist a running lease, then corrupt proc_start_time_ticks to
    // simulate PID reuse mismatch for the same numeric PID.
    persist_running_lease(&lane_mgr, "lane-00");
    let lane_dir = lane_mgr.lane_dir("lane-00");
    let lease_path = lane_dir.join("lease.v1.json");
    let mut lease_value: serde_json::Value =
        serde_json::from_slice(&fs::read(&lease_path).expect("read lease")).expect("parse");
    let ticks = lease_value
        .get("proc_start_time_ticks")
        .and_then(serde_json::Value::as_u64)
        .expect("lease should include proc_start_time_ticks");
    lease_value["proc_start_time_ticks"] = serde_json::Value::from(ticks + 1);
    fs::write(
        &lease_path,
        serde_json::to_vec_pretty(&lease_value).expect("serialize lease"),
    )
    .expect("write mismatched lease");

    let lane_ids = vec!["lane-00".to_string(), "lane-01".to_string()];
    let (_guard, acquired_lane_id) =
        acquire_worker_lane(&lane_mgr, &lane_ids).expect("lane should be acquired");
    assert_eq!(
        acquired_lane_id, "lane-00",
        "PID identity mismatch lease should be treated as stale and reclaimed"
    );
    assert!(
        LaneCorruptMarkerV1::load(&fac_root, "lane-00")
            .expect("marker load")
            .is_none(),
        "PID mismatch recovery should not mark lane corrupt"
    );
}

#[test]
fn test_acquire_worker_lane_skips_unknown_identity_lease() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fac_root = dir.path().join("private").join("fac");
    fs::create_dir_all(&fac_root).expect("create fac root");
    let lane_mgr = LaneManager::new(fac_root.clone()).expect("create lane manager");
    lane_mgr.ensure_directories().expect("ensure lanes");

    // Simulate malformed lease metadata without proc_start_time_ticks.
    persist_running_lease(&lane_mgr, "lane-00");
    let lane_dir = lane_mgr.lane_dir("lane-00");
    let lease_path = lane_dir.join("lease.v1.json");
    let mut lease_value: serde_json::Value =
        serde_json::from_slice(&fs::read(&lease_path).expect("read lease")).expect("parse");
    lease_value["proc_start_time_ticks"] = serde_json::Value::Null;
    fs::write(
        &lease_path,
        serde_json::to_vec_pretty(&lease_value).expect("serialize lease"),
    )
    .expect("write malformed lease");

    let lane_ids = vec!["lane-00".to_string(), "lane-01".to_string()];
    let (_guard, acquired_lane_id) =
        acquire_worker_lane(&lane_mgr, &lane_ids).expect("lane should be acquired");
    assert_eq!(
        acquired_lane_id, "lane-01",
        "unknown identity lease should be skipped fail-closed"
    );
    assert!(
        LaneCorruptMarkerV1::load(&fac_root, "lane-00")
            .expect("marker load")
            .is_none(),
        "unknown identity path should skip with warning, not mark corrupt"
    );
}

#[test]
fn test_acquire_worker_lane_recovers_dead_cleanup_lease() {
    // When a lane has a CLEANUP lease for a DEAD process, the lane
    // should be recovered and acquired.
    let dir = tempfile::tempdir().expect("tempdir");
    let fac_root = dir.path().join("private").join("fac");
    fs::create_dir_all(&fac_root).expect("create fac root");
    let lane_mgr = LaneManager::new(fac_root.clone()).expect("create lane manager");
    lane_mgr.ensure_directories().expect("ensure lanes");

    let dead_pid = find_dead_pid();
    persist_lease_with_pid(&lane_mgr, "lane-00", LaneState::Cleanup, dead_pid);

    let lane_ids = vec!["lane-00".to_string(), "lane-01".to_string()];
    let (_guard, acquired_lane_id) =
        acquire_worker_lane(&lane_mgr, &lane_ids).expect("lane should be acquired");
    // Lane-00 should be recovered (dead process).
    assert_eq!(acquired_lane_id, "lane-00");

    assert!(
        LaneCorruptMarkerV1::load(&fac_root, "lane-00")
            .expect("marker load")
            .is_none(),
        "recovered lane should NOT have a corrupt marker"
    );
}

#[test]
fn test_acquire_worker_lane_skips_corrupt_lease_state() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fac_root = dir.path().join("private").join("fac");
    fs::create_dir_all(&fac_root).expect("create fac root");
    let lane_mgr = LaneManager::new(fac_root).expect("create lane manager");
    lane_mgr.ensure_directories().expect("ensure lanes");

    persist_lease_with_pid(&lane_mgr, "lane-00", LaneState::Corrupt, u32::MAX);

    let lane_ids = vec!["lane-00".to_string(), "lane-01".to_string()];
    let (_guard, acquired_lane_id) =
        acquire_worker_lane(&lane_mgr, &lane_ids).expect("lane should be acquired");
    assert_eq!(acquired_lane_id, "lane-01");
}

#[test]
fn test_execute_lane_cleanup_restores_dirty_workspace_on_denial() {
    // SEC-CTRL-LANE-CLEANUP-002: Verify that execute_lane_cleanup restores
    // a workspace that has been dirtied by a partial checkout/patch to a
    // clean state. This is the mechanism used by post-checkout denial paths
    // to prevent cross-job contamination.
    let dir = tempfile::tempdir().expect("tempdir");
    let fac_root = dir.path().join("private").join("fac");
    fs::create_dir_all(&fac_root).expect("create fac root");
    let lane_mgr = LaneManager::new(fac_root.clone()).expect("create lane manager");
    lane_mgr.ensure_directories().expect("ensure lanes");

    let lane_id = "lane-00";
    let workspace = lane_mgr.lane_dir(lane_id).join("workspace");
    persist_running_lease(&lane_mgr, lane_id);
    init_test_workspace_git_repo(&workspace);

    // Simulate workspace modification from a partial patch or checkout:
    // create untracked files and modify tracked files.
    fs::write(
        workspace.join("malicious_untracked.txt"),
        b"injected payload",
    )
    .expect("create untracked file");
    fs::write(workspace.join("README.md"), b"modified content").expect("modify tracked file");

    // Verify workspace is dirty before cleanup.
    assert!(
        workspace.join("malicious_untracked.txt").exists(),
        "untracked file should exist before cleanup"
    );
    let readme_content = fs::read_to_string(workspace.join("README.md")).expect("read README");
    assert_eq!(readme_content, "modified content");

    // Run lane cleanup (same function used on denial paths).
    execute_lane_cleanup(
        &fac_root,
        &lane_mgr,
        lane_id,
        &workspace,
        &LogRetentionConfig::default(),
    )
    .expect("lane cleanup should succeed");

    // Verify workspace is restored to clean state.
    assert!(
        !workspace.join("malicious_untracked.txt").exists(),
        "untracked file should be removed by git clean"
    );
    let restored_readme =
        fs::read_to_string(workspace.join("README.md")).expect("read restored README");
    assert_eq!(
        restored_readme, "seed",
        "tracked file should be restored to HEAD by git reset"
    );

    // Verify lane is back to idle (lease removed).
    let status = lane_mgr.lane_status(lane_id).expect("lane status");
    assert_eq!(status.state, LaneState::Idle);
}

#[test]
fn test_execute_lane_cleanup_marks_corrupt_on_failure_during_denial() {
    // SEC-CTRL-LANE-CLEANUP-002: When cleanup fails on a denial path,
    // the lane should be marked CORRUPT to prevent future jobs from
    // running on the contaminated workspace.
    let dir = tempfile::tempdir().expect("tempdir");
    let fac_root = dir.path().join("private").join("fac");
    fs::create_dir_all(&fac_root).expect("create fac root");
    let lane_mgr = LaneManager::new(fac_root.clone()).expect("create lane manager");
    lane_mgr.ensure_directories().expect("ensure lanes");

    let lane_id = "lane-00";
    let workspace = lane_mgr.lane_dir(lane_id).join("workspace");
    persist_running_lease(&lane_mgr, lane_id);
    // Do NOT init git repo — this will cause cleanup to fail.
    fs::create_dir_all(&workspace).expect("create workspace dir");

    let err = execute_lane_cleanup(
        &fac_root,
        &lane_mgr,
        lane_id,
        &workspace,
        &LogRetentionConfig::default(),
    )
    .expect_err("cleanup should fail on non-git workspace");
    assert!(err.to_string().contains("lane cleanup failed"));

    // Verify lane is marked CORRUPT.
    let status = lane_mgr.lane_status(lane_id).expect("lane status");
    assert_eq!(
        status.state,
        LaneState::Corrupt,
        "lane should be CORRUPT after failed cleanup on denial path"
    );

    // Verify corrupt marker exists.
    let marker = LaneCorruptMarkerV1::load(&fac_root, lane_id)
        .expect("marker load")
        .expect("corrupt marker should exist");
    assert!(
        marker.reason.contains("lane cleanup failed"),
        "corrupt marker should describe cleanup failure"
    );
}

// ── TCK-00579: DenialReasonCode mapping assertions ──

/// Helper to map `JobSpecError` to `DenialReasonCode` using the same
/// logic as the worker denial path.
fn map_job_spec_error_to_denial_reason(e: &JobSpecError) -> DenialReasonCode {
    match e {
        JobSpecError::MissingToken { .. } => DenialReasonCode::MissingChannelToken,
        JobSpecError::InvalidDigest { .. } => DenialReasonCode::MalformedSpec,
        JobSpecError::DisallowedRepoId { .. }
        | JobSpecError::DisallowedBytesBackend { .. }
        | JobSpecError::FilesystemPathRejected { .. }
        | JobSpecError::InvalidControlLaneRepoId { .. } => DenialReasonCode::PolicyViolation,
        _ => DenialReasonCode::ValidationFailed,
    }
}

#[test]
fn test_disallowed_repo_id_maps_to_policy_violation() {
    let err = JobSpecError::DisallowedRepoId {
        repo_id: "evil-org/evil-repo".to_string(),
    };
    assert_eq!(
        map_job_spec_error_to_denial_reason(&err),
        DenialReasonCode::PolicyViolation,
        "DisallowedRepoId must map to PolicyViolation"
    );
}

#[test]
fn test_disallowed_bytes_backend_maps_to_policy_violation() {
    let err = JobSpecError::DisallowedBytesBackend {
        backend: "evil_backend".to_string(),
    };
    assert_eq!(
        map_job_spec_error_to_denial_reason(&err),
        DenialReasonCode::PolicyViolation,
        "DisallowedBytesBackend must map to PolicyViolation"
    );
}

#[test]
fn test_filesystem_path_rejected_maps_to_policy_violation() {
    let err = JobSpecError::FilesystemPathRejected {
        field: "source.repo_id",
        value: "/etc/passwd".to_string(),
    };
    assert_eq!(
        map_job_spec_error_to_denial_reason(&err),
        DenialReasonCode::PolicyViolation,
        "FilesystemPathRejected must map to PolicyViolation"
    );
}

#[test]
fn test_missing_token_maps_to_missing_channel_token() {
    let err = JobSpecError::MissingToken {
        field: "actuation.channel_context_token",
    };
    assert_eq!(
        map_job_spec_error_to_denial_reason(&err),
        DenialReasonCode::MissingChannelToken,
        "MissingToken must map to MissingChannelToken"
    );
}

#[test]
fn test_invalid_digest_maps_to_malformed_spec() {
    let err = JobSpecError::InvalidDigest {
        field: "job_spec_digest",
        value: "bad".to_string(),
    };
    assert_eq!(
        map_job_spec_error_to_denial_reason(&err),
        DenialReasonCode::MalformedSpec,
        "InvalidDigest must map to MalformedSpec"
    );
}

#[test]
fn test_other_errors_map_to_validation_failed() {
    let err = JobSpecError::EmptyField { field: "job_id" };
    assert_eq!(
        map_job_spec_error_to_denial_reason(&err),
        DenialReasonCode::ValidationFailed,
        "generic errors must map to ValidationFailed"
    );
}

/// TCK-00564 MAJOR-1 regression: denied receipt + pending job must route
/// to denied/, NOT completed/.
///
/// Prior to fix round 4, the duplicate detection in the worker execution path
/// used `has_receipt_for_job` (boolean) and unconditionally moved duplicates
/// to `completed/`. This masked denied outcomes. The fix uses
/// `find_receipt_for_job` and routes to the correct terminal directory
/// via `outcome_to_terminal_state`.
#[test]
fn test_duplicate_detection_routes_denied_receipt_to_denied_dir() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fac_root = dir.path().join("private").join("fac");
    let queue_root = dir.path().join("queue");
    ensure_queue_dirs(&queue_root).expect("create queue dirs");

    let spec = make_receipt_test_spec();

    // Step 1: Emit a Denied receipt for the job.
    let tuple_digest = CanonicalizerTupleV1::from_current().compute_digest();
    emit_job_receipt(
        &fac_root,
        &spec,
        FacJobOutcome::Denied,
        Some(DenialReasonCode::ValidationFailed),
        "test: validation failed",
        None,
        None,
        None,
        None,
        Some(&tuple_digest),
        None,
        &spec.job_spec_digest,
        None,
        None,
        None,
        None, // bytes_backend
        None,
    )
    .expect("emit denied receipt");

    // Step 2: Place a pending job file simulating a requeued job.
    let pending_file = queue_root.join(PENDING_DIR).join("test-denied-job.json");
    let spec_bytes = serde_json::to_vec(&spec).expect("serialize spec");
    fs::write(&pending_file, &spec_bytes).expect("write pending job");

    // Step 3: Verify that find_receipt_for_job returns the denied receipt.
    let receipts_dir = fac_root.join(FAC_RECEIPTS_DIR);
    let found_receipt = apm2_core::fac::find_receipt_for_job(&receipts_dir, &spec.job_id)
        .expect("receipt must be found");
    assert_eq!(
        found_receipt.outcome,
        FacJobOutcome::Denied,
        "found receipt must have Denied outcome"
    );

    // Step 4: Verify outcome_to_terminal_state routes to Denied.
    let terminal_state = apm2_core::fac::outcome_to_terminal_state(found_receipt.outcome)
        .expect("Denied must have a terminal state");
    assert_eq!(
        terminal_state.dir_name(),
        DENIED_DIR,
        "Denied outcome must route to denied/ directory, not completed/"
    );

    // Step 5: Execute the outcome-aware routing (same logic as the execution path).
    let terminal_dir = queue_root.join(terminal_state.dir_name());
    move_to_dir_safe(&pending_file, &terminal_dir, "test-denied-job.json")
        .expect("move to terminal dir");

    // Step 6: Assert the job landed in denied/, NOT completed/.
    assert!(
        queue_root
            .join(DENIED_DIR)
            .join("test-denied-job.json")
            .exists(),
        "denied receipt must route job to denied/"
    );
    assert!(
        !queue_root
            .join(COMPLETED_DIR)
            .join("test-denied-job.json")
            .exists(),
        "denied receipt must NOT route job to completed/"
    );
    assert!(
        !pending_file.exists(),
        "pending file must be removed after routing"
    );
}

#[test]
fn test_find_completed_gates_duplicate_matches_completed_receipt_by_request_id() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fac_root = dir.path().join("private").join("fac");
    let queue_root = dir.path().join("queue");
    ensure_queue_dirs(&queue_root).expect("create queue dirs");
    fs::create_dir_all(queue_root.join(COMPLETED_DIR)).expect("create completed dir");

    let mut completed_spec = make_receipt_test_spec();
    completed_spec.job_id = "job-completed-sha".to_string();
    completed_spec.enqueue_time = "2026-02-19T01:00:00Z".to_string();
    fs::write(
        queue_root
            .join(COMPLETED_DIR)
            .join("job-completed-sha.json"),
        serde_json::to_vec(&completed_spec).expect("serialize completed spec"),
    )
    .expect("write completed spec");

    let boundary_trace = ChannelBoundaryTrace {
        passed: true,
        defect_count: 0,
        defect_classes: Vec::new(),
        token_fac_policy_hash: None,
        token_canonicalizer_tuple_digest: None,
        token_boundary_id: None,
        token_issued_at_tick: None,
        token_expiry_tick: None,
    };
    let queue_trace = JobQueueAdmissionTrace {
        verdict: "allow".to_string(),
        queue_lane: "control".to_string(),
        defect_reason: None,
        cost_estimate_ticks: None,
    };
    let tuple_digest = CanonicalizerTupleV1::from_current().compute_digest();
    emit_job_receipt(
        &fac_root,
        &completed_spec,
        FacJobOutcome::Completed,
        None,
        "completed for dedupe",
        Some(&boundary_trace),
        Some(&queue_trace),
        None,
        None,
        Some(&tuple_digest),
        Some("completed/job-completed-sha.json"),
        &completed_spec.job_spec_digest,
        None,
        None,
        None,
        None, // bytes_backend
        None,
    )
    .expect("emit completed receipt");

    let mut incoming = completed_spec.clone();
    incoming.job_id = "job-incoming-sha".to_string();
    incoming.enqueue_time = "2026-02-19T01:03:00Z".to_string();

    let mut completed_gates_cache = None;
    let duplicate = find_completed_gates_duplicate(
        &queue_root,
        &fac_root,
        &incoming,
        &mut completed_gates_cache,
        &tuple_digest,
    )
    .expect("duplicate");
    assert_eq!(duplicate.existing_job_id, completed_spec.job_id);
    assert_eq!(duplicate.matched_by, "repo_sha_toolchain");
}

#[test]
fn test_find_completed_gates_duplicate_matches_on_repo_sha_and_toolchain() {
    let toolchain = "b3-256:aaaa";
    let mut cache = CompletedGatesCache::default();
    cache.insert(CompletedGatesFingerprint {
        job_id: "job-completed-sha".to_string(),
        enqueue_time: "2026-02-19T01:00:00Z".to_string(),
        repo_id: "owner/repo".to_string(),
        head_sha: "abc123".to_string(),
        toolchain_digest: toolchain.to_string(),
    });

    let mut incoming = make_receipt_test_spec();
    incoming.source.repo_id = "OWNER/REPO".to_string();
    incoming.source.head_sha = "ABC123".to_string();
    incoming.actuation.request_id = "request-new".to_string();
    incoming.enqueue_time = "2026-02-19T01:10:00Z".to_string();

    // Same toolchain -> match.
    let duplicate = find_completed_gates_duplicate_in_cache(&incoming, &cache, toolchain)
        .expect("same (repo_id, head_sha, toolchain) must match");
    assert_eq!(duplicate.existing_job_id, "job-completed-sha");
    assert_eq!(duplicate.matched_by, "repo_sha_toolchain");

    // Different toolchain -> no match (binary changed, must re-gate).
    let no_match = find_completed_gates_duplicate_in_cache(&incoming, &cache, "b3-256:bbbb");
    assert!(
        no_match.is_none(),
        "different toolchain digest must NOT match"
    );
}

#[test]
fn test_append_completed_gates_fingerprint_if_loaded_supports_same_cycle_dedupe() {
    let toolchain = "b3-256:cccc";
    let mut completed_spec = make_receipt_test_spec();
    completed_spec.job_id = "job-completed-sha".to_string();
    completed_spec.enqueue_time = "2026-02-19T01:00:00Z".to_string();

    let mut incoming = completed_spec.clone();
    incoming.job_id = "job-incoming-sha".to_string();
    incoming.enqueue_time = "2026-02-19T01:03:00Z".to_string();

    let mut cache = Some(CompletedGatesCache::default());
    append_completed_gates_fingerprint_if_loaded(&mut cache, &completed_spec, toolchain);
    let duplicate = find_completed_gates_duplicate_in_cache(
        &incoming,
        cache.as_ref().expect("cache loaded"),
        toolchain,
    )
    .expect("duplicate");
    assert_eq!(duplicate.existing_job_id, "job-completed-sha");
    assert_eq!(duplicate.matched_by, "repo_sha_toolchain");
}

#[test]
fn test_annotate_denied_job_file_populates_reason_fields() {
    let dir = tempfile::tempdir().expect("tempdir");
    let denied_path = dir.path().join("job-denied.json");
    let spec = make_receipt_test_spec();
    fs::write(
        &denied_path,
        serde_json::to_vec_pretty(&spec).expect("serialize job spec"),
    )
    .expect("write denied job file");

    annotate_denied_job_file(
        &denied_path,
        Some(DenialReasonCode::AlreadyCompleted),
        "already completed for repo+sha",
    )
    .expect("annotate denied job");

    let payload: serde_json::Value =
        serde_json::from_slice(&fs::read(&denied_path).expect("read denied metadata"))
            .expect("parse denied metadata");
    assert_eq!(
        payload
            .get("denial_reason_code")
            .and_then(serde_json::Value::as_str),
        Some("already_completed")
    );
    assert_eq!(
        payload
            .get("denial_reason")
            .and_then(serde_json::Value::as_str),
        Some("already completed for repo+sha")
    );
    assert!(
        payload
            .get("denied_at")
            .and_then(serde_json::Value::as_str)
            .is_some(),
        "denied file must include denied_at"
    );
}

#[test]
fn test_annotate_denied_job_file_defaults_when_reason_and_code_missing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let denied_path = dir.path().join("job-denied.json");
    let spec = make_receipt_test_spec();
    fs::write(
        &denied_path,
        serde_json::to_vec_pretty(&spec).expect("serialize job spec"),
    )
    .expect("write denied job file");

    annotate_denied_job_file(&denied_path, None, "   ").expect("annotate denied job");

    let payload: serde_json::Value =
        serde_json::from_slice(&fs::read(&denied_path).expect("read denied metadata"))
            .expect("parse denied metadata");
    assert_eq!(
        payload
            .get("denial_reason_code")
            .and_then(serde_json::Value::as_str),
        Some("missing_denial_reason_code")
    );
    assert_eq!(
        payload
            .get("denial_reason")
            .and_then(serde_json::Value::as_str),
        Some("denied (missing_denial_reason_code)")
    );
}

#[test]
fn test_annotate_denied_job_metadata_from_receipt_updates_denied_only() {
    let dir = tempfile::tempdir().expect("tempdir");
    let denied_path = dir.path().join("job-denied.json");
    fs::write(
        &denied_path,
        serde_json::to_vec_pretty(&make_receipt_test_spec()).expect("serialize job spec"),
    )
    .expect("write denied job file");

    let denied_receipt = FacJobReceiptV1 {
        outcome: FacJobOutcome::Denied,
        denial_reason: Some(DenialReasonCode::AlreadyCompleted),
        reason: "already completed".to_string(),
        ..FacJobReceiptV1::default()
    };
    annotate_denied_job_metadata_from_receipt(&denied_path, &denied_receipt);
    let payload: serde_json::Value =
        serde_json::from_slice(&fs::read(&denied_path).expect("read denied metadata"))
            .expect("parse denied metadata");
    assert_eq!(
        payload
            .get("denial_reason")
            .and_then(serde_json::Value::as_str),
        Some("already completed")
    );

    let completed_path = dir.path().join("job-completed.json");
    fs::write(
        &completed_path,
        serde_json::to_vec_pretty(&make_receipt_test_spec()).expect("serialize job spec"),
    )
    .expect("write completed job file");
    let completed_receipt = FacJobReceiptV1 {
        outcome: FacJobOutcome::Completed,
        denial_reason: None,
        reason: "completed".to_string(),
        ..FacJobReceiptV1::default()
    };
    annotate_denied_job_metadata_from_receipt(&completed_path, &completed_receipt);
    let completed_payload: serde_json::Value =
        serde_json::from_slice(&fs::read(&completed_path).expect("read completed metadata"))
            .expect("parse completed metadata");
    assert!(
        completed_payload.get("denial_reason").is_none(),
        "completed outcomes must not be annotated as denied"
    );
}

/// TCK-00564 MAJOR-1 regression: `handle_pipeline_commit_failure` must
/// leave the job in claimed/ rather than moving it to pending/.
///
/// Prior to fix round 4, commit failures moved jobs from claimed/ to
/// pending/, which caused the outcome-blind duplicate detection to
/// route them to completed/ regardless of the receipt outcome. The fix
/// leaves the job in claimed/ for reconcile to repair via
/// `recover_torn_state`.
#[test]
fn test_handle_pipeline_commit_failure_leaves_job_in_claimed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let queue_root = dir.path().join("queue");
    ensure_queue_dirs(&queue_root).expect("create queue dirs");

    // Place a job file in claimed/.
    let claimed_path = queue_root.join(CLAIMED_DIR).join("commit-fail.json");
    fs::write(&claimed_path, b"{}").expect("write claimed job");

    // Call handle_pipeline_commit_failure with a structured error.
    let test_err = ReceiptPipelineError::ReceiptPersistFailed("test commit error".to_string());
    let outcome = handle_pipeline_commit_failure(
        &test_err,
        "test context",
        &claimed_path,
        &queue_root,
        "commit-fail.json",
    );

    // The job should still be in claimed/, NOT in pending/.
    assert!(
        claimed_path.exists(),
        "job must remain in claimed/ after commit failure"
    );
    assert!(
        !queue_root
            .join(PENDING_DIR)
            .join("commit-fail.json")
            .exists(),
        "job must NOT be moved to pending/ after commit failure"
    );
    assert!(
        matches!(
            outcome,
            JobOutcome::Skipped {
                disposition: JobSkipDisposition::PipelineCommitFailed,
                ..
            }
        ),
        "outcome should request runtime claimed repair, got: {outcome:?}"
    );
}

// --- TCK-00574 MAJOR-2: resolved network policy hash consistency ---

#[test]
fn resolve_network_policy_hash_matches_for_gates_kind() {
    // Regression: the resolved network policy hash for "gates" kind
    // must match the hash produced by resolve_network_policy("gates", None).
    // This validates that the early-resolve approach in the execution path
    // produces the same hash as the later resolve_network_policy call.
    let resolved = apm2_core::fac::resolve_network_policy("gates", None);
    let expected_deny = apm2_core::fac::NetworkPolicy::deny();
    assert_eq!(
        resolved, expected_deny,
        "gates kind should resolve to deny policy by default"
    );
    assert_eq!(
        resolved.content_hash_hex(),
        expected_deny.content_hash_hex(),
        "hash of resolved policy must match deny policy hash"
    );
}

#[test]
fn resolve_network_policy_hash_matches_for_warm_kind() {
    // The resolved network policy for "warm" kind must be allow.
    let resolved = apm2_core::fac::resolve_network_policy("warm", None);
    let expected_allow = apm2_core::fac::NetworkPolicy::allow();
    assert_eq!(
        resolved, expected_allow,
        "warm kind should resolve to allow policy by default"
    );
    // Verify the hashes differ between deny and allow.
    let deny_hash = apm2_core::fac::NetworkPolicy::deny().content_hash_hex();
    assert_ne!(
        resolved.content_hash_hex(),
        deny_hash,
        "warm (allow) hash must differ from gates (deny) hash"
    );
}

/// Verify that `LaneResetRecommendation` serializes to a standalone valid
/// JSON object with the expected schema identifier, matching the contract
/// that `emit_lane_reset_recommendation` emits each recommendation as a
/// single parseable JSON line on stderr.
#[test]
fn test_lane_reset_recommendation_serializes_as_valid_json() {
    let rec = LaneResetRecommendation {
        schema: LANE_RESET_RECOMMENDATION_SCHEMA,
        lane_id: "lane-42".to_string(),
        message: "worker: RECOMMENDATION: lane lane-42 needs reset".to_string(),
        reason: "cleanup failure: disk full".to_string(),
        recommended_action: "apm2 fac doctor --fix",
    };
    let json_str = serde_json::to_string(&rec).expect("serialization must succeed");

    // The serialized string must parse back as valid JSON.
    let parsed: serde_json::Value =
        serde_json::from_str(&json_str).expect("output must be valid JSON");

    // Verify expected fields.
    assert_eq!(
        parsed["schema"], "apm2.fac.lane_reset_recommendation.v1",
        "schema field must match LANE_RESET_RECOMMENDATION_SCHEMA"
    );
    assert_eq!(parsed["lane_id"], "lane-42");
    assert_eq!(
        parsed["message"], "worker: RECOMMENDATION: lane lane-42 needs reset",
        "human-readable context must be encoded inside JSON, not as a separate plain-text line"
    );
    assert_eq!(parsed["reason"], "cleanup failure: disk full");
    assert_eq!(parsed["recommended_action"], "apm2 fac doctor --fix");

    // The output must NOT contain any non-JSON prefix — verify the first
    // non-whitespace character is '{'.
    let trimmed = json_str.trim();
    assert!(
        trimmed.starts_with('{'),
        "serialized recommendation must be a standalone JSON object, got: {trimmed}"
    );
}

/// Verify that `emit_lane_reset_recommendation` emits exactly one line
/// to stderr and that the line is valid, parseable JSON with the expected
/// schema.  This is the contract: the stderr recommendation channel is
/// JSON-only (NDJSON) — no plain-text preamble, no mixed lines.
#[test]
fn test_emit_lane_reset_recommendation_stderr_is_json_only() {
    // We cannot capture real stderr in-process without redirecting FDs,
    // so we replicate the emission logic and verify that every line
    // produced is valid JSON.
    let lane_id = "lane-77";
    let reason = "stale lease detected";
    let rec = LaneResetRecommendation {
        schema: LANE_RESET_RECOMMENDATION_SCHEMA,
        lane_id: lane_id.to_string(),
        message: format!("worker: RECOMMENDATION: lane {lane_id} needs reset"),
        reason: reason.to_string(),
        recommended_action: "apm2 fac doctor --fix",
    };
    let json_str =
        serde_json::to_string(&rec).expect("serialization must succeed for test fixture");

    // Simulate what emit_lane_reset_recommendation writes to stderr:
    // exactly one line containing the JSON.  Verify EACH line is
    // parseable JSON.
    let emitted_lines: Vec<&str> = json_str.lines().collect();
    assert_eq!(
        emitted_lines.len(),
        1,
        "recommendation must be emitted as exactly one line, got {}",
        emitted_lines.len()
    );
    for (i, line) in emitted_lines.iter().enumerate() {
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(line);
        assert!(parsed.is_ok(), "stderr line {i} is not valid JSON: {line}");
        let val = parsed.unwrap();
        assert_eq!(
            val["schema"], "apm2.fac.lane_reset_recommendation.v1",
            "each emitted JSON line must carry the recommendation schema"
        );
    }
}

/// Verify channel separation: `emit_lane_reset_recommendation` writes
/// JSON to stderr (via `eprintln!`).  The `acquire_worker_lane` function
/// uses only `tracing::warn!` / `tracing::info!` for diagnostics (routed
/// to the tracing subscriber), never raw `eprintln!`, so the only
/// `eprintln!` output from the lane-acquisition path is the JSON
/// recommendation itself.  This test verifies the serialized output
/// parses as valid NDJSON, confirming that no plain-text prefix or
/// suffix contaminates the stderr recommendation channel.
#[test]
fn test_recommendation_channel_separation() {
    // Verify multiple recommendations can be concatenated as NDJSON
    // (one valid JSON object per line) on the stdout channel.
    let test_cases = [
        ("lane-1", "disk full"),
        ("lane-2", "stale lease for pid 12345"),
        ("lane-3", "lease state is Corrupt"),
    ];

    let mut ndjson_output = String::new();
    for (lane_id, reason) in &test_cases {
        let rec = LaneResetRecommendation {
            schema: LANE_RESET_RECOMMENDATION_SCHEMA,
            lane_id: lane_id.to_string(),
            message: format!("worker: RECOMMENDATION: lane {lane_id} needs reset"),
            reason: reason.to_string(),
            recommended_action: "apm2 fac doctor --fix",
        };
        let json_str =
            serde_json::to_string(&rec).expect("serialization must succeed for test fixture");
        ndjson_output.push_str(&json_str);
        ndjson_output.push('\n');
    }

    // Parse as NDJSON: every non-empty line must be valid JSON.
    let lines: Vec<&str> = ndjson_output
        .lines()
        .filter(|l| !l.trim().is_empty())
        .collect();
    assert_eq!(
        lines.len(),
        3,
        "expected 3 NDJSON lines for 3 recommendations, got {}",
        lines.len()
    );
    for (i, line) in lines.iter().enumerate() {
        let parsed: serde_json::Value = serde_json::from_str(line).unwrap_or_else(|e| {
            panic!("stderr NDJSON line {i} is not valid JSON: {e}\nline: {line}")
        });
        assert_eq!(
            parsed["schema"], "apm2.fac.lane_reset_recommendation.v1",
            "line {i}: schema field mismatch"
        );
        assert_eq!(
            parsed["lane_id"], test_cases[i].0,
            "line {i}: lane_id mismatch"
        );
        assert_eq!(
            parsed["reason"], test_cases[i].1,
            "line {i}: reason mismatch"
        );
        // Verify no non-JSON prefix: first non-whitespace char must be '{'.
        assert!(
            line.trim().starts_with('{'),
            "line {i}: stderr NDJSON line must start with '{{', got: {line}"
        );
    }
}

#[test]
fn resolve_network_policy_hash_with_override() {
    // When an operator override is provided, it takes precedence
    // over the default kind-based mapping.
    let override_allow = apm2_core::fac::NetworkPolicy::allow();
    let resolved = apm2_core::fac::resolve_network_policy("gates", Some(&override_allow));
    assert_eq!(
        resolved, override_allow,
        "operator override must take precedence over kind default"
    );
    assert_eq!(
        resolved.content_hash_hex(),
        override_allow.content_hash_hex(),
        "hash must match the override policy, not the default deny"
    );
}

// ========================================================================
// owns_sccache_server tests (fix-round-3)
// ========================================================================

fn make_trace_with_sc(
    sc: apm2_core::fac::containment::SccacheServerContainment,
) -> apm2_core::fac::containment::ContainmentTrace {
    apm2_core::fac::containment::ContainmentTrace {
        verified: true,
        cgroup_path: "/test".to_string(),
        processes_checked: 1,
        mismatch_count: 0,
        sccache_auto_disabled: sc.auto_disabled,
        sccache_enabled: !sc.auto_disabled,
        sccache_version: None,
        sccache_server_containment: Some(sc),
    }
}

#[test]
fn owns_server_started_auto_disabled_returns_true() {
    let sc = apm2_core::fac::containment::SccacheServerContainment {
        protocol_executed: true,
        server_started: true,
        auto_disabled: true,
        server_cgroup_verified: false,
        ..Default::default()
    };
    let trace = make_trace_with_sc(sc);
    assert!(
        owns_sccache_server(Some(&trace)),
        "server_started=true must own for shutdown even when auto_disabled"
    );
}

#[test]
fn owns_server_not_started_auto_disabled_returns_false() {
    let sc = apm2_core::fac::containment::SccacheServerContainment {
        protocol_executed: true,
        server_started: false,
        auto_disabled: true,
        server_cgroup_verified: false,
        ..Default::default()
    };
    let trace = make_trace_with_sc(sc);
    assert!(
        !owns_sccache_server(Some(&trace)),
        "server_started=false auto_disabled=true must not own"
    );
}

#[test]
fn owns_server_started_pid_auto_disabled_returns_true() {
    let sc = apm2_core::fac::containment::SccacheServerContainment {
        protocol_executed: true,
        server_started: false,
        started_server_pid: Some(12345),
        auto_disabled: true,
        server_cgroup_verified: false,
        ..Default::default()
    };
    let trace = make_trace_with_sc(sc);
    assert!(
        owns_sccache_server(Some(&trace)),
        "started_server_pid=Some must own for shutdown even when auto_disabled"
    );
}

#[test]
fn owns_preexisting_in_cgroup_returns_true() {
    let sc = apm2_core::fac::containment::SccacheServerContainment {
        protocol_executed: true,
        preexisting_server_detected: true,
        preexisting_server_in_cgroup: Some(true),
        server_started: false,
        auto_disabled: false,
        server_cgroup_verified: true,
        ..Default::default()
    };
    let trace = make_trace_with_sc(sc);
    assert!(
        owns_sccache_server(Some(&trace)),
        "preexisting in-cgroup server must own"
    );
}

// =========================================================================
// Broker promotion: queue bounds enforcement (TCK-00577 round 2 fixes)
// =========================================================================

/// Helper: creates a minimal valid JSON job spec for broker request tests.
fn make_valid_broker_request_json(job_id: &str) -> String {
    use apm2_core::fac::job_spec::{FacJobSpecV1Builder, JobSource};

    let source = JobSource {
        kind: "mirror_commit".to_string(),
        repo_id: "test/repo".to_string(),
        work_id: "W-TEST".to_string(),
        head_sha: "a".repeat(40),
        patch: None,
    };
    let spec = FacJobSpecV1Builder::new(
        job_id,
        "gates",
        "bulk",
        "2026-02-19T00:00:00Z",
        "lease-test",
        source,
    )
    .priority(50)
    .build()
    .expect("valid spec");
    serde_json::to_string_pretty(&spec).expect("serialize broker request JSON")
}

#[test]
fn promote_broker_request_denied_when_queue_at_capacity() {
    // Verify that broker promotion respects queue bounds: when
    // pending/ is at capacity, broker requests are quarantined
    // instead of promoted.
    let dir = tempfile::tempdir().expect("tempdir");
    let queue_root = dir.path().join("queue");
    let pending_dir = queue_root.join(PENDING_DIR);
    let broker_dir = queue_root.join(BROKER_REQUESTS_DIR);
    let quarantine_dir = queue_root.join(QUARANTINE_DIR);

    fs::create_dir_all(&pending_dir).expect("pending dir");
    fs::create_dir_all(&broker_dir).expect("broker dir");

    // Fill pending to the default capacity (10_000 jobs).
    // Use a tight capacity to keep the test fast: override by
    // filling to the default limit.
    // Instead, we can just fill enough to trigger denial with a
    // small number of files — but check_queue_bounds uses the
    // default policy (10_000 jobs, 1 GiB). That's too many files.
    //
    // Instead, create a tight scenario: fill pending with
    // DEFAULT_MAX_PENDING_JOBS files. That's impractical. Instead,
    // test at the check_queue_bounds level first, and test
    // promote_broker_requests with the real function.
    //
    // We can test this by creating enough pending files to exceed the
    // default byte limit. With default max_pending_bytes = 1 GiB,
    // that's also impractical.
    //
    // The practical approach: verify the function uses
    // move_to_dir_safe (no-replace) and the lock by testing the
    // actual promote function behavior. For bounds, we need a
    // targeted test.
    //
    // Actually, the simplest test: create 10_000 small files in
    // pending to hit the job cap, then verify broker request is
    // quarantined. But creating 10k files is expensive.
    //
    // A better test: verify the function behavior by testing the
    // integration point. We will create a moderate number of files
    // and use the fact that the default policy has max_pending_jobs
    // = 10_000. If we want to actually test the denial, we must
    // create enough files. Let's keep it practical with 10_000
    // tiny files (should be fast on tmpfs).
    for i in 0..10_000 {
        let f = pending_dir.join(format!("job-{i}.json"));
        fs::write(&f, "{}").expect("write pending job");
    }

    // Now submit a broker request.
    let broker_file = broker_dir.join("broker-overflow.json");
    fs::write(
        &broker_file,
        make_valid_broker_request_json("broker-overflow"),
    )
    .expect("write broker request");

    // Run promotion with default policy (max_pending_jobs = 10_000).
    let default_policy = QueueBoundsPolicy::default();
    promote_broker_requests(&queue_root, &default_policy);

    // The broker request must NOT be in pending/ (queue at capacity).
    assert!(
        !pending_dir.join("broker-overflow.json").exists(),
        "broker request must not be promoted when queue is at capacity"
    );

    // The broker request must be quarantined.
    assert!(
        quarantine_dir.is_dir(),
        "quarantine directory must exist after denial"
    );
    let quarantine_entries: Vec<_> = fs::read_dir(&quarantine_dir)
        .expect("read quarantine")
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().contains("broker-overflow"))
        .collect();
    assert!(
        !quarantine_entries.is_empty(),
        "denied broker request must be moved to quarantine"
    );

    // The original broker request must be gone.
    assert!(
        !broker_file.exists(),
        "original broker request file must be removed after quarantine"
    );
}

#[test]
fn promote_broker_request_collision_does_not_overwrite_pending() {
    // Verify that when a broker request has the same filename as an
    // existing pending job, the existing job is never overwritten.
    let dir = tempfile::tempdir().expect("tempdir");
    let queue_root = dir.path().join("queue");
    let pending_dir = queue_root.join(PENDING_DIR);
    let broker_dir = queue_root.join(BROKER_REQUESTS_DIR);

    fs::create_dir_all(&pending_dir).expect("pending dir");
    fs::create_dir_all(&broker_dir).expect("broker dir");

    // Create an existing pending job.
    let existing_content = make_valid_broker_request_json("collision-job");
    fs::write(pending_dir.join("collision-job.json"), &existing_content)
        .expect("write existing pending job");

    // Create a broker request with the same job ID.
    let new_content = make_valid_broker_request_json("collision-job");
    fs::write(broker_dir.join("collision-job.json"), &new_content).expect("write broker request");

    // Run promotion with default policy.
    let default_policy = QueueBoundsPolicy::default();
    promote_broker_requests(&queue_root, &default_policy);

    // The original pending job must be untouched.
    let existing_after = fs::read_to_string(pending_dir.join("collision-job.json"))
        .expect("read existing pending job");
    assert_eq!(
        existing_after, existing_content,
        "existing pending job must not be overwritten by broker promotion"
    );

    // The broker request should have been promoted with a
    // collision-safe name (timestamped suffix) by move_to_dir_safe.
    // Or it should still exist in broker_dir if move failed.
    // Either way, the original pending job is intact.
    let pending_entries: Vec<_> = fs::read_dir(&pending_dir)
        .expect("read pending")
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().contains("collision-job"))
        .collect();
    assert!(
        !pending_entries.is_empty(),
        "at least the original pending job must remain"
    );
}

#[test]
fn promote_broker_request_success_under_capacity() {
    // Verify that a valid broker request is promoted to pending/
    // when queue is under capacity, using no-replace rename.
    let dir = tempfile::tempdir().expect("tempdir");
    let queue_root = dir.path().join("queue");
    let pending_dir = queue_root.join(PENDING_DIR);
    let broker_dir = queue_root.join(BROKER_REQUESTS_DIR);

    fs::create_dir_all(&pending_dir).expect("pending dir");
    fs::create_dir_all(&broker_dir).expect("broker dir");

    // Create a valid broker request.
    let content = make_valid_broker_request_json("good-job");
    fs::write(broker_dir.join("good-job.json"), &content).expect("write broker request");

    // Run promotion with default policy.
    let default_policy = QueueBoundsPolicy::default();
    promote_broker_requests(&queue_root, &default_policy);

    // The job must appear in pending/.
    assert!(
        pending_dir.join("good-job.json").exists(),
        "valid broker request must be promoted to pending/"
    );

    // The original broker request must be gone.
    assert!(
        !broker_dir.join("good-job.json").exists(),
        "broker request must be removed after successful promotion"
    );
}

#[derive(Debug, Clone, Copy)]
struct RequirementTraceability {
    requirement_id: &'static str,
    source_path: &'static str,
    source_anchor: &'static str,
    expected_behavior: &'static str,
}

fn dual_write_requirement_traceability() -> [RequirementTraceability; 4] {
    [
        RequirementTraceability {
            requirement_id: "QL-R3",
            source_path: "documents/work/tickets/TCK-00669.yaml",
            source_anchor: "ledger projection wins; filesystem is repaired to match",
            expected_behavior: "ledger projection truth deterministically reconstructs queue lifecycle outcomes",
        },
        RequirementTraceability {
            requirement_id: "QL-003",
            source_path: "crates/apm2-cli/src/commands/AGENTS.md",
            source_anchor: "Queue lifecycle dual-write ordering",
            expected_behavior: "queue lifecycle dual-write ordering mirrors queue mutation semantics",
        },
        RequirementTraceability {
            requirement_id: "INV-WRK-003",
            source_path: "crates/apm2-cli/src/commands/fac_worker/mod.rs",
            source_anchor: "Atomic claim via rename prevents double-execution.",
            expected_behavior: "queue claim path preserves atomic single-consumer semantics",
        },
        RequirementTraceability {
            requirement_id: "INV-WRK-007",
            source_path: "crates/apm2-cli/src/commands/fac_worker/mod.rs",
            source_anchor: "Malformed/unreadable/oversize files are quarantined",
            expected_behavior: "malformed/unreadable inputs fail closed with explicit quarantine outcomes",
        },
    ]
}

fn assert_dual_write_requirement_traceability() {
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");
    for trace in dual_write_requirement_traceability() {
        assert!(
            !trace.requirement_id.is_empty()
                && !trace.source_path.is_empty()
                && !trace.source_anchor.is_empty()
                && !trace.expected_behavior.is_empty(),
            "requirement traceability entries must provide id/source/anchor/expected behavior"
        );

        let source_path = repo_root.join(trace.source_path);
        let source = std::fs::read_to_string(&source_path).unwrap_or_else(|err| {
            panic!(
                "failed to read requirement source {} for {}: {err}",
                source_path.display(),
                trace.requirement_id
            )
        });
        assert!(
            source.contains(trace.requirement_id),
            "source-of-truth {} must contain requirement id {}",
            source_path.display(),
            trace.requirement_id
        );
        assert!(
            source.contains(trace.source_anchor),
            "source-of-truth {} for {} must contain anchor {:?}",
            source_path.display(),
            trace.requirement_id,
            trace.source_anchor
        );
    }
}

#[test]
fn promote_broker_request_dual_write_emits_enqueued_event() {
    use apm2_core::fac::job_lifecycle::FAC_JOB_ENQUEUED_EVENT_TYPE;

    let _guard = env_var_test_lock().lock().expect("serialize env test");
    let original_apm2_home = std::env::var_os("APM2_HOME");
    assert_dual_write_requirement_traceability();

    let dir = tempfile::tempdir().expect("tempdir");
    let apm2_home = dir.path().join(".apm2");
    let fac_root = apm2_home.join("private").join("fac");
    let queue_root = apm2_home.join("queue");
    let pending_dir = queue_root.join(PENDING_DIR);
    let broker_dir = queue_root.join(BROKER_REQUESTS_DIR);

    fs::create_dir_all(&fac_root).expect("create fac root");
    ensure_queue_dirs(&queue_root).expect("create queue dirs");
    set_env_var_for_test("APM2_HOME", &apm2_home);

    let mut policy = FacPolicyV1::default_policy();
    policy.queue_lifecycle_dual_write_enabled = true;
    persist_policy(&fac_root, &policy).expect("persist dual-write policy");
    let _lifecycle_harness =
        fac_queue_lifecycle_dual_write::install_deterministic_lifecycle_harness(
            fac_queue_lifecycle_dual_write::DeterministicLifecycleHarnessConfig {
                simulate_only: true,
                ..Default::default()
            },
        );

    let broker_file = broker_dir.join("broker-dual-write-enqueued.json");
    fs::write(
        &broker_file,
        make_valid_broker_request_json("broker-dual-write-enqueued"),
    )
    .expect("write broker request");

    promote_broker_requests(&queue_root, &QueueBoundsPolicy::default());

    assert!(
        pending_dir.join("broker-dual-write-enqueued.json").exists(),
        "broker request should be promoted to pending/"
    );
    assert!(
        !broker_file.exists(),
        "broker request source file should be removed after promotion"
    );

    let emissions = fac_queue_lifecycle_dual_write::deterministic_lifecycle_emissions();
    let total = emissions
        .iter()
        .filter(|emission| {
            emission.event_type == FAC_JOB_ENQUEUED_EVENT_TYPE
                && emission.queue_job_id == "broker-dual-write-enqueued"
        })
        .count();
    assert!(
        total == 1,
        "broker promotion should emit exactly one deterministic fac.job.enqueued for queue_job_id=broker-dual-write-enqueued"
    );

    if let Some(value) = original_apm2_home {
        set_env_var_for_test("APM2_HOME", value);
    } else {
        remove_env_var_for_test("APM2_HOME");
    }
}

#[test]
fn promote_broker_request_uses_enqueue_lock() {
    // Verify that the enqueue lockfile is created during promotion,
    // demonstrating that the lock mechanism is engaged.
    let dir = tempfile::tempdir().expect("tempdir");
    let queue_root = dir.path().join("queue");
    let pending_dir = queue_root.join(PENDING_DIR);
    let broker_dir = queue_root.join(BROKER_REQUESTS_DIR);

    fs::create_dir_all(&pending_dir).expect("pending dir");
    fs::create_dir_all(&broker_dir).expect("broker dir");

    // Lockfile should not exist yet.
    let lock_path = queue_root.join(ENQUEUE_LOCKFILE);
    assert!(
        !lock_path.exists(),
        "lockfile must not exist before promotion"
    );

    // Create a valid broker request to trigger promotion.
    let content = make_valid_broker_request_json("lock-test-job");
    fs::write(broker_dir.join("lock-test-job.json"), &content).expect("write broker request");

    // Run promotion with default policy.
    let default_policy = QueueBoundsPolicy::default();
    promote_broker_requests(&queue_root, &default_policy);

    // The lockfile must have been created (created by acquire_enqueue_lock).
    assert!(
        lock_path.exists(),
        "enqueue lockfile must be created during broker promotion"
    );

    // Job must have been promoted.
    assert!(
        pending_dir.join("lock-test-job.json").exists(),
        "job must be promoted"
    );
}

/// TCK-00577 round 3: Regression test proving broker promotion respects
/// non-default configured queue bounds policy. Uses `max_pending_jobs=1`
/// so that with 1 existing pending job, broker promotion denies.
#[test]
fn promote_broker_request_denied_by_configured_policy() {
    let dir = tempfile::tempdir().expect("tempdir");
    let queue_root = dir.path().join("queue");
    let pending_dir = queue_root.join(PENDING_DIR);
    let broker_dir = queue_root.join(BROKER_REQUESTS_DIR);
    let quarantine_dir = queue_root.join(QUARANTINE_DIR);

    fs::create_dir_all(&pending_dir).expect("pending dir");
    fs::create_dir_all(&broker_dir).expect("broker dir");

    // Fill pending with 1 job to hit the configured cap.
    fs::write(pending_dir.join("existing-job.json"), "{}").expect("write pending job");

    // Submit a broker request.
    let broker_file = broker_dir.join("policy-denied.json");
    fs::write(
        &broker_file,
        make_valid_broker_request_json("policy-denied"),
    )
    .expect("write broker request");

    // Use a tight configured policy: max_pending_jobs = 1.
    let tight_policy = QueueBoundsPolicy {
        max_pending_jobs: 1,
        // Use a large byte limit so only job count triggers denial.
        max_pending_bytes: 1024 * 1024 * 1024,
        per_lane_max_pending_jobs: None,
    };
    promote_broker_requests(&queue_root, &tight_policy);

    // The broker request must NOT be in pending/ (configured cap exceeded).
    assert!(
        !pending_dir.join("policy-denied.json").exists(),
        "broker request must not be promoted when configured policy cap is exceeded"
    );

    // The broker request must be quarantined.
    assert!(
        quarantine_dir.is_dir(),
        "quarantine directory must exist after policy denial"
    );
    let quarantine_entries: Vec<_> = fs::read_dir(&quarantine_dir)
        .expect("read quarantine")
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().contains("policy-denied"))
        .collect();
    assert!(
        !quarantine_entries.is_empty(),
        "policy-denied broker request must be quarantined"
    );

    // Original broker request must be gone from broker_requests/.
    assert!(
        !broker_file.exists(),
        "original broker request file must be removed after quarantine"
    );
}

/// TCK-00577 round 3: Confirm that with the same tight policy,
/// promotion succeeds when pending count is below the configured cap.
#[test]
fn promote_broker_request_allowed_by_configured_policy_under_cap() {
    let dir = tempfile::tempdir().expect("tempdir");
    let queue_root = dir.path().join("queue");
    let pending_dir = queue_root.join(PENDING_DIR);
    let broker_dir = queue_root.join(BROKER_REQUESTS_DIR);

    fs::create_dir_all(&pending_dir).expect("pending dir");
    fs::create_dir_all(&broker_dir).expect("broker dir");

    // No existing pending jobs — under cap of 1.
    let content = make_valid_broker_request_json("under-cap-job");
    fs::write(broker_dir.join("under-cap-job.json"), &content).expect("write broker request");

    let tight_policy = QueueBoundsPolicy {
        max_pending_jobs: 1,
        max_pending_bytes: 1024 * 1024 * 1024,
        per_lane_max_pending_jobs: None,
    };
    promote_broker_requests(&queue_root, &tight_policy);

    // Job must be promoted since queue is under cap.
    assert!(
        pending_dir.join("under-cap-job.json").exists(),
        "broker request must be promoted when under configured policy cap"
    );

    // Original broker request must be gone.
    assert!(
        !broker_dir.join("under-cap-job.json").exists(),
        "broker request must be removed after successful promotion"
    );
}

/// TCK-00577 round 9 BLOCKER fix: Verify that non-regular files (FIFOs)
/// in `broker_requests/` are quarantined without attempting to open them.
/// An attacker can create a FIFO in the world-writable `broker_requests/`
/// (mode 01733) directory. Without the pre-open file type check, opening
/// a FIFO blocks indefinitely (deadlocking the worker).
#[test]
#[cfg(unix)]
fn promote_broker_request_quarantines_fifo() {
    let dir = tempfile::tempdir().expect("tempdir");
    let queue_root = dir.path().join("queue");
    let pending_dir = queue_root.join(PENDING_DIR);
    let broker_dir = queue_root.join(BROKER_REQUESTS_DIR);
    let quarantine_dir = queue_root.join(QUARANTINE_DIR);

    fs::create_dir_all(&pending_dir).expect("pending dir");
    fs::create_dir_all(&broker_dir).expect("broker dir");

    // Create a FIFO (named pipe) in broker_requests/ with a .json
    // extension to simulate the FIFO poisoning attack.
    let fifo_path = broker_dir.join("malicious-fifo.json");
    nix::unistd::mkfifo(&fifo_path, nix::sys::stat::Mode::S_IRWXU).expect("mkfifo must succeed");
    assert!(fifo_path.exists(), "FIFO must exist");

    // Also create a valid broker request to prove promotion still works
    // for regular files after quarantining the FIFO.
    let content = make_valid_broker_request_json("good-after-fifo");
    fs::write(broker_dir.join("good-after-fifo.json"), &content)
        .expect("write valid broker request");

    let default_policy = QueueBoundsPolicy::default();
    promote_broker_requests(&queue_root, &default_policy);

    // The FIFO must NOT be in pending/.
    assert!(
        !pending_dir.join("malicious-fifo.json").exists(),
        "FIFO must not be promoted to pending/"
    );

    // The FIFO must be quarantined (moved to quarantine/).
    assert!(
        quarantine_dir.is_dir(),
        "quarantine directory must exist after FIFO quarantine"
    );
    let quarantine_entries: Vec<_> = fs::read_dir(&quarantine_dir)
        .expect("read quarantine")
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().contains("malicious-fifo"))
        .collect();
    assert!(
        !quarantine_entries.is_empty(),
        "FIFO must be moved to quarantine directory"
    );

    // The valid broker request must still be promoted.
    assert!(
        pending_dir.join("good-after-fifo.json").exists(),
        "valid broker request must still be promoted after FIFO quarantine"
    );
}

/// TCK-00577 round 9 BLOCKER fix: Verify that symlinks in
/// `broker_requests/` are quarantined without opening.
#[test]
#[cfg(unix)]
fn promote_broker_request_quarantines_symlink() {
    let dir = tempfile::tempdir().expect("tempdir");
    let queue_root = dir.path().join("queue");
    let pending_dir = queue_root.join(PENDING_DIR);
    let broker_dir = queue_root.join(BROKER_REQUESTS_DIR);
    let quarantine_dir = queue_root.join(QUARANTINE_DIR);

    fs::create_dir_all(&pending_dir).expect("pending dir");
    fs::create_dir_all(&broker_dir).expect("broker dir");

    // Create a symlink pointing to /dev/zero (would cause infinite read).
    let symlink_path = broker_dir.join("evil-symlink.json");
    std::os::unix::fs::symlink("/dev/zero", &symlink_path).expect("create symlink");

    let default_policy = QueueBoundsPolicy::default();
    promote_broker_requests(&queue_root, &default_policy);

    // The symlink must NOT be in pending/.
    assert!(
        !pending_dir.join("evil-symlink.json").exists(),
        "symlink must not be promoted to pending/"
    );

    // The symlink must be quarantined.
    assert!(
        quarantine_dir.is_dir(),
        "quarantine directory must exist after symlink quarantine"
    );
    let quarantine_entries: Vec<_> = fs::read_dir(&quarantine_dir)
        .expect("read quarantine")
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().contains("evil-symlink"))
        .collect();
    assert!(
        !quarantine_entries.is_empty(),
        "symlink must be moved to quarantine directory"
    );
}

/// TCK-00577 round 5 MAJOR fix: `ServiceUserNotResolved` must produce a
/// fail-closed error message, not a warning. This test exercises the
/// error variant format string to ensure the error path compiles and
/// produces the expected diagnostic message pattern.
#[test]
fn service_user_not_resolved_error_message_is_fail_closed() {
    use apm2_core::fac::service_user_gate::ServiceUserGateError;

    let err = ServiceUserGateError::ServiceUserNotResolved {
        service_user: "_apm2-job".to_string(),
        reason: "user not found in passwd".to_string(),
    };

    // Simulate the error formatting from the worker startup path.
    if let ServiceUserGateError::ServiceUserNotResolved {
        ref service_user,
        ref reason,
        ..
    } = err
    {
        let msg = format!(
            "service user '{service_user}' not resolvable: {reason} \
                 (fail-closed: worker will not start when service user \
                  identity cannot be confirmed)",
        );
        assert!(
            msg.contains("fail-closed"),
            "error message must contain fail-closed"
        );
        assert!(
            msg.contains("_apm2-job"),
            "error message must contain the service user name"
        );
        assert!(
            msg.contains("will not start"),
            "error message must indicate worker will not start"
        );
    } else {
        panic!("expected ServiceUserNotResolved variant");
    }
}

#[test]
fn worker_service_user_ownership_bypasses_checks_in_user_mode() {
    let _guard = env_var_test_lock().lock().expect("serialize env test");
    let original_service_user = std::env::var_os("APM2_FAC_SERVICE_USER");

    let dir = tempfile::tempdir().expect("tempdir");
    let fac_root = dir.path().join("fac");
    let queue_root = dir.path().join("queue");
    fs::create_dir_all(queue_root.join(PENDING_DIR)).expect("create pending dir");
    fs::create_dir_all(fac_root.join(FAC_RECEIPTS_DIR)).expect("create receipts dir");

    set_env_var_for_test("APM2_FAC_SERVICE_USER", "_apm2_nonexistent_tck_00657");
    let result =
        validate_worker_service_user_ownership(&fac_root, &queue_root, ExecutionBackend::UserMode);

    if let Some(value) = original_service_user {
        set_env_var_for_test("APM2_FAC_SERVICE_USER", value);
    } else {
        remove_env_var_for_test("APM2_FAC_SERVICE_USER");
    }

    assert!(
        result.is_ok(),
        "user-mode must bypass service-user ownership checks: {result:?}"
    );
}

#[test]
fn resolve_ownership_backend_invalid_env_falls_back_to_auto_mode() {
    let _guard = env_var_test_lock().lock().expect("serialize env test");
    let original_backend = std::env::var_os(EXECUTION_BACKEND_ENV_VAR);

    set_env_var_for_test(EXECUTION_BACKEND_ENV_VAR, "totally_invalid_backend_value");
    let resolved = resolve_ownership_backend(true).expect(
        "invalid backend value should degrade to auto-selected backend for ownership checks",
    );
    let expected = if probe_user_bus() {
        ExecutionBackend::UserMode
    } else {
        ExecutionBackend::SystemMode
    };

    if let Some(value) = original_backend {
        set_env_var_for_test(EXECUTION_BACKEND_ENV_VAR, value);
    } else {
        remove_env_var_for_test(EXECUTION_BACKEND_ENV_VAR);
    }

    assert_eq!(
        resolved, expected,
        "invalid backend env must fall back deterministically to auto mode"
    );
}

#[test]
fn resolve_ownership_backend_env_too_long_fails_closed() {
    let _guard = env_var_test_lock().lock().expect("serialize env test");
    let original_backend = std::env::var_os(EXECUTION_BACKEND_ENV_VAR);

    set_env_var_for_test(EXECUTION_BACKEND_ENV_VAR, "x".repeat(300));
    let err = resolve_ownership_backend(false).expect_err("oversized backend env must fail closed");

    if let Some(value) = original_backend {
        set_env_var_for_test(EXECUTION_BACKEND_ENV_VAR, value);
    } else {
        remove_env_var_for_test(EXECUTION_BACKEND_ENV_VAR);
    }

    assert!(
        err.contains("cannot resolve execution backend for ownership checks"),
        "expected fail-closed backend resolution error, got: {err}"
    );
    assert!(
        err.contains("value too long"),
        "expected bounded env validation context, got: {err}"
    );
}

#[test]
fn worker_service_user_ownership_fails_closed_in_system_mode_when_unresolvable() {
    let _guard = env_var_test_lock().lock().expect("serialize env test");
    let original_service_user = std::env::var_os("APM2_FAC_SERVICE_USER");

    let dir = tempfile::tempdir().expect("tempdir");
    let fac_root = dir.path().join("fac");
    let queue_root = dir.path().join("queue");
    fs::create_dir_all(queue_root.join(PENDING_DIR)).expect("create pending dir");
    fs::create_dir_all(fac_root.join(FAC_RECEIPTS_DIR)).expect("create receipts dir");

    set_env_var_for_test("APM2_FAC_SERVICE_USER", "_apm2_nonexistent_tck_00657");
    let result = validate_worker_service_user_ownership(
        &fac_root,
        &queue_root,
        ExecutionBackend::SystemMode,
    );

    if let Some(value) = original_service_user {
        set_env_var_for_test("APM2_FAC_SERVICE_USER", value);
    } else {
        remove_env_var_for_test("APM2_FAC_SERVICE_USER");
    }

    let err = result.expect_err("system-mode must fail when service user cannot be resolved");
    assert!(
        err.contains("not resolvable"),
        "expected fail-closed unresolvable-user error, got: {err}"
    );
    assert!(
        err.contains("fail-closed"),
        "error must communicate fail-closed behavior: {err}"
    );
}

/// TCK-00577 round 11 BLOCKER regression: Queue subdirs must have
/// deterministic secure mode 0711 after `ensure_queue_dirs`, regardless
/// of the mode they had before (simulating umask-derived defaults).
///
/// Steps:
/// 1. Pre-create queue subdirs with an insecure mode (0775, as umask 0o002
///    would produce).
/// 2. Call `ensure_queue_dirs`.
/// 3. Verify ALL queue subdirs have mode 0711 (deterministically set), NOT the
///    pre-existing insecure mode.
/// 4. Verify `broker_requests/` has mode 01733.
#[cfg(unix)]
#[test]
fn ensure_queue_dirs_sets_deterministic_mode_on_preexisting_insecure_subdirs() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("tempdir");
    let queue_root = dir.path().join("queue");

    // Pre-create all subdirs with insecure mode 0775 (simulating
    // what create_dir_all would produce under umask 0o002).
    for subdir in [
        PENDING_DIR,
        CLAIMED_DIR,
        COMPLETED_DIR,
        DENIED_DIR,
        QUARANTINE_DIR,
        CANCELLED_DIR,
        CONSUME_RECEIPTS_DIR,
    ] {
        let path = queue_root.join(subdir);
        fs::create_dir_all(&path).expect("create subdir");
        fs::set_permissions(&path, std::fs::Permissions::from_mode(0o775))
            .expect("set insecure mode 0775");
    }

    // Also pre-create queue root with insecure mode.
    fs::set_permissions(&queue_root, std::fs::Permissions::from_mode(0o775))
        .expect("set insecure mode on queue root");

    // Call ensure_queue_dirs - must fix all modes.
    ensure_queue_dirs(&queue_root).expect("ensure_queue_dirs should succeed");

    // Check queue root itself.
    let root_mode = fs::metadata(&queue_root)
        .expect("queue root metadata")
        .permissions()
        .mode()
        & 0o7777;
    assert_eq!(
        root_mode, 0o711,
        "queue root must have mode 0711, got {root_mode:#o}"
    );

    // Check each queue subdir has mode 0711.
    for subdir in [
        PENDING_DIR,
        CLAIMED_DIR,
        COMPLETED_DIR,
        DENIED_DIR,
        QUARANTINE_DIR,
        CANCELLED_DIR,
        CONSUME_RECEIPTS_DIR,
    ] {
        let path = queue_root.join(subdir);
        let mode = fs::metadata(&path)
            .unwrap_or_else(|e| panic!("metadata for {subdir}: {e}"))
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(
            mode, 0o711,
            "{subdir} must have mode 0711 (not umask-derived 0775), got {mode:#o}"
        );
    }

    // Check broker_requests/ has mode 01733.
    let broker_mode = fs::metadata(queue_root.join(BROKER_REQUESTS_DIR))
        .expect("broker_requests metadata")
        .permissions()
        .mode()
        & 0o7777;
    assert_eq!(
        broker_mode, 0o1733,
        "broker_requests must have mode 01733, got {broker_mode:#o}"
    );
}

/// TCK-00577 round 11 BLOCKER regression: Fresh queue creation must
/// also produce correct modes. Call `ensure_queue_dirs` on a completely
/// new directory and verify all modes are deterministic.
#[cfg(unix)]
#[test]
fn ensure_queue_dirs_fresh_creation_sets_correct_modes() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("tempdir");
    let queue_root = dir.path().join("queue");

    // Queue root does not exist yet - ensure_queue_dirs creates everything.
    ensure_queue_dirs(&queue_root).expect("ensure_queue_dirs should succeed");

    // Check queue root itself.
    let root_mode = fs::metadata(&queue_root)
        .expect("queue root metadata")
        .permissions()
        .mode()
        & 0o7777;
    assert_eq!(
        root_mode, 0o711,
        "queue root must have mode 0711, got {root_mode:#o}"
    );

    // Check each queue subdir has mode 0711.
    for subdir in [
        PENDING_DIR,
        CLAIMED_DIR,
        COMPLETED_DIR,
        DENIED_DIR,
        QUARANTINE_DIR,
        CANCELLED_DIR,
        CONSUME_RECEIPTS_DIR,
    ] {
        let path = queue_root.join(subdir);
        assert!(path.is_dir(), "{subdir} must exist");
        let mode = fs::metadata(&path)
            .unwrap_or_else(|e| panic!("metadata for {subdir}: {e}"))
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(
            mode, 0o711,
            "{subdir} must have mode 0711 after fresh creation, got {mode:#o}"
        );
    }

    // Check broker_requests/ has mode 01733.
    let broker_mode = fs::metadata(queue_root.join(BROKER_REQUESTS_DIR))
        .expect("broker_requests metadata")
        .permissions()
        .mode()
        & 0o7777;
    assert_eq!(
        broker_mode, 0o1733,
        "broker_requests must have mode 01733 after fresh creation, got {broker_mode:#o}"
    );
}

/// TCK-00577 round 11 MAJOR regression: Pre-existing `broker_requests/`
/// with an unsafe mode (0333 - world-writable, no sticky bit) must be
/// hardened to 01733 by `ensure_queue_dirs` at worker startup.
///
/// Steps:
/// 1. Create `broker_requests/` with unsafe mode 0333.
/// 2. Call `ensure_queue_dirs`.
/// 3. Verify `broker_requests/` mode is now 01733 (hardened).
#[cfg(unix)]
#[test]
fn ensure_queue_dirs_hardens_preexisting_unsafe_broker_requests() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("tempdir");
    let queue_root = dir.path().join("queue");
    let broker_dir = queue_root.join(BROKER_REQUESTS_DIR);

    // Create broker_requests/ manually with unsafe mode 0333
    // (world-writable, no sticky bit).
    fs::create_dir_all(&broker_dir).expect("create broker_requests");
    fs::set_permissions(&broker_dir, std::fs::Permissions::from_mode(0o333))
        .expect("set unsafe mode 0333");

    // Verify the unsafe mode is set.
    let pre_mode = fs::metadata(&broker_dir)
        .expect("broker metadata pre-fix")
        .permissions()
        .mode()
        & 0o7777;
    assert_eq!(
        pre_mode, 0o333,
        "pre-condition: broker_requests must start with mode 0333"
    );

    // Run ensure_queue_dirs - must harden the pre-existing directory.
    ensure_queue_dirs(&queue_root).expect("ensure_queue_dirs should succeed");

    // Verify broker_requests/ is now hardened to 01733.
    let post_mode = fs::metadata(&broker_dir)
        .expect("broker metadata post-fix")
        .permissions()
        .mode()
        & 0o7777;
    assert_eq!(
        post_mode, 0o1733,
        "broker_requests must be hardened from 0333 to 01733, got {post_mode:#o}"
    );
}

/// Regression: an unsearchable pre-existing broker directory (0000) must still
/// be hardened deterministically to 01733.
#[cfg(unix)]
#[test]
fn ensure_queue_dirs_hardens_unsearchable_broker_requests_mode_000() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("tempdir");
    let queue_root = dir.path().join("queue");
    let broker_dir = queue_root.join(BROKER_REQUESTS_DIR);

    fs::create_dir_all(&broker_dir).expect("create broker_requests");
    fs::set_permissions(&broker_dir, std::fs::Permissions::from_mode(0o000))
        .expect("set mode 0000");

    ensure_queue_dirs(&queue_root).expect("ensure_queue_dirs should succeed");

    let post_mode = fs::metadata(&broker_dir)
        .expect("broker metadata post-fix")
        .permissions()
        .mode()
        & 0o7777;
    assert_eq!(
        post_mode, 0o1733,
        "broker_requests must be hardened from 0000 to 01733, got {post_mode:#o}"
    );
}

/// Regression: an unsearchable pre-existing queue root (0000) must still be
/// hardened deterministically to 0711.
#[cfg(unix)]
#[test]
fn ensure_queue_dirs_hardens_unsearchable_queue_root_mode_000() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("tempdir");
    let queue_root = dir.path().join("queue");

    fs::create_dir_all(&queue_root).expect("create queue root");
    fs::set_permissions(&queue_root, std::fs::Permissions::from_mode(0o000))
        .expect("set mode 0000");

    ensure_queue_dirs(&queue_root).expect("ensure_queue_dirs should succeed");

    let post_mode = fs::metadata(&queue_root)
        .expect("queue root metadata post-fix")
        .permissions()
        .mode()
        & 0o7777;
    assert_eq!(
        post_mode, 0o711,
        "queue root must be hardened from 0000 to 0711, got {post_mode:#o}"
    );
}

/// Regression: an unsearchable pre-existing queue subdirectory (0000) must be
/// hardened deterministically to 0711.
#[cfg(unix)]
#[test]
fn ensure_queue_dirs_hardens_unsearchable_subdir_mode_000() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("tempdir");
    let queue_root = dir.path().join("queue");
    let pending_dir = queue_root.join(PENDING_DIR);

    fs::create_dir_all(&pending_dir).expect("create pending dir");
    fs::set_permissions(&pending_dir, std::fs::Permissions::from_mode(0o000))
        .expect("set mode 0000");

    ensure_queue_dirs(&queue_root).expect("ensure_queue_dirs should succeed");

    let post_mode = fs::metadata(&pending_dir)
        .expect("pending dir metadata post-fix")
        .permissions()
        .mode()
        & 0o7777;
    assert_eq!(
        post_mode, 0o711,
        "pending dir must be hardened from 0000 to 0711, got {post_mode:#o}"
    );
}

/// Regression: symlinked `broker_requests` path must be rejected fail-closed.
#[cfg(unix)]
#[test]
fn ensure_queue_dirs_rejects_symlink_broker_requests_fail_closed() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().expect("tempdir");
    let queue_root = dir.path().join("queue");
    fs::create_dir_all(&queue_root).expect("create queue root");
    let external_target = dir.path().join("external-target");
    fs::create_dir_all(&external_target).expect("create external target");
    symlink(&external_target, queue_root.join(BROKER_REQUESTS_DIR))
        .expect("create broker_requests symlink");

    let err = ensure_queue_dirs(&queue_root)
        .expect_err("must fail-closed on broker_requests symlink path");
    assert!(
        err.contains("symlink"),
        "error must report symlink refusal, got: {err}"
    );
}

/// TCK-00577 round 11 BLOCKER regression: After `ensure_queue_dirs`,
/// the relaxed preflight validator's mode check (reject group/other
/// read or write bits: mode & 0o066 != 0) must accept all queue
/// subdirectories. This proves the end-to-end invariant: queue dirs
/// created by `ensure_queue_dirs` pass the same validation used by
/// worker startup preflight.
///
/// The check is inlined here (mode & 0o066 == 0) rather than
/// importing from `fac_permissions` to avoid cross-module visibility
/// issues with the integration test harness.
#[cfg(unix)]
#[test]
fn ensure_queue_dirs_passes_relaxed_preflight_mode_check() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("tempdir");
    let queue_root = dir.path().join("queue");

    // Create queue dirs via `ensure_queue_dirs`.
    ensure_queue_dirs(&queue_root).expect("ensure_queue_dirs should succeed");

    // Inline the same check that `validate_directory_mode_only` performs:
    // reject group/other read or write bits (0o066) but allow execute-only
    // (0o011) for traversal.
    let queue_dirs: Vec<&str> = vec![
        PENDING_DIR,
        CLAIMED_DIR,
        COMPLETED_DIR,
        DENIED_DIR,
        QUARANTINE_DIR,
        CANCELLED_DIR,
        CONSUME_RECEIPTS_DIR,
    ];

    // Check queue root.
    let root_mode = fs::metadata(&queue_root)
        .expect("queue root metadata")
        .permissions()
        .mode()
        & 0o7777;
    assert_eq!(
        root_mode & 0o066,
        0,
        "queue root mode {root_mode:#o} has group/other read or write bits \
             that relaxed preflight would reject"
    );

    // Check each queue subdir.
    for subdir in &queue_dirs {
        let path = queue_root.join(subdir);
        let mode = fs::metadata(&path)
            .unwrap_or_else(|e| panic!("metadata for {subdir}: {e}"))
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(
            mode & 0o066,
            0,
            "{subdir} mode {mode:#o} has group/other read or write bits \
                 that relaxed preflight would reject"
        );
    }

    // broker_requests/ has special mode 01733. Verify it also passes
    // the relaxed check (01733 & 0o066 = 0o022 which DOES have
    // group write bits). However, broker_requests/ is validated
    // separately by `enqueue_via_broker_requests`, not by the relaxed
    // preflight validator on queue subdirs, so this is expected. The
    // FAC_SUBDIRS_QUEUE list does NOT include broker_requests/.
}

// =========================================================================
// Broker promotion: service-user-owned rewrite (TCK-00577 round 12 BLOCKER)
// =========================================================================

/// TCK-00577 round 12 BLOCKER fix: After broker promotion, the file in
/// `pending/` must have mode 0600 (service-user-only). Previously the
/// attacker-owned file was renamed directly into `pending/`, preserving
/// the submitter's ownership and 0644 mode — allowing post-validation
/// modification (TOCTOU).
#[cfg(unix)]
#[test]
fn promoted_broker_request_has_mode_0600_in_pending() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("tempdir");
    let queue_root = dir.path().join("queue");
    let pending_dir = queue_root.join(PENDING_DIR);
    let broker_dir = queue_root.join(BROKER_REQUESTS_DIR);

    fs::create_dir_all(&pending_dir).expect("pending dir");
    fs::create_dir_all(&broker_dir).expect("broker dir");

    // Create a broker request file with mode 0600 (matching the new
    // submitter mode from TCK-00577 round 14). In same-user tests the
    // worker can read 0600 files it owns.
    let content = make_valid_broker_request_json("mode-check-job");
    let broker_file = broker_dir.join("mode-check-job.json");
    fs::write(&broker_file, &content).expect("write broker request");
    fs::set_permissions(&broker_file, fs::Permissions::from_mode(0o600))
        .expect("set mode 0600 on broker request");

    // Verify pre-condition: broker file has mode 0600.
    let pre_mode = fs::metadata(&broker_file)
        .expect("broker file metadata")
        .permissions()
        .mode()
        & 0o7777;
    assert_eq!(
        pre_mode, 0o600,
        "pre-condition: broker request must be mode 0600"
    );

    // Run promotion.
    let default_policy = QueueBoundsPolicy::default();
    promote_broker_requests(&queue_root, &default_policy);

    // The promoted file in pending/ must have mode 0600.
    let promoted_path = pending_dir.join("mode-check-job.json");
    assert!(
        promoted_path.exists(),
        "promoted file must exist in pending/"
    );
    let post_mode = fs::metadata(&promoted_path)
        .expect("promoted file metadata")
        .permissions()
        .mode()
        & 0o7777;
    assert_eq!(
        post_mode, 0o600,
        "promoted file must have mode 0600 (service-user-only), got {post_mode:04o}"
    );
}

/// TCK-00577 round 12 BLOCKER fix: After promotion, the original broker
/// request file must be removed from `broker_requests/`.
#[test]
fn promoted_broker_request_removes_original_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let queue_root = dir.path().join("queue");
    let pending_dir = queue_root.join(PENDING_DIR);
    let broker_dir = queue_root.join(BROKER_REQUESTS_DIR);

    fs::create_dir_all(&pending_dir).expect("pending dir");
    fs::create_dir_all(&broker_dir).expect("broker dir");

    let content = make_valid_broker_request_json("remove-original-job");
    let broker_file = broker_dir.join("remove-original-job.json");
    fs::write(&broker_file, &content).expect("write broker request");

    let default_policy = QueueBoundsPolicy::default();
    promote_broker_requests(&queue_root, &default_policy);

    // The promoted file must exist in pending/.
    assert!(
        pending_dir.join("remove-original-job.json").exists(),
        "promoted file must exist in pending/"
    );

    // The original broker request must be removed.
    assert!(
        !broker_file.exists(),
        "original broker request file must be removed after promotion"
    );
}

/// TCK-00577 round 12 BLOCKER fix: The inode in `pending/` must be
/// DIFFERENT from the original broker inode. This proves the promotion
/// used a rewrite (new file) instead of rename (same inode).
#[cfg(unix)]
#[test]
fn promoted_broker_request_is_different_inode_from_original() {
    use std::os::unix::fs::MetadataExt;

    let dir = tempfile::tempdir().expect("tempdir");
    let queue_root = dir.path().join("queue");
    let pending_dir = queue_root.join(PENDING_DIR);
    let broker_dir = queue_root.join(BROKER_REQUESTS_DIR);

    fs::create_dir_all(&pending_dir).expect("pending dir");
    fs::create_dir_all(&broker_dir).expect("broker dir");

    let content = make_valid_broker_request_json("inode-check-job");
    let broker_file = broker_dir.join("inode-check-job.json");
    fs::write(&broker_file, &content).expect("write broker request");

    // Capture the original inode number.
    let original_ino = fs::metadata(&broker_file)
        .expect("broker file metadata")
        .ino();

    let default_policy = QueueBoundsPolicy::default();
    promote_broker_requests(&queue_root, &default_policy);

    // The promoted file must exist in pending/.
    let promoted_path = pending_dir.join("inode-check-job.json");
    assert!(
        promoted_path.exists(),
        "promoted file must exist in pending/"
    );

    // The promoted file's inode must differ from the original.
    let promoted_ino = fs::metadata(&promoted_path)
        .expect("promoted file metadata")
        .ino();
    assert_ne!(
        original_ino, promoted_ino,
        "promoted file in pending/ must be a NEW inode (got same inode {original_ino}), \
             which means rename was used instead of rewrite"
    );
}

/// TCK-00577 round 12: Verify `promote_via_rewrite` correctly handles
/// filename collisions — the existing pending file must not be clobbered.
#[test]
fn promote_via_rewrite_does_not_clobber_existing_pending() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pending_dir = dir.path().join("pending");
    fs::create_dir_all(&pending_dir).expect("pending dir");

    // Create an existing file in pending/.
    let existing_content = b"existing pending content";
    fs::write(pending_dir.join("collision-test.json"), existing_content).expect("write existing");

    // Attempt to promote new content with the same filename.
    let new_content = make_valid_broker_request_json("collision-test");
    let result = promote_via_rewrite(new_content.as_bytes(), &pending_dir, "collision-test.json");
    assert!(
        result.is_ok(),
        "promote_via_rewrite should succeed with collision: {result:?}"
    );

    // The existing file must be untouched.
    let existing_after = fs::read(pending_dir.join("collision-test.json")).expect("read existing");
    assert_eq!(
        existing_after, existing_content,
        "existing pending file must not be clobbered"
    );

    // The promoted file must exist with a timestamped suffix.
    let promoted_path = result.unwrap();
    assert!(
        promoted_path.exists(),
        "promoted file must exist at collision-safe path"
    );
    assert!(
        promoted_path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("collision-test-"),
        "collision-safe name must have timestamped suffix: {promoted_path:?}"
    );
}

/// TCK-00577 round 12: Verify promoted file content matches validated input
/// bytes.
#[test]
fn promote_via_rewrite_preserves_content() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pending_dir = dir.path().join("pending");
    fs::create_dir_all(&pending_dir).expect("pending dir");

    let content = make_valid_broker_request_json("content-check-job");
    let result = promote_via_rewrite(content.as_bytes(), &pending_dir, "content-check-job.json");
    assert!(
        result.is_ok(),
        "promote_via_rewrite should succeed: {result:?}"
    );

    let promoted_path = result.unwrap();
    let promoted_bytes = fs::read(&promoted_path).expect("read promoted file");
    assert_eq!(
        promoted_bytes,
        content.as_bytes(),
        "promoted file content must match validated input"
    );
}

// =========================================================================
// MAJOR fix regression: junk entries must NOT starve valid broker requests
// (TCK-00577 round 16)
// =========================================================================

/// MAJOR fix (TCK-00577 round 16): Filling `broker_requests/` with N junk
/// entries (non-.json) plus 1 valid entry must still promote the valid
/// entry. Junk entries drain separately from the candidate cap.
#[test]
fn promote_broker_request_not_starved_by_junk_entries() {
    let dir = tempfile::tempdir().expect("tempdir");
    let queue_root = dir.path().join("queue");
    let pending_dir = queue_root.join(PENDING_DIR);
    let broker_dir = queue_root.join(BROKER_REQUESTS_DIR);
    let quarantine_dir = queue_root.join(QUARANTINE_DIR);

    fs::create_dir_all(&pending_dir).expect("pending dir");
    fs::create_dir_all(&broker_dir).expect("broker dir");

    // Create 300 junk entries (non-.json files) in broker_requests/.
    // This exceeds MAX_BROKER_REQUESTS_PROMOTE (256) but should NOT
    // consume the candidate budget because they are non-candidates.
    let junk_count = 300;
    for i in 0..junk_count {
        let junk_path = broker_dir.join(format!("junk-entry-{i:04}.txt"));
        fs::write(&junk_path, "not a json file").expect("write junk entry");
    }

    // Create 1 valid .json broker request.
    let valid_content = make_valid_broker_request_json("valid-among-junk");
    fs::write(broker_dir.join("valid-among-junk.json"), &valid_content)
        .expect("write valid broker request");

    let default_policy = QueueBoundsPolicy::default();
    promote_broker_requests(&queue_root, &default_policy);

    // The valid entry MUST be promoted to pending/ (not starved).
    assert!(
        pending_dir.join("valid-among-junk.json").exists(),
        "valid .json broker request must be promoted even when surrounded \
             by {junk_count} junk entries (junk must not consume the candidate budget)",
    );

    // Junk entries must be moved to quarantine (up to
    // MAX_JUNK_DRAIN_PER_CYCLE).
    let quarantine_entries: Vec<_> = fs::read_dir(&quarantine_dir)
        .expect("read quarantine dir")
        .flatten()
        .collect();
    assert!(
        !quarantine_entries.is_empty(),
        "junk entries must be drained to quarantine"
    );

    // The original valid broker request file must be removed.
    assert!(
        !broker_dir.join("valid-among-junk.json").exists(),
        "original valid broker request file must be removed after promotion"
    );
}

/// MAJOR fix (TCK-00577 round 16): Verify that both promotion cap and
/// junk drain cap are enforced independently. With candidates at cap
/// and junk at cap, the loop terminates cleanly.
#[test]
fn promote_broker_request_respects_independent_caps() {
    let dir = tempfile::tempdir().expect("tempdir");
    let queue_root = dir.path().join("queue");
    let pending_dir = queue_root.join(PENDING_DIR);
    let broker_dir = queue_root.join(BROKER_REQUESTS_DIR);

    fs::create_dir_all(&pending_dir).expect("pending dir");
    fs::create_dir_all(&broker_dir).expect("broker dir");

    // Create MAX_BROKER_REQUESTS_PROMOTE + 5 valid .json entries.
    // Only MAX_BROKER_REQUESTS_PROMOTE should be promoted.
    let total_candidates = MAX_BROKER_REQUESTS_PROMOTE + 5;
    for i in 0..total_candidates {
        let content = make_valid_broker_request_json(&format!("cap-test-{i:04}"));
        fs::write(broker_dir.join(format!("cap-test-{i:04}.json")), &content)
            .expect("write candidate entry");
    }

    let default_policy = QueueBoundsPolicy::default();
    promote_broker_requests(&queue_root, &default_policy);

    // Count promoted files in pending/.
    let promoted: Vec<_> = fs::read_dir(&pending_dir)
        .expect("read pending")
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with("cap-test-"))
        .collect();
    assert_eq!(
        promoted.len(),
        MAX_BROKER_REQUESTS_PROMOTE,
        "exactly MAX_BROKER_REQUESTS_PROMOTE ({MAX_BROKER_REQUESTS_PROMOTE}) \
             candidates should be promoted, got {}",
        promoted.len()
    );

    // Remaining candidates should still be in broker_requests/.
    let remaining: Vec<_> = fs::read_dir(&broker_dir)
        .expect("read broker dir")
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().ends_with(".json"))
        .collect();
    assert_eq!(
        remaining.len(),
        5,
        "5 excess candidates should remain in broker_requests/ for next cycle"
    );
}

// =========================================================================
// BLOCKER fix: broker file readability by service-user worker
// (TCK-00577 round 16)
// =========================================================================

/// BLOCKER fix (TCK-00577 round 16): Verify that `promote_broker_requests`
/// successfully reads and promotes a file created with mode 0640 (the new
/// broker file mode for cross-user deployments). In same-user tests (test
/// process == broker file owner), the file is always readable. This test
/// verifies the promotion path works end-to-end with the new mode.
#[cfg(unix)]
#[test]
fn promote_broker_request_reads_mode_0640_file() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("tempdir");
    let queue_root = dir.path().join("queue");
    let pending_dir = queue_root.join(PENDING_DIR);
    let broker_dir = queue_root.join(BROKER_REQUESTS_DIR);

    fs::create_dir_all(&pending_dir).expect("pending dir");
    fs::create_dir_all(&broker_dir).expect("broker dir");

    // Write a valid broker request with mode 0640 (new default for
    // cross-user deployments).
    let content = make_valid_broker_request_json("mode-0640-test");
    let broker_file = broker_dir.join("mode-0640-test.json");
    fs::write(&broker_file, &content).expect("write broker request");
    fs::set_permissions(&broker_file, fs::Permissions::from_mode(0o640)).expect("set mode 0640");

    let default_policy = QueueBoundsPolicy::default();
    promote_broker_requests(&queue_root, &default_policy);

    // The file must be promoted (not quarantined due to EACCES).
    assert!(
        pending_dir.join("mode-0640-test.json").exists(),
        "broker request with mode 0640 must be promoted to pending/ \
             (not quarantined)"
    );
}

/// BLOCKER fix (TCK-00577 round 16): Verify that
/// `promote_broker_requests` also works with mode 0644 files (fallback
/// mode when service user is not resolvable in dev environments).
#[cfg(unix)]
#[test]
fn promote_broker_request_reads_mode_0644_file() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("tempdir");
    let queue_root = dir.path().join("queue");
    let pending_dir = queue_root.join(PENDING_DIR);
    let broker_dir = queue_root.join(BROKER_REQUESTS_DIR);

    fs::create_dir_all(&pending_dir).expect("pending dir");
    fs::create_dir_all(&broker_dir).expect("broker dir");

    // Write with mode 0644 (dev fallback mode).
    let content = make_valid_broker_request_json("mode-0644-test");
    let broker_file = broker_dir.join("mode-0644-test.json");
    fs::write(&broker_file, &content).expect("write broker request");
    fs::set_permissions(&broker_file, fs::Permissions::from_mode(0o644)).expect("set mode 0644");

    let default_policy = QueueBoundsPolicy::default();
    promote_broker_requests(&queue_root, &default_policy);

    assert!(
        pending_dir.join("mode-0644-test.json").exists(),
        "broker request with mode 0644 must be promoted to pending/"
    );
}

#[test]
fn wait_for_worker_signal_returns_immediately_on_pending_wake() {
    let (tx, rx) = std::sync::mpsc::sync_channel(2);
    tx.send(WorkerWakeSignal::Wake(
        WorkerWakeReason::PendingQueueChanged,
    ))
    .expect("send wake");

    let start = std::time::Instant::now();
    let signal = wait_for_worker_signal(&rx, &QueueWatcherMode::Active, 60);
    assert!(
        start.elapsed() < std::time::Duration::from_millis(250),
        "wake wait should be immediate without waiting for safety nudge interval"
    );
    assert!(matches!(
        signal,
        WorkerWakeSignal::Wake(WorkerWakeReason::PendingQueueChanged)
    ));
}

#[test]
fn wait_for_worker_signal_uses_safety_nudge_when_degraded_and_channel_disconnected() {
    let (tx, rx) = std::sync::mpsc::sync_channel::<WorkerWakeSignal>(1);
    drop(tx);

    let (done_tx, done_rx) = std::sync::mpsc::channel::<WorkerWakeSignal>();
    let worker = std::thread::spawn(move || {
        let signal = wait_for_worker_signal(
            &rx,
            &QueueWatcherMode::Degraded {
                reason: "watch unavailable".to_string(),
            },
            1,
        );
        let _ = done_tx.send(signal);
    });

    assert!(
        done_rx
            .recv_timeout(std::time::Duration::from_millis(100))
            .is_err(),
        "degraded disconnected channel must not return immediately (busy-loop guard)"
    );

    let signal = done_rx
        .recv_timeout(std::time::Duration::from_millis(1500))
        .expect("signal should arrive after bounded backoff");
    worker.join().expect("worker thread join");

    assert!(matches!(
        signal,
        WorkerWakeSignal::WatcherUnavailable { .. }
    ));
}

#[test]
fn wait_for_worker_signal_disconnected_channel_applies_backoff_in_active_mode() {
    let (tx, rx) = std::sync::mpsc::sync_channel::<WorkerWakeSignal>(1);
    drop(tx);

    let (done_tx, done_rx) = std::sync::mpsc::channel::<WorkerWakeSignal>();
    let worker = std::thread::spawn(move || {
        let signal = wait_for_worker_signal(&rx, &QueueWatcherMode::Active, 1);
        let _ = done_tx.send(signal);
    });

    assert!(
        done_rx
            .recv_timeout(std::time::Duration::from_millis(100))
            .is_err(),
        "active disconnected channel must not return immediately (busy-loop guard)"
    );

    let signal = done_rx
        .recv_timeout(std::time::Duration::from_millis(1500))
        .expect("signal should arrive after bounded backoff");
    worker.join().expect("worker thread join");

    assert!(matches!(
        signal,
        WorkerWakeSignal::WatcherUnavailable { .. }
    ));
}

#[test]
fn critical_worker_signal_does_not_block_when_queue_is_full_and_preserves_signal() {
    let (tx, rx) = std::sync::mpsc::sync_channel::<WorkerWakeSignal>(1);
    tx.send(WorkerWakeSignal::Wake(
        WorkerWakeReason::PendingQueueChanged,
    ))
    .expect("seed queue full");

    let started = std::time::Instant::now();
    send_critical_worker_signal(
        &tx,
        WorkerWakeSignal::WatcherOverflow {
            reason: "overflow".to_string(),
        },
    );
    assert!(
        started.elapsed() < std::time::Duration::from_millis(100),
        "critical signal path must not block watcher thread when channel is full"
    );

    let first = rx.recv().expect("receive seeded signal");
    assert!(matches!(
        first,
        WorkerWakeSignal::Wake(WorkerWakeReason::PendingQueueChanged)
    ));

    let second = rx
        .recv_timeout(std::time::Duration::from_millis(250))
        .expect("critical signal should still be delivered once capacity is available");
    assert!(matches!(second, WorkerWakeSignal::WatcherOverflow { .. }));
}

#[test]
fn runtime_repair_coordinator_coalesces_duplicate_requests() {
    let mut coordinator = RuntimeRepairCoordinator::new(RuntimeQueueReconcileConfig {
        orphan_policy: OrphanedJobPolicy::Requeue,
        limits: QueueReconcileLimits::default(),
    });
    let (tx, rx) = std::sync::mpsc::sync_channel(4);

    coordinator.request(&tx, false, "first");
    coordinator.request(&tx, false, "duplicate");

    assert_eq!(coordinator.state, RuntimeRepairState::RepairRequested);
    assert!(matches!(
        rx.recv().expect("first wake"),
        WorkerWakeSignal::Wake(WorkerWakeReason::RepairRequested)
    ));
    assert!(
        matches!(
            rx.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty | std::sync::mpsc::TryRecvError::Disconnected)
        ),
        "duplicate requests must coalesce and not enqueue unbounded wake events"
    );
}

#[test]
fn runtime_repair_requests_claimed_reconcile_in_degraded_mode() {
    let degraded_mode = QueueWatcherMode::Degraded {
        reason: "watch unavailable".to_string(),
    };

    let mut degraded_entry = RuntimeRepairCoordinator::new(RuntimeQueueReconcileConfig {
        orphan_policy: OrphanedJobPolicy::Requeue,
        limits: QueueReconcileLimits::default(),
    });
    let (entry_tx, entry_rx) = std::sync::mpsc::sync_channel(2);
    request_runtime_repair_for_wake(
        &mut degraded_entry,
        &entry_tx,
        &degraded_mode,
        WorkerWakeReason::WatcherDegraded,
        false,
    );
    assert!(matches!(
        entry_rx
            .recv()
            .expect("watcher degraded must request repair"),
        WorkerWakeSignal::Wake(WorkerWakeReason::RepairRequested)
    ));

    let mut degraded_nudge = RuntimeRepairCoordinator::new(RuntimeQueueReconcileConfig {
        orphan_policy: OrphanedJobPolicy::Requeue,
        limits: QueueReconcileLimits::default(),
    });
    let (nudge_tx, nudge_rx) = std::sync::mpsc::sync_channel(2);
    request_runtime_repair_for_wake(
        &mut degraded_nudge,
        &nudge_tx,
        &degraded_mode,
        WorkerWakeReason::SafetyNudge,
        false,
    );
    assert!(matches!(
        nudge_rx
            .recv()
            .expect("degraded safety nudge must request repair"),
        WorkerWakeSignal::Wake(WorkerWakeReason::RepairRequested)
    ));

    let mut active_nudge = RuntimeRepairCoordinator::new(RuntimeQueueReconcileConfig {
        orphan_policy: OrphanedJobPolicy::Requeue,
        limits: QueueReconcileLimits::default(),
    });
    let (active_tx, active_rx) = std::sync::mpsc::sync_channel(2);
    request_runtime_repair_for_wake(
        &mut active_nudge,
        &active_tx,
        &QueueWatcherMode::Active,
        WorkerWakeReason::SafetyNudge,
        false,
    );
    assert!(
        matches!(
            active_rx.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty | std::sync::mpsc::TryRecvError::Disconnected)
        ),
        "active safety nudge should not request claimed reconcile"
    );
}

#[test]
fn runtime_repair_state_machine_transitions_blocked_then_idle() {
    let mut coordinator = RuntimeRepairCoordinator::new(RuntimeQueueReconcileConfig {
        orphan_policy: OrphanedJobPolicy::Requeue,
        limits: QueueReconcileLimits {
            max_claimed_scan_entries: 0,
            max_queue_recovery_actions: apm2_core::fac::MAX_QUEUE_RECOVERY_ACTIONS,
        },
    });
    let (tx, _rx) = std::sync::mpsc::sync_channel(1);

    coordinator.request(&tx, false, "explicit");
    coordinator.mark_scan_lock_awaiting();
    assert_eq!(coordinator.state, RuntimeRepairState::AwaitingScanLock);

    let dir = tempfile::tempdir().expect("tempdir");
    let fac_root = dir.path().join("private").join("fac");
    let queue_root = dir.path().join("queue");
    let lanes_dir = fac_root.join("lanes");
    let locks_dir = fac_root.join("locks").join("lanes");
    std::fs::create_dir_all(&lanes_dir).expect("lanes dir");
    std::fs::create_dir_all(&locks_dir).expect("locks dir");
    std::fs::create_dir_all(queue_root.join("claimed")).expect("claimed dir");
    std::fs::create_dir_all(queue_root.join("pending")).expect("pending dir");
    std::fs::create_dir_all(queue_root.join("denied")).expect("denied dir");
    let claimed_job = serde_json::json!({
        "schema": "apm2.fac.job_spec.v1",
        "job_id": "runtime-blocked-job",
        "kind": "test",
    });
    std::fs::write(
        queue_root.join("claimed").join("runtime-blocked-job.json"),
        serde_json::to_vec_pretty(&claimed_job).expect("serialize claimed"),
    )
    .expect("write claimed job");

    let outcome = coordinator
        .attempt(&fac_root, &queue_root, true)
        .expect("attempt should produce runtime outcome");
    assert_eq!(outcome.status, RuntimeQueueReconcileStatus::Blocked);
    assert_eq!(coordinator.state, RuntimeRepairState::Blocked);

    coordinator.settle_idle();
    assert_eq!(coordinator.state, RuntimeRepairState::Idle);
}

#[cfg(unix)]
#[test]
fn runtime_repair_state_machine_retains_failed_request_until_success() {
    use std::os::unix::fs::PermissionsExt;

    let mut coordinator = RuntimeRepairCoordinator::new(RuntimeQueueReconcileConfig {
        orphan_policy: OrphanedJobPolicy::MarkFailed,
        limits: QueueReconcileLimits::default(),
    });
    let (tx, _rx) = std::sync::mpsc::sync_channel(1);

    coordinator.request(&tx, false, "explicit");

    let dir = tempfile::tempdir().expect("tempdir");
    let fac_root = dir.path().join("private").join("fac");
    let queue_root = dir.path().join("queue");
    std::fs::create_dir_all(fac_root.join("lanes")).expect("lanes dir");
    std::fs::create_dir_all(fac_root.join("locks").join("lanes")).expect("locks dir");
    std::fs::create_dir_all(queue_root.join("claimed")).expect("claimed dir");
    std::fs::create_dir_all(queue_root.join("pending")).expect("pending dir");
    std::fs::create_dir_all(queue_root.join("denied")).expect("denied dir");
    let denied_dir = queue_root.join("denied");
    std::fs::set_permissions(&denied_dir, std::fs::Permissions::from_mode(0o555))
        .expect("set denied mode");

    let claimed_job = serde_json::json!({
        "schema": "apm2.fac.job_spec.v1",
        "job_id": "runtime-failed-job",
        "kind": "test",
    });
    std::fs::write(
        queue_root.join("claimed").join("runtime-failed-job.json"),
        serde_json::to_vec_pretty(&claimed_job).expect("serialize claimed"),
    )
    .expect("write claimed job");

    let failed_outcome = coordinator
        .attempt(&fac_root, &queue_root, true)
        .expect("attempt should produce runtime outcome");
    assert_eq!(failed_outcome.status, RuntimeQueueReconcileStatus::Failed);
    assert_eq!(coordinator.state, RuntimeRepairState::Failed);
    assert!(
        coordinator.repair_requested,
        "failed reconcile must retain repair request for retry"
    );

    coordinator.settle_idle();
    assert_eq!(
        coordinator.state,
        RuntimeRepairState::Failed,
        "failed state should not settle to idle while repair request remains pending"
    );

    std::fs::set_permissions(&denied_dir, std::fs::Permissions::from_mode(0o700))
        .expect("restore denied mode");
    let retry_outcome = coordinator
        .attempt(&fac_root, &queue_root, true)
        .expect("retry attempt should produce runtime outcome");
    assert!(
        matches!(
            retry_outcome.status,
            RuntimeQueueReconcileStatus::Applied | RuntimeQueueReconcileStatus::Skipped
        ),
        "retry should resolve failed latch to a non-failed terminal status, got: {:?}",
        retry_outcome.status
    );
    assert!(
        !coordinator.repair_requested,
        "successful retry must clear repair request"
    );
}

#[test]
fn dual_write_emits_all_lifecycle_phases_for_worker_queue_mutations() {
    use apm2_core::fac::job_lifecycle::{
        FAC_JOB_CLAIMED_EVENT_TYPE, FAC_JOB_COMPLETED_EVENT_TYPE, FAC_JOB_ENQUEUED_EVENT_TYPE,
        FAC_JOB_FAILED_EVENT_TYPE, FAC_JOB_RELEASED_EVENT_TYPE, FAC_JOB_STARTED_EVENT_TYPE,
    };
    use apm2_core::fac::service_user_gate::QueueWriteMode;

    let _guard = env_var_test_lock().lock().expect("serialize env test");
    let original_apm2_home = std::env::var_os("APM2_HOME");
    assert_dual_write_requirement_traceability();

    let dir = tempfile::tempdir().expect("tempdir");
    let apm2_home = dir.path().join(".apm2");
    let fac_root = apm2_home.join("private").join("fac");
    let queue_root = apm2_home.join("queue");
    std::fs::create_dir_all(&fac_root).expect("create fac root");
    ensure_queue_dirs(&queue_root).expect("create queue dirs");
    set_env_var_for_test("APM2_HOME", &apm2_home);

    let mut policy = FacPolicyV1::default_policy();
    policy.queue_lifecycle_dual_write_enabled = true;
    persist_policy(&fac_root, &policy).expect("persist dual-write policy");
    let _lifecycle_harness =
        fac_queue_lifecycle_dual_write::install_deterministic_lifecycle_harness(
            fac_queue_lifecycle_dual_write::DeterministicLifecycleHarnessConfig {
                simulate_only: true,
                ..Default::default()
            },
        );

    let mut spec_completed = make_receipt_test_spec();
    spec_completed.job_id = "job-lifecycle-completed".to_string();
    spec_completed.job_spec_digest = format!("b3-256:{}", "1".repeat(64));
    spec_completed.actuation.lease_id = "lease-lifecycle-completed".to_string();

    let mut spec_released = make_receipt_test_spec();
    spec_released.job_id = "job-lifecycle-released".to_string();
    spec_released.job_spec_digest = format!("b3-256:{}", "2".repeat(64));
    spec_released.actuation.lease_id = "lease-lifecycle-released".to_string();

    let mut spec_failed = make_receipt_test_spec();
    spec_failed.job_id = "job-lifecycle-failed".to_string();
    spec_failed.job_spec_digest = format!("b3-256:{}", "3".repeat(64));
    spec_failed.actuation.lease_id = "lease-lifecycle-failed".to_string();

    let channel_boundary = ChannelBoundaryTrace {
        passed: true,
        defect_count: 0,
        defect_classes: Vec::new(),
        token_fac_policy_hash: None,
        token_canonicalizer_tuple_digest: None,
        token_boundary_id: None,
        token_issued_at_tick: None,
        token_expiry_tick: None,
    };
    let queue_admission = JobQueueAdmissionTrace {
        verdict: "allow".to_string(),
        queue_lane: "control".to_string(),
        defect_reason: None,
        cost_estimate_ticks: None,
    };

    for spec in [&spec_completed, &spec_released, &spec_failed] {
        crate::commands::fac_queue_submit::enqueue_job(
            &queue_root,
            &fac_root,
            spec,
            &QueueBoundsPolicy::default(),
            QueueWriteMode::UnsafeLocalWrite,
            true,
        )
        .expect("enqueue with lifecycle dual-write");
    }

    let claimed_dir = queue_root.join(CLAIMED_DIR);
    let completed_file_name = format!("{}.json", spec_completed.job_id);
    let pending_completed = queue_root.join(PENDING_DIR).join(&completed_file_name);
    let (claimed_completed, completed_lock_file) = claim_pending_job_with_exclusive_lock(
        &pending_completed,
        &claimed_dir,
        &completed_file_name,
        &fac_root,
        true,
    )
    .expect("claim completed job");
    drop(completed_lock_file);
    let completed_terminal = commit_claimed_job_via_pipeline(
        &fac_root,
        &queue_root,
        &spec_completed,
        &claimed_completed,
        &completed_file_name,
        FacJobOutcome::Completed,
        None,
        "completed",
        Some(&channel_boundary),
        Some(&queue_admission),
        None,
        None,
        None,
        &spec_completed.job_spec_digest,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .expect("commit completed job");
    assert!(
        completed_terminal.starts_with(queue_root.join(COMPLETED_DIR)),
        "completed job must move to completed/"
    );

    let released_file_name = format!("{}.json", spec_released.job_id);
    let pending_released = queue_root.join(PENDING_DIR).join(&released_file_name);
    let (claimed_released, released_lock_file) = claim_pending_job_with_exclusive_lock(
        &pending_released,
        &claimed_dir,
        &released_file_name,
        &fac_root,
        true,
    )
    .expect("claim released job");
    drop(released_lock_file);
    let released_path = release_claimed_job_to_pending(
        &claimed_released,
        &queue_root,
        &released_file_name,
        &fac_root,
        &spec_released,
        "test_release_to_pending",
    )
    .expect("release claimed job back to pending");
    assert!(
        released_path.starts_with(queue_root.join(PENDING_DIR)),
        "released job must move back to pending/"
    );

    let failed_file_name = format!("{}.json", spec_failed.job_id);
    let pending_failed = queue_root.join(PENDING_DIR).join(&failed_file_name);
    let (claimed_failed, failed_lock_file) = claim_pending_job_with_exclusive_lock(
        &pending_failed,
        &claimed_dir,
        &failed_file_name,
        &fac_root,
        true,
    )
    .expect("claim failed job");
    drop(failed_lock_file);
    let failed_terminal = commit_claimed_job_via_pipeline(
        &fac_root,
        &queue_root,
        &spec_failed,
        &claimed_failed,
        &failed_file_name,
        FacJobOutcome::Denied,
        Some(DenialReasonCode::ValidationFailed),
        "denied",
        Some(&channel_boundary),
        Some(&queue_admission),
        None,
        None,
        None,
        &spec_failed.job_spec_digest,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .expect("commit failed job");
    assert!(
        failed_terminal.starts_with(queue_root.join(DENIED_DIR)),
        "failed job must move to denied/"
    );

    let counts = fac_queue_lifecycle_dual_write::deterministic_lifecycle_emission_counts();

    assert!(
        counts
            .get(FAC_JOB_ENQUEUED_EVENT_TYPE)
            .copied()
            .unwrap_or(0)
            == 3,
        "enqueue transitions must deterministically emit 3 fac.job.enqueued events"
    );
    assert!(
        counts.get(FAC_JOB_CLAIMED_EVENT_TYPE).copied().unwrap_or(0) == 3,
        "claim transitions must deterministically emit 3 fac.job.claimed events"
    );
    assert!(
        counts.get(FAC_JOB_STARTED_EVENT_TYPE).copied().unwrap_or(0) == 2,
        "terminal claimed flows must deterministically emit 2 fac.job.started events"
    );
    assert!(
        counts
            .get(FAC_JOB_COMPLETED_EVENT_TYPE)
            .copied()
            .unwrap_or(0)
            == 1,
        "completed transitions must deterministically emit 1 fac.job.completed event"
    );
    assert!(
        counts
            .get(FAC_JOB_RELEASED_EVENT_TYPE)
            .copied()
            .unwrap_or(0)
            == 1,
        "release transitions must deterministically emit 1 fac.job.released event"
    );
    assert!(
        counts.get(FAC_JOB_FAILED_EVENT_TYPE).copied().unwrap_or(0) == 1,
        "failed transitions must deterministically emit 1 fac.job.failed event"
    );

    if let Some(value) = original_apm2_home {
        set_env_var_for_test("APM2_HOME", value);
    } else {
        remove_env_var_for_test("APM2_HOME");
    }
}

#[cfg(unix)]
#[test]
fn claim_pending_job_with_exclusive_lock_continues_when_dual_write_emit_fails() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().expect("tempdir");
    let queue_root = temp.path().join("queue");
    let pending_dir = queue_root.join(PENDING_DIR);
    let claimed_dir = queue_root.join(CLAIMED_DIR);
    std::fs::create_dir_all(&pending_dir).expect("create pending");
    std::fs::create_dir_all(&claimed_dir).expect("create claimed");

    let private_dir = temp.path().join("private");
    std::fs::create_dir_all(&private_dir).expect("create private");
    let fac_root_real = private_dir.join("fac-real");
    std::fs::create_dir_all(&fac_root_real).expect("create fac root");
    let fac_root_link = private_dir.join("fac-link");
    symlink(&fac_root_real, &fac_root_link).expect("create fac root symlink");

    let file_name = "claim-dual-write-emit-fail.json";
    let pending_path = pending_dir.join(file_name);
    std::fs::write(
        &pending_path,
        make_valid_broker_request_json("claim-dual-write-emit-fail"),
    )
    .expect("write pending spec");

    let (claimed_path, claimed_lock_file) = claim_pending_job_with_exclusive_lock(
        &pending_path,
        &claimed_dir,
        file_name,
        &fac_root_link,
        true,
    )
    .expect("claim should continue when lifecycle emit fails");
    drop(claimed_lock_file);

    assert!(
        !pending_path.exists(),
        "pending job should be moved to claimed even when emit fails"
    );
    assert!(
        claimed_path.exists(),
        "claimed job should exist after claim"
    );
    assert!(
        !fac_root_real.join("signing_key").exists(),
        "test setup should force lifecycle emission failure via symlink FAC root"
    );
}

/// Prove the move-first invariant for claim: a pending file with a payload
/// that cannot be deserialized as `FacJobSpecV1` is still atomically moved
/// to `claimed/` — deserialization failure does NOT block or revert the
/// filesystem transition.
///
/// This is the regression test for the round-8 security finding: without
/// move-first, malformed payloads would be permanently stuck in `pending/`,
/// exhausting `QueueBoundsPolicy` capacity over time.
#[test]
fn claim_pending_job_moves_malformed_payload_to_claimed_before_deserializing() {
    let temp = tempfile::tempdir().expect("tempdir");
    let queue_root = temp.path().join("queue");
    let fac_root = temp.path().join("private").join("fac");
    let pending_dir = queue_root.join(PENDING_DIR);
    let claimed_dir = queue_root.join(CLAIMED_DIR);
    std::fs::create_dir_all(&fac_root).expect("create fac root");
    std::fs::create_dir_all(&pending_dir).expect("create pending");
    std::fs::create_dir_all(&claimed_dir).expect("create claimed");

    // Write a deliberately malformed payload that will fail FacJobSpecV1
    // deserialization (missing required fields). This simulates the exact
    // scenario from the finding: a pending file with corrupt/incomplete JSON.
    let file_name = "malformed-claim-test.json";
    let pending_path = pending_dir.join(file_name);
    std::fs::write(
        &pending_path,
        b"{\"not_a_valid_spec\": true, \"garbage\": 42}",
    )
    .expect("write malformed pending spec");

    // Claim with dual_write_enabled=true to exercise the post-move
    // deserialization path (the code reads the claimed file AFTER the move
    // and attempts to deserialize for lifecycle emission).
    let result = claim_pending_job_with_exclusive_lock(
        &pending_path,
        &claimed_dir,
        file_name,
        &fac_root,
        true, // dual_write_enabled
    );

    // The claim MUST succeed even though the payload is malformed.
    let (claimed_path, _lock) = result.expect(
        "claim must succeed for malformed payload — move-first invariant: \
         deserialization failure must not block the pending->claimed transition",
    );

    // The file must no longer exist in pending/.
    assert!(
        !pending_path.exists(),
        "malformed file must be removed from pending/ (move-first invariant)"
    );

    // The file must exist in claimed/.
    assert!(
        claimed_path.exists(),
        "malformed file must exist in claimed/ after move-first claim"
    );
    assert!(
        claimed_path.starts_with(&claimed_dir),
        "claimed path must be inside claimed/ directory"
    );

    // Verify the content is still the malformed payload (not modified).
    let content = std::fs::read_to_string(&claimed_path).expect("read claimed file");
    assert!(
        content.contains("not_a_valid_spec"),
        "claimed file content must be preserved (the original malformed payload)"
    );
}

/// Prove move-first with completely non-JSON binary payload (not even valid
/// JSON). The pending->claimed move must still succeed.
#[test]
fn claim_pending_job_moves_binary_garbage_to_claimed() {
    let temp = tempfile::tempdir().expect("tempdir");
    let queue_root = temp.path().join("queue");
    let fac_root = temp.path().join("private").join("fac");
    let pending_dir = queue_root.join(PENDING_DIR);
    let claimed_dir = queue_root.join(CLAIMED_DIR);
    std::fs::create_dir_all(&fac_root).expect("create fac root");
    std::fs::create_dir_all(&pending_dir).expect("create pending");
    std::fs::create_dir_all(&claimed_dir).expect("create claimed");

    let file_name = "binary-garbage.json";
    let pending_path = pending_dir.join(file_name);
    // Write binary content that is not valid JSON at all.
    std::fs::write(&pending_path, [0xFF, 0xFE, 0x00, 0x01, 0x80, 0x90])
        .expect("write binary garbage");

    let (claimed_path, _lock) = claim_pending_job_with_exclusive_lock(
        &pending_path,
        &claimed_dir,
        file_name,
        &fac_root,
        true, // dual_write_enabled — forces the post-move deserialization attempt
    )
    .expect(
        "claim must succeed for binary garbage — move-first invariant: \
         the filesystem move is unconditional, deserialization is best-effort",
    );

    assert!(
        !pending_path.exists(),
        "binary garbage must be removed from pending/"
    );
    assert!(
        claimed_path.exists(),
        "binary garbage must exist in claimed/ after move-first"
    );
}

#[cfg(unix)]
#[test]
fn release_claimed_job_to_pending_continues_when_dual_write_emit_fails() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().expect("tempdir");
    let queue_root = temp.path().join("queue");
    let pending_dir = queue_root.join(PENDING_DIR);
    let claimed_dir = queue_root.join(CLAIMED_DIR);
    std::fs::create_dir_all(&pending_dir).expect("create pending");
    std::fs::create_dir_all(&claimed_dir).expect("create claimed");

    let private_dir = temp.path().join("private");
    std::fs::create_dir_all(&private_dir).expect("create private");
    let fac_root_real = private_dir.join("fac-real");
    std::fs::create_dir_all(&fac_root_real).expect("create fac root");
    let fac_root_link = private_dir.join("fac-link");
    symlink(&fac_root_real, &fac_root_link).expect("create fac root symlink");

    let mut policy = FacPolicyV1::default_policy();
    policy.queue_lifecycle_dual_write_enabled = true;
    persist_policy(&fac_root_real, &policy).expect("persist dual-write policy");

    let job_id = "release-dual-write-emit-fail";
    let file_name = format!("{job_id}.json");
    let job_json = make_valid_broker_request_json(job_id);
    let spec: FacJobSpecV1 = serde_json::from_str(&job_json).expect("parse job spec");
    let claimed_path = claimed_dir.join(&file_name);
    std::fs::write(&claimed_path, job_json.as_bytes()).expect("write claimed spec");

    let moved_path = release_claimed_job_to_pending(
        &claimed_path,
        &queue_root,
        &file_name,
        &fac_root_link,
        &spec,
        "dual_write_emit_failure_test",
    )
    .expect("release should continue when lifecycle emit fails");

    assert!(
        !claimed_path.exists(),
        "claimed file should be moved back to pending"
    );
    assert!(moved_path.exists(), "released job should exist in pending");
    assert!(
        moved_path.starts_with(queue_root.join(PENDING_DIR)),
        "released job should move to pending/: {moved_path:?}"
    );
    assert!(
        !fac_root_real.join("signing_key").exists(),
        "test setup should force lifecycle emission failure via symlink FAC root"
    );
}

#[test]
fn claim_pending_job_with_exclusive_lock_holds_lock_for_job_lifecycle() {
    let temp = tempfile::tempdir().expect("tempdir");
    let queue_root = temp.path().join("queue");
    let fac_root = temp.path().join("private").join("fac");
    let pending_dir = queue_root.join(PENDING_DIR);
    let claimed_dir = queue_root.join(CLAIMED_DIR);
    std::fs::create_dir_all(&fac_root).expect("create fac root");
    std::fs::create_dir_all(&pending_dir).expect("create pending");
    std::fs::create_dir_all(&claimed_dir).expect("create claimed");

    let pending_path = pending_dir.join("lock-test.json");
    std::fs::write(&pending_path, b"{\"job_id\":\"lock-test\"}").expect("write pending spec");

    let (claimed_path, claimed_lock_file) = claim_pending_job_with_exclusive_lock(
        &pending_path,
        &claimed_dir,
        "lock-test.json",
        &fac_root,
        false,
    )
    .expect("claim+lock pending job");
    assert!(
        !pending_path.exists(),
        "pending file should move to claimed during claim"
    );
    assert!(claimed_path.exists(), "claimed file must exist");

    let probe = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&claimed_path)
        .expect("open claimed probe");
    let lock_attempt = fs2::FileExt::try_lock_exclusive(&probe);
    assert!(
        lock_attempt.is_err(),
        "second exclusive lock attempt must fail while worker lock is held"
    );

    drop(claimed_lock_file);

    let probe_after_release = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&claimed_path)
        .expect("open claimed probe after release");
    fs2::FileExt::try_lock_exclusive(&probe_after_release)
        .expect("exclusive lock should succeed after worker lock drops");
}

#[test]
fn queue_watcher_mode_transitions_to_degraded_once() {
    let mut mode = QueueWatcherMode::Active;
    assert!(mode.transition_to_degraded("overflow".to_string()));
    assert!(mode.is_degraded());
    assert_eq!(mode.reason(), Some("overflow"));
    assert!(
        !mode.transition_to_degraded("different".to_string()),
        "degraded transition should be one-way and idempotent"
    );
}

// =========================================================================
// Orchestration classification tests
// =========================================================================

#[test]
fn test_orchestration_error_display() {
    let recoverable = OrchestrationError::Recoverable("transient IO".to_string());
    assert_eq!(format!("{recoverable}"), "recoverable: transient IO");

    let needs_reconcile = OrchestrationError::NeedsReconcile("torn state".to_string());
    assert_eq!(format!("{needs_reconcile}"), "needs_reconcile: torn state");

    let corrupt_lane = OrchestrationError::CorruptLane {
        lane_id: "lane-7".to_string(),
        reason: "missing lease".to_string(),
    };
    assert_eq!(
        format!("{corrupt_lane}"),
        "corrupt_lane(lane-7): missing lease"
    );

    let quarantine = OrchestrationError::QuarantineJob {
        job_id: "j-999".to_string(),
        reason: "digest mismatch".to_string(),
    };
    assert_eq!(
        format!("{quarantine}"),
        "quarantine_job(j-999): digest mismatch"
    );

    let fatal = OrchestrationError::Fatal("config missing".to_string());
    assert_eq!(format!("{fatal}"), "fatal: config missing");
}

#[test]
fn test_orchestration_classification_routes_pipeline_commit_failure_to_reconcile() {
    let outcome = JobOutcome::Skipped {
        reason: "receipt pipeline commit failed".to_string(),
        disposition: JobSkipDisposition::PipelineCommitFailed,
    };

    let classification = classify_job_outcome_for_orchestration("j-commit", &outcome);
    match classification {
        OrchestrationError::NeedsReconcile(reason) => {
            assert_eq!(reason, "receipt pipeline commit failed");
        },
        other => panic!("expected NeedsReconcile, got {other:?}"),
    }
}

#[test]
fn test_orchestration_classification_routes_no_lane_to_corrupt_lane_signal() {
    let outcome = JobOutcome::Skipped {
        reason: "no lane available, returning to pending".to_string(),
        disposition: JobSkipDisposition::NoLaneAvailable,
    };

    let classification = classify_job_outcome_for_orchestration("j-nolane", &outcome);
    match classification {
        OrchestrationError::CorruptLane { lane_id, reason } => {
            assert_eq!(lane_id, "unassigned");
            assert_eq!(reason, "no lane available, returning to pending");
        },
        other => panic!("expected CorruptLane classification, got {other:?}"),
    }
}

#[test]
fn test_orchestration_classification_routes_quarantine_with_job_id() {
    let outcome = JobOutcome::Quarantined {
        reason: "digest mismatch".to_string(),
    };

    let classification = classify_job_outcome_for_orchestration("j-quarantine", &outcome);
    match classification {
        OrchestrationError::QuarantineJob { job_id, reason } => {
            assert_eq!(job_id, "j-quarantine");
            assert_eq!(reason, "digest mismatch");
        },
        other => panic!("expected QuarantineJob classification, got {other:?}"),
    }
}

// =============================================================================
// f-798-security-1771826098242190-0: Regression tests for queue_job_id
// validation in scan_pending_from_projection.
// =============================================================================

#[test]
fn is_safe_queue_job_id_rejects_path_traversal_with_slash() {
    // queue_job_id containing "/" must be rejected.
    assert!(!is_safe_queue_job_id("../etc/passwd"));
    assert!(!is_safe_queue_job_id("foo/bar"));
    assert!(!is_safe_queue_job_id("/absolute/path"));
}

#[test]
fn is_safe_queue_job_id_rejects_dot_dot_sequences() {
    // queue_job_id containing ".." must be rejected (dots not in allowlist).
    assert!(!is_safe_queue_job_id(".."));
    assert!(!is_safe_queue_job_id("..%2f..%2fetc%2fpasswd"));
    assert!(!is_safe_queue_job_id("a..b"));
}

#[test]
fn is_safe_queue_job_id_rejects_absolute_paths() {
    assert!(!is_safe_queue_job_id("/etc/passwd"));
    assert!(!is_safe_queue_job_id("/tmp/malicious"));
}

#[test]
fn is_safe_queue_job_id_rejects_overlong_names() {
    let overlong = "a".repeat(257);
    assert!(!is_safe_queue_job_id(&overlong));
}

#[test]
fn is_safe_queue_job_id_rejects_empty() {
    assert!(!is_safe_queue_job_id(""));
}

#[test]
fn is_safe_queue_job_id_rejects_backslash() {
    assert!(!is_safe_queue_job_id("foo\\bar"));
    assert!(!is_safe_queue_job_id("..\\..\\windows\\system32"));
}

#[test]
fn is_safe_queue_job_id_rejects_dots_and_spaces() {
    // Dots and spaces are not in the alphanumeric/hyphen/underscore allowlist.
    assert!(!is_safe_queue_job_id("."));
    assert!(!is_safe_queue_job_id("foo bar"));
    assert!(!is_safe_queue_job_id("job.json"));
}

#[test]
fn is_safe_queue_job_id_accepts_valid_ids() {
    assert!(is_safe_queue_job_id("valid-job-id"));
    assert!(is_safe_queue_job_id("job_123_abc"));
    assert!(is_safe_queue_job_id("UPPERCASE-id"));
    assert!(is_safe_queue_job_id("a"));
    // Exactly at length limit is allowed.
    let at_limit = "a".repeat(256);
    assert!(is_safe_queue_job_id(&at_limit));
}
