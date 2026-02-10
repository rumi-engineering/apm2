//! Dispatch pipeline: detached review spawning, locks, and pending tracking.

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use chrono::Utc;
use fs2::FileExt;

use super::state::{
    ReviewRunStateLoad, build_review_run_id, load_review_run_state_for_home,
    next_review_sequence_number_for_home, write_review_run_state_for_home,
};
use super::types::{
    DISPATCH_LOCK_ACQUIRE_TIMEOUT, DISPATCH_PENDING_TTL, DispatchIdempotencyKey,
    DispatchReviewResult, PendingDispatchEntry, ReviewKind, ReviewRunState, ReviewRunStatus,
    TERMINAL_AMBIGUOUS_DISPATCH_OWNERSHIP, TERMINAL_DISPATCH_LOCK_TIMEOUT,
    TERMINAL_SHA_DRIFT_SUPERSEDED, TERMINAL_STALE_HEAD_AMBIGUITY, TERMINATE_TIMEOUT, apm2_home_dir,
    ensure_parent_dir, now_iso8601,
};

// ── Path helpers ────────────────────────────────────────────────────────────

fn review_dispatch_locks_dir_for_home(home: &Path) -> PathBuf {
    home.join("review_dispatch_locks")
}

fn review_dispatch_pending_dir_for_home(home: &Path) -> PathBuf {
    home.join("review_dispatch_pending")
}

fn review_dispatch_lock_path_for_home(home: &Path, key: &DispatchIdempotencyKey) -> PathBuf {
    key.lock_path(&review_dispatch_locks_dir_for_home(home))
}

fn review_dispatch_scope_lock_path_for_home(home: &Path, key: &DispatchIdempotencyKey) -> PathBuf {
    key.scope_lock_path(&review_dispatch_locks_dir_for_home(home))
}

fn review_dispatch_pending_path_for_home(home: &Path, key: &DispatchIdempotencyKey) -> PathBuf {
    key.pending_path(&review_dispatch_pending_dir_for_home(home))
}

// ── Pending dispatch I/O ────────────────────────────────────────────────────

fn read_pending_dispatch_entry(path: &Path) -> Result<Option<PendingDispatchEntry>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let text = fs::read_to_string(path)
        .map_err(|err| format!("failed to read dispatch marker {}: {err}", path.display()))?;
    let entry = serde_json::from_str::<PendingDispatchEntry>(&text)
        .map_err(|err| format!("failed to parse dispatch marker {}: {err}", path.display()))?;
    Ok(Some(entry))
}

fn read_fresh_pending_dispatch_for_home(
    home: &Path,
    key: &DispatchIdempotencyKey,
) -> Result<Option<PendingDispatchEntry>, String> {
    let path = review_dispatch_pending_path_for_home(home, key);
    let Some(entry) = read_pending_dispatch_entry(&path)? else {
        return Ok(None);
    };

    let age = Utc::now()
        .signed_duration_since(entry.started_at)
        .to_std()
        .unwrap_or_default();
    if age > DISPATCH_PENDING_TTL {
        let _ = fs::remove_file(&path);
        return Ok(None);
    }

    if pending_dispatch_is_live(&entry) {
        return Ok(Some(entry));
    }

    let _ = fs::remove_file(&path);
    Ok(None)
}

fn write_pending_dispatch_for_home(
    home: &Path,
    key: &DispatchIdempotencyKey,
    result: &DispatchReviewResult,
) -> Result<(), String> {
    let path = review_dispatch_pending_path_for_home(home, key);
    ensure_parent_dir(&path)?;
    let entry = PendingDispatchEntry {
        started_at: Utc::now(),
        pid: result.pid,
        unit: result.unit.clone(),
        log_file: result.log_file.clone(),
    };
    let payload = serde_json::to_vec_pretty(&entry)
        .map_err(|err| format!("failed to serialize dispatch marker: {err}"))?;
    let parent = path
        .parent()
        .ok_or_else(|| format!("dispatch marker path has no parent: {}", path.display()))?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)
        .map_err(|err| format!("failed to create dispatch marker temp file: {err}"))?;
    temp.write_all(&payload)
        .map_err(|err| format!("failed to write dispatch marker temp file: {err}"))?;
    temp.as_file()
        .sync_all()
        .map_err(|err| format!("failed to sync dispatch marker temp file: {err}"))?;
    temp.persist(&path).map_err(|err| {
        format!(
            "failed to persist dispatch marker {}: {err}",
            path.display()
        )
    })?;
    Ok(())
}

fn pending_dispatch_is_live(entry: &PendingDispatchEntry) -> bool {
    if let Some(pid) = entry.pid {
        return is_process_alive(pid);
    }
    if let Some(unit) = entry.unit.as_deref() {
        return is_systemd_unit_active(unit);
    }
    false
}

// ── Dispatch locking ────────────────────────────────────────────────────────

#[derive(Debug)]
enum DispatchLockError {
    Timeout { path: PathBuf },
    Other(String),
}

fn acquire_dispatch_lock(path: &Path) -> Result<File, DispatchLockError> {
    ensure_parent_dir(path).map_err(DispatchLockError::Other)?;
    let lock_file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(path)
        .map_err(|err| {
            DispatchLockError::Other(format!(
                "failed to open dispatch lock {}: {err}",
                path.display()
            ))
        })?;

    let started = Instant::now();
    loop {
        match FileExt::try_lock_exclusive(&lock_file) {
            Ok(()) => return Ok(lock_file),
            Err(err)
                if err.kind() == ErrorKind::WouldBlock
                    && started.elapsed() < DISPATCH_LOCK_ACQUIRE_TIMEOUT =>
            {
                thread::sleep(Duration::from_millis(50));
            },
            Err(err) if err.kind() == ErrorKind::WouldBlock => {
                return Err(DispatchLockError::Timeout {
                    path: path.to_path_buf(),
                });
            },
            Err(err) => {
                return Err(DispatchLockError::Other(format!(
                    "failed to lock dispatch {}: {err}",
                    path.display()
                )));
            },
        }
    }
}

fn dispatch_lock_error_detail(error: &DispatchLockError) -> String {
    match error {
        DispatchLockError::Timeout { path } => format!(
            "dispatch lock timeout after {:?}: {}",
            DISPATCH_LOCK_ACQUIRE_TIMEOUT,
            path.display()
        ),
        DispatchLockError::Other(detail) => detail.clone(),
    }
}

// ── Process helpers ─────────────────────────────────────────────────────────

fn is_systemd_unit_active(unit: &str) -> bool {
    Command::new("systemctl")
        .args(["--user", "is-active", "--quiet", unit])
        .status()
        .is_ok_and(|status| status.success())
}

fn is_process_alive(pid: u32) -> bool {
    super::state::is_process_alive(pid)
}

fn run_state_has_live_process(state: &ReviewRunState) -> bool {
    state.pid.is_some_and(is_process_alive)
}

fn wait_for_process_exit(pid: u32, timeout: Duration) {
    let started = Instant::now();
    while started.elapsed() < timeout {
        if !is_process_alive(pid) {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn send_signal(pid: u32, signal: &str) -> Result<(), String> {
    if !is_process_alive(pid) {
        return Ok(());
    }
    let status = Command::new("kill")
        .args([signal, &pid.to_string()])
        .status()
        .map_err(|err| format!("failed to send {signal} to pid {pid}: {err}"))?;
    if status.success() || !is_process_alive(pid) {
        return Ok(());
    }
    Err(format!("failed to send {signal} to pid {pid}"))
}

fn terminate_process_with_timeout(pid: u32) -> Result<(), String> {
    if !is_process_alive(pid) {
        return Ok(());
    }

    let _ = send_signal(pid, "-TERM");
    wait_for_process_exit(pid, TERMINATE_TIMEOUT);
    if !is_process_alive(pid) {
        return Ok(());
    }

    send_signal(pid, "-KILL")?;
    wait_for_process_exit(pid, Duration::from_secs(1));
    if is_process_alive(pid) {
        return Err(format!("pid {pid} remained alive after SIGKILL"));
    }
    Ok(())
}

fn wait_for_unit_inactive(unit: &str, timeout: Duration) {
    let started = Instant::now();
    while started.elapsed() < timeout {
        if !is_systemd_unit_active(unit) {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn send_unit_signal(unit: &str, signal: &str) -> Result<(), String> {
    if !is_systemd_unit_active(unit) {
        return Ok(());
    }
    let status = Command::new("systemctl")
        .args(["--user", "kill", "--signal", signal, unit])
        .status()
        .map_err(|err| format!("failed to send SIG{signal} to unit {unit}: {err}"))?;
    if status.success() || !is_systemd_unit_active(unit) {
        return Ok(());
    }
    Err(format!("failed to send SIG{signal} to unit {unit}"))
}

fn terminate_systemd_unit_with_timeout(unit: &str) -> Result<(), String> {
    if !is_systemd_unit_active(unit) {
        return Ok(());
    }

    let _ = send_unit_signal(unit, "TERM");
    wait_for_unit_inactive(unit, TERMINATE_TIMEOUT);
    if !is_systemd_unit_active(unit) {
        return Ok(());
    }

    send_unit_signal(unit, "KILL")?;
    wait_for_unit_inactive(unit, Duration::from_secs(1));
    if is_systemd_unit_active(unit) {
        return Err(format!("unit {unit} remained active after SIGKILL"));
    }
    Ok(())
}

fn terminate_pending_dispatch_entry(entry: &PendingDispatchEntry) -> Result<(), String> {
    if let Some(pid) = entry.pid {
        terminate_process_with_timeout(pid)?;
    }
    if let Some(unit) = entry.unit.as_deref() {
        terminate_systemd_unit_with_timeout(unit)?;
    }
    Ok(())
}

// ── Tool availability ───────────────────────────────────────────────────────

fn command_available(command: &str) -> bool {
    Command::new("sh")
        .args(["-lc", &format!("command -v {command} >/dev/null 2>&1")])
        .status()
        .is_ok_and(|status| status.success())
}

// ── Run-state contract helpers ──────────────────────────────────────────────

fn attach_run_state_contract_for_home(
    home: &Path,
    key: &DispatchIdempotencyKey,
    mut result: DispatchReviewResult,
) -> Result<DispatchReviewResult, String> {
    match load_review_run_state_for_home(home, key.pr_number, &key.review_type)? {
        ReviewRunStateLoad::Present(state) => {
            if state.head_sha.eq_ignore_ascii_case(&key.head_sha) {
                result.run_state = state.status.as_str().to_string();
                result.run_id = Some(state.run_id);
                result.sequence_number = Some(state.sequence_number);
                result.terminal_reason = state.terminal_reason;
                if result.pid.is_none() {
                    result.pid = state.pid;
                }
            }
            Ok(result)
        },
        ReviewRunStateLoad::Missing { .. } => {
            result.run_state = "no-run-state".to_string();
            Ok(result)
        },
        ReviewRunStateLoad::Corrupt { path, error } => Err(format!(
            "corrupt-state path={} detail={error}",
            path.display()
        )),
        ReviewRunStateLoad::Ambiguous { dir, candidates } => {
            let rendered = candidates
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(",");
            Err(format!(
                "ambiguous-state dir={} candidates={rendered}",
                dir.display()
            ))
        },
    }
}

fn write_fail_closed_state_for_dispatch(
    home: &Path,
    pr_url: &str,
    key: &DispatchIdempotencyKey,
    terminal_reason: &str,
    sequence_hint: Option<u32>,
) -> Result<ReviewRunState, String> {
    let sequence_number = sequence_hint
        .or_else(|| {
            next_review_sequence_number_for_home(home, key.pr_number, &key.review_type)
                .ok()
                .filter(|value| *value > 0)
        })
        .unwrap_or(1);
    let state = ReviewRunState {
        run_id: build_review_run_id(
            key.pr_number,
            &key.review_type,
            sequence_number,
            &key.head_sha,
        ),
        pr_url: pr_url.to_string(),
        pr_number: key.pr_number,
        head_sha: key.head_sha.clone(),
        review_type: key.review_type.clone(),
        reviewer_role: "fac_reviewer".to_string(),
        started_at: now_iso8601(),
        status: ReviewRunStatus::Failed,
        terminal_reason: Some(terminal_reason.to_string()),
        model_id: None,
        backend_id: None,
        restart_count: 0,
        sequence_number,
        previous_run_id: None,
        previous_head_sha: None,
        pid: None,
    };
    write_review_run_state_for_home(home, &state)?;
    Ok(state)
}

fn fail_closed_dispatch(
    home: &Path,
    pr_url: &str,
    key: &DispatchIdempotencyKey,
    terminal_reason: &str,
    detail: &str,
    sequence_hint: Option<u32>,
) -> Result<DispatchReviewResult, String> {
    let state_write_error =
        write_fail_closed_state_for_dispatch(home, pr_url, key, terminal_reason, sequence_hint)
            .err();
    let mut message = format!("dispatch denied: reason={terminal_reason} detail={detail}");
    if let Some(err) = state_write_error {
        use std::fmt::Write as _;
        let _ = write!(message, " state_write_error={err}");
    }
    Err(message)
}

fn deny_dispatch_without_state_mutation(
    terminal_reason: &str,
    detail: &str,
) -> Result<DispatchReviewResult, String> {
    Err(format!(
        "dispatch denied: reason={terminal_reason} detail={detail}"
    ))
}

#[derive(Debug, Clone)]
struct DriftLineage {
    previous_run_id: String,
    previous_head_sha: String,
}

fn drift_lineage_from_state(state: &ReviewRunState, key: &DispatchIdempotencyKey) -> DriftLineage {
    let old_run_id = if state.run_id.is_empty() {
        build_review_run_id(
            key.pr_number,
            &key.review_type,
            state.sequence_number.max(1),
            &state.head_sha,
        )
    } else {
        state.run_id.clone()
    };
    DriftLineage {
        previous_run_id: old_run_id,
        previous_head_sha: state.head_sha.clone(),
    }
}

fn resume_dispatch_after_head_drift_for_home<F>(
    home: &Path,
    pr_url: &str,
    key: &DispatchIdempotencyKey,
    review_kind: ReviewKind,
    dispatch_epoch: u64,
    state: &ReviewRunState,
    spawn_review: &F,
) -> Result<DispatchReviewResult, String>
where
    F: Fn(&str, u32, ReviewKind, &str, u64) -> Result<DispatchReviewResult, String>,
{
    let mut superseded = state.clone();
    superseded.status = ReviewRunStatus::Failed;
    superseded.terminal_reason = Some(TERMINAL_SHA_DRIFT_SUPERSEDED.to_string());
    superseded.pid = None;
    write_review_run_state_for_home(home, &superseded)?;

    let lineage = drift_lineage_from_state(state, key);
    let mut seeded =
        seed_pending_run_state_for_dispatch_for_home(home, pr_url, key, Some(&lineage))?;
    let started = match spawn_review(
        pr_url,
        key.pr_number,
        review_kind,
        &key.head_sha,
        dispatch_epoch,
    ) {
        Ok(result) => result,
        Err(err) => {
            seeded.status = ReviewRunStatus::Failed;
            seeded.terminal_reason = Some("dispatch_spawn_failed".to_string());
            write_review_run_state_for_home(home, &seeded)?;
            return Err(err);
        },
    };
    write_pending_dispatch_for_home(home, key, &started)?;

    attach_run_state_contract_for_home(
        home,
        key,
        DispatchReviewResult {
            review_type: key.review_type.clone(),
            mode: "drift_resumed".to_string(),
            run_state: "pending".to_string(),
            run_id: None,
            sequence_number: None,
            terminal_reason: None,
            pid: started.pid,
            unit: started.unit,
            log_file: started.log_file,
        },
    )
}

fn seed_pending_run_state_for_dispatch_for_home(
    home: &Path,
    pr_url: &str,
    key: &DispatchIdempotencyKey,
    lineage: Option<&DriftLineage>,
) -> Result<ReviewRunState, String> {
    let sequence_number =
        next_review_sequence_number_for_home(home, key.pr_number, &key.review_type)?;
    let state = ReviewRunState {
        run_id: build_review_run_id(
            key.pr_number,
            &key.review_type,
            sequence_number,
            &key.head_sha,
        ),
        pr_url: pr_url.to_string(),
        pr_number: key.pr_number,
        head_sha: key.head_sha.clone(),
        review_type: key.review_type.clone(),
        reviewer_role: "fac_reviewer".to_string(),
        started_at: now_iso8601(),
        status: ReviewRunStatus::Pending,
        terminal_reason: None,
        model_id: None,
        backend_id: None,
        restart_count: 0,
        sequence_number,
        previous_run_id: lineage.map(|value| value.previous_run_id.clone()),
        previous_head_sha: lineage.map(|value| value.previous_head_sha.clone()),
        pid: None,
    };
    write_review_run_state_for_home(home, &state)?;
    Ok(state)
}

fn next_sequence_hint_from_state(load: &ReviewRunStateLoad) -> Option<u32> {
    if let ReviewRunStateLoad::Present(state) = load {
        return Some(state.sequence_number.saturating_add(1).max(1));
    }
    None
}

fn dispatch_single_review_locked_for_home<F>(
    home: &Path,
    pr_url: &str,
    key: &DispatchIdempotencyKey,
    review_kind: ReviewKind,
    dispatch_epoch: u64,
    spawn_review: &F,
) -> Result<DispatchReviewResult, String>
where
    F: Fn(&str, u32, ReviewKind, &str, u64) -> Result<DispatchReviewResult, String>,
{
    let run_state_load = load_review_run_state_for_home(home, key.pr_number, &key.review_type)?;
    let sequence_hint = next_sequence_hint_from_state(&run_state_load);
    match run_state_load {
        ReviewRunStateLoad::Ambiguous { dir, candidates } => {
            let rendered = candidates
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(",");
            return fail_closed_dispatch(
                home,
                pr_url,
                key,
                TERMINAL_AMBIGUOUS_DISPATCH_OWNERSHIP,
                &format!(
                    "ambiguous-state dir={} candidates={rendered}",
                    dir.display()
                ),
                sequence_hint,
            );
        },
        ReviewRunStateLoad::Corrupt { path, error } => {
            return fail_closed_dispatch(
                home,
                pr_url,
                key,
                TERMINAL_AMBIGUOUS_DISPATCH_OWNERSHIP,
                &format!("corrupt-state path={} detail={error}", path.display()),
                sequence_hint,
            );
        },
        ReviewRunStateLoad::Present(state) => {
            if !state.status.is_terminal() && state.head_sha.eq_ignore_ascii_case(&key.head_sha) {
                if run_state_has_live_process(&state) {
                    return Ok(DispatchReviewResult {
                        review_type: key.review_type.clone(),
                        mode: "joined".to_string(),
                        run_state: state.status.as_str().to_string(),
                        run_id: Some(state.run_id),
                        sequence_number: Some(state.sequence_number),
                        terminal_reason: state.terminal_reason,
                        pid: state.pid,
                        unit: None,
                        log_file: None,
                    });
                }
                if state.pid.is_none() {
                    if let Some(pending) = read_fresh_pending_dispatch_for_home(home, key)? {
                        return attach_run_state_contract_for_home(
                            home,
                            key,
                            DispatchReviewResult {
                                review_type: key.review_type.clone(),
                                mode: "joined".to_string(),
                                run_state: "unknown".to_string(),
                                run_id: None,
                                sequence_number: None,
                                terminal_reason: None,
                                pid: pending.pid,
                                unit: pending.unit,
                                log_file: pending.log_file,
                            },
                        );
                    }
                    return fail_closed_dispatch(
                        home,
                        pr_url,
                        key,
                        TERMINAL_AMBIGUOUS_DISPATCH_OWNERSHIP,
                        "matching run-state has no pid and no live pending marker",
                        Some(state.sequence_number.saturating_add(1).max(1)),
                    );
                }
            }

            if !state.status.is_terminal() && !state.head_sha.eq_ignore_ascii_case(&key.head_sha) {
                match state.pid {
                    Some(pid) if is_process_alive(pid) => {
                        if let Err(err) = terminate_process_with_timeout(pid) {
                            return fail_closed_dispatch(
                                home,
                                pr_url,
                                key,
                                TERMINAL_STALE_HEAD_AMBIGUITY,
                                &format!(
                                    "failed to terminate stale run pid={pid} head={} run_id={}: {err}",
                                    state.head_sha, state.run_id
                                ),
                                Some(state.sequence_number.saturating_add(1).max(1)),
                            );
                        }
                        return resume_dispatch_after_head_drift_for_home(
                            home,
                            pr_url,
                            key,
                            review_kind,
                            dispatch_epoch,
                            &state,
                            spawn_review,
                        );
                    },
                    _ => {
                        let stale_key = DispatchIdempotencyKey::new(
                            &key.owner_repo,
                            key.pr_number,
                            &key.review_type,
                            &state.head_sha,
                        );
                        if let Err(err) = stale_key.validate() {
                            return fail_closed_dispatch(
                                home,
                                pr_url,
                                key,
                                TERMINAL_STALE_HEAD_AMBIGUITY,
                                &format!(
                                    "stale run-state has invalid head old_head={} run_id={} detail={err}",
                                    state.head_sha, state.run_id
                                ),
                                Some(state.sequence_number.saturating_add(1).max(1)),
                            );
                        }
                        if let Some(pending) =
                            read_fresh_pending_dispatch_for_home(home, &stale_key)?
                        {
                            if let Err(err) = terminate_pending_dispatch_entry(&pending) {
                                return fail_closed_dispatch(
                                    home,
                                    pr_url,
                                    key,
                                    TERMINAL_STALE_HEAD_AMBIGUITY,
                                    &format!(
                                        "failed to terminate stale pending run old_head={} run_id={}: {err}",
                                        state.head_sha, state.run_id
                                    ),
                                    Some(state.sequence_number.saturating_add(1).max(1)),
                                );
                            }
                            return resume_dispatch_after_head_drift_for_home(
                                home,
                                pr_url,
                                key,
                                review_kind,
                                dispatch_epoch,
                                &state,
                                spawn_review,
                            );
                        }
                        let detail = match state.pid {
                            Some(pid) => format!(
                                "stale run-state pid={pid} is not live and no live pending marker old_head={} run_id={}",
                                state.head_sha, state.run_id
                            ),
                            None => format!(
                                "stale run-state has no pid and no live pending marker old_head={} run_id={}",
                                state.head_sha, state.run_id
                            ),
                        };
                        return fail_closed_dispatch(
                            home,
                            pr_url,
                            key,
                            TERMINAL_STALE_HEAD_AMBIGUITY,
                            &detail,
                            Some(state.sequence_number.saturating_add(1).max(1)),
                        );
                    },
                }
            }
        },
        ReviewRunStateLoad::Missing { .. } => {},
    }

    if let Some(pending) = read_fresh_pending_dispatch_for_home(home, key)? {
        return attach_run_state_contract_for_home(
            home,
            key,
            DispatchReviewResult {
                review_type: key.review_type.clone(),
                mode: "joined".to_string(),
                run_state: "unknown".to_string(),
                run_id: None,
                sequence_number: None,
                terminal_reason: None,
                pid: pending.pid,
                unit: pending.unit,
                log_file: pending.log_file,
            },
        );
    }

    let mut seeded = seed_pending_run_state_for_dispatch_for_home(home, pr_url, key, None)?;
    let started = match spawn_review(
        pr_url,
        key.pr_number,
        review_kind,
        &key.head_sha,
        dispatch_epoch,
    ) {
        Ok(result) => result,
        Err(err) => {
            seeded.status = ReviewRunStatus::Failed;
            seeded.terminal_reason = Some("dispatch_spawn_failed".to_string());
            write_review_run_state_for_home(home, &seeded)?;
            return Err(err);
        },
    };
    write_pending_dispatch_for_home(home, key, &started)?;
    attach_run_state_contract_for_home(home, key, started)
}

fn dispatch_single_review_for_home_with_spawn<F>(
    home: &Path,
    pr_url: &str,
    key: &DispatchIdempotencyKey,
    review_kind: ReviewKind,
    dispatch_epoch: u64,
    spawn_review: &F,
) -> Result<DispatchReviewResult, String>
where
    F: Fn(&str, u32, ReviewKind, &str, u64) -> Result<DispatchReviewResult, String>,
{
    key.validate()?;
    if !key.review_type.eq_ignore_ascii_case(review_kind.as_str()) {
        return Err(format!(
            "dispatch key review type mismatch: key={} kind={}",
            key.review_type,
            review_kind.as_str()
        ));
    }

    let scope_lock_path = review_dispatch_scope_lock_path_for_home(home, key);
    let _scope_lock = match acquire_dispatch_lock(&scope_lock_path) {
        Ok(lock) => lock,
        Err(error @ DispatchLockError::Timeout { .. }) => {
            return deny_dispatch_without_state_mutation(
                TERMINAL_DISPATCH_LOCK_TIMEOUT,
                &dispatch_lock_error_detail(&error),
            );
        },
        Err(error) => {
            return Err(dispatch_lock_error_detail(&error));
        },
    };

    let lock_path = review_dispatch_lock_path_for_home(home, key);
    let _lock = match acquire_dispatch_lock(&lock_path) {
        Ok(lock) => lock,
        Err(error @ DispatchLockError::Timeout { .. }) => {
            return deny_dispatch_without_state_mutation(
                TERMINAL_DISPATCH_LOCK_TIMEOUT,
                &dispatch_lock_error_detail(&error),
            );
        },
        Err(error) => {
            return Err(dispatch_lock_error_detail(&error));
        },
    };

    dispatch_single_review_locked_for_home(
        home,
        pr_url,
        key,
        review_kind,
        dispatch_epoch,
        spawn_review,
    )
}

fn dispatch_single_review_for_home(
    home: &Path,
    pr_url: &str,
    key: &DispatchIdempotencyKey,
    review_kind: ReviewKind,
    dispatch_epoch: u64,
) -> Result<DispatchReviewResult, String> {
    dispatch_single_review_for_home_with_spawn(
        home,
        pr_url,
        key,
        review_kind,
        dispatch_epoch,
        &spawn_detached_review,
    )
}

// ── Single review dispatch ──────────────────────────────────────────────────

pub fn dispatch_single_review(
    pr_url: &str,
    owner_repo: &str,
    pr_number: u32,
    review_kind: ReviewKind,
    head_sha: &str,
    dispatch_epoch: u64,
) -> Result<DispatchReviewResult, String> {
    let key = DispatchIdempotencyKey::new(owner_repo, pr_number, review_kind.as_str(), head_sha);
    key.validate()?;
    let home = apm2_home_dir()?;
    dispatch_single_review_for_home(&home, pr_url, &key, review_kind, dispatch_epoch)
}

fn spawn_detached_review(
    pr_url: &str,
    pr_number: u32,
    review_kind: ReviewKind,
    expected_head_sha: &str,
    dispatch_epoch: u64,
) -> Result<DispatchReviewResult, String> {
    let exe_path = std::env::current_exe()
        .map_err(|err| format!("failed to resolve current executable: {err}"))?;
    let cwd = std::env::current_dir().map_err(|err| format!("failed to resolve cwd: {err}"))?;
    let head_short = &expected_head_sha[..expected_head_sha.len().min(8)];
    let ts = Utc::now().format("%Y%m%dT%H%M%SZ");

    let has_sensitive_token_env =
        std::env::var_os("GH_TOKEN").is_some() || std::env::var_os("GITHUB_TOKEN").is_some();
    if command_available("systemd-run") && !has_sensitive_token_env {
        let unit = format!(
            "apm2-review-pr{pr_number}-{}-{head_short}-{ts}",
            review_kind.as_str()
        );
        let mut command = Command::new("systemd-run");
        command
            .arg("--user")
            .arg("--collect")
            .arg("--unit")
            .arg(&unit)
            .arg("--property")
            .arg(format!("WorkingDirectory={}", cwd.display()));

        for key in ["PATH", "HOME", "CARGO_HOME"] {
            if let Ok(value) = std::env::var(key) {
                command.arg("--setenv").arg(format!("{key}={value}"));
            }
        }

        let output = command
            .arg(&exe_path)
            .arg("fac")
            .arg("review")
            .arg("run")
            .arg(pr_url)
            .arg("--type")
            .arg(review_kind.as_str())
            .arg("--expected-head-sha")
            .arg(expected_head_sha)
            .output()
            .map_err(|err| format!("failed to execute systemd-run: {err}"))?;
        if !output.status.success() {
            return Err(format!(
                "systemd-run failed dispatching {} review: {}",
                review_kind.as_str(),
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        return Ok(DispatchReviewResult {
            review_type: review_kind.as_str().to_string(),
            mode: "started".to_string(),
            run_state: "pending".to_string(),
            run_id: None,
            sequence_number: None,
            terminal_reason: None,
            pid: None,
            unit: Some(unit),
            log_file: None,
        });
    }

    let dispatch_dir = apm2_home_dir()?.join("review_dispatch");
    fs::create_dir_all(&dispatch_dir).map_err(|err| {
        format!(
            "failed to create dispatch directory {}: {err}",
            dispatch_dir.display()
        )
    })?;
    let log_path = dispatch_dir.join(format!(
        "pr{pr_number}-{}-{head_short}-{dispatch_epoch}.log",
        review_kind.as_str()
    ));
    let stdout = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .map_err(|err| format!("failed to open dispatch log {}: {err}", log_path.display()))?;
    let stderr = stdout
        .try_clone()
        .map_err(|err| format!("failed to clone dispatch log handle: {err}"))?;
    let child = Command::new(&exe_path)
        .arg("fac")
        .arg("review")
        .arg("run")
        .arg(pr_url)
        .arg("--type")
        .arg(review_kind.as_str())
        .arg("--expected-head-sha")
        .arg(expected_head_sha)
        .current_dir(cwd)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::from(stdout))
        .stderr(std::process::Stdio::from(stderr))
        .spawn()
        .map_err(|err| format!("failed to spawn detached review process: {err}"))?;

    Ok(DispatchReviewResult {
        review_type: review_kind.as_str().to_string(),
        mode: "started".to_string(),
        run_state: "pending".to_string(),
        run_id: None,
        sequence_number: None,
        terminal_reason: None,
        pid: Some(child.id()),
        unit: None,
        log_file: Some(log_path.display().to_string()),
    })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier, Mutex};
    use std::time::Duration;

    use super::{
        DispatchIdempotencyKey, DispatchReviewResult, ReviewRunStateLoad, acquire_dispatch_lock,
        dispatch_single_review_for_home_with_spawn, review_dispatch_scope_lock_path_for_home,
        run_state_has_live_process, write_pending_dispatch_for_home,
    };
    use crate::commands::fac_review::state::{
        load_review_run_state_for_home, review_run_state_path_for_home,
        write_review_run_state_for_home,
    };
    use crate::commands::fac_review::types::{
        DISPATCH_LOCK_ACQUIRE_TIMEOUT, ReviewKind, ReviewRunState, ReviewRunStatus,
        TERMINAL_AMBIGUOUS_DISPATCH_OWNERSHIP, TERMINAL_DISPATCH_LOCK_TIMEOUT,
        TERMINAL_SHA_DRIFT_SUPERSEDED, TERMINAL_STALE_HEAD_AMBIGUITY,
    };

    fn sample_run_state(pid: Option<u32>) -> ReviewRunState {
        ReviewRunState {
            run_id: "pr441-security-s1-01234567".to_string(),
            pr_url: "https://github.com/example/repo/pull/441".to_string(),
            pr_number: 441,
            head_sha: "0123456789abcdef0123456789abcdef01234567".to_string(),
            review_type: "security".to_string(),
            reviewer_role: "fac_reviewer".to_string(),
            started_at: "2026-02-10T00:00:00Z".to_string(),
            status: ReviewRunStatus::Alive,
            terminal_reason: None,
            model_id: Some("gpt-5.3-codex".to_string()),
            backend_id: Some("codex".to_string()),
            restart_count: 0,
            sequence_number: 1,
            previous_run_id: None,
            previous_head_sha: None,
            pid,
        }
    }

    fn dead_pid_for_test() -> u32 {
        let mut child = std::process::Command::new("sh")
            .args(["-lc", "exit 0"])
            .spawn()
            .expect("spawn short-lived child");
        let pid = child.id();
        let _ = child.wait();
        pid
    }

    fn spawn_long_lived_pid() -> u32 {
        let output = std::process::Command::new("sh")
            .args(["-lc", "sleep 120 >/dev/null 2>&1 & echo $!"])
            .output()
            .expect("spawn long-lived pid");
        assert!(
            output.status.success(),
            "failed to spawn pid: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout)
            .trim()
            .parse::<u32>()
            .expect("parse spawned pid")
    }

    fn cleanup_children(children: &Arc<Mutex<Vec<u32>>>) {
        let mut owned = children.lock().expect("children lock");
        for pid in &*owned {
            if crate::commands::fac_review::state::is_process_alive(*pid) {
                let _ = std::process::Command::new("kill")
                    .args(["-KILL", &pid.to_string()])
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status();
            }
        }
        owned.clear();
    }

    fn dispatch_key(head_sha: &str) -> DispatchIdempotencyKey {
        DispatchIdempotencyKey::new("Example/Repo", 441, "security", head_sha)
    }

    fn pr_url() -> &'static str {
        "https://github.com/example/repo/pull/441"
    }

    #[test]
    fn run_state_liveness_requires_pid() {
        assert!(!run_state_has_live_process(&sample_run_state(None)));
    }

    #[test]
    fn run_state_liveness_rejects_dead_pid() {
        assert!(!run_state_has_live_process(&sample_run_state(Some(
            dead_pid_for_test()
        ))));
    }

    #[test]
    fn test_idempotent_dispatch_dedup() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();
        let key = dispatch_key("0123456789abcdef0123456789abcdef01234567");
        let spawn_count = Arc::new(AtomicUsize::new(0));
        let spawned_children = Arc::new(Mutex::new(Vec::new()));

        let spawn_count_ref = Arc::clone(&spawn_count);
        let children_ref = Arc::clone(&spawned_children);
        let spawn = move |_: &str,
                          _: u32,
                          _: ReviewKind,
                          _: &str,
                          _: u64|
              -> Result<DispatchReviewResult, String> {
            spawn_count_ref.fetch_add(1, Ordering::SeqCst);
            let pid = spawn_long_lived_pid();
            children_ref.lock().expect("children lock").push(pid);
            Ok(DispatchReviewResult {
                review_type: "security".to_string(),
                mode: "started".to_string(),
                run_state: "pending".to_string(),
                run_id: None,
                sequence_number: None,
                terminal_reason: None,
                pid: Some(pid),
                unit: None,
                log_file: None,
            })
        };

        let first = dispatch_single_review_for_home_with_spawn(
            home,
            pr_url(),
            &key,
            ReviewKind::Security,
            1,
            &spawn,
        )
        .expect("first dispatch");
        let second = dispatch_single_review_for_home_with_spawn(
            home,
            pr_url(),
            &key,
            ReviewKind::Security,
            1,
            &spawn,
        )
        .expect("second dispatch");

        assert_eq!(first.mode, "started");
        assert_eq!(second.mode, "joined");
        assert_eq!(spawn_count.load(Ordering::SeqCst), 1);

        cleanup_children(&spawned_children);
    }

    #[test]
    fn test_dispatch_different_sha_after_terminal_state_creates_new() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();

        let mut stale = sample_run_state(Some(dead_pid_for_test()));
        stale.sequence_number = 2;
        stale.head_sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
        stale.run_id = "pr441-security-s2-aaaaaaaa".to_string();
        stale.status = ReviewRunStatus::Done;
        write_review_run_state_for_home(home, &stale).expect("seed stale state");

        let spawn = |_: &str,
                     _: u32,
                     _: ReviewKind,
                     _: &str,
                     _: u64|
         -> Result<DispatchReviewResult, String> {
            Ok(DispatchReviewResult {
                review_type: "security".to_string(),
                mode: "started".to_string(),
                run_state: "pending".to_string(),
                run_id: None,
                sequence_number: None,
                terminal_reason: None,
                pid: Some(dead_pid_for_test()),
                unit: None,
                log_file: None,
            })
        };

        let key = dispatch_key("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        let result = dispatch_single_review_for_home_with_spawn(
            home,
            pr_url(),
            &key,
            ReviewKind::Security,
            2,
            &spawn,
        )
        .expect("dispatch with new sha");

        assert_eq!(result.mode, "started");
    }

    #[test]
    fn test_stale_head_no_live_handle_fails_closed() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();

        let mut stale_state = sample_run_state(None);
        stale_state.head_sha = "1111111111111111111111111111111111111111".to_string();
        stale_state.run_id = "pr441-security-s3-11111111".to_string();
        stale_state.sequence_number = 3;
        write_review_run_state_for_home(home, &stale_state).expect("seed stale state");

        let key = dispatch_key("2222222222222222222222222222222222222222");
        let spawn = |_: &str,
                     _: u32,
                     _: ReviewKind,
                     _: &str,
                     _: u64|
         -> Result<DispatchReviewResult, String> {
            panic!("spawn must not be called for unresolved stale-head ownership");
        };

        let err = dispatch_single_review_for_home_with_spawn(
            home,
            pr_url(),
            &key,
            ReviewKind::Security,
            42,
            &spawn,
        )
        .expect_err("dispatch with no stale live handle must fail closed");
        assert!(
            err.contains(TERMINAL_STALE_HEAD_AMBIGUITY),
            "unexpected error: {err}"
        );

        match load_review_run_state_for_home(home, 441, "security").expect("load state") {
            ReviewRunStateLoad::Present(state) => {
                assert_eq!(state.status, ReviewRunStatus::Failed);
                assert_eq!(
                    state.terminal_reason.as_deref(),
                    Some(TERMINAL_STALE_HEAD_AMBIGUITY)
                );
                assert_eq!(state.head_sha, "2222222222222222222222222222222222222222");
                assert_eq!(state.sequence_number, 4);
            },
            other => panic!("expected present run-state, got {other:?}"),
        }
    }

    #[test]
    fn test_stale_head_dead_pid_no_marker_fails_closed() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();

        let mut stale_state = sample_run_state(Some(dead_pid_for_test()));
        stale_state.head_sha = "3333333333333333333333333333333333333333".to_string();
        stale_state.run_id = "pr441-security-s7-33333333".to_string();
        stale_state.sequence_number = 7;
        write_review_run_state_for_home(home, &stale_state).expect("seed stale state");

        let key = dispatch_key("4444444444444444444444444444444444444444");
        let spawn = |_: &str,
                     _: u32,
                     _: ReviewKind,
                     _: &str,
                     _: u64|
         -> Result<DispatchReviewResult, String> {
            panic!("spawn must not be called for stale dead-pid ambiguity");
        };

        let err = dispatch_single_review_for_home_with_spawn(
            home,
            pr_url(),
            &key,
            ReviewKind::Security,
            43,
            &spawn,
        )
        .expect_err("dispatch with stale dead pid and no marker must fail closed");
        assert!(
            err.contains(TERMINAL_STALE_HEAD_AMBIGUITY),
            "unexpected error: {err}"
        );

        match load_review_run_state_for_home(home, 441, "security").expect("load state") {
            ReviewRunStateLoad::Present(state) => {
                assert_eq!(state.status, ReviewRunStatus::Failed);
                assert_eq!(
                    state.terminal_reason.as_deref(),
                    Some(TERMINAL_STALE_HEAD_AMBIGUITY)
                );
                assert_eq!(state.head_sha, "4444444444444444444444444444444444444444");
                assert_eq!(state.sequence_number, 8);
            },
            other => panic!("expected present run-state, got {other:?}"),
        }
    }

    #[test]
    fn test_sha_drift_kills_old_run() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();

        let old_pid = spawn_long_lived_pid();

        let mut old_state = sample_run_state(Some(old_pid));
        old_state.head_sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
        old_state.run_id = "pr441-security-s5-aaaaaaaa".to_string();
        old_state.sequence_number = 5;
        write_review_run_state_for_home(home, &old_state).expect("seed old state");

        let spawned_children = Arc::new(Mutex::new(Vec::new()));
        let children_ref = Arc::clone(&spawned_children);
        let spawn = move |_: &str,
                          _: u32,
                          _: ReviewKind,
                          _: &str,
                          _: u64|
              -> Result<DispatchReviewResult, String> {
            let pid = spawn_long_lived_pid();
            children_ref.lock().expect("children lock").push(pid);
            Ok(DispatchReviewResult {
                review_type: "security".to_string(),
                mode: "started".to_string(),
                run_state: "pending".to_string(),
                run_id: None,
                sequence_number: None,
                terminal_reason: None,
                pid: Some(pid),
                unit: None,
                log_file: None,
            })
        };

        let key = dispatch_key("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        let result = dispatch_single_review_for_home_with_spawn(
            home,
            pr_url(),
            &key,
            ReviewKind::Security,
            3,
            &spawn,
        )
        .expect("dispatch with drift");

        assert_eq!(result.mode, "drift_resumed");
        assert!(
            !crate::commands::fac_review::state::is_process_alive(old_pid),
            "old process should be terminated"
        );

        match load_review_run_state_for_home(home, 441, "security").expect("load state") {
            ReviewRunStateLoad::Present(state) => {
                assert_eq!(state.head_sha, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
                assert_eq!(
                    state.previous_run_id.as_deref(),
                    Some("pr441-security-s5-aaaaaaaa")
                );
                assert_eq!(
                    state.previous_head_sha.as_deref(),
                    Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                );
                assert_eq!(state.sequence_number, 6);
            },
            other => panic!("expected present run-state, got {other:?}"),
        }

        if crate::commands::fac_review::state::is_process_alive(old_pid) {
            let _ = std::process::Command::new("kill")
                .args(["-KILL", &old_pid.to_string()])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        }
        cleanup_children(&spawned_children);
    }

    #[test]
    fn test_stale_head_pid_none_with_pending_marker() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();

        let stale_pid = spawn_long_lived_pid();

        let mut stale_state = sample_run_state(None);
        stale_state.head_sha = "1111111111111111111111111111111111111111".to_string();
        stale_state.run_id = "pr441-security-s3-11111111".to_string();
        stale_state.sequence_number = 3;
        write_review_run_state_for_home(home, &stale_state).expect("seed stale state");

        let stale_key = dispatch_key("1111111111111111111111111111111111111111");
        write_pending_dispatch_for_home(
            home,
            &stale_key,
            &DispatchReviewResult {
                review_type: "security".to_string(),
                mode: "started".to_string(),
                run_state: "pending".to_string(),
                run_id: None,
                sequence_number: None,
                terminal_reason: None,
                pid: Some(stale_pid),
                unit: None,
                log_file: None,
            },
        )
        .expect("write stale pending marker");

        let spawned_children = Arc::new(Mutex::new(Vec::new()));
        let children_ref = Arc::clone(&spawned_children);
        let spawn = move |_: &str,
                          _: u32,
                          _: ReviewKind,
                          _: &str,
                          _: u64|
              -> Result<DispatchReviewResult, String> {
            let pid = spawn_long_lived_pid();
            children_ref.lock().expect("children lock").push(pid);
            Ok(DispatchReviewResult {
                review_type: "security".to_string(),
                mode: "started".to_string(),
                run_state: "pending".to_string(),
                run_id: None,
                sequence_number: None,
                terminal_reason: None,
                pid: Some(pid),
                unit: None,
                log_file: None,
            })
        };

        let key = dispatch_key("2222222222222222222222222222222222222222");
        let result = dispatch_single_review_for_home_with_spawn(
            home,
            pr_url(),
            &key,
            ReviewKind::Security,
            42,
            &spawn,
        )
        .expect("dispatch with stale pid none + pending marker");

        assert_eq!(result.mode, "drift_resumed");
        assert!(
            !crate::commands::fac_review::state::is_process_alive(stale_pid),
            "stale pid should be terminated from pending marker"
        );

        match load_review_run_state_for_home(home, 441, "security").expect("load state") {
            ReviewRunStateLoad::Present(state) => {
                assert_eq!(state.head_sha, "2222222222222222222222222222222222222222");
                assert_eq!(
                    state.previous_run_id.as_deref(),
                    Some("pr441-security-s3-11111111")
                );
                assert_eq!(
                    state.previous_head_sha.as_deref(),
                    Some("1111111111111111111111111111111111111111")
                );
                assert_eq!(state.sequence_number, 4);
            },
            other => panic!("expected present run-state, got {other:?}"),
        }

        if crate::commands::fac_review::state::is_process_alive(stale_pid) {
            let _ = std::process::Command::new("kill")
                .args(["-KILL", &stale_pid.to_string()])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        }
        cleanup_children(&spawned_children);
    }

    #[test]
    fn test_ambiguous_state_fails_closed() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();
        let state = sample_run_state(Some(dead_pid_for_test()));

        let canonical = review_run_state_path_for_home(home, 441, "security");
        write_review_run_state_for_home(home, &state).expect("write canonical state");
        let alt = canonical
            .parent()
            .expect("parent")
            .join("state.backup.json");
        fs::create_dir_all(alt.parent().expect("alt parent")).expect("create alt parent");
        fs::write(
            &alt,
            serde_json::to_vec_pretty(&state).expect("serialize state"),
        )
        .expect("write alternate state");

        let key = dispatch_key("0123456789abcdef0123456789abcdef01234567");
        let spawn = |_: &str,
                     _: u32,
                     _: ReviewKind,
                     _: &str,
                     _: u64|
         -> Result<DispatchReviewResult, String> {
            panic!("spawn must not be called for ambiguous state");
        };
        let err = dispatch_single_review_for_home_with_spawn(
            home,
            pr_url(),
            &key,
            ReviewKind::Security,
            4,
            &spawn,
        )
        .expect_err("ambiguous state must fail closed");
        assert!(
            err.contains(TERMINAL_AMBIGUOUS_DISPATCH_OWNERSHIP),
            "unexpected error: {err}"
        );

        let canonical_text =
            fs::read_to_string(&canonical).expect("read canonical fail-closed state");
        let canonical_state: ReviewRunState =
            serde_json::from_str(&canonical_text).expect("parse canonical fail-closed state");
        assert_eq!(canonical_state.status, ReviewRunStatus::Failed);
        assert_eq!(
            canonical_state.terminal_reason.as_deref(),
            Some(TERMINAL_AMBIGUOUS_DISPATCH_OWNERSHIP)
        );
    }

    #[test]
    fn test_stale_pid_not_joined() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();

        let stale = sample_run_state(Some(dead_pid_for_test()));
        write_review_run_state_for_home(home, &stale).expect("write stale state");

        let spawn_count = Arc::new(AtomicUsize::new(0));
        let spawn_count_ref = Arc::clone(&spawn_count);
        let spawn = move |_: &str,
                          _: u32,
                          _: ReviewKind,
                          _: &str,
                          _: u64|
              -> Result<DispatchReviewResult, String> {
            spawn_count_ref.fetch_add(1, Ordering::SeqCst);
            Ok(DispatchReviewResult {
                review_type: "security".to_string(),
                mode: "started".to_string(),
                run_state: "pending".to_string(),
                run_id: None,
                sequence_number: None,
                terminal_reason: None,
                pid: Some(dead_pid_for_test()),
                unit: None,
                log_file: None,
            })
        };

        let key = dispatch_key("0123456789abcdef0123456789abcdef01234567");
        let result = dispatch_single_review_for_home_with_spawn(
            home,
            pr_url(),
            &key,
            ReviewKind::Security,
            5,
            &spawn,
        )
        .expect("dispatch after stale pid");

        assert_eq!(result.mode, "started");
        assert_eq!(spawn_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_concurrent_dispatch_race() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path().to_path_buf();
        let key = dispatch_key("0123456789abcdef0123456789abcdef01234567");

        let spawn_count = Arc::new(AtomicUsize::new(0));
        let spawned_children = Arc::new(Mutex::new(Vec::new()));
        let barrier = Arc::new(Barrier::new(3));

        let run_one = {
            let home = home.clone();
            let key = key.clone();
            let spawn_count = Arc::clone(&spawn_count);
            let spawned_children = Arc::clone(&spawned_children);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let spawn = |_: &str,
                             _: u32,
                             _: ReviewKind,
                             _: &str,
                             _: u64|
                 -> Result<DispatchReviewResult, String> {
                    spawn_count.fetch_add(1, Ordering::SeqCst);
                    std::thread::sleep(std::time::Duration::from_millis(200));
                    let pid = spawn_long_lived_pid();
                    spawned_children.lock().expect("children lock").push(pid);
                    Ok(DispatchReviewResult {
                        review_type: "security".to_string(),
                        mode: "started".to_string(),
                        run_state: "pending".to_string(),
                        run_id: None,
                        sequence_number: None,
                        terminal_reason: None,
                        pid: Some(pid),
                        unit: None,
                        log_file: None,
                    })
                };
                barrier.wait();
                dispatch_single_review_for_home_with_spawn(
                    &home,
                    pr_url(),
                    &key,
                    ReviewKind::Security,
                    6,
                    &spawn,
                )
            })
        };

        let run_two = {
            let spawn_count = Arc::clone(&spawn_count);
            let spawned_children = Arc::clone(&spawned_children);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let spawn = |_: &str,
                             _: u32,
                             _: ReviewKind,
                             _: &str,
                             _: u64|
                 -> Result<DispatchReviewResult, String> {
                    spawn_count.fetch_add(1, Ordering::SeqCst);
                    let pid = spawn_long_lived_pid();
                    spawned_children.lock().expect("children lock").push(pid);
                    Ok(DispatchReviewResult {
                        review_type: "security".to_string(),
                        mode: "started".to_string(),
                        run_state: "pending".to_string(),
                        run_id: None,
                        sequence_number: None,
                        terminal_reason: None,
                        pid: Some(pid),
                        unit: None,
                        log_file: None,
                    })
                };
                barrier.wait();
                dispatch_single_review_for_home_with_spawn(
                    &home,
                    pr_url(),
                    &key,
                    ReviewKind::Security,
                    6,
                    &spawn,
                )
            })
        };

        barrier.wait();
        let one = run_one
            .join()
            .expect("thread one join")
            .expect("thread one dispatch");
        let two = run_two
            .join()
            .expect("thread two join")
            .expect("thread two dispatch");

        let mut modes = vec![one.mode, two.mode];
        modes.sort();
        assert_eq!(modes, vec!["joined".to_string(), "started".to_string()]);
        assert_eq!(spawn_count.load(Ordering::SeqCst), 1);

        cleanup_children(&spawned_children);
    }

    #[test]
    fn test_lock_timeout_no_state_mutation() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path().to_path_buf();
        let key = dispatch_key("0123456789abcdef0123456789abcdef01234567");

        let mut seeded_state = sample_run_state(Some(dead_pid_for_test()));
        seeded_state.run_id = "pr441-security-s11-01234567".to_string();
        seeded_state.sequence_number = 11;
        write_review_run_state_for_home(&home, &seeded_state).expect("seed state");
        let canonical = review_run_state_path_for_home(&home, 441, "security");
        let before = fs::read_to_string(&canonical).expect("read seeded state");

        let scope_lock_path = review_dispatch_scope_lock_path_for_home(&home, &key);
        let barrier = Arc::new(Barrier::new(2));
        let holder = {
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let _lock = acquire_dispatch_lock(&scope_lock_path).expect("acquire scope lock");
                barrier.wait();
                std::thread::sleep(DISPATCH_LOCK_ACQUIRE_TIMEOUT + Duration::from_millis(250));
            })
        };

        barrier.wait();

        let spawn = |_: &str,
                     _: u32,
                     _: ReviewKind,
                     _: &str,
                     _: u64|
         -> Result<DispatchReviewResult, String> {
            panic!("spawn should not execute when lock acquisition times out");
        };

        let err = dispatch_single_review_for_home_with_spawn(
            &home,
            pr_url(),
            &key,
            ReviewKind::Security,
            99,
            &spawn,
        )
        .expect_err("lock-timeout dispatch must fail");
        assert!(
            err.contains(TERMINAL_DISPATCH_LOCK_TIMEOUT),
            "unexpected error: {err}"
        );

        holder.join().expect("holder join");
        let after = fs::read_to_string(&canonical).expect("read seeded state after timeout");
        assert_eq!(
            after, before,
            "lock-timeout contender must not mutate state"
        );
    }

    #[test]
    fn test_dispatch_key_validation() {
        let bad_sha = DispatchIdempotencyKey::new("example/repo", 441, "security", "abc");
        assert!(bad_sha.validate().is_err());

        let bad_repo = DispatchIdempotencyKey::new(
            "example-repo",
            441,
            "security",
            "0123456789abcdef0123456789abcdef01234567",
        );
        assert!(bad_repo.validate().is_err());

        let bad_type = DispatchIdempotencyKey::new(
            "example/repo",
            441,
            "lint",
            "0123456789abcdef0123456789abcdef01234567",
        );
        assert!(bad_type.validate().is_err());
    }

    #[test]
    fn test_lineage_fields_populated() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();

        let old_pid = spawn_long_lived_pid();

        let mut old_state = sample_run_state(Some(old_pid));
        old_state.head_sha = "cccccccccccccccccccccccccccccccccccccccc".to_string();
        old_state.run_id = "pr441-security-s7-cccccccc".to_string();
        old_state.sequence_number = 7;
        write_review_run_state_for_home(home, &old_state).expect("seed old state");

        let spawn = |_: &str,
                     _: u32,
                     _: ReviewKind,
                     _: &str,
                     _: u64|
         -> Result<DispatchReviewResult, String> {
            Ok(DispatchReviewResult {
                review_type: "security".to_string(),
                mode: "started".to_string(),
                run_state: "pending".to_string(),
                run_id: None,
                sequence_number: None,
                terminal_reason: None,
                pid: Some(dead_pid_for_test()),
                unit: None,
                log_file: None,
            })
        };

        let key = dispatch_key("dddddddddddddddddddddddddddddddddddddddd");
        let result = dispatch_single_review_for_home_with_spawn(
            home,
            pr_url(),
            &key,
            ReviewKind::Security,
            7,
            &spawn,
        )
        .expect("drift dispatch for lineage");

        assert_eq!(result.mode, "drift_resumed");
        match load_review_run_state_for_home(home, 441, "security").expect("load state") {
            ReviewRunStateLoad::Present(state) => {
                assert_eq!(
                    state.previous_run_id.as_deref(),
                    Some("pr441-security-s7-cccccccc")
                );
                assert_eq!(
                    state.previous_head_sha.as_deref(),
                    Some("cccccccccccccccccccccccccccccccccccccccc")
                );
                assert_eq!(state.sequence_number, 8);
            },
            other => panic!("expected present run-state, got {other:?}"),
        }

        if crate::commands::fac_review::state::is_process_alive(old_pid) {
            let _ = std::process::Command::new("kill")
                .args(["-KILL", &old_pid.to_string()])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        }
    }

    #[test]
    fn test_sha_drift_marks_superseded_before_resume() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();

        let old_pid = spawn_long_lived_pid();

        let mut old_state = sample_run_state(Some(old_pid));
        old_state.head_sha = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_string();
        old_state.run_id = "pr441-security-s9-eeeeeeee".to_string();
        old_state.sequence_number = 9;
        write_review_run_state_for_home(home, &old_state).expect("seed old state");

        let spawn = |_: &str,
                     _: u32,
                     _: ReviewKind,
                     _: &str,
                     _: u64|
         -> Result<DispatchReviewResult, String> {
            Ok(DispatchReviewResult {
                review_type: "security".to_string(),
                mode: "started".to_string(),
                run_state: "pending".to_string(),
                run_id: None,
                sequence_number: None,
                terminal_reason: None,
                pid: Some(dead_pid_for_test()),
                unit: None,
                log_file: None,
            })
        };

        let key = dispatch_key("ffffffffffffffffffffffffffffffffffffffff");
        let _ = dispatch_single_review_for_home_with_spawn(
            home,
            pr_url(),
            &key,
            ReviewKind::Security,
            8,
            &spawn,
        )
        .expect("drift dispatch");

        assert!(
            !crate::commands::fac_review::state::is_process_alive(old_pid),
            "old process should be terminated"
        );
        if crate::commands::fac_review::state::is_process_alive(old_pid) {
            let _ = std::process::Command::new("kill")
                .args(["-KILL", &old_pid.to_string()])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        }

        match load_review_run_state_for_home(home, 441, "security").expect("load state") {
            ReviewRunStateLoad::Present(state) => {
                assert_ne!(
                    state.terminal_reason.as_deref(),
                    Some(TERMINAL_SHA_DRIFT_SUPERSEDED)
                );
                assert_eq!(state.head_sha, "ffffffffffffffffffffffffffffffffffffffff");
            },
            other => panic!("expected present run-state, got {other:?}"),
        }
    }

    #[test]
    fn test_dispatch_paths_use_canonical_key_segment() {
        let key = DispatchIdempotencyKey::new(
            "Owner/Repo",
            7,
            "code-quality",
            "0123456789abcdef0123456789abcdef01234567",
        );
        assert_eq!(
            key.canonical_path_segment(),
            "owner_repo-pr7-quality-0123456789abcdef0123456789abcdef01234567"
        );
    }
}
