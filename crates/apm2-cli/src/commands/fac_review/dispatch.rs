//! Dispatch pipeline: detached review spawning, locks, and pending tracking.

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use chrono::Utc;
use fs2::FileExt;

use super::merge_conflicts::{check_merge_conflicts_against_main, render_merge_conflict_summary};
use super::projection_store;
use super::state::{
    COMPLETION_RECEIPT_SCHEMA, ReviewRunCompletionReceipt, ReviewRunStateLoad, build_review_run_id,
    get_process_start_time, load_review_run_state_for_home, load_review_run_state_strict_for_home,
    load_review_run_state_verified_for_home, load_review_run_termination_receipt_for_home,
    next_review_sequence_number_for_home, try_acquire_review_lease_for_home,
    write_review_run_completion_receipt_for_home, write_review_run_state_for_home,
    write_review_run_termination_receipt_for_home,
};
use super::types::{
    DISPATCH_LOCK_ACQUIRE_TIMEOUT, DISPATCH_PENDING_TTL, DispatchIdempotencyKey,
    DispatchReviewResult, PendingDispatchEntry, ReviewKind, ReviewRunState, ReviewRunStatus,
    TERMINAL_AMBIGUOUS_DISPATCH_OWNERSHIP, TERMINAL_DISPATCH_LOCK_TIMEOUT,
    TERMINAL_SHA_DRIFT_SUPERSEDED, TERMINAL_STALE_HEAD_AMBIGUITY,
    TERMINAL_VERDICT_FINALIZED_AGENT_STOPPED, TERMINATE_TIMEOUT, TerminationAuthority,
    apm2_home_dir, ensure_parent_dir, now_iso8601,
};
use crate::commands::fac_permissions;

const SYSTEMD_DISPATCH_ENV_ALLOWLIST: [&str; 11] = [
    "PATH",
    "HOME",
    "CARGO_HOME",
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "GEMINI_API_KEY",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "APM2_HOME",
    "XDG_RUNTIME_DIR",
];

fn present_systemd_dispatch_env_keys() -> Vec<&'static str> {
    SYSTEMD_DISPATCH_ENV_ALLOWLIST
        .iter()
        .copied()
        .filter(|key| std::env::var_os(key).is_some())
        .collect()
}

fn build_systemd_setenv_args(keys: &[&str]) -> Vec<String> {
    let mut args = Vec::with_capacity(keys.len().saturating_mul(2));
    for key in keys {
        args.push("--setenv".to_string());
        args.push((*key).to_string());
    }
    args
}

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

// ── Worktree discovery ───────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
struct WorktreeEntry {
    path: PathBuf,
    head_sha: String,
    branch: Option<String>,
}

fn finalize_worktree_entry(
    entries: &mut Vec<WorktreeEntry>,
    path: &mut Option<PathBuf>,
    head_sha: &mut Option<String>,
    branch: &mut Option<String>,
) -> Result<(), String> {
    if path.is_none() && head_sha.is_none() && branch.is_none() {
        return Ok(());
    }
    let Some(entry_path) = path.take() else {
        return Err("invalid worktree porcelain: missing `worktree` field".to_string());
    };
    let Some(entry_head_sha) = head_sha.take() else {
        return Err(format!(
            "invalid worktree porcelain: missing `HEAD` field for {}",
            entry_path.display()
        ));
    };
    super::types::validate_expected_head_sha(&entry_head_sha)?;
    entries.push(WorktreeEntry {
        path: entry_path,
        head_sha: entry_head_sha.to_ascii_lowercase(),
        branch: branch.take(),
    });
    Ok(())
}

fn parse_worktree_list(porcelain: &str) -> Result<Vec<WorktreeEntry>, String> {
    let mut entries = Vec::new();
    let mut path: Option<PathBuf> = None;
    let mut head_sha: Option<String> = None;
    let mut branch: Option<String> = None;

    for raw_line in porcelain.lines() {
        let line = raw_line.trim_end();
        if line.is_empty() {
            finalize_worktree_entry(&mut entries, &mut path, &mut head_sha, &mut branch)?;
            continue;
        }
        if let Some(value) = line.strip_prefix("worktree ") {
            if path.is_some() || head_sha.is_some() || branch.is_some() {
                finalize_worktree_entry(&mut entries, &mut path, &mut head_sha, &mut branch)?;
            }
            path = Some(PathBuf::from(value.trim()));
        } else if let Some(value) = line.strip_prefix("HEAD ") {
            head_sha = Some(value.trim().to_string());
        } else if let Some(value) = line.strip_prefix("branch ") {
            let normalized = value
                .trim()
                .strip_prefix("refs/heads/")
                .unwrap_or_else(|| value.trim())
                .to_string();
            branch = Some(normalized);
        }
    }

    finalize_worktree_entry(&mut entries, &mut path, &mut head_sha, &mut branch)?;
    Ok(entries)
}

fn resolve_head_for_path(path: &Path) -> Result<String, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(path)
        .args(["rev-parse", "HEAD"])
        .output()
        .map_err(|err| {
            format!(
                "failed to execute git rev-parse HEAD in {}: {err}",
                path.display()
            )
        })?;
    if !output.status.success() {
        return Err(format!(
            "git rev-parse HEAD failed in {}: {}",
            path.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let sha = String::from_utf8_lossy(&output.stdout).trim().to_string();
    super::types::validate_expected_head_sha(&sha)?;
    Ok(sha.to_ascii_lowercase())
}

pub(super) fn resolve_worktree_for_sha(expected_sha: &str) -> Result<PathBuf, String> {
    super::types::validate_expected_head_sha(expected_sha)?;
    let expected_sha = expected_sha.to_ascii_lowercase();

    let output = Command::new("git")
        .args(["worktree", "list", "--porcelain"])
        .output()
        .map_err(|err| format!("failed to execute `git worktree list --porcelain`: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "`git worktree list --porcelain` failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    let porcelain = String::from_utf8(output.stdout)
        .map_err(|err| format!("git worktree output is not valid UTF-8: {err}"))?;
    let entries = parse_worktree_list(&porcelain)?;
    if let Some(entry) = entries
        .iter()
        .find(|entry| entry.head_sha.eq_ignore_ascii_case(&expected_sha))
    {
        return Ok(entry.path.clone());
    }

    let cwd = std::env::current_dir().map_err(|err| format!("failed to resolve cwd: {err}"))?;
    let cwd_head_sha = resolve_head_for_path(&cwd)?;
    if cwd_head_sha.eq_ignore_ascii_case(&expected_sha) {
        eprintln!(
            "WARNING: no matching worktree found for sha={expected_sha}; falling back to cwd {}",
            cwd.display()
        );
        return Ok(cwd);
    }

    Err(format!(
        "no worktree matches head sha {expected_sha}; cwd {} is at {cwd_head_sha}",
        cwd.display()
    ))
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
        proc_start_time: result.pid.and_then(get_process_start_time),
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

pub(super) fn verify_process_identity(
    pid: u32,
    recorded_proc_start_time: Option<u64>,
) -> Result<(), String> {
    let expected_start =
        recorded_proc_start_time.ok_or_else(|| format!("missing proc_start_time for pid={pid}"))?;
    let observed_start = get_process_start_time(pid)
        .ok_or_else(|| format!("failed to read /proc/{pid}/stat starttime"))?;
    if observed_start != expected_start {
        return Err(format!(
            "identity mismatch pid={pid} expected={expected_start} observed={observed_start}"
        ));
    }
    Ok(())
}

pub(super) fn wait_for_process_exit(pid: u32, timeout: Duration) {
    let started = Instant::now();
    while started.elapsed() < timeout {
        if !is_process_alive(pid) {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
}

pub(super) fn send_signal(pid: u32, signal: &str) -> Result<(), String> {
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

pub(super) fn terminate_process_with_timeout(pid: u32) -> Result<(), String> {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TerminationOutcome {
    Killed,
    AlreadyDead,
    SkippedMismatch,
    IdentityFailure(String),
}

fn finalize_termination_outcome(
    home: &Path,
    authority: &TerminationAuthority,
    outcome: TerminationOutcome,
) -> Result<TerminationOutcome, String> {
    write_termination_receipt(home, authority, &outcome)?;
    Ok(outcome)
}

pub fn terminate_review_agent_for_home(
    home: &Path,
    authority: &TerminationAuthority,
) -> Result<TerminationOutcome, String> {
    let Some(mut state) =
        load_review_run_state_strict_for_home(home, authority.pr_number, &authority.review_type)?
    else {
        return finalize_termination_outcome(home, authority, TerminationOutcome::AlreadyDead);
    };
    if state.run_id != authority.run_id {
        return finalize_termination_outcome(
            home,
            authority,
            TerminationOutcome::IdentityFailure(format!(
                "run-id mismatch for PR #{}: authority={} state={}",
                authority.pr_number, authority.run_id, state.run_id
            )),
        );
    }
    if !state.owner_repo.eq_ignore_ascii_case(&authority.repo) {
        eprintln!(
            "WARNING: skipping agent termination: run-state repo {} does not match requested repo {}",
            state.owner_repo, authority.repo
        );
        return finalize_termination_outcome(home, authority, TerminationOutcome::SkippedMismatch);
    }
    if state.status.is_terminal() {
        eprintln!(
            "INFO: skipping agent termination: run state for PR #{} type {} is already terminal",
            authority.pr_number, authority.review_type
        );
        return finalize_termination_outcome(home, authority, TerminationOutcome::AlreadyDead);
    }

    if !state.head_sha.eq_ignore_ascii_case(&authority.head_sha) {
        let message = format!(
            "skipping agent termination: reviewed sha {} does not match state sha {}",
            authority.head_sha, state.head_sha
        );
        eprintln!("WARNING: {message}");
        return finalize_termination_outcome(home, authority, TerminationOutcome::SkippedMismatch);
    }
    let Some(pid) = state.pid else {
        return finalize_termination_outcome(
            home,
            authority,
            TerminationOutcome::IdentityFailure(format!(
                "failed to terminate review agent for PR #{}: missing pid on active state",
                authority.pr_number
            )),
        );
    };
    if !is_process_alive(pid) {
        eprintln!("WARNING: skipping agent termination: pid {pid} is already not alive");
        return finalize_termination_outcome(home, authority, TerminationOutcome::AlreadyDead);
    }
    let Some(recorded_proc_start) = state.proc_start_time else {
        return finalize_termination_outcome(
            home,
            authority,
            TerminationOutcome::IdentityFailure(format!(
                "failed to terminate review agent pid {pid}: missing proc_start_time"
            )),
        );
    };
    if let Err(err) = verify_process_identity(pid, Some(recorded_proc_start)) {
        return finalize_termination_outcome(
            home,
            authority,
            TerminationOutcome::IdentityFailure(format!(
                "failed to verify process identity for pid {pid}: {err}"
            )),
        );
    }
    if !is_process_alive(pid) {
        eprintln!("WARNING: skipping agent termination: pid {pid} is already not alive");
        return finalize_termination_outcome(home, authority, TerminationOutcome::AlreadyDead);
    }

    if let Err(err) = terminate_process_with_timeout(pid) {
        return finalize_termination_outcome(
            home,
            authority,
            TerminationOutcome::IdentityFailure(format!(
                "failed to terminate review agent pid={pid}: {err}"
            )),
        );
    }

    if is_process_alive(pid) {
        return finalize_termination_outcome(
            home,
            authority,
            TerminationOutcome::IdentityFailure(format!(
                "review agent pid={pid} is still alive after termination attempt"
            )),
        );
    }

    let mut outcome = TerminationOutcome::Killed;
    state.status = ReviewRunStatus::Done;
    state.terminal_reason = Some(TERMINAL_VERDICT_FINALIZED_AGENT_STOPPED.to_string());
    if let Err(err) = write_review_run_state_for_home(home, &state).map_err(|err| {
        format!(
            "failed to persist terminal review state for PR #{}: {err}",
            authority.pr_number
        )
    }) {
        outcome = TerminationOutcome::IdentityFailure(err);
    }

    write_termination_receipt(home, authority, &outcome)?;
    eprintln!("INFO: terminated review agent pid={pid} after verdict finalized");
    Ok(outcome)
}

pub fn write_completion_receipt_for_verdict(
    home: &Path,
    authority: &TerminationAuthority,
    decision: &str,
) -> Result<(), String> {
    let completion_receipt = ReviewRunCompletionReceipt {
        schema: COMPLETION_RECEIPT_SCHEMA.to_string(),
        emitted_at: now_iso8601(),
        repo: authority.repo.clone(),
        pr_number: authority.pr_number,
        review_type: authority.review_type.clone(),
        run_id: authority.run_id.clone(),
        head_sha: authority.head_sha.clone(),
        decision: decision.to_string(),
        decision_comment_id: authority.decision_comment_id,
        decision_author: authority.decision_author.clone(),
        decision_summary: authority.decision_signature.clone(),
        integrity_hmac: String::new(),
    };
    write_review_run_completion_receipt_for_home(home, &completion_receipt).map(|_| ())
}

fn write_termination_receipt(
    home: &Path,
    authority: &TerminationAuthority,
    outcome: &TerminationOutcome,
) -> Result<(), String> {
    let (outcome_label, outcome_reason) = match outcome {
        TerminationOutcome::Killed => ("killed", None),
        TerminationOutcome::AlreadyDead => ("already_dead", None),
        TerminationOutcome::SkippedMismatch => ("skipped_mismatch", None),
        TerminationOutcome::IdentityFailure(reason) => ("identity_failure", Some(reason.clone())),
    };
    let receipt = super::state::ReviewRunTerminationReceipt {
        schema: super::state::TERMINATION_RECEIPT_SCHEMA.to_string(),
        emitted_at: now_iso8601(),
        repo: authority.repo.clone(),
        pr_number: authority.pr_number,
        review_type: authority.review_type.clone(),
        run_id: authority.run_id.clone(),
        head_sha: authority.head_sha.clone(),
        decision_comment_id: authority.decision_comment_id,
        decision_author: authority.decision_author.clone(),
        decision_summary: authority.decision_signature.clone(),
        integrity_hmac: String::new(),
        outcome: outcome_label.to_string(),
        outcome_reason,
    };
    write_review_run_termination_receipt_for_home(home, &receipt)?;
    let _ = load_review_run_termination_receipt_for_home(
        home,
        authority.pr_number,
        &authority.review_type,
    )?
    .ok_or_else(|| {
        format!(
            "termination receipt missing after write for PR #{} type={}",
            authority.pr_number, authority.review_type
        )
    })?;
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
        if is_process_alive(pid) {
            verify_process_identity(pid, entry.proc_start_time)?;
        }
        terminate_process_with_timeout(pid)?;
    }
    if let Some(unit) = entry.unit.as_deref() {
        terminate_systemd_unit_with_timeout(unit)?;
    }
    Ok(())
}

// ── Tool availability ───────────────────────────────────────────────────────

fn command_available(command: &str) -> bool {
    // Check if the binary is locatable via `which`. This avoids passing
    // untrusted strings through `sh -lc` while remaining portable across
    // tools that may not implement `--version`.
    Command::new("which")
        .arg(command)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn strip_deleted_executable_suffix(path: &Path) -> Option<PathBuf> {
    let file_name = path.file_name()?.to_str()?;
    let stripped = file_name.strip_suffix(" (deleted)")?;
    let mut sanitized = path.to_path_buf();
    sanitized.set_file_name(stripped);
    Some(sanitized)
}

fn is_regular_file(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|metadata| metadata.is_file())
}

fn first_existing_dispatch_executable(candidates: &[PathBuf]) -> Option<PathBuf> {
    candidates
        .iter()
        .find(|candidate| is_regular_file(candidate))
        .cloned()
}

fn resolve_dispatch_executable_path(workspace_root: &Path) -> Result<PathBuf, String> {
    let current_exe = std::env::current_exe()
        .map_err(|err| format!("failed to resolve current executable: {err}"))?;
    let mut candidates = Vec::new();
    if let Some(sanitized) = strip_deleted_executable_suffix(&current_exe) {
        candidates.push(sanitized);
    }
    candidates.push(current_exe.clone());
    candidates.push(workspace_root.join("target").join("debug").join("apm2"));
    candidates.push(workspace_root.join("target").join("release").join("apm2"));

    if let Some(executable) = first_existing_dispatch_executable(&candidates) {
        return Ok(executable);
    }

    let rendered = candidates
        .iter()
        .map(|candidate| candidate.display().to_string())
        .collect::<Vec<_>>()
        .join(",");
    Err(format!(
        "failed to resolve dispatch executable (current_exe={}, candidates={rendered})",
        current_exe.display()
    ))
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
        owner_repo: key.owner_repo.clone(),
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
        nudge_count: 0,
        sequence_number,
        previous_run_id: None,
        previous_head_sha: None,
        pid: None,
        proc_start_time: None,
        integrity_hmac: None,
    };
    write_review_run_state_for_home(home, &state)?;
    Ok(state)
}

fn fail_closed_dispatch(
    home: &Path,
    key: &DispatchIdempotencyKey,
    terminal_reason: &str,
    detail: &str,
    sequence_hint: Option<u32>,
) -> Result<DispatchReviewResult, String> {
    let state_write_error =
        write_fail_closed_state_for_dispatch(home, key, terminal_reason, sequence_hint).err();
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

#[allow(clippy::too_many_arguments)]
fn resume_dispatch_after_head_drift_for_home<F>(
    home: &Path,
    workspace_root: &Path,
    key: &DispatchIdempotencyKey,
    review_kind: ReviewKind,
    dispatch_epoch: u64,
    state: &ReviewRunState,
    spawn_review: &F,
) -> Result<DispatchReviewResult, String>
where
    F: Fn(&Path, u32, ReviewKind, &str, u64) -> Result<DispatchReviewResult, String>,
{
    let mut superseded = state.clone();
    superseded.status = ReviewRunStatus::Failed;
    superseded.terminal_reason = Some(TERMINAL_SHA_DRIFT_SUPERSEDED.to_string());
    superseded.pid = None;
    superseded.proc_start_time = None;
    write_review_run_state_for_home(home, &superseded)?;

    let _ = projection_store::save_identity_with_context(
        &key.owner_repo,
        key.pr_number,
        &key.head_sha,
        "dispatch_drift",
    );

    let lineage = drift_lineage_from_state(state, key);
    let mut seeded = seed_pending_run_state_for_dispatch_for_home(home, key, Some(&lineage))?;
    let started = match spawn_review(
        workspace_root,
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
        owner_repo: key.owner_repo.clone(),
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
        nudge_count: 0,
        sequence_number,
        previous_run_id: lineage.map(|value| value.previous_run_id.clone()),
        previous_head_sha: lineage.map(|value| value.previous_head_sha.clone()),
        pid: None,
        proc_start_time: None,
        integrity_hmac: None,
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

#[allow(clippy::too_many_arguments)]
fn dispatch_single_review_locked_for_home<F>(
    home: &Path,
    workspace_root: &Path,
    key: &DispatchIdempotencyKey,
    review_kind: ReviewKind,
    dispatch_epoch: u64,
    force_same_sha_retry: bool,
    spawn_review: &F,
) -> Result<DispatchReviewResult, String>
where
    F: Fn(&Path, u32, ReviewKind, &str, u64) -> Result<DispatchReviewResult, String>,
{
    let run_state_load =
        load_review_run_state_verified_for_home(home, key.pr_number, &key.review_type)?;
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
                key,
                TERMINAL_AMBIGUOUS_DISPATCH_OWNERSHIP,
                &format!("corrupt-state path={} detail={error}", path.display()),
                sequence_hint,
            );
        },
        ReviewRunStateLoad::Present(state) => {
            if state.head_sha.eq_ignore_ascii_case(&key.head_sha) && state.status.is_terminal() {
                if !force_same_sha_retry && state.pid.is_some() {
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
                if !force_same_sha_retry && state.pid.is_none() {
                    eprintln!(
                        "WARNING: terminal run-state missing pid for PR #{} type={} sha={}; dispatching new review",
                        key.pr_number, key.review_type, key.head_sha
                    );
                }
            }

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
                        if let Err(err) = verify_process_identity(pid, state.proc_start_time) {
                            return fail_closed_dispatch(
                                home,
                                key,
                                TERMINAL_STALE_HEAD_AMBIGUITY,
                                &format!(
                                    "stale run-state process identity mismatch pid={pid} head={} run_id={}: {err}",
                                    state.head_sha, state.run_id
                                ),
                                Some(state.sequence_number.saturating_add(1).max(1)),
                            );
                        }
                        if let Err(err) = terminate_process_with_timeout(pid) {
                            return fail_closed_dispatch(
                                home,
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
                            workspace_root,
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
                                workspace_root,
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

    // Final dedup gate: if the orchestrator's review lease is already held,
    // a reviewer is actively running — no need to spawn another.
    let review_lease = match try_acquire_review_lease_for_home(
        home,
        &key.owner_repo,
        key.pr_number,
        &key.review_type,
    ) {
        Ok(Some(lease)) => lease,
        Ok(None) => {
            // Lease held — enrich the response with current run state so callers
            // can see which run_id/pid they joined.
            let (run_state_str, run_id, seq, pid) =
                match load_review_run_state_for_home(home, key.pr_number, &key.review_type) {
                    Ok(ReviewRunStateLoad::Present(state)) => (
                        state.status.as_str().to_string(),
                        Some(state.run_id),
                        Some(state.sequence_number),
                        state.pid,
                    ),
                    _ => ("unknown".to_string(), None, None, None),
                };
            return Ok(DispatchReviewResult {
                review_type: key.review_type.clone(),
                mode: "joined".to_string(),
                run_state: run_state_str,
                run_id,
                sequence_number: seq,
                terminal_reason: None,
                pid,
                unit: None,
                log_file: None,
            });
        },
        Err(err) => {
            return Err(format!(
                "failed to acquire review lease for {}#{} {}: {err}",
                key.owner_repo, key.pr_number, key.review_type
            ));
        },
    };

    // SECURITY NOTE (RSK-1601 TOCTOU): review_lease is intentionally held from
    // acquisition through spawn and pending-marker write. The dispatch lock
    // (held by caller) additionally serializes concurrent dispatchers for the
    // same idempotency key. The child process re-acquires the lease after this
    // function returns.

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

    let mut seeded = seed_pending_run_state_for_dispatch_for_home(home, key, None)?;
    let started = match spawn_review(
        workspace_root,
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
    let _ = review_lease;
    attach_run_state_contract_for_home(home, key, started)
}

#[allow(clippy::too_many_arguments)]
fn dispatch_single_review_for_home_with_spawn_force_workspace<F>(
    home: &Path,
    workspace_root: &Path,
    key: &DispatchIdempotencyKey,
    review_kind: ReviewKind,
    dispatch_epoch: u64,
    force_same_sha_retry: bool,
    spawn_review: &F,
) -> Result<DispatchReviewResult, String>
where
    F: Fn(&Path, u32, ReviewKind, &str, u64) -> Result<DispatchReviewResult, String>,
{
    dispatch_single_review_for_home_with_spawn_force_workspace_and_lock(
        home,
        workspace_root,
        key,
        review_kind,
        dispatch_epoch,
        force_same_sha_retry,
        spawn_review,
        &acquire_dispatch_lock,
    )
}

#[allow(clippy::too_many_arguments)]
fn dispatch_single_review_for_home_with_spawn_force_workspace_and_lock<F, L>(
    home: &Path,
    workspace_root: &Path,
    key: &DispatchIdempotencyKey,
    review_kind: ReviewKind,
    dispatch_epoch: u64,
    force_same_sha_retry: bool,
    spawn_review: &F,
    acquire_lock: &L,
) -> Result<DispatchReviewResult, String>
where
    F: Fn(&Path, u32, ReviewKind, &str, u64) -> Result<DispatchReviewResult, String>,
    L: Fn(&Path) -> Result<File, DispatchLockError>,
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
    let _scope_lock = match acquire_lock(&scope_lock_path) {
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
    let _lock = match acquire_lock(&lock_path) {
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
        workspace_root,
        key,
        review_kind,
        dispatch_epoch,
        force_same_sha_retry,
        spawn_review,
    )
}

#[cfg(test)]
fn dispatch_single_review_for_home_with_spawn<F>(
    home: &Path,
    key: &DispatchIdempotencyKey,
    review_kind: ReviewKind,
    dispatch_epoch: u64,
    spawn_review: &F,
) -> Result<DispatchReviewResult, String>
where
    F: Fn(u32, ReviewKind, &str, u64) -> Result<DispatchReviewResult, String>,
{
    let adapter = |_: &Path,
                   pr_number: u32,
                   kind: ReviewKind,
                   expected_head_sha: &str,
                   epoch: u64|
     -> Result<DispatchReviewResult, String> {
        spawn_review(pr_number, kind, expected_head_sha, epoch)
    };
    dispatch_single_review_for_home_with_spawn_force_workspace(
        home,
        Path::new("."),
        key,
        review_kind,
        dispatch_epoch,
        false,
        &adapter,
    )
}

#[cfg(test)]
fn dispatch_single_review_for_home_with_spawn_force<F>(
    home: &Path,
    key: &DispatchIdempotencyKey,
    review_kind: ReviewKind,
    dispatch_epoch: u64,
    force_same_sha_retry: bool,
    spawn_review: &F,
) -> Result<DispatchReviewResult, String>
where
    F: Fn(u32, ReviewKind, &str, u64) -> Result<DispatchReviewResult, String>,
{
    let adapter = |_: &Path,
                   pr_number: u32,
                   kind: ReviewKind,
                   expected_head_sha: &str,
                   epoch: u64|
     -> Result<DispatchReviewResult, String> {
        spawn_review(pr_number, kind, expected_head_sha, epoch)
    };
    dispatch_single_review_for_home_with_spawn_force_workspace(
        home,
        Path::new("."),
        key,
        review_kind,
        dispatch_epoch,
        force_same_sha_retry,
        &adapter,
    )
}

fn dispatch_single_review_for_home(
    home: &Path,
    workspace_root: &Path,
    key: &DispatchIdempotencyKey,
    review_kind: ReviewKind,
    dispatch_epoch: u64,
    force_same_sha_retry: bool,
) -> Result<DispatchReviewResult, String> {
    dispatch_single_review_for_home_with_spawn_force_workspace(
        home,
        workspace_root,
        key,
        review_kind,
        dispatch_epoch,
        force_same_sha_retry,
        &spawn_detached_review,
    )
}

// ── Single review dispatch ──────────────────────────────────────────────────

pub fn dispatch_single_review(
    owner_repo: &str,
    pr_number: u32,
    review_kind: ReviewKind,
    head_sha: &str,
    dispatch_epoch: u64,
) -> Result<DispatchReviewResult, String> {
    dispatch_single_review_with_force(
        owner_repo,
        pr_number,
        review_kind,
        head_sha,
        dispatch_epoch,
        false,
    )
}

pub fn dispatch_single_review_with_force(
    owner_repo: &str,
    pr_number: u32,
    review_kind: ReviewKind,
    head_sha: &str,
    dispatch_epoch: u64,
    force_same_sha_retry: bool,
) -> Result<DispatchReviewResult, String> {
    let key = DispatchIdempotencyKey::new(owner_repo, pr_number, review_kind.as_str(), head_sha);
    key.validate()?;
    let workspace_root = resolve_worktree_for_sha(head_sha)?;
    let merge_report = check_merge_conflicts_against_main(&workspace_root, head_sha)?;
    if merge_report.has_conflicts() {
        return Err(format!(
            "cannot dispatch review for conflicted head SHA {head_sha}:\n{}",
            render_merge_conflict_summary(&merge_report)
        ));
    }
    let home = apm2_home_dir()?;
    dispatch_single_review_for_home(
        &home,
        &workspace_root,
        &key,
        review_kind,
        dispatch_epoch,
        force_same_sha_retry,
    )
}

fn spawn_detached_review(
    workspace_root: &Path,
    pr_number: u32,
    review_kind: ReviewKind,
    expected_head_sha: &str,
    dispatch_epoch: u64,
) -> Result<DispatchReviewResult, String> {
    let exe_path = resolve_dispatch_executable_path(workspace_root)?;
    let head_short = &expected_head_sha[..expected_head_sha.len().min(8)];
    let ts = Utc::now().format("%Y%m%dT%H%M%SZ");
    let use_systemd_run = command_available("systemd-run");

    if use_systemd_run {
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
            .arg(format!("WorkingDirectory={}", workspace_root.display()))
            .arg("--property")
            .arg(format!("ReadOnlyPaths={}", workspace_root.display()));

        // Preserve env-auth compatibility without placing secret values on the
        // systemd-run argv surface. `--setenv NAME` copies from caller env.
        command.args(build_systemd_setenv_args(
            &present_systemd_dispatch_env_keys(),
        ));

        let output = command
            .arg(&exe_path)
            .arg("fac")
            .arg("review")
            .arg("run")
            .arg("--pr")
            .arg(pr_number.to_string())
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

    if !use_systemd_run {
        eprintln!("WARNING: systemd-run unavailable; read-only confinement not applied");
    }

    let dispatch_dir = apm2_home_dir()?.join("review_dispatch");
    fac_permissions::ensure_dir_with_mode(&dispatch_dir).map_err(|err| {
        format!(
            "failed to create dispatch directory {}: {err}",
            dispatch_dir.display()
        )
    })?;
    let log_path = dispatch_dir.join(format!(
        "pr{pr_number}-{}-{head_short}-{dispatch_epoch}.log",
        review_kind.as_str()
    ));
    let stdout = fac_permissions::append_fac_file_with_mode(&log_path)
        .map_err(|err| format!("failed to open dispatch log {}: {err}", log_path.display()))?;
    let stderr = fac_permissions::append_fac_file_with_mode(&log_path)
        .map_err(|err| format!("failed to open dispatch log {}: {err}", log_path.display()))?;
    let child = Command::new(&exe_path)
        .arg("fac")
        .arg("review")
        .arg("run")
        .arg("--pr")
        .arg(pr_number.to_string())
        .arg("--type")
        .arg(review_kind.as_str())
        .arg("--expected-head-sha")
        .arg(expected_head_sha)
        .current_dir(workspace_root)
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
    use std::sync::{Arc, Barrier, Condvar, Mutex, mpsc};
    use std::time::Duration;

    use super::{
        DispatchIdempotencyKey, DispatchLockError, DispatchReviewResult, ReviewRunStateLoad,
        build_systemd_setenv_args, dispatch_single_review_for_home_with_spawn,
        dispatch_single_review_for_home_with_spawn_force,
        dispatch_single_review_for_home_with_spawn_force_workspace_and_lock,
        first_existing_dispatch_executable, run_state_has_live_process,
        strip_deleted_executable_suffix, write_pending_dispatch_for_home,
    };
    use crate::commands::fac_review::state::{
        get_process_start_time, load_review_run_state_for_home, review_run_state_path_for_home,
        write_review_run_state_for_home,
    };
    use crate::commands::fac_review::types::{
        ReviewKind, ReviewRunState, ReviewRunStatus, TERMINAL_AMBIGUOUS_DISPATCH_OWNERSHIP,
        TERMINAL_DISPATCH_LOCK_TIMEOUT, TERMINAL_SHA_DRIFT_SUPERSEDED,
        TERMINAL_STALE_HEAD_AMBIGUITY,
    };

    fn sample_run_state(pid: Option<u32>) -> ReviewRunState {
        ReviewRunState {
            run_id: "pr441-security-s1-01234567".to_string(),
            owner_repo: "example/repo".to_string(),
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
            nudge_count: 0,
            sequence_number: 1,
            previous_run_id: None,
            previous_head_sha: None,
            pid,
            proc_start_time: pid.map(|process_id| get_process_start_time(process_id).unwrap_or(1)),
            integrity_hmac: None,
        }
    }

    fn dead_pid_for_test() -> u32 {
        let mut child = std::process::Command::new("true")
            .spawn()
            .expect("spawn short-lived child");
        let pid = child.id();
        let _ = child.wait();
        pid
    }

    #[test]
    fn strip_deleted_executable_suffix_strips_deleted_marker() {
        let path = std::path::Path::new("/tmp/apm2 (deleted)");
        let sanitized = strip_deleted_executable_suffix(path).expect("sanitized path");
        assert_eq!(sanitized, std::path::PathBuf::from("/tmp/apm2"));
    }

    #[test]
    fn strip_deleted_executable_suffix_leaves_clean_path_unmodified() {
        let path = std::path::Path::new("/tmp/apm2");
        assert!(
            strip_deleted_executable_suffix(path).is_none(),
            "clean path should not change"
        );
    }

    #[test]
    fn systemd_setenv_args_do_not_embed_values() {
        let args = build_systemd_setenv_args(&["GH_TOKEN", "OPENAI_API_KEY"]);
        assert_eq!(
            args,
            vec![
                "--setenv".to_string(),
                "GH_TOKEN".to_string(),
                "--setenv".to_string(),
                "OPENAI_API_KEY".to_string()
            ]
        );
        assert!(
            args.iter().all(|arg| !arg.contains('=')),
            "setenv args must not include KEY=VALUE pairs"
        );
    }

    #[test]
    fn first_existing_dispatch_executable_selects_first_file() {
        let temp = tempfile::tempdir().expect("tempdir");
        let first = temp.path().join("apm2-first");
        let second = temp.path().join("apm2-second");
        fs::write(&first, b"first").expect("write first executable stub");
        fs::write(&second, b"second").expect("write second executable stub");
        let missing = temp.path().join("missing");

        let selected = first_existing_dispatch_executable(&[missing, first.clone(), second])
            .expect("select executable");
        assert_eq!(selected, first);
    }

    fn spawn_long_lived_pid() -> u32 {
        // Spawn a background sleep process via sh -c so that the sleep
        // is reparented to init and will not become a zombie when killed.
        // This is a test-only helper with fully hardcoded arguments—no
        // user-controlled data is passed through the shell.
        let output = std::process::Command::new("sh")
            .args(["-c", "sleep 120 >/dev/null 2>&1 & echo $!"])
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

    fn dispatch_key_with_owner(owner_repo: &str, head_sha: &str) -> DispatchIdempotencyKey {
        DispatchIdempotencyKey::new(owner_repo, 441, "security", head_sha)
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
        let key = dispatch_key_with_owner(
            "Example/Repo-Idempotent",
            "0123456789abcdef0123456789abcdef01234567",
        );
        let spawn_count = Arc::new(AtomicUsize::new(0));
        let spawned_children = Arc::new(Mutex::new(Vec::new()));

        let spawn_count_ref = Arc::clone(&spawn_count);
        let children_ref = Arc::clone(&spawned_children);
        let spawn =
            move |_: u32, _: ReviewKind, _: &str, _: u64| -> Result<DispatchReviewResult, String> {
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

        let first =
            dispatch_single_review_for_home_with_spawn(home, &key, ReviewKind::Security, 1, &spawn)
                .expect("first dispatch");
        let second =
            dispatch_single_review_for_home_with_spawn(home, &key, ReviewKind::Security, 1, &spawn)
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

        let spawn =
            |_: u32, _: ReviewKind, _: &str, _: u64| -> Result<DispatchReviewResult, String> {
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

        let key = dispatch_key_with_owner(
            "Example/Repo-DifferentSha",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        );
        let result =
            dispatch_single_review_for_home_with_spawn(home, &key, ReviewKind::Security, 2, &spawn)
                .expect("dispatch with new sha");

        assert_eq!(result.mode, "started");
    }

    #[test]
    fn test_same_sha_terminal_state_joined_without_force() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();

        let mut terminal = sample_run_state(Some(dead_pid_for_test()));
        terminal.status = ReviewRunStatus::Done;
        terminal.sequence_number = 4;
        terminal.run_id = "pr441-security-s4-01234567".to_string();
        write_review_run_state_for_home(home, &terminal).expect("seed terminal state");

        let key = dispatch_key_with_owner(
            "Example/Repo-Force",
            "0123456789abcdef0123456789abcdef01234567",
        );
        let spawn =
            |_: u32, _: ReviewKind, _: &str, _: u64| -> Result<DispatchReviewResult, String> {
                panic!("spawn must not be called when same SHA is terminal");
            };

        let result = dispatch_single_review_for_home_with_spawn(
            home,
            &key,
            ReviewKind::Security,
            100,
            &spawn,
        )
        .expect("same-sha terminal state should join");
        assert_eq!(result.mode, "joined");
        assert_eq!(result.run_state, "done");
        assert_eq!(result.run_id.as_deref(), Some("pr441-security-s4-01234567"));
    }

    #[test]
    fn test_same_sha_terminal_state_missing_pid_dispatches_new_review() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();

        let mut terminal = sample_run_state(None);
        terminal.status = ReviewRunStatus::Done;
        terminal.sequence_number = 4;
        terminal.run_id = "pr441-security-s4-01234567".to_string();
        write_review_run_state_for_home(home, &terminal).expect("seed terminal state");

        let spawn_count = Arc::new(AtomicUsize::new(0));
        let spawn_count_ref = Arc::clone(&spawn_count);
        let spawn =
            move |_: u32, _: ReviewKind, _: &str, _: u64| -> Result<DispatchReviewResult, String> {
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

        let key = dispatch_key_with_owner(
            "Example/Repo-TerminalMissingPid",
            "0123456789abcdef0123456789abcdef01234567",
        );
        let result = dispatch_single_review_for_home_with_spawn(
            home,
            &key,
            ReviewKind::Security,
            100,
            &spawn,
        )
        .expect("same-sha terminal without pid should dispatch");
        assert_eq!(result.mode, "started");
        assert_eq!(spawn_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_same_sha_terminal_state_allowed_with_force() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();

        let mut terminal = sample_run_state(Some(dead_pid_for_test()));
        terminal.status = ReviewRunStatus::Done;
        terminal.sequence_number = 9;
        terminal.run_id = "pr441-security-s9-01234567".to_string();
        write_review_run_state_for_home(home, &terminal).expect("seed terminal state");

        let spawn_count = Arc::new(AtomicUsize::new(0));
        let spawn_count_ref = Arc::clone(&spawn_count);
        let spawn =
            move |_: u32, _: ReviewKind, _: &str, _: u64| -> Result<DispatchReviewResult, String> {
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

        let key = dispatch_key_with_owner(
            "Example/Repo-Force-Spawn",
            "0123456789abcdef0123456789abcdef01234567",
        );
        let result = dispatch_single_review_for_home_with_spawn_force(
            home,
            &key,
            ReviewKind::Security,
            101,
            true,
            &spawn,
        )
        .expect("force same-sha dispatch should start");

        assert_eq!(result.mode, "started");
        assert_eq!(spawn_count.load(Ordering::SeqCst), 1);
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
        let spawn =
            |_: u32, _: ReviewKind, _: &str, _: u64| -> Result<DispatchReviewResult, String> {
                panic!("spawn must not be called for unresolved stale-head ownership");
            };

        let err = dispatch_single_review_for_home_with_spawn(
            home,
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
        let spawn =
            |_: u32, _: ReviewKind, _: &str, _: u64| -> Result<DispatchReviewResult, String> {
                panic!("spawn must not be called for stale dead-pid ambiguity");
            };

        let err = dispatch_single_review_for_home_with_spawn(
            home,
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
    fn test_pid_reuse_not_killed() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();

        let stale_pid = spawn_long_lived_pid();
        let mut stale_state = sample_run_state(Some(stale_pid));
        stale_state.head_sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
        stale_state.run_id = "pr441-security-s12-aaaaaaaa".to_string();
        stale_state.sequence_number = 12;
        // Simulate pid reuse by forcing a mismatched recorded starttime.
        stale_state.proc_start_time = Some(0);
        write_review_run_state_for_home(home, &stale_state).expect("seed stale state");

        let key = dispatch_key("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        let spawn =
            |_: u32, _: ReviewKind, _: &str, _: u64| -> Result<DispatchReviewResult, String> {
                panic!("spawn must not be called when stale-head identity is ambiguous");
            };

        let err = dispatch_single_review_for_home_with_spawn(
            home,
            &key,
            ReviewKind::Security,
            44,
            &spawn,
        )
        .expect_err("dispatch with pid reuse ambiguity must fail closed");
        assert!(
            err.contains(TERMINAL_STALE_HEAD_AMBIGUITY),
            "unexpected error: {err}"
        );
        assert!(
            crate::commands::fac_review::state::is_process_alive(stale_pid),
            "ambiguous pid identity must not be killed"
        );

        let _ = std::process::Command::new("kill")
            .args(["-KILL", &stale_pid.to_string()])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }

    #[test]
    fn test_identity_verified_before_kill() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();

        let old_pid = spawn_long_lived_pid();
        let mut old_state = sample_run_state(Some(old_pid));
        old_state.head_sha = "cccccccccccccccccccccccccccccccccccccccc".to_string();
        old_state.run_id = "pr441-security-s13-cccccccc".to_string();
        old_state.sequence_number = 13;
        old_state.proc_start_time = get_process_start_time(old_pid);
        assert!(
            old_state.proc_start_time.is_some(),
            "expected /proc start time for live pid"
        );
        write_review_run_state_for_home(home, &old_state).expect("seed old state");

        let spawn =
            |_: u32, _: ReviewKind, _: &str, _: u64| -> Result<DispatchReviewResult, String> {
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
            &key,
            ReviewKind::Security,
            45,
            &spawn,
        )
        .expect("dispatch with matching identity should terminate stale pid");

        assert_eq!(result.mode, "drift_resumed");
        assert!(
            !crate::commands::fac_review::state::is_process_alive(old_pid),
            "identity-verified stale process should be terminated"
        );
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
        let spawn =
            move |_: u32, _: ReviewKind, _: &str, _: u64| -> Result<DispatchReviewResult, String> {
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
        let result =
            dispatch_single_review_for_home_with_spawn(home, &key, ReviewKind::Security, 3, &spawn)
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
        let spawn =
            move |_: u32, _: ReviewKind, _: &str, _: u64| -> Result<DispatchReviewResult, String> {
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
        let spawn =
            |_: u32, _: ReviewKind, _: &str, _: u64| -> Result<DispatchReviewResult, String> {
                panic!("spawn must not be called for ambiguous state");
            };
        let err =
            dispatch_single_review_for_home_with_spawn(home, &key, ReviewKind::Security, 4, &spawn)
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
        let spawn =
            move |_: u32, _: ReviewKind, _: &str, _: u64| -> Result<DispatchReviewResult, String> {
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

        let key = dispatch_key_with_owner(
            "Example/Repo-StalePidNotJoined",
            "0123456789abcdef0123456789abcdef01234567",
        );
        let result =
            dispatch_single_review_for_home_with_spawn(home, &key, ReviewKind::Security, 5, &spawn)
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
        let barrier = Arc::new(Barrier::new(3));
        let release_first_spawn = Arc::new((Mutex::new(false), Condvar::new()));
        let (first_spawn_entered_tx, first_spawn_entered_rx) = mpsc::channel();

        let run_one = {
            let home = home.clone();
            let key = key.clone();
            let spawn_count = Arc::clone(&spawn_count);
            let barrier = Arc::clone(&barrier);
            let release_first_spawn = Arc::clone(&release_first_spawn);
            let first_spawn_entered_tx = first_spawn_entered_tx.clone();
            std::thread::spawn(move || {
                let spawn = |_: u32,
                             _: ReviewKind,
                             _: &str,
                             _: u64|
                 -> Result<DispatchReviewResult, String> {
                    let previous = spawn_count.fetch_add(1, Ordering::SeqCst);
                    if previous == 0 {
                        first_spawn_entered_tx
                            .send(())
                            .expect("notify first spawn entry");
                        let (released_lock, released_cv) = &*release_first_spawn;
                        let mut released = released_lock.lock().expect("release lock");
                        while !*released {
                            released = released_cv.wait(released).expect("release wait");
                        }
                    }
                    let pid = std::process::id();
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
                    &key,
                    ReviewKind::Security,
                    6,
                    &spawn,
                )
            })
        };

        let run_two = {
            let spawn_count = Arc::clone(&spawn_count);
            let barrier = Arc::clone(&barrier);
            let release_first_spawn = Arc::clone(&release_first_spawn);
            let first_spawn_entered_tx = first_spawn_entered_tx.clone();
            std::thread::spawn(move || {
                let spawn = |_: u32,
                             _: ReviewKind,
                             _: &str,
                             _: u64|
                 -> Result<DispatchReviewResult, String> {
                    let previous = spawn_count.fetch_add(1, Ordering::SeqCst);
                    if previous == 0 {
                        first_spawn_entered_tx
                            .send(())
                            .expect("notify first spawn entry");
                        let (released_lock, released_cv) = &*release_first_spawn;
                        let mut released = released_lock.lock().expect("release lock");
                        while !*released {
                            released = released_cv.wait(released).expect("release wait");
                        }
                    }
                    let pid = std::process::id();
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
                    &key,
                    ReviewKind::Security,
                    6,
                    &spawn,
                )
            })
        };

        barrier.wait();
        first_spawn_entered_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("first spawn should enter deterministically");
        {
            let (released_lock, released_cv) = &*release_first_spawn;
            let mut released = released_lock.lock().expect("release lock");
            *released = true;
            released_cv.notify_all();
        }
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

        let spawn = |_: &std::path::Path,
                     _: u32,
                     _: ReviewKind,
                     _: &str,
                     _: u64|
         -> Result<DispatchReviewResult, String> {
            panic!("spawn should not execute when lock acquisition times out");
        };
        let timeout_path = home.join("dispatch.timeout.lock");
        let acquire_timeout =
            |_path: &std::path::Path| -> Result<std::fs::File, DispatchLockError> {
                Err(DispatchLockError::Timeout {
                    path: timeout_path.clone(),
                })
            };

        let err = dispatch_single_review_for_home_with_spawn_force_workspace_and_lock(
            &home,
            std::path::Path::new("."),
            &key,
            ReviewKind::Security,
            99,
            false,
            &spawn,
            &acquire_timeout,
        )
        .expect_err("lock-timeout dispatch must fail");
        assert!(
            err.contains(TERMINAL_DISPATCH_LOCK_TIMEOUT),
            "unexpected error: {err}"
        );

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

        let spawn =
            |_: u32, _: ReviewKind, _: &str, _: u64| -> Result<DispatchReviewResult, String> {
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
        let result =
            dispatch_single_review_for_home_with_spawn(home, &key, ReviewKind::Security, 7, &spawn)
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

        let spawn =
            |_: u32, _: ReviewKind, _: &str, _: u64| -> Result<DispatchReviewResult, String> {
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
        let _ =
            dispatch_single_review_for_home_with_spawn(home, &key, ReviewKind::Security, 8, &spawn)
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
            "owner~2Frepo-pr7-quality-0123456789abcdef0123456789abcdef01234567"
        );
    }
}
