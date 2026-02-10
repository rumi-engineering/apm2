//! Dispatch pipeline: detached review spawning, locks, and pending tracking.

use std::fs::{self, OpenOptions};
use std::path::PathBuf;
use std::process::Command;

use chrono::Utc;
use fs2::FileExt;

use super::state::{
    build_review_run_id, find_active_review_entry, load_review_run_state,
    next_review_sequence_number, write_review_run_state,
};
use super::types::{
    DISPATCH_PENDING_TTL, DispatchReviewResult, PendingDispatchEntry, ReviewKind, ReviewRunState,
    ReviewRunStatus, apm2_home_dir, ensure_parent_dir, now_iso8601, sanitize_for_path,
};

// ── Dispatch lock paths ─────────────────────────────────────────────────────

fn review_dispatch_locks_dir_path() -> Result<PathBuf, String> {
    Ok(apm2_home_dir()?.join("review_dispatch_locks"))
}

fn review_dispatch_lock_path(
    owner_repo: &str,
    pr_number: u32,
    review_type: &str,
    head_sha: &str,
) -> Result<PathBuf, String> {
    let safe_repo = sanitize_for_path(owner_repo);
    let safe_type = sanitize_for_path(review_type);
    let safe_head = sanitize_for_path(&head_sha[..head_sha.len().min(12)]);
    Ok(review_dispatch_locks_dir_path()?.join(format!(
        "{safe_repo}-pr{pr_number}-{safe_type}-{safe_head}.lock"
    )))
}

// ── Pending dispatch paths ──────────────────────────────────────────────────

fn review_dispatch_pending_dir_path() -> Result<PathBuf, String> {
    Ok(apm2_home_dir()?.join("review_dispatch_pending"))
}

fn review_dispatch_pending_path(
    owner_repo: &str,
    pr_number: u32,
    review_type: &str,
    head_sha: &str,
) -> Result<PathBuf, String> {
    let safe_repo = sanitize_for_path(owner_repo);
    let safe_type = sanitize_for_path(review_type);
    let safe_head = sanitize_for_path(&head_sha[..head_sha.len().min(12)]);
    Ok(review_dispatch_pending_dir_path()?.join(format!(
        "{safe_repo}-pr{pr_number}-{safe_type}-{safe_head}.json"
    )))
}

// ── Pending dispatch I/O ────────────────────────────────────────────────────

fn read_pending_dispatch_entry(
    path: &std::path::Path,
) -> Result<Option<PendingDispatchEntry>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let text = fs::read_to_string(path)
        .map_err(|err| format!("failed to read dispatch marker {}: {err}", path.display()))?;
    let entry = serde_json::from_str::<PendingDispatchEntry>(&text)
        .map_err(|err| format!("failed to parse dispatch marker {}: {err}", path.display()))?;
    Ok(Some(entry))
}

fn read_fresh_pending_dispatch(
    owner_repo: &str,
    pr_number: u32,
    review_type: &str,
    head_sha: &str,
) -> Result<Option<PendingDispatchEntry>, String> {
    let path = review_dispatch_pending_path(owner_repo, pr_number, review_type, head_sha)?;
    let Some(entry) = read_pending_dispatch_entry(&path)? else {
        return Ok(None);
    };
    let age = Utc::now()
        .signed_duration_since(entry.started_at)
        .to_std()
        .unwrap_or_default();
    if age <= DISPATCH_PENDING_TTL {
        if pending_dispatch_is_live(&entry) {
            return Ok(Some(entry));
        }
        let _ = fs::remove_file(&path);
        return Ok(None);
    }

    let _ = fs::remove_file(&path);
    Ok(None)
}

fn write_pending_dispatch(
    owner_repo: &str,
    pr_number: u32,
    review_type: &str,
    head_sha: &str,
    result: &DispatchReviewResult,
) -> Result<(), String> {
    let path = review_dispatch_pending_path(owner_repo, pr_number, review_type, head_sha)?;
    ensure_parent_dir(&path)?;
    let entry = PendingDispatchEntry {
        started_at: Utc::now(),
        pid: result.pid,
        unit: result.unit.clone(),
        log_file: result.log_file.clone(),
    };
    let payload = serde_json::to_string(&entry)
        .map_err(|err| format!("failed to serialize dispatch marker: {err}"))?;
    fs::write(&path, payload)
        .map_err(|err| format!("failed to write dispatch marker {}: {err}", path.display()))
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

// ── Dispatch locking ────────────────────────────────────────────────────────

fn with_dispatch_lock<T>(
    owner_repo: &str,
    pr_number: u32,
    review_type: &str,
    head_sha: &str,
    operation: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    let lock_path = review_dispatch_lock_path(owner_repo, pr_number, review_type, head_sha)?;
    ensure_parent_dir(&lock_path)?;
    let lock_file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|err| {
            format!(
                "failed to open dispatch lock {}: {err}",
                lock_path.display()
            )
        })?;
    FileExt::lock_exclusive(&lock_file)
        .map_err(|err| format!("failed to lock dispatch {}: {err}", lock_path.display()))?;
    let result = operation();
    drop(lock_file);
    result
}

// ── Tool availability ───────────────────────────────────────────────────────

fn command_available(command: &str) -> bool {
    Command::new("sh")
        .args(["-lc", &format!("command -v {command} >/dev/null 2>&1")])
        .status()
        .is_ok_and(|status| status.success())
}

fn attach_run_state_contract(
    pr_number: u32,
    review_type: &str,
    mut result: DispatchReviewResult,
) -> Result<DispatchReviewResult, String> {
    match load_review_run_state(pr_number, review_type)? {
        super::state::ReviewRunStateLoad::Present(state) => {
            result.run_state = state.status.as_str().to_string();
            result.run_id = Some(state.run_id);
            result.sequence_number = Some(state.sequence_number);
            result.terminal_reason = state.terminal_reason;
            if result.pid.is_none() {
                result.pid = state.pid;
            }
            Ok(result)
        },
        super::state::ReviewRunStateLoad::Missing { .. } => {
            result.run_state = "no-run-state".to_string();
            Ok(result)
        },
        super::state::ReviewRunStateLoad::Corrupt { path, error } => Err(format!(
            "corrupt-state path={} detail={error}",
            path.display()
        )),
        super::state::ReviewRunStateLoad::Ambiguous { dir, candidates } => {
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

fn seed_pending_run_state_for_dispatch(
    pr_url: &str,
    pr_number: u32,
    review_kind: ReviewKind,
    head_sha: &str,
) -> Result<ReviewRunState, String> {
    let review_type = review_kind.as_str();
    let sequence_number = next_review_sequence_number(pr_number, review_type)?;
    let state = ReviewRunState {
        run_id: build_review_run_id(pr_number, review_type, sequence_number, head_sha),
        pr_url: pr_url.to_string(),
        pr_number,
        head_sha: head_sha.to_string(),
        review_type: review_type.to_string(),
        reviewer_role: "fac_reviewer".to_string(),
        started_at: now_iso8601(),
        status: ReviewRunStatus::Pending,
        terminal_reason: None,
        model_id: None,
        backend_id: None,
        restart_count: 0,
        sequence_number,
        pid: None,
    };
    write_review_run_state(&state)?;
    Ok(state)
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
    let review_type = review_kind.as_str();
    with_dispatch_lock(owner_repo, pr_number, review_type, head_sha, || {
        if let super::state::ReviewRunStateLoad::Present(state) =
            load_review_run_state(pr_number, review_type)?
        {
            if state.head_sha.eq_ignore_ascii_case(head_sha)
                && !state.status.is_terminal()
                && run_state_has_live_process(&state)
            {
                return attach_run_state_contract(
                    pr_number,
                    review_type,
                    DispatchReviewResult {
                        review_type: review_type.to_string(),
                        mode: "joined".to_string(),
                        run_state: "alive".to_string(),
                        run_id: Some(state.run_id),
                        sequence_number: Some(state.sequence_number),
                        terminal_reason: state.terminal_reason,
                        pid: state.pid,
                        unit: None,
                        log_file: None,
                    },
                );
            }
        }

        if let Some(existing) = find_active_review_entry(pr_number, review_type, Some(head_sha))? {
            return attach_run_state_contract(
                pr_number,
                review_type,
                DispatchReviewResult {
                    review_type: review_type.to_string(),
                    mode: "joined".to_string(),
                    run_state: "unknown".to_string(),
                    run_id: None,
                    sequence_number: None,
                    terminal_reason: None,
                    pid: Some(existing.pid),
                    unit: None,
                    log_file: Some(existing.log_file.display().to_string()),
                },
            );
        }

        if let Some(pending) =
            read_fresh_pending_dispatch(owner_repo, pr_number, review_type, head_sha)?
        {
            return attach_run_state_contract(
                pr_number,
                review_type,
                DispatchReviewResult {
                    review_type: review_type.to_string(),
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

        let mut seeded_state =
            seed_pending_run_state_for_dispatch(pr_url, pr_number, review_kind, head_sha)?;
        let result =
            match spawn_detached_review(pr_url, pr_number, review_kind, head_sha, dispatch_epoch) {
                Ok(result) => result,
                Err(err) => {
                    seeded_state.status = ReviewRunStatus::Failed;
                    seeded_state.terminal_reason = Some("dispatch_spawn_failed".to_string());
                    write_review_run_state(&seeded_state)?;
                    return Err(err);
                },
            };
        write_pending_dispatch(owner_repo, pr_number, review_type, head_sha, &result)?;
        attach_run_state_contract(pr_number, review_type, result)
    })
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
    use super::run_state_has_live_process;
    use crate::commands::fac_review::types::{ReviewRunState, ReviewRunStatus};

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
}
