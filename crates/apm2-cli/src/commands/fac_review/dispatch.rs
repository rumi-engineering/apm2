//! Dispatch pipeline: detached review spawning, locks, and pending tracking.

use std::fs::{self, OpenOptions};
use std::path::PathBuf;
use std::process::Command;

use chrono::Utc;
use fs2::FileExt;

use super::state::{find_active_review_entry, is_process_alive};
use super::types::{
    DISPATCH_PENDING_TTL, DispatchReviewResult, PendingDispatchEntry, ReviewKind, apm2_home_dir,
    ensure_parent_dir, sanitize_for_path,
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

// ── Single review dispatch ──────────────────────────────────────────────────

pub fn dispatch_single_review(
    pr_url: &str,
    owner_repo: &str,
    pr_number: u32,
    review_kind: ReviewKind,
    head_sha: &str,
    dispatch_epoch: u64,
) -> Result<DispatchReviewResult, String> {
    with_dispatch_lock(
        owner_repo,
        pr_number,
        review_kind.as_str(),
        head_sha,
        || {
            if let Some(existing) =
                find_active_review_entry(pr_number, review_kind.as_str(), Some(head_sha))?
            {
                return Ok(DispatchReviewResult {
                    review_type: review_kind.as_str().to_string(),
                    mode: "joined".to_string(),
                    pid: Some(existing.pid),
                    unit: None,
                    log_file: Some(existing.log_file.display().to_string()),
                });
            }

            if let Some(pending) =
                read_fresh_pending_dispatch(owner_repo, pr_number, review_kind.as_str(), head_sha)?
            {
                return Ok(DispatchReviewResult {
                    review_type: review_kind.as_str().to_string(),
                    mode: "joined".to_string(),
                    pid: pending.pid,
                    unit: pending.unit,
                    log_file: pending.log_file,
                });
            }

            let result =
                spawn_detached_review(pr_url, pr_number, review_kind, head_sha, dispatch_epoch)?;
            write_pending_dispatch(
                owner_repo,
                pr_number,
                review_kind.as_str(),
                head_sha,
                &result,
            )?;
            Ok(result)
        },
    )
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
    let pid = child.id();
    drop(child);

    Ok(DispatchReviewResult {
        review_type: review_kind.as_str().to_string(),
        mode: "started".to_string(),
        pid: Some(pid),
        unit: None,
        log_file: Some(log_path.display().to_string()),
    })
}
