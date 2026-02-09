//! `ReviewStateFile` persistence, pulse files, file locking, and process
//! checks.

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use chrono::Utc;
use fs2::FileExt;

use super::types::{
    PulseFile, ReviewStateEntry, ReviewStateFile, apm2_home_dir, ensure_parent_dir,
    entry_pr_number, sanitize_for_path,
};

// ── Path helpers ────────────────────────────────────────────────────────────

fn review_state_path() -> Result<PathBuf, String> {
    Ok(apm2_home_dir()?.join("review_state.json"))
}

fn review_state_lock_path() -> Result<PathBuf, String> {
    Ok(apm2_home_dir()?.join("review_state.lock"))
}

pub fn review_locks_dir_path() -> Result<PathBuf, String> {
    Ok(apm2_home_dir()?.join("review_locks"))
}

pub fn review_lock_path(
    owner_repo: &str,
    pr_number: u32,
    review_type: &str,
) -> Result<PathBuf, String> {
    let safe_repo = sanitize_for_path(owner_repo);
    let safe_type = sanitize_for_path(review_type);
    Ok(review_locks_dir_path()?.join(format!("{safe_repo}-pr{pr_number}-{safe_type}.lock")))
}

fn review_pulses_dir_path() -> Result<PathBuf, String> {
    Ok(apm2_home_dir()?.join("review_pulses"))
}

fn pulse_file_path(pr_number: u32, review_type: &str) -> Result<PathBuf, String> {
    let suffix = match review_type {
        "security" => "review_pulse_security.json",
        "quality" => "review_pulse_quality.json",
        other => {
            return Err(format!(
                "invalid pulse review type: {other} (expected security|quality)"
            ));
        },
    };
    Ok(review_pulses_dir_path()?.join(format!("pr{pr_number}_{suffix}")))
}

fn legacy_pulse_file_path(review_type: &str) -> Result<PathBuf, String> {
    let suffix = match review_type {
        "security" => "review_pulse_security.json",
        "quality" => "review_pulse_quality.json",
        other => {
            return Err(format!(
                "invalid pulse review type: {other} (expected security|quality)"
            ));
        },
    };
    Ok(apm2_home_dir()?.join(suffix))
}

// ── ReviewStateFile persistence ─────────────────────────────────────────────

impl ReviewStateFile {
    fn load_from_path(path: &Path) -> Result<Self, String> {
        let content = match fs::read_to_string(path) {
            Ok(content) => content,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(err) => return Err(format!("failed to read {}: {err}", path.display())),
        };
        serde_json::from_str(&content)
            .map_err(|err| format!("failed to parse {}: {err}", path.display()))
    }

    fn save_to_path(&self, path: &Path) -> Result<(), String> {
        ensure_parent_dir(path)?;
        let serialized = serde_json::to_vec_pretty(self)
            .map_err(|err| format!("failed to serialize review state: {err}"))?;

        let parent = path
            .parent()
            .ok_or_else(|| format!("state path has no parent: {}", path.display()))?;
        let mut temp = tempfile::NamedTempFile::new_in(parent)
            .map_err(|err| format!("failed to create temp state file: {err}"))?;
        temp.write_all(&serialized)
            .map_err(|err| format!("failed to write temp state file: {err}"))?;
        temp.as_file()
            .sync_all()
            .map_err(|err| format!("failed to sync temp state file: {err}"))?;
        temp.persist(path)
            .map_err(|err| format!("failed to persist {}: {err}", path.display()))?;
        Ok(())
    }
}

// ── State locking ───────────────────────────────────────────────────────────

pub fn with_review_state_shared<T>(
    operation: impl FnOnce(&ReviewStateFile) -> Result<T, String>,
) -> Result<T, String> {
    let lock_path = review_state_lock_path()?;
    let state_path = review_state_path()?;
    ensure_parent_dir(&lock_path)?;
    let lock_file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|err| format!("failed to open state lock {}: {err}", lock_path.display()))?;
    FileExt::lock_shared(&lock_file)
        .map_err(|err| format!("failed to lock state {}: {err}", lock_path.display()))?;
    let state = ReviewStateFile::load_from_path(&state_path)?;
    let result = operation(&state);
    drop(lock_file);
    result
}

fn with_review_state_exclusive<T>(
    operation: impl FnOnce(&mut ReviewStateFile) -> Result<T, String>,
) -> Result<T, String> {
    let lock_path = review_state_lock_path()?;
    let state_path = review_state_path()?;
    ensure_parent_dir(&lock_path)?;
    let lock_file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|err| format!("failed to open state lock {}: {err}", lock_path.display()))?;
    FileExt::lock_exclusive(&lock_file)
        .map_err(|err| format!("failed to lock state {}: {err}", lock_path.display()))?;
    let mut state = ReviewStateFile::load_from_path(&state_path)?;
    let result = operation(&mut state)?;
    state.save_to_path(&state_path)?;
    drop(lock_file);
    Ok(result)
}

// ── State entry operations ──────────────────────────────────────────────────

pub fn upsert_review_state_entry(run_key: &str, entry: ReviewStateEntry) -> Result<(), String> {
    with_review_state_exclusive(|state| {
        state.reviewers.insert(run_key.to_string(), entry);
        Ok(())
    })
}

pub fn remove_review_state_entry(run_key: &str) -> Result<(), String> {
    with_review_state_exclusive(|state| {
        state.reviewers.remove(run_key);
        Ok(())
    })
}

pub fn find_active_review_entry(
    pr_number: u32,
    review_type: &str,
    head_sha: Option<&str>,
) -> Result<Option<ReviewStateEntry>, String> {
    with_review_state_shared(|state| {
        let mut candidates = state
            .reviewers
            .values()
            .filter(|entry| entry_pr_number(entry).is_some_and(|number| number == pr_number))
            .filter(|entry| entry.review_type.eq_ignore_ascii_case(review_type))
            .filter(|entry| is_process_alive(entry.pid))
            .cloned()
            .collect::<Vec<_>>();
        if let Some(head) = head_sha {
            candidates.retain(|entry| entry.head_sha.eq_ignore_ascii_case(head));
        }
        candidates.sort_by_key(|entry| entry.started_at);
        Ok(candidates.pop())
    })
}

pub fn try_acquire_review_lease(
    owner_repo: &str,
    pr_number: u32,
    review_type: &str,
) -> Result<Option<File>, String> {
    let lock_path = review_lock_path(owner_repo, pr_number, review_type)?;
    ensure_parent_dir(&lock_path)?;
    let lock_file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|err| format!("failed to open review lock {}: {err}", lock_path.display()))?;
    match FileExt::try_lock_exclusive(&lock_file) {
        Ok(()) => Ok(Some(lock_file)),
        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
        Err(err) => Err(format!(
            "failed to acquire review lock {}: {err}",
            lock_path.display()
        )),
    }
}

// ── Run key ─────────────────────────────────────────────────────────────────

pub fn build_run_key(pr_number: u32, review_type: &str, head_sha: &str) -> String {
    let head = &head_sha[..head_sha.len().min(8)];
    let ts = super::types::now_iso8601_millis().replace([':', '.'], "");
    format!("pr{pr_number}-{review_type}-{head}-{ts}")
}

// ── Process aliveness ───────────────────────────────────────────────────────

pub fn is_process_alive(pid: u32) -> bool {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

// ── Pulse files ─────────────────────────────────────────────────────────────

pub fn write_pulse_file(pr_number: u32, review_type: &str, head_sha: &str) -> Result<(), String> {
    let path = pulse_file_path(pr_number, review_type)?;
    write_pulse_file_to_path(&path, head_sha)
}

pub fn write_pulse_file_to_path(path: &Path, head_sha: &str) -> Result<(), String> {
    ensure_parent_dir(path)?;
    let pulse = PulseFile {
        head_sha: head_sha.to_string(),
        written_at: Utc::now(),
    };
    let content = serde_json::to_vec_pretty(&pulse)
        .map_err(|err| format!("failed to serialize pulse file: {err}"))?;
    let parent = path
        .parent()
        .ok_or_else(|| format!("pulse path has no parent: {}", path.display()))?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)
        .map_err(|err| format!("failed to create pulse temp file: {err}"))?;
    temp.write_all(&content)
        .map_err(|err| format!("failed to write pulse temp file: {err}"))?;
    temp.as_file()
        .sync_all()
        .map_err(|err| format!("failed to sync pulse temp file: {err}"))?;
    temp.persist(path)
        .map_err(|err| format!("failed to persist {}: {err}", path.display()))?;
    Ok(())
}

pub fn read_pulse_file(pr_number: u32, review_type: &str) -> Result<Option<PulseFile>, String> {
    let path = pulse_file_path(pr_number, review_type)?;
    if let Some(pulse) = read_pulse_file_from_path(&path)? {
        Ok(Some(pulse))
    } else {
        let legacy = legacy_pulse_file_path(review_type)?;
        read_pulse_file_from_path(&legacy)
    }
}

pub fn read_pulse_file_from_path(path: &Path) -> Result<Option<PulseFile>, String> {
    let content = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(format!("failed to read {}: {err}", path.display())),
    };
    let pulse = serde_json::from_slice::<PulseFile>(&content)
        .map_err(|err| format!("failed to parse pulse file {}: {err}", path.display()))?;
    Ok(Some(pulse))
}

// ── File reading helpers ────────────────────────────────────────────────────

pub fn read_tail(path: &Path, max_lines: usize) -> Result<String, String> {
    let file =
        File::open(path).map_err(|err| format!("failed to open {}: {err}", path.display()))?;
    let reader = BufReader::new(file);
    let mut lines = Vec::new();
    for line in reader.lines() {
        let line = line.map_err(|err| format!("failed to read line: {err}"))?;
        lines.push(line);
        if lines.len() > max_lines {
            let _ = lines.remove(0);
        }
    }
    Ok(lines.join("\n"))
}

pub fn read_last_lines(path: &Path, max_lines: usize) -> Result<Vec<String>, String> {
    let file =
        File::open(path).map_err(|err| format!("failed to open {}: {err}", path.display()))?;
    let reader = BufReader::new(file);
    let mut lines = Vec::new();
    for line in reader.lines() {
        let line = line.map_err(|err| format!("failed to read line: {err}"))?;
        lines.push(line);
        if lines.len() > max_lines {
            let _ = lines.remove(0);
        }
    }
    Ok(lines)
}
