//! `ReviewStateFile` persistence, pulse files, file locking, and process
//! checks.

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use chrono::Utc;
use fs2::FileExt;

use super::types::{
    PulseFile, ReviewRunState, ReviewStateEntry, ReviewStateFile, apm2_home_dir, ensure_parent_dir,
    entry_pr_number, sanitize_for_path,
};

// ── Path helpers ────────────────────────────────────────────────────────────

fn review_state_path() -> Result<PathBuf, String> {
    Ok(apm2_home_dir()?.join("review_state.json"))
}

fn review_state_lock_path() -> Result<PathBuf, String> {
    Ok(apm2_home_dir()?.join("review_state.lock"))
}

fn review_runs_dir_for_home(home: &Path) -> PathBuf {
    home.join("reviews")
}

fn review_run_dir_for_home(home: &Path, pr_number: u32, review_type: &str) -> PathBuf {
    review_runs_dir_for_home(home)
        .join(pr_number.to_string())
        .join(review_type)
}

fn review_run_state_path_for_home(home: &Path, pr_number: u32, review_type: &str) -> PathBuf {
    review_run_dir_for_home(home, pr_number, review_type).join("state.json")
}

fn review_runs_dir_path() -> Result<PathBuf, String> {
    Ok(review_runs_dir_for_home(&apm2_home_dir()?))
}

pub fn review_run_state_path(pr_number: u32, review_type: &str) -> Result<PathBuf, String> {
    Ok(review_run_state_path_for_home(
        &apm2_home_dir()?,
        pr_number,
        review_type,
    ))
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

#[derive(Debug, Clone)]
pub enum ReviewRunStateLoad {
    Present(ReviewRunState),
    Missing {
        path: PathBuf,
    },
    Corrupt {
        path: PathBuf,
        error: String,
    },
    Ambiguous {
        dir: PathBuf,
        candidates: Vec<PathBuf>,
    },
}

fn review_run_state_candidates(dir: &Path) -> Result<Vec<PathBuf>, String> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut candidates = fs::read_dir(dir)
        .map_err(|err| format!("failed to read run-state dir {}: {err}", dir.display()))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_file())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    name.starts_with("state")
                        && std::path::Path::new(name)
                            .extension()
                            .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
                })
        })
        .collect::<Vec<_>>();
    candidates.sort();
    Ok(candidates)
}

fn load_review_run_state_for_home(
    home: &Path,
    pr_number: u32,
    review_type: &str,
) -> Result<ReviewRunStateLoad, String> {
    let dir = review_run_dir_for_home(home, pr_number, review_type);
    let canonical = review_run_state_path_for_home(home, pr_number, review_type);
    let candidates = review_run_state_candidates(&dir)?;
    if candidates.is_empty() {
        return Ok(ReviewRunStateLoad::Missing { path: canonical });
    }
    if candidates.len() > 1 {
        return Ok(ReviewRunStateLoad::Ambiguous { dir, candidates });
    }
    let candidate = candidates
        .into_iter()
        .next()
        .ok_or_else(|| "run-state candidate resolution failed".to_string())?;
    if candidate != canonical {
        return Ok(ReviewRunStateLoad::Ambiguous {
            dir,
            candidates: vec![candidate],
        });
    }
    let content = match fs::read(&candidate) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ReviewRunStateLoad::Missing { path: canonical });
        },
        Err(err) => {
            return Ok(ReviewRunStateLoad::Corrupt {
                path: candidate,
                error: format!("failed to read run-state file: {err}"),
            });
        },
    };
    let parsed = match serde_json::from_slice::<ReviewRunState>(&content) {
        Ok(state) => state,
        Err(err) => {
            return Ok(ReviewRunStateLoad::Corrupt {
                path: candidate,
                error: format!("failed to parse run-state JSON: {err}"),
            });
        },
    };
    if parsed.pr_number != pr_number || !parsed.review_type.eq_ignore_ascii_case(review_type) {
        return Ok(ReviewRunStateLoad::Corrupt {
            path: candidate,
            error: format!(
                "run-state identity mismatch (expected pr={pr_number} type={review_type}, got pr={} type={})",
                parsed.pr_number, parsed.review_type
            ),
        });
    }
    Ok(ReviewRunStateLoad::Present(parsed))
}

pub fn load_review_run_state(
    pr_number: u32,
    review_type: &str,
) -> Result<ReviewRunStateLoad, String> {
    let home = apm2_home_dir()?;
    load_review_run_state_for_home(&home, pr_number, review_type)
}

fn load_review_run_state_strict_for_home(
    home: &Path,
    pr_number: u32,
    review_type: &str,
) -> Result<Option<ReviewRunState>, String> {
    match load_review_run_state_for_home(home, pr_number, review_type)? {
        ReviewRunStateLoad::Present(state) => Ok(Some(state)),
        ReviewRunStateLoad::Missing { .. } => Ok(None),
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

pub fn load_review_run_state_strict(
    pr_number: u32,
    review_type: &str,
) -> Result<Option<ReviewRunState>, String> {
    let home = apm2_home_dir()?;
    load_review_run_state_strict_for_home(&home, pr_number, review_type)
}

pub fn write_review_run_state(state: &ReviewRunState) -> Result<PathBuf, String> {
    let path = review_run_state_path(state.pr_number, &state.review_type)?;
    write_review_run_state_to_path(&path, state)?;
    Ok(path)
}

pub fn write_review_run_state_to_path(path: &Path, state: &ReviewRunState) -> Result<(), String> {
    ensure_parent_dir(path)?;
    let payload = serde_json::to_vec_pretty(state)
        .map_err(|err| format!("failed to serialize run-state: {err}"))?;
    let parent = path
        .parent()
        .ok_or_else(|| format!("run-state path has no parent: {}", path.display()))?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)
        .map_err(|err| format!("failed to create run-state temp file: {err}"))?;
    temp.write_all(&payload)
        .map_err(|err| format!("failed to write run-state temp file: {err}"))?;
    temp.as_file()
        .sync_all()
        .map_err(|err| format!("failed to sync run-state temp file: {err}"))?;
    temp.persist(path)
        .map_err(|err| format!("failed to persist {}: {err}", path.display()))?;
    Ok(())
}

fn next_review_sequence_number_for_home(
    home: &Path,
    pr_number: u32,
    review_type: &str,
) -> Result<u32, String> {
    match load_review_run_state_for_home(home, pr_number, review_type)? {
        ReviewRunStateLoad::Present(state) => Ok(state.sequence_number.saturating_add(1).max(1)),
        ReviewRunStateLoad::Missing { .. } => Ok(1),
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

pub fn next_review_sequence_number(pr_number: u32, review_type: &str) -> Result<u32, String> {
    let home = apm2_home_dir()?;
    next_review_sequence_number_for_home(&home, pr_number, review_type)
}

pub fn build_review_run_id(
    pr_number: u32,
    review_type: &str,
    sequence_number: u32,
    head_sha: &str,
) -> String {
    let head = &head_sha[..head_sha.len().min(8)];
    format!("pr{pr_number}-{review_type}-s{sequence_number}-{head}")
}

pub fn list_review_pr_numbers() -> Result<Vec<u32>, String> {
    let root = review_runs_dir_path()?;
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut numbers = fs::read_dir(&root)
        .map_err(|err| format!("failed to read reviews root {}: {err}", root.display()))?
        .filter_map(Result::ok)
        .filter_map(|entry| {
            entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<u32>().ok())
        })
        .collect::<Vec<_>>();
    numbers.sort_unstable();
    numbers.dedup();
    Ok(numbers)
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

#[cfg(test)]
mod tests {
    use super::{
        ReviewRunStateLoad, build_review_run_id, load_review_run_state_for_home,
        load_review_run_state_strict_for_home, next_review_sequence_number_for_home,
        review_run_state_path_for_home, write_review_run_state_to_path,
    };
    use crate::commands::fac_review::types::{ReviewRunState, ReviewRunStatus};

    fn sample_state() -> ReviewRunState {
        ReviewRunState {
            run_id: build_review_run_id(
                441,
                "security",
                3,
                "0123456789abcdef0123456789abcdef01234567",
            ),
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
            restart_count: 1,
            sequence_number: 3,
            pid: Some(12345),
        }
    }

    #[test]
    fn test_review_run_state_roundtrip() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();
        let state = sample_state();
        let path = review_run_state_path_for_home(home, 441, "security");
        write_review_run_state_to_path(&path, &state).expect("write run-state");
        let loaded = load_review_run_state_for_home(home, 441, "security").expect("load run-state");
        match loaded {
            ReviewRunStateLoad::Present(found) => {
                assert_eq!(found.run_id, state.run_id);
                assert_eq!(found.sequence_number, 3);
                assert_eq!(found.status, ReviewRunStatus::Alive);
            },
            other => panic!("expected present state, got {other:?}"),
        }
    }

    #[test]
    fn test_review_run_state_schema_fields_stable() {
        let value = serde_json::to_value(sample_state()).expect("serialize");
        assert_eq!(
            value
                .get("run_id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(""),
            "pr441-security-s3-01234567"
        );
        assert_eq!(
            value
                .get("review_type")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(""),
            "security"
        );
        assert_eq!(
            value
                .get("status")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(""),
            "alive"
        );
        assert!(
            value.get("sequence_number").is_some(),
            "sequence_number field must exist"
        );
    }

    #[test]
    fn test_review_run_state_missing_is_explicit() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();
        let loaded = load_review_run_state_for_home(home, 999, "quality").expect("load run-state");
        match loaded {
            ReviewRunStateLoad::Missing { path } => {
                assert_eq!(path, review_run_state_path_for_home(home, 999, "quality"));
            },
            other => panic!("expected missing state, got {other:?}"),
        }
    }

    #[test]
    fn test_review_run_state_corrupt_is_explicit() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();
        let path = review_run_state_path_for_home(home, 77, "security");
        std::fs::create_dir_all(path.parent().expect("path parent")).expect("create dir");
        std::fs::write(&path, "{not-json").expect("write corrupt json");
        let loaded = load_review_run_state_for_home(home, 77, "security").expect("load run-state");
        match loaded {
            ReviewRunStateLoad::Corrupt { path: found, error } => {
                assert_eq!(found, path);
                assert!(error.contains("parse"), "unexpected error detail: {error}");
            },
            other => panic!("expected corrupt state, got {other:?}"),
        }
    }

    #[test]
    fn test_review_run_state_ambiguous_is_explicit() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();
        let state = sample_state();
        let path = review_run_state_path_for_home(home, 441, "security");
        write_review_run_state_to_path(&path, &state).expect("write state");
        let alt = path.parent().expect("parent dir").join("state.backup.json");
        write_review_run_state_to_path(&alt, &state).expect("write secondary state");
        let loaded = load_review_run_state_for_home(home, 441, "security").expect("load run-state");
        match loaded {
            ReviewRunStateLoad::Ambiguous { candidates, .. } => {
                assert_eq!(candidates.len(), 2);
            },
            other => panic!("expected ambiguous state, got {other:?}"),
        }
    }

    #[test]
    fn test_next_sequence_number_reconstructs_from_state() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();
        let state = sample_state();
        let path = review_run_state_path_for_home(home, 441, "security");
        write_review_run_state_to_path(&path, &state).expect("write run-state");
        let next =
            next_review_sequence_number_for_home(home, 441, "security").expect("next sequence");
        assert_eq!(next, 4);
    }

    #[test]
    fn test_load_review_run_state_strict_fails_closed_for_corrupt_state() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();
        let path = review_run_state_path_for_home(home, 441, "quality");
        std::fs::create_dir_all(path.parent().expect("path parent")).expect("create dir");
        std::fs::write(&path, "{\"run_id\":").expect("write corrupt json");
        let error = load_review_run_state_strict_for_home(home, 441, "quality")
            .expect_err("must fail closed");
        assert!(
            error.contains("corrupt-state"),
            "unexpected error detail: {error}"
        );
    }
}
