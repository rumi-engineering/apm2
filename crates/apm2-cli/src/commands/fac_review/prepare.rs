//! `apm2 fac review prepare` — materialize deterministic local review inputs.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Serialize;

use super::barrier::{ensure_gh_cli_ready, fetch_pr_head_sha};
use super::target::resolve_pr_target;
use super::types::{apm2_home_dir, sanitize_for_path, validate_expected_head_sha};
use crate::commands::fac_permissions;
use crate::exit_codes::codes as exit_codes;

const DEFAULT_TMP_SUBDIR: &str = "private/fac/prepared";
const PREPARE_SCHEMA: &str = "apm2.fac.review.prepare.v1";

#[derive(Debug, Serialize)]
struct PrepareSummary {
    schema: String,
    repo: String,
    pr_number: u32,
    pr_url: String,
    head_sha: String,
    base_ref: String,
    diff_path: String,
    commit_history_path: String,
    temp_dir: String,
}

pub fn run_prepare(
    repo: &str,
    pr_number: Option<u32>,
    pr_url: Option<&str>,
    sha: Option<&str>,
    json_output: bool,
) -> Result<u8, String> {
    ensure_gh_cli_ready()?;
    let (owner_repo, resolved_pr) = resolve_pr_target(repo, pr_number, pr_url)?;
    let head_sha = resolve_head_sha(&owner_repo, resolved_pr, sha)?;

    let repo_root = resolve_repo_root()?;
    let local_head = resolve_local_head_sha(&repo_root)?;
    if !local_head.eq_ignore_ascii_case(&head_sha) {
        return Err(format!(
            "local HEAD {local_head} does not match PR head {head_sha}; sync your branch and retry `apm2 fac review prepare`"
        ));
    }

    let base_ref = resolve_main_base_ref(&repo_root)?;
    let diff = collect_diff_against_main(&repo_root, &base_ref, &head_sha)?;
    let commit_history = collect_commit_history_against_main(&repo_root, &base_ref, &head_sha)?;

    let prepared_dir = prepared_review_dir(&owner_repo, resolved_pr, &head_sha)?;
    fac_permissions::ensure_dir_with_mode(&prepared_dir).map_err(|err| {
        format!(
            "failed to create prepared review directory {}: {err}",
            prepared_dir.display()
        )
    })?;

    let diff_path = prepared_dir.join("review.diff");
    let history_path = prepared_dir.join("commit_history.txt");
    fs::write(&diff_path, diff).map_err(|err| {
        format!(
            "failed to write prepared diff file {}: {err}",
            diff_path.display()
        )
    })?;
    fs::write(&history_path, commit_history).map_err(|err| {
        format!(
            "failed to write prepared commit history file {}: {err}",
            history_path.display()
        )
    })?;

    let summary = PrepareSummary {
        schema: PREPARE_SCHEMA.to_string(),
        repo: owner_repo.clone(),
        pr_number: resolved_pr,
        pr_url: format!("https://github.com/{owner_repo}/pull/{resolved_pr}"),
        head_sha,
        base_ref,
        diff_path: diff_path.display().to_string(),
        commit_history_path: history_path.display().to_string(),
        temp_dir: prepared_dir.display().to_string(),
    };

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&summary).unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        println!("FAC Review Prepare");
        println!("  Repo:            {}", summary.repo);
        println!("  PR Number:       {}", summary.pr_number);
        println!("  PR URL:          {}", summary.pr_url);
        println!("  Head SHA:        {}", summary.head_sha);
        println!("  Base Ref:        {}", summary.base_ref);
        println!("  Diff:            {}", summary.diff_path);
        println!("  Commit History:  {}", summary.commit_history_path);
        println!("  Temp Dir:        {}", summary.temp_dir);
    }

    Ok(exit_codes::SUCCESS)
}

pub fn cleanup_prepared_review_inputs(
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
) -> Result<bool, String> {
    cleanup_prepared_review_inputs_at(&review_tmp_root()?, owner_repo, pr_number, head_sha)
}

fn cleanup_prepared_review_inputs_at(
    root: &Path,
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
) -> Result<bool, String> {
    let dir = prepared_review_dir_from_root(root, owner_repo, pr_number, head_sha);
    if !dir.exists() {
        return Ok(false);
    }
    fs::remove_dir_all(&dir).map_err(|err| {
        format!(
            "failed to clean prepared review inputs at {}: {err}",
            dir.display()
        )
    })?;
    Ok(true)
}

fn resolve_repo_root() -> Result<PathBuf, String> {
    let output = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .map_err(|err| format!("failed to resolve repository root: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "git rev-parse --show-toplevel failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let repo_root = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if repo_root.is_empty() {
        return Err("git returned empty repository root".to_string());
    }
    Ok(PathBuf::from(repo_root))
}

fn resolve_local_head_sha(repo_root: &Path) -> Result<String, String> {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(repo_root)
        .output()
        .map_err(|err| format!("failed to resolve local HEAD SHA: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "git rev-parse HEAD failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let head = String::from_utf8_lossy(&output.stdout)
        .trim()
        .to_ascii_lowercase();
    validate_expected_head_sha(&head)?;
    Ok(head)
}

fn resolve_head_sha(owner_repo: &str, pr_number: u32, sha: Option<&str>) -> Result<String, String> {
    if let Some(value) = sha {
        validate_expected_head_sha(value)?;
        return Ok(value.to_ascii_lowercase());
    }
    let value = fetch_pr_head_sha(owner_repo, pr_number)?;
    validate_expected_head_sha(&value)?;
    Ok(value.to_ascii_lowercase())
}

fn resolve_main_base_ref(repo_root: &Path) -> Result<String, String> {
    let remote_main = "origin/main^{commit}";
    let remote_status = Command::new("git")
        .args(["rev-parse", "--verify", "--quiet", remote_main])
        .current_dir(repo_root)
        .status()
        .map_err(|err| format!("failed to resolve base ref: {err}"))?;
    if remote_status.success() {
        return Ok("origin/main".to_string());
    }

    let local_main = "main^{commit}";
    let local_status = Command::new("git")
        .args(["rev-parse", "--verify", "--quiet", local_main])
        .current_dir(repo_root)
        .status()
        .map_err(|err| format!("failed to resolve base ref: {err}"))?;
    if local_status.success() {
        return Ok("main".to_string());
    }

    Err("failed to resolve main base ref; neither `origin/main` nor `main` exists".to_string())
}

fn collect_diff_against_main(
    repo_root: &Path,
    base_ref: &str,
    head_sha: &str,
) -> Result<String, String> {
    let range = format!("{base_ref}...{head_sha}");
    let output = Command::new("git")
        .args(["diff", "--binary", "--no-color", "--no-ext-diff", &range])
        .current_dir(repo_root)
        .output()
        .map_err(|err| format!("failed to collect diff for `{range}`: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "failed to collect diff for `{range}`: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn collect_commit_history_against_main(
    repo_root: &Path,
    base_ref: &str,
    head_sha: &str,
) -> Result<String, String> {
    let range = format!("{base_ref}..{head_sha}");
    let output = Command::new("git")
        .args(["log", "--format=%h%x09%s", "--reverse", &range])
        .current_dir(repo_root)
        .output()
        .map_err(|err| format!("failed to collect commit history for `{range}`: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "failed to collect commit history for `{range}`: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    let history = String::from_utf8_lossy(&output.stdout).to_string();
    if !history.trim().is_empty() {
        return Ok(history);
    }

    let head_output = Command::new("git")
        .args(["log", "-1", "--format=%h%x09%s", head_sha])
        .current_dir(repo_root)
        .output()
        .map_err(|err| format!("failed to collect HEAD commit summary for `{head_sha}`: {err}"))?;
    if !head_output.status.success() {
        return Err(format!(
            "failed to collect HEAD commit summary for `{head_sha}`: {}",
            String::from_utf8_lossy(&head_output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&head_output.stdout).to_string())
}

fn review_tmp_root() -> Result<PathBuf, String> {
    let Some(custom_root) =
        std::env::var_os("APM2_FAC_REVIEW_TMP_DIR").filter(|value| !value.is_empty())
    else {
        return apm2_home_dir().map(|apm2_home| apm2_home.join(DEFAULT_TMP_SUBDIR));
    };

    Ok(PathBuf::from(custom_root))
}

fn prepared_review_dir_from_root(
    root: &Path,
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
) -> PathBuf {
    root.join(sanitize_for_path(owner_repo))
        .join(format!("pr{pr_number}"))
        .join(head_sha.to_ascii_lowercase())
}

pub fn prepared_review_dir(
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
) -> Result<PathBuf, String> {
    Ok(prepared_review_dir_from_root(
        &review_tmp_root()?,
        owner_repo,
        pr_number,
        head_sha,
    ))
}

#[cfg(test)]
mod tests {
    use super::{cleanup_prepared_review_inputs_at, prepared_review_dir_from_root};

    #[test]
    fn prepared_review_dir_normalizes_repo_and_sha() {
        let root = std::path::Path::new("/tmp/review-root");
        let path = prepared_review_dir_from_root(
            root,
            "guardian-intelligence/apm2",
            17,
            "ABCDEF0123456789ABCDEF0123456789ABCDEF01",
        );
        assert_eq!(
            path,
            std::path::PathBuf::from(
                "/tmp/review-root/guardian-intelligence~2Fapm2/pr17/abcdef0123456789abcdef0123456789abcdef01"
            )
        );
    }

    #[test]
    fn cleanup_prepared_review_inputs_at_removes_directory() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let prepared = prepared_review_dir_from_root(
            temp_dir.path(),
            "guardian-intelligence/apm2",
            99,
            "0123456789abcdef0123456789abcdef01234567",
        );
        crate::commands::fac_permissions::ensure_dir_with_mode(&prepared)
            .expect("create prepared dir");
        std::fs::write(prepared.join("review.diff"), "diff").expect("write diff");

        let removed = cleanup_prepared_review_inputs_at(
            temp_dir.path(),
            "guardian-intelligence/apm2",
            99,
            "0123456789abcdef0123456789abcdef01234567",
        )
        .expect("cleanup");
        assert!(removed);
        assert!(!prepared.exists());
    }
}
