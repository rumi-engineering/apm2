//! `apm2 fac review prepare` — materialize deterministic local review inputs.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Serialize;

use super::github_reads::{fetch_pr_base_sha, fetch_pr_head_sha};
use super::projection_store;
use super::target::resolve_pr_target;
use super::types::{apm2_home_dir, sanitize_for_path, validate_expected_head_sha};
use crate::commands::fac_permissions;
use crate::exit_codes::codes as exit_codes;

const PREPARE_SCHEMA: &str = "apm2.fac.review.prepare.v1";

#[derive(Debug, Serialize)]
struct PrepareSummary {
    schema: String,
    repo: String,
    pr_number: u32,
    pr_url: String,
    head_sha: String,
    head_source: String,
    base_ref: String,
    base_source: String,
    diff_path: String,
    commit_history_path: String,
    diff_content: String,
    commit_history_content: String,
    temp_dir: String,
}

pub fn run_prepare(
    repo: &str,
    pr_number: Option<u32>,
    sha: Option<&str>,
    json_output: bool,
) -> Result<u8, String> {
    let (owner_repo, resolved_pr) = resolve_pr_target(repo, pr_number)?;
    let repo_root = resolve_repo_root()?;
    let local_head = resolve_local_head_sha(&repo_root)?;
    let resolved_head = resolve_head_sha(&owner_repo, resolved_pr, sha, &local_head)?;
    if !local_head.eq_ignore_ascii_case(&resolved_head.head_sha) {
        return Err(format!(
            "local HEAD {local_head} does not match resolved PR head {} (source={}); sync your branch and retry `apm2 fac review prepare`",
            resolved_head.head_sha, resolved_head.head_source
        ));
    }
    let _ = projection_store::save_identity_with_context(
        &owner_repo,
        resolved_pr,
        &resolved_head.head_sha,
        "prepare",
    );

    let resolved_base = resolve_base_ref_for_pr(
        &repo_root,
        &owner_repo,
        resolved_pr,
        &resolved_head.head_sha,
    )?;
    let diff =
        collect_diff_against_main(&repo_root, &resolved_base.base_ref, &resolved_head.head_sha)?;
    let commit_history = collect_commit_history_against_main(
        &repo_root,
        &resolved_base.base_ref,
        &resolved_head.head_sha,
    )?;

    let prepared_dir = prepared_review_dir(&owner_repo, resolved_pr, &resolved_head.head_sha);
    fac_permissions::ensure_dir_with_mode(&prepared_dir).map_err(|err| {
        format!(
            "failed to create prepared review directory {}: {err}",
            prepared_dir.display()
        )
    })?;

    let diff_path = prepared_dir.join("review.diff");
    let history_path = prepared_dir.join("commit_history.txt");
    fac_permissions::write_fac_file_with_mode(&diff_path, diff.as_bytes()).map_err(|err| {
        format!(
            "failed to write prepared diff file {}: {err}",
            diff_path.display()
        )
    })?;
    fac_permissions::write_fac_file_with_mode(&history_path, commit_history.as_bytes()).map_err(
        |err| {
            format!(
                "failed to write prepared commit history file {}: {err}",
                history_path.display()
            )
        },
    )?;

    let summary = PrepareSummary {
        schema: PREPARE_SCHEMA.to_string(),
        repo: owner_repo.clone(),
        pr_number: resolved_pr,
        pr_url: format!("https://github.com/{owner_repo}/pull/{resolved_pr}"),
        head_sha: resolved_head.head_sha,
        head_source: resolved_head.head_source.to_string(),
        base_ref: resolved_base.base_ref,
        base_source: resolved_base.base_source.to_string(),
        diff_path: diff_path.display().to_string(),
        commit_history_path: history_path.display().to_string(),
        diff_content: diff,
        commit_history_content: commit_history,
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
        println!("  Head Source:     {}", summary.head_source);
        println!("  Base Ref:        {}", summary.base_ref);
        println!("  Base Source:     {}", summary.base_source);
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
    cleanup_prepared_review_inputs_at(&review_tmp_root(), owner_repo, pr_number, head_sha)
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct OwnedResolvedBaseRef {
    base_ref: String,
    base_source: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OwnedResolvedHead {
    head_sha: String,
    head_source: &'static str,
}

fn resolve_head_sha(
    owner_repo: &str,
    pr_number: u32,
    sha: Option<&str>,
    local_head_sha: &str,
) -> Result<OwnedResolvedHead, String> {
    resolve_head_sha_with(
        owner_repo,
        pr_number,
        sha,
        local_head_sha,
        |owner_repo, pr_number| {
            projection_store::load_pr_identity(owner_repo, pr_number)
                .map(|record| record.map(|value| value.head_sha))
        },
        fetch_pr_head_sha,
    )
}

fn resolve_head_sha_with<FLoad, FFetch>(
    owner_repo: &str,
    pr_number: u32,
    sha: Option<&str>,
    local_head_sha: &str,
    mut load_local_identity_head_sha_fn: FLoad,
    mut fetch_pr_head_sha_fn: FFetch,
) -> Result<OwnedResolvedHead, String>
where
    FLoad: FnMut(&str, u32) -> Result<Option<String>, String>,
    FFetch: FnMut(&str, u32) -> Result<String, String>,
{
    if let Some(value) = sha {
        validate_expected_head_sha(value)?;
        return Ok(OwnedResolvedHead {
            head_sha: value.to_ascii_lowercase(),
            head_source: "explicit_arg",
        });
    }

    if let Some(local_identity_head_sha) = load_local_identity_head_sha_fn(owner_repo, pr_number)?
        .map(|value| value.to_ascii_lowercase())
    {
        match validate_expected_head_sha(&local_identity_head_sha) {
            Ok(()) => {
                return Ok(OwnedResolvedHead {
                    head_sha: local_identity_head_sha,
                    head_source: "local_identity",
                });
            },
            Err(err) => {
                eprintln!(
                    "warn: ignoring invalid local identity head SHA for PR #{pr_number}; attempting remote/local fallback: {err}"
                );
            },
        }
    }

    match fetch_pr_head_sha_fn(owner_repo, pr_number) {
        Ok(remote_head_sha) => {
            validate_expected_head_sha(&remote_head_sha)?;
            Ok(OwnedResolvedHead {
                head_sha: remote_head_sha.to_ascii_lowercase(),
                head_source: "github_pr_head",
            })
        },
        Err(err) => {
            validate_expected_head_sha(local_head_sha)?;
            eprintln!(
                "warn: failed to fetch PR head SHA for PR #{pr_number}; using local HEAD fallback: {err}"
            );
            Ok(OwnedResolvedHead {
                head_sha: local_head_sha.to_ascii_lowercase(),
                head_source: "local_head_fallback",
            })
        },
    }
}

/// Resolve the diff base reference for a PR.
///
/// Resolution order:
/// 1) local persisted base snapshot keyed by (repo, pr, head)
/// 2) GitHub `pr.base.sha` when reachable (and cache it locally)
/// 3) local `origin/main` then local `main`
///
/// This keeps `prepare` fully usable offline after at least one successful
/// projection-backed `fac push`, while still recovering from missing local
/// snapshot state when GitHub is reachable.
fn resolve_base_ref_for_pr(
    repo_root: &Path,
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
) -> Result<OwnedResolvedBaseRef, String> {
    resolve_base_ref_for_pr_with(
        repo_root,
        owner_repo,
        pr_number,
        head_sha,
        fetch_pr_base_sha,
        |owner_repo, pr_number, head_sha| {
            projection_store::load_prepare_base_snapshot(owner_repo, pr_number, head_sha)
                .map(|snapshot| snapshot.map(|value| value.base_sha))
        },
        |owner_repo, pr_number, head_sha, base_sha, source| {
            projection_store::save_prepare_base_snapshot(
                owner_repo, pr_number, head_sha, base_sha, source,
            )
        },
        resolve_main_base_ref,
        sha_is_locally_reachable,
    )
}

#[allow(clippy::too_many_arguments)]
fn resolve_base_ref_for_pr_with<FFetch, FLoad, FSave, FMain, FReach>(
    repo_root: &Path,
    owner_repo: &str,
    pr_number: u32,
    head_sha: &str,
    mut fetch_pr_base_sha_fn: FFetch,
    mut load_snapshot_base_sha_fn: FLoad,
    mut save_snapshot_base_sha_fn: FSave,
    mut resolve_main_base_ref_fn: FMain,
    mut sha_is_reachable_fn: FReach,
) -> Result<OwnedResolvedBaseRef, String>
where
    FFetch: FnMut(&str, u32) -> Result<String, String>,
    FLoad: FnMut(&str, u32, &str) -> Result<Option<String>, String>,
    FSave: FnMut(&str, u32, &str, &str, &str) -> Result<(), String>,
    FMain: FnMut(&Path) -> Result<String, String>,
    FReach: FnMut(&Path, &str) -> bool,
{
    let cached_base_sha = load_snapshot_base_sha_fn(owner_repo, pr_number, head_sha)?
        .map(|value| value.to_ascii_lowercase());
    if let Some(cached_base_sha) = cached_base_sha {
        if sha_is_reachable_fn(repo_root, &cached_base_sha) {
            return Ok(OwnedResolvedBaseRef {
                base_ref: cached_base_sha,
                base_source: "local_snapshot",
            });
        }
        eprintln!(
            "warn: cached prepare base sha for PR #{pr_number} is not locally reachable; trying API/local fallback"
        );
    }

    if let Ok(base_sha) = fetch_pr_base_sha_fn(owner_repo, pr_number) {
        let normalized_base_sha = base_sha.to_ascii_lowercase();
        if sha_is_reachable_fn(repo_root, &normalized_base_sha) {
            if let Err(err) = save_snapshot_base_sha_fn(
                owner_repo,
                pr_number,
                head_sha,
                &normalized_base_sha,
                "prepare_pr_base_api",
            ) {
                eprintln!(
                    "warn: unable to persist prepare base snapshot for PR #{pr_number}: {err}"
                );
            }
            return Ok(OwnedResolvedBaseRef {
                base_ref: normalized_base_sha,
                base_source: "github_pr_base",
            });
        }
        eprintln!(
            "warn: GitHub PR base sha is not locally reachable for PR #{pr_number}; trying local main fallback"
        );
    }

    let fallback = resolve_main_base_ref_fn(repo_root)?;
    Ok(OwnedResolvedBaseRef {
        base_ref: fallback,
        base_source: "local_main",
    })
}

/// Return true if `sha` names an object that is reachable in the local repo.
fn sha_is_locally_reachable(repo_root: &Path, sha: &str) -> bool {
    Command::new("git")
        .args(["cat-file", "-e", sha])
        .current_dir(repo_root)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn resolve_main_base_ref(repo_root: &Path) -> Result<String, String> {
    let remote_main = "origin/main^{commit}";
    let remote_status = Command::new("git")
        .args(["rev-parse", "--verify", "--quiet", remote_main])
        .current_dir(repo_root)
        .output()
        .map_err(|err| format!("failed to resolve base ref: {err}"))?;
    if remote_status.status.success() {
        return Ok("origin/main".to_string());
    }

    let local_main = "main^{commit}";
    let local_status = Command::new("git")
        .args(["rev-parse", "--verify", "--quiet", local_main])
        .current_dir(repo_root)
        .output()
        .map_err(|err| format!("failed to resolve base ref: {err}"))?;
    if local_status.status.success() {
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

fn review_tmp_root() -> PathBuf {
    std::env::var_os("APM2_FAC_REVIEW_TMP_DIR")
        .filter(|value| !value.is_empty())
        .map_or_else(
            || {
                apm2_home_dir().map_or_else(
                    |_| PathBuf::from(".apm2-fallback/private/fac/prepared"),
                    |home| home.join("private").join("fac").join("prepared"),
                )
            },
            PathBuf::from,
        )
}

pub(super) fn prepared_review_root() -> PathBuf {
    review_tmp_root()
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

pub fn prepared_review_dir(owner_repo: &str, pr_number: u32, head_sha: &str) -> PathBuf {
    prepared_review_dir_from_root(&review_tmp_root(), owner_repo, pr_number, head_sha)
}

#[cfg(test)]
mod tests {
    use super::{
        cleanup_prepared_review_inputs_at, prepared_review_dir_from_root,
        resolve_base_ref_for_pr_with, resolve_head_sha_with, sha_is_locally_reachable,
    };

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
        std::fs::create_dir_all(&prepared).expect("create prepared dir");
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

    #[test]
    fn sha_is_locally_reachable_returns_true_for_real_object() {
        // "4b825dc642cb6eb9a060e54bf8d69288fbee4904" is the SHA1 of the empty
        // tree — it exists in every git repo unconditionally.
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        assert!(
            sha_is_locally_reachable(repo_root, "4b825dc642cb6eb9a060e54bf8d69288fbee4904"),
            "empty-tree SHA must be reachable in every git repo"
        );
    }

    #[test]
    fn sha_is_locally_reachable_returns_false_for_nonexistent_sha() {
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        assert!(
            !sha_is_locally_reachable(repo_root, "0000000000000000000000000000000000000000"),
            "all-zeros SHA must not be reachable"
        );
    }

    #[test]
    fn resolve_base_ref_prefers_local_snapshot_when_reachable() {
        let save_calls = std::cell::Cell::new(0u32);
        let base = resolve_base_ref_for_pr_with(
            std::path::Path::new("/tmp"),
            "example/repo",
            12,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            |_owner_repo, _pr_number| Ok("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string()),
            |_owner_repo, _pr_number, _head_sha| {
                Ok(Some("1111111111111111111111111111111111111111".to_string()))
            },
            |_owner_repo, _pr_number, _head_sha, _base_sha, _source| {
                save_calls.set(save_calls.get().saturating_add(1));
                Ok(())
            },
            |_repo_root| Ok("origin/main".to_string()),
            |_repo_root, sha| sha == "1111111111111111111111111111111111111111",
        )
        .expect("resolve base");
        assert_eq!(base.base_ref, "1111111111111111111111111111111111111111");
        assert_eq!(base.base_source, "local_snapshot");
        assert_eq!(
            save_calls.get(),
            0,
            "local snapshot hit must not rewrite snapshot state"
        );
    }

    #[test]
    fn resolve_base_ref_uses_github_base_when_snapshot_missing() {
        let save_calls = std::cell::Cell::new(0u32);
        let base = resolve_base_ref_for_pr_with(
            std::path::Path::new("/tmp"),
            "example/repo",
            13,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            |_owner_repo, _pr_number| Ok("2222222222222222222222222222222222222222".to_string()),
            |_owner_repo, _pr_number, _head_sha| Ok(None),
            |_owner_repo, _pr_number, _head_sha, _base_sha, _source| {
                save_calls.set(save_calls.get().saturating_add(1));
                Ok(())
            },
            |_repo_root| Ok("origin/main".to_string()),
            |_repo_root, sha| sha == "2222222222222222222222222222222222222222",
        )
        .expect("resolve base");
        assert_eq!(base.base_ref, "2222222222222222222222222222222222222222");
        assert_eq!(base.base_source, "github_pr_base");
        assert_eq!(
            save_calls.get(),
            1,
            "github-resolved base must persist snapshot exactly once"
        );
    }

    #[test]
    fn resolve_base_ref_falls_back_to_local_main_when_remote_unavailable() {
        let save_calls = std::cell::Cell::new(0u32);
        let base = resolve_base_ref_for_pr_with(
            std::path::Path::new("/tmp"),
            "example/repo",
            14,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            |_owner_repo, _pr_number| Err("network offline".to_string()),
            |_owner_repo, _pr_number, _head_sha| Ok(None),
            |_owner_repo, _pr_number, _head_sha, _base_sha, _source| {
                save_calls.set(save_calls.get().saturating_add(1));
                Ok(())
            },
            |_repo_root| Ok("main".to_string()),
            |_repo_root, _sha| false,
        )
        .expect("resolve base");
        assert_eq!(base.base_ref, "main");
        assert_eq!(base.base_source, "local_main");
        assert_eq!(
            save_calls.get(),
            0,
            "fallback must not persist a remote snapshot"
        );
    }

    #[test]
    fn resolve_base_ref_falls_back_to_local_main_when_snapshot_and_remote_unreachable() {
        let save_calls = std::cell::Cell::new(0u32);
        let base = resolve_base_ref_for_pr_with(
            std::path::Path::new("/tmp"),
            "example/repo",
            15,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            |_owner_repo, _pr_number| Ok("3333333333333333333333333333333333333333".to_string()),
            |_owner_repo, _pr_number, _head_sha| {
                Ok(Some("4444444444444444444444444444444444444444".to_string()))
            },
            |_owner_repo, _pr_number, _head_sha, _base_sha, _source| {
                save_calls.set(save_calls.get().saturating_add(1));
                Ok(())
            },
            |_repo_root| Ok("origin/main".to_string()),
            |_repo_root, _sha| false,
        )
        .expect("resolve base");
        assert_eq!(base.base_ref, "origin/main");
        assert_eq!(base.base_source, "local_main");
        assert_eq!(
            save_calls.get(),
            0,
            "unreachable base must not persist snapshot"
        );
    }

    #[test]
    fn resolve_head_sha_prefers_explicit_sha() {
        let local_head = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let resolved = resolve_head_sha_with(
            "example/repo",
            41,
            Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
            local_head,
            |_owner_repo, _pr_number| {
                Ok(Some("cccccccccccccccccccccccccccccccccccccccc".to_string()))
            },
            |_owner_repo, _pr_number| {
                panic!("remote fetch must not run when explicit SHA is provided")
            },
        )
        .expect("resolve head");
        assert_eq!(
            resolved.head_sha,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        );
        assert_eq!(resolved.head_source, "explicit_arg");
    }

    #[test]
    fn resolve_head_sha_uses_local_identity_without_remote_fetch() {
        let local_head = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let resolved = resolve_head_sha_with(
            "example/repo",
            42,
            None,
            local_head,
            |_owner_repo, _pr_number| {
                Ok(Some("dddddddddddddddddddddddddddddddddddddddd".to_string()))
            },
            |_owner_repo, _pr_number| {
                panic!("remote fetch must not run when local identity is present")
            },
        )
        .expect("resolve head");
        assert_eq!(
            resolved.head_sha,
            "dddddddddddddddddddddddddddddddddddddddd"
        );
        assert_eq!(resolved.head_source, "local_identity");
    }

    #[test]
    fn resolve_head_sha_uses_remote_when_identity_missing() {
        let local_head = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let resolved = resolve_head_sha_with(
            "example/repo",
            43,
            None,
            local_head,
            |_owner_repo, _pr_number| Ok(None),
            |_owner_repo, _pr_number| Ok("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_string()),
        )
        .expect("resolve head");
        assert_eq!(
            resolved.head_sha,
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        );
        assert_eq!(resolved.head_source, "github_pr_head");
    }

    #[test]
    fn resolve_head_sha_falls_back_to_local_head_when_remote_unavailable() {
        let local_head = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let resolved = resolve_head_sha_with(
            "example/repo",
            44,
            None,
            local_head,
            |_owner_repo, _pr_number| Ok(None),
            |_owner_repo, _pr_number| Err("network offline".to_string()),
        )
        .expect("resolve head");
        assert_eq!(
            resolved.head_sha,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(resolved.head_source, "local_head_fallback");
    }

    #[test]
    fn resolve_head_sha_rejects_invalid_local_head_fallback() {
        let err = resolve_head_sha_with(
            "example/repo",
            45,
            None,
            "not-a-sha",
            |_owner_repo, _pr_number| Ok(None),
            |_owner_repo, _pr_number| Err("network offline".to_string()),
        )
        .expect_err("invalid local fallback head must fail");
        assert!(!err.is_empty());
    }
}
