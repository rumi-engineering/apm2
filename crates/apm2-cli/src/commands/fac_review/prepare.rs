//! `apm2 fac review prepare` — materialize deterministic local review inputs.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use apm2_core::fac::gh_command;
use serde::Serialize;

use super::github_reads::{fetch_pr_base_sha, fetch_pr_head_sha};
use super::projection_store;
use super::target::resolve_pr_target;
use super::types::{apm2_home_dir, sanitize_for_path, validate_expected_head_sha};
use crate::commands::fac_permissions;
use crate::exit_codes::codes as exit_codes;

const PREPARE_SCHEMA: &str = "apm2.fac.review.prepare.v1";
const PREPARE_INLINE_LINE_LIMIT: usize = 2_000;
/// Maximum accepted PR body size in bytes. Bodies larger than this are treated
/// as unbounded/hostile and cause work scope enrichment to degrade to null.
const PREPARE_PR_BODY_MAX_BYTES: usize = 1_048_576; // 1 MiB

/// A single expanded requirement node extracted from an RFC document.
/// Reserved for future use when work objects include `requirement_ids`.
#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct RequirementNode {
    id: String,
    statement: String,
    acceptance: serde_json::Value,
}

/// Work scope context embedded in the prepare summary.
///
/// Present when the PR body contains a valid `apm2.fac_push_metadata.v1` block
/// with trusted origin (same-repo PR, branch field matches actual head ref).
///
/// `requirement_ids` and `requirements` are reserved for future population
/// once daemon work objects carry explicit requirements (post-TCK-00683).
#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct WorkScopeContext {
    work_id: String,
    ticket_alias: Option<String>,
    rfc_id: Option<String>,
    requirement_ids: Vec<String>,
    requirements: Vec<RequirementNode>,
}

#[derive(Debug, Serialize)]
struct PrepareArtifactMetadata {
    path: String,
    bytes: usize,
    lines: usize,
    inlined: bool,
    omitted_lines: usize,
}

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
    output_mode: String,
    inline_line_limit: usize,
    inline_line_count: usize,
    omitted_line_count: usize,
    diff: PrepareArtifactMetadata,
    commit_history: PrepareArtifactMetadata,
    diff_content: String,
    commit_history_content: String,
    temp_dir: String,
    work_scope: Option<WorkScopeContext>,
}

#[derive(Debug)]
struct PrepareInlineContent {
    output_mode: &'static str,
    inline_line_count: usize,
    omitted_line_count: usize,
    diff_content: String,
    diff_inlined: bool,
    diff_omitted_lines: usize,
    commit_history_content: String,
    commit_history_inlined: bool,
    commit_history_omitted_lines: usize,
}

fn count_text_lines(content: &str) -> usize {
    if content.is_empty() {
        0
    } else {
        content.lines().count()
    }
}

fn omitted_payload_notice(kind: &str, path: &Path, lines: usize, line_limit: usize) -> String {
    format!(
        "<<prepare omitted inline {kind} payload: {lines} lines exceed inline limit {line_limit}; read {}>>",
        path.display()
    )
}

fn build_prepare_inline_content(
    diff: &str,
    diff_path: &Path,
    commit_history: &str,
    commit_history_path: &Path,
    line_limit: usize,
) -> PrepareInlineContent {
    let diff_lines = count_text_lines(diff);
    let commit_history_lines = count_text_lines(commit_history);
    let total_lines = diff_lines.saturating_add(commit_history_lines);
    if total_lines <= line_limit {
        return PrepareInlineContent {
            output_mode: "inline",
            inline_line_count: total_lines,
            omitted_line_count: 0,
            diff_content: diff.to_string(),
            diff_inlined: true,
            diff_omitted_lines: 0,
            commit_history_content: commit_history.to_string(),
            commit_history_inlined: true,
            commit_history_omitted_lines: 0,
        };
    }

    let mut remaining_budget = line_limit;

    let (diff_content, diff_inlined, diff_omitted_lines) = if diff_lines <= remaining_budget {
        remaining_budget = remaining_budget.saturating_sub(diff_lines);
        (diff.to_string(), true, 0)
    } else {
        let notice = omitted_payload_notice("diff", diff_path, diff_lines, line_limit);
        remaining_budget = remaining_budget.saturating_sub(count_text_lines(&notice));
        (notice, false, diff_lines)
    };

    let (commit_history_content, commit_history_inlined, commit_history_omitted_lines) =
        if commit_history_lines <= remaining_budget {
            (commit_history.to_string(), true, 0)
        } else {
            (
                omitted_payload_notice(
                    "commit_history",
                    commit_history_path,
                    commit_history_lines,
                    line_limit,
                ),
                false,
                commit_history_lines,
            )
        };

    let inline_line_count =
        count_text_lines(&diff_content).saturating_add(count_text_lines(&commit_history_content));
    let omitted_line_count = diff_omitted_lines.saturating_add(commit_history_omitted_lines);
    PrepareInlineContent {
        output_mode: "artifact_reference",
        inline_line_count,
        omitted_line_count,
        diff_content,
        diff_inlined,
        diff_omitted_lines,
        commit_history_content,
        commit_history_inlined,
        commit_history_omitted_lines,
    }
}

/// Search all fenced YAML blocks in `body` and return the content of the first
/// one whose `schema` field equals `target_schema`.
///
/// This correctly handles PR bodies that contain multiple YAML blocks (e.g.
/// gate-status fences) by iterating until the matching schema is found.
fn find_yaml_block_with_schema<'a>(body: &'a str, target_schema: &str) -> Option<&'a str> {
    let open_marker = "```yaml";
    let mut search_start = 0usize;

    while let Some(rel_open) = body[search_start..].find(open_marker) {
        let open_start = search_start.saturating_add(rel_open);
        let content_start = open_start.saturating_add(open_marker.len());

        // Skip past the (optional) rest of the opening-fence line.
        let after_open = body.get(content_start..)?;
        let newline_offset = after_open.find('\n').unwrap_or(after_open.len());
        let inner_start = content_start
            .saturating_add(newline_offset)
            .saturating_add(1);
        if inner_start > body.len() {
            break;
        }

        // Find the closing fence (``` on its own line).
        let remaining = body.get(inner_start..)?;
        if let Some(close_offset) = remaining.find("```") {
            let inner_end = inner_start.saturating_add(close_offset);
            if let Some(block) = body.get(inner_start..inner_end) {
                if let Ok(yaml) = serde_yaml::from_str::<serde_yaml::Value>(block) {
                    if yaml.get("schema").and_then(serde_yaml::Value::as_str) == Some(target_schema)
                    {
                        return Some(block);
                    }
                }
            }
            // Advance past this block's closing fence and continue.
            search_start = inner_end.saturating_add(3); // skip past ```
        } else {
            break;
        }
    }
    None
}

/// Trust context fetched from GitHub for a PR.
struct PrTrustContext {
    /// Actual head branch ref (e.g. `ticket/RFC-0019/TCK-00685`).
    head_ref: String,
    /// Full repository name of the head branch owner (e.g.
    /// `guardian-intelligence/apm2`). For fork PRs this differs from the
    /// base repo's full name.
    head_repo_full_name: String,
}

/// Fetch trust-relevant PR fields from the GitHub API in a single call.
/// Uses `gh_command()` for FAC-hardened non-interactive access.
fn fetch_pr_trust_context(owner_repo: &str, pr_number: u32) -> Option<PrTrustContext> {
    let endpoint = format!("/repos/{owner_repo}/pulls/{pr_number}");
    // Fetch both head.ref and head.repo.full_name in one API call.
    let output = gh_command()
        .args([
            "api",
            &endpoint,
            "--jq",
            "{ref: .head.ref, repo: .head.repo.full_name}",
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).ok()?;
    let head_ref = json.get("ref").and_then(|v| v.as_str())?.to_string();
    let head_repo_full_name = json.get("repo").and_then(|v| v.as_str())?.to_string();
    if head_ref.is_empty() || head_ref == "null" || head_repo_full_name.is_empty() {
        return None;
    }
    Some(PrTrustContext {
        head_ref,
        head_repo_full_name,
    })
}

/// Fetch the PR body text from the GitHub API.
///
/// Uses `gh_command()` for FAC-hardened non-interactive access.
/// Bodies exceeding `PREPARE_PR_BODY_MAX_BYTES` are rejected to prevent
/// unbounded memory consumption from hostile or malformed PR bodies.
fn fetch_pr_body_text(owner_repo: &str, pr_number: u32) -> Option<String> {
    let endpoint = format!("/repos/{owner_repo}/pulls/{pr_number}");
    let output = gh_command()
        .args(["api", &endpoint, "--jq", ".body"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    if output.stdout.len() > PREPARE_PR_BODY_MAX_BYTES {
        eprintln!(
            "warn: PR body exceeds {PREPARE_PR_BODY_MAX_BYTES} bytes; skipping work scope enrichment"
        );
        return None;
    }
    let body = String::from_utf8(output.stdout).ok()?;
    if body.trim().is_empty() || body.trim() == "null" {
        return None;
    }
    Some(body)
}

/// Attempt to parse `RFC-XXXX` from a branch name of the form
/// `ticket/RFC-XXXX/...`.
fn parse_rfc_id_from_branch(branch: &str) -> Option<String> {
    branch.split('/').find_map(|segment| {
        if segment.starts_with("RFC-")
            && segment.len() > 4
            && segment[4..].chars().all(|c| c.is_ascii_digit())
        {
            Some(segment.to_string())
        } else {
            None
        }
    })
}

const PUSH_METADATA_SCHEMA: &str = "apm2.fac_push_metadata.v1";

/// Attempt to enrich prepare output with the work scope for this PR.
///
/// Resolution steps:
/// 1. Fetch PR body from GitHub API via `gh_command()` (bounded to 1 MiB)
/// 2. Locate the `apm2.fac_push_metadata.v1` YAML block among all fenced blocks
///    → extract `work_id`, `ticket_alias`, `branch`
/// 3. Fetch actual PR trust context (head ref + head repo full name) and
///    validate:
///    - `head.repo.full_name == owner_repo` (same-repo PR, not a fork)
///    - `head.ref == yaml branch` (branch field binding integrity)
/// 4. Parse `rfc_id` from branch name
/// 5. Return `Some(WorkScopeContext{...})` with `work_id`, `ticket_alias`, and
///    `rfc_id`; `requirement_ids` and `requirements` are empty (reserved for
///    future population once daemon work objects carry explicit requirements,
///    post-TCK-00683).
///
/// Returns `None` on any failure — graceful degradation for external/fork PRs
/// or offline mode.
fn fetch_work_scope(owner_repo: &str, pr_number: u32) -> Option<WorkScopeContext> {
    let pr_body = fetch_pr_body_text(owner_repo, pr_number)?;

    // Find the fac_push_metadata.v1 block among all fenced YAML blocks.
    let yaml_block = find_yaml_block_with_schema(&pr_body, PUSH_METADATA_SCHEMA)?;
    let yaml_value: serde_yaml::Value = serde_yaml::from_str(yaml_block).ok()?;

    let work_id = yaml_value
        .get("work_id")
        .and_then(serde_yaml::Value::as_str)?
        .to_string();
    if work_id.is_empty() {
        return None;
    }
    let ticket_alias = yaml_value
        .get("ticket_alias")
        .and_then(serde_yaml::Value::as_str)
        .map(String::from);
    let yaml_branch = yaml_value
        .get("branch")
        .and_then(serde_yaml::Value::as_str)?
        .to_string();

    // Trust gate: verify both same-repo origin and branch binding integrity.
    // - head.repo.full_name must equal owner_repo: rejects fork PRs where an
    //   attacker controls the PR body.
    // - head.ref must match the YAML branch field: verifies binding integrity
    //   between the push metadata and the actual PR head branch.
    let trust_ctx = fetch_pr_trust_context(owner_repo, pr_number)?;
    if trust_ctx.head_repo_full_name != owner_repo {
        eprintln!(
            "warn: work_scope trust gate: PR head repo '{}' differs from base repo '{owner_repo}'; skipping work scope enrichment for fork PR",
            trust_ctx.head_repo_full_name
        );
        return None;
    }
    if trust_ctx.head_ref != yaml_branch {
        eprintln!(
            "warn: work_scope trust gate: branch field '{yaml_branch}' in PR body does not match actual head ref '{}'; skipping work scope enrichment",
            trust_ctx.head_ref
        );
        return None;
    }

    let rfc_id = parse_rfc_id_from_branch(&yaml_branch);

    Some(WorkScopeContext {
        work_id,
        ticket_alias,
        rfc_id,
        requirement_ids: vec![],
        requirements: vec![],
    })
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
    ensure_prepare_head_alignment(&local_head, &resolved_head, sha.is_some())?;
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

    let inline_payload = build_prepare_inline_content(
        &diff,
        &diff_path,
        &commit_history,
        &history_path,
        PREPARE_INLINE_LINE_LIMIT,
    );
    let diff_lines = count_text_lines(&diff);
    let commit_history_lines = count_text_lines(&commit_history);

    let work_scope = fetch_work_scope(&owner_repo, resolved_pr);

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
        output_mode: inline_payload.output_mode.to_string(),
        inline_line_limit: PREPARE_INLINE_LINE_LIMIT,
        inline_line_count: inline_payload.inline_line_count,
        omitted_line_count: inline_payload.omitted_line_count,
        diff: PrepareArtifactMetadata {
            path: diff_path.display().to_string(),
            bytes: diff.len(),
            lines: diff_lines,
            inlined: inline_payload.diff_inlined,
            omitted_lines: inline_payload.diff_omitted_lines,
        },
        commit_history: PrepareArtifactMetadata {
            path: history_path.display().to_string(),
            bytes: commit_history.len(),
            lines: commit_history_lines,
            inlined: inline_payload.commit_history_inlined,
            omitted_lines: inline_payload.commit_history_omitted_lines,
        },
        diff_content: inline_payload.diff_content,
        commit_history_content: inline_payload.commit_history_content,
        temp_dir: prepared_dir.display().to_string(),
        work_scope,
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

fn ensure_prepare_head_alignment(
    local_head: &str,
    resolved_head: &OwnedResolvedHead,
    explicit_sha_supplied: bool,
) -> Result<(), String> {
    if local_head.eq_ignore_ascii_case(&resolved_head.head_sha) {
        return Ok(());
    }
    if explicit_sha_supplied {
        eprintln!(
            "warn: local HEAD {local_head} differs from requested review SHA {}; continuing because explicit --sha was supplied",
            resolved_head.head_sha
        );
        return Ok(());
    }
    Err(format!(
        "local HEAD {local_head} does not match resolved PR head {} (source={}); sync your branch and retry `apm2 fac review prepare`",
        resolved_head.head_sha, resolved_head.head_source
    ))
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
                if local_identity_head_sha.eq_ignore_ascii_case(local_head_sha) {
                    return Ok(OwnedResolvedHead {
                        head_sha: local_identity_head_sha,
                        head_source: "local_identity",
                    });
                }
                eprintln!(
                    "warn: local identity head SHA for PR #{pr_number} does not match local HEAD; treating identity as stale and attempting remote/local fallback"
                );
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
        match validate_expected_head_sha(&cached_base_sha) {
            Ok(()) => {
                if sha_is_reachable_fn(repo_root, &cached_base_sha) {
                    return Ok(OwnedResolvedBaseRef {
                        base_ref: cached_base_sha,
                        base_source: "local_snapshot",
                    });
                }
                eprintln!(
                    "warn: cached prepare base sha for PR #{pr_number} is not locally reachable; trying API/local fallback"
                );
            },
            Err(err) => {
                eprintln!(
                    "warn: ignoring invalid cached prepare base sha for PR #{pr_number}; trying API/local fallback: {err}"
                );
            },
        }
    }

    if let Ok(base_sha) = fetch_pr_base_sha_fn(owner_repo, pr_number) {
        let normalized_base_sha = base_sha.to_ascii_lowercase();
        match validate_expected_head_sha(&normalized_base_sha) {
            Ok(()) => {
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
            },
            Err(err) => {
                eprintln!(
                    "warn: ignoring invalid GitHub PR base sha for PR #{pr_number}; trying local main fallback: {err}"
                );
            },
        }
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
        OwnedResolvedHead, PREPARE_INLINE_LINE_LIMIT, build_prepare_inline_content,
        cleanup_prepared_review_inputs_at, count_text_lines, ensure_prepare_head_alignment,
        find_yaml_block_with_schema, parse_rfc_id_from_branch, prepared_review_dir_from_root,
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
    fn ensure_prepare_head_alignment_allows_explicit_sha_mismatch() {
        let resolved = OwnedResolvedHead {
            head_sha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            head_source: "explicit_arg",
        };
        ensure_prepare_head_alignment("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", &resolved, true)
            .expect("explicit --sha should allow local HEAD mismatch");
    }

    #[test]
    fn ensure_prepare_head_alignment_rejects_implicit_mismatch() {
        let resolved = OwnedResolvedHead {
            head_sha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            head_source: "github_pr_head",
        };
        let err = ensure_prepare_head_alignment(
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            &resolved,
            false,
        )
        .expect_err("implicit mismatch must remain fail-closed");
        assert!(err.contains("does not match resolved PR head"));
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
    fn resolve_base_ref_ignores_invalid_local_snapshot_before_reachability() {
        let save_calls = std::cell::Cell::new(0u32);
        let reachable_calls = std::cell::Cell::new(0u32);
        let base = resolve_base_ref_for_pr_with(
            std::path::Path::new("/tmp"),
            "example/repo",
            16,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            |_owner_repo, _pr_number| Ok("5555555555555555555555555555555555555555".to_string()),
            |_owner_repo, _pr_number, _head_sha| Ok(Some("origin/main".to_string())),
            |_owner_repo, _pr_number, _head_sha, _base_sha, _source| {
                save_calls.set(save_calls.get().saturating_add(1));
                Ok(())
            },
            |_repo_root| Ok("main".to_string()),
            |_repo_root, sha| {
                reachable_calls.set(reachable_calls.get().saturating_add(1));
                sha == "5555555555555555555555555555555555555555"
            },
        )
        .expect("resolve base");
        assert_eq!(base.base_ref, "5555555555555555555555555555555555555555");
        assert_eq!(base.base_source, "github_pr_base");
        assert_eq!(
            save_calls.get(),
            1,
            "valid github base should still be persisted once"
        );
        assert_eq!(
            reachable_calls.get(),
            1,
            "invalid cached base must be rejected before reachability probes"
        );
    }

    #[test]
    fn resolve_base_ref_rejects_invalid_github_base_and_falls_back_to_local_main() {
        let save_calls = std::cell::Cell::new(0u32);
        let reachable_calls = std::cell::Cell::new(0u32);
        let base = resolve_base_ref_for_pr_with(
            std::path::Path::new("/tmp"),
            "example/repo",
            17,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            |_owner_repo, _pr_number| Ok("origin/main".to_string()),
            |_owner_repo, _pr_number, _head_sha| Ok(None),
            |_owner_repo, _pr_number, _head_sha, _base_sha, _source| {
                save_calls.set(save_calls.get().saturating_add(1));
                Ok(())
            },
            |_repo_root| Ok("origin/main".to_string()),
            |_repo_root, _sha| {
                reachable_calls.set(reachable_calls.get().saturating_add(1));
                true
            },
        )
        .expect("resolve base");
        assert_eq!(base.base_ref, "origin/main");
        assert_eq!(base.base_source, "local_main");
        assert_eq!(
            save_calls.get(),
            0,
            "invalid github base must not be cached"
        );
        assert_eq!(
            reachable_calls.get(),
            0,
            "invalid github base must be rejected before reachability checks"
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
        let local_head = "dddddddddddddddddddddddddddddddddddddddd";
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
    fn resolve_head_sha_ignores_stale_local_identity_and_uses_remote() {
        let local_head = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let resolved = resolve_head_sha_with(
            "example/repo",
            42,
            None,
            local_head,
            |_owner_repo, _pr_number| {
                Ok(Some("dddddddddddddddddddddddddddddddddddddddd".to_string()))
            },
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

    #[test]
    fn build_prepare_inline_content_inlines_when_under_limit() {
        let payload = build_prepare_inline_content(
            "line1\nline2\n",
            std::path::Path::new("/tmp/review.diff"),
            "commit1\ncommit2\n",
            std::path::Path::new("/tmp/commit_history.txt"),
            PREPARE_INLINE_LINE_LIMIT,
        );
        assert_eq!(payload.output_mode, "inline");
        assert!(payload.diff_inlined);
        assert!(payload.commit_history_inlined);
        assert_eq!(payload.inline_line_count, 4);
        assert_eq!(payload.omitted_line_count, 0);
        assert_eq!(payload.diff_content, "line1\nline2\n");
        assert_eq!(payload.commit_history_content, "commit1\ncommit2\n");
    }

    #[test]
    fn build_prepare_inline_content_spills_large_diff_and_keeps_history() {
        let large_diff = "d\n".repeat(PREPARE_INLINE_LINE_LIMIT.saturating_add(25));
        let commit_history = "commit-a\ncommit-b\n";
        let payload = build_prepare_inline_content(
            &large_diff,
            std::path::Path::new("/tmp/review.diff"),
            commit_history,
            std::path::Path::new("/tmp/commit_history.txt"),
            PREPARE_INLINE_LINE_LIMIT,
        );
        assert_eq!(payload.output_mode, "artifact_reference");
        assert!(!payload.diff_inlined);
        assert!(payload.commit_history_inlined);
        assert!(
            payload
                .diff_content
                .contains("prepare omitted inline diff payload")
        );
        assert!(payload.diff_content.contains("/tmp/review.diff"));
        assert_eq!(
            payload.diff_omitted_lines,
            PREPARE_INLINE_LINE_LIMIT.saturating_add(25)
        );
        assert_eq!(payload.commit_history_content, commit_history);
        assert!(
            payload.inline_line_count <= PREPARE_INLINE_LINE_LIMIT,
            "inline line count must remain bounded"
        );
    }

    #[test]
    fn build_prepare_inline_content_spills_both_payloads_when_needed() {
        let large_diff = "d\n".repeat(PREPARE_INLINE_LINE_LIMIT.saturating_add(1));
        let large_history = "h\n".repeat(PREPARE_INLINE_LINE_LIMIT.saturating_add(1));
        let payload = build_prepare_inline_content(
            &large_diff,
            std::path::Path::new("/tmp/review.diff"),
            &large_history,
            std::path::Path::new("/tmp/commit_history.txt"),
            PREPARE_INLINE_LINE_LIMIT,
        );
        assert_eq!(payload.output_mode, "artifact_reference");
        assert!(!payload.diff_inlined);
        assert!(!payload.commit_history_inlined);
        assert!(
            payload
                .commit_history_content
                .contains("prepare omitted inline commit_history payload")
        );
        assert!(
            payload.inline_line_count <= PREPARE_INLINE_LINE_LIMIT,
            "inline line count must stay bounded even when both payloads are large"
        );
        assert_eq!(
            payload.omitted_line_count,
            PREPARE_INLINE_LINE_LIMIT
                .saturating_mul(2)
                .saturating_add(2)
        );
    }

    #[test]
    fn count_text_lines_handles_empty_and_non_empty_content() {
        assert_eq!(count_text_lines(""), 0);
        assert_eq!(count_text_lines("single"), 1);
        assert_eq!(count_text_lines("a\nb\n"), 2);
    }

    #[test]
    fn test_find_yaml_block_skips_non_matching_schema() {
        // The gate-status block comes first; the push-metadata block is second.
        let body = "<!-- gate-status:start -->\n```yaml\nschema: apm2.gate_status.v2\nfoo: bar\n```\n<!-- gate-status:end -->\n```yaml\nschema: apm2.fac_push_metadata.v1\nwork_id: W-TCK-12345\nbranch: ticket/RFC-0019/TCK-12345\n```\n";
        let yaml = find_yaml_block_with_schema(body, "apm2.fac_push_metadata.v1")
            .expect("should find push metadata block");
        assert!(
            yaml.contains("work_id: W-TCK-12345"),
            "extracted block must contain work_id"
        );

        let parsed: serde_yaml::Value =
            serde_yaml::from_str(yaml).expect("extracted block must parse as YAML");
        assert_eq!(
            parsed.get("work_id").and_then(serde_yaml::Value::as_str),
            Some("W-TCK-12345"),
        );
    }

    #[test]
    fn test_find_yaml_block_returns_none_when_schema_absent() {
        let body =
            "some intro\n```yaml\nschema: apm2.other.v1\nwork_id: W-TCK-12345\n```\nsome footer";
        assert!(
            find_yaml_block_with_schema(body, "apm2.fac_push_metadata.v1").is_none(),
            "should not find block with wrong schema"
        );
    }

    #[test]
    fn test_find_yaml_block_finds_push_metadata() {
        let body = "some intro\n```yaml\nschema: apm2.fac_push_metadata.v1\nwork_id: W-TCK-12345\n```\nsome footer";
        let yaml =
            find_yaml_block_with_schema(body, "apm2.fac_push_metadata.v1").expect("yaml block");
        assert!(yaml.contains("work_id: W-TCK-12345"));
    }

    #[test]
    fn test_parse_rfc_id_from_branch_standard_format() {
        assert_eq!(
            parse_rfc_id_from_branch("ticket/RFC-0019/TCK-00685"),
            Some("RFC-0019".to_string())
        );
    }

    #[test]
    fn test_parse_rfc_id_from_branch_no_rfc_returns_none() {
        assert_eq!(parse_rfc_id_from_branch("feat/some-feature"), None);
    }
}
