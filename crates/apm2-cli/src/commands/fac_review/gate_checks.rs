//! Native FAC evidence gate checks (Rust replacements for legacy shell gates).

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fmt::Write as _;
use std::fs;
use std::io::Read;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use regex::Regex;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::commands::fac_secure_io;

pub const TEST_SAFETY_ALLOWLIST_REL_PATH: &str = "documents/reviews/test-safety-allowlist.txt";
pub const REVIEW_ARTIFACTS_REL_PATH: &str = "documents/reviews";
pub const WORKSPACE_INTEGRITY_SNAPSHOT_REL_PATH: &str =
    "target/ci/workspace_integrity.snapshot.tsv";

const MAX_TEST_SAFETY_SOURCE_FILE_SIZE: usize = 10 * 1024 * 1024;
const MAX_TEST_SAFETY_TARGET_FILES: usize = 20_000;
const MAX_TEST_SAFETY_TOTAL_SOURCE_BYTES: usize = 128 * 1024 * 1024;
const MAX_TEST_SAFETY_ALLOWLIST_FILE_SIZE: usize = 512 * 1024;
const MAX_REVIEW_ARTIFACT_FILE_SIZE: usize = 10 * 1024 * 1024;
const MAX_PROMPT_FILE_SIZE: usize = 4 * 1024 * 1024;
const MAX_WORKSPACE_SNAPSHOT_FILE_SIZE: usize = 10 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct CheckExecution {
    pub passed: bool,
    pub output: String,
}

#[derive(Debug)]
struct RuleSpec {
    id: &'static str,
    description: &'static str,
    pattern: &'static str,
    multiline: bool,
}

#[derive(Debug)]
struct Violation {
    rule_id: String,
    file: String,
    line: usize,
    description: String,
    text: String,
}

#[derive(Debug)]
enum AllowlistSelector {
    Exact(String),
    Regex(Regex),
}

#[derive(Debug)]
struct AllowlistEntry {
    rule_id: Option<String>,
    selector: AllowlistSelector,
}

const TEST_SAFETY_RULES: &[RuleSpec] = &[
    RuleSpec {
        id: "TSG001",
        description: "recursive delete targeting root/home",
        pattern: r"rm[[:space:]]+-[[:alnum:]-]*r[[:alnum:]-]*f[[:space:]]+(/|~|\$[{]?HOME[}]?)",
        multiline: false,
    },
    RuleSpec {
        id: "TSG002",
        description: "recursive delete targeting current/parent workspace",
        pattern: r"rm[[:space:]]+-[[:alnum:]-]*r[[:alnum:]-]*f[[:space:]]+(\$[{]?PWD[}]?|\.\.)",
        multiline: false,
    },
    RuleSpec {
        id: "TSG003",
        description: "absolute-path recursive delete via std::fs::remove_dir_all",
        pattern: r#"std::fs::remove_dir_all[[:space:]]*\([[:space:]]*("(/|~)|std::env::var[[:space:]]*\([[:space:]]*"HOME")"#,
        multiline: false,
    },
    RuleSpec {
        id: "TSG004",
        description: "absolute-path file delete via std::fs::remove_file",
        pattern: r#"std::fs::remove_file[[:space:]]*\([[:space:]]*("(/|~)|std::env::var[[:space:]]*\([[:space:]]*"HOME")"#,
        multiline: false,
    },
    RuleSpec {
        id: "TSG005",
        description: "unbounded shell execution via Command::new(<shell>).arg(\"-c\")",
        pattern: r#"Command::new[[:space:]]*\([[:space:]]*"(sh|bash|zsh)"[[:space:]]*\)[[:space:]]*[.][[:space:]]*arg[[:space:]]*\([[:space:]]*"-c""#,
        multiline: false,
    },
    RuleSpec {
        id: "TSG006",
        description: "shelling out to recursive rm command construction",
        pattern: r#"Command::new[[:space:]]*\([[:space:]]*"rm"[[:space:]]*\).*(-rf|-fr|-r[[:space:]]+-f|-f[[:space:]]+-r)"#,
        multiline: false,
    },
    RuleSpec {
        id: "TSG007",
        description: "destructive git clean of entire working tree",
        pattern: r"git[[:space:]]+clean[[:space:]]+-fdx",
        multiline: false,
    },
    RuleSpec {
        id: "TSG008",
        description: "recursive delete targeting quoted root path",
        pattern: r#"rm[[:space:]]+-[[:alnum:]-]*r[[:alnum:]-]*f[[:space:]]+(['"])[[:space:]]*/[[:space:]]*(['"])"#,
        multiline: false,
    },
    RuleSpec {
        id: "TSG009",
        description: "recursive delete targeting quoted home path",
        pattern: r#"rm[[:space:]]+-[[:alnum:]-]*r[[:alnum:]-]*f[[:space:]]+(['"])[[:space:]]*~[[:space:]]*(['"])"#,
        multiline: false,
    },
    RuleSpec {
        id: "TSG010",
        description: "shell execution via environment variable resolution",
        pattern: r#"Command::new\s*\(\s*(std::env::var|env::var)\s*\(\s*"(SHELL|COMSPEC)""#,
        multiline: false,
    },
    RuleSpec {
        id: "TSG011",
        description: "direct exec-family syscall in test code",
        pattern: r"(libc::(execv|execve|execvp)|nix::unistd::(execv|execve|execvp))",
        multiline: false,
    },
    RuleSpec {
        id: "TSG005M",
        description: "multiline unbounded shell execution via Command::new(<shell>).arg(\"-c\")",
        pattern: r#"Command::new\s*\(\s*"(sh|bash|zsh)"\s*\)\s*\n\s*\.\s*arg\s*\(\s*"-c""#,
        multiline: true,
    },
    RuleSpec {
        id: "TSG006M",
        description: "multiline shelling out to recursive rm command construction",
        pattern: r#"Command::new\s*\(\s*"rm"\s*\)\s*\n\s*\.arg\s*\(\s*"(-rf|-fr|-r)"\s*\)"#,
        multiline: true,
    },
];

fn walk_regular_files(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut stack = vec![root.to_path_buf()];
    let mut files = Vec::new();

    while let Some(dir) = stack.pop() {
        let entries = fs::read_dir(&dir)
            .map_err(|err| format!("failed to read directory {}: {err}", dir.display()))?;
        for entry in entries {
            let entry = entry.map_err(|err| {
                format!(
                    "failed to read directory entry under {}: {err}",
                    dir.display()
                )
            })?;
            let path = entry.path();
            let file_type = entry
                .file_type()
                .map_err(|err| format!("failed to inspect entry type {}: {err}", path.display()))?;
            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() {
                stack.push(path);
                continue;
            }
            if file_type.is_file() {
                files.push(path);
            }
        }
    }

    Ok(files)
}

fn is_scannable_source_ext(path: &Path) -> bool {
    matches!(
        path.extension().and_then(OsStr::to_str),
        Some("rs" | "sh" | "bash" | "zsh" | "py")
    )
}

fn basename_matches_test_pattern(path: &Path) -> bool {
    let stem = path.file_stem().and_then(OsStr::to_str).unwrap_or_default();
    stem.starts_with("test_") || stem.ends_with("_test")
}

fn path_contains_test_segment(rel: &str) -> bool {
    rel.split('/').any(|segment| {
        matches!(
            segment,
            "test" | "tests" | "testdata" | "fixtures" | "fixture"
        )
    })
}

fn file_contains_cfg_test(path: &Path) -> Result<bool, String> {
    let bytes = fac_secure_io::read_bounded(path, MAX_TEST_SAFETY_SOURCE_FILE_SIZE)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    let text = String::from_utf8_lossy(&bytes);
    Ok(text.contains("#[cfg(test)]"))
}

fn should_scan_default_target(rel: &str, abs: &Path) -> Result<bool, String> {
    if !is_scannable_source_ext(abs) {
        return Ok(false);
    }

    if path_contains_test_segment(rel) || basename_matches_test_pattern(abs) {
        return Ok(true);
    }

    if abs
        .extension()
        .and_then(OsStr::to_str)
        .is_some_and(|ext| ext.eq_ignore_ascii_case("rs"))
        && (rel.starts_with("src/") || rel.contains("/src/"))
        && file_contains_cfg_test(abs)?
    {
        return Ok(true);
    }

    Ok(false)
}

fn collect_test_safety_targets(workspace_root: &Path) -> Result<BTreeSet<String>, String> {
    let mut targets = BTreeSet::new();

    let files = tracked_files(workspace_root)
        .map_err(|err| format!("test safety target discovery failed (fail-closed): {err}"))?;
    for rel in files {
        let abs = workspace_root.join(&rel);
        if !abs.is_file() {
            continue;
        }
        if should_scan_default_target(&rel, &abs)? {
            targets.insert(rel);
            if targets.len() > MAX_TEST_SAFETY_TARGET_FILES {
                return Err(format!(
                    "test safety target count exceeded cap: {} > {}",
                    targets.len(),
                    MAX_TEST_SAFETY_TARGET_FILES
                ));
            }
        }
    }

    Ok(targets)
}

fn parse_allowlist(path: &Path) -> Result<Vec<AllowlistEntry>, String> {
    let bytes =
        fac_secure_io::read_bounded(path, MAX_TEST_SAFETY_ALLOWLIST_FILE_SIZE).map_err(|err| {
            format!(
                "allowlist file not found (fail-closed): {} ({err})",
                path.display()
            )
        })?;
    let text = String::from_utf8_lossy(&bytes);

    let mut entries = Vec::new();
    for raw_line in text.lines() {
        let line = raw_line.trim_end();
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let (rule_raw, selector_raw) = if let Some((left, right)) = trimmed.split_once('|') {
            (left.trim(), right.trim())
        } else {
            ("*", trimmed)
        };

        let rule_id = if rule_raw == "*" {
            None
        } else {
            Some(rule_raw.to_string())
        };

        let selector = if let Some(expr) = selector_raw.strip_prefix("re:") {
            let regex = Regex::new(expr)
                .map_err(|err| format!("invalid allowlist regex `{expr}`: {err}"))?;
            AllowlistSelector::Regex(regex)
        } else {
            AllowlistSelector::Exact(selector_raw.to_string())
        };

        entries.push(AllowlistEntry { rule_id, selector });
    }

    Ok(entries)
}

fn is_allowlisted(
    entries: &[AllowlistEntry],
    rule_id: &str,
    file: &str,
    line: usize,
    text: &str,
) -> bool {
    let key = format!("{file}:{line}");
    let payload = format!("{rule_id}|{key}|{text}");

    entries.iter().any(|entry| {
        if let Some(entry_rule) = &entry.rule_id {
            if entry_rule != rule_id {
                return false;
            }
        }

        match &entry.selector {
            AllowlistSelector::Exact(selector) => selector == file || selector == &key,
            AllowlistSelector::Regex(regex) => regex.is_match(&payload),
        }
    })
}

fn line_number_for_offset(content: &str, byte_offset: usize) -> usize {
    let mut line = 1_usize;
    for (idx, b) in content.bytes().enumerate() {
        if idx >= byte_offset {
            break;
        }
        if b == b'\n' {
            line += 1;
        }
    }
    line
}

fn line_text_at(content: &str, line_number: usize) -> String {
    content
        .lines()
        .nth(line_number.saturating_sub(1))
        .unwrap_or_default()
        .to_string()
}

fn is_shell_literal_rule(rule_id: &str) -> bool {
    matches!(
        rule_id,
        "TSG001" | "TSG002" | "TSG007" | "TSG008" | "TSG009"
    )
}

fn has_rs_extension(rel: &str) -> bool {
    Path::new(rel)
        .extension()
        .and_then(std::ffi::OsStr::to_str)
        .is_some_and(|ext| ext.eq_ignore_ascii_case("rs"))
}

fn rule_applies_to_target(rule: &RuleSpec, rel: &str) -> bool {
    let is_rust = has_rs_extension(rel);
    if rule.multiline {
        return is_rust;
    }
    if rule.id == "TSG011" {
        return is_rust;
    }
    if is_shell_literal_rule(rule.id) {
        return !is_rust;
    }
    true
}

fn scan_view_for_rust_target<'a>(rel: &str, content: &'a str) -> (&'a str, usize) {
    let under_src = rel.starts_with("src/") || rel.contains("/src/");
    if !has_rs_extension(rel) || !under_src {
        return (content, 0);
    }
    let Some(idx) = content.find("#[cfg(test)]") else {
        return (content, 0);
    };
    let prefix = &content[..idx];
    let line_base = prefix.bytes().filter(|b| *b == b'\n').count();
    (&content[idx..], line_base)
}

fn is_rust_commentish_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("//")
        || trimmed.starts_with("/*")
        || trimmed.starts_with('*')
        || trimmed.starts_with("*/")
}

pub fn run_test_safety_guard(workspace_root: &Path) -> Result<CheckExecution, String> {
    let allowlist_path = workspace_root.join(TEST_SAFETY_ALLOWLIST_REL_PATH);
    let allowlist = parse_allowlist(&allowlist_path)?;
    let targets = collect_test_safety_targets(workspace_root)?;

    let mut output = String::new();
    writeln!(output, "INFO: === Test Safety Guard (TCK-00410) ===").ok();
    writeln!(output, "INFO: Scanning {} file(s)", targets.len()).ok();
    writeln!(
        output,
        "INFO: Using allowlist: {}",
        allowlist_path.display()
    )
    .ok();
    writeln!(output).ok();

    if targets.is_empty() {
        writeln!(output, "WARN: No files matched test safety scan targets.").ok();
        return Ok(CheckExecution {
            passed: true,
            output,
        });
    }

    let mut violations = Vec::new();
    let mut target_contents = BTreeMap::new();
    let mut total_source_bytes = 0usize;
    for rel in &targets {
        let abs = workspace_root.join(rel);
        let bytes = fac_secure_io::read_bounded(&abs, MAX_TEST_SAFETY_SOURCE_FILE_SIZE)
            .map_err(|err| format!("failed to read test safety target {}: {err}", abs.display()))?;
        total_source_bytes = total_source_bytes
            .checked_add(bytes.len())
            .ok_or_else(|| "test safety source byte accounting overflow".to_string())?;
        if total_source_bytes > MAX_TEST_SAFETY_TOTAL_SOURCE_BYTES {
            return Err(format!(
                "test safety source bytes exceeded cap: {total_source_bytes} > {MAX_TEST_SAFETY_TOTAL_SOURCE_BYTES}",
            ));
        }
        target_contents.insert(rel.clone(), String::from_utf8_lossy(&bytes).into_owned());
    }

    for rule in TEST_SAFETY_RULES {
        let regex = Regex::new(rule.pattern)
            .map_err(|err| format!("invalid built-in test safety regex {}: {err}", rule.id))?;

        for rel in &targets {
            if !rule_applies_to_target(rule, rel) {
                continue;
            }
            let content = target_contents
                .get(rel)
                .ok_or_else(|| format!("missing cached test-safety target {rel}"))?;
            let (scan_content, line_base) = scan_view_for_rust_target(rel, content);
            let is_rust = has_rs_extension(rel);

            if rule.multiline {
                for m in regex.find_iter(scan_content) {
                    let line_number = line_number_for_offset(scan_content, m.start()) + line_base;
                    let line_text = line_text_at(content, line_number);
                    if is_allowlisted(&allowlist, rule.id, rel, line_number, &line_text) {
                        continue;
                    }
                    violations.push(Violation {
                        rule_id: rule.id.to_string(),
                        file: rel.clone(),
                        line: line_number,
                        description: rule.description.to_string(),
                        text: line_text,
                    });
                }
                continue;
            }

            for (idx, line) in scan_content.lines().enumerate() {
                if is_rust && is_rust_commentish_line(line) {
                    continue;
                }
                if !regex.is_match(line) {
                    continue;
                }
                let line_number = idx + 1 + line_base;
                let full_line = line_text_at(content, line_number);
                if is_allowlisted(&allowlist, rule.id, rel, line_number, &full_line) {
                    continue;
                }
                violations.push(Violation {
                    rule_id: rule.id.to_string(),
                    file: rel.clone(),
                    line: line_number,
                    description: rule.description.to_string(),
                    text: full_line,
                });
            }
        }
    }

    violations.sort_by(|left, right| {
        left.file
            .cmp(&right.file)
            .then(left.line.cmp(&right.line))
            .then(left.rule_id.cmp(&right.rule_id))
    });

    for violation in &violations {
        writeln!(
            output,
            "ERROR: [{}] {}:{} {}",
            violation.rule_id, violation.file, violation.line, violation.description
        )
        .ok();
        writeln!(output, "ERROR:   {}", violation.text).ok();
    }

    writeln!(output).ok();
    if violations.is_empty() {
        writeln!(output, "INFO: No unsafe test patterns detected.").ok();
        Ok(CheckExecution {
            passed: true,
            output,
        })
    } else {
        writeln!(
            output,
            "ERROR: Detected {} unsafe test pattern(s).",
            violations.len()
        )
        .ok();
        writeln!(
            output,
            "ERROR: Add tightly-scoped entries to documents/reviews/test-safety-allowlist.txt only when justified."
        )
        .ok();
        Ok(CheckExecution {
            passed: false,
            output,
        })
    }
}

fn strip_comment_lines(content: &str) -> String {
    let mut kept = String::new();
    for line in content.lines() {
        if line.trim_start().starts_with('#') {
            continue;
        }
        kept.push_str(line);
        kept.push('\n');
    }
    kept
}

fn flatten_stream(content: &str) -> String {
    content
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

fn contains_tokens_in_order(haystack: &str, tokens: &[&str]) -> bool {
    let mut cursor = 0_usize;
    for token in tokens {
        let Some(pos) = haystack[cursor..].find(token) else {
            return false;
        };
        cursor += pos + token.len();
    }
    true
}

fn detect_forbidden_api_usage_stream(stream: &str) -> bool {
    if contains_tokens_in_order(stream, &["gh", "pr", "review", "--approve"]) {
        return true;
    }
    if stream.contains("gh api") {
        return true;
    }
    if stream.contains("curl") && (stream.contains("github") || stream.contains("api.github")) {
        return true;
    }
    false
}

fn detect_direct_status_write_line(line: &str) -> bool {
    let stripped = line.trim_start();
    if stripped.starts_with('#') {
        return false;
    }

    let lc = line.to_lowercase();
    if lc.contains("gh") && lc.contains("pr") && lc.contains("review") && lc.contains("--approve") {
        return true;
    }

    if Regex::new(r"gh\s+api")
        .expect("static gh api regex")
        .is_match(&lc)
    {
        return true;
    }

    if lc.contains("curl") && (lc.contains("github") || lc.contains("api.github")) {
        return true;
    }

    if (lc.contains("statuses/") || lc.contains("check-runs"))
        && (lc.contains("-f ")
            || lc.contains("--field ")
            || lc.contains("--method")
            || lc.contains("-x post")
            || lc.contains("post"))
    {
        return true;
    }

    false
}

fn detect_cross_category_exec(line: &str, file_basename: &str) -> bool {
    if line.trim_start().starts_with('#') {
        return false;
    }
    file_basename.contains("CODE_QUALITY") && line.contains("security-review-exec")
}

fn join_continuations(content: &str) -> Vec<(usize, String)> {
    let mut result = Vec::new();
    let mut accum = String::new();
    let mut start_line = 1_usize;

    for (idx, raw) in content.lines().enumerate() {
        let line_number = idx + 1;
        if accum.is_empty() {
            start_line = line_number;
        }

        if let Some(prefix) = raw.strip_suffix('\\') {
            accum.push_str(prefix);
            accum.push(' ');
            continue;
        }

        accum.push_str(raw);
        result.push((start_line, accum.clone()));
        accum.clear();
    }

    if !accum.is_empty() {
        result.push((start_line, accum));
    }

    result
}

fn validate_prompt_identity_constraints(prompt_path: &Path) -> Result<Vec<String>, String> {
    let bytes = fac_secure_io::read_bounded(prompt_path, MAX_PROMPT_FILE_SIZE)
        .map_err(|err| format!("failed to read {}: {err}", prompt_path.display()))?;
    let value: Value =
        serde_json::from_slice(&bytes).map_err(|err| format!("invalid JSON: {err}"))?;

    let mut errors = Vec::new();
    let expected_prefix = "apm2";

    let payload = value.get("payload").and_then(Value::as_object);
    if payload.is_none() {
        errors.push("missing payload object".to_string());
    }
    let commands = payload
        .and_then(|p| p.get("commands"))
        .and_then(Value::as_object);
    if commands.is_none() {
        errors.push("missing payload.commands object".to_string());
    }
    let constraints = payload
        .and_then(|p| p.get("constraints"))
        .and_then(Value::as_object);
    if constraints.is_none() {
        errors.push("missing payload.constraints object".to_string());
    }

    let binary_prefix = commands
        .and_then(|commands| commands.get("binary_prefix"))
        .and_then(Value::as_str);
    if binary_prefix != Some(expected_prefix) {
        errors.push("commands.binary_prefix must equal 'apm2'".to_string());
    }

    let required = [
        ("prepare", "apm2 fac review prepare"),
        ("finding", "apm2 fac review finding"),
        ("verdict", "apm2 fac review verdict set"),
    ];
    for (name, prefix) in required {
        let command = commands
            .and_then(|commands| commands.get(name))
            .and_then(Value::as_str);
        match command {
            Some(command) => {
                if !command.starts_with(prefix) {
                    errors.push(format!("commands.{name} must start with '{prefix}'"));
                }
            },
            None => errors.push(format!("commands.{name} must be a string")),
        }
    }

    let forbidden_ops_text = constraints
        .and_then(|constraints| constraints.get("forbidden_operations"))
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_lowercase)
                .collect::<Vec<_>>()
                .join("\n")
        });
    if forbidden_ops_text.is_none() {
        errors.push("constraints.forbidden_operations must be an array".to_string());
    }
    let forbidden_ops_text = forbidden_ops_text.unwrap_or_default();

    if !forbidden_ops_text.contains("$pr_number") || !forbidden_ops_text.contains("$head_sha") {
        errors.push(
            "constraints.forbidden_operations must require $PR_NUMBER/$HEAD_SHA command binding"
                .to_string(),
        );
    }
    if forbidden_ops_text.contains("never pass --sha")
        || forbidden_ops_text.contains("auto-derives the sha")
    {
        errors.push(
            "constraints.forbidden_operations must not require implicit SHA auto-derivation"
                .to_string(),
        );
    }

    let invariants_text = constraints
        .and_then(|constraints| constraints.get("invariants"))
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(|entry| {
                    entry.as_str().map(str::to_string).or_else(|| {
                        entry
                            .as_object()
                            .and_then(|obj| obj.get("description"))
                            .and_then(Value::as_str)
                            .map(str::to_string)
                    })
                })
                .map(|line| line.to_lowercase())
                .collect::<Vec<_>>()
                .join("\n")
        });
    if invariants_text.is_none() {
        errors.push("constraints.invariants must be an array".to_string());
    }
    let invariants_text = invariants_text.unwrap_or_default();
    if !(invariants_text.contains("sha is managed by the cli")
        || (invariants_text.contains("$pr_number") && invariants_text.contains("$head_sha")))
    {
        errors.push(
            "constraints.invariants must include SHA-binding guidance (CLI-managed SHA or $PR_NUMBER/$HEAD_SHA binding)"
                .to_string(),
        );
    }

    Ok(errors)
}

fn should_scan_review_artifact(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(OsStr::to_str) else {
        return false;
    };

    if let Some(ext) = path.extension().and_then(OsStr::to_str) {
        if matches!(ext, "md" | "sh" | "yaml" | "yml") {
            return true;
        }
        if ext == "json" && name.contains("PROMPT") {
            return true;
        }
    }
    false
}

pub fn run_review_artifact_lint(workspace_root: &Path) -> Result<CheckExecution, String> {
    let review_dir = workspace_root.join(REVIEW_ARTIFACTS_REL_PATH);
    if !review_dir.is_dir() {
        return Err(format!(
            "Review directory not found: {} (are you inside the repository?)",
            review_dir.display()
        ));
    }

    let mut review_files: Vec<PathBuf> = walk_regular_files(&review_dir)?
        .into_iter()
        .filter(|path| should_scan_review_artifact(path))
        .collect();
    review_files.sort();

    let mut violations = Vec::new();
    let mut output = String::new();
    writeln!(
        output,
        "INFO: === Review Artifact Integrity Lint (TCK-00409) ==="
    )
    .ok();
    writeln!(output).ok();
    writeln!(
        output,
        "INFO: Primary gate: scanning for ai-review/security literal in non-exempt files..."
    )
    .ok();

    for file in &review_files {
        let file_basename = file
            .file_name()
            .and_then(OsStr::to_str)
            .unwrap_or_default()
            .to_string();
        let content = fac_secure_io::read_bounded_text(file, MAX_REVIEW_ARTIFACT_FILE_SIZE)
            .map_err(|err| format!("failed to read {}: {err}", file.display()))?;
        let stripped = strip_comment_lines(&content);
        let stream = flatten_stream(&stripped);

        if file_basename != "SECURITY_REVIEW_PROMPT.cac.json"
            && stream.contains("ai-review/security")
        {
            violations.push(format!(
                "Forbidden ai-review/security literal in non-exempt review artifact: {}",
                file.display()
            ));
        }

        let exempt_from_split_token = file_basename == "CODE_QUALITY_PROMPT.cac.json";
        if !exempt_from_split_token && stream.contains("ai-review") && stream.contains("security") {
            let looks_code_like = stream.contains("\"ai-review")
                || stream.contains("'ai-review")
                || stream.contains("=ai-review")
                || stream.contains("=\"ai-review")
                || stream.contains("='ai-review");
            if looks_code_like {
                violations.push(format!(
                    "Suspicious ai-review + security component tokens in non-exempt review artifact: {}",
                    file.display()
                ));
            }
        }

        if detect_forbidden_api_usage_stream(&stream) {
            violations.push(format!(
                "Forbidden direct GitHub API usage in review artifact: {}",
                file.display()
            ));
        }

        for (line_number, logical_line) in join_continuations(&content) {
            if detect_direct_status_write_line(&logical_line) {
                violations.push(format!(
                    "Forbidden direct GitHub API call in review artifact: {}:{}: {}",
                    file.display(),
                    line_number,
                    logical_line
                ));
            }
            if detect_cross_category_exec(&logical_line, &file_basename) {
                violations.push(format!(
                    "Cross-category executor misuse: {}:{}: {}",
                    file.display(),
                    line_number,
                    logical_line
                ));
            }
        }
    }

    writeln!(
        output,
        "INFO: Checking review prompt CLI identity-binding constraints..."
    )
    .ok();
    for prompt in [
        review_dir.join("CODE_QUALITY_PROMPT.cac.json"),
        review_dir.join("SECURITY_REVIEW_PROMPT.cac.json"),
    ] {
        if !prompt.exists() {
            violations.push(format!("Review prompt not found: {}", prompt.display()));
            continue;
        }
        match validate_prompt_identity_constraints(&prompt) {
            Ok(errors) if errors.is_empty() => {
                writeln!(
                    output,
                    "INFO:   {}: CLI identity-binding constraints present",
                    prompt.display()
                )
                .ok();
            },
            Ok(errors) => {
                for error in errors {
                    violations.push(format!("Review prompt {}: {error}", prompt.display()));
                }
            },
            Err(err) => {
                violations.push(format!("Review prompt {}: {err}", prompt.display()));
            },
        }
    }

    if violations.is_empty() {
        writeln!(output).ok();
        writeln!(
            output,
            "INFO: === PASSED: All review artifacts are compliant ==="
        )
        .ok();
        Ok(CheckExecution {
            passed: true,
            output,
        })
    } else {
        for violation in &violations {
            writeln!(output, "ERROR: {violation}").ok();
        }
        writeln!(output).ok();
        writeln!(
            output,
            "ERROR: === FAILED: Review artifact integrity violations found ==="
        )
        .ok();
        Ok(CheckExecution {
            passed: false,
            output,
        })
    }
}

fn hash_file_contents_into(path: &Path, hasher: &mut Sha256) -> Result<(), String> {
    let mut file = fs::File::open(path)
        .map_err(|err| format!("failed to open {} for hashing: {err}", path.display()))?;
    let mut buf = [0_u8; 8192];
    loop {
        let read = file
            .read(&mut buf)
            .map_err(|err| format!("failed to read {} for hashing: {err}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    Ok(())
}

fn hash_file(path: &Path) -> Result<String, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|err| format!("failed to inspect {}: {err}", path.display()))?;
    if metadata.file_type().is_symlink() {
        let target = fs::read_link(path)
            .map_err(|err| format!("failed to read symlink {}: {err}", path.display()))?;
        let target_path = if target.is_absolute() {
            target.clone()
        } else {
            path.parent().unwrap_or_else(|| Path::new("")).join(&target)
        };

        let mut hasher = Sha256::new();
        hasher.update(b"apm2_workspace_symlink_v1\0");
        #[cfg(unix)]
        hasher.update(target.as_os_str().as_bytes());
        #[cfg(not(unix))]
        hasher.update(target.to_string_lossy().as_bytes());
        hasher.update(b"\0");
        hash_file_contents_into(&target_path, &mut hasher)?;
        return Ok(format!("{:x}", hasher.finalize()));
    }

    let mut hasher = Sha256::new();
    hash_file_contents_into(path, &mut hasher)?;
    Ok(format!("{:x}", hasher.finalize()))
}

fn tracked_files(workspace_root: &Path) -> Result<Vec<String>, String> {
    let output = Command::new("git")
        .args(["ls-files", "-z"])
        .current_dir(workspace_root)
        .output()
        .map_err(|err| format!("failed to run git ls-files: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "git ls-files failed in {}: {}",
            workspace_root.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    let mut files = Vec::new();
    for raw in output.stdout.split(|byte| *byte == b'\0') {
        if raw.is_empty() {
            continue;
        }
        let tracked = std::str::from_utf8(raw).map_err(|_| {
            let mut hex = String::with_capacity(raw.len().saturating_mul(2));
            for byte in raw {
                let _ = write!(&mut hex, "{byte:02x}");
            }
            format!(
                "git ls-files returned non-UTF8 tracked path bytes (hex={hex}); \
                 workspace integrity scan fails closed"
            )
        })?;
        files.push(tracked.to_string());
    }
    files.sort();
    Ok(files)
}

fn build_workspace_manifest(
    workspace_root: &Path,
) -> Result<BTreeMap<String, (String, String)>, String> {
    let mut manifest = BTreeMap::new();
    for tracked in tracked_files(workspace_root)? {
        let abs = workspace_root.join(&tracked);
        if !abs.exists() {
            manifest.insert(tracked, ("MISSING".to_string(), "000000".to_string()));
            continue;
        }

        let hash = hash_file(&abs)?;
        #[cfg(unix)]
        let mode = format!(
            "{:x}",
            fs::metadata(&abs)
                .map_err(|err| { format!("failed to read metadata for {}: {err}", abs.display()) })?
                .mode()
        );
        #[cfg(not(unix))]
        let mode = "000000".to_string();

        manifest.insert(tracked, (hash, mode));
    }
    Ok(manifest)
}

fn write_manifest(
    path: &Path,
    manifest: &BTreeMap<String, (String, String)>,
) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "failed to create snapshot directory {}: {err}",
                parent.display()
            )
        })?;
    }

    let mut body = String::new();
    for (tracked, (hash, mode)) in manifest {
        writeln!(body, "{tracked}\t{hash}\t{mode}").ok();
    }

    fs::write(path, body.as_bytes())
        .map_err(|err| format!("failed to write snapshot {}: {err}", path.display()))
}

fn read_manifest(path: &Path) -> Result<BTreeMap<String, (String, String)>, String> {
    let bytes = fac_secure_io::read_bounded(path, MAX_WORKSPACE_SNAPSHOT_FILE_SIZE)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    let content = String::from_utf8_lossy(&bytes);
    let mut manifest = BTreeMap::new();

    for (line_no, raw_line) in content.lines().enumerate() {
        if raw_line.trim().is_empty() {
            continue;
        }
        let mut parts = raw_line.splitn(3, '\t');
        let Some(path_part) = parts.next() else {
            continue;
        };
        let Some(hash_part) = parts.next() else {
            return Err(format!(
                "invalid snapshot format at {}:{}",
                path.display(),
                line_no + 1
            ));
        };
        let Some(mode_part) = parts.next() else {
            return Err(format!(
                "invalid snapshot format at {}:{}",
                path.display(),
                line_no + 1
            ));
        };

        manifest.insert(
            path_part.to_string(),
            (hash_part.to_string(), mode_part.to_string()),
        );
    }

    Ok(manifest)
}

fn parse_allowlisted_paths(path: &Path) -> Result<BTreeSet<String>, String> {
    let bytes = fac_secure_io::read_bounded(path, MAX_TEST_SAFETY_ALLOWLIST_FILE_SIZE)
        .map_err(|err| format!("allowlist file not found: {} ({err})", path.display()))?;
    let content = String::from_utf8_lossy(&bytes);
    let mut allowed = BTreeSet::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        allowed.insert(trimmed.to_string());
    }
    Ok(allowed)
}

pub fn snapshot_workspace_integrity(
    workspace_root: &Path,
    snapshot_file: &Path,
) -> Result<(), String> {
    let manifest = build_workspace_manifest(workspace_root)?;
    write_manifest(snapshot_file, &manifest)
}

pub fn verify_workspace_integrity(
    workspace_root: &Path,
    snapshot_file: &Path,
    allowlist_path: Option<&Path>,
) -> Result<CheckExecution, String> {
    if !snapshot_file.is_file() {
        return Err(format!(
            "Snapshot file not found: {}",
            snapshot_file.display()
        ));
    }

    let baseline = read_manifest(snapshot_file)?;
    let current = build_workspace_manifest(workspace_root)?;
    let allowed = if let Some(path) = allowlist_path {
        parse_allowlisted_paths(path)?
    } else {
        BTreeSet::new()
    };

    let mut changed = BTreeSet::new();
    for path in baseline.keys() {
        let Some(current_entry) = current.get(path) else {
            changed.insert(path.clone());
            continue;
        };
        if baseline.get(path) != Some(current_entry) {
            changed.insert(path.clone());
        }
    }
    for path in current.keys() {
        if !baseline.contains_key(path) {
            changed.insert(path.clone());
        }
    }

    let mut output = String::new();
    if changed.is_empty() {
        writeln!(
            output,
            "INFO: Workspace integrity verified: no tracked mutations detected."
        )
        .ok();
        return Ok(CheckExecution {
            passed: true,
            output,
        });
    }

    let mut violations = Vec::new();
    for path in changed {
        if allowed.contains(&path) {
            continue;
        }
        violations.push(path);
    }

    if violations.is_empty() {
        writeln!(
            output,
            "WARN: Only allowlisted tracked mutations were detected."
        )
        .ok();
        Ok(CheckExecution {
            passed: true,
            output,
        })
    } else {
        writeln!(
            output,
            "ERROR: Tracked workspace mutations detected after test execution:"
        )
        .ok();
        for path in &violations {
            writeln!(output, "ERROR:   {path}").ok();
        }
        writeln!(
            output,
            "ERROR: Workspace integrity guard failed (fail-closed)."
        )
        .ok();
        Ok(CheckExecution {
            passed: false,
            output,
        })
    }
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::os::unix::ffi::OsStringExt;
    #[cfg(unix)]
    use std::os::unix::fs::symlink;

    use super::*;

    fn run_git(repo: &Path, args: &[&str]) {
        let output = Command::new("git")
            .args(args)
            .current_dir(repo)
            .output()
            .expect("run git command");
        assert!(
            output.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn init_git_repo(repo: &Path) {
        run_git(repo, &["init"]);
        run_git(repo, &["config", "user.email", "test@example.com"]);
        run_git(repo, &["config", "user.name", "Test User"]);
    }

    fn write_valid_review_artifacts(repo: &Path) {
        let review_dir = repo.join("documents/reviews");
        fs::create_dir_all(&review_dir).expect("create review dir");

        let prompt = r#"{
  "payload": {
    "commands": {
      "binary_prefix": "apm2",
      "prepare": "apm2 fac review prepare --pr $PR_NUMBER --sha $HEAD_SHA",
      "finding": "apm2 fac review finding --pr $PR_NUMBER --sha $HEAD_SHA",
      "verdict": "apm2 fac review verdict set --pr $PR_NUMBER --sha $HEAD_SHA"
    },
    "constraints": {
      "forbidden_operations": [
        "Always pass --pr $PR_NUMBER --sha $HEAD_SHA when running prepare/finding/verdict."
      ],
      "invariants": [
        "Bind commands using $PR_NUMBER and $HEAD_SHA."
      ]
    }
  }
}
"#;
        fs::write(review_dir.join("CODE_QUALITY_PROMPT.cac.json"), prompt)
            .expect("write code quality prompt");
        fs::write(review_dir.join("SECURITY_REVIEW_PROMPT.cac.json"), prompt)
            .expect("write security prompt");
    }

    #[test]
    fn strip_comment_lines_removes_hash_prefixed_lines() {
        let input = "# one\n  # two\nkeep\n";
        let stripped = strip_comment_lines(input);
        assert!(stripped.contains("keep"));
        assert!(!stripped.contains("one"));
        assert!(!stripped.contains("two"));
    }

    #[test]
    fn flatten_stream_collapses_whitespace() {
        let input = "a   b\n c\t d";
        assert_eq!(flatten_stream(input), "a b c d");
    }

    #[test]
    fn workspace_manifest_round_trip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let repo = dir.path();
        fs::create_dir_all(repo.join("sub")).expect("create dirs");
        fs::write(repo.join("sub/file.txt"), b"hello").expect("write file");

        init_git_repo(repo);
        run_git(repo, &["add", "."]);

        let snapshot = repo.join("target/ci/workspace_integrity.snapshot.tsv");
        snapshot_workspace_integrity(repo, &snapshot).expect("snapshot");
        let loaded = read_manifest(&snapshot).expect("read snapshot");
        assert!(loaded.contains_key("sub/file.txt"));
    }

    #[cfg(unix)]
    #[test]
    fn tracked_files_fail_closed_on_non_utf8_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let repo = dir.path();
        init_git_repo(repo);

        let non_utf8 = std::ffi::OsString::from_vec(vec![0x66, 0x6f, 0x80, 0x2e, 0x72, 0x73]);
        fs::write(
            repo.join(std::path::PathBuf::from(non_utf8)),
            b"fn main() {}\n",
        )
        .expect("write non-utf8 path");
        run_git(repo, &["add", "."]);

        let err = tracked_files(repo).expect_err("non-utf8 tracked path must fail closed");
        assert!(err.contains("non-UTF8"), "unexpected error: {err}");
    }

    #[test]
    fn test_safety_guard_fails_closed_when_allowlist_missing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let repo = dir.path();
        fs::create_dir_all(repo.join("tests")).expect("create tests");
        fs::write(repo.join("tests/unsafe_test.sh"), b"rm -rf /\n").expect("write unsafe test");
        init_git_repo(repo);
        run_git(repo, &["add", "."]);

        let err = run_test_safety_guard(repo).expect_err("missing allowlist should fail closed");
        assert!(err.contains("allowlist file not found"));
    }

    #[test]
    fn test_safety_guard_fails_closed_when_git_tracking_unavailable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let repo = dir.path();
        fs::create_dir_all(repo.join("tests")).expect("create tests");
        fs::create_dir_all(repo.join("documents/reviews")).expect("create review-gate");
        fs::write(repo.join("tests/unsafe_test.sh"), b"rm -rf /\n").expect("write unsafe test");
        fs::write(
            repo.join("documents/reviews/test-safety-allowlist.txt"),
            b"# empty\n",
        )
        .expect("write allowlist");

        let err =
            run_test_safety_guard(repo).expect_err("non-git workspace must fail target discovery");
        assert!(err.contains("target discovery failed"));
    }

    #[test]
    fn test_safety_guard_honors_allowlist_entries() {
        let dir = tempfile::tempdir().expect("tempdir");
        let repo = dir.path();
        fs::create_dir_all(repo.join("tests")).expect("create tests");
        fs::create_dir_all(repo.join("documents/reviews")).expect("create review-gate");
        fs::write(repo.join("tests/unsafe_test.sh"), b"rm -rf /\n").expect("write unsafe test");
        fs::write(
            repo.join("documents/reviews/test-safety-allowlist.txt"),
            b"TSG001|tests/unsafe_test.sh:1\n",
        )
        .expect("write allowlist");
        init_git_repo(repo);
        run_git(repo, &["add", "."]);

        let check = run_test_safety_guard(repo).expect("run guard");
        assert!(check.passed, "unexpected output:\n{}", check.output);

        fs::write(
            repo.join("documents/reviews/test-safety-allowlist.txt"),
            b"# empty\n",
        )
        .expect("clear allowlist");
        let check = run_test_safety_guard(repo).expect("run guard");
        assert!(!check.passed, "expected violation");
        assert!(check.output.contains("[TSG001]"));
    }

    #[test]
    fn test_safety_guard_ignores_shell_literal_rules_in_rust_test_code() {
        let dir = tempfile::tempdir().expect("tempdir");
        let repo = dir.path();
        fs::create_dir_all(repo.join("src")).expect("create src");
        fs::create_dir_all(repo.join("documents/reviews")).expect("create review-gate");
        fs::write(
            repo.join("documents/reviews/test-safety-allowlist.txt"),
            b"# empty\n",
        )
        .expect("write allowlist");
        fs::write(
            repo.join("src/lib.rs"),
            br#"
#[cfg(test)]
mod tests {
    #[test]
    fn literal_fixture_is_data_not_execution() {
        let _fixture = "rm -rf /";
        assert_eq!(_fixture, "rm -rf /");
    }
}
"#,
        )
        .expect("write rust file");
        init_git_repo(repo);
        run_git(repo, &["add", "."]);

        let check = run_test_safety_guard(repo).expect("run guard");
        assert!(check.passed, "unexpected output:\n{}", check.output);
    }

    #[test]
    fn test_safety_guard_scans_only_rust_test_region_under_src() {
        let dir = tempfile::tempdir().expect("tempdir");
        let repo = dir.path();
        fs::create_dir_all(repo.join("src")).expect("create src");
        fs::create_dir_all(repo.join("documents/reviews")).expect("create review-gate");
        fs::write(
            repo.join("documents/reviews/test-safety-allowlist.txt"),
            b"# empty\n",
        )
        .expect("write allowlist");
        let fixture = [
            "pub fn production_exec_path(program_cstr: *const libc::c_char, argv_ptrs: *const *const libc::c_char) {\n",
            "    unsafe {\n",
            "        libc::exec",
            "ve(program_cstr, argv_ptrs, std::ptr::null());\n",
            "    }\n",
            "}\n\n",
            "#[cfg(test)]\n",
            "mod tests {\n",
            "    #[test]\n",
            "    fn smoke() {\n",
            "        assert!(true);\n",
            "    }\n",
            "}\n",
        ]
        .join("");
        fs::write(repo.join("src/lib.rs"), fixture).expect("write rust file");
        init_git_repo(repo);
        run_git(repo, &["add", "."]);

        let check = run_test_safety_guard(repo).expect("run guard");
        assert!(check.passed, "unexpected output:\n{}", check.output);
    }

    #[test]
    fn test_safety_guard_detects_top_level_src_lib_cfg_test_violation() {
        let dir = tempfile::tempdir().expect("tempdir");
        let repo = dir.path();
        fs::create_dir_all(repo.join("src")).expect("create src");
        fs::create_dir_all(repo.join("documents/reviews")).expect("create review-gate");
        fs::write(
            repo.join("documents/reviews/test-safety-allowlist.txt"),
            b"# empty\n",
        )
        .expect("write allowlist");
        fs::write(
            repo.join("src/lib.rs"),
            [
                "pub fn safe_prod_path() {}\n\n",
                "#[cfg(test)]\n",
                "mod tests {\n",
                "    #[test]\n",
                "    fn detects_exec_rule() {\n",
                "        unsafe { libc::exec",
                "vp(std::ptr::null(), std::ptr::null()); }\n",
                "    }\n",
                "}\n",
            ]
            .join("")
            .as_bytes(),
        )
        .expect("write rust file");
        init_git_repo(repo);
        run_git(repo, &["add", "."]);

        let check = run_test_safety_guard(repo).expect("run guard");
        assert!(!check.passed, "expected violation:\n{}", check.output);
        assert!(check.output.contains("[TSG011]"));
    }

    #[test]
    fn test_safety_guard_detects_top_level_src_main_cfg_test_violation() {
        let dir = tempfile::tempdir().expect("tempdir");
        let repo = dir.path();
        fs::create_dir_all(repo.join("src")).expect("create src");
        fs::create_dir_all(repo.join("documents/reviews")).expect("create review-gate");
        fs::write(
            repo.join("documents/reviews/test-safety-allowlist.txt"),
            b"# empty\n",
        )
        .expect("write allowlist");
        fs::write(
            repo.join("src/main.rs"),
            [
                "fn main() {}\n\n",
                "#[cfg(test)]\n",
                "mod tests {\n",
                "    #[test]\n",
                "    fn detects_exec_rule() {\n",
                "        unsafe { libc::exec",
                "vp(std::ptr::null(), std::ptr::null()); }\n",
                "    }\n",
                "}\n",
            ]
            .join("")
            .as_bytes(),
        )
        .expect("write rust file");
        init_git_repo(repo);
        run_git(repo, &["add", "."]);

        let check = run_test_safety_guard(repo).expect("run guard");
        assert!(!check.passed, "expected violation:\n{}", check.output);
        assert!(check.output.contains("[TSG011]"));
    }

    #[test]
    fn test_safety_guard_fails_closed_on_oversized_target() {
        let dir = tempfile::tempdir().expect("tempdir");
        let repo = dir.path();
        fs::create_dir_all(repo.join("tests")).expect("create tests");
        fs::create_dir_all(repo.join("documents/reviews")).expect("create review-gate");
        fs::write(
            repo.join("documents/reviews/test-safety-allowlist.txt"),
            b"# empty\n",
        )
        .expect("write allowlist");
        let oversized = vec![b'x'; MAX_TEST_SAFETY_SOURCE_FILE_SIZE + 1];
        fs::write(repo.join("tests/huge_test.sh"), oversized).expect("write oversized file");
        init_git_repo(repo);
        run_git(repo, &["add", "."]);

        let err = run_test_safety_guard(repo).expect_err("oversized source must fail closed");
        assert!(err.contains("too large"));
    }

    #[test]
    fn review_artifact_lint_passes_with_valid_artifacts() {
        let dir = tempfile::tempdir().expect("tempdir");
        let repo = dir.path();
        write_valid_review_artifacts(repo);

        let check = run_review_artifact_lint(repo).expect("run lint");
        assert!(check.passed, "unexpected output:\n{}", check.output);
    }

    #[test]
    fn review_artifact_lint_detects_forbidden_literals() {
        let dir = tempfile::tempdir().expect("tempdir");
        let repo = dir.path();
        write_valid_review_artifacts(repo);
        fs::write(
            repo.join("documents/reviews/review_notes.md"),
            b"This artifact includes ai-review/security token\n",
        )
        .expect("write review file");

        let check = run_review_artifact_lint(repo).expect("run lint");
        assert!(!check.passed, "expected lint failure");
        assert!(
            check
                .output
                .contains("Forbidden ai-review/security literal")
        );
    }

    #[test]
    fn workspace_integrity_detects_and_allowlists_mutations() {
        let dir = tempfile::tempdir().expect("tempdir");
        let repo = dir.path();
        init_git_repo(repo);
        fs::write(repo.join("tracked.txt"), b"v1\n").expect("write tracked file");
        run_git(repo, &["add", "tracked.txt"]);

        let snapshot = repo.join("target/ci/workspace_integrity.snapshot.tsv");
        snapshot_workspace_integrity(repo, &snapshot).expect("snapshot");

        fs::write(repo.join("tracked.txt"), b"v2\n").expect("mutate tracked file");
        let check =
            verify_workspace_integrity(repo, &snapshot, None).expect("verify without allowlist");
        assert!(!check.passed, "expected failure on mutation");
        assert!(check.output.contains("tracked.txt"));

        let allow = repo.join("target/ci/workspace_integrity.allowlist");
        fs::write(&allow, b"tracked.txt\n").expect("write allowlist");
        let check = verify_workspace_integrity(repo, &snapshot, Some(&allow))
            .expect("verify with allowlist");
        assert!(check.passed, "allowlisted mutation should pass");
    }

    #[cfg(unix)]
    #[test]
    fn workspace_integrity_detects_tracked_symlink_target_content_mutation() {
        let dir = tempfile::tempdir().expect("tempdir");
        let repo = dir.path();
        init_git_repo(repo);

        fs::write(repo.join("target_payload.txt"), b"v1\n").expect("write untracked target");
        symlink("target_payload.txt", repo.join("tracked_link.txt")).expect("create symlink");
        run_git(repo, &["add", "tracked_link.txt"]);

        let snapshot = repo.join("target/ci/workspace_integrity.snapshot.tsv");
        snapshot_workspace_integrity(repo, &snapshot).expect("snapshot");

        fs::write(repo.join("target_payload.txt"), b"v2\n").expect("mutate target");
        let check =
            verify_workspace_integrity(repo, &snapshot, None).expect("verify without allowlist");
        assert!(
            !check.passed,
            "tracked symlink target-content mutation must fail:\n{}",
            check.output
        );
        assert!(
            check.output.contains("tracked_link.txt"),
            "expected symlink path in output:\n{}",
            check.output
        );
    }
}
