//! Merge-conflict detection against `main` for FAC gates and review prechecks.

use std::fmt::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};

/// One merge conflict entry returned by `git merge-tree --messages`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeConflictEntry {
    pub conflict_type: String,
    pub file: Option<String>,
    pub message: String,
}

/// Structured report for merge-conflict analysis against `main`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeConflictReport {
    pub base_ref: String,
    pub head_sha: String,
    pub merge_tree: Option<String>,
    pub conflicts: Vec<MergeConflictEntry>,
    pub raw_output: String,
}

impl MergeConflictReport {
    pub fn has_conflicts(&self) -> bool {
        !self.conflicts.is_empty()
    }

    pub fn conflict_count(&self) -> usize {
        self.conflicts.len()
    }
}

fn short_sha(sha: &str) -> &str {
    let end = sha.len().min(12);
    &sha[..end]
}

fn is_hex_tree_id(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn resolve_main_ref(workspace_root: &Path) -> Result<String, String> {
    for candidate in ["origin/main", "main"] {
        let verify = format!("{candidate}^{{commit}}");
        let output = Command::new("git")
            .args(["rev-parse", "--verify", "--quiet", &verify])
            .current_dir(workspace_root)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .map_err(|err| format!("failed to resolve merge base ref `{candidate}`: {err}"))?;
        if output.status.success() {
            return Ok(candidate.to_string());
        }
    }

    Err(
        "failed to resolve merge base ref: neither `origin/main` nor `main` exists locally"
            .to_string(),
    )
}

fn ensure_head_exists(workspace_root: &Path, head_sha: &str) -> Result<(), String> {
    let verify = format!("{head_sha}^{{commit}}");
    let output = Command::new("git")
        .args(["rev-parse", "--verify", "--quiet", &verify])
        .current_dir(workspace_root)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|err| format!("failed to verify head SHA `{head_sha}`: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "head SHA `{head_sha}` is not available in the local repository"
        ));
    }
    Ok(())
}

fn parse_conflict_line(line: &str) -> Option<MergeConflictEntry> {
    if !line.starts_with("CONFLICT (") {
        return None;
    }

    let close_idx = line.find("): ")?;
    let conflict_type = line["CONFLICT (".len()..close_idx].trim().to_string();
    let message = line[close_idx + 3..].trim().to_string();
    let file = message
        .strip_prefix("Merge conflict in ")
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .or_else(|| {
            message
                .split_once(" deleted in ")
                .map(|(path, _)| path.trim().to_string())
                .filter(|path| !path.is_empty())
        });

    Some(MergeConflictEntry {
        conflict_type,
        file,
        message,
    })
}

fn is_docs_migration_conflict(workspace_root: &Path, entry: &MergeConflictEntry) -> bool {
    if entry.conflict_type != "modify/delete"
        || !entry.message.contains("deleted in HEAD and modified in")
    {
        return false;
    }

    let Some(file) = entry.file.as_deref() else {
        return false;
    };
    let file_path = Path::new(file);
    let Some(extension) = file_path.extension().and_then(|value| value.to_str()) else {
        return false;
    };
    let docs_candidate = match extension {
        "md" => {
            file_path.file_name().and_then(|name| name.to_str()) == Some("AGENTS.md")
                || file.starts_with("documents/")
        },
        "yaml" | "yml" => file.starts_with("documents/"),
        _ => false,
    };
    if !docs_candidate {
        return false;
    }

    let mut successor = file_path.to_path_buf();
    successor.set_extension("json");
    workspace_root.join(successor).is_file()
}

fn parse_merge_tree_output(raw: &str) -> (Option<String>, Vec<MergeConflictEntry>) {
    let mut merge_tree = None;
    let mut conflicts = Vec::new();

    for (idx, line) in raw.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if idx == 0 && is_hex_tree_id(trimmed) {
            merge_tree = Some(trimmed.to_string());
            continue;
        }
        if let Some(entry) = parse_conflict_line(trimmed) {
            conflicts.push(entry);
        }
    }

    (merge_tree, conflicts)
}

/// Check whether `head_sha` merges cleanly with `main`.
///
/// This is fail-closed: command errors are returned as `Err`.
pub fn check_merge_conflicts_against_main(
    workspace_root: &Path,
    head_sha: &str,
) -> Result<MergeConflictReport, String> {
    let base_ref = resolve_main_ref(workspace_root)?;
    ensure_head_exists(workspace_root, head_sha)?;

    let output = Command::new("git")
        .args([
            "merge-tree",
            "--name-only",
            "--messages",
            &base_ref,
            head_sha,
        ])
        .current_dir(workspace_root)
        .output()
        .map_err(|err| format!("failed to execute git merge-tree: {err}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    if !output.status.success() {
        let has_conflict_markers = stdout.lines().any(|line| line.starts_with("CONFLICT ("));
        if !has_conflict_markers {
            return Err(format!("git merge-tree failed: {}", stderr.trim()));
        }
    }
    let raw_output = if stderr.trim().is_empty() {
        stdout.clone()
    } else {
        format!("{stdout}\n[stderr]\n{stderr}")
    };

    let (merge_tree, conflicts) = parse_merge_tree_output(&stdout);
    let conflicts = conflicts
        .into_iter()
        .filter(|entry| !is_docs_migration_conflict(workspace_root, entry))
        .collect();

    Ok(MergeConflictReport {
        base_ref,
        head_sha: head_sha.to_string(),
        merge_tree,
        conflicts,
        raw_output,
    })
}

/// Render a concise, terminal-friendly failure summary.
pub fn render_merge_conflict_summary(report: &MergeConflictReport) -> String {
    if !report.has_conflicts() {
        return format!(
            "merge_conflict_main: PASS head={} base={}",
            short_sha(&report.head_sha),
            report.base_ref
        );
    }

    let mut out = String::new();
    let _ = writeln!(
        out,
        "merge_conflict_main: FAIL head={} base={} conflicts={}",
        short_sha(&report.head_sha),
        report.base_ref,
        report.conflict_count()
    );

    for entry in report.conflicts.iter().take(50) {
        if let Some(file) = entry.file.as_deref() {
            let _ = writeln!(out, "  - {} [{}]", file.trim(), entry.conflict_type.trim());
        } else {
            let _ = writeln!(
                out,
                "  - {} [{}]",
                entry.message.trim(),
                entry.conflict_type.trim()
            );
        }
    }

    if report.conflicts.len() > 50 {
        let _ = writeln!(
            out,
            "  - ... {} additional conflict(s)",
            report.conflicts.len() - 50
        );
    }

    out.push_str("resolve conflicts with main before dispatching reviews");
    out
}

/// Render full diagnostic content for gate log files.
pub fn render_merge_conflict_log(report: &MergeConflictReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "base_ref: {}", report.base_ref);
    let _ = writeln!(out, "head_sha: {}", report.head_sha);
    let _ = writeln!(out, "conflict_count: {}", report.conflict_count());
    if let Some(tree) = report.merge_tree.as_deref() {
        let _ = writeln!(out, "merge_tree: {tree}");
    }
    out.push_str("\nsummary:\n");
    out.push_str(&render_merge_conflict_summary(report));
    out.push_str("\n\nraw_merge_tree_output:\n");
    out.push_str(report.raw_output.trim_end());
    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::{
        is_docs_migration_conflict, parse_conflict_line, parse_merge_tree_output,
        render_merge_conflict_summary,
    };

    #[test]
    fn parse_modify_delete_conflict_extracts_file() {
        let parsed = parse_conflict_line("CONFLICT (modify/delete): crates/apm2-core/AGENTS.md deleted in HEAD and modified in origin/main.  Version origin/main of crates/apm2-core/AGENTS.md left in tree.")
            .expect("conflict should parse");
        assert_eq!(parsed.conflict_type, "modify/delete");
        assert_eq!(parsed.file.as_deref(), Some("crates/apm2-core/AGENTS.md"));
    }

    #[test]
    fn parse_conflict_line_extracts_type_and_file() {
        let parsed = parse_conflict_line(
            "CONFLICT (content): Merge conflict in crates/apm2-cli/src/commands/fac.rs",
        )
        .expect("conflict should parse");
        assert_eq!(parsed.conflict_type, "content");
        assert_eq!(
            parsed.file.as_deref(),
            Some("crates/apm2-cli/src/commands/fac.rs")
        );
    }

    #[test]
    fn parse_merge_tree_output_extracts_tree_and_conflicts() {
        let raw = "\
0123456789abcdef0123456789abcdef01234567
crates/apm2-cli/src/commands/fac.rs

Auto-merging crates/apm2-cli/src/commands/fac.rs
CONFLICT (content): Merge conflict in crates/apm2-cli/src/commands/fac.rs
";

        let (tree, conflicts) = parse_merge_tree_output(raw);
        assert_eq!(
            tree.as_deref(),
            Some("0123456789abcdef0123456789abcdef01234567")
        );
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].conflict_type, "content");
    }

    #[test]
    fn summary_includes_conflict_count() {
        let raw = "\
0123456789abcdef0123456789abcdef01234567
Auto-merging path
CONFLICT (add/add): Merge conflict in foo/bar.rs
CONFLICT (content): Merge conflict in baz/qux.rs
";
        let (_, conflicts) = parse_merge_tree_output(raw);
        let report = super::MergeConflictReport {
            base_ref: "origin/main".to_string(),
            head_sha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            merge_tree: Some("0123456789abcdef0123456789abcdef01234567".to_string()),
            conflicts,
            raw_output: raw.to_string(),
        };
        let rendered = render_merge_conflict_summary(&report);
        assert!(rendered.contains("conflicts=2"));
        assert!(rendered.contains("foo/bar.rs"));
        assert!(rendered.contains("baz/qux.rs"));
    }

    #[test]
    fn docs_migration_conflict_is_ignored_when_json_successor_exists() {
        let temp = tempfile::tempdir().expect("tempdir");
        let successor = temp.path().join("documents/work/tickets/TCK-00672.json");
        fs::create_dir_all(successor.parent().expect("parent")).expect("mkdir");
        fs::write(&successor, "{}").expect("write successor");

        let parsed = parse_conflict_line("CONFLICT (modify/delete): documents/work/tickets/TCK-00672.yaml deleted in HEAD and modified in origin/main.  Version origin/main of documents/work/tickets/TCK-00672.yaml left in tree.")
            .expect("conflict should parse");
        assert!(is_docs_migration_conflict(temp.path(), &parsed));
    }

    #[test]
    fn docs_migration_conflict_is_not_ignored_without_json_successor() {
        let temp = tempfile::tempdir().expect("tempdir");
        let parsed = parse_conflict_line("CONFLICT (modify/delete): crates/apm2-daemon/src/gate/AGENTS.md deleted in HEAD and modified in origin/main.  Version origin/main of crates/apm2-daemon/src/gate/AGENTS.md left in tree.")
            .expect("conflict should parse");
        assert!(!is_docs_migration_conflict(temp.path(), &parsed));
    }
}
