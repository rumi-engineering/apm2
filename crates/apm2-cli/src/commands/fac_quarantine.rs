use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use apm2_core::fac::{
    DEFAULT_MIN_FREE_BYTES, FacPolicyV1, GcActionKind, GcReceiptV1, MAX_POLICY_SIZE,
    check_disk_space, deserialize_policy, execute_gc, persist_gc_receipt, persist_policy,
    plan_quarantine_prune,
};
use apm2_core::github::resolve_apm2_home;
use clap::{Args, Subcommand};
use serde::Serialize;

use crate::exit_codes::codes as exit_codes;

/// Arguments for `apm2 fac quarantine`.
#[derive(Debug, Args)]
pub struct QuarantineArgs {
    #[command(subcommand)]
    pub subcommand: QuarantineSubcommand,
}

/// Subcommands for quarantined and denied queue management.
#[derive(Debug, Subcommand)]
pub enum QuarantineSubcommand {
    /// List quarantine and denied queue entries.
    List(QuarantineListArgs),
    /// Prune quarantine and denied queue entries using policy.
    Prune(QuarantinePruneArgs),
}

/// Arguments for `apm2 fac quarantine list`.
#[derive(Debug, Args)]
pub struct QuarantineListArgs {
    /// Output machine-readable JSON.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Arguments for `apm2 fac quarantine prune`.
#[derive(Debug, Args)]
pub struct QuarantinePruneArgs {
    /// Show what would be deleted without applying changes.
    #[arg(long, default_value_t = false)]
    pub dry_run: bool,
    /// Apply deletions.
    #[arg(long, default_value_t = false)]
    pub apply: bool,
    /// Output machine-readable JSON.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Entry metadata for queue inspection.
#[derive(Debug, Serialize)]
struct QueueEntry {
    filename: String,
    directory: String,
    size_bytes: u64,
    age_secs: u64,
    path: String,
}

/// Run `apm2 fac quarantine` commands.
pub fn run_quarantine(args: &QuarantineArgs, parent_json_output: bool) -> u8 {
    match &args.subcommand {
        QuarantineSubcommand::List(args) => {
            run_quarantine_list(args, parent_json_output || args.json)
        },
        QuarantineSubcommand::Prune(args) => {
            run_quarantine_prune(args, parent_json_output || args.json)
        },
    }
}

fn run_quarantine_list(_args: &QuarantineListArgs, json_output: bool) -> u8 {
    let fac_root = match resolve_fac_root() {
        Ok(path) => path,
        Err(error) => {
            return output_error(
                json_output,
                "fac_root_unavailable",
                &error,
                exit_codes::GENERIC_ERROR,
            );
        },
    };

    let queue_root = infer_queue_root(&fac_root);
    let now = current_wall_clock_secs();
    let mut entries = Vec::new();

    entries.extend(scan_queue_dir(
        &queue_root,
        QUARANTINE_DIR,
        QUARANTINE_DIR,
        now,
    ));
    entries.extend(scan_queue_dir(&queue_root, DENIED_DIR, DENIED_DIR, now));
    entries.extend(scan_queue_dir(
        &queue_root,
        QUARANTINE_LEGACY_DIR,
        QUEUE_PRUNE_KIND_LABEL_LEGACY,
        now,
    ));

    entries.sort_by(|a, b| {
        b.age_secs
            .cmp(&a.age_secs)
            .then_with(|| b.size_bytes.cmp(&a.size_bytes))
            .then_with(|| a.path.cmp(&b.path))
    });

    let total_entries = entries.len();
    let total_bytes: u64 = entries.iter().map(|entry| entry.size_bytes).sum();
    let oldest_entry_age_secs = entries.first().map(|entry| entry.age_secs);

    if json_output {
        let payload = serde_json::json!({
            "entries": entries,
            "summary": {
                "total_entries": total_entries,
                "total_bytes": total_bytes,
                "oldest_entry_age_secs": oldest_entry_age_secs,
            },
        });
        return match serde_json::to_string_pretty(&payload) {
            Ok(json) => {
                println!("{json}");
                exit_codes::SUCCESS
            },
            Err(error) => output_error(
                json_output,
                "fac_quarantine_list_serialize_failed",
                &format!("cannot serialize list output: {error}"),
                exit_codes::GENERIC_ERROR,
            ),
        };
    }

    if entries.is_empty() {
        println!("No quarantine or denied entries found.");
        println!("Summary: 0 entries, 0 bytes, oldest age 0s");
        return exit_codes::SUCCESS;
    }

    println!(
        "{:<10} {:<12} {:>12} {:>12}  path",
        "directory", "filename", "size", "age",
    );
    for entry in &entries {
        println!(
            "{:<10} {:<12} {:>12} {:>12}  {}",
            entry.directory,
            entry.filename,
            format_bytes(entry.size_bytes),
            format_age(entry.age_secs),
            entry.path,
        );
    }

    if let Some(oldest) = oldest_entry_age_secs {
        println!("Summary: {total_entries} entries, {total_bytes} bytes, oldest age {oldest}s");
    } else {
        println!("Summary: {total_entries} entries, {total_bytes} bytes, oldest age n/a");
    }
    exit_codes::SUCCESS
}

fn run_quarantine_prune(args: &QuarantinePruneArgs, json_output: bool) -> u8 {
    if args.dry_run && args.apply {
        return output_error(
            json_output,
            "invalid_args",
            "--dry-run and --apply are mutually exclusive",
            exit_codes::VALIDATION_ERROR,
        );
    }

    let apply = args.apply;
    let fac_root = match resolve_fac_root() {
        Ok(path) => path,
        Err(error) => {
            return output_error(
                json_output,
                "fac_root_unavailable",
                &error,
                exit_codes::GENERIC_ERROR,
            );
        },
    };

    let queue_root = infer_queue_root(&fac_root);
    let policy = match load_or_create_policy(&fac_root) {
        Ok(policy) => policy,
        Err(error) => {
            return output_error(
                json_output,
                "fac_quarantine_policy_load_failed",
                &format!("cannot load fac policy: {error}"),
                exit_codes::GENERIC_ERROR,
            );
        },
    };

    let plan = match plan_quarantine_prune(
        &queue_root,
        u64::from(policy.quarantine_ttl_days).saturating_mul(24 * 3600),
        u64::from(policy.denied_ttl_days).saturating_mul(24 * 3600),
        policy.quarantine_max_bytes,
        current_wall_clock_secs(),
    ) {
        Ok(plan) => plan,
        Err(error) => {
            return output_error(
                json_output,
                "fac_quarantine_plan_failed",
                &format!("cannot compute quarantine prune plan: {error:?}"),
                exit_codes::GENERIC_ERROR,
            );
        },
    };

    if plan.targets.is_empty() {
        if json_output {
            let payload = serde_json::json!({
                "apply": apply,
                "summary": {
                    "total_targets": 0,
                    "total_bytes": 0_u64,
                },
                "targets": [],
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".to_string())
            );
        } else {
            println!("No entries would be deleted.");
        }
        return exit_codes::SUCCESS;
    }

    let total_targets = plan.targets.len();
    let total_bytes: u64 = plan
        .targets
        .iter()
        .map(|target| target.estimated_bytes)
        .sum();

    if !apply {
        if json_output {
            let targets = plan
                .targets
                .iter()
                .map(|target| {
                    let target_path = target.path.display().to_string();
                    serde_json::json!({
                        "kind": queue_prune_kind_label_for_target(target.kind, &target_path),
                        "estimated_bytes": target.estimated_bytes,
                        "path": sanitize_for_terminal(&target_path),
                    })
                })
                .collect::<Vec<_>>();
            let payload = serde_json::json!({
                "apply": false,
                "summary": {
                    "total_targets": total_targets,
                    "total_bytes": total_bytes,
                },
                "targets": targets,
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".to_string())
            );
        } else {
            println!("Would delete {total_targets} entries ({total_bytes} bytes)");
            for target in &plan.targets {
                let target_path = target.path.display().to_string();
                println!(
                    "{} {} {}",
                    queue_prune_kind_label_for_target(target.kind, &target_path),
                    target.estimated_bytes,
                    sanitize_for_terminal(&target_path),
                );
            }
        }
        return exit_codes::SUCCESS;
    }

    let before_free = match check_disk_space(&fac_root) {
        Ok(value) => value,
        Err(error) => {
            return output_error(
                json_output,
                "fac_quarantine_before_disk_sample_failed",
                &format!("cannot check free space before prune: {error}"),
                exit_codes::GENERIC_ERROR,
            );
        },
    };

    let receipt = execute_gc(&plan);
    let after_free = match check_disk_space(&fac_root) {
        Ok(value) => value,
        Err(error) => {
            return output_error(
                json_output,
                "fac_quarantine_after_disk_sample_failed",
                &format!("cannot check free space after prune: {error}"),
                exit_codes::GENERIC_ERROR,
            );
        },
    };

    let receipts_dir = fac_root.join("receipts");
    let receipt_path = match persist_gc_receipt(
        &receipts_dir,
        GcReceiptV1 {
            schema: receipt.schema,
            receipt_id: receipt.receipt_id,
            timestamp_secs: receipt.timestamp_secs,
            before_free_bytes: before_free,
            after_free_bytes: after_free,
            min_free_threshold: if receipt.min_free_threshold == 0 {
                DEFAULT_MIN_FREE_BYTES
            } else {
                receipt.min_free_threshold
            },
            actions: receipt.actions,
            errors: receipt.errors,
            content_hash: receipt.content_hash,
        },
    ) {
        Ok(path) => path,
        Err(error) => {
            return output_error(
                json_output,
                "fac_quarantine_receipt_persist_failed",
                &format!("cannot persist quarantine prune receipt: {error}"),
                exit_codes::GENERIC_ERROR,
            );
        },
    };

    if json_output {
        let payload = serde_json::json!({
            "apply": true,
            "summary": {
                "total_targets": total_targets,
                "total_bytes": total_bytes,
                "before_free_bytes": before_free,
                "after_free_bytes": after_free,
            },
            "receipt": receipt_path.to_string_lossy(),
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        println!("Pruned {total_targets} entries ({total_bytes} bytes)");
        println!("receipt: {}", receipt_path.display());
    }
    exit_codes::SUCCESS
}

fn load_or_create_policy(fac_root: &Path) -> Result<FacPolicyV1, String> {
    let policy_dir = fac_root.join(POLICY_DIR);
    let policy_path = policy_dir.join(FAC_POLICY_FILE);

    if policy_path.exists() {
        let bytes = read_bounded(&policy_path, MAX_POLICY_SIZE)?;
        deserialize_policy(&bytes).map_err(|error| format!("cannot load fac policy: {error}"))
    } else {
        let default_policy = FacPolicyV1::default_policy();
        persist_policy(fac_root, &default_policy)
            .map_err(|error| format!("cannot persist default fac policy: {error}"))?;
        Ok(default_policy)
    }
}

fn scan_queue_dir(
    queue_root: &Path,
    directory: &str,
    display_directory: &str,
    now: u64,
) -> Vec<QueueEntry> {
    let allowed_parent = queue_root.join(directory);
    let Ok(entries) = fs::read_dir(&allowed_parent) else {
        return Vec::new();
    };

    let mut count = 0usize;
    let mut out = Vec::new();
    for entry in entries.flatten() {
        count += 1;
        if count > MAX_SCAN_ENTRIES {
            eprintln!("WARNING: scan truncated at {MAX_SCAN_ENTRIES} entries");
            break;
        }
        let path = entry.path();
        let filename = entry.file_name().to_string_lossy().into_owned();
        let Ok(metadata) = path.symlink_metadata() else {
            continue;
        };
        if metadata.file_type().is_symlink() {
            continue;
        }
        let Ok(modified) = metadata.modified() else {
            continue;
        };
        let Ok(modified_secs) = modified.duration_since(UNIX_EPOCH) else {
            continue;
        };
        let age_secs = now.saturating_sub(modified_secs.as_secs());

        out.push(QueueEntry {
            filename: sanitize_for_terminal(&filename),
            directory: display_directory.to_string(),
            size_bytes: metadata.len(),
            age_secs,
            path: sanitize_for_terminal(&path.display().to_string()),
        });
    }

    out
}

#[allow(clippy::cast_precision_loss)]
fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_073_741_824 {
        format!("{:.1} GiB", bytes as f64 / 1_073_741_824.0)
    } else if bytes >= 1_048_576 {
        format!("{:.1} MiB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}

fn format_age(secs: u64) -> String {
    if secs >= 86_400 {
        format!("{}d", secs / 86_400)
    } else if secs >= 3600 {
        format!("{}h", secs / 3600)
    } else if secs >= 60 {
        format!("{}m", secs / 60)
    } else {
        format!("{secs}s")
    }
}

fn sanitize_for_terminal(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_control() || c == '\x1b' {
                '\u{FFFD}'
            } else {
                c
            }
        })
        .collect()
}

fn queue_prune_kind_label_for_target(kind: GcActionKind, target_path: &str) -> &'static str {
    if matches!(kind, GcActionKind::QuarantinePrune) && is_legacy_quarantine_path(target_path) {
        QUEUE_PRUNE_KIND_LABEL_LEGACY
    } else {
        queue_prune_kind_label(kind)
    }
}

fn is_legacy_quarantine_path(path: &str) -> bool {
    path.split(['/', '\\'])
        .any(|segment| segment == QUARANTINE_LEGACY_DIR)
}

const fn queue_prune_kind_label(kind: GcActionKind) -> &'static str {
    match kind {
        GcActionKind::QuarantinePrune => "quarantine",
        GcActionKind::DeniedPrune => "denied",
        _ => "other",
    }
}

fn resolve_fac_root() -> Result<PathBuf, String> {
    resolve_apm2_home()
        .map(|home| home.join("private").join("fac"))
        .ok_or_else(|| "could not resolve APM2 home".to_string())
}

fn infer_queue_root(fac_root: &Path) -> PathBuf {
    fac_root.parent().and_then(Path::parent).map_or_else(
        || fac_root.join("queue"),
        |apm2_home| apm2_home.join("queue"),
    )
}

fn output_error(json_output: bool, code: &str, message: &str, exit_code: u8) -> u8 {
    if json_output {
        let payload = serde_json::json!({
            "error": code,
            "message": message,
        });
        if let Ok(json) = serde_json::to_string_pretty(&payload) {
            println!("{json}");
        } else {
            println!("{{\"error\":\"{code}\",\"message\":\"{message}\"}}");
        }
        return exit_code;
    }

    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "error": code,
            "message": message,
        }))
        .unwrap_or_else(|_| "{\"error\":\"serialization_failure\"}".to_string())
    );
    exit_code
}

fn read_bounded(path: &Path, max_size: usize) -> Result<Vec<u8>, String> {
    let file =
        File::open(path).map_err(|error| format!("cannot open {}: {error}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("cannot stat {}: {error}", path.display()))?;
    if metadata.len() > max_size as u64 {
        return Err(format!(
            "file {} exceeds max {} bytes",
            path.display(),
            max_size
        ));
    }

    #[allow(clippy::cast_possible_truncation)]
    let read_limit = metadata.len() as usize;
    let mut limited_reader = file.take((max_size.saturating_add(1)) as u64);
    let mut bytes = Vec::with_capacity(read_limit);
    limited_reader
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    if bytes.len() > max_size {
        return Err(format!(
            "file {} exceeds max {} bytes",
            path.display(),
            max_size
        ));
    }

    Ok(bytes)
}

#[allow(clippy::cast_possible_wrap)]
fn current_wall_clock_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

const QUARANTINE_DIR: &str = "quarantine";
const QUARANTINE_LEGACY_DIR: &str = "quarantined";
const DENIED_DIR: &str = "denied";
const QUEUE_PRUNE_KIND_LABEL_LEGACY: &str = "quarantine (legacy)";
const POLICY_DIR: &str = "policy";
const FAC_POLICY_FILE: &str = "fac_policy.v1.json";
const MAX_SCAN_ENTRIES: usize = 10_000;

#[cfg(test)]
mod tests {
    use apm2_core::fac::GcActionKind;

    use super::*;

    #[test]
    fn test_quarantine_prune_kind_label() {
        assert_eq!(
            queue_prune_kind_label(GcActionKind::QuarantinePrune),
            "quarantine"
        );
        assert_eq!(queue_prune_kind_label(GcActionKind::DeniedPrune), "denied");
        assert_eq!(queue_prune_kind_label(GcActionKind::LaneTarget), "other");
    }
}
