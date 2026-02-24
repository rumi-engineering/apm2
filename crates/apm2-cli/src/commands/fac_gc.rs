use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use apm2_core::fac::{
    DEFAULT_MIN_FREE_BYTES, FacPolicyV1, GcActionKind, GcPlan, GcReceiptV1, LaneManager,
    LogRetentionConfig, MAX_POLICY_SIZE, check_disk_space, deserialize_policy, execute_gc,
    persist_gc_receipt, persist_policy, plan_gc_with_log_retention, run_migration_to_completion,
};
use serde_json;
use serde_json::json;

use crate::exit_codes::codes as exit_codes;

/// Arguments for `apm2 fac gc`.
#[derive(Debug, clap::Args)]
pub struct GcArgs {
    /// Print plan only.
    #[arg(long)]
    pub dry_run: bool,
    /// Minimum free bytes to enforce.
    #[arg(long, default_value_t = 1_073_741_824)]
    pub min_free_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct DoctorGcMaintenanceSummary {
    pub plan_targets: usize,
    pub actions_applied: usize,
    pub errors: usize,
    pub bytes_freed: u64,
    pub receipt_path: PathBuf,
    pub migration_files_moved: usize,
    pub migration_files_failed: usize,
    pub migration_skipped: bool,
    pub migration_warning: Option<String>,
}

/// Run full FAC GC maintenance as an internal doctor remediation action.
///
/// This includes:
/// - legacy evidence migration (non-fatal on error)
/// - policy-derived GC planning
/// - GC execution and durable receipt persistence
pub fn run_gc_for_doctor_fix() -> Result<DoctorGcMaintenanceSummary, String> {
    let lane_manager = LaneManager::from_default_home()
        .map_err(|error| format!("cannot initialize lane manager: {error}"))?;
    let fac_root = lane_manager.fac_root().to_path_buf();

    let policy = load_or_create_policy(&fac_root)
        .map_err(|error| format!("cannot load fac policy: {error}"))?;

    let (migration_files_moved, migration_files_failed, migration_skipped, migration_warning) =
        match run_migration_to_completion(&fac_root) {
            Ok(receipt) => (
                receipt.files_moved,
                receipt.files_failed,
                receipt.skipped,
                None,
            ),
            Err(error) => (0_usize, 0_usize, true, Some(error.to_string())),
        };

    let quarantine_ttl_secs = u64::from(policy.quarantine_ttl_days).saturating_mul(24 * 3600);
    let denied_ttl_secs = u64::from(policy.denied_ttl_days).saturating_mul(24 * 3600);
    let log_retention = LogRetentionConfig {
        per_lane_log_max_bytes: policy.per_lane_log_max_bytes,
        per_job_log_ttl_secs: u64::from(policy.per_job_log_ttl_days).saturating_mul(24 * 3600),
        keep_last_n_jobs_per_lane: policy.keep_last_n_jobs_per_lane,
    };

    let plan = plan_gc_with_log_retention(
        &fac_root,
        &lane_manager,
        quarantine_ttl_secs,
        denied_ttl_secs,
        &log_retention,
    )
    .map_err(|error| format!("planning failed: {error:?}"))?;
    let plan_targets = plan.targets.len();

    let before_free = check_disk_space(&fac_root)
        .map_err(|error| format!("cannot sample pre-gc free space: {error}"))?;
    let mut receipt = execute_gc(&plan);
    let after_free = check_disk_space(&fac_root)
        .map_err(|error| format!("cannot sample post-gc free space: {error}"))?;

    if receipt.min_free_threshold == 0 {
        receipt.min_free_threshold = DEFAULT_MIN_FREE_BYTES;
    }

    let actions_applied = receipt.actions.len();
    let errors = receipt.errors.len();
    let bytes_freed = receipt
        .actions
        .iter()
        .fold(0_u64, |acc, action| acc.saturating_add(action.bytes_freed));

    let receipts_dir = fac_root.join("receipts");
    let receipt_path = persist_gc_receipt(
        &receipts_dir,
        GcReceiptV1 {
            schema: receipt.schema,
            receipt_id: receipt.receipt_id,
            timestamp_secs: receipt.timestamp_secs,
            before_free_bytes: before_free,
            after_free_bytes: after_free,
            min_free_threshold: receipt.min_free_threshold,
            actions: receipt.actions,
            errors: receipt.errors,
            content_hash: receipt.content_hash,
        },
    )
    .map_err(|error| format!("cannot persist GC receipt: {error}"))?;

    Ok(DoctorGcMaintenanceSummary {
        plan_targets,
        actions_applied,
        errors,
        bytes_freed,
        receipt_path,
        migration_files_moved,
        migration_files_failed,
        migration_skipped,
        migration_warning,
    })
}

/// Run garbage collection for FAC workspace artifacts.
pub fn run_gc(args: &GcArgs, parent_json_output: bool) -> u8 {
    let json_output = parent_json_output;
    let lane_manager = match LaneManager::from_default_home() {
        Ok(manager) => manager,
        Err(error) => {
            return output_gc_error(
                "fac_gc_lane_manager_init_failed",
                &format!("cannot initialize lane manager: {error}"),
                exit_codes::GENERIC_ERROR,
            );
        },
    };

    let fac_root = lane_manager.fac_root().to_path_buf();

    let policy = match load_or_create_policy(&fac_root) {
        Ok(policy) => policy,
        Err(error) => {
            return output_gc_error(
                "fac_gc_policy_load_failed",
                &format!("cannot load fac policy: {error}"),
                exit_codes::GENERIC_ERROR,
            );
        },
    };

    // TCK-00589: Run legacy evidence migration before GC planning.
    // This ensures upgraded installations automatically migrate files from
    // `evidence/` to `legacy/` during routine garbage collection. The
    // migration helper is bounded and idempotent; it is a no-op when the
    // legacy evidence directory does not exist or has already been migrated.
    //
    // Migration is skipped in --dry-run mode because it is a mutating
    // operation (moves files, removes directories, writes receipts). In
    // dry-run mode we only report whether migration WOULD run.
    if args.dry_run {
        let evidence_dir = fac_root.join("evidence");
        if evidence_dir.is_dir() && !json_output {
            eprintln!("legacy evidence migration: would migrate (skipped in --dry-run mode)");
        }
    } else {
        match run_migration_to_completion(&fac_root) {
            Ok(receipt) if !receipt.skipped && !json_output => {
                let status = if receipt.is_complete {
                    "complete"
                } else {
                    "partial"
                };
                eprintln!(
                    "legacy evidence migration: {status}, {} moved, {} failed",
                    receipt.files_moved, receipt.files_failed
                );
            },
            Ok(_) => {}, // skipped or json mode — no human output
            Err(error) => {
                // Migration failure is non-fatal for GC — log and continue.
                eprintln!("WARNING: legacy evidence migration failed: {error}, continuing with GC");
            },
        }
    }

    let quarantine_ttl_secs = u64::from(policy.quarantine_ttl_days).saturating_mul(24 * 3600);
    let denied_ttl_secs = u64::from(policy.denied_ttl_days).saturating_mul(24 * 3600);

    // TCK-00571: Derive log retention config from policy.
    let log_retention = LogRetentionConfig {
        per_lane_log_max_bytes: policy.per_lane_log_max_bytes,
        per_job_log_ttl_secs: u64::from(policy.per_job_log_ttl_days).saturating_mul(24 * 3600),
        keep_last_n_jobs_per_lane: policy.keep_last_n_jobs_per_lane,
    };

    let plan = match plan_gc_with_log_retention(
        &fac_root,
        &lane_manager,
        quarantine_ttl_secs,
        denied_ttl_secs,
        &log_retention,
    ) {
        Ok(plan) => plan,
        Err(error) => {
            return output_gc_error(
                "fac_gc_plan_failed",
                &format!("planning failed: {error:?}"),
                exit_codes::GENERIC_ERROR,
            );
        },
    };

    if args.dry_run {
        if json_output {
            match serde_json::to_string_pretty(&gc_plan_to_json(&plan)) {
                Ok(json) => println!("{json}"),
                Err(error) => {
                    return output_gc_error(
                        "fac_gc_serialize_plan_failed",
                        &format!("cannot serialize plan: {error}"),
                        exit_codes::GENERIC_ERROR,
                    );
                },
            }
        } else {
            for target in &plan.targets {
                println!(
                    "{} {} {}",
                    gc_target_kind_to_str(target.kind),
                    target.estimated_bytes,
                    target.path.display(),
                );
            }
        }
        return exit_codes::SUCCESS;
    }

    let before_free = match check_disk_space(&fac_root) {
        Ok(value) => value,
        Err(error) => {
            return output_gc_error(
                "fac_gc_pre_disk_sample_failed",
                &format!("cannot sample pre-gc free space: {error}"),
                exit_codes::GENERIC_ERROR,
            );
        },
    };
    let mut receipt = execute_gc(&plan);
    let after_free = match check_disk_space(&fac_root) {
        Ok(value) => value,
        Err(error) => {
            return output_gc_error(
                "fac_gc_post_disk_sample_failed",
                &format!("cannot sample post-gc free space: {error}"),
                exit_codes::GENERIC_ERROR,
            );
        },
    };
    let action_count = receipt.actions.len();
    let error_count = receipt.errors.len();

    if receipt.min_free_threshold == 0 {
        receipt.min_free_threshold = if args.min_free_bytes == 0 {
            DEFAULT_MIN_FREE_BYTES
        } else {
            args.min_free_bytes
        };
    } else if args.min_free_bytes != 0 {
        receipt.min_free_threshold = args.min_free_bytes;
    }

    let receipts_dir = fac_root.join("receipts");
    let path = match persist_gc_receipt(
        &receipts_dir,
        GcReceiptV1 {
            schema: receipt.schema,
            receipt_id: receipt.receipt_id,
            timestamp_secs: receipt.timestamp_secs,
            before_free_bytes: before_free,
            after_free_bytes: after_free,
            min_free_threshold: receipt.min_free_threshold,
            actions: receipt.actions,
            errors: receipt.errors,
            content_hash: receipt.content_hash,
        },
    ) {
        Ok(path) => path,
        Err(error) => {
            return output_gc_error(
                "fac_gc_receipt_persist_failed",
                &format!("cannot persist GC receipt: {error}"),
                exit_codes::GENERIC_ERROR,
            );
        },
    };

    if json_output {
        let payload = json!({
            "applied": true,
            "plan_targets": plan.targets.len(),
            "actions": action_count,
            "errors": error_count,
            "receipt": path.to_string_lossy(),
        });
        match serde_json::to_string_pretty(&payload) {
            Ok(json) => println!("{json}"),
            Err(error) => {
                return output_gc_error(
                    "fac_gc_serialize_result_failed",
                    &format!("cannot print json: {error}"),
                    exit_codes::GENERIC_ERROR,
                );
            },
        }
    } else {
        println!(
            "applied {} GC targets, {} actions, {} errors",
            plan.targets.len(),
            action_count,
            error_count
        );
        println!("receipt: {}", path.display());
    }
    exit_codes::SUCCESS
}

fn output_gc_error(code: &str, message: &str, exit_code: u8) -> u8 {
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "error": code,
            "message": message,
        }))
        .unwrap_or_else(|_| "{\"error\":\"serialization_failure\"}".to_string())
    );
    exit_code
}

fn gc_plan_to_json(plan: &GcPlan) -> serde_json::Value {
    let mut entries = Vec::new();
    for target in &plan.targets {
        entries.push(serde_json::json!({
            "path": target.path.to_string_lossy(),
            "kind": gc_target_kind_to_str(target.kind),
            "estimated_bytes": target.estimated_bytes,
            "allowed_parent": target.allowed_parent.to_string_lossy(),
        }));
    }
    serde_json::json!({ "targets": entries, "count": plan.targets.len() })
}

const fn gc_target_kind_to_str(kind: GcActionKind) -> &'static str {
    match kind {
        GcActionKind::LaneTarget => "lane_target",
        GcActionKind::LaneLog => "lane_log",
        GcActionKind::BlobPrune => "blob_prune",
        GcActionKind::GateCache => "gate_cache",
        GcActionKind::GateCacheV3 => "gate_cache_v3",
        GcActionKind::QuarantinePrune => "quarantine_prune",
        GcActionKind::DeniedPrune => "denied_prune",
        GcActionKind::CargoCache => "cargo_cache",
        GcActionKind::CasBlobPrune => "cas_blob_prune",
        GcActionKind::SccacheCache => "sccache_cache",
        GcActionKind::IndexCompaction => "index_compaction",
        GcActionKind::LaneLogRetention => "lane_log_retention",
    }
}

const POLICY_DIR: &str = "policy";
const FAC_POLICY_FILE: &str = "fac_policy.v1.json";

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

fn read_bounded(path: &Path, max_size: usize) -> Result<Vec<u8>, String> {
    let file =
        fs::File::open(path).map_err(|error| format!("cannot open {}: {error}", path.display()))?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(unsafe_code)] // Env mutation is required for scoped test setup.
    fn set_apm2_home(path: &Path) {
        unsafe {
            // SAFETY: test-only helper guarded by `env_var_test_lock()` in callers,
            // so no concurrent env mutation occurs while setting APM2_HOME.
            std::env::set_var("APM2_HOME", path);
        }
    }

    #[allow(unsafe_code)] // Env mutation is required for scoped test teardown.
    fn restore_apm2_home(previous: Option<&std::ffi::OsString>) {
        unsafe {
            // SAFETY: test-only helper guarded by `env_var_test_lock()` in callers,
            // so no concurrent env mutation occurs while restoring APM2_HOME.
            match previous {
                Some(value) => std::env::set_var("APM2_HOME", value),
                None => std::env::remove_var("APM2_HOME"),
            }
        }
    }

    #[test]
    fn run_gc_for_doctor_fix_fails_when_fac_root_is_not_directory() {
        let _env_lock = crate::commands::env_var_test_lock()
            .lock()
            .expect("serialize env-mutating test");
        let previous = std::env::var_os("APM2_HOME");

        let tmp = tempfile::tempdir().expect("tempdir");
        let private_dir = tmp.path().join("private");
        std::fs::create_dir_all(&private_dir).expect("create private dir");
        std::fs::write(private_dir.join("fac"), b"not-a-directory")
            .expect("create fac blocker file");
        set_apm2_home(tmp.path());

        let result = run_gc_for_doctor_fix();

        restore_apm2_home(previous.as_ref());
        assert!(
            result.is_err(),
            "doctor GC should fail closed when fac root is not a directory"
        );
        let error = result.expect_err("result should be error");
        assert!(
            error.contains("cannot load fac policy"),
            "error should indicate policy load failure, got: {error}"
        );
    }
}
