use std::fs;
use std::io::Read;
use std::path::Path;

use apm2_core::fac::{
    DEFAULT_MIN_FREE_BYTES, FacPolicyV1, GcActionKind, GcPlan, GcReceiptV1, LaneManager,
    MAX_POLICY_SIZE, check_disk_space, deserialize_policy, execute_gc, persist_gc_receipt,
    persist_policy, plan_gc,
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
    /// Output machine-readable JSON.
    #[arg(long)]
    pub json: bool,
    /// Minimum free bytes to enforce.
    #[arg(long, default_value_t = 1_073_741_824)]
    pub min_free_bytes: u64,
}

/// Run garbage collection for FAC workspace artifacts.
pub fn run_gc(args: &GcArgs, parent_json_output: bool) -> u8 {
    let json_output = parent_json_output || args.json;
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

    let quarantine_ttl_secs = u64::from(policy.quarantine_ttl_days).saturating_mul(24 * 3600);
    let denied_ttl_secs = u64::from(policy.denied_ttl_days).saturating_mul(24 * 3600);

    let plan = match plan_gc(
        &fac_root,
        &lane_manager,
        quarantine_ttl_secs,
        denied_ttl_secs,
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
        GcActionKind::QuarantinePrune => "quarantine_prune",
        GcActionKind::DeniedPrune => "denied_prune",
        GcActionKind::CargoCache => "cargo_cache",
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
