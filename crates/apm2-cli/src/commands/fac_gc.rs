use apm2_core::fac::{
    DEFAULT_MIN_FREE_BYTES, GcActionKind, GcPlan, GcReceiptV1, LaneManager, check_disk_space,
    execute_gc, persist_gc_receipt, plan_gc,
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
pub fn run_gc(args: &GcArgs) -> u8 {
    let lane_manager = match LaneManager::from_default_home() {
        Ok(manager) => manager,
        Err(error) => {
            eprintln!("ERROR: cannot initialize lane manager: {error}");
            return exit_codes::GENERIC_ERROR;
        },
    };

    let fac_root = lane_manager.fac_root().to_path_buf();

    let plan = match plan_gc(&fac_root, &lane_manager) {
        Ok(plan) => plan,
        Err(error) => {
            eprintln!("ERROR: planning failed: {error:?}");
            return exit_codes::GENERIC_ERROR;
        },
    };

    if args.dry_run {
        if args.json {
            match serde_json::to_string_pretty(&gc_plan_to_json(&plan)) {
                Ok(json) => println!("{json}"),
                Err(error) => {
                    eprintln!("ERROR: cannot serialize plan: {error}");
                    return exit_codes::GENERIC_ERROR;
                },
            }
        } else {
            for target in &plan.targets {
                println!(
                    "{} {} {}",
                    gc_target_kind_to_str(&target.kind),
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
            eprintln!("ERROR: cannot sample pre-gc free space: {error}");
            return exit_codes::GENERIC_ERROR;
        },
    };
    let mut receipt = execute_gc(&plan);
    let after_free = match check_disk_space(&fac_root) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("ERROR: cannot sample post-gc free space: {error}");
            return exit_codes::GENERIC_ERROR;
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
            eprintln!("ERROR: cannot persist GC receipt: {error}");
            return exit_codes::GENERIC_ERROR;
        },
    };

    if args.json {
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
                eprintln!("ERROR: cannot print json: {error}");
                return exit_codes::GENERIC_ERROR;
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

fn gc_plan_to_json(plan: &GcPlan) -> serde_json::Value {
    let mut entries = Vec::new();
    for target in &plan.targets {
        entries.push(serde_json::json!({
            "path": target.path.to_string_lossy(),
            "kind": gc_target_kind_to_str(&target.kind),
            "estimated_bytes": target.estimated_bytes,
            "allowed_parent": target.allowed_parent.to_string_lossy(),
        }));
    }
    serde_json::json!({ "targets": entries, "count": plan.targets.len() })
}

const fn gc_target_kind_to_str(kind: &GcActionKind) -> &'static str {
    match kind {
        GcActionKind::LaneTarget => "lane_target",
        GcActionKind::LaneLog => "lane_log",
        GcActionKind::GateCache => "gate_cache",
        GcActionKind::QuarantinePrune => "quarantine_prune",
        GcActionKind::CargoCache => "cargo_cache",
    }
}
