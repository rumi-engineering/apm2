// AGENT-AUTHORED (TCK-00590)
//! CLI command for FAC configuration introspection: `apm2 fac config show`.
//!
//! Aggregates resolved policy, boundary identity, execution backend, lane
//! configuration, admitted digests, and queue bounds from broker and filesystem
//! state. Prints either human-readable text or structured JSON (`--json`).
//!
//! # Security
//!
//! - All file reads are bounded (CTR-1603).
//! - No state mutations; read-only introspection.
//! - Fail-closed: unresolvable state fields report errors inline rather than
//!   omitting or synthesising default values.

use std::path::PathBuf;

use apm2_core::fac::broker_rate_limits::{
    MAX_QUEUE_BYTES_LIMIT, MAX_QUEUE_ENQUEUE_LIMIT, MAX_TOKEN_ISSUANCE_LIMIT,
};
use apm2_core::fac::economics_adoption::EconomicsAdoptionError;
use apm2_core::fac::execution_backend::{ExecutionBackend, select_backend};
use apm2_core::fac::{
    CanonicalizerTupleV1, DEFAULT_LANE_COUNT, LaneManager, MAX_LANE_COUNT,
    load_admitted_economics_profile_root, load_admitted_policy_root, load_or_default_boundary_id,
};
use apm2_core::github::resolve_apm2_home;
use clap::{Args, Subcommand};
use serde::Serialize;

use crate::exit_codes::codes as exit_codes;

// =============================================================================
// Constants
// =============================================================================

/// Policy file relative path under the FAC root.
const POLICY_FILE_RELATIVE_PATH: &str = "policy/fac_policy.v1.json";

// =============================================================================
// Args
// =============================================================================

/// Arguments for `apm2 fac config`.
#[derive(Debug, Args)]
pub struct ConfigArgs {
    /// Config subcommand.
    #[command(subcommand)]
    pub subcommand: ConfigSubcommand,
}

/// Config subcommands.
#[derive(Debug, Subcommand)]
pub enum ConfigSubcommand {
    /// Show the resolved FAC configuration (operator correctness tool).
    Show(ConfigShowArgs),
}

/// Arguments for `apm2 fac config show`.
#[derive(Debug, Args)]
pub struct ConfigShowArgs {
    /// Emit JSON output.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

// =============================================================================
// Response types
// =============================================================================

/// Structured response for `apm2 fac config show`.
#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct ConfigShowResponse {
    /// Current admitted `FacPolicyHash` (b3-256 hex string) or null if not
    /// adopted.
    pub fac_policy_hash: Option<String>,

    /// Path to the on-disk policy file.
    pub policy_path: String,

    /// Admitted policy root details, or null if no policy is admitted.
    pub admitted_policy_root: Option<AdmittedPolicyInfo>,

    /// Canonicalizer tuple digest (b3-256 hex string).
    pub canonicalizer_tuple_digest: String,

    /// Admitted economics profile digest (b3-256 hex string) or null.
    pub admitted_economics_profile_hash: Option<String>,

    /// Boundary ID for this node.
    pub boundary_id: String,

    /// Execution backend: "user" or "system".
    pub execution_backend: String,

    /// Number of configured lanes.
    pub lane_count: usize,

    /// List of lane IDs.
    pub lane_ids: Vec<String>,

    /// Queue bounds from broker rate-limit constants.
    pub queue_bounds: QueueBoundsInfo,

    /// Errors encountered during introspection (non-fatal; included for
    /// operator diagnostics).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// Admitted policy root info subset for display.
#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct AdmittedPolicyInfo {
    pub admitted_policy_hash: String,
    pub adopted_at_unix_secs: u64,
    pub actor_id: String,
}

/// Queue bounds from broker rate-limit constants.
#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_field_names)] // Field names mirror the upstream constant names.
struct QueueBoundsInfo {
    /// Maximum token issuance operations per budget window.
    pub token_issuance_limit: u64,
    /// Maximum queue enqueue operations per budget window.
    pub queue_enqueue_ops_limit: u64,
    /// Maximum queue bytes per budget window.
    pub queue_bytes_limit: u64,
}

// =============================================================================
// Dispatch
// =============================================================================

/// Execute a config subcommand. Returns a CLI exit code.
pub fn run_config_command(args: &ConfigArgs, json_global: bool) -> u8 {
    match &args.subcommand {
        ConfigSubcommand::Show(show_args) => run_show(show_args, json_global),
    }
}

// =============================================================================
// Show
// =============================================================================

fn run_show(args: &ConfigShowArgs, json_global: bool) -> u8 {
    let json = args.json || json_global;

    let response = build_config_show_response();

    if json {
        match serde_json::to_string_pretty(&response) {
            Ok(s) => {
                println!("{s}");
                exit_codes::SUCCESS
            },
            Err(e) => {
                let err = serde_json::json!({
                    "error": "config_show_serialization_failed",
                    "message": format!("failed to serialize config show response: {e}"),
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&err)
                        .unwrap_or_else(|_| "{\"error\":\"serialization_failure\"}".to_string())
                );
                exit_codes::GENERIC_ERROR
            },
        }
    } else {
        print_human_readable(&response);
        exit_codes::SUCCESS
    }
}

fn build_config_show_response() -> ConfigShowResponse {
    let mut warnings: Vec<String> = Vec::new();

    // -- FAC root --
    let fac_root = resolve_fac_root_or_warn(&mut warnings);

    // -- Policy path --
    let policy_path = fac_root.as_ref().map_or_else(
        || "<unresolvable>".to_string(),
        |r| r.join(POLICY_FILE_RELATIVE_PATH).display().to_string(),
    );

    // -- Admitted policy root --
    let (fac_policy_hash, admitted_policy_root) =
        fac_root
            .as_ref()
            .map_or((None, None), |root| match load_admitted_policy_root(root) {
                Ok(root_v1) => (
                    Some(root_v1.admitted_policy_hash.clone()),
                    Some(AdmittedPolicyInfo {
                        admitted_policy_hash: root_v1.admitted_policy_hash,
                        adopted_at_unix_secs: root_v1.adopted_at_unix_secs,
                        actor_id: root_v1.actor_id,
                    }),
                ),
                Err(e) => {
                    warnings.push(format!("admitted policy root: {e}"));
                    (None, None)
                },
            });

    // -- Canonicalizer tuple digest --
    let canonicalizer_tuple_digest = CanonicalizerTupleV1::from_current().compute_digest();

    // -- Economics profile digest --
    let admitted_economics_profile_hash =
        fac_root
            .as_ref()
            .and_then(|root| match load_admitted_economics_profile_root(root) {
                Ok(econ_root) => Some(econ_root.admitted_profile_hash),
                Err(EconomicsAdoptionError::NoAdmittedRoot { .. }) => {
                    warnings.push("no admitted economics profile".to_string());
                    None
                },
                Err(e) => {
                    warnings.push(format!("admitted economics profile root: {e}"));
                    None
                },
            });

    // -- Boundary ID --
    let boundary_id = if let Some(home) = resolve_apm2_home() {
        load_or_default_boundary_id(&home).unwrap_or_else(|e| {
            warnings.push(format!("boundary_id: {e}"));
            "<error>".to_string()
        })
    } else {
        warnings.push("cannot resolve APM2 home for boundary_id".to_string());
        "<unresolvable>".to_string()
    };

    // -- Execution backend --
    let execution_backend = match select_backend() {
        Ok(backend) => match backend {
            ExecutionBackend::UserMode => "user".to_string(),
            ExecutionBackend::SystemMode => "system".to_string(),
        },
        Err(e) => {
            warnings.push(format!("execution backend: {e}"));
            "<unavailable>".to_string()
        },
    };

    // -- Lane count and IDs --
    let lane_count = LaneManager::lane_count();
    let lane_ids = LaneManager::default_lane_ids();

    // -- Queue bounds --
    let queue_bounds = QueueBoundsInfo {
        token_issuance_limit: MAX_TOKEN_ISSUANCE_LIMIT,
        queue_enqueue_ops_limit: MAX_QUEUE_ENQUEUE_LIMIT,
        queue_bytes_limit: MAX_QUEUE_BYTES_LIMIT,
    };

    ConfigShowResponse {
        fac_policy_hash,
        policy_path,
        admitted_policy_root,
        canonicalizer_tuple_digest,
        admitted_economics_profile_hash,
        boundary_id,
        execution_backend,
        lane_count,
        lane_ids,
        queue_bounds,
        warnings,
    }
}

fn resolve_fac_root_or_warn(warnings: &mut Vec<String>) -> Option<PathBuf> {
    match super::fac_utils::resolve_fac_root() {
        Ok(root) => Some(root),
        Err(e) => {
            warnings.push(format!("fac_root: {e}"));
            None
        },
    }
}

#[allow(clippy::cast_precision_loss)] // Queue bytes display is informational only.
fn print_human_readable(response: &ConfigShowResponse) {
    println!("FAC Configuration:");
    println!();

    // Policy
    println!("  Policy:");
    println!("    path:         {}", response.policy_path);
    match &response.fac_policy_hash {
        Some(hash) => println!("    hash:         {hash}"),
        None => println!("    hash:         <not adopted>"),
    }
    if let Some(ref root) = response.admitted_policy_root {
        println!(
            "    adopted_at:   {} (unix secs)",
            root.adopted_at_unix_secs
        );
        println!("    actor:        {}", root.actor_id);
    }

    // Canonicalizer
    println!();
    println!("  Canonicalizer:");
    println!("    tuple_digest: {}", response.canonicalizer_tuple_digest);

    // Economics
    println!();
    println!("  Economics:");
    match &response.admitted_economics_profile_hash {
        Some(hash) => println!("    profile_hash: {hash}"),
        None => println!("    profile_hash: <not adopted>"),
    }

    // Identity
    println!();
    println!("  Identity:");
    println!("    boundary_id:  {}", response.boundary_id);

    // Backend
    println!();
    println!("  Execution:");
    println!("    backend:      {}", response.execution_backend);

    // Lanes
    println!();
    println!("  Lanes:");
    println!("    count:        {}", response.lane_count);
    println!("    ids:          {}", response.lane_ids.join(", "));
    println!(
        "    env_var:      APM2_FAC_LANE_COUNT (default={DEFAULT_LANE_COUNT}, max={MAX_LANE_COUNT})"
    );

    // Queue bounds
    println!();
    println!("  Queue Bounds:");
    println!(
        "    token_issuance_limit:     {}",
        response.queue_bounds.token_issuance_limit
    );
    println!(
        "    queue_enqueue_ops_limit:  {}",
        response.queue_bounds.queue_enqueue_ops_limit
    );
    println!(
        "    queue_bytes_limit:        {} ({:.1} GiB)",
        response.queue_bounds.queue_bytes_limit,
        response.queue_bounds.queue_bytes_limit as f64 / (1024.0 * 1024.0 * 1024.0)
    );

    // Warnings
    if !response.warnings.is_empty() {
        println!();
        println!("  Warnings:");
        for w in &response.warnings {
            println!("    - {w}");
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// The response must serialize to valid JSON without panicking.
    #[test]
    fn config_show_response_serializes_to_valid_json() {
        let response = build_config_show_response();
        let json =
            serde_json::to_string_pretty(&response).expect("ConfigShowResponse must serialize");
        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("serialized output must be valid JSON");
        assert!(parsed.is_object(), "top-level value must be a JSON object");
    }

    /// Verify mandatory fields are present in the JSON output.
    #[test]
    fn config_show_response_has_required_fields() {
        let response = build_config_show_response();
        let json = serde_json::to_string(&response).expect("serialize");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse");
        let obj = parsed.as_object().expect("object");

        // All top-level fields required by the ticket scope:
        assert!(
            obj.contains_key("fac_policy_hash"),
            "missing fac_policy_hash"
        );
        assert!(obj.contains_key("policy_path"), "missing policy_path");
        assert!(
            obj.contains_key("admitted_policy_root"),
            "missing admitted_policy_root"
        );
        assert!(
            obj.contains_key("canonicalizer_tuple_digest"),
            "missing canonicalizer_tuple_digest"
        );
        assert!(
            obj.contains_key("admitted_economics_profile_hash"),
            "missing admitted_economics_profile_hash"
        );
        assert!(obj.contains_key("boundary_id"), "missing boundary_id");
        assert!(
            obj.contains_key("execution_backend"),
            "missing execution_backend"
        );
        assert!(obj.contains_key("lane_count"), "missing lane_count");
        assert!(obj.contains_key("lane_ids"), "missing lane_ids");
        assert!(obj.contains_key("queue_bounds"), "missing queue_bounds");
    }

    /// Canonicalizer tuple digest must follow the `b3-256:<hex>` format.
    #[test]
    fn canonicalizer_tuple_digest_is_b3_256_format() {
        let response = build_config_show_response();
        assert!(
            response.canonicalizer_tuple_digest.starts_with("b3-256:"),
            "canonicalizer_tuple_digest must start with b3-256: prefix, got: {}",
            response.canonicalizer_tuple_digest
        );
        // b3-256:<64 hex chars> = 71 chars total
        assert_eq!(
            response.canonicalizer_tuple_digest.len(),
            71,
            "canonicalizer_tuple_digest must be exactly 71 chars"
        );
    }

    /// Lane count must match the number of lane IDs.
    #[test]
    fn lane_count_matches_lane_ids() {
        let response = build_config_show_response();
        assert_eq!(
            response.lane_count,
            response.lane_ids.len(),
            "lane_count must equal lane_ids.len()"
        );
    }

    /// Lane count must be within bounds.
    #[test]
    fn lane_count_within_bounds() {
        let response = build_config_show_response();
        assert!(
            response.lane_count >= 1 && response.lane_count <= MAX_LANE_COUNT,
            "lane_count {} out of range [1, {}]",
            response.lane_count,
            MAX_LANE_COUNT
        );
    }

    /// Queue bounds must reflect the rate-limit constants.
    #[test]
    fn queue_bounds_match_constants() {
        let response = build_config_show_response();
        assert_eq!(
            response.queue_bounds.token_issuance_limit,
            MAX_TOKEN_ISSUANCE_LIMIT
        );
        assert_eq!(
            response.queue_bounds.queue_enqueue_ops_limit,
            MAX_QUEUE_ENQUEUE_LIMIT
        );
        assert_eq!(
            response.queue_bounds.queue_bytes_limit,
            MAX_QUEUE_BYTES_LIMIT
        );
    }

    /// Policy path must contain the expected relative path component.
    #[test]
    fn policy_path_contains_expected_relative() {
        let response = build_config_show_response();
        // When FAC root is resolvable, path must include the policy filename.
        if !response.policy_path.contains("<unresolvable>") {
            assert!(
                response.policy_path.contains(POLICY_FILE_RELATIVE_PATH),
                "policy_path must contain {POLICY_FILE_RELATIVE_PATH}, got: {}",
                response.policy_path
            );
        }
    }

    /// Boundary ID must be non-empty.
    #[test]
    fn boundary_id_is_non_empty() {
        let response = build_config_show_response();
        assert!(
            !response.boundary_id.is_empty(),
            "boundary_id must not be empty"
        );
    }

    /// Execution backend must be one of the known values.
    #[test]
    fn execution_backend_is_known_value() {
        let response = build_config_show_response();
        let valid = ["user", "system", "<unavailable>"];
        assert!(
            valid.contains(&response.execution_backend.as_str()),
            "execution_backend '{}' is not a recognised value",
            response.execution_backend
        );
    }

    /// Human-readable output must not panic.
    #[test]
    fn print_human_readable_does_not_panic() {
        let response = build_config_show_response();
        // This would panic if the format strings are broken.
        print_human_readable(&response);
    }
}
