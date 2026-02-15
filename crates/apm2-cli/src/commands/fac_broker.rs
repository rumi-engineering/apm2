//! `apm2 fac broker` command implementations.
//!
//! This module exposes broker introspection for status checks used by
//! local operators when debugging FAC admission state and authority freshness.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow, bail};
use apm2_core::crypto::Signer;
use apm2_core::fac::FacBroker;
use apm2_core::github::resolve_apm2_home;
use blake3::hash as blake3_hash;
use clap::{Args, Subcommand};
use serde::Serialize;

use crate::exit_codes::codes as exit_codes;

/// Relative path for broker state persisted on disk.
const BROKER_STATE_RELATIVE_PATH: &str = "broker_state.json";

/// Maximum size allowed for the broker state file.
const MAX_BROKER_STATE_FILE_SIZE: usize = 1_048_576;

/// Arguments for `apm2 fac broker`.
#[derive(Debug, Args)]
pub struct BrokerArgs {
    #[command(subcommand)]
    pub subcommand: BrokerSubcommand,
}

/// Subcommands under `apm2 fac broker`.
#[derive(Debug, Subcommand)]
pub enum BrokerSubcommand {
    /// Show persisted broker status (state schema/tick + key fingerprint +
    /// health).
    Status(BrokerStatusArgs),
}

/// Arguments for `apm2 fac broker status`.
#[derive(Debug, Args)]
pub struct BrokerStatusArgs {
    /// Emit structured JSON output.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct BrokerStatusResponse {
    /// Broker state schema version.
    pub schema_version: String,
    /// Number of admitted policy digests currently tracked.
    pub admitted_digest_count: usize,
    /// Current broker tick.
    pub tick: u64,
    /// Prefix of the BLAKE3 fingerprint of the broker verifying key.
    pub verifying_key_fingerprint: String,
    /// Health status at command execution time.
    pub health_status: String,
}

/// Runs `apm2 fac broker`.
pub fn run_broker(args: &BrokerArgs, json_output: bool) -> u8 {
    match &args.subcommand {
        BrokerSubcommand::Status(status_args) => run_status(status_args, json_output),
    }
}

fn run_status(status_args: &BrokerStatusArgs, parent_json_output: bool) -> u8 {
    let _ = parent_json_output || status_args.json;
    match build_status() {
        Ok(response) => {
            match serde_json::to_string_pretty(&response) {
                Ok(payload) => {
                    println!("{payload}");
                },
                Err(error) => {
                    let err_payload = serde_json::json!({
                        "error": "broker_status_serialization_failed",
                        "message": format!("failed to serialize broker status response: {error}"),
                    });
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&err_payload)
                            .unwrap_or_else(|_| "{\"error\":\"serialization_failure\"}".to_string())
                    );
                    return exit_codes::GENERIC_ERROR;
                },
            }
            exit_codes::SUCCESS
        },
        Err(error) => {
            let err_payload = serde_json::json!({
                "error": "broker_status_failed",
                "message": format!("{error}"),
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&err_payload)
                    .unwrap_or_else(|_| "{\"error\":\"serialization_failure\"}".to_string())
            );
            exit_codes::GENERIC_ERROR
        },
    }
}

fn build_status() -> Result<BrokerStatusResponse> {
    let broker = load_broker_for_status()?;
    let state = broker.state();
    let verifying_key = broker.verifying_key().to_bytes();
    let fingerprint = blake3_hash(&verifying_key).to_hex().to_string();
    let health_status = "unknown (offline inspection)".to_string();

    Ok(BrokerStatusResponse {
        schema_version: state.schema_version.clone(),
        admitted_digest_count: state.admitted_policy_digests.len(),
        tick: state.current_tick,
        verifying_key_fingerprint: fingerprint.chars().take(16).collect::<String>(),
        health_status,
    })
}

fn load_broker_for_status() -> Result<FacBroker> {
    let state_path = resolve_state_path()?;
    let state = load_state(&state_path)?.unwrap_or_default();
    let signer = load_persistent_signer()?;
    FacBroker::from_signer_and_state(signer, state)
        .map_err(|error| anyhow!("cannot instantiate broker from persisted state: {error}"))
}

fn load_persistent_signer() -> Result<Signer> {
    let fac_root = resolve_fac_root()?;
    let key_path = fac_root.join("signing_key");
    if !key_path.exists() {
        bail!("no persistent signing key found");
    }

    let bytes = fs::read(&key_path)
        .map_err(|error| anyhow!("cannot read signing key {}: {error}", key_path.display()))?;

    Signer::from_bytes(&bytes).map_err(|error| anyhow!("invalid signing key: {error}"))
}

fn resolve_state_path() -> Result<PathBuf> {
    let fac_root = resolve_fac_root()?;
    Ok(fac_root.join(BROKER_STATE_RELATIVE_PATH))
}

fn resolve_fac_root() -> Result<PathBuf> {
    resolve_apm2_home()
        .map(|home| home.join("private").join("fac"))
        .ok_or_else(|| anyhow!("could not resolve APM2 home"))
}

fn load_state(path: &Path) -> Result<Option<apm2_core::fac::BrokerState>> {
    if !path.exists() {
        return Ok(None);
    }

    let metadata = fs::metadata(path).map_err(|error| {
        anyhow!(
            "cannot read broker state metadata {}: {error}",
            path.display()
        )
    })?;
    if metadata.len() > MAX_BROKER_STATE_FILE_SIZE as u64 {
        bail!(
            "broker state file {} exceeds max size {MAX_BROKER_STATE_FILE_SIZE}",
            path.display()
        );
    }

    let bytes = fs::read(path)
        .map_err(|error| anyhow!("cannot read broker state {}: {error}", path.display()))?;

    let state = FacBroker::deserialize_state(&bytes)
        .map_err(|error| anyhow!("cannot deserialize state: {error}"))?;

    Ok(Some(state))
}
