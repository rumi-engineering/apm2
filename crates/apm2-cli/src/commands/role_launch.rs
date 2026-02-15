//! FAC role launch command with hash-binding admission checks.
//!
//! This command enforces fail-closed launch admission using explicit hash
//! bindings and emits a replay-verifiable launch receipt.

use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use anyhow::{Result, anyhow};
#[cfg(test)]
use apm2_core::channel::LeakageEstimatorFamily;
#[cfg(test)]
use apm2_core::channel::derive_channel_source_witness;
use apm2_core::channel::{
    BoundaryFlowPolicyBinding, ChannelBoundaryCheck, ChannelBoundaryDefect, ChannelSource,
    ChannelViolationClass, DeclassificationIntentScope, DisclosurePolicyBinding,
    LeakageBudgetReceipt, RedundancyDeclassificationReceipt, TimingChannelBudget,
    decode_channel_context_token, validate_channel_boundary,
};
use apm2_core::crypto::VerifyingKey;
use apm2_core::determinism::canonicalize_json;
#[cfg(test)]
use apm2_core::disclosure::{DisclosureChannelClass, DisclosurePolicyMode};
use apm2_core::fac::{DenyCondition, RoleSpecV2};
use apm2_core::ledger::{Ledger, LedgerError};
use clap::Args;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::client::protocol::SessionClient;
use crate::exit_codes::codes as exit_codes;

/// Maximum allowed size for a CAS object read by this command (64 MiB).
const MAX_CAS_FILE_SIZE: u64 = 64 * 1024 * 1024;
/// Maximum supported `work_id` length.
const MAX_WORK_ID_LENGTH: usize = 512;
/// Maximum supported `role` length.
const MAX_ROLE_LENGTH: usize = 128;
/// Maximum supported `lease_id` length.
const MAX_LEASE_ID_LENGTH: usize = 256;
/// Maximum supported `request_id` length.
const MAX_REQUEST_ID_LENGTH: usize = 256;
/// Maximum accepted channel context token length.
const MAX_CHANNEL_CONTEXT_TOKEN_LENGTH: usize = 8192;
/// Maximum number of defect details surfaced in deny payloads.
const MAX_CHANNEL_DEFECT_DETAILS: usize = 8;
/// Maximum length for each surfaced defect detail.
const MAX_CHANNEL_DEFECT_DETAIL_LENGTH: usize = 160;
/// Launch receipt schema identifier.
const LAUNCH_RECEIPT_SCHEMA_ID: &str = "apm2.launch_receipt.v1";

/// Arguments for `apm2 fac role-launch`.
#[derive(Debug, Args)]
pub struct RoleLaunchArgs {
    /// Work identifier from prior claim.
    pub work_id: String,
    /// Role (implementer, reviewer, etc.).
    pub role: String,
    /// Hex-encoded 32-byte BLAKE3 hash of the `RoleSpec` to bind (REQUIRED).
    #[arg(long)]
    pub role_spec_hash: String,
    /// Hex-encoded 32-byte BLAKE3 hash of the compiled context pack (REQUIRED).
    #[arg(long)]
    pub context_pack_hash: String,
    /// Hex-encoded 32-byte BLAKE3 hash of the capability manifest (REQUIRED).
    #[arg(long)]
    pub capability_manifest_hash: String,
    /// Hex-encoded 32-byte BLAKE3 hash of the policy snapshot (REQUIRED).
    #[arg(long)]
    pub policy_hash: String,
    /// Optional lease ID for authorization.
    #[arg(long)]
    pub lease_id: Option<String>,
    /// Optional daemon-issued request ID bound to the channel context token.
    #[arg(long, requires = "channel_context_token")]
    pub request_id: Option<String>,
    /// Optional daemon-issued base64 channel context token.
    #[arg(long, requires = "request_id")]
    pub channel_context_token: Option<String>,
}

/// System-resolved channel context used for boundary enforcement.
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
struct RoleLaunchChannelContext {
    source: ChannelSource,
    channel_source_witness: Option<[u8; 32]>,
    broker_verified: bool,
    capability_verified: bool,
    context_firewall_verified: bool,
    policy_ledger_verified: bool,
    taint_allow: bool,
    classification_allow: bool,
    declass_receipt_valid: bool,
    declassification_intent: DeclassificationIntentScope,
    redundancy_declassification_receipt: Option<RedundancyDeclassificationReceipt>,
    boundary_flow_policy_binding: Option<BoundaryFlowPolicyBinding>,
    disclosure_policy_binding: Option<DisclosurePolicyBinding>,
    leakage_budget_receipt: Option<LeakageBudgetReceipt>,
    timing_channel_budget: Option<TimingChannelBudget>,
    leakage_budget_policy_max_bits: Option<u64>,
    declared_leakage_budget_bits: Option<u64>,
    timing_budget_policy_max_ticks: Option<u64>,
    declared_timing_budget_ticks: Option<u64>,
}

impl RoleLaunchChannelContext {
    const fn direct_cli_fail_closed() -> Self {
        Self {
            source: ChannelSource::Unknown,
            channel_source_witness: None,
            broker_verified: false,
            capability_verified: false,
            context_firewall_verified: false,
            policy_ledger_verified: false,
            taint_allow: false,
            classification_allow: false,
            declass_receipt_valid: false,
            declassification_intent: DeclassificationIntentScope::Unknown,
            redundancy_declassification_receipt: None,
            boundary_flow_policy_binding: None,
            disclosure_policy_binding: None,
            leakage_budget_receipt: None,
            timing_channel_budget: None,
            leakage_budget_policy_max_bits: None,
            declared_leakage_budget_bits: None,
            timing_budget_policy_max_ticks: None,
            declared_timing_budget_ticks: None,
        }
    }

    #[cfg(test)]
    fn daemon_verified_for_tests() -> Self {
        Self {
            source: ChannelSource::TypedToolIntent,
            channel_source_witness: Some(derive_channel_source_witness(
                ChannelSource::TypedToolIntent,
            )),
            broker_verified: true,
            capability_verified: true,
            context_firewall_verified: true,
            policy_ledger_verified: true,
            taint_allow: true,
            classification_allow: true,
            declass_receipt_valid: true,
            declassification_intent: DeclassificationIntentScope::None,
            redundancy_declassification_receipt: None,
            boundary_flow_policy_binding: Some(BoundaryFlowPolicyBinding {
                policy_digest: [1u8; 32],
                admitted_policy_root_digest: [1u8; 32],
                canonicalizer_tuple_digest: [2u8; 32],
                admitted_canonicalizer_tuple_digest: [2u8; 32],
            }),
            disclosure_policy_binding: Some(DisclosurePolicyBinding {
                required_for_effect: false,
                state_valid: true,
                active_mode: DisclosurePolicyMode::TradeSecretOnly,
                expected_mode: DisclosurePolicyMode::TradeSecretOnly,
                attempted_channel: DisclosureChannelClass::Internal,
                policy_snapshot_digest: [3u8; 32],
                admitted_policy_epoch_root_digest: [3u8; 32],
                policy_epoch: 1,
                phase_id: "pre_federation".to_string(),
                state_reason: "ok".to_string(),
            }),
            leakage_budget_receipt: Some(LeakageBudgetReceipt {
                leakage_bits: 4,
                budget_bits: 8,
                estimator_family: LeakageEstimatorFamily::MutualInformationUpperBound,
                confidence_bps: 9_500,
                confidence_label: "high".to_string(),
            }),
            timing_channel_budget: Some(TimingChannelBudget {
                release_bucket_ticks: 10,
                observed_variance_ticks: 3,
                budget_ticks: 10,
            }),
            leakage_budget_policy_max_bits: Some(8),
            declared_leakage_budget_bits: None,
            timing_budget_policy_max_ticks: Some(10),
            declared_timing_budget_ticks: None,
        }
    }
}

/// Fail-closed denial reasons for role launch admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaunchDenyReason {
    /// `role_spec_hash` is all-zero and therefore missing.
    MissingRoleSpecHash,
    /// `role_spec_hash` could not be resolved in CAS.
    UnresolvableRoleSpec,
    /// `context_pack_hash` is all-zero and therefore missing.
    MissingContextPackHash,
    /// `context_pack_hash` could not be resolved in CAS.
    UnresolvableContextPack,
    /// `capability_manifest_hash` is all-zero and therefore missing.
    MissingCapabilityManifestHash,
    /// `capability_manifest_hash` could not be resolved in CAS.
    UnresolvableCapabilityManifest,
    /// `policy_hash` is all-zero and therefore missing.
    MissingPolicyHash,
    /// `policy_hash` could not be resolved in CAS.
    UnresolvablePolicy,
    /// Policy artifact does not declare a required `work_id` binding.
    MissingPolicyWorkIdBinding,
    /// Policy `work_id` binding does not match the requested work id.
    WorkIdBindingMismatch,
    /// Policy `capability_manifest_hash` binding does not match request.
    CapabilityManifestHashBindingMismatch,
    /// Policy artifact does not declare a required `capability_manifest_hash`
    /// binding.
    MissingPolicyCapabilityManifestBinding,
    /// Capability manifest artifact is malformed or missing declarations.
    InvalidCapabilityManifest {
        /// Validation detail.
        detail: String,
    },
    /// Capability manifest misses role-required capabilities.
    MissingRequiredCapabilities {
        /// Missing capability identifiers.
        missing: Vec<String>,
    },
    /// Channel boundary violations detected before authoritative launch.
    ChannelBoundaryViolation {
        /// Channel violation classes observed in deterministic validation
        /// order.
        violations: Vec<ChannelViolationClass>,
        /// Bounded defect detail payloads.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        defect_details: Vec<String>,
    },
    /// A hash input is malformed.
    InvalidHashFormat {
        /// Input field name.
        field: String,
        /// Validation detail.
        detail: String,
    },
    /// Hash bindings do not form a coherent launch context.
    StaleBindingContext {
        /// Mismatch detail.
        detail: String,
    },
    /// Internal error while evaluating admission.
    InternalError {
        /// Failure detail.
        detail: String,
    },
}

/// Launch receipt payload for replay verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchReceiptV1 {
    /// Schema identifier.
    pub schema_id: String,
    /// Work identifier.
    pub work_id: String,
    /// Role selected for launch.
    pub role: String,
    /// Bound role spec hash.
    pub role_spec_hash: [u8; 32],
    /// Bound context pack hash.
    pub context_pack_hash: [u8; 32],
    /// Bound capability manifest hash.
    pub capability_manifest_hash: [u8; 32],
    /// Bound policy hash.
    pub policy_hash: [u8; 32],
    /// Bound lease identifier used for authorization context.
    pub lease_id: String,
    /// Classified authority channel source used for this launch decision.
    pub channel_source: ChannelSource,
    /// Monotonic timestamp in nanoseconds.
    pub timestamp_ns: u64,
    /// BLAKE3 digest over canonical receipt bytes (excluding this field).
    pub receipt_digest: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LaunchReceiptDigestInput {
    schema_id: String,
    work_id: String,
    role: String,
    role_spec_hash: [u8; 32],
    context_pack_hash: [u8; 32],
    capability_manifest_hash: [u8; 32],
    policy_hash: [u8; 32],
    lease_id: String,
    channel_source: ChannelSource,
    timestamp_ns: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RoleLaunchResponse {
    work_id: String,
    role: String,
    role_spec_hash: String,
    context_pack_hash: String,
    capability_manifest_hash: String,
    policy_hash: String,
    receipt_digest: String,
    receipt_hash: String,
    timestamp_ns: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RoleLaunchErrorResponse {
    code: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    deny_reason: Option<LaunchDenyReason>,
}

#[derive(Debug, Clone, Copy)]
struct ParsedHashes {
    role_spec: [u8; 32],
    context_pack: [u8; 32],
    capability_manifest: [u8; 32],
    policy: [u8; 32],
}

/// Error type for `role-launch` execution.
#[derive(Debug, Clone)]
pub enum RoleLaunchError {
    /// Client-side validation failed.
    Validation { message: String },
    /// Admission was denied with a fail-closed reason.
    Denied { reason: LaunchDenyReason },
    /// Internal processing failed.
    Internal { message: String },
}

impl RoleLaunchError {
    /// Returns the RFC-0018 compatible exit code for this error.
    #[must_use]
    pub const fn exit_code(&self) -> u8 {
        match self {
            Self::Validation { .. } => exit_codes::VALIDATION_ERROR,
            Self::Denied { reason } => {
                if matches!(reason, LaunchDenyReason::InvalidHashFormat { .. }) {
                    exit_codes::VALIDATION_ERROR
                } else {
                    exit_codes::POLICY_DENY
                }
            },
            Self::Internal { .. } => exit_codes::GENERIC_ERROR,
        }
    }

    const fn code(&self) -> &'static str {
        match self {
            Self::Validation { .. } => "validation_error",
            Self::Denied { .. } => "launch_denied",
            Self::Internal { .. } => "internal_error",
        }
    }

    fn message(&self) -> String {
        match self {
            Self::Validation { message } | Self::Internal { message } => message.clone(),
            Self::Denied { reason } => format!("launch denied: {}", deny_reason_message(reason)),
        }
    }

    const fn denied(reason: LaunchDenyReason) -> Self {
        Self::Denied { reason }
    }

    fn validation(message: impl Into<String>) -> Self {
        Self::Validation {
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self::Internal {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for RoleLaunchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message())
    }
}

impl std::error::Error for RoleLaunchError {}

/// Handles `apm2 fac role-launch`.
///
/// This function validates explicit hash-bound launch inputs, executes the
/// fail-closed admission pipeline, emits a deterministic launch receipt, and
/// writes the receipt to CAS.
pub fn handle_role_launch(
    args: &RoleLaunchArgs,
    ledger_path: &Path,
    cas_path: &Path,
    session_socket_path: &Path,
    json: bool,
) -> Result<()> {
    let daemon_verifying_key = resolve_daemon_channel_verifying_key(args, session_socket_path);
    match execute_role_launch_with_daemon_verifying_key(
        args,
        ledger_path,
        cas_path,
        daemon_verifying_key.as_ref(),
    ) {
        Ok(response) => {
            output_success(&response, json);
            Ok(())
        },
        Err(error) => {
            output_error(&error, json);
            Err(anyhow!(error))
        },
    }
}

fn execute_role_launch_with_daemon_verifying_key(
    args: &RoleLaunchArgs,
    ledger_path: &Path,
    cas_path: &Path,
    daemon_verifying_key: Option<&VerifyingKey>,
) -> std::result::Result<RoleLaunchResponse, RoleLaunchError> {
    let channel_context = resolve_channel_context(args, daemon_verifying_key);
    execute_role_launch_with_channel_context(args, ledger_path, cas_path, &channel_context)
}

fn resolve_daemon_channel_verifying_key(
    args: &RoleLaunchArgs,
    session_socket_path: &Path,
) -> Option<VerifyingKey> {
    args.channel_context_token.as_ref()?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .ok()?;
    runtime.block_on(async {
        let client = SessionClient::connect(session_socket_path).await.ok()?;
        let key_bytes = client.daemon_signing_public_key()?;
        apm2_core::crypto::parse_verifying_key(key_bytes).ok()
    })
}

fn resolve_channel_context(
    args: &RoleLaunchArgs,
    daemon_verifying_key: Option<&VerifyingKey>,
) -> RoleLaunchChannelContext {
    let Some(token) = args.channel_context_token.as_deref() else {
        return RoleLaunchChannelContext::direct_cli_fail_closed();
    };
    let Some(daemon_verifying_key) = daemon_verifying_key else {
        return RoleLaunchChannelContext::direct_cli_fail_closed();
    };
    let Some(expected_lease_id) = args.lease_id.as_deref() else {
        return RoleLaunchChannelContext::direct_cli_fail_closed();
    };
    let Some(expected_request_id) = args.request_id.as_deref() else {
        return RoleLaunchChannelContext::direct_cli_fail_closed();
    };
    let Ok(current_time_secs) = UNIX_EPOCH.elapsed().map(|duration| duration.as_secs()) else {
        return RoleLaunchChannelContext::direct_cli_fail_closed();
    };

    if token.len() > MAX_CHANNEL_CONTEXT_TOKEN_LENGTH {
        return RoleLaunchChannelContext::direct_cli_fail_closed();
    }

    let Ok(check) = decode_channel_context_token(
        token,
        daemon_verifying_key,
        expected_lease_id,
        current_time_secs,
        expected_request_id,
    ) else {
        return RoleLaunchChannelContext::direct_cli_fail_closed();
    };

    let Some(witness) = check.channel_source_witness else {
        return RoleLaunchChannelContext::direct_cli_fail_closed();
    };

    if check.source != ChannelSource::TypedToolIntent {
        return RoleLaunchChannelContext::direct_cli_fail_closed();
    }

    RoleLaunchChannelContext {
        source: ChannelSource::TypedToolIntent,
        channel_source_witness: Some(witness),
        broker_verified: check.broker_verified,
        capability_verified: check.capability_verified,
        context_firewall_verified: check.context_firewall_verified,
        policy_ledger_verified: check.policy_ledger_verified,
        taint_allow: check.taint_allow,
        classification_allow: check.classification_allow,
        declass_receipt_valid: check.declass_receipt_valid,
        declassification_intent: check.declassification_intent,
        redundancy_declassification_receipt: check.redundancy_declassification_receipt,
        boundary_flow_policy_binding: check.boundary_flow_policy_binding,
        disclosure_policy_binding: check.disclosure_policy_binding,
        leakage_budget_receipt: check.leakage_budget_receipt,
        timing_channel_budget: check.timing_channel_budget,
        leakage_budget_policy_max_bits: check.leakage_budget_policy_max_bits,
        declared_leakage_budget_bits: check.declared_leakage_budget_bits,
        timing_budget_policy_max_ticks: check.timing_budget_policy_max_ticks,
        declared_timing_budget_ticks: check.declared_timing_budget_ticks,
    }
}

fn execute_role_launch_with_channel_context(
    args: &RoleLaunchArgs,
    ledger_path: &Path,
    cas_path: &Path,
    channel_context: &RoleLaunchChannelContext,
) -> std::result::Result<RoleLaunchResponse, RoleLaunchError> {
    validate_required_bounded("work_id", &args.work_id, MAX_WORK_ID_LENGTH)?;
    validate_required_bounded("role", &args.role, MAX_ROLE_LENGTH)?;
    if let Some(lease_id) = &args.lease_id {
        validate_optional_bounded("lease_id", lease_id, MAX_LEASE_ID_LENGTH)?;
    }
    if let Some(request_id) = &args.request_id {
        validate_optional_bounded("request_id", request_id, MAX_REQUEST_ID_LENGTH)?;
    }

    let hashes = ParsedHashes {
        role_spec: parse_hash_input("role_spec_hash", &args.role_spec_hash)
            .map_err(RoleLaunchError::denied)?,
        context_pack: parse_hash_input("context_pack_hash", &args.context_pack_hash)
            .map_err(RoleLaunchError::denied)?,
        capability_manifest: parse_hash_input(
            "capability_manifest_hash",
            &args.capability_manifest_hash,
        )
        .map_err(RoleLaunchError::denied)?,
        policy: parse_hash_input("policy_hash", &args.policy_hash)
            .map_err(RoleLaunchError::denied)?,
    };

    ensure_cas_open(cas_path)?;
    let ledger = open_ledger(ledger_path)?;

    validate_launch_bindings(
        &args.work_id,
        &args.role,
        hashes.role_spec,
        hashes.context_pack,
        hashes.capability_manifest,
        hashes.policy,
        cas_path,
    )
    .map_err(RoleLaunchError::denied)?;

    enforce_channel_boundary(channel_context).map_err(RoleLaunchError::denied)?;

    let timestamp_ns = derive_receipt_timestamp_ns(&ledger)?;
    let receipt = build_launch_receipt(args, hashes, timestamp_ns, channel_context.source)?;
    let receipt_hash = store_receipt_in_cas(cas_path, &receipt)?;

    Ok(RoleLaunchResponse {
        work_id: args.work_id.clone(),
        role: args.role.clone(),
        role_spec_hash: hex::encode(hashes.role_spec),
        context_pack_hash: hex::encode(hashes.context_pack),
        capability_manifest_hash: hex::encode(hashes.capability_manifest),
        policy_hash: hex::encode(hashes.policy),
        receipt_digest: hex::encode(receipt.receipt_digest),
        receipt_hash: hex::encode(receipt_hash),
        timestamp_ns,
    })
}

fn output_success(response: &RoleLaunchResponse, json_output: bool) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(response).unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        println!("Role launch admitted");
        println!("  Work ID:                   {}", response.work_id);
        println!("  Role:                      {}", response.role);
        println!("  Role Spec Hash:            {}", response.role_spec_hash);
        println!(
            "  Context Pack Hash:         {}",
            response.context_pack_hash
        );
        println!(
            "  Capability Manifest Hash:  {}",
            response.capability_manifest_hash
        );
        println!("  Policy Hash:               {}", response.policy_hash);
        println!("  Receipt Digest:            {}", response.receipt_digest);
        println!("  Receipt Hash:              {}", response.receipt_hash);
        println!("  Timestamp (ns):            {}", response.timestamp_ns);
    }
}

fn output_error(error: &RoleLaunchError, json_output: bool) {
    if json_output {
        let response = RoleLaunchErrorResponse {
            code: error.code().to_string(),
            message: error.message(),
            deny_reason: match error {
                RoleLaunchError::Denied { reason } => Some(reason.clone()),
                _ => None,
            },
        };
        eprintln!(
            "{}",
            serde_json::to_string_pretty(&response).unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        eprintln!("Error: {}", error.message());
    }
}

fn validate_required_bounded(
    field: &str,
    value: &str,
    max_len: usize,
) -> std::result::Result<(), RoleLaunchError> {
    if value.is_empty() {
        return Err(RoleLaunchError::validation(format!(
            "{field} cannot be empty"
        )));
    }
    if value.len() > max_len {
        return Err(RoleLaunchError::validation(format!(
            "{field} length {} exceeds maximum {}",
            value.len(),
            max_len
        )));
    }
    Ok(())
}

fn validate_optional_bounded(
    field: &str,
    value: &str,
    max_len: usize,
) -> std::result::Result<(), RoleLaunchError> {
    if value.is_empty() {
        return Err(RoleLaunchError::validation(format!(
            "{field} cannot be empty"
        )));
    }
    if value.len() > max_len {
        return Err(RoleLaunchError::validation(format!(
            "{field} length {} exceeds maximum {}",
            value.len(),
            max_len
        )));
    }
    Ok(())
}

fn parse_hash_input(field: &str, value: &str) -> std::result::Result<[u8; 32], LaunchDenyReason> {
    parse_hex_hash_literal(field, value).map_err(|detail| LaunchDenyReason::InvalidHashFormat {
        field: field.to_string(),
        detail,
    })
}

fn enforce_channel_boundary(
    channel_context: &RoleLaunchChannelContext,
) -> std::result::Result<(), LaunchDenyReason> {
    let check = ChannelBoundaryCheck {
        source: channel_context.source,
        channel_source_witness: channel_context.channel_source_witness,
        broker_verified: channel_context.broker_verified,
        capability_verified: channel_context.capability_verified,
        context_firewall_verified: channel_context.context_firewall_verified,
        policy_ledger_verified: channel_context.policy_ledger_verified,
        taint_allow: channel_context.taint_allow,
        classification_allow: channel_context.classification_allow,
        declass_receipt_valid: channel_context.declass_receipt_valid,
        declassification_intent: channel_context.declassification_intent,
        redundancy_declassification_receipt: channel_context
            .redundancy_declassification_receipt
            .clone(),
        boundary_flow_policy_binding: channel_context.boundary_flow_policy_binding.clone(),
        disclosure_policy_binding: channel_context.disclosure_policy_binding.clone(),
        leakage_budget_receipt: channel_context.leakage_budget_receipt.clone(),
        timing_channel_budget: channel_context.timing_channel_budget.clone(),
        leakage_budget_policy_max_bits: channel_context.leakage_budget_policy_max_bits,
        declared_leakage_budget_bits: channel_context.declared_leakage_budget_bits,
        timing_budget_policy_max_ticks: channel_context.timing_budget_policy_max_ticks,
        declared_timing_budget_ticks: channel_context.declared_timing_budget_ticks,
        token_binding: None,
    };
    let defects = validate_channel_boundary(&check);
    if defects.is_empty() {
        return Ok(());
    }

    let defect_details = bounded_channel_defect_details(&defects);
    let mut violations = Vec::new();
    for defect in defects {
        if !violations.contains(&defect.violation_class) {
            violations.push(defect.violation_class);
        }
    }

    Err(LaunchDenyReason::ChannelBoundaryViolation {
        violations,
        defect_details,
    })
}

fn bounded_channel_defect_details(defects: &[ChannelBoundaryDefect]) -> Vec<String> {
    defects
        .iter()
        .take(MAX_CHANNEL_DEFECT_DETAILS)
        .map(|defect| {
            let label = channel_violation_label(defect.violation_class);
            truncate_boundary_detail(format!("{label}: {}", defect.detail))
        })
        .collect()
}

fn truncate_boundary_detail(mut detail: String) -> String {
    if detail.len() <= MAX_CHANNEL_DEFECT_DETAIL_LENGTH {
        return detail;
    }
    let mut boundary = MAX_CHANNEL_DEFECT_DETAIL_LENGTH;
    while !detail.is_char_boundary(boundary) {
        boundary = boundary.saturating_sub(1);
    }
    detail.truncate(boundary);
    detail
}

fn parse_hex_hash_literal(field: &str, value: &str) -> std::result::Result<[u8; 32], String> {
    if value.len() != 64 {
        return Err(format!(
            "{field} must be exactly 64 hex characters; got {}",
            value.len()
        ));
    }

    let decoded =
        hex::decode(value).map_err(|error| format!("{field} contains non-hex data: {error}"))?;
    decoded
        .as_slice()
        .try_into()
        .map_err(|_| format!("{field} must decode to 32 bytes"))
}

fn ensure_cas_open(cas_path: &Path) -> std::result::Result<(), RoleLaunchError> {
    let objects_path = cas_path.join("objects");
    if !objects_path.exists() {
        return Err(RoleLaunchError::internal(format!(
            "CAS objects directory not found: {}",
            objects_path.display()
        )));
    }
    Ok(())
}

fn open_ledger(ledger_path: &Path) -> std::result::Result<Ledger, RoleLaunchError> {
    if !ledger_path.exists() {
        return Err(RoleLaunchError::internal(format!(
            "ledger not found: {}",
            ledger_path.display()
        )));
    }
    Ledger::open(ledger_path)
        .map_err(|error| RoleLaunchError::internal(format!("failed to open ledger: {error}")))
}

fn derive_receipt_timestamp_ns(ledger: &Ledger) -> std::result::Result<u64, RoleLaunchError> {
    let head = ledger.head_sync().map_err(|error| {
        RoleLaunchError::internal(format!("failed to query ledger head: {error}"))
    })?;
    if head == 0 {
        return Err(RoleLaunchError::internal(
            "ledger has no events; cannot derive monotonic timestamp",
        ));
    }

    let tail_events = ledger.read_from(head, 1).map_err(|error| {
        RoleLaunchError::internal(format!("failed to read ledger tail: {error}"))
    })?;
    let latest_event = tail_events.last().ok_or_else(|| {
        RoleLaunchError::internal("ledger tail read returned no events at head cursor")
    })?;

    latest_event.timestamp_ns.checked_add(1).ok_or_else(|| {
        RoleLaunchError::internal("timestamp overflow while deriving launch receipt timestamp")
    })
}

fn build_launch_receipt(
    args: &RoleLaunchArgs,
    hashes: ParsedHashes,
    timestamp_ns: u64,
    channel_source: ChannelSource,
) -> std::result::Result<LaunchReceiptV1, RoleLaunchError> {
    let lease_id = args.lease_id.clone().unwrap_or_default();
    let digest_input = LaunchReceiptDigestInput {
        schema_id: LAUNCH_RECEIPT_SCHEMA_ID.to_string(),
        work_id: args.work_id.clone(),
        role: args.role.clone(),
        role_spec_hash: hashes.role_spec,
        context_pack_hash: hashes.context_pack,
        capability_manifest_hash: hashes.capability_manifest,
        policy_hash: hashes.policy,
        lease_id: lease_id.clone(),
        channel_source,
        timestamp_ns,
    };

    let digest_bytes = canonical_json_bytes(&digest_input)?;
    let receipt_digest = *blake3::hash(&digest_bytes).as_bytes();

    Ok(LaunchReceiptV1 {
        schema_id: LAUNCH_RECEIPT_SCHEMA_ID.to_string(),
        work_id: args.work_id.clone(),
        role: args.role.clone(),
        role_spec_hash: hashes.role_spec,
        context_pack_hash: hashes.context_pack,
        capability_manifest_hash: hashes.capability_manifest,
        policy_hash: hashes.policy,
        lease_id,
        channel_source,
        timestamp_ns,
        receipt_digest,
    })
}

fn canonical_json_bytes<T: Serialize>(value: &T) -> std::result::Result<Vec<u8>, RoleLaunchError> {
    let json = serde_json::to_string(value)
        .map_err(|error| RoleLaunchError::internal(format!("failed to serialize JSON: {error}")))?;
    let canonical = canonicalize_json(&json).map_err(|error| {
        RoleLaunchError::internal(format!("failed to canonicalize JSON: {error}"))
    })?;
    Ok(canonical.into_bytes())
}

fn store_receipt_in_cas(
    cas_path: &Path,
    receipt: &LaunchReceiptV1,
) -> std::result::Result<[u8; 32], RoleLaunchError> {
    let bytes = canonical_json_bytes(receipt)?;
    store_bytes_in_cas(cas_path, &bytes)
}

fn store_bytes_in_cas(
    cas_path: &Path,
    bytes: &[u8],
) -> std::result::Result<[u8; 32], RoleLaunchError> {
    if bytes.is_empty() {
        return Err(RoleLaunchError::internal(
            "refusing to store empty CAS content",
        ));
    }
    if bytes.len() as u64 > MAX_CAS_FILE_SIZE {
        return Err(RoleLaunchError::internal(format!(
            "CAS object size {} exceeds local safety cap {}",
            bytes.len(),
            MAX_CAS_FILE_SIZE
        )));
    }

    let hash = *blake3::hash(bytes).as_bytes();
    let object_path = cas_object_path(cas_path, &hash);
    if let Some(parent) = object_path.parent() {
        crate::commands::fac_permissions::ensure_dir_with_mode(parent).map_err(|error| {
            RoleLaunchError::internal(format!(
                "failed to create CAS object directory '{}': {error}",
                parent.display()
            ))
        })?;
    }

    if object_path.exists() {
        let existing = fs::read(&object_path).map_err(|error| {
            RoleLaunchError::internal(format!(
                "failed reading existing CAS object '{}': {error}",
                object_path.display()
            ))
        })?;
        if existing != bytes {
            return Err(RoleLaunchError::internal(format!(
                "CAS collision at '{}': existing bytes differ for identical hash",
                object_path.display()
            )));
        }
        return Ok(hash);
    }

    fs::write(&object_path, bytes).map_err(|error| {
        RoleLaunchError::internal(format!(
            "failed writing CAS object '{}': {error}",
            object_path.display()
        ))
    })?;
    Ok(hash)
}

fn cas_object_path(cas_path: &Path, hash: &[u8; 32]) -> PathBuf {
    let hex_hash = hex::encode(hash);
    let (prefix, suffix) = hex_hash.split_at(4);
    cas_path.join("objects").join(prefix).join(suffix)
}

fn read_cas_object(cas_path: &Path, hash: &[u8; 32]) -> std::result::Result<Vec<u8>, String> {
    let path = cas_object_path(cas_path, hash);
    let mut file = fs::File::open(&path)
        .map_err(|error| format!("failed to open CAS object '{}': {error}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("failed to read CAS metadata '{}': {error}", path.display()))?;
    if metadata.len() == 0 {
        return Err(format!("CAS object '{}' is empty", path.display()));
    }
    if metadata.len() > MAX_CAS_FILE_SIZE {
        return Err(format!(
            "CAS object '{}' exceeds limit ({} > {})",
            path.display(),
            metadata.len(),
            MAX_CAS_FILE_SIZE
        ));
    }

    let mut bytes = Vec::new();
    let mut limited_reader = (&mut file).take(MAX_CAS_FILE_SIZE + 1);
    limited_reader
        .read_to_end(&mut bytes)
        .map_err(|error| format!("failed to read CAS object '{}': {error}", path.display()))?;
    if bytes.is_empty() {
        return Err(format!("CAS object '{}' is empty", path.display()));
    }
    if bytes.len() as u64 > MAX_CAS_FILE_SIZE {
        return Err(format!(
            "CAS object '{}' exceeds limit ({} > {})",
            path.display(),
            bytes.len(),
            MAX_CAS_FILE_SIZE
        ));
    }

    let computed_hash = *blake3::hash(&bytes).as_bytes();
    if !bool::from(computed_hash.ct_eq(hash)) {
        return Err(format!(
            "CAS object '{}' hash mismatch (expected {}, got {})",
            path.display(),
            hex::encode(hash),
            hex::encode(computed_hash)
        ));
    }

    Ok(bytes)
}

fn resolve_required_hash(
    cas_path: &Path,
    hash: [u8; 32],
    missing_reason: LaunchDenyReason,
    unresolvable_reason: LaunchDenyReason,
) -> std::result::Result<Vec<u8>, LaunchDenyReason> {
    if bool::from(hash.ct_eq(&[0u8; 32])) {
        return Err(missing_reason);
    }
    read_cas_object(cas_path, &hash).map_err(|_| unresolvable_reason)
}

fn validate_launch_bindings(
    work_id: &str,
    role: &str,
    role_spec_hash: [u8; 32],
    context_pack_hash: [u8; 32],
    capability_manifest_hash: [u8; 32],
    policy_hash: [u8; 32],
    cas_path: &Path,
) -> std::result::Result<(), LaunchDenyReason> {
    let role_spec_bytes = resolve_required_hash(
        cas_path,
        role_spec_hash,
        LaunchDenyReason::MissingRoleSpecHash,
        LaunchDenyReason::UnresolvableRoleSpec,
    )?;
    let _context_pack_bytes = resolve_required_hash(
        cas_path,
        context_pack_hash,
        LaunchDenyReason::MissingContextPackHash,
        LaunchDenyReason::UnresolvableContextPack,
    )?;
    let capability_manifest_bytes = resolve_required_hash(
        cas_path,
        capability_manifest_hash,
        LaunchDenyReason::MissingCapabilityManifestHash,
        LaunchDenyReason::UnresolvableCapabilityManifest,
    )?;
    let policy_bytes = resolve_required_hash(
        cas_path,
        policy_hash,
        LaunchDenyReason::MissingPolicyHash,
        LaunchDenyReason::UnresolvablePolicy,
    )?;

    validate_cross_binding_consistency(
        work_id,
        role,
        ParsedHashes {
            role_spec: role_spec_hash,
            context_pack: context_pack_hash,
            capability_manifest: capability_manifest_hash,
            policy: policy_hash,
        },
        &role_spec_bytes,
        &capability_manifest_bytes,
        &policy_bytes,
    )
}

fn validate_cross_binding_consistency(
    work_id: &str,
    role: &str,
    hashes: ParsedHashes,
    role_spec_bytes: &[u8],
    capability_manifest_bytes: &[u8],
    policy_bytes: &[u8],
) -> std::result::Result<(), LaunchDenyReason> {
    let role_spec: RoleSpecV2 = serde_json::from_slice(role_spec_bytes).map_err(|error| {
        LaunchDenyReason::StaleBindingContext {
            detail: format!("role_spec artifact is not a valid RoleSpecV2 document: {error}"),
        }
    })?;
    role_spec
        .validate()
        .map_err(|error| LaunchDenyReason::StaleBindingContext {
            detail: format!("role_spec artifact failed validation: {error}"),
        })?;

    for condition in [
        DenyCondition::MissingAuthorityContext,
        DenyCondition::StaleAuthorityContext,
        DenyCondition::UnverifiableContextHash,
    ] {
        if !role_spec.deny_taxonomy.contains_key(&condition) {
            return Err(LaunchDenyReason::StaleBindingContext {
                detail: format!(
                    "role_spec deny taxonomy missing required context condition '{condition}'"
                ),
            });
        }
    }

    let requested_role = normalize_role(role);
    let role_type = normalize_role(&role_spec.role_type.to_string());
    let role_id = normalize_role(&role_spec.role_id);
    if requested_role != role_type && requested_role != role_id {
        return Err(LaunchDenyReason::StaleBindingContext {
            detail: format!(
                "requested role '{}' does not match role_spec role_id '{}' / role_type '{}'",
                role, role_spec.role_id, role_spec.role_type
            ),
        });
    }

    let policy_value: serde_json::Value =
        serde_json::from_slice(policy_bytes).map_err(|error| {
            LaunchDenyReason::StaleBindingContext {
                detail: format!("policy artifact is not valid JSON: {error}"),
            }
        })?;
    let policy_object =
        policy_value
            .as_object()
            .ok_or_else(|| LaunchDenyReason::StaleBindingContext {
                detail: "policy artifact must be a JSON object".to_string(),
            })?;
    validate_policy_work_binding(policy_object, work_id)?;

    let policy_role_spec_hash = extract_policy_hash(policy_object, "role_spec_hash")?;
    if !bool::from(policy_role_spec_hash.ct_eq(&hashes.role_spec)) {
        return Err(LaunchDenyReason::StaleBindingContext {
            detail: format!(
                "policy role_spec_hash {} does not match requested role_spec_hash {}",
                hex::encode(policy_role_spec_hash),
                hex::encode(hashes.role_spec)
            ),
        });
    }

    let policy_context_pack_hash = extract_policy_hash(policy_object, "context_pack_hash")?;
    if !bool::from(policy_context_pack_hash.ct_eq(&hashes.context_pack)) {
        return Err(LaunchDenyReason::StaleBindingContext {
            detail: format!(
                "policy context_pack_hash {} does not match requested context_pack_hash {}",
                hex::encode(policy_context_pack_hash),
                hex::encode(hashes.context_pack)
            ),
        });
    }

    if let Some(policy_role) = policy_object
        .get("role")
        .and_then(serde_json::Value::as_str)
    {
        if normalize_role(policy_role) != requested_role {
            return Err(LaunchDenyReason::StaleBindingContext {
                detail: format!(
                    "policy role '{policy_role}' does not match requested role '{role}'"
                ),
            });
        }
    }

    if let Some(policy_hash_value) = policy_object
        .get("policy_hash")
        .and_then(serde_json::Value::as_str)
    {
        let embedded_policy_hash = parse_hex_hash_literal("policy.policy_hash", policy_hash_value)
            .map_err(|detail| LaunchDenyReason::StaleBindingContext { detail })?;
        if !bool::from(embedded_policy_hash.ct_eq(&hashes.policy)) {
            return Err(LaunchDenyReason::StaleBindingContext {
                detail: format!(
                    "embedded policy_hash {} does not match requested policy_hash {}",
                    hex::encode(embedded_policy_hash),
                    hex::encode(hashes.policy)
                ),
            });
        }
    }
    validate_policy_capability_manifest_binding(policy_object, hashes.capability_manifest)?;
    validate_role_required_capabilities(&role_spec, capability_manifest_bytes)?;

    Ok(())
}

fn validate_policy_work_binding(
    policy_object: &serde_json::Map<String, serde_json::Value>,
    work_id: &str,
) -> std::result::Result<(), LaunchDenyReason> {
    let policy_work_id = policy_object
        .get("work_id")
        .and_then(serde_json::Value::as_str)
        .ok_or(LaunchDenyReason::MissingPolicyWorkIdBinding)?;
    if policy_work_id != work_id {
        return Err(LaunchDenyReason::WorkIdBindingMismatch);
    }
    Ok(())
}

fn validate_policy_capability_manifest_binding(
    policy_object: &serde_json::Map<String, serde_json::Value>,
    capability_manifest_hash: [u8; 32],
) -> std::result::Result<(), LaunchDenyReason> {
    let Some(policy_capability_manifest_hash) = policy_object
        .get("capability_manifest_hash")
        .and_then(serde_json::Value::as_str)
    else {
        return Err(LaunchDenyReason::MissingPolicyCapabilityManifestBinding);
    };
    let policy_hash =
        parse_hex_hash_literal("capability_manifest_hash", policy_capability_manifest_hash)
            .map_err(|detail| LaunchDenyReason::StaleBindingContext {
                detail: format!("invalid 'capability_manifest_hash' in policy artifact: {detail}"),
            })?;
    if !bool::from(policy_hash.ct_eq(&capability_manifest_hash)) {
        return Err(LaunchDenyReason::CapabilityManifestHashBindingMismatch);
    }
    Ok(())
}

fn validate_role_required_capabilities(
    role_spec: &RoleSpecV2,
    capability_manifest_bytes: &[u8],
) -> std::result::Result<(), LaunchDenyReason> {
    if role_spec.required_capabilities.is_empty() {
        return Ok(());
    }

    let declared_capabilities = collect_declared_capabilities(capability_manifest_bytes)?;
    let mut missing = Vec::new();
    for required_capability in role_spec.required_capabilities.keys() {
        let aliases = capability_aliases(required_capability);
        if !aliases
            .iter()
            .any(|alias| declared_capabilities.contains(alias))
        {
            missing.push(required_capability.clone());
        }
    }

    if missing.is_empty() {
        Ok(())
    } else {
        Err(LaunchDenyReason::MissingRequiredCapabilities { missing })
    }
}

fn collect_declared_capabilities(
    capability_manifest_bytes: &[u8],
) -> std::result::Result<BTreeSet<String>, LaunchDenyReason> {
    let manifest_value: serde_json::Value = serde_json::from_slice(capability_manifest_bytes)
        .map_err(|error| LaunchDenyReason::InvalidCapabilityManifest {
            detail: format!("capability manifest artifact is not valid JSON: {error}"),
        })?;
    let manifest_object =
        manifest_value
            .as_object()
            .ok_or_else(|| LaunchDenyReason::InvalidCapabilityManifest {
                detail: "capability manifest artifact must be a JSON object".to_string(),
            })?;

    let mut declared = BTreeSet::new();
    if let Some(capabilities_value) = manifest_object.get("capabilities") {
        collect_capability_aliases_from_capability_objects(capabilities_value, &mut declared)?;
    }
    if let Some(granted_value) = manifest_object.get("granted_capabilities") {
        collect_capability_aliases_from_array(
            "granted_capabilities",
            granted_value,
            &mut declared,
        )?;
    }
    if let Some(tool_allowlist_value) = manifest_object.get("tool_allowlist") {
        collect_capability_aliases_from_array(
            "tool_allowlist",
            tool_allowlist_value,
            &mut declared,
        )?;
    }

    if declared.is_empty() {
        return Err(LaunchDenyReason::InvalidCapabilityManifest {
            detail: "capability manifest artifact does not declare any capabilities".to_string(),
        });
    }
    Ok(declared)
}

fn collect_capability_aliases_from_array(
    field: &str,
    value: &serde_json::Value,
    declared: &mut BTreeSet<String>,
) -> std::result::Result<(), LaunchDenyReason> {
    let entries = value
        .as_array()
        .ok_or_else(|| LaunchDenyReason::InvalidCapabilityManifest {
            detail: format!("'{field}' in capability manifest must be an array"),
        })?;
    for (index, entry) in entries.iter().enumerate() {
        let capability =
            entry
                .as_str()
                .ok_or_else(|| LaunchDenyReason::InvalidCapabilityManifest {
                    detail: format!("'{field}[{index}]' in capability manifest must be a string"),
                })?;
        add_capability_aliases(declared, capability);
    }
    Ok(())
}

fn collect_capability_aliases_from_capability_objects(
    value: &serde_json::Value,
    declared: &mut BTreeSet<String>,
) -> std::result::Result<(), LaunchDenyReason> {
    let capabilities =
        value
            .as_array()
            .ok_or_else(|| LaunchDenyReason::InvalidCapabilityManifest {
                detail: "'capabilities' in capability manifest must be an array".to_string(),
            })?;

    for (index, capability_entry) in capabilities.iter().enumerate() {
        match capability_entry {
            serde_json::Value::String(capability) => add_capability_aliases(declared, capability),
            serde_json::Value::Object(object) => {
                let mut found = false;
                for field in ["capability_id", "id", "name", "tool_class"] {
                    if let Some(field_value) = object.get(field) {
                        let capability =
                            field_value.as_str().ok_or_else(|| {
                                LaunchDenyReason::InvalidCapabilityManifest {
                                    detail: format!(
                                        "'capabilities[{index}].{field}' in capability manifest must be a string"
                                    ),
                                }
                            })?;
                        add_capability_aliases(declared, capability);
                        found = true;
                    }
                }
                if !found {
                    return Err(LaunchDenyReason::InvalidCapabilityManifest {
                        detail: format!(
                            "'capabilities[{index}]' in capability manifest is missing a recognizable capability identifier"
                        ),
                    });
                }
            },
            _ => {
                return Err(LaunchDenyReason::InvalidCapabilityManifest {
                    detail: format!(
                        "'capabilities[{index}]' in capability manifest must be a string or object"
                    ),
                });
            },
        }
    }

    Ok(())
}

fn add_capability_aliases(declared: &mut BTreeSet<String>, capability: &str) {
    for alias in capability_aliases(capability) {
        declared.insert(alias);
    }
}

fn capability_aliases(capability: &str) -> BTreeSet<String> {
    let mut aliases = BTreeSet::new();
    let normalized = capability.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return aliases;
    }

    aliases.insert(normalized.clone());
    if let Some(stripped) = normalized.strip_prefix("kernel.") {
        aliases.insert(stripped.to_string());
    } else {
        aliases.insert(format!("kernel.{normalized}"));
    }
    aliases.extend(tool_class_aliases(&normalized));
    aliases
}

fn tool_class_aliases(capability: &str) -> BTreeSet<String> {
    let mut aliases = BTreeSet::new();
    let normalized = capability.replace('_', "");

    match normalized.as_str() {
        "read" => {
            aliases.insert("fs.read".to_string());
            aliases.insert("kernel.fs.read".to_string());
        },
        "write" => {
            aliases.insert("fs.write".to_string());
            aliases.insert("kernel.fs.write".to_string());
        },
        "execute" | "exec" => {
            aliases.insert("shell.exec".to_string());
            aliases.insert("kernel.shell.exec".to_string());
        },
        "listfiles" | "ls" => {
            aliases.insert("fs.list".to_string());
            aliases.insert("kernel.fs.list".to_string());
        },
        "search" | "grep" => {
            aliases.insert("fs.search".to_string());
            aliases.insert("kernel.fs.search".to_string());
        },
        "artifact" | "cas" => {
            aliases.insert("artifact.fetch".to_string());
            aliases.insert("kernel.artifact.fetch".to_string());
        },
        _ => {},
    }
    aliases
}

fn extract_policy_hash(
    policy_object: &serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> std::result::Result<[u8; 32], LaunchDenyReason> {
    let value = policy_object
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| LaunchDenyReason::StaleBindingContext {
            detail: format!("policy artifact missing required '{field}' binding"),
        })?;
    parse_hex_hash_literal(field, value).map_err(|detail| LaunchDenyReason::StaleBindingContext {
        detail: format!("invalid '{field}' in policy artifact: {detail}"),
    })
}

fn normalize_role(role: &str) -> String {
    role.trim().to_ascii_lowercase().replace('-', "_")
}

fn deny_reason_message(reason: &LaunchDenyReason) -> String {
    match reason {
        LaunchDenyReason::MissingRoleSpecHash => "missing role_spec_hash".to_string(),
        LaunchDenyReason::UnresolvableRoleSpec => {
            "role_spec_hash is not resolvable in CAS".to_string()
        },
        LaunchDenyReason::MissingContextPackHash => "missing context_pack_hash".to_string(),
        LaunchDenyReason::UnresolvableContextPack => {
            "context_pack_hash is not resolvable in CAS".to_string()
        },
        LaunchDenyReason::MissingCapabilityManifestHash => {
            "missing capability_manifest_hash".to_string()
        },
        LaunchDenyReason::UnresolvableCapabilityManifest => {
            "capability_manifest_hash is not resolvable in CAS".to_string()
        },
        LaunchDenyReason::MissingPolicyHash => "missing policy_hash".to_string(),
        LaunchDenyReason::UnresolvablePolicy => "policy_hash is not resolvable in CAS".to_string(),
        LaunchDenyReason::MissingPolicyWorkIdBinding => {
            "policy artifact missing required work_id binding".to_string()
        },
        LaunchDenyReason::WorkIdBindingMismatch => {
            "policy work_id binding does not match requested work_id".to_string()
        },
        LaunchDenyReason::CapabilityManifestHashBindingMismatch => {
            "policy capability_manifest_hash does not match requested capability_manifest_hash"
                .to_string()
        },
        LaunchDenyReason::MissingPolicyCapabilityManifestBinding => {
            "policy artifact missing required capability_manifest_hash binding".to_string()
        },
        LaunchDenyReason::InvalidCapabilityManifest { detail } => {
            format!("invalid capability manifest: {detail}")
        },
        LaunchDenyReason::MissingRequiredCapabilities { missing } => {
            format!(
                "capability manifest missing role-required capabilities: {}",
                missing.join(", ")
            )
        },
        LaunchDenyReason::ChannelBoundaryViolation {
            violations,
            defect_details,
        } => {
            if violations.is_empty() {
                "channel boundary violation".to_string()
            } else {
                let labels = violations
                    .iter()
                    .map(|violation| channel_violation_label(*violation))
                    .collect::<Vec<_>>()
                    .join(", ");
                if defect_details.is_empty() {
                    format!("channel boundary violation: {labels}")
                } else {
                    format!(
                        "channel boundary violation: {labels}; details: {}",
                        defect_details.join(" | ")
                    )
                }
            }
        },
        LaunchDenyReason::InvalidHashFormat { field, detail } => {
            format!("invalid hash format for '{field}': {detail}")
        },
        LaunchDenyReason::StaleBindingContext { detail } => {
            format!("stale binding context: {detail}")
        },
        LaunchDenyReason::InternalError { detail } => {
            format!("internal launch binding error: {detail}")
        },
    }
}

const fn channel_violation_label(violation: ChannelViolationClass) -> &'static str {
    match violation {
        ChannelViolationClass::UntypedChannelSource => "untyped_channel_source",
        ChannelViolationClass::BrokerBypassDetected => "broker_bypass_detected",
        ChannelViolationClass::CapabilityNotVerified => "capability_not_verified",
        ChannelViolationClass::ContextFirewallNotVerified => "context_firewall_not_verified",
        ChannelViolationClass::MissingChannelMetadata => "missing_channel_metadata",
        ChannelViolationClass::UnknownChannelSource => "unknown_channel_source",
        ChannelViolationClass::PolicyNotLedgerVerified => "policy_not_ledger_verified",
        ChannelViolationClass::TaintNotAdmitted => "taint_not_admitted",
        ChannelViolationClass::ClassificationNotAdmitted => "classification_not_admitted",
        ChannelViolationClass::DeclassificationReceiptInvalid => "declassification_receipt_invalid",
        ChannelViolationClass::UnknownOrUnscopedDeclassificationIntent => {
            "unknown_or_unscoped_declassification_intent"
        },
        ChannelViolationClass::PolicyDigestBindingMismatch => "policy_digest_binding_mismatch",
        ChannelViolationClass::CanonicalizerTupleBindingMismatch => {
            "canonicalizer_tuple_binding_mismatch"
        },
        ChannelViolationClass::LeakageBudgetExceeded => "leakage_budget_exceeded",
        ChannelViolationClass::TimingChannelBudgetExceeded => "timing_channel_budget_exceeded",
        ChannelViolationClass::DisclosurePolicyStateInvalid => "disclosure_policy_state_invalid",
        ChannelViolationClass::DisclosurePolicyModeMismatch => "disclosure_policy_mode_mismatch",
        ChannelViolationClass::DisclosurePolicyDigestBindingMismatch => {
            "disclosure_policy_digest_binding_mismatch"
        },
        ChannelViolationClass::DisclosureChannelNotAdmitted => "disclosure_channel_not_admitted",
    }
}

impl From<LedgerError> for RoleLaunchError {
    fn from(error: LedgerError) -> Self {
        Self::internal(format!("ledger error: {error}"))
    }
}

#[cfg(test)]
mod tests {
    use apm2_core::channel::issue_channel_context_token;
    use apm2_core::crypto::Signer;
    use apm2_core::fac::fac_workobject_implementor_v2_role_contract;
    use apm2_core::ledger::EventRecord;

    use super::*;

    struct TestEnv {
        _tempdir: tempfile::TempDir,
        ledger_path: PathBuf,
        cas_path: PathBuf,
        args: RoleLaunchArgs,
        channel_context: RoleLaunchChannelContext,
    }

    fn store_capability_manifest(cas_path: &Path, capability_ids: &[String]) -> [u8; 32] {
        let capabilities: Vec<serde_json::Value> = capability_ids
            .iter()
            .map(|capability_id| serde_json::json!({ "capability_id": capability_id }))
            .collect();
        let payload = serde_json::json!({
            "schema": "apm2.capability_manifest.v1",
            "schema_version": "1.0.0",
            "capabilities": capabilities,
        });
        let bytes = canonical_json_bytes(&payload)
            .expect("capability manifest payload canonicalization should succeed");
        store_bytes_in_cas(cas_path, &bytes).expect("capability manifest should store")
    }

    fn store_policy_snapshot(
        cas_path: &Path,
        work_id: Option<&str>,
        role: &str,
        role_spec_hash: &str,
        context_pack_hash: &str,
        capability_manifest_hash: Option<&str>,
    ) -> [u8; 32] {
        let mut policy_payload = serde_json::Map::new();
        policy_payload.insert(
            "schema_id".to_string(),
            serde_json::json!("apm2.policy_snapshot.v1"),
        );
        policy_payload.insert(
            "role_spec_hash".to_string(),
            serde_json::json!(role_spec_hash),
        );
        policy_payload.insert(
            "context_pack_hash".to_string(),
            serde_json::json!(context_pack_hash),
        );
        policy_payload.insert("role".to_string(), serde_json::json!(role));
        if let Some(work_id) = work_id {
            policy_payload.insert("work_id".to_string(), serde_json::json!(work_id));
        }
        if let Some(capability_manifest_hash) = capability_manifest_hash {
            policy_payload.insert(
                "capability_manifest_hash".to_string(),
                serde_json::json!(capability_manifest_hash),
            );
        }

        let policy_bytes = canonical_json_bytes(&serde_json::Value::Object(policy_payload))
            .expect("policy payload canonicalization should succeed");
        store_bytes_in_cas(cas_path, &policy_bytes).expect("policy should store")
    }

    fn setup_test_env() -> TestEnv {
        let tempdir = tempfile::TempDir::new().expect("temp dir should create");
        let cas_path = tempdir.path().join("cas");
        crate::commands::fac_permissions::ensure_dir_with_mode(&cas_path.join("objects"))
            .expect("CAS objects dir should create");

        let ledger_path = tempdir.path().join("ledger.db");
        let ledger = Ledger::open(&ledger_path).expect("ledger should open");
        let bootstrap = EventRecord::with_timestamp(
            "bootstrap",
            "bootstrap-session",
            "bootstrap-actor",
            b"{}".to_vec(),
            1_000_000_000,
        );
        ledger
            .append(&bootstrap)
            .expect("bootstrap event should append");

        let role_spec = fac_workobject_implementor_v2_role_contract();
        let role_spec_bytes = serde_json::to_vec(&role_spec).expect("role spec should serialize");
        let role_spec_hash =
            store_bytes_in_cas(&cas_path, &role_spec_bytes).expect("role spec should store");

        let context_pack_hash =
            store_bytes_in_cas(&cas_path, b"context-pack").expect("context pack should store");
        let required_capability_ids: Vec<String> =
            role_spec.required_capabilities.keys().cloned().collect();
        let capability_manifest_hash =
            store_capability_manifest(&cas_path, &required_capability_ids);

        let role_spec_hash_hex = hex::encode(role_spec_hash);
        let context_pack_hash_hex = hex::encode(context_pack_hash);
        let capability_manifest_hash_hex = hex::encode(capability_manifest_hash);
        let policy_hash = store_policy_snapshot(
            &cas_path,
            Some("W-TEST-001"),
            "implementer",
            &role_spec_hash_hex,
            &context_pack_hash_hex,
            Some(&capability_manifest_hash_hex),
        );

        let args = RoleLaunchArgs {
            work_id: "W-TEST-001".to_string(),
            role: "implementer".to_string(),
            role_spec_hash: role_spec_hash_hex,
            context_pack_hash: context_pack_hash_hex,
            capability_manifest_hash: capability_manifest_hash_hex,
            policy_hash: hex::encode(policy_hash),
            lease_id: Some("L-TEST-001".to_string()),
            request_id: None,
            channel_context_token: None,
        };

        TestEnv {
            _tempdir: tempdir,
            ledger_path,
            cas_path,
            args,
            channel_context: RoleLaunchChannelContext::daemon_verified_for_tests(),
        }
    }

    fn daemon_admitted_boundary_check() -> ChannelBoundaryCheck {
        ChannelBoundaryCheck {
            source: ChannelSource::TypedToolIntent,
            channel_source_witness: Some(derive_channel_source_witness(
                ChannelSource::TypedToolIntent,
            )),
            broker_verified: true,
            capability_verified: true,
            context_firewall_verified: true,
            policy_ledger_verified: true,
            taint_allow: true,
            classification_allow: true,
            declass_receipt_valid: true,
            declassification_intent: DeclassificationIntentScope::None,
            redundancy_declassification_receipt: None,
            boundary_flow_policy_binding: Some(BoundaryFlowPolicyBinding {
                policy_digest: [1u8; 32],
                admitted_policy_root_digest: [1u8; 32],
                canonicalizer_tuple_digest: [2u8; 32],
                admitted_canonicalizer_tuple_digest: [2u8; 32],
            }),
            disclosure_policy_binding: Some(DisclosurePolicyBinding {
                required_for_effect: false,
                state_valid: true,
                active_mode: DisclosurePolicyMode::TradeSecretOnly,
                expected_mode: DisclosurePolicyMode::TradeSecretOnly,
                attempted_channel: DisclosureChannelClass::Internal,
                policy_snapshot_digest: [3u8; 32],
                admitted_policy_epoch_root_digest: [3u8; 32],
                policy_epoch: 1,
                phase_id: "pre_federation".to_string(),
                state_reason: "ok".to_string(),
            }),
            leakage_budget_receipt: Some(LeakageBudgetReceipt {
                leakage_bits: 4,
                budget_bits: 8,
                estimator_family: LeakageEstimatorFamily::MutualInformationUpperBound,
                confidence_bps: 9_500,
                confidence_label: "high".to_string(),
            }),
            timing_channel_budget: Some(TimingChannelBudget {
                release_bucket_ticks: 10,
                observed_variance_ticks: 3,
                budget_ticks: 10,
            }),
            leakage_budget_policy_max_bits: Some(8),
            declared_leakage_budget_bits: None,
            timing_budget_policy_max_ticks: Some(10),
            declared_timing_budget_ticks: None,
            token_binding: None,
        }
    }

    fn execute_launch(env: &TestEnv) -> std::result::Result<RoleLaunchResponse, RoleLaunchError> {
        execute_role_launch_with_channel_context(
            &env.args,
            &env.ledger_path,
            &env.cas_path,
            &env.channel_context,
        )
    }

    fn load_receipt(cas_path: &Path, receipt_hash_hex: &str) -> LaunchReceiptV1 {
        let receipt_hash = parse_hex_hash_literal("receipt_hash", receipt_hash_hex)
            .expect("receipt hash should parse");
        let receipt_bytes =
            read_cas_object(cas_path, &receipt_hash).expect("receipt should be readable from CAS");
        serde_json::from_slice(&receipt_bytes).expect("receipt payload should deserialize")
    }

    #[test]
    fn test_valid_launch_succeeds() {
        let env = setup_test_env();
        let response = execute_launch(&env).expect("valid launch should succeed");

        assert_eq!(response.work_id, env.args.work_id);
        assert_eq!(response.role, env.args.role);
        assert_eq!(response.role_spec_hash, env.args.role_spec_hash);
        assert_eq!(response.context_pack_hash, env.args.context_pack_hash);
        assert_eq!(
            response.capability_manifest_hash,
            env.args.capability_manifest_hash
        );
        assert_eq!(response.policy_hash, env.args.policy_hash);
        assert_eq!(response.timestamp_ns, 1_000_000_001);

        let receipt_hash = parse_hex_hash_literal("receipt_hash", &response.receipt_hash)
            .expect("receipt hash should parse");
        let receipt_path = cas_object_path(&env.cas_path, &receipt_hash);
        assert!(
            receipt_path.exists(),
            "launch receipt must be stored in CAS at {}",
            receipt_path.display()
        );
        let receipt = load_receipt(&env.cas_path, &response.receipt_hash);
        assert_eq!(receipt.channel_source, ChannelSource::TypedToolIntent);
    }

    #[test]
    fn test_lease_id_included_in_receipt() {
        let mut env = setup_test_env();
        env.args.lease_id = Some("L-TEST-LEASE-A".to_string());
        let first = execute_launch(&env).expect("launch with lease id should succeed");

        let first_receipt = load_receipt(&env.cas_path, &first.receipt_hash);
        assert_eq!(first_receipt.lease_id, "L-TEST-LEASE-A");

        env.args.lease_id = Some("L-TEST-LEASE-B".to_string());
        let second = execute_launch(&env).expect("launch with changed lease id should succeed");

        assert_ne!(
            first.receipt_digest, second.receipt_digest,
            "changing lease_id must change receipt_digest"
        );
    }

    #[test]
    fn test_missing_role_spec_hash_denied() {
        let mut env = setup_test_env();
        env.args.role_spec_hash = "00".repeat(32);

        let error = execute_launch(&env).expect_err("missing role_spec_hash should deny launch");
        match error {
            RoleLaunchError::Denied { reason } => {
                assert_eq!(reason, LaunchDenyReason::MissingRoleSpecHash);
            },
            other => panic!("expected denied error, got {other:?}"),
        }
    }

    #[test]
    fn test_missing_context_pack_hash_denied() {
        let mut env = setup_test_env();
        env.args.context_pack_hash = "00".repeat(32);

        let error = execute_launch(&env).expect_err("missing context_pack_hash should deny launch");
        match error {
            RoleLaunchError::Denied { reason } => {
                assert_eq!(reason, LaunchDenyReason::MissingContextPackHash);
            },
            other => panic!("expected denied error, got {other:?}"),
        }
    }

    #[test]
    fn test_invalid_hex_format_denied() {
        let mut env = setup_test_env();
        env.args.role_spec_hash = "not-hex".to_string();

        let error = execute_launch(&env).expect_err("invalid hash format should deny launch");
        match error {
            RoleLaunchError::Denied {
                reason: LaunchDenyReason::InvalidHashFormat { field, .. },
            } => {
                assert_eq!(field, "role_spec_hash");
            },
            other => panic!("expected invalid-hash-format denial, got {other:?}"),
        }
    }

    #[test]
    fn test_unresolvable_cas_denied() {
        let mut env = setup_test_env();
        env.args.role_spec_hash = hex::encode([0xAB; 32]);

        let error =
            execute_launch(&env).expect_err("unresolvable role_spec_hash should deny launch");
        match error {
            RoleLaunchError::Denied { reason } => {
                assert_eq!(reason, LaunchDenyReason::UnresolvableRoleSpec);
            },
            other => panic!("expected denied error, got {other:?}"),
        }
    }

    #[test]
    fn test_work_id_mismatch_between_cli_and_policy_denied() {
        let mut env = setup_test_env();
        env.args.work_id = "W-TEST-OTHER".to_string();

        let error = execute_launch(&env).expect_err("work_id mismatch should deny launch");
        match error {
            RoleLaunchError::Denied { reason } => {
                assert_eq!(reason, LaunchDenyReason::WorkIdBindingMismatch);
            },
            other => panic!("expected denied error, got {other:?}"),
        }
    }

    #[test]
    fn test_policy_missing_work_id_binding_denied() {
        let mut env = setup_test_env();
        let policy_hash = store_policy_snapshot(
            &env.cas_path,
            None,
            &env.args.role,
            &env.args.role_spec_hash,
            &env.args.context_pack_hash,
            Some(&env.args.capability_manifest_hash),
        );
        env.args.policy_hash = hex::encode(policy_hash);

        let error =
            execute_launch(&env).expect_err("policy missing work_id binding should deny launch");
        match error {
            RoleLaunchError::Denied { reason } => {
                assert_eq!(reason, LaunchDenyReason::MissingPolicyWorkIdBinding);
            },
            other => panic!("expected denied error, got {other:?}"),
        }
    }

    #[test]
    fn test_missing_policy_capability_manifest_denied() {
        let mut env = setup_test_env();
        let policy_hash = store_policy_snapshot(
            &env.cas_path,
            Some(&env.args.work_id),
            &env.args.role,
            &env.args.role_spec_hash,
            &env.args.context_pack_hash,
            None,
        );
        env.args.policy_hash = hex::encode(policy_hash);

        let error = execute_launch(&env)
            .expect_err("policy missing capability_manifest_hash binding should deny launch");
        match error {
            RoleLaunchError::Denied { reason } => {
                assert_eq!(
                    reason,
                    LaunchDenyReason::MissingPolicyCapabilityManifestBinding
                );
            },
            other => panic!("expected denied error, got {other:?}"),
        }
    }

    #[test]
    fn test_capability_manifest_hash_mismatch_with_policy_denied() {
        let mut env = setup_test_env();
        let mut capabilities = fac_workobject_implementor_v2_role_contract()
            .required_capabilities
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        capabilities.push("extra.capability".to_string());
        let alternate_manifest_hash = store_capability_manifest(&env.cas_path, &capabilities);
        env.args.capability_manifest_hash = hex::encode(alternate_manifest_hash);

        let error =
            execute_launch(&env).expect_err("capability manifest hash mismatch should deny launch");
        match error {
            RoleLaunchError::Denied { reason } => {
                assert_eq!(
                    reason,
                    LaunchDenyReason::CapabilityManifestHashBindingMismatch
                );
            },
            other => panic!("expected denied error, got {other:?}"),
        }
    }

    #[test]
    fn test_capability_manifest_missing_required_role_capabilities_denied() {
        let mut env = setup_test_env();
        let minimal_manifest_hash =
            store_capability_manifest(&env.cas_path, &[String::from("fs.read")]);
        env.args.capability_manifest_hash = hex::encode(minimal_manifest_hash);

        let policy_hash = store_policy_snapshot(
            &env.cas_path,
            Some(&env.args.work_id),
            &env.args.role,
            &env.args.role_spec_hash,
            &env.args.context_pack_hash,
            Some(&env.args.capability_manifest_hash),
        );
        env.args.policy_hash = hex::encode(policy_hash);

        let error = execute_launch(&env)
            .expect_err("missing required role capabilities should deny launch");
        match error {
            RoleLaunchError::Denied {
                reason: LaunchDenyReason::MissingRequiredCapabilities { missing },
            } => {
                assert!(
                    missing.contains(&"artifact.fetch".to_string()),
                    "missing set should include artifact.fetch"
                );
                assert!(
                    missing.contains(&"evidence.publish".to_string()),
                    "missing set should include evidence.publish"
                );
            },
            other => panic!("expected missing-required-capabilities denial, got {other:?}"),
        }
    }

    #[test]
    fn test_stale_context_binding_denied() {
        let mut env = setup_test_env();
        let stale_context_hash = store_bytes_in_cas(&env.cas_path, b"context-pack-stale")
            .expect("stale context should store");
        env.args.context_pack_hash = hex::encode(stale_context_hash);

        let error = execute_launch(&env).expect_err("stale context binding should deny launch");
        match error {
            RoleLaunchError::Denied {
                reason: LaunchDenyReason::StaleBindingContext { detail },
            } => {
                assert!(
                    detail.contains("context_pack_hash"),
                    "stale detail should mention context_pack_hash mismatch"
                );
            },
            other => panic!("expected stale-binding-context denial, got {other:?}"),
        }
    }

    #[test]
    fn test_receipt_deterministic() {
        let env = setup_test_env();
        let first = execute_launch(&env).expect("first launch should succeed");
        let second = execute_launch(&env).expect("second launch should succeed");

        assert_eq!(
            first.receipt_digest, second.receipt_digest,
            "same inputs must produce same receipt_digest"
        );
        assert_eq!(
            first.receipt_hash, second.receipt_hash,
            "same inputs must produce same receipt_hash"
        );
    }

    #[test]
    fn test_launch_denied_on_channel_violation() {
        let mut env = setup_test_env();
        env.channel_context.source = ChannelSource::FreeFormOutput;
        env.channel_context.channel_source_witness = None;
        env.channel_context.broker_verified = false;

        let error = execute_launch(&env).expect_err("free-form channel source should deny launch");
        match error {
            RoleLaunchError::Denied {
                reason: LaunchDenyReason::ChannelBoundaryViolation { violations, .. },
            } => {
                assert!(
                    violations.contains(&ChannelViolationClass::UntypedChannelSource),
                    "violations should include untyped channel source"
                );
                assert!(
                    violations.contains(&ChannelViolationClass::BrokerBypassDetected),
                    "violations should include broker bypass detection"
                );
            },
            other => panic!("expected channel-boundary denial, got {other:?}"),
        }
    }

    #[test]
    fn test_launch_denied_when_policy_not_ledger_verified() {
        let mut env = setup_test_env();
        env.channel_context.policy_ledger_verified = false;

        let error = execute_launch(&env).expect_err("unverified policy should deny launch");
        match error {
            RoleLaunchError::Denied {
                reason: LaunchDenyReason::ChannelBoundaryViolation { violations, .. },
            } => {
                assert!(
                    violations.contains(&ChannelViolationClass::PolicyNotLedgerVerified),
                    "violations should include policy_not_ledger_verified"
                );
            },
            other => panic!("expected channel-boundary denial, got {other:?}"),
        }
    }

    #[test]
    fn test_direct_cli_context_defaults_fail_closed() {
        let env = setup_test_env();
        let error = execute_role_launch_with_daemon_verifying_key(
            &env.args,
            &env.ledger_path,
            &env.cas_path,
            None,
        )
        .expect_err("direct CLI launch without daemon context should fail closed");
        match error {
            RoleLaunchError::Denied {
                reason: LaunchDenyReason::ChannelBoundaryViolation { ref violations, .. },
            } => {
                assert!(
                    violations.contains(&ChannelViolationClass::UnknownChannelSource),
                    "violations should include unknown channel source"
                );
                assert!(
                    violations.contains(&ChannelViolationClass::PolicyNotLedgerVerified),
                    "violations should include policy_not_ledger_verified"
                );
            },
            other => panic!("expected channel-boundary denial, got {other:?}"),
        }

        assert!(
            error.message().contains("details:"),
            "channel-boundary deny message must include bounded defect details"
        );
    }

    #[test]
    fn test_daemon_channel_context_token_allows_launch() {
        let mut env = setup_test_env();
        let signer = Signer::generate();
        let daemon_verifying_key = signer.verifying_key();
        let request_id = "REQ-TEST-ROLE-LAUNCH-1";
        let check = daemon_admitted_boundary_check();
        env.args.request_id = Some(request_id.to_string());
        env.args.channel_context_token = Some(
            issue_channel_context_token(
                &check,
                "L-TEST-001",
                request_id,
                UNIX_EPOCH
                    .elapsed()
                    .expect("current time should be after unix epoch")
                    .as_secs(),
                &signer,
            )
            .expect("token issuance should succeed"),
        );

        let response = execute_role_launch_with_daemon_verifying_key(
            &env.args,
            &env.ledger_path,
            &env.cas_path,
            Some(&daemon_verifying_key),
        )
        .expect("daemon-issued channel context token should admit launch");
        assert_eq!(response.work_id, env.args.work_id);
        assert_eq!(response.role, env.args.role);
    }

    #[test]
    fn test_invalid_channel_context_token_fails_closed() {
        let mut env = setup_test_env();
        let signer = Signer::generate();
        let daemon_verifying_key = signer.verifying_key();
        env.args.request_id = Some("REQ-TEST-ROLE-LAUNCH-INVALID".to_string());
        env.args.channel_context_token = Some("not-base64-token".to_string());

        let error = execute_role_launch_with_daemon_verifying_key(
            &env.args,
            &env.ledger_path,
            &env.cas_path,
            Some(&daemon_verifying_key),
        )
        .expect_err("invalid token should fail closed to direct CLI denial");
        match error {
            RoleLaunchError::Denied {
                reason: LaunchDenyReason::ChannelBoundaryViolation { violations, .. },
            } => {
                assert!(
                    violations.contains(&ChannelViolationClass::UnknownChannelSource),
                    "fail-closed fallback should deny unknown channel source"
                );
            },
            other => panic!("expected channel-boundary denial, got {other:?}"),
        }
    }

    #[test]
    fn test_channel_context_token_with_wrong_lease_id_fails_closed() {
        let mut env = setup_test_env();
        let signer = Signer::generate();
        let daemon_verifying_key = signer.verifying_key();
        let request_id = "REQ-TEST-ROLE-LAUNCH-2";
        let check = daemon_admitted_boundary_check();
        env.args.request_id = Some(request_id.to_string());
        env.args.channel_context_token = Some(
            issue_channel_context_token(
                &check,
                "L-OTHER",
                request_id,
                UNIX_EPOCH
                    .elapsed()
                    .expect("current time should be after unix epoch")
                    .as_secs(),
                &signer,
            )
            .expect("token issuance should succeed"),
        );

        let error = execute_role_launch_with_daemon_verifying_key(
            &env.args,
            &env.ledger_path,
            &env.cas_path,
            Some(&daemon_verifying_key),
        )
        .expect_err("token bound to a different lease id must fail closed");
        match error {
            RoleLaunchError::Denied {
                reason: LaunchDenyReason::ChannelBoundaryViolation { violations, .. },
            } => {
                assert!(
                    violations.contains(&ChannelViolationClass::UnknownChannelSource),
                    "mismatched lease token must fail closed to unknown source"
                );
            },
            other => panic!("expected channel-boundary denial, got {other:?}"),
        }
    }

    #[test]
    fn test_channel_context_token_with_wrong_request_id_fails_closed() {
        let mut env = setup_test_env();
        let signer = Signer::generate();
        let daemon_verifying_key = signer.verifying_key();
        let check = daemon_admitted_boundary_check();
        env.args.request_id = Some("REQ-TEST-ROLE-LAUNCH-WRONG".to_string());
        env.args.channel_context_token = Some(
            issue_channel_context_token(
                &check,
                "L-TEST-001",
                "REQ-TEST-ROLE-LAUNCH-ACTUAL",
                UNIX_EPOCH
                    .elapsed()
                    .expect("current time should be after unix epoch")
                    .as_secs(),
                &signer,
            )
            .expect("token issuance should succeed"),
        );

        let error = execute_role_launch_with_daemon_verifying_key(
            &env.args,
            &env.ledger_path,
            &env.cas_path,
            Some(&daemon_verifying_key),
        )
        .expect_err("token bound to a different request id must fail closed");
        match error {
            RoleLaunchError::Denied {
                reason: LaunchDenyReason::ChannelBoundaryViolation { violations, .. },
            } => {
                assert!(
                    violations.contains(&ChannelViolationClass::UnknownChannelSource),
                    "mismatched request-id token must fail closed to unknown source"
                );
            },
            other => panic!("expected channel-boundary denial, got {other:?}"),
        }
    }
}
