//! FAC role launch command with hash-binding admission checks.
//!
//! This command enforces fail-closed launch admission using explicit hash
//! bindings and emits a replay-verifiable launch receipt.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow};
use apm2_core::determinism::canonicalize_json;
use apm2_core::fac::{DenyCondition, RoleSpecV2};
use apm2_core::ledger::{Ledger, LedgerError};
use clap::Args;
use serde::{Deserialize, Serialize};

use crate::exit_codes::codes as exit_codes;

/// Maximum allowed size for a CAS object read by this command (64 MiB).
const MAX_CAS_FILE_SIZE: u64 = 64 * 1024 * 1024;
/// Maximum supported `work_id` length.
const MAX_WORK_ID_LENGTH: usize = 512;
/// Maximum supported `role` length.
const MAX_ROLE_LENGTH: usize = 128;
/// Maximum supported `lease_id` length.
const MAX_LEASE_ID_LENGTH: usize = 256;
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
    json: bool,
) -> Result<()> {
    match execute_role_launch(args, ledger_path, cas_path) {
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

fn execute_role_launch(
    args: &RoleLaunchArgs,
    ledger_path: &Path,
    cas_path: &Path,
) -> std::result::Result<RoleLaunchResponse, RoleLaunchError> {
    validate_required_bounded("work_id", &args.work_id, MAX_WORK_ID_LENGTH)?;
    validate_required_bounded("role", &args.role, MAX_ROLE_LENGTH)?;
    if let Some(lease_id) = &args.lease_id {
        validate_optional_bounded("lease_id", lease_id, MAX_LEASE_ID_LENGTH)?;
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
        &args.role,
        hashes.role_spec,
        hashes.context_pack,
        hashes.capability_manifest,
        hashes.policy,
        cas_path,
    )
    .map_err(RoleLaunchError::denied)?;

    let timestamp_ns = derive_receipt_timestamp_ns(&ledger)?;
    let receipt = build_launch_receipt(args, hashes, timestamp_ns)?;
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
) -> std::result::Result<LaunchReceiptV1, RoleLaunchError> {
    let digest_input = LaunchReceiptDigestInput {
        schema_id: LAUNCH_RECEIPT_SCHEMA_ID.to_string(),
        work_id: args.work_id.clone(),
        role: args.role.clone(),
        role_spec_hash: hashes.role_spec,
        context_pack_hash: hashes.context_pack,
        capability_manifest_hash: hashes.capability_manifest,
        policy_hash: hashes.policy,
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
        fs::create_dir_all(parent).map_err(|error| {
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
    let metadata = fs::metadata(&path)
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

    let bytes = fs::read(&path)
        .map_err(|error| format!("failed to read CAS object '{}': {error}", path.display()))?;
    let computed_hash = *blake3::hash(&bytes).as_bytes();
    if computed_hash != *hash {
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
    if hash == [0u8; 32] {
        return Err(missing_reason);
    }
    read_cas_object(cas_path, &hash).map_err(|_| unresolvable_reason)
}

fn validate_launch_bindings(
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
    let _capability_manifest_bytes = resolve_required_hash(
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
        role,
        role_spec_hash,
        context_pack_hash,
        policy_hash,
        &role_spec_bytes,
        &policy_bytes,
    )
}

fn validate_cross_binding_consistency(
    role: &str,
    role_spec_hash: [u8; 32],
    context_pack_hash: [u8; 32],
    policy_hash: [u8; 32],
    role_spec_bytes: &[u8],
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

    let policy_role_spec_hash = extract_policy_hash(policy_object, "role_spec_hash")?;
    if policy_role_spec_hash != role_spec_hash {
        return Err(LaunchDenyReason::StaleBindingContext {
            detail: format!(
                "policy role_spec_hash {} does not match requested role_spec_hash {}",
                hex::encode(policy_role_spec_hash),
                hex::encode(role_spec_hash)
            ),
        });
    }

    let policy_context_pack_hash = extract_policy_hash(policy_object, "context_pack_hash")?;
    if policy_context_pack_hash != context_pack_hash {
        return Err(LaunchDenyReason::StaleBindingContext {
            detail: format!(
                "policy context_pack_hash {} does not match requested context_pack_hash {}",
                hex::encode(policy_context_pack_hash),
                hex::encode(context_pack_hash)
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
        if embedded_policy_hash != policy_hash {
            return Err(LaunchDenyReason::StaleBindingContext {
                detail: format!(
                    "embedded policy_hash {} does not match requested policy_hash {}",
                    hex::encode(embedded_policy_hash),
                    hex::encode(policy_hash)
                ),
            });
        }
    }

    Ok(())
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

impl From<LedgerError> for RoleLaunchError {
    fn from(error: LedgerError) -> Self {
        Self::internal(format!("ledger error: {error}"))
    }
}

#[cfg(test)]
mod tests {
    use apm2_core::fac::fac_workobject_implementor_v2_role_contract;
    use apm2_core::ledger::EventRecord;

    use super::*;

    struct TestEnv {
        _tempdir: tempfile::TempDir,
        ledger_path: PathBuf,
        cas_path: PathBuf,
        args: RoleLaunchArgs,
    }

    fn setup_test_env() -> TestEnv {
        let tempdir = tempfile::TempDir::new().expect("temp dir should create");
        let cas_path = tempdir.path().join("cas");
        fs::create_dir_all(cas_path.join("objects")).expect("CAS objects dir should create");

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
        let capability_manifest_hash = store_bytes_in_cas(&cas_path, b"capability-manifest")
            .expect("capability manifest should store");

        let policy_payload = serde_json::json!({
            "schema_id": "apm2.policy_snapshot.v1",
            "role_spec_hash": hex::encode(role_spec_hash),
            "context_pack_hash": hex::encode(context_pack_hash),
            "role": "implementer"
        });
        let policy_bytes = canonical_json_bytes(&policy_payload)
            .expect("policy payload canonicalization should succeed");
        let policy_hash =
            store_bytes_in_cas(&cas_path, &policy_bytes).expect("policy should store");

        let args = RoleLaunchArgs {
            work_id: "W-TEST-001".to_string(),
            role: "implementer".to_string(),
            role_spec_hash: hex::encode(role_spec_hash),
            context_pack_hash: hex::encode(context_pack_hash),
            capability_manifest_hash: hex::encode(capability_manifest_hash),
            policy_hash: hex::encode(policy_hash),
            lease_id: Some("L-TEST-001".to_string()),
        };

        TestEnv {
            _tempdir: tempdir,
            ledger_path,
            cas_path,
            args,
        }
    }

    #[test]
    fn test_valid_launch_succeeds() {
        let env = setup_test_env();
        let response = execute_role_launch(&env.args, &env.ledger_path, &env.cas_path)
            .expect("valid launch should succeed");

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
    }

    #[test]
    fn test_missing_role_spec_hash_denied() {
        let mut env = setup_test_env();
        env.args.role_spec_hash = "00".repeat(32);

        let error = execute_role_launch(&env.args, &env.ledger_path, &env.cas_path)
            .expect_err("missing role_spec_hash should deny launch");
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

        let error = execute_role_launch(&env.args, &env.ledger_path, &env.cas_path)
            .expect_err("missing context_pack_hash should deny launch");
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

        let error = execute_role_launch(&env.args, &env.ledger_path, &env.cas_path)
            .expect_err("invalid hash format should deny launch");
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

        let error = execute_role_launch(&env.args, &env.ledger_path, &env.cas_path)
            .expect_err("unresolvable role_spec_hash should deny launch");
        match error {
            RoleLaunchError::Denied { reason } => {
                assert_eq!(reason, LaunchDenyReason::UnresolvableRoleSpec);
            },
            other => panic!("expected denied error, got {other:?}"),
        }
    }

    #[test]
    fn test_receipt_deterministic() {
        let env = setup_test_env();
        let first = execute_role_launch(&env.args, &env.ledger_path, &env.cas_path)
            .expect("first launch should succeed");
        let second = execute_role_launch(&env.args, &env.ledger_path, &env.cas_path)
            .expect("second launch should succeed");

        assert_eq!(
            first.receipt_digest, second.receipt_digest,
            "same inputs must produce same receipt_digest"
        );
        assert_eq!(
            first.receipt_hash, second.receipt_hash,
            "same inputs must produce same receipt_hash"
        );
    }
}
