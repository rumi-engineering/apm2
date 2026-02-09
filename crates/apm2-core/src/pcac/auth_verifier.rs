// AGENT-AUTHORED
//! Receipt authentication verifier for PCAC acceptance-fact composition
//! (RFC-0027 §6.5, TCK-00425).
//!
//! This module implements the verification logic that distinguishes
//! authoritative acceptance facts from non-authoritative routing facts:
//!
//! - [`verify_receipt_authentication`]: validates direct or pointer/batched
//!   receipt authentication shapes.
//! - [`validate_authoritative_bindings`]: ensures all mandatory fields in
//!   [`AuthoritativeBindings`] are non-zero and structurally valid.
//! - [`classify_fact`]: classifies a lifecycle outcome as an acceptance fact or
//!   routing fact based on the presence and validity of authoritative bindings.
//!
//! # Fail-Closed Semantics
//!
//! Every function in this module fails closed: unknown authentication
//! shapes, missing fields, zero hashes, and malformed inclusion proofs
//! all produce deterministic [`AuthorityDenyV1`] denials.

use serde::{Deserialize, Serialize};

use super::deny::{AuthorityDenyClass, AuthorityDenyV1};
use super::receipts::{AuthoritativeBindings, ReceiptAuthentication};
use crate::crypto::Hash;

/// Zero hash constant for fail-closed comparisons.
const ZERO_HASH: Hash = [0u8; 32];

// =============================================================================
// FactClass
// =============================================================================

/// Classification of a lifecycle outcome as acceptance fact or routing fact.
///
/// Per RFC-0027 §6.5:
/// - **Acceptance facts** have complete authoritative bindings with valid
///   receipt authentication. They are authority-bearing and suitable for
///   replay/adjudication.
/// - **Routing facts** lack authoritative bindings or have incomplete
///   authentication. They are forwarded raw bytes without admissible authority
///   proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactClass {
    /// Authoritative acceptance fact with valid receipt authentication.
    AcceptanceFact,
    /// Non-authoritative routing fact (missing or invalid bindings).
    RoutingFact,
}

impl std::fmt::Display for FactClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AcceptanceFact => write!(f, "acceptance_fact"),
            Self::RoutingFact => write!(f, "routing_fact"),
        }
    }
}

// =============================================================================
// Receipt authentication verification
// =============================================================================

/// Verify a receipt authentication shape is admissible.
///
/// # Direct Path
///
/// Verifies that `authority_seal_hash` is non-zero and matches the
/// `expected_seal_hash`.
///
/// # Pointer Path
///
/// Verifies:
/// 1. `receipt_hash` is non-zero.
/// 2. `authority_seal_hash` is non-zero and matches `expected_seal_hash`.
/// 3. If `merkle_inclusion_proof` is present, it is non-empty and all proof
///    hashes are non-zero.
/// 4. If `receipt_batch_root_hash` is present, it is non-zero.
/// 5. When `merkle_inclusion_proof` is present, `receipt_batch_root_hash` must
///    also be present (and vice versa).
///
/// # Errors
///
/// Returns [`AuthorityDenyV1`] on any invalid or missing state.
pub fn verify_receipt_authentication(
    auth: &ReceiptAuthentication,
    expected_seal_hash: &Hash,
    time_envelope_ref: Hash,
    ledger_anchor: Hash,
    denied_at_tick: u64,
) -> Result<(), Box<AuthorityDenyV1>> {
    let ctx = DenyContext {
        time_envelope_ref,
        ledger_anchor,
        denied_at_tick,
    };
    match auth {
        ReceiptAuthentication::Direct {
            authority_seal_hash,
        } => verify_direct_auth(authority_seal_hash, expected_seal_hash, &ctx),
        ReceiptAuthentication::Pointer {
            receipt_hash,
            authority_seal_hash,
            merkle_inclusion_proof,
            receipt_batch_root_hash,
        } => verify_pointer_auth(
            receipt_hash,
            authority_seal_hash,
            expected_seal_hash,
            merkle_inclusion_proof.as_deref(),
            receipt_batch_root_hash.as_ref(),
            &ctx,
        ),
    }
}

// =============================================================================
// Authoritative bindings validation
// =============================================================================

/// Validate that all mandatory authoritative binding fields are present
/// and non-zero.
///
/// Checks:
/// 1. `episode_envelope_hash` is non-zero.
/// 2. `view_commitment_hash` is non-zero.
/// 3. `time_envelope_ref` is non-zero.
/// 4. `authentication` shape is structurally valid (delegated to
///    [`verify_receipt_authentication`] by the caller).
/// 5. When `permeability_receipt_hash` is present, it must be non-zero.
/// 6. When `delegation_chain_hash` is present, it must be non-zero.
///
/// # Errors
///
/// Returns [`AuthorityDenyV1`] for any missing or zero-hash mandatory field.
pub fn validate_authoritative_bindings(
    bindings: &AuthoritativeBindings,
    time_envelope_ref: Hash,
    ledger_anchor: Hash,
    denied_at_tick: u64,
) -> Result<(), Box<AuthorityDenyV1>> {
    let ctx = DenyContext {
        time_envelope_ref,
        ledger_anchor,
        denied_at_tick,
    };

    require_nonzero(
        &bindings.episode_envelope_hash,
        "episode_envelope_hash",
        &ctx,
    )?;
    require_nonzero(&bindings.view_commitment_hash, "view_commitment_hash", &ctx)?;
    require_nonzero(&bindings.time_envelope_ref, "time_envelope_ref", &ctx)?;

    if let Some(ref h) = bindings.permeability_receipt_hash {
        require_nonzero(h, "permeability_receipt_hash", &ctx)?;
    }
    if let Some(ref h) = bindings.delegation_chain_hash {
        require_nonzero(h, "delegation_chain_hash", &ctx)?;
    }

    Ok(())
}

// =============================================================================
// Fact classification
// =============================================================================

/// Classify a lifecycle outcome as an acceptance fact or routing fact.
///
/// - If `bindings` is `None`, the outcome is a routing fact.
/// - If `bindings` is `Some`, validation is performed on all mandatory fields
///   and the authentication shape. If validation succeeds, the outcome is an
///   acceptance fact. If validation fails, the outcome is a routing fact
///   (fail-closed: invalid bindings do not produce acceptance facts).
#[must_use]
pub fn classify_fact(
    bindings: Option<&AuthoritativeBindings>,
    expected_seal_hash: &Hash,
    time_envelope_ref: Hash,
    ledger_anchor: Hash,
    current_tick: u64,
) -> FactClass {
    let Some(bindings) = bindings else {
        return FactClass::RoutingFact;
    };

    if validate_authoritative_bindings(bindings, time_envelope_ref, ledger_anchor, current_tick)
        .is_err()
    {
        return FactClass::RoutingFact;
    }

    if verify_receipt_authentication(
        &bindings.authentication,
        expected_seal_hash,
        time_envelope_ref,
        ledger_anchor,
        current_tick,
    )
    .is_err()
    {
        return FactClass::RoutingFact;
    }

    FactClass::AcceptanceFact
}

// =============================================================================
// Internal helpers
// =============================================================================

/// Context for building deny values.
struct DenyContext {
    time_envelope_ref: Hash,
    ledger_anchor: Hash,
    denied_at_tick: u64,
}

fn make_deny(deny_class: AuthorityDenyClass, ctx: &DenyContext) -> Box<AuthorityDenyV1> {
    Box::new(AuthorityDenyV1 {
        deny_class,
        ajc_id: None,
        time_envelope_ref: ctx.time_envelope_ref,
        ledger_anchor: ctx.ledger_anchor,
        denied_at_tick: ctx.denied_at_tick,
    })
}

fn require_nonzero(
    hash: &Hash,
    field_name: &str,
    ctx: &DenyContext,
) -> Result<(), Box<AuthorityDenyV1>> {
    if *hash == ZERO_HASH {
        return Err(make_deny(
            AuthorityDenyClass::ZeroHash {
                field_name: field_name.to_string(),
            },
            ctx,
        ));
    }
    Ok(())
}

fn verify_seal(
    authority_seal_hash: &Hash,
    expected_seal_hash: &Hash,
    ctx: &DenyContext,
) -> Result<(), Box<AuthorityDenyV1>> {
    require_nonzero(authority_seal_hash, "authority_seal_hash", ctx)?;
    if authority_seal_hash != expected_seal_hash {
        return Err(make_deny(
            AuthorityDenyClass::UnknownState {
                description: "authority_seal_hash does not match expected seal".to_string(),
            },
            ctx,
        ));
    }
    Ok(())
}

fn verify_direct_auth(
    authority_seal_hash: &Hash,
    expected_seal_hash: &Hash,
    ctx: &DenyContext,
) -> Result<(), Box<AuthorityDenyV1>> {
    verify_seal(authority_seal_hash, expected_seal_hash, ctx)
}

fn verify_pointer_auth(
    receipt_hash: &Hash,
    authority_seal_hash: &Hash,
    expected_seal_hash: &Hash,
    merkle_inclusion_proof: Option<&[Hash]>,
    receipt_batch_root_hash: Option<&Hash>,
    ctx: &DenyContext,
) -> Result<(), Box<AuthorityDenyV1>> {
    require_nonzero(receipt_hash, "receipt_hash", ctx)?;
    verify_seal(authority_seal_hash, expected_seal_hash, ctx)?;

    match (merkle_inclusion_proof, receipt_batch_root_hash) {
        (Some(proof), Some(batch_root)) => {
            if proof.is_empty() {
                return Err(make_deny(
                    AuthorityDenyClass::UnknownState {
                        description: "merkle_inclusion_proof is empty".to_string(),
                    },
                    ctx,
                ));
            }
            for (i, hash) in proof.iter().enumerate() {
                if *hash == ZERO_HASH {
                    return Err(make_deny(
                        AuthorityDenyClass::ZeroHash {
                            field_name: format!("merkle_inclusion_proof[{i}]"),
                        },
                        ctx,
                    ));
                }
            }
            require_nonzero(batch_root, "receipt_batch_root_hash", ctx)?;
        },
        (Some(_), None) => {
            return Err(make_deny(
                AuthorityDenyClass::UnknownState {
                    description: "merkle_inclusion_proof present without receipt_batch_root_hash"
                        .to_string(),
                },
                ctx,
            ));
        },
        (None, Some(_)) => {
            return Err(make_deny(
                AuthorityDenyClass::UnknownState {
                    description: "receipt_batch_root_hash present without merkle_inclusion_proof"
                        .to_string(),
                },
                ctx,
            ));
        },
        (None, None) => {},
    }
    Ok(())
}
