// AGENT-AUTHORED
//! Temporal arbitration for RFC-0028 REQ-0002.
//!
//! Implements evaluator-tuple validation, arbitration outcome mapping,
//! and signed arbitration receipts for shared temporal predicates.

use serde::{Deserialize, Deserializer, Serialize};
use subtle::ConstantTimeEq;

use super::types::MAX_REASON_LENGTH;
use crate::crypto::{Signer, parse_signature, parse_verifying_key, verify_signature};

/// Maximum length for evaluator identifiers.
pub const MAX_EVALUATOR_ID_LENGTH: usize = 256;
/// Maximum number of evaluator tuples allowed in one receipt.
pub const MAX_EVALUATORS: usize = 64;
/// Maximum length for predicate identifiers.
pub const MAX_PREDICATE_ID_LENGTH: usize = 256;
/// Maximum length for deny reason strings.
pub const MAX_DENY_REASON_LENGTH: usize = MAX_REASON_LENGTH;

const ZERO_HASH: [u8; 32] = [0u8; 32];

mod signature_bytes_serde {
    use serde::de::{self, SeqAccess, Visitor};
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(value: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(value)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SignatureBytesVisitor;

        impl<'de> Visitor<'de> for SignatureBytesVisitor {
            type Value = [u8; 64];

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a byte sequence of exactly 64 bytes")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                if let Some(size) = seq.size_hint() {
                    if size > 64 {
                        return Err(de::Error::custom(format!(
                            "signature too long: more than 64 bytes ({size})"
                        )));
                    }
                }

                let mut arr = [0u8; 64];
                for (index, slot) in arr.iter_mut().enumerate() {
                    *slot = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(index, &self))?;
                }

                if seq.next_element::<u8>()?.is_some() {
                    return Err(de::Error::custom("signature too long: more than 64 bytes"));
                }

                Ok(arr)
            }

            fn visit_bytes<E>(self, bytes: &[u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if bytes.len() != 64 {
                    return Err(E::custom(format!(
                        "expected 64 bytes for signature, got {}",
                        bytes.len()
                    )));
                }
                let mut arr = [0u8; 64];
                arr.copy_from_slice(bytes);
                Ok(arr)
            }

            fn visit_byte_buf<E>(self, bytes: Vec<u8>) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                self.visit_bytes(&bytes)
            }
        }

        deserializer.deserialize_seq(SignatureBytesVisitor)
    }
}

/// Temporal predicate identifiers for shared arbitration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TemporalPredicateId {
    /// Time authority envelope is valid.
    #[serde(rename = "TP-EIO29-001")]
    TpEio29001,
    /// Promotion temporal ambiguity is false.
    #[serde(rename = "TP-EIO29-008")]
    TpEio29008,
}

impl std::fmt::Display for TemporalPredicateId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TpEio29001 => write!(f, "TP-EIO29-001"),
            Self::TpEio29008 => write!(f, "TP-EIO29-008"),
        }
    }
}

/// Outcome of temporal arbitration between evaluators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArbitrationOutcome {
    /// All evaluators agree to allow.
    AgreedAllow,
    /// All evaluators agree to deny.
    AgreedDeny,
    /// Evaluators disagree but condition is transient (recoverable).
    DisagreementTransient,
    /// Evaluators disagree persistently (requires rebaseline).
    DisagreementPersistent,
}

impl std::fmt::Display for ArbitrationOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AgreedAllow => write!(f, "agreed_allow"),
            Self::AgreedDeny => write!(f, "agreed_deny"),
            Self::DisagreementTransient => write!(f, "disagreement_transient"),
            Self::DisagreementPersistent => write!(f, "disagreement_persistent"),
        }
    }
}

/// Evaluator tuple for temporal predicate evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluatorTuple {
    /// Identity of the evaluator.
    #[serde(deserialize_with = "deserialize_evaluator_id")]
    pub evaluator_id: String,
    /// The temporal predicate being evaluated.
    pub predicate_id: TemporalPredicateId,
    /// Digest set of the contract being evaluated against.
    pub contract_digest_set: [u8; 32],
    /// Canonicalizer tuple reference.
    pub canonicalizer_tuple: [u8; 32],
    /// Time authority reference (HTF).
    pub time_authority_ref: [u8; 32],
    /// Window reference for freshness evaluation.
    pub window_ref: [u8; 32],
    /// The verdict from this evaluator.
    pub verdict: ArbitrationOutcome,
    /// Deny reason (required when verdict is not `AgreedAllow`).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_deny_reason"
    )]
    pub deny_reason: Option<String>,
}

impl EvaluatorTuple {
    /// Validates tuple shape and fail-closed invariants.
    ///
    /// # Errors
    ///
    /// Returns an error string when the tuple is missing required data,
    /// has oversized strings, has zero hash references, or violates
    /// deny-reason coherence rules.
    pub fn validate(&self) -> Result<(), String> {
        if self.evaluator_id.is_empty() {
            return Err("evaluator_id must not be empty".to_string());
        }
        if self.evaluator_id.len() > MAX_EVALUATOR_ID_LENGTH {
            return Err(format!(
                "evaluator_id length {} exceeds maximum {}",
                self.evaluator_id.len(),
                MAX_EVALUATOR_ID_LENGTH,
            ));
        }

        if is_zero_hash(&self.contract_digest_set) {
            return Err("contract_digest_set must not be zero".to_string());
        }
        if is_zero_hash(&self.canonicalizer_tuple) {
            return Err("canonicalizer_tuple must not be zero".to_string());
        }
        if is_zero_hash(&self.time_authority_ref) {
            return Err("time_authority_ref must not be zero".to_string());
        }
        if is_zero_hash(&self.window_ref) {
            return Err("window_ref must not be zero".to_string());
        }

        if self.verdict == ArbitrationOutcome::AgreedAllow {
            if self.deny_reason.is_some() {
                return Err("deny_reason must be absent when verdict is agreed_allow".to_string());
            }
        } else {
            let Some(reason) = self.deny_reason.as_ref() else {
                return Err("deny_reason is required for non-allow verdicts".to_string());
            };

            if reason.is_empty() {
                return Err("deny_reason must not be empty".to_string());
            }
            if reason.len() > MAX_DENY_REASON_LENGTH {
                return Err(format!(
                    "deny_reason length {} exceeds maximum {}",
                    reason.len(),
                    MAX_DENY_REASON_LENGTH,
                ));
            }
        }

        Ok(())
    }
}

/// Signed temporal arbitration receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemporalArbitrationReceiptV1 {
    /// The predicate being arbitrated.
    pub predicate_id: TemporalPredicateId,
    /// Evaluator tuples participating in this arbitration.
    #[serde(deserialize_with = "deserialize_evaluators")]
    pub evaluators: Vec<EvaluatorTuple>,
    /// Aggregate outcome.
    pub aggregate_outcome: ArbitrationOutcome,
    /// Time envelope reference at arbitration time.
    pub time_envelope_ref: [u8; 32],
    /// HTF tick at which arbitration was performed.
    pub arbitrated_at_tick: u64,
    /// Optional adjudication deadline tick for disagreement resolution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline_tick: Option<u64>,
    /// Content digest of this receipt (for CAS binding).
    pub content_digest: [u8; 32],
    /// Ed25519 public key of the signer (32 bytes).
    pub signer_id: [u8; 32],
    /// Ed25519 signature over the canonical receipt payload (64 bytes).
    #[serde(with = "signature_bytes_serde")]
    pub signature: [u8; 64],
}

impl TemporalArbitrationReceiptV1 {
    /// Serializes the canonical payload covered by signature verification.
    ///
    /// This payload includes all fields except `signer_id` and `signature`.
    #[must_use]
    pub fn canonical_payload_for_signing(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(b"apm2-temporal-arbitration-receipt-v1");
        payload.push(predicate_tag(self.predicate_id));
        encode_u64(&mut payload, self.evaluators.len() as u64);
        for evaluator in &self.evaluators {
            encode_string(&mut payload, &evaluator.evaluator_id);
            payload.push(predicate_tag(evaluator.predicate_id));
            payload.extend_from_slice(&evaluator.contract_digest_set);
            payload.extend_from_slice(&evaluator.canonicalizer_tuple);
            payload.extend_from_slice(&evaluator.time_authority_ref);
            payload.extend_from_slice(&evaluator.window_ref);
            payload.push(outcome_tag(evaluator.verdict));
            match evaluator.deny_reason.as_ref() {
                Some(reason) => {
                    payload.push(1);
                    encode_string(&mut payload, reason);
                },
                None => payload.push(0),
            }
        }
        payload.push(outcome_tag(self.aggregate_outcome));
        payload.extend_from_slice(&self.time_envelope_ref);
        encode_u64(&mut payload, self.arbitrated_at_tick);
        match self.deadline_tick {
            Some(deadline_tick) => {
                payload.push(1);
                encode_u64(&mut payload, deadline_tick);
            },
            None => payload.push(0),
        }
        payload.extend_from_slice(&self.content_digest);
        payload
    }

    /// Signs the receipt payload with the provided signer.
    pub fn sign(&mut self, signer: &Signer) {
        let payload = self.canonical_payload_for_signing();
        self.signer_id = signer.public_key_bytes();
        self.signature = signer.sign(&payload).to_bytes();
    }

    /// Validates receipt shape and deterministic arbitration constraints.
    ///
    /// # Errors
    ///
    /// Returns an error string when evaluator tuples are missing/invalid,
    /// ordering is non-deterministic, hash references are zero, or aggregate
    /// outcome is inconsistent with tuple verdicts.
    pub fn validate(&self) -> Result<(), String> {
        if self.evaluators.is_empty() {
            return Err("at least one evaluator tuple is required".to_string());
        }
        if self.evaluators.len() > MAX_EVALUATORS {
            return Err(format!(
                "evaluators length {} exceeds maximum {}",
                self.evaluators.len(),
                MAX_EVALUATORS,
            ));
        }
        if is_zero_hash(&self.time_envelope_ref) {
            return Err("time_envelope_ref must not be zero".to_string());
        }
        if self.arbitrated_at_tick == 0 {
            return Err("arbitrated_at_tick must be > 0".to_string());
        }
        if matches!(self.deadline_tick, Some(0)) {
            return Err("deadline_tick must be > 0 when present".to_string());
        }
        if self.aggregate_outcome == ArbitrationOutcome::DisagreementTransient {
            match self.deadline_tick {
                None => {
                    return Err("DisagreementTransient requires deadline_tick".to_string());
                },
                Some(deadline) if deadline <= self.arbitrated_at_tick => {
                    return Err(
                        "deadline_tick must be strictly greater than arbitrated_at_tick"
                            .to_string(),
                    );
                },
                Some(_) => {},
            }
        }
        if is_zero_hash(&self.content_digest) {
            return Err("content_digest must not be zero".to_string());
        }
        if is_zero_hash(&self.signer_id) {
            return Err("signer_id must not be zero".to_string());
        }
        if self.signature == [0u8; 64] {
            return Err("signature must not be zero".to_string());
        }

        let first = &self.evaluators[0];
        let mut previous_evaluator_id: Option<&str> = None;
        for evaluator in &self.evaluators {
            evaluator.validate()?;

            if evaluator.predicate_id != self.predicate_id {
                return Err(format!(
                    "tuple predicate {} does not match receipt predicate {}",
                    evaluator.predicate_id, self.predicate_id,
                ));
            }
            if !hashes_equal(&evaluator.contract_digest_set, &first.contract_digest_set) {
                return Err("context coherence violation: contract_digest_set mismatch".to_string());
            }
            if !hashes_equal(&evaluator.canonicalizer_tuple, &first.canonicalizer_tuple) {
                return Err("context coherence violation: canonicalizer_tuple mismatch".to_string());
            }
            if !hashes_equal(&evaluator.time_authority_ref, &first.time_authority_ref) {
                return Err("context coherence violation: time_authority_ref mismatch".to_string());
            }
            if !hashes_equal(&evaluator.window_ref, &first.window_ref) {
                return Err("context coherence violation: window_ref mismatch".to_string());
            }

            if let Some(previous) = previous_evaluator_id {
                if evaluator.evaluator_id.as_str() <= previous {
                    return Err(
                        "evaluator tuples must be sorted by strictly increasing evaluator_id"
                            .to_string(),
                    );
                }
            }
            previous_evaluator_id = Some(&evaluator.evaluator_id);
        }

        let expected = derive_aggregate_outcome(&self.evaluators);
        if self.aggregate_outcome != expected {
            return Err(format!(
                "aggregate_outcome {} does not match evaluator-derived {}",
                self.aggregate_outcome, expected,
            ));
        }

        let verifying_key = parse_verifying_key(&self.signer_id)
            .map_err(|error| format!("invalid signer_id: {error}"))?;
        let signature = parse_signature(&self.signature)
            .map_err(|error| format!("invalid signature bytes: {error}"))?;
        verify_signature(
            &verifying_key,
            &self.canonical_payload_for_signing(),
            &signature,
        )
        .map_err(|_| "receipt signature verification failed".to_string())?;

        Ok(())
    }

    /// Returns `true` if arbitration missed its adjudication deadline.
    #[must_use]
    pub fn check_deadline_miss(&self, current_tick: u64) -> bool {
        self.deadline_tick.is_some_and(|d| current_tick > d)
    }

    /// Returns the effective outcome at `current_tick`, escalating transient
    /// disagreement to persistent after deadline miss.
    #[must_use]
    pub fn effective_outcome(&self, current_tick: u64) -> ArbitrationOutcome {
        if self.check_deadline_miss(current_tick)
            && self.aggregate_outcome == ArbitrationOutcome::DisagreementTransient
        {
            ArbitrationOutcome::DisagreementPersistent
        } else {
            self.aggregate_outcome
        }
    }
}

/// Map arbitration outcome to admission behavior.
///
/// Fail-closed: anything other than `AgreedAllow` produces a denial or freeze.
#[must_use]
pub fn map_arbitration_outcome(
    outcome: ArbitrationOutcome,
    predicate_id: TemporalPredicateId,
) -> ArbitrationAction {
    let predicate = predicate_id.to_string();

    match outcome {
        ArbitrationOutcome::AgreedAllow => ArbitrationAction::Continue,
        ArbitrationOutcome::AgreedDeny => ArbitrationAction::Deny {
            reason: format!(
                "temporal arbitration denied for predicate {predicate} with outcome {outcome}",
            ),
        },
        ArbitrationOutcome::DisagreementTransient => {
            ArbitrationAction::FreezeAndRequireAdjudication {
                reason: format!(
                    "transient evaluator disagreement on predicate {predicate}; adjudication receipt required",
                ),
            }
        },
        ArbitrationOutcome::DisagreementPersistent => ArbitrationAction::DenyAndRebaseline {
            reason: format!(
                "persistent evaluator disagreement on predicate {predicate}; rebaseline is mandatory",
            ),
        },
    }
}

/// Admission action derived from temporal arbitration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ArbitrationAction {
    /// Continue processing — all evaluators agree to allow.
    Continue,
    /// Deny admission immediately.
    Deny {
        /// Deterministic deny reason.
        #[serde(deserialize_with = "deserialize_action_reason")]
        reason: String,
    },
    /// Freeze promotion paths and require adjudication receipt.
    FreezeAndRequireAdjudication {
        /// Deterministic freeze reason.
        #[serde(deserialize_with = "deserialize_action_reason")]
        reason: String,
    },
    /// Deny and trigger mandatory rebaseline workflow.
    DenyAndRebaseline {
        /// Deterministic deny/rebaseline reason.
        #[serde(deserialize_with = "deserialize_action_reason")]
        reason: String,
    },
}

/// Check freshness dominance at revalidate/consume boundary.
///
/// Denies if freshness witness tick exceeds max age from current tick.
///
/// # Errors
///
/// Returns [`FreshnessViolation`] for stale, future, or otherwise
/// non-admissible witness ticks.
pub fn check_freshness_dominance(
    freshness_witness_tick: u64,
    current_tick: u64,
    max_age_ticks: u64,
) -> Result<(), FreshnessViolation> {
    if freshness_witness_tick > current_tick {
        return Err(FreshnessViolation {
            witness_tick: freshness_witness_tick,
            current_tick,
            max_age_ticks,
            detail: "freshness witness tick is ahead of current tick".to_string(),
        });
    }

    let age = current_tick - freshness_witness_tick;
    if age > max_age_ticks {
        return Err(FreshnessViolation {
            witness_tick: freshness_witness_tick,
            current_tick,
            max_age_ticks,
            detail: "freshness witness tick exceeded max age window".to_string(),
        });
    }

    Ok(())
}

/// Check revocation frontier dominance.
///
/// Denies if current revocation head has advanced beyond the AJC's
/// recorded head.
///
/// # Errors
///
/// Returns [`RevocationViolation`] when heads are zero, ambiguous, or not equal
/// under constant-time comparison.
pub fn check_revocation_dominance(
    ajc_revocation_head: &[u8; 32],
    current_revocation_head: &[u8; 32],
) -> Result<(), RevocationViolation> {
    if is_zero_hash(ajc_revocation_head) {
        return Err(RevocationViolation {
            ajc_revocation_head: *ajc_revocation_head,
            current_revocation_head: *current_revocation_head,
            detail: "AJC revocation head is zero (unverifiable)".to_string(),
        });
    }

    if is_zero_hash(current_revocation_head) {
        return Err(RevocationViolation {
            ajc_revocation_head: *ajc_revocation_head,
            current_revocation_head: *current_revocation_head,
            detail: "current revocation head is zero (ambiguous)".to_string(),
        });
    }

    if hashes_equal(ajc_revocation_head, current_revocation_head) {
        return Ok(());
    }

    Err(RevocationViolation {
        ajc_revocation_head: *ajc_revocation_head,
        current_revocation_head: *current_revocation_head,
        detail: "revocation frontier advanced or diverged from AJC binding".to_string(),
    })
}

/// Freshness dominance violation details.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FreshnessViolation {
    /// Witness tick carried by the authority proof.
    pub witness_tick: u64,
    /// Current HTF tick at evaluation time.
    pub current_tick: u64,
    /// Maximum allowed witness age in ticks.
    pub max_age_ticks: u64,
    /// Human-readable violation detail.
    #[serde(deserialize_with = "deserialize_violation_detail")]
    pub detail: String,
}

/// Revocation dominance violation details.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationViolation {
    /// Revocation head hash recorded in the AJC.
    pub ajc_revocation_head: [u8; 32],
    /// Current revocation frontier hash.
    pub current_revocation_head: [u8; 32],
    /// Human-readable violation detail.
    #[serde(deserialize_with = "deserialize_violation_detail")]
    pub detail: String,
}

fn derive_aggregate_outcome(evaluators: &[EvaluatorTuple]) -> ArbitrationOutcome {
    if evaluators
        .iter()
        .all(|tuple| tuple.verdict == ArbitrationOutcome::AgreedAllow)
    {
        return ArbitrationOutcome::AgreedAllow;
    }

    if evaluators
        .iter()
        .all(|tuple| tuple.verdict == ArbitrationOutcome::AgreedDeny)
    {
        return ArbitrationOutcome::AgreedDeny;
    }

    if evaluators
        .iter()
        .any(|tuple| tuple.verdict == ArbitrationOutcome::DisagreementPersistent)
    {
        return ArbitrationOutcome::DisagreementPersistent;
    }

    ArbitrationOutcome::DisagreementTransient
}

fn encode_u64(payload: &mut Vec<u8>, value: u64) {
    payload.extend_from_slice(&value.to_le_bytes());
}

fn encode_string(payload: &mut Vec<u8>, value: &str) {
    encode_u64(payload, value.len() as u64);
    payload.extend_from_slice(value.as_bytes());
}

const fn predicate_tag(predicate: TemporalPredicateId) -> u8 {
    match predicate {
        TemporalPredicateId::TpEio29001 => 1,
        TemporalPredicateId::TpEio29008 => 8,
    }
}

const fn outcome_tag(outcome: ArbitrationOutcome) -> u8 {
    match outcome {
        ArbitrationOutcome::AgreedAllow => 1,
        ArbitrationOutcome::AgreedDeny => 2,
        ArbitrationOutcome::DisagreementTransient => 3,
        ArbitrationOutcome::DisagreementPersistent => 4,
    }
}

fn is_zero_hash(hash: &[u8; 32]) -> bool {
    hash.ct_eq(&ZERO_HASH).unwrap_u8() == 1
}

fn hashes_equal(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.ct_eq(right).unwrap_u8() == 1
}

fn deserialize_evaluator_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if value.len() > MAX_EVALUATOR_ID_LENGTH {
        return Err(serde::de::Error::custom(format!(
            "evaluator_id length {} exceeds maximum {}",
            value.len(),
            MAX_EVALUATOR_ID_LENGTH,
        )));
    }
    Ok(value)
}

fn deserialize_optional_deny_reason<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?;
    if let Some(reason) = value.as_ref() {
        if reason.len() > MAX_DENY_REASON_LENGTH {
            return Err(serde::de::Error::custom(format!(
                "deny_reason length {} exceeds maximum {}",
                reason.len(),
                MAX_DENY_REASON_LENGTH,
            )));
        }
    }
    Ok(value)
}

fn deserialize_evaluators<'de, D>(deserializer: D) -> Result<Vec<EvaluatorTuple>, D::Error>
where
    D: Deserializer<'de>,
{
    let evaluators = Vec::<EvaluatorTuple>::deserialize(deserializer)?;
    if evaluators.len() > MAX_EVALUATORS {
        return Err(serde::de::Error::custom(format!(
            "evaluators length {} exceeds maximum {}",
            evaluators.len(),
            MAX_EVALUATORS,
        )));
    }
    Ok(evaluators)
}

fn deserialize_action_reason<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_reason_with_limit(deserializer)
}

fn deserialize_violation_detail<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_reason_with_limit(deserializer)
}

fn deserialize_reason_with_limit<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if value.len() > MAX_DENY_REASON_LENGTH {
        return Err(serde::de::Error::custom(format!(
            "string length {} exceeds maximum {}",
            value.len(),
            MAX_DENY_REASON_LENGTH,
        )));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn test_signer() -> Signer {
        Signer::from_bytes(&[0x5A; 32]).expect("deterministic temporal arbitration signer")
    }

    fn valid_tuple() -> EvaluatorTuple {
        EvaluatorTuple {
            evaluator_id: "eval-a".to_string(),
            predicate_id: TemporalPredicateId::TpEio29001,
            contract_digest_set: hash(0x11),
            canonicalizer_tuple: hash(0x22),
            time_authority_ref: hash(0x33),
            window_ref: hash(0x44),
            verdict: ArbitrationOutcome::AgreedAllow,
            deny_reason: None,
        }
    }

    fn valid_receipt() -> TemporalArbitrationReceiptV1 {
        let mut tuple_b = valid_tuple();
        tuple_b.evaluator_id = "eval-b".to_string();

        let mut receipt = TemporalArbitrationReceiptV1 {
            predicate_id: TemporalPredicateId::TpEio29001,
            evaluators: vec![valid_tuple(), tuple_b],
            aggregate_outcome: ArbitrationOutcome::AgreedAllow,
            time_envelope_ref: hash(0x99),
            arbitrated_at_tick: 42,
            deadline_tick: None,
            content_digest: hash(0xAA),
            signer_id: [0u8; 32],
            signature: [0u8; 64],
        };
        receipt.sign(&test_signer());
        receipt
    }

    #[test]
    fn test_agreed_allow_continues() {
        let action = map_arbitration_outcome(
            ArbitrationOutcome::AgreedAllow,
            TemporalPredicateId::TpEio29001,
        );
        assert_eq!(action, ArbitrationAction::Continue);
    }

    #[test]
    fn test_agreed_deny_denies() {
        let action = map_arbitration_outcome(
            ArbitrationOutcome::AgreedDeny,
            TemporalPredicateId::TpEio29001,
        );
        assert!(matches!(action, ArbitrationAction::Deny { .. }));
    }

    #[test]
    fn test_transient_disagreement_freezes() {
        let action = map_arbitration_outcome(
            ArbitrationOutcome::DisagreementTransient,
            TemporalPredicateId::TpEio29008,
        );
        assert!(matches!(
            action,
            ArbitrationAction::FreezeAndRequireAdjudication { .. }
        ));
    }

    #[test]
    fn test_persistent_disagreement_rebaselines() {
        let action = map_arbitration_outcome(
            ArbitrationOutcome::DisagreementPersistent,
            TemporalPredicateId::TpEio29008,
        );
        assert!(matches!(
            action,
            ArbitrationAction::DenyAndRebaseline { .. }
        ));
    }

    #[test]
    fn test_freshness_within_window_passes() {
        let result = check_freshness_dominance(95, 100, 5);
        assert!(result.is_ok());
    }

    #[test]
    fn test_freshness_stale_denied() {
        let result = check_freshness_dominance(90, 100, 5);
        assert!(result.is_err());
        let violation = result.unwrap_err();
        assert_eq!(violation.witness_tick, 90);
        assert_eq!(violation.current_tick, 100);
        assert_eq!(violation.max_age_ticks, 5);
    }

    #[test]
    fn test_revocation_head_unchanged_passes() {
        let head = hash(0xAB);
        let result = check_revocation_dominance(&head, &head);
        assert!(result.is_ok());
    }

    #[test]
    fn test_revocation_head_advanced_denied() {
        let result = check_revocation_dominance(&hash(0xAB), &hash(0xCD));
        assert!(result.is_err());
    }

    #[test]
    fn test_evaluator_tuple_validation() {
        let tuple = valid_tuple();
        assert!(tuple.validate().is_ok());

        let mut invalid = valid_tuple();
        invalid.evaluator_id = "x".repeat(MAX_EVALUATOR_ID_LENGTH + 1);
        assert!(invalid.validate().is_err());

        let mut invalid_reason = valid_tuple();
        invalid_reason.verdict = ArbitrationOutcome::AgreedDeny;
        invalid_reason.deny_reason = None;
        assert!(invalid_reason.validate().is_err());
    }

    #[test]
    fn test_arbitration_receipt_serialization() {
        let receipt = valid_receipt();

        assert!(receipt.validate().is_ok());

        let json = serde_json::to_string(&receipt).unwrap();
        let decoded: TemporalArbitrationReceiptV1 = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, receipt);
        assert!(decoded.validate().is_ok());
    }

    #[test]
    fn test_tp_eio29_001_serializes_correctly() {
        let value = serde_json::to_string(&TemporalPredicateId::TpEio29001).unwrap();
        assert_eq!(value, "\"TP-EIO29-001\"");
    }

    #[test]
    fn test_tp_eio29_008_serializes_correctly() {
        let value = serde_json::to_string(&TemporalPredicateId::TpEio29008).unwrap();
        assert_eq!(value, "\"TP-EIO29-008\"");
    }

    #[test]
    fn test_mismatched_contract_digest_rejected() {
        let mut receipt = valid_receipt();
        receipt.evaluators[1].contract_digest_set = hash(0xFE);
        let err = receipt.validate().unwrap_err();
        assert!(err.contains("contract_digest_set mismatch"));
    }

    #[test]
    fn test_mismatched_canonicalizer_tuple_rejected() {
        let mut receipt = valid_receipt();
        receipt.evaluators[1].canonicalizer_tuple = hash(0xFE);
        let err = receipt.validate().unwrap_err();
        assert!(err.contains("canonicalizer_tuple mismatch"));
    }

    #[test]
    fn test_mismatched_time_authority_rejected() {
        let mut receipt = valid_receipt();
        receipt.evaluators[1].time_authority_ref = hash(0xFE);
        let err = receipt.validate().unwrap_err();
        assert!(err.contains("time_authority_ref mismatch"));
    }

    #[test]
    fn test_mismatched_window_ref_rejected() {
        let mut receipt = valid_receipt();
        receipt.evaluators[1].window_ref = hash(0xFE);
        let err = receipt.validate().unwrap_err();
        assert!(err.contains("window_ref mismatch"));
    }

    #[test]
    fn test_too_many_evaluators_rejected() {
        let mut evaluators = Vec::with_capacity(MAX_EVALUATORS + 1);
        for i in 0..=MAX_EVALUATORS {
            let mut tuple = valid_tuple();
            tuple.evaluator_id = format!("eval-{i:03}");
            evaluators.push(tuple);
        }

        let receipt = TemporalArbitrationReceiptV1 {
            predicate_id: TemporalPredicateId::TpEio29001,
            evaluators,
            aggregate_outcome: ArbitrationOutcome::AgreedAllow,
            time_envelope_ref: hash(0x99),
            arbitrated_at_tick: 42,
            deadline_tick: None,
            content_digest: hash(0xAA),
            signer_id: [0u8; 32],
            signature: [0u8; 64],
        };

        let err = receipt.validate().unwrap_err();
        assert!(err.contains("evaluators length"));

        let json = serde_json::to_string(&receipt).unwrap();
        let decode_err = serde_json::from_str::<TemporalArbitrationReceiptV1>(&json).unwrap_err();
        assert!(decode_err.to_string().contains("evaluators length"));
    }

    #[test]
    fn test_deadline_miss_escalates_to_persistent() {
        let mut tuple_a = valid_tuple();
        tuple_a.predicate_id = TemporalPredicateId::TpEio29008;
        tuple_a.verdict = ArbitrationOutcome::DisagreementTransient;
        tuple_a.deny_reason = Some("awaiting adjudication".to_string());

        let mut tuple_b = tuple_a.clone();
        tuple_b.evaluator_id = "eval-b".to_string();

        let mut receipt = TemporalArbitrationReceiptV1 {
            predicate_id: TemporalPredicateId::TpEio29008,
            evaluators: vec![tuple_a, tuple_b],
            aggregate_outcome: ArbitrationOutcome::DisagreementTransient,
            time_envelope_ref: hash(0x99),
            arbitrated_at_tick: 42,
            deadline_tick: Some(100),
            content_digest: hash(0xAA),
            signer_id: [0u8; 32],
            signature: [0u8; 64],
        };
        receipt.sign(&test_signer());

        assert!(receipt.validate().is_ok());
        assert!(receipt.check_deadline_miss(101));
        let action = map_arbitration_outcome(
            receipt.effective_outcome(101),
            TemporalPredicateId::TpEio29008,
        );
        assert!(matches!(
            action,
            ArbitrationAction::DenyAndRebaseline { .. }
        ));
    }

    #[test]
    fn test_transient_disagreement_requires_deadline() {
        let mut tuple_a = valid_tuple();
        tuple_a.predicate_id = TemporalPredicateId::TpEio29008;
        tuple_a.verdict = ArbitrationOutcome::DisagreementTransient;
        tuple_a.deny_reason = Some("awaiting adjudication".to_string());

        let mut tuple_b = tuple_a.clone();
        tuple_b.evaluator_id = "eval-b".to_string();

        let receipt = TemporalArbitrationReceiptV1 {
            predicate_id: TemporalPredicateId::TpEio29008,
            evaluators: vec![tuple_a, tuple_b],
            aggregate_outcome: ArbitrationOutcome::DisagreementTransient,
            time_envelope_ref: hash(0x99),
            arbitrated_at_tick: 42,
            deadline_tick: None,
            content_digest: hash(0xAA),
            signer_id: [0u8; 32],
            signature: [0u8; 64],
        };

        let err = receipt.validate().unwrap_err();
        assert!(err.contains("DisagreementTransient requires deadline_tick"));
    }

    #[test]
    fn test_transient_disagreement_deadline_must_exceed_arbitrated_at() {
        let mut tuple_a = valid_tuple();
        tuple_a.predicate_id = TemporalPredicateId::TpEio29008;
        tuple_a.verdict = ArbitrationOutcome::DisagreementTransient;
        tuple_a.deny_reason = Some("awaiting adjudication".to_string());

        let mut tuple_b = tuple_a.clone();
        tuple_b.evaluator_id = "eval-b".to_string();

        let receipt = TemporalArbitrationReceiptV1 {
            predicate_id: TemporalPredicateId::TpEio29008,
            evaluators: vec![tuple_a, tuple_b],
            aggregate_outcome: ArbitrationOutcome::DisagreementTransient,
            time_envelope_ref: hash(0x99),
            arbitrated_at_tick: 42,
            deadline_tick: Some(42),
            content_digest: hash(0xAA),
            signer_id: [0u8; 32],
            signature: [0u8; 64],
        };

        let err = receipt.validate().unwrap_err();
        assert!(err.contains("deadline_tick must be strictly greater than arbitrated_at_tick"));
    }

    #[test]
    fn test_zero_revocation_head_fails() {
        let zero = [0u8; 32];
        let result = check_revocation_dominance(&zero, &hash(0x10));
        assert!(result.is_err());

        let result = check_revocation_dominance(&hash(0x10), &zero);
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_receipt_fails_validation() {
        let mut receipt = valid_receipt();
        receipt.arbitrated_at_tick += 1;
        let err = receipt.validate().unwrap_err();
        assert!(err.contains("signature verification failed"));
    }

    #[test]
    fn test_unsigned_receipt_fails_validation() {
        let mut receipt = valid_receipt();
        receipt.signature = [0u8; 64];
        let err = receipt.validate().unwrap_err();
        assert!(err.contains("signature must not be zero"));
    }
}
