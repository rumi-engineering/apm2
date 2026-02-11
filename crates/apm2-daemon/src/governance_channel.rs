//! Governance channel handling for cross-cell stop/rotation/ratchet actions.
//!
//! This module processes signed governance messages carried on HMP governance
//! channels, routes stop actions into runtime stop authority, applies rotation
//! announcements via pluggable sinks, and emits auditable receipts.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;

use apm2_core::crypto::{Hash, Signer, parse_signature, verify_signature};
use apm2_core::governance::{
    GOVERNANCE_SIGNATURE_LEN, GovernanceMessageError, GovernanceRatchetUpdateV1,
    GovernanceRotationAnnouncementV1, GovernanceStopClass, GovernanceStopOrderV1,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::episode::preactuation::StopAuthority;
use crate::hmp::admission::ImportAdmissionGate;
use crate::hmp::{HmpMessageV1, VerificationMethod};

/// Maximum age of a governance message in milliseconds (5 minutes).
/// Messages older than this relative to `admitted_at_hlc` are rejected as
/// stale.
pub const MAX_GOVERNANCE_MESSAGE_AGE_MS: u64 = 300_000;
/// Maximum future tolerance for governance message timestamps in milliseconds
/// (30 seconds). Messages with `timestamp_ms` more than this far ahead of
/// `admitted_at_hlc` are rejected.
pub const GOVERNANCE_FUTURE_TOLERANCE_MS: u64 = 30_000;
/// Maximum retained governance action receipts.
pub const MAX_GOVERNANCE_ACTION_RECEIPTS: usize = 4_096;
/// Maximum retained breakglass receipts.
pub const MAX_BREAKGLASS_RECEIPTS: usize = 4_096;
/// Maximum active breakglass authorizations.
pub const MAX_BREAKGLASS_AUTHS: usize = 512;
/// Maximum operator identifier length.
pub const MAX_BREAKGLASS_OPERATOR_ID_LEN: usize = 128;
/// Maximum breakglass reason length.
pub const MAX_BREAKGLASS_REASON_LEN: usize = 1_024;
/// Maximum breakglass scope length.
pub const MAX_BREAKGLASS_SCOPE_LEN: usize = 128;

/// Governance handler errors.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum GovernanceChannelError {
    /// Envelope validation or admission failed.
    #[error("HMP governance envelope rejected: {reason}")]
    EnvelopeRejected {
        /// Rejection reason.
        reason: String,
    },
    /// Body hash mismatch against envelope body reference.
    #[error("governance body hash mismatch")]
    BodyHashMismatch,
    /// Unsupported governance message class.
    #[error("unsupported governance message class '{message_class}'")]
    UnsupportedMessageClass {
        /// Unsupported message class.
        message_class: String,
    },
    /// Governance message payload decode failed.
    #[error("governance payload decode failed: {reason}")]
    PayloadDecode {
        /// Decode reason.
        reason: String,
    },
    /// Governance message validation failed.
    #[error("governance message validation failed: {0}")]
    MessageValidation(#[from] GovernanceMessageError),
    /// Signature verification failed.
    #[error("governance signature verification failed: {reason}")]
    SignatureVerificationFailed {
        /// Failure reason.
        reason: String,
    },
    /// Envelope sender identity does not match payload issuer identity.
    #[error("sender identity mismatch between envelope and payload")]
    SenderMismatch,
    /// Governance message timestamp is outside the acceptable freshness window.
    #[error("governance message timestamp freshness check failed: {reason}")]
    MessageTimestampFreshness {
        /// Freshness failure reason.
        reason: String,
    },
    /// Message target does not match local cell.
    #[error("target cell mismatch: expected '{expected}', got '{actual}'")]
    TargetCellMismatch {
        /// Expected local cell identifier.
        expected: String,
        /// Actual target identifier from message.
        actual: String,
    },
    /// Breakglass authorization failed.
    #[error("breakglass authorization required or invalid: {reason}")]
    BreakglassDenied {
        /// Authorization failure reason.
        reason: String,
    },
    /// Rotation sink rejected an announcement.
    #[error("rotation sink rejected announcement: {reason}")]
    RotationSinkRejected {
        /// Rejection reason.
        reason: String,
    },
}

/// Governance enforcement level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GovernanceEnforcementLevel {
    /// Observe-only posture.
    G0,
    /// Warn posture.
    G1,
    /// Enforce posture.
    G2,
}

/// Breakglass authorization token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BreakglassAuthorization {
    /// Operator identifier invoking breakglass.
    pub operator_id: String,
    /// Human-readable reason.
    pub reason: String,
    /// Authorization validity start.
    pub valid_from_ms: u64,
    /// Authorization validity end.
    pub valid_until_ms: u64,
    /// Monotonically increasing sequence number per operator.
    /// Authorizations with a sequence number <= the previously accepted
    /// sequence number for the same operator are rejected as replays.
    pub sequence_number: u64,
    /// Signature over authorization fields.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signature: Vec<u8>,
}

impl BreakglassAuthorization {
    /// Validates structural and bounded constraints.
    ///
    /// # Errors
    ///
    /// Returns [`GovernanceChannelError::BreakglassDenied`] when validation
    /// fails.
    pub fn validate(&self) -> Result<(), GovernanceChannelError> {
        if self.operator_id.is_empty() {
            return Err(GovernanceChannelError::BreakglassDenied {
                reason: "operator_id must be non-empty".to_string(),
            });
        }
        if self.operator_id.len() > MAX_BREAKGLASS_OPERATOR_ID_LEN {
            return Err(GovernanceChannelError::BreakglassDenied {
                reason: format!(
                    "operator_id too long: {} > {}",
                    self.operator_id.len(),
                    MAX_BREAKGLASS_OPERATOR_ID_LEN
                ),
            });
        }
        if self.reason.is_empty() {
            return Err(GovernanceChannelError::BreakglassDenied {
                reason: "reason must be non-empty".to_string(),
            });
        }
        if self.reason.len() > MAX_BREAKGLASS_REASON_LEN {
            return Err(GovernanceChannelError::BreakglassDenied {
                reason: format!(
                    "reason too long: {} > {}",
                    self.reason.len(),
                    MAX_BREAKGLASS_REASON_LEN
                ),
            });
        }
        if self.valid_until_ms < self.valid_from_ms {
            return Err(GovernanceChannelError::BreakglassDenied {
                reason: "valid_until_ms < valid_from_ms".to_string(),
            });
        }
        if !self.signature.is_empty() && self.signature.len() != GOVERNANCE_SIGNATURE_LEN {
            return Err(GovernanceChannelError::BreakglassDenied {
                reason: format!(
                    "invalid breakglass signature length: {}",
                    self.signature.len()
                ),
            });
        }
        Ok(())
    }

    /// Returns `true` if authorization is active at `now_ms`.
    #[must_use]
    pub const fn is_active_at(&self, now_ms: u64) -> bool {
        self.valid_from_ms <= now_ms && now_ms <= self.valid_until_ms
    }

    /// Computes signable bytes for this authorization.
    #[must_use]
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(256);
        bytes.extend_from_slice(b"GOV_BREAKGLASS_AUTH_V1\0");
        write_len_prefixed_string(&mut bytes, &self.operator_id);
        write_len_prefixed_string(&mut bytes, &self.reason);
        bytes.extend_from_slice(&self.valid_from_ms.to_be_bytes());
        bytes.extend_from_slice(&self.valid_until_ms.to_be_bytes());
        bytes.extend_from_slice(&self.sequence_number.to_be_bytes());
        bytes
    }

    /// Signs this authorization with `signer`.
    ///
    /// # Errors
    ///
    /// Returns [`GovernanceChannelError::BreakglassDenied`] when validation
    /// fails.
    pub fn sign(&mut self, signer: &Signer) -> Result<(), GovernanceChannelError> {
        self.validate()?;
        self.signature = signer.sign(&self.signable_bytes()).to_bytes().to_vec();
        Ok(())
    }

    /// Verifies this authorization signature.
    ///
    /// # Errors
    ///
    /// Returns [`GovernanceChannelError::BreakglassDenied`] when verification
    /// fails.
    pub fn verify_signature(
        &self,
        verifying_key: &apm2_core::crypto::VerifyingKey,
    ) -> Result<(), GovernanceChannelError> {
        self.validate()?;
        if self.signature.is_empty() {
            return Err(GovernanceChannelError::BreakglassDenied {
                reason: "missing breakglass signature".to_string(),
            });
        }
        let signature = parse_signature(&self.signature).map_err(|error| {
            GovernanceChannelError::BreakglassDenied {
                reason: format!("signature parse failed: {error}"),
            }
        })?;
        verify_signature(verifying_key, &self.signable_bytes(), &signature).map_err(|error| {
            GovernanceChannelError::BreakglassDenied {
                reason: format!("signature verification failed: {error}"),
            }
        })
    }
}

/// Breakglass invocation receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BreakglassReceiptV1 {
    /// Operator identity that invoked breakglass.
    pub operator_id: String,
    /// Invocation scope (for example `governance.ratchet.g2`).
    pub scope: String,
    /// Invocation reason.
    pub reason: String,
    /// Invocation timestamp.
    pub invoked_at_ms: u64,
    /// Authorization expiry timestamp.
    pub valid_until_ms: u64,
    /// Governance message identifier tied to this invocation.
    pub message_id: Hash,
}

/// Runtime control for breakglass authorizations and receipt emission.
#[derive(Debug, Clone)]
pub struct BreakglassControl {
    active: BTreeMap<String, BreakglassAuthorization>,
    /// Tracks highest accepted `sequence_number` per `operator_id`.
    accepted_sequences: BTreeMap<String, u64>,
    receipts: VecDeque<BreakglassReceiptV1>,
    max_active: usize,
    max_receipts: usize,
}

impl Default for BreakglassControl {
    fn default() -> Self {
        Self::new(MAX_BREAKGLASS_AUTHS, MAX_BREAKGLASS_RECEIPTS)
    }
}

impl BreakglassControl {
    /// Creates a new breakglass control surface with bounded storage.
    #[must_use]
    pub const fn new(max_active: usize, max_receipts: usize) -> Self {
        Self {
            active: BTreeMap::new(),
            accepted_sequences: BTreeMap::new(),
            receipts: VecDeque::new(),
            max_active,
            max_receipts,
        }
    }

    /// Registers a breakglass authorization after signature verification.
    ///
    /// # Errors
    ///
    /// Returns [`GovernanceChannelError::BreakglassDenied`] when
    /// authorization is invalid or storage bounds are exceeded.
    pub fn authorize(
        &mut self,
        authorization: BreakglassAuthorization,
        verifying_key: &apm2_core::crypto::VerifyingKey,
    ) -> Result<(), GovernanceChannelError> {
        authorization.verify_signature(verifying_key)?;
        // Enforce monotonic sequence_number per operator (anti-replay)
        if let Some(&stored_seq) = self.accepted_sequences.get(&authorization.operator_id) {
            if authorization.sequence_number <= stored_seq {
                return Err(GovernanceChannelError::BreakglassDenied {
                    reason: format!(
                        "sequence_number {} is not greater than previously accepted {} for operator '{}'",
                        authorization.sequence_number, stored_seq, authorization.operator_id
                    ),
                });
            }
        }
        if !self.active.contains_key(&authorization.operator_id)
            && self.active.len() >= self.max_active
        {
            return Err(GovernanceChannelError::BreakglassDenied {
                reason: format!("max active authorizations reached ({})", self.max_active),
            });
        }
        self.accepted_sequences.insert(
            authorization.operator_id.clone(),
            authorization.sequence_number,
        );
        self.active
            .insert(authorization.operator_id.clone(), authorization);
        Ok(())
    }

    /// Consumes a valid breakglass authorization for a scoped action.
    ///
    /// # Errors
    ///
    /// Returns [`GovernanceChannelError::BreakglassDenied`] when no valid
    /// authorization is available.
    pub fn consume(
        &mut self,
        operator_id: &str,
        scope: &str,
        message_id: Hash,
        now_ms: u64,
    ) -> Result<BreakglassReceiptV1, GovernanceChannelError> {
        if scope.is_empty() {
            return Err(GovernanceChannelError::BreakglassDenied {
                reason: "scope must be non-empty".to_string(),
            });
        }
        if scope.len() > MAX_BREAKGLASS_SCOPE_LEN {
            return Err(GovernanceChannelError::BreakglassDenied {
                reason: format!(
                    "scope too long: {} > {}",
                    scope.len(),
                    MAX_BREAKGLASS_SCOPE_LEN
                ),
            });
        }

        let Some(auth) = self.active.get(operator_id) else {
            return Err(GovernanceChannelError::BreakglassDenied {
                reason: "no active authorization for operator".to_string(),
            });
        };
        if !auth.is_active_at(now_ms) {
            return Err(GovernanceChannelError::BreakglassDenied {
                reason: "authorization expired or not yet active".to_string(),
            });
        }

        let receipt = BreakglassReceiptV1 {
            operator_id: auth.operator_id.clone(),
            scope: scope.to_string(),
            reason: auth.reason.clone(),
            invoked_at_ms: now_ms,
            valid_until_ms: auth.valid_until_ms,
            message_id,
        };
        self.receipts.push_back(receipt.clone());
        while self.receipts.len() > self.max_receipts {
            let _ = self.receipts.pop_front();
        }
        Ok(receipt)
    }

    /// Returns all retained breakglass receipts.
    #[must_use]
    pub fn receipts(&self) -> Vec<BreakglassReceiptV1> {
        self.receipts.iter().cloned().collect()
    }
}

/// Governance action classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GovernanceActionKind {
    /// Stop-order action.
    StopOrder,
    /// Rotation announcement action.
    RotationAnnouncement,
    /// Ratchet update action.
    RatchetUpdate,
}

/// Auditable receipt for cross-cell governance actions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernanceActionReceiptV1 {
    /// Action kind.
    pub action_kind: GovernanceActionKind,
    /// Envelope message identifier.
    pub message_id: Hash,
    /// Canonical hash of admitted governance payload.
    pub admitted_payload_hash: Hash,
    /// Admission receipt hash emitted by HMP pipeline.
    pub admission_receipt_hash: Hash,
    /// Action timestamp in milliseconds.
    pub action_timestamp_ms: u64,
    /// Whether action authentication succeeded.
    pub authenticated: bool,
    /// Optional breakglass receipt.
    pub breakglass_receipt: Option<BreakglassReceiptV1>,
}

/// Pluggable sink for rotation announcements.
pub trait GovernanceRotationSink: Send + Sync {
    /// Applies a validated rotation announcement.
    fn apply_rotation(
        &self,
        announcement: &GovernanceRotationAnnouncementV1,
    ) -> Result<(), GovernanceChannelError>;
}

/// In-memory rotation sink for deterministic testing and local execution.
#[derive(Debug, Default)]
pub struct InMemoryRotationSink {
    announcements: std::sync::Mutex<Vec<GovernanceRotationAnnouncementV1>>,
}

impl InMemoryRotationSink {
    /// Returns all retained announcements.
    #[must_use]
    pub fn announcements(&self) -> Vec<GovernanceRotationAnnouncementV1> {
        self.announcements
            .lock()
            .expect("rotation sink lock poisoned")
            .clone()
    }
}

impl GovernanceRotationSink for InMemoryRotationSink {
    fn apply_rotation(
        &self,
        announcement: &GovernanceRotationAnnouncementV1,
    ) -> Result<(), GovernanceChannelError> {
        self.announcements
            .lock()
            .expect("rotation sink lock poisoned")
            .push(announcement.clone());
        Ok(())
    }
}

/// Governance-channel handler.
pub struct GovernanceChannelHandler {
    local_cell_id: String,
    stop_authority: Arc<StopAuthority>,
    import_gate: ImportAdmissionGate,
    breakglass: BreakglassControl,
    rotation_sink: Arc<dyn GovernanceRotationSink>,
    enforcement_level: GovernanceEnforcementLevel,
    action_receipts: VecDeque<GovernanceActionReceiptV1>,
    max_action_receipts: usize,
    breakglass_invocations: u64,
    total_actions: u64,
}

impl GovernanceChannelHandler {
    /// Creates a governance handler with in-memory rotation sink.
    #[must_use]
    pub fn new(local_cell_id: String, stop_authority: Arc<StopAuthority>) -> Self {
        Self::with_rotation_sink(
            local_cell_id,
            stop_authority,
            Arc::new(InMemoryRotationSink::default()),
        )
    }

    /// Creates a governance handler with a custom rotation sink.
    #[must_use]
    pub fn with_rotation_sink(
        local_cell_id: String,
        stop_authority: Arc<StopAuthority>,
        rotation_sink: Arc<dyn GovernanceRotationSink>,
    ) -> Self {
        let import_gate = ImportAdmissionGate::new(
            crate::hmp::admission::DigestFirstFetchPolicy::default_bounded(),
            local_cell_id.clone(),
        );
        Self {
            local_cell_id,
            stop_authority,
            import_gate,
            breakglass: BreakglassControl::default(),
            rotation_sink,
            enforcement_level: GovernanceEnforcementLevel::G1,
            action_receipts: VecDeque::new(),
            max_action_receipts: MAX_GOVERNANCE_ACTION_RECEIPTS,
            breakglass_invocations: 0,
            total_actions: 0,
        }
    }

    /// Returns current governance enforcement level.
    #[must_use]
    pub const fn enforcement_level(&self) -> GovernanceEnforcementLevel {
        self.enforcement_level
    }

    /// Sets governance enforcement level.
    pub const fn set_enforcement_level(&mut self, level: GovernanceEnforcementLevel) {
        self.enforcement_level = level;
    }

    /// Attempts to ratchet from `G1` to `G2` based on breakglass escape rate.
    ///
    /// Returns `true` when ratcheted.
    pub fn try_ratchet_to_g2(&mut self, max_escape_rate_per_thousand: u64) -> bool {
        if self.enforcement_level != GovernanceEnforcementLevel::G1 || self.total_actions == 0 {
            return false;
        }
        let escape_rate =
            self.breakglass_invocations.saturating_mul(1_000) / self.total_actions.max(1);
        if escape_rate < max_escape_rate_per_thousand {
            self.enforcement_level = GovernanceEnforcementLevel::G2;
            return true;
        }
        false
    }

    /// Returns retained governance action receipts.
    #[must_use]
    pub fn action_receipts(&self) -> Vec<GovernanceActionReceiptV1> {
        self.action_receipts.iter().cloned().collect()
    }

    /// Returns retained breakglass receipts.
    #[must_use]
    pub fn breakglass_receipts(&self) -> Vec<BreakglassReceiptV1> {
        self.breakglass.receipts()
    }

    /// Registers a breakglass authorization.
    ///
    /// # Errors
    ///
    /// Returns [`GovernanceChannelError`] when authorization is invalid.
    pub fn authorize_breakglass(
        &mut self,
        authorization: BreakglassAuthorization,
        operator_verifying_key: &apm2_core::crypto::VerifyingKey,
    ) -> Result<(), GovernanceChannelError> {
        self.breakglass
            .authorize(authorization, operator_verifying_key)
    }

    /// Processes one governance message through HMP admission and signed
    /// payload handling.
    ///
    /// # Errors
    ///
    /// Returns [`GovernanceChannelError`] when admission/authentication or
    /// enforcement checks fail.
    pub fn process_message(
        &mut self,
        envelope: &HmpMessageV1,
        payload_bytes: &[u8],
        sender_verifying_key: &apm2_core::crypto::VerifyingKey,
        local_ledger_anchor: Hash,
        admitted_at_hlc: u64,
        breakglass_operator_id: Option<&str>,
    ) -> Result<GovernanceActionReceiptV1, GovernanceChannelError> {
        envelope
            .validate()
            .map_err(|error| GovernanceChannelError::EnvelopeRejected {
                reason: error.to_string(),
            })?;
        if envelope.channel_class != crate::hmp::ChannelClass::Governance {
            return Err(GovernanceChannelError::EnvelopeRejected {
                reason: "message is not on governance channel".to_string(),
            });
        }

        let payload_hash = apm2_core::crypto::EventHasher::hash_content(payload_bytes);
        if payload_hash != envelope.body_ref.cas_hash {
            return Err(GovernanceChannelError::BodyHashMismatch);
        }

        let (_decisions, admission_receipt) = self
            .import_gate
            .evaluate_admission(
                envelope,
                &[payload_hash],
                VerificationMethod::SingleSignature,
                local_ledger_anchor,
                admitted_at_hlc,
                |hash| {
                    if hash == &payload_hash {
                        Ok(())
                    } else {
                        Err("payload hash mismatch".to_string())
                    }
                },
            )
            .map_err(|error| GovernanceChannelError::EnvelopeRejected {
                reason: error.to_string(),
            })?;

        let admission_receipt_hash = admission_receipt.compute_receipt_hash();
        let action_timestamp_ms = admitted_at_hlc;

        let (action_kind, breakglass_receipt) = if envelope.message_class
            == "HSI.GOVERNANCE.STOP_ORDER.V1"
        {
            let message: GovernanceStopOrderV1 =
                serde_json::from_slice(payload_bytes).map_err(|error| {
                    GovernanceChannelError::PayloadDecode {
                        reason: error.to_string(),
                    }
                })?;
            message.validate()?;
            message
                .verify_signature(sender_verifying_key)
                .map_err(
                    |error| GovernanceChannelError::SignatureVerificationFailed {
                        reason: error.to_string(),
                    },
                )?;
            if message.issuer_cell_id != envelope.sender_cell_id {
                return Err(GovernanceChannelError::SenderMismatch);
            }
            self.enforce_message_freshness(message.timestamp_ms, admitted_at_hlc)?;
            self.enforce_target_cell(&message.target_cell_id, breakglass_operator_id, envelope)?;
            self.route_stop_class(message.stop_class);
            (GovernanceActionKind::StopOrder, None)
        } else if envelope.message_class == "HSI.GOVERNANCE.ROTATION_ANNOUNCEMENT.V1" {
            let message: GovernanceRotationAnnouncementV1 = serde_json::from_slice(payload_bytes)
                .map_err(|error| {
                GovernanceChannelError::PayloadDecode {
                    reason: error.to_string(),
                }
            })?;
            message.validate()?;
            message
                .verify_signature(sender_verifying_key)
                .map_err(
                    |error| GovernanceChannelError::SignatureVerificationFailed {
                        reason: error.to_string(),
                    },
                )?;
            if message.cell_id != envelope.sender_cell_id {
                return Err(GovernanceChannelError::SenderMismatch);
            }
            self.enforce_message_freshness(message.timestamp_ms, admitted_at_hlc)?;
            self.enforce_target_cell(
                &self.local_cell_id.clone(),
                breakglass_operator_id,
                envelope,
            )?;
            self.rotation_sink.apply_rotation(&message)?;
            (GovernanceActionKind::RotationAnnouncement, None)
        } else if envelope.message_class == "HSI.GOVERNANCE.RATCHET_UPDATE.V1" {
            let message: GovernanceRatchetUpdateV1 = serde_json::from_slice(payload_bytes)
                .map_err(|error| GovernanceChannelError::PayloadDecode {
                    reason: error.to_string(),
                })?;
            message.validate()?;
            message
                .verify_signature(sender_verifying_key)
                .map_err(
                    |error| GovernanceChannelError::SignatureVerificationFailed {
                        reason: error.to_string(),
                    },
                )?;
            if message.cell_id != envelope.sender_cell_id {
                return Err(GovernanceChannelError::SenderMismatch);
            }
            self.enforce_message_freshness(message.timestamp_ms, admitted_at_hlc)?;

            let breakglass_receipt = if self.enforcement_level == GovernanceEnforcementLevel::G2
                && message.tightens_enforcement()
            {
                let Some(operator_id) = breakglass_operator_id else {
                    return Err(GovernanceChannelError::BreakglassDenied {
                        reason: "G2 ratchet-tightening update requires breakglass authorization"
                            .to_string(),
                    });
                };
                self.breakglass_invocations = self.breakglass_invocations.saturating_add(1);
                Some(self.breakglass.consume(
                    operator_id,
                    "governance.ratchet.g2",
                    envelope.message_id,
                    admitted_at_hlc,
                )?)
            } else {
                None
            };
            (GovernanceActionKind::RatchetUpdate, breakglass_receipt)
        } else {
            return Err(GovernanceChannelError::UnsupportedMessageClass {
                message_class: envelope.message_class.clone(),
            });
        };

        self.total_actions = self.total_actions.saturating_add(1);
        let receipt = GovernanceActionReceiptV1 {
            action_kind,
            message_id: envelope.message_id,
            admitted_payload_hash: payload_hash,
            admission_receipt_hash,
            action_timestamp_ms,
            authenticated: true,
            breakglass_receipt,
        };
        self.action_receipts.push_back(receipt.clone());
        while self.action_receipts.len() > self.max_action_receipts {
            let _ = self.action_receipts.pop_front();
        }
        Ok(receipt)
    }

    fn route_stop_class(&self, stop_class: GovernanceStopClass) {
        match stop_class {
            GovernanceStopClass::EmergencyStop => self.stop_authority.set_emergency_stop(true),
            GovernanceStopClass::GovernanceStop
            | GovernanceStopClass::EscalationTriggered
            | GovernanceStopClass::MaxEpisodesReached => {
                self.stop_authority.set_governance_stop(true);
            },
        }
    }

    fn enforce_message_freshness(
        &self,
        message_timestamp_ms: u64,
        admitted_at_hlc: u64,
    ) -> Result<(), GovernanceChannelError> {
        let local_cell_id = &self.local_cell_id;
        // Reject messages from the future (beyond tolerance)
        if message_timestamp_ms > admitted_at_hlc.saturating_add(GOVERNANCE_FUTURE_TOLERANCE_MS) {
            return Err(GovernanceChannelError::MessageTimestampFreshness {
                reason: format!(
                    "message timestamp {message_timestamp_ms} is too far in the future (admitted_at_hlc={admitted_at_hlc}, tolerance={GOVERNANCE_FUTURE_TOLERANCE_MS}ms, local_cell_id={local_cell_id})"
                ),
            });
        }
        // Reject stale messages (too old)
        if admitted_at_hlc.saturating_sub(message_timestamp_ms) > MAX_GOVERNANCE_MESSAGE_AGE_MS {
            return Err(GovernanceChannelError::MessageTimestampFreshness {
                reason: format!(
                    "message timestamp {message_timestamp_ms} is too old (admitted_at_hlc={admitted_at_hlc}, max_age={MAX_GOVERNANCE_MESSAGE_AGE_MS}ms, local_cell_id={local_cell_id})"
                ),
            });
        }
        Ok(())
    }

    fn enforce_target_cell(
        &mut self,
        target_cell_id: &str,
        breakglass_operator_id: Option<&str>,
        envelope: &HmpMessageV1,
    ) -> Result<(), GovernanceChannelError> {
        if target_cell_id == self.local_cell_id || target_cell_id == "*" {
            return Ok(());
        }

        if self.enforcement_level == GovernanceEnforcementLevel::G2 {
            let Some(operator_id) = breakglass_operator_id else {
                return Err(GovernanceChannelError::TargetCellMismatch {
                    expected: self.local_cell_id.clone(),
                    actual: target_cell_id.to_string(),
                });
            };
            self.breakglass_invocations = self.breakglass_invocations.saturating_add(1);
            let _ = self.breakglass.consume(
                operator_id,
                "governance.target_cell_mismatch",
                envelope.message_id,
                envelope.hlc_timestamp,
            )?;
            return Ok(());
        }

        Err(GovernanceChannelError::TargetCellMismatch {
            expected: self.local_cell_id.clone(),
            actual: target_cell_id.to_string(),
        })
    }
}

fn write_len_prefixed_string(buf: &mut Vec<u8>, value: &str) {
    let len = u32::try_from(value.len()).unwrap_or(u32::MAX);
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(value.as_bytes());
}

#[cfg(test)]
mod tests {
    use apm2_core::governance::{
        GovernanceRatchetUpdateV1, GovernanceRotationAnnouncementV1, GovernanceStopOrderV1,
        OverlapValidityWindowV1,
    };

    use super::*;

    const fn test_hash(byte: u8) -> Hash {
        [byte; 32]
    }

    fn governance_envelope(message_class: &str, body_hash: Hash) -> HmpMessageV1 {
        HmpMessageV1 {
            protocol_id: "hsi:v1".to_string(),
            message_class: message_class.to_string(),
            message_id: test_hash(7),
            idempotency_key: "idem-001".to_string(),
            hlc_timestamp: 1_000,
            parents: Vec::new(),
            sender_holon_id: "holon-a".to_string(),
            sender_actor_id: "actor-a".to_string(),
            channel_class: crate::hmp::ChannelClass::Governance,
            sender_cell_id: "cell-a".to_string(),
            receiver_cell_id: "cell-local".to_string(),
            sender_policy_root_key_id: "pkid-a".to_string(),
            body_ref: crate::hmp::BodyRef::new(body_hash, "application/json".to_string())
                .expect("body_ref should be valid"),
            ledger_head_hash: test_hash(2),
            context_pack_hash: None,
            manifest_hash: None,
            view_commitment_hash: None,
            permeability_receipt_hash: Some(test_hash(3)),
        }
    }

    #[test]
    fn governance_stop_order_sets_stop_authority() {
        let signer = Signer::generate();
        let stop_authority = Arc::new(StopAuthority::new());
        let mut handler =
            GovernanceChannelHandler::new("cell-local".to_string(), Arc::clone(&stop_authority));

        let mut message = GovernanceStopOrderV1 {
            issuer_cell_id: "cell-a".to_string(),
            target_cell_id: "cell-local".to_string(),
            stop_class: GovernanceStopClass::GovernanceStop,
            reason: "federated stop".to_string(),
            timestamp_ms: 1_000,
            signature: Vec::new(),
        };
        message.sign(&signer).expect("stop order should sign");
        let payload = serde_json::to_vec(&message).expect("payload should serialize");
        let envelope = governance_envelope(
            "HSI.GOVERNANCE.STOP_ORDER.V1",
            apm2_core::crypto::EventHasher::hash_content(&payload),
        );

        let receipt = handler
            .process_message(
                &envelope,
                &payload,
                &signer.verifying_key(),
                test_hash(9),
                1_000,
                None,
            )
            .expect("governance stop should be processed");

        assert_eq!(receipt.action_kind, GovernanceActionKind::StopOrder);
        assert!(stop_authority.governance_stop_active());
        assert_eq!(handler.action_receipts().len(), 1);
    }

    #[test]
    fn governance_rotation_routes_to_rotation_sink() {
        let signer = Signer::generate();
        let stop_authority = Arc::new(StopAuthority::new());
        let sink = Arc::new(InMemoryRotationSink::default());
        let mut handler = GovernanceChannelHandler::with_rotation_sink(
            "cell-local".to_string(),
            Arc::clone(&stop_authority),
            sink.clone(),
        );

        let mut message = GovernanceRotationAnnouncementV1 {
            cell_id: "cell-a".to_string(),
            old_key_id: "old-key".to_string(),
            new_key_id: "new-key".to_string(),
            overlap_validity_window: OverlapValidityWindowV1 {
                not_before_ms: 1_000,
                not_after_ms: 2_000,
            },
            timestamp_ms: 1_500,
            signature: Vec::new(),
        };
        message.sign(&signer).expect("rotation should sign");
        let payload = serde_json::to_vec(&message).expect("payload should serialize");
        let envelope = governance_envelope(
            "HSI.GOVERNANCE.ROTATION_ANNOUNCEMENT.V1",
            apm2_core::crypto::EventHasher::hash_content(&payload),
        );

        let receipt = handler
            .process_message(
                &envelope,
                &payload,
                &signer.verifying_key(),
                test_hash(9),
                1_500,
                None,
            )
            .expect("rotation should process");

        assert_eq!(
            receipt.action_kind,
            GovernanceActionKind::RotationAnnouncement
        );
        assert_eq!(sink.announcements().len(), 1);
    }

    #[test]
    fn governance_ratchet_g2_requires_breakglass() {
        let signer = Signer::generate();
        let operator_signer = Signer::generate();
        let stop_authority = Arc::new(StopAuthority::new());
        let mut handler =
            GovernanceChannelHandler::new("cell-local".to_string(), Arc::clone(&stop_authority));
        handler.set_enforcement_level(GovernanceEnforcementLevel::G2);

        let mut update = GovernanceRatchetUpdateV1 {
            cell_id: "cell-a".to_string(),
            previous_gate_level: "G1".to_string(),
            next_gate_level: "G2".to_string(),
            justification: "incident rollback".to_string(),
            timestamp_ms: 2_000,
            signature: Vec::new(),
        };
        update.sign(&signer).expect("ratchet update should sign");
        let payload = serde_json::to_vec(&update).expect("payload should serialize");
        let envelope = governance_envelope(
            "HSI.GOVERNANCE.RATCHET_UPDATE.V1",
            apm2_core::crypto::EventHasher::hash_content(&payload),
        );

        let denied = handler.process_message(
            &envelope,
            &payload,
            &signer.verifying_key(),
            test_hash(9),
            2_000,
            None,
        );
        assert!(denied.is_err(), "G2 should deny without breakglass");

        let mut auth = BreakglassAuthorization {
            operator_id: "op-001".to_string(),
            reason: "incident mitigation".to_string(),
            valid_from_ms: 1_900,
            valid_until_ms: 2_500,
            sequence_number: 1,
            signature: Vec::new(),
        };
        auth.sign(&operator_signer).expect("auth should sign");
        handler
            .authorize_breakglass(auth, &operator_signer.verifying_key())
            .expect("breakglass auth should register");

        let allowed = handler
            .process_message(
                &envelope,
                &payload,
                &signer.verifying_key(),
                test_hash(9),
                2_000,
                Some("op-001"),
            )
            .expect("G2 should allow with breakglass");
        assert_eq!(allowed.action_kind, GovernanceActionKind::RatchetUpdate);
        assert_eq!(handler.breakglass_receipts().len(), 1);
    }
}
