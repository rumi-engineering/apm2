//! Projection compromise detection, containment, and replay recovery.
//!
//! This module implements RFC-0028 REQ-0009 controls:
//! - divergence detection between authoritative CAS+ledger digests and observed
//!   projection digests
//! - quarantine decisions bound to temporal authority (`time_authority_ref`,
//!   `window_ref`)
//! - replay recovery from durable, signature-verified receipts

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use thiserror::Error;

use super::domain_separator::{
    PROJECTION_COMPROMISE_SIGNAL_PREFIX, PROJECTION_REPLAY_RECEIPT_PREFIX, sign_with_domain,
    verify_with_domain,
};
use crate::crypto::{Hash, Signature, Signer, VerifyingKey, parse_verifying_key};

const MAX_CHANNEL_ID_LENGTH: usize = 256;
const MAX_REASON_LENGTH: usize = 1024;
const MAX_ACTOR_ID_LENGTH: usize = 256;
const MAX_SIGNAL_ID_LENGTH: usize = 256;
const MAX_RECEIPT_ID_LENGTH: usize = 256;
const MAX_REPLAY_RECEIPTS: usize = 4096;

/// Errors returned by projection compromise controls.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProjectionCompromiseError {
    /// A required hash was zero (unset).
    #[error("{field} must not be zero")]
    MissingHash {
        /// Field name.
        field: &'static str,
    },
    /// A bounded string exceeded its limit.
    #[error("string field '{field}' exceeds max length ({actual} > {max})")]
    StringTooLong {
        /// Field name.
        field: &'static str,
        /// Actual length.
        actual: usize,
        /// Maximum allowed length.
        max: usize,
    },
    /// A required string field was empty.
    #[error("missing required field: {field}")]
    MissingField {
        /// Field name.
        field: &'static str,
    },
    /// Expected and actual channel IDs mismatch.
    #[error("channel mismatch: expected={expected}, actual={actual}")]
    ChannelMismatch {
        /// Expected channel ID.
        expected: String,
        /// Actual channel ID.
        actual: String,
    },
    /// Source/sink snapshot linkage mismatch.
    #[error("snapshot mismatch: {detail}")]
    SnapshotMismatch {
        /// Mismatch detail.
        detail: String,
    },
    /// Replay receipts had a gap or out-of-order sequence.
    #[error("missing replay receipt: expected sequence {expected}, actual {actual:?}")]
    MissingReceipt {
        /// Expected sequence.
        expected: u64,
        /// Actual sequence observed.
        actual: Option<u64>,
    },
    /// No receipts were provided for reconstruction.
    #[error("no replay receipts provided")]
    EmptyReceipts,
    /// Too many replay receipts provided.
    #[error("too many replay receipts: {actual} exceeds maximum {max}")]
    TooManyReceipts {
        /// Actual count provided.
        actual: usize,
        /// Maximum allowed.
        max: usize,
    },
    /// Signature verification failed for a signal/receipt.
    #[error("signature verification failed: {detail}")]
    SignatureVerificationFailed {
        /// Failure detail.
        detail: String,
    },
    /// Public key bytes were invalid.
    #[error("invalid signer key: {detail}")]
    InvalidSignerKey {
        /// Failure detail.
        detail: String,
    },
    /// Replay receipt signer actor is not in trusted authority mapping.
    #[error("unknown replay signer actor: {actor_id}")]
    UnknownSignerActor {
        /// Actor identifier carried in replay receipt.
        actor_id: String,
    },
    /// Replay receipt signer key is not trusted for the declared actor.
    #[error("untrusted replay signer key for actor: {actor_id}")]
    UntrustedSignerKey {
        /// Actor identifier carried in replay receipt.
        actor_id: String,
    },
    /// Replay sequence bounds are invalid.
    #[error(
        "invalid replay sequence bounds: start={required_start_sequence}, end={required_end_sequence}"
    )]
    InvalidReplaySequenceBounds {
        /// Required inclusive start sequence.
        required_start_sequence: u64,
        /// Required inclusive end sequence.
        required_end_sequence: u64,
    },
    /// Replay stream contains receipts beyond required sequence bounds.
    #[error(
        "unexpected replay receipt sequence beyond required end: required_end={required_end_sequence}, actual={actual}"
    )]
    UnexpectedReceiptSequence {
        /// Required inclusive end sequence.
        required_end_sequence: u64,
        /// Unexpected sequence observed.
        actual: u64,
    },
    /// Replayed digest did not match authoritative source trust snapshot.
    #[error("reconstructed digest mismatch: expected={expected}, actual={actual}")]
    ReplayDigestMismatch {
        /// Expected digest (hex).
        expected: String,
        /// Actual digest (hex).
        actual: String,
    },
}

/// Trusted authority binding for replay receipt verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityKeyBindingV1 {
    /// Trusted actor identity.
    pub actor_id: String,
    /// Trusted Ed25519 public key bytes.
    #[serde(with = "serde_bytes")]
    pub verifying_key: [u8; 32],
}

/// Required contiguous replay sequence contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplaySequenceBoundsV1 {
    /// Required inclusive start sequence for reconstruction.
    pub required_start_sequence: u64,
    /// Required inclusive end sequence for reconstruction.
    pub required_end_sequence: u64,
}

/// Projection surface type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectionSurfaceType {
    /// Git repository projection.
    GitRepository,
    /// CI status projection.
    CiPipeline,
    /// Deployment endpoint projection.
    DeploymentEndpoint,
    /// API-facing projection endpoint.
    ApiProjection,
}

impl ProjectionSurfaceType {
    const fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::GitRepository => b"git_repository",
            Self::CiPipeline => b"ci_pipeline",
            Self::DeploymentEndpoint => b"deployment_endpoint",
            Self::ApiProjection => b"api_projection",
        }
    }
}

/// Quarantine state for a projection channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineStatus {
    /// Channel is active.
    Active,
    /// Channel is quarantined due to compromise evidence.
    Quarantined {
        /// Quarantine start timestamp (unix nanos).
        quarantined_at_ns: u64,
        /// Time authority reference hash.
        #[serde(with = "serde_bytes")]
        time_authority_ref: Hash,
        /// HTF window reference hash.
        #[serde(with = "serde_bytes")]
        window_ref: Hash,
        /// Human-readable reason.
        reason: String,
    },
}

/// Downstream projection channel bound to authoritative expected state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionChannel {
    /// Unique channel identifier.
    pub channel_id: String,
    /// Projection surface class.
    pub surface_type: ProjectionSurfaceType,
    /// Expected state digest derived from authoritative CAS+ledger roots.
    #[serde(with = "serde_bytes")]
    pub expected_state_digest: Hash,
    /// Current quarantine status.
    pub quarantine_status: QuarantineStatus,
}

impl ProjectionChannel {
    /// Creates a projection channel in active state.
    ///
    /// # Errors
    ///
    /// Returns an error when required fields are missing or invalid.
    pub fn new(
        channel_id: impl Into<String>,
        surface_type: ProjectionSurfaceType,
        expected_state_digest: Hash,
    ) -> Result<Self, ProjectionCompromiseError> {
        let channel_id = channel_id.into();
        validate_required_string("channel_id", &channel_id, MAX_CHANNEL_ID_LENGTH)?;
        validate_non_zero_hash("expected_state_digest", &expected_state_digest)?;

        Ok(Self {
            channel_id,
            surface_type,
            expected_state_digest,
            quarantine_status: QuarantineStatus::Active,
        })
    }
}

/// Digest-bound divergence evidence tuple.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DivergenceEvidence {
    /// CAS-derived expected digest.
    #[serde(with = "serde_bytes")]
    pub cas_state_digest: Hash,
    /// Ledger-derived expected digest.
    #[serde(with = "serde_bytes")]
    pub ledger_state_digest: Hash,
    /// Human-readable observed-state summary.
    pub observed_summary: String,
}

impl DivergenceEvidence {
    /// Returns a deterministic digest binding all evidence fields.
    #[must_use]
    pub fn evidence_digest(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"apm2.projection_divergence_evidence.v1");
        hasher.update(&self.cas_state_digest);
        hasher.update(&self.ledger_state_digest);
        hasher.update(self.observed_summary.as_bytes());
        *hasher.finalize().as_bytes()
    }
}

/// Divergence event between expected and observed projection state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionDivergence {
    /// Diverged channel.
    pub channel_id: String,
    /// Expected digest from authoritative roots.
    #[serde(with = "serde_bytes")]
    pub expected_digest: Hash,
    /// Observed digest from projection surface.
    #[serde(with = "serde_bytes")]
    pub observed_digest: Hash,
    /// Time authority reference hash.
    #[serde(with = "serde_bytes")]
    pub time_authority_ref: Hash,
    /// HTF window reference hash.
    #[serde(with = "serde_bytes")]
    pub window_ref: Hash,
    /// Structured evidence.
    pub evidence: DivergenceEvidence,
}

impl ProjectionDivergence {
    /// Returns digest-bound evidence hash.
    #[must_use]
    pub fn evidence_digest(&self) -> Hash {
        self.evidence.evidence_digest()
    }
}

/// Authoritative source-trust snapshot used for compromise adjudication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceTrustSnapshotV1 {
    /// Channel identifier.
    pub channel_id: String,
    /// CAS root state digest.
    #[serde(with = "serde_bytes")]
    pub cas_state_digest: Hash,
    /// Ledger root state digest.
    #[serde(with = "serde_bytes")]
    pub ledger_state_digest: Hash,
    /// Expected projection digest rooted in authoritative state.
    #[serde(with = "serde_bytes")]
    pub expected_projection_digest: Hash,
    /// Time authority reference hash.
    #[serde(with = "serde_bytes")]
    pub time_authority_ref: Hash,
    /// HTF window reference hash.
    #[serde(with = "serde_bytes")]
    pub window_ref: Hash,
}

impl SourceTrustSnapshotV1 {
    /// Returns digest binding all source-trust fields.
    #[must_use]
    pub fn snapshot_digest(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"apm2.source_trust_snapshot.v1");
        hasher.update(self.channel_id.as_bytes());
        hasher.update(&self.cas_state_digest);
        hasher.update(&self.ledger_state_digest);
        hasher.update(&self.expected_projection_digest);
        hasher.update(&self.time_authority_ref);
        hasher.update(&self.window_ref);
        *hasher.finalize().as_bytes()
    }
}

/// Sink identity snapshot used to bind observed projection identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SinkIdentitySnapshotV1 {
    /// Channel identifier.
    pub channel_id: String,
    /// Digest of sink identity material (e.g. endpoint key fingerprint).
    #[serde(with = "serde_bytes")]
    pub sink_identity_digest: Hash,
    /// Observed projection digest from the sink.
    #[serde(with = "serde_bytes")]
    pub observed_projection_digest: Hash,
    /// Digest binding endpoint identity continuity.
    #[serde(with = "serde_bytes")]
    pub endpoint_binding_digest: Hash,
    /// Time authority reference hash.
    #[serde(with = "serde_bytes")]
    pub time_authority_ref: Hash,
    /// HTF window reference hash.
    #[serde(with = "serde_bytes")]
    pub window_ref: Hash,
}

impl SinkIdentitySnapshotV1 {
    /// Returns digest binding all sink-identity fields.
    #[must_use]
    pub fn snapshot_digest(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"apm2.sink_identity_snapshot.v1");
        hasher.update(self.channel_id.as_bytes());
        hasher.update(&self.sink_identity_digest);
        hasher.update(&self.observed_projection_digest);
        hasher.update(&self.endpoint_binding_digest);
        hasher.update(&self.time_authority_ref);
        hasher.update(&self.window_ref);
        *hasher.finalize().as_bytes()
    }
}

/// Signed compromise decision emitted when a channel is quarantined.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionCompromiseSignalV1 {
    /// Unique signal identifier.
    pub signal_id: String,
    /// Channel identifier.
    pub channel_id: String,
    /// Projection surface type.
    pub surface_type: ProjectionSurfaceType,
    /// Expected authoritative digest.
    #[serde(with = "serde_bytes")]
    pub expected_digest: Hash,
    /// Observed sink digest.
    #[serde(with = "serde_bytes")]
    pub observed_digest: Hash,
    /// Digest of divergence evidence.
    #[serde(with = "serde_bytes")]
    pub divergence_evidence_digest: Hash,
    /// Digest of source trust snapshot.
    #[serde(with = "serde_bytes")]
    pub source_trust_snapshot_digest: Hash,
    /// Digest of sink identity snapshot.
    #[serde(with = "serde_bytes")]
    pub sink_identity_snapshot_digest: Hash,
    /// Quarantine timestamp.
    pub quarantined_at_ns: u64,
    /// Time authority reference hash.
    #[serde(with = "serde_bytes")]
    pub time_authority_ref: Hash,
    /// HTF window reference hash.
    #[serde(with = "serde_bytes")]
    pub window_ref: Hash,
    /// Actor issuing the signal.
    pub issuer_actor_id: String,
    /// Ed25519 signature over canonical bytes (domain-separated).
    #[serde(with = "serde_bytes")]
    pub issuer_signature: [u8; 64],
}

impl ProjectionCompromiseSignalV1 {
    /// Returns canonical bytes for signing.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.extend_from_slice(&(self.signal_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.signal_id.as_bytes());

        bytes.extend_from_slice(&(self.channel_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.channel_id.as_bytes());

        let surface = self.surface_type.as_bytes();
        bytes.extend_from_slice(&(surface.len() as u32).to_be_bytes());
        bytes.extend_from_slice(surface);

        bytes.extend_from_slice(&self.expected_digest);
        bytes.extend_from_slice(&self.observed_digest);
        bytes.extend_from_slice(&self.divergence_evidence_digest);
        bytes.extend_from_slice(&self.source_trust_snapshot_digest);
        bytes.extend_from_slice(&self.sink_identity_snapshot_digest);
        bytes.extend_from_slice(&self.quarantined_at_ns.to_be_bytes());
        bytes.extend_from_slice(&self.time_authority_ref);
        bytes.extend_from_slice(&self.window_ref);

        bytes.extend_from_slice(&(self.issuer_actor_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.issuer_actor_id.as_bytes());

        bytes
    }

    /// Verifies the signal signature.
    ///
    /// # Errors
    ///
    /// Returns an error when signature verification fails.
    pub fn verify_signature(
        &self,
        verifying_key: &VerifyingKey,
    ) -> Result<(), ProjectionCompromiseError> {
        let signature = Signature::from_bytes(&self.issuer_signature);
        verify_with_domain(
            verifying_key,
            PROJECTION_COMPROMISE_SIGNAL_PREFIX,
            &self.canonical_bytes(),
            &signature,
        )
        .map_err(
            |error| ProjectionCompromiseError::SignatureVerificationFailed {
                detail: error.to_string(),
            },
        )
    }
}

/// Durable, signed replay receipt used for reconstruction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionReplayReceiptV1 {
    /// Receipt identifier.
    pub receipt_id: String,
    /// Channel identifier.
    pub channel_id: String,
    /// Monotonic replay sequence.
    pub sequence: u64,
    /// Replayed projected state digest.
    #[serde(with = "serde_bytes")]
    pub projected_state_digest: Hash,
    /// Time authority reference hash.
    #[serde(with = "serde_bytes")]
    pub time_authority_ref: Hash,
    /// HTF window reference hash.
    #[serde(with = "serde_bytes")]
    pub window_ref: Hash,
    /// Source trust snapshot digest bound to this receipt.
    #[serde(with = "serde_bytes")]
    pub source_trust_snapshot_digest: Hash,
    /// Sink identity snapshot digest bound to this receipt.
    #[serde(with = "serde_bytes")]
    pub sink_identity_snapshot_digest: Hash,
    /// Signer actor identity.
    pub signer_actor_id: String,
    /// Ed25519 public key bytes for signature verification.
    #[serde(with = "serde_bytes")]
    pub signer_key: [u8; 32],
    /// Ed25519 signature over canonical bytes.
    #[serde(with = "serde_bytes")]
    pub signature: [u8; 64],
}

impl ProjectionReplayReceiptV1 {
    /// Creates and signs a replay receipt.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid field values.
    #[allow(clippy::too_many_arguments)]
    pub fn create_signed(
        receipt_id: impl Into<String>,
        channel_id: impl Into<String>,
        sequence: u64,
        projected_state_digest: Hash,
        time_authority_ref: Hash,
        window_ref: Hash,
        source_trust_snapshot_digest: Hash,
        sink_identity_snapshot_digest: Hash,
        signer_actor_id: impl Into<String>,
        signer: &Signer,
    ) -> Result<Self, ProjectionCompromiseError> {
        let receipt_id = receipt_id.into();
        let channel_id = channel_id.into();
        let signer_actor_id = signer_actor_id.into();

        validate_required_string("receipt_id", &receipt_id, MAX_RECEIPT_ID_LENGTH)?;
        validate_required_string("channel_id", &channel_id, MAX_CHANNEL_ID_LENGTH)?;
        validate_required_string("signer_actor_id", &signer_actor_id, MAX_ACTOR_ID_LENGTH)?;
        validate_non_zero_hash("projected_state_digest", &projected_state_digest)?;
        validate_non_zero_hash("time_authority_ref", &time_authority_ref)?;
        validate_non_zero_hash("window_ref", &window_ref)?;
        validate_non_zero_hash(
            "source_trust_snapshot_digest",
            &source_trust_snapshot_digest,
        )?;
        validate_non_zero_hash(
            "sink_identity_snapshot_digest",
            &sink_identity_snapshot_digest,
        )?;

        let mut receipt = Self {
            receipt_id,
            channel_id,
            sequence,
            projected_state_digest,
            time_authority_ref,
            window_ref,
            source_trust_snapshot_digest,
            sink_identity_snapshot_digest,
            signer_actor_id,
            signer_key: signer.public_key_bytes(),
            signature: [0u8; 64],
        };

        let signature = sign_with_domain(
            signer,
            PROJECTION_REPLAY_RECEIPT_PREFIX,
            &receipt.canonical_bytes(),
        );
        receipt.signature = signature.to_bytes();
        Ok(receipt)
    }

    /// Returns canonical bytes for signing.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.extend_from_slice(&(self.receipt_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.receipt_id.as_bytes());

        bytes.extend_from_slice(&(self.channel_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.channel_id.as_bytes());

        bytes.extend_from_slice(&self.sequence.to_be_bytes());
        bytes.extend_from_slice(&self.projected_state_digest);
        bytes.extend_from_slice(&self.time_authority_ref);
        bytes.extend_from_slice(&self.window_ref);
        bytes.extend_from_slice(&self.source_trust_snapshot_digest);
        bytes.extend_from_slice(&self.sink_identity_snapshot_digest);

        bytes.extend_from_slice(&(self.signer_actor_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.signer_actor_id.as_bytes());
        bytes.extend_from_slice(&self.signer_key);

        bytes
    }

    /// Verifies replay receipt signature against trusted authority key
    /// bindings.
    ///
    /// # Errors
    ///
    /// Returns an error when signer actor/key are untrusted or signature
    /// verification fails.
    pub fn verify_signature(
        &self,
        trusted_authority_bindings: &[AuthorityKeyBindingV1],
    ) -> Result<(), ProjectionCompromiseError> {
        validate_required_string(
            "signer_actor_id",
            &self.signer_actor_id,
            MAX_ACTOR_ID_LENGTH,
        )?;
        let actor_keyset =
            trusted_keyset_for_actor(&self.signer_actor_id, trusted_authority_bindings)?;
        if !actor_keyset
            .iter()
            .any(|trusted_key| bool::from(trusted_key.ct_eq(&self.signer_key)))
        {
            return Err(ProjectionCompromiseError::UntrustedSignerKey {
                actor_id: self.signer_actor_id.clone(),
            });
        }

        let key = parse_verifying_key(&self.signer_key).map_err(|error| {
            ProjectionCompromiseError::InvalidSignerKey {
                detail: error.to_string(),
            }
        })?;
        let signature = Signature::from_bytes(&self.signature);
        verify_with_domain(
            &key,
            PROJECTION_REPLAY_RECEIPT_PREFIX,
            &self.canonical_bytes(),
            &signature,
        )
        .map_err(
            |error| ProjectionCompromiseError::SignatureVerificationFailed {
                detail: error.to_string(),
            },
        )
    }
}

/// Reconstructed projection state from durable replay receipts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconstructedProjectionState {
    /// Channel ID reconstructed.
    pub channel_id: String,
    /// Final expected state digest recovered from replay.
    #[serde(with = "serde_bytes")]
    pub expected_state_digest: Hash,
    /// Digest of the replay trace.
    #[serde(with = "serde_bytes")]
    pub replay_trace_digest: Hash,
    /// Number of receipts replayed.
    pub replayed_receipt_count: u64,
    /// Last replay sequence.
    pub last_sequence: u64,
    /// Temporal authority reference used for reconstruction.
    #[serde(with = "serde_bytes")]
    pub time_authority_ref: Hash,
    /// HTF window reference used for reconstruction.
    #[serde(with = "serde_bytes")]
    pub window_ref: Hash,
}

/// Detects projection divergence from authoritative expected digest.
///
/// # Errors
///
/// Returns fail-closed errors when temporal authority references are
/// missing/invalid.
pub fn detect_projection_divergence(
    channel: &ProjectionChannel,
    observed_digest: Hash,
    cas_state_digest: Hash,
    ledger_state_digest: Hash,
    time_authority_ref: Hash,
    window_ref: Hash,
) -> Result<Option<ProjectionDivergence>, ProjectionCompromiseError> {
    validate_non_zero_hash("time_authority_ref", &time_authority_ref)?;
    validate_non_zero_hash("window_ref", &window_ref)?;
    validate_non_zero_hash("cas_state_digest", &cas_state_digest)?;
    validate_non_zero_hash("ledger_state_digest", &ledger_state_digest)?;
    validate_non_zero_hash("observed_digest", &observed_digest)?;

    if bool::from(channel.expected_state_digest.ct_eq(&observed_digest)) {
        return Ok(None);
    }

    let evidence = DivergenceEvidence {
        cas_state_digest,
        ledger_state_digest,
        observed_summary: format!(
            "digest mismatch: expected={}, observed={}",
            hex::encode(channel.expected_state_digest),
            hex::encode(observed_digest)
        ),
    };

    Ok(Some(ProjectionDivergence {
        channel_id: channel.channel_id.clone(),
        expected_digest: channel.expected_state_digest,
        observed_digest,
        time_authority_ref,
        window_ref,
        evidence,
    }))
}

/// Quarantines a projection channel from a verified divergence.
///
/// Returns a signed compromise signal suitable for durable recording.
///
/// # Errors
///
/// Returns fail-closed errors for missing temporal authority, snapshot mismatch
/// or invalid signatures/fields.
#[allow(clippy::too_many_arguments)]
pub fn quarantine_channel(
    channel: &mut ProjectionChannel,
    divergence: &ProjectionDivergence,
    source_snapshot: &SourceTrustSnapshotV1,
    sink_snapshot: &SinkIdentitySnapshotV1,
    signal_id: impl Into<String>,
    issuer_actor_id: impl Into<String>,
    signer: &Signer,
    quarantined_at_ns: u64,
) -> Result<ProjectionCompromiseSignalV1, ProjectionCompromiseError> {
    if divergence.channel_id != channel.channel_id {
        return Err(ProjectionCompromiseError::ChannelMismatch {
            expected: channel.channel_id.clone(),
            actual: divergence.channel_id.clone(),
        });
    }
    if source_snapshot.channel_id != channel.channel_id {
        return Err(ProjectionCompromiseError::ChannelMismatch {
            expected: channel.channel_id.clone(),
            actual: source_snapshot.channel_id.clone(),
        });
    }
    if sink_snapshot.channel_id != channel.channel_id {
        return Err(ProjectionCompromiseError::ChannelMismatch {
            expected: channel.channel_id.clone(),
            actual: sink_snapshot.channel_id.clone(),
        });
    }
    if !bool::from(
        source_snapshot
            .expected_projection_digest
            .ct_eq(&divergence.expected_digest),
    ) {
        return Err(ProjectionCompromiseError::SnapshotMismatch {
            detail: "source snapshot expected digest does not match divergence expected digest"
                .to_string(),
        });
    }
    if !bool::from(
        sink_snapshot
            .observed_projection_digest
            .ct_eq(&divergence.observed_digest),
    ) {
        return Err(ProjectionCompromiseError::SnapshotMismatch {
            detail: "sink snapshot observed digest does not match divergence observed digest"
                .to_string(),
        });
    }
    if !bool::from(
        source_snapshot
            .time_authority_ref
            .ct_eq(&divergence.time_authority_ref),
    ) || !bool::from(
        sink_snapshot
            .time_authority_ref
            .ct_eq(&divergence.time_authority_ref),
    ) {
        return Err(ProjectionCompromiseError::SnapshotMismatch {
            detail: "time_authority_ref mismatch between divergence and snapshots".to_string(),
        });
    }
    if !bool::from(source_snapshot.window_ref.ct_eq(&divergence.window_ref))
        || !bool::from(sink_snapshot.window_ref.ct_eq(&divergence.window_ref))
    {
        return Err(ProjectionCompromiseError::SnapshotMismatch {
            detail: "window_ref mismatch between divergence and snapshots".to_string(),
        });
    }

    let signal_id = signal_id.into();
    let issuer_actor_id = issuer_actor_id.into();
    validate_required_string("signal_id", &signal_id, MAX_SIGNAL_ID_LENGTH)?;
    validate_required_string("issuer_actor_id", &issuer_actor_id, MAX_ACTOR_ID_LENGTH)?;
    validate_non_zero_hash("time_authority_ref", &divergence.time_authority_ref)?;
    validate_non_zero_hash("window_ref", &divergence.window_ref)?;

    let reason = format!("projection divergence detected: {}", channel.channel_id);
    validate_required_string("reason", &reason, MAX_REASON_LENGTH)?;

    channel.quarantine_status = QuarantineStatus::Quarantined {
        quarantined_at_ns,
        time_authority_ref: divergence.time_authority_ref,
        window_ref: divergence.window_ref,
        reason,
    };

    let mut signal = ProjectionCompromiseSignalV1 {
        signal_id,
        channel_id: channel.channel_id.clone(),
        surface_type: channel.surface_type,
        expected_digest: divergence.expected_digest,
        observed_digest: divergence.observed_digest,
        divergence_evidence_digest: divergence.evidence_digest(),
        source_trust_snapshot_digest: source_snapshot.snapshot_digest(),
        sink_identity_snapshot_digest: sink_snapshot.snapshot_digest(),
        quarantined_at_ns,
        time_authority_ref: divergence.time_authority_ref,
        window_ref: divergence.window_ref,
        issuer_actor_id,
        issuer_signature: [0u8; 64],
    };

    let signature = sign_with_domain(
        signer,
        PROJECTION_COMPROMISE_SIGNAL_PREFIX,
        &signal.canonical_bytes(),
    );
    signal.issuer_signature = signature.to_bytes();
    Ok(signal)
}

/// Reconstructs projection state from trusted durable replay receipts.
///
/// # Errors
///
/// Returns fail-closed errors when signatures are invalid, temporal authority
/// is inconsistent, receipt ordering is incomplete, or reconstructed digest
/// does not match source trust snapshot.
pub fn reconstruct_projection_state(
    channel_id: &str,
    receipts: &[ProjectionReplayReceiptV1],
    source_snapshot: &SourceTrustSnapshotV1,
    sink_snapshot: &SinkIdentitySnapshotV1,
    trusted_authority_bindings: &[AuthorityKeyBindingV1],
    sequence_bounds: ReplaySequenceBoundsV1,
) -> Result<ReconstructedProjectionState, ProjectionCompromiseError> {
    validate_reconstruction_inputs(
        channel_id,
        source_snapshot,
        sink_snapshot,
        trusted_authority_bindings,
        sequence_bounds,
    )?;
    let sorted = sorted_replay_receipts(receipts)?;
    let expected_source_digest = source_snapshot.snapshot_digest();
    let expected_sink_digest = sink_snapshot.snapshot_digest();

    let mut replay_hasher = blake3::Hasher::new();
    replay_hasher.update(b"apm2.projection_replay_trace.v1");

    let expected_count = sequence_bounds
        .required_end_sequence
        .checked_sub(sequence_bounds.required_start_sequence)
        .and_then(|delta| delta.checked_add(1))
        .ok_or(ProjectionCompromiseError::InvalidReplaySequenceBounds {
            required_start_sequence: sequence_bounds.required_start_sequence,
            required_end_sequence: sequence_bounds.required_end_sequence,
        })?;

    let sorted_len_u64 = u64::try_from(sorted.len()).map_err(|_| {
        ProjectionCompromiseError::InvalidReplaySequenceBounds {
            required_start_sequence: sequence_bounds.required_start_sequence,
            required_end_sequence: sequence_bounds.required_end_sequence,
        }
    })?;

    let receipts_to_validate = sorted_len_u64.min(expected_count);
    let mut final_digest = [0u8; 32];

    for idx in 0..receipts_to_validate {
        let expected_sequence = sequence_bounds
            .required_start_sequence
            .checked_add(idx)
            .ok_or(ProjectionCompromiseError::InvalidReplaySequenceBounds {
                required_start_sequence: sequence_bounds.required_start_sequence,
                required_end_sequence: sequence_bounds.required_end_sequence,
            })?;
        let receipt_index = usize::try_from(idx).map_err(|_| {
            ProjectionCompromiseError::InvalidReplaySequenceBounds {
                required_start_sequence: sequence_bounds.required_start_sequence,
                required_end_sequence: sequence_bounds.required_end_sequence,
            }
        })?;
        let receipt = &sorted[receipt_index];

        validate_replay_receipt(
            channel_id,
            receipt,
            expected_sequence,
            source_snapshot,
            expected_source_digest,
            expected_sink_digest,
            trusted_authority_bindings,
        )?;
        replay_hasher.update(&receipt.canonical_bytes());
        replay_hasher.update(&receipt.signature);
        final_digest = receipt.projected_state_digest;
    }

    validate_replay_receipt_count(&sorted, sequence_bounds, sorted_len_u64, expected_count)?;

    if !bool::from(final_digest.ct_eq(&source_snapshot.expected_projection_digest)) {
        return Err(ProjectionCompromiseError::ReplayDigestMismatch {
            expected: hex::encode(source_snapshot.expected_projection_digest),
            actual: hex::encode(final_digest),
        });
    }

    Ok(ReconstructedProjectionState {
        channel_id: channel_id.to_string(),
        expected_state_digest: final_digest,
        replay_trace_digest: *replay_hasher.finalize().as_bytes(),
        replayed_receipt_count: sorted.len() as u64,
        last_sequence: sequence_bounds.required_end_sequence,
        time_authority_ref: source_snapshot.time_authority_ref,
        window_ref: source_snapshot.window_ref,
    })
}

fn validate_replay_receipt_count(
    sorted: &[ProjectionReplayReceiptV1],
    sequence_bounds: ReplaySequenceBoundsV1,
    sorted_len_u64: u64,
    expected_count: u64,
) -> Result<(), ProjectionCompromiseError> {
    if sorted_len_u64 < expected_count {
        let expected_missing_sequence = sequence_bounds
            .required_start_sequence
            .checked_add(sorted_len_u64)
            .ok_or(ProjectionCompromiseError::InvalidReplaySequenceBounds {
                required_start_sequence: sequence_bounds.required_start_sequence,
                required_end_sequence: sequence_bounds.required_end_sequence,
            })?;
        return Err(ProjectionCompromiseError::MissingReceipt {
            expected: expected_missing_sequence,
            actual: None,
        });
    }

    if sorted_len_u64 > expected_count {
        let extra_index = usize::try_from(expected_count).map_err(|_| {
            ProjectionCompromiseError::InvalidReplaySequenceBounds {
                required_start_sequence: sequence_bounds.required_start_sequence,
                required_end_sequence: sequence_bounds.required_end_sequence,
            }
        })?;
        let extra_sequence = sorted
            .get(extra_index)
            .map_or(sequence_bounds.required_end_sequence, |receipt| {
                receipt.sequence
            });
        return Err(ProjectionCompromiseError::UnexpectedReceiptSequence {
            required_end_sequence: sequence_bounds.required_end_sequence,
            actual: extra_sequence,
        });
    }

    Ok(())
}

fn validate_reconstruction_inputs(
    channel_id: &str,
    source_snapshot: &SourceTrustSnapshotV1,
    sink_snapshot: &SinkIdentitySnapshotV1,
    trusted_authority_bindings: &[AuthorityKeyBindingV1],
    sequence_bounds: ReplaySequenceBoundsV1,
) -> Result<(), ProjectionCompromiseError> {
    validate_required_string("channel_id", channel_id, MAX_CHANNEL_ID_LENGTH)?;
    if sequence_bounds.required_start_sequence > sequence_bounds.required_end_sequence {
        return Err(ProjectionCompromiseError::InvalidReplaySequenceBounds {
            required_start_sequence: sequence_bounds.required_start_sequence,
            required_end_sequence: sequence_bounds.required_end_sequence,
        });
    }
    validate_non_zero_hash(
        "source_snapshot.time_authority_ref",
        &source_snapshot.time_authority_ref,
    )?;
    validate_non_zero_hash("source_snapshot.window_ref", &source_snapshot.window_ref)?;
    validate_non_zero_hash(
        "sink_snapshot.time_authority_ref",
        &sink_snapshot.time_authority_ref,
    )?;
    validate_non_zero_hash("sink_snapshot.window_ref", &sink_snapshot.window_ref)?;

    if source_snapshot.channel_id != channel_id {
        return Err(ProjectionCompromiseError::ChannelMismatch {
            expected: channel_id.to_string(),
            actual: source_snapshot.channel_id.clone(),
        });
    }
    if sink_snapshot.channel_id != channel_id {
        return Err(ProjectionCompromiseError::ChannelMismatch {
            expected: channel_id.to_string(),
            actual: sink_snapshot.channel_id.clone(),
        });
    }
    if !bool::from(
        source_snapshot
            .time_authority_ref
            .ct_eq(&sink_snapshot.time_authority_ref),
    ) {
        return Err(ProjectionCompromiseError::SnapshotMismatch {
            detail: "source/sink time_authority_ref mismatch".to_string(),
        });
    }
    if !bool::from(source_snapshot.window_ref.ct_eq(&sink_snapshot.window_ref)) {
        return Err(ProjectionCompromiseError::SnapshotMismatch {
            detail: "source/sink window_ref mismatch".to_string(),
        });
    }
    validate_trusted_authority_bindings(trusted_authority_bindings)?;
    Ok(())
}

fn sorted_replay_receipts(
    receipts: &[ProjectionReplayReceiptV1],
) -> Result<Vec<ProjectionReplayReceiptV1>, ProjectionCompromiseError> {
    if receipts.is_empty() {
        return Err(ProjectionCompromiseError::EmptyReceipts);
    }
    if receipts.len() > MAX_REPLAY_RECEIPTS {
        return Err(ProjectionCompromiseError::TooManyReceipts {
            actual: receipts.len(),
            max: MAX_REPLAY_RECEIPTS,
        });
    }

    let mut sorted = receipts.to_vec();
    sorted.sort_by(|left, right| {
        left.sequence
            .cmp(&right.sequence)
            .then_with(|| left.receipt_id.cmp(&right.receipt_id))
    });
    Ok(sorted)
}

fn validate_replay_receipt(
    channel_id: &str,
    receipt: &ProjectionReplayReceiptV1,
    expected_sequence: u64,
    source_snapshot: &SourceTrustSnapshotV1,
    expected_source_digest: Hash,
    expected_sink_digest: Hash,
    trusted_authority_bindings: &[AuthorityKeyBindingV1],
) -> Result<(), ProjectionCompromiseError> {
    if receipt.sequence != expected_sequence {
        return Err(ProjectionCompromiseError::MissingReceipt {
            expected: expected_sequence,
            actual: Some(receipt.sequence),
        });
    }
    if receipt.channel_id != channel_id {
        return Err(ProjectionCompromiseError::ChannelMismatch {
            expected: channel_id.to_string(),
            actual: receipt.channel_id.clone(),
        });
    }
    validate_non_zero_hash(
        "receipt.projected_state_digest",
        &receipt.projected_state_digest,
    )?;
    validate_non_zero_hash("receipt.time_authority_ref", &receipt.time_authority_ref)?;
    validate_non_zero_hash("receipt.window_ref", &receipt.window_ref)?;

    if !bool::from(
        receipt
            .time_authority_ref
            .ct_eq(&source_snapshot.time_authority_ref),
    ) {
        return Err(ProjectionCompromiseError::SnapshotMismatch {
            detail: format!("receipt {} time_authority_ref mismatch", receipt.receipt_id),
        });
    }
    if !bool::from(receipt.window_ref.ct_eq(&source_snapshot.window_ref)) {
        return Err(ProjectionCompromiseError::SnapshotMismatch {
            detail: format!("receipt {} window_ref mismatch", receipt.receipt_id),
        });
    }
    if !bool::from(
        receipt
            .source_trust_snapshot_digest
            .ct_eq(&expected_source_digest),
    ) {
        return Err(ProjectionCompromiseError::SnapshotMismatch {
            detail: format!(
                "receipt {} source snapshot digest mismatch",
                receipt.receipt_id
            ),
        });
    }
    if !bool::from(
        receipt
            .sink_identity_snapshot_digest
            .ct_eq(&expected_sink_digest),
    ) {
        return Err(ProjectionCompromiseError::SnapshotMismatch {
            detail: format!(
                "receipt {} sink snapshot digest mismatch",
                receipt.receipt_id
            ),
        });
    }
    receipt.verify_signature(trusted_authority_bindings)?;
    Ok(())
}

fn validate_trusted_authority_bindings(
    trusted_authority_bindings: &[AuthorityKeyBindingV1],
) -> Result<(), ProjectionCompromiseError> {
    if trusted_authority_bindings.is_empty() {
        return Err(ProjectionCompromiseError::MissingField {
            field: "trusted_authority_bindings",
        });
    }
    for binding in trusted_authority_bindings {
        validate_required_string(
            "authority_binding.actor_id",
            &binding.actor_id,
            MAX_ACTOR_ID_LENGTH,
        )?;
        let _ = parse_verifying_key(&binding.verifying_key).map_err(|error| {
            ProjectionCompromiseError::InvalidSignerKey {
                detail: error.to_string(),
            }
        })?;
    }
    Ok(())
}

fn trusted_keyset_for_actor(
    actor_id: &str,
    trusted_authority_bindings: &[AuthorityKeyBindingV1],
) -> Result<Vec<[u8; 32]>, ProjectionCompromiseError> {
    let keys = trusted_authority_bindings
        .iter()
        .filter(|binding| binding.actor_id == actor_id)
        .map(|binding| binding.verifying_key)
        .collect::<Vec<_>>();
    if keys.is_empty() {
        return Err(ProjectionCompromiseError::UnknownSignerActor {
            actor_id: actor_id.to_string(),
        });
    }
    Ok(keys)
}

fn validate_required_string(
    field: &'static str,
    value: &str,
    max: usize,
) -> Result<(), ProjectionCompromiseError> {
    if value.trim().is_empty() {
        return Err(ProjectionCompromiseError::MissingField { field });
    }
    if value.len() > max {
        return Err(ProjectionCompromiseError::StringTooLong {
            field,
            actual: value.len(),
            max,
        });
    }
    Ok(())
}

fn validate_non_zero_hash(
    field: &'static str,
    value: &Hash,
) -> Result<(), ProjectionCompromiseError> {
    if value.iter().all(|byte| *byte == 0) {
        return Err(ProjectionCompromiseError::MissingHash { field });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(seed: u8) -> Hash {
        [seed; 32]
    }

    fn authority_binding(actor_id: &str, signer: &Signer) -> AuthorityKeyBindingV1 {
        AuthorityKeyBindingV1 {
            actor_id: actor_id.to_string(),
            verifying_key: signer.public_key_bytes(),
        }
    }

    const fn bounds(start: u64, end: u64) -> ReplaySequenceBoundsV1 {
        ReplaySequenceBoundsV1 {
            required_start_sequence: start,
            required_end_sequence: end,
        }
    }

    fn make_snapshots(
        channel_id: &str,
        expected_digest: Hash,
        observed_digest: Hash,
        time_authority_ref: Hash,
        window_ref: Hash,
    ) -> (SourceTrustSnapshotV1, SinkIdentitySnapshotV1) {
        (
            SourceTrustSnapshotV1 {
                channel_id: channel_id.to_string(),
                cas_state_digest: expected_digest,
                ledger_state_digest: expected_digest,
                expected_projection_digest: expected_digest,
                time_authority_ref,
                window_ref,
            },
            SinkIdentitySnapshotV1 {
                channel_id: channel_id.to_string(),
                sink_identity_digest: hash(0xAA),
                observed_projection_digest: observed_digest,
                endpoint_binding_digest: hash(0xBB),
                time_authority_ref,
                window_ref,
            },
        )
    }

    #[test]
    fn detect_projection_divergence_matching_digest_returns_none() {
        let channel = ProjectionChannel::new(
            "repo/main",
            ProjectionSurfaceType::GitRepository,
            hash(0x11),
        )
        .expect("channel must be valid");

        let divergence = detect_projection_divergence(
            &channel,
            hash(0x11),
            hash(0x11),
            hash(0x11),
            hash(0x21),
            hash(0x31),
        )
        .expect("detection should succeed");

        assert!(divergence.is_none(), "matching digest must not diverge");
    }

    #[test]
    fn detect_projection_divergence_mismatch_emits_evidence() {
        let channel = ProjectionChannel::new(
            "repo/main",
            ProjectionSurfaceType::GitRepository,
            hash(0x11),
        )
        .expect("channel must be valid");

        let divergence = detect_projection_divergence(
            &channel,
            hash(0x12),
            hash(0x11),
            hash(0x11),
            hash(0x21),
            hash(0x31),
        )
        .expect("detection should succeed")
        .expect("mismatch should produce divergence");

        assert_eq!(divergence.channel_id, "repo/main");
        assert_eq!(divergence.expected_digest, hash(0x11));
        assert_eq!(divergence.observed_digest, hash(0x12));
        assert_ne!(
            divergence.evidence_digest(),
            [0u8; 32],
            "evidence digest must be non-zero"
        );
    }

    #[test]
    fn detect_projection_divergence_missing_temporal_authority_fails_closed() {
        let channel = ProjectionChannel::new(
            "repo/main",
            ProjectionSurfaceType::GitRepository,
            hash(0x11),
        )
        .expect("channel must be valid");

        let err = detect_projection_divergence(
            &channel,
            hash(0x12),
            hash(0x11),
            hash(0x11),
            [0u8; 32],
            hash(0x31),
        )
        .expect_err("zero time authority must fail closed");

        assert!(
            matches!(err, ProjectionCompromiseError::MissingHash { field } if field == "time_authority_ref")
        );
    }

    #[test]
    fn quarantine_channel_updates_status_and_emits_signed_signal() {
        let signer = Signer::generate();
        let mut channel = ProjectionChannel::new(
            "repo/main",
            ProjectionSurfaceType::GitRepository,
            hash(0x11),
        )
        .expect("channel must be valid");
        let divergence = detect_projection_divergence(
            &channel,
            hash(0x12),
            hash(0x11),
            hash(0x11),
            hash(0x21),
            hash(0x31),
        )
        .expect("detection should succeed")
        .expect("mismatch should produce divergence");
        let (source_snapshot, sink_snapshot) = make_snapshots(
            &channel.channel_id,
            hash(0x11),
            hash(0x12),
            hash(0x21),
            hash(0x31),
        );

        let signal = quarantine_channel(
            &mut channel,
            &divergence,
            &source_snapshot,
            &sink_snapshot,
            "signal-001",
            "watchdog-actor",
            &signer,
            42,
        )
        .expect("quarantine must succeed");

        match &channel.quarantine_status {
            QuarantineStatus::Quarantined {
                quarantined_at_ns,
                time_authority_ref,
                window_ref,
                ..
            } => {
                assert_eq!(*quarantined_at_ns, 42);
                assert_eq!(*time_authority_ref, hash(0x21));
                assert_eq!(*window_ref, hash(0x31));
            },
            QuarantineStatus::Active => panic!("channel should be quarantined"),
        }

        assert_eq!(signal.channel_id, channel.channel_id);
        assert_eq!(signal.time_authority_ref, hash(0x21));
        assert_eq!(signal.window_ref, hash(0x31));
        signal
            .verify_signature(&signer.verifying_key())
            .expect("signal signature must verify");
    }

    #[test]
    fn reconstruct_projection_state_from_valid_receipts() {
        let signer = Signer::generate();
        let channel_id = "repo/main";
        let time_authority_ref = hash(0x21);
        let window_ref = hash(0x31);
        let state_digest_1 = hash(0x40);
        let state_digest_2 = hash(0x41);
        let (source_snapshot, sink_snapshot) = make_snapshots(
            channel_id,
            state_digest_2,
            hash(0x55),
            time_authority_ref,
            window_ref,
        );
        let source_digest = source_snapshot.snapshot_digest();
        let sink_digest = sink_snapshot.snapshot_digest();

        let receipt_0 = ProjectionReplayReceiptV1::create_signed(
            "receipt-0",
            channel_id,
            0,
            state_digest_1,
            time_authority_ref,
            window_ref,
            source_digest,
            sink_digest,
            "projector-actor",
            &signer,
        )
        .expect("receipt 0 must be valid");
        let receipt_1 = ProjectionReplayReceiptV1::create_signed(
            "receipt-1",
            channel_id,
            1,
            state_digest_2,
            time_authority_ref,
            window_ref,
            source_digest,
            sink_digest,
            "projector-actor",
            &signer,
        )
        .expect("receipt 1 must be valid");

        let reconstructed = reconstruct_projection_state(
            channel_id,
            &[receipt_0, receipt_1],
            &source_snapshot,
            &sink_snapshot,
            &[authority_binding("projector-actor", &signer)],
            bounds(0, 1),
        )
        .expect("reconstruction must succeed");

        assert_eq!(reconstructed.channel_id, channel_id);
        assert_eq!(reconstructed.expected_state_digest, state_digest_2);
        assert_eq!(reconstructed.replayed_receipt_count, 2);
        assert_eq!(reconstructed.last_sequence, 1);
    }

    #[test]
    fn reconstruct_projection_state_missing_receipt_fails_closed() {
        let signer = Signer::generate();
        let channel_id = "repo/main";
        let time_authority_ref = hash(0x21);
        let window_ref = hash(0x31);
        let (source_snapshot, sink_snapshot) = make_snapshots(
            channel_id,
            hash(0x41),
            hash(0x55),
            time_authority_ref,
            window_ref,
        );
        let source_digest = source_snapshot.snapshot_digest();
        let sink_digest = sink_snapshot.snapshot_digest();

        let receipt_0 = ProjectionReplayReceiptV1::create_signed(
            "receipt-0",
            channel_id,
            0,
            hash(0x40),
            time_authority_ref,
            window_ref,
            source_digest,
            sink_digest,
            "projector-actor",
            &signer,
        )
        .expect("receipt 0 must be valid");
        let receipt_2 = ProjectionReplayReceiptV1::create_signed(
            "receipt-2",
            channel_id,
            2,
            hash(0x41),
            time_authority_ref,
            window_ref,
            source_digest,
            sink_digest,
            "projector-actor",
            &signer,
        )
        .expect("receipt 2 must be valid");

        let err = reconstruct_projection_state(
            channel_id,
            &[receipt_0, receipt_2],
            &source_snapshot,
            &sink_snapshot,
            &[authority_binding("projector-actor", &signer)],
            bounds(0, 2),
        )
        .expect_err("sequence gap must fail closed");

        assert!(
            matches!(
                err,
                ProjectionCompromiseError::MissingReceipt {
                    expected: 1,
                    actual: Some(2)
                }
            ),
            "expected MissingReceipt, got {err:?}"
        );
    }

    #[test]
    fn reconstruct_projection_state_invalid_signature_fails_closed() {
        let signer = Signer::generate();
        let channel_id = "repo/main";
        let time_authority_ref = hash(0x21);
        let window_ref = hash(0x31);
        let (source_snapshot, sink_snapshot) = make_snapshots(
            channel_id,
            hash(0x41),
            hash(0x55),
            time_authority_ref,
            window_ref,
        );
        let source_digest = source_snapshot.snapshot_digest();
        let sink_digest = sink_snapshot.snapshot_digest();

        let mut receipt = ProjectionReplayReceiptV1::create_signed(
            "receipt-0",
            channel_id,
            0,
            hash(0x41),
            time_authority_ref,
            window_ref,
            source_digest,
            sink_digest,
            "projector-actor",
            &signer,
        )
        .expect("receipt must be valid");
        receipt.signature[0] ^= 0xFF;

        let err = reconstruct_projection_state(
            channel_id,
            &[receipt],
            &source_snapshot,
            &sink_snapshot,
            &[authority_binding("projector-actor", &signer)],
            bounds(0, 0),
        )
        .expect_err("tampered signature must fail");

        assert!(
            matches!(
                err,
                ProjectionCompromiseError::SignatureVerificationFailed { .. }
            ),
            "expected signature failure, got {err:?}"
        );
    }

    #[test]
    fn reconstruct_projection_state_missing_leading_receipt_fails_closed() {
        let signer = Signer::generate();
        let channel_id = "repo/main";
        let time_authority_ref = hash(0x21);
        let window_ref = hash(0x31);
        let (source_snapshot, sink_snapshot) = make_snapshots(
            channel_id,
            hash(0x42),
            hash(0x55),
            time_authority_ref,
            window_ref,
        );
        let source_digest = source_snapshot.snapshot_digest();
        let sink_digest = sink_snapshot.snapshot_digest();

        let receipt_1 = ProjectionReplayReceiptV1::create_signed(
            "receipt-1",
            channel_id,
            1,
            hash(0x42),
            time_authority_ref,
            window_ref,
            source_digest,
            sink_digest,
            "projector-actor",
            &signer,
        )
        .expect("receipt must be valid");

        let err = reconstruct_projection_state(
            channel_id,
            &[receipt_1],
            &source_snapshot,
            &sink_snapshot,
            &[authority_binding("projector-actor", &signer)],
            bounds(0, 1),
        )
        .expect_err("missing leading sequence must fail");

        assert!(
            matches!(
                err,
                ProjectionCompromiseError::MissingReceipt {
                    expected: 0,
                    actual: Some(1)
                }
            ),
            "expected leading MissingReceipt, got {err:?}"
        );
    }

    #[test]
    fn reconstruct_projection_state_rejects_untrusted_signer_key() {
        let trusted_signer = Signer::generate();
        let rogue_signer = Signer::generate();
        let channel_id = "repo/main";
        let time_authority_ref = hash(0x21);
        let window_ref = hash(0x31);
        let (source_snapshot, sink_snapshot) = make_snapshots(
            channel_id,
            hash(0x41),
            hash(0x55),
            time_authority_ref,
            window_ref,
        );
        let source_digest = source_snapshot.snapshot_digest();
        let sink_digest = sink_snapshot.snapshot_digest();

        let rogue_receipt = ProjectionReplayReceiptV1::create_signed(
            "receipt-0",
            channel_id,
            0,
            hash(0x41),
            time_authority_ref,
            window_ref,
            source_digest,
            sink_digest,
            "projector-actor",
            &rogue_signer,
        )
        .expect("rogue receipt must be structurally valid");

        let err = reconstruct_projection_state(
            channel_id,
            &[rogue_receipt],
            &source_snapshot,
            &sink_snapshot,
            &[authority_binding("projector-actor", &trusted_signer)],
            bounds(0, 0),
        )
        .expect_err("rogue key must be rejected");

        assert!(
            matches!(err, ProjectionCompromiseError::UntrustedSignerKey { .. }),
            "expected untrusted signer key error, got {err:?}"
        );
    }

    #[test]
    fn reconstruct_projection_state_rejects_excessive_receipts() {
        let signer = Signer::generate();
        let channel_id = "repo/main";
        let time_authority_ref = hash(0x21);
        let window_ref = hash(0x31);
        let (source_snapshot, sink_snapshot) = make_snapshots(
            channel_id,
            hash(0x41),
            hash(0x55),
            time_authority_ref,
            window_ref,
        );
        let source_digest = source_snapshot.snapshot_digest();
        let sink_digest = sink_snapshot.snapshot_digest();

        let receipt = ProjectionReplayReceiptV1::create_signed(
            "receipt-0",
            channel_id,
            0,
            hash(0x41),
            time_authority_ref,
            window_ref,
            source_digest,
            sink_digest,
            "projector-actor",
            &signer,
        )
        .expect("receipt must be valid");

        let excessive: Vec<_> = (0..=super::MAX_REPLAY_RECEIPTS)
            .map(|_| receipt.clone())
            .collect();

        let err = reconstruct_projection_state(
            channel_id,
            &excessive,
            &source_snapshot,
            &sink_snapshot,
            &[authority_binding("projector-actor", &signer)],
            bounds(0, super::MAX_REPLAY_RECEIPTS as u64),
        )
        .expect_err("excessive receipts must be rejected");

        assert!(
            matches!(
                err,
                ProjectionCompromiseError::TooManyReceipts { actual, max }
                    if actual == super::MAX_REPLAY_RECEIPTS + 1 && max == super::MAX_REPLAY_RECEIPTS
            ),
            "expected TooManyReceipts, got {err:?}"
        );
    }
}
