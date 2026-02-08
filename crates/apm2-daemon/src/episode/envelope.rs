//! Episode envelope types for immutable episode configuration.
//!
//! This module defines the `EpisodeEnvelope` struct that captures all
//! immutable configuration for an episode. Per AD-EPISODE-001, the envelope
//! is created once, referenced by digest, and bound into all receipts.
//!
//! # Architecture
//!
//! The envelope is the authoritative source of episode configuration:
//!
//! ```text
//! EpisodeEnvelope (immutable)
//!     |
//!     +-- episode_id, actor_id, work_id, lease_id
//!     +-- budget: EpisodeBudget
//!     +-- stop_conditions: StopConditions
//!     +-- pinned_snapshot: PinnedSnapshot
//!     +-- capability_manifest_hash
//!     +-- adapter_profile_hash (optional)
//!     +-- role_spec_hash (optional)
//!     +-- risk_tier, determinism_class
//!     +-- context_refs (optional)
//!           |
//!           +-- digest() --> bound into all receipts
//! ```
//!
//! # Canonicalization
//!
//! Per AD-VERIFY-001, the envelope is serialized deterministically:
//! - Fields in tag order
//! - No maps (forbidden in signed messages)
//! - Repeated fields sorted
//! - Unknown fields dropped
//!
//! # Contract References
//!
//! - AD-EPISODE-001: Immutable episode envelope
//! - AD-VERIFY-001: Deterministic Protobuf serialization
//! - REQ-EPISODE-001: Episode envelope requirements

use prost::Message;
use serde::{Deserialize, Serialize};

use super::budget::EpisodeBudget;
use super::snapshot::PinnedSnapshot;

/// Maximum length for string identifiers (`episode_id`, `actor_id`, etc.).
pub const MAX_ID_LENGTH: usize = 256;

/// Maximum number of context pack references.
pub const MAX_CONTEXT_REFS: usize = 100;

/// Maximum number of DCP references.
pub const MAX_DCP_REFS: usize = 100;

/// Risk tier for an episode, determining security gates and evidence strength.
///
/// Per AD-EPISODE-001, the risk tier drives:
/// - Mandatory gates before execution
/// - Evidence strength requirements
/// - Sandbox isolation level
///
/// # Discriminant Stability
///
/// Explicit discriminant values maintain semver compatibility. New variants
/// must use new values; existing values must not change.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
#[non_exhaustive]
pub enum RiskTier {
    /// Tier 0: Read-only operations with no side effects.
    #[default]
    Tier0 = 0,

    /// Tier 1: Local development with minimal risk.
    Tier1 = 1,

    /// Tier 2: Production-adjacent operations.
    Tier2 = 2,

    /// Tier 3: Production operations with external effects.
    Tier3 = 3,

    /// Tier 4: Critical operations requiring enhanced oversight.
    Tier4 = 4,
}

impl RiskTier {
    /// Returns the tier number.
    #[must_use]
    pub const fn tier(&self) -> u8 {
        *self as u8
    }

    /// Returns `true` if this tier requires sandbox isolation.
    ///
    /// Per AD-SEC-001, sandbox is required for tier 3+.
    #[must_use]
    pub const fn requires_sandbox(&self) -> bool {
        matches!(self, Self::Tier3 | Self::Tier4)
    }

    /// Returns `true` if this tier requires enhanced evidence.
    #[must_use]
    pub const fn requires_enhanced_evidence(&self) -> bool {
        matches!(self, Self::Tier2 | Self::Tier3 | Self::Tier4)
    }

    /// Parses a risk tier from a u8 value.
    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Tier0),
            1 => Some(Self::Tier1),
            2 => Some(Self::Tier2),
            3 => Some(Self::Tier3),
            4 => Some(Self::Tier4),
            _ => None,
        }
    }

    /// Parses a risk tier from a u32 value.
    ///
    /// # Security
    ///
    /// This method exists to prevent truncation attacks. When decoding from
    /// Protobuf (which uses u32 for enum values), we must validate the full
    /// u32 range. Casting to u8 first would truncate values like 256 to 0,
    /// allowing an attacker to bypass security gates.
    #[must_use]
    pub const fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::Tier0),
            1 => Some(Self::Tier1),
            2 => Some(Self::Tier2),
            3 => Some(Self::Tier3),
            4 => Some(Self::Tier4),
            _ => None,
        }
    }
}

/// Determinism class for episode execution.
///
/// Per AD-EPISODE-001, the determinism class declares the expected
/// reproducibility of the episode. Receipts verify this declaration.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
#[non_exhaustive]
pub enum DeterminismClass {
    /// Non-deterministic: Different runs may produce different outputs.
    #[default]
    NonDeterministic   = 0,

    /// Soft-deterministic: Same inputs should produce same outputs,
    /// but external factors (time, network) may cause variation.
    SoftDeterministic  = 1,

    /// Fully deterministic: Same inputs always produce same outputs.
    /// Verified by replaying tool calls and comparing results.
    FullyDeterministic = 2,
}

impl DeterminismClass {
    /// Returns the class value.
    #[must_use]
    pub const fn value(&self) -> u8 {
        *self as u8
    }

    /// Returns `true` if this class requires replay verification.
    #[must_use]
    pub const fn requires_replay_verification(&self) -> bool {
        matches!(self, Self::FullyDeterministic)
    }

    /// Parses a determinism class from a u8 value.
    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::NonDeterministic),
            1 => Some(Self::SoftDeterministic),
            2 => Some(Self::FullyDeterministic),
            _ => None,
        }
    }

    /// Parses a determinism class from a u32 value.
    ///
    /// # Security
    ///
    /// This method exists to prevent truncation attacks. When decoding from
    /// Protobuf (which uses u32 for enum values), we must validate the full
    /// u32 range. Casting to u8 first would truncate values like 256 to 0,
    /// allowing an attacker to bypass replay verification requirements.
    #[must_use]
    pub const fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::NonDeterministic),
            1 => Some(Self::SoftDeterministic),
            2 => Some(Self::FullyDeterministic),
            _ => None,
        }
    }
}

/// Internal protobuf representation for `StopConditions`.
///
/// Per AD-VERIFY-001, we use `optional` fields to ensure explicit serialization
/// of all values including defaults. This prevents encoding from omitting
/// zero values which would violate deterministic encoding requirements.
#[derive(Clone, PartialEq, Message)]
struct StopConditionsProto {
    #[prost(uint64, optional, tag = "1")]
    max_episodes: Option<u64>,
    #[prost(string, optional, tag = "2")]
    goal_predicate: Option<String>,
    #[prost(string, optional, tag = "3")]
    failure_predicate: Option<String>,
    #[prost(string, optional, tag = "4")]
    escalation_predicate: Option<String>,
}

/// Stop conditions for episode termination.
///
/// These predicates define when an episode should stop executing.
/// They are evaluated after each episode step.
///
/// # Security
///
/// Uses `deny_unknown_fields` to prevent field injection attacks when
/// deserializing from untrusted input.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StopConditions {
    /// Maximum number of episodes to execute.
    pub max_episodes: u64,

    /// Goal satisfaction predicate (free-form for v1).
    pub goal_predicate: String,

    /// Failure predicate (free-form for v1).
    pub failure_predicate: String,

    /// Escalation predicate (free-form for v1).
    pub escalation_predicate: String,
}

impl StopConditions {
    /// Creates stop conditions with only a max episodes limit.
    #[must_use]
    pub const fn max_episodes(count: u64) -> Self {
        Self {
            max_episodes: count,
            goal_predicate: String::new(),
            failure_predicate: String::new(),
            escalation_predicate: String::new(),
        }
    }

    /// Returns `true` if a max episodes limit is set.
    #[must_use]
    pub const fn has_max_episodes(&self) -> bool {
        self.max_episodes > 0
    }

    /// Returns the canonical bytes for these conditions.
    ///
    /// Per AD-VERIFY-001, all fields are explicitly serialized even when
    /// they contain default values.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let proto = StopConditionsProto {
            max_episodes: Some(self.max_episodes),
            goal_predicate: Some(self.goal_predicate.clone()),
            failure_predicate: Some(self.failure_predicate.clone()),
            escalation_predicate: Some(self.escalation_predicate.clone()),
        };
        proto.encode_to_vec()
    }
}

/// Internal protobuf representation for `ContextRefs`.
#[derive(Clone, PartialEq, Message)]
struct ContextRefsProto {
    #[prost(bytes = "vec", tag = "1")]
    context_pack_hash: Vec<u8>,
    #[prost(string, repeated, tag = "2")]
    dcp_refs: Vec<String>,
}

/// Context references for episode execution.
///
/// Per AD-EPISODE-001, context refs include:
/// - `context_pack_hash`: Hash of the bundled context pack
/// - `dcp_refs`: References to dynamic context providers
///
/// # Security
///
/// Uses `deny_unknown_fields` to prevent field injection attacks when
/// deserializing from untrusted input.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextRefs {
    /// Hash of the context pack (bundled context artifacts).
    pub context_pack_hash: Vec<u8>,

    /// References to dynamic context providers.
    pub dcp_refs: Vec<String>,
}

impl ContextRefs {
    /// Creates empty context refs.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            context_pack_hash: Vec::new(),
            dcp_refs: Vec::new(),
        }
    }

    /// Returns `true` if no context is referenced.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.context_pack_hash.is_empty() && self.dcp_refs.is_empty()
    }

    /// Returns the canonical bytes with sorted DCP refs.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut sorted_refs = self.dcp_refs.clone();
        sorted_refs.sort();
        let proto = ContextRefsProto {
            context_pack_hash: self.context_pack_hash.clone(),
            dcp_refs: sorted_refs,
        };
        proto.encode_to_vec()
    }
}

/// Internal protobuf representation for the budget in envelope.
///
/// Per AD-VERIFY-001, we use `optional` fields to ensure explicit serialization
/// of all values including defaults.
#[derive(Clone, PartialEq, Message)]
struct BudgetProto {
    #[prost(uint64, optional, tag = "1")]
    tokens: Option<u64>,
    #[prost(uint32, optional, tag = "2")]
    tool_calls: Option<u32>,
    #[prost(uint64, optional, tag = "3")]
    wall_ms: Option<u64>,
    #[prost(uint64, optional, tag = "4")]
    cpu_ms: Option<u64>,
    #[prost(uint64, optional, tag = "5")]
    bytes_io: Option<u64>,
    #[prost(uint64, optional, tag = "6")]
    evidence_bytes: Option<u64>,
}

/// Internal protobuf representation for the snapshot in envelope.
///
/// Per AD-VERIFY-001, we use `optional` bytes fields to ensure explicit
/// serialization of all values including empty hashes. This prevents
/// Protobuf 3's implicit default skipping which would violate deterministic
/// encoding requirements.
#[allow(clippy::struct_field_names)]
#[derive(Clone, PartialEq, Message)]
struct SnapshotProto {
    #[prost(bytes = "vec", optional, tag = "1")]
    repo_hash: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "2")]
    lockfile_hash: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "3")]
    policy_hash: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "4")]
    toolchain_hash: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "5")]
    model_profile_hash: Option<Vec<u8>>,
}

/// Internal protobuf representation for `EpisodeEnvelope`.
///
/// Per AD-VERIFY-001, we use `optional` fields for numeric values to ensure
/// explicit serialization even when they contain default values.
#[derive(Clone, PartialEq, Message)]
struct EpisodeEnvelopeProto {
    #[prost(string, tag = "1")]
    episode_id: String,
    #[prost(string, tag = "2")]
    actor_id: String,
    #[prost(string, tag = "3")]
    work_id: String,
    #[prost(string, tag = "4")]
    lease_id: String,
    #[prost(message, optional, tag = "5")]
    budget: Option<BudgetProto>,
    #[prost(message, optional, tag = "6")]
    stop_conditions: Option<StopConditionsProto>,
    #[prost(message, optional, tag = "7")]
    pinned_snapshot: Option<SnapshotProto>,
    #[prost(bytes = "vec", tag = "8")]
    capability_manifest_hash: Vec<u8>,
    #[prost(uint32, optional, tag = "9")]
    risk_tier: Option<u32>,
    #[prost(uint32, optional, tag = "10")]
    determinism_class: Option<u32>,
    #[prost(message, optional, tag = "11")]
    context_refs: Option<ContextRefsProto>,
    #[prost(bytes = "vec", optional, tag = "12")]
    adapter_profile_hash: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "13")]
    role_spec_hash: Option<Vec<u8>>,
}

/// Immutable episode envelope.
///
/// Per AD-EPISODE-001, the envelope captures all configuration for an
/// episode at creation time. It is referenced by digest and bound into
/// all receipts for the episode.
///
/// # Required Fields
///
/// - `episode_id`: Stable UUID or content-derived digest
/// - `actor_id`: Caller identity (agent or user)
/// - `lease_id`: Required for actuation (tool execution)
/// - `budget`: Resource limits for the episode
/// - `stop_conditions`: Termination predicates
/// - `pinned_snapshot`: Reproducibility digests
/// - `capability_manifest_hash`: OCAP tool handles and scope
/// - `risk_tier`: Determines gates and evidence strength
/// - `determinism_class`: Declared reproducibility level
///
/// # Optional Fields
///
/// - `work_id`: Recommended but optional link to work item
/// - `context_refs`: Context pack and DCP references
/// - `adapter_profile_hash`: Optional adapter profile CAS hash attribution
/// - `role_spec_hash`: Optional role spec CAS hash attribution
///
/// # Invariants
///
/// - [INV-ENV-001] All ID fields are non-empty and <= `MAX_ID_LENGTH`.
/// - [INV-ENV-002] Envelope is immutable after creation.
/// - [INV-ENV-003] Digest is computed from canonical bytes.
///
/// # Example
///
/// ```rust
/// use apm2_daemon::episode::{
///     DeterminismClass, EpisodeBudget, EpisodeEnvelope, PinnedSnapshot, RiskTier, StopConditions,
/// };
///
/// let envelope = EpisodeEnvelope::builder()
///     .episode_id("ep-001")
///     .actor_id("agent-007")
///     .lease_id("lease-123")
///     .budget(EpisodeBudget::default())
///     .stop_conditions(StopConditions::max_episodes(100))
///     .pinned_snapshot(PinnedSnapshot::empty())
///     .capability_manifest_hash([0xab; 32])
///     .risk_tier(RiskTier::Tier1)
///     .determinism_class(DeterminismClass::NonDeterministic)
///     .build()
///     .expect("valid envelope");
///
/// assert_eq!(envelope.episode_id(), "ep-001");
/// let digest = envelope.digest();
/// assert_eq!(digest.len(), 32);
/// ```
///
/// # Security
///
/// Uses `deny_unknown_fields` to prevent field injection attacks when
/// deserializing from untrusted input.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpisodeEnvelope {
    /// Unique identifier for this episode.
    episode_id: String,

    /// Identity of the actor (agent or user) that created this episode.
    actor_id: String,

    /// Optional work item ID this episode is processing.
    work_id: String,

    /// Lease ID granting authority for this episode.
    lease_id: String,

    /// Resource budget for this episode.
    budget: Option<EpisodeBudget>,

    /// Stop conditions for episode termination.
    stop_conditions: Option<StopConditions>,

    /// Pinned snapshot of reproducibility inputs.
    pinned_snapshot: Option<PinnedSnapshot>,

    /// Hash of the capability manifest (OCAP handles).
    capability_manifest_hash: Vec<u8>,

    /// Optional hash of the adapter profile used for this episode.
    adapter_profile_hash: Option<[u8; 32]>,

    /// Optional hash of the role specification used for this episode.
    role_spec_hash: Option<[u8; 32]>,

    /// Risk tier for this episode.
    risk_tier: RiskTier,

    /// Determinism class for this episode.
    determinism_class: DeterminismClass,

    /// Optional context references.
    context_refs: Option<ContextRefs>,
}

impl EpisodeEnvelope {
    /// Creates a new envelope builder.
    #[must_use]
    pub const fn builder() -> EpisodeEnvelopeBuilder {
        EpisodeEnvelopeBuilder::new()
    }

    /// Returns the episode ID.
    #[must_use]
    pub fn episode_id(&self) -> &str {
        &self.episode_id
    }

    /// Returns the actor ID.
    #[must_use]
    pub fn actor_id(&self) -> &str {
        &self.actor_id
    }

    /// Returns the work ID, if set.
    #[must_use]
    pub fn work_id(&self) -> Option<&str> {
        if self.work_id.is_empty() {
            None
        } else {
            Some(&self.work_id)
        }
    }

    /// Returns the lease ID.
    #[must_use]
    pub fn lease_id(&self) -> &str {
        &self.lease_id
    }

    /// Returns the budget.
    #[must_use]
    pub fn budget(&self) -> &EpisodeBudget {
        static DEFAULT_BUDGET: EpisodeBudget = EpisodeBudget {
            tokens: 1_000_000,
            tool_calls: 10_000,
            wall_ms: 3_600_000,
            cpu_ms: 600_000,
            bytes_io: 10_737_418_240,
            evidence_bytes: 104_857_600,
        };
        self.budget.as_ref().unwrap_or(&DEFAULT_BUDGET)
    }

    /// Returns the stop conditions.
    #[must_use]
    pub fn stop_conditions(&self) -> &StopConditions {
        static DEFAULT_STOP_CONDITIONS: StopConditions = StopConditions {
            max_episodes: 0,
            goal_predicate: String::new(),
            failure_predicate: String::new(),
            escalation_predicate: String::new(),
        };
        self.stop_conditions
            .as_ref()
            .unwrap_or(&DEFAULT_STOP_CONDITIONS)
    }

    /// Returns the pinned snapshot.
    #[must_use]
    pub fn pinned_snapshot(&self) -> &PinnedSnapshot {
        static DEFAULT_PINNED_SNAPSHOT: PinnedSnapshot = PinnedSnapshot {
            repo_hash: Vec::new(),
            lockfile_hash: Vec::new(),
            policy_hash: Vec::new(),
            toolchain_hash: Vec::new(),
            model_profile_hash: Vec::new(),
        };
        self.pinned_snapshot
            .as_ref()
            .unwrap_or(&DEFAULT_PINNED_SNAPSHOT)
    }

    /// Returns the capability manifest hash.
    #[must_use]
    pub fn capability_manifest_hash(&self) -> &[u8] {
        &self.capability_manifest_hash
    }

    /// Returns the adapter profile hash, if set.
    #[must_use]
    pub const fn adapter_profile_hash(&self) -> Option<&[u8; 32]> {
        self.adapter_profile_hash.as_ref()
    }

    /// Returns the role spec hash, if set.
    #[must_use]
    pub const fn role_spec_hash(&self) -> Option<&[u8; 32]> {
        self.role_spec_hash.as_ref()
    }

    /// Returns the risk tier.
    #[must_use]
    pub const fn risk_tier(&self) -> RiskTier {
        self.risk_tier
    }

    /// Returns the determinism class.
    #[must_use]
    pub const fn determinism_class(&self) -> DeterminismClass {
        self.determinism_class
    }

    /// Returns the context refs, if set.
    #[must_use]
    pub fn context_refs(&self) -> Option<&ContextRefs> {
        self.context_refs.as_ref().filter(|c| !c.is_empty())
    }

    /// Returns the canonical bytes for this envelope.
    ///
    /// Per AD-VERIFY-001, this produces deterministic bytes suitable
    /// for hashing and signing. The method:
    /// 1. Sorts any repeated fields (`dcp_refs` in `context_refs`)
    /// 2. Encodes in protobuf tag order
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let proto = self.to_proto();
        proto.encode_to_vec()
    }

    /// Decodes an envelope from protobuf bytes.
    ///
    /// This method validates the decoded data using the same rules as
    /// [`EpisodeEnvelopeBuilder::build`], ensuring fail-closed security.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Protobuf decoding fails
    /// - Any required field is missing or invalid
    /// - `risk_tier` or `determinism_class` values are out of range
    /// - Hash lengths are invalid (must be 0 or 32 bytes)
    /// - ID lengths exceed `MAX_ID_LENGTH`
    /// - DCP refs count exceeds `MAX_DCP_REFS`
    pub fn decode(buf: &[u8]) -> Result<Self, EnvelopeError> {
        let proto = EpisodeEnvelopeProto::decode(buf)
            .map_err(|e| EnvelopeError::DecodeError(e.to_string()))?;
        Self::from_proto(proto)
    }

    /// Computes the BLAKE3 digest of this envelope.
    ///
    /// This digest is bound into all receipts for the episode.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        *blake3::hash(&self.canonical_bytes()).as_bytes()
    }

    /// Returns the digest as a hex string.
    #[must_use]
    pub fn digest_hex(&self) -> String {
        hex::encode(self.digest())
    }

    /// Converts to protobuf representation with sorted repeated fields.
    ///
    /// Per AD-VERIFY-001, all fields are explicitly serialized even when
    /// they contain default values.
    fn to_proto(&self) -> EpisodeEnvelopeProto {
        let budget = self.budget.as_ref().map(|b| BudgetProto {
            tokens: Some(b.tokens()),
            tool_calls: Some(b.tool_calls()),
            wall_ms: Some(b.wall_ms()),
            cpu_ms: Some(b.cpu_ms()),
            bytes_io: Some(b.bytes_io()),
            evidence_bytes: Some(b.evidence_bytes()),
        });

        let stop_conditions = self.stop_conditions.as_ref().map(|s| StopConditionsProto {
            max_episodes: Some(s.max_episodes),
            goal_predicate: Some(s.goal_predicate.clone()),
            failure_predicate: Some(s.failure_predicate.clone()),
            escalation_predicate: Some(s.escalation_predicate.clone()),
        });

        // Per AD-VERIFY-001, all snapshot hash fields are explicitly serialized
        // even when empty (using Some(vec![])) to ensure deterministic encoding.
        let pinned_snapshot = self.pinned_snapshot.as_ref().map(|s| SnapshotProto {
            repo_hash: Some(s.repo_hash().map(<[u8]>::to_vec).unwrap_or_default()),
            lockfile_hash: Some(s.lockfile_hash().map(<[u8]>::to_vec).unwrap_or_default()),
            policy_hash: Some(s.policy_hash().map(<[u8]>::to_vec).unwrap_or_default()),
            toolchain_hash: Some(s.toolchain_hash().map(<[u8]>::to_vec).unwrap_or_default()),
            model_profile_hash: Some(
                s.model_profile_hash()
                    .map(<[u8]>::to_vec)
                    .unwrap_or_default(),
            ),
        });

        let context_refs = self.context_refs.as_ref().map(|c| {
            let mut sorted_refs = c.dcp_refs.clone();
            sorted_refs.sort();
            ContextRefsProto {
                context_pack_hash: c.context_pack_hash.clone(),
                dcp_refs: sorted_refs,
            }
        });

        EpisodeEnvelopeProto {
            episode_id: self.episode_id.clone(),
            actor_id: self.actor_id.clone(),
            work_id: self.work_id.clone(),
            lease_id: self.lease_id.clone(),
            budget,
            stop_conditions,
            pinned_snapshot,
            capability_manifest_hash: self.capability_manifest_hash.clone(),
            risk_tier: Some(u32::from(self.risk_tier.tier())),
            determinism_class: Some(u32::from(self.determinism_class.value())),
            context_refs,
            adapter_profile_hash: self.adapter_profile_hash.map(|hash| hash.to_vec()),
            role_spec_hash: self.role_spec_hash.map(|hash| hash.to_vec()),
        }
    }

    /// Converts from protobuf representation with full validation.
    ///
    /// # Security
    ///
    /// This method enforces the same validation as `build()` to prevent
    /// validation bypass attacks via crafted protobuf messages.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Any required field is missing or invalid
    /// - `risk_tier` or `determinism_class` values are out of range
    ///   (fail-closed)
    /// - Hash lengths are invalid (must be 0 or exactly 32 bytes)
    /// - ID lengths exceed `MAX_ID_LENGTH`
    /// - DCP refs count exceeds `MAX_DCP_REFS`
    fn from_proto(proto: EpisodeEnvelopeProto) -> Result<Self, EnvelopeError> {
        // Validate required ID fields - same checks as build()
        if proto.episode_id.is_empty() {
            return Err(EnvelopeError::MissingEpisodeId);
        }
        if proto.actor_id.is_empty() {
            return Err(EnvelopeError::MissingActorId);
        }
        if proto.lease_id.is_empty() {
            return Err(EnvelopeError::MissingLeaseId);
        }
        if proto.capability_manifest_hash.is_empty() {
            return Err(EnvelopeError::MissingCapabilityManifestHash);
        }

        // Validate required fields per AD-EPISODE-001 - same checks as build()
        if proto.budget.is_none() {
            return Err(EnvelopeError::MissingBudget);
        }
        if proto.stop_conditions.is_none() {
            return Err(EnvelopeError::MissingStopConditions);
        }
        if proto.pinned_snapshot.is_none() {
            return Err(EnvelopeError::MissingPinnedSnapshot);
        }

        // Validate ID lengths - same checks as build()
        if proto.episode_id.len() > MAX_ID_LENGTH {
            return Err(EnvelopeError::IdTooLong {
                field: "episode_id",
                max: MAX_ID_LENGTH,
            });
        }
        if proto.actor_id.len() > MAX_ID_LENGTH {
            return Err(EnvelopeError::IdTooLong {
                field: "actor_id",
                max: MAX_ID_LENGTH,
            });
        }
        if proto.work_id.len() > MAX_ID_LENGTH {
            return Err(EnvelopeError::IdTooLong {
                field: "work_id",
                max: MAX_ID_LENGTH,
            });
        }
        if proto.lease_id.len() > MAX_ID_LENGTH {
            return Err(EnvelopeError::IdTooLong {
                field: "lease_id",
                max: MAX_ID_LENGTH,
            });
        }

        // Validate capability manifest hash size
        if proto.capability_manifest_hash.len() != 32 {
            return Err(EnvelopeError::InvalidCapabilityManifestHashSize);
        }

        // Validate risk_tier - FAIL-CLOSED: reject invalid values
        // SECURITY: Match on u32 directly to prevent truncation attacks (e.g., 256 ->
        // 0)
        let risk_tier_u32 = proto.risk_tier.unwrap_or(0);
        let risk_tier =
            RiskTier::from_u32(risk_tier_u32).ok_or(EnvelopeError::InvalidRiskTier {
                value: risk_tier_u32,
            })?;

        // Validate determinism_class - FAIL-CLOSED: reject invalid values
        // SECURITY: Match on u32 directly to prevent truncation attacks (e.g., 256 ->
        // 0)
        let determinism_class_u32 = proto.determinism_class.unwrap_or(0);
        let determinism_class = DeterminismClass::from_u32(determinism_class_u32).ok_or(
            EnvelopeError::InvalidDeterminismClass {
                value: determinism_class_u32,
            },
        )?;

        // Validate DCP refs count and individual ref lengths (DoS protection)
        if let Some(ref ctx) = proto.context_refs {
            if ctx.dcp_refs.len() > MAX_DCP_REFS {
                return Err(EnvelopeError::TooManyDcpRefs { max: MAX_DCP_REFS });
            }
            // SECURITY: Validate each DCP ref string length to prevent DoS
            for dcp_ref in &ctx.dcp_refs {
                if dcp_ref.len() > MAX_ID_LENGTH {
                    return Err(EnvelopeError::StringTooLong {
                        field: "context_refs.dcp_refs",
                        max: MAX_ID_LENGTH,
                    });
                }
            }
        }

        // SECURITY: Validate stop_conditions string field lengths (DoS protection)
        if let Some(ref sc) = proto.stop_conditions {
            if let Some(ref gp) = sc.goal_predicate {
                if gp.len() > MAX_ID_LENGTH {
                    return Err(EnvelopeError::StringTooLong {
                        field: "stop_conditions.goal_predicate",
                        max: MAX_ID_LENGTH,
                    });
                }
            }
            if let Some(ref fp) = sc.failure_predicate {
                if fp.len() > MAX_ID_LENGTH {
                    return Err(EnvelopeError::StringTooLong {
                        field: "stop_conditions.failure_predicate",
                        max: MAX_ID_LENGTH,
                    });
                }
            }
            if let Some(ref ep) = sc.escalation_predicate {
                if ep.len() > MAX_ID_LENGTH {
                    return Err(EnvelopeError::StringTooLong {
                        field: "stop_conditions.escalation_predicate",
                        max: MAX_ID_LENGTH,
                    });
                }
            }
        }

        let budget = proto.budget.map(|b| {
            EpisodeBudget::builder()
                .tokens(b.tokens.unwrap_or(0))
                .tool_calls(b.tool_calls.unwrap_or(0))
                .wall_ms(b.wall_ms.unwrap_or(0))
                .cpu_ms(b.cpu_ms.unwrap_or(0))
                .bytes_io(b.bytes_io.unwrap_or(0))
                .evidence_bytes(b.evidence_bytes.unwrap_or(0))
                .build()
        });

        let stop_conditions = proto.stop_conditions.map(|s| StopConditions {
            max_episodes: s.max_episodes.unwrap_or(0),
            goal_predicate: s.goal_predicate.unwrap_or_default(),
            failure_predicate: s.failure_predicate.unwrap_or_default(),
            escalation_predicate: s.escalation_predicate.unwrap_or_default(),
        });

        // Validate pinned snapshot hash lengths - FAIL-CLOSED: reject invalid lengths
        let pinned_snapshot = match proto.pinned_snapshot {
            Some(s) => {
                // Helper to validate hash length: must be 0 or exactly 32 bytes
                // Helper to validate optional hash length: must be empty or exactly 32 bytes
                let validate_hash =
                    |hash: &Option<Vec<u8>>, field: &'static str| -> Result<(), EnvelopeError> {
                        if let Some(h) = hash {
                            if !h.is_empty() && h.len() != 32 {
                                return Err(EnvelopeError::InvalidHashLength {
                                    field,
                                    expected: 32,
                                    actual: h.len(),
                                });
                            }
                        }
                        Ok(())
                    };

                validate_hash(&s.repo_hash, "repo_hash")?;
                validate_hash(&s.lockfile_hash, "lockfile_hash")?;
                validate_hash(&s.policy_hash, "policy_hash")?;
                validate_hash(&s.toolchain_hash, "toolchain_hash")?;
                validate_hash(&s.model_profile_hash, "model_profile_hash")?;

                let mut builder = PinnedSnapshot::builder();
                if let Some(ref hash) = s.repo_hash {
                    if hash.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(hash);
                        builder = builder.repo_hash(arr);
                    }
                }
                if let Some(ref hash) = s.lockfile_hash {
                    if hash.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(hash);
                        builder = builder.lockfile_hash(arr);
                    }
                }
                if let Some(ref hash) = s.policy_hash {
                    if hash.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(hash);
                        builder = builder.policy_hash(arr);
                    }
                }
                if let Some(ref hash) = s.toolchain_hash {
                    if hash.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(hash);
                        builder = builder.toolchain_hash(arr);
                    }
                }
                if let Some(ref hash) = s.model_profile_hash {
                    if hash.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(hash);
                        builder = builder.model_profile_hash(arr);
                    }
                }
                Some(builder.build())
            },
            None => None,
        };

        let context_refs = proto.context_refs.map(|c| ContextRefs {
            context_pack_hash: c.context_pack_hash,
            dcp_refs: c.dcp_refs,
        });

        let adapter_profile_hash = match proto.adapter_profile_hash {
            Some(hash) => {
                if hash.len() != 32 {
                    return Err(EnvelopeError::InvalidHashLength {
                        field: "adapter_profile_hash",
                        expected: 32,
                        actual: hash.len(),
                    });
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&hash);
                Some(arr)
            },
            None => None,
        };

        let role_spec_hash = match proto.role_spec_hash {
            Some(hash) => {
                if hash.len() != 32 {
                    return Err(EnvelopeError::InvalidHashLength {
                        field: "role_spec_hash",
                        expected: 32,
                        actual: hash.len(),
                    });
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&hash);
                Some(arr)
            },
            None => None,
        };

        Ok(Self {
            episode_id: proto.episode_id,
            actor_id: proto.actor_id,
            work_id: proto.work_id,
            lease_id: proto.lease_id,
            budget,
            stop_conditions,
            pinned_snapshot,
            capability_manifest_hash: proto.capability_manifest_hash,
            adapter_profile_hash,
            role_spec_hash,
            risk_tier,
            determinism_class,
            context_refs,
        })
    }
}

/// Error type for envelope construction and decoding.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EnvelopeError {
    /// Episode ID is missing or empty.
    #[error("episode_id is required")]
    MissingEpisodeId,

    /// Actor ID is missing or empty.
    #[error("actor_id is required")]
    MissingActorId,

    /// Lease ID is missing or empty.
    #[error("lease_id is required")]
    MissingLeaseId,

    /// Capability manifest hash is missing.
    #[error("capability_manifest_hash is required")]
    MissingCapabilityManifestHash,

    /// Budget is missing (required per AD-EPISODE-001).
    #[error("budget is required per AD-EPISODE-001")]
    MissingBudget,

    /// Stop conditions are missing (required per AD-EPISODE-001).
    #[error("stop_conditions is required per AD-EPISODE-001")]
    MissingStopConditions,

    /// Pinned snapshot is missing (required per AD-EPISODE-001).
    #[error("pinned_snapshot is required per AD-EPISODE-001")]
    MissingPinnedSnapshot,

    /// ID exceeds maximum length.
    #[error("{field} exceeds maximum length of {max} characters")]
    IdTooLong {
        /// Field name.
        field: &'static str,
        /// Maximum allowed length.
        max: usize,
    },

    /// Capability manifest hash has wrong size.
    #[error("capability_manifest_hash must be exactly 32 bytes")]
    InvalidCapabilityManifestHashSize,

    /// Too many DCP references.
    #[error("context_refs.dcp_refs exceeds maximum of {max} entries")]
    TooManyDcpRefs {
        /// Maximum allowed count.
        max: usize,
    },

    /// Invalid risk tier value.
    #[error("invalid risk_tier value: {value}")]
    InvalidRiskTier {
        /// The invalid value (stored as u32 to capture truncation attacks).
        value: u32,
    },

    /// Invalid determinism class value.
    #[error("invalid determinism_class value: {value}")]
    InvalidDeterminismClass {
        /// The invalid value (stored as u32 to capture truncation attacks).
        value: u32,
    },

    /// String field too long (denial-of-service protection).
    #[error("{field} exceeds maximum length of {max} bytes")]
    StringTooLong {
        /// Field name.
        field: &'static str,
        /// Maximum allowed length in bytes.
        max: usize,
    },

    /// Protobuf decoding error.
    #[error("protobuf decode error: {0}")]
    DecodeError(String),

    /// Invalid hash length in pinned snapshot.
    #[error("{field} has invalid length {actual}, expected 0 or {expected}")]
    InvalidHashLength {
        /// Field name.
        field: &'static str,
        /// Expected length.
        expected: usize,
        /// Actual length.
        actual: usize,
    },

    /// Invalid hash length when setting field.
    #[error("{field} must be exactly {expected} bytes, got {actual}")]
    InvalidHashSize {
        /// Field name.
        field: &'static str,
        /// Expected length.
        expected: usize,
        /// Actual length.
        actual: usize,
    },
}

/// Builder for [`EpisodeEnvelope`].
#[derive(Debug, Clone, Default)]
pub struct EpisodeEnvelopeBuilder {
    episode_id: String,
    actor_id: String,
    work_id: String,
    lease_id: String,
    budget: Option<EpisodeBudget>,
    stop_conditions: Option<StopConditions>,
    pinned_snapshot: Option<PinnedSnapshot>,
    capability_manifest_hash: Vec<u8>,
    adapter_profile_hash: Option<[u8; 32]>,
    role_spec_hash: Option<[u8; 32]>,
    risk_tier: RiskTier,
    determinism_class: DeterminismClass,
    context_refs: Option<ContextRefs>,
}

impl EpisodeEnvelopeBuilder {
    /// Creates a new builder.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            episode_id: String::new(),
            actor_id: String::new(),
            work_id: String::new(),
            lease_id: String::new(),
            budget: None,
            stop_conditions: None,
            pinned_snapshot: None,
            capability_manifest_hash: Vec::new(),
            adapter_profile_hash: None,
            role_spec_hash: None,
            risk_tier: RiskTier::Tier0,
            determinism_class: DeterminismClass::NonDeterministic,
            context_refs: None,
        }
    }

    /// Sets the episode ID (required).
    #[must_use]
    pub fn episode_id(mut self, id: impl Into<String>) -> Self {
        self.episode_id = id.into();
        self
    }

    /// Sets the actor ID (required).
    #[must_use]
    pub fn actor_id(mut self, id: impl Into<String>) -> Self {
        self.actor_id = id.into();
        self
    }

    /// Sets the work ID (optional).
    #[must_use]
    pub fn work_id(mut self, id: impl Into<String>) -> Self {
        self.work_id = id.into();
        self
    }

    /// Sets the lease ID (required).
    #[must_use]
    pub fn lease_id(mut self, id: impl Into<String>) -> Self {
        self.lease_id = id.into();
        self
    }

    /// Sets the budget.
    #[must_use]
    pub const fn budget(mut self, budget: EpisodeBudget) -> Self {
        self.budget = Some(budget);
        self
    }

    /// Sets the stop conditions.
    #[must_use]
    pub fn stop_conditions(mut self, conditions: StopConditions) -> Self {
        self.stop_conditions = Some(conditions);
        self
    }

    /// Sets the pinned snapshot.
    #[must_use]
    pub fn pinned_snapshot(mut self, snapshot: PinnedSnapshot) -> Self {
        self.pinned_snapshot = Some(snapshot);
        self
    }

    /// Sets the capability manifest hash.
    #[must_use]
    pub fn capability_manifest_hash(mut self, hash: [u8; 32]) -> Self {
        self.capability_manifest_hash = hash.to_vec();
        self
    }

    /// Sets the capability manifest hash from a slice.
    #[must_use]
    pub fn capability_manifest_hash_from_slice(mut self, hash: &[u8]) -> Self {
        self.capability_manifest_hash = hash.to_vec();
        self
    }

    /// Sets the adapter profile hash attribution.
    #[must_use]
    pub const fn adapter_profile_hash(mut self, hash: [u8; 32]) -> Self {
        self.adapter_profile_hash = Some(hash);
        self
    }

    /// Sets the role spec hash attribution.
    #[must_use]
    pub const fn role_spec_hash(mut self, hash: [u8; 32]) -> Self {
        self.role_spec_hash = Some(hash);
        self
    }

    /// Sets the risk tier.
    #[must_use]
    pub const fn risk_tier(mut self, tier: RiskTier) -> Self {
        self.risk_tier = tier;
        self
    }

    /// Sets the determinism class.
    #[must_use]
    pub const fn determinism_class(mut self, class: DeterminismClass) -> Self {
        self.determinism_class = class;
        self
    }

    /// Sets the context refs.
    #[must_use]
    pub fn context_refs(mut self, refs: ContextRefs) -> Self {
        self.context_refs = Some(refs);
        self
    }

    /// Builds the envelope, validating all required fields.
    ///
    /// # Required Fields (per AD-EPISODE-001)
    ///
    /// - `episode_id`: Stable identifier for this episode
    /// - `actor_id`: Identity of the caller (agent or user)
    /// - `lease_id`: Lease granting authority for this episode
    /// - `capability_manifest_hash`: Hash of OCAP tool handles
    /// - `budget`: Resource limits for the episode
    /// - `stop_conditions`: Termination predicates
    /// - `pinned_snapshot`: Reproducibility digests
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Any required field is missing
    /// - Any ID exceeds `MAX_ID_LENGTH`
    /// - Capability manifest hash is not 32 bytes
    /// - Too many DCP references
    pub fn build(self) -> Result<EpisodeEnvelope, EnvelopeError> {
        // Validate required ID fields
        if self.episode_id.is_empty() {
            return Err(EnvelopeError::MissingEpisodeId);
        }
        if self.actor_id.is_empty() {
            return Err(EnvelopeError::MissingActorId);
        }
        if self.lease_id.is_empty() {
            return Err(EnvelopeError::MissingLeaseId);
        }
        if self.capability_manifest_hash.is_empty() {
            return Err(EnvelopeError::MissingCapabilityManifestHash);
        }

        // Validate required fields per AD-EPISODE-001
        if self.budget.is_none() {
            return Err(EnvelopeError::MissingBudget);
        }
        if self.stop_conditions.is_none() {
            return Err(EnvelopeError::MissingStopConditions);
        }
        if self.pinned_snapshot.is_none() {
            return Err(EnvelopeError::MissingPinnedSnapshot);
        }

        // Validate field lengths
        if self.episode_id.len() > MAX_ID_LENGTH {
            return Err(EnvelopeError::IdTooLong {
                field: "episode_id",
                max: MAX_ID_LENGTH,
            });
        }
        if self.actor_id.len() > MAX_ID_LENGTH {
            return Err(EnvelopeError::IdTooLong {
                field: "actor_id",
                max: MAX_ID_LENGTH,
            });
        }
        if self.work_id.len() > MAX_ID_LENGTH {
            return Err(EnvelopeError::IdTooLong {
                field: "work_id",
                max: MAX_ID_LENGTH,
            });
        }
        if self.lease_id.len() > MAX_ID_LENGTH {
            return Err(EnvelopeError::IdTooLong {
                field: "lease_id",
                max: MAX_ID_LENGTH,
            });
        }

        // Validate capability manifest hash size
        if self.capability_manifest_hash.len() != 32 {
            return Err(EnvelopeError::InvalidCapabilityManifestHashSize);
        }

        // Validate DCP refs count and individual ref lengths (DoS protection)
        if let Some(ref ctx) = self.context_refs {
            if ctx.dcp_refs.len() > MAX_DCP_REFS {
                return Err(EnvelopeError::TooManyDcpRefs { max: MAX_DCP_REFS });
            }
            // SECURITY: Validate each DCP ref string length to prevent DoS
            for dcp_ref in &ctx.dcp_refs {
                if dcp_ref.len() > MAX_ID_LENGTH {
                    return Err(EnvelopeError::StringTooLong {
                        field: "context_refs.dcp_refs",
                        max: MAX_ID_LENGTH,
                    });
                }
            }
        }

        // SECURITY: Validate stop_conditions string field lengths (DoS protection)
        if let Some(ref sc) = self.stop_conditions {
            if sc.goal_predicate.len() > MAX_ID_LENGTH {
                return Err(EnvelopeError::StringTooLong {
                    field: "stop_conditions.goal_predicate",
                    max: MAX_ID_LENGTH,
                });
            }
            if sc.failure_predicate.len() > MAX_ID_LENGTH {
                return Err(EnvelopeError::StringTooLong {
                    field: "stop_conditions.failure_predicate",
                    max: MAX_ID_LENGTH,
                });
            }
            if sc.escalation_predicate.len() > MAX_ID_LENGTH {
                return Err(EnvelopeError::StringTooLong {
                    field: "stop_conditions.escalation_predicate",
                    max: MAX_ID_LENGTH,
                });
            }
        }

        Ok(EpisodeEnvelope {
            episode_id: self.episode_id,
            actor_id: self.actor_id,
            work_id: self.work_id,
            lease_id: self.lease_id,
            budget: self.budget,
            stop_conditions: self.stop_conditions,
            pinned_snapshot: self.pinned_snapshot,
            capability_manifest_hash: self.capability_manifest_hash,
            adapter_profile_hash: self.adapter_profile_hash,
            role_spec_hash: self.role_spec_hash,
            risk_tier: self.risk_tier,
            determinism_class: self.determinism_class,
            context_refs: self.context_refs,
        })
    }
}

// ============================================================================
// TCK-00350: EpisodeEnvelopeV1 — envelope with receipt binding fields
// ============================================================================

/// V1 envelope that extends [`EpisodeEnvelope`] with receipt binding fields
/// required by REQ-0004.
///
/// Per REQ-0004:
/// - All authoritative effects MUST bind `envelope_hash`,
///   `capability_manifest_hash`, and `view_commitment_hash` in receipts.
/// - `EpisodeEnvelopeV1` MUST bind `freshness_pinset_hash` (deterministic
///   pinned-snapshot commitment).
/// - Delegated episodes MUST bind `permeability_receipt_hash`.
/// - Spawn or resume without valid envelope bindings MUST be denied.
///
/// # Fail-closed Semantics
///
/// All hash fields are validated as non-zero at construction time. Attempts
/// to build an `EpisodeEnvelopeV1` with zero hashes are rejected, enforcing
/// fail-closed behavior.
///
/// # Security
///
/// Uses `deny_unknown_fields` to prevent field injection attacks.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpisodeEnvelopeV1 {
    /// The inner episode envelope with all base fields.
    inner: EpisodeEnvelope,

    /// BLAKE3 hash of the `ViewCommitmentV1` binding.
    ///
    /// This hash commits to the specific view of the world that the episode
    /// is operating against. Receipts MUST include this hash to enable
    /// replay verification.
    view_commitment_hash: [u8; 32],

    /// BLAKE3 hash of the deterministic freshness pinset commitment.
    ///
    /// Per REQ-0004, the envelope MUST bind a deterministic pinned-snapshot
    /// commitment hash, ensuring that the freshness of referenced artifacts
    /// is verifiable during replay.
    freshness_pinset_hash: [u8; 32],

    /// Optional BLAKE3 hash of the permeability receipt for delegated
    /// episodes.
    ///
    /// Per REQ-0004, delegated episodes MUST bind `permeability_receipt_hash`.
    /// Non-delegated episodes leave this as `None`.
    permeability_receipt_hash: Option<[u8; 32]>,
}

impl EpisodeEnvelopeV1 {
    /// Creates a new V1 envelope builder.
    #[must_use]
    pub const fn builder() -> EpisodeEnvelopeV1Builder {
        EpisodeEnvelopeV1Builder::new()
    }

    /// Returns the inner base envelope.
    #[must_use]
    pub const fn inner(&self) -> &EpisodeEnvelope {
        &self.inner
    }

    /// Returns the BLAKE3 digest of the inner envelope.
    ///
    /// This is the `envelope_hash` bound into all receipts.
    #[must_use]
    pub fn envelope_hash(&self) -> [u8; 32] {
        self.inner.digest()
    }

    /// Returns the capability manifest hash from the inner envelope.
    #[must_use]
    pub fn capability_manifest_hash(&self) -> &[u8] {
        self.inner.capability_manifest_hash()
    }

    /// Returns the view commitment hash.
    #[must_use]
    pub const fn view_commitment_hash(&self) -> &[u8; 32] {
        &self.view_commitment_hash
    }

    /// Returns the freshness pinset hash.
    #[must_use]
    pub const fn freshness_pinset_hash(&self) -> &[u8; 32] {
        &self.freshness_pinset_hash
    }

    /// Returns the permeability receipt hash, if present.
    #[must_use]
    pub const fn permeability_receipt_hash(&self) -> Option<&[u8; 32]> {
        self.permeability_receipt_hash.as_ref()
    }

    /// Returns `true` if this is a delegated episode (has permeability
    /// receipt).
    #[must_use]
    pub const fn is_delegated(&self) -> bool {
        self.permeability_receipt_hash.is_some()
    }

    /// Extracts the [`EnvelopeBindings`] for embedding into receipts.
    ///
    /// Per REQ-0004, every authoritative receipt MUST carry these three
    /// binding hashes.
    #[must_use]
    pub fn bindings(&self) -> EnvelopeBindings {
        let mut cap_hash = [0u8; 32];
        let cap_slice = self.inner.capability_manifest_hash();
        if cap_slice.len() == 32 {
            cap_hash.copy_from_slice(cap_slice);
        }
        EnvelopeBindings {
            envelope_hash: self.envelope_hash(),
            capability_manifest_hash: cap_hash,
            view_commitment_hash: self.view_commitment_hash,
        }
    }

    /// Validates that this envelope is well-formed for spawn/resume.
    ///
    /// # Fail-closed
    ///
    /// Returns an error if any required binding is missing or zero. This
    /// is the enforcement point for the spawn/resume gate.
    ///
    /// # Errors
    ///
    /// Returns [`EnvelopeV1Error`] if validation fails.
    pub fn validate_for_spawn(&self) -> Result<(), EnvelopeV1Error> {
        // Envelope hash is derived from inner, always non-zero if inner is
        // valid. But double-check as defense-in-depth.
        if self.envelope_hash() == [0u8; 32] {
            return Err(EnvelopeV1Error::ZeroEnvelopeHash);
        }

        // Capability manifest hash must be non-zero
        if self.inner.capability_manifest_hash() == [0u8; 32] {
            return Err(EnvelopeV1Error::ZeroCapabilityManifestHash);
        }

        // View commitment hash must be non-zero
        if self.view_commitment_hash == [0u8; 32] {
            return Err(EnvelopeV1Error::ZeroViewCommitmentHash);
        }

        // Freshness pinset hash must be non-zero
        if self.freshness_pinset_hash == [0u8; 32] {
            return Err(EnvelopeV1Error::ZeroFreshnessPinsetHash);
        }

        Ok(())
    }

    /// Validates that this envelope is well-formed for a delegated
    /// spawn/resume.
    ///
    /// In addition to the base spawn validation, delegated episodes
    /// MUST have a non-zero `permeability_receipt_hash`.
    ///
    /// # Errors
    ///
    /// Returns [`EnvelopeV1Error`] if validation fails.
    pub fn validate_for_delegated_spawn(&self) -> Result<(), EnvelopeV1Error> {
        self.validate_for_spawn()?;

        match &self.permeability_receipt_hash {
            None => Err(EnvelopeV1Error::MissingPermeabilityReceiptHash),
            Some(hash) if *hash == [0u8; 32] => Err(EnvelopeV1Error::ZeroPermeabilityReceiptHash),
            Some(_) => Ok(()),
        }
    }

    /// Validates that this envelope is well-formed for a delegated
    /// spawn **and** that the bound permeability receipt passes full
    /// consumption binding verification (REQ-0027).
    ///
    /// This is the production-grade delegated spawn gate. It performs:
    /// 1. All base spawn checks
    ///    ([`validate_for_spawn`](Self::validate_for_spawn))
    /// 2. Presence/non-zero check on `permeability_receipt_hash`
    /// 3. Receipt admission (structural, expiry, issuance-time checks)
    /// 4. Hash binding: `receipt.content_hash() == permeability_receipt_hash`
    /// 5. **BLOCKER 1**: Policy root provenance verification
    /// 6. **BLOCKER 2**: Scope binding (actor identity match)
    /// 7. **BLOCKER 3**: Delegation chain continuity for delegated receipts
    /// 8. **MAJOR**: Authority ceiling validation against envelope state
    /// 9. Authority subset: `required_authority` is a subset of the receipt's
    ///    delegated authority
    ///
    /// # Arguments
    ///
    /// * `receipt` - The permeability receipt to validate against.
    /// * `required_authority` - The minimum authority needed for this spawn.
    /// * `now_ms` - Current time in milliseconds since epoch.
    ///
    /// # Errors
    ///
    /// Returns [`EnvelopeV1Error`] if any check fails (fail-closed).
    pub fn validate_for_delegated_spawn_with_receipt(
        &self,
        receipt: &apm2_core::policy::permeability::PermeabilityReceipt,
        required_authority: &apm2_core::policy::permeability::AuthorityVector,
        now_ms: u64,
    ) -> Result<(), EnvelopeV1Error> {
        // First: all structural envelope checks (base spawn + hash presence).
        self.validate_for_delegated_spawn()?;

        // Second: full consumption binding verification (admission + hash
        // match + authority subset + provenance + scope + chain + ceiling).
        let bound_hash = self
            .permeability_receipt_hash
            .as_ref()
            .expect("validate_for_delegated_spawn ensures Some");

        // Derive policy root hash from the envelope's pinned snapshot.
        // The policy_hash in the pinned snapshot IS the policy root.
        // Fail-closed: if the envelope lacks a valid policy hash, deny
        // the delegated spawn rather than falling back to a synthetic
        // caller-controlled value.
        let policy_root = self.derive_policy_root_hash()?;

        // Derive authority ceiling from the envelope's risk tier.
        let authority_ceiling = self.derive_authority_ceiling();

        let ctx = apm2_core::policy::permeability::ConsumptionContext {
            actor_id: self.inner.actor_id(),
            policy_root_hash: &policy_root,
            authority_ceiling: Some(&authority_ceiling),
            parent_chain_commitment: None,
        };

        apm2_core::policy::permeability::validate_consumption_binding(
            receipt,
            bound_hash,
            required_authority,
            now_ms,
            Some(&ctx),
        )
        .map_err(EnvelopeV1Error::PermeabilityBindingFailure)?;

        Ok(())
    }

    /// Derives the policy root hash from the envelope's pinned snapshot.
    ///
    /// The policy root MUST come from the pinned snapshot's `policy_hash`.
    /// If the snapshot lacks a valid 32-byte non-zero policy hash, this
    /// function returns an error (fail-closed). A synthetic/fallback
    /// value would make the compared root caller-controlled, defeating
    /// cryptographic provenance verification.
    ///
    /// # Errors
    ///
    /// Returns [`EnvelopeV1Error::MissingPolicyRootDerivation`] when the
    /// envelope lacks a valid policy hash.
    fn derive_policy_root_hash(&self) -> Result<[u8; 32], EnvelopeV1Error> {
        if let Some(ph) = self.inner.pinned_snapshot().policy_hash() {
            if ph.len() == 32 {
                let mut hash = [0u8; 32];
                hash.copy_from_slice(ph);
                if hash == [0u8; 32] {
                    return Err(EnvelopeV1Error::MissingPolicyRootDerivation);
                }
                return Ok(hash);
            }
        }
        // Fail-closed: no valid policy_hash means we cannot derive a
        // trustworthy policy root. Returning a synthetic value would
        // allow caller-controlled policy root bypass.
        Err(EnvelopeV1Error::MissingPolicyRootDerivation)
    }

    /// Derives an authority ceiling from the envelope's risk tier.
    ///
    /// The risk tier constrains the maximum authority that can be
    /// consumed in this envelope context. Higher tiers allow wider
    /// authority ceilings.
    const fn derive_authority_ceiling(&self) -> apm2_core::policy::permeability::AuthorityVector {
        use apm2_core::policy::permeability::{
            AuthorityVector, BudgetLevel, CapabilityLevel, ClassificationLevel, RiskLevel,
            StopPredicateLevel, TaintCeiling,
        };

        match self.inner.risk_tier() {
            RiskTier::Tier0 => AuthorityVector::new(
                RiskLevel::Low,
                CapabilityLevel::ReadOnly,
                BudgetLevel::Capped(1_000_000),
                StopPredicateLevel::Inherit,
                TaintCeiling::Attested,
                ClassificationLevel::Confidential,
            ),
            RiskTier::Tier1 => AuthorityVector::new(
                RiskLevel::Med,
                CapabilityLevel::ReadWrite,
                BudgetLevel::Capped(10_000_000),
                StopPredicateLevel::Extend,
                TaintCeiling::Untrusted,
                ClassificationLevel::Secret,
            ),
            // Tier2+ get full authority ceiling — the receipt's
            // delegated authority is the binding constraint.
            RiskTier::Tier2 | RiskTier::Tier3 | RiskTier::Tier4 => AuthorityVector::top(),
        }
    }
}

/// Receipt binding triplet extracted from an `EpisodeEnvelopeV1`.
///
/// Per REQ-0004, every authoritative effect receipt MUST carry these
/// three binding hashes. Receipts emitted without these bindings MUST
/// be rejected (fail-closed).
///
/// # Validation
///
/// Use [`EnvelopeBindings::validate`] to ensure all bindings are
/// present and non-zero before signing a receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EnvelopeBindings {
    /// BLAKE3 hash of the `EpisodeEnvelope` canonical bytes.
    pub envelope_hash: [u8; 32],

    /// BLAKE3 hash of the capability manifest.
    pub capability_manifest_hash: [u8; 32],

    /// BLAKE3 hash of the `ViewCommitmentV1`.
    pub view_commitment_hash: [u8; 32],
}

impl EnvelopeBindings {
    /// Validates that all binding hashes are non-zero.
    ///
    /// # Fail-closed
    ///
    /// Receipts MUST NOT be signed if any binding is zero. This method
    /// enforces that invariant.
    ///
    /// # Errors
    ///
    /// Returns [`EnvelopeV1Error`] if any binding hash is zero.
    pub fn validate(&self) -> Result<(), EnvelopeV1Error> {
        if self.envelope_hash == [0u8; 32] {
            return Err(EnvelopeV1Error::ZeroEnvelopeHash);
        }
        if self.capability_manifest_hash == [0u8; 32] {
            return Err(EnvelopeV1Error::ZeroCapabilityManifestHash);
        }
        if self.view_commitment_hash == [0u8; 32] {
            return Err(EnvelopeV1Error::ZeroViewCommitmentHash);
        }
        Ok(())
    }

    /// Verifies that these bindings match the given envelope.
    ///
    /// This is the replay verification path: given a receipt's bindings
    /// and the CAS-stored envelope, verify consistency.
    ///
    /// # Errors
    ///
    /// Returns [`EnvelopeV1Error::BindingMismatch`] if any hash does
    /// not match.
    pub fn verify_against(&self, envelope: &EpisodeEnvelopeV1) -> Result<(), EnvelopeV1Error> {
        let expected = envelope.bindings();

        if self.envelope_hash != expected.envelope_hash {
            return Err(EnvelopeV1Error::BindingMismatch {
                field: "envelope_hash",
            });
        }
        if self.capability_manifest_hash != expected.capability_manifest_hash {
            return Err(EnvelopeV1Error::BindingMismatch {
                field: "capability_manifest_hash",
            });
        }
        if self.view_commitment_hash != expected.view_commitment_hash {
            return Err(EnvelopeV1Error::BindingMismatch {
                field: "view_commitment_hash",
            });
        }
        Ok(())
    }

    /// Returns hex-encoded representations for JSON inclusion in ledger
    /// events.
    #[must_use]
    pub fn to_hex_map(&self) -> (String, String, String) {
        (
            hex::encode(self.envelope_hash),
            hex::encode(self.capability_manifest_hash),
            hex::encode(self.view_commitment_hash),
        )
    }
}

/// Error type for `EpisodeEnvelopeV1` operations (TCK-00350).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EnvelopeV1Error {
    /// Inner envelope construction failed.
    #[error("inner envelope error: {0}")]
    InnerEnvelopeError(#[from] EnvelopeError),

    /// View commitment hash is missing (zero).
    #[error("view_commitment_hash is zero (fail-closed)")]
    ZeroViewCommitmentHash,

    /// Freshness pinset hash is missing (zero).
    #[error("freshness_pinset_hash is zero (fail-closed)")]
    ZeroFreshnessPinsetHash,

    /// Envelope hash is zero (should never happen with valid inner).
    #[error("envelope_hash is zero (fail-closed)")]
    ZeroEnvelopeHash,

    /// Capability manifest hash is zero.
    #[error("capability_manifest_hash is zero (fail-closed)")]
    ZeroCapabilityManifestHash,

    /// Permeability receipt hash is required for delegated episodes.
    #[error("permeability_receipt_hash is required for delegated episodes")]
    MissingPermeabilityReceiptHash,

    /// Permeability receipt hash is zero.
    #[error("permeability_receipt_hash is zero (fail-closed)")]
    ZeroPermeabilityReceiptHash,

    /// Binding mismatch during replay verification.
    #[error("{field} does not match envelope")]
    BindingMismatch {
        /// The field that mismatched.
        field: &'static str,
    },

    /// Permeability consumption binding validation failed.
    ///
    /// The delegated spawn's permeability receipt did not pass full
    /// consumption binding verification (admission, hash match, or
    /// authority subset check). Fail-closed per REQ-0027.
    #[error("permeability consumption binding failure: {0}")]
    PermeabilityBindingFailure(apm2_core::policy::permeability::PermeabilityError),

    /// Delegated spawn attempted through the legacy gate without full
    /// consumption binding verification.
    ///
    /// All delegated spawn authorization MUST use
    /// [`validate_delegated_spawn_gate`] which enforces receipt
    /// consumption binding. The legacy [`validate_spawn_gate`] does not
    /// provide sufficient security for delegated mode. Fail-closed.
    #[error("delegated spawn requires consumption binding; use validate_delegated_spawn_gate")]
    DelegatedRequiresConsumptionBinding,

    /// Policy root hash could not be derived from the envelope's pinned
    /// snapshot because `policy_hash` is absent, not 32 bytes, or all
    /// zeros. Fail-closed: a synthetic fallback would make the compared
    /// root caller-controlled, defeating provenance verification.
    #[error(
        "policy root derivation failed: envelope lacks valid non-zero policy_hash in pinned snapshot"
    )]
    MissingPolicyRootDerivation,
}

/// Builder for [`EpisodeEnvelopeV1`].
///
/// Follows the same pattern as [`EpisodeEnvelopeBuilder`] but adds
/// V1-specific fields.
#[derive(Debug, Clone, Default)]
pub struct EpisodeEnvelopeV1Builder {
    /// Inner envelope builder.
    inner: EpisodeEnvelopeBuilder,
    /// View commitment hash.
    view_commitment_hash: [u8; 32],
    /// Freshness pinset hash.
    freshness_pinset_hash: [u8; 32],
    /// Permeability receipt hash (for delegated episodes).
    permeability_receipt_hash: Option<[u8; 32]>,
}

impl EpisodeEnvelopeV1Builder {
    /// Creates a new V1 builder.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            inner: EpisodeEnvelopeBuilder::new(),
            view_commitment_hash: [0u8; 32],
            freshness_pinset_hash: [0u8; 32],
            permeability_receipt_hash: None,
        }
    }

    /// Sets the episode ID (required).
    #[must_use]
    pub fn episode_id(mut self, id: impl Into<String>) -> Self {
        self.inner = self.inner.episode_id(id);
        self
    }

    /// Sets the actor ID (required).
    #[must_use]
    pub fn actor_id(mut self, id: impl Into<String>) -> Self {
        self.inner = self.inner.actor_id(id);
        self
    }

    /// Sets the work ID (optional).
    #[must_use]
    pub fn work_id(mut self, id: impl Into<String>) -> Self {
        self.inner = self.inner.work_id(id);
        self
    }

    /// Sets the lease ID (required).
    #[must_use]
    pub fn lease_id(mut self, id: impl Into<String>) -> Self {
        self.inner = self.inner.lease_id(id);
        self
    }

    /// Sets the budget.
    #[must_use]
    pub fn budget(mut self, budget: EpisodeBudget) -> Self {
        self.inner = self.inner.budget(budget);
        self
    }

    /// Sets the stop conditions.
    #[must_use]
    pub fn stop_conditions(mut self, conditions: StopConditions) -> Self {
        self.inner = self.inner.stop_conditions(conditions);
        self
    }

    /// Sets the pinned snapshot.
    #[must_use]
    pub fn pinned_snapshot(mut self, snapshot: PinnedSnapshot) -> Self {
        self.inner = self.inner.pinned_snapshot(snapshot);
        self
    }

    /// Sets the capability manifest hash.
    #[must_use]
    pub fn capability_manifest_hash(mut self, hash: [u8; 32]) -> Self {
        self.inner = self.inner.capability_manifest_hash(hash);
        self
    }

    /// Sets the risk tier.
    #[must_use]
    pub fn risk_tier(mut self, tier: RiskTier) -> Self {
        self.inner = self.inner.risk_tier(tier);
        self
    }

    /// Sets the determinism class.
    #[must_use]
    pub fn determinism_class(mut self, class: DeterminismClass) -> Self {
        self.inner = self.inner.determinism_class(class);
        self
    }

    /// Sets the context refs.
    #[must_use]
    pub fn context_refs(mut self, refs: ContextRefs) -> Self {
        self.inner = self.inner.context_refs(refs);
        self
    }

    /// Sets the view commitment hash (required).
    #[must_use]
    pub const fn view_commitment_hash(mut self, hash: [u8; 32]) -> Self {
        self.view_commitment_hash = hash;
        self
    }

    /// Sets the freshness pinset hash (required).
    #[must_use]
    pub const fn freshness_pinset_hash(mut self, hash: [u8; 32]) -> Self {
        self.freshness_pinset_hash = hash;
        self
    }

    /// Sets the permeability receipt hash (required for delegated episodes).
    #[must_use]
    pub const fn permeability_receipt_hash(mut self, hash: [u8; 32]) -> Self {
        self.permeability_receipt_hash = Some(hash);
        self
    }

    /// Builds the V1 envelope, validating all required fields.
    ///
    /// # Fail-closed
    ///
    /// In addition to base envelope validation, this checks that:
    /// - `view_commitment_hash` is non-zero
    /// - `freshness_pinset_hash` is non-zero
    ///
    /// # Errors
    ///
    /// Returns [`EnvelopeV1Error`] if any required field is missing or
    /// invalid.
    pub fn build(self) -> Result<EpisodeEnvelopeV1, EnvelopeV1Error> {
        let inner = self.inner.build()?;

        // Fail-closed: view_commitment_hash must be non-zero
        if self.view_commitment_hash == [0u8; 32] {
            return Err(EnvelopeV1Error::ZeroViewCommitmentHash);
        }

        // Fail-closed: freshness_pinset_hash must be non-zero
        if self.freshness_pinset_hash == [0u8; 32] {
            return Err(EnvelopeV1Error::ZeroFreshnessPinsetHash);
        }

        // Fail-closed: permeability_receipt_hash, if present, must be non-zero
        if let Some(ref hash) = self.permeability_receipt_hash {
            if *hash == [0u8; 32] {
                return Err(EnvelopeV1Error::ZeroPermeabilityReceiptHash);
            }
        }

        Ok(EpisodeEnvelopeV1 {
            inner,
            view_commitment_hash: self.view_commitment_hash,
            freshness_pinset_hash: self.freshness_pinset_hash,
            permeability_receipt_hash: self.permeability_receipt_hash,
        })
    }
}

/// Validates envelope bindings at the spawn/resume gate for
/// **non-delegated** episodes only.
///
/// This is the top-level enforcement point for standard (non-delegated)
/// spawns. Callers MUST invoke this before allowing a spawn or resume to
/// proceed.
///
/// # Delegated episodes
///
/// Delegated spawn authorization **must** use
/// [`validate_delegated_spawn_gate`] instead, which enforces full
/// consumption binding verification. Passing `is_delegated = true` to
/// this function is a programming error and will return
/// [`EnvelopeV1Error::DelegatedRequiresConsumptionBinding`].
///
/// # Fail-closed
///
/// Returns an error if:
/// - `is_delegated` is `true` (must use [`validate_delegated_spawn_gate`])
/// - The envelope is `None` (absent)
/// - The envelope fails validation
///
/// # Arguments
///
/// * `envelope` - The V1 envelope, or `None` if absent
/// * `is_delegated` - Whether this is a delegated episode
///
/// # Errors
///
/// Returns [`EnvelopeV1Error`] if the gate check fails.
pub fn validate_spawn_gate(
    envelope: Option<&EpisodeEnvelopeV1>,
    is_delegated: bool,
) -> Result<&EpisodeEnvelopeV1, EnvelopeV1Error> {
    // Delegated spawns MUST go through validate_delegated_spawn_gate which
    // enforces full consumption binding. Reject the legacy path outright.
    if is_delegated {
        return Err(EnvelopeV1Error::DelegatedRequiresConsumptionBinding);
    }

    let env = envelope.ok_or(EnvelopeV1Error::ZeroEnvelopeHash)?;
    env.validate_for_spawn()?;
    Ok(env)
}

/// Production-grade delegated spawn gate with full consumption binding
/// verification.
///
/// This is the **only** valid entry-point for delegated spawn
/// authorization. [`validate_spawn_gate`] rejects `is_delegated = true`
/// outright, so all delegated paths must come through here. It performs
/// structural envelope validation **plus** full
/// [`validate_consumption_binding`](apm2_core::policy::permeability::validate_consumption_binding)
/// verification of the permeability receipt.
///
/// # Fail-closed
///
/// Returns an error if:
/// - The envelope is `None` (absent)
/// - The envelope fails structural validation
/// - `permeability_receipt_hash` is missing or zero
/// - Receipt admission fails (expired, revoked, invalid issuance time, etc.)
/// - Receipt hash does not match the envelope's `permeability_receipt_hash`
/// - `required_authority` is not a subset of the receipt's delegated authority
///
/// # Arguments
///
/// * `envelope` - The V1 envelope, or `None` if absent
/// * `receipt` - The permeability receipt to validate against
/// * `required_authority` - Minimum authority needed for this spawn
/// * `now_ms` - Current time in milliseconds since epoch
///
/// # Errors
///
/// Returns [`EnvelopeV1Error`] if any gate check fails.
pub fn validate_delegated_spawn_gate<'a>(
    envelope: Option<&'a EpisodeEnvelopeV1>,
    receipt: &apm2_core::policy::permeability::PermeabilityReceipt,
    required_authority: &apm2_core::policy::permeability::AuthorityVector,
    now_ms: u64,
) -> Result<&'a EpisodeEnvelopeV1, EnvelopeV1Error> {
    let env = envelope.ok_or(EnvelopeV1Error::ZeroEnvelopeHash)?;
    env.validate_for_delegated_spawn_with_receipt(receipt, required_authority, now_ms)?;
    Ok(env)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Creates a minimal valid envelope with all required fields per
    /// AD-EPISODE-001.
    fn minimal_envelope() -> EpisodeEnvelope {
        EpisodeEnvelope::builder()
            .episode_id("ep-001")
            .actor_id("agent-007")
            .lease_id("lease-123")
            .capability_manifest_hash([0xab; 32])
            .budget(EpisodeBudget::default())
            .stop_conditions(StopConditions::max_episodes(100))
            .pinned_snapshot(PinnedSnapshot::empty())
            .build()
            .expect("valid envelope")
    }

    #[test]
    fn test_envelope_builder_minimal() {
        let envelope = minimal_envelope();

        assert_eq!(envelope.episode_id(), "ep-001");
        assert_eq!(envelope.actor_id(), "agent-007");
        assert_eq!(envelope.lease_id(), "lease-123");
        assert!(envelope.work_id().is_none());
        assert_eq!(envelope.capability_manifest_hash(), &[0xab; 32]);
        assert_eq!(envelope.risk_tier(), RiskTier::Tier0);
        assert_eq!(
            envelope.determinism_class(),
            DeterminismClass::NonDeterministic
        );
    }

    #[test]
    fn test_envelope_builder_full() {
        let envelope = EpisodeEnvelope::builder()
            .episode_id("ep-001")
            .actor_id("agent-007")
            .work_id("work-456")
            .lease_id("lease-123")
            .budget(EpisodeBudget::builder().tokens(50_000).build())
            .stop_conditions(StopConditions::max_episodes(100))
            .pinned_snapshot(PinnedSnapshot::builder().repo_hash([0xcd; 32]).build())
            .capability_manifest_hash([0xab; 32])
            .risk_tier(RiskTier::Tier2)
            .determinism_class(DeterminismClass::SoftDeterministic)
            .context_refs(ContextRefs {
                context_pack_hash: vec![0xef; 32],
                dcp_refs: vec!["dcp-1".to_string()],
            })
            .build()
            .expect("valid envelope");

        assert_eq!(envelope.episode_id(), "ep-001");
        assert_eq!(envelope.work_id(), Some("work-456"));
        assert_eq!(envelope.budget().tokens(), 50_000);
        assert!(envelope.stop_conditions().has_max_episodes());
        assert!(envelope.pinned_snapshot().has_repo_hash());
        assert_eq!(envelope.risk_tier(), RiskTier::Tier2);
        assert_eq!(
            envelope.determinism_class(),
            DeterminismClass::SoftDeterministic
        );
        assert!(envelope.context_refs().is_some());
    }

    #[test]
    fn test_envelope_builder_adapter_and_role_spec_hash_roundtrip() {
        let envelope = EpisodeEnvelope::builder()
            .episode_id("ep-attr-001")
            .actor_id("agent-attr")
            .lease_id("lease-attr")
            .capability_manifest_hash([0xab; 32])
            .adapter_profile_hash([0x11; 32])
            .role_spec_hash([0x22; 32])
            .budget(EpisodeBudget::default())
            .stop_conditions(StopConditions::max_episodes(100))
            .pinned_snapshot(PinnedSnapshot::empty())
            .build()
            .expect("valid envelope with attribution hashes");

        let decoded =
            EpisodeEnvelope::decode(&envelope.canonical_bytes()).expect("decode should succeed");
        assert_eq!(decoded.adapter_profile_hash(), Some(&[0x11; 32]));
        assert_eq!(decoded.role_spec_hash(), Some(&[0x22; 32]));
    }

    #[test]
    fn test_envelope_missing_episode_id() {
        let result = EpisodeEnvelope::builder()
            .actor_id("agent")
            .lease_id("lease")
            .capability_manifest_hash([0xab; 32])
            .build();

        assert!(matches!(result, Err(EnvelopeError::MissingEpisodeId)));
    }

    #[test]
    fn test_envelope_missing_actor_id() {
        let result = EpisodeEnvelope::builder()
            .episode_id("ep")
            .lease_id("lease")
            .capability_manifest_hash([0xab; 32])
            .build();

        assert!(matches!(result, Err(EnvelopeError::MissingActorId)));
    }

    #[test]
    fn test_envelope_missing_lease_id() {
        let result = EpisodeEnvelope::builder()
            .episode_id("ep")
            .actor_id("actor")
            .capability_manifest_hash([0xab; 32])
            .build();

        assert!(matches!(result, Err(EnvelopeError::MissingLeaseId)));
    }

    #[test]
    fn test_envelope_missing_capability_hash() {
        let result = EpisodeEnvelope::builder()
            .episode_id("ep")
            .actor_id("actor")
            .lease_id("lease")
            .budget(EpisodeBudget::default())
            .stop_conditions(StopConditions::max_episodes(100))
            .pinned_snapshot(PinnedSnapshot::empty())
            .build();

        assert!(matches!(
            result,
            Err(EnvelopeError::MissingCapabilityManifestHash)
        ));
    }

    #[test]
    fn test_envelope_missing_budget() {
        let result = EpisodeEnvelope::builder()
            .episode_id("ep")
            .actor_id("actor")
            .lease_id("lease")
            .capability_manifest_hash([0xab; 32])
            .stop_conditions(StopConditions::max_episodes(100))
            .pinned_snapshot(PinnedSnapshot::empty())
            .build();

        assert!(matches!(result, Err(EnvelopeError::MissingBudget)));
    }

    #[test]
    fn test_envelope_missing_stop_conditions() {
        let result = EpisodeEnvelope::builder()
            .episode_id("ep")
            .actor_id("actor")
            .lease_id("lease")
            .capability_manifest_hash([0xab; 32])
            .budget(EpisodeBudget::default())
            .pinned_snapshot(PinnedSnapshot::empty())
            .build();

        assert!(matches!(result, Err(EnvelopeError::MissingStopConditions)));
    }

    #[test]
    fn test_envelope_missing_pinned_snapshot() {
        let result = EpisodeEnvelope::builder()
            .episode_id("ep")
            .actor_id("actor")
            .lease_id("lease")
            .capability_manifest_hash([0xab; 32])
            .budget(EpisodeBudget::default())
            .stop_conditions(StopConditions::max_episodes(100))
            .build();

        assert!(matches!(result, Err(EnvelopeError::MissingPinnedSnapshot)));
    }

    #[test]
    fn test_envelope_invalid_capability_hash_size() {
        let result = EpisodeEnvelope::builder()
            .episode_id("ep")
            .actor_id("actor")
            .lease_id("lease")
            .capability_manifest_hash_from_slice(&[0xab; 16]) // Wrong size
            .budget(EpisodeBudget::default())
            .stop_conditions(StopConditions::max_episodes(100))
            .pinned_snapshot(PinnedSnapshot::empty())
            .build();

        assert!(matches!(
            result,
            Err(EnvelopeError::InvalidCapabilityManifestHashSize)
        ));
    }

    #[test]
    fn test_envelope_id_too_long() {
        let long_id = "x".repeat(MAX_ID_LENGTH + 1);

        let result = EpisodeEnvelope::builder()
            .episode_id(&long_id)
            .actor_id("actor")
            .lease_id("lease")
            .capability_manifest_hash([0xab; 32])
            .budget(EpisodeBudget::default())
            .stop_conditions(StopConditions::max_episodes(100))
            .pinned_snapshot(PinnedSnapshot::empty())
            .build();

        assert!(matches!(
            result,
            Err(EnvelopeError::IdTooLong {
                field: "episode_id",
                ..
            })
        ));
    }

    #[test]
    fn test_envelope_too_many_dcp_refs() {
        let dcp_refs: Vec<String> = (0..=MAX_DCP_REFS).map(|i| format!("dcp-{i}")).collect();

        let result = EpisodeEnvelope::builder()
            .episode_id("ep")
            .actor_id("actor")
            .lease_id("lease")
            .capability_manifest_hash([0xab; 32])
            .budget(EpisodeBudget::default())
            .stop_conditions(StopConditions::max_episodes(100))
            .pinned_snapshot(PinnedSnapshot::empty())
            .context_refs(ContextRefs {
                context_pack_hash: vec![],
                dcp_refs,
            })
            .build();

        assert!(matches!(result, Err(EnvelopeError::TooManyDcpRefs { .. })));
    }

    #[test]
    fn test_envelope_canonical_bytes_deterministic() {
        let envelope = minimal_envelope();

        let bytes1 = envelope.canonical_bytes();
        let bytes2 = envelope.canonical_bytes();
        let bytes3 = envelope.canonical_bytes();

        assert_eq!(bytes1, bytes2);
        assert_eq!(bytes2, bytes3);
    }

    #[test]
    fn test_envelope_canonical_bytes_sorts_dcp_refs() {
        let envelope1 = EpisodeEnvelope::builder()
            .episode_id("ep")
            .actor_id("actor")
            .lease_id("lease")
            .capability_manifest_hash([0xab; 32])
            .budget(EpisodeBudget::default())
            .stop_conditions(StopConditions::max_episodes(100))
            .pinned_snapshot(PinnedSnapshot::empty())
            .context_refs(ContextRefs {
                context_pack_hash: vec![],
                dcp_refs: vec!["z".to_string(), "a".to_string(), "m".to_string()],
            })
            .build()
            .expect("valid");

        let envelope2 = EpisodeEnvelope::builder()
            .episode_id("ep")
            .actor_id("actor")
            .lease_id("lease")
            .capability_manifest_hash([0xab; 32])
            .budget(EpisodeBudget::default())
            .stop_conditions(StopConditions::max_episodes(100))
            .pinned_snapshot(PinnedSnapshot::empty())
            .context_refs(ContextRefs {
                context_pack_hash: vec![],
                dcp_refs: vec!["a".to_string(), "m".to_string(), "z".to_string()],
            })
            .build()
            .expect("valid");

        // Different insertion order should produce same canonical bytes
        assert_eq!(envelope1.canonical_bytes(), envelope2.canonical_bytes());
    }

    #[test]
    fn test_envelope_digest_stable() {
        let envelope = minimal_envelope();

        let digest1 = envelope.digest();
        let digest2 = envelope.digest();

        assert_eq!(digest1, digest2);
        assert_eq!(digest1.len(), 32);
    }

    #[test]
    fn test_envelope_digest_hex() {
        let envelope = minimal_envelope();

        let hex = envelope.digest_hex();
        assert_eq!(hex.len(), 64); // 32 bytes = 64 hex chars
    }

    #[test]
    fn test_envelope_different_values_different_digests() {
        let envelope1 = minimal_envelope();

        let envelope2 = EpisodeEnvelope::builder()
            .episode_id("ep-002") // Different ID
            .actor_id("agent-007")
            .lease_id("lease-123")
            .capability_manifest_hash([0xab; 32])
            .budget(EpisodeBudget::default())
            .stop_conditions(StopConditions::max_episodes(100))
            .pinned_snapshot(PinnedSnapshot::empty())
            .build()
            .expect("valid");

        assert_ne!(envelope1.digest(), envelope2.digest());
    }

    #[test]
    fn test_envelope_roundtrip() {
        let original = EpisodeEnvelope::builder()
            .episode_id("ep-001")
            .actor_id("agent-007")
            .work_id("work-456")
            .lease_id("lease-123")
            .budget(EpisodeBudget::builder().tokens(50_000).build())
            .stop_conditions(StopConditions::max_episodes(100))
            .pinned_snapshot(PinnedSnapshot::builder().repo_hash([0xcd; 32]).build())
            .capability_manifest_hash([0xab; 32])
            .risk_tier(RiskTier::Tier2)
            .determinism_class(DeterminismClass::SoftDeterministic)
            .build()
            .expect("valid");

        let bytes = original.canonical_bytes();
        let decoded = EpisodeEnvelope::decode(&bytes).expect("decode failed");

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_risk_tier_properties() {
        assert!(!RiskTier::Tier0.requires_sandbox());
        assert!(!RiskTier::Tier1.requires_sandbox());
        assert!(!RiskTier::Tier2.requires_sandbox());
        assert!(RiskTier::Tier3.requires_sandbox());
        assert!(RiskTier::Tier4.requires_sandbox());

        assert!(!RiskTier::Tier0.requires_enhanced_evidence());
        assert!(!RiskTier::Tier1.requires_enhanced_evidence());
        assert!(RiskTier::Tier2.requires_enhanced_evidence());
        assert!(RiskTier::Tier3.requires_enhanced_evidence());
        assert!(RiskTier::Tier4.requires_enhanced_evidence());
    }

    #[test]
    fn test_risk_tier_from_u8() {
        assert_eq!(RiskTier::from_u8(0), Some(RiskTier::Tier0));
        assert_eq!(RiskTier::from_u8(1), Some(RiskTier::Tier1));
        assert_eq!(RiskTier::from_u8(2), Some(RiskTier::Tier2));
        assert_eq!(RiskTier::from_u8(3), Some(RiskTier::Tier3));
        assert_eq!(RiskTier::from_u8(4), Some(RiskTier::Tier4));
        assert_eq!(RiskTier::from_u8(5), None);
    }

    #[test]
    fn test_determinism_class_properties() {
        assert!(!DeterminismClass::NonDeterministic.requires_replay_verification());
        assert!(!DeterminismClass::SoftDeterministic.requires_replay_verification());
        assert!(DeterminismClass::FullyDeterministic.requires_replay_verification());
    }

    #[test]
    fn test_determinism_class_from_u8() {
        assert_eq!(
            DeterminismClass::from_u8(0),
            Some(DeterminismClass::NonDeterministic)
        );
        assert_eq!(
            DeterminismClass::from_u8(1),
            Some(DeterminismClass::SoftDeterministic)
        );
        assert_eq!(
            DeterminismClass::from_u8(2),
            Some(DeterminismClass::FullyDeterministic)
        );
        assert_eq!(DeterminismClass::from_u8(3), None);
    }

    #[test]
    fn test_stop_conditions() {
        let cond = StopConditions::max_episodes(100);
        assert!(cond.has_max_episodes());
        assert_eq!(cond.max_episodes, 100);
    }

    #[test]
    fn test_context_refs_empty() {
        let refs = ContextRefs::empty();
        assert!(refs.is_empty());
    }

    #[test]
    fn test_context_refs_canonical_bytes_sorts() {
        let refs1 = ContextRefs {
            context_pack_hash: vec![],
            dcp_refs: vec!["z".to_string(), "a".to_string()],
        };

        let refs2 = ContextRefs {
            context_pack_hash: vec![],
            dcp_refs: vec!["a".to_string(), "z".to_string()],
        };

        assert_eq!(refs1.canonical_bytes(), refs2.canonical_bytes());
    }

    #[test]
    fn test_envelope_serialize_deserialize() {
        let envelope = minimal_envelope();

        let json = serde_json::to_string(&envelope).expect("serialize failed");
        let decoded: EpisodeEnvelope = serde_json::from_str(&json).expect("deserialize failed");

        assert_eq!(envelope.episode_id(), decoded.episode_id());
        assert_eq!(envelope.actor_id(), decoded.actor_id());
    }

    // ========================================================================
    // Security Tests - Fail-Closed Decoding
    // ========================================================================

    /// Tests that `decode()` rejects invalid `risk_tier` values (fail-closed).
    ///
    /// SECURITY: Attackers must not be able to bypass sandbox requirements
    /// by providing out-of-range tier values that default to `Tier0`.
    #[test]
    fn test_decode_rejects_invalid_risk_tier() {
        // Craft a protobuf message with an invalid risk_tier value
        use prost::Message;

        #[derive(Clone, PartialEq, Message)]
        struct CraftedBudget {
            #[prost(uint64, optional, tag = "1")]
            tokens: Option<u64>,
        }

        #[derive(Clone, PartialEq, Message)]
        struct CraftedStopConditions {
            #[prost(uint64, optional, tag = "1")]
            max_episodes: Option<u64>,
        }

        #[derive(Clone, PartialEq, Message)]
        struct CraftedSnapshot {}

        #[derive(Clone, PartialEq, Message)]
        struct CraftedEnvelope {
            #[prost(string, tag = "1")]
            episode_id: String,
            #[prost(string, tag = "2")]
            actor_id: String,
            #[prost(string, tag = "4")]
            lease_id: String,
            #[prost(message, optional, tag = "5")]
            budget: Option<CraftedBudget>,
            #[prost(message, optional, tag = "6")]
            stop_conditions: Option<CraftedStopConditions>,
            #[prost(message, optional, tag = "7")]
            pinned_snapshot: Option<CraftedSnapshot>,
            #[prost(bytes = "vec", tag = "8")]
            capability_manifest_hash: Vec<u8>,
            #[prost(uint32, optional, tag = "9")]
            risk_tier: Option<u32>,
        }

        let crafted = CraftedEnvelope {
            episode_id: "ep-001".to_string(),
            actor_id: "agent-007".to_string(),
            lease_id: "lease-123".to_string(),
            budget: Some(CraftedBudget { tokens: Some(0) }),
            stop_conditions: Some(CraftedStopConditions {
                max_episodes: Some(0),
            }),
            pinned_snapshot: Some(CraftedSnapshot {}),
            capability_manifest_hash: vec![0xab; 32],
            risk_tier: Some(99), // Invalid - must fail
        };

        let crafted_bytes = crafted.encode_to_vec();
        let result = EpisodeEnvelope::decode(&crafted_bytes);

        assert!(
            matches!(result, Err(EnvelopeError::InvalidRiskTier { value: 99 })),
            "decode() must reject invalid risk_tier values, got: {result:?}"
        );
    }

    /// Tests that `decode()` rejects invalid `determinism_class` values
    /// (fail-closed).
    #[test]
    fn test_decode_rejects_invalid_determinism_class() {
        use prost::Message;

        #[derive(Clone, PartialEq, Message)]
        struct CraftedBudget {
            #[prost(uint64, optional, tag = "1")]
            tokens: Option<u64>,
        }

        #[derive(Clone, PartialEq, Message)]
        struct CraftedStopConditions {
            #[prost(uint64, optional, tag = "1")]
            max_episodes: Option<u64>,
        }

        #[derive(Clone, PartialEq, Message)]
        struct CraftedSnapshot {}

        #[derive(Clone, PartialEq, Message)]
        struct CraftedEnvelope {
            #[prost(string, tag = "1")]
            episode_id: String,
            #[prost(string, tag = "2")]
            actor_id: String,
            #[prost(string, tag = "4")]
            lease_id: String,
            #[prost(message, optional, tag = "5")]
            budget: Option<CraftedBudget>,
            #[prost(message, optional, tag = "6")]
            stop_conditions: Option<CraftedStopConditions>,
            #[prost(message, optional, tag = "7")]
            pinned_snapshot: Option<CraftedSnapshot>,
            #[prost(bytes = "vec", tag = "8")]
            capability_manifest_hash: Vec<u8>,
            #[prost(uint32, optional, tag = "10")]
            determinism_class: Option<u32>,
        }

        let crafted = CraftedEnvelope {
            episode_id: "ep-001".to_string(),
            actor_id: "agent-007".to_string(),
            lease_id: "lease-123".to_string(),
            budget: Some(CraftedBudget { tokens: Some(0) }),
            stop_conditions: Some(CraftedStopConditions {
                max_episodes: Some(0),
            }),
            pinned_snapshot: Some(CraftedSnapshot {}),
            capability_manifest_hash: vec![0xab; 32],
            determinism_class: Some(99), // Invalid - must fail
        };

        let crafted_bytes = crafted.encode_to_vec();
        let result = EpisodeEnvelope::decode(&crafted_bytes);

        assert!(
            matches!(
                result,
                Err(EnvelopeError::InvalidDeterminismClass { value: 99 })
            ),
            "decode() must reject invalid determinism_class values, got: {result:?}"
        );
    }

    /// Tests that `decode()` enforces `MAX_ID_LENGTH` validation.
    ///
    /// SECURITY: Prevents memory exhaustion via oversized ID fields.
    #[test]
    fn test_decode_rejects_oversized_episode_id() {
        use prost::Message;

        #[derive(Clone, PartialEq, Message)]
        struct CraftedBudget {
            #[prost(uint64, optional, tag = "1")]
            tokens: Option<u64>,
        }

        #[derive(Clone, PartialEq, Message)]
        struct CraftedStopConditions {
            #[prost(uint64, optional, tag = "1")]
            max_episodes: Option<u64>,
        }

        #[derive(Clone, PartialEq, Message)]
        struct CraftedSnapshot {}

        #[derive(Clone, PartialEq, Message)]
        struct CraftedEnvelope {
            #[prost(string, tag = "1")]
            episode_id: String,
            #[prost(string, tag = "2")]
            actor_id: String,
            #[prost(string, tag = "4")]
            lease_id: String,
            #[prost(message, optional, tag = "5")]
            budget: Option<CraftedBudget>,
            #[prost(message, optional, tag = "6")]
            stop_conditions: Option<CraftedStopConditions>,
            #[prost(message, optional, tag = "7")]
            pinned_snapshot: Option<CraftedSnapshot>,
            #[prost(bytes = "vec", tag = "8")]
            capability_manifest_hash: Vec<u8>,
        }

        let crafted = CraftedEnvelope {
            episode_id: "x".repeat(MAX_ID_LENGTH + 1), // Too long
            actor_id: "agent".to_string(),
            lease_id: "lease".to_string(),
            budget: Some(CraftedBudget { tokens: Some(0) }),
            stop_conditions: Some(CraftedStopConditions {
                max_episodes: Some(0),
            }),
            pinned_snapshot: Some(CraftedSnapshot {}),
            capability_manifest_hash: vec![0xab; 32],
        };

        let crafted_bytes = crafted.encode_to_vec();
        let result = EpisodeEnvelope::decode(&crafted_bytes);

        assert!(
            matches!(
                result,
                Err(EnvelopeError::IdTooLong {
                    field: "episode_id",
                    ..
                })
            ),
            "decode() must reject oversized episode_id, got: {result:?}"
        );
    }

    /// Tests that `decode()` enforces `MAX_DCP_REFS` validation.
    ///
    /// SECURITY: Prevents memory exhaustion via excessive DCP refs.
    #[test]
    fn test_decode_rejects_too_many_dcp_refs() {
        use prost::Message;

        #[derive(Clone, PartialEq, Message)]
        struct CraftedBudget {
            #[prost(uint64, optional, tag = "1")]
            tokens: Option<u64>,
        }

        #[derive(Clone, PartialEq, Message)]
        struct CraftedStopConditions {
            #[prost(uint64, optional, tag = "1")]
            max_episodes: Option<u64>,
        }

        #[derive(Clone, PartialEq, Message)]
        struct CraftedSnapshot {}

        #[derive(Clone, PartialEq, Message)]
        struct CraftedContextRefs {
            #[prost(bytes = "vec", tag = "1")]
            context_pack_hash: Vec<u8>,
            #[prost(string, repeated, tag = "2")]
            dcp_refs: Vec<String>,
        }

        #[derive(Clone, PartialEq, Message)]
        struct CraftedEnvelope {
            #[prost(string, tag = "1")]
            episode_id: String,
            #[prost(string, tag = "2")]
            actor_id: String,
            #[prost(string, tag = "4")]
            lease_id: String,
            #[prost(message, optional, tag = "5")]
            budget: Option<CraftedBudget>,
            #[prost(message, optional, tag = "6")]
            stop_conditions: Option<CraftedStopConditions>,
            #[prost(message, optional, tag = "7")]
            pinned_snapshot: Option<CraftedSnapshot>,
            #[prost(bytes = "vec", tag = "8")]
            capability_manifest_hash: Vec<u8>,
            #[prost(message, optional, tag = "11")]
            context_refs: Option<CraftedContextRefs>,
        }

        let dcp_refs: Vec<String> = (0..=MAX_DCP_REFS).map(|i| format!("dcp-{i}")).collect();

        let crafted = CraftedEnvelope {
            episode_id: "ep-001".to_string(),
            actor_id: "agent".to_string(),
            lease_id: "lease".to_string(),
            budget: Some(CraftedBudget { tokens: Some(0) }),
            stop_conditions: Some(CraftedStopConditions {
                max_episodes: Some(0),
            }),
            pinned_snapshot: Some(CraftedSnapshot {}),
            capability_manifest_hash: vec![0xab; 32],
            context_refs: Some(CraftedContextRefs {
                context_pack_hash: vec![],
                dcp_refs,
            }),
        };

        let crafted_bytes = crafted.encode_to_vec();
        let result = EpisodeEnvelope::decode(&crafted_bytes);

        assert!(
            matches!(result, Err(EnvelopeError::TooManyDcpRefs { .. })),
            "decode() must reject excessive DCP refs, got: {result:?}"
        );
    }

    /// Tests that `decode()` rejects truncated hash in `PinnedSnapshot`
    /// (fail-closed).
    ///
    /// SECURITY: Attackers must not be able to omit reproducibility anchors
    /// by providing truncated hash values that get silently ignored.
    #[test]
    fn test_decode_rejects_invalid_snapshot_hash_length() {
        use prost::Message;

        #[derive(Clone, PartialEq, Message)]
        struct CraftedBudget {
            #[prost(uint64, optional, tag = "1")]
            tokens: Option<u64>,
        }

        #[derive(Clone, PartialEq, Message)]
        struct CraftedStopConditions {
            #[prost(uint64, optional, tag = "1")]
            max_episodes: Option<u64>,
        }

        #[derive(Clone, PartialEq, Message)]
        struct CraftedSnapshot {
            #[prost(bytes = "vec", tag = "1")]
            repo_hash: Vec<u8>,
        }

        #[derive(Clone, PartialEq, Message)]
        struct CraftedEnvelope {
            #[prost(string, tag = "1")]
            episode_id: String,
            #[prost(string, tag = "2")]
            actor_id: String,
            #[prost(string, tag = "4")]
            lease_id: String,
            #[prost(message, optional, tag = "5")]
            budget: Option<CraftedBudget>,
            #[prost(message, optional, tag = "6")]
            stop_conditions: Option<CraftedStopConditions>,
            #[prost(message, optional, tag = "7")]
            pinned_snapshot: Option<CraftedSnapshot>,
            #[prost(bytes = "vec", tag = "8")]
            capability_manifest_hash: Vec<u8>,
        }

        // Test with truncated hash (16 bytes instead of 32)
        let crafted = CraftedEnvelope {
            episode_id: "ep-001".to_string(),
            actor_id: "agent".to_string(),
            lease_id: "lease".to_string(),
            budget: Some(CraftedBudget { tokens: Some(0) }),
            stop_conditions: Some(CraftedStopConditions {
                max_episodes: Some(0),
            }),
            pinned_snapshot: Some(CraftedSnapshot {
                repo_hash: vec![0xab; 16], // Truncated - must fail
            }),
            capability_manifest_hash: vec![0xab; 32],
        };

        let crafted_bytes = crafted.encode_to_vec();
        let result = EpisodeEnvelope::decode(&crafted_bytes);

        assert!(
            matches!(
                result,
                Err(EnvelopeError::InvalidHashLength {
                    field: "repo_hash",
                    expected: 32,
                    actual: 16,
                })
            ),
            "decode() must reject truncated snapshot hashes, got: {result:?}"
        );
    }

    /// Tests that `decode()` rejects missing required fields.
    #[test]
    fn test_decode_rejects_missing_episode_id() {
        use prost::Message;

        #[derive(Clone, PartialEq, Message)]
        struct CraftedEnvelope {
            #[prost(string, tag = "2")]
            actor_id: String,
            #[prost(string, tag = "4")]
            lease_id: String,
            #[prost(bytes = "vec", tag = "8")]
            capability_manifest_hash: Vec<u8>,
        }

        let crafted = CraftedEnvelope {
            actor_id: "agent".to_string(),
            lease_id: "lease".to_string(),
            capability_manifest_hash: vec![0xab; 32],
        };

        let crafted_bytes = crafted.encode_to_vec();
        let result = EpisodeEnvelope::decode(&crafted_bytes);

        assert!(
            matches!(result, Err(EnvelopeError::MissingEpisodeId)),
            "decode() must reject missing episode_id, got: {result:?}"
        );
    }

    /// Tests that `decode()` rejects invalid `capability_manifest_hash` size.
    #[test]
    fn test_decode_rejects_invalid_capability_hash_size() {
        use prost::Message;

        #[derive(Clone, PartialEq, Message)]
        struct CraftedBudget {
            #[prost(uint64, optional, tag = "1")]
            tokens: Option<u64>,
        }

        #[derive(Clone, PartialEq, Message)]
        struct CraftedStopConditions {
            #[prost(uint64, optional, tag = "1")]
            max_episodes: Option<u64>,
        }

        #[derive(Clone, PartialEq, Message)]
        struct CraftedSnapshot {}

        #[derive(Clone, PartialEq, Message)]
        struct CraftedEnvelope {
            #[prost(string, tag = "1")]
            episode_id: String,
            #[prost(string, tag = "2")]
            actor_id: String,
            #[prost(string, tag = "4")]
            lease_id: String,
            #[prost(message, optional, tag = "5")]
            budget: Option<CraftedBudget>,
            #[prost(message, optional, tag = "6")]
            stop_conditions: Option<CraftedStopConditions>,
            #[prost(message, optional, tag = "7")]
            pinned_snapshot: Option<CraftedSnapshot>,
            #[prost(bytes = "vec", tag = "8")]
            capability_manifest_hash: Vec<u8>,
        }

        let crafted = CraftedEnvelope {
            episode_id: "ep-001".to_string(),
            actor_id: "agent".to_string(),
            lease_id: "lease".to_string(),
            budget: Some(CraftedBudget { tokens: Some(0) }),
            stop_conditions: Some(CraftedStopConditions {
                max_episodes: Some(0),
            }),
            pinned_snapshot: Some(CraftedSnapshot {}),
            capability_manifest_hash: vec![0xab; 16], // Wrong size
        };

        let crafted_bytes = crafted.encode_to_vec();
        let result = EpisodeEnvelope::decode(&crafted_bytes);

        assert!(
            matches!(
                result,
                Err(EnvelopeError::InvalidCapabilityManifestHashSize)
            ),
            "decode() must reject invalid capability_manifest_hash size, got: {result:?}"
        );
    }

    /// Tests that `decode()` rejects missing budget (required per
    /// AD-EPISODE-001).
    #[test]
    fn test_decode_rejects_missing_budget() {
        use prost::Message;

        #[derive(Clone, PartialEq, Message)]
        struct CraftedStopConditions {
            #[prost(uint64, optional, tag = "1")]
            max_episodes: Option<u64>,
        }

        #[derive(Clone, PartialEq, Message)]
        struct CraftedSnapshot {}

        #[derive(Clone, PartialEq, Message)]
        struct CraftedEnvelope {
            #[prost(string, tag = "1")]
            episode_id: String,
            #[prost(string, tag = "2")]
            actor_id: String,
            #[prost(string, tag = "4")]
            lease_id: String,
            #[prost(message, optional, tag = "6")]
            stop_conditions: Option<CraftedStopConditions>,
            #[prost(message, optional, tag = "7")]
            pinned_snapshot: Option<CraftedSnapshot>,
            #[prost(bytes = "vec", tag = "8")]
            capability_manifest_hash: Vec<u8>,
        }

        let crafted = CraftedEnvelope {
            episode_id: "ep-001".to_string(),
            actor_id: "agent".to_string(),
            lease_id: "lease".to_string(),
            stop_conditions: Some(CraftedStopConditions {
                max_episodes: Some(0),
            }),
            pinned_snapshot: Some(CraftedSnapshot {}),
            capability_manifest_hash: vec![0xab; 32],
        };

        let crafted_bytes = crafted.encode_to_vec();
        let result = EpisodeEnvelope::decode(&crafted_bytes);

        assert!(
            matches!(result, Err(EnvelopeError::MissingBudget)),
            "decode() must reject missing budget, got: {result:?}"
        );
    }

    /// Tests that `decode()` rejects missing `stop_conditions` (required per
    /// AD-EPISODE-001).
    #[test]
    fn test_decode_rejects_missing_stop_conditions() {
        use prost::Message;

        #[derive(Clone, PartialEq, Message)]
        struct CraftedBudget {
            #[prost(uint64, optional, tag = "1")]
            tokens: Option<u64>,
        }

        #[derive(Clone, PartialEq, Message)]
        struct CraftedSnapshot {}

        #[derive(Clone, PartialEq, Message)]
        struct CraftedEnvelope {
            #[prost(string, tag = "1")]
            episode_id: String,
            #[prost(string, tag = "2")]
            actor_id: String,
            #[prost(string, tag = "4")]
            lease_id: String,
            #[prost(message, optional, tag = "5")]
            budget: Option<CraftedBudget>,
            #[prost(message, optional, tag = "7")]
            pinned_snapshot: Option<CraftedSnapshot>,
            #[prost(bytes = "vec", tag = "8")]
            capability_manifest_hash: Vec<u8>,
        }

        let crafted = CraftedEnvelope {
            episode_id: "ep-001".to_string(),
            actor_id: "agent".to_string(),
            lease_id: "lease".to_string(),
            budget: Some(CraftedBudget { tokens: Some(0) }),
            pinned_snapshot: Some(CraftedSnapshot {}),
            capability_manifest_hash: vec![0xab; 32],
        };

        let crafted_bytes = crafted.encode_to_vec();
        let result = EpisodeEnvelope::decode(&crafted_bytes);

        assert!(
            matches!(result, Err(EnvelopeError::MissingStopConditions)),
            "decode() must reject missing stop_conditions, got: {result:?}"
        );
    }

    /// Tests that `decode()` rejects missing `pinned_snapshot` (required per
    /// AD-EPISODE-001).
    #[test]
    fn test_decode_rejects_missing_pinned_snapshot() {
        use prost::Message;

        #[derive(Clone, PartialEq, Message)]
        struct CraftedBudget {
            #[prost(uint64, optional, tag = "1")]
            tokens: Option<u64>,
        }

        #[derive(Clone, PartialEq, Message)]
        struct CraftedStopConditions {
            #[prost(uint64, optional, tag = "1")]
            max_episodes: Option<u64>,
        }

        #[derive(Clone, PartialEq, Message)]
        struct CraftedEnvelope {
            #[prost(string, tag = "1")]
            episode_id: String,
            #[prost(string, tag = "2")]
            actor_id: String,
            #[prost(string, tag = "4")]
            lease_id: String,
            #[prost(message, optional, tag = "5")]
            budget: Option<CraftedBudget>,
            #[prost(message, optional, tag = "6")]
            stop_conditions: Option<CraftedStopConditions>,
            #[prost(bytes = "vec", tag = "8")]
            capability_manifest_hash: Vec<u8>,
        }

        let crafted = CraftedEnvelope {
            episode_id: "ep-001".to_string(),
            actor_id: "agent".to_string(),
            lease_id: "lease".to_string(),
            budget: Some(CraftedBudget { tokens: Some(0) }),
            stop_conditions: Some(CraftedStopConditions {
                max_episodes: Some(0),
            }),
            capability_manifest_hash: vec![0xab; 32],
        };

        let crafted_bytes = crafted.encode_to_vec();
        let result = EpisodeEnvelope::decode(&crafted_bytes);

        assert!(
            matches!(result, Err(EnvelopeError::MissingPinnedSnapshot)),
            "decode() must reject missing pinned_snapshot, got: {result:?}"
        );
    }

    /// Tests that `decode()` rejects `risk_tier` value 256 (truncation attack).
    ///
    /// SECURITY: If we cast `u32` to `u8` before validation, 256 truncates to
    /// 0, which maps to `Tier0`. This test ensures we reject such values.
    #[test]
    fn test_decode_rejects_truncated_risk_tier_256() {
        use prost::Message;

        #[derive(Clone, PartialEq, Message)]
        struct CraftedBudget {
            #[prost(uint64, optional, tag = "1")]
            tokens: Option<u64>,
        }

        #[derive(Clone, PartialEq, Message)]
        struct CraftedStopConditions {
            #[prost(uint64, optional, tag = "1")]
            max_episodes: Option<u64>,
        }

        #[derive(Clone, PartialEq, Message)]
        struct CraftedSnapshot {}

        #[derive(Clone, PartialEq, Message)]
        struct CraftedEnvelope {
            #[prost(string, tag = "1")]
            episode_id: String,
            #[prost(string, tag = "2")]
            actor_id: String,
            #[prost(string, tag = "4")]
            lease_id: String,
            #[prost(message, optional, tag = "5")]
            budget: Option<CraftedBudget>,
            #[prost(message, optional, tag = "6")]
            stop_conditions: Option<CraftedStopConditions>,
            #[prost(message, optional, tag = "7")]
            pinned_snapshot: Option<CraftedSnapshot>,
            #[prost(bytes = "vec", tag = "8")]
            capability_manifest_hash: Vec<u8>,
            #[prost(uint32, optional, tag = "9")]
            risk_tier: Option<u32>,
        }

        // 256 would truncate to 0 (Tier0) if cast to u8 - SECURITY BYPASS!
        let crafted = CraftedEnvelope {
            episode_id: "ep-001".to_string(),
            actor_id: "agent-007".to_string(),
            lease_id: "lease-123".to_string(),
            budget: Some(CraftedBudget { tokens: Some(0) }),
            stop_conditions: Some(CraftedStopConditions {
                max_episodes: Some(0),
            }),
            pinned_snapshot: Some(CraftedSnapshot {}),
            capability_manifest_hash: vec![0xab; 32],
            risk_tier: Some(256), // Would truncate to 0 if cast to u8
        };

        let crafted_bytes = crafted.encode_to_vec();
        let result = EpisodeEnvelope::decode(&crafted_bytes);

        assert!(
            matches!(result, Err(EnvelopeError::InvalidRiskTier { value: 256 })),
            "decode() must reject risk_tier=256 (truncation attack), got: {result:?}"
        );
    }

    /// Tests that `decode()` rejects `determinism_class` value 256 (truncation
    /// attack).
    #[test]
    fn test_decode_rejects_truncated_determinism_class_256() {
        use prost::Message;

        #[derive(Clone, PartialEq, Message)]
        struct CraftedBudget {
            #[prost(uint64, optional, tag = "1")]
            tokens: Option<u64>,
        }

        #[derive(Clone, PartialEq, Message)]
        struct CraftedStopConditions {
            #[prost(uint64, optional, tag = "1")]
            max_episodes: Option<u64>,
        }

        #[derive(Clone, PartialEq, Message)]
        struct CraftedSnapshot {}

        #[derive(Clone, PartialEq, Message)]
        struct CraftedEnvelope {
            #[prost(string, tag = "1")]
            episode_id: String,
            #[prost(string, tag = "2")]
            actor_id: String,
            #[prost(string, tag = "4")]
            lease_id: String,
            #[prost(message, optional, tag = "5")]
            budget: Option<CraftedBudget>,
            #[prost(message, optional, tag = "6")]
            stop_conditions: Option<CraftedStopConditions>,
            #[prost(message, optional, tag = "7")]
            pinned_snapshot: Option<CraftedSnapshot>,
            #[prost(bytes = "vec", tag = "8")]
            capability_manifest_hash: Vec<u8>,
            #[prost(uint32, optional, tag = "10")]
            determinism_class: Option<u32>,
        }

        // 256 would truncate to 0 (NonDeterministic) if cast to u8
        let crafted = CraftedEnvelope {
            episode_id: "ep-001".to_string(),
            actor_id: "agent-007".to_string(),
            lease_id: "lease-123".to_string(),
            budget: Some(CraftedBudget { tokens: Some(0) }),
            stop_conditions: Some(CraftedStopConditions {
                max_episodes: Some(0),
            }),
            pinned_snapshot: Some(CraftedSnapshot {}),
            capability_manifest_hash: vec![0xab; 32],
            determinism_class: Some(256), // Would truncate to 0 if cast to u8
        };

        let crafted_bytes = crafted.encode_to_vec();
        let result = EpisodeEnvelope::decode(&crafted_bytes);

        assert!(
            matches!(
                result,
                Err(EnvelopeError::InvalidDeterminismClass { value: 256 })
            ),
            "decode() must reject determinism_class=256 (truncation attack), got: {result:?}"
        );
    }

    /// Tests that `decode()` rejects oversized `goal_predicate` string.
    ///
    /// SECURITY: Denial-of-service protection - prevents memory exhaustion via
    /// large strings.
    #[test]
    fn test_decode_rejects_oversized_goal_predicate() {
        use prost::Message;

        #[derive(Clone, PartialEq, Message)]
        struct CraftedBudget {
            #[prost(uint64, optional, tag = "1")]
            tokens: Option<u64>,
        }

        #[derive(Clone, PartialEq, Message)]
        struct CraftedStopConditions {
            #[prost(uint64, optional, tag = "1")]
            max_episodes: Option<u64>,
            #[prost(string, optional, tag = "2")]
            goal_predicate: Option<String>,
        }

        #[derive(Clone, PartialEq, Message)]
        struct CraftedSnapshot {}

        #[derive(Clone, PartialEq, Message)]
        struct CraftedEnvelope {
            #[prost(string, tag = "1")]
            episode_id: String,
            #[prost(string, tag = "2")]
            actor_id: String,
            #[prost(string, tag = "4")]
            lease_id: String,
            #[prost(message, optional, tag = "5")]
            budget: Option<CraftedBudget>,
            #[prost(message, optional, tag = "6")]
            stop_conditions: Option<CraftedStopConditions>,
            #[prost(message, optional, tag = "7")]
            pinned_snapshot: Option<CraftedSnapshot>,
            #[prost(bytes = "vec", tag = "8")]
            capability_manifest_hash: Vec<u8>,
        }

        let crafted = CraftedEnvelope {
            episode_id: "ep-001".to_string(),
            actor_id: "agent".to_string(),
            lease_id: "lease".to_string(),
            budget: Some(CraftedBudget { tokens: Some(0) }),
            stop_conditions: Some(CraftedStopConditions {
                max_episodes: Some(0),
                goal_predicate: Some("x".repeat(MAX_ID_LENGTH + 1)),
            }),
            pinned_snapshot: Some(CraftedSnapshot {}),
            capability_manifest_hash: vec![0xab; 32],
        };

        let crafted_bytes = crafted.encode_to_vec();
        let result = EpisodeEnvelope::decode(&crafted_bytes);

        assert!(
            matches!(
                result,
                Err(EnvelopeError::StringTooLong {
                    field: "stop_conditions.goal_predicate",
                    ..
                })
            ),
            "decode() must reject oversized goal_predicate, got: {result:?}"
        );
    }

    /// Tests that `decode()` rejects oversized DCP ref string.
    ///
    /// SECURITY: Denial-of-service protection - prevents memory exhaustion via
    /// large strings.
    #[test]
    fn test_decode_rejects_oversized_dcp_ref() {
        use prost::Message;

        #[derive(Clone, PartialEq, Message)]
        struct CraftedBudget {
            #[prost(uint64, optional, tag = "1")]
            tokens: Option<u64>,
        }

        #[derive(Clone, PartialEq, Message)]
        struct CraftedStopConditions {
            #[prost(uint64, optional, tag = "1")]
            max_episodes: Option<u64>,
        }

        #[derive(Clone, PartialEq, Message)]
        struct CraftedSnapshot {}

        #[derive(Clone, PartialEq, Message)]
        struct CraftedContextRefs {
            #[prost(bytes = "vec", tag = "1")]
            context_pack_hash: Vec<u8>,
            #[prost(string, repeated, tag = "2")]
            dcp_refs: Vec<String>,
        }

        #[derive(Clone, PartialEq, Message)]
        struct CraftedEnvelope {
            #[prost(string, tag = "1")]
            episode_id: String,
            #[prost(string, tag = "2")]
            actor_id: String,
            #[prost(string, tag = "4")]
            lease_id: String,
            #[prost(message, optional, tag = "5")]
            budget: Option<CraftedBudget>,
            #[prost(message, optional, tag = "6")]
            stop_conditions: Option<CraftedStopConditions>,
            #[prost(message, optional, tag = "7")]
            pinned_snapshot: Option<CraftedSnapshot>,
            #[prost(bytes = "vec", tag = "8")]
            capability_manifest_hash: Vec<u8>,
            #[prost(message, optional, tag = "11")]
            context_refs: Option<CraftedContextRefs>,
        }

        let crafted = CraftedEnvelope {
            episode_id: "ep-001".to_string(),
            actor_id: "agent".to_string(),
            lease_id: "lease".to_string(),
            budget: Some(CraftedBudget { tokens: Some(0) }),
            stop_conditions: Some(CraftedStopConditions {
                max_episodes: Some(0),
            }),
            pinned_snapshot: Some(CraftedSnapshot {}),
            capability_manifest_hash: vec![0xab; 32],
            context_refs: Some(CraftedContextRefs {
                context_pack_hash: vec![],
                dcp_refs: vec!["x".repeat(MAX_ID_LENGTH + 1)],
            }),
        };

        let crafted_bytes = crafted.encode_to_vec();
        let result = EpisodeEnvelope::decode(&crafted_bytes);

        assert!(
            matches!(
                result,
                Err(EnvelopeError::StringTooLong {
                    field: "context_refs.dcp_refs",
                    ..
                })
            ),
            "decode() must reject oversized DCP ref, got: {result:?}"
        );
    }

    /// Tests that `build()` rejects oversized DCP ref string.
    #[test]
    fn test_build_rejects_oversized_dcp_ref() {
        let result = EpisodeEnvelope::builder()
            .episode_id("ep")
            .actor_id("actor")
            .lease_id("lease")
            .capability_manifest_hash([0xab; 32])
            .budget(EpisodeBudget::default())
            .stop_conditions(StopConditions::max_episodes(100))
            .pinned_snapshot(PinnedSnapshot::empty())
            .context_refs(ContextRefs {
                context_pack_hash: vec![],
                dcp_refs: vec!["x".repeat(MAX_ID_LENGTH + 1)],
            })
            .build();

        assert!(
            matches!(
                result,
                Err(EnvelopeError::StringTooLong {
                    field: "context_refs.dcp_refs",
                    ..
                })
            ),
            "build() must reject oversized DCP ref, got: {result:?}"
        );
    }

    /// Tests that `build()` rejects oversized `goal_predicate`.
    #[test]
    fn test_build_rejects_oversized_goal_predicate() {
        let result = EpisodeEnvelope::builder()
            .episode_id("ep")
            .actor_id("actor")
            .lease_id("lease")
            .capability_manifest_hash([0xab; 32])
            .budget(EpisodeBudget::default())
            .stop_conditions(StopConditions {
                max_episodes: 100,
                goal_predicate: "x".repeat(MAX_ID_LENGTH + 1),
                failure_predicate: String::new(),
                escalation_predicate: String::new(),
            })
            .pinned_snapshot(PinnedSnapshot::empty())
            .build();

        assert!(
            matches!(
                result,
                Err(EnvelopeError::StringTooLong {
                    field: "stop_conditions.goal_predicate",
                    ..
                })
            ),
            "build() must reject oversized goal_predicate, got: {result:?}"
        );
    }

    // ========================================================================
    // TCK-00350: EpisodeEnvelopeV1 tests
    // ========================================================================

    /// Helper to create a minimal valid V1 envelope.
    fn minimal_v1_envelope() -> EpisodeEnvelopeV1 {
        EpisodeEnvelopeV1::builder()
            .episode_id("ep-001")
            .actor_id("agent-007")
            .lease_id("lease-123")
            .capability_manifest_hash([0xab; 32])
            .budget(EpisodeBudget::default())
            .stop_conditions(StopConditions::max_episodes(100))
            .pinned_snapshot(PinnedSnapshot::empty())
            .view_commitment_hash([0xcc; 32])
            .freshness_pinset_hash([0xdd; 32])
            .build()
            .expect("valid V1 envelope")
    }

    #[test]
    fn test_v1_envelope_builder_minimal() {
        let env = minimal_v1_envelope();

        assert_eq!(env.inner().episode_id(), "ep-001");
        assert_eq!(env.inner().actor_id(), "agent-007");
        assert_eq!(env.inner().lease_id(), "lease-123");
        assert_eq!(env.view_commitment_hash(), &[0xcc; 32]);
        assert_eq!(env.freshness_pinset_hash(), &[0xdd; 32]);
        assert!(env.permeability_receipt_hash().is_none());
        assert!(!env.is_delegated());
    }

    #[test]
    fn test_v1_envelope_delegated() {
        let env = EpisodeEnvelopeV1::builder()
            .episode_id("ep-del")
            .actor_id("agent")
            .lease_id("lease")
            .capability_manifest_hash([0xab; 32])
            .budget(EpisodeBudget::default())
            .stop_conditions(StopConditions::max_episodes(10))
            .pinned_snapshot(PinnedSnapshot::empty())
            .view_commitment_hash([0xcc; 32])
            .freshness_pinset_hash([0xdd; 32])
            .permeability_receipt_hash([0xee; 32])
            .build()
            .expect("valid delegated V1 envelope");

        assert!(env.is_delegated());
        assert_eq!(env.permeability_receipt_hash(), Some(&[0xee; 32]));
    }

    #[test]
    fn test_v1_envelope_rejects_zero_view_commitment() {
        let result = EpisodeEnvelopeV1::builder()
            .episode_id("ep")
            .actor_id("agent")
            .lease_id("lease")
            .capability_manifest_hash([0xab; 32])
            .budget(EpisodeBudget::default())
            .stop_conditions(StopConditions::max_episodes(10))
            .pinned_snapshot(PinnedSnapshot::empty())
            .view_commitment_hash([0u8; 32]) // zero — must fail
            .freshness_pinset_hash([0xdd; 32])
            .build();

        assert!(
            matches!(result, Err(EnvelopeV1Error::ZeroViewCommitmentHash)),
            "expected ZeroViewCommitmentHash, got: {result:?}"
        );
    }

    #[test]
    fn test_v1_envelope_rejects_zero_freshness_pinset() {
        let result = EpisodeEnvelopeV1::builder()
            .episode_id("ep")
            .actor_id("agent")
            .lease_id("lease")
            .capability_manifest_hash([0xab; 32])
            .budget(EpisodeBudget::default())
            .stop_conditions(StopConditions::max_episodes(10))
            .pinned_snapshot(PinnedSnapshot::empty())
            .view_commitment_hash([0xcc; 32])
            .freshness_pinset_hash([0u8; 32]) // zero — must fail
            .build();

        assert!(
            matches!(result, Err(EnvelopeV1Error::ZeroFreshnessPinsetHash)),
            "expected ZeroFreshnessPinsetHash, got: {result:?}"
        );
    }

    #[test]
    fn test_v1_envelope_rejects_zero_permeability_receipt() {
        let result = EpisodeEnvelopeV1::builder()
            .episode_id("ep")
            .actor_id("agent")
            .lease_id("lease")
            .capability_manifest_hash([0xab; 32])
            .budget(EpisodeBudget::default())
            .stop_conditions(StopConditions::max_episodes(10))
            .pinned_snapshot(PinnedSnapshot::empty())
            .view_commitment_hash([0xcc; 32])
            .freshness_pinset_hash([0xdd; 32])
            .permeability_receipt_hash([0u8; 32]) // zero — must fail
            .build();

        assert!(
            matches!(result, Err(EnvelopeV1Error::ZeroPermeabilityReceiptHash)),
            "expected ZeroPermeabilityReceiptHash, got: {result:?}"
        );
    }

    #[test]
    fn test_v1_envelope_inner_error_propagated() {
        // Missing episode_id should propagate through V1 builder
        let result = EpisodeEnvelopeV1::builder()
            .actor_id("agent")
            .lease_id("lease")
            .capability_manifest_hash([0xab; 32])
            .view_commitment_hash([0xcc; 32])
            .freshness_pinset_hash([0xdd; 32])
            .build();

        assert!(
            matches!(
                result,
                Err(EnvelopeV1Error::InnerEnvelopeError(
                    EnvelopeError::MissingEpisodeId
                ))
            ),
            "expected inner MissingEpisodeId, got: {result:?}"
        );
    }

    #[test]
    fn test_v1_bindings_extraction() {
        let env = minimal_v1_envelope();
        let bindings = env.bindings();

        // envelope_hash should be the BLAKE3 digest of inner canonical bytes
        assert_eq!(bindings.envelope_hash, env.envelope_hash());
        assert_eq!(bindings.capability_manifest_hash, [0xab; 32]);
        assert_eq!(bindings.view_commitment_hash, [0xcc; 32]);
    }

    #[test]
    fn test_v1_bindings_validate_passes() {
        let env = minimal_v1_envelope();
        let bindings = env.bindings();

        assert!(bindings.validate().is_ok());
    }

    #[test]
    fn test_v1_bindings_validate_rejects_zero_envelope_hash() {
        let bindings = EnvelopeBindings {
            envelope_hash: [0u8; 32],
            capability_manifest_hash: [0xab; 32],
            view_commitment_hash: [0xcc; 32],
        };

        assert!(matches!(
            bindings.validate(),
            Err(EnvelopeV1Error::ZeroEnvelopeHash)
        ));
    }

    #[test]
    fn test_v1_bindings_validate_rejects_zero_capability_hash() {
        let bindings = EnvelopeBindings {
            envelope_hash: [0x11; 32],
            capability_manifest_hash: [0u8; 32],
            view_commitment_hash: [0xcc; 32],
        };

        assert!(matches!(
            bindings.validate(),
            Err(EnvelopeV1Error::ZeroCapabilityManifestHash)
        ));
    }

    #[test]
    fn test_v1_bindings_validate_rejects_zero_view_hash() {
        let bindings = EnvelopeBindings {
            envelope_hash: [0x11; 32],
            capability_manifest_hash: [0xab; 32],
            view_commitment_hash: [0u8; 32],
        };

        assert!(matches!(
            bindings.validate(),
            Err(EnvelopeV1Error::ZeroViewCommitmentHash)
        ));
    }

    #[test]
    fn test_v1_bindings_verify_against_matching_envelope() {
        let env = minimal_v1_envelope();
        let bindings = env.bindings();

        assert!(bindings.verify_against(&env).is_ok());
    }

    #[test]
    fn test_v1_bindings_verify_against_mismatched_envelope() {
        let env1 = minimal_v1_envelope();
        let bindings = env1.bindings();

        // Build a different envelope (different view_commitment_hash)
        let env2 = EpisodeEnvelopeV1::builder()
            .episode_id("ep-001")
            .actor_id("agent-007")
            .lease_id("lease-123")
            .capability_manifest_hash([0xab; 32])
            .budget(EpisodeBudget::default())
            .stop_conditions(StopConditions::max_episodes(100))
            .pinned_snapshot(PinnedSnapshot::empty())
            .view_commitment_hash([0xff; 32]) // different
            .freshness_pinset_hash([0xdd; 32])
            .build()
            .expect("valid V1 envelope");

        let result = bindings.verify_against(&env2);
        assert!(
            matches!(
                result,
                Err(EnvelopeV1Error::BindingMismatch {
                    field: "view_commitment_hash"
                })
            ),
            "expected view_commitment_hash mismatch, got: {result:?}"
        );
    }

    #[test]
    fn test_v1_validate_for_spawn_passes() {
        let env = minimal_v1_envelope();
        assert!(env.validate_for_spawn().is_ok());
    }

    #[test]
    fn test_v1_validate_for_delegated_spawn_requires_permeability() {
        let env = minimal_v1_envelope();
        // Non-delegated envelope should fail delegated validation
        let result = env.validate_for_delegated_spawn();
        assert!(
            matches!(result, Err(EnvelopeV1Error::MissingPermeabilityReceiptHash)),
            "expected MissingPermeabilityReceiptHash, got: {result:?}"
        );
    }

    #[test]
    fn test_v1_validate_for_delegated_spawn_passes_with_hash() {
        let env = EpisodeEnvelopeV1::builder()
            .episode_id("ep-del")
            .actor_id("agent")
            .lease_id("lease")
            .capability_manifest_hash([0xab; 32])
            .budget(EpisodeBudget::default())
            .stop_conditions(StopConditions::max_episodes(10))
            .pinned_snapshot(PinnedSnapshot::empty())
            .view_commitment_hash([0xcc; 32])
            .freshness_pinset_hash([0xdd; 32])
            .permeability_receipt_hash([0xee; 32])
            .build()
            .expect("valid delegated V1 envelope");

        assert!(env.validate_for_delegated_spawn().is_ok());
    }

    #[test]
    fn test_spawn_gate_rejects_absent_envelope() {
        let result = validate_spawn_gate(None, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_spawn_gate_accepts_valid_envelope() {
        let env = minimal_v1_envelope();
        let result = validate_spawn_gate(Some(&env), false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_spawn_gate_rejects_delegated_mode() {
        // Even with a valid envelope, delegated mode MUST be rejected by
        // the legacy gate — callers must use validate_delegated_spawn_gate.
        let env = minimal_v1_envelope();
        let result = validate_spawn_gate(Some(&env), true);
        assert!(
            matches!(
                result,
                Err(EnvelopeV1Error::DelegatedRequiresConsumptionBinding)
            ),
            "expected DelegatedRequiresConsumptionBinding for delegated spawn, got: {result:?}"
        );
    }

    #[test]
    fn test_spawn_gate_rejects_delegated_even_with_receipt_hash() {
        // A delegated envelope with a permeability_receipt_hash must STILL
        // be rejected by the legacy gate — only
        // validate_delegated_spawn_gate may authorize delegated spawns.
        let env = EpisodeEnvelopeV1::builder()
            .episode_id("ep-del")
            .actor_id("agent-del")
            .lease_id("lease-del")
            .capability_manifest_hash([0xab; 32])
            .budget(EpisodeBudget::default())
            .stop_conditions(StopConditions::max_episodes(10))
            .pinned_snapshot(PinnedSnapshot::empty())
            .view_commitment_hash([0xcc; 32])
            .freshness_pinset_hash([0xdd; 32])
            .permeability_receipt_hash([0xee; 32])
            .build()
            .expect("valid delegated V1 envelope");

        let result = validate_spawn_gate(Some(&env), true);
        assert!(
            matches!(
                result,
                Err(EnvelopeV1Error::DelegatedRequiresConsumptionBinding)
            ),
            "expected DelegatedRequiresConsumptionBinding even with receipt hash, got: {result:?}"
        );
    }

    #[test]
    fn test_v1_bindings_to_hex_map() {
        let env = minimal_v1_envelope();
        let bindings = env.bindings();
        let (env_hex, cap_hex, view_hex) = bindings.to_hex_map();

        assert_eq!(env_hex.len(), 64);
        assert_eq!(cap_hex, hex::encode([0xab; 32]));
        assert_eq!(view_hex, hex::encode([0xcc; 32]));
    }

    #[test]
    fn test_v1_envelope_hash_is_inner_digest() {
        let env = minimal_v1_envelope();
        // The envelope_hash should exactly equal the inner envelope's BLAKE3
        // digest
        assert_eq!(env.envelope_hash(), env.inner().digest());
    }

    #[test]
    fn test_v1_replay_verification_roundtrip() {
        // Simulate full lifecycle:
        // 1. Build envelope
        // 2. Extract bindings for receipt
        // 3. Verify bindings against original envelope
        let env = EpisodeEnvelopeV1::builder()
            .episode_id("ep-replay")
            .actor_id("agent-replay")
            .work_id("work-replay")
            .lease_id("lease-replay")
            .capability_manifest_hash([0x11; 32])
            .budget(EpisodeBudget::default())
            .stop_conditions(StopConditions::max_episodes(50))
            .pinned_snapshot(PinnedSnapshot::empty())
            .view_commitment_hash([0x22; 32])
            .freshness_pinset_hash([0x33; 32])
            .build()
            .expect("valid V1 envelope");

        // Step 2: Extract bindings (as would be embedded in receipt)
        let receipt_bindings = env.bindings();

        // Step 3: Validate bindings
        assert!(receipt_bindings.validate().is_ok());

        // Step 4: Verify against the original envelope (replay path)
        assert!(receipt_bindings.verify_against(&env).is_ok());
    }

    // =========================================================================
    // Delegated Spawn Consumption Binding Tests (REQ-0027)
    // =========================================================================

    /// Test policy root hash used across delegated spawn binding tests.
    const TEST_POLICY_ROOT: [u8; 32] = [0xEE; 32];

    /// Helper: builds a valid permeability receipt and returns (receipt,
    /// `receipt_hash`).
    ///
    /// The receipt's `delegate_actor_id` is set to "agent" and its
    /// `policy_root_hash` is set to `TEST_POLICY_ROOT` so that scope
    /// and provenance bindings match the test envelopes.
    fn build_test_receipt(
        expires_at_ms: u64,
        issued_at_ms: u64,
    ) -> (
        apm2_core::policy::permeability::PermeabilityReceipt,
        [u8; 32],
    ) {
        use apm2_core::policy::permeability::{
            AuthorityVector, BudgetLevel, CapabilityLevel, ClassificationLevel,
            PermeabilityReceiptBuilder, RiskLevel, StopPredicateLevel, TaintCeiling,
        };

        let parent = AuthorityVector::top();
        let overlay = AuthorityVector::new(
            RiskLevel::High,
            CapabilityLevel::Full,
            BudgetLevel::Capped(100),
            StopPredicateLevel::Inherit,
            TaintCeiling::Attested,
            ClassificationLevel::Public,
        );
        let receipt = PermeabilityReceiptBuilder::new("test-receipt", parent, overlay)
            .delegator_actor_id("alice")
            .delegate_actor_id("agent")
            .issued_at_ms(issued_at_ms)
            .expires_at_ms(expires_at_ms)
            .policy_root_hash(TEST_POLICY_ROOT)
            .build()
            .expect("valid receipt");
        let hash = receipt.content_hash();
        (receipt, hash)
    }

    /// Helper: builds a pinned snapshot with the test policy root hash.
    fn snapshot_with_policy_root() -> PinnedSnapshot {
        PinnedSnapshot::builder()
            .policy_hash(TEST_POLICY_ROOT)
            .build()
    }

    #[test]
    fn test_delegated_spawn_with_receipt_happy_path() {
        use apm2_core::policy::permeability::AuthorityVector;

        let (receipt, hash) = build_test_receipt(5_000_000, 1_000_000);
        let required = AuthorityVector::bottom();

        let env = EpisodeEnvelopeV1::builder()
            .episode_id("ep-del-binding")
            .actor_id("agent")
            .lease_id("lease")
            .capability_manifest_hash([0xab; 32])
            .budget(EpisodeBudget::default())
            .stop_conditions(StopConditions::max_episodes(10))
            .pinned_snapshot(snapshot_with_policy_root())
            .view_commitment_hash([0xcc; 32])
            .freshness_pinset_hash([0xdd; 32])
            .permeability_receipt_hash(hash)
            .build()
            .expect("valid delegated V1 envelope");

        assert!(
            env.validate_for_delegated_spawn_with_receipt(&receipt, &required, 2_000_000)
                .is_ok(),
            "valid receipt + matching hash + sufficient authority should pass"
        );
    }

    #[test]
    fn test_delegated_spawn_rejects_mismatched_receipt_hash() {
        use apm2_core::policy::permeability::AuthorityVector;

        let (receipt, _hash) = build_test_receipt(5_000_000, 1_000_000);
        let required = AuthorityVector::bottom();

        // Use a DIFFERENT hash in the envelope (not matching receipt)
        let wrong_hash = [0xFF; 32];
        let env = EpisodeEnvelopeV1::builder()
            .episode_id("ep-del-wrong-hash")
            .actor_id("agent")
            .lease_id("lease")
            .capability_manifest_hash([0xab; 32])
            .budget(EpisodeBudget::default())
            .stop_conditions(StopConditions::max_episodes(10))
            .pinned_snapshot(snapshot_with_policy_root())
            .view_commitment_hash([0xcc; 32])
            .freshness_pinset_hash([0xdd; 32])
            .permeability_receipt_hash(wrong_hash)
            .build()
            .expect("valid delegated V1 envelope");

        let result = env.validate_for_delegated_spawn_with_receipt(&receipt, &required, 2_000_000);
        assert!(
            matches!(result, Err(EnvelopeV1Error::PermeabilityBindingFailure(_))),
            "mismatched receipt hash must be rejected, got: {result:?}"
        );
    }

    #[test]
    fn test_delegated_spawn_rejects_expired_receipt() {
        use apm2_core::policy::permeability::AuthorityVector;

        let (receipt, hash) = build_test_receipt(2_000_000, 1_000_000);
        let required = AuthorityVector::bottom();

        let env = EpisodeEnvelopeV1::builder()
            .episode_id("ep-del-expired")
            .actor_id("agent")
            .lease_id("lease")
            .capability_manifest_hash([0xab; 32])
            .budget(EpisodeBudget::default())
            .stop_conditions(StopConditions::max_episodes(10))
            .pinned_snapshot(snapshot_with_policy_root())
            .view_commitment_hash([0xcc; 32])
            .freshness_pinset_hash([0xdd; 32])
            .permeability_receipt_hash(hash)
            .build()
            .expect("valid delegated V1 envelope");

        // now_ms = 3_000_000 > expires_at_ms = 2_000_000  =>  expired
        let result = env.validate_for_delegated_spawn_with_receipt(&receipt, &required, 3_000_000);
        assert!(
            matches!(result, Err(EnvelopeV1Error::PermeabilityBindingFailure(_))),
            "expired receipt must be rejected, got: {result:?}"
        );
    }

    #[test]
    fn test_delegated_spawn_rejects_insufficient_authority() {
        use apm2_core::policy::permeability::AuthorityVector;

        let (receipt, hash) = build_test_receipt(5_000_000, 1_000_000);
        // Required authority is top() — strictly wider than what the receipt
        // delegated (which was meet(top, overlay) = overlay, which is narrower
        // than top on several facets). At Tier2+ the ceiling is top() so this
        // tests the receipt authority check, not the ceiling.
        let required = AuthorityVector::top();

        let env = EpisodeEnvelopeV1::builder()
            .episode_id("ep-del-insufficient")
            .actor_id("agent")
            .lease_id("lease")
            .capability_manifest_hash([0xab; 32])
            .budget(EpisodeBudget::default())
            .stop_conditions(StopConditions::max_episodes(10))
            .pinned_snapshot(snapshot_with_policy_root())
            .risk_tier(RiskTier::Tier2)
            .view_commitment_hash([0xcc; 32])
            .freshness_pinset_hash([0xdd; 32])
            .permeability_receipt_hash(hash)
            .build()
            .expect("valid delegated V1 envelope");

        let result = env.validate_for_delegated_spawn_with_receipt(&receipt, &required, 2_000_000);
        assert!(
            matches!(result, Err(EnvelopeV1Error::PermeabilityBindingFailure(_))),
            "authority exceeding delegation must be rejected, got: {result:?}"
        );
    }

    #[test]
    fn test_delegated_spawn_gate_with_receipt_happy_path() {
        use apm2_core::policy::permeability::AuthorityVector;

        let (receipt, hash) = build_test_receipt(5_000_000, 1_000_000);
        let required = AuthorityVector::bottom();

        let env = EpisodeEnvelopeV1::builder()
            .episode_id("ep-gate-binding")
            .actor_id("agent")
            .lease_id("lease")
            .capability_manifest_hash([0xab; 32])
            .budget(EpisodeBudget::default())
            .stop_conditions(StopConditions::max_episodes(10))
            .pinned_snapshot(snapshot_with_policy_root())
            .view_commitment_hash([0xcc; 32])
            .freshness_pinset_hash([0xdd; 32])
            .permeability_receipt_hash(hash)
            .build()
            .expect("valid delegated V1 envelope");

        let result = validate_delegated_spawn_gate(Some(&env), &receipt, &required, 2_000_000);
        assert!(result.is_ok(), "gate should pass with valid binding");
    }

    #[test]
    fn test_delegated_spawn_gate_rejects_absent_envelope() {
        use apm2_core::policy::permeability::AuthorityVector;

        let (receipt, _hash) = build_test_receipt(5_000_000, 1_000_000);
        let required = AuthorityVector::bottom();

        let result = validate_delegated_spawn_gate(None, &receipt, &required, 2_000_000);
        assert!(
            matches!(result, Err(EnvelopeV1Error::ZeroEnvelopeHash)),
            "absent envelope must be rejected, got: {result:?}"
        );
    }

    #[test]
    fn test_delegated_spawn_gate_rejects_wrong_hash() {
        use apm2_core::policy::permeability::AuthorityVector;

        let (receipt, _hash) = build_test_receipt(5_000_000, 1_000_000);
        let required = AuthorityVector::bottom();

        let env = EpisodeEnvelopeV1::builder()
            .episode_id("ep-gate-wrong-hash")
            .actor_id("agent")
            .lease_id("lease")
            .capability_manifest_hash([0xab; 32])
            .budget(EpisodeBudget::default())
            .stop_conditions(StopConditions::max_episodes(10))
            .pinned_snapshot(snapshot_with_policy_root())
            .view_commitment_hash([0xcc; 32])
            .freshness_pinset_hash([0xdd; 32])
            .permeability_receipt_hash([0xFF; 32])
            .build()
            .expect("valid delegated V1 envelope");

        let result = validate_delegated_spawn_gate(Some(&env), &receipt, &required, 2_000_000);
        assert!(
            matches!(result, Err(EnvelopeV1Error::PermeabilityBindingFailure(_))),
            "wrong hash must be rejected via gate, got: {result:?}"
        );
    }

    #[test]
    fn test_delegated_spawn_rejects_scope_mismatch() {
        use apm2_core::policy::permeability::{
            AuthorityVector, BudgetLevel, CapabilityLevel, ClassificationLevel,
            PermeabilityReceiptBuilder, RiskLevel, StopPredicateLevel, TaintCeiling,
        };

        // Build a receipt delegated to "wrong-agent" instead of "agent"
        let parent = AuthorityVector::top();
        let overlay = AuthorityVector::new(
            RiskLevel::High,
            CapabilityLevel::Full,
            BudgetLevel::Capped(100),
            StopPredicateLevel::Inherit,
            TaintCeiling::Attested,
            ClassificationLevel::Public,
        );
        let receipt = PermeabilityReceiptBuilder::new("test-scope", parent, overlay)
            .delegator_actor_id("alice")
            .delegate_actor_id("wrong-agent")
            .issued_at_ms(1_000_000)
            .expires_at_ms(5_000_000)
            .policy_root_hash(TEST_POLICY_ROOT)
            .build()
            .expect("valid receipt");
        let hash = receipt.content_hash();

        let required = AuthorityVector::bottom();
        let env = EpisodeEnvelopeV1::builder()
            .episode_id("ep-scope-mismatch")
            .actor_id("agent")
            .lease_id("lease")
            .capability_manifest_hash([0xab; 32])
            .budget(EpisodeBudget::default())
            .stop_conditions(StopConditions::max_episodes(10))
            .pinned_snapshot(snapshot_with_policy_root())
            .view_commitment_hash([0xcc; 32])
            .freshness_pinset_hash([0xdd; 32])
            .permeability_receipt_hash(hash)
            .build()
            .expect("valid delegated V1 envelope");

        let result = env.validate_for_delegated_spawn_with_receipt(&receipt, &required, 2_000_000);
        assert!(
            matches!(result, Err(EnvelopeV1Error::PermeabilityBindingFailure(_))),
            "scope mismatch (wrong actor) must be rejected, got: {result:?}"
        );
    }

    #[test]
    fn test_delegated_spawn_rejects_policy_root_mismatch() {
        use apm2_core::policy::permeability::{
            AuthorityVector, BudgetLevel, CapabilityLevel, ClassificationLevel,
            PermeabilityReceiptBuilder, RiskLevel, StopPredicateLevel, TaintCeiling,
        };

        // Build a receipt with a DIFFERENT policy root
        let wrong_root = [0xFF; 32];
        let parent = AuthorityVector::top();
        let overlay = AuthorityVector::new(
            RiskLevel::High,
            CapabilityLevel::Full,
            BudgetLevel::Capped(100),
            StopPredicateLevel::Inherit,
            TaintCeiling::Attested,
            ClassificationLevel::Public,
        );
        let receipt = PermeabilityReceiptBuilder::new("test-prh", parent, overlay)
            .delegator_actor_id("alice")
            .delegate_actor_id("agent")
            .issued_at_ms(1_000_000)
            .expires_at_ms(5_000_000)
            .policy_root_hash(wrong_root)
            .build()
            .expect("valid receipt");
        let hash = receipt.content_hash();

        let required = AuthorityVector::bottom();
        let env = EpisodeEnvelopeV1::builder()
            .episode_id("ep-prh-mismatch")
            .actor_id("agent")
            .lease_id("lease")
            .capability_manifest_hash([0xab; 32])
            .budget(EpisodeBudget::default())
            .stop_conditions(StopConditions::max_episodes(10))
            .pinned_snapshot(snapshot_with_policy_root())
            .view_commitment_hash([0xcc; 32])
            .freshness_pinset_hash([0xdd; 32])
            .permeability_receipt_hash(hash)
            .build()
            .expect("valid delegated V1 envelope");

        let result = env.validate_for_delegated_spawn_with_receipt(&receipt, &required, 2_000_000);
        assert!(
            matches!(result, Err(EnvelopeV1Error::PermeabilityBindingFailure(_))),
            "policy root mismatch must be rejected, got: {result:?}"
        );
    }

    #[test]
    fn test_delegated_spawn_rejects_missing_policy_hash() {
        use apm2_core::policy::permeability::{
            AuthorityVector, BudgetLevel, CapabilityLevel, ClassificationLevel,
            PermeabilityReceiptBuilder, RiskLevel, StopPredicateLevel, TaintCeiling,
        };

        let parent = AuthorityVector::top();
        let overlay = AuthorityVector::new(
            RiskLevel::High,
            CapabilityLevel::Full,
            BudgetLevel::Capped(100),
            StopPredicateLevel::Inherit,
            TaintCeiling::Attested,
            ClassificationLevel::Public,
        );
        let receipt = PermeabilityReceiptBuilder::new("test-no-policy", parent, overlay)
            .delegator_actor_id("alice")
            .delegate_actor_id("agent")
            .issued_at_ms(1_000_000)
            .expires_at_ms(5_000_000)
            .policy_root_hash(TEST_POLICY_ROOT)
            .build()
            .expect("valid receipt");
        let hash = receipt.content_hash();

        let required = AuthorityVector::bottom();
        // Build envelope WITHOUT policy hash in pinned snapshot
        let env = EpisodeEnvelopeV1::builder()
            .episode_id("ep-no-policy")
            .actor_id("agent")
            .lease_id("lease")
            .capability_manifest_hash([0xab; 32])
            .budget(EpisodeBudget::default())
            .stop_conditions(StopConditions::max_episodes(10))
            .pinned_snapshot(PinnedSnapshot::empty())
            .view_commitment_hash([0xcc; 32])
            .freshness_pinset_hash([0xdd; 32])
            .permeability_receipt_hash(hash)
            .build()
            .expect("valid delegated V1 envelope");

        let result = env.validate_for_delegated_spawn_with_receipt(&receipt, &required, 2_000_000);
        assert!(
            matches!(result, Err(EnvelopeV1Error::MissingPolicyRootDerivation)),
            "missing policy hash must fail with MissingPolicyRootDerivation, got: {result:?}"
        );
    }
}
