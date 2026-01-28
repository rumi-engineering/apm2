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
}

/// Internal protobuf representation for `StopConditions`.
#[derive(Clone, PartialEq, Message)]
struct StopConditionsProto {
    #[prost(uint64, tag = "1")]
    max_episodes: u64,
    #[prost(string, tag = "2")]
    goal_predicate: String,
    #[prost(string, tag = "3")]
    failure_predicate: String,
    #[prost(string, tag = "4")]
    escalation_predicate: String,
}

/// Stop conditions for episode termination.
///
/// These predicates define when an episode should stop executing.
/// They are evaluated after each episode step.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let proto = StopConditionsProto {
            max_episodes: self.max_episodes,
            goal_predicate: self.goal_predicate.clone(),
            failure_predicate: self.failure_predicate.clone(),
            escalation_predicate: self.escalation_predicate.clone(),
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
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
#[derive(Clone, PartialEq, Message)]
struct BudgetProto {
    #[prost(uint64, tag = "1")]
    tokens: u64,
    #[prost(uint32, tag = "2")]
    tool_calls: u32,
    #[prost(uint64, tag = "3")]
    wall_ms: u64,
    #[prost(uint64, tag = "4")]
    cpu_ms: u64,
    #[prost(uint64, tag = "5")]
    bytes_io: u64,
    #[prost(uint64, tag = "6")]
    evidence_bytes: u64,
}

/// Internal protobuf representation for the snapshot in envelope.
#[allow(clippy::struct_field_names)]
#[derive(Clone, PartialEq, Message)]
struct SnapshotProto {
    #[prost(bytes = "vec", tag = "1")]
    repo_hash: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    lockfile_hash: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    policy_hash: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    toolchain_hash: Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    model_profile_hash: Vec<u8>,
}

/// Internal protobuf representation for `EpisodeEnvelope`.
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
    #[prost(uint32, tag = "9")]
    risk_tier: u32,
    #[prost(uint32, tag = "10")]
    determinism_class: u32,
    #[prost(message, optional, tag = "11")]
    context_refs: Option<ContextRefsProto>,
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
///     DeterminismClass, EpisodeBudget, EpisodeEnvelope, PinnedSnapshot,
///     RiskTier, StopConditions,
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
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
    /// # Errors
    ///
    /// Returns an error if decoding fails.
    pub fn decode(buf: &[u8]) -> Result<Self, prost::DecodeError> {
        let proto = EpisodeEnvelopeProto::decode(buf)?;
        Ok(Self::from_proto(proto))
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
    fn to_proto(&self) -> EpisodeEnvelopeProto {
        let budget = self.budget.as_ref().map(|b| BudgetProto {
            tokens: b.tokens(),
            tool_calls: b.tool_calls(),
            wall_ms: b.wall_ms(),
            cpu_ms: b.cpu_ms(),
            bytes_io: b.bytes_io(),
            evidence_bytes: b.evidence_bytes(),
        });

        let stop_conditions = self.stop_conditions.as_ref().map(|s| StopConditionsProto {
            max_episodes: s.max_episodes,
            goal_predicate: s.goal_predicate.clone(),
            failure_predicate: s.failure_predicate.clone(),
            escalation_predicate: s.escalation_predicate.clone(),
        });

        let pinned_snapshot = self.pinned_snapshot.as_ref().map(|s| SnapshotProto {
            repo_hash: s.repo_hash().map(<[u8]>::to_vec).unwrap_or_default(),
            lockfile_hash: s.lockfile_hash().map(<[u8]>::to_vec).unwrap_or_default(),
            policy_hash: s.policy_hash().map(<[u8]>::to_vec).unwrap_or_default(),
            toolchain_hash: s.toolchain_hash().map(<[u8]>::to_vec).unwrap_or_default(),
            model_profile_hash: s
                .model_profile_hash()
                .map(<[u8]>::to_vec)
                .unwrap_or_default(),
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
            risk_tier: u32::from(self.risk_tier.tier()),
            determinism_class: u32::from(self.determinism_class.value()),
            context_refs,
        }
    }

    /// Converts from protobuf representation.
    fn from_proto(proto: EpisodeEnvelopeProto) -> Self {
        let budget = proto.budget.map(|b| {
            EpisodeBudget::builder()
                .tokens(b.tokens)
                .tool_calls(b.tool_calls)
                .wall_ms(b.wall_ms)
                .cpu_ms(b.cpu_ms)
                .bytes_io(b.bytes_io)
                .evidence_bytes(b.evidence_bytes)
                .build()
        });

        let stop_conditions = proto.stop_conditions.map(|s| StopConditions {
            max_episodes: s.max_episodes,
            goal_predicate: s.goal_predicate,
            failure_predicate: s.failure_predicate,
            escalation_predicate: s.escalation_predicate,
        });

        let pinned_snapshot = proto.pinned_snapshot.map(|s| {
            let mut builder = PinnedSnapshot::builder();
            if s.repo_hash.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&s.repo_hash);
                builder = builder.repo_hash(arr);
            }
            if s.lockfile_hash.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&s.lockfile_hash);
                builder = builder.lockfile_hash(arr);
            }
            if s.policy_hash.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&s.policy_hash);
                builder = builder.policy_hash(arr);
            }
            if s.toolchain_hash.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&s.toolchain_hash);
                builder = builder.toolchain_hash(arr);
            }
            if s.model_profile_hash.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&s.model_profile_hash);
                builder = builder.model_profile_hash(arr);
            }
            builder.build()
        });

        let context_refs = proto.context_refs.map(|c| ContextRefs {
            context_pack_hash: c.context_pack_hash,
            dcp_refs: c.dcp_refs,
        });

        Self {
            episode_id: proto.episode_id,
            actor_id: proto.actor_id,
            work_id: proto.work_id,
            lease_id: proto.lease_id,
            budget,
            stop_conditions,
            pinned_snapshot,
            capability_manifest_hash: proto.capability_manifest_hash,
            #[allow(clippy::cast_possible_truncation)]
            risk_tier: RiskTier::from_u8(proto.risk_tier as u8).unwrap_or_default(),
            #[allow(clippy::cast_possible_truncation)]
            determinism_class: DeterminismClass::from_u8(proto.determinism_class as u8)
                .unwrap_or_default(),
            context_refs,
        }
    }
}

/// Error type for envelope construction.
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
    /// # Errors
    ///
    /// Returns an error if:
    /// - Any required field is missing
    /// - Any ID exceeds `MAX_ID_LENGTH`
    /// - Capability manifest hash is not 32 bytes
    /// - Too many DCP references
    pub fn build(self) -> Result<EpisodeEnvelope, EnvelopeError> {
        // Validate required fields
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

        // Validate DCP refs count
        if let Some(ref ctx) = self.context_refs {
            if ctx.dcp_refs.len() > MAX_DCP_REFS {
                return Err(EnvelopeError::TooManyDcpRefs { max: MAX_DCP_REFS });
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
            risk_tier: self.risk_tier,
            determinism_class: self.determinism_class,
            context_refs: self.context_refs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_envelope() -> EpisodeEnvelope {
        EpisodeEnvelope::builder()
            .episode_id("ep-001")
            .actor_id("agent-007")
            .lease_id("lease-123")
            .capability_manifest_hash([0xab; 32])
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
            .build();

        assert!(matches!(
            result,
            Err(EnvelopeError::MissingCapabilityManifestHash)
        ));
    }

    #[test]
    fn test_envelope_invalid_capability_hash_size() {
        let result = EpisodeEnvelope::builder()
            .episode_id("ep")
            .actor_id("actor")
            .lease_id("lease")
            .capability_manifest_hash_from_slice(&[0xab; 16]) // Wrong size
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
}
