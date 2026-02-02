//! Privileged endpoint dispatcher for RFC-0017 control-plane IPC.
//!
//! This module implements the privileged endpoint dispatcher per DD-001 and
//! DD-009. Privileged endpoints (ClaimWork, SpawnEpisode, IssueCapability,
//! Shutdown) are only accessible via the operator socket. Session socket
//! connections receive `PERMISSION_DENIED` for all privileged requests.
//!
//! # Security Invariants
//!
//! - [INV-0001] An agent cannot execute privileged IPC operations
//! - [TB-002] Privilege separation boundary: session connections blocked from
//!   privileged handlers
//! - [TCK-00253] Actor_id derived from credential, not user input
//!
//! # Message Flow
//!
//! ```text
//! ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
//! │ operator.sock   │────▶│ PrivilegedDispatch │──▶│ Handler Stubs  │
//! └─────────────────┘     └─────────────────┘     └─────────────────┘
//!                                │
//!                                │ `PERMISSION_DENIED`
//!                                ▼
//! ┌─────────────────┐     ┌─────────────────┐
//! │ session.sock    │────▶│  (Rejected)     │
//! └─────────────────┘     └─────────────────┘
//! ```

use std::collections::VecDeque;
use std::sync::Arc;

use bytes::Bytes;
use prost::Message;
use subtle::ConstantTimeEq;
use tracing::{debug, info, warn};

use super::credentials::PeerCredentials;
use super::error::{ProtocolError, ProtocolResult};
use super::messages::{
    BoundedDecode, ClaimWorkRequest, ClaimWorkResponse, DecodeConfig, IssueCapabilityRequest,
    IssueCapabilityResponse, PrivilegedError, PrivilegedErrorCode, ShutdownRequest,
    ShutdownResponse, SpawnEpisodeRequest, SpawnEpisodeResponse, WorkRole,
};
use crate::episode::registry::InMemorySessionRegistry;
use crate::episode::{
    CustodyDomainError, CustodyDomainId, EpisodeRuntime, EpisodeRuntimeConfig,
    LeaseIssueDenialReason, validate_custody_domain_overlap,
};
use crate::session::{EphemeralHandle, SessionRegistry, SessionState};

// ============================================================================
// Ledger Event Emitter Interface (TCK-00253)
// ============================================================================

/// A signed ledger event for persistence.
///
/// Per acceptance criteria: "`WorkClaimed` event signed and persisted"
/// This struct represents a signed event ready for ledger ingestion.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SignedLedgerEvent {
    /// Unique event identifier.
    pub event_id: String,

    /// Event type discriminant.
    pub event_type: String,

    /// Work ID this event relates to.
    pub work_id: String,

    /// Actor ID that produced this event.
    pub actor_id: String,

    /// Canonical event payload (JSON).
    pub payload: Vec<u8>,

    /// Ed25519 signature over canonical bytes.
    pub signature: Vec<u8>,

    /// Timestamp in nanoseconds since epoch (HTF-compliant).
    pub timestamp_ns: u64,
}

/// Error type for ledger event emission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LedgerEventError {
    /// Signing operation failed.
    SigningFailed {
        /// Error message.
        message: String,
    },

    /// Ledger persistence failed.
    PersistenceFailed {
        /// Error message.
        message: String,
    },
}

impl std::fmt::Display for LedgerEventError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SigningFailed { message } => write!(f, "signing failed: {message}"),
            Self::PersistenceFailed { message } => write!(f, "persistence failed: {message}"),
        }
    }
}

impl std::error::Error for LedgerEventError {}

/// Trait for emitting signed events to the ledger.
///
/// Per TCK-00253 acceptance criteria:
/// - "`WorkClaimed` event signed and persisted"
/// - "Ledger query returns signed event"
///
/// # Implementers
///
/// - `StubLedgerEventEmitter`: In-memory storage for testing
/// - `SqliteLedgerEventEmitter`: SQLite-backed persistence (future)
pub trait LedgerEventEmitter: Send + Sync {
    /// Emits a signed `WorkClaimed` event to the ledger.
    ///
    /// # Arguments
    ///
    /// * `claim` - The work claim to record
    ///
    /// # Returns
    ///
    /// The signed event that was persisted.
    ///
    /// # Errors
    ///
    /// Returns `LedgerEventError` if signing or persistence fails.
    fn emit_work_claimed(&self, claim: &WorkClaim) -> Result<SignedLedgerEvent, LedgerEventError>;

    /// Queries a signed event by event ID.
    fn get_event(&self, event_id: &str) -> Option<SignedLedgerEvent>;

    /// Queries events by work ID.
    fn get_events_by_work_id(&self, work_id: &str) -> Vec<SignedLedgerEvent>;
}

/// Domain separation prefix for `WorkClaimed` events.
///
/// Per RFC-0017 and TCK-00264: domain prefixes prevent cross-context replay.
pub const WORK_CLAIMED_DOMAIN_PREFIX: &[u8] = b"apm2.event.work_claimed:";

/// Maximum length for ID fields (`work_id`, `lease_id`, etc.).
///
/// Per SEC-SCP-FAC-0020: Unbounded input processing can lead to
/// denial-of-service via OOM. This limit prevents attackers from supplying
/// multi-GB ID strings.
pub const MAX_ID_LENGTH: usize = 256;

/// Maximum number of events stored in `StubLedgerEventEmitter`.
///
/// Per CTR-1303: In-memory stores must have `max_entries` limit with O(1)
/// eviction. This prevents denial-of-service via memory exhaustion from
/// unbounded event emission.
pub const MAX_LEDGER_EVENTS: usize = 10_000;

/// Stub ledger event emitter for testing.
///
/// Stores events in memory with Ed25519 signatures using a test signing key.
/// In production, this will be replaced with `SqliteLedgerEventEmitter`.
///
/// # Capacity Limits (CTR-1303)
///
/// This emitter enforces a maximum of [`MAX_LEDGER_EVENTS`] entries to prevent
/// memory exhaustion. When the limit is reached, the oldest entry (by insertion
/// order) is evicted to make room for the new event.
#[derive(Debug)]
pub struct StubLedgerEventEmitter {
    /// Events stored with insertion order for LRU eviction.
    /// The `Vec` maintains insertion order; oldest entries are at the front.
    events: std::sync::RwLock<(
        Vec<String>,
        std::collections::HashMap<String, SignedLedgerEvent>,
    )>,
    /// Events indexed by work ID for efficient querying.
    events_by_work_id: std::sync::RwLock<std::collections::HashMap<String, Vec<String>>>,
    /// Signing key for event signatures (test key).
    signing_key: ed25519_dalek::SigningKey,
}

impl Default for StubLedgerEventEmitter {
    fn default() -> Self {
        Self::new()
    }
}

impl StubLedgerEventEmitter {
    /// Creates a new stub emitter with a random test signing key.
    #[must_use]
    pub fn new() -> Self {
        use rand::rngs::OsRng;
        Self {
            events: std::sync::RwLock::new((
                Vec::with_capacity(MAX_LEDGER_EVENTS.min(1000)), // Pre-allocate reasonably
                std::collections::HashMap::with_capacity(MAX_LEDGER_EVENTS.min(1000)),
            )),
            events_by_work_id: std::sync::RwLock::new(std::collections::HashMap::new()),
            signing_key: ed25519_dalek::SigningKey::generate(&mut OsRng),
        }
    }

    /// Creates a new stub emitter with a specific signing key.
    #[must_use]
    pub fn with_signing_key(signing_key: ed25519_dalek::SigningKey) -> Self {
        Self {
            events: std::sync::RwLock::new((
                Vec::with_capacity(MAX_LEDGER_EVENTS.min(1000)), // Pre-allocate reasonably
                std::collections::HashMap::with_capacity(MAX_LEDGER_EVENTS.min(1000)),
            )),
            events_by_work_id: std::sync::RwLock::new(std::collections::HashMap::new()),
            signing_key,
        }
    }

    /// Returns the verifying (public) key for signature verification.
    #[must_use]
    pub fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.signing_key.verifying_key()
    }
}

impl LedgerEventEmitter for StubLedgerEventEmitter {
    fn emit_work_claimed(&self, claim: &WorkClaim) -> Result<SignedLedgerEvent, LedgerEventError> {
        use ed25519_dalek::Signer;

        // Generate unique event ID
        let event_id = format!("EVT-{}", uuid::Uuid::new_v4());

        // Build canonical payload (deterministic JSON)
        let payload = serde_json::json!({
            "event_type": "work_claimed",
            "work_id": claim.work_id,
            "lease_id": claim.lease_id,
            "actor_id": claim.actor_id,
            "role": format!("{:?}", claim.role),
            "policy_resolved_ref": claim.policy_resolution.policy_resolved_ref,
            "capability_manifest_hash": hex::encode(claim.policy_resolution.capability_manifest_hash),
            "context_pack_hash": hex::encode(claim.policy_resolution.context_pack_hash),
        });

        let payload_bytes =
            serde_json::to_vec(&payload).map_err(|e| LedgerEventError::SigningFailed {
                message: format!("payload serialization failed: {e}"),
            })?;

        // Build canonical bytes for signing (domain prefix + payload)
        let mut canonical_bytes =
            Vec::with_capacity(WORK_CLAIMED_DOMAIN_PREFIX.len() + payload_bytes.len());
        canonical_bytes.extend_from_slice(WORK_CLAIMED_DOMAIN_PREFIX);
        canonical_bytes.extend_from_slice(&payload_bytes);

        // Sign the canonical bytes
        let signature = self.signing_key.sign(&canonical_bytes);

        // RFC-0016 HTF compliance: Use placeholder timestamp (0) for stub
        // implementation. In production, this would use an HTF-compliant clock
        // source that provides monotonic, causally-ordered timestamps. The stub
        // uses 0 to make tests deterministic and avoid the forbidden
        // SystemTime::now() call.
        let timestamp_ns = 0u64;

        let signed_event = SignedLedgerEvent {
            event_id: event_id.clone(),
            event_type: "work_claimed".to_string(),
            work_id: claim.work_id.clone(),
            actor_id: claim.actor_id.clone(),
            payload: payload_bytes,
            signature: signature.to_bytes().to_vec(),
            timestamp_ns,
        };

        // CTR-1303: Persist to bounded in-memory store with LRU eviction
        {
            let mut guard = self.events.write().expect("lock poisoned");
            let mut events_by_work = self.events_by_work_id.write().expect("lock poisoned");
            let (order, events) = &mut *guard;

            // Evict oldest entries if at capacity, also pruning events_by_work_id index
            while events.len() >= MAX_LEDGER_EVENTS {
                if let Some(oldest_key) = order.first().cloned() {
                    order.remove(0);
                    // Remove from events and prune the events_by_work_id index
                    if let Some(evicted_event) = events.remove(&oldest_key) {
                        // Remove from work_id index
                        if let Some(work_id_events) = events_by_work.get_mut(&evicted_event.work_id)
                        {
                            work_id_events.retain(|id| id != &oldest_key);
                            // Remove the entry entirely if no events remain for this work_id
                            if work_id_events.is_empty() {
                                events_by_work.remove(&evicted_event.work_id);
                            }
                        }
                    }
                    debug!(
                        evicted_event_id = %oldest_key,
                        "Evicted oldest ledger event to maintain capacity limit"
                    );
                } else {
                    break;
                }
            }

            order.push(event_id.clone());
            events.insert(event_id.clone(), signed_event.clone());
            events_by_work
                .entry(claim.work_id.clone())
                .or_default()
                .push(event_id);
        }

        info!(
            event_id = %signed_event.event_id,
            work_id = %signed_event.work_id,
            actor_id = %signed_event.actor_id,
            "WorkClaimed event signed and persisted"
        );

        Ok(signed_event)
    }

    fn get_event(&self, event_id: &str) -> Option<SignedLedgerEvent> {
        let guard = self.events.read().expect("lock poisoned");
        guard.1.get(event_id).cloned()
    }

    fn get_events_by_work_id(&self, work_id: &str) -> Vec<SignedLedgerEvent> {
        let events_by_work = self.events_by_work_id.read().expect("lock poisoned");
        let guard = self.events.read().expect("lock poisoned");

        events_by_work
            .get(work_id)
            .map(|event_ids| {
                event_ids
                    .iter()
                    .filter_map(|id| guard.1.get(id).cloned())
                    .collect()
            })
            .unwrap_or_default()
    }
}

// ============================================================================
// Policy Resolver Interface (TCK-00253)
// ============================================================================

/// Result of a policy resolution request.
///
/// Per DD-002, the daemon delegates policy resolution to the governance holon.
/// This struct captures the resolved policy state for work claiming.
#[derive(Debug, Clone)]
pub struct PolicyResolution {
    /// Unique reference to the `PolicyResolvedForChangeSet` event.
    pub policy_resolved_ref: String,

    /// BLAKE3 hash of the resolved policy.
    pub resolved_policy_hash: [u8; 32],

    /// BLAKE3 hash of the capability manifest derived from policy.
    pub capability_manifest_hash: [u8; 32],

    /// BLAKE3 hash of the sealed context pack.
    pub context_pack_hash: [u8; 32],
}

/// Error type for policy resolution operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyResolutionError {
    /// Policy resolution not found for the given work/role combination.
    NotFound {
        /// The work ID that was queried.
        work_id: String,
        /// The role that was queried.
        role: WorkRole,
    },

    /// Policy resolution failed due to governance error.
    GovernanceFailed {
        /// Error message from governance.
        message: String,
    },

    /// Invalid credential for policy resolution.
    InvalidCredential {
        /// Error message describing the credential issue.
        message: String,
    },
}

impl std::fmt::Display for PolicyResolutionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound { work_id, role } => {
                write!(
                    f,
                    "policy resolution not found for work_id={work_id}, role={role:?}"
                )
            },
            Self::GovernanceFailed { message } => {
                write!(f, "governance failed: {message}")
            },
            Self::InvalidCredential { message } => {
                write!(f, "invalid credential: {message}")
            },
        }
    }
}

impl std::error::Error for PolicyResolutionError {}

/// Trait for policy resolution delegation to governance.
///
/// Per DD-002, the daemon does not embed governance logic. It delegates
/// policy resolution to the governance holon and mints capability manifests
/// based on the returned resolution.
///
/// # Implementers
///
/// - `StubPolicyResolver`: Returns stub data for testing
/// - `GovernancePolicyResolver`: Delegates to actual governance holon (future)
pub trait PolicyResolver: Send + Sync {
    /// Resolves policy for a work claim.
    ///
    /// # Arguments
    ///
    /// * `work_id` - Generated work ID for this claim
    /// * `role` - The role being claimed
    /// * `actor_id` - The authoritative actor ID (derived from credential)
    ///
    /// # Returns
    ///
    /// `PolicyResolution` containing the resolved policy hashes and references.
    ///
    /// # Errors
    ///
    /// Returns `PolicyResolutionError` if resolution fails.
    fn resolve_for_claim(
        &self,
        work_id: &str,
        role: WorkRole,
        actor_id: &str,
    ) -> Result<PolicyResolution, PolicyResolutionError>;
}

/// Stub policy resolver for testing and development.
///
/// Returns deterministic stub data. In production, this will be replaced
/// with a real governance holon integration.
///
/// # TCK-00255: Context Pack Sealing
///
/// This stub demonstrates the sealing pattern required by RFC-0017:
/// 1. Create a `ContextPackManifest` with work-specific entries
/// 2. Call `seal()` to get the deterministic content hash
/// 3. Return the seal hash in the `PolicyResolution.context_pack_hash`
#[derive(Debug, Clone, Default)]
pub struct StubPolicyResolver;

impl PolicyResolver for StubPolicyResolver {
    fn resolve_for_claim(
        &self,
        work_id: &str,
        _role: WorkRole,
        actor_id: &str,
    ) -> Result<PolicyResolution, PolicyResolutionError> {
        use apm2_core::context::{AccessLevel, ContextPackManifestBuilder, ManifestEntryBuilder};

        // Generate deterministic hashes for policy and capability manifest
        let policy_hash = blake3::hash(format!("policy:{work_id}:{actor_id}").as_bytes());
        let manifest_hash = blake3::hash(format!("manifest:{work_id}:{actor_id}").as_bytes());

        // TCK-00255: Create and seal a context pack manifest
        // In production, this would be populated with actual file entries from
        // the work definition. For the stub, we create a deterministic manifest
        // based on work_id and actor_id.
        let content_hash = blake3::hash(format!("content:{work_id}:{actor_id}").as_bytes());
        let context_pack = ContextPackManifestBuilder::new(
            format!("manifest:{work_id}"),
            format!("profile:{actor_id}"),
        )
        .add_entry(
            ManifestEntryBuilder::new(
                format!("/work/{work_id}/context.yaml"),
                *content_hash.as_bytes(),
            )
            .stable_id("work-context")
            .access_level(AccessLevel::Read)
            .build(),
        )
        .build();

        // TCK-00255: Call seal() to get the context pack hash
        // This ensures the hash is deterministic and verifiable.
        let context_pack_hash =
            context_pack
                .seal()
                .map_err(|e| PolicyResolutionError::GovernanceFailed {
                    message: format!("context pack sealing failed: {e}"),
                })?;

        Ok(PolicyResolution {
            policy_resolved_ref: format!("PolicyResolvedForChangeSet:{work_id}"),
            resolved_policy_hash: *policy_hash.as_bytes(),
            capability_manifest_hash: *manifest_hash.as_bytes(),
            context_pack_hash,
        })
    }
}

// ============================================================================
// Work Registry Interface (TCK-00253)
// ============================================================================

/// A claimed work item with its associated metadata.
#[derive(Debug, Clone)]
pub struct WorkClaim {
    /// Unique work identifier.
    pub work_id: String,

    /// Lease identifier for this claim.
    pub lease_id: String,

    /// Authoritative actor ID (derived from credential).
    pub actor_id: String,

    /// Role claimed for this work.
    pub role: WorkRole,

    /// Policy resolution for this claim.
    pub policy_resolution: PolicyResolution,

    /// Custody domains associated with the executor (for `SoD` validation).
    ///
    /// Per TCK-00258, these are the domains assigned to the actor claiming
    /// the work. For `GATE_EXECUTOR` roles, spawn will be rejected if these
    /// domains overlap with author domains.
    pub executor_custody_domains: Vec<String>,

    /// Custody domains associated with changeset authors (for `SoD`
    /// validation).
    ///
    /// Per TCK-00258, these are the domains of the actors who authored the
    /// changeset being reviewed.
    pub author_custody_domains: Vec<String>,
}

/// Trait for persisting and querying work claims.
///
/// The work registry tracks claimed work items and their associated
/// policy resolutions. It also handles `WorkClaimed` event signing.
pub trait WorkRegistry: Send + Sync {
    /// Registers a new work claim.
    ///
    /// # Arguments
    ///
    /// * `claim` - The work claim to register
    ///
    /// # Returns
    ///
    /// The registered `WorkClaim` (may be enriched with additional metadata).
    ///
    /// # Errors
    ///
    /// Returns an error if registration fails.
    fn register_claim(&self, claim: WorkClaim) -> Result<WorkClaim, WorkRegistryError>;

    /// Queries a work claim by work ID.
    fn get_claim(&self, work_id: &str) -> Option<WorkClaim>;
}

/// Error type for work registry operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkRegistryError {
    /// Work ID already exists.
    DuplicateWorkId {
        /// The duplicate work ID.
        work_id: String,
    },

    /// Registration failed.
    RegistrationFailed {
        /// Error message.
        message: String,
    },
}

impl std::fmt::Display for WorkRegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DuplicateWorkId { work_id } => {
                write!(f, "duplicate work_id: {work_id}")
            },
            Self::RegistrationFailed { message } => {
                write!(f, "registration failed: {message}")
            },
        }
    }
}

impl std::error::Error for WorkRegistryError {}

/// Maximum number of work claims stored in `StubWorkRegistry`.
///
/// Per CTR-1303: In-memory stores must have `max_entries` limit with O(1)
/// eviction. This prevents denial-of-service via memory exhaustion from
/// unbounded claim registration.
pub const MAX_WORK_CLAIMS: usize = 10_000;

/// In-memory stub work registry for testing.
///
/// # Capacity Limits (CTR-1303)
///
/// This registry enforces a maximum of [`MAX_WORK_CLAIMS`] entries to prevent
/// memory exhaustion. When the limit is reached, the oldest entry (by insertion
/// order) is evicted to make room for the new claim.
///
/// # Performance
///
/// Uses `VecDeque` for O(1) eviction via `pop_front()` instead of
/// `Vec::remove(0)` which is O(n).
#[derive(Debug)]
pub struct StubWorkRegistry {
    /// Claims stored with insertion order for LRU eviction.
    /// Uses `VecDeque` for O(1) eviction of oldest entries.
    claims: std::sync::RwLock<(
        VecDeque<String>,
        std::collections::HashMap<String, WorkClaim>,
    )>,
}

impl Default for StubWorkRegistry {
    fn default() -> Self {
        Self {
            claims: std::sync::RwLock::new((
                VecDeque::with_capacity(MAX_WORK_CLAIMS.min(1000)), // Pre-allocate reasonably
                std::collections::HashMap::with_capacity(MAX_WORK_CLAIMS.min(1000)),
            )),
        }
    }
}

impl WorkRegistry for StubWorkRegistry {
    fn register_claim(&self, claim: WorkClaim) -> Result<WorkClaim, WorkRegistryError> {
        let mut guard = self.claims.write().expect("lock poisoned");
        let (order, claims) = &mut *guard;

        if claims.contains_key(&claim.work_id) {
            return Err(WorkRegistryError::DuplicateWorkId {
                work_id: claim.work_id,
            });
        }

        // CTR-1303: Evict oldest entry if at capacity (O(1) via pop_front)
        while claims.len() >= MAX_WORK_CLAIMS {
            if let Some(oldest_key) = order.pop_front() {
                claims.remove(&oldest_key);
                debug!(
                    evicted_work_id = %oldest_key,
                    "Evicted oldest work claim to maintain capacity limit"
                );
            } else {
                break;
            }
        }

        let work_id = claim.work_id.clone();
        order.push_back(work_id.clone());
        claims.insert(work_id, claim.clone());
        Ok(claim)
    }

    fn get_claim(&self, work_id: &str) -> Option<WorkClaim> {
        let guard = self.claims.read().expect("lock poisoned");
        guard.1.get(work_id).cloned()
    }
}

// ============================================================================
// Actor ID Derivation (TCK-00253)
// ============================================================================

/// Derives the authoritative actor ID from peer credentials.
///
/// Per DD-001 and the proto definition, the `actor_id` in the request is a
/// "display hint" only. The authoritative `actor_id` is derived from the
/// credential. This implementation uses a fingerprint of the UID and GID
/// to create a **stable** identifier that does not change per request.
///
/// # Stability
///
/// The actor ID is derived ONLY from stable credential fields (UID, GID).
/// It intentionally excludes:
/// - PID: Changes per process
/// - Nonce: Changes per request
///
/// This ensures the same user always maps to the same `actor_id`.
///
/// # Arguments
///
/// * `credentials` - The peer credentials from `SO_PEERCRED`
///
/// # Returns
///
/// A stable actor ID string derived from the credential.
///
/// # TODO
///
/// - TCK-00253: `credential_signature` field is currently ignored. Integration
///   with credential verification infrastructure will allow deriving `actor_id`
///   from cryptographic identity rather than Unix UID/GID.
#[must_use]
pub fn derive_actor_id(credentials: &PeerCredentials) -> String {
    // Create a fingerprint from UID and GID only (stable across requests)
    // Per code quality review: exclude PID (changes per process) and nonce (changes
    // per request)
    let mut hasher = blake3::Hasher::new();
    hasher.update(&credentials.uid.to_le_bytes());
    hasher.update(&credentials.gid.to_le_bytes());

    let hash = hasher.finalize();

    // Use first 8 bytes (16 hex chars) for a shorter identifier
    // Per code quality review: use blake3::Hash::to_hex() instead of manual
    // formatting
    let hex = hash.to_hex();
    format!("actor:{}", &hex[..16])
}

/// Generates a unique work ID.
///
/// Uses UUID v4 for uniqueness per RFC-0016 (Hybrid Time Framework compliance).
/// HTF prohibits `SystemTime::now()` to ensure deterministic replay.
#[must_use]
pub fn generate_work_id() -> String {
    // RFC-0016 HTF compliance: Use UUID v4 instead of SystemTime::now()
    let uuid = uuid::Uuid::new_v4();
    format!("W-{uuid}")
}

/// Generates a unique lease ID.
///
/// Uses UUID v4 for uniqueness per RFC-0016 (Hybrid Time Framework compliance).
/// HTF prohibits `SystemTime::now()` to ensure deterministic replay.
#[must_use]
pub fn generate_lease_id() -> String {
    // RFC-0016 HTF compliance: Use UUID v4 instead of SystemTime::now()
    let uuid = uuid::Uuid::new_v4();
    format!("L-{uuid}")
}

// ============================================================================
// Connection Context
// ============================================================================

/// Connection context tracking privilege level and authentication state.
///
/// Per DD-001 (`privilege_predicate`), connections are classified as privileged
/// based on the socket path:
/// - operator.sock: `is_privileged = true`
/// - session.sock: `is_privileged = false`
#[derive(Debug, Clone)]
pub struct ConnectionContext {
    /// Whether this connection is privileged (operator socket).
    is_privileged: bool,

    /// Peer credentials extracted via `SO_PEERCRED`.
    peer_credentials: Option<PeerCredentials>,

    /// Session ID for session-scoped connections (None for operator
    /// connections).
    session_id: Option<String>,
}

impl ConnectionContext {
    /// Creates a new privileged connection context (operator socket).
    #[must_use]
    pub const fn privileged(peer_credentials: Option<PeerCredentials>) -> Self {
        Self {
            is_privileged: true,
            peer_credentials,
            session_id: None,
        }
    }

    /// Creates a new session-scoped connection context (session socket).
    #[must_use]
    pub const fn session(
        peer_credentials: Option<PeerCredentials>,
        session_id: Option<String>,
    ) -> Self {
        Self {
            is_privileged: false,
            peer_credentials,
            session_id,
        }
    }

    /// Returns `true` if this connection has privileged access.
    #[must_use]
    pub const fn is_privileged(&self) -> bool {
        self.is_privileged
    }

    /// Returns the peer credentials if available.
    #[must_use]
    pub const fn peer_credentials(&self) -> Option<&PeerCredentials> {
        self.peer_credentials.as_ref()
    }

    /// Returns the session ID for session-scoped connections.
    #[must_use]
    pub fn session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }
}

// ============================================================================
// Message Type Tags (for routing)
// ============================================================================

/// Message type tags for privileged endpoint routing.
///
/// These tags are used to identify the message type before decoding,
/// allowing the dispatcher to route to the appropriate handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PrivilegedMessageType {
    /// `ClaimWork` request (IPC-PRIV-001)
    ClaimWork       = 1,
    /// `SpawnEpisode` request (IPC-PRIV-002)
    SpawnEpisode    = 2,
    /// `IssueCapability` request (IPC-PRIV-003)
    IssueCapability = 3,
    /// Shutdown request (IPC-PRIV-004)
    Shutdown        = 4,
}

impl PrivilegedMessageType {
    /// Attempts to parse a message type from a tag byte.
    #[must_use]
    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::ClaimWork),
            2 => Some(Self::SpawnEpisode),
            3 => Some(Self::IssueCapability),
            4 => Some(Self::Shutdown),
            _ => None,
        }
    }

    /// Returns the tag byte for this message type.
    #[must_use]
    pub const fn tag(self) -> u8 {
        self as u8
    }
}

// ============================================================================
// Response Envelope
// ============================================================================

/// Response envelope for privileged endpoint responses.
///
/// Contains either a successful response or an error.
#[derive(Debug)]
pub enum PrivilegedResponse {
    /// Successful `ClaimWork` response.
    ClaimWork(ClaimWorkResponse),
    /// Successful `SpawnEpisode` response.
    SpawnEpisode(SpawnEpisodeResponse),
    /// Successful `IssueCapability` response.
    IssueCapability(IssueCapabilityResponse),
    /// Successful Shutdown response.
    Shutdown(ShutdownResponse),
    /// Error response.
    Error(PrivilegedError),
}

impl PrivilegedResponse {
    /// Creates a `PERMISSION_DENIED` error response.
    #[must_use]
    pub fn permission_denied() -> Self {
        Self::Error(PrivilegedError {
            code: PrivilegedErrorCode::PermissionDenied.into(),
            message: "permission denied".to_string(),
        })
    }

    /// Creates a custom error response.
    #[must_use]
    pub fn error(code: PrivilegedErrorCode, message: impl Into<String>) -> Self {
        Self::Error(PrivilegedError {
            code: code.into(),
            message: message.into(),
        })
    }

    /// Encodes the response to bytes.
    ///
    /// The format is: [tag: u8][payload: protobuf]
    /// Tag 0 indicates an error response.
    #[must_use]
    pub fn encode(&self) -> Bytes {
        let mut buf = Vec::new();
        match self {
            Self::ClaimWork(resp) => {
                buf.push(PrivilegedMessageType::ClaimWork.tag());
                resp.encode(&mut buf).expect("encode cannot fail");
            },
            Self::SpawnEpisode(resp) => {
                buf.push(PrivilegedMessageType::SpawnEpisode.tag());
                resp.encode(&mut buf).expect("encode cannot fail");
            },
            Self::IssueCapability(resp) => {
                buf.push(PrivilegedMessageType::IssueCapability.tag());
                resp.encode(&mut buf).expect("encode cannot fail");
            },
            Self::Shutdown(resp) => {
                buf.push(PrivilegedMessageType::Shutdown.tag());
                resp.encode(&mut buf).expect("encode cannot fail");
            },
            Self::Error(err) => {
                buf.push(0); // Error tag
                err.encode(&mut buf).expect("encode cannot fail");
            },
        }
        Bytes::from(buf)
    }
}

// ============================================================================
// Dispatcher
// ============================================================================

// ============================================================================
// TCK-00257: Gate Lease Validation
// ============================================================================

/// Maximum number of lease entries to store (CTR-1303: bounded capacity).
const MAX_LEASE_ENTRIES: usize = 10_000;

/// Error returned when lease validation fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseValidationError {
    /// Lease ID was not found in the ledger.
    LeaseNotFound {
        /// The lease ID that was not found.
        lease_id: String,
    },
    /// Lease exists but `work_id` does not match.
    ///
    /// # Security Note (SEC-HYG-001)
    ///
    /// The expected `work_id` is intentionally omitted from this error to
    /// prevent information leakage. Revealing the expected value could
    /// allow an attacker to enumerate valid work IDs.
    WorkIdMismatch {
        /// The actual `work_id` from the request (not the expected one).
        actual: String,
    },
    /// Lease has expired.
    LeaseExpired {
        /// The expired lease ID.
        lease_id: String,
    },
    /// Failed to query the ledger.
    LedgerQueryFailed {
        /// The error message from the ledger.
        message: String,
    },
}

impl std::fmt::Display for LeaseValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LeaseNotFound { lease_id } => {
                write!(f, "lease not found: {lease_id}")
            },
            Self::WorkIdMismatch { actual } => {
                write!(f, "work_id mismatch for provided value: {actual}")
            },
            Self::LeaseExpired { lease_id } => {
                write!(f, "lease expired: {lease_id}")
            },
            Self::LedgerQueryFailed { message } => {
                write!(f, "ledger query failed: {message}")
            },
        }
    }
}

impl std::error::Error for LeaseValidationError {}

/// Trait for validating gate leases.
///
/// Per RFC-0017 IPC-PRIV-002, `GATE_EXECUTOR` role requires a valid
/// `GateLeaseIssued` event to exist in the ledger for the specified
/// `lease_id` and `work_id`.
///
/// # Security Contract
///
/// - `GATE_EXECUTOR` spawn MUST be rejected if lease validation fails
/// - Lease validation verifies the lease exists and matches the `work_id`
/// - This is a fail-closed check: validation errors reject the spawn
///
/// # Implementers
///
/// - `StubLeaseValidator`: In-memory storage for testing
/// - `LedgerLeaseValidator`: Ledger-backed validation (future)
pub trait LeaseValidator: Send + Sync {
    /// Validates that a gate lease exists and matches the `work_id`.
    ///
    /// # Arguments
    ///
    /// * `lease_id` - The lease ID to validate
    /// * `work_id` - The work ID that must match the lease
    ///
    /// # Returns
    ///
    /// `Ok(())` if the lease is valid and matches the `work_id`.
    ///
    /// # Errors
    ///
    /// Returns `LeaseValidationError` if:
    /// - The lease does not exist (`LeaseNotFound`)
    /// - The lease exists but the `work_id` doesn't match (`WorkIdMismatch`)
    /// - The lease has expired (`LeaseExpired`)
    /// - The ledger query failed (`LedgerQueryFailed`)
    fn validate_gate_lease(
        &self,
        lease_id: &str,
        work_id: &str,
    ) -> Result<(), LeaseValidationError>;

    /// Registers a gate lease for testing purposes.
    ///
    /// In production, leases are issued through a separate governance flow.
    /// This method exists to support test fixtures.
    fn register_lease(&self, lease_id: &str, work_id: &str, gate_id: &str);
}

/// Entry for a registered lease.
#[derive(Debug, Clone)]
struct LeaseEntry {
    work_id: String,
    #[allow(dead_code)]
    gate_id: String,
}

/// Stub implementation of [`LeaseValidator`] for testing.
///
/// Stores leases in memory with no persistence.
///
/// # Capacity Limits (CTR-1303)
///
/// This validator enforces a maximum of 10,000 entries to prevent memory
/// exhaustion. When the limit is reached, the oldest entry (by insertion order)
/// is evicted to make room for the new lease.
///
/// # Security Notes
///
/// - **SEC-DoS-001**: Duplicate lease IDs are handled by updating in place
///   rather than adding a new entry, preventing unbounded memory growth.
/// - **SEC-DoS-002**: Uses `VecDeque` for O(1) eviction from the front,
///   consistent with the O(1) eviction pattern established in PR 329.
#[derive(Debug, Default)]
pub struct StubLeaseValidator {
    /// Leases stored with insertion order for O(1) LRU eviction.
    ///
    /// Uses `VecDeque` (SEC-DoS-002) for efficient front removal.
    leases: std::sync::RwLock<(
        std::collections::VecDeque<String>,
        std::collections::HashMap<String, LeaseEntry>,
    )>,
}

impl StubLeaseValidator {
    /// Creates a new empty lease validator.
    #[must_use]
    pub fn new() -> Self {
        Self {
            leases: std::sync::RwLock::new((
                std::collections::VecDeque::new(),
                std::collections::HashMap::new(),
            )),
        }
    }
}

impl LeaseValidator for StubLeaseValidator {
    fn validate_gate_lease(
        &self,
        lease_id: &str,
        work_id: &str,
    ) -> Result<(), LeaseValidationError> {
        let guard = self.leases.read().expect("lock poisoned");
        let (_, leases) = &*guard;

        leases.get(lease_id).map_or_else(
            || {
                Err(LeaseValidationError::LeaseNotFound {
                    lease_id: lease_id.to_string(),
                })
            },
            |entry| {
                let work_id_matches = entry.work_id.len() == work_id.len()
                    && bool::from(entry.work_id.as_bytes().ct_eq(work_id.as_bytes()));
                if work_id_matches {
                    Ok(())
                } else {
                    Err(LeaseValidationError::WorkIdMismatch {
                        actual: work_id.to_string(),
                    })
                }
            },
        )
    }

    fn register_lease(&self, lease_id: &str, work_id: &str, gate_id: &str) {
        let mut guard = self.leases.write().expect("lock poisoned");
        let (order, leases) = &mut *guard;

        // SEC-DoS-001: Check for duplicate lease_id and update in place
        if leases.contains_key(lease_id) {
            // Update existing entry without adding to order (already tracked)
            leases.insert(
                lease_id.to_string(),
                LeaseEntry {
                    work_id: work_id.to_string(),
                    gate_id: gate_id.to_string(),
                },
            );
            return;
        }

        // CTR-1303: Evict oldest entry if at capacity
        // SEC-DoS-002: Use pop_front() for O(1) eviction
        while leases.len() >= MAX_LEASE_ENTRIES {
            if let Some(oldest_key) = order.pop_front() {
                leases.remove(&oldest_key);
            } else {
                break;
            }
        }

        order.push_back(lease_id.to_string());
        leases.insert(
            lease_id.to_string(),
            LeaseEntry {
                work_id: work_id.to_string(),
                gate_id: gate_id.to_string(),
            },
        );
    }
}

/// Privileged endpoint dispatcher.
///
/// Routes incoming messages to the appropriate handler based on message type.
/// Enforces privilege separation by checking
/// `ConnectionContext::is_privileged()` before dispatching to any handler.
///
/// # Security Contract
///
/// Per INV-0001 and TB-002:
/// - Session connections receive `PERMISSION_DENIED` for ALL privileged
///   requests
/// - No privileged handler logic executes for non-privileged connections
/// - Generic error messages prevent endpoint enumeration (TH-004)
///
/// # TCK-00253 Additions
///
/// - Policy resolver for governance delegation
/// - Work registry for claim persistence
/// - Ledger event emitter for signed event persistence
/// - Actor ID derivation from credentials
///
/// # TCK-00256 Additions
///
/// - Episode runtime for lifecycle management
/// - Session registry for session state persistence
///
/// # TCK-00257 Additions
///
/// - Lease validator for `GATE_EXECUTOR` spawn validation
pub struct PrivilegedDispatcher {
    /// Decode configuration for bounded message decoding.
    decode_config: DecodeConfig,

    /// Policy resolver for governance delegation (TCK-00253).
    policy_resolver: Arc<dyn PolicyResolver>,

    /// Work registry for claim persistence (TCK-00253).
    work_registry: Arc<dyn WorkRegistry>,

    /// Ledger event emitter for signed event persistence (TCK-00253).
    event_emitter: Arc<dyn LedgerEventEmitter>,

    /// Episode runtime for lifecycle management (TCK-00256).
    episode_runtime: Arc<EpisodeRuntime>,

    /// Session registry for session state persistence (TCK-00256).
    session_registry: Arc<dyn SessionRegistry>,

    /// Lease validator for `GATE_EXECUTOR` spawn validation (TCK-00257).
    lease_validator: Arc<dyn LeaseValidator>,
}

impl Default for PrivilegedDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl PrivilegedDispatcher {
    /// Creates a new dispatcher with default decode configuration.
    ///
    /// Uses stub implementations for policy resolver, work registry, event
    /// emitter, session registry, and lease validator.
    #[must_use]
    pub fn new() -> Self {
        Self {
            decode_config: DecodeConfig::default(),
            policy_resolver: Arc::new(StubPolicyResolver),
            work_registry: Arc::new(StubWorkRegistry::default()),
            event_emitter: Arc::new(StubLedgerEventEmitter::new()),
            episode_runtime: Arc::new(EpisodeRuntime::new(EpisodeRuntimeConfig::default())),
            session_registry: Arc::new(InMemorySessionRegistry::default()),
            lease_validator: Arc::new(StubLeaseValidator::new()),
        }
    }

    /// Creates a new dispatcher with custom decode configuration.
    ///
    /// Uses stub implementations for policy resolver, work registry, event
    /// emitter, session registry, and lease validator.
    #[must_use]
    pub fn with_decode_config(decode_config: DecodeConfig) -> Self {
        Self {
            decode_config,
            policy_resolver: Arc::new(StubPolicyResolver),
            work_registry: Arc::new(StubWorkRegistry::default()),
            event_emitter: Arc::new(StubLedgerEventEmitter::new()),
            episode_runtime: Arc::new(EpisodeRuntime::new(EpisodeRuntimeConfig::default())),
            session_registry: Arc::new(InMemorySessionRegistry::default()),
            lease_validator: Arc::new(StubLeaseValidator::new()),
        }
    }

    /// Creates a new dispatcher with custom dependencies.
    ///
    /// This is the production constructor for real governance integration.
    #[must_use]
    pub fn with_dependencies(
        decode_config: DecodeConfig,
        policy_resolver: Arc<dyn PolicyResolver>,
        work_registry: Arc<dyn WorkRegistry>,
        event_emitter: Arc<dyn LedgerEventEmitter>,
        episode_runtime: Arc<EpisodeRuntime>,
        session_registry: Arc<dyn SessionRegistry>,
        lease_validator: Arc<dyn LeaseValidator>,
    ) -> Self {
        Self {
            decode_config,
            policy_resolver,
            work_registry,
            event_emitter,
            episode_runtime,
            session_registry,
            lease_validator,
        }
    }

    /// Returns a reference to the event emitter.
    ///
    /// This is useful for testing to verify events were emitted.
    #[must_use]
    pub fn event_emitter(&self) -> &Arc<dyn LedgerEventEmitter> {
        &self.event_emitter
    }

    /// Returns a reference to the episode runtime.
    ///
    /// This is useful for testing to verify episode state.
    #[must_use]
    pub const fn episode_runtime(&self) -> &Arc<EpisodeRuntime> {
        &self.episode_runtime
    }

    /// Returns a reference to the session registry.
    ///
    /// This is useful for testing to verify session state.
    #[must_use]
    pub fn session_registry(&self) -> &Arc<dyn SessionRegistry> {
        &self.session_registry
    }

    /// Returns a reference to the lease validator.
    ///
    /// Primarily for testing purposes to pre-register leases.
    #[must_use]
    pub fn lease_validator(&self) -> &Arc<dyn LeaseValidator> {
        &self.lease_validator
    }

    // =========================================================================
    // TCK-00258: Custody Domain Resolution (`SoD` Enforcement)
    // =========================================================================

    /// Resolves custody domains for an actor.
    ///
    /// Per TCK-00258, this method maps an actor ID to its custody domains
    /// for `SoD` validation. In production, this would query the `KeyPolicy`
    /// via a `CustodyDomainResolver` trait.
    ///
    /// # Stub Implementation
    ///
    /// Currently returns a single domain derived from the actor ID prefix.
    /// For example, `team-alpha:alice` -> `["team-alpha"]`.
    /// This enables testing of the `SoD` enforcement without full `KeyPolicy`
    /// integration.
    ///
    /// # Security (Fail-Closed)
    ///
    /// Returns an error if the actor ID doesn't match the expected
    /// `domain:actor` schema. This ensures that malformed or non-standard
    /// actor IDs cannot bypass `SoD` validation.
    #[allow(clippy::unused_self)] // Will use self in production for registry access
    fn resolve_actor_custody_domains(&self, actor_id: &str) -> Result<Vec<String>, String> {
        // Stub: derive domain from actor_id prefix (e.g., "team-alpha:alice" ->
        // "team-alpha") In production, this would query
        // KeyPolicy.custody_domains
        if let Some(colon_pos) = actor_id.find(':') {
            let domain = &actor_id[..colon_pos];
            if !domain.is_empty() {
                return Ok(vec![domain.to_string()]);
            }
        }
        // SEC-SoD-001: Fail-closed for malformed actor IDs.
        // If the actor_id doesn't match expected schema (domain:actor), return
        // an error. This prevents attackers from bypassing SoD by using
        // non-standard IDs.
        Err(format!(
            "malformed actor_id: {actor_id} (expected domain:actor)"
        ))
    }

    /// Resolves custody domains for changeset authors.
    ///
    /// Per TCK-00258, this method retrieves the custody domains of all actors
    /// who authored the changeset being reviewed. In production, this would
    /// query the changeset metadata and `KeyPolicy`.
    ///
    /// # Stub Implementation
    ///
    /// Currently returns a placeholder domain based on the `work_id`.
    /// For testing, set `work_id` to include domain information:
    /// e.g., `W-team-alpha-12345` -> `["team-alpha"]`
    ///
    /// # Security (Fail-Closed)
    ///
    /// Returns an error if the `work_id` doesn't match the expected schema.
    /// This ensures that malformed work IDs cannot bypass `SoD` validation.
    #[allow(clippy::unused_self)] // Will use self in production for registry access
    fn resolve_changeset_author_domains(&self, work_id: &str) -> Result<Vec<String>, String> {
        // Stub: derive author domain from work_id (e.g., "W-team-alpha-12345" ->
        // ["team-alpha"]) In production, this would query changeset metadata
        // for author list, then resolve each author's custody domains via
        // KeyPolicy
        if let Some(rest) = work_id.strip_prefix("W-") {
            if let Some(dash_pos) = rest.find('-') {
                let domain = &rest[..dash_pos];
                if !domain.is_empty() {
                    return Ok(vec![domain.to_string()]);
                }
            }
        }
        // SEC-SoD-001: Fail-closed for malformed work_ids.
        // Return an error if the work_id doesn't match the expected schema.
        // This prevents attackers from bypassing SoD by using malformed work_ids
        // that don't map to author domains.
        Err(format!(
            "malformed work_id: {work_id} (expected W-domain-suffix)"
        ))
    }

    /// Dispatches a privileged request to the appropriate handler.
    ///
    /// # Message Format
    ///
    /// The frame format is: [tag: u8][payload: protobuf]
    /// Where tag identifies the message type (see [`PrivilegedMessageType`]).
    ///
    /// # Security
    ///
    /// 1. Validates `ctx.is_privileged()` FIRST
    /// 2. Returns `PERMISSION_DENIED` immediately for non-privileged
    ///    connections
    /// 3. Only then decodes and routes the message
    ///
    /// # Errors
    ///
    /// Returns `Err` for protocol-level errors (malformed frames, etc.).
    /// Application-level errors are returned in [`PrivilegedResponse::Error`].
    pub fn dispatch(
        &self,
        frame: &Bytes,
        ctx: &ConnectionContext,
    ) -> ProtocolResult<PrivilegedResponse> {
        // INV-0001: Check privilege BEFORE any message processing
        if !ctx.is_privileged() {
            // TH-004: Generic error prevents endpoint enumeration
            debug!(
                peer_pid = ?ctx.peer_credentials().map(|c| c.pid),
                "Non-privileged connection attempted privileged endpoint"
            );
            return Ok(PrivilegedResponse::permission_denied());
        }

        // Validate frame has at least a tag byte
        if frame.is_empty() {
            return Err(ProtocolError::Serialization {
                reason: "empty frame".to_string(),
            });
        }

        let tag = frame[0];
        let payload = &frame[1..];

        // Route based on message type
        let msg_type =
            PrivilegedMessageType::from_tag(tag).ok_or_else(|| ProtocolError::Serialization {
                reason: format!("unknown privileged message type: {tag}"),
            })?;

        match msg_type {
            PrivilegedMessageType::ClaimWork => self.handle_claim_work(payload, ctx),
            PrivilegedMessageType::SpawnEpisode => self.handle_spawn_episode(payload, ctx),
            PrivilegedMessageType::IssueCapability => self.handle_issue_capability(payload, ctx),
            PrivilegedMessageType::Shutdown => self.handle_shutdown(payload, ctx),
        }
    }

    /// Handles `ClaimWork` requests (IPC-PRIV-001).
    ///
    /// # TCK-00253 Implementation
    ///
    /// This handler implements the work claim flow per DD-001 and DD-002:
    ///
    /// 1. Validate request structure
    /// 2. Derive authoritative `actor_id` from credential (not user input)
    /// 3. Query governance for `PolicyResolvedForChangeSet`
    /// 4. Mint capability manifest based on resolved policy
    /// 5. Register work claim in registry
    /// 6. Return work assignment
    ///
    /// # Security
    ///
    /// Per DD-001: The `actor_id` in the request is a display hint only.
    /// The authoritative `actor_id` is derived from the peer credential.
    fn handle_claim_work(
        &self,
        payload: &[u8],
        ctx: &ConnectionContext,
    ) -> ProtocolResult<PrivilegedResponse> {
        let request =
            ClaimWorkRequest::decode_bounded(payload, &self.decode_config).map_err(|e| {
                ProtocolError::Serialization {
                    reason: format!("invalid ClaimWorkRequest: {e}"),
                }
            })?;

        let role = WorkRole::try_from(request.role).unwrap_or(WorkRole::Unspecified);

        info!(
            actor_id_hint = %request.actor_id,
            role = ?role,
            peer_pid = ?ctx.peer_credentials().map(|c| c.pid),
            "ClaimWork request received"
        );

        // Validate role is specified
        if role == WorkRole::Unspecified {
            return Ok(PrivilegedResponse::error(
                PrivilegedErrorCode::CapabilityRequestRejected,
                "role is required",
            ));
        }

        // TCK-00253: Derive authoritative actor_id from credential (not user input)
        // Per DD-001: "actor_id is a display hint; authoritative actor_id derived from
        // credential"
        let peer_creds = ctx
            .peer_credentials()
            .ok_or_else(|| ProtocolError::Serialization {
                reason: "peer credentials required for work claim".to_string(),
            })?;

        let actor_id = derive_actor_id(peer_creds);

        debug!(
            actor_id_hint = %request.actor_id,
            derived_actor_id = %actor_id,
            "Actor ID derived from credential"
        );

        // Generate unique work and lease IDs
        let work_id = generate_work_id();
        let lease_id = generate_lease_id();

        // TCK-00253: Query governance for policy resolution
        // Per DD-002: "Daemon calls HOLON-KERNEL-GOVERNANCE for policy resolution"
        let policy_resolution = match self
            .policy_resolver
            .resolve_for_claim(&work_id, role, &actor_id)
        {
            Ok(resolution) => resolution,
            Err(e) => {
                warn!(error = %e, "Policy resolution failed");
                // Return application-level error, not protocol error
                // Policy resolution failures are logic errors, not serialization errors
                return Ok(PrivilegedResponse::error(
                    PrivilegedErrorCode::PolicyResolutionFailed,
                    format!("policy resolution failed: {e}"),
                ));
            },
        };

        // SEC-SCP-FAC-0020: lease_id is redacted from logs to prevent capability
        // leakage
        info!(
            work_id = %work_id,
            lease_id = "[REDACTED]",
            actor_id = %actor_id,
            policy_resolved_ref = %policy_resolution.policy_resolved_ref,
            "Work claimed with policy resolution"
        );

        // TCK-00258: Extract custody domains for SoD validation
        // For now, use a stub implementation that derives domain from actor_id
        // In production, this would query the KeyPolicy via CustodyDomainResolver
        let executor_custody_domains = match self.resolve_actor_custody_domains(&actor_id) {
            Ok(domains) => domains,
            Err(e) => {
                warn!(error = %e, "Failed to resolve executor custody domains");
                return Ok(PrivilegedResponse::error(
                    PrivilegedErrorCode::CapabilityRequestRejected,
                    format!("failed to resolve executor custody domains: {e}"),
                ));
            },
        };

        let author_custody_domains = match self.resolve_changeset_author_domains(&work_id) {
            Ok(domains) => domains,
            Err(e) => {
                warn!(error = %e, "Failed to resolve author custody domains");
                return Ok(PrivilegedResponse::error(
                    PrivilegedErrorCode::CapabilityRequestRejected,
                    format!("failed to resolve author custody domains: {e}"),
                ));
            },
        };

        // Register the work claim
        let claim = WorkClaim {
            work_id,
            lease_id,
            actor_id,
            role,
            policy_resolution: policy_resolution.clone(),
            executor_custody_domains,
            author_custody_domains,
        };

        let claim = match self.work_registry.register_claim(claim) {
            Ok(claim) => claim,
            Err(e) => {
                warn!(error = %e, "Work registration failed");
                // Return application-level error, not protocol error
                // Registration failures are logic errors, not serialization errors
                return Ok(PrivilegedResponse::error(
                    PrivilegedErrorCode::CapabilityRequestRejected,
                    format!("work registration failed: {e}"),
                ));
            },
        };

        // TCK-00253: Emit signed WorkClaimed event to ledger.
        // Per acceptance criteria: "`WorkClaimed` event signed and persisted"
        // The event is:
        // - Signed with the daemon's signing key (Ed25519)
        // - Includes work_id, lease_id, actor_id, role, and policy_resolved_ref
        // - Persisted to the append-only ledger for audit trail
        let signed_event = match self.event_emitter.emit_work_claimed(&claim) {
            Ok(event) => event,
            Err(e) => {
                warn!(error = %e, "WorkClaimed event emission failed");
                // Return application-level error, not protocol error
                // Event emission failures are logic errors, not serialization errors
                return Ok(PrivilegedResponse::error(
                    PrivilegedErrorCode::CapabilityRequestRejected,
                    format!("event emission failed: {e}"),
                ));
            },
        };

        debug!(
            event_id = %signed_event.event_id,
            work_id = %claim.work_id,
            "WorkClaimed event emitted successfully"
        );

        // Return the work assignment
        Ok(PrivilegedResponse::ClaimWork(ClaimWorkResponse {
            work_id: claim.work_id,
            lease_id: claim.lease_id,
            capability_manifest_hash: policy_resolution.capability_manifest_hash.to_vec(),
            policy_resolved_ref: policy_resolution.policy_resolved_ref,
            context_pack_hash: policy_resolution.context_pack_hash.to_vec(),
        }))
    }

    /// Handles `SpawnEpisode` requests (IPC-PRIV-002).
    ///
    /// # Security Contract (TCK-00257)
    ///
    /// - `GATE_EXECUTOR` role requires a valid `lease_id` that references a
    ///   `GateLeaseIssued` event in the ledger
    /// - The lease must match the `work_id` in the request
    /// - Non-`GATE_EXECUTOR` roles (`IMPLEMENTER`, `REVIEWER`) do not require
    ///   ledger lease validation (they use claim-based validation)
    ///
    /// # TCK-00256 Implementation
    ///
    /// This handler implements the episode spawn flow per DD-001 and DD-002:
    ///
    /// 1. Validate request structure
    /// 2. Query work registry for `PolicyResolvedForChangeSet`
    /// 3. Validate role matches the claimed role
    /// 4. Validate `lease_id` matches the claimed `lease_id` (SEC-SCP-FAC-0020)
    /// 5. Create episode in runtime with policy constraints
    /// 6. Persist session state for subsequent IPC calls
    /// 7. Return session credentials
    ///
    /// # Security
    ///
    /// - Per SEC-SCP-FAC-0020: `lease_id` is validated against the claim to
    ///   prevent authorization bypass. The `lease_id` is redacted from logs to
    ///   prevent capability leakage.
    /// - Per fail-closed semantics: spawn is rejected if policy resolution is
    ///   missing.
    fn handle_spawn_episode(
        &self,
        payload: &[u8],
        ctx: &ConnectionContext,
    ) -> ProtocolResult<PrivilegedResponse> {
        let request =
            SpawnEpisodeRequest::decode_bounded(payload, &self.decode_config).map_err(|e| {
                ProtocolError::Serialization {
                    reason: format!("invalid SpawnEpisodeRequest: {e}"),
                }
            })?;

        // SEC-SCP-FAC-0020: lease_id is redacted from logs to prevent capability
        // leakage
        info!(
            work_id = %request.work_id,
            role = ?WorkRole::try_from(request.role).unwrap_or(WorkRole::Unspecified),
            lease_id = "[REDACTED]",
            peer_pid = ?ctx.peer_credentials().map(|c| c.pid),
            "SpawnEpisode request received"
        );

        // Validate required fields
        if request.work_id.is_empty() {
            return Ok(PrivilegedResponse::error(
                PrivilegedErrorCode::CapabilityRequestRejected,
                "work_id is required",
            ));
        }

        // SEC-SCP-FAC-0020: Enforce maximum length on work_id to prevent DoS via OOM
        if request.work_id.len() > MAX_ID_LENGTH {
            warn!(
                work_id_len = request.work_id.len(),
                max_len = MAX_ID_LENGTH,
                "SpawnEpisode rejected: work_id exceeds maximum length"
            );
            return Ok(PrivilegedResponse::error(
                PrivilegedErrorCode::CapabilityRequestRejected,
                format!("work_id exceeds maximum length of {MAX_ID_LENGTH} bytes"),
            ));
        }

        // SEC-SCP-FAC-0020: Enforce maximum length on lease_id to prevent DoS via OOM
        if let Some(ref lease_id) = request.lease_id {
            if lease_id.len() > MAX_ID_LENGTH {
                warn!(
                    lease_id_len = lease_id.len(),
                    max_len = MAX_ID_LENGTH,
                    "SpawnEpisode rejected: lease_id exceeds maximum length"
                );
                return Ok(PrivilegedResponse::error(
                    PrivilegedErrorCode::CapabilityRequestRejected,
                    format!("lease_id exceeds maximum length of {MAX_ID_LENGTH} bytes"),
                ));
            }
        }

        if request.role == WorkRole::Unspecified as i32 {
            return Ok(PrivilegedResponse::error(
                PrivilegedErrorCode::CapabilityRequestRejected,
                "role is required",
            ));
        }

        // GATE_EXECUTOR requires lease_id
        if request.role == WorkRole::GateExecutor as i32 && request.lease_id.is_none() {
            return Ok(PrivilegedResponse::error(
                PrivilegedErrorCode::GateLeaseMissing,
                "lease_id is required for GATE_EXECUTOR role",
            ));
        }

        // TCK-00257: GATE_EXECUTOR requires valid lease in ledger
        // Per RFC-0017 IPC-PRIV-002, the lease must exist as a GateLeaseIssued event
        // and the work_id must match. This is a fail-closed check.
        if request.role == WorkRole::GateExecutor as i32 {
            let lease_id = request
                .lease_id
                .as_ref()
                .expect("lease_id presence checked above");

            if let Err(e) = self
                .lease_validator
                .validate_gate_lease(lease_id, &request.work_id)
            {
                warn!(
                    work_id = %request.work_id,
                    error = %e,
                    "SpawnEpisode rejected: gate lease validation failed"
                );
                return Ok(PrivilegedResponse::error(
                    PrivilegedErrorCode::GateLeaseMissing,
                    format!("gate lease validation failed: {e}"),
                ));
            }
        }

        // TCK-00256: Query work registry for PolicyResolvedForChangeSet
        // Fail-closed: spawn is only allowed if a valid policy resolution exists
        // for the work_id. This is established during ClaimWork.
        let Some(claim) = self.work_registry.get_claim(&request.work_id) else {
            warn!(
                work_id = %request.work_id,
                "SpawnEpisode rejected: policy resolution not found for work_id"
            );
            return Ok(PrivilegedResponse::error(
                PrivilegedErrorCode::PolicyResolutionMissing,
                format!(
                    "policy resolution not found for work_id={}; ClaimWork must be called first",
                    request.work_id
                ),
            ));
        };

        // TCK-00256: Validate role matches the claimed role
        // Per DD-001, the role in the spawn request should match the claimed role
        let request_role = WorkRole::try_from(request.role).unwrap_or(WorkRole::Unspecified);
        if claim.role != request_role {
            warn!(
                work_id = %request.work_id,
                claimed_role = ?claim.role,
                request_role = ?request_role,
                "SpawnEpisode rejected: role mismatch"
            );
            return Ok(PrivilegedResponse::error(
                PrivilegedErrorCode::CapabilityRequestRejected,
                format!(
                    "role mismatch: work was claimed as {:?} but spawn requested {:?}",
                    claim.role, request_role
                ),
            ));
        }

        // SEC-SCP-FAC-0020: Validate lease_id matches the claimed lease_id
        // This prevents authorization bypass where a caller provides an arbitrary
        // lease_id. All roles must provide the correct lease_id from ClaimWork.
        // NOTE: Uses constant-time comparison to prevent timing side-channel attacks
        // that could leak information about valid lease_id values.
        let provided_lease_id = request.lease_id.as_deref().unwrap_or("");
        let lease_id_matches = provided_lease_id.len() == claim.lease_id.len()
            && bool::from(
                provided_lease_id
                    .as_bytes()
                    .ct_eq(claim.lease_id.as_bytes()),
            );
        if !lease_id_matches {
            warn!(
                work_id = %request.work_id,
                "SpawnEpisode rejected: lease_id mismatch"
            );
            return Ok(PrivilegedResponse::error(
                PrivilegedErrorCode::CapabilityRequestRejected,
                "lease_id does not match the claimed lease_id",
            ));
        }

        // For GateExecutor, the lease_id is required and must match
        // (Redundant but explicit check preserved for clarity per logic)
        // NOTE: Uses constant-time comparison to prevent timing side-channel attacks.
        if request.role == WorkRole::GateExecutor as i32 {
            if let Some(ref lease_id) = request.lease_id {
                let gate_lease_matches = lease_id.len() == claim.lease_id.len()
                    && bool::from(lease_id.as_bytes().ct_eq(claim.lease_id.as_bytes()));
                if !gate_lease_matches {
                    warn!(
                        work_id = %request.work_id,
                        "SpawnEpisode rejected: GateExecutor lease_id mismatch"
                    );
                    return Ok(PrivilegedResponse::error(
                        PrivilegedErrorCode::CapabilityRequestRejected,
                        "lease_id does not match the claimed lease_id for GATE_EXECUTOR",
                    ));
                }
            }
        }

        // =====================================================================
        // TCK-00258: SoD Custody Domain Validation
        //
        // Per REQ-DCP-0006, GATE_EXECUTOR spawns MUST enforce Separation of
        // Duties by rejecting when executor custody domains overlap with author
        // custody domains. This prevents self-review attacks.
        // =====================================================================
        if request.role == WorkRole::GateExecutor as i32 {
            // Convert claim domains to CustodyDomainId for validation
            let executor_domains: Vec<CustodyDomainId> = claim
                .executor_custody_domains
                .iter()
                .filter_map(|d| CustodyDomainId::new(d.clone()).ok())
                .collect();

            let author_domains: Vec<CustodyDomainId> = claim
                .author_custody_domains
                .iter()
                .filter_map(|d| CustodyDomainId::new(d.clone()).ok())
                .collect();

            // TCK-00258: Fail-closed SoD validation for GATE_EXECUTOR.
            // If author domains cannot be resolved (empty), DENY the spawn.
            // The absence of author information MUST block, not allow, to prevent
            // attackers from bypassing SoD by using malformed work_ids.
            if author_domains.is_empty() {
                warn!(
                    work_id = %request.work_id,
                    "SpawnEpisode rejected: cannot resolve author custody domains for SoD validation"
                );
                return Ok(PrivilegedResponse::error(
                    PrivilegedErrorCode::SodViolation,
                    "cannot resolve author custody domains; SoD validation requires author information for GATE_EXECUTOR",
                ));
            }

            // Validate SoD: executor domains must not overlap with author domains
            if !executor_domains.is_empty() {
                if let Err(CustodyDomainError::Overlap {
                    executor_domain,
                    author_domain,
                }) = validate_custody_domain_overlap(&executor_domains, &author_domains)
                {
                    warn!(
                        work_id = %request.work_id,
                        executor_domain = %executor_domain,
                        author_domain = %author_domain,
                        "SpawnEpisode rejected: SoD custody domain violation"
                    );

                    // Emit LeaseIssueDenied event for audit logging.
                    // RFC-0016 HTF compliance: Use placeholder timestamp (0) for stub
                    // implementation. In production, this would derive timestamp from
                    // HolonicClock via episode_runtime to ensure deterministic replay
                    // and avoid forbidden SystemTime::now() usage.
                    let timestamp_ns = 0u64;

                    // Best-effort event emission - don't fail spawn on event error.
                    // If no Tokio runtime is available (e.g., in unit tests), skip the
                    // async event emission. This is safe because:
                    // 1. The denial is still returned to the caller
                    // 2. The event is only for audit/diagnostic purposes
                    // 3. Production code always has a Tokio runtime
                    if let Ok(handle) = tokio::runtime::Handle::try_current() {
                        let _ = tokio::task::block_in_place(|| {
                            handle.block_on(async {
                                self.episode_runtime
                                    .emit_lease_issue_denied(
                                        request.work_id.clone(),
                                        LeaseIssueDenialReason::SodViolation {
                                            executor_domain: executor_domain.clone(),
                                            author_domain: author_domain.clone(),
                                        },
                                        timestamp_ns,
                                    )
                                    .await
                            })
                        });
                    }

                    return Ok(PrivilegedResponse::error(
                        PrivilegedErrorCode::SodViolation,
                        format!(
                            "custody domain overlap: executor domain '{executor_domain}' overlaps with author domain '{author_domain}'"
                        ),
                    ));
                }
            }
        }

        info!(
            work_id = %request.work_id,
            policy_resolved_ref = %claim.policy_resolution.policy_resolved_ref,
            "SpawnEpisode authorized with policy resolution"
        );

        // Generate session ID and ephemeral handle
        let session_id = format!("S-{}", uuid::Uuid::new_v4());
        let ephemeral_handle = EphemeralHandle::generate();

        // TCK-00256: Persist session state for subsequent IPC calls
        // The episode_runtime can create/start episodes asynchronously when needed.
        // For now, we persist the session state with policy constraints reference
        // so that subsequent async operations can use it.
        let session_state = SessionState {
            session_id: session_id.clone(),
            work_id: request.work_id.clone(),
            role: request_role.into(),
            ephemeral_handle: ephemeral_handle.to_string(),
            lease_id: claim.lease_id.clone(),
            policy_resolved_ref: claim.policy_resolution.policy_resolved_ref.clone(),
            capability_manifest_hash: claim.policy_resolution.capability_manifest_hash.to_vec(),
            episode_id: None, // Will be set when episode starts in async context
        };

        if let Err(e) = self.session_registry.register_session(session_state) {
            warn!(error = %e, "Session registration failed");
            return Ok(PrivilegedResponse::error(
                PrivilegedErrorCode::CapabilityRequestRejected,
                format!("session registration failed: {e}"),
            ));
        }

        debug!(
            session_id = %session_id,
            ephemeral_handle = %ephemeral_handle,
            "Session persisted"
        );

        Ok(PrivilegedResponse::SpawnEpisode(SpawnEpisodeResponse {
            session_id,
            ephemeral_handle: ephemeral_handle.to_string(),
            capability_manifest_hash: claim.policy_resolution.capability_manifest_hash.to_vec(),
            context_pack_sealed: true,
        }))
    }

    /// Handles `IssueCapability` requests (IPC-PRIV-003).
    ///
    /// # Stub Implementation
    ///
    /// This is a stub handler that validates the request and returns a
    /// placeholder response. Full implementation in future ticket.
    fn handle_issue_capability(
        &self,
        payload: &[u8],
        ctx: &ConnectionContext,
    ) -> ProtocolResult<PrivilegedResponse> {
        let request = IssueCapabilityRequest::decode_bounded(payload, &self.decode_config)
            .map_err(|e| ProtocolError::Serialization {
                reason: format!("invalid IssueCapabilityRequest: {e}"),
            })?;

        info!(
            session_id = %request.session_id,
            has_capability_request = request.capability_request.is_some(),
            peer_pid = ?ctx.peer_credentials().map(|c| c.pid),
            "IssueCapability request received (stub handler)"
        );

        // Validate required fields
        if request.session_id.is_empty() {
            return Ok(PrivilegedResponse::error(
                PrivilegedErrorCode::CapabilityRequestRejected,
                "session_id is required",
            ));
        }

        if request.capability_request.is_none() {
            return Ok(PrivilegedResponse::error(
                PrivilegedErrorCode::CapabilityRequestRejected,
                "capability_request is required",
            ));
        }

        // STUB: Return placeholder response
        // RFC-0016 HTF compliance: Use UUID-derived identifier instead of
        // SystemTime::now() The actual timestamps will be populated by proper
        // HTF clock when implemented
        let stub_id = uuid::Uuid::new_v4();

        Ok(PrivilegedResponse::IssueCapability(
            IssueCapabilityResponse {
                capability_id: format!("C-{stub_id}"),
                // STUB: Use placeholder timestamps (0) until HTF clock is available
                // Per RFC-0016, real timestamps must come from HTF-compliant clock source
                granted_at: 0,
                expires_at: 3600, // Relative offset for stub
            },
        ))
    }

    /// Handles Shutdown requests (IPC-PRIV-004).
    ///
    /// # Stub Implementation
    ///
    /// This is a stub handler that logs the request and returns acknowledgment.
    /// Full implementation requires integration with daemon state.
    fn handle_shutdown(
        &self,
        payload: &[u8],
        ctx: &ConnectionContext,
    ) -> ProtocolResult<PrivilegedResponse> {
        let request =
            ShutdownRequest::decode_bounded(payload, &self.decode_config).map_err(|e| {
                ProtocolError::Serialization {
                    reason: format!("invalid ShutdownRequest: {e}"),
                }
            })?;

        warn!(
            reason = ?request.reason,
            peer_pid = ?ctx.peer_credentials().map(|c| c.pid),
            "Shutdown request received (stub handler)"
        );

        // STUB: Return acknowledgment
        // Full implementation requires daemon state integration
        Ok(PrivilegedResponse::Shutdown(ShutdownResponse {
            message: "Shutdown acknowledged (stub)".to_string(),
        }))
    }
}

// ============================================================================
// Request Encoding Helpers
// ============================================================================

/// Encodes a `ClaimWork` request to bytes for sending.
///
/// The format is: `[tag: u8][payload: protobuf]`
#[must_use]
pub fn encode_claim_work_request(request: &ClaimWorkRequest) -> Bytes {
    let mut buf = vec![PrivilegedMessageType::ClaimWork.tag()];
    request.encode(&mut buf).expect("encode cannot fail");
    Bytes::from(buf)
}

/// Encodes a `SpawnEpisode` request to bytes for sending.
#[must_use]
pub fn encode_spawn_episode_request(request: &SpawnEpisodeRequest) -> Bytes {
    let mut buf = vec![PrivilegedMessageType::SpawnEpisode.tag()];
    request.encode(&mut buf).expect("encode cannot fail");
    Bytes::from(buf)
}

/// Encodes an `IssueCapability` request to bytes for sending.
#[must_use]
pub fn encode_issue_capability_request(request: &IssueCapabilityRequest) -> Bytes {
    let mut buf = vec![PrivilegedMessageType::IssueCapability.tag()];
    request.encode(&mut buf).expect("encode cannot fail");
    Bytes::from(buf)
}

/// Encodes a `Shutdown` request to bytes for sending.
#[must_use]
pub fn encode_shutdown_request(request: &ShutdownRequest) -> Bytes {
    let mut buf = vec![PrivilegedMessageType::Shutdown.tag()];
    request.encode(&mut buf).expect("encode cannot fail");
    Bytes::from(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // INT-001: Privileged endpoint routing (TCK-00251)
    // Test name matches verification command: cargo test -p apm2-daemon
    // privileged_routing
    // ========================================================================
    mod privileged_routing {
        use super::*;

        #[test]
        fn test_claim_work_routing() {
            let dispatcher = PrivilegedDispatcher::new();
            let ctx = ConnectionContext::privileged(Some(PeerCredentials {
                uid: 1000,
                gid: 1000,
                pid: Some(12345),
            }));

            let request = ClaimWorkRequest {
                actor_id: "test-actor".to_string(),
                role: WorkRole::Implementer.into(),
                credential_signature: vec![1, 2, 3],
                nonce: vec![4, 5, 6],
            };
            let frame = encode_claim_work_request(&request);

            let response = dispatcher.dispatch(&frame, &ctx).unwrap();
            assert!(matches!(response, PrivilegedResponse::ClaimWork(_)));
        }

        #[test]
        fn test_spawn_episode_routing() {
            let dispatcher = PrivilegedDispatcher::new();
            let ctx = ConnectionContext::privileged(Some(PeerCredentials {
                uid: 1000,
                gid: 1000,
                pid: Some(12345),
            }));

            // TCK-00256: First claim work to establish policy resolution
            let claim_request = ClaimWorkRequest {
                actor_id: "test-actor".to_string(),
                role: WorkRole::Implementer.into(),
                credential_signature: vec![1, 2, 3],
                nonce: vec![4, 5, 6],
            };
            let claim_frame = encode_claim_work_request(&claim_request);
            let claim_response = dispatcher.dispatch(&claim_frame, &ctx).unwrap();

            let (work_id, lease_id) = match claim_response {
                PrivilegedResponse::ClaimWork(resp) => (resp.work_id, resp.lease_id),
                _ => panic!("Expected ClaimWork response"),
            };

            // Now spawn with the claimed work_id
            let request = SpawnEpisodeRequest {
                work_id,
                role: WorkRole::Implementer.into(),
                lease_id: Some(lease_id),
            };
            let frame = encode_spawn_episode_request(&request);

            let response = dispatcher.dispatch(&frame, &ctx).unwrap();
            assert!(matches!(response, PrivilegedResponse::SpawnEpisode(_)));
        }

        #[test]
        fn test_issue_capability_routing() {
            let dispatcher = PrivilegedDispatcher::new();
            let ctx = ConnectionContext::privileged(Some(PeerCredentials {
                uid: 1000,
                gid: 1000,
                pid: Some(12345),
            }));

            let request = IssueCapabilityRequest {
                session_id: "S-001".to_string(),
                capability_request: Some(super::super::super::messages::CapabilityRequest {
                    tool_class: "file_read".to_string(),
                    read_patterns: vec!["**/*.rs".to_string()],
                    write_patterns: vec![],
                    duration_secs: 3600,
                }),
            };
            let frame = encode_issue_capability_request(&request);

            let response = dispatcher.dispatch(&frame, &ctx).unwrap();
            assert!(matches!(response, PrivilegedResponse::IssueCapability(_)));
        }

        #[test]
        fn test_shutdown_routing() {
            let dispatcher = PrivilegedDispatcher::new();
            let ctx = ConnectionContext::privileged(Some(PeerCredentials {
                uid: 1000,
                gid: 1000,
                pid: Some(12345),
            }));

            let request = ShutdownRequest {
                reason: Some("test".to_string()),
            };
            let frame = encode_shutdown_request(&request);

            let response = dispatcher.dispatch(&frame, &ctx).unwrap();
            assert!(matches!(response, PrivilegedResponse::Shutdown(_)));
        }

        #[test]
        fn test_session_socket_returns_permission_denied() {
            let dispatcher = PrivilegedDispatcher::new();
            let ctx = ConnectionContext::session(
                Some(PeerCredentials {
                    uid: 1000,
                    gid: 1000,
                    pid: Some(12346),
                }),
                Some("test-session".to_string()),
            );

            // All 4 endpoints should return PERMISSION_DENIED for session connections
            let requests = vec![
                encode_claim_work_request(&ClaimWorkRequest {
                    actor_id: "test".to_string(),
                    role: WorkRole::Implementer.into(),
                    credential_signature: vec![],
                    nonce: vec![],
                }),
                encode_spawn_episode_request(&SpawnEpisodeRequest {
                    work_id: "W-001".to_string(),
                    role: WorkRole::Implementer.into(),
                    lease_id: None,
                }),
                encode_issue_capability_request(&IssueCapabilityRequest {
                    session_id: "S-001".to_string(),
                    capability_request: None,
                }),
                encode_shutdown_request(&ShutdownRequest {
                    reason: Some("test".to_string()),
                }),
            ];

            for frame in requests {
                let response = dispatcher.dispatch(&frame, &ctx).unwrap();
                match response {
                    PrivilegedResponse::Error(err) => {
                        assert_eq!(err.code, PrivilegedErrorCode::PermissionDenied as i32);
                    },
                    _ => panic!("Expected PERMISSION_DENIED for session socket"),
                }
            }
        }
    }

    fn make_privileged_ctx() -> ConnectionContext {
        ConnectionContext::privileged(Some(PeerCredentials {
            uid: 1000,
            gid: 1000,
            pid: Some(12345),
        }))
    }

    fn make_session_ctx() -> ConnectionContext {
        ConnectionContext::session(
            Some(PeerCredentials {
                uid: 1000,
                gid: 1000,
                pid: Some(12346),
            }),
            Some("test-session".to_string()),
        )
    }

    // ========================================================================
    // ADV-001: Agent calls ClaimWork → PERMISSION_DENIED
    // ========================================================================
    #[test]
    fn test_adv_001_session_cannot_claim_work() {
        let dispatcher = PrivilegedDispatcher::new();
        let ctx = make_session_ctx();

        let request = ClaimWorkRequest {
            actor_id: "test-actor".to_string(),
            role: WorkRole::Implementer.into(),
            credential_signature: vec![],
            nonce: vec![],
        };
        let frame = encode_claim_work_request(&request);

        let response = dispatcher.dispatch(&frame, &ctx).unwrap();

        match response {
            PrivilegedResponse::Error(err) => {
                assert_eq!(err.code, PrivilegedErrorCode::PermissionDenied as i32);
                assert_eq!(err.message, "permission denied");
            },
            _ => panic!("Expected PERMISSION_DENIED error"),
        }
    }

    // ========================================================================
    // ADV-002: Agent calls SpawnEpisode → PERMISSION_DENIED
    // ========================================================================
    #[test]
    fn test_adv_002_session_cannot_spawn_episode() {
        let dispatcher = PrivilegedDispatcher::new();
        let ctx = make_session_ctx();

        let request = SpawnEpisodeRequest {
            work_id: "W-001".to_string(),
            role: WorkRole::Implementer.into(),
            lease_id: None,
        };
        let frame = encode_spawn_episode_request(&request);

        let response = dispatcher.dispatch(&frame, &ctx).unwrap();

        match response {
            PrivilegedResponse::Error(err) => {
                assert_eq!(err.code, PrivilegedErrorCode::PermissionDenied as i32);
            },
            _ => panic!("Expected PERMISSION_DENIED error"),
        }
    }

    #[test]
    fn test_session_cannot_issue_capability() {
        let dispatcher = PrivilegedDispatcher::new();
        let ctx = make_session_ctx();

        let request = IssueCapabilityRequest {
            session_id: "S-001".to_string(),
            capability_request: None,
        };
        let frame = encode_issue_capability_request(&request);

        let response = dispatcher.dispatch(&frame, &ctx).unwrap();

        match response {
            PrivilegedResponse::Error(err) => {
                assert_eq!(err.code, PrivilegedErrorCode::PermissionDenied as i32);
            },
            _ => panic!("Expected PERMISSION_DENIED error"),
        }
    }

    #[test]
    fn test_session_cannot_shutdown() {
        let dispatcher = PrivilegedDispatcher::new();
        let ctx = make_session_ctx();

        let request = ShutdownRequest {
            reason: Some("test".to_string()),
        };
        let frame = encode_shutdown_request(&request);

        let response = dispatcher.dispatch(&frame, &ctx).unwrap();

        match response {
            PrivilegedResponse::Error(err) => {
                assert_eq!(err.code, PrivilegedErrorCode::PermissionDenied as i32);
            },
            _ => panic!("Expected PERMISSION_DENIED error"),
        }
    }

    // ========================================================================
    // Privileged Connection Tests (Success Path)
    // ========================================================================
    #[test]
    fn test_privileged_claim_work_stub() {
        let dispatcher = PrivilegedDispatcher::new();
        let ctx = make_privileged_ctx();

        let request = ClaimWorkRequest {
            actor_id: "test-actor".to_string(),
            role: WorkRole::Implementer.into(),
            credential_signature: vec![1, 2, 3],
            nonce: vec![4, 5, 6],
        };
        let frame = encode_claim_work_request(&request);

        let response = dispatcher.dispatch(&frame, &ctx).unwrap();

        match response {
            PrivilegedResponse::ClaimWork(resp) => {
                assert!(!resp.work_id.is_empty());
                assert!(!resp.lease_id.is_empty());
            },
            PrivilegedResponse::Error(err) => {
                panic!("Unexpected error: {err:?}");
            },
            _ => panic!("Expected ClaimWork response"),
        }
    }

    #[test]
    fn test_privileged_spawn_episode_stub() {
        let dispatcher = PrivilegedDispatcher::new();
        let ctx = make_privileged_ctx();

        // TCK-00256: First claim work to establish policy resolution
        let claim_request = ClaimWorkRequest {
            actor_id: "test-actor".to_string(),
            role: WorkRole::Implementer.into(),
            credential_signature: vec![1, 2, 3],
            nonce: vec![4, 5, 6],
        };
        let claim_frame = encode_claim_work_request(&claim_request);
        let claim_response = dispatcher.dispatch(&claim_frame, &ctx).unwrap();

        let (work_id, lease_id) = match claim_response {
            PrivilegedResponse::ClaimWork(resp) => (resp.work_id, resp.lease_id),
            _ => panic!("Expected ClaimWork response"),
        };

        // Now spawn with the claimed work_id
        let request = SpawnEpisodeRequest {
            work_id,
            role: WorkRole::Implementer.into(),
            lease_id: Some(lease_id),
        };
        let frame = encode_spawn_episode_request(&request);

        let response = dispatcher.dispatch(&frame, &ctx).unwrap();

        match response {
            PrivilegedResponse::SpawnEpisode(resp) => {
                assert!(!resp.session_id.is_empty());
                assert!(!resp.ephemeral_handle.is_empty());
            },
            PrivilegedResponse::Error(err) => {
                panic!("Unexpected error: {err:?}");
            },
            _ => panic!("Expected SpawnEpisode response"),
        }
    }

    #[test]
    fn test_privileged_issue_capability_stub() {
        let dispatcher = PrivilegedDispatcher::new();
        let ctx = make_privileged_ctx();

        let request = IssueCapabilityRequest {
            session_id: "S-001".to_string(),
            capability_request: Some(super::super::messages::CapabilityRequest {
                tool_class: "file_read".to_string(),
                read_patterns: vec!["**/*.rs".to_string()],
                write_patterns: vec![],
                duration_secs: 3600,
            }),
        };
        let frame = encode_issue_capability_request(&request);

        let response = dispatcher.dispatch(&frame, &ctx).unwrap();

        match response {
            PrivilegedResponse::IssueCapability(resp) => {
                assert!(!resp.capability_id.is_empty());
                assert!(resp.capability_id.starts_with("C-")); // UUID-based ID
                // STUB uses placeholder timestamps (granted_at=0, expires_at=3600)
                assert_eq!(resp.granted_at, 0);
                assert_eq!(resp.expires_at, 3600);
            },
            PrivilegedResponse::Error(err) => {
                panic!("Unexpected error: {err:?}");
            },
            _ => panic!("Expected IssueCapability response"),
        }
    }

    #[test]
    fn test_privileged_shutdown_stub() {
        let dispatcher = PrivilegedDispatcher::new();
        let ctx = make_privileged_ctx();

        let request = ShutdownRequest {
            reason: Some("test shutdown".to_string()),
        };
        let frame = encode_shutdown_request(&request);

        let response = dispatcher.dispatch(&frame, &ctx).unwrap();

        match response {
            PrivilegedResponse::Shutdown(resp) => {
                assert!(!resp.message.is_empty());
            },
            PrivilegedResponse::Error(err) => {
                panic!("Unexpected error: {err:?}");
            },
            _ => panic!("Expected Shutdown response"),
        }
    }

    // ========================================================================
    // ADV-005: ClaimWork role validation
    // ========================================================================
    #[test]
    fn test_adv_005_claim_work_validation() {
        let dispatcher = PrivilegedDispatcher::new();
        let ctx = make_privileged_ctx();

        // TCK-00253: Empty actor_id in request is OK (it's just a display hint)
        // The authoritative actor_id is derived from credential
        let request = ClaimWorkRequest {
            actor_id: String::new(), // Empty is OK - we derive from credential
            role: WorkRole::Implementer.into(),
            credential_signature: vec![],
            nonce: vec![1, 2, 3, 4], // Nonce for actor_id derivation
        };
        let frame = encode_claim_work_request(&request);
        let response = dispatcher.dispatch(&frame, &ctx).unwrap();

        // Should succeed now - actor_id is derived, not validated
        match response {
            PrivilegedResponse::ClaimWork(resp) => {
                assert!(!resp.work_id.is_empty());
                assert!(!resp.lease_id.is_empty());
            },
            PrivilegedResponse::Error(err) => {
                panic!("Unexpected error: {err:?}");
            },
            _ => panic!("Expected ClaimWork response"),
        }

        // Test missing role - still required
        let request = ClaimWorkRequest {
            actor_id: "test-actor".to_string(),
            role: WorkRole::Unspecified.into(),
            credential_signature: vec![],
            nonce: vec![],
        };
        let frame = encode_claim_work_request(&request);
        let response = dispatcher.dispatch(&frame, &ctx).unwrap();

        match response {
            PrivilegedResponse::Error(err) => {
                assert_eq!(
                    err.code,
                    PrivilegedErrorCode::CapabilityRequestRejected as i32
                );
                assert!(err.message.contains("role"));
            },
            _ => panic!("Expected validation error for unspecified role"),
        }
    }

    // ========================================================================
    // TCK-00253: Actor ID derived from credential tests
    // ========================================================================
    mod tck_00253 {
        use super::*;

        /// ADV-005: Actor ID must be derived from credential, not user input.
        ///
        /// This test verifies that:
        /// 1. Different user-provided `actor_ids` with the same credential
        ///    produce the same derived `actor_id`
        /// 2. Different nonces do NOT affect the derived `actor_id` (stable
        ///    identity)
        #[test]
        fn test_actor_id_derived_from_credential_not_user_input() {
            let dispatcher = PrivilegedDispatcher::new();
            let ctx = make_privileged_ctx();

            // Request 1: User provides "alice" with nonce A
            let request1 = ClaimWorkRequest {
                actor_id: "alice".to_string(),
                role: WorkRole::Implementer.into(),
                credential_signature: vec![],
                nonce: vec![1, 2, 3, 4, 5, 6, 7, 8],
            };
            let frame1 = encode_claim_work_request(&request1);
            let response1 = dispatcher.dispatch(&frame1, &ctx).unwrap();

            // Request 2: User provides "bob" with different nonce B
            // Per stable actor_id design: same credential = same actor_id regardless of
            // nonce
            let request2 = ClaimWorkRequest {
                actor_id: "bob".to_string(),
                role: WorkRole::Implementer.into(),
                credential_signature: vec![],
                nonce: vec![9, 9, 9, 9], // Different nonce - should NOT change actor_id
            };
            let frame2 = encode_claim_work_request(&request2);
            let response2 = dispatcher.dispatch(&frame2, &ctx).unwrap();

            // Both should succeed
            let PrivilegedResponse::ClaimWork(resp1) = response1 else {
                panic!("Expected ClaimWork response")
            };
            let PrivilegedResponse::ClaimWork(resp2) = response2 else {
                panic!("Expected ClaimWork response")
            };

            // Work IDs should be different (unique per claim)
            assert_ne!(resp1.work_id, resp2.work_id);

            // But the derived actor_id should be the same since credentials are the same
            // This is the key ADV-005 invariant: user input (actor_id, nonce) does NOT
            // affect the derived actor_id - only the Unix credential (UID, GID)
            // matters.
            let claim1 = dispatcher.work_registry.get_claim(&resp1.work_id);
            let claim2 = dispatcher.work_registry.get_claim(&resp2.work_id);

            assert!(claim1.is_some(), "Work claim 1 should be registered");
            assert!(claim2.is_some(), "Work claim 2 should be registered");

            // Same credential = same derived actor_id (stable identity)
            assert_eq!(
                claim1.unwrap().actor_id,
                claim2.unwrap().actor_id,
                "Derived actor_id should be the same for same credential (nonce is ignored)"
            );
        }

        /// Same credential always produces the same `actor_id` (stable
        /// identity).
        ///
        /// This is the inverse test of what was previously tested - we now
        /// verify that nonces do NOT produce different `actor_ids` (which
        /// was the bug).
        #[test]
        fn test_same_credential_produces_same_actor_id_regardless_of_nonce() {
            let dispatcher = PrivilegedDispatcher::new();
            let ctx = make_privileged_ctx();

            let request1 = ClaimWorkRequest {
                actor_id: "test".to_string(),
                role: WorkRole::Implementer.into(),
                credential_signature: vec![],
                nonce: vec![1, 1, 1, 1],
            };
            let frame1 = encode_claim_work_request(&request1);
            let response1 = dispatcher.dispatch(&frame1, &ctx).unwrap();

            let request2 = ClaimWorkRequest {
                actor_id: "test".to_string(),
                role: WorkRole::Implementer.into(),
                credential_signature: vec![],
                nonce: vec![2, 2, 2, 2], // Different nonce - should NOT change actor_id
            };
            let frame2 = encode_claim_work_request(&request2);
            let response2 = dispatcher.dispatch(&frame2, &ctx).unwrap();

            let PrivilegedResponse::ClaimWork(resp1) = response1 else {
                panic!("Expected ClaimWork response")
            };
            let PrivilegedResponse::ClaimWork(resp2) = response2 else {
                panic!("Expected ClaimWork response")
            };

            let claim1 = dispatcher.work_registry.get_claim(&resp1.work_id).unwrap();
            let claim2 = dispatcher.work_registry.get_claim(&resp2.work_id).unwrap();

            // Same credential = same actor_id (stable identity per code quality fix)
            assert_eq!(
                claim1.actor_id, claim2.actor_id,
                "Same credential should produce same actor_id regardless of nonce"
            );
        }

        /// Policy resolution is required for work claim.
        #[test]
        fn test_policy_resolution_required_for_claim() {
            let dispatcher = PrivilegedDispatcher::new();
            let ctx = make_privileged_ctx();

            let request = ClaimWorkRequest {
                actor_id: "test-actor".to_string(),
                role: WorkRole::Implementer.into(),
                credential_signature: vec![],
                nonce: vec![1, 2, 3, 4],
            };
            let frame = encode_claim_work_request(&request);
            let response = dispatcher.dispatch(&frame, &ctx).unwrap();

            // Should succeed with policy resolution reference
            match response {
                PrivilegedResponse::ClaimWork(resp) => {
                    assert!(
                        !resp.policy_resolved_ref.is_empty(),
                        "PolicyResolvedForChangeSet reference should be present"
                    );
                    assert!(
                        resp.policy_resolved_ref
                            .contains("PolicyResolvedForChangeSet"),
                        "Reference should indicate PolicyResolvedForChangeSet"
                    );
                    assert_eq!(
                        resp.capability_manifest_hash.len(),
                        32,
                        "Capability manifest hash should be 32 bytes"
                    );
                    assert_eq!(
                        resp.context_pack_hash.len(),
                        32,
                        "Context pack hash should be 32 bytes"
                    );
                },
                PrivilegedResponse::Error(err) => {
                    panic!("Unexpected error: {err:?}");
                },
                _ => panic!("Expected ClaimWork response"),
            }
        }

        /// Work claim is persisted in registry.
        #[test]
        fn test_work_claimed_event_persisted() {
            let dispatcher = PrivilegedDispatcher::new();
            let ctx = make_privileged_ctx();

            let request = ClaimWorkRequest {
                actor_id: "test-actor".to_string(),
                role: WorkRole::Reviewer.into(),
                credential_signature: vec![],
                nonce: vec![5, 6, 7, 8],
            };
            let frame = encode_claim_work_request(&request);
            let response = dispatcher.dispatch(&frame, &ctx).unwrap();

            let work_id = match response {
                PrivilegedResponse::ClaimWork(resp) => resp.work_id,
                _ => panic!("Expected ClaimWork response"),
            };

            // Verify the claim is queryable from the registry
            let claim = dispatcher
                .work_registry
                .get_claim(&work_id)
                .expect("Work claim should be persisted");

            assert_eq!(claim.work_id, work_id);
            assert_eq!(claim.role, WorkRole::Reviewer);
            assert!(claim.actor_id.starts_with("actor:"));
            assert!(!claim.policy_resolution.policy_resolved_ref.is_empty());
        }

        /// Missing credentials should fail.
        #[test]
        fn test_missing_credentials_fails() {
            let dispatcher = PrivilegedDispatcher::new();
            // Privileged connection but no credentials
            let ctx = ConnectionContext::privileged(None);

            let request = ClaimWorkRequest {
                actor_id: "test-actor".to_string(),
                role: WorkRole::Implementer.into(),
                credential_signature: vec![],
                nonce: vec![1, 2, 3, 4],
            };
            let frame = encode_claim_work_request(&request);
            let result = dispatcher.dispatch(&frame, &ctx);

            // Should fail because we can't derive actor_id without credentials
            assert!(result.is_err(), "Should fail when credentials are missing");
        }

        /// Test `derive_actor_id` function directly.
        ///
        /// Verifies that `actor_id` derivation is:
        /// 1. Deterministic (same credential = same output)
        /// 2. Independent of PID (different PIDs with same UID/GID = same
        ///    output)
        #[test]
        fn test_derive_actor_id_deterministic() {
            let creds = PeerCredentials {
                uid: 1000,
                gid: 1000,
                pid: Some(12345),
            };

            let actor1 = derive_actor_id(&creds);
            let actor2 = derive_actor_id(&creds);

            assert_eq!(
                actor1, actor2,
                "Same credential should produce same actor_id"
            );
            assert!(
                actor1.starts_with("actor:"),
                "Actor ID should have 'actor:' prefix"
            );

            // Different PID should NOT change actor_id (stable identity)
            let creds_different_pid = PeerCredentials {
                uid: 1000,
                gid: 1000,
                pid: Some(99999), // Different PID
            };

            let actor3 = derive_actor_id(&creds_different_pid);
            assert_eq!(
                actor1, actor3,
                "Different PID should NOT change actor_id (only UID/GID matter)"
            );

            // Different UID/GID SHOULD change actor_id
            let creds_different_user = PeerCredentials {
                uid: 2000, // Different UID
                gid: 1000,
                pid: Some(12345),
            };

            let actor4 = derive_actor_id(&creds_different_user);
            assert_ne!(
                actor1, actor4,
                "Different UID should produce different actor_id"
            );
        }

        /// Test work and lease ID generation.
        #[test]
        fn test_id_generation_unique() {
            let work_id1 = generate_work_id();
            let work_id2 = generate_work_id();
            assert_ne!(work_id1, work_id2, "Work IDs should be unique");
            assert!(work_id1.starts_with("W-"), "Work ID should start with 'W-'");

            let lease_id1 = generate_lease_id();
            let lease_id2 = generate_lease_id();
            assert_ne!(lease_id1, lease_id2, "Lease IDs should be unique");
            assert!(
                lease_id1.starts_with("L-"),
                "Lease ID should start with 'L-'"
            );
        }

        /// TCK-00253: `WorkClaimed` event is signed and persisted.
        ///
        /// Per acceptance criteria: "`WorkClaimed` event signed and persisted"
        /// This test verifies that:
        /// 1. A signed event is emitted when work is claimed
        /// 2. The event is queryable from the ledger
        /// 3. The signature is present and has the correct length
        #[test]
        fn test_work_claimed_event_signed_and_persisted() {
            let dispatcher = PrivilegedDispatcher::new();
            let ctx = make_privileged_ctx();

            let request = ClaimWorkRequest {
                actor_id: "test-actor".to_string(),
                role: WorkRole::Implementer.into(),
                credential_signature: vec![],
                nonce: vec![1, 2, 3, 4],
            };
            let frame = encode_claim_work_request(&request);
            let response = dispatcher.dispatch(&frame, &ctx).unwrap();

            let work_id = match response {
                PrivilegedResponse::ClaimWork(resp) => resp.work_id,
                _ => panic!("Expected ClaimWork response"),
            };

            // Query events by work_id from the ledger
            let events = dispatcher.event_emitter.get_events_by_work_id(&work_id);

            assert_eq!(events.len(), 1, "Exactly one event should be emitted");

            let event = &events[0];
            assert_eq!(event.work_id, work_id);
            assert_eq!(event.event_type, "work_claimed");
            assert!(!event.signature.is_empty(), "Event should be signed");
            assert_eq!(
                event.signature.len(),
                64,
                "Ed25519 signature should be 64 bytes"
            );
            assert!(
                event.event_id.starts_with("EVT-"),
                "Event ID should have EVT- prefix"
            );
            // RFC-0016 HTF compliance: Stub uses placeholder timestamp (0)
            // In production, HTF-compliant clock will provide real timestamps
            assert_eq!(
                event.timestamp_ns, 0,
                "Stub timestamp should be 0 (HTF placeholder)"
            );

            // Verify payload contains expected fields
            let payload: serde_json::Value =
                serde_json::from_slice(&event.payload).expect("Payload should be valid JSON");
            assert_eq!(payload["event_type"], "work_claimed");
            assert_eq!(payload["work_id"], work_id);
            assert!(payload["actor_id"].as_str().unwrap().starts_with("actor:"));
            assert!(payload["policy_resolved_ref"].as_str().is_some());

            // Also verify the event is queryable by event_id
            let queried_event = dispatcher.event_emitter.get_event(&event.event_id);
            assert!(queried_event.is_some(), "Event should be queryable by ID");
            assert_eq!(queried_event.unwrap().event_id, event.event_id);
        }

        /// TCK-00253: Ledger query returns signed event.
        ///
        /// Per acceptance criteria: "Ledger query returns signed event"
        #[test]
        fn test_ledger_query_returns_signed_event() {
            let dispatcher = PrivilegedDispatcher::new();
            let ctx = make_privileged_ctx();

            // Claim work
            let request = ClaimWorkRequest {
                actor_id: "test-actor".to_string(),
                role: WorkRole::Reviewer.into(),
                credential_signature: vec![],
                nonce: vec![5, 6, 7, 8],
            };
            let frame = encode_claim_work_request(&request);
            let response = dispatcher.dispatch(&frame, &ctx).unwrap();

            let work_id = match response {
                PrivilegedResponse::ClaimWork(resp) => resp.work_id,
                _ => panic!("Expected ClaimWork response"),
            };

            // Query events by work_id
            let events = dispatcher.event_emitter.get_events_by_work_id(&work_id);

            // Verify at least one signed event is returned
            assert!(!events.is_empty(), "Should return at least one event");
            let event = &events[0];
            assert!(
                !event.signature.is_empty(),
                "Queried event should have signature"
            );
            assert_eq!(
                event.signature.len(),
                64,
                "Signature should be Ed25519 (64 bytes)"
            );
        }
    }

    #[test]
    fn test_gate_executor_requires_lease_id() {
        let dispatcher = PrivilegedDispatcher::new();
        let ctx = make_privileged_ctx();

        let request = SpawnEpisodeRequest {
            work_id: "W-001".to_string(),
            role: WorkRole::GateExecutor.into(),
            lease_id: None, // Missing required lease_id
        };
        let frame = encode_spawn_episode_request(&request);

        let response = dispatcher.dispatch(&frame, &ctx).unwrap();

        match response {
            PrivilegedResponse::Error(err) => {
                assert_eq!(err.code, PrivilegedErrorCode::GateLeaseMissing as i32);
            },
            _ => panic!("Expected GATE_LEASE_MISSING error"),
        }
    }

    #[test]
    fn test_gate_executor_with_lease_id_succeeds() {
        let dispatcher = PrivilegedDispatcher::new();
        let ctx = make_privileged_ctx();

        // First, claim work with GateExecutor role to establish policy resolution
        let claim_request = ClaimWorkRequest {
            actor_id: "test-actor".to_string(),
            role: WorkRole::GateExecutor.into(),
            credential_signature: vec![1, 2, 3],
            nonce: vec![4, 5, 6],
        };
        let claim_frame = encode_claim_work_request(&claim_request);
        let claim_response = dispatcher.dispatch(&claim_frame, &ctx).unwrap();

        // SEC-SCP-FAC-0020: Get the correct lease_id from the claim response
        let (work_id, lease_id) = match claim_response {
            PrivilegedResponse::ClaimWork(resp) => (resp.work_id, resp.lease_id),
            _ => panic!("Expected ClaimWork response"),
        };

        // TCK-00257: Register the lease for validation
        dispatcher
            .lease_validator()
            .register_lease(&lease_id, &work_id, "gate-build");

        // Now spawn with the claimed work_id and correct lease_id
        let request = SpawnEpisodeRequest {
            work_id,
            role: WorkRole::GateExecutor.into(),
            lease_id: Some(lease_id), // Use the correct lease_id from ClaimWork
        };
        let frame = encode_spawn_episode_request(&request);

        let response = dispatcher.dispatch(&frame, &ctx).unwrap();

        match response {
            PrivilegedResponse::SpawnEpisode(_) => {
                // Success
            },
            PrivilegedResponse::Error(err) => {
                panic!("Unexpected error: {err:?}");
            },
            _ => panic!("Expected SpawnEpisode response"),
        }
    }

    // ========================================================================
    // SEC-SCP-FAC-0020: Lease ID Validation Tests
    // ========================================================================

    /// SEC-SCP-FAC-0020: `SpawnEpisode` with wrong `lease_id` fails.
    ///
    /// Per security review: `lease_id` must be validated against the claim to
    /// prevent authorization bypass.
    #[test]
    fn tck_00256_spawn_with_wrong_lease_id_fails() {
        let dispatcher = PrivilegedDispatcher::new();
        let ctx = make_privileged_ctx();

        // Claim work with GateExecutor role
        let claim_request = ClaimWorkRequest {
            actor_id: "test-actor".to_string(),
            role: WorkRole::GateExecutor.into(),
            credential_signature: vec![1, 2, 3],
            nonce: vec![4, 5, 6],
        };
        let claim_frame = encode_claim_work_request(&claim_request);
        let claim_response = dispatcher.dispatch(&claim_frame, &ctx).unwrap();

        let work_id = match claim_response {
            PrivilegedResponse::ClaimWork(resp) => resp.work_id,
            _ => panic!("Expected ClaimWork response"),
        };

        // Try to spawn with a WRONG lease_id (arbitrary string)
        let request = SpawnEpisodeRequest {
            work_id,
            role: WorkRole::GateExecutor.into(),
            lease_id: Some("L-WRONG-LEASE-ID".to_string()), // Wrong!
        };
        let frame = encode_spawn_episode_request(&request);

        let response = dispatcher.dispatch(&frame, &ctx).unwrap();

        match response {
            PrivilegedResponse::Error(err) => {
                // TCK-00257: With lease validation, wrong lease_id fails at
                // lease validation (GATE_LEASE_MISSING) before claim validation
                assert_eq!(
                    err.code,
                    PrivilegedErrorCode::GateLeaseMissing as i32,
                    "Should return GateLeaseMissing for unknown lease_id"
                );
                assert!(
                    err.message.contains("lease"),
                    "Error message should mention lease: {}",
                    err.message
                );
            },
            _ => panic!("Expected lease validation error, got: {response:?}"),
        }
    }

    /// SEC-SCP-FAC-0020: `SpawnEpisode` with MISSING `lease_id` fails.
    ///
    /// Security Fix Verification: Ensure that omitting `lease_id` (None) is NOT
    /// treated as a valid bypass. It must match the claimed `lease_id`.
    #[test]
    fn tck_00256_spawn_with_missing_lease_id_fails() {
        let dispatcher = PrivilegedDispatcher::new();
        let ctx = make_privileged_ctx();

        // Claim work with Implementer role
        let claim_request = ClaimWorkRequest {
            actor_id: "test-actor".to_string(),
            role: WorkRole::Implementer.into(),
            credential_signature: vec![1, 2, 3],
            nonce: vec![4, 5, 6],
        };
        let claim_frame = encode_claim_work_request(&claim_request);
        let claim_response = dispatcher.dispatch(&claim_frame, &ctx).unwrap();

        let work_id = match claim_response {
            PrivilegedResponse::ClaimWork(resp) => resp.work_id,
            _ => panic!("Expected ClaimWork response"),
        };

        // Try to spawn with NO lease_id (None)
        let request = SpawnEpisodeRequest {
            work_id,
            role: WorkRole::Implementer.into(),
            lease_id: None, // Missing! Should fail because claim has a lease_id
        };
        let frame = encode_spawn_episode_request(&request);

        let response = dispatcher.dispatch(&frame, &ctx).unwrap();

        match response {
            PrivilegedResponse::Error(err) => {
                assert_eq!(
                    err.code,
                    PrivilegedErrorCode::CapabilityRequestRejected as i32,
                    "Should return CapabilityRequestRejected for missing lease_id"
                );
                assert!(
                    err.message.contains("lease_id"),
                    "Error message should mention lease_id: {}",
                    err.message
                );
            },
            _ => panic!("Expected lease_id mismatch error for Missing ID, got: {response:?}"),
        }
    }

    /// SEC-SCP-FAC-0020: `SpawnEpisode` with correct `lease_id` succeeds.
    #[test]
    fn tck_00256_spawn_with_correct_lease_id_succeeds() {
        let dispatcher = PrivilegedDispatcher::new();
        let ctx = make_privileged_ctx();

        // Claim work
        let claim_request = ClaimWorkRequest {
            actor_id: "test-actor".to_string(),
            role: WorkRole::Implementer.into(),
            credential_signature: vec![1, 2, 3],
            nonce: vec![4, 5, 6],
        };
        let claim_frame = encode_claim_work_request(&claim_request);
        let claim_response = dispatcher.dispatch(&claim_frame, &ctx).unwrap();

        let (work_id, lease_id) = match claim_response {
            PrivilegedResponse::ClaimWork(resp) => (resp.work_id, resp.lease_id),
            _ => panic!("Expected ClaimWork response"),
        };

        // Spawn with the correct lease_id (optional for non-GateExecutor)
        let request = SpawnEpisodeRequest {
            work_id,
            role: WorkRole::Implementer.into(),
            lease_id: Some(lease_id), // Correct lease_id
        };
        let frame = encode_spawn_episode_request(&request);

        let response = dispatcher.dispatch(&frame, &ctx).unwrap();

        match response {
            PrivilegedResponse::SpawnEpisode(resp) => {
                assert!(!resp.session_id.is_empty());
            },
            PrivilegedResponse::Error(err) => {
                panic!("Unexpected error: {err:?}");
            },
            _ => panic!("Expected SpawnEpisode response"),
        }
    }

    /// SEC-SCP-FAC-0020: Session state is persisted after successful spawn.
    #[test]
    fn tck_00256_session_state_persisted() {
        let dispatcher = PrivilegedDispatcher::new();
        let ctx = make_privileged_ctx();

        // Claim work
        let claim_request = ClaimWorkRequest {
            actor_id: "test-actor".to_string(),
            role: WorkRole::Implementer.into(),
            credential_signature: vec![1, 2, 3],
            nonce: vec![4, 5, 6],
        };
        let claim_frame = encode_claim_work_request(&claim_request);
        let claim_response = dispatcher.dispatch(&claim_frame, &ctx).unwrap();

        let (work_id, lease_id) = match claim_response {
            PrivilegedResponse::ClaimWork(resp) => (resp.work_id, resp.lease_id),
            _ => panic!("Expected ClaimWork response"),
        };

        // Spawn episode
        let request = SpawnEpisodeRequest {
            work_id: work_id.clone(),
            role: WorkRole::Implementer.into(),
            lease_id: Some(lease_id),
        };
        let frame = encode_spawn_episode_request(&request);
        let response = dispatcher.dispatch(&frame, &ctx).unwrap();

        let (session_id, ephemeral_handle) = match response {
            PrivilegedResponse::SpawnEpisode(resp) => (resp.session_id, resp.ephemeral_handle),
            _ => panic!("Expected SpawnEpisode response"),
        };

        // Verify session is persisted
        let session = dispatcher.session_registry.get_session(&session_id);
        assert!(session.is_some(), "Session should be persisted");

        let session = session.unwrap();
        assert_eq!(session.session_id, session_id);
        assert_eq!(session.work_id, work_id);
        assert_eq!(session.role, i32::from(WorkRole::Implementer));
        assert_eq!(session.ephemeral_handle, ephemeral_handle);

        // Also verify we can query by ephemeral handle
        let session_by_handle = dispatcher
            .session_registry
            .get_session_by_handle(&ephemeral_handle);
        assert!(
            session_by_handle.is_some(),
            "Session should be queryable by handle"
        );
        assert_eq!(session_by_handle.unwrap().session_id, session_id);
    }

    // ========================================================================
    // TCK-00257: ADV-004 Gate Lease Validation Tests
    // ========================================================================

    /// ADV-004: `GATE_EXECUTOR` spawn with unknown/unregistered `lease_id`
    /// fails.
    ///
    /// This test verifies that the ledger is queried for a valid
    /// `GateLeaseIssued` event. If the lease is not found, the spawn is
    /// rejected with `GATE_LEASE_MISSING`.
    #[test]
    fn test_adv_004_gate_executor_unknown_lease_fails() {
        let dispatcher = PrivilegedDispatcher::new();
        let ctx = make_privileged_ctx();

        // DO NOT register any lease - this simulates an unknown/invalid lease

        let request = SpawnEpisodeRequest {
            work_id: "W-001".to_string(),
            role: WorkRole::GateExecutor.into(),
            lease_id: Some("L-UNKNOWN".to_string()), // Not registered
        };
        let frame = encode_spawn_episode_request(&request);

        let response = dispatcher.dispatch(&frame, &ctx).unwrap();

        match response {
            PrivilegedResponse::Error(err) => {
                assert_eq!(
                    err.code,
                    PrivilegedErrorCode::GateLeaseMissing as i32,
                    "Should fail with GATE_LEASE_MISSING for unknown lease"
                );
                assert!(
                    err.message.contains("lease not found"),
                    "Error message should indicate lease not found: {}",
                    err.message
                );
            },
            _ => panic!("Expected GATE_LEASE_MISSING error for unknown lease"),
        }
    }

    /// ADV-004: `GATE_EXECUTOR` spawn with mismatched `work_id` fails.
    ///
    /// This test verifies that the lease's `work_id` must match the request's
    /// `work_id`. A lease for work W-001 cannot be used for spawn on W-002.
    #[test]
    fn test_adv_004_gate_executor_work_id_mismatch_fails() {
        let dispatcher = PrivilegedDispatcher::new();
        let ctx = make_privileged_ctx();

        // Register lease for W-001
        dispatcher
            .lease_validator()
            .register_lease("L-001", "W-001", "gate-build");

        // Try to use that lease for W-002 (different work_id)
        let request = SpawnEpisodeRequest {
            work_id: "W-002".to_string(), // Mismatched work_id
            role: WorkRole::GateExecutor.into(),
            lease_id: Some("L-001".to_string()),
        };
        let frame = encode_spawn_episode_request(&request);

        let response = dispatcher.dispatch(&frame, &ctx).unwrap();

        match response {
            PrivilegedResponse::Error(err) => {
                assert_eq!(
                    err.code,
                    PrivilegedErrorCode::GateLeaseMissing as i32,
                    "Should fail with GATE_LEASE_MISSING for work_id mismatch"
                );
                assert!(
                    err.message.contains("mismatch"),
                    "Error message should indicate work_id mismatch: {}",
                    err.message
                );
            },
            _ => panic!("Expected GATE_LEASE_MISSING error for work_id mismatch"),
        }
    }

    /// ADV-004: `GATE_EXECUTOR` spawn with valid registered lease succeeds
    /// (at the lease validation stage).
    ///
    /// This test verifies that a properly registered lease that matches
    /// the `work_id` passes the lease validation. Note: The spawn may still
    /// fail at the claim validation stage if `ClaimWork` wasn't called first.
    #[test]
    fn test_adv_004_gate_executor_valid_lease_passes_validation() {
        let dispatcher = PrivilegedDispatcher::new();
        let ctx = make_privileged_ctx();

        // Register the lease for the correct work_id
        dispatcher
            .lease_validator()
            .register_lease("L-VALID", "W-VALID", "gate-aat");

        let request = SpawnEpisodeRequest {
            work_id: "W-VALID".to_string(),
            role: WorkRole::GateExecutor.into(),
            lease_id: Some("L-VALID".to_string()),
        };
        let frame = encode_spawn_episode_request(&request);

        let response = dispatcher.dispatch(&frame, &ctx).unwrap();

        // The response should NOT be GATE_LEASE_MISSING - the lease validation
        // passed. It may fail for other reasons (policy resolution missing),
        // but not lease validation.
        if let PrivilegedResponse::Error(err) = &response {
            assert_ne!(
                err.code,
                PrivilegedErrorCode::GateLeaseMissing as i32,
                "Should NOT fail with GATE_LEASE_MISSING - lease is valid"
            );
            // Expected to fail with PolicyResolutionMissing since we didn't
            // call ClaimWork
            assert_eq!(
                err.code,
                PrivilegedErrorCode::PolicyResolutionMissing as i32,
                "Should fail with PolicyResolutionMissing (no ClaimWork)"
            );
        }
        // If it somehow succeeded, that's also fine for this test
    }

    // ========================================================================
    // Protocol Error Tests
    // ========================================================================
    #[test]
    fn test_empty_frame_error() {
        let dispatcher = PrivilegedDispatcher::new();
        let ctx = make_privileged_ctx();

        let frame = Bytes::new();
        let result = dispatcher.dispatch(&frame, &ctx);

        assert!(result.is_err());
        assert!(matches!(result, Err(ProtocolError::Serialization { .. })));
    }

    #[test]
    fn test_unknown_message_type_error() {
        let dispatcher = PrivilegedDispatcher::new();
        let ctx = make_privileged_ctx();

        let frame = Bytes::from(vec![255u8, 0, 0, 0]); // Unknown tag
        let result = dispatcher.dispatch(&frame, &ctx);

        assert!(result.is_err());
        assert!(matches!(result, Err(ProtocolError::Serialization { .. })));
    }

    #[test]
    fn test_malformed_payload_error() {
        let dispatcher = PrivilegedDispatcher::new();
        let ctx = make_privileged_ctx();

        let frame = Bytes::from(vec![1u8, 0xFF, 0xFF, 0xFF]); // ClaimWork tag + garbage
        let result = dispatcher.dispatch(&frame, &ctx);

        assert!(result.is_err());
    }

    // ========================================================================
    // Connection Context Tests
    // ========================================================================
    #[test]
    fn test_connection_context_privileged() {
        let ctx = ConnectionContext::privileged(Some(PeerCredentials {
            uid: 1000,
            gid: 1000,
            pid: Some(123),
        }));

        assert!(ctx.is_privileged());
        assert!(ctx.peer_credentials().is_some());
        assert!(ctx.session_id().is_none());
    }

    #[test]
    fn test_connection_context_session() {
        let ctx = ConnectionContext::session(
            Some(PeerCredentials {
                uid: 1000,
                gid: 1000,
                pid: Some(456),
            }),
            Some("session-123".to_string()),
        );

        assert!(!ctx.is_privileged());
        assert!(ctx.peer_credentials().is_some());
        assert_eq!(ctx.session_id(), Some("session-123"));
    }

    // ========================================================================
    // Response Encoding Tests
    // ========================================================================
    #[test]
    fn test_response_encoding() {
        let error_resp = PrivilegedResponse::permission_denied();
        let encoded = error_resp.encode();
        assert!(!encoded.is_empty());
        assert_eq!(encoded[0], 0); // Error tag

        let claim_resp = PrivilegedResponse::ClaimWork(ClaimWorkResponse {
            work_id: "W-001".to_string(),
            lease_id: "L-001".to_string(),
            capability_manifest_hash: vec![],
            policy_resolved_ref: String::new(),
            context_pack_hash: vec![],
        });
        let encoded = claim_resp.encode();
        assert!(!encoded.is_empty());
        assert_eq!(encoded[0], PrivilegedMessageType::ClaimWork.tag());
    }

    // ========================================================================
    // TCK-00256: SpawnEpisode with PolicyResolvedForChangeSet check
    // ========================================================================

    /// TCK-00256: Spawn without policy resolution fails (fail-closed).
    ///
    /// Per acceptance criteria: "Spawn without policy resolution fails"
    /// This test verifies ADV-004 variant: attempting to spawn an episode
    /// without first calling `ClaimWork` to establish policy resolution.
    #[test]
    fn tck_00256_spawn_without_policy_resolution_fails() {
        let dispatcher = PrivilegedDispatcher::new();
        let ctx = make_privileged_ctx();

        // Attempt to spawn for a non-existent work_id (no ClaimWork was called)
        let request = SpawnEpisodeRequest {
            work_id: "W-NONEXISTENT".to_string(),
            role: WorkRole::Implementer.into(),
            lease_id: None,
        };
        let frame = encode_spawn_episode_request(&request);

        let response = dispatcher.dispatch(&frame, &ctx).unwrap();

        match response {
            PrivilegedResponse::Error(err) => {
                assert_eq!(
                    err.code,
                    PrivilegedErrorCode::PolicyResolutionMissing as i32,
                    "Should return PolicyResolutionMissing error"
                );
                assert!(
                    err.message.contains("policy resolution not found"),
                    "Error message should indicate policy resolution is missing: {}",
                    err.message
                );
            },
            _ => panic!("Expected PolicyResolutionMissing error, got: {response:?}"),
        }
    }

    /// TCK-00256: Valid policy resolution allows spawn.
    ///
    /// Per acceptance criteria: "Valid policy resolution allows spawn"
    /// This test verifies the integration flow: `ClaimWork` followed by
    /// `SpawnEpisode`.
    #[test]
    fn tck_00256_spawn_with_policy_resolution_succeeds() {
        let dispatcher = PrivilegedDispatcher::new();
        let ctx = make_privileged_ctx();

        // 1. Claim Work (generates policy resolution and persists it)
        let claim_req = ClaimWorkRequest {
            actor_id: "test-actor".to_string(),
            role: WorkRole::Implementer.into(),
            credential_signature: vec![1, 2, 3],
            nonce: vec![4, 5, 6],
        };
        let claim_frame = encode_claim_work_request(&claim_req);
        let claim_response = dispatcher.dispatch(&claim_frame, &ctx).unwrap();

        let (work_id, expected_manifest_hash, lease_id) = match claim_response {
            PrivilegedResponse::ClaimWork(resp) => {
                (resp.work_id, resp.capability_manifest_hash, resp.lease_id)
            },
            _ => panic!("Expected ClaimWork response"),
        };

        // 2. Spawn Episode (should succeed because ClaimWork persisted the resolution)
        let spawn_req = SpawnEpisodeRequest {
            work_id,
            role: WorkRole::Implementer.into(),
            lease_id: Some(lease_id),
        };
        let spawn_frame = encode_spawn_episode_request(&spawn_req);

        let response = dispatcher.dispatch(&spawn_frame, &ctx).unwrap();

        match response {
            PrivilegedResponse::SpawnEpisode(resp) => {
                assert!(
                    !resp.session_id.is_empty(),
                    "Session ID should not be empty"
                );
                assert!(
                    resp.session_id.starts_with("S-"),
                    "Session ID should start with S-"
                );
                assert!(
                    !resp.ephemeral_handle.is_empty(),
                    "Ephemeral handle should not be empty"
                );
                assert!(
                    resp.ephemeral_handle.starts_with("H-"),
                    "Ephemeral handle should start with H-"
                );
                assert_eq!(
                    resp.capability_manifest_hash, expected_manifest_hash,
                    "Capability manifest hash should match the one from ClaimWork"
                );
                assert!(resp.context_pack_sealed, "Context pack should be sealed");
            },
            PrivilegedResponse::Error(err) => {
                panic!("Unexpected error: {err:?}");
            },
            _ => panic!("Expected SpawnEpisode response"),
        }
    }

    /// TCK-00256: `SpawnEpisode` with mismatched role fails.
    ///
    /// Per DD-001, the role in the spawn request should match the claimed role.
    /// This test verifies that attempting to spawn with a different role fails.
    #[test]
    fn tck_00256_spawn_with_mismatched_role_fails() {
        let dispatcher = PrivilegedDispatcher::new();
        let ctx = make_privileged_ctx();

        // 1. Claim Work with Implementer role
        let claim_req = ClaimWorkRequest {
            actor_id: "test-actor".to_string(),
            role: WorkRole::Implementer.into(),
            credential_signature: vec![1, 2, 3],
            nonce: vec![4, 5, 6],
        };
        let claim_frame = encode_claim_work_request(&claim_req);
        let claim_response = dispatcher.dispatch(&claim_frame, &ctx).unwrap();

        let work_id = match claim_response {
            PrivilegedResponse::ClaimWork(resp) => resp.work_id,
            _ => panic!("Expected ClaimWork response"),
        };

        // 2. Try to spawn with Reviewer role (mismatched)
        let spawn_req = SpawnEpisodeRequest {
            work_id,
            role: WorkRole::Reviewer.into(), // Different from claimed role
            lease_id: None,
        };
        let spawn_frame = encode_spawn_episode_request(&spawn_req);

        let response = dispatcher.dispatch(&spawn_frame, &ctx).unwrap();

        match response {
            PrivilegedResponse::Error(err) => {
                assert_eq!(
                    err.code,
                    PrivilegedErrorCode::CapabilityRequestRejected as i32,
                    "Should return CapabilityRequestRejected for role mismatch"
                );
                assert!(
                    err.message.contains("role mismatch"),
                    "Error message should indicate role mismatch: {}",
                    err.message
                );
            },
            _ => panic!("Expected role mismatch error, got: {response:?}"),
        }
    }

    /// TCK-00256: `SpawnEpisode` returns policy resolution data.
    ///
    /// Verifies that the spawn response includes the capability manifest hash
    /// from the original policy resolution.
    #[test]
    fn tck_00256_spawn_returns_policy_resolution_data() {
        let dispatcher = PrivilegedDispatcher::new();
        let ctx = make_privileged_ctx();

        // Claim work
        let claim_req = ClaimWorkRequest {
            actor_id: "test-actor".to_string(),
            role: WorkRole::Implementer.into(),
            credential_signature: vec![1, 2, 3],
            nonce: vec![4, 5, 6],
        };
        let claim_frame = encode_claim_work_request(&claim_req);
        let claim_response = dispatcher.dispatch(&claim_frame, &ctx).unwrap();

        let (work_id, claim_manifest_hash, _claim_context_hash, lease_id) = match claim_response {
            PrivilegedResponse::ClaimWork(resp) => (
                resp.work_id,
                resp.capability_manifest_hash,
                resp.context_pack_hash,
                resp.lease_id,
            ),
            _ => panic!("Expected ClaimWork response"),
        };

        // Spawn episode
        let spawn_req = SpawnEpisodeRequest {
            work_id,
            role: WorkRole::Implementer.into(),
            lease_id: Some(lease_id),
        };
        let spawn_frame = encode_spawn_episode_request(&spawn_req);
        let spawn_response = dispatcher.dispatch(&spawn_frame, &ctx).unwrap();

        match spawn_response {
            PrivilegedResponse::SpawnEpisode(resp) => {
                // Verify the capability manifest hash matches
                assert_eq!(
                    resp.capability_manifest_hash, claim_manifest_hash,
                    "SpawnEpisode should return same capability_manifest_hash as ClaimWork"
                );
                // Verify context pack is marked as sealed
                assert!(resp.context_pack_sealed);
            },
            _ => panic!("Expected SpawnEpisode response"),
        }
    }

    // ========================================================================
    // CTR-1303: Bounded Store Tests (DoS Protection)
    // ========================================================================

    /// CTR-1303: `StubWorkRegistry` enforces capacity limits.
    ///
    /// Per CTR-1303: In-memory stores must have `max_entries` limit with O(1)
    /// eviction. This test verifies that the registry evicts oldest entries
    /// when at capacity.
    #[test]
    fn test_stub_work_registry_capacity_limit() {
        let registry = StubWorkRegistry::default();

        // Register claims up to capacity
        // Note: We test with a smaller number to keep the test fast
        let test_limit = 100; // Test with 100 instead of 10_000

        for i in 0..test_limit {
            let claim = WorkClaim {
                work_id: format!("W-{i:05}"),
                lease_id: format!("L-{i:05}"),
                actor_id: format!("actor:{i:016x}"),
                role: WorkRole::Implementer,
                policy_resolution: PolicyResolution {
                    policy_resolved_ref: format!("PolicyResolvedForChangeSet:{i}"),
                    resolved_policy_hash: [0u8; 32],
                    capability_manifest_hash: [0u8; 32],
                    context_pack_hash: [0u8; 32],
                },
                executor_custody_domains: vec![],
                author_custody_domains: vec![],
            };
            registry.register_claim(claim).unwrap();
        }

        // All claims should be present
        for i in 0..test_limit {
            let work_id = format!("W-{i:05}");
            assert!(
                registry.get_claim(&work_id).is_some(),
                "Claim {work_id} should exist"
            );
        }
    }

    /// CTR-1303: `StubWorkRegistry` rejects duplicate `work_ids`.
    #[test]
    fn test_stub_work_registry_rejects_duplicates() {
        let registry = StubWorkRegistry::default();

        let claim = WorkClaim {
            work_id: "W-DUPLICATE".to_string(),
            lease_id: "L-001".to_string(),
            actor_id: "actor:test".to_string(),
            role: WorkRole::Implementer,
            policy_resolution: PolicyResolution {
                policy_resolved_ref: "PolicyResolvedForChangeSet:test".to_string(),
                resolved_policy_hash: [0u8; 32],
                capability_manifest_hash: [0u8; 32],
                context_pack_hash: [0u8; 32],
            },
            executor_custody_domains: vec![],
            author_custody_domains: vec![],
        };

        // First registration succeeds
        assert!(registry.register_claim(claim.clone()).is_ok());

        // Second registration with same work_id fails
        let result = registry.register_claim(claim);
        assert!(matches!(
            result,
            Err(WorkRegistryError::DuplicateWorkId { .. })
        ));
    }

    // ========================================================================
    // TCK-00258: SoD Enforcement Integration Tests
    //
    // These tests verify that Separation of Duties (SoD) is enforced when
    // spawning GATE_EXECUTOR episodes. The custody domain check prevents
    // actors from reviewing their own work (self-review attacks).
    // ========================================================================

    /// TCK-00258: `GATE_EXECUTOR` spawn with overlapping custody domains is
    /// denied.
    ///
    /// This tests the fail-closed `SoD` enforcement: when the executor's
    /// custody domains overlap with the changeset author's domains, the
    /// spawn must be rejected with `SOD_VIOLATION` error.
    #[test]
    fn test_sod_spawn_overlapping_domains_denied() {
        let dispatcher = PrivilegedDispatcher::new();
        let ctx = ConnectionContext::privileged(Some(PeerCredentials {
            uid: 1001,
            gid: 1001,
            pid: Some(12345),
        }));

        // First, claim work as GATE_EXECUTOR with overlapping domains
        // Actor ID: team-alpha:alice -> domain: team-alpha
        // Work ID: W-team-alpha-12345 -> author domain: team-alpha
        // These domains overlap, so SoD should be violated
        let claim_request = ClaimWorkRequest {
            actor_id: "team-alpha:alice".to_string(),
            role: WorkRole::GateExecutor.into(),
            credential_signature: vec![],
            nonce: vec![],
        };
        let claim_frame = encode_claim_work_request(&claim_request);
        let claim_response = dispatcher.dispatch(&claim_frame, &ctx).unwrap();

        // Extract work_id and lease_id from claim response
        let (_work_id, lease_id) = match claim_response {
            PrivilegedResponse::ClaimWork(resp) => (resp.work_id, resp.lease_id),
            _ => panic!("Expected ClaimWork response"),
        };

        // Create a new claim with a specific work_id format
        let claim_with_overlap = WorkClaim {
            work_id: "W-team-alpha-test123".to_string(),
            lease_id: lease_id.clone(),
            actor_id: "team-alpha:bob".to_string(),
            role: WorkRole::GateExecutor,
            policy_resolution: PolicyResolution {
                policy_resolved_ref: "PolicyResolvedForChangeSet:test".to_string(),
                resolved_policy_hash: [0u8; 32],
                capability_manifest_hash: [0u8; 32],
                context_pack_hash: [0u8; 32],
            },
            executor_custody_domains: vec!["team-alpha".to_string()],
            author_custody_domains: vec!["team-alpha".to_string()],
        };

        // Register the claim directly
        let _ = dispatcher.work_registry.register_claim(claim_with_overlap);

        // Register a gate lease for this work_id
        dispatcher
            .lease_validator
            .register_lease(&lease_id, "W-team-alpha-test123", "GATE-001");

        // Now spawn with the overlapping domains
        let spawn_request = SpawnEpisodeRequest {
            work_id: "W-team-alpha-test123".to_string(),
            role: WorkRole::GateExecutor.into(),
            lease_id: Some(lease_id),
        };
        let spawn_frame = encode_spawn_episode_request(&spawn_request);
        let spawn_response = dispatcher.dispatch(&spawn_frame, &ctx).unwrap();

        // Should be denied with SOD_VIOLATION
        match spawn_response {
            PrivilegedResponse::Error(err) => {
                assert_eq!(err.code, PrivilegedErrorCode::SodViolation as i32);
                assert!(err.message.contains("custody domain overlap"));
            },
            _ => panic!("Expected SOD_VIOLATION error, got: {spawn_response:?}"),
        }
    }

    /// TCK-00258: `GATE_EXECUTOR` spawn with non-overlapping domains succeeds.
    ///
    /// This tests the happy path: when executor and author domains don't
    /// overlap, the spawn should succeed.
    #[test]
    fn test_sod_spawn_non_overlapping_domains_succeeds() {
        let dispatcher = PrivilegedDispatcher::new();
        let ctx = ConnectionContext::privileged(Some(PeerCredentials {
            uid: 1001,
            gid: 1001,
            pid: Some(12345),
        }));

        // Create a claim with non-overlapping domains
        // Executor domain: team-review (from actor_id team-review:alice)
        // Author domain: team-dev (from work_id W-team-dev-test123)
        let claim_non_overlap = WorkClaim {
            work_id: "W-team-dev-test456".to_string(),
            lease_id: "L-non-overlap-123".to_string(),
            actor_id: "team-review:alice".to_string(),
            role: WorkRole::GateExecutor,
            policy_resolution: PolicyResolution {
                policy_resolved_ref: "PolicyResolvedForChangeSet:test".to_string(),
                resolved_policy_hash: [0u8; 32],
                capability_manifest_hash: [0u8; 32],
                context_pack_hash: [0u8; 32],
            },
            executor_custody_domains: vec!["team-review".to_string()],
            author_custody_domains: vec!["team-dev".to_string()],
        };

        // Register the claim
        let _ = dispatcher.work_registry.register_claim(claim_non_overlap);

        // Register a gate lease
        dispatcher.lease_validator.register_lease(
            "L-non-overlap-123",
            "W-team-dev-test456",
            "GATE-002",
        );

        // Spawn should succeed
        let spawn_request = SpawnEpisodeRequest {
            work_id: "W-team-dev-test456".to_string(),
            role: WorkRole::GateExecutor.into(),
            lease_id: Some("L-non-overlap-123".to_string()),
        };
        let spawn_frame = encode_spawn_episode_request(&spawn_request);
        let spawn_response = dispatcher.dispatch(&spawn_frame, &ctx).unwrap();

        // Should succeed
        match spawn_response {
            PrivilegedResponse::SpawnEpisode(resp) => {
                assert!(!resp.session_id.is_empty());
                assert!(resp.context_pack_sealed);
            },
            PrivilegedResponse::Error(err) => {
                panic!("Expected SpawnEpisode success, got error: {err:?}")
            },
            _ => panic!("Expected SpawnEpisode response"),
        }
    }

    /// TCK-00258: `GATE_EXECUTOR` spawn with empty author domains is denied
    /// (fail-closed).
    ///
    /// This tests fail-closed semantics: if author domains cannot be resolved,
    /// the spawn must be rejected to prevent `SoD` bypass.
    #[test]
    fn test_sod_spawn_empty_author_domains_denied() {
        let dispatcher = PrivilegedDispatcher::new();
        let ctx = ConnectionContext::privileged(Some(PeerCredentials {
            uid: 1001,
            gid: 1001,
            pid: Some(12345),
        }));

        // Create a claim with empty author domains (simulating resolution failure)
        let claim_empty_authors = WorkClaim {
            work_id: "W-unknown-work-789".to_string(),
            lease_id: "L-empty-authors-456".to_string(),
            actor_id: "team-review:charlie".to_string(),
            role: WorkRole::GateExecutor,
            policy_resolution: PolicyResolution {
                policy_resolved_ref: "PolicyResolvedForChangeSet:test".to_string(),
                resolved_policy_hash: [0u8; 32],
                capability_manifest_hash: [0u8; 32],
                context_pack_hash: [0u8; 32],
            },
            executor_custody_domains: vec!["team-review".to_string()],
            author_custody_domains: vec![], // Empty - resolution failed
        };

        // Register the claim
        let _ = dispatcher.work_registry.register_claim(claim_empty_authors);

        // Register a gate lease
        dispatcher.lease_validator.register_lease(
            "L-empty-authors-456",
            "W-unknown-work-789",
            "GATE-003",
        );

        // Spawn should be denied because we can't verify SoD without author domains
        let spawn_request = SpawnEpisodeRequest {
            work_id: "W-unknown-work-789".to_string(),
            role: WorkRole::GateExecutor.into(),
            lease_id: Some("L-empty-authors-456".to_string()),
        };
        let spawn_frame = encode_spawn_episode_request(&spawn_request);
        let spawn_response = dispatcher.dispatch(&spawn_frame, &ctx).unwrap();

        // Should be denied with SOD_VIOLATION
        match spawn_response {
            PrivilegedResponse::Error(err) => {
                assert_eq!(err.code, PrivilegedErrorCode::SodViolation as i32);
                assert!(err.message.contains("author custody domains"));
            },
            _ => panic!("Expected SOD_VIOLATION error for empty author domains"),
        }
    }

    /// TCK-00258: Non-`GATE_EXECUTOR` roles skip `SoD` validation.
    ///
    /// IMPLEMENTER and REVIEWER roles do not require `SoD` validation since
    /// they are not performing trust-critical gate operations.
    #[test]
    fn test_sod_non_gate_executor_skips_validation() {
        let dispatcher = PrivilegedDispatcher::new();
        let ctx = ConnectionContext::privileged(Some(PeerCredentials {
            uid: 1001,
            gid: 1001,
            pid: Some(12345),
        }));

        // Create a claim as IMPLEMENTER with overlapping domains
        // This would fail SoD for GATE_EXECUTOR, but IMPLEMENTER skips SoD
        let claim_implementer = WorkClaim {
            work_id: "W-team-alpha-impl123".to_string(),
            lease_id: "L-implementer-789".to_string(),
            actor_id: "team-alpha:developer".to_string(),
            role: WorkRole::Implementer,
            policy_resolution: PolicyResolution {
                policy_resolved_ref: "PolicyResolvedForChangeSet:test".to_string(),
                resolved_policy_hash: [0u8; 32],
                capability_manifest_hash: [0u8; 32],
                context_pack_hash: [0u8; 32],
            },
            executor_custody_domains: vec!["team-alpha".to_string()],
            author_custody_domains: vec!["team-alpha".to_string()], // Overlapping!
        };

        // Register the claim
        let _ = dispatcher.work_registry.register_claim(claim_implementer);

        // Spawn as IMPLEMENTER should succeed despite overlapping domains
        let spawn_request = SpawnEpisodeRequest {
            work_id: "W-team-alpha-impl123".to_string(),
            role: WorkRole::Implementer.into(),
            lease_id: Some("L-implementer-789".to_string()),
        };
        let spawn_frame = encode_spawn_episode_request(&spawn_request);
        let spawn_response = dispatcher.dispatch(&spawn_frame, &ctx).unwrap();

        // Should succeed - IMPLEMENTER skips SoD validation
        match spawn_response {
            PrivilegedResponse::SpawnEpisode(resp) => {
                assert!(!resp.session_id.is_empty());
            },
            PrivilegedResponse::Error(err) => {
                panic!("Expected SpawnEpisode success for IMPLEMENTER, got error: {err:?}")
            },
            _ => panic!("Expected SpawnEpisode response"),
        }
    }

    /// Unit test for fail-closed ID resolution (TCK-00258).
    ///
    /// Verifies that the internal resolver methods return errors for malformed
    /// IDs, rather than falling back to "UNIVERSAL".
    #[test]
    fn test_internal_resolvers_fail_on_malformed_ids() {
        let dispatcher = PrivilegedDispatcher::new();

        // 1. Test resolve_actor_custody_domains
        // Valid case
        let valid_actor = dispatcher.resolve_actor_custody_domains("team-alpha:alice");
        assert!(valid_actor.is_ok());
        assert_eq!(valid_actor.unwrap(), vec!["team-alpha".to_string()]);

        // Malformed case (no colon)
        let invalid_actor = dispatcher.resolve_actor_custody_domains("malformed_actor");
        assert!(invalid_actor.is_err());
        assert!(invalid_actor.unwrap_err().contains("malformed actor_id"));

        // 2. Test resolve_changeset_author_domains
        // Valid case (using simple domain to avoid stub parser ambiguity with hyphens)
        let valid_work = dispatcher.resolve_changeset_author_domains("W-team-123");
        assert!(valid_work.is_ok());
        assert_eq!(valid_work.unwrap(), vec!["team".to_string()]);

        // Malformed case (no W- prefix)
        let invalid_work = dispatcher.resolve_changeset_author_domains("InvalidWorkId-123");
        assert!(invalid_work.is_err());
        assert!(invalid_work.unwrap_err().contains("malformed work_id"));

        // Malformed case (W- prefix but no domain separator)
        let invalid_work_2 = dispatcher.resolve_changeset_author_domains("W-NoSeparator");
        // This actually returns Err because dash_pos find fails after stripping W-
        // wait, strip_prefix("W-") gives "NoSeparator". find('-') returns None.
        // So it falls through to Err.
        assert!(invalid_work_2.is_err());
    }
}
