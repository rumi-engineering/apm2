//! Protocol buffer message types for daemon-client communication.
//!
//! This module provides the generated Protocol Buffer message types for the
//! daemon runtime protocol, along with helper methods for canonical encoding
//! and type conversions.
//!
//! # Message Categories
//!
//! Messages are organized per AD-DAEMON-003 and CTR-PROTO contracts:
//!
//! - **CTR-PROTO-001 (Handshake)**: [`Hello`], [`HelloAck`], [`ClientInfo`],
//!   [`ServerInfo`]
//! - **CTR-PROTO-002 (Episode Control)**: [`CreateEpisode`],
//!   [`EpisodeCreated`], [`StartEpisode`], [`EpisodeStarted`], [`StopEpisode`],
//!   [`EpisodeStopped`], [`SignalEpisode`], [`ResizePty`],
//!   [`EpisodeQuarantined`]
//! - **CTR-PROTO-003 (I/O)**: [`SendInput`], [`StreamOutput`], [`StreamKind`]
//! - **CTR-PROTO-004 (Tool Mediation)**: [`ToolRequest`], [`ToolDecision`],
//!   [`ToolResult`], [`DecisionType`], [`ToolOutcome`], [`BudgetDelta`]
//! - **CTR-PROTO-005 (Telemetry)**: [`TelemetryFrame`], [`TelemetryPolicy`],
//!   [`CgroupStats`], [`PromoteTrigger`], [`RingBufferLimits`]
//! - **CTR-PROTO-006 (Receipts/Evidence)**: [`Receipt`], [`PublishEvidence`],
//!   [`EvidencePinned`], [`EvidenceTtlExpired`], [`CompactionCompleted`],
//!   [`ReceiptKind`], [`EvidenceKind`], [`RetentionHint`]
//! - **CTR-PROTO-010 (HEF Pulse Plane)**: [`PulseEnvelopeV1`], [`EntityRef`],
//!   [`CasRef`], [`HlcStamp`], [`BoundedWallInterval`],
//!   [`SubscribePulseRequest`], [`SubscribePulseResponse`],
//!   [`PatternRejection`], [`UnsubscribePulseRequest`],
//!   [`UnsubscribePulseResponse`], [`PulseEvent`], [`HefError`],
//!   [`HefErrorCode`]
//!
//! # Canonical Encoding
//!
//! Per AD-DAEMON-003 and AD-VERIFY-001, signed messages require deterministic
//! serialization. The [`Canonicalize`] trait is implemented for messages that
//! participate in signing workflows:
//!
//! ```rust,ignore
//! use apm2_daemon::protocol::messages::{Receipt, Canonicalize};
//! use prost::Message;
//!
//! let mut receipt = Receipt {
//!     kind: 0,
//!     unsigned_bytes_hash: vec![0u8; 32],
//!     signature: vec![],  // Empty for unsigned canonical bytes
//!     // ... other fields
//!     ..Default::default()
//! };
//!
//! receipt.canonicalize();
//! let canonical_bytes = receipt.canonical_bytes();
//! // Use canonical_bytes for signing
//! ```
//!
//! # The Unsigned Canonical Bytes Rule
//!
//! Per AD-VERIFY-001, authoritative signing is performed over the "Unsigned
//! Canonical Bytes" of a message. This is defined as the Protobuf-encoded bytes
//! of the message where the `signature` and any `issuer_signature` fields are
//! set to their default (empty) values.

#[allow(
    clippy::derive_partial_eq_without_eq,
    clippy::doc_markdown,
    clippy::match_single_binding,
    clippy::missing_const_for_fn,
    clippy::redundant_closure,
    clippy::struct_field_names,
    missing_docs
)]
mod generated {
    include!("apm2.daemon.v1.rs");
}

pub use generated::*;
use prost::Message;

// ============================================================================
// Bounded Decoding (CTR-1603, RSK-1601)
// ============================================================================

/// Default maximum message size for bounded decoding (64 MiB).
///
/// Per security review findings, this limit prevents denial-of-service attacks
/// where a malicious peer sends oversized messages to exhaust memory. The limit
/// is intentionally larger than `MAX_FRAME_SIZE` (16 MiB) to allow for future
/// protocol extensions while still providing protection.
pub const DEFAULT_MAX_MESSAGE_SIZE: usize = 64 * 1024 * 1024;

/// Default maximum count for repeated fields.
///
/// Per security review findings, this limit prevents denial-of-service attacks
/// where a malicious peer sends messages with millions of repeated field
/// entries.
pub const DEFAULT_MAX_REPEATED_FIELD_COUNT: usize = 100_000;

/// Configuration for bounded message decoding.
///
/// # Security Considerations
///
/// Per CTR-1603 and RSK-1601, all untrusted message decoding must enforce
/// explicit bounds to prevent denial-of-service attacks:
///
/// - `max_message_size`: Limits total message bytes
/// - `max_repeated_field_count`: Limits repeated field element counts
///
/// These limits are validated during decoding to prevent memory exhaustion
/// before allocations occur.
#[derive(Debug, Clone, Copy)]
pub struct DecodeConfig {
    /// Maximum allowed message size in bytes.
    pub max_message_size: usize,
    /// Maximum allowed count for any repeated field.
    pub max_repeated_field_count: usize,
}

impl Default for DecodeConfig {
    fn default() -> Self {
        Self {
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
            max_repeated_field_count: DEFAULT_MAX_REPEATED_FIELD_COUNT,
        }
    }
}

impl DecodeConfig {
    /// Creates a new decode configuration with custom limits.
    #[must_use]
    pub const fn new(max_message_size: usize, max_repeated_field_count: usize) -> Self {
        Self {
            max_message_size,
            max_repeated_field_count,
        }
    }

    /// Creates a strict configuration for handshake messages.
    ///
    /// Uses tighter limits appropriate for the unauthenticated handshake phase.
    #[must_use]
    pub const fn handshake() -> Self {
        Self {
            max_message_size: 64 * 1024, // 64 KiB
            max_repeated_field_count: 1_000,
        }
    }
}

/// Error returned when bounded decoding fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// Message size exceeds the configured limit.
    MessageTooLarge {
        /// Actual size of the message in bytes.
        size: usize,
        /// Maximum allowed size.
        max: usize,
    },
    /// A repeated field exceeds the configured count limit.
    RepeatedFieldTooLarge {
        /// Name of the field that exceeded the limit.
        field: &'static str,
        /// Actual count of elements.
        count: usize,
        /// Maximum allowed count.
        max: usize,
    },
    /// Underlying prost decode error.
    Prost(String),
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MessageTooLarge { size, max } => {
                write!(
                    f,
                    "message too large: {size} bytes exceeds maximum {max} bytes"
                )
            },
            Self::RepeatedFieldTooLarge { field, count, max } => {
                write!(
                    f,
                    "repeated field '{field}' too large: {count} elements exceeds maximum {max}"
                )
            },
            Self::Prost(msg) => write!(f, "protobuf decode error: {msg}"),
        }
    }
}

impl std::error::Error for DecodeError {}

impl From<prost::DecodeError> for DecodeError {
    fn from(err: prost::DecodeError) -> Self {
        Self::Prost(err.to_string())
    }
}

/// Trait for bounded message decoding.
///
/// This trait extends prost's `Message` trait to provide size-validated
/// decoding that prevents denial-of-service attacks from oversized messages.
///
/// # Security Contract: CTR-1603
///
/// All implementations MUST:
/// 1. Validate message size BEFORE decoding
/// 2. Validate repeated field counts AFTER decoding
/// 3. Return appropriate `DecodeError` variants for violations
pub trait BoundedDecode: Message + Default + Sized {
    /// Decodes a message from bytes with size validation.
    ///
    /// # Arguments
    ///
    /// * `buf` - The bytes to decode from
    /// * `config` - Configuration specifying size and count limits
    ///
    /// # Errors
    ///
    /// Returns `DecodeError::MessageTooLarge` if the buffer exceeds the
    /// configured `max_message_size`.
    ///
    /// Returns `DecodeError::RepeatedFieldTooLarge` if any repeated field
    /// exceeds the configured `max_repeated_field_count`.
    ///
    /// Returns `DecodeError::Prost` for underlying protobuf decode errors.
    fn decode_bounded(buf: &[u8], config: &DecodeConfig) -> Result<Self, DecodeError>;

    /// Decodes a message from bytes with default configuration.
    ///
    /// Convenience method that uses [`DecodeConfig::default()`].
    fn decode_bounded_default(buf: &[u8]) -> Result<Self, DecodeError> {
        Self::decode_bounded(buf, &DecodeConfig::default())
    }
}

/// Macro to implement `BoundedDecode` for messages without repeated fields.
macro_rules! impl_bounded_decode_simple {
    ($($ty:ty),* $(,)?) => {
        $(
            impl BoundedDecode for $ty {
                fn decode_bounded(buf: &[u8], config: &DecodeConfig) -> Result<Self, DecodeError> {
                    // CTR-1603: Validate size BEFORE decoding
                    if buf.len() > config.max_message_size {
                        return Err(DecodeError::MessageTooLarge {
                            size: buf.len(),
                            max: config.max_message_size,
                        });
                    }

                    // Decode using prost
                    let msg = Self::decode(buf)?;
                    Ok(msg)
                }
            }
        )*
    };
}

/// Macro to implement `BoundedDecode` for messages with repeated fields.
macro_rules! impl_bounded_decode_with_repeated {
    ($ty:ty, $($field:ident),* $(,)?) => {
        impl BoundedDecode for $ty {
            fn decode_bounded(buf: &[u8], config: &DecodeConfig) -> Result<Self, DecodeError> {
                // CTR-1603: Validate size BEFORE decoding
                if buf.len() > config.max_message_size {
                    return Err(DecodeError::MessageTooLarge {
                        size: buf.len(),
                        max: config.max_message_size,
                    });
                }

                // Decode using prost
                let msg = Self::decode(buf)?;

                // Validate repeated field counts AFTER decoding
                $(
                    if msg.$field.len() > config.max_repeated_field_count {
                        return Err(DecodeError::RepeatedFieldTooLarge {
                            field: stringify!($field),
                            count: msg.$field.len(),
                            max: config.max_repeated_field_count,
                        });
                    }
                )*

                Ok(msg)
            }
        }
    };
}

// Implement BoundedDecode for messages without repeated fields
impl_bounded_decode_simple!(
    ClientInfo,
    ServerInfo,
    CreateEpisode,
    EpisodeCreated,
    StartEpisode,
    EpisodeStarted,
    StopEpisode,
    EpisodeStopped,
    SignalEpisode,
    ResizePty,
    SendInput,
    StreamOutput,
    ToolRequest,
    ToolDecision,
    ToolResult,
    BudgetDelta,
    TelemetryFrame,
    CgroupStats,
    RingBufferLimits,
    PublishEvidence,
    EvidencePinned,
    EvidenceTtlExpired,
    PromoteTrigger,
    // CTR-PROTO-007: Privileged Endpoints (RFC-0017)
    ClaimWorkRequest,
    ClaimWorkResponse,
    SpawnEpisodeRequest,
    SpawnEpisodeResponse,
    IssueCapabilityRequest,
    IssueCapabilityResponse,
    ShutdownRequest,
    ShutdownResponse,
    PrivilegedError,
    // CTR-PROTO-008: Session-Scoped Endpoints (RFC-0017, TCK-00252)
    RequestToolRequest,
    RequestToolResponse,
    EmitEventRequest,
    EmitEventResponse,
    PublishEvidenceRequest,
    PublishEvidenceResponse,
    StreamTelemetryRequest,
    StreamTelemetryResponse,
    SessionError,
    // CTR-PROTO-009: Crash Recovery Signals (TCK-00267)
    LeaseRevoked,
    RecoverSessionsRequest,
    RecoverSessionsResponse,
    // CTR-PROTO-010: HEF Pulse Plane (RFC-0018, TCK-00300)
    // Simple messages without repeated fields
    EntityRef,
    CasRef,
    HlcStamp,
    BoundedWallInterval,
    PatternRejection,
    UnsubscribePulseRequest,
    UnsubscribePulseResponse,
    PulseEvent,
    HefError,
    // CTR-PROTO-011: Process Management Endpoints (TCK-00342)
    ListProcessesRequest,
    ProcessInfo,
    ProcessStatusRequest,
    ProcessStatusResponse,
    StartProcessRequest,
    StartProcessResponse,
    StopProcessRequest,
    StopProcessResponse,
    RestartProcessRequest,
    RestartProcessResponse,
    ReloadProcessRequest,
    ReloadProcessResponse,
    StreamLogsRequest,
    LogEntry,
);

// Implement BoundedDecode for messages with repeated fields
impl_bounded_decode_with_repeated!(Hello, requested_caps);
impl_bounded_decode_with_repeated!(HelloAck, granted_caps);
impl_bounded_decode_with_repeated!(EpisodeQuarantined, evidence_pinned);
impl_bounded_decode_with_repeated!(Receipt, evidence_refs);
impl_bounded_decode_with_repeated!(CompactionCompleted, tombstoned_hashes);
impl_bounded_decode_with_repeated!(TelemetryPolicy, promote_triggers);
// CTR-PROTO-007: Privileged Endpoints (RFC-0017)
impl_bounded_decode_with_repeated!(CapabilityRequest, read_patterns, write_patterns);
// CTR-PROTO-010: HEF Pulse Plane (RFC-0018, TCK-00300)
impl_bounded_decode_with_repeated!(PulseEnvelopeV1, entities, cas_refs);
impl_bounded_decode_with_repeated!(SubscribePulseRequest, topic_patterns);
impl_bounded_decode_with_repeated!(SubscribePulseResponse, accepted_patterns, rejected_patterns);
// CTR-PROTO-011: Process Management Endpoints (TCK-00342)
impl_bounded_decode_with_repeated!(ListProcessesResponse, processes);
impl_bounded_decode_with_repeated!(StreamLogsResponse, entries);

// ============================================================================
// HEF Field Bounds (CTR-HEF-0001, REQ-HEF-0002, RFC-0018)
// ============================================================================

/// Maximum size for `PulseEnvelopeV1` in bytes.
/// Per INV-HEF-001: "`PulseEnvelopeV1` max size: 2048 bytes"
pub const HEF_MAX_ENVELOPE_SIZE: usize = 2048;

/// Maximum number of entities in a `PulseEnvelopeV1`.
/// Per REQ-HEF-0002: "Max entities: 8"
pub const HEF_MAX_ENTITIES: usize = 8;

/// Maximum number of CAS references in a `PulseEnvelopeV1`.
/// Per REQ-HEF-0002: "Max `cas_refs`: 8"
pub const HEF_MAX_CAS_REFS: usize = 8;

/// Maximum length for `pulse_id` in a `PulseEnvelopeV1`.
/// Per REQ-HEF-0002: "`pulse_id`: max 64 chars, ASCII only"
pub const HEF_MAX_PULSE_ID_LEN: usize = 64;

/// Maximum length for `topic` in a `PulseEnvelopeV1`.
/// Per REQ-HEF-0002: "`topic`: max 128 chars, ASCII only, dot-delimited"
pub const HEF_MAX_TOPIC_LEN: usize = 128;

/// Maximum length for `event_type` in a `PulseEnvelopeV1`.
/// Per REQ-HEF-0002: "`event_type`: max 64 chars"
pub const HEF_MAX_EVENT_TYPE_LEN: usize = 64;

/// Maximum length for `kind` in an `EntityRef`.
/// Per CTR-HEF-0001: "Max length: 16 characters, ASCII only"
pub const HEF_MAX_ENTITY_KIND_LEN: usize = 16;

/// Maximum length for `id` in an `EntityRef`.
/// Per CTR-HEF-0001: "Max length: 128 characters, ASCII only"
pub const HEF_MAX_ENTITY_ID_LEN: usize = 128;

/// Maximum length for `kind` in a `CasRef`.
/// Per CTR-HEF-0001: "Max length: 32 characters, ASCII only"
pub const HEF_MAX_CAS_KIND_LEN: usize = 32;

/// Maximum number of topic patterns in a `SubscribePulseRequest`.
/// Per RFC-0018: "Max `topic_patterns`: 16"
pub const HEF_MAX_TOPIC_PATTERNS: usize = 16;

/// Maximum length for each topic pattern.
/// Per RFC-0018: "Each pattern: max 128 chars, ASCII only"
pub const HEF_MAX_PATTERN_LEN: usize = 128;

/// Maximum length for `client_sub_id` in a `SubscribePulseRequest`.
/// Per RFC-0018: "Max length: 64 characters"
pub const HEF_MAX_CLIENT_SUB_ID_LEN: usize = 64;

/// Error type for HEF field bounds validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HefValidationError {
    /// Envelope exceeds maximum size.
    EnvelopeTooLarge {
        /// Actual size in bytes.
        size: usize,
        /// Maximum allowed size.
        max: usize,
    },
    /// String field exceeds maximum length.
    FieldTooLong {
        /// Name of the field.
        field: &'static str,
        /// Actual length.
        len: usize,
        /// Maximum allowed length.
        max: usize,
    },
    /// Repeated field exceeds maximum count.
    TooManyItems {
        /// Name of the field.
        field: &'static str,
        /// Actual count.
        count: usize,
        /// Maximum allowed count.
        max: usize,
    },
    /// String field contains non-ASCII characters.
    NonAscii {
        /// Name of the field.
        field: &'static str,
    },
}

impl std::fmt::Display for HefValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EnvelopeTooLarge { size, max } => {
                write!(
                    f,
                    "pulse envelope too large: {size} bytes exceeds maximum {max} bytes"
                )
            },
            Self::FieldTooLong { field, len, max } => {
                write!(
                    f,
                    "field '{field}' too long: {len} characters exceeds maximum {max}"
                )
            },
            Self::TooManyItems { field, count, max } => {
                write!(
                    f,
                    "field '{field}' has too many items: {count} exceeds maximum {max}"
                )
            },
            Self::NonAscii { field } => {
                write!(f, "field '{field}' contains non-ASCII characters")
            },
        }
    }
}

impl std::error::Error for HefValidationError {}

/// Validates an ASCII string field.
#[allow(clippy::missing_const_for_fn)] // str::is_ascii() prevents const
fn validate_ascii_field(
    value: &str,
    field: &'static str,
    max_len: usize,
) -> Result<(), HefValidationError> {
    if value.len() > max_len {
        return Err(HefValidationError::FieldTooLong {
            field,
            len: value.len(),
            max: max_len,
        });
    }
    if !value.is_ascii() {
        return Err(HefValidationError::NonAscii { field });
    }
    Ok(())
}

impl EntityRef {
    /// Validates the `EntityRef` against HEF field bounds (CTR-HEF-0001).
    ///
    /// # Errors
    ///
    /// Returns `HefValidationError` if:
    /// - `kind` exceeds 16 characters or contains non-ASCII
    /// - `id` exceeds 128 characters or contains non-ASCII
    pub fn validate(&self) -> Result<(), HefValidationError> {
        validate_ascii_field(&self.kind, "EntityRef.kind", HEF_MAX_ENTITY_KIND_LEN)?;
        validate_ascii_field(&self.id, "EntityRef.id", HEF_MAX_ENTITY_ID_LEN)?;
        Ok(())
    }
}

impl CasRef {
    /// Validates the `CasRef` against HEF field bounds (CTR-HEF-0001).
    ///
    /// # Errors
    ///
    /// Returns `HefValidationError` if:
    /// - `kind` exceeds 32 characters or contains non-ASCII
    pub fn validate(&self) -> Result<(), HefValidationError> {
        validate_ascii_field(&self.kind, "CasRef.kind", HEF_MAX_CAS_KIND_LEN)?;
        Ok(())
    }
}

impl PatternRejection {
    /// Validates the `PatternRejection` against HEF field bounds.
    ///
    /// # Errors
    ///
    /// Returns `HefValidationError` if:
    /// - `pattern` exceeds 128 characters
    pub fn validate(&self) -> Result<(), HefValidationError> {
        if self.pattern.len() > HEF_MAX_PATTERN_LEN {
            return Err(HefValidationError::FieldTooLong {
                field: "PatternRejection.pattern",
                len: self.pattern.len(),
                max: HEF_MAX_PATTERN_LEN,
            });
        }
        Ok(())
    }
}

impl PulseEnvelopeV1 {
    /// Validates the `PulseEnvelopeV1` against HEF field bounds (CTR-HEF-0001,
    /// REQ-HEF-0002).
    ///
    /// # Errors
    ///
    /// Returns `HefValidationError` if any field constraint is violated:
    /// - Envelope size exceeds 2048 bytes
    /// - `entities` count exceeds 8
    /// - `cas_refs` count exceeds 8
    /// - `pulse_id` exceeds 64 characters or contains non-ASCII
    /// - `topic` exceeds 128 characters or contains non-ASCII
    /// - `event_type` exceeds 64 characters
    pub fn validate(&self) -> Result<(), HefValidationError> {
        // Check repeated field counts
        if self.entities.len() > HEF_MAX_ENTITIES {
            return Err(HefValidationError::TooManyItems {
                field: "entities",
                count: self.entities.len(),
                max: HEF_MAX_ENTITIES,
            });
        }
        if self.cas_refs.len() > HEF_MAX_CAS_REFS {
            return Err(HefValidationError::TooManyItems {
                field: "cas_refs",
                count: self.cas_refs.len(),
                max: HEF_MAX_CAS_REFS,
            });
        }

        // Check string field lengths and ASCII
        validate_ascii_field(&self.pulse_id, "pulse_id", HEF_MAX_PULSE_ID_LEN)?;
        validate_ascii_field(&self.topic, "topic", HEF_MAX_TOPIC_LEN)?;
        if self.event_type.len() > HEF_MAX_EVENT_TYPE_LEN {
            return Err(HefValidationError::FieldTooLong {
                field: "event_type",
                len: self.event_type.len(),
                max: HEF_MAX_EVENT_TYPE_LEN,
            });
        }

        // Validate nested entities and CAS refs
        for entity in &self.entities {
            entity.validate()?;
        }
        for cas_ref in &self.cas_refs {
            cas_ref.validate()?;
        }

        // Check total encoded size
        let encoded_size = self.encode_to_vec().len();
        if encoded_size > HEF_MAX_ENVELOPE_SIZE {
            return Err(HefValidationError::EnvelopeTooLarge {
                size: encoded_size,
                max: HEF_MAX_ENVELOPE_SIZE,
            });
        }

        Ok(())
    }
}

impl SubscribePulseRequest {
    /// Validates the `SubscribePulseRequest` against HEF field bounds.
    ///
    /// # Errors
    ///
    /// Returns `HefValidationError` if:
    /// - `topic_patterns` count exceeds 16
    /// - Any pattern exceeds 128 characters or contains non-ASCII
    /// - `client_sub_id` exceeds 64 characters
    pub fn validate(&self) -> Result<(), HefValidationError> {
        if self.topic_patterns.len() > HEF_MAX_TOPIC_PATTERNS {
            return Err(HefValidationError::TooManyItems {
                field: "topic_patterns",
                count: self.topic_patterns.len(),
                max: HEF_MAX_TOPIC_PATTERNS,
            });
        }

        for pattern in &self.topic_patterns {
            validate_ascii_field(pattern, "topic_patterns[]", HEF_MAX_PATTERN_LEN)?;
        }

        if self.client_sub_id.len() > HEF_MAX_CLIENT_SUB_ID_LEN {
            return Err(HefValidationError::FieldTooLong {
                field: "client_sub_id",
                len: self.client_sub_id.len(),
                max: HEF_MAX_CLIENT_SUB_ID_LEN,
            });
        }

        Ok(())
    }
}

impl SubscribePulseResponse {
    /// Validates the `SubscribePulseResponse` against HEF field bounds.
    ///
    /// # Errors
    ///
    /// Returns `HefValidationError` if any nested `PatternRejection` is
    /// invalid.
    pub fn validate(&self) -> Result<(), HefValidationError> {
        for rejection in &self.rejected_patterns {
            rejection.validate()?;
        }
        Ok(())
    }
}

/// Trait for canonicalizing messages before signing.
///
/// Types implementing this trait have repeated fields that must be sorted
/// to ensure deterministic encoding. Call `canonicalize()` before computing
/// signatures or hashes.
pub trait Canonicalize {
    /// Sorts all repeated fields to ensure canonical encoding.
    ///
    /// This method modifies the message in place, sorting any repeated fields
    /// in lexicographic order (for strings) or ascending order (for byte
    /// arrays).
    fn canonicalize(&mut self);
}

/// Trait for messages that support unsigned canonical bytes extraction.
///
/// This trait is implemented by messages that participate in signing workflows.
/// Per AD-VERIFY-001, the canonical bytes exclude signature fields.
pub trait CanonicalBytes: Message + Clone {
    /// Returns the unsigned canonical bytes for signing.
    ///
    /// This method returns the Protobuf-encoded bytes with signature fields
    /// cleared (set to empty), ensuring a stable fixpoint for verification.
    fn canonical_bytes(&self) -> Vec<u8>;
}

// ============================================================================
// Canonicalize implementations
// ============================================================================

impl Canonicalize for Hello {
    fn canonicalize(&mut self) {
        self.requested_caps.sort();
    }
}

impl Canonicalize for HelloAck {
    fn canonicalize(&mut self) {
        self.granted_caps.sort();
        // Note: BTreeMap is already sorted by key, so canonicalizer_versions
        // is deterministically ordered.
    }
}

impl Canonicalize for EpisodeQuarantined {
    fn canonicalize(&mut self) {
        self.evidence_pinned.sort();
    }
}

impl Canonicalize for Receipt {
    fn canonicalize(&mut self) {
        self.evidence_refs.sort();
    }
}

impl Canonicalize for CompactionCompleted {
    fn canonicalize(&mut self) {
        self.tombstoned_hashes.sort();
    }
}

impl Canonicalize for TelemetryPolicy {
    fn canonicalize(&mut self) {
        // Sort promote_triggers by (metric, threshold) for total ordering.
        // Uses f64::total_cmp for threshold to handle NaN and -0.0 consistently.
        self.promote_triggers.sort_by(|a, b| {
            a.metric
                .cmp(&b.metric)
                .then_with(|| a.threshold.total_cmp(&b.threshold))
        });
    }
}

// ============================================================================
// CanonicalBytes implementations
// ============================================================================

impl CanonicalBytes for Receipt {
    fn canonical_bytes(&self) -> Vec<u8> {
        // Create a copy with signature fields cleared
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        unsigned.issuer_signature = None;
        // Per AD-VERIFY-001: canonical bytes require sorted repeated fields
        unsigned.canonicalize();
        unsigned.encode_to_vec()
    }
}

impl CanonicalBytes for Hello {
    fn canonical_bytes(&self) -> Vec<u8> {
        // Per AD-VERIFY-001: canonical bytes require sorted repeated fields
        let mut copy = self.clone();
        copy.canonicalize();
        copy.encode_to_vec()
    }
}

impl CanonicalBytes for HelloAck {
    fn canonical_bytes(&self) -> Vec<u8> {
        // Per AD-VERIFY-001: canonical bytes require sorted repeated fields
        let mut copy = self.clone();
        copy.canonicalize();
        copy.encode_to_vec()
    }
}

impl CanonicalBytes for TelemetryFrame {
    fn canonical_bytes(&self) -> Vec<u8> {
        self.encode_to_vec()
    }
}

impl CanonicalBytes for ToolRequest {
    fn canonical_bytes(&self) -> Vec<u8> {
        self.encode_to_vec()
    }
}

impl CanonicalBytes for ToolDecision {
    fn canonical_bytes(&self) -> Vec<u8> {
        self.encode_to_vec()
    }
}

impl CanonicalBytes for ToolResult {
    fn canonical_bytes(&self) -> Vec<u8> {
        self.encode_to_vec()
    }
}

// Note: From<Enum> for i32 implementations are provided by prost::Enumeration
// derive

// ============================================================================
// Builder helpers
// ============================================================================

impl Hello {
    /// Creates a new `Hello` message with the given protocol version.
    #[must_use]
    pub const fn new(protocol_version: u32) -> Self {
        Self {
            protocol_version,
            client_info: None,
            requested_caps: Vec::new(),
        }
    }

    /// Sets the client info.
    #[must_use]
    pub fn with_client_info(mut self, name: impl Into<String>, version: impl Into<String>) -> Self {
        self.client_info = Some(ClientInfo {
            name: name.into(),
            version: version.into(),
        });
        self
    }

    /// Adds a requested capability.
    #[must_use]
    pub fn with_capability(mut self, cap: impl Into<String>) -> Self {
        self.requested_caps.push(cap.into());
        self
    }
}

impl HelloAck {
    /// Creates a new `HelloAck` message.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the server info.
    #[must_use]
    pub fn with_server_info(mut self, name: impl Into<String>, version: impl Into<String>) -> Self {
        self.server_info = Some(ServerInfo {
            name: name.into(),
            version: version.into(),
        });
        self
    }

    /// Adds a granted capability.
    #[must_use]
    pub fn with_granted_cap(mut self, cap: impl Into<String>) -> Self {
        self.granted_caps.push(cap.into());
        self
    }

    /// Sets the policy hash.
    #[must_use]
    pub fn with_policy_hash(mut self, hash: Vec<u8>) -> Self {
        self.policy_hash = hash;
        self
    }
}

impl Receipt {
    /// Creates a new Receipt with the given kind.
    #[must_use]
    pub fn new(kind: ReceiptKind) -> Self {
        Self {
            kind: kind.into(),
            unsigned_bytes_hash: Vec::new(),
            signature: Vec::new(),
            evidence_refs: Vec::new(),
            policy_hash: Vec::new(),
            envelope_hash: Vec::new(),
            issuer_id: None,
            issuer_signature: None,
        }
    }

    /// Sets the envelope hash.
    #[must_use]
    pub fn with_envelope_hash(mut self, hash: Vec<u8>) -> Self {
        self.envelope_hash = hash;
        self
    }

    /// Sets the policy hash.
    #[must_use]
    pub fn with_policy_hash(mut self, hash: Vec<u8>) -> Self {
        self.policy_hash = hash;
        self
    }

    /// Adds an evidence reference.
    #[must_use]
    pub fn with_evidence_ref(mut self, evidence_ref: Vec<u8>) -> Self {
        self.evidence_refs.push(evidence_ref);
        self
    }

    /// Computes and sets the unsigned bytes hash using BLAKE3.
    ///
    /// This should be called after all other fields are set but before signing.
    #[must_use]
    pub fn compute_unsigned_bytes_hash(mut self) -> Self {
        let canonical = self.canonical_bytes();
        self.unsigned_bytes_hash = blake3::hash(&canonical).as_bytes().to_vec();
        self
    }
}

impl TelemetryFrame {
    /// Creates a new `TelemetryFrame` for the given episode.
    #[must_use]
    pub fn new(episode_id: impl Into<String>, seq: u64, ts_mono: u64) -> Self {
        Self {
            episode_id: episode_id.into(),
            seq,
            ts_mono,
            cpu_ns: 0,
            mem_rss_bytes: 0,
            io_read_bytes: 0,
            io_write_bytes: 0,
            cgroup_stats: None,
            o11y_flags: 0,
        }
    }

    /// Sets CPU nanoseconds.
    #[must_use]
    pub const fn with_cpu_ns(mut self, cpu_ns: u64) -> Self {
        self.cpu_ns = cpu_ns;
        self
    }

    /// Sets memory RSS bytes.
    #[must_use]
    pub const fn with_mem_rss_bytes(mut self, mem_rss_bytes: u64) -> Self {
        self.mem_rss_bytes = mem_rss_bytes;
        self
    }

    /// Sets I/O read/write bytes.
    #[must_use]
    pub const fn with_io_bytes(mut self, read_bytes: u64, write_bytes: u64) -> Self {
        self.io_read_bytes = read_bytes;
        self.io_write_bytes = write_bytes;
        self
    }

    /// Sets cgroup stats.
    #[must_use]
    pub const fn with_cgroup_stats(mut self, stats: CgroupStats) -> Self {
        self.cgroup_stats = Some(stats);
        self
    }
}

impl StreamOutput {
    /// Creates a new stdout output chunk.
    #[must_use]
    pub fn stdout(chunk: Vec<u8>, seq: u64, ts: u64) -> Self {
        Self {
            chunk,
            kind: StreamKind::Stdout.into(),
            seq,
            ts,
        }
    }

    /// Creates a new stderr output chunk.
    #[must_use]
    pub fn stderr(chunk: Vec<u8>, seq: u64, ts: u64) -> Self {
        Self {
            chunk,
            kind: StreamKind::Stderr.into(),
            seq,
            ts,
        }
    }
}

impl BudgetDelta {
    /// Creates a new `BudgetDelta`.
    #[must_use]
    pub const fn new(tokens: u64, tool_calls: u32, cpu_ms: u64) -> Self {
        Self {
            tokens,
            tool_calls,
            cpu_ms,
        }
    }
}

#[cfg(test)]
mod tests;
