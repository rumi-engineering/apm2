//! Episode budget types for resource limit tracking.
//!
//! This module defines the resource limits for episode execution per
//! AD-EPISODE-001. The budget is immutable once set in the envelope and
//! participates in canonical serialization for digest computation.
//!
//! # Security Model
//!
//! Budget enforcement is a **fail-closed** security mechanism:
//! - Requests are denied when any budget limit is exceeded
//! - Budget checks occur before tool execution
//! - Budgets are bound into the envelope digest for integrity
//!
//! # Canonicalization
//!
//! Per AD-VERIFY-001, budget fields are serialized in a deterministic order
//! for stable digest computation. The `canonical_bytes()` method produces
//! bytes suitable for signing and hashing.
//!
//! # Contract References
//!
//! - AD-EPISODE-001: Immutable episode envelope with budget field
//! - AD-VERIFY-001: Deterministic Protobuf serialization

use prost::Message;
use serde::{Deserialize, Serialize};

/// Maximum tokens budget value (prevents u64 overflow in calculations).
pub const MAX_TOKENS: u64 = u64::MAX / 2;

/// Maximum tool calls budget value.
pub const MAX_TOOL_CALLS: u32 = u32::MAX / 2;

/// Maximum wall clock milliseconds (approximately 292 million years).
pub const MAX_WALL_MS: u64 = u64::MAX / 2;

/// Maximum CPU milliseconds.
pub const MAX_CPU_MS: u64 = u64::MAX / 2;

/// Maximum I/O bytes.
pub const MAX_BYTES_IO: u64 = u64::MAX / 2;

/// Maximum evidence bytes.
pub const MAX_EVIDENCE_BYTES: u64 = u64::MAX / 2;

/// Resource budget for an episode.
///
/// This struct defines the resource limits that bound episode execution.
/// All fields are immutable once the envelope is created and are bound
/// into the envelope digest per AD-EPISODE-001.
///
/// # Fields
///
/// Per AD-EPISODE-001, the budget includes:
/// - `tokens`: Maximum inference tokens that can be consumed
/// - `tool_calls`: Maximum number of tool invocations
/// - `wall_ms`: Maximum wall-clock execution time in milliseconds
/// - `cpu_ms`: Maximum CPU time in milliseconds
/// - `bytes_io`: Maximum I/O bytes (read + write)
/// - `evidence_bytes`: Maximum evidence artifact storage in bytes
///
/// # Invariants
///
/// - [INV-BUDGET-001] All values are bounded by their respective MAX_*
///   constants to prevent overflow.
/// - [INV-BUDGET-002] A zero value means unlimited for that resource.
/// - [INV-BUDGET-003] Budget is immutable after envelope creation.
///
/// # Example
///
/// ```rust
/// use apm2_daemon::episode::EpisodeBudget;
///
/// let budget = EpisodeBudget::builder()
///     .tokens(100_000)
///     .tool_calls(500)
///     .wall_ms(3_600_000)  // 1 hour
///     .cpu_ms(300_000)     // 5 minutes
///     .bytes_io(1_073_741_824)  // 1 GiB
///     .evidence_bytes(10_485_760)  // 10 MiB
///     .build();
///
/// assert_eq!(budget.tokens(), 100_000);
/// assert!(!budget.is_unlimited());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EpisodeBudget {
    /// Maximum inference tokens that can be consumed.
    /// A value of 0 means unlimited.
    pub(crate) tokens: u64,

    /// Maximum number of tool invocations.
    /// A value of 0 means unlimited.
    pub(crate) tool_calls: u32,

    /// Maximum wall-clock execution time in milliseconds.
    /// A value of 0 means unlimited.
    pub(crate) wall_ms: u64,

    /// Maximum CPU time in milliseconds.
    /// A value of 0 means unlimited.
    pub(crate) cpu_ms: u64,

    /// Maximum I/O bytes (read + write combined).
    /// A value of 0 means unlimited.
    pub(crate) bytes_io: u64,

    /// Maximum evidence artifact storage in bytes.
    /// A value of 0 means unlimited.
    pub(crate) evidence_bytes: u64,
}

/// Internal protobuf representation for encoding/decoding.
///
/// Per AD-VERIFY-001, we use `optional` fields to ensure explicit serialization
/// of all values including defaults (e.g., 0). Protobuf 3's standard encoding
/// omits default values, which would violate deterministic encoding
/// requirements.
#[derive(Clone, PartialEq, Message)]
struct EpisodeBudgetProto {
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

impl EpisodeBudget {
    /// Creates a new budget builder.
    #[must_use]
    pub const fn builder() -> EpisodeBudgetBuilder {
        EpisodeBudgetBuilder::new()
    }

    /// Creates a budget with all resources unlimited.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            tokens: 0,
            tool_calls: 0,
            wall_ms: 0,
            cpu_ms: 0,
            bytes_io: 0,
            evidence_bytes: 0,
        }
    }

    /// Returns the token budget.
    #[must_use]
    pub const fn tokens(&self) -> u64 {
        self.tokens
    }

    /// Returns the tool calls budget.
    #[must_use]
    pub const fn tool_calls(&self) -> u32 {
        self.tool_calls
    }

    /// Returns the wall-clock time budget in milliseconds.
    #[must_use]
    pub const fn wall_ms(&self) -> u64 {
        self.wall_ms
    }

    /// Returns the CPU time budget in milliseconds.
    #[must_use]
    pub const fn cpu_ms(&self) -> u64 {
        self.cpu_ms
    }

    /// Returns the I/O bytes budget.
    #[must_use]
    pub const fn bytes_io(&self) -> u64 {
        self.bytes_io
    }

    /// Returns the evidence bytes budget.
    #[must_use]
    pub const fn evidence_bytes(&self) -> u64 {
        self.evidence_bytes
    }

    /// Returns `true` if all resources are unlimited.
    #[must_use]
    pub const fn is_unlimited(&self) -> bool {
        self.tokens == 0
            && self.tool_calls == 0
            && self.wall_ms == 0
            && self.cpu_ms == 0
            && self.bytes_io == 0
            && self.evidence_bytes == 0
    }

    /// Returns `true` if the token budget is limited.
    #[must_use]
    pub const fn has_token_limit(&self) -> bool {
        self.tokens > 0
    }

    /// Returns `true` if the tool calls budget is limited.
    #[must_use]
    pub const fn has_tool_call_limit(&self) -> bool {
        self.tool_calls > 0
    }

    /// Returns `true` if the wall time budget is limited.
    #[must_use]
    pub const fn has_wall_time_limit(&self) -> bool {
        self.wall_ms > 0
    }

    /// Returns the canonical bytes for this budget.
    ///
    /// Per AD-VERIFY-001, this produces deterministic bytes suitable
    /// for hashing and signing. All fields are explicitly serialized
    /// even when they contain default values (e.g., 0) by using
    /// `optional` protobuf fields.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let proto = EpisodeBudgetProto {
            tokens: Some(self.tokens),
            tool_calls: Some(self.tool_calls),
            wall_ms: Some(self.wall_ms),
            cpu_ms: Some(self.cpu_ms),
            bytes_io: Some(self.bytes_io),
            evidence_bytes: Some(self.evidence_bytes),
        };
        proto.encode_to_vec()
    }

    /// Decodes a budget from protobuf bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if decoding fails.
    pub fn decode(buf: &[u8]) -> Result<Self, prost::DecodeError> {
        let proto = EpisodeBudgetProto::decode(buf)?;
        Ok(Self {
            tokens: proto.tokens.unwrap_or(0),
            tool_calls: proto.tool_calls.unwrap_or(0),
            wall_ms: proto.wall_ms.unwrap_or(0),
            cpu_ms: proto.cpu_ms.unwrap_or(0),
            bytes_io: proto.bytes_io.unwrap_or(0),
            evidence_bytes: proto.evidence_bytes.unwrap_or(0),
        })
    }

    /// Computes the BLAKE3 digest of this budget.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        *blake3::hash(&self.canonical_bytes()).as_bytes()
    }
}

impl Default for EpisodeBudget {
    fn default() -> Self {
        // Default to reasonable limits for typical episodes
        Self {
            tokens: 1_000_000,           // 1M tokens
            tool_calls: 10_000,          // 10k tool calls
            wall_ms: 3_600_000,          // 1 hour
            cpu_ms: 600_000,             // 10 minutes
            bytes_io: 10_737_418_240,    // 10 GiB
            evidence_bytes: 104_857_600, // 100 MiB
        }
    }
}

/// Builder for [`EpisodeBudget`].
#[derive(Debug, Clone, Copy)]
pub struct EpisodeBudgetBuilder {
    tokens: u64,
    tool_calls: u32,
    wall_ms: u64,
    cpu_ms: u64,
    bytes_io: u64,
    evidence_bytes: u64,
}

impl EpisodeBudgetBuilder {
    /// Creates a new builder with default values.
    #[must_use]
    pub const fn new() -> Self {
        // Use explicit defaults since we can't call EpisodeBudget::default() in const
        Self {
            tokens: 1_000_000,
            tool_calls: 10_000,
            wall_ms: 3_600_000,
            cpu_ms: 600_000,
            bytes_io: 10_737_418_240,
            evidence_bytes: 104_857_600,
        }
    }

    /// Sets the token budget.
    ///
    /// Values are clamped to `MAX_TOKENS` to prevent overflow.
    #[must_use]
    pub const fn tokens(mut self, tokens: u64) -> Self {
        self.tokens = if tokens > MAX_TOKENS {
            MAX_TOKENS
        } else {
            tokens
        };
        self
    }

    /// Sets the tool calls budget.
    ///
    /// Values are clamped to `MAX_TOOL_CALLS` to prevent overflow.
    #[must_use]
    pub const fn tool_calls(mut self, tool_calls: u32) -> Self {
        self.tool_calls = if tool_calls > MAX_TOOL_CALLS {
            MAX_TOOL_CALLS
        } else {
            tool_calls
        };
        self
    }

    /// Sets the wall-clock time budget in milliseconds.
    ///
    /// Values are clamped to `MAX_WALL_MS` to prevent overflow.
    #[must_use]
    pub const fn wall_ms(mut self, wall_ms: u64) -> Self {
        self.wall_ms = if wall_ms > MAX_WALL_MS {
            MAX_WALL_MS
        } else {
            wall_ms
        };
        self
    }

    /// Sets the CPU time budget in milliseconds.
    ///
    /// Values are clamped to `MAX_CPU_MS` to prevent overflow.
    #[must_use]
    pub const fn cpu_ms(mut self, cpu_ms: u64) -> Self {
        self.cpu_ms = if cpu_ms > MAX_CPU_MS {
            MAX_CPU_MS
        } else {
            cpu_ms
        };
        self
    }

    /// Sets the I/O bytes budget.
    ///
    /// Values are clamped to `MAX_BYTES_IO` to prevent overflow.
    #[must_use]
    pub const fn bytes_io(mut self, bytes_io: u64) -> Self {
        self.bytes_io = if bytes_io > MAX_BYTES_IO {
            MAX_BYTES_IO
        } else {
            bytes_io
        };
        self
    }

    /// Sets the evidence bytes budget.
    ///
    /// Values are clamped to `MAX_EVIDENCE_BYTES` to prevent overflow.
    #[must_use]
    pub const fn evidence_bytes(mut self, evidence_bytes: u64) -> Self {
        self.evidence_bytes = if evidence_bytes > MAX_EVIDENCE_BYTES {
            MAX_EVIDENCE_BYTES
        } else {
            evidence_bytes
        };
        self
    }

    /// Builds the budget.
    #[must_use]
    pub const fn build(self) -> EpisodeBudget {
        EpisodeBudget {
            tokens: self.tokens,
            tool_calls: self.tool_calls,
            wall_ms: self.wall_ms,
            cpu_ms: self.cpu_ms,
            bytes_io: self.bytes_io,
            evidence_bytes: self.evidence_bytes,
        }
    }
}

impl Default for EpisodeBudgetBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_budget_default() {
        let budget = EpisodeBudget::default();
        assert_eq!(budget.tokens(), 1_000_000);
        assert_eq!(budget.tool_calls(), 10_000);
        assert_eq!(budget.wall_ms(), 3_600_000);
        assert_eq!(budget.cpu_ms(), 600_000);
        assert!(!budget.is_unlimited());
    }

    #[test]
    fn test_budget_unlimited() {
        let budget = EpisodeBudget::unlimited();
        assert_eq!(budget.tokens(), 0);
        assert_eq!(budget.tool_calls(), 0);
        assert_eq!(budget.wall_ms(), 0);
        assert_eq!(budget.cpu_ms(), 0);
        assert_eq!(budget.bytes_io(), 0);
        assert_eq!(budget.evidence_bytes(), 0);
        assert!(budget.is_unlimited());
    }

    #[test]
    fn test_budget_builder() {
        let budget = EpisodeBudget::builder()
            .tokens(50_000)
            .tool_calls(100)
            .wall_ms(60_000)
            .cpu_ms(30_000)
            .bytes_io(1_000_000)
            .evidence_bytes(500_000)
            .build();

        assert_eq!(budget.tokens(), 50_000);
        assert_eq!(budget.tool_calls(), 100);
        assert_eq!(budget.wall_ms(), 60_000);
        assert_eq!(budget.cpu_ms(), 30_000);
        assert_eq!(budget.bytes_io(), 1_000_000);
        assert_eq!(budget.evidence_bytes(), 500_000);
    }

    #[test]
    fn test_budget_builder_clamps_values() {
        let budget = EpisodeBudget::builder()
            .tokens(u64::MAX)
            .tool_calls(u32::MAX)
            .wall_ms(u64::MAX)
            .cpu_ms(u64::MAX)
            .bytes_io(u64::MAX)
            .evidence_bytes(u64::MAX)
            .build();

        assert_eq!(budget.tokens(), MAX_TOKENS);
        assert_eq!(budget.tool_calls(), MAX_TOOL_CALLS);
        assert_eq!(budget.wall_ms(), MAX_WALL_MS);
        assert_eq!(budget.cpu_ms(), MAX_CPU_MS);
        assert_eq!(budget.bytes_io(), MAX_BYTES_IO);
        assert_eq!(budget.evidence_bytes(), MAX_EVIDENCE_BYTES);
    }

    #[test]
    fn test_budget_has_limit_checks() {
        let limited = EpisodeBudget::builder()
            .tokens(1000)
            .tool_calls(50)
            .wall_ms(60_000)
            .build();

        assert!(limited.has_token_limit());
        assert!(limited.has_tool_call_limit());
        assert!(limited.has_wall_time_limit());

        let unlimited = EpisodeBudget::unlimited();
        assert!(!unlimited.has_token_limit());
        assert!(!unlimited.has_tool_call_limit());
        assert!(!unlimited.has_wall_time_limit());
    }

    #[test]
    fn test_budget_canonical_bytes_deterministic() {
        let budget = EpisodeBudget::builder()
            .tokens(100_000)
            .tool_calls(500)
            .wall_ms(3_600_000)
            .build();

        let bytes1 = budget.canonical_bytes();
        let bytes2 = budget.canonical_bytes();
        let bytes3 = budget.canonical_bytes();

        assert_eq!(bytes1, bytes2);
        assert_eq!(bytes2, bytes3);
    }

    #[test]
    fn test_budget_roundtrip() {
        let original = EpisodeBudget::builder()
            .tokens(100_000)
            .tool_calls(500)
            .wall_ms(3_600_000)
            .cpu_ms(600_000)
            .bytes_io(1_000_000_000)
            .evidence_bytes(10_000_000)
            .build();

        let bytes = original.canonical_bytes();
        let decoded = EpisodeBudget::decode(&bytes).expect("decode failed");

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_budget_digest_stable() {
        let budget = EpisodeBudget::builder()
            .tokens(100_000)
            .tool_calls(500)
            .build();

        let digest1 = budget.digest();
        let digest2 = budget.digest();

        assert_eq!(digest1, digest2);
        assert_eq!(digest1.len(), 32);
    }

    #[test]
    fn test_budget_different_values_different_digests() {
        let budget1 = EpisodeBudget::builder().tokens(100_000).build();
        let budget2 = EpisodeBudget::builder().tokens(100_001).build();

        assert_ne!(budget1.digest(), budget2.digest());
    }

    #[test]
    fn test_budget_serialize_deserialize() {
        let budget = EpisodeBudget::builder()
            .tokens(50_000)
            .tool_calls(100)
            .build();

        let json = serde_json::to_string(&budget).expect("serialize failed");
        let decoded: EpisodeBudget = serde_json::from_str(&json).expect("deserialize failed");

        assert_eq!(budget, decoded);
    }
}
