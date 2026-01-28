//! Output capture with metadata for PTY streams.
//!
//! This module defines the output structures for capturing PTY output
//! with sequence numbers and timestamps for evidence ordering.
//!
//! # Invariants
//!
//! - [INV-OUT001] Sequence numbers are monotonically increasing
//! - [INV-OUT002] Timestamps are monotonic (caller-provided per HARD-TIME)
//! - [INV-OUT003] All serializable types use `deny_unknown_fields`
//!
//! # Security Considerations
//!
//! This is SCP (Security-Critical Path) code:
//! - Timestamps are provided by caller (HARD-TIME principle)
//! - All types use `#[serde(deny_unknown_fields)]` to prevent injection
//! - Output chunks are bounded to prevent memory exhaustion

use bytes::Bytes;
use serde::{Deserialize, Serialize};

/// Maximum size for a single output chunk in bytes.
///
/// This prevents memory exhaustion from large output bursts.
pub const MAX_CHUNK_SIZE: usize = 64 * 1024; // 64 KB

/// Classification of output stream.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum StreamKind {
    /// Standard output stream.
    Stdout,
    /// Standard error stream.
    Stderr,
    /// Combined/unknown stream (PTY typically combines stdout/stderr).
    #[default]
    Combined,
}

impl StreamKind {
    /// Returns the stream kind as a string identifier.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Stdout => "STDOUT",
            Self::Stderr => "STDERR",
            Self::Combined => "COMBINED",
        }
    }
}

impl std::fmt::Display for StreamKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A chunk of PTY output with metadata.
///
/// This structure captures output data along with sequence number and
/// timestamp for ordering and evidence collection.
///
/// # Fields
///
/// * `chunk` - The output data
/// * `seq` - Monotonically increasing sequence number
/// * `ts_mono` - Monotonic timestamp in nanoseconds (caller-provided)
/// * `kind` - Classification of the output stream
///
/// # Invariants
///
/// - [INV-PO001] seq is unique within an episode
/// - [INV-PO002] `ts_mono` is provided by caller (HARD-TIME)
/// - [INV-PO003] `chunk.len()` <= `MAX_CHUNK_SIZE`
#[derive(Debug, Clone)]
pub struct PtyOutput {
    /// The output data.
    pub chunk: Bytes,
    /// Monotonically increasing sequence number.
    pub seq: u64,
    /// Monotonic timestamp in nanoseconds (caller-provided per HARD-TIME).
    pub ts_mono: u64,
    /// Classification of the output stream.
    pub kind: StreamKind,
}

impl PtyOutput {
    /// Creates a new PTY output chunk.
    ///
    /// # Arguments
    ///
    /// * `chunk` - The output data
    /// * `seq` - Sequence number
    /// * `ts_mono` - Monotonic timestamp in nanoseconds
    /// * `kind` - Stream classification
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Bytes is not const-constructible
    pub fn new(chunk: Bytes, seq: u64, ts_mono: u64, kind: StreamKind) -> Self {
        Self {
            chunk,
            seq,
            ts_mono,
            kind,
        }
    }

    /// Creates a new stdout output chunk.
    #[must_use]
    pub fn stdout(chunk: Bytes, seq: u64, ts_mono: u64) -> Self {
        Self::new(chunk, seq, ts_mono, StreamKind::Stdout)
    }

    /// Creates a new stderr output chunk.
    #[must_use]
    pub fn stderr(chunk: Bytes, seq: u64, ts_mono: u64) -> Self {
        Self::new(chunk, seq, ts_mono, StreamKind::Stderr)
    }

    /// Creates a new combined output chunk.
    #[must_use]
    pub fn combined(chunk: Bytes, seq: u64, ts_mono: u64) -> Self {
        Self::new(chunk, seq, ts_mono, StreamKind::Combined)
    }

    /// Returns the size of the output chunk in bytes.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Bytes::len() is not const
    pub fn len(&self) -> usize {
        self.chunk.len()
    }

    /// Returns `true` if the output chunk is empty.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Bytes::is_empty() is not const
    pub fn is_empty(&self) -> bool {
        self.chunk.is_empty()
    }
}

/// Serializable representation of PTY output for evidence.
///
/// This is a serializable version of `PtyOutput` that stores the data
/// as a byte vector instead of `Bytes` for JSON/protobuf compatibility.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PtyOutputRecord {
    /// The output data as bytes.
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
    /// Monotonically increasing sequence number.
    pub seq: u64,
    /// Monotonic timestamp in nanoseconds.
    pub ts_mono: u64,
    /// Classification of the output stream.
    pub kind: StreamKind,
}

impl From<PtyOutput> for PtyOutputRecord {
    fn from(output: PtyOutput) -> Self {
        Self {
            data: output.chunk.to_vec(),
            seq: output.seq,
            ts_mono: output.ts_mono,
            kind: output.kind,
        }
    }
}

impl From<PtyOutputRecord> for PtyOutput {
    fn from(record: PtyOutputRecord) -> Self {
        Self {
            chunk: Bytes::from(record.data),
            seq: record.seq,
            ts_mono: record.ts_mono,
            kind: record.kind,
        }
    }
}

/// Generator for monotonically increasing sequence numbers.
///
/// This is used to assign unique sequence numbers to output chunks
/// within an episode.
#[derive(Debug)]
pub struct SequenceGenerator {
    /// Next sequence number to assign.
    next: u64,
}

impl SequenceGenerator {
    /// Creates a new sequence generator starting at 0.
    #[must_use]
    pub const fn new() -> Self {
        Self { next: 0 }
    }

    /// Creates a new sequence generator starting at the given value.
    #[must_use]
    pub const fn starting_at(start: u64) -> Self {
        Self { next: start }
    }

    /// Returns the next sequence number and advances the generator.
    #[allow(clippy::should_implement_trait)]
    pub const fn next(&mut self) -> u64 {
        let seq = self.next;
        self.next = self.next.wrapping_add(1);
        seq
    }

    /// Returns the current sequence number without advancing.
    #[must_use]
    pub const fn current(&self) -> u64 {
        self.next
    }
}

impl Default for SequenceGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // UT-00161-03: Output sequencing test
    // ========================================================================

    /// UT-00161-03: Test output sequence number ordering.
    #[test]
    fn test_output_sequence_ordering() {
        let mut seq_gen = SequenceGenerator::new();
        let base_ts = 1_704_067_200_000_000_000_u64; // 2024-01-01

        let outputs: Vec<PtyOutput> = (0..5)
            .map(|i| {
                PtyOutput::combined(
                    Bytes::from(format!("output {i}")),
                    seq_gen.next(),
                    base_ts + i * 1_000_000, // 1ms apart
                )
            })
            .collect();

        // Verify sequence numbers are monotonically increasing
        for (i, output) in outputs.iter().enumerate() {
            assert_eq!(output.seq, i as u64);
        }

        // Verify timestamps are increasing
        for i in 1..outputs.len() {
            assert!(outputs[i].ts_mono > outputs[i - 1].ts_mono);
        }
    }

    #[test]
    fn test_pty_output_new() {
        let chunk = Bytes::from("hello world");
        let output = PtyOutput::new(chunk.clone(), 42, 123_456_789, StreamKind::Stdout);

        assert_eq!(output.chunk, chunk);
        assert_eq!(output.seq, 42);
        assert_eq!(output.ts_mono, 123_456_789);
        assert_eq!(output.kind, StreamKind::Stdout);
    }

    #[test]
    fn test_pty_output_factories() {
        let chunk = Bytes::from("test");

        let stdout = PtyOutput::stdout(chunk.clone(), 1, 100);
        assert_eq!(stdout.kind, StreamKind::Stdout);

        let stderr = PtyOutput::stderr(chunk.clone(), 2, 200);
        assert_eq!(stderr.kind, StreamKind::Stderr);

        let combined = PtyOutput::combined(chunk, 3, 300);
        assert_eq!(combined.kind, StreamKind::Combined);
    }

    #[test]
    fn test_pty_output_len() {
        let output = PtyOutput::combined(Bytes::from("12345"), 0, 0);
        assert_eq!(output.len(), 5);
        assert!(!output.is_empty());

        let empty_output = PtyOutput::combined(Bytes::new(), 0, 0);
        assert_eq!(empty_output.len(), 0);
        assert!(empty_output.is_empty());
    }

    #[test]
    fn test_stream_kind_as_str() {
        assert_eq!(StreamKind::Stdout.as_str(), "STDOUT");
        assert_eq!(StreamKind::Stderr.as_str(), "STDERR");
        assert_eq!(StreamKind::Combined.as_str(), "COMBINED");
    }

    #[test]
    fn test_stream_kind_default() {
        assert_eq!(StreamKind::default(), StreamKind::Combined);
    }

    #[test]
    fn test_stream_kind_display() {
        assert_eq!(format!("{}", StreamKind::Stdout), "STDOUT");
        assert_eq!(format!("{}", StreamKind::Stderr), "STDERR");
        assert_eq!(format!("{}", StreamKind::Combined), "COMBINED");
    }

    #[test]
    fn test_sequence_generator_new() {
        let mut seq_gen = SequenceGenerator::new();
        assert_eq!(seq_gen.current(), 0);
        assert_eq!(seq_gen.next(), 0);
        assert_eq!(seq_gen.current(), 1);
        assert_eq!(seq_gen.next(), 1);
        assert_eq!(seq_gen.next(), 2);
    }

    #[test]
    fn test_sequence_generator_starting_at() {
        let mut seq_gen = SequenceGenerator::starting_at(100);
        assert_eq!(seq_gen.current(), 100);
        assert_eq!(seq_gen.next(), 100);
        assert_eq!(seq_gen.next(), 101);
    }

    #[test]
    fn test_sequence_generator_default() {
        let seq_gen = SequenceGenerator::default();
        assert_eq!(seq_gen.current(), 0);
    }

    #[test]
    fn test_sequence_generator_wrapping() {
        let mut seq_gen = SequenceGenerator::starting_at(u64::MAX);
        assert_eq!(seq_gen.next(), u64::MAX);
        assert_eq!(seq_gen.next(), 0); // Wraps around
    }

    // ========================================================================
    // Serialization tests
    // ========================================================================

    #[test]
    fn test_pty_output_record_serialization() {
        let record = PtyOutputRecord {
            data: vec![1, 2, 3, 4, 5],
            seq: 42,
            ts_mono: 123_456_789,
            kind: StreamKind::Stdout,
        };

        let json = serde_json::to_string(&record).unwrap();
        let deserialized: PtyOutputRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, record);
    }

    #[test]
    fn test_pty_output_record_from_pty_output() {
        let output = PtyOutput::stdout(Bytes::from("hello"), 5, 999);
        let record: PtyOutputRecord = output.into();

        assert_eq!(record.data, b"hello".to_vec());
        assert_eq!(record.seq, 5);
        assert_eq!(record.ts_mono, 999);
        assert_eq!(record.kind, StreamKind::Stdout);
    }

    #[test]
    fn test_pty_output_from_record() {
        let record = PtyOutputRecord {
            data: vec![1, 2, 3],
            seq: 10,
            ts_mono: 500,
            kind: StreamKind::Stderr,
        };

        let output: PtyOutput = record.into();
        assert_eq!(output.chunk.as_ref(), &[1, 2, 3]);
        assert_eq!(output.seq, 10);
        assert_eq!(output.ts_mono, 500);
        assert_eq!(output.kind, StreamKind::Stderr);
    }

    /// SECURITY TEST: Verify `PtyOutputRecord` rejects unknown fields.
    #[test]
    fn test_pty_output_record_rejects_unknown_fields() {
        let json = r#"{
            "data": [1, 2, 3],
            "seq": 42,
            "ts_mono": 123456789,
            "kind": "STDOUT",
            "malicious_field": "attack"
        }"#;

        let result: Result<PtyOutputRecord, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "PtyOutputRecord should reject unknown fields"
        );
    }

    #[test]
    fn test_stream_kind_serialization() {
        let kinds = vec![StreamKind::Stdout, StreamKind::Stderr, StreamKind::Combined];

        for kind in kinds {
            let json = serde_json::to_string(&kind).unwrap();
            let deserialized: StreamKind = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, kind);
        }
    }

    #[test]
    fn test_stream_kind_json_format() {
        assert_eq!(
            serde_json::to_string(&StreamKind::Stdout).unwrap(),
            "\"STDOUT\""
        );
        assert_eq!(
            serde_json::to_string(&StreamKind::Stderr).unwrap(),
            "\"STDERR\""
        );
        assert_eq!(
            serde_json::to_string(&StreamKind::Combined).unwrap(),
            "\"COMBINED\""
        );
    }
}
