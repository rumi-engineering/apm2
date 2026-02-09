// AGENT-AUTHORED
//! Durable consume index for authoritative single-use enforcement (TCK-00426).
//!
//! # Design
//!
//! The [`DurableConsumeIndex`] trait abstracts durable AJC consumption
//! tracking. The primary implementation, [`FileBackedConsumeIndex`], uses an
//! append-only file with fsync to guarantee the pre-effect durability barrier:
//!
//! > The consume record MUST be fsynced to durable storage before any side
//! > effect is accepted. (RFC-0027 §12, invariant 2)
//!
//! # Crash-Replay Safety
//!
//! On startup, [`FileBackedConsumeIndex::open`] replays the append-only log
//! to rebuild the in-memory index. Any AJC ID found in the log is permanently
//! consumed — duplicate attempts are denied even after restart.
//!
//! # Metrics
//!
//! Three counters are exposed:
//! - `pcac_durable_consume_recorded_total`: successful durable consume writes
//! - `pcac_durable_consume_denied_total`: duplicate consume denials
//! - `pcac_durable_consume_fsync_total`: fsync operations completed

use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use apm2_core::crypto::Hash;
use prometheus::{IntCounter, opts, register_int_counter};

// =============================================================================
// Error types
// =============================================================================

/// Errors from durable consume operations.
#[derive(Debug, thiserror::Error)]
pub enum ConsumeError {
    /// The AJC ID has already been consumed.
    #[error("ajc_id already consumed: {}", hex::encode(ajc_id))]
    AlreadyConsumed {
        /// The AJC ID that was already consumed.
        ajc_id: Hash,
    },

    /// I/O error during durable write or fsync.
    #[error("durable write failed: {0}")]
    IoError(#[from] std::io::Error),

    /// Corrupt or invalid record in the consume log.
    #[error("corrupt consume log entry at line {line}: {reason}")]
    CorruptLog {
        /// Line number in the consume log where corruption was detected.
        line: usize,
        /// Description of the corruption.
        reason: String,
    },
}

// =============================================================================
// DurableConsumeIndex trait
// =============================================================================

/// Abstraction for durable AJC consumption tracking.
///
/// Implementations must guarantee that `record_consume` returns `Ok(())` only
/// after the consume record has been durably persisted. This is the pre-effect
/// durability barrier.
pub trait DurableConsumeIndex: Send + Sync {
    /// Record consumption of an AJC ID. Returns `Ok(())` only after the record
    /// is durably committed (fsync). Returns
    /// `Err(ConsumeError::AlreadyConsumed)` if the AJC ID was previously
    /// consumed.
    fn record_consume(&self, ajc_id: Hash) -> Result<(), ConsumeError>;

    /// Check whether an AJC ID has been consumed.
    fn is_consumed(&self, ajc_id: &Hash) -> bool;
}

// =============================================================================
// Metrics
// =============================================================================

/// Metrics for durable consume operations.
pub struct DurableConsumeMetrics {
    /// Counter for successful durable consume writes.
    pub recorded_total: IntCounter,
    /// Counter for duplicate consume denials.
    pub denied_total: IntCounter,
    /// Counter for fsync operations completed.
    pub fsync_total: IntCounter,
}

impl DurableConsumeMetrics {
    /// Register prometheus metrics. Panics if metrics are already registered
    /// (call only once).
    pub fn register() -> Self {
        Self {
            recorded_total: register_int_counter!(opts!(
                "pcac_durable_consume_recorded_total",
                "Successful durable consume record writes"
            ))
            .expect("metric registration"),
            denied_total: register_int_counter!(opts!(
                "pcac_durable_consume_denied_total",
                "Duplicate consume denial count"
            ))
            .expect("metric registration"),
            fsync_total: register_int_counter!(opts!(
                "pcac_durable_consume_fsync_total",
                "Fsync operations completed for consume durability"
            ))
            .expect("metric registration"),
        }
    }
}

// =============================================================================
// FileBackedConsumeIndex
// =============================================================================

/// Append-only file-backed durable consume index.
///
/// Each consumed AJC ID is written as a 64-character hex line followed by
/// newline. On open, the file is replayed line-by-line to rebuild the
/// in-memory set.
///
/// The pre-effect durability barrier is enforced by fsyncing the file after
/// each append before returning `Ok(())`.
pub struct FileBackedConsumeIndex {
    /// Path to the append-only consume log.
    path: PathBuf,
    /// In-memory set for fast lookup.
    consumed: Mutex<HashSet<Hash>>,
    /// Append-only file handle.
    file: Mutex<File>,
    /// Optional metrics (None in tests without prometheus).
    metrics: Option<DurableConsumeMetrics>,
}

impl std::fmt::Debug for FileBackedConsumeIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileBackedConsumeIndex")
            .field("path", &self.path)
            .field("consumed_count", &self.len())
            .finish_non_exhaustive()
    }
}

impl FileBackedConsumeIndex {
    /// Open or create the consume log at `path`, replaying any existing
    /// entries.
    ///
    /// # Errors
    ///
    /// Returns `ConsumeError::IoError` if the file cannot be opened.
    /// Returns `ConsumeError::CorruptLog` if the file contains invalid entries.
    pub fn open(
        path: impl AsRef<Path>,
        metrics: Option<DurableConsumeMetrics>,
    ) -> Result<Self, ConsumeError> {
        let path = path.as_ref().to_path_buf();
        let mut consumed = HashSet::new();

        // Replay existing entries if the file exists.
        if path.exists() {
            let file = File::open(&path)?;
            let reader = BufReader::new(file);
            for (line_idx, line_result) in reader.lines().enumerate() {
                let line = line_result?;
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let hash = hex_to_hash(trimmed).map_err(|reason| ConsumeError::CorruptLog {
                    line: line_idx + 1,
                    reason,
                })?;
                consumed.insert(hash);
            }
        }

        // Open for appending.
        let file = OpenOptions::new().create(true).append(true).open(&path)?;

        Ok(Self {
            path,
            consumed: Mutex::new(consumed),
            file: Mutex::new(file),
            metrics,
        })
    }

    /// Returns the file path for this index.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the number of consumed AJC IDs.
    pub fn len(&self) -> usize {
        self.consumed.lock().expect("lock poisoned").len()
    }

    /// Returns true if no AJC IDs have been consumed.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl DurableConsumeIndex for FileBackedConsumeIndex {
    fn record_consume(&self, ajc_id: Hash) -> Result<(), ConsumeError> {
        let mut consumed = self.consumed.lock().expect("lock poisoned");

        // Check for duplicate.
        if consumed.contains(&ajc_id) {
            if let Some(ref metrics) = self.metrics {
                metrics.denied_total.inc();
            }
            return Err(ConsumeError::AlreadyConsumed { ajc_id });
        }

        // Write to durable storage BEFORE marking in memory.
        {
            let mut file = self.file.lock().expect("lock poisoned");
            writeln!(file, "{}", hex::encode(ajc_id))?;
            file.sync_all()?;
        }

        if let Some(ref metrics) = self.metrics {
            metrics.fsync_total.inc();
            metrics.recorded_total.inc();
        }

        // Only mark consumed after successful fsync.
        consumed.insert(ajc_id);
        Ok(())
    }

    fn is_consumed(&self, ajc_id: &Hash) -> bool {
        self.consumed
            .lock()
            .expect("lock poisoned")
            .contains(ajc_id)
    }
}

// =============================================================================
// DurableKernel
// =============================================================================

/// Kernel wrapper that adds durable consume tracking to any
/// `AuthorityJoinKernel` implementation.
///
/// The inner kernel handles join and revalidate. On consume, the durable index
/// is checked/written BEFORE the inner kernel's consume is called, enforcing
/// the pre-effect durability barrier.
pub struct DurableKernel<K: apm2_core::pcac::AuthorityJoinKernel> {
    inner: K,
    durable_index: Box<dyn DurableConsumeIndex>,
}

impl<K: apm2_core::pcac::AuthorityJoinKernel> DurableKernel<K> {
    /// Create a durable kernel wrapping `inner` with the given durable index.
    pub fn new(inner: K, durable_index: Box<dyn DurableConsumeIndex>) -> Self {
        Self {
            inner,
            durable_index,
        }
    }
}

impl<K: apm2_core::pcac::AuthorityJoinKernel> apm2_core::pcac::AuthorityJoinKernel
    for DurableKernel<K>
{
    fn join(
        &self,
        input: &apm2_core::pcac::AuthorityJoinInputV1,
    ) -> Result<apm2_core::pcac::AuthorityJoinCertificateV1, Box<apm2_core::pcac::AuthorityDenyV1>>
    {
        self.inner.join(input)
    }

    fn revalidate(
        &self,
        cert: &apm2_core::pcac::AuthorityJoinCertificateV1,
        current_time_envelope_ref: Hash,
        current_ledger_anchor: Hash,
        current_revocation_head_hash: Hash,
    ) -> Result<(), Box<apm2_core::pcac::AuthorityDenyV1>> {
        self.inner.revalidate(
            cert,
            current_time_envelope_ref,
            current_ledger_anchor,
            current_revocation_head_hash,
        )
    }

    fn consume(
        &self,
        cert: &apm2_core::pcac::AuthorityJoinCertificateV1,
        intent_digest: Hash,
        current_time_envelope_ref: Hash,
    ) -> Result<
        (
            apm2_core::pcac::AuthorityConsumedV1,
            apm2_core::pcac::AuthorityConsumeRecordV1,
        ),
        Box<apm2_core::pcac::AuthorityDenyV1>,
    > {
        // Pre-effect durability barrier: record consume durably BEFORE
        // allowing the inner kernel to accept the consume.
        let tick = {
            // We need to produce a deny with the right shape if the durable
            // index rejects. We don't have the tick directly, so we use 0
            // as a sentinel — the deny_class carries the real signal.
            0u64
        };

        if let Err(e) = self.durable_index.record_consume(cert.ajc_id) {
            match e {
                ConsumeError::AlreadyConsumed { ajc_id } => {
                    return Err(Box::new(apm2_core::pcac::AuthorityDenyV1 {
                        deny_class: apm2_core::pcac::AuthorityDenyClass::AlreadyConsumed { ajc_id },
                        ajc_id: Some(cert.ajc_id),
                        time_envelope_ref: current_time_envelope_ref,
                        ledger_anchor: cert.as_of_ledger_anchor,
                        denied_at_tick: tick,
                    }));
                },
                ConsumeError::IoError(io_err) => {
                    // I/O failure is fail-closed: deny with UnknownState.
                    return Err(Box::new(apm2_core::pcac::AuthorityDenyV1 {
                        deny_class: apm2_core::pcac::AuthorityDenyClass::UnknownState {
                            description: format!("durable consume write failed: {io_err}"),
                        },
                        ajc_id: Some(cert.ajc_id),
                        time_envelope_ref: current_time_envelope_ref,
                        ledger_anchor: cert.as_of_ledger_anchor,
                        denied_at_tick: tick,
                    }));
                },
                ConsumeError::CorruptLog { line, reason } => {
                    return Err(Box::new(apm2_core::pcac::AuthorityDenyV1 {
                        deny_class: apm2_core::pcac::AuthorityDenyClass::UnknownState {
                            description: format!("corrupt consume log at line {line}: {reason}"),
                        },
                        ajc_id: Some(cert.ajc_id),
                        time_envelope_ref: current_time_envelope_ref,
                        ledger_anchor: cert.as_of_ledger_anchor,
                        denied_at_tick: tick,
                    }));
                },
            }
        }

        // Durable record committed — now execute the inner kernel consume.
        self.inner
            .consume(cert, intent_digest, current_time_envelope_ref)
    }
}

// =============================================================================
// Helpers
// =============================================================================

/// Parse a 64-character hex string into a 32-byte hash.
fn hex_to_hash(s: &str) -> Result<Hash, String> {
    if s.len() != 64 {
        return Err(format!("expected 64 hex chars, got {}", s.len()));
    }
    let bytes = hex::decode(s).map_err(|e| format!("invalid hex: {e}"))?;
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&bytes);
    Ok(hash)
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    fn test_hash(byte: u8) -> Hash {
        [byte; 32]
    }

    // =========================================================================
    // FileBackedConsumeIndex basic tests
    // =========================================================================

    #[test]
    fn record_and_query() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("consume.log");
        let index = FileBackedConsumeIndex::open(&path, None).unwrap();

        let h = test_hash(0x01);
        assert!(!index.is_consumed(&h));
        index.record_consume(h).unwrap();
        assert!(index.is_consumed(&h));
        assert_eq!(index.len(), 1);
    }

    #[test]
    fn duplicate_denied() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("consume.log");
        let index = FileBackedConsumeIndex::open(&path, None).unwrap();

        let h = test_hash(0x02);
        index.record_consume(h).unwrap();

        let err = index.record_consume(h).unwrap_err();
        assert!(matches!(err, ConsumeError::AlreadyConsumed { .. }));
    }

    #[test]
    fn crash_replay_preserves_consumed() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("consume.log");

        let h1 = test_hash(0x10);
        let h2 = test_hash(0x20);

        // First session: record two consumes.
        {
            let index = FileBackedConsumeIndex::open(&path, None).unwrap();
            index.record_consume(h1).unwrap();
            index.record_consume(h2).unwrap();
            assert_eq!(index.len(), 2);
        }
        // Drop simulates crash.

        // Second session: reopen and verify both are still consumed.
        {
            let index = FileBackedConsumeIndex::open(&path, None).unwrap();
            assert!(index.is_consumed(&h1));
            assert!(index.is_consumed(&h2));
            assert_eq!(index.len(), 2);

            // Duplicate after reload is still denied.
            let err = index.record_consume(h1).unwrap_err();
            assert!(matches!(err, ConsumeError::AlreadyConsumed { .. }));
        }
    }

    #[test]
    fn new_consume_after_reload() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("consume.log");

        let h1 = test_hash(0x30);
        let h2 = test_hash(0x40);

        // First session.
        {
            let index = FileBackedConsumeIndex::open(&path, None).unwrap();
            index.record_consume(h1).unwrap();
        }

        // Second session: new consume works.
        {
            let index = FileBackedConsumeIndex::open(&path, None).unwrap();
            assert!(index.is_consumed(&h1));
            assert!(!index.is_consumed(&h2));
            index.record_consume(h2).unwrap();
            assert!(index.is_consumed(&h2));
            assert_eq!(index.len(), 2);
        }
    }

    #[test]
    fn empty_file_opens_cleanly() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("consume.log");
        let index = FileBackedConsumeIndex::open(&path, None).unwrap();
        assert!(index.is_empty());
        assert_eq!(index.len(), 0);
    }

    #[test]
    fn corrupt_log_detected() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("consume.log");

        // Write corrupt data.
        std::fs::write(&path, "not-valid-hex\n").unwrap();

        let err = FileBackedConsumeIndex::open(&path, None).unwrap_err();
        assert!(matches!(err, ConsumeError::CorruptLog { line: 1, .. }));
    }

    // =========================================================================
    // DurableKernel tests
    // =========================================================================

    use apm2_core::pcac::{
        AuthorityJoinInputV1, AuthorityJoinKernel, DeterminismClass, IdentityEvidenceLevel,
        RiskTier,
    };

    use super::super::lifecycle_gate::InProcessKernel;

    fn valid_input() -> AuthorityJoinInputV1 {
        AuthorityJoinInputV1 {
            session_id: "session-001".to_string(),
            holon_id: None,
            intent_digest: test_hash(0x01),
            capability_manifest_hash: test_hash(0x02),
            scope_witness_hashes: vec![],
            lease_id: "lease-001".to_string(),
            permeability_receipt_hash: None,
            identity_proof_hash: test_hash(0x03),
            identity_evidence_level: IdentityEvidenceLevel::Verified,
            directory_head_hash: test_hash(0x04),
            freshness_policy_hash: test_hash(0x05),
            freshness_witness_tick: 1000,
            stop_budget_profile_digest: test_hash(0x06),
            pre_actuation_receipt_hashes: vec![],
            risk_tier: RiskTier::Tier1,
            determinism_class: DeterminismClass::Deterministic,
            time_envelope_ref: test_hash(0x07),
            as_of_ledger_anchor: test_hash(0x08),
        }
    }

    #[test]
    fn durable_kernel_consume_succeeds() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("consume.log");
        let index = FileBackedConsumeIndex::open(&path, None).unwrap();
        let inner = InProcessKernel::new(100);
        let kernel = DurableKernel::new(inner, Box::new(index));

        let input = valid_input();
        let cert = kernel.join(&input).unwrap();
        let (witness, record) = kernel
            .consume(&cert, input.intent_digest, input.time_envelope_ref)
            .unwrap();
        assert_eq!(witness.ajc_id, cert.ajc_id);
        assert_eq!(record.ajc_id, cert.ajc_id);
    }

    #[test]
    fn durable_kernel_denies_duplicate_consume() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("consume.log");
        let index = FileBackedConsumeIndex::open(&path, None).unwrap();
        let inner = InProcessKernel::new(100);
        let kernel = DurableKernel::new(inner, Box::new(index));

        let input = valid_input();
        let cert = kernel.join(&input).unwrap();

        // First consume succeeds.
        kernel
            .consume(&cert, input.intent_digest, input.time_envelope_ref)
            .unwrap();

        // Second consume denied by durable index.
        let err = kernel
            .consume(&cert, input.intent_digest, input.time_envelope_ref)
            .unwrap_err();
        assert!(matches!(
            err.deny_class,
            apm2_core::pcac::AuthorityDenyClass::AlreadyConsumed { .. }
        ));
    }

    #[test]
    fn durable_kernel_crash_replay_denies() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("consume.log");

        let input = valid_input();
        let ajc_id;

        // First session: consume once.
        {
            let index = FileBackedConsumeIndex::open(&path, None).unwrap();
            let inner = InProcessKernel::new(100);
            let kernel = DurableKernel::new(inner, Box::new(index));

            let cert = kernel.join(&input).unwrap();
            ajc_id = cert.ajc_id;
            kernel
                .consume(&cert, input.intent_digest, input.time_envelope_ref)
                .unwrap();
        }
        // Drop = simulated crash.

        // Second session: same AJC ID must be denied.
        {
            let index = FileBackedConsumeIndex::open(&path, None).unwrap();
            assert!(index.is_consumed(&ajc_id));

            let inner = InProcessKernel::new(100);
            let kernel = DurableKernel::new(inner, Box::new(index));

            // Same tick + same input = same AJC ID.
            let cert = kernel.join(&input).unwrap();
            assert_eq!(cert.ajc_id, ajc_id);

            let err = kernel
                .consume(&cert, input.intent_digest, input.time_envelope_ref)
                .unwrap_err();
            assert!(matches!(
                err.deny_class,
                apm2_core::pcac::AuthorityDenyClass::AlreadyConsumed { .. }
            ));
        }
    }

    #[test]
    fn durable_record_committed_before_effect() {
        // Verify that after a successful consume, the file contains the record
        // BEFORE the consume returns (i.e., we can observe it on disk).
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("consume.log");
        let index = FileBackedConsumeIndex::open(&path, None).unwrap();
        let inner = InProcessKernel::new(100);
        let kernel = DurableKernel::new(inner, Box::new(index));

        let input = valid_input();
        let cert = kernel.join(&input).unwrap();
        kernel
            .consume(&cert, input.intent_digest, input.time_envelope_ref)
            .unwrap();

        // Read the file directly — the record must be present.
        let contents = std::fs::read_to_string(&path).unwrap();
        let expected_hex = hex::encode(cert.ajc_id);
        assert!(
            contents.contains(&expected_hex),
            "durable consume record must be on disk after consume returns"
        );
    }

    // =========================================================================
    // hex_to_hash helper tests
    // =========================================================================

    #[test]
    fn hex_to_hash_roundtrip() {
        let h = test_hash(0xAB);
        let encoded = hex::encode(h);
        let decoded = hex_to_hash(&encoded).unwrap();
        assert_eq!(h, decoded);
    }

    #[test]
    fn hex_to_hash_rejects_short() {
        assert!(hex_to_hash("abcd").is_err());
    }

    #[test]
    fn hex_to_hash_rejects_invalid() {
        let bad = "zz".repeat(32);
        assert!(hex_to_hash(&bad).is_err());
    }
}
