//! Evidence publisher for artifact storage and event emission.
//!
//! The publisher coordinates between the CAS (for storage) and the event
//! system (for ledger recording).

use super::cas::ContentAddressedStore;
use super::category::EvidenceCategory;
use super::classification::DataClassification;
use super::error::EvidenceError;
use crate::crypto::Hash;

/// Result of a successful publish operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishResult {
    /// The evidence ID.
    pub evidence_id: String,

    /// The work ID this evidence is linked to.
    pub work_id: String,

    /// The artifact hash.
    pub artifact_hash: Hash,

    /// The size of the artifact in bytes.
    pub artifact_size: usize,

    /// Whether the content was newly stored (true) or deduplicated (false).
    pub is_new_content: bool,

    /// The category of the evidence.
    pub category: EvidenceCategory,

    /// The data classification.
    pub classification: DataClassification,

    /// Verification command IDs, if any.
    pub verification_command_ids: Vec<String>,
}

/// Evidence publisher that stores artifacts in CAS and generates events.
///
/// The publisher provides a high-level API for publishing evidence:
/// 1. Validates the artifact and metadata
/// 2. Stores the content in the CAS
/// 3. Returns the information needed to emit an `EvidencePublished` event
///
/// # Event Emission
///
/// The publisher does NOT emit events directly. Instead, it returns a
/// [`PublishResult`] that contains all the information needed to create
/// an `EvidencePublished` event. This separation allows the caller to:
/// - Control when the event is emitted
/// - Handle ledger errors separately from storage errors
/// - Batch multiple publications if needed
///
/// # Example
///
/// ```rust
/// use apm2_core::evidence::{
///     ContentAddressedStore, DataClassification, EvidenceCategory, EvidencePublisher, MemoryCas,
/// };
///
/// let cas = MemoryCas::new();
/// let publisher = EvidencePublisher::new(cas);
///
/// let result = publisher
///     .publish(
///         "test-001",
///         "work-123",
///         b"test output",
///         EvidenceCategory::TestResults,
///         DataClassification::Internal,
///         &[],
///     )
///     .unwrap();
///
/// assert_eq!(result.evidence_id, "test-001");
/// assert_eq!(result.work_id, "work-123");
/// ```
pub struct EvidencePublisher<C: ContentAddressedStore> {
    cas: C,
}

impl<C: ContentAddressedStore> EvidencePublisher<C> {
    /// Creates a new evidence publisher with the given CAS backend.
    #[must_use]
    pub const fn new(cas: C) -> Self {
        Self { cas }
    }

    /// Returns a reference to the underlying CAS.
    #[must_use]
    pub const fn cas(&self) -> &C {
        &self.cas
    }

    /// Publishes an artifact to the CAS.
    ///
    /// # Arguments
    ///
    /// * `evidence_id` - Unique identifier for this evidence
    /// * `work_id` - The work item this evidence is linked to
    /// * `content` - The artifact content
    /// * `category` - The evidence category
    /// * `classification` - The data classification
    /// * `verification_command_ids` - IDs of verification commands (if any)
    ///
    /// # Returns
    ///
    /// Returns a [`PublishResult`] containing the hash and other metadata.
    /// Use this to create an `EvidencePublished` event.
    ///
    /// # Errors
    ///
    /// - [`EvidenceError::InvalidEvidenceId`] if evidence ID is empty or too
    ///   long
    /// - [`EvidenceError::InvalidWorkId`] if work ID is empty or too long
    /// - [`EvidenceError::EmptyContent`] if content is empty
    /// - [`EvidenceError::ContentTooLarge`] if content exceeds size limit
    /// - [`EvidenceError::CasError`] if CAS storage fails
    pub fn publish(
        &self,
        evidence_id: &str,
        work_id: &str,
        content: &[u8],
        category: EvidenceCategory,
        classification: DataClassification,
        verification_command_ids: &[String],
    ) -> Result<PublishResult, EvidenceError> {
        // Validate evidence ID
        if evidence_id.is_empty() {
            return Err(EvidenceError::InvalidEvidenceId {
                value: String::new(),
            });
        }
        if evidence_id.len() > 256 {
            return Err(EvidenceError::InvalidEvidenceId {
                value: format!("exceeds 256 bytes: {}", evidence_id.len()),
            });
        }

        // Validate work ID
        if work_id.is_empty() {
            return Err(EvidenceError::InvalidWorkId {
                value: String::new(),
            });
        }
        if work_id.len() > 256 {
            return Err(EvidenceError::InvalidWorkId {
                value: format!("exceeds 256 bytes: {}", work_id.len()),
            });
        }

        // Validate content
        if content.is_empty() {
            return Err(EvidenceError::EmptyContent);
        }

        // Store in CAS
        let store_result = self.cas.store(content)?;

        Ok(PublishResult {
            evidence_id: evidence_id.to_string(),
            work_id: work_id.to_string(),
            artifact_hash: store_result.hash,
            artifact_size: store_result.size,
            is_new_content: store_result.is_new,
            category,
            classification,
            verification_command_ids: verification_command_ids.to_vec(),
        })
    }

    /// Publishes an artifact with metadata.
    ///
    /// This is a convenience method that includes metadata parsing and
    /// validation.
    ///
    /// # Arguments
    ///
    /// * `evidence_id` - Unique identifier for this evidence
    /// * `work_id` - The work item this evidence is linked to
    /// * `content` - The artifact content
    /// * `category` - The evidence category
    /// * `classification` - The data classification
    /// * `verification_command_ids` - IDs of verification commands (if any)
    /// * `metadata` - Key-value metadata as `["key=value", ...]` strings
    ///
    /// # Errors
    ///
    /// Same as [`Self::publish`], plus:
    /// - [`EvidenceError::MalformedMetadata`] if a metadata entry is malformed
    #[allow(clippy::too_many_arguments)]
    pub fn publish_with_metadata(
        &self,
        evidence_id: &str,
        work_id: &str,
        content: &[u8],
        category: EvidenceCategory,
        classification: DataClassification,
        verification_command_ids: &[String],
        metadata: &[String],
    ) -> Result<(PublishResult, Vec<(String, String)>), EvidenceError> {
        // Parse and validate metadata
        let parsed_metadata = parse_metadata(metadata)?;

        // Publish the artifact
        let result = self.publish(
            evidence_id,
            work_id,
            content,
            category,
            classification,
            verification_command_ids,
        )?;

        Ok((result, parsed_metadata))
    }

    /// Retrieves artifact content by hash.
    ///
    /// # Errors
    ///
    /// - [`EvidenceError::CasError`] if retrieval fails
    pub fn retrieve(&self, hash: &Hash) -> Result<Vec<u8>, EvidenceError> {
        self.cas.retrieve(hash).map_err(EvidenceError::from)
    }

    /// Checks if an artifact exists in the CAS.
    ///
    /// # Errors
    ///
    /// - [`EvidenceError::CasError`] if the check fails
    pub fn exists(&self, hash: &Hash) -> Result<bool, EvidenceError> {
        self.cas.exists(hash).map_err(EvidenceError::from)
    }

    /// Returns the size of an artifact without retrieving it.
    ///
    /// # Errors
    ///
    /// - [`EvidenceError::CasError`] if the artifact is not found
    pub fn artifact_size(&self, hash: &Hash) -> Result<usize, EvidenceError> {
        self.cas.size(hash).map_err(EvidenceError::from)
    }

    /// Verifies that content matches the expected hash.
    ///
    /// # Errors
    ///
    /// - [`EvidenceError::CasError`] with `HashMismatch` if verification fails
    pub fn verify(&self, content: &[u8], expected_hash: &Hash) -> Result<(), EvidenceError> {
        self.cas
            .verify(content, expected_hash)
            .map_err(EvidenceError::from)
    }
}

/// Parses metadata from `["key=value", ...]` format.
///
/// # Errors
///
/// Returns [`EvidenceError::MalformedMetadata`] if an entry doesn't contain
/// exactly one `=` separator.
fn parse_metadata(metadata: &[String]) -> Result<Vec<(String, String)>, EvidenceError> {
    metadata
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            let parts: Vec<&str> = entry.splitn(2, '=').collect();
            if parts.len() != 2 {
                return Err(EvidenceError::MalformedMetadata { index });
            }
            Ok((parts[0].to_string(), parts[1].to_string()))
        })
        .collect()
}

#[cfg(test)]
mod unit_tests {
    use super::*;
    use crate::evidence::MemoryCas;

    fn make_publisher() -> EvidencePublisher<MemoryCas> {
        EvidencePublisher::new(MemoryCas::new())
    }

    #[test]
    fn test_publish_success() {
        let publisher = make_publisher();
        let content = b"test content";

        let result = publisher
            .publish(
                "evid-001",
                "work-123",
                content,
                EvidenceCategory::TestResults,
                DataClassification::Internal,
                &[],
            )
            .unwrap();

        assert_eq!(result.evidence_id, "evid-001");
        assert_eq!(result.work_id, "work-123");
        assert_eq!(result.artifact_size, content.len());
        assert!(result.is_new_content);
        assert_eq!(result.category, EvidenceCategory::TestResults);
        assert_eq!(result.classification, DataClassification::Internal);
    }

    #[test]
    fn test_publish_deduplication() {
        let publisher = make_publisher();
        let content = b"duplicate content";

        let result1 = publisher
            .publish(
                "evid-001",
                "work-123",
                content,
                EvidenceCategory::TestResults,
                DataClassification::Internal,
                &[],
            )
            .unwrap();

        let result2 = publisher
            .publish(
                "evid-002",
                "work-123",
                content,
                EvidenceCategory::TestResults,
                DataClassification::Internal,
                &[],
            )
            .unwrap();

        assert!(result1.is_new_content);
        assert!(!result2.is_new_content);
        assert_eq!(result1.artifact_hash, result2.artifact_hash);
    }

    #[test]
    fn test_publish_empty_evidence_id() {
        let publisher = make_publisher();

        let result = publisher.publish(
            "",
            "work-123",
            b"content",
            EvidenceCategory::TestResults,
            DataClassification::Internal,
            &[],
        );

        assert!(matches!(
            result,
            Err(EvidenceError::InvalidEvidenceId { .. })
        ));
    }

    #[test]
    fn test_publish_empty_work_id() {
        let publisher = make_publisher();

        let result = publisher.publish(
            "evid-001",
            "",
            b"content",
            EvidenceCategory::TestResults,
            DataClassification::Internal,
            &[],
        );

        assert!(matches!(result, Err(EvidenceError::InvalidWorkId { .. })));
    }

    #[test]
    fn test_publish_empty_content() {
        let publisher = make_publisher();

        let result = publisher.publish(
            "evid-001",
            "work-123",
            b"",
            EvidenceCategory::TestResults,
            DataClassification::Internal,
            &[],
        );

        assert!(matches!(result, Err(EvidenceError::EmptyContent)));
    }

    #[test]
    fn test_publish_with_verification_commands() {
        let publisher = make_publisher();
        let commands = vec!["CMD-001".to_string(), "CMD-002".to_string()];

        let result = publisher
            .publish(
                "evid-001",
                "work-123",
                b"content",
                EvidenceCategory::TestResults,
                DataClassification::Internal,
                &commands,
            )
            .unwrap();

        assert_eq!(result.verification_command_ids, commands);
    }

    #[test]
    fn test_publish_with_metadata() {
        let publisher = make_publisher();
        let metadata = vec!["key1=value1".to_string(), "key2=value2".to_string()];

        let (result, parsed) = publisher
            .publish_with_metadata(
                "evid-001",
                "work-123",
                b"content",
                EvidenceCategory::TestResults,
                DataClassification::Internal,
                &[],
                &metadata,
            )
            .unwrap();

        assert_eq!(result.evidence_id, "evid-001");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0], ("key1".to_string(), "value1".to_string()));
        assert_eq!(parsed[1], ("key2".to_string(), "value2".to_string()));
    }

    #[test]
    fn test_publish_with_malformed_metadata() {
        let publisher = make_publisher();
        let metadata = vec!["valid=value".to_string(), "invalid_no_equals".to_string()];

        let result = publisher.publish_with_metadata(
            "evid-001",
            "work-123",
            b"content",
            EvidenceCategory::TestResults,
            DataClassification::Internal,
            &[],
            &metadata,
        );

        assert!(matches!(
            result,
            Err(EvidenceError::MalformedMetadata { index: 1 })
        ));
    }

    #[test]
    fn test_retrieve() {
        let publisher = make_publisher();
        let content = b"retrievable content";

        let result = publisher
            .publish(
                "evid-001",
                "work-123",
                content,
                EvidenceCategory::TestResults,
                DataClassification::Internal,
                &[],
            )
            .unwrap();

        let retrieved = publisher.retrieve(&result.artifact_hash).unwrap();
        assert_eq!(retrieved, content);
    }

    #[test]
    fn test_exists() {
        let publisher = make_publisher();
        let content = b"content";

        let result = publisher
            .publish(
                "evid-001",
                "work-123",
                content,
                EvidenceCategory::TestResults,
                DataClassification::Internal,
                &[],
            )
            .unwrap();

        assert!(publisher.exists(&result.artifact_hash).unwrap());

        let fake_hash = [0u8; 32];
        assert!(!publisher.exists(&fake_hash).unwrap());
    }

    #[test]
    fn test_artifact_size() {
        let publisher = make_publisher();
        let content = b"content for size check";

        let result = publisher
            .publish(
                "evid-001",
                "work-123",
                content,
                EvidenceCategory::TestResults,
                DataClassification::Internal,
                &[],
            )
            .unwrap();

        let size = publisher.artifact_size(&result.artifact_hash).unwrap();
        assert_eq!(size, content.len());
    }

    #[test]
    fn test_verify() {
        let publisher = make_publisher();
        let content = b"content to verify";

        let result = publisher
            .publish(
                "evid-001",
                "work-123",
                content,
                EvidenceCategory::TestResults,
                DataClassification::Internal,
                &[],
            )
            .unwrap();

        // Verification should pass
        assert!(publisher.verify(content, &result.artifact_hash).is_ok());

        // Verification should fail for wrong content
        assert!(publisher.verify(b"wrong", &result.artifact_hash).is_err());
    }

    #[test]
    fn test_parse_metadata() {
        let metadata = vec![
            "key1=value1".to_string(),
            "key2=value with = in it".to_string(),
        ];

        let parsed = parse_metadata(&metadata).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0], ("key1".to_string(), "value1".to_string()));
        assert_eq!(
            parsed[1],
            ("key2".to_string(), "value with = in it".to_string())
        );
    }

    #[test]
    fn test_parse_metadata_empty() {
        let metadata: Vec<String> = vec![];
        let parsed = parse_metadata(&metadata).unwrap();
        assert!(parsed.is_empty());
    }
}
