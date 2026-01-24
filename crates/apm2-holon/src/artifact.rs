//! Artifact types for evidence emission.
//!
//! Artifacts are evidence produced during holon execution and logged to the
//! ledger. They provide a record of what the holon did, enabling auditing,
//! debugging, and verification.

use serde::{Deserialize, Serialize};

/// An artifact produced during holon execution.
///
/// Artifacts are evidence that is logged to the ledger. They capture
/// what the holon produced, when, and with what properties.
///
/// # Example
///
/// ```rust
/// use apm2_holon::Artifact;
///
/// let artifact = Artifact::builder()
///     .kind("code_change")
///     .work_id("work-123")
///     .content("Added new function")
///     .build();
///
/// assert_eq!(artifact.kind(), "code_change");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Artifact {
    /// Unique identifier for this artifact.
    id: String,

    /// Type of artifact (e.g., `code_change`, `document`, `test_result`).
    kind: String,

    /// ID of the work item that produced this artifact.
    work_id: String,

    /// ID of the episode that produced this artifact.
    episode_id: Option<String>,

    /// Human-readable content or description.
    content: Option<String>,

    /// Hash of the artifact content (for integrity verification).
    content_hash: Option<String>,

    /// MIME type of the content.
    mime_type: Option<String>,

    /// Size of the artifact in bytes.
    size_bytes: Option<u64>,

    /// Path to the artifact (if stored externally).
    path: Option<String>,

    /// Timestamp when the artifact was created (nanoseconds since epoch).
    created_at_ns: u64,

    /// Additional metadata as key-value pairs.
    metadata: Vec<(String, String)>,
}

impl Artifact {
    /// Creates a new builder for constructing an `Artifact`.
    #[must_use]
    pub fn builder() -> ArtifactBuilder {
        ArtifactBuilder::default()
    }

    /// Returns the artifact ID.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the artifact type.
    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// Returns the work ID.
    #[must_use]
    pub fn work_id(&self) -> &str {
        &self.work_id
    }

    /// Returns the episode ID, if any.
    #[must_use]
    pub fn episode_id(&self) -> Option<&str> {
        self.episode_id.as_deref()
    }

    /// Returns the content, if any.
    #[must_use]
    pub fn content(&self) -> Option<&str> {
        self.content.as_deref()
    }

    /// Returns the content hash, if any.
    #[must_use]
    pub fn content_hash(&self) -> Option<&str> {
        self.content_hash.as_deref()
    }

    /// Returns the MIME type, if any.
    #[must_use]
    pub fn mime_type(&self) -> Option<&str> {
        self.mime_type.as_deref()
    }

    /// Returns the size in bytes, if known.
    #[must_use]
    pub const fn size_bytes(&self) -> Option<u64> {
        self.size_bytes
    }

    /// Returns the path, if any.
    #[must_use]
    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }

    /// Returns the creation timestamp in nanoseconds.
    #[must_use]
    pub const fn created_at_ns(&self) -> u64 {
        self.created_at_ns
    }

    /// Returns the metadata as key-value pairs.
    #[must_use]
    pub fn metadata(&self) -> &[(String, String)] {
        &self.metadata
    }

    /// Returns a metadata value by key.
    #[must_use]
    pub fn get_metadata(&self, key: &str) -> Option<&str> {
        self.metadata
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

/// Builder for constructing [`Artifact`] instances.
#[derive(Debug, Default)]
pub struct ArtifactBuilder {
    id: Option<String>,
    kind: Option<String>,
    work_id: Option<String>,
    episode_id: Option<String>,
    content: Option<String>,
    content_hash: Option<String>,
    mime_type: Option<String>,
    size_bytes: Option<u64>,
    path: Option<String>,
    created_at_ns: Option<u64>,
    metadata: Vec<(String, String)>,
}

impl ArtifactBuilder {
    /// Sets the artifact ID.
    #[must_use]
    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    /// Sets the artifact type.
    #[must_use]
    pub fn kind(mut self, kind: impl Into<String>) -> Self {
        self.kind = Some(kind.into());
        self
    }

    /// Sets the work ID.
    #[must_use]
    pub fn work_id(mut self, work_id: impl Into<String>) -> Self {
        self.work_id = Some(work_id.into());
        self
    }

    /// Sets the episode ID.
    #[must_use]
    pub fn episode_id(mut self, episode_id: impl Into<String>) -> Self {
        self.episode_id = Some(episode_id.into());
        self
    }

    /// Sets the content.
    #[must_use]
    pub fn content(mut self, content: impl Into<String>) -> Self {
        self.content = Some(content.into());
        self
    }

    /// Sets the content hash.
    #[must_use]
    pub fn content_hash(mut self, hash: impl Into<String>) -> Self {
        self.content_hash = Some(hash.into());
        self
    }

    /// Sets the MIME type.
    #[must_use]
    pub fn mime_type(mut self, mime: impl Into<String>) -> Self {
        self.mime_type = Some(mime.into());
        self
    }

    /// Sets the size in bytes.
    #[must_use]
    pub const fn size_bytes(mut self, size: u64) -> Self {
        self.size_bytes = Some(size);
        self
    }

    /// Sets the path.
    #[must_use]
    pub fn path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    /// Sets the creation timestamp.
    #[must_use]
    pub const fn created_at_ns(mut self, ts: u64) -> Self {
        self.created_at_ns = Some(ts);
        self
    }

    /// Adds a metadata key-value pair.
    #[must_use]
    pub fn metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.push((key.into(), value.into()));
        self
    }

    /// Builds the `Artifact`.
    ///
    /// # Panics
    ///
    /// Panics if `kind` or `work_id` is not set.
    #[must_use]
    pub fn build(self) -> Artifact {
        Artifact {
            id: self.id.unwrap_or_else(generate_id),
            kind: self.kind.expect("kind is required"),
            work_id: self.work_id.expect("work_id is required"),
            episode_id: self.episode_id,
            content: self.content,
            content_hash: self.content_hash,
            mime_type: self.mime_type,
            size_bytes: self.size_bytes,
            path: self.path,
            created_at_ns: self.created_at_ns.unwrap_or_else(current_timestamp_ns),
            metadata: self.metadata,
        }
    }
}

/// Common artifact types.
pub mod kinds {
    /// A code change artifact.
    pub const CODE_CHANGE: &str = "code_change";

    /// A document artifact.
    pub const DOCUMENT: &str = "document";

    /// A test result artifact.
    pub const TEST_RESULT: &str = "test_result";

    /// A log artifact.
    pub const LOG: &str = "log";

    /// A checkpoint artifact (state snapshot).
    pub const CHECKPOINT: &str = "checkpoint";

    /// A decision artifact (reasoning trace).
    pub const DECISION: &str = "decision";

    /// An error artifact.
    pub const ERROR: &str = "error";

    /// A metric artifact.
    pub const METRIC: &str = "metric";
}

/// Generates a new artifact ID.
fn generate_id() -> String {
    format!("art-{}", uuid::Uuid::new_v4())
}

/// Returns the current timestamp in nanoseconds since epoch.
fn current_timestamp_ns() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    #[allow(clippy::cast_possible_truncation)]
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_artifact_builder_basic() {
        let artifact = Artifact::builder()
            .kind("code_change")
            .work_id("work-123")
            .build();

        assert_eq!(artifact.kind(), "code_change");
        assert_eq!(artifact.work_id(), "work-123");
        assert!(artifact.id().starts_with("art-"));
    }

    #[test]
    fn test_artifact_builder_full() {
        let artifact = Artifact::builder()
            .id("art-custom-123")
            .kind("document")
            .work_id("work-456")
            .episode_id("ep-789")
            .content("Some content here")
            .content_hash("blake3:abc123")
            .mime_type("text/plain")
            .size_bytes(1024)
            .path("/tmp/artifact.txt")
            .created_at_ns(1_000_000_000)
            .metadata("author", "holon-1")
            .metadata("version", "1.0")
            .build();

        assert_eq!(artifact.id(), "art-custom-123");
        assert_eq!(artifact.episode_id(), Some("ep-789"));
        assert_eq!(artifact.content(), Some("Some content here"));
        assert_eq!(artifact.content_hash(), Some("blake3:abc123"));
        assert_eq!(artifact.mime_type(), Some("text/plain"));
        assert_eq!(artifact.size_bytes(), Some(1024));
        assert_eq!(artifact.path(), Some("/tmp/artifact.txt"));
        assert_eq!(artifact.created_at_ns(), 1_000_000_000);
        assert_eq!(artifact.get_metadata("author"), Some("holon-1"));
        assert_eq!(artifact.get_metadata("version"), Some("1.0"));
        assert_eq!(artifact.get_metadata("nonexistent"), None);
    }

    #[test]
    #[should_panic(expected = "kind is required")]
    fn test_builder_missing_type() {
        let _ = Artifact::builder().work_id("work-123").build();
    }

    #[test]
    #[should_panic(expected = "work_id is required")]
    fn test_builder_missing_work_id() {
        let _ = Artifact::builder().kind("code_change").build();
    }

    #[test]
    fn test_kinds_constants() {
        assert_eq!(kinds::CODE_CHANGE, "code_change");
        assert_eq!(kinds::DOCUMENT, "document");
        assert_eq!(kinds::TEST_RESULT, "test_result");
        assert_eq!(kinds::LOG, "log");
        assert_eq!(kinds::CHECKPOINT, "checkpoint");
        assert_eq!(kinds::DECISION, "decision");
        assert_eq!(kinds::ERROR, "error");
        assert_eq!(kinds::METRIC, "metric");
    }

    #[test]
    fn test_metadata_iteration() {
        let artifact = Artifact::builder()
            .kind("test")
            .work_id("work-1")
            .metadata("key1", "value1")
            .metadata("key2", "value2")
            .build();

        let metadata = artifact.metadata();
        assert_eq!(metadata.len(), 2);
        assert!(metadata.contains(&("key1".to_string(), "value1".to_string())));
        assert!(metadata.contains(&("key2".to_string(), "value2".to_string())));
    }
}
