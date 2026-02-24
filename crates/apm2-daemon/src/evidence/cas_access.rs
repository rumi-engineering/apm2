//! CAS access facade with capability allowlist enforcement (RFC-0032::REQ-0108).
//!
//! This module implements daemon-side CAS access control for session contexts.
//! Per RFC-0018, session CAS reads are gated via capability manifest allowlist.
//!
//! # Security Model
//!
//! Per DD-HEF-0004 and RFC-0018:
//! - **Operator sockets** (`operator.sock`): Full CAS access (no restrictions)
//! - **Session sockets** (`session.sock`): CAS reads gated by
//!   `cas_hash_allowlist` in the capability manifest
//!
//! # Access Control
//!
//! This facade is the sole entry point for session-context CAS reads.
//! Direct CAS access should only be used by:
//! - Operator socket handlers
//! - Daemon-internal operations (ledger commits, evidence storage)
//!
//! # Security Invariants
//!
//! - [INV-CAS-001] Session CAS reads are deny-by-default
//! - [INV-CAS-002] Empty `cas_hash_allowlist` denies all reads (fail-closed)
//! - [INV-CAS-003] Only exact hash matches are allowed
//! - [INV-CAS-004] CAS writes are not gated (out of scope per RFC-0032::REQ-0108)
//!
//! # Contract References
//!
//! - RFC-0018: HEF CAS access control
//! - RFC-0032::REQ-0108: Capability allowlists for CAS reads
//! - SEC-CTRL-FAC-0015: Fail-closed access control

use std::sync::Arc;

use apm2_core::evidence::{CasError, ContentAddressedStore};
use tracing::{debug, warn};

use crate::episode::CapabilityManifest;

// ============================================================================
// Error Types (CTR-0703: Structured Error Types)
// ============================================================================

/// Error type for CAS access control.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CasAccessError {
    /// CAS hash is not in the session's allowlist.
    HashNotAllowed {
        /// The hash that was denied (hex-encoded).
        hash: String,
    },

    /// No capability manifest found for the session.
    NoManifest {
        /// The session ID.
        session_id: String,
    },

    /// Underlying CAS error.
    CasError {
        /// Description of the CAS error.
        message: String,
    },
}

impl std::fmt::Display for CasAccessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HashNotAllowed { hash } => {
                write!(f, "CAS hash not in allowlist: {hash}")
            },
            Self::NoManifest { session_id } => {
                write!(f, "no capability manifest for session: {session_id}")
            },
            Self::CasError { message } => {
                write!(f, "CAS error: {message}")
            },
        }
    }
}

impl std::error::Error for CasAccessError {}

impl From<CasError> for CasAccessError {
    fn from(e: CasError) -> Self {
        Self::CasError {
            message: e.to_string(),
        }
    }
}

// ============================================================================
// CAS Access Facade
// ============================================================================

/// Access type for CAS operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CasAccessType {
    /// Operator access (full CAS access).
    Operator,
    /// Session access (gated by capability manifest).
    Session,
}

/// CAS access facade with capability allowlist enforcement.
///
/// This facade wraps a `ContentAddressedStore` and enforces access control
/// based on the session's capability manifest.
///
/// # Usage
///
/// ```rust,ignore
/// let facade = CasAccessFacade::new(cas);
///
/// // Operator access (unrestricted)
/// let content = facade.read_operator(&hash)?;
///
/// // Session access (checks allowlist)
/// let content = facade.read_session(&hash, &manifest)?;
/// ```
#[derive(Clone)]
pub struct CasAccessFacade {
    /// The underlying CAS store.
    cas: Arc<dyn ContentAddressedStore>,
}

impl std::fmt::Debug for CasAccessFacade {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CasAccessFacade").finish_non_exhaustive()
    }
}

impl CasAccessFacade {
    /// Creates a new CAS access facade.
    #[must_use]
    pub fn new(cas: Arc<dyn ContentAddressedStore>) -> Self {
        Self { cas }
    }

    /// Reads content from CAS with operator-level access (unrestricted).
    ///
    /// # Arguments
    ///
    /// * `hash` - The content hash to retrieve
    ///
    /// # Returns
    ///
    /// The content bytes if found.
    ///
    /// # Errors
    ///
    /// Returns `CasAccessError::CasError` if the CAS operation fails.
    pub fn read_operator(&self, hash: &[u8; 32]) -> Result<Vec<u8>, CasAccessError> {
        debug!(
            hash = %hex::encode(hash),
            "CAS read: operator access"
        );
        self.cas.retrieve(hash).map_err(CasAccessError::from)
    }

    /// Reads content from CAS with session-level access (allowlist gated).
    ///
    /// Per RFC-0032::REQ-0108, session CAS reads are validated against the session's
    /// capability manifest `cas_hash_allowlist`.
    ///
    /// # Arguments
    ///
    /// * `hash` - The content hash to retrieve
    /// * `manifest` - The session's capability manifest
    ///
    /// # Returns
    ///
    /// The content bytes if the hash is allowed and found.
    ///
    /// # Errors
    ///
    /// - `CasAccessError::HashNotAllowed` if hash is not in allowlist
    /// - `CasAccessError::CasError` if the CAS operation fails
    ///
    /// # Security (INV-CAS-002)
    ///
    /// Empty allowlist = deny all (fail-closed).
    pub fn read_session(
        &self,
        hash: &[u8; 32],
        manifest: &CapabilityManifest,
    ) -> Result<Vec<u8>, CasAccessError> {
        // Check allowlist (fail-closed: empty allowlist = deny all)
        if !manifest.is_cas_hash_allowed(hash) {
            warn!(
                hash = %hex::encode(hash),
                manifest_id = %manifest.manifest_id,
                "CAS read denied: hash not in allowlist"
            );
            return Err(CasAccessError::HashNotAllowed {
                hash: hex::encode(hash),
            });
        }

        debug!(
            hash = %hex::encode(hash),
            manifest_id = %manifest.manifest_id,
            "CAS read: session access allowed"
        );

        self.cas.retrieve(hash).map_err(CasAccessError::from)
    }

    /// Checks if a hash is allowed for session access without reading content.
    ///
    /// # Arguments
    ///
    /// * `hash` - The content hash to check
    /// * `manifest` - The session's capability manifest
    ///
    /// # Returns
    ///
    /// `true` if the hash is in the allowlist.
    #[must_use]
    pub fn is_hash_allowed(&self, hash: &[u8; 32], manifest: &CapabilityManifest) -> bool {
        manifest.is_cas_hash_allowed(hash)
    }

    /// Checks if content exists in CAS (session access).
    ///
    /// Per RFC-0032::REQ-0108, this checks the allowlist before checking CAS existence.
    ///
    /// # Arguments
    ///
    /// * `hash` - The content hash to check
    /// * `manifest` - The session's capability manifest
    ///
    /// # Returns
    ///
    /// `true` if the hash is allowed AND exists in CAS.
    ///
    /// # Errors
    ///
    /// Returns `CasAccessError` if hash is not allowed or CAS check fails.
    pub fn exists_session(
        &self,
        hash: &[u8; 32],
        manifest: &CapabilityManifest,
    ) -> Result<bool, CasAccessError> {
        // Check allowlist first
        if !manifest.is_cas_hash_allowed(hash) {
            return Err(CasAccessError::HashNotAllowed {
                hash: hex::encode(hash),
            });
        }

        self.cas.exists(hash).map_err(CasAccessError::from)
    }

    /// Gets content size from CAS (session access).
    ///
    /// Per RFC-0032::REQ-0108, this checks the allowlist before getting size.
    ///
    /// # Arguments
    ///
    /// * `hash` - The content hash
    /// * `manifest` - The session's capability manifest
    ///
    /// # Returns
    ///
    /// The content size in bytes.
    ///
    /// # Errors
    ///
    /// Returns `CasAccessError` if hash is not allowed or CAS operation fails.
    pub fn size_session(
        &self,
        hash: &[u8; 32],
        manifest: &CapabilityManifest,
    ) -> Result<usize, CasAccessError> {
        // Check allowlist first
        if !manifest.is_cas_hash_allowed(hash) {
            return Err(CasAccessError::HashNotAllowed {
                hash: hex::encode(hash),
            });
        }

        self.cas.size(hash).map_err(CasAccessError::from)
    }

    /// Reads multiple hashes from CAS (session access).
    ///
    /// Returns a vector of results, one for each hash. All hashes must be
    /// allowed by the manifest.
    ///
    /// # Arguments
    ///
    /// * `hashes` - The content hashes to retrieve
    /// * `manifest` - The session's capability manifest
    ///
    /// # Returns
    ///
    /// A vector of results, one for each hash.
    pub fn read_session_batch(
        &self,
        hashes: &[[u8; 32]],
        manifest: &CapabilityManifest,
    ) -> Vec<Result<Vec<u8>, CasAccessError>> {
        hashes
            .iter()
            .map(|hash| self.read_session(hash, manifest))
            .collect()
    }

    /// Returns a reference to the underlying CAS store.
    ///
    /// # Security Note
    ///
    /// This provides unrestricted access to the CAS. Should only be used
    /// for daemon-internal operations (ledger commits, evidence storage).
    #[must_use]
    pub fn inner(&self) -> &Arc<dyn ContentAddressedStore> {
        &self.cas
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use apm2_core::evidence::MemoryCas;

    use super::*;
    use crate::episode::capability::CapabilityManifestBuilder;

    fn create_test_facade() -> (CasAccessFacade, Arc<MemoryCas>) {
        let cas = Arc::new(MemoryCas::new());
        let facade = CasAccessFacade::new(cas.clone());
        (facade, cas)
    }

    fn store_test_content(cas: &MemoryCas, content: &[u8]) -> [u8; 32] {
        let result = cas.store(content).expect("store should succeed");
        result.hash
    }

    fn create_manifest_with_cas_hashes(hashes: Vec<[u8; 32]>) -> CapabilityManifest {
        CapabilityManifestBuilder::new("test-manifest")
            .delegator("test-delegator")
            .cas_hash_allowlist(hashes)
            .build()
            .expect("manifest should be valid")
    }

    // ========================================================================
    // Operator Access Tests
    // ========================================================================

    mod operator_access {
        use super::*;

        #[test]
        fn operator_can_read_any_hash() {
            let (facade, cas) = create_test_facade();
            let content = b"test content";
            let hash = store_test_content(&cas, content);

            let result = facade.read_operator(&hash);
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), content);
        }

        #[test]
        fn operator_read_not_found() {
            let (facade, _cas) = create_test_facade();
            let fake_hash = [0u8; 32];

            let result = facade.read_operator(&fake_hash);
            assert!(matches!(result, Err(CasAccessError::CasError { .. })));
        }
    }

    // ========================================================================
    // Session Access Tests
    // ========================================================================

    mod session_access {
        use super::*;

        #[test]
        fn session_can_read_allowed_hash() {
            let (facade, cas) = create_test_facade();
            let content = b"allowed content";
            let hash = store_test_content(&cas, content);

            let manifest = create_manifest_with_cas_hashes(vec![hash]);

            let result = facade.read_session(&hash, &manifest);
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), content);
        }

        #[test]
        fn session_denied_for_non_allowed_hash() {
            let (facade, cas) = create_test_facade();
            let content = b"secret content";
            let hash = store_test_content(&cas, content);

            // Manifest with different hash
            let manifest = create_manifest_with_cas_hashes(vec![[1u8; 32]]);

            let result = facade.read_session(&hash, &manifest);
            assert!(matches!(result, Err(CasAccessError::HashNotAllowed { .. })));
        }

        #[test]
        fn session_denied_for_empty_allowlist() {
            let (facade, cas) = create_test_facade();
            let content = b"content";
            let hash = store_test_content(&cas, content);

            // Empty allowlist = deny all
            let manifest = create_manifest_with_cas_hashes(vec![]);

            let result = facade.read_session(&hash, &manifest);
            assert!(matches!(result, Err(CasAccessError::HashNotAllowed { .. })));
        }

        #[test]
        fn session_exists_allowed() {
            let (facade, cas) = create_test_facade();
            let content = b"content";
            let hash = store_test_content(&cas, content);

            let manifest = create_manifest_with_cas_hashes(vec![hash]);

            let result = facade.exists_session(&hash, &manifest);
            assert!(result.is_ok());
            assert!(result.unwrap());
        }

        #[test]
        fn session_exists_denied() {
            let (facade, _cas) = create_test_facade();
            let hash = [0u8; 32];

            let manifest = create_manifest_with_cas_hashes(vec![[1u8; 32]]);

            let result = facade.exists_session(&hash, &manifest);
            assert!(matches!(result, Err(CasAccessError::HashNotAllowed { .. })));
        }

        #[test]
        fn session_size_allowed() {
            let (facade, cas) = create_test_facade();
            let content = b"content for size test";
            let hash = store_test_content(&cas, content);

            let manifest = create_manifest_with_cas_hashes(vec![hash]);

            let result = facade.size_session(&hash, &manifest);
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), content.len());
        }

        #[test]
        fn is_hash_allowed_check() {
            let (facade, _cas) = create_test_facade();
            let allowed_hash = [1u8; 32];
            let denied_hash = [2u8; 32];

            let manifest = create_manifest_with_cas_hashes(vec![allowed_hash]);

            assert!(facade.is_hash_allowed(&allowed_hash, &manifest));
            assert!(!facade.is_hash_allowed(&denied_hash, &manifest));
        }
    }

    // ========================================================================
    // Batch Access Tests
    // ========================================================================

    mod batch_access {
        use super::*;

        #[test]
        fn batch_read_mixed_results() {
            let (facade, cas) = create_test_facade();
            let content1 = b"content 1";
            let content2 = b"content 2";
            let hash1 = store_test_content(&cas, content1);
            let hash2 = store_test_content(&cas, content2);
            let denied_hash = [99u8; 32];

            let manifest = create_manifest_with_cas_hashes(vec![hash1, hash2]);

            let results = facade.read_session_batch(&[hash1, denied_hash, hash2], &manifest);

            assert_eq!(results.len(), 3);
            assert!(results[0].is_ok());
            assert_eq!(results[0].as_ref().unwrap(), content1);
            assert!(matches!(
                results[1],
                Err(CasAccessError::HashNotAllowed { .. })
            ));
            assert!(results[2].is_ok());
            assert_eq!(results[2].as_ref().unwrap(), content2);
        }
    }

    // ========================================================================
    // Security Invariant Tests
    // ========================================================================

    mod security {
        use super::*;

        /// INV-CAS-001: Session CAS reads are deny-by-default
        #[test]
        fn deny_by_default() {
            let (facade, cas) = create_test_facade();
            let content = b"content";
            let hash = store_test_content(&cas, content);

            // Empty manifest = deny
            let manifest = create_manifest_with_cas_hashes(vec![]);

            assert!(facade.read_session(&hash, &manifest).is_err());
        }

        /// INV-CAS-002: Empty `cas_hash_allowlist` denies all reads
        #[test]
        fn empty_allowlist_fail_closed() {
            let (facade, cas) = create_test_facade();
            let content = b"content";
            let hash = store_test_content(&cas, content);

            let manifest = create_manifest_with_cas_hashes(vec![]);

            let result = facade.read_session(&hash, &manifest);
            assert!(matches!(result, Err(CasAccessError::HashNotAllowed { .. })));
        }

        /// INV-CAS-003: Only exact hash matches are allowed
        #[test]
        fn exact_match_only() {
            let (facade, cas) = create_test_facade();
            let content = b"content";
            let hash = store_test_content(&cas, content);

            // Similar but not exact hash
            let mut similar_hash = hash;
            similar_hash[0] ^= 0xFF;

            let manifest = create_manifest_with_cas_hashes(vec![similar_hash]);

            let result = facade.read_session(&hash, &manifest);
            assert!(matches!(result, Err(CasAccessError::HashNotAllowed { .. })));
        }
    }
}
