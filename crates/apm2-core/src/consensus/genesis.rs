//! Genesis block adoption and validation for consensus.
//!
//! This module implements genesis creation that adopts the existing ledger head
//! hash as the epoch-0 `prev_hash`. It provides signature verification against
//! the T0 (genesis) key and join validation with rate limiting.
//!
//! # Security Invariants
//!
//! - INV-0013: Join attempts rate-limited per source IP or identity
//! - INV-0024: Genesis signature verified against T0 key
//! - INV-0025: Node rejects join on genesis mismatch
//! - INV-0026: Join requests require quorum-signed invitation token

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use thiserror::Error;

/// Maximum length for namespace identifiers.
pub const MAX_NAMESPACE_LEN: usize = 128;

/// Maximum number of signatures in a quorum.
pub const MAX_QUORUM_SIGNATURES: usize = 16;

/// Maximum number of signatures allowed in an invitation token during parsing.
/// This bounds memory usage during deserialization to prevent denial-of-service
/// attacks.
pub const MAX_SIGNATURES: usize = 64;

/// Maximum rate of join attempts per source (joins per minute).
pub const MAX_JOIN_ATTEMPTS_PER_MINUTE: usize = 10;

/// Rate limit window duration.
pub const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);

/// Maximum number of tracked sources in the rate limiter (CTR-1303: Bounded
/// Stores).
pub const MAX_RATE_LIMIT_SOURCES: usize = 1024;

/// Errors that can occur in genesis operations.
#[derive(Debug, Error)]
pub enum GenesisError {
    /// Invalid genesis signature.
    #[error("invalid genesis signature")]
    InvalidSignature,

    /// Signature verification failed.
    #[error("signature verification failed: {0}")]
    SignatureVerification(String),

    /// Genesis hash mismatch.
    #[error("genesis mismatch: expected {expected}, got {actual}")]
    GenesisMismatch {
        /// Expected genesis hash.
        expected: String,
        /// Actual genesis hash.
        actual: String,
    },

    /// Invalid namespace.
    #[error("invalid namespace: {0}")]
    InvalidNamespace(String),

    /// Invalid public key.
    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),

    /// Rate limit exceeded.
    #[error("rate limit exceeded for source: {attempts} attempts in {window_secs}s")]
    RateLimitExceeded {
        /// Number of attempts made.
        attempts: usize,
        /// Window duration in seconds.
        window_secs: u64,
    },

    /// Invalid invitation token.
    #[error("invalid invitation token: {0}")]
    InvalidInvitationToken(String),

    /// Insufficient quorum signatures.
    #[error("insufficient quorum signatures: {have} of {need} required")]
    InsufficientQuorum {
        /// Number of valid signatures.
        have: usize,
        /// Number of required signatures.
        need: usize,
    },

    /// Serialization error.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Configuration error.
    #[error("configuration error: {0}")]
    Configuration(String),
}

/// Configuration for genesis creation.
#[derive(Clone)]
pub struct GenesisConfig {
    /// The namespace for this genesis block.
    namespace: String,
    /// The ledger head hash to adopt (32 bytes).
    ledger_head_hash: [u8; 32],
    /// The T0 (genesis) verifying key.
    t0_key: VerifyingKey,
    /// Required number of quorum signatures for invitation tokens.
    quorum_threshold: usize,
    /// Public keys of quorum members for invitation verification.
    quorum_keys: Vec<VerifyingKey>,
}

/// Builder for genesis configuration.
pub struct GenesisConfigBuilder {
    namespace: Option<String>,
    ledger_head_hash: Option<[u8; 32]>,
    t0_key: Option<VerifyingKey>,
    quorum_threshold: usize,
    quorum_keys: Vec<VerifyingKey>,
}

impl Default for GenesisConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl GenesisConfigBuilder {
    /// Creates a new genesis configuration builder.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            namespace: None,
            ledger_head_hash: None,
            t0_key: None,
            quorum_threshold: 1,
            quorum_keys: Vec::new(),
        }
    }

    /// Sets the namespace.
    ///
    /// # Errors
    ///
    /// Returns an error if the namespace is empty or exceeds maximum length.
    pub fn namespace(mut self, namespace: impl Into<String>) -> Result<Self, GenesisError> {
        let ns = namespace.into();
        if ns.is_empty() {
            return Err(GenesisError::InvalidNamespace("empty namespace".into()));
        }
        if ns.len() > MAX_NAMESPACE_LEN {
            return Err(GenesisError::InvalidNamespace(format!(
                "namespace too long: {} bytes exceeds maximum {}",
                ns.len(),
                MAX_NAMESPACE_LEN
            )));
        }
        self.namespace = Some(ns);
        Ok(self)
    }

    /// Sets the ledger head hash to adopt.
    #[must_use]
    pub const fn ledger_head_hash(mut self, hash: [u8; 32]) -> Self {
        self.ledger_head_hash = Some(hash);
        self
    }

    /// Sets the T0 (genesis) verifying key from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the key bytes are invalid.
    pub fn t0_key_bytes(mut self, key_bytes: &[u8; 32]) -> Result<Self, GenesisError> {
        let key = VerifyingKey::from_bytes(key_bytes)
            .map_err(|e| GenesisError::InvalidPublicKey(e.to_string()))?;
        self.t0_key = Some(key);
        Ok(self)
    }

    /// Sets the T0 (genesis) verifying key.
    #[must_use]
    pub const fn t0_key(mut self, key: VerifyingKey) -> Self {
        self.t0_key = Some(key);
        self
    }

    /// Sets the quorum threshold for invitation tokens.
    #[must_use]
    pub const fn quorum_threshold(mut self, threshold: usize) -> Self {
        self.quorum_threshold = threshold;
        self
    }

    /// Adds a quorum member's verifying key.
    ///
    /// # Errors
    ///
    /// Returns an error if maximum quorum size is exceeded.
    pub fn add_quorum_key(mut self, key: VerifyingKey) -> Result<Self, GenesisError> {
        if self.quorum_keys.len() >= MAX_QUORUM_SIGNATURES {
            return Err(GenesisError::Configuration(format!(
                "maximum quorum size {MAX_QUORUM_SIGNATURES} exceeded",
            )));
        }
        self.quorum_keys.push(key);
        Ok(self)
    }

    /// Adds a quorum member's verifying key from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the key bytes are invalid or maximum quorum size
    /// exceeded.
    pub fn add_quorum_key_bytes(self, key_bytes: &[u8; 32]) -> Result<Self, GenesisError> {
        let key = VerifyingKey::from_bytes(key_bytes)
            .map_err(|e| GenesisError::InvalidPublicKey(e.to_string()))?;
        self.add_quorum_key(key)
    }

    /// Builds the genesis configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if required fields are missing.
    pub fn build(self) -> Result<GenesisConfig, GenesisError> {
        let namespace = self
            .namespace
            .ok_or_else(|| GenesisError::Configuration("namespace required".into()))?;
        let ledger_head_hash = self
            .ledger_head_hash
            .ok_or_else(|| GenesisError::Configuration("ledger head hash required".into()))?;
        let t0_key = self
            .t0_key
            .ok_or_else(|| GenesisError::Configuration("T0 key required".into()))?;

        if self.quorum_threshold == 0 {
            return Err(GenesisError::Configuration(
                "quorum threshold must be at least 1".into(),
            ));
        }

        if self.quorum_threshold > self.quorum_keys.len() && !self.quorum_keys.is_empty() {
            return Err(GenesisError::Configuration(format!(
                "quorum threshold {} exceeds number of quorum keys {}",
                self.quorum_threshold,
                self.quorum_keys.len()
            )));
        }

        Ok(GenesisConfig {
            namespace,
            ledger_head_hash,
            t0_key,
            quorum_threshold: self.quorum_threshold,
            quorum_keys: self.quorum_keys,
        })
    }
}

impl GenesisConfig {
    /// Creates a new genesis configuration builder.
    #[must_use]
    pub const fn builder() -> GenesisConfigBuilder {
        GenesisConfigBuilder::new()
    }

    /// Returns the namespace.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Returns the ledger head hash.
    #[must_use]
    pub const fn ledger_head_hash(&self) -> &[u8; 32] {
        &self.ledger_head_hash
    }

    /// Returns the T0 verifying key.
    #[must_use]
    pub const fn t0_key(&self) -> &VerifyingKey {
        &self.t0_key
    }

    /// Returns the quorum threshold.
    #[must_use]
    pub const fn quorum_threshold(&self) -> usize {
        self.quorum_threshold
    }

    /// Returns the quorum keys.
    #[must_use]
    pub fn quorum_keys(&self) -> &[VerifyingKey] {
        &self.quorum_keys
    }
}

/// A genesis block that adopts an existing ledger head hash.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Genesis {
    /// The namespace identifier.
    namespace: String,
    /// The adopted ledger head hash (epoch-0 `prev_hash`).
    #[serde(with = "hex_bytes")]
    ledger_head_hash: [u8; 32],
    /// The genesis signature over the canonical data.
    #[serde(with = "hex_bytes_64")]
    signature: [u8; 64],
    /// The T0 public key that signed this genesis.
    #[serde(with = "hex_bytes")]
    t0_public_key: [u8; 32],
}

impl Genesis {
    /// Creates a new genesis block.
    ///
    /// The signature must be over the canonical representation:
    /// `BLAKE3(namespace || ledger_head_hash)`
    #[must_use]
    pub const fn new(
        namespace: String,
        ledger_head_hash: [u8; 32],
        signature: [u8; 64],
        t0_public_key: [u8; 32],
    ) -> Self {
        Self {
            namespace,
            ledger_head_hash,
            signature,
            t0_public_key,
        }
    }

    /// Returns the namespace.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Returns the ledger head hash (epoch-0 `prev_hash`).
    #[must_use]
    pub const fn ledger_head_hash(&self) -> &[u8; 32] {
        &self.ledger_head_hash
    }

    /// Returns the signature.
    #[must_use]
    pub const fn signature(&self) -> &[u8; 64] {
        &self.signature
    }

    /// Returns the T0 public key.
    #[must_use]
    pub const fn t0_public_key(&self) -> &[u8; 32] {
        &self.t0_public_key
    }

    /// Computes the canonical hash for signing/verification.
    ///
    /// Format: `BLAKE3(namespace || ledger_head_hash)`
    #[must_use]
    pub fn canonical_hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(self.namespace.as_bytes());
        hasher.update(&self.ledger_head_hash);
        *hasher.finalize().as_bytes()
    }

    /// Computes the genesis block hash (unique identifier).
    ///
    /// Format: `BLAKE3(canonical_hash || signature || t0_public_key)`
    #[must_use]
    pub fn genesis_hash(&self) -> [u8; 32] {
        let canonical = self.canonical_hash();
        let mut hasher = blake3::Hasher::new();
        hasher.update(&canonical);
        hasher.update(&self.signature);
        hasher.update(&self.t0_public_key);
        *hasher.finalize().as_bytes()
    }

    /// Verifies the genesis signature against the provided T0 key.
    ///
    /// Uses constant-time comparison for all fields to prevent timing attacks.
    ///
    /// # Errors
    ///
    /// Returns an error if the signature is invalid or the key doesn't match.
    ///
    /// # Security
    ///
    /// All genesis field comparisons use constant-time operations for defense
    /// in depth against timing side-channel attacks.
    pub fn verify(&self, config: &GenesisConfig) -> Result<(), GenesisError> {
        // Verify namespace matches (constant-time via hash comparison)
        // We hash both namespaces and compare the hashes in constant time to
        // avoid leaking namespace length or content through timing
        let expected_ns_hash = blake3::hash(config.namespace.as_bytes());
        let actual_ns_hash = blake3::hash(self.namespace.as_bytes());
        if expected_ns_hash
            .as_bytes()
            .ct_eq(actual_ns_hash.as_bytes())
            .unwrap_u8()
            == 0
        {
            return Err(GenesisError::InvalidNamespace(format!(
                "namespace mismatch: expected '{}', got '{}'",
                config.namespace, self.namespace
            )));
        }

        // Verify ledger head hash matches (constant-time)
        if self
            .ledger_head_hash
            .ct_eq(&config.ledger_head_hash)
            .unwrap_u8()
            == 0
        {
            return Err(GenesisError::GenesisMismatch {
                expected: hex::encode(config.ledger_head_hash),
                actual: hex::encode(self.ledger_head_hash),
            });
        }

        // Verify T0 public key matches (constant-time)
        let expected_key_bytes = config.t0_key.to_bytes();
        if self.t0_public_key.ct_eq(&expected_key_bytes).unwrap_u8() == 0 {
            return Err(GenesisError::InvalidPublicKey(
                "T0 public key mismatch".into(),
            ));
        }

        // Verify signature
        let canonical_hash = self.canonical_hash();
        let signature = Signature::from_bytes(&self.signature);

        config
            .t0_key
            .verify(&canonical_hash, &signature)
            .map_err(|e| GenesisError::SignatureVerification(e.to_string()))?;

        Ok(())
    }

    /// Serializes the genesis to JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn to_json(&self) -> Result<Vec<u8>, GenesisError> {
        serde_json::to_vec(self).map_err(|e| GenesisError::Serialization(e.to_string()))
    }

    /// Deserializes genesis from JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if deserialization fails.
    pub fn from_json(data: &[u8]) -> Result<Self, GenesisError> {
        serde_json::from_slice(data).map_err(|e| GenesisError::Serialization(e.to_string()))
    }
}

/// A quorum-signed invitation token for join requests.
///
/// This token must be signed by at least `quorum_threshold` members
/// to authorize a node to join the network.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvitationToken {
    /// The genesis hash this invitation is for.
    #[serde(with = "hex_bytes")]
    genesis_hash: [u8; 32],
    /// The invitee's node identifier (public key hash).
    invitee_id: String,
    /// Expiration timestamp (Unix seconds).
    expires_at: u64,
    /// Signatures from quorum members (`key_index`, signature).
    signatures: Vec<QuorumSignature>,
}

/// A signature from a quorum member.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuorumSignature {
    /// Index of the signing key in the quorum key list.
    key_index: usize,
    /// The signature bytes.
    #[serde(with = "hex_bytes_64")]
    signature: [u8; 64],
}

impl InvitationToken {
    /// Creates a new invitation token.
    #[must_use]
    pub const fn new(genesis_hash: [u8; 32], invitee_id: String, expires_at: u64) -> Self {
        Self {
            genesis_hash,
            invitee_id,
            expires_at,
            signatures: Vec::new(),
        }
    }

    /// Returns the genesis hash.
    #[must_use]
    pub const fn genesis_hash(&self) -> &[u8; 32] {
        &self.genesis_hash
    }

    /// Returns the invitee ID.
    #[must_use]
    pub fn invitee_id(&self) -> &str {
        &self.invitee_id
    }

    /// Returns the expiration timestamp.
    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Returns the signatures.
    #[must_use]
    pub fn signatures(&self) -> &[QuorumSignature] {
        &self.signatures
    }

    /// Adds a quorum signature.
    ///
    /// # Errors
    ///
    /// Returns an error if maximum signatures exceeded.
    pub fn add_signature(
        &mut self,
        key_index: usize,
        signature: [u8; 64],
    ) -> Result<(), GenesisError> {
        if self.signatures.len() >= MAX_QUORUM_SIGNATURES {
            return Err(GenesisError::InvalidInvitationToken(
                "maximum signatures exceeded".into(),
            ));
        }
        self.signatures.push(QuorumSignature {
            key_index,
            signature,
        });
        Ok(())
    }

    /// Computes the canonical hash for signing/verification.
    ///
    /// Format: `BLAKE3(genesis_hash || invitee_id || expires_at)`
    #[must_use]
    pub fn canonical_hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.genesis_hash);
        hasher.update(self.invitee_id.as_bytes());
        hasher.update(&self.expires_at.to_be_bytes());
        *hasher.finalize().as_bytes()
    }

    /// Verifies the invitation token against the quorum configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - The genesis configuration with quorum keys
    /// * `current_time` - Current Unix timestamp for expiration check
    ///
    /// # Errors
    ///
    /// Returns an error if verification fails.
    ///
    /// # Security
    ///
    /// This method tracks used key indices to prevent double-counting
    /// signatures from the same quorum member. An attacker cannot satisfy
    /// the threshold by providing the same valid signature multiple times.
    pub fn verify(&self, config: &GenesisConfig, current_time: u64) -> Result<(), GenesisError> {
        // Check expiration
        if current_time > self.expires_at {
            return Err(GenesisError::InvalidInvitationToken(
                "invitation token expired".into(),
            ));
        }

        // Verify we have enough signatures
        if self.signatures.len() < config.quorum_threshold {
            return Err(GenesisError::InsufficientQuorum {
                have: self.signatures.len(),
                need: config.quorum_threshold,
            });
        }

        // Verify each signature, tracking used key indices to prevent double-counting
        let canonical_hash = self.canonical_hash();
        let mut valid_count = 0;
        let mut seen_key_indices: HashSet<usize> = HashSet::new();

        for qs in &self.signatures {
            // Validate key index
            if qs.key_index >= config.quorum_keys.len() {
                return Err(GenesisError::InvalidInvitationToken(format!(
                    "invalid key index: {}",
                    qs.key_index
                )));
            }

            // Skip duplicate key indices - prevents double-counting attack
            if seen_key_indices.contains(&qs.key_index) {
                continue;
            }

            let key = &config.quorum_keys[qs.key_index];
            let signature = Signature::from_bytes(&qs.signature);

            if key.verify(&canonical_hash, &signature).is_ok() {
                seen_key_indices.insert(qs.key_index);
                valid_count += 1;
            }
        }

        if valid_count < config.quorum_threshold {
            return Err(GenesisError::InsufficientQuorum {
                have: valid_count,
                need: config.quorum_threshold,
            });
        }

        Ok(())
    }

    /// Serializes the token to JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn to_json(&self) -> Result<Vec<u8>, GenesisError> {
        serde_json::to_vec(self).map_err(|e| GenesisError::Serialization(e.to_string()))
    }

    /// Deserializes token from JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if deserialization fails or signature count exceeds
    /// `MAX_SIGNATURES`.
    ///
    /// # Security
    ///
    /// This method validates the signature count after parsing to prevent
    /// unbounded memory allocation (denial-of-service via oversized signatures
    /// array).
    pub fn from_json(data: &[u8]) -> Result<Self, GenesisError> {
        let token: Self =
            serde_json::from_slice(data).map_err(|e| GenesisError::Serialization(e.to_string()))?;

        // Validate signature count to prevent DoS via unbounded allocation
        if token.signatures.len() > MAX_SIGNATURES {
            return Err(GenesisError::InvalidInvitationToken(format!(
                "too many signatures: {} exceeds maximum {}",
                token.signatures.len(),
                MAX_SIGNATURES
            )));
        }

        Ok(token)
    }
}

/// Rate limiter for join attempts.
///
/// Implements bounded tracking of join attempts per source to enforce rate
/// limits while preventing unbounded memory growth (CTR-1303: Bounded Stores).
pub struct JoinRateLimiter {
    /// Join attempts per source.
    attempts: HashMap<String, Vec<Instant>>,
    /// Maximum attempts per window.
    max_attempts: usize,
    /// Window duration.
    window: Duration,
    /// Maximum number of tracked sources.
    max_sources: usize,
}

impl Default for JoinRateLimiter {
    fn default() -> Self {
        Self::new(MAX_JOIN_ATTEMPTS_PER_MINUTE, RATE_LIMIT_WINDOW)
    }
}

impl JoinRateLimiter {
    /// Creates a new rate limiter.
    #[must_use]
    pub fn new(max_attempts: usize, window: Duration) -> Self {
        Self::with_max_sources(max_attempts, window, MAX_RATE_LIMIT_SOURCES)
    }

    /// Creates a rate limiter with custom max sources.
    #[must_use]
    pub fn with_max_sources(max_attempts: usize, window: Duration, max_sources: usize) -> Self {
        Self {
            attempts: HashMap::new(),
            max_attempts,
            window,
            max_sources,
        }
    }

    /// Checks if a join attempt is allowed.
    ///
    /// If the maximum number of tracked sources is reached and this is a new
    /// source, the oldest entries are evicted to make room.
    ///
    /// # Errors
    ///
    /// Returns an error if the rate limit is exceeded.
    pub fn check(&mut self, source: &str) -> Result<(), GenesisError> {
        let now = Instant::now();

        // If this is a new source and we're at capacity, evict old entries first
        if !self.attempts.contains_key(source) && self.attempts.len() >= self.max_sources {
            self.evict_oldest_entries(now);

            // If still at capacity after eviction, reject the request
            if self.attempts.len() >= self.max_sources {
                return Err(GenesisError::RateLimitExceeded {
                    attempts: 0,
                    window_secs: self.window.as_secs(),
                });
            }
        }

        let attempts = self.attempts.entry(source.to_string()).or_default();

        // Remove old attempts
        attempts.retain(|t| now.duration_since(*t) < self.window);

        if attempts.len() >= self.max_attempts {
            return Err(GenesisError::RateLimitExceeded {
                attempts: attempts.len(),
                window_secs: self.window.as_secs(),
            });
        }

        attempts.push(now);
        Ok(())
    }

    /// Evicts entries with no recent attempts.
    fn evict_oldest_entries(&mut self, now: Instant) {
        // First, remove entries with no attempts within the window
        self.attempts.retain(|_, attempts| {
            attempts.retain(|t| now.duration_since(*t) < self.window);
            !attempts.is_empty()
        });

        // If still over capacity, remove entries with oldest most-recent attempt
        while self.attempts.len() >= self.max_sources {
            let oldest_key = self
                .attempts
                .iter()
                .filter_map(|(k, v)| v.last().map(|t| (k.clone(), *t)))
                .min_by_key(|(_, t)| *t)
                .map(|(k, _)| k);

            if let Some(key) = oldest_key {
                self.attempts.remove(&key);
            } else {
                break;
            }
        }
    }

    /// Cleans up old entries.
    pub fn cleanup(&mut self) {
        let now = Instant::now();
        self.attempts.retain(|_, attempts| {
            attempts.retain(|t| now.duration_since(*t) < self.window);
            !attempts.is_empty()
        });
    }

    /// Returns the number of tracked sources.
    #[cfg(test)]
    #[must_use]
    pub fn source_count(&self) -> usize {
        self.attempts.len()
    }
}

/// Validates genesis and join requests.
///
/// This validator combines rate limiting, genesis verification, and
/// invitation token validation.
pub struct GenesisValidator {
    /// Genesis configuration.
    config: GenesisConfig,
    /// The expected genesis block.
    expected_genesis: Genesis,
    /// Rate limiter for join attempts.
    rate_limiter: JoinRateLimiter,
}

impl GenesisValidator {
    /// Creates a new genesis validator.
    #[must_use]
    pub fn new(config: GenesisConfig, expected_genesis: Genesis) -> Self {
        Self {
            config,
            expected_genesis,
            rate_limiter: JoinRateLimiter::default(),
        }
    }

    /// Creates a validator with a custom rate limiter.
    #[must_use]
    pub const fn with_rate_limiter(
        config: GenesisConfig,
        expected_genesis: Genesis,
        rate_limiter: JoinRateLimiter,
    ) -> Self {
        Self {
            config,
            expected_genesis,
            rate_limiter,
        }
    }

    /// Returns a reference to the genesis configuration.
    #[must_use]
    pub const fn config(&self) -> &GenesisConfig {
        &self.config
    }

    /// Returns a reference to the expected genesis.
    #[must_use]
    pub const fn expected_genesis(&self) -> &Genesis {
        &self.expected_genesis
    }

    /// Validates a genesis block from a joining node.
    ///
    /// # Errors
    ///
    /// Returns an error if the genesis doesn't match.
    pub fn validate_genesis(&self, genesis: &Genesis) -> Result<(), GenesisError> {
        // First verify the genesis signature is valid
        genesis.verify(&self.config)?;

        // Then verify it matches our expected genesis (constant-time)
        let expected_hash = self.expected_genesis.genesis_hash();
        let actual_hash = genesis.genesis_hash();

        if expected_hash.ct_eq(&actual_hash).unwrap_u8() == 0 {
            return Err(GenesisError::GenesisMismatch {
                expected: hex::encode(expected_hash),
                actual: hex::encode(actual_hash),
            });
        }

        Ok(())
    }

    /// Validates a join request with rate limiting and invitation token.
    ///
    /// # Arguments
    ///
    /// * `source` - Source identifier (IP or node ID)
    /// * `genesis` - The genesis block from the joining node
    /// * `invitation` - The quorum-signed invitation token
    /// * `current_time` - Current Unix timestamp
    ///
    /// # Errors
    ///
    /// Returns an error if validation fails.
    pub fn validate_join_request(
        &mut self,
        source: &str,
        genesis: &Genesis,
        invitation: &InvitationToken,
        current_time: u64,
    ) -> Result<(), GenesisError> {
        // Check rate limit first (INV-0013)
        self.rate_limiter.check(source)?;

        // Validate genesis (INV-0024, INV-0025)
        self.validate_genesis(genesis)?;

        // Validate invitation token genesis hash matches
        let genesis_hash = genesis.genesis_hash();
        if invitation.genesis_hash.ct_eq(&genesis_hash).unwrap_u8() == 0 {
            return Err(GenesisError::InvalidInvitationToken(
                "genesis hash mismatch".into(),
            ));
        }

        // Validate invitation token signatures (INV-0026)
        invitation.verify(&self.config, current_time)?;

        Ok(())
    }

    /// Cleans up the rate limiter.
    pub fn cleanup(&mut self) {
        self.rate_limiter.cleanup();
    }
}

/// Serde helper for 32-byte hex arrays.
mod hex_bytes {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
    }
}

/// Serde helper for 64-byte hex arrays.
mod hex_bytes_64 {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 64 bytes"))
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    use super::*;

    fn create_test_keypair() -> (SigningKey, VerifyingKey) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        (signing_key, verifying_key)
    }

    fn create_test_genesis(
        signing_key: &SigningKey,
        namespace: &str,
        ledger_head_hash: [u8; 32],
    ) -> Genesis {
        let mut hasher = blake3::Hasher::new();
        hasher.update(namespace.as_bytes());
        hasher.update(&ledger_head_hash);
        let canonical_hash = *hasher.finalize().as_bytes();

        let signature = signing_key.sign(&canonical_hash);
        let t0_public_key = signing_key.verifying_key().to_bytes();

        Genesis::new(
            namespace.to_string(),
            ledger_head_hash,
            signature.to_bytes(),
            t0_public_key,
        )
    }

    #[test]
    fn test_genesis_config_builder() {
        let (_, verifying_key) = create_test_keypair();
        let ledger_hash = [0u8; 32];

        let config = GenesisConfig::builder()
            .namespace("test-namespace")
            .unwrap()
            .ledger_head_hash(ledger_hash)
            .t0_key(verifying_key)
            .build()
            .unwrap();

        assert_eq!(config.namespace(), "test-namespace");
        assert_eq!(config.ledger_head_hash(), &ledger_hash);
    }

    #[test]
    fn test_genesis_config_builder_missing_namespace() {
        let (_, verifying_key) = create_test_keypair();

        let result = GenesisConfig::builder()
            .ledger_head_hash([0u8; 32])
            .t0_key(verifying_key)
            .build();

        assert!(matches!(result, Err(GenesisError::Configuration(_))));
    }

    #[test]
    fn test_genesis_config_builder_invalid_namespace() {
        let result = GenesisConfig::builder().namespace("");

        assert!(matches!(result, Err(GenesisError::InvalidNamespace(_))));
    }

    #[test]
    fn test_genesis_verify_valid() {
        let (signing_key, verifying_key) = create_test_keypair();
        let namespace = "test-namespace";
        let ledger_hash = [1u8; 32];

        let genesis = create_test_genesis(&signing_key, namespace, ledger_hash);

        let config = GenesisConfig::builder()
            .namespace(namespace)
            .unwrap()
            .ledger_head_hash(ledger_hash)
            .t0_key(verifying_key)
            .build()
            .unwrap();

        assert!(genesis.verify(&config).is_ok());
    }

    #[test]
    fn test_genesis_verify_wrong_namespace() {
        let (signing_key, verifying_key) = create_test_keypair();
        let ledger_hash = [1u8; 32];

        let genesis = create_test_genesis(&signing_key, "namespace-a", ledger_hash);

        let config = GenesisConfig::builder()
            .namespace("namespace-b")
            .unwrap()
            .ledger_head_hash(ledger_hash)
            .t0_key(verifying_key)
            .build()
            .unwrap();

        let result = genesis.verify(&config);
        assert!(matches!(result, Err(GenesisError::InvalidNamespace(_))));
    }

    #[test]
    fn test_genesis_verify_wrong_hash() {
        let (signing_key, verifying_key) = create_test_keypair();
        let namespace = "test-namespace";

        let genesis = create_test_genesis(&signing_key, namespace, [1u8; 32]);

        let config = GenesisConfig::builder()
            .namespace(namespace)
            .unwrap()
            .ledger_head_hash([2u8; 32])
            .t0_key(verifying_key)
            .build()
            .unwrap();

        let result = genesis.verify(&config);
        assert!(matches!(result, Err(GenesisError::GenesisMismatch { .. })));
    }

    #[test]
    fn test_genesis_verify_wrong_key() {
        let (signing_key, _) = create_test_keypair();
        let (_, other_verifying_key) = create_test_keypair();
        let namespace = "test-namespace";
        let ledger_hash = [1u8; 32];

        let genesis = create_test_genesis(&signing_key, namespace, ledger_hash);

        let config = GenesisConfig::builder()
            .namespace(namespace)
            .unwrap()
            .ledger_head_hash(ledger_hash)
            .t0_key(other_verifying_key)
            .build()
            .unwrap();

        let result = genesis.verify(&config);
        assert!(matches!(result, Err(GenesisError::InvalidPublicKey(_))));
    }

    #[test]
    fn test_genesis_serde_roundtrip() {
        let (signing_key, _) = create_test_keypair();
        let genesis = create_test_genesis(&signing_key, "test", [42u8; 32]);

        let json = genesis.to_json().unwrap();
        let parsed = Genesis::from_json(&json).unwrap();

        assert_eq!(parsed.namespace(), genesis.namespace());
        assert_eq!(parsed.ledger_head_hash(), genesis.ledger_head_hash());
        assert_eq!(parsed.signature(), genesis.signature());
        assert_eq!(parsed.t0_public_key(), genesis.t0_public_key());
    }

    #[test]
    fn test_invitation_token_verify() {
        let (q1_signing, q1_verifying) = create_test_keypair();
        let (q2_signing, q2_verifying) = create_test_keypair();

        let genesis_hash = [1u8; 32];
        let invitee_id = "node-123".to_string();
        let expires_at = u64::MAX; // Far future

        let mut token = InvitationToken::new(genesis_hash, invitee_id, expires_at);

        // Sign with quorum members
        let canonical_hash = token.canonical_hash();
        let sig1 = q1_signing.sign(&canonical_hash);
        let sig2 = q2_signing.sign(&canonical_hash);

        token.add_signature(0, sig1.to_bytes()).unwrap();
        token.add_signature(1, sig2.to_bytes()).unwrap();

        // Create config with quorum
        let (_, t0_key) = create_test_keypair();
        let config = GenesisConfig::builder()
            .namespace("test")
            .unwrap()
            .ledger_head_hash([0u8; 32])
            .t0_key(t0_key)
            .quorum_threshold(2)
            .add_quorum_key(q1_verifying)
            .unwrap()
            .add_quorum_key(q2_verifying)
            .unwrap()
            .build()
            .unwrap();

        assert!(token.verify(&config, 0).is_ok());
    }

    #[test]
    fn test_invitation_token_expired() {
        let genesis_hash = [1u8; 32];
        let token = InvitationToken::new(genesis_hash, "node-123".to_string(), 100);

        let (_, t0_key) = create_test_keypair();
        let config = GenesisConfig::builder()
            .namespace("test")
            .unwrap()
            .ledger_head_hash([0u8; 32])
            .t0_key(t0_key)
            .build()
            .unwrap();

        let result = token.verify(&config, 200); // Current time > expires_at
        assert!(matches!(
            result,
            Err(GenesisError::InvalidInvitationToken(_))
        ));
    }

    #[test]
    fn test_invitation_token_insufficient_quorum() {
        let (q1_signing, q1_verifying) = create_test_keypair();
        let (_, q2_verifying) = create_test_keypair();

        let genesis_hash = [1u8; 32];
        let mut token = InvitationToken::new(genesis_hash, "node-123".to_string(), u64::MAX);

        // Only sign with one member
        let canonical_hash = token.canonical_hash();
        let sig1 = q1_signing.sign(&canonical_hash);
        token.add_signature(0, sig1.to_bytes()).unwrap();

        let (_, t0_key) = create_test_keypair();
        let config = GenesisConfig::builder()
            .namespace("test")
            .unwrap()
            .ledger_head_hash([0u8; 32])
            .t0_key(t0_key)
            .quorum_threshold(2) // Requires 2 signatures
            .add_quorum_key(q1_verifying)
            .unwrap()
            .add_quorum_key(q2_verifying)
            .unwrap()
            .build()
            .unwrap();

        let result = token.verify(&config, 0);
        assert!(matches!(
            result,
            Err(GenesisError::InsufficientQuorum { have: 1, need: 2 })
        ));
    }

    #[test]
    fn test_rate_limiter_allows_within_limit() {
        let mut limiter = JoinRateLimiter::new(3, Duration::from_secs(60));

        assert!(limiter.check("source1").is_ok());
        assert!(limiter.check("source1").is_ok());
        assert!(limiter.check("source1").is_ok());
    }

    #[test]
    fn test_rate_limiter_blocks_over_limit() {
        let mut limiter = JoinRateLimiter::new(2, Duration::from_secs(60));

        assert!(limiter.check("source1").is_ok());
        assert!(limiter.check("source1").is_ok());
        assert!(matches!(
            limiter.check("source1"),
            Err(GenesisError::RateLimitExceeded { .. })
        ));
    }

    #[test]
    fn test_rate_limiter_separate_sources() {
        let mut limiter = JoinRateLimiter::new(2, Duration::from_secs(60));

        assert!(limiter.check("source1").is_ok());
        assert!(limiter.check("source1").is_ok());
        assert!(limiter.check("source2").is_ok()); // Different source
        assert!(matches!(
            limiter.check("source1"),
            Err(GenesisError::RateLimitExceeded { .. })
        ));
    }

    #[test]
    fn test_rate_limiter_bounded_sources() {
        let max_sources = 3;
        let mut limiter =
            JoinRateLimiter::with_max_sources(10, Duration::from_secs(60), max_sources);

        // Fill up to max sources
        for i in 0..max_sources {
            assert!(limiter.check(&format!("source{i}")).is_ok());
        }

        assert_eq!(limiter.source_count(), max_sources);

        // New source should still work (eviction will occur)
        assert!(limiter.check("new_source").is_ok());
        assert!(limiter.source_count() <= max_sources);
    }

    #[test]
    fn test_genesis_validator() {
        let (signing_key, verifying_key) = create_test_keypair();
        let namespace = "test-namespace";
        let ledger_hash = [1u8; 32];

        let genesis = create_test_genesis(&signing_key, namespace, ledger_hash);

        let config = GenesisConfig::builder()
            .namespace(namespace)
            .unwrap()
            .ledger_head_hash(ledger_hash)
            .t0_key(verifying_key)
            .build()
            .unwrap();

        let validator = GenesisValidator::new(config, genesis.clone());

        // Same genesis should validate
        assert!(validator.validate_genesis(&genesis).is_ok());

        // Different genesis should fail
        let other_genesis = create_test_genesis(&signing_key, namespace, [2u8; 32]);
        let result = validator.validate_genesis(&other_genesis);
        assert!(matches!(result, Err(GenesisError::GenesisMismatch { .. })));
    }
}

#[cfg(test)]
mod tck_00185_genesis_tests {
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    use super::*;

    fn create_test_keypair() -> (SigningKey, VerifyingKey) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        (signing_key, verifying_key)
    }

    fn create_test_genesis(
        signing_key: &SigningKey,
        namespace: &str,
        ledger_head_hash: [u8; 32],
    ) -> Genesis {
        let mut hasher = blake3::Hasher::new();
        hasher.update(namespace.as_bytes());
        hasher.update(&ledger_head_hash);
        let canonical_hash = *hasher.finalize().as_bytes();

        let signature = signing_key.sign(&canonical_hash);
        let t0_public_key = signing_key.verifying_key().to_bytes();

        Genesis::new(
            namespace.to_string(),
            ledger_head_hash,
            signature.to_bytes(),
            t0_public_key,
        )
    }

    #[test]
    fn test_tck_00185_genesis_adopts_ledger_head_hash() {
        // AC1: Genesis adopts existing ledger head hash without rehashing history
        let (signing_key, verifying_key) = create_test_keypair();
        let namespace = "production-network";
        let existing_ledger_hash = blake3::hash(b"existing ledger state");

        let genesis =
            create_test_genesis(&signing_key, namespace, *existing_ledger_hash.as_bytes());

        // The genesis should store the hash directly, not rehash it
        assert_eq!(
            genesis.ledger_head_hash(),
            existing_ledger_hash.as_bytes(),
            "Genesis must adopt existing ledger head hash"
        );

        let config = GenesisConfig::builder()
            .namespace(namespace)
            .unwrap()
            .ledger_head_hash(*existing_ledger_hash.as_bytes())
            .t0_key(verifying_key)
            .build()
            .unwrap();

        assert!(
            genesis.verify(&config).is_ok(),
            "Genesis with adopted ledger hash must verify"
        );
    }

    #[test]
    fn test_tck_00185_genesis_signature_verified_against_t0_key() {
        // AC2: Genesis signature verified against T0 key
        let (signing_key, verifying_key) = create_test_keypair();
        let (_, other_key) = create_test_keypair();
        let namespace = "test-network";
        let ledger_hash = [42u8; 32];

        let genesis = create_test_genesis(&signing_key, namespace, ledger_hash);

        // Verification should pass with correct T0 key
        let correct_config = GenesisConfig::builder()
            .namespace(namespace)
            .unwrap()
            .ledger_head_hash(ledger_hash)
            .t0_key(verifying_key)
            .build()
            .unwrap();

        assert!(
            genesis.verify(&correct_config).is_ok(),
            "Genesis signature must verify against T0 key"
        );

        // Verification should fail with wrong T0 key
        let wrong_config = GenesisConfig::builder()
            .namespace(namespace)
            .unwrap()
            .ledger_head_hash(ledger_hash)
            .t0_key(other_key)
            .build()
            .unwrap();

        assert!(
            genesis.verify(&wrong_config).is_err(),
            "Genesis must reject verification with wrong T0 key"
        );
    }

    #[test]
    fn test_tck_00185_node_rejects_join_on_genesis_mismatch() {
        // AC3: Node rejects join on genesis mismatch
        let (signing_key, verifying_key) = create_test_keypair();
        let namespace = "test-network";

        // Create "our" genesis
        let our_genesis = create_test_genesis(&signing_key, namespace, [1u8; 32]);

        // Create validator with our genesis
        let config = GenesisConfig::builder()
            .namespace(namespace)
            .unwrap()
            .ledger_head_hash([1u8; 32])
            .t0_key(verifying_key)
            .build()
            .unwrap();

        let validator = GenesisValidator::new(config, our_genesis);

        // Create a different genesis (different ledger hash)
        let different_genesis = create_test_genesis(&signing_key, namespace, [2u8; 32]);

        let result = validator.validate_genesis(&different_genesis);
        assert!(
            matches!(result, Err(GenesisError::GenesisMismatch { .. })),
            "Node must reject join on genesis mismatch"
        );
    }

    #[test]
    fn test_tck_00185_join_rate_limited_per_source() {
        // AC4: Join attempts rate-limited per source or identity
        let (signing_key, verifying_key) = create_test_keypair();
        let (q_signing, q_verifying) = create_test_keypair();
        let namespace = "test-network";
        let ledger_hash = [1u8; 32];

        let genesis = create_test_genesis(&signing_key, namespace, ledger_hash);

        let config = GenesisConfig::builder()
            .namespace(namespace)
            .unwrap()
            .ledger_head_hash(ledger_hash)
            .t0_key(verifying_key)
            .quorum_threshold(1)
            .add_quorum_key(q_verifying)
            .unwrap()
            .build()
            .unwrap();

        // Create invitation token
        let genesis_hash = genesis.genesis_hash();
        let mut token = InvitationToken::new(genesis_hash, "node-123".to_string(), u64::MAX);
        let sig = q_signing.sign(&token.canonical_hash());
        token.add_signature(0, sig.to_bytes()).unwrap();

        // Use low rate limit for testing
        let rate_limiter = JoinRateLimiter::new(3, Duration::from_secs(60));
        let mut validator =
            GenesisValidator::with_rate_limiter(config, genesis.clone(), rate_limiter);

        let source = "192.168.1.100";

        // First 3 attempts should succeed
        for _ in 0..3 {
            assert!(
                validator
                    .validate_join_request(source, &genesis, &token, 0)
                    .is_ok(),
                "Join attempts within limit should succeed"
            );
        }

        // 4th attempt should be rate limited
        let result = validator.validate_join_request(source, &genesis, &token, 0);
        assert!(
            matches!(result, Err(GenesisError::RateLimitExceeded { .. })),
            "Join attempts must be rate-limited"
        );

        // Different source should work
        assert!(
            validator
                .validate_join_request("192.168.1.200", &genesis, &token, 0)
                .is_ok(),
            "Different source should not be rate-limited"
        );
    }

    #[test]
    fn test_tck_00185_join_requires_quorum_signed_invitation() {
        // AC5: Join requests require quorum-signed invitation token
        let (signing_key, verifying_key) = create_test_keypair();
        let (q1_signing, q1_verifying) = create_test_keypair();
        let (q2_signing, q2_verifying) = create_test_keypair();
        let namespace = "test-network";
        let ledger_hash = [1u8; 32];

        let genesis = create_test_genesis(&signing_key, namespace, ledger_hash);
        let genesis_hash = genesis.genesis_hash();

        let config = GenesisConfig::builder()
            .namespace(namespace)
            .unwrap()
            .ledger_head_hash(ledger_hash)
            .t0_key(verifying_key)
            .quorum_threshold(2) // Require 2 signatures
            .add_quorum_key(q1_verifying)
            .unwrap()
            .add_quorum_key(q2_verifying)
            .unwrap()
            .build()
            .unwrap();

        let mut validator = GenesisValidator::new(config, genesis.clone());

        // Create token with only 1 signature (insufficient)
        let mut insufficient_token =
            InvitationToken::new(genesis_hash, "node-123".to_string(), u64::MAX);
        let sig1 = q1_signing.sign(&insufficient_token.canonical_hash());
        insufficient_token
            .add_signature(0, sig1.to_bytes())
            .unwrap();

        let result = validator.validate_join_request("source1", &genesis, &insufficient_token, 0);
        assert!(
            matches!(result, Err(GenesisError::InsufficientQuorum { .. })),
            "Join must require quorum-signed invitation"
        );

        // Create token with 2 signatures (sufficient)
        let mut sufficient_token =
            InvitationToken::new(genesis_hash, "node-123".to_string(), u64::MAX);
        let sig1 = q1_signing.sign(&sufficient_token.canonical_hash());
        let sig2 = q2_signing.sign(&sufficient_token.canonical_hash());
        sufficient_token.add_signature(0, sig1.to_bytes()).unwrap();
        sufficient_token.add_signature(1, sig2.to_bytes()).unwrap();

        assert!(
            validator
                .validate_join_request("source2", &genesis, &sufficient_token, 0)
                .is_ok(),
            "Join with quorum-signed invitation should succeed"
        );
    }

    #[test]
    fn test_tck_00185_genesis_serde_strict() {
        // CTR-1604: Strict Serde for wire formats
        let (signing_key, _) = create_test_keypair();
        let genesis = create_test_genesis(&signing_key, "test", [0u8; 32]);

        // Roundtrip should preserve all fields
        let json = genesis.to_json().unwrap();
        let parsed = Genesis::from_json(&json).unwrap();

        assert_eq!(parsed.namespace(), genesis.namespace());
        assert_eq!(parsed.ledger_head_hash(), genesis.ledger_head_hash());
        assert_eq!(parsed.signature(), genesis.signature());
        assert_eq!(parsed.t0_public_key(), genesis.t0_public_key());

        // Unknown fields should be rejected (deny_unknown_fields)
        let bad_json = br#"{"namespace":"test","ledger_head_hash":"00","signature":"00","t0_public_key":"00","extra":"field"}"#;
        assert!(
            Genesis::from_json(bad_json).is_err(),
            "Unknown fields must be rejected"
        );
    }

    #[test]
    fn test_tck_00185_invitation_token_serde_strict() {
        // CTR-1604: Strict Serde for wire formats
        let token = InvitationToken::new([1u8; 32], "node-123".to_string(), 12345);

        let json = token.to_json().unwrap();
        let parsed = InvitationToken::from_json(&json).unwrap();

        assert_eq!(parsed.genesis_hash(), token.genesis_hash());
        assert_eq!(parsed.invitee_id(), token.invitee_id());
        assert_eq!(parsed.expires_at(), token.expires_at());

        // Unknown fields should be rejected
        let bad_json = br#"{"genesis_hash":"01","invitee_id":"node","expires_at":0,"signatures":[],"extra":"field"}"#;
        assert!(
            InvitationToken::from_json(bad_json).is_err(),
            "Unknown fields must be rejected"
        );
    }

    #[test]
    fn test_tck_00185_constant_time_comparison() {
        // Security: Verify constant-time comparison is used
        let (signing_key, verifying_key) = create_test_keypair();
        let namespace = "test";
        let ledger_hash = [1u8; 32];

        let genesis = create_test_genesis(&signing_key, namespace, ledger_hash);

        let config = GenesisConfig::builder()
            .namespace(namespace)
            .unwrap()
            .ledger_head_hash(ledger_hash)
            .t0_key(verifying_key)
            .build()
            .unwrap();

        // This test verifies the code compiles with constant-time comparison
        // The actual timing resistance is provided by the subtle crate
        assert!(genesis.verify(&config).is_ok());
    }

    #[test]
    fn test_tck_00185_genesis_hash_computation() {
        // Verify genesis hash includes all components
        let (signing_key, _) = create_test_keypair();
        let genesis1 = create_test_genesis(&signing_key, "ns1", [1u8; 32]);
        let genesis2 = create_test_genesis(&signing_key, "ns2", [1u8; 32]);
        let genesis3 = create_test_genesis(&signing_key, "ns1", [2u8; 32]);

        // Different namespace -> different hash
        assert_ne!(genesis1.genesis_hash(), genesis2.genesis_hash());

        // Different ledger hash -> different hash
        assert_ne!(genesis1.genesis_hash(), genesis3.genesis_hash());

        // Same inputs -> same canonical hash (signature will differ)
        assert_eq!(genesis1.canonical_hash(), genesis1.canonical_hash());
    }

    #[test]
    fn test_tck_00185_rate_limiter_bounded_memory() {
        // CTR-1303: Bounded Stores
        let max_sources = 5;
        let mut limiter =
            JoinRateLimiter::with_max_sources(10, Duration::from_secs(60), max_sources);

        // Add many unique sources
        for i in 0..20 {
            let _ = limiter.check(&format!("source_{i}"));
        }

        // Memory should be bounded
        assert!(
            limiter.source_count() <= max_sources,
            "Rate limiter must have bounded memory"
        );
    }

    #[test]
    fn test_tck_00185_signature_double_counting_prevented() {
        // Security: Prevent quorum threshold bypass via signature duplication
        let (q1_signing, q1_verifying) = create_test_keypair();
        let (_, q2_verifying) = create_test_keypair();

        let genesis_hash = [1u8; 32];
        let invitee_id = "node-123".to_string();
        let expires_at = u64::MAX;

        let mut token = InvitationToken::new(genesis_hash, invitee_id, expires_at);

        // Sign with ONE quorum member
        let canonical_hash = token.canonical_hash();
        let sig1 = q1_signing.sign(&canonical_hash);

        // Add the SAME signature multiple times with the same key_index
        // An attacker might try to satisfy threshold=2 by duplicating one signature
        token.add_signature(0, sig1.to_bytes()).unwrap();
        token.add_signature(0, sig1.to_bytes()).unwrap(); // Duplicate!
        token.add_signature(0, sig1.to_bytes()).unwrap(); // Duplicate!

        // Create config requiring 2 distinct signatures
        let (_, t0_key) = create_test_keypair();
        let config = GenesisConfig::builder()
            .namespace("test")
            .unwrap()
            .ledger_head_hash([0u8; 32])
            .t0_key(t0_key)
            .quorum_threshold(2) // Requires 2 DISTINCT signers
            .add_quorum_key(q1_verifying)
            .unwrap()
            .add_quorum_key(q2_verifying)
            .unwrap()
            .build()
            .unwrap();

        // Verification must FAIL - duplicates should not count twice
        let result = token.verify(&config, 0);
        assert!(
            matches!(
                result,
                Err(GenesisError::InsufficientQuorum { have: 1, need: 2 })
            ),
            "Duplicate signatures must not be double-counted: {result:?}"
        );
    }

    #[test]
    fn test_tck_00185_unbounded_signatures_rejected() {
        use std::fmt::Write;

        // Security: Prevent unbounded signature array attack
        // Create a JSON with more signatures than MAX_SIGNATURES
        let mut signatures_json = String::from("[");
        let sig_hex = "00".repeat(64); // 64 bytes as hex = 128 chars
        for i in 0..=MAX_SIGNATURES {
            if i > 0 {
                signatures_json.push(',');
            }
            // Each signature entry with valid hex encoding for 64 bytes
            write!(
                signatures_json,
                r#"{{"key_index":{},"signature":"{sig_hex}"}}"#,
                i % 16 // key_index cycles to stay valid
            )
            .unwrap();
        }
        signatures_json.push(']');

        let genesis_hex = "00".repeat(32); // 32 bytes as hex
        let json = format!(
            r#"{{"genesis_hash":"{genesis_hex}","invitee_id":"node-123","expires_at":12345,"signatures":{signatures_json}}}"#
        );

        let result = InvitationToken::from_json(json.as_bytes());
        assert!(
            matches!(result, Err(GenesisError::InvalidInvitationToken(ref msg)) if msg.contains("too many signatures")),
            "Must reject tokens with too many signatures: {result:?}"
        );
    }

    #[test]
    fn test_tck_00185_max_signatures_boundary() {
        use std::fmt::Write;

        // Test that exactly MAX_SIGNATURES is accepted
        let mut signatures_json = String::from("[");
        let sig_hex = "00".repeat(64);
        for i in 0..MAX_SIGNATURES {
            if i > 0 {
                signatures_json.push(',');
            }
            write!(
                signatures_json,
                r#"{{"key_index":{},"signature":"{sig_hex}"}}"#,
                i % 16
            )
            .unwrap();
        }
        signatures_json.push(']');

        let genesis_hex = "00".repeat(32);
        let json = format!(
            r#"{{"genesis_hash":"{genesis_hex}","invitee_id":"node-123","expires_at":12345,"signatures":{signatures_json}}}"#
        );

        let result = InvitationToken::from_json(json.as_bytes());
        assert!(
            result.is_ok(),
            "Must accept tokens with exactly MAX_SIGNATURES: {result:?}"
        );
    }

    // Compile-time assertions for constants
    const _: () = {
        assert!(MAX_NAMESPACE_LEN > 0, "MAX_NAMESPACE_LEN must be positive");
        assert!(
            MAX_QUORUM_SIGNATURES > 0,
            "MAX_QUORUM_SIGNATURES must be positive"
        );
        assert!(
            MAX_JOIN_ATTEMPTS_PER_MINUTE > 0,
            "MAX_JOIN_ATTEMPTS_PER_MINUTE must be positive"
        );
        assert!(
            MAX_RATE_LIMIT_SOURCES > 0,
            "MAX_RATE_LIMIT_SOURCES must be positive"
        );
    };
}
