//! Per-connection session token issuance and validation (TCK-00250).
//!
//! This module implements session tokens for authenticating session-scoped IPC
//! connections. Tokens bind a session to its authorization context and prevent
//! unauthorized access to session-scoped endpoints.
//!
//! # Token Structure
//!
//! A [`SessionToken`] contains:
//! - `session_id`: Unique session identifier
//! - `lease_id`: Lease authorizing this session
//! - `spawn_time_ns`: Spawn timestamp (nanoseconds since epoch)
//! - `expires_at_ns`: Token expiration (nanoseconds since epoch)
//! - `mac`: HMAC-SHA256 authenticator
//!
//! # Security Model
//!
//! Per DD-001 (`privilege_predicate.session_endpoints`):
//! - Tokens are minted by the daemon when an episode is spawned
//! - Token binds session to its authorization context
//! - Tokens have TTL matching lease expiration
//! - Token validation uses constant-time HMAC comparison
//!
//! # Validation Flow
//!
//! On each session-scoped request:
//! 1. Verify token HMAC (constant-time comparison)
//! 2. Verify `session_id` matches active session in registry
//! 3. Verify lease has not been revoked
//! 4. Verify token has not expired
//!
//! # Contract References
//!
//! - REQ-DCP-0008: IPC Authentication (per-connection capability tokens)
//! - CTR-WH001: Constant-time comparison for HMAC verification
//! - AD-SEC-001: Secrets wrapped in `SecretString`

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use secrecy::{ExposeSecret, SecretString};
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::Zeroizing;

// =============================================================================
// Constants
// =============================================================================

/// Length of the HMAC-SHA256 MAC in bytes.
pub const MAC_LENGTH: usize = 32;

/// Domain separation prefix for session token MACs.
///
/// This prefix is prepended to the token data before computing the HMAC,
/// preventing cross-context replay attacks where a MAC from another protocol
/// could be mistaken for a valid session token.
const DOMAIN_PREFIX: &[u8] = b"apm2.session_token.v1:";

/// Maximum length for `session_id` to prevent denial-of-service via oversized
/// tokens (CTR-1303).
pub const MAX_SESSION_ID_LENGTH: usize = 256;

/// Maximum length for `lease_id` to prevent denial-of-service via oversized
/// tokens (CTR-1303).
pub const MAX_LEASE_ID_LENGTH: usize = 256;

/// Expected length of the hex-encoded MAC string.
/// HMAC-SHA256 produces 32 bytes = 64 hex characters.
pub const EXPECTED_MAC_HEX_LENGTH: usize = MAC_LENGTH * 2;

// =============================================================================
// Bounded Deserialization Helpers
// =============================================================================

/// Deserializes a string with bounded length enforcement during
/// deserialization.
///
/// This prevents denial-of-service attacks where an attacker sends a very large
/// string field that causes memory allocation before validation can occur. The
/// check happens during deserialization itself, not after.
///
/// # Security (SEC-CTRL-FAC-001)
///
/// Length is checked DURING deserialization, before the full string is
/// allocated.
fn deserialize_bounded_session_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    struct BoundedSessionIdVisitor;

    impl Visitor<'_> for BoundedSessionIdVisitor {
        type Value = String;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(
                formatter,
                "a string with at most {MAX_SESSION_ID_LENGTH} bytes"
            )
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            let len = v.len();
            if len > MAX_SESSION_ID_LENGTH {
                return Err(E::custom(format!(
                    "session_id exceeds maximum length: {len} > {MAX_SESSION_ID_LENGTH}"
                )));
            }
            Ok(v.to_owned())
        }

        fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            let len = v.len();
            if len > MAX_SESSION_ID_LENGTH {
                return Err(E::custom(format!(
                    "session_id exceeds maximum length: {len} > {MAX_SESSION_ID_LENGTH}"
                )));
            }
            Ok(v)
        }
    }

    deserializer.deserialize_string(BoundedSessionIdVisitor)
}

/// Deserializes a `lease_id` string with bounded length enforcement.
fn deserialize_bounded_lease_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    struct BoundedLeaseIdVisitor;

    impl Visitor<'_> for BoundedLeaseIdVisitor {
        type Value = String;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(
                formatter,
                "a string with at most {MAX_LEASE_ID_LENGTH} bytes"
            )
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            let len = v.len();
            if len > MAX_LEASE_ID_LENGTH {
                return Err(E::custom(format!(
                    "lease_id exceeds maximum length: {len} > {MAX_LEASE_ID_LENGTH}"
                )));
            }
            Ok(v.to_owned())
        }

        fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            let len = v.len();
            if len > MAX_LEASE_ID_LENGTH {
                return Err(E::custom(format!(
                    "lease_id exceeds maximum length: {len} > {MAX_LEASE_ID_LENGTH}"
                )));
            }
            Ok(v)
        }
    }

    deserializer.deserialize_string(BoundedLeaseIdVisitor)
}

/// Deserializes a MAC hex string with bounded length enforcement.
///
/// The MAC must be exactly `EXPECTED_MAC_HEX_LENGTH` (64) characters.
fn deserialize_bounded_mac<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    struct BoundedMacVisitor;

    impl Visitor<'_> for BoundedMacVisitor {
        type Value = String;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(
                formatter,
                "a hex string of exactly {EXPECTED_MAC_HEX_LENGTH} characters"
            )
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            let len = v.len();
            if len != EXPECTED_MAC_HEX_LENGTH {
                return Err(E::custom(format!(
                    "mac hex length invalid: {len} chars, expected {EXPECTED_MAC_HEX_LENGTH} chars"
                )));
            }
            Ok(v.to_owned())
        }

        fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            let len = v.len();
            if len != EXPECTED_MAC_HEX_LENGTH {
                return Err(E::custom(format!(
                    "mac hex length invalid: {len} chars, expected {EXPECTED_MAC_HEX_LENGTH} chars"
                )));
            }
            Ok(v)
        }
    }

    deserializer.deserialize_string(BoundedMacVisitor)
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Converts a `SystemTime` to nanoseconds since Unix epoch.
///
/// # Errors
///
/// Returns an error if:
/// - The time is before the Unix epoch
/// - The nanosecond value exceeds `u64::MAX` (approximately year 2554)
fn system_time_to_nanos(time: SystemTime) -> Result<u64, SessionTokenError> {
    let duration = time
        .duration_since(UNIX_EPOCH)
        .map_err(|e| SessionTokenError::SystemTimeError(e.to_string()))?;

    let nanos = duration.as_nanos();
    u64::try_from(nanos).map_err(|_| {
        SessionTokenError::SystemTimeError(format!(
            "timestamp {nanos} nanoseconds exceeds u64::MAX"
        ))
    })
}

// =============================================================================
// Errors
// =============================================================================

/// Errors that can occur during session token operations.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum SessionTokenError {
    /// The token MAC is invalid (tampering detected).
    #[error("invalid token: MAC verification failed")]
    InvalidMac,

    /// The token has expired.
    #[error("token expired: expired at {expired_at_ns} ns, current time is {current_ns} ns")]
    Expired {
        /// Token expiration timestamp in nanoseconds.
        expired_at_ns: u64,
        /// Current time in nanoseconds.
        current_ns: u64,
    },

    /// The `session_id` exceeds maximum length.
    #[error("session_id too long: {len} bytes exceeds maximum {max} bytes")]
    SessionIdTooLong {
        /// Actual length.
        len: usize,
        /// Maximum allowed length.
        max: usize,
    },

    /// The `lease_id` exceeds maximum length.
    #[error("lease_id too long: {len} bytes exceeds maximum {max} bytes")]
    LeaseIdTooLong {
        /// Actual length.
        len: usize,
        /// Maximum allowed length.
        max: usize,
    },

    /// Failed to get system time.
    #[error("system time error: {0}")]
    SystemTimeError(String),

    /// Token deserialization failed.
    #[error("invalid token format: {0}")]
    InvalidFormat(String),
}

// =============================================================================
// SessionToken
// =============================================================================

/// A cryptographically authenticated session token.
///
/// Tokens bind a session to its authorization context and are validated on
/// every session-scoped request. The MAC ensures tokens cannot be forged or
/// modified without the daemon secret.
///
/// # Wire Format
///
/// Tokens are serialized as JSON for transport in the protocol. The MAC is
/// hex-encoded for safe embedding in JSON.
///
/// # Security Invariants
///
/// - [INV-TOKEN-001] MAC computed over domain-separated data prevents replay
/// - [INV-TOKEN-002] Expiration enforced before any authorization check
/// - [INV-TOKEN-003] MAC verification uses constant-time comparison
/// - [INV-TOKEN-004] Bounded deserialization prevents denial-of-service
///   (SEC-CTRL-FAC-001)
///
/// # Protocol Hygiene (SEC-PROTO-001)
///
/// - `#[serde(deny_unknown_fields)]` prevents field injection attacks
///   (CTR-1604)
/// - Bounded deserialization enforces length limits during parsing, not after
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SessionToken {
    /// Unique session identifier.
    ///
    /// Bounded by `MAX_SESSION_ID_LENGTH` during deserialization
    /// (SEC-CTRL-FAC-001).
    #[serde(deserialize_with = "deserialize_bounded_session_id")]
    pub session_id: String,

    /// Lease authorizing this session.
    ///
    /// Bounded by `MAX_LEASE_ID_LENGTH` during deserialization
    /// (SEC-CTRL-FAC-001).
    #[serde(deserialize_with = "deserialize_bounded_lease_id")]
    pub lease_id: String,

    /// Spawn timestamp in nanoseconds since Unix epoch.
    pub spawn_time_ns: u64,

    /// Token expiration in nanoseconds since Unix epoch.
    pub expires_at_ns: u64,

    /// HMAC-SHA256 over the token data (domain prefix, `session_id`,
    /// `lease_id`, `spawn_time_ns`, `expires_at_ns`).
    ///
    /// Hex-encoded for JSON serialization. Must be exactly 64 hex characters.
    /// Bounded during deserialization (SEC-CTRL-FAC-001).
    #[serde(deserialize_with = "deserialize_bounded_mac")]
    pub mac: String,
}

impl SessionToken {
    /// Returns the token expiration as a `SystemTime`.
    #[must_use]
    pub fn expires_at(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_nanos(self.expires_at_ns)
    }

    /// Returns the spawn time as a `SystemTime`.
    #[must_use]
    pub fn spawn_time(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_nanos(self.spawn_time_ns)
    }

    /// Checks if the token has expired based on the given current time.
    ///
    /// Returns `true` if expired or if the current time cannot be determined.
    #[must_use]
    pub fn is_expired(&self, now: SystemTime) -> bool {
        let now_ns = now
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|d| u64::try_from(d.as_nanos()).ok())
            .unwrap_or(u64::MAX); // Fail closed: treat unknown time as expired
        self.expires_at_ns <= now_ns
    }
}

// =============================================================================
// TokenMinter
// =============================================================================

/// Mints and validates session tokens using HMAC-SHA256.
///
/// The minter holds the daemon secret and provides methods for creating
/// new tokens and validating existing ones.
///
/// # Security
///
/// - The secret is wrapped in `SecretString` to prevent accidental logging
/// - Token validation uses constant-time MAC comparison
/// - Domain separation prevents cross-protocol replay attacks
#[derive(Clone)]
pub struct TokenMinter {
    /// The daemon secret used for HMAC computation.
    secret: SecretString,
}

impl TokenMinter {
    /// Creates a new token minter with the given secret.
    ///
    /// # Arguments
    ///
    /// * `secret` - The daemon secret for HMAC computation. Should be at least
    ///   32 bytes of cryptographically random data.
    ///
    /// # Security Note
    ///
    /// The secret should be generated securely and stored in the OS keychain
    /// or similar secure storage. See `evidence/keychain.rs` for the
    /// recommended storage pattern.
    #[must_use]
    pub const fn new(secret: SecretString) -> Self {
        Self { secret }
    }

    /// Generates a new daemon secret.
    ///
    /// Uses `rand::OsRng` for cryptographically secure randomness.
    /// The generated secret is 32 bytes (256 bits).
    #[must_use]
    pub fn generate_secret() -> SecretString {
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let hex_secret = hex::encode(bytes);
        // Zeroize the raw bytes
        bytes.fill(0);
        SecretString::from(hex_secret)
    }

    /// Mints a new session token.
    ///
    /// # Arguments
    ///
    /// * `session_id` - Unique session identifier
    /// * `lease_id` - Lease authorizing this session
    /// * `spawn_time` - When the session was spawned
    /// * `ttl` - Token time-to-live (should match lease expiration)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `session_id` exceeds [`MAX_SESSION_ID_LENGTH`]
    /// - `lease_id` exceeds [`MAX_LEASE_ID_LENGTH`]
    /// - System time cannot be determined
    pub fn mint(
        &self,
        session_id: impl Into<String>,
        lease_id: impl Into<String>,
        spawn_time: SystemTime,
        ttl: Duration,
    ) -> Result<SessionToken, SessionTokenError> {
        let session_id = session_id.into();
        let lease_id = lease_id.into();

        // Validate lengths (CTR-1303)
        if session_id.len() > MAX_SESSION_ID_LENGTH {
            return Err(SessionTokenError::SessionIdTooLong {
                len: session_id.len(),
                max: MAX_SESSION_ID_LENGTH,
            });
        }
        if lease_id.len() > MAX_LEASE_ID_LENGTH {
            return Err(SessionTokenError::LeaseIdTooLong {
                len: lease_id.len(),
                max: MAX_LEASE_ID_LENGTH,
            });
        }

        // Convert times to nanoseconds
        let spawn_time_ns = system_time_to_nanos(spawn_time)?;
        let expires_at = spawn_time + ttl;
        let expires_at_ns = system_time_to_nanos(expires_at)?;

        // Compute MAC
        let mac_bytes = self.compute_mac(&session_id, &lease_id, spawn_time_ns, expires_at_ns);
        let mac = hex::encode(&*mac_bytes);

        Ok(SessionToken {
            session_id,
            lease_id,
            spawn_time_ns,
            expires_at_ns,
            mac,
        })
    }

    /// Validates a session token.
    ///
    /// # Arguments
    ///
    /// * `token` - The token to validate
    /// * `now` - Current time for expiration check
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `session_id` or `lease_id` exceeds maximum length (CTR-1303)
    /// - MAC hex string has wrong length (CTR-1303: check before allocation)
    /// - The token has expired
    /// - The MAC is invalid (tampering detected)
    ///
    /// # Security
    ///
    /// - Input bounds validated BEFORE any allocation (SEC-CTRL-FAC-001)
    /// - Length invariants enforced in validation path, not just minting
    /// - MAC verification uses constant-time comparison (CTR-WH001)
    /// - Expiration is checked before returning success
    pub fn validate(&self, token: &SessionToken, now: SystemTime) -> Result<(), SessionTokenError> {
        // =================================================================
        // PHASE 1: Input bounds validation (before any allocation)
        // SEC-CTRL-FAC-001: Reject oversized inputs before resource use
        // =================================================================

        // Validate session_id length (CTR-1303)
        if token.session_id.len() > MAX_SESSION_ID_LENGTH {
            return Err(SessionTokenError::SessionIdTooLong {
                len: token.session_id.len(),
                max: MAX_SESSION_ID_LENGTH,
            });
        }

        // Validate lease_id length (CTR-1303)
        if token.lease_id.len() > MAX_LEASE_ID_LENGTH {
            return Err(SessionTokenError::LeaseIdTooLong {
                len: token.lease_id.len(),
                max: MAX_LEASE_ID_LENGTH,
            });
        }

        // Validate MAC hex length BEFORE calling hex::decode (SEC-CTRL-FAC-001)
        if token.mac.len() != EXPECTED_MAC_HEX_LENGTH {
            return Err(SessionTokenError::InvalidFormat(format!(
                "invalid MAC hex length: {} chars, expected {} chars",
                token.mac.len(),
                EXPECTED_MAC_HEX_LENGTH
            )));
        }

        // =================================================================
        // PHASE 2: Expiration check (fail fast on expired tokens)
        // =================================================================

        let now_ns = system_time_to_nanos(now)?;

        if token.expires_at_ns <= now_ns {
            return Err(SessionTokenError::Expired {
                expired_at_ns: token.expires_at_ns,
                current_ns: now_ns,
            });
        }

        // =================================================================
        // PHASE 3: MAC verification (constant-time comparison)
        // =================================================================

        // Now safe to decode: length already validated, allocation is bounded
        let provided_mac = hex::decode(&token.mac)
            .map_err(|e| SessionTokenError::InvalidFormat(format!("invalid MAC hex: {e}")))?;

        // Compute expected MAC
        let expected_mac = self.compute_mac(
            &token.session_id,
            &token.lease_id,
            token.spawn_time_ns,
            token.expires_at_ns,
        );

        // Constant-time comparison (CTR-WH001)
        if expected_mac.ct_eq(&provided_mac).into() {
            Ok(())
        } else {
            Err(SessionTokenError::InvalidMac)
        }
    }

    /// Computes the HMAC-SHA256 over the token data.
    ///
    /// The MAC is computed over:
    /// ```text
    /// domain_prefix || session_id_len (8 bytes BE) || session_id ||
    /// lease_id_len (8 bytes BE) || lease_id ||
    /// spawn_time_ns (8 bytes BE) || expires_at_ns (8 bytes BE)
    /// ```
    ///
    /// Length prefixes prevent extension attacks and ensure deterministic
    /// parsing.
    fn compute_mac(
        &self,
        session_id: &str,
        lease_id: &str,
        spawn_time_ns: u64,
        expires_at_ns: u64,
    ) -> Zeroizing<Vec<u8>> {
        type HmacSha256 = Hmac<Sha256>;

        let mut mac = HmacSha256::new_from_slice(self.secret.expose_secret().as_bytes())
            .expect("HMAC can take key of any size");

        // Domain separation
        mac.update(DOMAIN_PREFIX);

        // Session ID with length prefix
        mac.update(&(session_id.len() as u64).to_be_bytes());
        mac.update(session_id.as_bytes());

        // Lease ID with length prefix
        mac.update(&(lease_id.len() as u64).to_be_bytes());
        mac.update(lease_id.as_bytes());

        // Timestamps
        mac.update(&spawn_time_ns.to_be_bytes());
        mac.update(&expires_at_ns.to_be_bytes());

        Zeroizing::new(mac.finalize().into_bytes().to_vec())
    }
}

impl std::fmt::Debug for TokenMinter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenMinter")
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_minter() -> TokenMinter {
        TokenMinter::new(SecretString::from("test-daemon-secret-key-32bytes!!"))
    }

    fn test_spawn_time() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    }

    fn test_ttl() -> Duration {
        Duration::from_secs(3600) // 1 hour
    }

    #[test]
    fn test_mint_token() {
        let minter = test_minter();
        let token = minter
            .mint("session-001", "lease-001", test_spawn_time(), test_ttl())
            .unwrap();

        assert_eq!(token.session_id, "session-001");
        assert_eq!(token.lease_id, "lease-001");
        assert!(!token.mac.is_empty());
        assert_eq!(hex::decode(&token.mac).unwrap().len(), MAC_LENGTH);
    }

    #[test]
    fn test_tokens_are_unique() {
        let minter = test_minter();

        let token1 = minter
            .mint("session-001", "lease-001", test_spawn_time(), test_ttl())
            .unwrap();

        let token2 = minter
            .mint("session-002", "lease-001", test_spawn_time(), test_ttl())
            .unwrap();

        assert_ne!(token1.mac, token2.mac);
        assert_ne!(token1.session_id, token2.session_id);
    }

    #[test]
    fn test_validate_valid_token() {
        let minter = test_minter();
        let token = minter
            .mint("session-001", "lease-001", test_spawn_time(), test_ttl())
            .unwrap();

        // Validate at spawn time (not expired)
        let now = test_spawn_time() + Duration::from_secs(1800); // 30 minutes later
        let result = minter.validate(&token, now);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_expired_token() {
        let minter = test_minter();
        let token = minter
            .mint("session-001", "lease-001", test_spawn_time(), test_ttl())
            .unwrap();

        // Validate after expiration
        let now = test_spawn_time() + Duration::from_secs(7200); // 2 hours later
        let result = minter.validate(&token, now);

        assert!(matches!(result, Err(SessionTokenError::Expired { .. })));
    }

    #[test]
    fn test_validate_tampered_mac() {
        let minter = test_minter();
        let mut token = minter
            .mint("session-001", "lease-001", test_spawn_time(), test_ttl())
            .unwrap();

        // Tamper with the MAC
        token.mac = "00".repeat(MAC_LENGTH);

        let now = test_spawn_time() + Duration::from_secs(1800);
        let result = minter.validate(&token, now);

        assert!(matches!(result, Err(SessionTokenError::InvalidMac)));
    }

    #[test]
    fn test_validate_tampered_session_id() {
        let minter = test_minter();
        let mut token = minter
            .mint("session-001", "lease-001", test_spawn_time(), test_ttl())
            .unwrap();

        // Tamper with the session_id
        token.session_id = "session-EVIL".to_string();

        let now = test_spawn_time() + Duration::from_secs(1800);
        let result = minter.validate(&token, now);

        assert!(matches!(result, Err(SessionTokenError::InvalidMac)));
    }

    #[test]
    fn test_validate_tampered_lease_id() {
        let minter = test_minter();
        let mut token = minter
            .mint("session-001", "lease-001", test_spawn_time(), test_ttl())
            .unwrap();

        // Tamper with the lease_id
        token.lease_id = "lease-EVIL".to_string();

        let now = test_spawn_time() + Duration::from_secs(1800);
        let result = minter.validate(&token, now);

        assert!(matches!(result, Err(SessionTokenError::InvalidMac)));
    }

    #[test]
    fn test_validate_tampered_expiration() {
        let minter = test_minter();
        let mut token = minter
            .mint("session-001", "lease-001", test_spawn_time(), test_ttl())
            .unwrap();

        // Try to extend expiration
        token.expires_at_ns += 86_400_000_000_000; // +1 day

        let now = test_spawn_time() + Duration::from_secs(1800);
        let result = minter.validate(&token, now);

        assert!(matches!(result, Err(SessionTokenError::InvalidMac)));
    }

    #[test]
    fn test_different_secrets_produce_different_macs() {
        let minter1 = TokenMinter::new(SecretString::from("secret-1-32-bytes-long-paddings"));
        let minter2 = TokenMinter::new(SecretString::from("secret-2-32-bytes-long-paddings"));

        let token1 = minter1
            .mint("session-001", "lease-001", test_spawn_time(), test_ttl())
            .unwrap();

        let token2 = minter2
            .mint("session-001", "lease-001", test_spawn_time(), test_ttl())
            .unwrap();

        // Same inputs, different secrets -> different MACs
        assert_ne!(token1.mac, token2.mac);
    }

    #[test]
    fn test_cross_minter_validation_fails() {
        let minter1 = TokenMinter::new(SecretString::from("secret-1-32-bytes-long-paddings"));
        let minter2 = TokenMinter::new(SecretString::from("secret-2-32-bytes-long-paddings"));

        let token = minter1
            .mint("session-001", "lease-001", test_spawn_time(), test_ttl())
            .unwrap();

        // Token from minter1 should not validate with minter2
        let now = test_spawn_time() + Duration::from_secs(1800);
        let result = minter2.validate(&token, now);

        assert!(matches!(result, Err(SessionTokenError::InvalidMac)));
    }

    #[test]
    fn test_session_id_too_long() {
        let minter = test_minter();
        let long_id = "x".repeat(MAX_SESSION_ID_LENGTH + 1);

        let result = minter.mint(&long_id, "lease-001", test_spawn_time(), test_ttl());

        assert!(matches!(
            result,
            Err(SessionTokenError::SessionIdTooLong { .. })
        ));
    }

    #[test]
    fn test_lease_id_too_long() {
        let minter = test_minter();
        let long_id = "x".repeat(MAX_LEASE_ID_LENGTH + 1);

        let result = minter.mint("session-001", &long_id, test_spawn_time(), test_ttl());

        assert!(matches!(
            result,
            Err(SessionTokenError::LeaseIdTooLong { .. })
        ));
    }

    #[test]
    fn test_token_serialization_roundtrip() {
        let minter = test_minter();
        let token = minter
            .mint("session-001", "lease-001", test_spawn_time(), test_ttl())
            .unwrap();

        // Serialize to JSON
        let json = serde_json::to_string(&token).unwrap();

        // Deserialize back
        let parsed: SessionToken = serde_json::from_str(&json).unwrap();

        assert_eq!(token, parsed);

        // Validate the deserialized token
        let now = test_spawn_time() + Duration::from_secs(1800);
        assert!(minter.validate(&parsed, now).is_ok());
    }

    #[test]
    fn test_generate_secret() {
        let secret1 = TokenMinter::generate_secret();
        let secret2 = TokenMinter::generate_secret();

        // Each call should generate a unique secret
        assert_ne!(secret1.expose_secret(), secret2.expose_secret());

        // Secret should be 64 hex chars (32 bytes)
        assert_eq!(secret1.expose_secret().len(), 64);
    }

    #[test]
    fn test_invalid_mac_hex() {
        let minter = test_minter();
        let mut token = minter
            .mint("session-001", "lease-001", test_spawn_time(), test_ttl())
            .unwrap();

        token.mac = "not-valid-hex!".to_string();

        let now = test_spawn_time() + Duration::from_secs(1800);
        let result = minter.validate(&token, now);

        assert!(matches!(result, Err(SessionTokenError::InvalidFormat(_))));
    }

    #[test]
    fn test_invalid_mac_length() {
        let minter = test_minter();
        let mut token = minter
            .mint("session-001", "lease-001", test_spawn_time(), test_ttl())
            .unwrap();

        // Valid hex but wrong length
        token.mac = "abcd".to_string();

        let now = test_spawn_time() + Duration::from_secs(1800);
        let result = minter.validate(&token, now);

        assert!(matches!(result, Err(SessionTokenError::InvalidFormat(_))));
    }

    #[test]
    fn test_expire_at_boundary() {
        let minter = test_minter();
        let token = minter
            .mint("session-001", "lease-001", test_spawn_time(), test_ttl())
            .unwrap();

        // Validate exactly at expiration time (should fail - expired)
        let now = token.expires_at();
        let result = minter.validate(&token, now);
        assert!(matches!(result, Err(SessionTokenError::Expired { .. })));

        // Validate 1 nanosecond before expiration (should succeed)
        let now_before = token.expires_at() - Duration::from_nanos(1);
        let result = minter.validate(&token, now_before);
        assert!(result.is_ok());
    }

    #[test]
    fn test_token_debug_does_not_leak_secret() {
        let minter = test_minter();
        let debug_str = format!("{minter:?}");

        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains("test-daemon-secret"));
    }

    #[test]
    fn test_is_expired() {
        let minter = test_minter();
        let token = minter
            .mint("session-001", "lease-001", test_spawn_time(), test_ttl())
            .unwrap();

        // Before expiration
        let before = test_spawn_time() + Duration::from_secs(1800);
        assert!(!token.is_expired(before));

        // After expiration
        let after = test_spawn_time() + Duration::from_secs(7200);
        assert!(token.is_expired(after));
    }

    // =========================================================================
    // SEC-FIND-001 / SEC-FIND-002 Regression Tests (DoS Protection)
    // These tests verify that validation rejects oversized inputs BEFORE
    // performing any allocation or computation.
    // =========================================================================

    /// SEC-FIND-001: Verify MAC hex length validated BEFORE `hex::decode`
    /// allocation.
    ///
    /// Attack vector: Attacker supplies token with large `mac` string (e.g.,
    /// 1MB). Expected: Rejected immediately based on string length, no
    /// allocation occurs.
    #[test]
    fn test_validate_rejects_oversized_mac_before_allocation() {
        let minter = test_minter();
        let mut token = minter
            .mint("session-001", "lease-001", test_spawn_time(), test_ttl())
            .unwrap();

        // Simulate attacker supplying a very large MAC string (65536 chars)
        // This should be rejected BEFORE hex::decode is called
        token.mac = "a".repeat(65536);

        let now = test_spawn_time() + Duration::from_secs(1800);
        let result = minter.validate(&token, now);

        // Should fail with InvalidFormat, not InvalidMac (which would mean we
        // allocated and computed the MAC before checking length)
        assert!(
            matches!(result, Err(SessionTokenError::InvalidFormat(msg)) if msg.contains("hex length"))
        );
    }

    /// SEC-FIND-001: Verify short MAC hex rejected before allocation.
    #[test]
    fn test_validate_rejects_short_mac_hex_before_decode() {
        let minter = test_minter();
        let mut token = minter
            .mint("session-001", "lease-001", test_spawn_time(), test_ttl())
            .unwrap();

        // MAC that's too short (should be 64 hex chars, we provide 16)
        token.mac = "a".repeat(16);

        let now = test_spawn_time() + Duration::from_secs(1800);
        let result = minter.validate(&token, now);

        assert!(
            matches!(result, Err(SessionTokenError::InvalidFormat(msg)) if msg.contains("hex length"))
        );
    }

    /// SEC-FIND-002: Verify oversized `session_id` rejected in validation path.
    ///
    /// Attack vector: Attacker crafts token with valid MAC but oversized
    /// `session_id`. Expected: Rejected based on `session_id` length before
    /// HMAC computation.
    #[test]
    fn test_validate_rejects_oversized_session_id() {
        let minter = test_minter();
        let mut token = minter
            .mint("session-001", "lease-001", test_spawn_time(), test_ttl())
            .unwrap();

        // Replace session_id with oversized value (bypassing mint validation)
        token.session_id = "x".repeat(MAX_SESSION_ID_LENGTH + 1);

        let now = test_spawn_time() + Duration::from_secs(1800);
        let result = minter.validate(&token, now);

        assert!(matches!(
            result,
            Err(SessionTokenError::SessionIdTooLong { .. })
        ));
    }

    /// SEC-FIND-002: Verify oversized `lease_id` rejected in validation path.
    #[test]
    fn test_validate_rejects_oversized_lease_id() {
        let minter = test_minter();
        let mut token = minter
            .mint("session-001", "lease-001", test_spawn_time(), test_ttl())
            .unwrap();

        // Replace lease_id with oversized value (bypassing mint validation)
        token.lease_id = "x".repeat(MAX_LEASE_ID_LENGTH + 1);

        let now = test_spawn_time() + Duration::from_secs(1800);
        let result = minter.validate(&token, now);

        assert!(matches!(
            result,
            Err(SessionTokenError::LeaseIdTooLong { .. })
        ));
    }

    /// SEC-FIND-001/002: Verify validation order - bounds checked before
    /// expiration.
    ///
    /// This ensures denial-of-service protection takes priority: we don't even
    /// check expiration if bounds are violated, preventing any unnecessary
    /// computation.
    #[test]
    fn test_validate_checks_bounds_before_expiration() {
        let minter = test_minter();
        let mut token = minter
            .mint("session-001", "lease-001", test_spawn_time(), test_ttl())
            .unwrap();

        // Make token expired AND have oversized session_id
        token.session_id = "x".repeat(MAX_SESSION_ID_LENGTH + 1);

        // Use a time after expiration
        let now = test_spawn_time() + Duration::from_secs(7200);
        let result = minter.validate(&token, now);

        // Should fail with SessionIdTooLong, NOT Expired
        // This proves bounds are checked before expiration
        assert!(matches!(
            result,
            Err(SessionTokenError::SessionIdTooLong { .. })
        ));
    }

    /// SEC-FIND-001: Verify MAC length check before expiration check.
    #[test]
    fn test_validate_checks_mac_length_before_expiration() {
        let minter = test_minter();
        let mut token = minter
            .mint("session-001", "lease-001", test_spawn_time(), test_ttl())
            .unwrap();

        // Make token expired AND have invalid MAC length
        token.mac = "abcd".to_string();

        // Use a time after expiration
        let now = test_spawn_time() + Duration::from_secs(7200);
        let result = minter.validate(&token, now);

        // Should fail with InvalidFormat, NOT Expired
        assert!(matches!(result, Err(SessionTokenError::InvalidFormat(_))));
    }

    /// Boundary test: `session_id` at exactly `MAX_SESSION_ID_LENGTH` should
    /// pass.
    #[test]
    fn test_validate_accepts_max_length_session_id() {
        let minter = test_minter();
        let max_len_id = "x".repeat(MAX_SESSION_ID_LENGTH);

        let token = minter
            .mint(&max_len_id, "lease-001", test_spawn_time(), test_ttl())
            .unwrap();

        let now = test_spawn_time() + Duration::from_secs(1800);
        let result = minter.validate(&token, now);

        assert!(result.is_ok());
    }

    /// Boundary test: `lease_id` at exactly `MAX_LEASE_ID_LENGTH` should pass.
    #[test]
    fn test_validate_accepts_max_length_lease_id() {
        let minter = test_minter();
        let max_len_id = "x".repeat(MAX_LEASE_ID_LENGTH);

        let token = minter
            .mint("session-001", &max_len_id, test_spawn_time(), test_ttl())
            .unwrap();

        let now = test_spawn_time() + Duration::from_secs(1800);
        let result = minter.validate(&token, now);

        assert!(result.is_ok());
    }

    // =========================================================================
    // Bounded Deserialization Tests (SEC-CTRL-FAC-001)
    // These tests verify that deserialization rejects oversized inputs BEFORE
    // allocating memory for the full string. This is the critical fix for
    // the unbounded deserialization DoS vulnerability.
    // =========================================================================

    /// SEC-CTRL-FAC-001: Verify deserialization rejects oversized `session_id`
    /// during parsing.
    ///
    /// Attack vector: Attacker sends JSON with massive `session_id` (16MB).
    /// Expected: Rejected by serde during deserialization, before full
    /// allocation.
    #[test]
    fn test_deserialize_rejects_oversized_session_id() {
        let oversized_session_id = "x".repeat(MAX_SESSION_ID_LENGTH + 1);
        let json = format!(
            r#"{{"session_id":"{}","lease_id":"lease-001","spawn_time_ns":1700000000000000000,"expires_at_ns":1700003600000000000,"mac":"{}"}}"#,
            oversized_session_id,
            "a".repeat(EXPECTED_MAC_HEX_LENGTH)
        );

        let result: Result<SessionToken, _> = serde_json::from_str(&json);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("session_id exceeds maximum length"),
            "Expected session_id length error, got: {err_msg}"
        );
    }

    /// SEC-CTRL-FAC-001: Verify deserialization rejects oversized `lease_id`
    /// during parsing.
    #[test]
    fn test_deserialize_rejects_oversized_lease_id() {
        let oversized_lease_id = "x".repeat(MAX_LEASE_ID_LENGTH + 1);
        let json = format!(
            r#"{{"session_id":"session-001","lease_id":"{}","spawn_time_ns":1700000000000000000,"expires_at_ns":1700003600000000000,"mac":"{}"}}"#,
            oversized_lease_id,
            "a".repeat(EXPECTED_MAC_HEX_LENGTH)
        );

        let result: Result<SessionToken, _> = serde_json::from_str(&json);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("lease_id exceeds maximum length"),
            "Expected lease_id length error, got: {err_msg}"
        );
    }

    /// SEC-CTRL-FAC-001: Verify deserialization rejects oversized `mac` during
    /// parsing.
    #[test]
    fn test_deserialize_rejects_oversized_mac() {
        let oversized_mac = "a".repeat(65536);
        let json = format!(
            r#"{{"session_id":"session-001","lease_id":"lease-001","spawn_time_ns":1700000000000000000,"expires_at_ns":1700003600000000000,"mac":"{oversized_mac}"}}"#
        );

        let result: Result<SessionToken, _> = serde_json::from_str(&json);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("mac hex length invalid"),
            "Expected mac length error, got: {err_msg}"
        );
    }

    /// SEC-CTRL-FAC-001: Verify deserialization rejects short `mac` during
    /// parsing.
    #[test]
    fn test_deserialize_rejects_short_mac() {
        let short_mac = "a".repeat(16);
        let json = format!(
            r#"{{"session_id":"session-001","lease_id":"lease-001","spawn_time_ns":1700000000000000000,"expires_at_ns":1700003600000000000,"mac":"{short_mac}"}}"#
        );

        let result: Result<SessionToken, _> = serde_json::from_str(&json);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("mac hex length invalid"),
            "Expected mac length error, got: {err_msg}"
        );
    }

    /// SEC-PROTO-001: Verify deserialization rejects unknown fields.
    ///
    /// Attack vector: Attacker sends token with extra fields to probe for
    /// injection vulnerabilities.
    #[test]
    fn test_deserialize_rejects_unknown_fields() {
        let json = format!(
            r#"{{"session_id":"session-001","lease_id":"lease-001","spawn_time_ns":1700000000000000000,"expires_at_ns":1700003600000000000,"mac":"{}","extra_field":"malicious"}}"#,
            "a".repeat(EXPECTED_MAC_HEX_LENGTH)
        );

        let result: Result<SessionToken, _> = serde_json::from_str(&json);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("unknown field"),
            "Expected unknown field error, got: {err_msg}"
        );
    }

    /// Boundary test: deserialization accepts `session_id` at exactly
    /// `MAX_SESSION_ID_LENGTH`.
    #[test]
    fn test_deserialize_accepts_max_length_session_id() {
        let max_session_id = "x".repeat(MAX_SESSION_ID_LENGTH);
        let json = format!(
            r#"{{"session_id":"{}","lease_id":"lease-001","spawn_time_ns":1700000000000000000,"expires_at_ns":1700003600000000000,"mac":"{}"}}"#,
            max_session_id,
            "a".repeat(EXPECTED_MAC_HEX_LENGTH)
        );

        let result: Result<SessionToken, _> = serde_json::from_str(&json);
        assert!(result.is_ok());
        let token = result.unwrap();
        assert_eq!(token.session_id.len(), MAX_SESSION_ID_LENGTH);
    }

    /// Boundary test: deserialization accepts `lease_id` at exactly
    /// `MAX_LEASE_ID_LENGTH`.
    #[test]
    fn test_deserialize_accepts_max_length_lease_id() {
        let max_lease_id = "x".repeat(MAX_LEASE_ID_LENGTH);
        let json = format!(
            r#"{{"session_id":"session-001","lease_id":"{}","spawn_time_ns":1700000000000000000,"expires_at_ns":1700003600000000000,"mac":"{}"}}"#,
            max_lease_id,
            "a".repeat(EXPECTED_MAC_HEX_LENGTH)
        );

        let result: Result<SessionToken, _> = serde_json::from_str(&json);
        assert!(result.is_ok());
        let token = result.unwrap();
        assert_eq!(token.lease_id.len(), MAX_LEASE_ID_LENGTH);
    }

    /// Verify valid token still serializes and deserializes correctly after
    /// adding bounded deserialization.
    #[test]
    fn test_bounded_deserialization_roundtrip() {
        let minter = test_minter();
        let token = minter
            .mint("session-001", "lease-001", test_spawn_time(), test_ttl())
            .unwrap();

        // Serialize to JSON
        let json = serde_json::to_string(&token).unwrap();

        // Deserialize back (now with bounded deserialization)
        let parsed: SessionToken = serde_json::from_str(&json).unwrap();

        assert_eq!(token, parsed);

        // Validate the deserialized token still works
        let now = test_spawn_time() + Duration::from_secs(1800);
        assert!(minter.validate(&parsed, now).is_ok());
    }
}
