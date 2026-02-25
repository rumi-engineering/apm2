//! Connection handler for dual-socket `ProtocolServer` control plane.
//!
//! This module implements the connection handling logic for the daemon's
//! `ProtocolServer`-only control plane (RFC-0032::REQ-0085/RFC-0032::REQ-0086).
//! It performs the mandatory Hello/HelloAck handshake as specified in
//! DD-001/DD-008 before processing any protobuf messages.
//!
//! # Protocol Compliance
//!
//! Per the protocol specification in [`handshake`] and DD-001:
//!
//! 1. Client sends `Hello` message with protocol version
//! 2. Server validates and responds with `HelloAck` or `HelloNack`
//! 3. If accepted, connection enters message exchange phase
//! 4. Either party may close the connection
//!
//! Skipping the handshake violates the protocol specification and will cause
//! protocol-compliant clients to hang or fail when connecting.
//!
//! # Security Considerations
//!
//! - Handshake is performed AFTER UID validation (which happens at accept time)
//! - Frame size is limited during handshake to prevent DoS
//! - Invalid handshake terminates the connection
//! - Privilege checks are performed based on socket type before dispatching
//!
//! # RFC-0032::REQ-0086: Legacy JSON IPC Removal
//!
//! Per DD-009, legacy JSON IPC (apm2_core::ipc) has been removed. The daemon
//! now only accepts protobuf-encoded messages via PrivilegedDispatcher and
//! SessionDispatcher. This module provides only the handshake functionality;
//! message dispatch is handled by the protobuf dispatchers.

use anyhow::{Context, Result};
use futures::{SinkExt, StreamExt};
use tracing::{info, warn};

use super::handshake::{
    HandshakeMessage, ServerHandshake, parse_hello, serialize_handshake_message,
};
use super::server::Connection;
use crate::hsi_contract::handshake_binding::{CanonicalizerInfo, SessionContractBinding};
use crate::hsi_contract::{MismatchOutcome, RiskTier};
use crate::metrics::DaemonMetrics;

// ============================================================================
// RFC-0020::REQ-0003: Session-Typed Connection Phase State Machine
// ============================================================================

/// Connection phase for the session-typed state machine (RFC-0020::REQ-0003).
///
/// Per REQ-0003, authority-bearing operations MUST require valid session-state
/// progression. This enum enforces a strict, forward-only progression:
///
/// ```text
///   Connected ──> HandshakeComplete ──> SessionOpen
/// ```
///
/// No privileged (authority-bearing) IPC message can be dispatched before the
/// connection reaches the `SessionOpen` phase. Each transition is validated
/// explicitly — there are no implicit promotions.
///
/// # Security Invariants
///
/// - Transitions are forward-only: `Connected -> HandshakeComplete ->
///   SessionOpen`
/// - No skipping: transitioning from `Connected` to `SessionOpen` directly is
///   rejected
/// - Each transition returns `Result` so callers detect illegal jumps
/// - The `advance_to_session_open` method requires proof of a completed
///   handshake (via `HandshakeResult::Success`)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionPhase {
    /// TCP/UDS socket accepted but no handshake performed yet.
    ///
    /// In this phase, the only valid operation is the Hello/HelloAck
    /// handshake. All IPC dispatch is rejected.
    Connected,

    /// Handshake completed successfully, contract binding established.
    ///
    /// The server has validated the protocol version and contract binding.
    /// The connection is ready for session-open promotion (for session
    /// sockets) or immediate authority-bearing dispatch (for operator
    /// sockets, which are privileged by socket type).
    HandshakeComplete,

    /// Session is open and authority-bearing operations are allowed.
    ///
    /// For operator sockets: all privileged IPC messages are accepted.
    /// For session sockets: session-scoped IPC messages are accepted
    /// (with token validation per request).
    SessionOpen,
}

impl ConnectionPhase {
    /// Attempts to advance from `Connected` to `HandshakeComplete`.
    ///
    /// # Errors
    ///
    /// Returns `ConnectionPhaseError::IllegalTransition` if the current
    /// phase is not `Connected`.
    pub fn advance_to_handshake_complete(self) -> Result<Self, ConnectionPhaseError> {
        if self != Self::Connected {
            return Err(ConnectionPhaseError::IllegalTransition {
                from: self,
                to: Self::HandshakeComplete,
            });
        }
        Ok(Self::HandshakeComplete)
    }

    /// Attempts to advance from `HandshakeComplete` to `SessionOpen`.
    ///
    /// # Errors
    ///
    /// Returns `ConnectionPhaseError::IllegalTransition` if the current
    /// phase is not `HandshakeComplete`.
    pub fn advance_to_session_open(self) -> Result<Self, ConnectionPhaseError> {
        if self != Self::HandshakeComplete {
            return Err(ConnectionPhaseError::IllegalTransition {
                from: self,
                to: Self::SessionOpen,
            });
        }
        Ok(Self::SessionOpen)
    }

    /// Returns `true` if this phase permits authority-bearing dispatch.
    ///
    /// Only `SessionOpen` allows IPC message dispatch. `Connected` and
    /// `HandshakeComplete` reject all non-handshake frames.
    #[must_use]
    pub const fn allows_dispatch(&self) -> bool {
        matches!(self, Self::SessionOpen)
    }
}

impl std::fmt::Display for ConnectionPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connected => write!(f, "Connected"),
            Self::HandshakeComplete => write!(f, "HandshakeComplete"),
            Self::SessionOpen => write!(f, "SessionOpen"),
        }
    }
}

/// Error type for illegal connection phase transitions (RFC-0020::REQ-0003).
///
/// This is a structured defect — callers can log the exact illegal
/// transition without truncation or coercion to a default.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConnectionPhaseError {
    /// Attempted an illegal state transition.
    #[error("illegal connection phase transition from {from} to {to}")]
    IllegalTransition {
        /// Phase the connection was in.
        from: ConnectionPhase,
        /// Phase the caller attempted to reach.
        to: ConnectionPhase,
    },

    /// Dispatch attempted before session was open.
    #[error("dispatch rejected: connection is in {phase} phase, not SessionOpen")]
    DispatchBeforeSessionOpen {
        /// Current phase.
        phase: ConnectionPhase,
    },
}

/// Server information string for handshake.
///
/// This identifies the daemon to connecting clients during the Hello/HelloAck
/// handshake.
fn server_info() -> String {
    format!("apm2-daemon/{}", env!("CARGO_PKG_VERSION"))
}

/// Default canonicalizer declared by the daemon (RFC-0020::REQ-0002).
///
/// This is the canonical encoding version the daemon uses for deterministic
/// serialization. Clients must declare compatible canonicalizers.
pub const DAEMON_CANONICALIZER_ID: &str = "apm2.canonical.v1";

/// Default canonicalizer version.
pub const DAEMON_CANONICALIZER_VERSION: u32 = 1;

/// Configuration for contract binding in the handshake (RFC-0020::REQ-0002).
///
/// Provides the server's contract hash, canonicalizers, risk tier, and
/// optional metrics handle so `perform_handshake` can wire production
/// values into `ServerHandshake`.
#[derive(Clone)]
pub struct HandshakeConfig {
    /// The daemon's active HSI contract manifest content hash.
    ///
    /// Computed via `build_manifest().content_hash()` at daemon startup.
    pub server_contract_hash: String,

    /// The daemon's supported canonicalizers.
    pub server_canonicalizers: Vec<CanonicalizerInfo>,

    /// Risk tier for mismatch policy evaluation.
    pub risk_tier: RiskTier,

    /// Optional metrics handle for emitting `contract_mismatch_total`.
    pub metrics: Option<DaemonMetrics>,

    /// Daemon Ed25519 verifying key (hex-encoded) for signed authority tokens.
    pub daemon_signing_public_key: String,
}

impl Default for HandshakeConfig {
    /// Returns a default config with Tier2 risk (fail-closed), the daemon's
    /// standard canonicalizer, and no metrics.
    ///
    /// # Fail-Closed Default
    ///
    /// Per RFC-0020 section 4, the default risk tier is Tier2 so that
    /// contract mismatches are **denied** in production unless an operator
    /// explicitly relaxes the tier. This ensures unknown or unconfigured
    /// deployments default to the safe (deny) behaviour.
    ///
    /// The server contract hash is computed lazily from `build_manifest()`
    /// on first use via [`HandshakeConfig::from_manifest`].
    fn default() -> Self {
        Self {
            server_contract_hash: String::new(),
            server_canonicalizers: vec![CanonicalizerInfo {
                id: DAEMON_CANONICALIZER_ID.to_string(),
                version: DAEMON_CANONICALIZER_VERSION,
            }],
            risk_tier: RiskTier::Tier2,
            metrics: None,
            daemon_signing_public_key: String::new(),
        }
    }
}

impl HandshakeConfig {
    /// Builds a `HandshakeConfig` from the current HSI contract manifest.
    ///
    /// Computes the server contract hash from the dispatch registry
    /// manifest. On success the risk tier defaults to Tier2 (deny on
    /// mismatch). On build failure the tier escalates to Tier3
    /// (fail-closed: unknown state must deny).
    ///
    /// Operators can relax the tier afterwards via
    /// [`with_risk_tier`](Self::with_risk_tier).
    #[must_use]
    pub fn from_manifest() -> Self {
        let cli_version = crate::hsi_contract::CliVersion {
            semver: env!("CARGO_PKG_VERSION").to_string(),
            build_hash: String::new(),
        };

        let (server_contract_hash, risk_tier) =
            match crate::hsi_contract::build_manifest(cli_version) {
                Ok(manifest) => {
                    let hash = manifest.content_hash().unwrap_or_default();
                    let unavailable = hash.is_empty();
                    if unavailable {
                        tracing::warn!(
                            "HSI contract manifest content_hash() returned empty \
                             (escalating to Tier3 fail-closed)"
                        );
                    }
                    let tier = if unavailable {
                        RiskTier::Tier3
                    } else {
                        RiskTier::Tier2
                    };
                    (hash, tier)
                },
                Err(e) => {
                    tracing::warn!(
                        "Failed to build HSI contract manifest for handshake: {e} \
                         (escalating to Tier3 fail-closed)"
                    );
                    (String::new(), RiskTier::Tier3)
                },
            };

        Self {
            server_contract_hash,
            risk_tier,
            ..Self::default()
        }
    }

    /// Sets the risk tier.
    #[must_use]
    pub const fn with_risk_tier(mut self, tier: RiskTier) -> Self {
        self.risk_tier = tier;
        self
    }

    /// Sets the metrics handle.
    #[must_use]
    pub fn with_metrics(mut self, metrics: DaemonMetrics) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Sets the daemon signing public key (hex-encoded).
    #[must_use]
    pub fn with_daemon_signing_public_key(mut self, key_hex: impl Into<String>) -> Self {
        self.daemon_signing_public_key = key_hex.into();
        self
    }
}

/// Result of the handshake phase.
#[derive(Debug)]
pub enum HandshakeResult {
    /// Handshake succeeded, connection is ready for message exchange.
    Success {
        /// Contract binding metadata for this session (RFC-0020::REQ-0002).
        ///
        /// Persisted in `SessionStarted` events for audit trail.
        contract_binding: SessionContractBinding,
    },
    /// Handshake failed (sent `HelloNack`), connection should be closed.
    Failed,
    /// Connection closed during handshake (no frame received).
    ConnectionClosed,
}

impl HandshakeResult {
    /// Returns `true` if the handshake completed successfully.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        matches!(self, Self::Success { .. })
    }
}

/// Perform the mandatory protocol handshake on a connection.
///
/// This function implements the server-side of the Hello/HelloAck handshake
/// protocol as specified in DD-001/DD-008. It MUST be called before processing
/// any protobuf frames.
///
/// # Protocol Sequence
///
/// 1. Receive Hello frame from client
/// 2. Validate protocol version and contract binding bounds
/// 3. Evaluate tiered mismatch policy (Tier2+ denies on mismatch)
/// 4. Send `HelloAck` (on success) or `HelloNack` (on failure)
/// 5. Emit `contract_mismatch_total` counter if waived/denied
/// 6. Upgrade frame size limit for message exchange phase (on success)
///
/// # Arguments
///
/// * `connection` - The connection to handshake
/// * `config` - Contract binding configuration (hash, canonicalizers, tier,
///   metrics)
///
/// # Returns
///
/// - `Ok(HandshakeResult::Success { contract_binding })` if handshake completed
/// - `Ok(HandshakeResult::Failed)` if handshake failed (`HelloNack` sent)
/// - `Ok(HandshakeResult::ConnectionClosed)` if client closed connection
/// - `Err(_)` if I/O error occurred
///
/// # Example
///
/// ```rust,ignore
/// use apm2_daemon::protocol::connection_handler::{
///     perform_handshake, HandshakeConfig, HandshakeResult,
/// };
///
/// // Default is Tier2 (fail-closed: deny on contract mismatch).
/// // Operators can relax to Tier1 if needed.
/// let config = HandshakeConfig::from_manifest();
/// let (mut connection, _permit, socket_type) = socket_manager.accept().await?;
///
/// match perform_handshake(&mut connection, &config).await? {
///     HandshakeResult::Success { contract_binding } => {
///         // Connection is ready for protobuf message exchange.
///         // contract_binding MUST be persisted in SessionStarted events.
///         handle_protobuf_messages(&mut connection, socket_type).await?;
///     }
///     HandshakeResult::Failed | HandshakeResult::ConnectionClosed => {
///         // Connection will be closed
///     }
/// }
/// ```
pub async fn perform_handshake(
    connection: &mut Connection,
    config: &HandshakeConfig,
) -> Result<HandshakeResult> {
    // RFC-0020::REQ-0002 BLOCKER-1: Wire real contract binding into
    // ServerHandshake. Use the server's manifest hash, canonicalizers, and risk
    // tier from config.
    let mut handshake = ServerHandshake::new(server_info())
        .with_server_contract_hash(&config.server_contract_hash)
        .with_server_canonicalizers(config.server_canonicalizers.clone())
        .with_daemon_signing_public_key(&config.daemon_signing_public_key)
        .with_risk_tier(config.risk_tier);

    // Receive Hello from client
    let frame = match connection.framed().next().await {
        Some(Ok(frame)) => frame,
        Some(Err(e)) => {
            warn!("Failed to receive handshake frame: {e}");
            return Err(e.into());
        },
        None => {
            // Client closed connection before sending Hello
            return Ok(HandshakeResult::ConnectionClosed);
        },
    };

    // Parse the Hello message (enforces handshake frame size limit)
    let hello = match parse_hello(&frame) {
        Ok(hello) => hello,
        Err(e) => {
            warn!("Invalid Hello message: {e}");
            // Send HelloNack for invalid message
            let nack = super::handshake::HelloNack::rejected(format!("invalid Hello: {e}"));
            let nack_bytes = serialize_handshake_message(&HandshakeMessage::HelloNack(nack))
                .context("failed to serialize HelloNack")?;
            connection.framed().send(nack_bytes).await?;
            return Ok(HandshakeResult::Failed);
        },
    };

    // Process the Hello and generate response
    // (includes validation of contract binding bounds and mismatch evaluation)
    let response = handshake
        .process_hello(&hello)
        .context("failed to process Hello")?;

    // RFC-0020::REQ-0002 MAJOR-1: Emit metrics from production handshake path.
    // After mismatch evaluation, emit `contract_mismatch_total` counter
    // with risk-tier and outcome labels.
    if let Some(ref metrics) = config.metrics {
        if let Some(outcome) = handshake.mismatch_outcome() {
            match outcome {
                MismatchOutcome::Waived { tier, .. } => {
                    metrics.contract_mismatch(tier.label(), "waived");
                    info!(
                        risk_tier = %tier,
                        outcome = "waived",
                        "Contract mismatch waived during handshake"
                    );
                },
                MismatchOutcome::Denied { tier, .. } => {
                    metrics.contract_mismatch(tier.label(), "denied");
                    warn!(
                        risk_tier = %tier,
                        outcome = "denied",
                        "Contract mismatch denied during handshake"
                    );
                },
                MismatchOutcome::Match => {
                    // No mismatch — no counter emission needed.
                },
            }
        }
    }

    // Serialize and send response
    let response_bytes =
        serialize_handshake_message(&response).context("failed to serialize handshake response")?;
    connection.framed().send(response_bytes).await?;

    // Check if handshake succeeded
    if !handshake.is_completed() {
        return Ok(HandshakeResult::Failed);
    }

    // Upgrade to full frame size after successful handshake
    connection
        .upgrade_to_full_frame_size()
        .context("failed to upgrade frame size")?;

    // RFC-0020::REQ-0002 BLOCKER-4: Build SessionContractBinding for persistence
    // in SessionStarted events.
    let mismatch_waived = handshake
        .mismatch_outcome()
        .is_some_and(MismatchOutcome::is_waived);

    let contract_binding = SessionContractBinding {
        cli_contract_hash: hello.cli_contract_hash.clone(),
        server_contract_hash: config.server_contract_hash.clone(),
        client_canonicalizers: hello.canonicalizers.clone(),
        mismatch_waived,
        risk_tier: config.risk_tier,
    };

    Ok(HandshakeResult::Success { contract_binding })
}

#[cfg(test)]
#[allow(clippy::items_after_statements, clippy::float_cmp)]
mod tests {
    use std::time::Duration;

    use tempfile::TempDir;
    use tokio::time::timeout;

    use super::*;
    use crate::hsi_contract::handshake_binding::CanonicalizerInfo;
    use crate::protocol::{
        ClientHandshake, HandshakeMessage, SocketManagerConfig, parse_handshake_message,
        serialize_handshake_message,
    };

    /// Helper: test handshake config with Tier1 (waive mismatch) for
    /// backward-compatible basic handshake tests. Production default is
    /// Tier2 (deny), but most unit tests need the lenient tier.
    fn test_config() -> HandshakeConfig {
        HandshakeConfig::default().with_risk_tier(RiskTier::Tier1)
    }

    /// Test that handshake succeeds with a valid Hello message.
    #[tokio::test]
    async fn test_perform_handshake_success() {
        let tmp = TempDir::new().unwrap();
        let operator_path = tmp.path().join("operator.sock");
        let session_path = tmp.path().join("session.sock");

        let config = SocketManagerConfig::new(&operator_path, &session_path);
        let manager = std::sync::Arc::new(
            crate::protocol::socket_manager::SocketManager::bind(config).unwrap(),
        );

        let hs_config = test_config();

        // Spawn server that performs handshake
        let manager_clone = manager.clone();
        let hs_config_clone = hs_config.clone();
        let server_handle = tokio::spawn(async move {
            let (mut conn, _permit, _socket_type) = manager_clone.accept().await.unwrap();
            perform_handshake(&mut conn, &hs_config_clone).await
        });

        // Connect as client and perform handshake
        let stream = tokio::net::UnixStream::connect(&operator_path)
            .await
            .unwrap();
        let mut client_conn = Connection::new_with_credentials(stream, None);
        let mut client_handshake = ClientHandshake::new("test-client/1.0");

        // Send Hello
        let hello = client_handshake.create_hello();
        let hello_msg = HandshakeMessage::Hello(hello);
        let hello_bytes = serialize_handshake_message(&hello_msg).unwrap();
        client_conn.framed().send(hello_bytes).await.unwrap();

        // Receive HelloAck
        let response_frame = client_conn.framed().next().await.unwrap().unwrap();
        let response = parse_handshake_message(&response_frame).unwrap();
        client_handshake.process_response(response).unwrap();

        assert!(client_handshake.is_completed());

        // Verify server handshake succeeded
        let result = timeout(Duration::from_secs(1), server_handle)
            .await
            .expect("server timed out")
            .expect("server task panicked")
            .expect("handshake failed");

        assert!(result.is_success());
    }

    /// Test that handshake fails with invalid protocol version.
    #[tokio::test]
    async fn test_perform_handshake_version_mismatch() {
        use crate::protocol::handshake::Hello;

        let tmp = TempDir::new().unwrap();
        let operator_path = tmp.path().join("operator.sock");
        let session_path = tmp.path().join("session.sock");

        let config = SocketManagerConfig::new(&operator_path, &session_path);
        let manager = std::sync::Arc::new(
            crate::protocol::socket_manager::SocketManager::bind(config).unwrap(),
        );

        let hs_config = test_config();

        // Spawn server that performs handshake
        let manager_clone = manager.clone();
        let hs_config_clone = hs_config.clone();
        let server_handle = tokio::spawn(async move {
            let (mut conn, _permit, _socket_type) = manager_clone.accept().await.unwrap();
            perform_handshake(&mut conn, &hs_config_clone).await
        });

        // Connect as client with invalid version
        let stream = tokio::net::UnixStream::connect(&operator_path)
            .await
            .unwrap();
        let mut client_conn = Connection::new_with_credentials(stream, None);

        // Send Hello with invalid version
        let bad_hello = Hello::with_version(99, "bad-client/1.0");
        let hello_msg = HandshakeMessage::Hello(bad_hello);
        let hello_bytes = serialize_handshake_message(&hello_msg).unwrap();
        client_conn.framed().send(hello_bytes).await.unwrap();

        // Receive HelloNack
        let response_frame = client_conn.framed().next().await.unwrap().unwrap();
        let response = parse_handshake_message(&response_frame).unwrap();

        assert!(matches!(response, HandshakeMessage::HelloNack(_)));

        // Verify server handshake failed
        let result = timeout(Duration::from_secs(1), server_handle)
            .await
            .expect("server timed out")
            .expect("server task panicked")
            .expect("handshake error");

        assert!(matches!(result, HandshakeResult::Failed));
    }

    /// RFC-0020::REQ-0002: Test Tier2 denial through `perform_handshake`
    /// integration path.
    #[tokio::test]
    async fn test_perform_handshake_tier2_contract_mismatch_denied() {
        use crate::protocol::handshake::{HandshakeErrorCode, Hello};

        let tmp = TempDir::new().unwrap();
        let operator_path = tmp.path().join("operator.sock");
        let session_path = tmp.path().join("session.sock");

        let config = SocketManagerConfig::new(&operator_path, &session_path);
        let manager = std::sync::Arc::new(
            crate::protocol::socket_manager::SocketManager::bind(config).unwrap(),
        );

        // Configure server with Tier2 and a specific contract hash
        let hs_config = HandshakeConfig {
            server_contract_hash: "blake3:server_hash_abc".to_string(),
            server_canonicalizers: vec![CanonicalizerInfo {
                id: DAEMON_CANONICALIZER_ID.to_string(),
                version: DAEMON_CANONICALIZER_VERSION,
            }],
            risk_tier: RiskTier::Tier2,
            daemon_signing_public_key: String::new(),
            metrics: None,
        };

        let hs_config_clone = hs_config.clone();
        let manager_clone = manager.clone();
        let server_handle = tokio::spawn(async move {
            let (mut conn, _permit, _socket_type) = manager_clone.accept().await.unwrap();
            perform_handshake(&mut conn, &hs_config_clone).await
        });

        // Client sends Hello with DIFFERENT contract hash
        let stream = tokio::net::UnixStream::connect(&operator_path)
            .await
            .unwrap();
        let mut client_conn = Connection::new_with_credentials(stream, None);

        let hello = Hello::new("test-client/1.0")
            .with_contract_hash("blake3:client_hash_different")
            .with_canonicalizers(vec![CanonicalizerInfo {
                id: DAEMON_CANONICALIZER_ID.to_string(),
                version: DAEMON_CANONICALIZER_VERSION,
            }]);
        let hello_msg = HandshakeMessage::Hello(hello);
        let hello_bytes = serialize_handshake_message(&hello_msg).unwrap();
        client_conn.framed().send(hello_bytes).await.unwrap();

        // Should receive HelloNack with ContractMismatch
        let response_frame = client_conn.framed().next().await.unwrap().unwrap();
        let response = parse_handshake_message(&response_frame).unwrap();

        if let HandshakeMessage::HelloNack(nack) = response {
            assert_eq!(
                nack.error_code,
                HandshakeErrorCode::ContractMismatch,
                "Tier2 mismatch must return ContractMismatch error code"
            );
        } else {
            panic!("Expected HelloNack for Tier2 contract mismatch");
        }

        // Server should report Failed
        let result = timeout(Duration::from_secs(1), server_handle)
            .await
            .expect("server timed out")
            .expect("server task panicked")
            .expect("handshake error");

        assert!(matches!(result, HandshakeResult::Failed));
    }

    /// RFC-0020::REQ-0002: Test that the DEFAULT config (Tier2) denies contract
    /// mismatch without any manual tier override. This proves the
    /// fail-closed default is reachable in production.
    #[tokio::test]
    async fn test_perform_handshake_default_config_denies_mismatch() {
        use crate::protocol::handshake::{HandshakeErrorCode, Hello};

        let tmp = TempDir::new().unwrap();
        let operator_path = tmp.path().join("operator.sock");
        let session_path = tmp.path().join("session.sock");

        let config = SocketManagerConfig::new(&operator_path, &session_path);
        let manager = std::sync::Arc::new(
            crate::protocol::socket_manager::SocketManager::bind(config).unwrap(),
        );

        // Use the DEFAULT config -- no with_risk_tier() override.
        // The default is now Tier2, which MUST deny mismatches.
        let hs_config = HandshakeConfig {
            server_contract_hash: "blake3:server_production_hash".to_string(),
            server_canonicalizers: vec![CanonicalizerInfo {
                id: DAEMON_CANONICALIZER_ID.to_string(),
                version: DAEMON_CANONICALIZER_VERSION,
            }],
            metrics: None,
            // All other fields from default (risk_tier = Tier2)
            ..HandshakeConfig::default()
        };

        assert_eq!(
            hs_config.risk_tier,
            RiskTier::Tier2,
            "Default risk tier must be Tier2 (fail-closed)"
        );

        let hs_config_clone = hs_config.clone();
        let manager_clone = manager.clone();
        let server_handle = tokio::spawn(async move {
            let (mut conn, _permit, _socket_type) = manager_clone.accept().await.unwrap();
            perform_handshake(&mut conn, &hs_config_clone).await
        });

        // Client sends Hello with DIFFERENT contract hash
        let stream = tokio::net::UnixStream::connect(&operator_path)
            .await
            .unwrap();
        let mut client_conn = Connection::new_with_credentials(stream, None);

        let hello = Hello::new("test-client/1.0")
            .with_contract_hash("blake3:client_different_hash")
            .with_canonicalizers(vec![CanonicalizerInfo {
                id: DAEMON_CANONICALIZER_ID.to_string(),
                version: DAEMON_CANONICALIZER_VERSION,
            }]);
        let hello_msg = HandshakeMessage::Hello(hello);
        let hello_bytes = serialize_handshake_message(&hello_msg).unwrap();
        client_conn.framed().send(hello_bytes).await.unwrap();

        // Should receive HelloNack with ContractMismatch
        let response_frame = client_conn.framed().next().await.unwrap().unwrap();
        let response = parse_handshake_message(&response_frame).unwrap();

        if let HandshakeMessage::HelloNack(nack) = response {
            assert_eq!(
                nack.error_code,
                HandshakeErrorCode::ContractMismatch,
                "Default Tier2 mismatch must return ContractMismatch"
            );
        } else {
            panic!("Expected HelloNack for default Tier2 contract mismatch, got HelloAck");
        }

        // Server should report Failed
        let result = timeout(Duration::from_secs(1), server_handle)
            .await
            .expect("server timed out")
            .expect("server task panicked")
            .expect("handshake error");

        assert!(
            matches!(result, HandshakeResult::Failed),
            "Default Tier2 config must deny contract mismatch"
        );
    }

    /// RFC-0020::REQ-0002: Test that successful handshake returns contract
    /// binding.
    #[tokio::test]
    async fn test_perform_handshake_returns_contract_binding() {
        use crate::protocol::handshake::Hello;

        let tmp = TempDir::new().unwrap();
        let operator_path = tmp.path().join("operator.sock");
        let session_path = tmp.path().join("session.sock");

        let config = SocketManagerConfig::new(&operator_path, &session_path);
        let manager = std::sync::Arc::new(
            crate::protocol::socket_manager::SocketManager::bind(config).unwrap(),
        );

        let hs_config = HandshakeConfig {
            server_contract_hash: "blake3:server_abc".to_string(),
            server_canonicalizers: vec![CanonicalizerInfo {
                id: DAEMON_CANONICALIZER_ID.to_string(),
                version: DAEMON_CANONICALIZER_VERSION,
            }],
            risk_tier: RiskTier::Tier1,
            daemon_signing_public_key: String::new(),
            metrics: None,
        };

        let hs_config_clone = hs_config.clone();
        let manager_clone = manager.clone();
        let server_handle = tokio::spawn(async move {
            let (mut conn, _permit, _socket_type) = manager_clone.accept().await.unwrap();
            perform_handshake(&mut conn, &hs_config_clone).await
        });

        let stream = tokio::net::UnixStream::connect(&operator_path)
            .await
            .unwrap();
        let mut client_conn = Connection::new_with_credentials(stream, None);

        // Client sends Hello with a different hash (waived at Tier1)
        let hello = Hello::new("test-client/1.0")
            .with_contract_hash("blake3:client_xyz")
            .with_canonicalizers(vec![CanonicalizerInfo {
                id: DAEMON_CANONICALIZER_ID.to_string(),
                version: DAEMON_CANONICALIZER_VERSION,
            }]);
        let hello_msg = HandshakeMessage::Hello(hello);
        let hello_bytes = serialize_handshake_message(&hello_msg).unwrap();
        client_conn.framed().send(hello_bytes).await.unwrap();

        // Receive HelloAck (Tier1 waives mismatch)
        let response_frame = client_conn.framed().next().await.unwrap().unwrap();
        let response = parse_handshake_message(&response_frame).unwrap();
        assert!(matches!(response, HandshakeMessage::HelloAck(_)));

        let result = timeout(Duration::from_secs(1), server_handle)
            .await
            .expect("server timed out")
            .expect("server task panicked")
            .expect("handshake failed");

        if let HandshakeResult::Success { contract_binding } = result {
            assert_eq!(contract_binding.cli_contract_hash, "blake3:client_xyz");
            assert_eq!(contract_binding.server_contract_hash, "blake3:server_abc");
            assert!(
                contract_binding.mismatch_waived,
                "Tier1 mismatch should be waived"
            );
            assert_eq!(contract_binding.risk_tier, RiskTier::Tier1);
            assert_eq!(contract_binding.client_canonicalizers.len(), 1);
        } else {
            panic!("Expected HandshakeResult::Success with contract_binding");
        }
    }

    /// RFC-0020::REQ-0002: Test metrics emission on contract mismatch.
    #[tokio::test]
    async fn test_perform_handshake_emits_mismatch_metrics() {
        use crate::protocol::handshake::Hello;

        let tmp = TempDir::new().unwrap();
        let operator_path = tmp.path().join("operator.sock");
        let session_path = tmp.path().join("session.sock");

        let config = SocketManagerConfig::new(&operator_path, &session_path);
        let manager = std::sync::Arc::new(
            crate::protocol::socket_manager::SocketManager::bind(config).unwrap(),
        );

        let metrics_registry = crate::metrics::MetricsRegistry::new().expect("metrics registry");
        let metrics = metrics_registry.daemon_metrics().clone();

        let hs_config = HandshakeConfig {
            server_contract_hash: "blake3:server_hash".to_string(),
            server_canonicalizers: vec![],
            risk_tier: RiskTier::Tier0,
            daemon_signing_public_key: String::new(),
            metrics: Some(metrics.clone()),
        };

        let hs_config_clone = hs_config.clone();
        let manager_clone = manager.clone();
        let server_handle = tokio::spawn(async move {
            let (mut conn, _permit, _socket_type) = manager_clone.accept().await.unwrap();
            perform_handshake(&mut conn, &hs_config_clone).await
        });

        let stream = tokio::net::UnixStream::connect(&operator_path)
            .await
            .unwrap();
        let mut client_conn = Connection::new_with_credentials(stream, None);

        let hello = Hello::new("test-client/1.0").with_contract_hash("blake3:client_different");
        let hello_msg = HandshakeMessage::Hello(hello);
        let hello_bytes = serialize_handshake_message(&hello_msg).unwrap();
        client_conn.framed().send(hello_bytes).await.unwrap();

        let response_frame = client_conn.framed().next().await.unwrap().unwrap();
        let _response = parse_handshake_message(&response_frame).unwrap();

        let result = timeout(Duration::from_secs(1), server_handle)
            .await
            .expect("server timed out")
            .expect("server task panicked")
            .expect("handshake failed");

        assert!(result.is_success());

        // Verify mismatch counter was emitted
        assert_eq!(
            metrics.contract_mismatch_count("tier0", "waived"),
            1.0,
            "contract_mismatch_total(tier0,waived) should be 1"
        );
    }

    /// RFC-0020::REQ-0002: Test that over-limit contract hash is rejected.
    #[tokio::test]
    async fn test_perform_handshake_rejects_oversized_contract_hash() {
        use crate::protocol::handshake::Hello;

        let tmp = TempDir::new().unwrap();
        let operator_path = tmp.path().join("operator.sock");
        let session_path = tmp.path().join("session.sock");

        let config = SocketManagerConfig::new(&operator_path, &session_path);
        let manager = std::sync::Arc::new(
            crate::protocol::socket_manager::SocketManager::bind(config).unwrap(),
        );

        let hs_config = test_config();
        let hs_config_clone = hs_config.clone();
        let manager_clone = manager.clone();
        let server_handle = tokio::spawn(async move {
            let (mut conn, _permit, _socket_type) = manager_clone.accept().await.unwrap();
            perform_handshake(&mut conn, &hs_config_clone).await
        });

        let stream = tokio::net::UnixStream::connect(&operator_path)
            .await
            .unwrap();
        let mut client_conn = Connection::new_with_credentials(stream, None);

        // Send Hello with oversized contract hash (> 128 chars)
        let oversized_hash = "x".repeat(200);
        let hello = Hello::new("test-client/1.0").with_contract_hash(oversized_hash);
        let hello_msg = HandshakeMessage::Hello(hello);
        let hello_bytes = serialize_handshake_message(&hello_msg).unwrap();
        client_conn.framed().send(hello_bytes).await.unwrap();

        // Should receive HelloNack (rejected due to validation)
        let response_frame = client_conn.framed().next().await.unwrap().unwrap();
        let response = parse_handshake_message(&response_frame).unwrap();
        assert!(
            matches!(response, HandshakeMessage::HelloNack(_)),
            "Oversized contract hash should be rejected"
        );

        let result = timeout(Duration::from_secs(1), server_handle)
            .await
            .expect("server timed out")
            .expect("server task panicked")
            .expect("handshake error");

        assert!(matches!(result, HandshakeResult::Failed));
    }

    // =========================================================================
    // RFC-0020::REQ-0003: Session-typed state machine tests
    // =========================================================================

    #[test]
    fn test_connection_phase_initial_state_is_connected() {
        let phase = ConnectionPhase::Connected;
        assert!(!phase.allows_dispatch());
        assert_eq!(format!("{phase}"), "Connected");
    }

    #[test]
    fn test_connection_phase_handshake_complete_does_not_allow_dispatch() {
        let phase = ConnectionPhase::HandshakeComplete;
        assert!(!phase.allows_dispatch());
    }

    #[test]
    fn test_connection_phase_session_open_allows_dispatch() {
        let phase = ConnectionPhase::SessionOpen;
        assert!(phase.allows_dispatch());
    }

    #[test]
    fn test_connection_phase_valid_forward_progression() {
        // Connected -> HandshakeComplete -> SessionOpen
        let phase = ConnectionPhase::Connected;
        let phase = phase.advance_to_handshake_complete().unwrap();
        assert_eq!(phase, ConnectionPhase::HandshakeComplete);

        let phase = phase.advance_to_session_open().unwrap();
        assert_eq!(phase, ConnectionPhase::SessionOpen);
        assert!(phase.allows_dispatch());
    }

    #[test]
    fn test_connection_phase_cannot_skip_handshake() {
        // Connected -> SessionOpen must fail (skipping HandshakeComplete)
        let phase = ConnectionPhase::Connected;
        let result = phase.advance_to_session_open();
        assert!(result.is_err());
        if let Err(ConnectionPhaseError::IllegalTransition { from, to }) = result {
            assert_eq!(from, ConnectionPhase::Connected);
            assert_eq!(to, ConnectionPhase::SessionOpen);
        } else {
            panic!("Expected IllegalTransition error");
        }
    }

    #[test]
    fn test_connection_phase_cannot_double_advance_to_handshake() {
        // HandshakeComplete -> HandshakeComplete must fail
        let phase = ConnectionPhase::HandshakeComplete;
        let result = phase.advance_to_handshake_complete();
        assert!(result.is_err());
    }

    #[test]
    fn test_connection_phase_cannot_regress_from_session_open() {
        // SessionOpen -> HandshakeComplete must fail
        let phase = ConnectionPhase::SessionOpen;
        let result = phase.advance_to_handshake_complete();
        assert!(result.is_err());
        // SessionOpen -> SessionOpen (via advance_to_session_open) must also fail
        let result = phase.advance_to_session_open();
        assert!(result.is_err());
    }

    #[test]
    fn test_connection_phase_error_display() {
        let err = ConnectionPhaseError::IllegalTransition {
            from: ConnectionPhase::Connected,
            to: ConnectionPhase::SessionOpen,
        };
        let msg = format!("{err}");
        assert!(msg.contains("Connected"));
        assert!(msg.contains("SessionOpen"));

        let err = ConnectionPhaseError::DispatchBeforeSessionOpen {
            phase: ConnectionPhase::HandshakeComplete,
        };
        let msg = format!("{err}");
        assert!(msg.contains("HandshakeComplete"));
        assert!(msg.contains("not SessionOpen"));
    }

    /// RFC-0020::REQ-0003: Verify that privileged dispatch is rejected before
    /// `SessionOpen` phase.
    #[test]
    fn test_privileged_dispatch_rejected_before_session_open() {
        use super::super::dispatch::{ConnectionContext, PrivilegedDispatcher};
        use crate::protocol::credentials::PeerCredentials;

        let dispatcher = PrivilegedDispatcher::new();
        // Create context in Connected phase (no handshake yet)
        let ctx = ConnectionContext::privileged(Some(PeerCredentials {
            uid: 1000,
            gid: 1000,
            pid: Some(12345),
        }));

        // Attempt dispatch with a dummy frame (tag byte = 1 = ClaimWork)
        let frame = bytes::Bytes::from(vec![1u8, 0, 0, 0]);
        let response = dispatcher.dispatch(&frame, &ctx).unwrap();
        let encoded = response.encode();

        // Should get error response, not a successful route
        // Error tag is 0
        assert_eq!(
            encoded[0], 0,
            "Dispatch before SessionOpen must return error response"
        );
    }

    /// RFC-0020::REQ-0003: Verify that session dispatch is rejected before
    /// `SessionOpen` phase.
    #[test]
    fn test_session_dispatch_rejected_before_session_open() {
        use super::super::dispatch::ConnectionContext;
        use super::super::session_dispatch::{InMemoryManifestStore, SessionDispatcher};
        use crate::protocol::credentials::PeerCredentials;
        use crate::protocol::session_token::TokenMinter;

        let minter = TokenMinter::new(TokenMinter::generate_secret());
        let manifest_store = std::sync::Arc::new(InMemoryManifestStore::new());
        let dispatcher = SessionDispatcher::with_manifest_store(minter, manifest_store);

        // Create context in Connected phase (no handshake yet)
        let ctx = ConnectionContext::session(
            Some(PeerCredentials {
                uid: 1000,
                gid: 1000,
                pid: Some(12346),
            }),
            Some("sess-001".to_string()),
        );

        // Attempt dispatch with a dummy frame (tag byte = 1 = RequestTool)
        let frame = bytes::Bytes::from(vec![1u8, 0, 0, 0]);
        let response = dispatcher.dispatch(&frame, &ctx).unwrap();
        let encoded = response.encode();

        // Should get error response, not a successful route
        assert_eq!(
            encoded[0], 0,
            "Session dispatch before SessionOpen must return error response"
        );
    }

    /// RFC-0020::REQ-0003: Verify that dispatch succeeds after full phase
    /// progression.
    #[test]
    fn test_privileged_dispatch_succeeds_after_session_open() {
        use super::super::dispatch::{
            ConnectionContext, PrivilegedDispatcher, encode_claim_work_request,
        };
        use super::super::messages::{ClaimWorkRequest, WorkRole};
        use crate::protocol::credentials::PeerCredentials;

        let dispatcher = PrivilegedDispatcher::new();

        // Create context and advance through full progression
        let mut ctx = ConnectionContext::privileged(Some(PeerCredentials {
            uid: 1000,
            gid: 1000,
            pid: Some(12345),
        }));
        ctx.advance_to_handshake_complete().unwrap();
        ctx.advance_to_session_open().unwrap();

        // Encode a valid ClaimWork request
        let request = ClaimWorkRequest {
            actor_id: "test-actor".to_string(),
            role: WorkRole::Implementer.into(),
            credential_signature: vec![],
            nonce: vec![],
        };
        let frame = encode_claim_work_request(&request);

        let response = dispatcher.dispatch(&frame, &ctx).unwrap();
        let encoded = response.encode();

        // Should route to ClaimWork handler (not blocked by phase check)
        // The response is a ClaimWork response (tag=1) with a generated work_id
        assert_eq!(
            encoded[0], 1,
            "Dispatch after SessionOpen should route to handler"
        );
    }

    // =========================================================================
    // RFC-0020::REQ-0003: Fail-closed enum decoding tests
    // =========================================================================

    /// RFC-0020::REQ-0003: Verify that unknown message type tags are rejected
    /// (fail-closed, no default coercion).
    #[test]
    fn test_unknown_privileged_message_type_returns_none() {
        use super::super::dispatch::PrivilegedMessageType;

        // All valid tags should return Some
        for variant in PrivilegedMessageType::all_request_variants() {
            assert!(
                PrivilegedMessageType::from_tag(variant.tag()).is_some(),
                "Valid tag {} should return Some",
                variant.tag()
            );
        }

        // Unknown tags must return None (fail-closed)
        let unknown_tags: Vec<u8> = vec![0, 50, 63, 65, 67, 69, 71, 100, 255];
        for tag in unknown_tags {
            assert!(
                PrivilegedMessageType::from_tag(tag).is_none(),
                "Unknown tag {tag} must return None (fail-closed)",
            );
        }
    }

    /// RFC-0020::REQ-0003: Verify that unknown session message type tags are
    /// rejected.
    #[test]
    fn test_unknown_session_message_type_returns_none() {
        use super::super::session_dispatch::SessionMessageType;

        // All valid tags should return Some
        for variant in SessionMessageType::all_request_variants() {
            assert!(
                SessionMessageType::from_tag(variant.tag()).is_some(),
                "Valid tag {} should return Some",
                variant.tag()
            );
        }

        // Unknown tags must return None (fail-closed)
        let unknown_tags: Vec<u8> = vec![0, 8, 50, 63, 65, 67, 69, 100, 255];
        for tag in unknown_tags {
            assert!(
                SessionMessageType::from_tag(tag).is_none(),
                "Unknown tag {tag} must return None (fail-closed)",
            );
        }
    }

    /// RFC-0020::REQ-0003: Verify that unknown `HandshakeErrorCode` variants
    /// are rejected during deserialization (fail-closed).
    #[test]
    fn test_unknown_handshake_error_code_fails_closed() {
        use super::super::handshake::HandshakeErrorCode;

        // Valid variants deserialize successfully
        let valid = serde_json::from_str::<HandshakeErrorCode>("\"version_mismatch\"");
        assert!(valid.is_ok());

        let valid = serde_json::from_str::<HandshakeErrorCode>("\"rejected\"");
        assert!(valid.is_ok());

        let valid = serde_json::from_str::<HandshakeErrorCode>("\"contract_mismatch\"");
        assert!(valid.is_ok());

        // Unknown variant MUST fail (no default coercion)
        let unknown = serde_json::from_str::<HandshakeErrorCode>("\"unknown_code\"");
        assert!(
            unknown.is_err(),
            "Unknown HandshakeErrorCode must fail deserialization (fail-closed)"
        );

        let unknown = serde_json::from_str::<HandshakeErrorCode>("\"\"");
        assert!(unknown.is_err(), "Empty string must fail deserialization");
    }

    // =========================================================================
    // RFC-0020::REQ-0003: Bounded decode enforcement tests
    // =========================================================================

    /// RFC-0020::REQ-0003: Verify that oversized payloads are rejected BEFORE
    /// deserialization (bounded decode).
    #[test]
    fn test_bounded_decode_rejects_oversized_payload() {
        use super::super::messages::{BoundedDecode, ClaimWorkRequest, DecodeConfig, DecodeError};

        // Create a config with a small limit
        let config = DecodeConfig::new(64, 10);

        // Create a payload that exceeds the limit
        let oversized = vec![0u8; 128];
        let result = ClaimWorkRequest::decode_bounded(&oversized, &config);
        assert!(
            matches!(
                result,
                Err(DecodeError::MessageTooLarge { size: 128, max: 64 })
            ),
            "Oversized payload must be rejected before decode"
        );
    }

    /// RFC-0020::REQ-0003: Verify that payloads within bounds are accepted.
    #[test]
    fn test_bounded_decode_accepts_within_bounds() {
        use prost::Message;

        use super::super::messages::{BoundedDecode, DecodeConfig, ShutdownRequest};

        let config = DecodeConfig::default();

        // Create a valid protobuf message
        let request = ShutdownRequest {
            reason: Some("test".to_string()),
        };
        let mut buf = Vec::new();
        request.encode(&mut buf).unwrap();

        let result = ShutdownRequest::decode_bounded(&buf, &config);
        assert!(result.is_ok(), "Valid payload within bounds must decode");
    }

    /// RFC-0020::REQ-0003: Verify that unknown fields in `HelloNack` JSON are
    /// rejected (`deny_unknown_fields`).
    #[test]
    fn test_signed_json_rejects_unknown_fields_hello_nack() {
        use super::super::handshake::HelloNack;

        // HelloNack uses deny_unknown_fields
        let json = r#"{"error_code":"rejected","message":"test","unknown_field":"malicious"}"#;
        let result = serde_json::from_str::<HelloNack>(json);
        assert!(
            result.is_err(),
            "HelloNack must reject unknown fields (signed JSON hardening)"
        );
    }

    /// RFC-0020::REQ-0003: Verify that default `DecodeConfig` constants are
    /// reasonable.
    #[test]
    fn test_decode_config_defaults_are_bounded() {
        use super::super::messages::{
            DEFAULT_MAX_MESSAGE_SIZE, DEFAULT_MAX_REPEATED_FIELD_COUNT, DecodeConfig,
        };

        let config = DecodeConfig::default();
        assert_eq!(config.max_message_size, DEFAULT_MAX_MESSAGE_SIZE);
        assert_eq!(
            config.max_repeated_field_count,
            DEFAULT_MAX_REPEATED_FIELD_COUNT
        );

        // Sanity check: defaults are non-zero and bounded
        assert!(config.max_message_size > 0);
        assert!(config.max_message_size <= 128 * 1024 * 1024); // At most 128 MiB
        assert!(config.max_repeated_field_count > 0);
        assert!(config.max_repeated_field_count <= 1_000_000);
    }
}
