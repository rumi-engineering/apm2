//! Connection handler for dual-socket `ProtocolServer` control plane.
//!
//! This module implements the connection handling logic for the daemon's
//! `ProtocolServer`-only control plane (TCK-00279/TCK-00281). It performs the
//! mandatory Hello/HelloAck handshake as specified in DD-001/DD-008 before
//! processing any protobuf messages.
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
//! # TCK-00281: Legacy JSON IPC Removal
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

/// Server information string for handshake.
///
/// This identifies the daemon to connecting clients during the Hello/HelloAck
/// handshake.
fn server_info() -> String {
    format!("apm2-daemon/{}", env!("CARGO_PKG_VERSION"))
}

/// Default canonicalizer declared by the daemon (TCK-00348).
///
/// This is the canonical encoding version the daemon uses for deterministic
/// serialization. Clients must declare compatible canonicalizers.
pub const DAEMON_CANONICALIZER_ID: &str = "apm2.canonical.v1";

/// Default canonicalizer version.
pub const DAEMON_CANONICALIZER_VERSION: u32 = 1;

/// Configuration for contract binding in the handshake (TCK-00348).
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
}

impl Default for HandshakeConfig {
    /// Returns a default config with Tier1 risk, the daemon's standard
    /// canonicalizer, and no metrics.
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
            risk_tier: RiskTier::Tier1,
            metrics: None,
        }
    }
}

impl HandshakeConfig {
    /// Builds a `HandshakeConfig` from the current HSI contract manifest.
    ///
    /// Computes the server contract hash from the dispatch registry
    /// manifest. Falls back to empty hash on build failure (logged as
    /// warning) so the daemon can still accept connections in degraded
    /// mode.
    #[must_use]
    pub fn from_manifest() -> Self {
        let cli_version = crate::hsi_contract::CliVersion {
            semver: env!("CARGO_PKG_VERSION").to_string(),
            build_hash: String::new(),
        };

        let server_contract_hash = match crate::hsi_contract::build_manifest(cli_version) {
            Ok(manifest) => manifest.content_hash().unwrap_or_default(),
            Err(e) => {
                tracing::warn!("Failed to build HSI contract manifest for handshake: {e}");
                String::new()
            },
        };

        Self {
            server_contract_hash,
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
}

/// Result of the handshake phase.
#[derive(Debug)]
pub enum HandshakeResult {
    /// Handshake succeeded, connection is ready for message exchange.
    Success {
        /// Contract binding metadata for this session (TCK-00348).
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
/// let config = HandshakeConfig::from_manifest().with_risk_tier(RiskTier::Tier1);
/// let (mut connection, _permit, socket_type) = socket_manager.accept().await?;
///
/// match perform_handshake(&mut connection, &config).await? {
///     HandshakeResult::Success { contract_binding } => {
///         // Connection is ready for protobuf message exchange
///         // contract_binding can be persisted in SessionStarted events
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
    // TCK-00348 BLOCKER-1: Wire real contract binding into ServerHandshake.
    // Use the server's manifest hash, canonicalizers, and risk tier from config.
    let mut handshake = ServerHandshake::new(server_info())
        .with_server_contract_hash(&config.server_contract_hash)
        .with_server_canonicalizers(config.server_canonicalizers.clone())
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

    // TCK-00348 MAJOR-1: Emit metrics from production handshake path.
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

    // TCK-00348 BLOCKER-4: Build SessionContractBinding for persistence
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

    /// Helper: default test handshake config (Tier0 for backward compat).
    fn test_config() -> HandshakeConfig {
        HandshakeConfig::default()
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

    /// TCK-00348: Test Tier2 denial through `perform_handshake` integration
    /// path.
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

    /// TCK-00348: Test that successful handshake returns contract binding.
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

    /// TCK-00348: Test metrics emission on contract mismatch.
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

    /// TCK-00348: Test that over-limit contract hash is rejected.
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
}
