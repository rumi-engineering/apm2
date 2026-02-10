//! Protocol handshake for version negotiation.
//!
//! This module implements the Hello/HelloAck handshake protocol for
//! establishing a connection between client and server. The handshake
//! performs protocol version negotiation and exchanges initial metadata.
//!
//! # Handshake Sequence
//!
//! ```text
//! Client                                    Server
//!   |                                          |
//!   |  -- Hello { version, client_info } -->   |
//!   |                                          |
//!   |  <-- HelloAck { version, server_info } --|
//!   |      OR                                  |
//!   |  <-- HelloNack { error } ----------------|
//!   |                                          |
//! ```
//!
//! # Version Negotiation
//!
//! The server accepts clients with compatible protocol versions:
//! - Same major version
//! - Client minor version <= server minor version (backward compatible)
//!
//! # Session Authentication (TCK-00250)
//!
//! After handshake, session-scoped connections require a [`SessionToken`]
//! for authentication. Tokens are minted when an episode is spawned via
//! the `SpawnEpisode` privileged endpoint and bind the session to its
//! authorization context.
//!
//! The token is validated on each session-scoped request using HMAC-SHA256
//! with constant-time comparison. See [`super::session_token`] for details.
//!
//! [`SessionToken`]: super::session_token::SessionToken
//!
//! # Security Considerations
//!
//! - Handshake must complete before any other messages
//! - Invalid handshake terminates the connection
//! - Version mismatch provides diagnostic info without leaking internals
//! - Session tokens use constant-time MAC verification (CTR-WH001)

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use super::error::{MAX_HANDSHAKE_FRAME_SIZE, PROTOCOL_VERSION, ProtocolError, ProtocolResult};
use crate::hsi_contract::handshake_binding::CanonicalizerInfo;

/// Hello message sent by client to initiate handshake.
///
/// The client sends this as the first message after connecting.
/// The server validates the version and responds with [`HelloAck`]
/// or [`HelloNack`].
///
/// # TCK-00348: Contract Binding Fields
///
/// Per RFC-0020 section 3.1.2, the client MUST include its
/// `cli_contract_hash` and canonicalizer metadata so the daemon can
/// evaluate the tiered mismatch policy (section 3.1.3).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Hello {
    /// Protocol version requested by the client.
    pub protocol_version: u32,

    /// Client identifier for logging and diagnostics.
    ///
    /// Should include client name and version, e.g., "apm2-cli/0.3.0".
    pub client_info: String,

    /// Optional client capabilities for future extension.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,

    /// Client's HSI contract manifest content hash (TCK-00348).
    ///
    /// Per RFC-0020 section 3.1.2, this MUST be included in the session
    /// handshake. Format: `blake3:<64-hex>` (or equivalent hash scheme).
    /// Empty string if the client does not have a contract manifest.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cli_contract_hash: String,

    /// Canonicalizer metadata declared by the client (TCK-00348).
    ///
    /// Per RFC-0020 section 3.1.2, the client declares which
    /// canonicalizers it uses so the daemon can detect incompatible
    /// encodings.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub canonicalizers: Vec<CanonicalizerInfo>,
}

impl Hello {
    /// Create a new Hello message.
    #[must_use]
    pub fn new(client_info: impl Into<String>) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            client_info: client_info.into(),
            capabilities: Vec::new(),
            cli_contract_hash: String::new(),
            canonicalizers: Vec::new(),
        }
    }

    /// Create a Hello with specific protocol version (for testing).
    #[must_use]
    pub fn with_version(protocol_version: u32, client_info: impl Into<String>) -> Self {
        Self {
            protocol_version,
            client_info: client_info.into(),
            capabilities: Vec::new(),
            cli_contract_hash: String::new(),
            canonicalizers: Vec::new(),
        }
    }

    /// Add capabilities to the Hello message.
    #[must_use]
    pub fn with_capabilities(mut self, capabilities: Vec<String>) -> Self {
        self.capabilities = capabilities;
        self
    }

    /// Set the client's HSI contract manifest hash (TCK-00348).
    #[must_use]
    pub fn with_contract_hash(mut self, hash: impl Into<String>) -> Self {
        self.cli_contract_hash = hash.into();
        self
    }

    /// Set the client's canonicalizer metadata (TCK-00348).
    #[must_use]
    pub fn with_canonicalizers(mut self, canonicalizers: Vec<CanonicalizerInfo>) -> Self {
        self.canonicalizers = canonicalizers;
        self
    }
}

/// Successful handshake acknowledgment from server.
///
/// Sent when the server accepts the client's Hello message.
///
/// # TCK-00348: Contract Binding Fields
///
/// Per RFC-0020 section 3.1.2, the server echoes its active contract
/// hash and supported canonicalizers so the client can verify
/// compatibility.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HelloAck {
    /// Protocol version agreed upon.
    ///
    /// This may be lower than the client requested if the server
    /// only supports an older version.
    pub protocol_version: u32,

    /// Server identifier for logging and diagnostics.
    ///
    /// Should include server name and version, e.g., "apm2-daemon/0.3.0".
    pub server_info: String,

    /// Hash of the current policy configuration (optional).
    ///
    /// Allows clients to verify they're connecting to the expected
    /// daemon instance with the expected policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_hash: Option<String>,

    /// Server capabilities for feature negotiation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,

    /// The daemon's active HSI contract manifest content hash
    /// (TCK-00348).
    ///
    /// Per RFC-0020 section 3.1.2, echoed to the client so it can
    /// detect contract drift on its side.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub server_contract_hash: String,

    /// Canonicalizers supported by the daemon (TCK-00348).
    ///
    /// Allows the client to verify canonicalizer compatibility.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub server_canonicalizers: Vec<CanonicalizerInfo>,

    /// Daemon Ed25519 verifying key (hex-encoded) used for signed authority
    /// tokens.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub daemon_signing_public_key: String,

    /// Whether a contract mismatch was detected and waived (TCK-00348).
    ///
    /// `true` if the client's `cli_contract_hash` differs from the
    /// daemon's active contract but the session was allowed to proceed
    /// because the risk tier is Tier0/Tier1.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub contract_mismatch_waived: bool,
}

impl HelloAck {
    /// Create a new `HelloAck` message.
    #[must_use]
    pub fn new(server_info: impl Into<String>) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            server_info: server_info.into(),
            policy_hash: None,
            capabilities: Vec::new(),
            server_contract_hash: String::new(),
            server_canonicalizers: Vec::new(),
            daemon_signing_public_key: String::new(),
            contract_mismatch_waived: false,
        }
    }

    /// Set the policy hash.
    #[must_use]
    pub fn with_policy_hash(mut self, hash: impl Into<String>) -> Self {
        self.policy_hash = Some(hash.into());
        self
    }

    /// Add capabilities to the `HelloAck` message.
    #[must_use]
    pub fn with_capabilities(mut self, capabilities: Vec<String>) -> Self {
        self.capabilities = capabilities;
        self
    }

    /// Set the server's active contract hash (TCK-00348).
    #[must_use]
    pub fn with_server_contract_hash(mut self, hash: impl Into<String>) -> Self {
        self.server_contract_hash = hash.into();
        self
    }

    /// Set the server's supported canonicalizers (TCK-00348).
    #[must_use]
    pub fn with_server_canonicalizers(mut self, canonicalizers: Vec<CanonicalizerInfo>) -> Self {
        self.server_canonicalizers = canonicalizers;
        self
    }

    /// Set the daemon signing public key (hex-encoded).
    #[must_use]
    pub fn with_daemon_signing_public_key(mut self, key_hex: impl Into<String>) -> Self {
        self.daemon_signing_public_key = key_hex.into();
        self
    }

    /// Set the contract mismatch waived flag (TCK-00348).
    #[must_use]
    pub const fn with_contract_mismatch_waived(mut self, waived: bool) -> Self {
        self.contract_mismatch_waived = waived;
        self
    }
}

/// Handshake rejection from server.
///
/// Sent when the server cannot accept the client's Hello message.
/// The connection should be closed after sending/receiving this.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HelloNack {
    /// Error code for the rejection.
    pub error_code: HandshakeErrorCode,

    /// Human-readable error message.
    pub message: String,

    /// Server's protocol version (for version mismatch diagnostics).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_version: Option<u32>,
}

impl HelloNack {
    /// Create a version mismatch rejection.
    #[must_use]
    pub fn version_mismatch(client_version: u32) -> Self {
        Self {
            error_code: HandshakeErrorCode::VersionMismatch,
            message: format!(
                "protocol version {client_version} not supported, server supports version {PROTOCOL_VERSION}"
            ),
            server_version: Some(PROTOCOL_VERSION),
        }
    }

    /// Create a generic rejection with custom message.
    #[must_use]
    pub fn rejected(message: impl Into<String>) -> Self {
        Self {
            error_code: HandshakeErrorCode::Rejected,
            message: message.into(),
            server_version: None,
        }
    }

    /// Create a contract mismatch rejection (TCK-00348).
    ///
    /// Per RFC-0020 section 3.1.3, Tier2+ sessions MUST be denied when
    /// the client's contract or canonicalizer metadata does not match.
    #[must_use]
    pub fn contract_mismatch(detail: impl Into<String>) -> Self {
        Self {
            error_code: HandshakeErrorCode::ContractMismatch,
            message: detail.into(),
            server_version: Some(PROTOCOL_VERSION),
        }
    }
}

/// Error codes for handshake rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HandshakeErrorCode {
    /// Protocol version not supported.
    VersionMismatch,

    /// Handshake rejected for other reasons.
    Rejected,

    /// Server is shutting down.
    ServerShuttingDown,

    /// Too many connections.
    TooManyConnections,

    /// Contract hash or canonicalizer mismatch at Tier2+ (TCK-00348).
    ///
    /// Per RFC-0020 section 3.1.3, Tier2+ sessions MUST be denied when
    /// the client's `cli_contract_hash` or canonicalizer metadata does
    /// not match the daemon's active contract.
    ContractMismatch,
}

/// Handshake message envelope.
///
/// Used for serialization to determine the message type.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HandshakeMessage {
    /// Client Hello.
    Hello(Hello),

    /// Server acknowledgment.
    HelloAck(HelloAck),

    /// Server rejection.
    HelloNack(HelloNack),
}

impl From<Hello> for HandshakeMessage {
    fn from(hello: Hello) -> Self {
        Self::Hello(hello)
    }
}

impl From<HelloAck> for HandshakeMessage {
    fn from(ack: HelloAck) -> Self {
        Self::HelloAck(ack)
    }
}

impl From<HelloNack> for HandshakeMessage {
    fn from(nack: HelloNack) -> Self {
        Self::HelloNack(nack)
    }
}

/// Parse a handshake message from raw frame bytes with size validation.
///
/// # Security
///
/// This function enforces [`MAX_HANDSHAKE_FRAME_SIZE`] to prevent
/// denial-of-service attacks during the unauthenticated handshake phase. A
/// malicious client could otherwise send a large Hello message (up to the 16MB
/// general frame limit) to consume server memory and CPU before authentication.
///
/// # Errors
///
/// Returns `Err(ProtocolError::FrameTooLarge)` if the frame exceeds the
/// handshake size limit, or `Err(ProtocolError::Serialization)` if the
/// frame cannot be parsed as a valid handshake message.
pub fn parse_handshake_message(frame: &Bytes) -> ProtocolResult<HandshakeMessage> {
    // Validate frame size before parsing
    if frame.len() > MAX_HANDSHAKE_FRAME_SIZE {
        return Err(ProtocolError::FrameTooLarge {
            size: frame.len(),
            max: MAX_HANDSHAKE_FRAME_SIZE,
        });
    }

    serde_json::from_slice(frame).map_err(|e| ProtocolError::Serialization {
        reason: format!("invalid handshake message: {e}"),
    })
}

/// Parse a Hello message from raw frame bytes with size validation.
///
/// # Security
///
/// This function enforces [`MAX_HANDSHAKE_FRAME_SIZE`] to prevent
/// denial-of-service attacks. See [`parse_handshake_message`] for details.
///
/// # Errors
///
/// Returns `Err(ProtocolError::FrameTooLarge)` if the frame exceeds the
/// handshake size limit, or `Err(ProtocolError::Serialization)` if the
/// frame cannot be parsed as a valid Hello message.
pub fn parse_hello(frame: &Bytes) -> ProtocolResult<Hello> {
    // Validate frame size before parsing
    if frame.len() > MAX_HANDSHAKE_FRAME_SIZE {
        return Err(ProtocolError::FrameTooLarge {
            size: frame.len(),
            max: MAX_HANDSHAKE_FRAME_SIZE,
        });
    }

    // Parse as envelope first to validate structure
    let envelope: HandshakeMessage =
        serde_json::from_slice(frame).map_err(|e| ProtocolError::Serialization {
            reason: format!("invalid handshake message: {e}"),
        })?;

    match envelope {
        HandshakeMessage::Hello(hello) => Ok(hello),
        _ => Err(ProtocolError::HandshakeFailed {
            reason: "expected Hello message".to_string(),
        }),
    }
}

/// Serialize a handshake message to bytes.
///
/// # Errors
///
/// Returns `Err(ProtocolError::Serialization)` if serialization fails.
pub fn serialize_handshake_message(msg: &HandshakeMessage) -> ProtocolResult<Bytes> {
    serde_json::to_vec(msg)
        .map(Bytes::from)
        .map_err(|e| ProtocolError::Serialization {
            reason: format!("failed to serialize handshake message: {e}"),
        })
}

/// Handshake state machine for the server side.
///
/// Tracks the current state of the handshake negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HandshakeState {
    /// Waiting for client Hello.
    #[default]
    AwaitingHello,

    /// Handshake completed successfully.
    Completed,

    /// Handshake failed.
    Failed,
}

/// Server-side handshake handler.
///
/// Validates client Hello messages and generates appropriate responses.
///
/// # TCK-00348: Contract Binding and Mismatch Gates
///
/// When configured with a server contract hash and risk tier, the
/// handshake evaluates the tiered mismatch policy per RFC-0020
/// section 3.1.3:
/// - Tier0/Tier1: mismatch is warned and waived (session proceeds)
/// - Tier2+: mismatch is denied (`HelloNack` with `ContractMismatch`)
///
/// # Security Note (TCK-00248)
///
/// UID-based authorization is performed at the connection accept level
/// in [`crate::protocol::ProtocolServer::accept`], NOT during handshake.
/// This ensures unauthorized peers are rejected BEFORE they can send
/// any frames, satisfying the "rejection before handshake" requirement.
#[derive(Debug)]
pub struct ServerHandshake {
    /// Server info string for `HelloAck`.
    server_info: String,

    /// Optional policy hash to include in `HelloAck`.
    policy_hash: Option<String>,

    /// Current handshake state.
    state: HandshakeState,

    /// Negotiated protocol version (after successful handshake).
    negotiated_version: Option<u32>,

    /// Server's active HSI contract manifest hash (TCK-00348).
    server_contract_hash: String,

    /// Server's supported canonicalizers (TCK-00348).
    server_canonicalizers: Vec<CanonicalizerInfo>,

    /// Daemon Ed25519 verifying key (hex-encoded) used for signed authority
    /// tokens.
    daemon_signing_public_key: String,

    /// Risk tier for mismatch policy evaluation (TCK-00348).
    risk_tier: crate::hsi_contract::RiskTier,

    /// Mismatch outcome from the last `process_hello` call (TCK-00348).
    mismatch_outcome: Option<crate::hsi_contract::MismatchOutcome>,
}

impl ServerHandshake {
    /// Create a new server handshake handler.
    #[must_use]
    pub fn new(server_info: impl Into<String>) -> Self {
        Self {
            server_info: server_info.into(),
            policy_hash: None,
            state: HandshakeState::AwaitingHello,
            negotiated_version: None,
            server_contract_hash: String::new(),
            server_canonicalizers: Vec::new(),
            daemon_signing_public_key: String::new(),
            risk_tier: crate::hsi_contract::RiskTier::Tier0,
            mismatch_outcome: None,
        }
    }

    /// Set the policy hash for the handshake.
    #[must_use]
    pub fn with_policy_hash(mut self, hash: impl Into<String>) -> Self {
        self.policy_hash = Some(hash.into());
        self
    }

    /// Set the server's active contract hash (TCK-00348).
    #[must_use]
    pub fn with_server_contract_hash(mut self, hash: impl Into<String>) -> Self {
        self.server_contract_hash = hash.into();
        self
    }

    /// Set the server's supported canonicalizers (TCK-00348).
    #[must_use]
    pub fn with_server_canonicalizers(mut self, canonicalizers: Vec<CanonicalizerInfo>) -> Self {
        self.server_canonicalizers = canonicalizers;
        self
    }

    /// Set the daemon signing public key (hex-encoded).
    #[must_use]
    pub fn with_daemon_signing_public_key(mut self, key_hex: impl Into<String>) -> Self {
        self.daemon_signing_public_key = key_hex.into();
        self
    }

    /// Set the risk tier for mismatch policy evaluation (TCK-00348).
    #[must_use]
    pub const fn with_risk_tier(mut self, tier: crate::hsi_contract::RiskTier) -> Self {
        self.risk_tier = tier;
        self
    }

    /// Process a client Hello message.
    ///
    /// Returns the response to send to the client.
    ///
    /// # TCK-00348: Contract Mismatch Gates
    ///
    /// After version validation, this method evaluates the tiered
    /// mismatch policy. If the outcome is `Denied`, the handshake
    /// returns a `HelloNack` with `ContractMismatch` error code.
    /// Admission is checked BEFORE any state transition to `Completed`.
    ///
    /// # Security Note
    ///
    /// UID authorization is performed at `accept()` time, so by the time
    /// this method is called, the peer has already been authenticated.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the handshake is not in `AwaitingHello` state.
    pub fn process_hello(&mut self, hello: &Hello) -> ProtocolResult<HandshakeMessage> {
        if self.state != HandshakeState::AwaitingHello {
            self.state = HandshakeState::Failed;
            return Err(ProtocolError::handshake_failed(
                "unexpected Hello message (already handshaked)",
            ));
        }

        // Validate protocol version BEFORE mismatch evaluation
        if !Self::is_version_compatible(hello.protocol_version) {
            self.state = HandshakeState::Failed;
            return Ok(HelloNack::version_mismatch(hello.protocol_version).into());
        }

        // TCK-00348 BLOCKER-2: Validate untrusted contract binding fields
        // BEFORE mismatch evaluation. Reject over-limit payloads fail-closed.
        let binding = crate::hsi_contract::ContractBinding {
            cli_contract_hash: hello.cli_contract_hash.clone(),
            canonicalizers: hello.canonicalizers.clone(),
        };
        if let Err(e) = crate::hsi_contract::validate_contract_binding(&binding) {
            self.state = HandshakeState::Failed;
            return Ok(
                HelloNack::rejected(format!("contract binding validation failed: {e}")).into(),
            );
        }

        // TCK-00348: Evaluate contract mismatch policy.
        // Check admission BEFORE mutating state to Completed (transactional
        // state mutation pattern).
        let outcome = crate::hsi_contract::evaluate_mismatch_policy(
            &hello.cli_contract_hash,
            &self.server_contract_hash,
            &hello.canonicalizers,
            &self.server_canonicalizers,
            self.risk_tier,
        );

        // Fail-closed: deny on mismatch for Tier2+
        if outcome.is_denied() {
            self.state = HandshakeState::Failed;
            let detail =
                if let crate::hsi_contract::MismatchOutcome::Denied { detail, .. } = &outcome {
                    detail.clone()
                } else {
                    "contract mismatch denied".to_string()
                };
            self.mismatch_outcome = Some(outcome);
            return Ok(HelloNack::contract_mismatch(detail).into());
        }

        let mismatch_waived = outcome.is_waived();
        self.mismatch_outcome = Some(outcome);

        // Handshake successful (admission passed)
        self.state = HandshakeState::Completed;
        self.negotiated_version = Some(hello.protocol_version.min(PROTOCOL_VERSION));

        let mut ack = HelloAck::new(&self.server_info);
        if let Some(ref hash) = self.policy_hash {
            ack = ack.with_policy_hash(hash);
        }
        // TCK-00348: Include contract binding in HelloAck
        if !self.server_contract_hash.is_empty() {
            ack = ack.with_server_contract_hash(&self.server_contract_hash);
        }
        if !self.server_canonicalizers.is_empty() {
            ack = ack.with_server_canonicalizers(self.server_canonicalizers.clone());
        }
        if !self.daemon_signing_public_key.is_empty() {
            ack = ack.with_daemon_signing_public_key(&self.daemon_signing_public_key);
        }
        if mismatch_waived {
            ack = ack.with_contract_mismatch_waived(true);
        }

        Ok(ack.into())
    }

    /// Check if a client protocol version is compatible.
    ///
    /// Currently only version 1 is supported (exact match).
    /// Future versions may implement backward compatibility.
    const fn is_version_compatible(client_version: u32) -> bool {
        // For now, only exact version match is supported
        // Future: could implement major/minor version compatibility
        client_version == PROTOCOL_VERSION
    }

    /// Returns the current handshake state.
    #[must_use]
    pub const fn state(&self) -> HandshakeState {
        self.state
    }

    /// Returns the negotiated protocol version if handshake completed.
    #[must_use]
    pub const fn negotiated_version(&self) -> Option<u32> {
        self.negotiated_version
    }

    /// Returns `true` if the handshake completed successfully.
    #[must_use]
    pub const fn is_completed(&self) -> bool {
        matches!(self.state, HandshakeState::Completed)
    }

    /// Returns the mismatch outcome from the last `process_hello` call
    /// (TCK-00348).
    ///
    /// This is used by the caller to emit mismatch counters with
    /// risk-tier labels after the handshake completes.
    #[must_use]
    pub const fn mismatch_outcome(&self) -> Option<&crate::hsi_contract::MismatchOutcome> {
        self.mismatch_outcome.as_ref()
    }
}

/// Client-side handshake handler.
///
/// Generates Hello messages and processes server responses.
#[derive(Debug)]
pub struct ClientHandshake {
    /// Client info string for Hello.
    client_info: String,

    /// Current handshake state.
    state: HandshakeState,

    /// Negotiated protocol version (after successful handshake).
    negotiated_version: Option<u32>,

    /// Server info from `HelloAck`.
    server_info: Option<String>,
    /// Daemon signing public key (hex-encoded) from `HelloAck`.
    daemon_signing_public_key: Option<String>,
}

impl ClientHandshake {
    /// Create a new client handshake handler.
    #[must_use]
    pub fn new(client_info: impl Into<String>) -> Self {
        Self {
            client_info: client_info.into(),
            state: HandshakeState::AwaitingHello,
            negotiated_version: None,
            server_info: None,
            daemon_signing_public_key: None,
        }
    }

    /// Generate the Hello message to send to the server.
    #[must_use]
    pub fn create_hello(&self) -> Hello {
        Hello::new(&self.client_info)
    }

    /// Process the server's response to our Hello.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the server rejected the handshake.
    pub fn process_response(&mut self, response: HandshakeMessage) -> ProtocolResult<()> {
        match response {
            HandshakeMessage::HelloAck(ack) => {
                self.state = HandshakeState::Completed;
                self.negotiated_version = Some(ack.protocol_version);
                self.server_info = Some(ack.server_info);
                self.daemon_signing_public_key = (!ack.daemon_signing_public_key.is_empty())
                    .then_some(ack.daemon_signing_public_key);
                Ok(())
            },
            HandshakeMessage::HelloNack(nack) => {
                self.state = HandshakeState::Failed;
                match nack.error_code {
                    HandshakeErrorCode::VersionMismatch => {
                        Err(ProtocolError::version_mismatch(PROTOCOL_VERSION))
                    },
                    _ => Err(ProtocolError::handshake_failed(nack.message)),
                }
            },
            HandshakeMessage::Hello(_) => {
                self.state = HandshakeState::Failed;
                Err(ProtocolError::handshake_failed(
                    "received Hello instead of HelloAck/HelloNack",
                ))
            },
        }
    }

    /// Returns the current handshake state.
    #[must_use]
    pub const fn state(&self) -> HandshakeState {
        self.state
    }

    /// Returns the negotiated protocol version if handshake completed.
    #[must_use]
    pub const fn negotiated_version(&self) -> Option<u32> {
        self.negotiated_version
    }

    /// Returns the server info if handshake completed.
    #[must_use]
    pub fn server_info(&self) -> Option<&str> {
        self.server_info.as_deref()
    }

    /// Returns the daemon signing public key (hex-encoded), if provided.
    #[must_use]
    pub fn daemon_signing_public_key(&self) -> Option<&str> {
        self.daemon_signing_public_key.as_deref()
    }

    /// Returns `true` if the handshake completed successfully.
    #[must_use]
    pub const fn is_completed(&self) -> bool {
        matches!(self.state, HandshakeState::Completed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hello_serialization() {
        let hello = Hello::new("test-client/1.0");
        let json = serde_json::to_string(&hello).unwrap();

        assert!(json.contains("protocol_version"));
        assert!(json.contains("test-client/1.0"));

        let parsed: Hello = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, hello);
    }

    #[test]
    fn test_hello_ack_serialization() {
        let ack = HelloAck::new("test-server/1.0").with_policy_hash("abc123");

        let json = serde_json::to_string(&ack).unwrap();
        assert!(json.contains("policy_hash"));
        assert!(json.contains("abc123"));

        let parsed: HelloAck = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, ack);
    }

    #[test]
    fn test_hello_nack_serialization() {
        let nack = HelloNack::version_mismatch(99);
        let json = serde_json::to_string(&nack).unwrap();

        assert!(json.contains("version_mismatch"));
        assert!(json.contains(&PROTOCOL_VERSION.to_string()));

        let parsed: HelloNack = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, nack);
    }

    #[test]
    fn test_handshake_message_envelope() {
        let hello: HandshakeMessage = Hello::new("client").into();
        let json = serde_json::to_string(&hello).unwrap();

        assert!(json.contains(r#""type":"hello""#));

        let parsed: HandshakeMessage = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, HandshakeMessage::Hello(_)));
    }

    #[test]
    fn test_server_handshake_success() {
        let mut server = ServerHandshake::new("daemon/1.0");
        assert_eq!(server.state(), HandshakeState::AwaitingHello);

        let hello = Hello::new("cli/1.0");
        let response = server.process_hello(&hello).unwrap();

        assert!(matches!(response, HandshakeMessage::HelloAck(_)));
        assert!(server.is_completed());
        assert_eq!(server.negotiated_version(), Some(PROTOCOL_VERSION));
    }

    #[test]
    fn test_server_handshake_version_mismatch() {
        let mut server = ServerHandshake::new("daemon/1.0");

        let hello = Hello::with_version(99, "cli/1.0");
        let response = server.process_hello(&hello).unwrap();

        assert!(matches!(response, HandshakeMessage::HelloNack(_)));
        assert_eq!(server.state(), HandshakeState::Failed);
    }

    #[test]
    fn test_server_handshake_duplicate_hello() {
        let mut server = ServerHandshake::new("daemon/1.0");

        // First hello succeeds
        let hello1 = Hello::new("cli/1.0");
        server.process_hello(&hello1).unwrap();

        // Second hello fails
        let hello2 = Hello::new("cli/1.0");
        let result = server.process_hello(&hello2);
        assert!(result.is_err());
    }

    #[test]
    fn test_client_handshake_success() {
        let mut client = ClientHandshake::new("cli/1.0");

        let hello = client.create_hello();
        assert_eq!(hello.protocol_version, PROTOCOL_VERSION);
        assert_eq!(hello.client_info, "cli/1.0");

        let ack = HelloAck::new("daemon/1.0");
        client.process_response(ack.into()).unwrap();

        assert!(client.is_completed());
        assert_eq!(client.server_info(), Some("daemon/1.0"));
    }

    #[test]
    fn test_client_handshake_rejected() {
        let mut client = ClientHandshake::new("cli/1.0");

        let nack = HelloNack::version_mismatch(PROTOCOL_VERSION);
        let result = client.process_response(nack.into());

        assert!(result.is_err());
        assert_eq!(client.state(), HandshakeState::Failed);
    }

    #[test]
    fn test_server_with_policy_hash() {
        let mut server = ServerHandshake::new("daemon/1.0").with_policy_hash("policy123");

        let hello = Hello::new("cli/1.0");
        let response = server.process_hello(&hello).unwrap();

        if let HandshakeMessage::HelloAck(ack) = response {
            assert_eq!(ack.policy_hash, Some("policy123".to_string()));
        } else {
            panic!("Expected HelloAck");
        }
    }

    #[test]
    fn test_hello_with_capabilities() {
        let hello = Hello::new("cli/1.0").with_capabilities(vec!["streaming".to_string()]);

        let json = serde_json::to_string(&hello).unwrap();
        assert!(json.contains("streaming"));

        let parsed: Hello = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.capabilities, vec!["streaming"]);
    }

    #[test]
    fn test_hello_accepts_unknown_fields_for_forward_compat() {
        // TCK-00348: Hello no longer uses deny_unknown_fields to allow
        // forward-compatible field additions (e.g., cli_contract_hash,
        // canonicalizers). Unknown fields are silently ignored per standard
        // serde behavior.
        let json = r#"{"protocol_version": 1, "client_info": "test", "unknown": "field"}"#;
        let result: Result<Hello, _> = serde_json::from_str(json);
        assert!(
            result.is_ok(),
            "Hello should accept unknown fields for forward compatibility"
        );
        let hello = result.unwrap();
        assert_eq!(hello.client_info, "test");
    }

    #[test]
    fn test_hello_nack_still_denies_unknown_fields() {
        // HelloNack retains deny_unknown_fields since it is server-generated
        // and should be strict.
        let json = r#"{"error_code": "rejected", "message": "test", "unknown": "field"}"#;
        let result: Result<HelloNack, _> = serde_json::from_str(json);
        assert!(result.is_err(), "HelloNack should reject unknown fields");
    }

    #[test]
    fn test_parse_handshake_message_valid() {
        let hello = Hello::new("test-client/1.0");
        let msg: HandshakeMessage = hello.into();
        let json = serde_json::to_vec(&msg).unwrap();
        let frame = Bytes::from(json);

        let parsed = parse_handshake_message(&frame).unwrap();
        assert!(matches!(parsed, HandshakeMessage::Hello(_)));
    }

    #[test]
    fn test_parse_hello_valid() {
        let hello = Hello::new("test-client/1.0");
        let msg: HandshakeMessage = hello.into();
        let json = serde_json::to_vec(&msg).unwrap();
        let frame = Bytes::from(json);

        let parsed = parse_hello(&frame).unwrap();
        assert_eq!(parsed.client_info, "test-client/1.0");
    }

    #[test]
    fn test_parse_hello_wrong_type() {
        // Sending HelloAck when Hello expected
        let ack = HelloAck::new("server/1.0");
        let msg: HandshakeMessage = ack.into();
        let json = serde_json::to_vec(&msg).unwrap();
        let frame = Bytes::from(json);

        let result = parse_hello(&frame);
        assert!(result.is_err());
        assert!(matches!(result, Err(ProtocolError::HandshakeFailed { .. })));
    }

    /// Test that oversized Hello messages are rejected during handshake.
    ///
    /// This verifies the security fix for the excessive handshake resource
    /// limit. A malicious client should not be able to send a 1MB Hello
    /// message.
    #[test]
    fn test_parse_hello_rejects_oversized_frame() {
        // Create a frame that exceeds the handshake limit (64KB)
        // We'll create a 1MB payload as specified in the security review
        let oversized_payload = vec![b'x'; 1024 * 1024]; // 1 MB
        let frame = Bytes::from(oversized_payload);

        let result = parse_hello(&frame);
        assert!(result.is_err());

        match result {
            Err(ProtocolError::FrameTooLarge { size, max }) => {
                assert_eq!(size, 1024 * 1024);
                assert_eq!(max, MAX_HANDSHAKE_FRAME_SIZE);
            },
            other => panic!("Expected FrameTooLarge error, got: {other:?}"),
        }
    }

    /// Test that frames at exactly the handshake limit are accepted.
    #[test]
    fn test_parse_handshake_message_at_limit() {
        // Create a valid-ish JSON that's at the limit
        // We pad with whitespace which is valid JSON
        let hello = Hello::new("cli/1.0");
        let msg: HandshakeMessage = hello.into();
        let mut json = serde_json::to_vec(&msg).unwrap();

        // Pad to exactly the limit with spaces (valid JSON whitespace)
        while json.len() < MAX_HANDSHAKE_FRAME_SIZE {
            json.push(b' ');
        }

        let frame = Bytes::from(json);
        assert_eq!(frame.len(), MAX_HANDSHAKE_FRAME_SIZE);

        // Should succeed at exactly the limit
        let result = parse_handshake_message(&frame);
        assert!(result.is_ok());
    }

    /// Test that frames exceeding the handshake limit by 1 byte are rejected.
    #[test]
    fn test_parse_handshake_message_over_limit() {
        // Create a frame 1 byte over the limit
        let oversized_payload = vec![b'x'; MAX_HANDSHAKE_FRAME_SIZE + 1];
        let frame = Bytes::from(oversized_payload);

        let result = parse_handshake_message(&frame);
        assert!(matches!(
            result,
            Err(ProtocolError::FrameTooLarge { size, max })
            if size == MAX_HANDSHAKE_FRAME_SIZE + 1 && max == MAX_HANDSHAKE_FRAME_SIZE
        ));
    }

    #[test]
    fn test_serialize_handshake_message() {
        let hello = Hello::new("test-client/1.0");
        let msg: HandshakeMessage = hello.into();

        let bytes = serialize_handshake_message(&msg).unwrap();
        assert!(!bytes.is_empty());

        // Verify it can be parsed back
        let parsed = parse_handshake_message(&bytes).unwrap();
        assert!(matches!(parsed, HandshakeMessage::Hello(_)));
    }

    // NOTE: UID authorization tests have been moved to server.rs tests
    // since UID validation now occurs at accept() time, before handshake.
    // See `test_uid_constant_time_comparison` (verifies rejection logic) and
    // `test_accept_extracts_and_validates_credentials` (verifies success path)
    // in the server module tests.
    //
    // Integration-level UID rejection tests are not feasible because both
    // client and server run as the same process UID, and SO_PEERCRED cannot
    // be spoofed.

    // =========================================================================
    // TCK-00348: Contract binding and mismatch gate tests
    // =========================================================================

    #[test]
    fn test_hello_with_contract_hash() {
        let hello = Hello::new("cli/1.0").with_contract_hash("blake3:aabbccdd");
        assert_eq!(hello.cli_contract_hash, "blake3:aabbccdd");

        let json = serde_json::to_string(&hello).unwrap();
        assert!(json.contains("cli_contract_hash"));
        assert!(json.contains("blake3:aabbccdd"));

        let parsed: Hello = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.cli_contract_hash, "blake3:aabbccdd");
    }

    #[test]
    fn test_hello_without_contract_hash_omits_field() {
        let hello = Hello::new("cli/1.0");
        assert!(hello.cli_contract_hash.is_empty());

        let json = serde_json::to_string(&hello).unwrap();
        // skip_serializing_if = "String::is_empty" should omit the field
        assert!(
            !json.contains("cli_contract_hash"),
            "empty cli_contract_hash should be omitted from JSON"
        );
    }

    #[test]
    fn test_hello_with_canonicalizers() {
        let hello = Hello::new("cli/1.0").with_canonicalizers(vec![CanonicalizerInfo {
            id: "apm2.canonical.v1".to_string(),
            version: 1,
        }]);
        assert_eq!(hello.canonicalizers.len(), 1);
        assert_eq!(hello.canonicalizers[0].id, "apm2.canonical.v1");

        let json = serde_json::to_string(&hello).unwrap();
        assert!(json.contains("canonicalizers"));
        assert!(json.contains("apm2.canonical.v1"));
    }

    #[test]
    fn test_hello_without_canonicalizers_omits_field() {
        let hello = Hello::new("cli/1.0");
        assert!(hello.canonicalizers.is_empty());

        let json = serde_json::to_string(&hello).unwrap();
        assert!(
            !json.contains("canonicalizers"),
            "empty canonicalizers should be omitted from JSON"
        );
    }

    #[test]
    fn test_hello_ack_with_contract_binding_fields() {
        let ack = HelloAck::new("daemon/1.0")
            .with_server_contract_hash("blake3:server_hash")
            .with_server_canonicalizers(vec![CanonicalizerInfo {
                id: "apm2.canonical.v1".to_string(),
                version: 1,
            }])
            .with_contract_mismatch_waived(true);

        assert_eq!(ack.server_contract_hash, "blake3:server_hash");
        assert_eq!(ack.server_canonicalizers.len(), 1);
        assert!(ack.contract_mismatch_waived);

        let json = serde_json::to_string(&ack).unwrap();
        assert!(json.contains("server_contract_hash"));
        assert!(json.contains("contract_mismatch_waived"));

        let parsed: HelloAck = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, ack);
    }

    #[test]
    fn test_hello_ack_omits_empty_contract_fields() {
        let ack = HelloAck::new("daemon/1.0");
        let json = serde_json::to_string(&ack).unwrap();

        assert!(
            !json.contains("server_contract_hash"),
            "empty server_contract_hash should be omitted"
        );
        assert!(
            !json.contains("server_canonicalizers"),
            "empty server_canonicalizers should be omitted"
        );
        assert!(
            !json.contains("contract_mismatch_waived"),
            "false contract_mismatch_waived should be omitted"
        );
    }

    #[test]
    fn test_hello_nack_contract_mismatch() {
        let nack = HelloNack::contract_mismatch("contract hash mismatch at Tier2");
        assert_eq!(nack.error_code, HandshakeErrorCode::ContractMismatch);
        assert!(nack.message.contains("contract hash mismatch"));
        assert_eq!(nack.server_version, Some(PROTOCOL_VERSION));

        let json = serde_json::to_string(&nack).unwrap();
        assert!(json.contains("contract_mismatch"));
    }

    #[test]
    fn test_contract_mismatch_error_code_serialization() {
        let code = HandshakeErrorCode::ContractMismatch;
        let json = serde_json::to_string(&code).unwrap();
        // HandshakeErrorCode uses rename_all = "snake_case"
        assert_eq!(json, "\"contract_mismatch\"");

        let parsed: HandshakeErrorCode = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, HandshakeErrorCode::ContractMismatch);
    }

    #[test]
    fn test_server_handshake_contract_match_tier2() {
        // When client and server hashes match, handshake succeeds even at Tier2.
        let mut server = ServerHandshake::new("daemon/1.0")
            .with_server_contract_hash("blake3:same_hash")
            .with_risk_tier(crate::hsi_contract::RiskTier::Tier2);

        let hello = Hello::new("cli/1.0").with_contract_hash("blake3:same_hash");
        let response = server.process_hello(&hello).unwrap();

        assert!(matches!(response, HandshakeMessage::HelloAck(_)));
        assert!(server.is_completed());

        // Mismatch outcome should be Match
        let outcome = server.mismatch_outcome().unwrap();
        assert!(outcome.is_match());
    }

    #[test]
    fn test_server_handshake_contract_mismatch_tier0_waived() {
        // Tier0 mismatches are waived - handshake succeeds with mismatch_waived flag.
        let mut server = ServerHandshake::new("daemon/1.0")
            .with_server_contract_hash("blake3:server_hash")
            .with_risk_tier(crate::hsi_contract::RiskTier::Tier0);

        let hello = Hello::new("cli/1.0").with_contract_hash("blake3:client_hash");
        let response = server.process_hello(&hello).unwrap();

        if let HandshakeMessage::HelloAck(ack) = response {
            assert!(
                ack.contract_mismatch_waived,
                "Tier0 mismatch should set waived flag"
            );
            assert_eq!(ack.server_contract_hash, "blake3:server_hash");
        } else {
            panic!("Expected HelloAck for Tier0 mismatch waiver");
        }

        assert!(server.is_completed());

        let outcome = server.mismatch_outcome().unwrap();
        assert!(outcome.is_waived());
        assert_eq!(outcome.tier_label(), Some("tier0"));
    }

    #[test]
    fn test_server_handshake_contract_mismatch_tier2_denied() {
        // Tier2 mismatches MUST be denied (fail-closed).
        let mut server = ServerHandshake::new("daemon/1.0")
            .with_server_contract_hash("blake3:server_hash")
            .with_risk_tier(crate::hsi_contract::RiskTier::Tier2);

        let hello = Hello::new("cli/1.0").with_contract_hash("blake3:client_hash");
        let response = server.process_hello(&hello).unwrap();

        if let HandshakeMessage::HelloNack(nack) = response {
            assert_eq!(nack.error_code, HandshakeErrorCode::ContractMismatch);
            assert!(nack.message.contains("contract hash mismatch"));
        } else {
            panic!("Expected HelloNack for Tier2 mismatch denial");
        }

        assert_eq!(server.state(), HandshakeState::Failed);

        let outcome = server.mismatch_outcome().unwrap();
        assert!(outcome.is_denied());
        assert_eq!(outcome.tier_label(), Some("tier2"));
    }

    #[test]
    fn test_server_handshake_missing_client_hash_tier2_denied() {
        // Tier2+ with missing client hash: fail-closed.
        let mut server = ServerHandshake::new("daemon/1.0")
            .with_server_contract_hash("blake3:server_hash")
            .with_risk_tier(crate::hsi_contract::RiskTier::Tier2);

        let hello = Hello::new("cli/1.0"); // no contract hash
        let response = server.process_hello(&hello).unwrap();

        assert!(
            matches!(response, HandshakeMessage::HelloNack(ref nack) if nack.error_code == HandshakeErrorCode::ContractMismatch),
            "Missing client hash at Tier2 should be denied"
        );
    }

    #[test]
    fn test_server_handshake_missing_client_hash_tier0_allowed() {
        // Tier0 with missing client hash: acceptable (backward compat).
        let mut server = ServerHandshake::new("daemon/1.0")
            .with_server_contract_hash("blake3:server_hash")
            .with_risk_tier(crate::hsi_contract::RiskTier::Tier0);

        let hello = Hello::new("cli/1.0"); // no contract hash
        let response = server.process_hello(&hello).unwrap();

        assert!(
            matches!(response, HandshakeMessage::HelloAck(_)),
            "Missing client hash at Tier0 should be allowed"
        );
        assert!(server.is_completed());
    }

    #[test]
    fn test_server_handshake_version_mismatch_takes_precedence_over_contract() {
        // Version mismatch should fail BEFORE contract evaluation.
        let mut server = ServerHandshake::new("daemon/1.0")
            .with_server_contract_hash("blake3:server_hash")
            .with_risk_tier(crate::hsi_contract::RiskTier::Tier4);

        let hello = Hello::with_version(99, "cli/1.0").with_contract_hash("blake3:different");
        let response = server.process_hello(&hello).unwrap();

        if let HandshakeMessage::HelloNack(nack) = response {
            assert_eq!(
                nack.error_code,
                HandshakeErrorCode::VersionMismatch,
                "Version mismatch should take precedence over contract mismatch"
            );
        } else {
            panic!("Expected HelloNack for version mismatch");
        }
    }

    #[test]
    fn test_server_handshake_hello_ack_includes_server_canonicalizers() {
        let server_canons = vec![CanonicalizerInfo {
            id: "apm2.canonical.v1".to_string(),
            version: 1,
        }];

        let mut server = ServerHandshake::new("daemon/1.0")
            .with_server_contract_hash("blake3:hash")
            .with_server_canonicalizers(server_canons.clone())
            .with_risk_tier(crate::hsi_contract::RiskTier::Tier0);

        let hello = Hello::new("cli/1.0")
            .with_contract_hash("blake3:hash")
            .with_canonicalizers(vec![CanonicalizerInfo {
                id: "apm2.canonical.v1".to_string(),
                version: 1,
            }]);
        let response = server.process_hello(&hello).unwrap();

        if let HandshakeMessage::HelloAck(ack) = response {
            assert_eq!(ack.server_canonicalizers, server_canons);
            assert!(!ack.contract_mismatch_waived);
        } else {
            panic!("Expected HelloAck");
        }
    }

    #[test]
    fn test_server_handshake_no_contract_config_succeeds() {
        // When server has no contract hash configured, handshake succeeds.
        let mut server = ServerHandshake::new("daemon/1.0");
        // No with_server_contract_hash called — defaults to empty

        let hello = Hello::new("cli/1.0").with_contract_hash("blake3:anything");
        let response = server.process_hello(&hello).unwrap();

        // Empty server hash matches empty (both sides empty is Match),
        // but client has a hash. The mismatch function treats
        // non-empty client vs empty server as a mismatch check:
        // client_hash is non-empty, server_hash is empty, so it's a mismatch.
        // But at Tier0 (default), it should be waived.
        assert!(matches!(response, HandshakeMessage::HelloAck(_)));
        assert!(server.is_completed());
    }

    #[test]
    fn test_backward_compat_hello_without_contract_fields() {
        // A Hello from an old client without contract fields should
        // deserialize successfully.
        let json = r#"{"type":"hello","protocol_version":1,"client_info":"old-cli/0.1"}"#;
        let parsed: HandshakeMessage = serde_json::from_str(json).unwrap();

        if let HandshakeMessage::Hello(hello) = parsed {
            assert_eq!(hello.client_info, "old-cli/0.1");
            assert!(hello.cli_contract_hash.is_empty());
            assert!(hello.canonicalizers.is_empty());
        } else {
            panic!("Expected Hello message");
        }
    }

    #[test]
    fn test_backward_compat_hello_ack_without_contract_fields() {
        // A HelloAck from an old server without contract fields should
        // deserialize successfully.
        let json = r#"{"type":"hello_ack","protocol_version":1,"server_info":"old-daemon/0.1"}"#;
        let parsed: HandshakeMessage = serde_json::from_str(json).unwrap();

        if let HandshakeMessage::HelloAck(ack) = parsed {
            assert_eq!(ack.server_info, "old-daemon/0.1");
            assert!(ack.server_contract_hash.is_empty());
            assert!(ack.server_canonicalizers.is_empty());
            assert!(!ack.contract_mismatch_waived);
        } else {
            panic!("Expected HelloAck message");
        }
    }

    /// TCK-00348 BLOCKER-2: Validate contract binding bounds in
    /// `process_hello`. Over-limit contract hash must be rejected before
    /// mismatch evaluation.
    #[test]
    fn test_process_hello_rejects_oversized_contract_hash() {
        let mut server =
            ServerHandshake::new("daemon/1.0").with_risk_tier(crate::hsi_contract::RiskTier::Tier0);

        let hello = Hello::new("cli/1.0").with_contract_hash("x".repeat(200)); // exceeds MAX_CONTRACT_HASH_LEN (128)

        let response = server.process_hello(&hello).unwrap();
        assert!(
            matches!(response, HandshakeMessage::HelloNack(ref nack) if nack.error_code == HandshakeErrorCode::Rejected),
            "Over-limit contract hash should be rejected"
        );
        assert_eq!(server.state(), HandshakeState::Failed);
    }

    /// TCK-00348 BLOCKER-2: Too many canonicalizer entries must be rejected.
    #[test]
    fn test_process_hello_rejects_too_many_canonicalizers() {
        let mut server =
            ServerHandshake::new("daemon/1.0").with_risk_tier(crate::hsi_contract::RiskTier::Tier0);

        let canons: Vec<CanonicalizerInfo> = (0
            ..=crate::hsi_contract::handshake_binding::MAX_CANONICALIZER_ENTRIES)
            .map(|i| CanonicalizerInfo {
                id: format!("canon.{i}"),
                version: 1,
            })
            .collect();

        let hello = Hello::new("cli/1.0").with_canonicalizers(canons);

        let response = server.process_hello(&hello).unwrap();
        assert!(
            matches!(response, HandshakeMessage::HelloNack(ref nack) if nack.error_code == HandshakeErrorCode::Rejected),
            "Too many canonicalizers should be rejected"
        );
        assert_eq!(server.state(), HandshakeState::Failed);
    }
}
