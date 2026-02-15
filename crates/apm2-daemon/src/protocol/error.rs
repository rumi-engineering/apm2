//! Protocol error types for the UDS protocol layer.
//!
//! This module provides structured error types for protocol-level failures,
//! enabling callers to distinguish between different failure modes.
//!
//! # Error Hierarchy
//!
//! - [`ProtocolError`]: Top-level error for all protocol operations
//! - Variants cover framing, handshake, and I/O failures
//!
//! # Security Considerations
//!
//! Per [CTR-0703], error types are structured to enable caller branching
//! on specific failure modes without exposing internal details that could
//! aid attackers.

use std::io;

use apm2_core::fac::broker_rate_limits::ControlPlaneDenialReceipt;
use thiserror::Error;

/// Maximum frame size in bytes (16 MiB).
///
/// Per AD-DAEMON-002, frames are capped at 16 MiB to prevent
/// memory exhaustion attacks.
pub const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;

/// Maximum handshake frame size in bytes (64 KiB).
///
/// Handshake messages (Hello/HelloAck/HelloNack) have a stricter limit
/// than general protocol frames to prevent denial-of-service attacks during the
/// unauthenticated handshake phase. This limit prevents a malicious
/// client from consuming excessive memory and CPU (JSON parsing)
/// before completing authentication.
pub const MAX_HANDSHAKE_FRAME_SIZE: usize = 64 * 1024;

/// Protocol version supported by this implementation.
///
/// Version negotiation occurs during handshake. Clients with
/// incompatible versions are rejected with [`ProtocolError::VersionMismatch`].
pub const PROTOCOL_VERSION: u32 = 1;

/// Protocol errors for the UDS protocol layer.
///
/// # Error Classification
///
/// - **Framing errors**: Issues with frame encoding/decoding
/// - **Handshake errors**: Version negotiation failures
/// - **Connection errors**: I/O and connection lifecycle issues
///
/// # Contract: CTR-0703
///
/// All error variants include actionable context for caller branching.
#[derive(Debug, Error)]
pub enum ProtocolError {
    /// Frame exceeds maximum allowed size.
    ///
    /// The frame length prefix indicates a size larger than [`MAX_FRAME_SIZE`].
    /// This is detected BEFORE allocation to prevent memory exhaustion.
    #[error("frame too large: {size} bytes exceeds maximum {max} bytes")]
    FrameTooLarge {
        /// Actual frame size from length prefix.
        size: usize,
        /// Maximum allowed frame size.
        max: usize,
    },

    /// Frame data is invalid or corrupted.
    ///
    /// The frame structure does not match the expected format.
    #[error("invalid frame: {reason}")]
    InvalidFrame {
        /// Description of the framing error.
        reason: String,
    },

    /// Protocol version mismatch during handshake.
    ///
    /// The client requested a protocol version that this server cannot support.
    #[error("version mismatch: client version {client_version}, server version {server_version}")]
    VersionMismatch {
        /// Version requested by client.
        client_version: u32,
        /// Version supported by server.
        server_version: u32,
    },

    /// Handshake protocol failure.
    ///
    /// The handshake sequence did not complete successfully.
    #[error("handshake failed: {reason}")]
    HandshakeFailed {
        /// Description of the handshake failure.
        reason: String,
    },

    /// Connection was closed unexpectedly.
    ///
    /// The peer closed the connection before the operation completed.
    #[error("connection closed")]
    ConnectionClosed,

    /// Timeout waiting for a response or operation.
    #[error("operation timed out after {duration_ms} ms")]
    Timeout {
        /// Duration in milliseconds before timeout.
        duration_ms: u64,
    },

    /// Underlying I/O error.
    ///
    /// Wraps standard I/O errors from the transport layer.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// Serialization or deserialization error.
    ///
    /// The message payload could not be serialized or deserialized.
    #[error("serialization error: {reason}")]
    Serialization {
        /// Description of the serialization failure.
        reason: String,
    },

    /// Control-plane budget exceeded (TCK-00568).
    ///
    /// The requested operation would exceed a configured control-plane rate
    /// limit or quota. Carries a structured [`ControlPlaneDenialReceipt`]
    /// with machine-readable evidence of the exceeded dimension, current
    /// usage, and the configured limit (INV-CPRL-003).
    #[error("control-plane budget exceeded: {reason}")]
    BudgetExceeded {
        /// Human-readable denial reason.
        reason: String,
        /// Structured denial receipt for audit (INV-CPRL-003).
        receipt: ControlPlaneDenialReceipt,
    },
}

impl ProtocolError {
    /// Create a frame too large error.
    #[must_use]
    pub const fn frame_too_large(size: usize, max: usize) -> Self {
        Self::FrameTooLarge { size, max }
    }

    /// Create a version mismatch error.
    #[must_use]
    pub const fn version_mismatch(client_version: u32) -> Self {
        Self::VersionMismatch {
            client_version,
            server_version: PROTOCOL_VERSION,
        }
    }

    /// Create a timeout error.
    #[must_use]
    pub const fn timeout(duration_ms: u64) -> Self {
        Self::Timeout { duration_ms }
    }

    /// Create a handshake failed error.
    #[must_use]
    pub fn handshake_failed(reason: impl Into<String>) -> Self {
        Self::HandshakeFailed {
            reason: reason.into(),
        }
    }

    /// Returns `true` if this error indicates a recoverable connection issue.
    ///
    /// Recoverable errors typically indicate transient failures where
    /// retrying the connection may succeed.
    #[must_use]
    pub const fn is_recoverable(&self) -> bool {
        matches!(self, Self::Timeout { .. } | Self::ConnectionClosed)
    }

    /// Returns `true` if this error indicates a protocol violation.
    ///
    /// Protocol violations indicate bugs in the peer implementation
    /// or malicious behavior, and the connection should be terminated.
    #[must_use]
    pub const fn is_protocol_violation(&self) -> bool {
        matches!(
            self,
            Self::FrameTooLarge { .. }
                | Self::InvalidFrame { .. }
                | Self::VersionMismatch { .. }
                | Self::HandshakeFailed { .. }
        )
    }
}

/// Result type for protocol operations.
pub type ProtocolResult<T> = Result<T, ProtocolError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_too_large_error() {
        let err = ProtocolError::frame_too_large(20_000_000, MAX_FRAME_SIZE);
        assert!(err.is_protocol_violation());
        assert!(!err.is_recoverable());

        let msg = err.to_string();
        assert!(msg.contains("20000000"));
        assert!(msg.contains(&MAX_FRAME_SIZE.to_string()));
    }

    #[test]
    fn test_version_mismatch_error() {
        let err = ProtocolError::version_mismatch(99);
        assert!(err.is_protocol_violation());

        let msg = err.to_string();
        assert!(msg.contains("99"));
        assert!(msg.contains(&PROTOCOL_VERSION.to_string()));
    }

    #[test]
    fn test_timeout_is_recoverable() {
        let err = ProtocolError::timeout(5000);
        assert!(err.is_recoverable());
        assert!(!err.is_protocol_violation());
    }

    #[test]
    fn test_io_error_wrapping() {
        let io_err = io::Error::new(io::ErrorKind::ConnectionRefused, "refused");
        let err = ProtocolError::from(io_err);
        assert!(!err.is_protocol_violation());
        assert!(!err.is_recoverable());
    }

    // Compile-time assertion: handshake limit must be less than general frame limit
    const _: () = assert!(MAX_HANDSHAKE_FRAME_SIZE < MAX_FRAME_SIZE);

    #[test]
    fn test_constants() {
        assert_eq!(MAX_FRAME_SIZE, 16 * 1024 * 1024);
        assert_eq!(MAX_HANDSHAKE_FRAME_SIZE, 64 * 1024);
        assert_eq!(PROTOCOL_VERSION, 1);
    }
}
