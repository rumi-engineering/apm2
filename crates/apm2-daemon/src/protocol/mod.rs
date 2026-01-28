//! UDS protocol and framing module.
//!
//! This module handles Unix domain socket protocol implementation,
//! including message framing, handshake negotiation, and connection
//! lifecycle management.
//!
//! # Architecture
//!
//! The protocol stack is organized in layers:
//!
//! ```text
//! ┌─────────────────────────────────────────┐
//! │           Application Messages           │  (TCK-00158: protobuf)
//! ├─────────────────────────────────────────┤
//! │              Handshake                   │  Hello/HelloAck
//! ├─────────────────────────────────────────┤
//! │               Framing                    │  Length-prefixed
//! ├─────────────────────────────────────────┤
//! │            UDS Transport                 │  Unix socket
//! └─────────────────────────────────────────┘
//! ```
//!
//! # Module Overview
//!
//! - [`error`]: Protocol error types ([`ProtocolError`], [`ProtocolResult`])
//! - [`framing`]: Length-prefixed frame codec ([`FrameCodec`])
//! - [`handshake`]: Version negotiation ([`Hello`], [`HelloAck`],
//!   [`ServerHandshake`])
//! - [`server`]: UDS server ([`ProtocolServer`], [`Connection`])
//!
//! # Wire Format
//!
//! Per AD-DAEMON-002, messages use length-prefixed binary framing:
//!
//! ```text
//! +----------------------------+------------------+
//! | Length (4 bytes, BE)       | Payload          |
//! +----------------------------+------------------+
//! ```
//!
//! - Maximum frame size: 16 MiB
//! - Length prefix: 4-byte big-endian unsigned integer
//! - Payload: Binary data (protobuf in future tickets)
//!
//! # Usage Example
//!
//! ## Server
//!
//! ```ignore
//! use apm2_daemon::protocol::{ProtocolServer, ServerConfig, ServerHandshake};
//! use futures::{SinkExt, StreamExt};
//!
//! let config = ServerConfig::default();
//! let server = ProtocolServer::bind(config).await?;
//!
//! loop {
//!     let (mut conn, _permit) = server.accept().await?;
//!     tokio::spawn(async move {
//!         // Handle connection
//!         while let Some(Ok(frame)) = conn.framed().next().await {
//!             // Process frame
//!         }
//!     });
//! }
//! ```
//!
//! ## Client
//!
//! ```ignore
//! use apm2_daemon::protocol::{connect, default_socket_path, ClientHandshake};
//! use futures::{SinkExt, StreamExt};
//!
//! let mut conn = connect(default_socket_path()).await?;
//! conn.framed().send(payload).await?;
//! let response = conn.framed().next().await;
//! ```
//!
//! # Security Considerations
//!
//! - Frame size validated BEFORE allocation (prevents denial of service)
//! - Socket created with restrictive permissions (0600)
//! - Handshake required before message exchange
//! - Version mismatch terminates connection

pub mod error;
pub mod framing;
pub mod handshake;
pub mod server;

// Re-export commonly used types at module level
pub use error::{
    MAX_FRAME_SIZE, MAX_HANDSHAKE_FRAME_SIZE, PROTOCOL_VERSION, ProtocolError, ProtocolResult,
};
pub use framing::FrameCodec;
pub use handshake::{
    ClientHandshake, HandshakeErrorCode, HandshakeMessage, HandshakeState, Hello, HelloAck,
    HelloNack, ServerHandshake, parse_handshake_message, parse_hello, serialize_handshake_message,
};
pub use server::{
    Connection, ConnectionPermit, ProtocolServer, ServerConfig, connect, default_socket_path,
};
