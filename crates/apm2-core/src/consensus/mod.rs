//! Consensus layer for distributed coordination.
//!
//! This module implements peer discovery, mutual TLS networking, and relay
//! tunneling for the APM2 distributed consensus layer. It provides:
//!
//! - **Network Transport**: TLS 1.3 mutual authentication with connection
//!   pooling
//! - **Peer Discovery**: Bootstrap node connection and peer list management
//! - **Traffic Analysis Mitigation**: Fixed-size control plane frame padding
//! - **Relay Holon**: Message routing to workers behind NAT
//! - **Reverse-TLS Tunnels**: Persistent outbound connections for NAT traversal
//!
//! # Security Properties
//!
//! - All connections use TLS 1.3 with mutual authentication (INV-0015)
//! - Certificates are validated against a network CA (INV-0016)
//! - Control plane frames are padded to fixed size (INV-0017)
//! - Connection pooling prevents traffic analysis (INV-0019)
//! - Tunnel registration requires valid mTLS identity (INV-0021)
//! - Tunnel heartbeats prevent zombie connections (INV-0022)
//! - Relay validates worker identity matches certificate CN (INV-0023)
//!
//! # Example
//!
//! ```rust,ignore
//! use apm2_core::consensus::{NetworkConfig, PeerDiscovery, TlsConfig};
//!
//! // Configure TLS with network CA
//! let tls_config = TlsConfig::builder()
//!     .ca_cert_pem(ca_cert)
//!     .node_cert_pem(node_cert)
//!     .node_key_pem(node_key)
//!     .build()?;
//!
//! // Create network with bootstrap nodes
//! let config = NetworkConfig::builder()
//!     .tls(tls_config)
//!     .bootstrap_nodes(vec!["node1.example.com:8443".parse()?])
//!     .build()?;
//!
//! let network = Network::new(config).await?;
//! network.connect_to_bootstrap().await?;
//! ```
//!
//! # Relay and Tunnel Example
//!
//! ```rust,ignore
//! use apm2_core::consensus::{ManagedTunnel, RelayConfig, RelayHolon, TlsConfig};
//!
//! // Worker: Create tunnel to relay
//! let tunnel = ManagedTunnel::new(
//!     "tunnel-123".to_string(),
//!     "worker-456".to_string(),
//!     tls_config.clone(),
//! );
//! tunnel.connect(relay_addr, "relay.example.com").await?;
//!
//! // Relay: Accept and route messages
//! let relay_config = RelayConfig::builder("relay-001", tls_config)
//!     .bind_addr("0.0.0.0:8443".parse()?)
//!     .build()?;
//! let relay = RelayHolon::new(relay_config);
//! // ... handle incoming connections
//! ```

pub mod bft;
pub mod bft_machine;
pub mod discovery;
pub mod genesis;
pub mod network;
pub mod relay;
pub mod tunnel;

// BFT consensus (Chained HotStuff)
pub use bft::{
    BftError, DEFAULT_ROUND_TIMEOUT, HotStuffConfig, HotStuffConfigBuilder, HotStuffState,
    MAX_PAYLOAD_SIZE, MAX_QC_SIGNATURES, MAX_VALIDATORS, MIN_ROUND_TIMEOUT, NewView, Phase,
    Proposal, QuorumCertificate, TIMEOUT_MULTIPLIER, ValidatorId, ValidatorInfo,
    ValidatorSignature, Vote,
};
// BFT machine driver
pub use bft_machine::{
    BftAction, BftEvent, BftMachine, MAX_BUFFERED_MESSAGES, MAX_PENDING_ACTIONS, MSG_BFT_NEW_VIEW,
    MSG_BFT_PROPOSAL, MSG_BFT_QC, MSG_BFT_VOTE,
};
pub use discovery::{
    DiscoveryConfig, DiscoveryError, PeerDiscovery, PeerInfo, PeerList, PeerStatus,
};
pub use genesis::{
    Genesis, GenesisConfig, GenesisConfigBuilder, GenesisError, GenesisValidator, InvitationToken,
    JoinRateLimiter, MAX_JOIN_ATTEMPTS_PER_MINUTE, MAX_NAMESPACE_LEN, MAX_QUORUM_SIGNATURES,
    MAX_RATE_LIMIT_SOURCES, QuorumSignature, RATE_LIMIT_WINDOW,
};
pub use network::{
    CONTROL_FRAME_SIZE, Connection, ConnectionPool, ControlFrame, Network, NetworkConfig,
    NetworkError, PooledConnection, TlsConfig, TlsConfigBuilder, apply_dispatch_jitter,
};
// Note: process_tunnel_frame is deprecated, use the internal identity-bound
// version instead
#[allow(deprecated)]
pub use relay::process_tunnel_frame;
pub use relay::{
    CLEANUP_INTERVAL, MAX_PENDING_MESSAGES, MAX_RELAY_ID_LEN, ROUTE_TIMEOUT, RelayConfig,
    RelayConfigBuilder, RelayError, RelayHolon, RelayStats, TunnelRegistry,
};
pub use tunnel::{
    HEARTBEAT_INTERVAL, HEARTBEAT_TIMEOUT, MAX_TUNNEL_ID_LEN, MAX_TUNNELS, MAX_WORKER_ID_LEN,
    MSG_TUNNEL_ACCEPT, MSG_TUNNEL_CLOSE, MSG_TUNNEL_DATA, MSG_TUNNEL_HEARTBEAT,
    MSG_TUNNEL_HEARTBEAT_ACK, MSG_TUNNEL_REGISTER, MSG_TUNNEL_REJECT, ManagedTunnel,
    REGISTRATION_TIMEOUT, TunnelAcceptResponse, TunnelData, TunnelError, TunnelHeartbeat,
    TunnelInfo, TunnelRegisterRequest, TunnelRejectResponse, TunnelState,
};
