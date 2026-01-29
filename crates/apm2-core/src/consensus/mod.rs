//! Consensus layer for distributed coordination.
//!
//! This module implements peer discovery and mutual TLS networking for the
//! APM2 distributed consensus layer. It provides:
//!
//! - **Network Transport**: TLS 1.3 mutual authentication with connection
//!   pooling
//! - **Peer Discovery**: Bootstrap node connection and peer list management
//! - **Traffic Analysis Mitigation**: Fixed-size control plane frame padding
//!
//! # Security Properties
//!
//! - All connections use TLS 1.3 with mutual authentication (INV-0015)
//! - Certificates are validated against a network CA (INV-0016)
//! - Control plane frames are padded to fixed size (INV-0017)
//! - Connection pooling prevents traffic analysis (INV-0019)
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

pub mod discovery;
pub mod network;

pub use discovery::{
    DiscoveryConfig, DiscoveryError, PeerDiscovery, PeerInfo, PeerList, PeerStatus,
};
pub use network::{
    CONTROL_FRAME_SIZE, Connection, ConnectionPool, ControlFrame, Network, NetworkConfig,
    NetworkError, PooledConnection, TlsConfig, TlsConfigBuilder, apply_dispatch_jitter,
};
