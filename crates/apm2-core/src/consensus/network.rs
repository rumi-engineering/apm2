//! Network transport with mutual TLS for consensus.
//!
//! This module provides TLS 1.3 mutual authentication and connection pooling
//! for inter-node communication in the consensus layer.
//!
//! # Security Invariants
//!
//! - INV-0015: All connections use mutual TLS 1.3
//! - INV-0016: Certificates chain to network CA
//! - INV-0017: Control plane frames are fixed-size (1024 bytes)
//! - INV-0019: Connection pooling for reuse
//! - INV-0020: Bounded jitter on dispatch (0-50ms)

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rand::Rng;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tokio::time::timeout;
use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStream};
use zeroize::Zeroizing;

/// Fixed size for control plane frames (1024 bytes).
///
/// All control plane messages are padded to this size to prevent
/// traffic analysis attacks (INV-0017).
pub const CONTROL_FRAME_SIZE: usize = 1024;

/// Maximum payload size within a control frame.
/// Reserves 4 bytes for length prefix and 4 bytes for message type.
pub const MAX_PAYLOAD_SIZE: usize = CONTROL_FRAME_SIZE - 8;

/// Maximum connections in the pool per peer (CTR-1303: Bounded Stores).
pub const MAX_CONNECTIONS_PER_PEER: usize = 4;

/// Maximum total connections in the pool.
pub const MAX_TOTAL_CONNECTIONS: usize = 64;

/// Connection idle timeout before cleanup.
pub const CONNECTION_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Maximum dispatch jitter for traffic analysis mitigation (INV-0020).
pub const MAX_DISPATCH_JITTER_MS: u64 = 50;

/// Default timeout for TCP connection establishment.
pub const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Default timeout for TLS handshake.
pub const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Default timeout for frame send operations.
pub const FRAME_SEND_TIMEOUT: Duration = Duration::from_secs(30);

/// Default timeout for frame receive operations.
pub const FRAME_RECV_TIMEOUT: Duration = Duration::from_secs(30);

/// Errors that can occur in network operations.
#[derive(Debug, Error)]
pub enum NetworkError {
    /// TLS configuration error.
    #[error("TLS configuration error: {0}")]
    TlsConfig(String),

    /// Certificate parsing error.
    #[error("certificate error: {0}")]
    Certificate(String),

    /// Private key parsing error.
    #[error("private key error: {0}")]
    PrivateKey(String),

    /// Connection error.
    #[error("connection error: {0}")]
    Connection(#[from] io::Error),

    /// TLS handshake error.
    #[error("TLS handshake error: {0}")]
    Handshake(String),

    /// Frame too large.
    #[error("frame payload too large: {size} bytes exceeds maximum {max}")]
    FrameTooLarge {
        /// Actual payload size.
        size: usize,
        /// Maximum allowed size.
        max: usize,
    },

    /// Invalid frame format.
    #[error("invalid frame format: {0}")]
    InvalidFrame(String),

    /// Connection pool exhausted.
    #[error("connection pool exhausted: maximum {max} connections reached")]
    PoolExhausted {
        /// Maximum allowed connections.
        max: usize,
    },

    /// Peer not found in pool.
    #[error("peer not found: {peer}")]
    PeerNotFound {
        /// The peer identifier.
        peer: String,
    },

    /// Certificate validation failed.
    #[error("certificate validation failed: {0}")]
    CertificateValidation(String),

    /// Operation timed out.
    #[error("operation timed out: {operation}")]
    Timeout {
        /// The operation that timed out.
        operation: String,
    },
}

/// TLS configuration for mutual authentication.
#[derive(Clone)]
pub struct TlsConfig {
    /// Client configuration for outbound connections.
    pub(crate) client_config: Arc<ClientConfig>,
    /// Server configuration for inbound connections.
    pub(crate) server_config: Arc<ServerConfig>,
}

/// Builder for TLS configuration.
#[allow(clippy::struct_field_names)]
pub struct TlsConfigBuilder {
    ca_cert_pem: Option<Vec<u8>>,
    node_cert_pem: Option<Vec<u8>>,
    node_key_pem: Option<Zeroizing<Vec<u8>>>,
}

impl Default for TlsConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TlsConfigBuilder {
    /// Creates a new TLS configuration builder.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            ca_cert_pem: None,
            node_cert_pem: None,
            node_key_pem: None,
        }
    }

    /// Sets the CA certificate in PEM format.
    #[must_use]
    pub fn ca_cert_pem(mut self, pem: impl Into<Vec<u8>>) -> Self {
        self.ca_cert_pem = Some(pem.into());
        self
    }

    /// Sets the node certificate in PEM format.
    #[must_use]
    pub fn node_cert_pem(mut self, pem: impl Into<Vec<u8>>) -> Self {
        self.node_cert_pem = Some(pem.into());
        self
    }

    /// Sets the node private key in PEM format.
    #[must_use]
    pub fn node_key_pem(mut self, pem: impl Into<Vec<u8>>) -> Self {
        self.node_key_pem = Some(Zeroizing::new(pem.into()));
        self
    }

    /// Builds the TLS configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if certificates or keys are invalid or missing.
    pub fn build(self) -> Result<TlsConfig, NetworkError> {
        let ca_pem = self
            .ca_cert_pem
            .ok_or_else(|| NetworkError::TlsConfig("CA certificate required".into()))?;
        let node_cert_pem = self
            .node_cert_pem
            .ok_or_else(|| NetworkError::TlsConfig("node certificate required".into()))?;
        let node_key_pem = self
            .node_key_pem
            .ok_or_else(|| NetworkError::TlsConfig("node private key required".into()))?;

        // Parse CA certificate
        let ca_certs = parse_certificates(&ca_pem)?;
        if ca_certs.is_empty() {
            return Err(NetworkError::Certificate("no CA certificates found".into()));
        }

        // Build root cert store
        let mut root_store = RootCertStore::empty();
        for cert in &ca_certs {
            root_store.add(cert.clone()).map_err(|e| {
                NetworkError::Certificate(format!("failed to add CA certificate: {e}"))
            })?;
        }

        // Parse node certificate chain
        let node_certs = parse_certificates(&node_cert_pem)?;
        if node_certs.is_empty() {
            return Err(NetworkError::Certificate(
                "no node certificates found".into(),
            ));
        }

        // Parse node private key
        let node_key = parse_private_key(&node_key_pem)?;

        // Build client config for outbound connections
        let client_config = ClientConfig::builder()
            .with_root_certificates(root_store.clone())
            .with_client_auth_cert(node_certs.clone(), node_key.clone_key())
            .map_err(|e| NetworkError::TlsConfig(format!("client config error: {e}")))?;

        // Build server config for inbound connections
        // Require client certificates (mutual TLS)
        let client_cert_verifier =
            rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store))
                .build()
                .map_err(|e| NetworkError::TlsConfig(format!("client verifier error: {e}")))?;

        let server_config = ServerConfig::builder()
            .with_client_cert_verifier(client_cert_verifier)
            .with_single_cert(node_certs, node_key)
            .map_err(|e| NetworkError::TlsConfig(format!("server config error: {e}")))?;

        Ok(TlsConfig {
            client_config: Arc::new(client_config),
            server_config: Arc::new(server_config),
        })
    }
}

impl TlsConfig {
    /// Creates a new TLS configuration builder.
    #[must_use]
    pub const fn builder() -> TlsConfigBuilder {
        TlsConfigBuilder::new()
    }

    /// Creates a TLS connector for outbound connections.
    #[must_use]
    pub fn connector(&self) -> TlsConnector {
        TlsConnector::from(self.client_config.clone())
    }

    /// Creates a TLS acceptor for inbound connections.
    #[must_use]
    pub fn acceptor(&self) -> TlsAcceptor {
        TlsAcceptor::from(self.server_config.clone())
    }
}

/// Parse PEM-encoded certificates.
fn parse_certificates(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, NetworkError> {
    CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| NetworkError::Certificate(format!("failed to parse certificates: {e}")))
}

/// Parse PEM-encoded private key.
fn parse_private_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>, NetworkError> {
    PrivateKeyDer::from_pem_slice(pem)
        .map_err(|e| NetworkError::PrivateKey(format!("failed to parse private key: {e}")))
}

/// A fixed-size control plane frame.
///
/// Format:
/// - Bytes 0-3: Message type (u32 big-endian)
/// - Bytes 4-7: Payload length (u32 big-endian)
/// - Bytes 8-1023: Payload + padding
///
/// All frames are exactly `CONTROL_FRAME_SIZE` bytes (INV-0017).
#[derive(Clone)]
pub struct ControlFrame {
    /// The raw frame data (always `CONTROL_FRAME_SIZE` bytes).
    data: [u8; CONTROL_FRAME_SIZE],
}

impl ControlFrame {
    /// Creates a new control frame with the given message type and payload.
    ///
    /// # Errors
    ///
    /// Returns an error if the payload exceeds `MAX_PAYLOAD_SIZE`.
    ///
    /// # Panics
    ///
    /// Panics if payload length conversion fails (impossible for valid
    /// payloads).
    pub fn new(message_type: u32, payload: &[u8]) -> Result<Self, NetworkError> {
        if payload.len() > MAX_PAYLOAD_SIZE {
            return Err(NetworkError::FrameTooLarge {
                size: payload.len(),
                max: MAX_PAYLOAD_SIZE,
            });
        }

        let mut data = [0u8; CONTROL_FRAME_SIZE];

        // Write message type (bytes 0-3)
        data[0..4].copy_from_slice(&message_type.to_be_bytes());

        // Write payload length (bytes 4-7)
        let len = u32::try_from(payload.len()).expect("payload length checked above");
        data[4..8].copy_from_slice(&len.to_be_bytes());

        // Write payload (bytes 8+)
        data[8..8 + payload.len()].copy_from_slice(payload);

        // Remaining bytes are already zero (padding)

        Ok(Self { data })
    }

    /// Parses a control frame from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the frame is invalid.
    pub fn parse(data: &[u8; CONTROL_FRAME_SIZE]) -> Result<Self, NetworkError> {
        // Validate payload length
        let payload_len = u32::from_be_bytes([data[4], data[5], data[6], data[7]]) as usize;
        if payload_len > MAX_PAYLOAD_SIZE {
            return Err(NetworkError::InvalidFrame(format!(
                "payload length {payload_len} exceeds maximum {MAX_PAYLOAD_SIZE}"
            )));
        }

        Ok(Self { data: *data })
    }

    /// Returns the message type.
    #[must_use]
    pub const fn message_type(&self) -> u32 {
        u32::from_be_bytes([self.data[0], self.data[1], self.data[2], self.data[3]])
    }

    /// Returns the payload (without padding).
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        let len =
            u32::from_be_bytes([self.data[4], self.data[5], self.data[6], self.data[7]]) as usize;
        &self.data[8..8 + len]
    }

    /// Returns the raw frame data.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; CONTROL_FRAME_SIZE] {
        &self.data
    }
}

/// A TLS connection to a peer.
pub struct Connection {
    /// The underlying TLS stream.
    stream: TlsStream<TcpStream>,
    /// Remote peer address.
    peer_addr: SocketAddr,
    /// When this connection was last used.
    last_used: Instant,
}

impl Connection {
    /// Creates a new connection wrapper.
    fn new(stream: TlsStream<TcpStream>, peer_addr: SocketAddr) -> Self {
        Self {
            stream,
            peer_addr,
            last_used: Instant::now(),
        }
    }

    /// Returns the peer address.
    #[must_use]
    pub const fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    /// Sends a control frame with timeout.
    ///
    /// # Errors
    ///
    /// Returns an error if the write fails or times out.
    pub async fn send_frame(&mut self, frame: &ControlFrame) -> Result<(), NetworkError> {
        self.send_frame_with_timeout(frame, FRAME_SEND_TIMEOUT)
            .await
    }

    /// Sends a control frame with a custom timeout.
    ///
    /// # Errors
    ///
    /// Returns an error if the write fails or times out.
    pub async fn send_frame_with_timeout(
        &mut self,
        frame: &ControlFrame,
        timeout_duration: Duration,
    ) -> Result<(), NetworkError> {
        let send_fut = async {
            self.stream.write_all(frame.as_bytes()).await?;
            self.stream.flush().await?;
            Ok::<_, io::Error>(())
        };

        timeout(timeout_duration, send_fut)
            .await
            .map_err(|_| NetworkError::Timeout {
                operation: "send_frame".into(),
            })??;

        self.last_used = Instant::now();
        Ok(())
    }

    /// Receives a control frame with timeout.
    ///
    /// # Errors
    ///
    /// Returns an error if the read fails, times out, or the frame is invalid.
    pub async fn recv_frame(&mut self) -> Result<ControlFrame, NetworkError> {
        self.recv_frame_with_timeout(FRAME_RECV_TIMEOUT).await
    }

    /// Receives a control frame with a custom timeout.
    ///
    /// # Errors
    ///
    /// Returns an error if the read fails, times out, or the frame is invalid.
    pub async fn recv_frame_with_timeout(
        &mut self,
        timeout_duration: Duration,
    ) -> Result<ControlFrame, NetworkError> {
        let mut data = [0u8; CONTROL_FRAME_SIZE];

        timeout(timeout_duration, self.stream.read_exact(&mut data))
            .await
            .map_err(|_| NetworkError::Timeout {
                operation: "recv_frame".into(),
            })??;

        self.last_used = Instant::now();
        ControlFrame::parse(&data)
    }

    /// Returns whether this connection has been idle too long.
    #[must_use]
    pub fn is_idle(&self) -> bool {
        self.last_used.elapsed() > CONNECTION_IDLE_TIMEOUT
    }
}

/// RAII guard for a pooled connection.
///
/// This guard ensures connections are always returned to the pool when dropped,
/// preventing connection pool leaks. When the guard is dropped (whether
/// normally or due to an error/panic), the connection is automatically returned
/// to the pool.
///
/// # Example
///
/// ```rust,ignore
/// let guard = pool.get_pooled_connection(addr, server_name).await?;
/// guard.send_frame(&request).await?;
/// let response = guard.recv_frame().await?;
/// // Connection is automatically returned when guard goes out of scope
/// ```
pub struct PooledConnection {
    /// The underlying connection (Option for take on drop).
    connection: Option<Connection>,
    /// Reference to the pool for returning the connection.
    pool: Arc<ConnectionPool>,
}

impl PooledConnection {
    /// Creates a new pooled connection guard.
    const fn new(connection: Connection, pool: Arc<ConnectionPool>) -> Self {
        Self {
            connection: Some(connection),
            pool,
        }
    }

    /// Returns the peer address.
    #[must_use]
    pub fn peer_addr(&self) -> SocketAddr {
        self.connection.as_ref().map_or_else(
            || SocketAddr::from(([0, 0, 0, 0], 0)),
            Connection::peer_addr,
        )
    }

    /// Sends a control frame with timeout.
    ///
    /// # Errors
    ///
    /// Returns an error if the write fails or times out.
    pub async fn send_frame(&mut self, frame: &ControlFrame) -> Result<(), NetworkError> {
        if let Some(conn) = self.connection.as_mut() {
            conn.send_frame(frame).await
        } else {
            Err(NetworkError::Connection(io::Error::new(
                io::ErrorKind::NotConnected,
                "connection already returned to pool",
            )))
        }
    }

    /// Receives a control frame with timeout.
    ///
    /// # Errors
    ///
    /// Returns an error if the read fails, times out, or the frame is invalid.
    pub async fn recv_frame(&mut self) -> Result<ControlFrame, NetworkError> {
        if let Some(conn) = self.connection.as_mut() {
            conn.recv_frame().await
        } else {
            Err(NetworkError::Connection(io::Error::new(
                io::ErrorKind::NotConnected,
                "connection already returned to pool",
            )))
        }
    }

    /// Consumes the guard and explicitly returns the connection to the pool.
    ///
    /// This is useful when you want to return the connection early.
    /// Note: the connection is also returned automatically on drop.
    pub async fn return_to_pool(mut self) {
        if let Some(conn) = self.connection.take() {
            self.pool.return_connection(conn).await;
        }
    }
}

impl Drop for PooledConnection {
    fn drop(&mut self) {
        if let Some(conn) = self.connection.take() {
            // We need to return the connection to the pool.
            // Since Drop is synchronous, we spawn a task to do this async.
            let pool = self.pool.clone();
            tokio::spawn(async move {
                pool.return_connection(conn).await;
            });
        }
    }
}

/// A pool entry for a single peer's connections.
struct PeerConnections {
    /// Available (idle) connections.
    available: Vec<Connection>,
    /// Number of connections currently in use.
    in_use: usize,
}

impl PeerConnections {
    fn new() -> Self {
        Self {
            available: Vec::with_capacity(MAX_CONNECTIONS_PER_PEER),
            in_use: 0,
        }
    }

    fn total(&self) -> usize {
        self.available.len() + self.in_use
    }
}

/// Connection pool for reusing TLS connections (INV-0019).
///
/// The pool maintains up to `MAX_CONNECTIONS_PER_PEER` connections per peer
/// and `MAX_TOTAL_CONNECTIONS` total connections (CTR-1303: Bounded Stores).
pub struct ConnectionPool {
    /// TLS configuration.
    tls_config: TlsConfig,
    /// Connections indexed by peer address.
    connections: RwLock<HashMap<SocketAddr, PeerConnections>>,
}

impl ConnectionPool {
    /// Creates a new connection pool.
    #[must_use]
    pub fn new(tls_config: TlsConfig) -> Self {
        Self {
            tls_config,
            connections: RwLock::new(HashMap::new()),
        }
    }

    /// Gets or creates a connection to the given peer.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection cannot be established or the pool is
    /// exhausted.
    pub async fn get_connection(
        &self,
        peer_addr: SocketAddr,
        server_name: &str,
    ) -> Result<Connection, NetworkError> {
        // First, try to get an existing connection
        {
            let mut pool = self.connections.write().await;

            // Check total connection count
            let total: usize = pool.values().map(PeerConnections::total).sum();
            if total >= MAX_TOTAL_CONNECTIONS {
                // Try to evict idle connections
                Self::evict_idle_connections_locked(&mut pool);
                let new_total: usize = pool.values().map(PeerConnections::total).sum();
                if new_total >= MAX_TOTAL_CONNECTIONS {
                    return Err(NetworkError::PoolExhausted {
                        max: MAX_TOTAL_CONNECTIONS,
                    });
                }
            }

            if let Some(peer_conns) = pool.get_mut(&peer_addr) {
                // Remove idle connections
                peer_conns.available.retain(|c| !c.is_idle());

                // Try to get an available connection
                if let Some(conn) = peer_conns.available.pop() {
                    peer_conns.in_use += 1;
                    return Ok(conn);
                }

                // Check if we can create a new connection
                if peer_conns.total() >= MAX_CONNECTIONS_PER_PEER {
                    return Err(NetworkError::PoolExhausted {
                        max: MAX_CONNECTIONS_PER_PEER,
                    });
                }
                peer_conns.in_use += 1;
            } else {
                // Create entry for new peer
                let mut peer_conns = PeerConnections::new();
                peer_conns.in_use = 1;
                pool.insert(peer_addr, peer_conns);
            }
        }

        // Create a new connection (outside the lock)
        match self.create_connection(peer_addr, server_name).await {
            Ok(conn) => Ok(conn),
            Err(e) => {
                // Decrement in_use count on failure
                let mut pool = self.connections.write().await;
                if let Some(peer_conns) = pool.get_mut(&peer_addr) {
                    peer_conns.in_use = peer_conns.in_use.saturating_sub(1);
                }
                Err(e)
            },
        }
    }

    /// Gets or creates a pooled connection with RAII guard.
    ///
    /// This is the preferred method for getting connections as the RAII guard
    /// ensures the connection is always returned to the pool, even if an error
    /// occurs or the code panics.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection cannot be established or the pool is
    /// exhausted.
    pub async fn get_pooled_connection(
        self: &Arc<Self>,
        peer_addr: SocketAddr,
        server_name: &str,
    ) -> Result<PooledConnection, NetworkError> {
        let conn = self.get_connection(peer_addr, server_name).await?;
        Ok(PooledConnection::new(conn, Arc::clone(self)))
    }

    /// Returns a connection to the pool for reuse.
    pub async fn return_connection(&self, conn: Connection) {
        let peer_addr = conn.peer_addr;
        let mut pool = self.connections.write().await;

        if let Some(peer_conns) = pool.get_mut(&peer_addr) {
            peer_conns.in_use = peer_conns.in_use.saturating_sub(1);

            // Only keep if not idle and under limit
            if !conn.is_idle() && peer_conns.available.len() < MAX_CONNECTIONS_PER_PEER {
                peer_conns.available.push(conn);
            }
        }
    }

    /// Creates a new TLS connection to a peer with timeouts.
    async fn create_connection(
        &self,
        peer_addr: SocketAddr,
        server_name: &str,
    ) -> Result<Connection, NetworkError> {
        // Connect TCP with timeout
        let tcp_stream = timeout(TCP_CONNECT_TIMEOUT, TcpStream::connect(peer_addr))
            .await
            .map_err(|_| NetworkError::Timeout {
                operation: "TCP connect".into(),
            })??;

        // Perform TLS handshake with timeout
        let server_name = ServerName::try_from(server_name.to_owned())
            .map_err(|e| NetworkError::Handshake(format!("invalid server name: {e}")))?;

        let connector = self.tls_config.connector();
        let tls_stream = timeout(
            TLS_HANDSHAKE_TIMEOUT,
            connector.connect(server_name, tcp_stream),
        )
        .await
        .map_err(|_| NetworkError::Timeout {
            operation: "TLS handshake".into(),
        })?
        .map_err(|e| NetworkError::Handshake(format!("TLS handshake failed: {e}")))?;

        Ok(Connection::new(TlsStream::Client(tls_stream), peer_addr))
    }

    /// Evicts idle connections from the pool.
    fn evict_idle_connections_locked(pool: &mut HashMap<SocketAddr, PeerConnections>) {
        for peer_conns in pool.values_mut() {
            peer_conns.available.retain(|c| !c.is_idle());
        }
        // Remove entries with no connections
        pool.retain(|_, v| v.total() > 0);
    }

    /// Returns the total number of connections in the pool.
    pub async fn connection_count(&self) -> usize {
        let pool = self.connections.read().await;
        pool.values().map(PeerConnections::total).sum()
    }
}

/// Applies bounded dispatch jitter for traffic analysis mitigation (INV-0020).
///
/// This function introduces a random delay between 0 and
/// `MAX_DISPATCH_JITTER_MS` milliseconds before dispatching network frames.
/// This helps mitigate traffic analysis attacks by making timing patterns less
/// predictable.
///
/// # Example
///
/// ```rust,ignore
/// use apm2_core::consensus::apply_dispatch_jitter;
///
/// // Apply jitter before sending
/// apply_dispatch_jitter().await;
/// conn.send_frame(&frame).await?;
/// ```
pub async fn apply_dispatch_jitter() {
    let jitter_ms = rand::thread_rng().gen_range(0..=MAX_DISPATCH_JITTER_MS);
    if jitter_ms > 0 {
        tokio::time::sleep(Duration::from_millis(jitter_ms)).await;
    }
}

/// Network configuration.
pub struct NetworkConfig {
    /// TLS configuration.
    pub tls_config: TlsConfig,
    /// Bootstrap node addresses.
    pub bootstrap_nodes: Vec<SocketAddr>,
    /// Local bind address for incoming connections.
    pub bind_addr: Option<SocketAddr>,
}

impl NetworkConfig {
    /// Creates a new network configuration builder.
    #[must_use]
    pub const fn builder() -> NetworkConfigBuilder {
        NetworkConfigBuilder::new()
    }
}

/// Builder for network configuration.
pub struct NetworkConfigBuilder {
    tls_config: Option<TlsConfig>,
    bootstrap_nodes: Vec<SocketAddr>,
    bind_addr: Option<SocketAddr>,
}

impl Default for NetworkConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkConfigBuilder {
    /// Creates a new network configuration builder.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            tls_config: None,
            bootstrap_nodes: Vec::new(),
            bind_addr: None,
        }
    }

    /// Sets the TLS configuration.
    #[must_use]
    pub fn tls(mut self, config: TlsConfig) -> Self {
        self.tls_config = Some(config);
        self
    }

    /// Adds bootstrap nodes.
    #[must_use]
    pub fn bootstrap_nodes(mut self, nodes: Vec<SocketAddr>) -> Self {
        self.bootstrap_nodes = nodes;
        self
    }

    /// Sets the local bind address.
    #[must_use]
    pub const fn bind_addr(mut self, addr: SocketAddr) -> Self {
        self.bind_addr = Some(addr);
        self
    }

    /// Builds the network configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if required fields are missing.
    pub fn build(self) -> Result<NetworkConfig, NetworkError> {
        let tls_config = self
            .tls_config
            .ok_or_else(|| NetworkError::TlsConfig("TLS configuration required".into()))?;

        Ok(NetworkConfig {
            tls_config,
            bootstrap_nodes: self.bootstrap_nodes,
            bind_addr: self.bind_addr,
        })
    }
}

/// Network layer for consensus communication.
pub struct Network {
    /// Network configuration.
    config: NetworkConfig,
    /// Connection pool.
    pool: ConnectionPool,
}

impl Network {
    /// Creates a new network layer.
    #[must_use]
    pub fn new(config: NetworkConfig) -> Self {
        let pool = ConnectionPool::new(config.tls_config.clone());
        Self { config, pool }
    }

    /// Returns the connection pool.
    #[must_use]
    pub const fn pool(&self) -> &ConnectionPool {
        &self.pool
    }

    /// Returns the TLS configuration.
    #[must_use]
    pub const fn tls_config(&self) -> &TlsConfig {
        &self.config.tls_config
    }

    /// Returns the bootstrap nodes.
    #[must_use]
    pub fn bootstrap_nodes(&self) -> &[SocketAddr] {
        &self.config.bootstrap_nodes
    }

    /// Connects to a peer and sends a control frame.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection or send fails.
    pub async fn send_to(
        &self,
        peer_addr: SocketAddr,
        server_name: &str,
        frame: &ControlFrame,
    ) -> Result<(), NetworkError> {
        let mut conn = self.pool.get_connection(peer_addr, server_name).await?;
        let result = conn.send_frame(frame).await;
        self.pool.return_connection(conn).await;
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_control_frame_new() {
        let payload = b"hello";
        let frame = ControlFrame::new(1, payload).unwrap();

        assert_eq!(frame.message_type(), 1);
        assert_eq!(frame.payload(), payload);
        assert_eq!(frame.as_bytes().len(), CONTROL_FRAME_SIZE);
    }

    #[test]
    fn test_control_frame_payload_too_large() {
        let payload = vec![0u8; MAX_PAYLOAD_SIZE + 1];
        let result = ControlFrame::new(1, &payload);

        assert!(matches!(result, Err(NetworkError::FrameTooLarge { .. })));
    }

    #[test]
    fn test_control_frame_max_payload() {
        let payload = vec![0u8; MAX_PAYLOAD_SIZE];
        let frame = ControlFrame::new(42, &payload).unwrap();

        assert_eq!(frame.message_type(), 42);
        assert_eq!(frame.payload().len(), MAX_PAYLOAD_SIZE);
    }

    #[test]
    fn test_control_frame_empty_payload() {
        let frame = ControlFrame::new(0, &[]).unwrap();

        assert_eq!(frame.message_type(), 0);
        assert_eq!(frame.payload().len(), 0);
    }

    #[test]
    fn test_control_frame_parse_roundtrip() {
        let payload = b"test payload data";
        let frame = ControlFrame::new(123, payload).unwrap();
        let parsed = ControlFrame::parse(frame.as_bytes()).unwrap();

        assert_eq!(parsed.message_type(), 123);
        assert_eq!(parsed.payload(), payload);
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn test_control_frame_parse_invalid_length() {
        let mut data = [0u8; CONTROL_FRAME_SIZE];
        // Set payload length to exceed maximum (safe: MAX_PAYLOAD_SIZE + 100 fits in
        // u32)
        let invalid_len = (MAX_PAYLOAD_SIZE + 100) as u32;
        data[4..8].copy_from_slice(&invalid_len.to_be_bytes());

        let result = ControlFrame::parse(&data);
        assert!(matches!(result, Err(NetworkError::InvalidFrame(_))));
    }

    #[test]
    fn test_tls_config_builder_missing_ca() {
        let result = TlsConfigBuilder::new()
            .node_cert_pem(b"cert")
            .node_key_pem(b"key")
            .build();

        assert!(matches!(result, Err(NetworkError::TlsConfig(_))));
    }

    #[test]
    fn test_tls_config_builder_missing_node_cert() {
        let result = TlsConfigBuilder::new()
            .ca_cert_pem(b"ca")
            .node_key_pem(b"key")
            .build();

        assert!(matches!(result, Err(NetworkError::TlsConfig(_))));
    }

    #[test]
    fn test_tls_config_builder_missing_node_key() {
        let result = TlsConfigBuilder::new()
            .ca_cert_pem(b"ca")
            .node_cert_pem(b"cert")
            .build();

        assert!(matches!(result, Err(NetworkError::TlsConfig(_))));
    }

    #[test]
    fn test_network_config_builder_missing_tls() {
        let result = NetworkConfigBuilder::new()
            .bootstrap_nodes(vec!["127.0.0.1:8443".parse().unwrap()])
            .build();

        assert!(matches!(result, Err(NetworkError::TlsConfig(_))));
    }

    // Integration tests with actual TLS would go in a separate test module
    // that uses rcgen to generate test certificates
}

/// Test utilities for the network module.
#[cfg(test)]
pub mod test_utils {
    use std::sync::Once;

    use rcgen::{CertificateParams, DnType, KeyPair};

    use super::*;

    static CRYPTO_INIT: Once = Once::new();

    /// Initializes the rustls crypto provider for tests.
    ///
    /// # Panics
    ///
    /// Panics if crypto provider installation fails.
    pub fn init_crypto() {
        CRYPTO_INIT.call_once(|| {
            rustls::crypto::ring::default_provider()
                .install_default()
                .expect("failed to install crypto provider");
        });
    }

    /// Generates a self-signed CA certificate for testing.
    ///
    /// # Panics
    ///
    /// Panics if certificate generation fails (test-only).
    #[must_use]
    pub fn generate_test_ca() -> (Vec<u8>, Vec<u8>) {
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, "Test CA");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

        let key_pair = KeyPair::generate().expect("key generation should succeed");
        let cert = params
            .self_signed(&key_pair)
            .expect("self-signing should succeed");

        (
            cert.pem().into_bytes(),
            key_pair.serialize_pem().into_bytes(),
        )
    }

    /// Generates a node certificate signed by the CA.
    ///
    /// # Panics
    ///
    /// Panics if certificate generation fails (test-only).
    #[must_use]
    pub fn generate_test_node_cert(
        ca_cert_pem: &[u8],
        ca_key_pem: &[u8],
        node_name: &str,
    ) -> (Vec<u8>, Vec<u8>) {
        // Parse CA
        let ca_key = KeyPair::from_pem(&String::from_utf8_lossy(ca_key_pem))
            .expect("CA key parsing should succeed");
        let ca_params = CertificateParams::from_ca_cert_pem(&String::from_utf8_lossy(ca_cert_pem))
            .expect("CA cert parsing should succeed");
        let ca_cert = ca_params
            .self_signed(&ca_key)
            .expect("CA self-signing should succeed");

        // Generate node cert
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, node_name);
        params.subject_alt_names = vec![rcgen::SanType::DnsName(
            node_name.try_into().expect("valid DNS name"),
        )];

        let node_key = KeyPair::generate().expect("node key generation should succeed");
        let node_cert = params
            .signed_by(&node_key, &ca_cert, &ca_key)
            .expect("node cert signing should succeed");

        (
            node_cert.pem().into_bytes(),
            node_key.serialize_pem().into_bytes(),
        )
    }

    /// Creates a TLS config for testing.
    ///
    /// # Panics
    ///
    /// Panics if TLS configuration fails (test-only).
    #[must_use]
    pub fn create_test_tls_config() -> TlsConfig {
        init_crypto();
        let (ca_cert, ca_key) = generate_test_ca();
        let (node_cert, node_key) = generate_test_node_cert(&ca_cert, &ca_key, "localhost");

        TlsConfig::builder()
            .ca_cert_pem(ca_cert)
            .node_cert_pem(node_cert)
            .node_key_pem(node_key)
            .build()
            .expect("TLS config should build successfully")
    }
}

#[cfg(test)]
mod tck_00183_network_tests {
    use super::test_utils::*;
    use super::*;

    #[test]
    fn test_tck_00183_tls_config_creation() {
        let config = create_test_tls_config();

        // Should be able to create connector and acceptor
        let _connector = config.connector();
        let _acceptor = config.acceptor();
    }

    #[test]
    fn test_tck_00183_control_frame_fixed_size() {
        // All frames must be exactly CONTROL_FRAME_SIZE bytes (INV-0017)
        let payloads = [
            vec![],
            vec![0u8; 1],
            vec![0u8; 100],
            vec![0u8; MAX_PAYLOAD_SIZE],
        ];

        for payload in &payloads {
            let frame = ControlFrame::new(1, payload).unwrap();
            assert_eq!(
                frame.as_bytes().len(),
                CONTROL_FRAME_SIZE,
                "Frame size must be exactly {CONTROL_FRAME_SIZE} bytes"
            );
        }
    }

    #[test]
    fn test_tck_00183_connection_pool_bounded() {
        // CTR-1303: Connection pool must have bounded size
        // These are compile-time constant checks
        const _: () = {
            assert!(MAX_TOTAL_CONNECTIONS > 0);
            assert!(MAX_CONNECTIONS_PER_PEER > 0);
            assert!(MAX_CONNECTIONS_PER_PEER <= MAX_TOTAL_CONNECTIONS);
        };
    }

    #[test]
    fn test_tck_00183_frame_oversized_rejection() {
        // DoS test: oversized payloads must be rejected
        let oversized = vec![0u8; MAX_PAYLOAD_SIZE + 1];
        let result = ControlFrame::new(1, &oversized);
        assert!(
            matches!(result, Err(NetworkError::FrameTooLarge { .. })),
            "Oversized frames must be rejected"
        );
    }

    #[test]
    fn test_tck_00183_frame_parse_invalid_length_rejection() {
        // Malformed input test: invalid length field must be rejected
        let mut data = [0u8; CONTROL_FRAME_SIZE];
        // Set length to exceed buffer
        data[4..8].copy_from_slice(&u32::MAX.to_be_bytes());

        let result = ControlFrame::parse(&data);
        assert!(
            matches!(result, Err(NetworkError::InvalidFrame(_))),
            "Invalid length must be rejected"
        );
    }

    #[tokio::test]
    async fn test_tck_00183_connection_pool_creation() {
        let config = create_test_tls_config();
        let pool = ConnectionPool::new(config);

        assert_eq!(pool.connection_count().await, 0);
    }

    #[test]
    fn test_tck_00183_timeout_constants_defined() {
        // Verify all timeout constants are defined and reasonable
        assert!(
            TCP_CONNECT_TIMEOUT.as_secs() > 0,
            "TCP connect timeout must be positive"
        );
        assert!(
            TLS_HANDSHAKE_TIMEOUT.as_secs() > 0,
            "TLS handshake timeout must be positive"
        );
        assert!(
            FRAME_SEND_TIMEOUT.as_secs() > 0,
            "Frame send timeout must be positive"
        );
        assert!(
            FRAME_RECV_TIMEOUT.as_secs() > 0,
            "Frame receive timeout must be positive"
        );

        // Timeouts should be reasonable (not too short, not too long)
        assert!(
            TCP_CONNECT_TIMEOUT.as_secs() <= 60,
            "TCP connect timeout should be <= 60s"
        );
        assert!(
            TLS_HANDSHAKE_TIMEOUT.as_secs() <= 60,
            "TLS handshake timeout should be <= 60s"
        );
        assert!(
            FRAME_SEND_TIMEOUT.as_secs() <= 120,
            "Frame send timeout should be <= 120s"
        );
        assert!(
            FRAME_RECV_TIMEOUT.as_secs() <= 120,
            "Frame receive timeout should be <= 120s"
        );
    }

    #[test]
    fn test_tck_00183_dispatch_jitter_constant() {
        // INV-0020: Bounded jitter on dispatch (0-50ms)
        assert_eq!(
            MAX_DISPATCH_JITTER_MS, 50,
            "Dispatch jitter must be 50ms as per RFC-0014"
        );
    }

    #[tokio::test]
    async fn test_tck_00183_dispatch_jitter_bounded() {
        // INV-0020: Verify jitter function completes within bounded time
        let start = std::time::Instant::now();

        // Call jitter multiple times to verify it's bounded
        for _ in 0..10 {
            apply_dispatch_jitter().await;
        }

        let elapsed = start.elapsed();
        // 10 calls * max 50ms = 500ms max, but typically much less
        assert!(
            elapsed.as_millis() < 1000,
            "Dispatch jitter should be bounded (took {}ms)",
            elapsed.as_millis()
        );
    }

    #[test]
    fn test_tck_00183_timeout_error_variant() {
        // Verify timeout error variant exists and formats correctly
        let err = NetworkError::Timeout {
            operation: "test_operation".into(),
        };
        let msg = err.to_string();
        assert!(
            msg.contains("timed out"),
            "Error should mention 'timed out'"
        );
        assert!(
            msg.contains("test_operation"),
            "Error should mention operation"
        );
    }
}
