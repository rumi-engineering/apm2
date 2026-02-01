#![allow(clippy::disallowed_methods)] // Metadata/observability usage or adapter.
//! Relay Holon for routing messages to workers behind NAT.
//!
//! This module implements the Relay Holon, which maintains a registry of
//! worker tunnels and routes messages to workers that are behind NAT.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────┐         ┌─────────────┐         ┌─────────────┐
//! │   Worker    │◄────────│    Relay    │◄────────│   Client    │
//! │ (NAT-bound) │ tunnel  │   (Holon)   │  mTLS   │             │
//! └─────────────┘         └─────────────┘         └─────────────┘
//!       │                       │
//!       │   outbound conn       │   accepts both:
//!       └───────────────────────┤   - worker tunnels
//!                               └── - client requests
//! ```
//!
//! # Security Invariants
//!
//! - INV-0021: Tunnel registration requires valid mTLS identity
//! - INV-0023: Relay validates worker identity matches certificate CN
//! - INV-0024: Relay maintains bounded tunnel registry (CTR-1303)
//!
//! # Protocol
//!
//! 1. Worker connects to Relay via outbound TLS (bypasses NAT)
//! 2. Worker registers tunnel with identity
//! 3. Relay validates identity against mTLS certificate
//! 4. Client sends message to Relay for a specific worker
//! 5. Relay routes message over registered tunnel
//! 6. Worker receives message and responds over same tunnel

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use subtle::ConstantTimeEq;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{RwLock, Semaphore, mpsc, oneshot};
use tokio::time::timeout;
use tokio_rustls::TlsStream;

use super::network::{CONTROL_FRAME_SIZE, Connection, ControlFrame, NetworkError, TlsConfig};
use super::tunnel::{
    HEARTBEAT_INTERVAL, HEARTBEAT_TIMEOUT, MAX_TUNNELS, MSG_TUNNEL_CLOSE, MSG_TUNNEL_DATA,
    MSG_TUNNEL_HEARTBEAT, MSG_TUNNEL_HEARTBEAT_ACK, MSG_TUNNEL_REGISTER, TunnelAcceptResponse,
    TunnelData, TunnelError, TunnelHeartbeat, TunnelInfo, TunnelRegisterRequest,
    TunnelRejectResponse, TunnelState,
};

// =============================================================================
// Constants
// =============================================================================

/// Maximum pending messages per tunnel (CTR-1303: Bounded Stores).
pub const MAX_PENDING_MESSAGES: usize = 100;

/// Maximum tunnels per worker (CTR-1303: Bounded Stores).
///
/// This limit prevents a single worker from exhausting the global tunnel pool,
/// ensuring fair resource allocation across workers.
pub const MAX_TUNNELS_PER_WORKER: usize = 4;

/// Message routing timeout.
pub const ROUTE_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum relay ID length.
pub const MAX_RELAY_ID_LEN: usize = 128;

/// Tunnel cleanup interval.
pub const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);

/// Maximum concurrent TLS handshakes (denial-of-service protection).
///
/// Limits the number of simultaneous TLS handshakes to prevent resource
/// exhaustion attacks. Connections exceeding this limit will wait for
/// a permit before proceeding with the handshake.
pub const MAX_CONCURRENT_TLS_HANDSHAKES: usize = 64;

/// Maximum relay assignment duration before forced rotation (RFC-0014,
/// INV-0023).
///
/// Tunnels must be rotated after this duration to prevent connection squatting
/// attacks where a malicious actor holds connections indefinitely to exhaust
/// relay resources.
pub const MAX_RELAY_ASSIGNMENT_DURATION: Duration = Duration::from_secs(3600); // 1 hour

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur in relay operations.
#[derive(Debug, Error)]
pub enum RelayError {
    /// Tunnel error.
    #[error("tunnel error: {0}")]
    Tunnel(#[from] TunnelError),

    /// Network error.
    #[error("network error: {0}")]
    Network(#[from] NetworkError),

    /// Worker not found.
    #[error("worker not found: {worker_id}")]
    WorkerNotFound {
        /// The missing worker ID.
        worker_id: String,
    },

    /// Tunnel not found.
    #[error("tunnel not found: {tunnel_id}")]
    TunnelNotFound {
        /// The missing tunnel ID.
        tunnel_id: String,
    },

    /// Maximum tunnels reached.
    #[error("maximum tunnels reached: {max}")]
    MaxTunnelsReached {
        /// Maximum allowed tunnels.
        max: usize,
    },

    /// Maximum tunnels per worker reached.
    #[error(
        "maximum tunnels per worker reached: worker {worker_id} has {current} of {max} allowed"
    )]
    MaxTunnelsPerWorkerReached {
        /// The worker ID.
        worker_id: String,
        /// Current number of tunnels for this worker.
        current: usize,
        /// Maximum allowed tunnels per worker.
        max: usize,
    },

    /// Identity mismatch.
    #[error("identity mismatch: certificate CN {cert_cn} does not match worker ID {worker_id}")]
    IdentityMismatch {
        /// CN from certificate.
        cert_cn: String,
        /// Worker ID from registration.
        worker_id: String,
    },

    /// Duplicate tunnel ID.
    #[error("duplicate tunnel ID: {tunnel_id}")]
    DuplicateTunnelId {
        /// The duplicate tunnel ID.
        tunnel_id: String,
    },

    /// Routing failed.
    #[error("routing failed to worker {worker_id}: {reason}")]
    RoutingFailed {
        /// Target worker ID.
        worker_id: String,
        /// Reason for failure.
        reason: String,
    },

    /// Listener error.
    #[error("listener error: {0}")]
    Listener(String),

    /// Invalid message.
    #[error("invalid message: {0}")]
    InvalidMessage(String),

    /// Relay shutdown.
    #[error("relay is shutting down")]
    Shutdown,

    /// Tunnel identity mismatch (cross-tunnel spoofing attempt).
    #[error("tunnel identity mismatch: expected {expected}, received {received}")]
    TunnelIdentityMismatch {
        /// Expected tunnel ID bound to the connection.
        expected: String,
        /// Tunnel ID received in the message.
        received: String,
    },
}

// =============================================================================
// Tunnel Entry
// =============================================================================

/// An entry in the relay's tunnel registry.
struct TunnelEntry {
    /// Tunnel metadata.
    info: TunnelInfo,
    /// Channel for sending messages to the tunnel handler task.
    sender: mpsc::Sender<ControlFrame>,
    /// Handle to the tunnel handler task (for cleanup).
    task_handle: tokio::task::JoinHandle<()>,
}

impl TunnelEntry {
    /// Creates a new tunnel entry.
    #[allow(clippy::missing_const_for_fn)] // JoinHandle is not const-compatible
    fn new(
        info: TunnelInfo,
        sender: mpsc::Sender<ControlFrame>,
        task_handle: tokio::task::JoinHandle<()>,
    ) -> Self {
        Self {
            info,
            sender,
            task_handle,
        }
    }
}

impl Drop for TunnelEntry {
    fn drop(&mut self) {
        // Abort the handler task when the entry is dropped
        self.task_handle.abort();
    }
}

// =============================================================================
// Relay Configuration
// =============================================================================

/// Configuration for the Relay Holon.
#[derive(Clone)]
pub struct RelayConfig {
    /// Relay's unique identifier.
    pub relay_id: String,
    /// TLS configuration for accepting connections.
    pub tls_config: TlsConfig,
    /// Bind address for incoming connections.
    pub bind_addr: SocketAddr,
    /// Maximum number of tunnels.
    pub max_tunnels: usize,
    /// Heartbeat interval to recommend to workers.
    pub heartbeat_interval: Duration,
    /// Whether to validate identity (`worker_id` must match cert CN).
    pub validate_identity: bool,
}

impl RelayConfig {
    /// Creates a new relay configuration builder.
    #[must_use]
    pub fn builder(relay_id: impl Into<String>, tls_config: TlsConfig) -> RelayConfigBuilder {
        RelayConfigBuilder::new(relay_id, tls_config)
    }
}

/// Builder for relay configuration.
pub struct RelayConfigBuilder {
    relay_id: String,
    tls_config: TlsConfig,
    bind_addr: Option<SocketAddr>,
    max_tunnels: usize,
    heartbeat_interval: Duration,
    validate_identity: bool,
}

impl RelayConfigBuilder {
    /// Creates a new builder.
    fn new(relay_id: impl Into<String>, tls_config: TlsConfig) -> Self {
        Self {
            relay_id: relay_id.into(),
            tls_config,
            bind_addr: None,
            max_tunnels: MAX_TUNNELS,
            heartbeat_interval: HEARTBEAT_INTERVAL,
            validate_identity: true,
        }
    }

    /// Sets the bind address.
    #[must_use]
    pub const fn bind_addr(mut self, addr: SocketAddr) -> Self {
        self.bind_addr = Some(addr);
        self
    }

    /// Sets the maximum tunnels.
    #[must_use]
    pub const fn max_tunnels(mut self, max: usize) -> Self {
        self.max_tunnels = max;
        self
    }

    /// Sets the heartbeat interval.
    #[must_use]
    pub const fn heartbeat_interval(mut self, interval: Duration) -> Self {
        self.heartbeat_interval = interval;
        self
    }

    /// Sets whether to validate identity.
    #[must_use]
    pub const fn validate_identity(mut self, validate: bool) -> Self {
        self.validate_identity = validate;
        self
    }

    /// Builds the configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if required fields are missing.
    pub fn build(self) -> Result<RelayConfig, RelayError> {
        let bind_addr = self
            .bind_addr
            .ok_or_else(|| RelayError::InvalidMessage("bind address required".into()))?;

        if self.relay_id.is_empty() {
            return Err(RelayError::InvalidMessage(
                "relay_id cannot be empty".into(),
            ));
        }

        if self.relay_id.len() > MAX_RELAY_ID_LEN {
            return Err(RelayError::InvalidMessage(format!(
                "relay_id too long: {} > {MAX_RELAY_ID_LEN}",
                self.relay_id.len()
            )));
        }

        Ok(RelayConfig {
            relay_id: self.relay_id,
            tls_config: self.tls_config,
            bind_addr,
            max_tunnels: self.max_tunnels,
            heartbeat_interval: self.heartbeat_interval,
            validate_identity: self.validate_identity,
        })
    }
}

// =============================================================================
// Tunnel Registry
// =============================================================================

/// Registry of active tunnels maintained by the relay.
pub struct TunnelRegistry {
    /// Tunnels indexed by tunnel ID.
    tunnels_by_id: RwLock<HashMap<String, Arc<RwLock<TunnelEntry>>>>,
    /// Tunnel IDs indexed by worker ID (for routing).
    tunnels_by_worker: RwLock<HashMap<String, Vec<String>>>,
    /// Maximum allowed tunnels.
    max_tunnels: usize,
}

impl TunnelRegistry {
    /// Creates a new tunnel registry.
    #[must_use]
    pub fn new(max_tunnels: usize) -> Self {
        Self {
            tunnels_by_id: RwLock::new(HashMap::new()),
            tunnels_by_worker: RwLock::new(HashMap::new()),
            max_tunnels,
        }
    }

    /// Registers a new tunnel.
    ///
    /// # Errors
    ///
    /// Returns an error if max tunnels reached or tunnel ID exists.
    pub async fn register(
        &self,
        info: TunnelInfo,
        sender: mpsc::Sender<ControlFrame>,
        task_handle: tokio::task::JoinHandle<()>,
    ) -> Result<(), RelayError> {
        let mut by_id = self.tunnels_by_id.write().await;
        let mut by_worker = self.tunnels_by_worker.write().await;

        // Check max tunnels
        if by_id.len() >= self.max_tunnels {
            return Err(RelayError::MaxTunnelsReached {
                max: self.max_tunnels,
            });
        }

        // Check for duplicate tunnel ID
        if by_id.contains_key(&info.tunnel_id) {
            return Err(RelayError::DuplicateTunnelId {
                tunnel_id: info.tunnel_id.clone(),
            });
        }

        // Check per-worker tunnel limit (CTR-1303: Bounded Stores)
        let current_worker_tunnels = by_worker.get(&info.worker_id).map_or(0, Vec::len);
        if current_worker_tunnels >= MAX_TUNNELS_PER_WORKER {
            return Err(RelayError::MaxTunnelsPerWorkerReached {
                worker_id: info.worker_id.clone(),
                current: current_worker_tunnels,
                max: MAX_TUNNELS_PER_WORKER,
            });
        }

        let tunnel_id = info.tunnel_id.clone();
        let worker_id = info.worker_id.clone();

        // Create entry
        let entry = Arc::new(RwLock::new(TunnelEntry::new(info, sender, task_handle)));
        by_id.insert(tunnel_id.clone(), entry);

        // Add to worker index
        by_worker.entry(worker_id).or_default().push(tunnel_id);

        Ok(())
    }

    /// Unregisters a tunnel.
    pub async fn unregister(&self, tunnel_id: &str) {
        let mut by_id = self.tunnels_by_id.write().await;
        let mut by_worker = self.tunnels_by_worker.write().await;

        if let Some(entry) = by_id.remove(tunnel_id) {
            let info = entry.read().await;
            let worker_id = &info.info.worker_id;

            // Remove from worker index
            if let Some(tunnels) = by_worker.get_mut(worker_id) {
                tunnels.retain(|t| t != tunnel_id);
                if tunnels.is_empty() {
                    by_worker.remove(worker_id);
                }
            }
        }
    }

    /// Gets a tunnel by ID.
    async fn get(&self, tunnel_id: &str) -> Option<Arc<RwLock<TunnelEntry>>> {
        let by_id = self.tunnels_by_id.read().await;
        by_id.get(tunnel_id).cloned()
    }

    /// Gets tunnels for a worker.
    pub async fn get_by_worker(&self, worker_id: &str) -> Vec<String> {
        let by_worker = self.tunnels_by_worker.read().await;
        by_worker.get(worker_id).cloned().unwrap_or_default()
    }

    /// Returns the number of registered tunnels.
    pub async fn len(&self) -> usize {
        let by_id = self.tunnels_by_id.read().await;
        by_id.len()
    }

    /// Returns whether the registry is empty.
    pub async fn is_empty(&self) -> bool {
        let by_id = self.tunnels_by_id.read().await;
        by_id.is_empty()
    }

    /// Returns info about all tunnels.
    pub async fn list_tunnels(&self) -> Vec<TunnelInfo> {
        let by_id = self.tunnels_by_id.read().await;
        let mut result = Vec::with_capacity(by_id.len());
        for entry in by_id.values() {
            let guard = entry.read().await;
            result.push(guard.info.clone());
        }
        result
    }

    /// Removes stale tunnels (no recent heartbeat) and expired tunnels (max age
    /// exceeded).
    ///
    /// RFC-0014 (INV-0023): Tunnels are rotated after
    /// `MAX_RELAY_ASSIGNMENT_DURATION` to prevent connection squatting
    /// attacks.
    pub async fn cleanup_stale(&self) -> Vec<String> {
        let by_id = self.tunnels_by_id.read().await;
        let mut stale = Vec::new();

        for (tunnel_id, entry) in by_id.iter() {
            let guard = entry.read().await;
            // Check for heartbeat staleness OR maximum age exceeded (forced rotation)
            if guard.info.is_stale() || guard.info.exceeds_max_age(MAX_RELAY_ASSIGNMENT_DURATION) {
                stale.push(tunnel_id.clone());
                if guard.info.exceeds_max_age(MAX_RELAY_ASSIGNMENT_DURATION) {
                    tracing::info!(
                        tunnel_id = %tunnel_id,
                        worker_id = %guard.info.worker_id,
                        "Tunnel exceeded max assignment duration, forcing rotation (INV-0023)"
                    );
                }
            }
        }
        drop(by_id);

        // Remove stale/expired tunnels
        for tunnel_id in &stale {
            self.unregister(tunnel_id).await;
        }

        stale
    }

    /// Updates heartbeat for a tunnel.
    ///
    /// # Errors
    ///
    /// Returns an error if the tunnel is not found.
    pub async fn touch(&self, tunnel_id: &str) -> Result<(), RelayError> {
        let by_id = self.tunnels_by_id.read().await;
        if let Some(entry) = by_id.get(tunnel_id) {
            let mut guard = entry.write().await;
            guard.info.touch();
            Ok(())
        } else {
            Err(RelayError::TunnelNotFound {
                tunnel_id: tunnel_id.to_string(),
            })
        }
    }
}

// =============================================================================
// Relay Holon
// =============================================================================

/// The Relay Holon for routing messages to NAT-bound workers.
pub struct RelayHolon {
    /// Configuration.
    config: RelayConfig,
    /// Tunnel registry.
    registry: Arc<TunnelRegistry>,
    /// Shutdown signal sender for graceful shutdown.
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl RelayHolon {
    /// Creates a new relay holon.
    #[must_use]
    pub fn new(config: RelayConfig) -> Self {
        let registry = Arc::new(TunnelRegistry::new(config.max_tunnels));

        Self {
            config,
            registry,
            shutdown_tx: None,
        }
    }

    /// Runs the relay listener, accepting incoming tunnel connections.
    ///
    /// This method binds to the configured address and spawns handler tasks
    /// for each incoming connection. It processes tunnel registrations and
    /// maintains the tunnel registry.
    ///
    /// # Security
    ///
    /// TLS handshakes are rate-limited via semaphore to prevent
    /// denial-of-service attacks that could exhaust CPU/FD resources
    /// through unbounded concurrent handshakes.
    ///
    /// # Errors
    ///
    /// Returns an error if the listener cannot be started.
    pub async fn run(&mut self) -> Result<(), RelayError> {
        let listener = TcpListener::bind(self.config.bind_addr)
            .await
            .map_err(|e| RelayError::Listener(format!("failed to bind: {e}")))?;

        tracing::info!(
            bind_addr = %self.config.bind_addr,
            relay_id = %self.config.relay_id,
            "Relay listener started"
        );

        // Create shutdown channel
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        self.shutdown_tx = Some(shutdown_tx);

        let tls_acceptor = self.config.tls_config.acceptor();

        // SECURITY: Semaphore to limit concurrent TLS handshakes (DoS protection)
        let handshake_semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_TLS_HANDSHAKES));

        loop {
            tokio::select! {
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok((tcp_stream, peer_addr)) => {
                            let acceptor = tls_acceptor.clone();
                            let relay_config = self.config.clone();
                            let registry = Arc::clone(&self.registry);
                            let semaphore = Arc::clone(&handshake_semaphore);

                            // Spawn connection handler with semaphore-limited TLS handshake
                            tokio::spawn(async move {
                                // Acquire permit before TLS handshake (denial-of-service protection)
                                let Ok(_permit) = semaphore.acquire().await else {
                                    tracing::debug!(
                                        peer_addr = %peer_addr,
                                        "TLS handshake semaphore closed"
                                    );
                                    return;
                                };

                                if let Err(e) = handle_incoming_connection(
                                    tcp_stream,
                                    peer_addr,
                                    acceptor,
                                    relay_config,
                                    registry,
                                ).await {
                                    tracing::debug!(
                                        peer_addr = %peer_addr,
                                        error = %e,
                                        "Failed to handle incoming connection"
                                    );
                                }
                                // Permit automatically released when _permit drops
                            });
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "Failed to accept connection");
                        }
                    }
                }
                _ = &mut shutdown_rx => {
                    tracing::info!("Relay received shutdown signal");
                    break;
                }
            }
        }

        Ok(())
    }

    /// Triggers graceful shutdown of the relay.
    pub fn shutdown(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }

    /// Returns the relay ID.
    #[must_use]
    pub fn relay_id(&self) -> &str {
        &self.config.relay_id
    }

    /// Returns the registry.
    #[must_use]
    pub const fn registry(&self) -> &Arc<TunnelRegistry> {
        &self.registry
    }

    /// Handles an incoming tunnel registration request.
    ///
    /// # Security
    ///
    /// This method extracts the peer's Common Name (CN) directly from the TLS
    /// connection's verified certificate chain, ensuring the identity is
    /// mechanically bound to the connection and cannot be spoofed.
    ///
    /// Identity comparison uses constant-time equality to prevent timing
    /// attacks.
    ///
    /// The spawned handler task binds the `tunnel_id` to this connection,
    /// preventing cross-tunnel identity spoofing (CRITICAL security fix).
    ///
    /// # Errors
    ///
    /// Returns an error if registration fails.
    pub async fn handle_registration(
        &self,
        request: TunnelRegisterRequest,
        connection: Connection,
    ) -> Result<TunnelAcceptResponse, RelayError> {
        // Validate request
        request.validate()?;

        // Validate identity if configured (INV-0023)
        // Extract CN directly from connection to ensure identity-connection binding
        if self.config.validate_identity {
            let cert_cn = connection.peer_common_name().ok_or_else(|| {
                RelayError::InvalidMessage("certificate CN required for identity validation".into())
            })?;

            // Use constant-time comparison to prevent timing attacks
            let cn_bytes = cert_cn.as_bytes();
            let worker_id_bytes = request.worker_id.as_bytes();
            let is_equal: bool = cn_bytes.ct_eq(worker_id_bytes).into();

            if !is_equal {
                return Err(RelayError::IdentityMismatch {
                    cert_cn,
                    worker_id: request.worker_id.clone(),
                });
            }
        }

        // Create tunnel info
        let info = TunnelInfo::new(
            request.tunnel_id.clone(),
            request.worker_id.clone(),
            connection.peer_addr(),
        );

        // Create message channel for outbound messages to the tunnel
        let (sender, receiver) = mpsc::channel(MAX_PENDING_MESSAGES);

        // Spawn the tunnel handler task that:
        // 1. Reads incoming frames from the connection
        // 2. Writes outgoing frames from the channel to the connection
        // 3. Binds the expected tunnel_id to prevent cross-tunnel spoofing
        let registry = Arc::clone(&self.registry);
        let expected_tunnel_id = request.tunnel_id.clone();
        let task_handle =
            spawn_tunnel_handler(connection, receiver, registry, expected_tunnel_id.clone());

        // Register tunnel with the handler task
        self.registry.register(info, sender, task_handle).await?;

        // Create accept response
        let accept = TunnelAcceptResponse::new(
            request.tunnel_id,
            self.config.relay_id.clone(),
            self.config.heartbeat_interval.as_secs(),
        );

        Ok(accept)
    }

    /// Creates a rejection response.
    #[must_use]
    pub fn create_rejection(&self, tunnel_id: &str, reason: &str) -> TunnelRejectResponse {
        TunnelRejectResponse::new(tunnel_id.to_string(), reason.to_string())
    }

    /// Handles a heartbeat from a worker.
    ///
    /// # Errors
    ///
    /// Returns an error if the tunnel is not found.
    pub async fn handle_heartbeat(&self, heartbeat: TunnelHeartbeat) -> Result<(), RelayError> {
        self.registry.touch(&heartbeat.tunnel_id).await
    }

    /// Routes data to a worker.
    ///
    /// # Errors
    ///
    /// Returns an error if the worker is not found or routing fails.
    pub async fn route_to_worker(&self, worker_id: &str, data: Vec<u8>) -> Result<(), RelayError> {
        // Get tunnels for worker
        let tunnel_ids = self.registry.get_by_worker(worker_id).await;
        if tunnel_ids.is_empty() {
            return Err(RelayError::WorkerNotFound {
                worker_id: worker_id.to_string(),
            });
        }

        // Try each tunnel (use first available)
        for tunnel_id in &tunnel_ids {
            if let Some(entry) = self.registry.get(tunnel_id).await {
                let guard = entry.read().await;
                if guard.info.state == TunnelState::Active && !guard.info.is_stale() {
                    // Create data message (clone data since we may try multiple tunnels)
                    let tunnel_data = TunnelData::new(tunnel_id.clone(), data.clone());
                    let payload = tunnel_data.to_bytes()?;
                    let frame = ControlFrame::new(MSG_TUNNEL_DATA, &payload)?;

                    // Send via channel
                    if guard.sender.try_send(frame).is_ok() {
                        return Ok(());
                    }
                }
            }
        }

        Err(RelayError::RoutingFailed {
            worker_id: worker_id.to_string(),
            reason: "no healthy tunnel available".into(),
        })
    }

    /// Handles a close request from a worker.
    pub async fn handle_close(&self, tunnel_id: &str) {
        self.registry.unregister(tunnel_id).await;
        tracing::info!(tunnel_id = %tunnel_id, "Tunnel closed by worker");
    }

    /// Runs the cleanup task to remove stale tunnels.
    pub async fn run_cleanup(&self) {
        let stale = self.registry.cleanup_stale().await;
        if !stale.is_empty() {
            tracing::info!(
                count = stale.len(),
                tunnels = ?stale,
                "Cleaned up stale tunnels"
            );
        }
    }

    /// Returns statistics about the relay.
    pub async fn stats(&self) -> RelayStats {
        let tunnels = self.registry.list_tunnels().await;
        let active_count = tunnels
            .iter()
            .filter(|t| t.state == TunnelState::Active && !t.is_stale())
            .count();

        let workers: std::collections::HashSet<_> = tunnels.iter().map(|t| &t.worker_id).collect();

        RelayStats {
            total_tunnels: tunnels.len(),
            active_tunnels: active_count,
            unique_workers: workers.len(),
            max_tunnels: self.config.max_tunnels,
        }
    }
}

/// Statistics about the relay.
#[derive(Debug, Clone)]
pub struct RelayStats {
    /// Total registered tunnels.
    pub total_tunnels: usize,
    /// Active (healthy) tunnels.
    pub active_tunnels: usize,
    /// Unique workers with tunnels.
    pub unique_workers: usize,
    /// Maximum allowed tunnels.
    pub max_tunnels: usize,
}

// =============================================================================
// Connection Handler
// =============================================================================

/// Handles an incoming connection from a worker.
///
/// This function:
/// 1. Performs TLS handshake with client certificate verification
/// 2. Reads the registration request
/// 3. Validates identity against the mTLS certificate
/// 4. Sends accept/reject response
/// 5. On accept, the connection is handed off to the tunnel handler task
async fn handle_incoming_connection(
    tcp_stream: TcpStream,
    peer_addr: SocketAddr,
    acceptor: tokio_rustls::TlsAcceptor,
    config: RelayConfig,
    registry: Arc<TunnelRegistry>,
) -> Result<(), RelayError> {
    // Perform TLS handshake with timeout
    let tls_stream = timeout(
        super::network::TLS_HANDSHAKE_TIMEOUT,
        acceptor.accept(tcp_stream),
    )
    .await
    .map_err(|_| NetworkError::Timeout {
        operation: "TLS handshake".into(),
    })?
    .map_err(|e| NetworkError::Handshake(format!("TLS handshake failed: {e}")))?;

    let mut connection = Connection::new(TlsStream::Server(tls_stream), peer_addr);

    // Read registration request with timeout
    let frame = connection
        .recv_frame_with_timeout(super::tunnel::REGISTRATION_TIMEOUT)
        .await?;

    // Verify it's a registration request
    if frame.message_type() != MSG_TUNNEL_REGISTER {
        return Err(RelayError::InvalidMessage(format!(
            "expected TUNNEL_REGISTER ({}), got {}",
            MSG_TUNNEL_REGISTER,
            frame.message_type()
        )));
    }

    // Parse the registration request
    let request = TunnelRegisterRequest::from_bytes(frame.payload())?;
    request.validate()?;

    // Validate identity if configured (INV-0023)
    if config.validate_identity {
        let cert_cn = connection.peer_common_name().ok_or_else(|| {
            RelayError::InvalidMessage("certificate CN required for identity validation".into())
        })?;

        let cn_bytes = cert_cn.as_bytes();
        let worker_id_bytes = request.worker_id.as_bytes();
        let is_equal: bool = cn_bytes.ct_eq(worker_id_bytes).into();

        if !is_equal {
            // Send rejection
            let reject = TunnelRejectResponse::new(
                request.tunnel_id.clone(),
                format!("identity mismatch: certificate CN '{cert_cn}' does not match worker ID"),
            );
            let payload = reject.to_bytes()?;
            let frame = ControlFrame::new(super::tunnel::MSG_TUNNEL_REJECT, &payload)?;
            let _ = connection.send_frame(&frame).await;

            return Err(RelayError::IdentityMismatch {
                cert_cn,
                worker_id: request.worker_id,
            });
        }
    }

    // Check registry limits
    let current_count = registry.len().await;
    if current_count >= config.max_tunnels {
        let reject = TunnelRejectResponse::new(
            request.tunnel_id.clone(),
            "maximum tunnels reached".to_string(),
        );
        let payload = reject.to_bytes()?;
        let frame = ControlFrame::new(super::tunnel::MSG_TUNNEL_REJECT, &payload)?;
        let _ = connection.send_frame(&frame).await;

        return Err(RelayError::MaxTunnelsReached {
            max: config.max_tunnels,
        });
    }

    // Create tunnel info
    let info = TunnelInfo::new(
        request.tunnel_id.clone(),
        request.worker_id.clone(),
        peer_addr,
    );

    // Send accept response
    let accept = TunnelAcceptResponse::new(
        request.tunnel_id.clone(),
        config.relay_id.clone(),
        config.heartbeat_interval.as_secs(),
    );
    let payload = accept.to_bytes()?;
    let frame = ControlFrame::new(super::tunnel::MSG_TUNNEL_ACCEPT, &payload)?;
    connection.send_frame(&frame).await?;

    // Create message channel
    let (sender, receiver) = mpsc::channel(MAX_PENDING_MESSAGES);

    // Spawn tunnel handler task
    let expected_tunnel_id = request.tunnel_id.clone();
    let registry_clone = Arc::clone(&registry);
    let task_handle =
        spawn_tunnel_handler(connection, receiver, registry_clone, expected_tunnel_id);

    // Register tunnel
    registry.register(info, sender, task_handle).await?;

    tracing::info!(
        tunnel_id = %request.tunnel_id,
        worker_id = %request.worker_id,
        peer_addr = %peer_addr,
        "Tunnel registered"
    );

    Ok(())
}

// =============================================================================
// Tunnel Handler Task
// =============================================================================

/// Spawns a background task to handle a tunnel connection.
///
/// This task:
/// 1. Reads incoming frames from the TLS connection
/// 2. Writes outgoing frames from the channel to the connection
/// 3. Validates that all incoming frames match the expected tunnel ID
/// 4. Updates heartbeat timestamps in the registry
/// 5. Sends ACK frames back to the worker (CRITICAL: heartbeat ACKs must be
///    transmitted)
///
/// # Security
///
/// The `expected_tunnel_id` is bound to this connection during registration.
/// All incoming frames are validated to ensure they match this ID, preventing
/// cross-tunnel identity spoofing attacks.
fn spawn_tunnel_handler(
    connection: Connection,
    receiver: mpsc::Receiver<ControlFrame>,
    registry: Arc<TunnelRegistry>,
    expected_tunnel_id: String,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // Split the connection into read and write halves for concurrent I/O
        let (read_half, write_half) = connection.into_split();

        // Create channel for ACK frames from reader to writer (CRITICAL: fixes
        // heartbeat ACK transmission)
        let (ack_tx, ack_rx) = mpsc::channel::<ControlFrame>(MAX_PENDING_MESSAGES);

        // Spawn writer task with both outbound message channel and ACK channel
        let writer_handle = tokio::spawn(tunnel_writer_loop(write_half, receiver, ack_rx));

        // Run reader loop in this task, passing ACK sender
        let read_result = tunnel_reader_loop(
            read_half,
            Arc::clone(&registry),
            expected_tunnel_id.clone(),
            ack_tx,
        )
        .await;

        // Clean up on exit
        writer_handle.abort();

        if let Err(e) = read_result {
            tracing::debug!(
                tunnel_id = %expected_tunnel_id,
                error = %e,
                "Tunnel reader loop exited"
            );
        }

        // Unregister the tunnel
        registry.unregister(&expected_tunnel_id).await;
        tracing::info!(tunnel_id = %expected_tunnel_id, "Tunnel handler task completed");
    })
}

/// Writer loop that sends frames from the channel to the connection.
///
/// Handles both outbound messages from the relay and ACK frames from the
/// reader. CRITICAL: ACK frames (especially heartbeat ACKs) must be transmitted
/// to prevent tunnel timeouts on low-traffic connections.
async fn tunnel_writer_loop(
    mut write_half: WriteHalf<TlsStream<TcpStream>>,
    mut receiver: mpsc::Receiver<ControlFrame>,
    mut ack_receiver: mpsc::Receiver<ControlFrame>,
) {
    loop {
        tokio::select! {
            // Handle outbound messages from relay
            Some(frame) = receiver.recv() => {
                if let Err(e) = write_half.write_all(frame.as_bytes()).await {
                    tracing::debug!(error = %e, "Failed to write frame to tunnel");
                    break;
                }
                if let Err(e) = write_half.flush().await {
                    tracing::debug!(error = %e, "Failed to flush tunnel write");
                    break;
                }
            }
            // Handle ACK frames from reader (CRITICAL: heartbeat ACKs must be sent)
            Some(ack_frame) = ack_receiver.recv() => {
                if let Err(e) = write_half.write_all(ack_frame.as_bytes()).await {
                    tracing::debug!(error = %e, "Failed to write ACK frame to tunnel");
                    break;
                }
                if let Err(e) = write_half.flush().await {
                    tracing::debug!(error = %e, "Failed to flush ACK frame");
                    break;
                }
            }
            // Both channels closed
            else => break,
        }
    }
}

/// Reader loop that reads frames from the connection and processes them.
///
/// # Security
///
/// All incoming frames are validated to ensure their `tunnel_id` matches the
/// `expected_tunnel_id` that was bound during registration. This prevents
/// cross-tunnel identity spoofing.
///
/// Protocol errors result in connection termination (fail-closed).
async fn tunnel_reader_loop(
    mut read_half: ReadHalf<TlsStream<TcpStream>>,
    registry: Arc<TunnelRegistry>,
    expected_tunnel_id: String,
    ack_sender: mpsc::Sender<ControlFrame>,
) -> Result<(), RelayError> {
    let mut buf = [0u8; CONTROL_FRAME_SIZE];

    loop {
        // Read with heartbeat timeout
        let read_result = timeout(HEARTBEAT_TIMEOUT, read_half.read_exact(&mut buf)).await;

        match read_result {
            Ok(Ok(_)) => {
                // Parse the frame
                let frame = ControlFrame::parse(&buf)?;

                // Process the frame with identity binding
                match process_tunnel_frame_with_identity(&registry, &frame, &expected_tunnel_id)
                    .await
                {
                    Ok(Some(ack_frame)) => {
                        // CRITICAL: Send ACK frame back to worker (fixes heartbeat ACK
                        // transmission)
                        if ack_sender.send(ack_frame).await.is_err() {
                            tracing::debug!(
                                tunnel_id = %expected_tunnel_id,
                                "ACK channel closed, exiting reader loop"
                            );
                            return Err(RelayError::Shutdown);
                        }
                    },
                    Ok(None) => {
                        // Frame processed, no response needed
                    },
                    Err(e) => {
                        tracing::warn!(
                            tunnel_id = %expected_tunnel_id,
                            error = %e,
                            "Error processing tunnel frame"
                        );
                        // SECURITY: Fail-closed on all protocol errors (not just identity mismatch)
                        // Protocol violations should terminate the connection
                        return Err(e);
                    },
                }
            },
            Ok(Err(e)) => {
                // Read error
                return Err(RelayError::Network(e.into()));
            },
            Err(_) => {
                // Timeout - tunnel is stale
                tracing::info!(
                    tunnel_id = %expected_tunnel_id,
                    "Tunnel read timeout, marking as stale"
                );
                return Err(RelayError::Tunnel(TunnelError::HeartbeatTimeout {
                    tunnel_id: expected_tunnel_id,
                }));
            },
        }
    }
}

// =============================================================================
// Protocol Handlers
// =============================================================================

/// Processes an incoming control frame from a tunnel with identity validation.
///
/// # Security
///
/// This function validates that the `tunnel_id` in the frame payload matches
/// the `expected_tunnel_id` that was bound to this connection during
/// registration. This prevents cross-tunnel identity spoofing attacks where
/// a malicious peer with a valid mTLS certificate could send messages for
/// other active tunnels.
///
/// # Errors
///
/// Returns an error if:
/// - The frame cannot be processed
/// - The `tunnel_id` in the frame doesn't match the expected identity
async fn process_tunnel_frame_with_identity(
    registry: &TunnelRegistry,
    frame: &ControlFrame,
    expected_tunnel_id: &str,
) -> Result<Option<ControlFrame>, RelayError> {
    match frame.message_type() {
        MSG_TUNNEL_HEARTBEAT => {
            let heartbeat = TunnelHeartbeat::from_bytes(frame.payload())?;

            // CRITICAL: Validate tunnel_id matches the expected identity
            validate_tunnel_identity(&heartbeat.tunnel_id, expected_tunnel_id)?;

            // Update heartbeat in registry
            registry.touch(&heartbeat.tunnel_id).await?;

            // Send heartbeat ack
            let ack = TunnelHeartbeat::new(
                heartbeat.tunnel_id,
                heartbeat.sequence,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            );
            let payload = ack.to_bytes()?;
            let ack_frame = ControlFrame::new(MSG_TUNNEL_HEARTBEAT_ACK, &payload)?;
            Ok(Some(ack_frame))
        },
        MSG_TUNNEL_CLOSE => {
            let tunnel_id = std::str::from_utf8(frame.payload())
                .map_err(|e| RelayError::InvalidMessage(format!("invalid tunnel_id: {e}")))?;

            // CRITICAL: Validate tunnel_id matches the expected identity
            validate_tunnel_identity(tunnel_id, expected_tunnel_id)?;

            registry.unregister(tunnel_id).await;
            tracing::info!(tunnel_id = %tunnel_id, "Tunnel closed by worker");
            Ok(None)
        },
        MSG_TUNNEL_DATA => {
            let data = TunnelData::from_bytes(frame.payload())?;

            // CRITICAL: Validate tunnel_id matches the expected identity
            validate_tunnel_identity(&data.tunnel_id, expected_tunnel_id)?;

            // Data from worker - would be routed to appropriate client
            // This is typically handled by application-level routing
            Ok(None)
        },
        msg_type => Err(RelayError::InvalidMessage(format!(
            "unexpected message type on tunnel: {msg_type}"
        ))),
    }
}

/// Validates that a `tunnel_id` from a message matches the expected identity.
///
/// # Security
///
/// Uses constant-time comparison to prevent timing attacks that could leak
/// information about valid tunnel IDs.
///
/// # Errors
///
/// Returns `TunnelIdentityMismatch` if the IDs don't match.
fn validate_tunnel_identity(
    message_tunnel_id: &str,
    expected_tunnel_id: &str,
) -> Result<(), RelayError> {
    let msg_bytes = message_tunnel_id.as_bytes();
    let expected_bytes = expected_tunnel_id.as_bytes();
    let is_equal: bool = msg_bytes.ct_eq(expected_bytes).into();

    if !is_equal {
        return Err(RelayError::TunnelIdentityMismatch {
            expected: expected_tunnel_id.to_string(),
            received: message_tunnel_id.to_string(),
        });
    }

    Ok(())
}

/// Processes an incoming control frame from a tunnel (legacy API).
///
/// **Deprecated**: Use `process_tunnel_frame_with_identity` instead for
/// proper identity binding.
///
/// # Errors
///
/// Returns an error if the frame cannot be processed.
#[deprecated(
    since = "0.1.0",
    note = "Use process_tunnel_frame_with_identity for proper identity binding"
)]
pub async fn process_tunnel_frame(
    registry: &TunnelRegistry,
    frame: &ControlFrame,
) -> Result<Option<ControlFrame>, RelayError> {
    match frame.message_type() {
        MSG_TUNNEL_HEARTBEAT => {
            let heartbeat = TunnelHeartbeat::from_bytes(frame.payload())?;
            registry.touch(&heartbeat.tunnel_id).await?;

            // Send heartbeat ack
            let ack = TunnelHeartbeat::new(
                heartbeat.tunnel_id,
                heartbeat.sequence,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            );
            let payload = ack.to_bytes()?;
            let ack_frame = ControlFrame::new(MSG_TUNNEL_HEARTBEAT_ACK, &payload)?;
            Ok(Some(ack_frame))
        },
        MSG_TUNNEL_CLOSE => {
            let tunnel_id = std::str::from_utf8(frame.payload())
                .map_err(|e| RelayError::InvalidMessage(format!("invalid tunnel_id: {e}")))?;
            registry.unregister(tunnel_id).await;
            tracing::info!(tunnel_id = %tunnel_id, "Tunnel closed by worker");
            Ok(None)
        },
        MSG_TUNNEL_DATA => {
            // Data from worker - would be routed to appropriate client
            // This is typically handled by application-level routing
            Ok(None)
        },
        msg_type => Err(RelayError::InvalidMessage(format!(
            "unexpected message type on tunnel: {msg_type}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relay_config_builder_valid() {
        // Note: TlsConfig requires actual certificates, so we test validation
        // only Full tests with TlsConfig are in integration tests
    }

    #[test]
    fn test_relay_error_display() {
        let errors = [
            RelayError::WorkerNotFound {
                worker_id: "w-123".into(),
            },
            RelayError::TunnelNotFound {
                tunnel_id: "t-123".into(),
            },
            RelayError::MaxTunnelsReached { max: MAX_TUNNELS },
            RelayError::IdentityMismatch {
                cert_cn: "cert-cn".into(),
                worker_id: "worker-id".into(),
            },
            RelayError::DuplicateTunnelId {
                tunnel_id: "t-123".into(),
            },
            RelayError::RoutingFailed {
                worker_id: "w-123".into(),
                reason: "no healthy tunnel".into(),
            },
        ];

        for err in &errors {
            let msg = err.to_string();
            assert!(!msg.is_empty());
        }
    }

    #[tokio::test]
    async fn test_tunnel_registry_bounded() {
        let registry = TunnelRegistry::new(2);

        assert!(registry.is_empty().await);
        assert_eq!(registry.len().await, 0);
    }

    #[test]
    fn test_relay_stats() {
        let stats = RelayStats {
            total_tunnels: 10,
            active_tunnels: 8,
            unique_workers: 5,
            max_tunnels: MAX_TUNNELS,
        };

        assert_eq!(stats.total_tunnels, 10);
        assert_eq!(stats.active_tunnels, 8);
        assert_eq!(stats.unique_workers, 5);
        assert_eq!(stats.max_tunnels, MAX_TUNNELS);
    }
}

#[cfg(test)]
mod tck_00184_relay_tests {
    use super::*;

    // CTR-1303: All stores must be bounded - compile-time assertions
    const _: () = {
        assert!(MAX_TUNNELS > 0);
        assert!(MAX_TUNNELS <= 1024);
        assert!(MAX_PENDING_MESSAGES > 0);
        assert!(MAX_PENDING_MESSAGES <= 1000);
        // Per-worker tunnel limit must be positive and less than global limit
        assert!(MAX_TUNNELS_PER_WORKER > 0);
        assert!(MAX_TUNNELS_PER_WORKER <= MAX_TUNNELS);
    };

    #[tokio::test]
    async fn test_tck_00184_registry_max_tunnels() {
        // CTR-1303: Registry must enforce max tunnels
        // This is a structural test - actual enforcement is in register()
        let registry = TunnelRegistry::new(5);

        // Verify max is stored correctly
        assert_eq!(registry.max_tunnels, 5);
    }

    #[tokio::test]
    async fn test_tck_00184_registry_cleanup_stale() {
        let registry = TunnelRegistry::new(MAX_TUNNELS);

        // Cleanup on empty registry should succeed
        let stale = registry.cleanup_stale().await;
        assert!(stale.is_empty());
    }

    #[tokio::test]
    async fn test_tck_00184_registry_get_nonexistent() {
        let registry = TunnelRegistry::new(MAX_TUNNELS);

        let result = registry.get("nonexistent").await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_tck_00184_registry_get_by_worker_nonexistent() {
        let registry = TunnelRegistry::new(MAX_TUNNELS);

        let tunnels = registry.get_by_worker("nonexistent").await;
        assert!(tunnels.is_empty());
    }

    #[test]
    fn test_tck_00184_relay_stats_structure() {
        let stats = RelayStats {
            total_tunnels: 100,
            active_tunnels: 95,
            unique_workers: 50,
            max_tunnels: MAX_TUNNELS,
        };

        // Verify all fields are accessible
        assert!(stats.active_tunnels <= stats.total_tunnels);
        assert!(stats.unique_workers <= stats.total_tunnels);
        assert!(stats.total_tunnels <= stats.max_tunnels);
    }

    #[test]
    fn test_tck_00184_route_timeout_reasonable() {
        assert!(ROUTE_TIMEOUT.as_secs() >= 5, "Route timeout too short");
        assert!(ROUTE_TIMEOUT.as_secs() <= 120, "Route timeout too long");
    }

    #[test]
    fn test_tck_00184_cleanup_interval_reasonable() {
        use crate::consensus::tunnel::HEARTBEAT_TIMEOUT;
        assert!(
            CLEANUP_INTERVAL < HEARTBEAT_TIMEOUT,
            "Cleanup interval should be less than heartbeat timeout"
        );
    }

    #[test]
    fn test_tck_00184_error_variants_comprehensive() {
        // Ensure all important error cases are covered
        let _: RelayError = RelayError::WorkerNotFound {
            worker_id: String::new(),
        };
        let _: RelayError = RelayError::TunnelNotFound {
            tunnel_id: String::new(),
        };
        let _: RelayError = RelayError::MaxTunnelsReached { max: 0 };
        let _: RelayError = RelayError::IdentityMismatch {
            cert_cn: String::new(),
            worker_id: String::new(),
        };
        let _: RelayError = RelayError::DuplicateTunnelId {
            tunnel_id: String::new(),
        };
        let _: RelayError = RelayError::RoutingFailed {
            worker_id: String::new(),
            reason: String::new(),
        };
        let _: RelayError = RelayError::Shutdown;
        // Verify per-worker limit error variant exists
        let _: RelayError = RelayError::MaxTunnelsPerWorkerReached {
            worker_id: String::new(),
            current: 0,
            max: MAX_TUNNELS_PER_WORKER,
        };
        // Verify tunnel identity mismatch error variant exists (CRITICAL security fix)
        let _: RelayError = RelayError::TunnelIdentityMismatch {
            expected: String::new(),
            received: String::new(),
        };
    }

    #[test]
    fn test_tck_00184_validate_tunnel_identity_match() {
        // Matching identities should succeed
        let result = validate_tunnel_identity("tunnel-123", "tunnel-123");
        assert!(result.is_ok(), "Matching tunnel IDs should pass validation");
    }

    #[test]
    fn test_tck_00184_validate_tunnel_identity_mismatch() {
        // Mismatched identities should fail with TunnelIdentityMismatch
        let result = validate_tunnel_identity("tunnel-123", "tunnel-456");
        assert!(
            matches!(result, Err(RelayError::TunnelIdentityMismatch { .. })),
            "Mismatched tunnel IDs should fail validation"
        );

        if let Err(RelayError::TunnelIdentityMismatch { expected, received }) = result {
            assert_eq!(expected, "tunnel-456");
            assert_eq!(received, "tunnel-123");
        }
    }

    #[test]
    fn test_tck_00184_validate_tunnel_identity_empty() {
        // Empty string comparisons should work correctly
        let result = validate_tunnel_identity("", "");
        assert!(result.is_ok(), "Empty strings should match");

        let result = validate_tunnel_identity("tunnel", "");
        assert!(matches!(
            result,
            Err(RelayError::TunnelIdentityMismatch { .. })
        ));
    }

    #[test]
    fn test_tck_00184_identity_spoofing_prevention() {
        // This test verifies that the identity validation prevents cross-tunnel
        // spoofing A malicious peer cannot send messages for a different tunnel
        // ID

        // Simulate a legitimate tunnel registration
        let registered_tunnel = "legit-tunnel-abc123";

        // Attacker tries to send a message claiming to be from a different tunnel
        let attacker_claimed_tunnel = "victim-tunnel-xyz789";

        // The validation should reject the spoofed identity
        let result = validate_tunnel_identity(attacker_claimed_tunnel, registered_tunnel);
        assert!(
            matches!(result, Err(RelayError::TunnelIdentityMismatch { .. })),
            "Cross-tunnel spoofing attempt should be rejected"
        );
    }

    #[test]
    fn test_tck_00184_per_worker_tunnel_limit_constant() {
        // CTR-1303: Per-worker tunnel limit should be reasonable
        assert_eq!(
            MAX_TUNNELS_PER_WORKER, 4,
            "Per-worker tunnel limit should be 4"
        );
        // Note: MAX_TUNNELS_PER_WORKER <= MAX_TUNNELS is verified at
        // compile-time in the const block above
    }

    #[test]
    fn test_tck_00184_constant_time_comparison_trait_bound() {
        // Verify subtle::ConstantTimeEq is usable for identity comparison
        // This is a compile-time check that the trait is available
        use subtle::ConstantTimeEq;

        let a = b"test_identity";
        let b = b"test_identity";
        let c = b"other_identity";

        // Verify the API works as expected
        assert!(bool::from(a.ct_eq(b)));
        assert!(!bool::from(a.ct_eq(c)));
    }
}
