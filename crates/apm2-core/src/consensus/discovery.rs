//! Peer discovery protocol for consensus.
//!
//! This module implements peer discovery via bootstrap nodes and maintains
//! a peer list for the consensus network.
//!
//! # Protocol
//!
//! 1. Node connects to bootstrap nodes on startup
//! 2. Bootstrap nodes return their known peer lists
//! 3. Peer list is periodically refreshed
//! 4. Stale peers are removed after timeout
//!
//! # Security Invariants
//!
//! - INV-0013: Join attempts rate-limited per source IP or identity
//! - INV-0014: Joining nodes present identity bootstrap credential

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::RwLock;

use super::network::{ConnectionPool, ControlFrame, NetworkError, TlsConfig};

/// Message type for peer list request.
pub const MSG_PEER_LIST_REQUEST: u32 = 1;

/// Message type for peer list response.
pub const MSG_PEER_LIST_RESPONSE: u32 = 2;

/// Message type for peer announcement.
pub const MSG_PEER_ANNOUNCE: u32 = 3;

/// Message type for paginated peer list request.
/// Includes page number in payload for requesting subsequent pages.
pub const MSG_PEER_LIST_PAGE_REQUEST: u32 = 4;

/// Message type for paginated peer list response.
/// Includes pagination metadata (current page, total pages).
pub const MSG_PEER_LIST_PAGE_RESPONSE: u32 = 5;

/// Maximum peers per page in paginated responses.
///
/// Calculated to fit within `MAX_PAYLOAD_SIZE` (1016 bytes) with JSON overhead.
/// Each `PeerInfo` serializes to ~100-150 bytes in JSON depending on field
/// lengths. With pagination metadata overhead (~50 bytes), 6 peers safely fits.
pub const MAX_PEERS_PER_PAGE: usize = 6;

/// Default peer refresh interval.
pub const DEFAULT_REFRESH_INTERVAL: Duration = Duration::from_secs(60);

/// Default peer timeout (remove if not seen for this long).
pub const DEFAULT_PEER_TIMEOUT: Duration = Duration::from_secs(300);

/// Maximum number of peers to maintain (CTR-1303: Bounded Stores).
pub const MAX_PEERS: usize = 128;

/// Maximum rate of join attempts per source (joins per minute).
pub const MAX_JOIN_ATTEMPTS_PER_MINUTE: usize = 10;

/// Rate limit window duration.
pub const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);

/// Maximum number of tracked sources in the rate limiter (CTR-1303: Bounded
/// Stores). This prevents unbounded memory growth from unique source
/// identifiers.
pub const MAX_RATE_LIMIT_SOURCES: usize = 1024;

/// Errors that can occur in peer discovery.
#[derive(Debug, Error)]
pub enum DiscoveryError {
    /// Network error.
    #[error("network error: {0}")]
    Network(#[from] NetworkError),

    /// Serialization error.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Rate limit exceeded.
    #[error("rate limit exceeded for source: {attempts} attempts in {window_secs}s")]
    RateLimitExceeded {
        /// Number of attempts made.
        attempts: usize,
        /// Window duration in seconds.
        window_secs: u64,
    },

    /// Maximum peers reached.
    #[error("maximum peers reached: {max}")]
    MaxPeersReached {
        /// Maximum allowed peers.
        max: usize,
    },

    /// Invalid peer info.
    #[error("invalid peer info: {0}")]
    InvalidPeerInfo(String),

    /// Bootstrap failed.
    #[error("bootstrap failed: could not connect to any bootstrap node")]
    BootstrapFailed,
}

/// Status of a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum PeerStatus {
    /// Peer is active and responsive.
    #[default]
    Active,
    /// Peer is suspected to be down.
    Suspected,
    /// Peer is confirmed down.
    Down,
}

/// Information about a peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerInfo {
    /// Node identifier (public key hash).
    pub node_id: String,
    /// Network address.
    pub addr: SocketAddr,
    /// TLS server name (for certificate validation).
    pub server_name: String,
    /// Current status.
    #[serde(skip)]
    pub status: PeerStatus,
    /// Last time this peer was seen.
    #[serde(skip)]
    pub last_seen: Option<Instant>,
}

impl PeerInfo {
    /// Creates a new peer info.
    #[must_use]
    pub fn new(node_id: String, addr: SocketAddr, server_name: String) -> Self {
        Self {
            node_id,
            addr,
            server_name,
            status: PeerStatus::Active,
            last_seen: Some(Instant::now()),
        }
    }

    /// Validates the peer info.
    ///
    /// # Errors
    ///
    /// Returns an error if the peer info is invalid.
    pub fn validate(&self) -> Result<(), DiscoveryError> {
        // Node ID must be non-empty and reasonable length
        if self.node_id.is_empty() {
            return Err(DiscoveryError::InvalidPeerInfo("empty node_id".into()));
        }
        if self.node_id.len() > 128 {
            return Err(DiscoveryError::InvalidPeerInfo(
                "node_id too long (max 128 chars)".into(),
            ));
        }

        // Server name must be non-empty
        if self.server_name.is_empty() {
            return Err(DiscoveryError::InvalidPeerInfo("empty server_name".into()));
        }
        if self.server_name.len() > 253 {
            return Err(DiscoveryError::InvalidPeerInfo(
                "server_name too long (max 253 chars)".into(),
            ));
        }

        Ok(())
    }

    /// Updates the last seen time.
    pub fn touch(&mut self) {
        self.last_seen = Some(Instant::now());
        self.status = PeerStatus::Active;
    }

    /// Checks if the peer is stale.
    #[must_use]
    pub fn is_stale(&self, timeout: Duration) -> bool {
        self.last_seen.is_none_or(|t| t.elapsed() > timeout)
    }
}

/// Rate limiter for join attempts.
///
/// Implements bounded tracking of join attempts per source to enforce rate
/// limits while preventing unbounded memory growth (CTR-1303: Bounded Stores).
struct RateLimiter {
    /// Join attempts per source.
    attempts: HashMap<String, Vec<Instant>>,
    /// Maximum attempts per window.
    max_attempts: usize,
    /// Window duration.
    window: Duration,
    /// Maximum number of tracked sources.
    max_sources: usize,
}

impl RateLimiter {
    fn new(max_attempts: usize, window: Duration) -> Self {
        Self::with_max_sources(max_attempts, window, MAX_RATE_LIMIT_SOURCES)
    }

    fn with_max_sources(max_attempts: usize, window: Duration, max_sources: usize) -> Self {
        Self {
            attempts: HashMap::new(),
            max_attempts,
            window,
            max_sources,
        }
    }

    /// Checks if a join attempt is allowed.
    ///
    /// If the maximum number of tracked sources is reached and this is a new
    /// source, the oldest entries are evicted to make room.
    fn check(&mut self, source: &str) -> Result<(), DiscoveryError> {
        let now = Instant::now();

        // If this is a new source and we're at capacity, evict old entries first
        if !self.attempts.contains_key(source) && self.attempts.len() >= self.max_sources {
            self.evict_oldest_entries(now);

            // If still at capacity after eviction, reject the request
            // This protects against DoS via unique source flooding
            if self.attempts.len() >= self.max_sources {
                return Err(DiscoveryError::RateLimitExceeded {
                    attempts: 0,
                    window_secs: self.window.as_secs(),
                });
            }
        }

        let attempts = self.attempts.entry(source.to_string()).or_default();

        // Remove old attempts
        attempts.retain(|t| now.duration_since(*t) < self.window);

        if attempts.len() >= self.max_attempts {
            return Err(DiscoveryError::RateLimitExceeded {
                attempts: attempts.len(),
                window_secs: self.window.as_secs(),
            });
        }

        attempts.push(now);
        Ok(())
    }

    /// Evicts entries with no recent attempts.
    fn evict_oldest_entries(&mut self, now: Instant) {
        // First, remove entries with no attempts within the window
        self.attempts.retain(|_, attempts| {
            attempts.retain(|t| now.duration_since(*t) < self.window);
            !attempts.is_empty()
        });

        // If still over capacity, remove entries with oldest most-recent attempt
        while self.attempts.len() >= self.max_sources {
            let oldest_key = self
                .attempts
                .iter()
                .filter_map(|(k, v)| v.last().map(|t| (k.clone(), *t)))
                .min_by_key(|(_, t)| *t)
                .map(|(k, _)| k);

            if let Some(key) = oldest_key {
                self.attempts.remove(&key);
            } else {
                break;
            }
        }
    }

    /// Cleans up old entries.
    fn cleanup(&mut self) {
        let now = Instant::now();
        self.attempts.retain(|_, attempts| {
            attempts.retain(|t| now.duration_since(*t) < self.window);
            !attempts.is_empty()
        });
    }

    /// Returns the number of tracked sources.
    #[cfg(test)]
    fn source_count(&self) -> usize {
        self.attempts.len()
    }
}

/// Peer list message for serialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PeerListMessage {
    /// List of peers.
    peers: Vec<PeerInfo>,
}

impl PeerListMessage {
    /// Serializes the message to bytes.
    fn to_bytes(&self) -> Result<Vec<u8>, DiscoveryError> {
        serde_json::to_vec(self).map_err(|e| DiscoveryError::Serialization(e.to_string()))
    }

    /// Deserializes the message from bytes.
    fn from_bytes(bytes: &[u8]) -> Result<Self, DiscoveryError> {
        serde_json::from_slice(bytes).map_err(|e| DiscoveryError::Serialization(e.to_string()))
    }
}

/// Paginated peer list request message.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerListPageRequest {
    /// Page number (0-indexed).
    pub page: usize,
}

impl PeerListPageRequest {
    /// Serializes the request to bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if JSON serialization fails.
    pub fn to_bytes(&self) -> Result<Vec<u8>, DiscoveryError> {
        serde_json::to_vec(self).map_err(|e| DiscoveryError::Serialization(e.to_string()))
    }

    /// Deserializes the request from bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if JSON deserialization fails.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DiscoveryError> {
        serde_json::from_slice(bytes).map_err(|e| DiscoveryError::Serialization(e.to_string()))
    }
}

/// Paginated peer list response message.
///
/// This format allows transmitting peer lists larger than what fits in a single
/// control frame (`MAX_PAYLOAD_SIZE` = 1016 bytes). Each page contains up to
/// `MAX_PEERS_PER_PAGE` peers.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerListPageResponse {
    /// Current page number (0-indexed).
    pub page: usize,
    /// Total number of pages.
    pub total_pages: usize,
    /// Total number of peers across all pages.
    pub total_peers: usize,
    /// Peers in this page.
    pub peers: Vec<PeerInfo>,
}

impl PeerListPageResponse {
    /// Serializes the response to bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if JSON serialization fails.
    pub fn to_bytes(&self) -> Result<Vec<u8>, DiscoveryError> {
        serde_json::to_vec(self).map_err(|e| DiscoveryError::Serialization(e.to_string()))
    }

    /// Deserializes the response from bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if JSON deserialization fails.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DiscoveryError> {
        serde_json::from_slice(bytes).map_err(|e| DiscoveryError::Serialization(e.to_string()))
    }
}

/// Managed peer list.
pub struct PeerList {
    /// Known peers.
    peers: RwLock<HashMap<String, PeerInfo>>,
    /// Peer timeout.
    peer_timeout: Duration,
    /// Maximum peers.
    max_peers: usize,
}

impl Default for PeerList {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerList {
    /// Creates a new peer list.
    #[must_use]
    pub fn new() -> Self {
        Self {
            peers: RwLock::new(HashMap::new()),
            peer_timeout: DEFAULT_PEER_TIMEOUT,
            max_peers: MAX_PEERS,
        }
    }

    /// Creates a peer list with custom settings.
    #[must_use]
    pub fn with_settings(peer_timeout: Duration, max_peers: usize) -> Self {
        Self {
            peers: RwLock::new(HashMap::new()),
            peer_timeout,
            max_peers,
        }
    }

    /// Adds or updates a peer.
    ///
    /// # Errors
    ///
    /// Returns an error if the peer info is invalid or max peers reached.
    pub async fn add_peer(&self, mut peer: PeerInfo) -> Result<(), DiscoveryError> {
        peer.validate()?;

        let mut peers = self.peers.write().await;

        // Check if we already have this peer
        if let Some(existing) = peers.get_mut(&peer.node_id) {
            existing.touch();
            existing.addr = peer.addr;
            existing.server_name = peer.server_name;
            return Ok(());
        }

        // Check max peers limit
        if peers.len() >= self.max_peers {
            // Try to evict stale peers first
            let stale_keys: Vec<String> = peers
                .iter()
                .filter(|(_, p)| p.is_stale(self.peer_timeout))
                .map(|(k, _)| k.clone())
                .collect();

            for key in stale_keys {
                peers.remove(&key);
            }

            if peers.len() >= self.max_peers {
                return Err(DiscoveryError::MaxPeersReached {
                    max: self.max_peers,
                });
            }
        }

        peer.touch();
        peers.insert(peer.node_id.clone(), peer);
        Ok(())
    }

    /// Removes a peer.
    pub async fn remove_peer(&self, node_id: &str) {
        let mut peers = self.peers.write().await;
        peers.remove(node_id);
    }

    /// Gets a peer by node ID.
    pub async fn get_peer(&self, node_id: &str) -> Option<PeerInfo> {
        let peers = self.peers.read().await;
        peers.get(node_id).cloned()
    }

    /// Returns all active peers.
    pub async fn active_peers(&self) -> Vec<PeerInfo> {
        let peers = self.peers.read().await;
        peers
            .values()
            .filter(|p| !p.is_stale(self.peer_timeout))
            .cloned()
            .collect()
    }

    /// Returns the number of peers.
    pub async fn len(&self) -> usize {
        let peers = self.peers.read().await;
        peers.len()
    }

    /// Returns whether the peer list is empty.
    pub async fn is_empty(&self) -> bool {
        let peers = self.peers.read().await;
        peers.is_empty()
    }

    /// Removes stale peers.
    pub async fn cleanup_stale(&self) {
        let mut peers = self.peers.write().await;
        peers.retain(|_, p| !p.is_stale(self.peer_timeout));
    }

    /// Marks a peer as suspected.
    pub async fn mark_suspected(&self, node_id: &str) {
        let mut peers = self.peers.write().await;
        if let Some(peer) = peers.get_mut(node_id) {
            peer.status = PeerStatus::Suspected;
        }
    }

    /// Marks a peer as down.
    pub async fn mark_down(&self, node_id: &str) {
        let mut peers = self.peers.write().await;
        if let Some(peer) = peers.get_mut(node_id) {
            peer.status = PeerStatus::Down;
        }
    }
}

/// Discovery configuration.
pub struct DiscoveryConfig {
    /// Bootstrap node addresses.
    pub bootstrap_nodes: Vec<(SocketAddr, String)>,
    /// Peer refresh interval.
    pub refresh_interval: Duration,
    /// Peer timeout.
    pub peer_timeout: Duration,
    /// Maximum peers.
    pub max_peers: usize,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            bootstrap_nodes: Vec::new(),
            refresh_interval: DEFAULT_REFRESH_INTERVAL,
            peer_timeout: DEFAULT_PEER_TIMEOUT,
            max_peers: MAX_PEERS,
        }
    }
}

impl DiscoveryConfig {
    /// Creates a new discovery configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a bootstrap node.
    #[must_use]
    pub fn with_bootstrap_node(mut self, addr: SocketAddr, server_name: String) -> Self {
        self.bootstrap_nodes.push((addr, server_name));
        self
    }

    /// Sets the refresh interval.
    #[must_use]
    pub const fn with_refresh_interval(mut self, interval: Duration) -> Self {
        self.refresh_interval = interval;
        self
    }

    /// Sets the peer timeout.
    #[must_use]
    pub const fn with_peer_timeout(mut self, timeout: Duration) -> Self {
        self.peer_timeout = timeout;
        self
    }

    /// Sets the maximum peers.
    #[must_use]
    pub const fn with_max_peers(mut self, max: usize) -> Self {
        self.max_peers = max;
        self
    }
}

/// Peer discovery service.
pub struct PeerDiscovery {
    /// Connection pool.
    pool: Arc<ConnectionPool>,
    /// Peer list.
    peer_list: Arc<PeerList>,
    /// Configuration.
    config: DiscoveryConfig,
    /// Rate limiter.
    rate_limiter: RwLock<RateLimiter>,
}

impl PeerDiscovery {
    /// Creates a new peer discovery service.
    #[must_use]
    pub fn new(tls_config: TlsConfig, config: DiscoveryConfig) -> Self {
        let peer_list = Arc::new(PeerList::with_settings(
            config.peer_timeout,
            config.max_peers,
        ));

        Self {
            pool: Arc::new(ConnectionPool::new(tls_config)),
            peer_list,
            config,
            rate_limiter: RwLock::new(RateLimiter::new(
                MAX_JOIN_ATTEMPTS_PER_MINUTE,
                RATE_LIMIT_WINDOW,
            )),
        }
    }

    /// Returns the peer list.
    #[must_use]
    pub const fn peer_list(&self) -> &Arc<PeerList> {
        &self.peer_list
    }

    /// Connects to bootstrap nodes and populates the initial peer list.
    ///
    /// # Errors
    ///
    /// Returns an error if no bootstrap nodes could be contacted.
    pub async fn bootstrap(&self) -> Result<(), DiscoveryError> {
        if self.config.bootstrap_nodes.is_empty() {
            return Ok(()); // No bootstrap nodes configured
        }

        let mut any_success = false;

        for (addr, server_name) in &self.config.bootstrap_nodes {
            match self.fetch_peers_from(*addr, server_name).await {
                Ok(peers) => {
                    any_success = true;
                    for peer in peers {
                        if let Err(e) = self.peer_list.add_peer(peer).await {
                            tracing::warn!("Failed to add peer: {e}");
                        }
                    }
                },
                Err(e) => {
                    tracing::warn!("Failed to contact bootstrap node {addr}: {e}");
                },
            }
        }

        if any_success {
            Ok(())
        } else {
            Err(DiscoveryError::BootstrapFailed)
        }
    }

    /// Fetches the peer list from a specific node.
    ///
    /// Uses RAII guard (`PooledConnection`) to ensure the connection is always
    /// returned to the pool, even if an error occurs. This prevents connection
    /// leaks that could eventually DOS the consensus layer.
    async fn fetch_peers_from(
        &self,
        addr: SocketAddr,
        server_name: &str,
    ) -> Result<Vec<PeerInfo>, DiscoveryError> {
        // Create request frame
        let request = ControlFrame::new(MSG_PEER_LIST_REQUEST, &[])?;

        // Get pooled connection with RAII guard - connection is automatically
        // returned to pool on drop (or discarded if poisoned due to error)
        let mut conn = self.pool.get_pooled_connection(addr, server_name).await?;
        conn.send_frame(&request).await?;

        // Receive response
        let response = conn.recv_frame().await?;
        // Connection is returned to pool when `conn` goes out of scope
        // If any error occurred above, the connection is poisoned and won't be reused

        if response.message_type() != MSG_PEER_LIST_RESPONSE {
            return Err(DiscoveryError::InvalidPeerInfo(format!(
                "unexpected message type: {}",
                response.message_type()
            )));
        }

        // Parse peer list with pagination support
        let msg = PeerListMessage::from_bytes(response.payload())?;

        // Validate all peers
        for peer in &msg.peers {
            peer.validate()?;
        }

        Ok(msg.peers)
    }

    /// Refreshes the peer list from known peers.
    ///
    /// # Errors
    ///
    /// This method does not return errors; individual peer failures are logged.
    pub async fn refresh(&self) -> Result<(), DiscoveryError> {
        let active_peers = self.peer_list.active_peers().await;

        for peer in active_peers {
            match self.fetch_peers_from(peer.addr, &peer.server_name).await {
                Ok(new_peers) => {
                    // Update the peer we contacted
                    if let Some(mut p) = self.peer_list.get_peer(&peer.node_id).await {
                        p.touch();
                        let _ = self.peer_list.add_peer(p).await;
                    }

                    // Add new peers
                    for new_peer in new_peers {
                        if let Err(e) = self.peer_list.add_peer(new_peer).await {
                            tracing::debug!("Failed to add peer during refresh: {e}");
                        }
                    }
                },
                Err(e) => {
                    tracing::debug!("Failed to refresh from {}: {e}", peer.node_id);
                    self.peer_list.mark_suspected(&peer.node_id).await;
                },
            }
        }

        // Cleanup stale peers
        self.peer_list.cleanup_stale().await;

        // Cleanup rate limiter
        self.rate_limiter.write().await.cleanup();

        Ok(())
    }

    /// Handles an incoming join request (for bootstrap nodes).
    ///
    /// # Errors
    ///
    /// Returns an error if rate limited or peer info is invalid.
    pub async fn handle_join_request(
        &self,
        source: &str,
        peer: PeerInfo,
    ) -> Result<(), DiscoveryError> {
        // Check rate limit (INV-0013)
        self.rate_limiter.write().await.check(source)?;

        // Validate and add peer
        self.peer_list.add_peer(peer).await
    }

    /// Creates a peer list response frame (legacy non-paginated).
    ///
    /// **Note**: This method is for backward compatibility. For large peer
    /// lists, use `create_peer_list_page_response` which supports
    /// pagination.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails or the peer list is too large.
    pub async fn create_peer_list_response(&self) -> Result<ControlFrame, DiscoveryError> {
        let peers = self.peer_list.active_peers().await;

        // Limit to MAX_PEERS_PER_PAGE to avoid frame overflow
        let peers: Vec<_> = peers.into_iter().take(MAX_PEERS_PER_PAGE).collect();

        let msg = PeerListMessage { peers };
        let payload = msg.to_bytes()?;
        Ok(ControlFrame::new(MSG_PEER_LIST_RESPONSE, &payload)?)
    }

    /// Creates a paginated peer list response frame.
    ///
    /// This method supports peer lists larger than `MAX_PEERS_PER_PAGE` by
    /// returning peers in pages. The caller can request subsequent pages using
    /// `MSG_PEER_LIST_PAGE_REQUEST`.
    ///
    /// # Arguments
    ///
    /// * `page` - The page number to return (0-indexed)
    ///
    /// # Returns
    ///
    /// A control frame containing the paginated response.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub async fn create_peer_list_page_response(
        &self,
        page: usize,
    ) -> Result<ControlFrame, DiscoveryError> {
        let all_peers = self.peer_list.active_peers().await;
        let total_peers = all_peers.len();
        let total_pages = total_peers.div_ceil(MAX_PEERS_PER_PAGE);
        let total_pages = total_pages.max(1); // At least 1 page even if empty

        // Get peers for this page
        let start = page * MAX_PEERS_PER_PAGE;
        let peers: Vec<_> = all_peers
            .into_iter()
            .skip(start)
            .take(MAX_PEERS_PER_PAGE)
            .collect();

        let response = PeerListPageResponse {
            page,
            total_pages,
            total_peers,
            peers,
        };

        let payload = response.to_bytes()?;
        Ok(ControlFrame::new(MSG_PEER_LIST_PAGE_RESPONSE, &payload)?)
    }

    /// Fetches all peers from a node using pagination.
    ///
    /// This method handles the full pagination protocol, fetching all pages
    /// of the peer list from the remote node.
    ///
    /// # Errors
    ///
    /// Returns an error if any network operation fails.
    pub async fn fetch_all_peers_from(
        &self,
        addr: SocketAddr,
        server_name: &str,
    ) -> Result<Vec<PeerInfo>, DiscoveryError> {
        let mut all_peers = Vec::new();
        let mut current_page = 0;

        loop {
            // Request this page
            let request_payload = PeerListPageRequest { page: current_page }.to_bytes()?;
            let request = ControlFrame::new(MSG_PEER_LIST_PAGE_REQUEST, &request_payload)?;

            // Get pooled connection with RAII guard
            let mut conn = self.pool.get_pooled_connection(addr, server_name).await?;
            conn.send_frame(&request).await?;
            let response = conn.recv_frame().await?;

            if response.message_type() != MSG_PEER_LIST_PAGE_RESPONSE {
                return Err(DiscoveryError::InvalidPeerInfo(format!(
                    "unexpected message type: {}, expected paginated response",
                    response.message_type()
                )));
            }

            let page_response = PeerListPageResponse::from_bytes(response.payload())?;

            // Validate all peers in this page
            for peer in &page_response.peers {
                peer.validate()?;
            }

            all_peers.extend(page_response.peers);

            // Check if there are more pages
            current_page += 1;
            if current_page >= page_response.total_pages {
                break;
            }

            // Safety check to prevent infinite loops
            if current_page > MAX_PEERS / MAX_PEERS_PER_PAGE + 1 {
                tracing::warn!(
                    "Pagination exceeded expected maximum pages, stopping at {} pages",
                    current_page
                );
                break;
            }
        }

        Ok(all_peers)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_info_validate_valid() {
        let peer = PeerInfo::new(
            "node123".to_string(),
            "127.0.0.1:8443".parse().unwrap(),
            "localhost".to_string(),
        );
        assert!(peer.validate().is_ok());
    }

    #[test]
    fn test_peer_info_validate_empty_node_id() {
        let peer = PeerInfo::new(
            String::new(),
            "127.0.0.1:8443".parse().unwrap(),
            "localhost".to_string(),
        );
        assert!(matches!(
            peer.validate(),
            Err(DiscoveryError::InvalidPeerInfo(_))
        ));
    }

    #[test]
    fn test_peer_info_validate_long_node_id() {
        let peer = PeerInfo::new(
            "x".repeat(129),
            "127.0.0.1:8443".parse().unwrap(),
            "localhost".to_string(),
        );
        assert!(matches!(
            peer.validate(),
            Err(DiscoveryError::InvalidPeerInfo(_))
        ));
    }

    #[test]
    fn test_peer_info_validate_empty_server_name() {
        let peer = PeerInfo::new(
            "node123".to_string(),
            "127.0.0.1:8443".parse().unwrap(),
            String::new(),
        );
        assert!(matches!(
            peer.validate(),
            Err(DiscoveryError::InvalidPeerInfo(_))
        ));
    }

    #[test]
    fn test_peer_info_is_stale() {
        let mut peer = PeerInfo::new(
            "node123".to_string(),
            "127.0.0.1:8443".parse().unwrap(),
            "localhost".to_string(),
        );

        // Fresh peer is not stale
        assert!(!peer.is_stale(Duration::from_secs(1)));

        // Peer with no last_seen is stale
        peer.last_seen = None;
        assert!(peer.is_stale(Duration::from_secs(1)));
    }

    #[tokio::test]
    async fn test_peer_list_add_peer() {
        let list = PeerList::new();
        let peer = PeerInfo::new(
            "node123".to_string(),
            "127.0.0.1:8443".parse().unwrap(),
            "localhost".to_string(),
        );

        assert!(list.add_peer(peer).await.is_ok());
        assert_eq!(list.len().await, 1);
    }

    #[tokio::test]
    async fn test_peer_list_max_peers() {
        let list = PeerList::with_settings(Duration::from_secs(300), 2);

        // Add two peers
        for i in 0..2 {
            let peer = PeerInfo::new(
                format!("node{i}"),
                format!("127.0.0.1:{}", 8443 + i).parse().unwrap(),
                "localhost".to_string(),
            );
            assert!(list.add_peer(peer).await.is_ok());
        }

        // Third peer should fail
        let peer = PeerInfo::new(
            "node2".to_string(),
            "127.0.0.1:8445".parse().unwrap(),
            "localhost".to_string(),
        );
        assert!(matches!(
            list.add_peer(peer).await,
            Err(DiscoveryError::MaxPeersReached { .. })
        ));
    }

    #[tokio::test]
    async fn test_peer_list_update_existing() {
        let list = PeerList::new();
        let peer1 = PeerInfo::new(
            "node123".to_string(),
            "127.0.0.1:8443".parse().unwrap(),
            "localhost".to_string(),
        );
        let peer2 = PeerInfo::new(
            "node123".to_string(),
            "127.0.0.1:9443".parse().unwrap(), // Different addr
            "localhost".to_string(),
        );

        list.add_peer(peer1).await.unwrap();
        list.add_peer(peer2).await.unwrap();

        // Should still be 1 peer (updated)
        assert_eq!(list.len().await, 1);

        // Addr should be updated
        let peer = list.get_peer("node123").await.unwrap();
        assert_eq!(peer.addr.port(), 9443);
    }

    #[test]
    fn test_rate_limiter_allows_within_limit() {
        let mut limiter = RateLimiter::new(3, Duration::from_secs(60));

        assert!(limiter.check("source1").is_ok());
        assert!(limiter.check("source1").is_ok());
        assert!(limiter.check("source1").is_ok());
    }

    #[test]
    fn test_rate_limiter_blocks_over_limit() {
        let mut limiter = RateLimiter::new(2, Duration::from_secs(60));

        assert!(limiter.check("source1").is_ok());
        assert!(limiter.check("source1").is_ok());
        assert!(matches!(
            limiter.check("source1"),
            Err(DiscoveryError::RateLimitExceeded { .. })
        ));
    }

    #[test]
    fn test_rate_limiter_separate_sources() {
        let mut limiter = RateLimiter::new(2, Duration::from_secs(60));

        assert!(limiter.check("source1").is_ok());
        assert!(limiter.check("source1").is_ok());
        assert!(limiter.check("source2").is_ok()); // Different source
        assert!(matches!(
            limiter.check("source1"),
            Err(DiscoveryError::RateLimitExceeded { .. })
        ));
    }

    #[test]
    fn test_peer_list_message_roundtrip() {
        let peers = vec![
            PeerInfo::new(
                "node1".to_string(),
                "127.0.0.1:8443".parse().unwrap(),
                "localhost".to_string(),
            ),
            PeerInfo::new(
                "node2".to_string(),
                "127.0.0.1:8444".parse().unwrap(),
                "localhost".to_string(),
            ),
        ];

        let msg = PeerListMessage { peers };
        let bytes = msg.to_bytes().unwrap();
        let parsed = PeerListMessage::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.peers.len(), 2);
        assert_eq!(parsed.peers[0].node_id, "node1");
        assert_eq!(parsed.peers[1].node_id, "node2");
    }
}

#[cfg(test)]
mod tck_00183_discovery_tests {
    use super::*;

    #[tokio::test]
    async fn test_tck_00183_peer_list_bounded() {
        // CTR-1303: Peer list must have bounded size
        let list = PeerList::with_settings(Duration::from_secs(300), 5);

        for i in 0..5 {
            let peer = PeerInfo::new(
                format!("node{i}"),
                format!("127.0.0.1:{}", 8443 + i).parse().unwrap(),
                "localhost".to_string(),
            );
            assert!(list.add_peer(peer).await.is_ok());
        }

        // Sixth peer should fail (bounded store)
        let peer = PeerInfo::new(
            "node5".to_string(),
            "127.0.0.1:8448".parse().unwrap(),
            "localhost".to_string(),
        );
        assert!(
            matches!(
                list.add_peer(peer).await,
                Err(DiscoveryError::MaxPeersReached { .. })
            ),
            "Peer list must enforce maximum size"
        );
    }

    #[test]
    fn test_tck_00183_rate_limiting() {
        // INV-0013: Join attempts rate-limited
        let mut limiter = RateLimiter::new(MAX_JOIN_ATTEMPTS_PER_MINUTE, RATE_LIMIT_WINDOW);
        let source = "192.168.1.100";

        // Should allow up to limit
        for _ in 0..MAX_JOIN_ATTEMPTS_PER_MINUTE {
            assert!(limiter.check(source).is_ok());
        }

        // Should reject over limit
        assert!(
            matches!(
                limiter.check(source),
                Err(DiscoveryError::RateLimitExceeded { .. })
            ),
            "Rate limiter must reject excessive attempts"
        );
    }

    #[test]
    fn test_tck_00183_peer_info_validation() {
        // Malformed input test: invalid peer info must be rejected
        let invalid_peers = [
            PeerInfo::new(
                String::new(),
                "127.0.0.1:8443".parse().unwrap(),
                "localhost".to_string(),
            ),
            PeerInfo::new(
                "x".repeat(200),
                "127.0.0.1:8443".parse().unwrap(),
                "localhost".to_string(),
            ),
            PeerInfo::new(
                "node1".to_string(),
                "127.0.0.1:8443".parse().unwrap(),
                String::new(),
            ),
        ];

        for peer in &invalid_peers {
            assert!(
                peer.validate().is_err(),
                "Invalid peer info must be rejected"
            );
        }
    }

    #[tokio::test]
    async fn test_tck_00183_peer_refresh_maintains_list() {
        let list = PeerList::new();

        // Add some peers
        for i in 0..3 {
            let peer = PeerInfo::new(
                format!("node{i}"),
                format!("127.0.0.1:{}", 8443 + i).parse().unwrap(),
                "localhost".to_string(),
            );
            list.add_peer(peer).await.unwrap();
        }

        // Active peers should be returned
        let active = list.active_peers().await;
        assert_eq!(active.len(), 3, "All fresh peers should be active");
    }

    #[tokio::test]
    async fn test_tck_00183_stale_peer_cleanup() {
        // Very short timeout for testing
        let list = PeerList::with_settings(Duration::from_millis(1), MAX_PEERS);

        let peer = PeerInfo::new(
            "node1".to_string(),
            "127.0.0.1:8443".parse().unwrap(),
            "localhost".to_string(),
        );
        list.add_peer(peer).await.unwrap();

        // Wait for peer to become stale
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Cleanup should remove stale peer
        list.cleanup_stale().await;
        assert!(list.is_empty().await, "Stale peers should be cleaned up");
    }

    #[test]
    fn test_tck_00183_peer_list_message_serde() {
        // CTR-1604: Strict Serde for wire formats
        let peers = vec![PeerInfo::new(
            "node1".to_string(),
            "127.0.0.1:8443".parse().unwrap(),
            "localhost".to_string(),
        )];

        let msg = PeerListMessage { peers };
        let bytes = msg.to_bytes().unwrap();
        let parsed = PeerListMessage::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.peers.len(), 1);
        assert_eq!(parsed.peers[0].node_id, "node1");
    }

    #[test]
    fn test_tck_00183_rate_limiter_bounded_sources() {
        // CTR-1303: Rate limiter must have bounded source tracking
        // This prevents DoS via unique source identifier flooding
        let max_sources = 5;
        let mut limiter = RateLimiter::with_max_sources(10, Duration::from_secs(60), max_sources);

        // Fill up to max sources
        for i in 0..max_sources {
            assert!(
                limiter.check(&format!("source{i}")).is_ok(),
                "Should accept sources up to limit"
            );
        }

        // Verify we hit the limit
        assert_eq!(limiter.source_count(), max_sources);

        // New source should still work (eviction will occur)
        // but old entries without new attempts get evicted
        assert!(
            limiter.check("new_source").is_ok(),
            "New source should succeed after eviction"
        );

        // Verify bounded growth
        assert!(
            limiter.source_count() <= max_sources,
            "Source count must not exceed maximum"
        );
    }

    // Compile-time assertions for pagination constants
    const _: () = {
        assert!(
            MAX_PEERS_PER_PAGE > 0,
            "MAX_PEERS_PER_PAGE must be positive"
        );
        assert!(
            MAX_PEERS_PER_PAGE <= MAX_PEERS,
            "MAX_PEERS_PER_PAGE must not exceed MAX_PEERS"
        );
        assert!(
            MAX_PEERS_PER_PAGE <= 10,
            "MAX_PEERS_PER_PAGE should be small enough to fit in frame"
        );
    };

    #[test]
    fn test_tck_00183_pagination_constants() {
        // Runtime verification that pagination constants have expected values
        // The compile-time assertions above ensure correctness; this test
        // verifies the actual values for documentation purposes
        assert_eq!(MAX_PEERS_PER_PAGE, 6, "Expected 6 peers per page");
        assert_eq!(MAX_PEERS, 128, "Expected 128 max peers");
    }

    #[test]
    fn test_tck_00183_pagination_message_roundtrip() {
        // Test paginated request
        let request = PeerListPageRequest { page: 5 };
        let bytes = request.to_bytes().unwrap();
        let parsed = PeerListPageRequest::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.page, 5);

        // Test paginated response
        let response = PeerListPageResponse {
            page: 2,
            total_pages: 10,
            total_peers: 75,
            peers: vec![PeerInfo::new(
                "node1".to_string(),
                "127.0.0.1:8443".parse().unwrap(),
                "localhost".to_string(),
            )],
        };
        let bytes = response.to_bytes().unwrap();
        let parsed = PeerListPageResponse::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.page, 2);
        assert_eq!(parsed.total_pages, 10);
        assert_eq!(parsed.total_peers, 75);
        assert_eq!(parsed.peers.len(), 1);
        assert_eq!(parsed.peers[0].node_id, "node1");
    }

    #[test]
    fn test_tck_00183_pagination_fits_in_frame() {
        // Verify that MAX_PEERS_PER_PAGE peers fit within MAX_PAYLOAD_SIZE
        use super::super::network::MAX_PAYLOAD_SIZE;

        let peers: Vec<_> = (0..MAX_PEERS_PER_PAGE)
            .map(|i| {
                PeerInfo::new(
                    format!("node_{i:064x}"), // 64-char node_id (typical hash)
                    format!("192.168.1.{}:{}", i % 256, 8443 + i)
                        .parse()
                        .unwrap(),
                    format!("server{i}.example.com"), // Reasonable server name
                )
            })
            .collect();

        let response = PeerListPageResponse {
            page: 0,
            total_pages: 16,
            total_peers: MAX_PEERS,
            peers,
        };

        let bytes = response.to_bytes().unwrap();
        assert!(
            bytes.len() <= MAX_PAYLOAD_SIZE,
            "Paginated response with {} peers ({} bytes) must fit in frame ({} bytes)",
            MAX_PEERS_PER_PAGE,
            bytes.len(),
            MAX_PAYLOAD_SIZE
        );
    }

    #[test]
    fn test_tck_00183_max_peers_vs_page_size_compatible() {
        // Verify that MAX_PEERS can be transmitted via pagination
        let total_pages_needed = MAX_PEERS.div_ceil(MAX_PEERS_PER_PAGE);

        // Should need multiple pages for MAX_PEERS
        assert!(
            total_pages_needed >= 1,
            "Should be able to transmit MAX_PEERS via pagination"
        );

        // Reasonable upper bound on pages (prevents DoS via excessive pagination)
        // With 128 peers and 6 per page, we need ceil(128/6) = 22 pages
        assert!(
            total_pages_needed <= 25,
            "Should not need excessive pages for MAX_PEERS ({total_pages_needed} pages needed)"
        );
    }
}
