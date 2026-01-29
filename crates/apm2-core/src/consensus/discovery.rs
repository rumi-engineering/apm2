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
struct RateLimiter {
    /// Join attempts per source.
    attempts: HashMap<String, Vec<Instant>>,
    /// Maximum attempts per window.
    max_attempts: usize,
    /// Window duration.
    window: Duration,
}

impl RateLimiter {
    fn new(max_attempts: usize, window: Duration) -> Self {
        Self {
            attempts: HashMap::new(),
            max_attempts,
            window,
        }
    }

    /// Checks if a join attempt is allowed.
    fn check(&mut self, source: &str) -> Result<(), DiscoveryError> {
        let now = Instant::now();

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

    /// Cleans up old entries.
    fn cleanup(&mut self) {
        let now = Instant::now();
        self.attempts.retain(|_, attempts| {
            attempts.retain(|t| now.duration_since(*t) < self.window);
            !attempts.is_empty()
        });
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
    async fn fetch_peers_from(
        &self,
        addr: SocketAddr,
        server_name: &str,
    ) -> Result<Vec<PeerInfo>, DiscoveryError> {
        // Create request frame
        let request = ControlFrame::new(MSG_PEER_LIST_REQUEST, &[])?;

        // Get connection and send request
        let mut conn = self.pool.get_connection(addr, server_name).await?;
        conn.send_frame(&request).await?;

        // Receive response
        let response = conn.recv_frame().await?;
        self.pool.return_connection(conn).await;

        if response.message_type() != MSG_PEER_LIST_RESPONSE {
            return Err(DiscoveryError::InvalidPeerInfo(format!(
                "unexpected message type: {}",
                response.message_type()
            )));
        }

        // Parse peer list
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

    /// Creates a peer list response frame.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub async fn create_peer_list_response(&self) -> Result<ControlFrame, DiscoveryError> {
        let peers = self.peer_list.active_peers().await;
        let msg = PeerListMessage { peers };
        let payload = msg.to_bytes()?;
        Ok(ControlFrame::new(MSG_PEER_LIST_RESPONSE, &payload)?)
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
}
