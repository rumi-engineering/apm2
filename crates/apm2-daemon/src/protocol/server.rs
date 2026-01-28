//! UDS (Unix Domain Socket) protocol server.
//!
//! This module implements the server-side of the UDS protocol for the
//! daemon. The server listens on a Unix socket and handles incoming
//! connections with framed binary messaging.
//!
//! # Socket Path
//!
//! Per AD-DAEMON-002, the default socket path is:
//! `${XDG_RUNTIME_DIR}/apm2/apm2d.sock`
//!
//! If `XDG_RUNTIME_DIR` is not set, falls back to `/tmp/apm2/apm2d.sock`.
//!
//! # Connection Lifecycle
//!
//! 1. Client connects to socket
//! 2. Client sends Hello message
//! 3. Server validates and sends `HelloAck` or `HelloNack`
//! 4. If accepted, connection enters message exchange phase
//! 5. Either party may close the connection
//!
//! # Security Considerations
//!
//! - Socket permissions: mode 0600 (owner read/write only)
//! - Parent directory created with mode 0700
//! - Stale socket files are removed before binding

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;
use tokio_util::codec::Framed;
use tracing::{debug, info, warn};

use super::error::{MAX_FRAME_SIZE, MAX_HANDSHAKE_FRAME_SIZE, ProtocolError, ProtocolResult};
use super::framing::FrameCodec;

/// Default socket filename.
const DEFAULT_SOCKET_NAME: &str = "apm2d.sock";

/// Default subdirectory under runtime directory.
const DEFAULT_SUBDIR: &str = "apm2";

/// Maximum concurrent connections.
const MAX_CONNECTIONS: usize = 100;

/// Get the default socket path based on environment.
///
/// Priority:
/// 1. `XDG_RUNTIME_DIR/apm2/apm2d.sock` if `XDG_RUNTIME_DIR` is set
/// 2. `/tmp/apm2/apm2d.sock` as fallback
#[must_use]
pub fn default_socket_path() -> PathBuf {
    std::env::var("XDG_RUNTIME_DIR").map_or_else(
        |_| {
            PathBuf::from("/tmp")
                .join(DEFAULT_SUBDIR)
                .join(DEFAULT_SOCKET_NAME)
        },
        |runtime_dir| {
            PathBuf::from(runtime_dir)
                .join(DEFAULT_SUBDIR)
                .join(DEFAULT_SOCKET_NAME)
        },
    )
}

/// Configuration for the protocol server.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Socket path to listen on.
    pub socket_path: PathBuf,

    /// Maximum concurrent connections.
    pub max_connections: usize,

    /// Server info string for handshake.
    pub server_info: String,

    /// Optional policy hash for handshake.
    pub policy_hash: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            socket_path: default_socket_path(),
            max_connections: MAX_CONNECTIONS,
            server_info: format!("apm2-daemon/{}", env!("CARGO_PKG_VERSION")),
            policy_hash: None,
        }
    }
}

impl ServerConfig {
    /// Create a new server config with the given socket path.
    #[must_use]
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
            ..Default::default()
        }
    }

    /// Set the maximum concurrent connections.
    #[must_use]
    pub const fn with_max_connections(mut self, max: usize) -> Self {
        self.max_connections = max;
        self
    }

    /// Set the server info string.
    #[must_use]
    pub fn with_server_info(mut self, info: impl Into<String>) -> Self {
        self.server_info = info.into();
        self
    }

    /// Set the policy hash.
    #[must_use]
    pub fn with_policy_hash(mut self, hash: impl Into<String>) -> Self {
        self.policy_hash = Some(hash.into());
        self
    }
}

/// UDS protocol server.
///
/// Manages the Unix domain socket listener and connection handling.
///
/// # Invariants
///
/// - [INV-SRV-001] Socket is cleaned up when server stops.
/// - [INV-SRV-002] Concurrent connections limited by semaphore.
/// - [INV-SRV-003] Handshake required before message exchange.
pub struct ProtocolServer {
    /// Server configuration.
    config: ServerConfig,

    /// Unix socket listener.
    listener: UnixListener,

    /// Connection semaphore for limiting concurrent connections.
    connection_sem: Arc<Semaphore>,
}

impl ProtocolServer {
    /// Create and bind a new protocol server.
    ///
    /// This will:
    /// 1. Create the parent directory if needed
    /// 2. Remove any stale socket file
    /// 3. Bind to the socket path
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Parent directory cannot be created
    /// - Socket cannot be bound
    /// - Stale socket cannot be removed
    pub fn bind(config: ServerConfig) -> ProtocolResult<Self> {
        // Ensure parent directory exists
        if let Some(parent) = config.socket_path.parent() {
            Self::ensure_directory(parent)?;
        }

        // Remove stale socket file if exists
        Self::cleanup_socket(&config.socket_path)?;

        // Bind to the socket
        let listener = UnixListener::bind(&config.socket_path).map_err(|e| {
            ProtocolError::Io(io::Error::new(
                e.kind(),
                format!("failed to bind to {}: {e}", config.socket_path.display()),
            ))
        })?;

        // Set socket file permissions to 0600 (owner read/write only)
        // This is critical for security when custom socket paths are used in
        // shared directories where the parent directory permissions may not
        // be restrictive (e.g., /tmp).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&config.socket_path, perms).map_err(|e| {
                ProtocolError::Io(io::Error::new(
                    e.kind(),
                    format!(
                        "failed to set socket permissions on {}: {e}",
                        config.socket_path.display()
                    ),
                ))
            })?;
        }

        info!(
            socket_path = %config.socket_path.display(),
            max_connections = config.max_connections,
            "Protocol server bound"
        );

        Ok(Self {
            connection_sem: Arc::new(Semaphore::new(config.max_connections)),
            config,
            listener,
        })
    }

    /// Ensure a directory exists with appropriate permissions.
    ///
    /// # Security
    ///
    /// This function enforces directory permissions unconditionally
    /// (fail-closed). Even if the directory already exists with loose
    /// permissions (e.g., 0777), we correct them to 0700 to prevent local
    /// manipulation of the socket.
    fn ensure_directory(path: &Path) -> ProtocolResult<()> {
        // Create directory if it doesn't exist
        if !path.exists() {
            std::fs::create_dir_all(path).map_err(|e| {
                ProtocolError::Io(io::Error::new(
                    e.kind(),
                    format!("failed to create directory {}: {e}", path.display()),
                ))
            })?;
        }

        // Always enforce directory permissions to 0700 (owner only)
        // This is critical even for pre-existing directories to prevent
        // attackers from pre-creating directories with loose permissions.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o700);
            std::fs::set_permissions(path, perms).map_err(|e| {
                ProtocolError::Io(io::Error::new(
                    e.kind(),
                    format!("failed to set permissions on {}: {e}", path.display()),
                ))
            })?;
        }

        Ok(())
    }

    /// Remove a stale socket file if it exists.
    fn cleanup_socket(path: &Path) -> ProtocolResult<()> {
        if path.exists() {
            // Check if it's actually a socket
            let metadata = std::fs::symlink_metadata(path).map_err(|e| {
                ProtocolError::Io(io::Error::new(
                    e.kind(),
                    format!("failed to stat {}: {e}", path.display()),
                ))
            })?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::FileTypeExt;
                if !metadata.file_type().is_socket() {
                    return Err(ProtocolError::Io(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        format!("path {} exists but is not a socket", path.display()),
                    )));
                }
            }

            std::fs::remove_file(path).map_err(|e| {
                ProtocolError::Io(io::Error::new(
                    e.kind(),
                    format!("failed to remove stale socket {}: {e}", path.display()),
                ))
            })?;

            debug!(path = %path.display(), "Removed stale socket file");
        }

        Ok(())
    }

    /// Accept the next incoming connection.
    ///
    /// This method blocks until a connection is available or an error occurs.
    /// The returned connection is already framed with [`FrameCodec`].
    ///
    /// # Connection Limiting
    ///
    /// Uses a semaphore to limit concurrent connections. If the limit is
    /// reached, this will wait until a slot becomes available.
    ///
    /// # Returns
    ///
    /// A tuple of:
    /// - `Connection`: The framed connection
    /// - `ConnectionPermit`: A permit that must be held while the connection is
    ///   active
    pub async fn accept(&self) -> ProtocolResult<(Connection, ConnectionPermit)> {
        // Acquire connection permit
        let permit = self
            .connection_sem
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| ProtocolError::Io(io::Error::other("connection semaphore closed")))?;

        // Accept connection
        let (stream, _addr) = self.listener.accept().await?;

        debug!("Accepted new connection");

        let connection = Connection::new(stream);
        let connection_permit = ConnectionPermit { _permit: permit };

        Ok((connection, connection_permit))
    }

    /// Returns the socket path this server is listening on.
    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.config.socket_path
    }

    /// Returns the server configuration.
    #[must_use]
    pub const fn config(&self) -> &ServerConfig {
        &self.config
    }

    /// Cleanup the socket file.
    ///
    /// Should be called when the server is shutting down.
    pub fn cleanup(&self) -> ProtocolResult<()> {
        if self.config.socket_path.exists() {
            std::fs::remove_file(&self.config.socket_path).map_err(|e| {
                ProtocolError::Io(io::Error::new(
                    e.kind(),
                    format!(
                        "failed to remove socket {}: {e}",
                        self.config.socket_path.display()
                    ),
                ))
            })?;
            info!(
                socket_path = %self.config.socket_path.display(),
                "Removed socket file"
            );
        }
        Ok(())
    }
}

impl Drop for ProtocolServer {
    fn drop(&mut self) {
        // Best-effort cleanup on drop
        if let Err(e) = self.cleanup() {
            warn!("Failed to cleanup socket on drop: {e}");
        }
    }
}

/// Permit for an active connection.
///
/// Holds a semaphore permit that is released when dropped,
/// allowing another connection to be accepted.
#[derive(Debug)]
pub struct ConnectionPermit {
    _permit: tokio::sync::OwnedSemaphorePermit,
}

/// A framed connection to a client.
///
/// Wraps a Unix stream with the frame codec for length-prefixed messaging.
///
/// # Security
///
/// Connections are initialized with [`MAX_HANDSHAKE_FRAME_SIZE`] to prevent `DoS`
/// during the unauthenticated handshake phase. After a successful handshake,
/// the connection should be upgraded to [`MAX_FRAME_SIZE`] using
/// [`Connection::upgrade_to_full_frame_size`].
pub struct Connection {
    /// The framed stream.
    framed: Framed<UnixStream, FrameCodec>,
}

impl Connection {
    /// Create a new connection from a Unix stream.
    ///
    /// Initializes with [`MAX_HANDSHAKE_FRAME_SIZE`] limit.
    fn new(stream: UnixStream) -> Self {
        Self {
            framed: Framed::new(stream, FrameCodec::with_max_size(MAX_HANDSHAKE_FRAME_SIZE)),
        }
    }

    /// Upgrade the connection to support full-sized frames.
    ///
    /// Should be called after a successful handshake to allow messages
    /// up to [`MAX_FRAME_SIZE`].
    pub fn upgrade_to_full_frame_size(&mut self) {
        self.framed.codec_mut().set_max_frame_size(MAX_FRAME_SIZE);
    }

    /// Get a reference to the underlying framed stream.
    ///
    /// Use this to send/receive frames using futures-based APIs.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // const fn with &mut return requires nightly
    pub fn framed(&mut self) -> &mut Framed<UnixStream, FrameCodec> {
        &mut self.framed
    }

    /// Get the raw Unix stream reference.
    #[must_use]
    pub fn stream(&self) -> &UnixStream {
        self.framed.get_ref()
    }

    /// Consume the connection and return the inner framed stream.
    #[must_use]
    pub fn into_framed(self) -> Framed<UnixStream, FrameCodec> {
        self.framed
    }
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("codec", &"FrameCodec")
            .finish_non_exhaustive()
    }
}

/// Connect to a protocol server as a client.
///
/// # Arguments
///
/// * `socket_path` - Path to the Unix socket to connect to
///
/// # Returns
///
/// A framed connection ready for communication.
///
/// # Errors
///
/// Returns an error if the connection fails.
pub async fn connect(socket_path: impl AsRef<Path>) -> ProtocolResult<Connection> {
    let path = socket_path.as_ref();

    let stream = UnixStream::connect(path).await.map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            ProtocolError::Io(io::Error::new(
                io::ErrorKind::NotFound,
                format!("daemon socket not found at {}", path.display()),
            ))
        } else if e.kind() == io::ErrorKind::ConnectionRefused {
            ProtocolError::Io(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("connection refused to {}", path.display()),
            ))
        } else {
            ProtocolError::Io(io::Error::new(
                e.kind(),
                format!("failed to connect to {}: {e}", path.display()),
            ))
        }
    })?;

    debug!(socket_path = %path.display(), "Connected to server");

    Ok(Connection::new(stream))
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use futures::{SinkExt, StreamExt};
    use tempfile::TempDir;

    use super::*;

    fn test_socket_path(dir: &TempDir) -> PathBuf {
        dir.path().join("test.sock")
    }

    #[tokio::test]
    async fn test_server_bind_and_cleanup() {
        let tmp = TempDir::new().unwrap();
        let socket_path = test_socket_path(&tmp);

        let config = ServerConfig::new(&socket_path);
        let server = ProtocolServer::bind(config).unwrap();

        assert!(socket_path.exists());
        assert_eq!(server.socket_path(), socket_path);

        server.cleanup().unwrap();
        assert!(!socket_path.exists());
    }

    #[tokio::test]
    async fn test_server_removes_stale_socket() {
        let tmp = TempDir::new().unwrap();
        let socket_path = test_socket_path(&tmp);

        // Create first server
        {
            let config = ServerConfig::new(&socket_path);
            let server = ProtocolServer::bind(config).unwrap();
            // Drop without cleanup to leave stale socket
            std::mem::forget(server);
        }

        assert!(socket_path.exists());

        // Second server should succeed by removing stale socket
        let config = ServerConfig::new(&socket_path);
        let server = ProtocolServer::bind(config).unwrap();
        assert!(server.socket_path().exists());
    }

    #[tokio::test]
    async fn test_connect_and_send_frame() {
        let tmp = TempDir::new().unwrap();
        let socket_path = test_socket_path(&tmp);

        let config = ServerConfig::new(&socket_path);
        let server = ProtocolServer::bind(config).unwrap();

        // Spawn server accept task
        let server_handle = tokio::spawn(async move {
            let (mut conn, _permit) = server.accept().await.unwrap();
            conn.framed().next().await.unwrap().unwrap()
        });

        // Connect as client and send frame
        let mut client = connect(&socket_path).await.unwrap();
        let payload = Bytes::from_static(b"hello server");
        client.framed().send(payload.clone()).await.unwrap();

        // Verify server received the frame
        let received = server_handle.await.unwrap();
        assert_eq!(received, payload);
    }

    #[tokio::test]
    async fn test_bidirectional_communication() {
        let tmp = TempDir::new().unwrap();
        let socket_path = test_socket_path(&tmp);

        let config = ServerConfig::new(&socket_path);
        let server = ProtocolServer::bind(config).unwrap();

        // Spawn server that echoes messages
        let server_handle = tokio::spawn(async move {
            let (mut conn, _permit) = server.accept().await.unwrap();
            while let Some(Ok(frame)) = conn.framed().next().await {
                if frame.is_empty() {
                    break;
                }
                conn.framed().send(frame).await.unwrap();
            }
        });

        // Connect as client
        let mut client = connect(&socket_path).await.unwrap();

        // Send and receive multiple messages
        for i in 0..3 {
            let msg = format!("message {i}");
            client
                .framed()
                .send(Bytes::from(msg.clone()))
                .await
                .unwrap();
            let response = client.framed().next().await.unwrap().unwrap();
            assert_eq!(response, Bytes::from(msg));
        }

        // Send empty frame to signal end
        client.framed().send(Bytes::new()).await.unwrap();
        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_connection_limit() {
        let tmp = TempDir::new().unwrap();
        let socket_path = test_socket_path(&tmp);

        let config = ServerConfig::new(&socket_path).with_max_connections(2);
        let server = Arc::new(ProtocolServer::bind(config).unwrap());

        // Connect two clients (up to limit)
        let _client1 = connect(&socket_path).await.unwrap();
        let _client2 = connect(&socket_path).await.unwrap();

        // Accept both connections
        let server_clone = Arc::clone(&server);
        let accept1 = tokio::spawn(async move { server_clone.accept().await });

        let server_clone = Arc::clone(&server);
        let accept2 = tokio::spawn(async move { server_clone.accept().await });

        let (conn1, permit1) = accept1.await.unwrap().unwrap();
        let (conn2, permit2) = accept2.await.unwrap().unwrap();

        // Third connection should block
        let _client3 = connect(&socket_path).await.unwrap();

        // Use timeout to check that accept blocks
        let server_clone = Arc::clone(&server);
        let accept3 = tokio::time::timeout(std::time::Duration::from_millis(50), async move {
            server_clone.accept().await
        });

        assert!(accept3.await.is_err(), "Third accept should have timed out");

        // Drop one permit, third connection should now succeed
        drop(permit1);
        drop(conn1);

        let server_clone = Arc::clone(&server);
        let accept3 = tokio::time::timeout(std::time::Duration::from_millis(100), async move {
            server_clone.accept().await
        });

        assert!(
            accept3.await.is_ok(),
            "Third accept should succeed after permit released"
        );

        drop(permit2);
        drop(conn2);
    }

    #[tokio::test]
    async fn test_default_socket_path() {
        let path = default_socket_path();

        // Should end with expected filename
        assert!(path.ends_with(format!("{DEFAULT_SUBDIR}/{DEFAULT_SOCKET_NAME}")));

        // Should use XDG_RUNTIME_DIR if set
        if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
            assert!(path.starts_with(runtime_dir));
        }
    }

    #[tokio::test]
    async fn test_connect_nonexistent_socket() {
        let tmp = TempDir::new().unwrap();
        let socket_path = tmp.path().join("nonexistent.sock");

        let result = connect(&socket_path).await;
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(matches!(err, ProtocolError::Io(ref e) if e.kind() == io::ErrorKind::NotFound));
    }

    #[test]
    fn test_server_config_builder() {
        let config = ServerConfig::new("/custom/path.sock")
            .with_max_connections(50)
            .with_server_info("test-server/1.0")
            .with_policy_hash("abc123");

        assert_eq!(config.socket_path, PathBuf::from("/custom/path.sock"));
        assert_eq!(config.max_connections, 50);
        assert_eq!(config.server_info, "test-server/1.0");
        assert_eq!(config.policy_hash, Some("abc123".to_string()));
    }

    /// Test that socket file permissions are set to 0600 (owner read/write
    /// only).
    ///
    /// This test verifies the security fix for custom socket paths that may be
    /// created in shared directories (e.g., /tmp) where the parent directory
    /// permissions are not restrictive.
    #[tokio::test]
    #[cfg(unix)]
    async fn test_socket_permissions_0600() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new().unwrap();
        let socket_path = test_socket_path(&tmp);

        let config = ServerConfig::new(&socket_path);
        let _server = ProtocolServer::bind(config).unwrap();

        // Verify socket file exists and has correct permissions
        let metadata = std::fs::metadata(&socket_path).unwrap();
        let mode = metadata.permissions().mode() & 0o777;

        assert_eq!(
            mode, 0o600,
            "socket permissions should be 0600, got {mode:04o}"
        );
    }

    /// Test that pre-existing directories with loose permissions are corrected.
    ///
    /// This test verifies the fail-closed security behavior: if an attacker
    /// pre-creates the socket directory with loose permissions (0777), the
    /// server must correct them to 0700 to prevent local manipulation.
    #[tokio::test]
    #[cfg(unix)]
    async fn test_directory_permissions_corrected() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new().unwrap();
        let socket_dir = tmp.path().join("apm2_test_dir");
        let socket_path = socket_dir.join("test.sock");

        // Pre-create directory with loose permissions (simulating attacker)
        std::fs::create_dir_all(&socket_dir).unwrap();
        std::fs::set_permissions(&socket_dir, std::fs::Permissions::from_mode(0o777)).unwrap();

        // Verify the directory has loose permissions
        let initial_mode = std::fs::metadata(&socket_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            initial_mode, 0o777,
            "Pre-condition: directory should be 0777"
        );

        // Bind server - should correct directory permissions
        let config = ServerConfig::new(&socket_path);
        let _server = ProtocolServer::bind(config).unwrap();

        // Verify directory permissions were corrected to 0700
        let corrected_mode = std::fs::metadata(&socket_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            corrected_mode, 0o700,
            "Directory permissions should be corrected to 0700, got {corrected_mode:04o}"
        );
    }
}
