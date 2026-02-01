//! Dual-socket manager for privilege separation (TCK-00249).
//!
//! This module implements the dual-socket topology required by RFC-0017 for
//! privilege separation between operator and session connections.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    SocketManager                            │
//! │  ┌────────────────────┐  ┌────────────────────┐            │
//! │  │   operator.sock    │  │   session.sock     │            │
//! │  │   (mode 0600)      │  │   (mode 0660)      │            │
//! │  │   is_privileged=   │  │   is_privileged=   │            │
//! │  │       true         │  │       false        │            │
//! │  └────────┬───────────┘  └────────┬───────────┘            │
//! │           │                       │                         │
//! │           └───────────┬───────────┘                         │
//! │                       ▼                                     │
//! │               ConnectionContext                             │
//! │            (socket_type, is_privileged)                     │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Socket Types
//!
//! - **Operator socket** (`operator.sock`): Mode 0600 (owner only). Connections
//!   are privileged and may invoke `ClaimWork`, `SpawnEpisode`,
//!   `IssueCapability`, and `Shutdown`.
//!
//! - **Session socket** (`session.sock`): Mode 0660 (owner + group).
//!   Connections are unprivileged and limited to session-scoped operations like
//!   `RequestTool`, `EmitEvent`, and `PublishEvidence`.
//!
//! # Security Considerations
//!
//! - Socket permissions are set AFTER binding to ensure correctness
//! - Parent directory permissions are enforced to 0700
//! - Stale socket files are removed before binding
//! - Connection type is determined by socket path, not client assertion
//!
//! # Invariants
//!
//! - [INV-SM-001] Operator socket always has mode 0600
//! - [INV-SM-002] Session socket always has mode 0660
//! - [INV-SM-003] `is_privileged` is determined solely by which socket accepted
//!   the connection
//! - [INV-SM-004] Both sockets share the same parent directory (mode 0700)

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

use super::credentials::PeerCredentials;
use super::error::{ProtocolError, ProtocolResult};
use super::server::{Connection, ConnectionPermit};

/// Default socket filenames.
const DEFAULT_OPERATOR_SOCKET_NAME: &str = "operator.sock";
const DEFAULT_SESSION_SOCKET_NAME: &str = "session.sock";

/// Default subdirectory under runtime directory.
const DEFAULT_SUBDIR: &str = "apm2";

/// Maximum concurrent connections across both sockets.
const MAX_CONNECTIONS: usize = 100;

/// Socket permissions for operator socket (owner read/write only).
const OPERATOR_SOCKET_MODE: u32 = 0o600;

/// Socket permissions for session socket (owner + group read/write).
const SESSION_SOCKET_MODE: u32 = 0o660;

/// Directory permissions (owner only).
const DIRECTORY_MODE: u32 = 0o700;

/// Type of socket connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketType {
    /// Operator socket - privileged operations allowed.
    Operator,
    /// Session socket - only session-scoped operations allowed.
    Session,
}

impl SocketType {
    /// Returns `true` if this socket type allows privileged operations.
    #[must_use]
    pub const fn is_privileged(self) -> bool {
        matches!(self, Self::Operator)
    }
}

impl std::fmt::Display for SocketType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Operator => write!(f, "operator"),
            Self::Session => write!(f, "session"),
        }
    }
}

/// Get the default operator socket path based on environment.
///
/// Priority:
/// 1. `XDG_RUNTIME_DIR/apm2/operator.sock` if `XDG_RUNTIME_DIR` is set
/// 2. `/tmp/apm2/operator.sock` as fallback
#[must_use]
pub fn default_operator_socket_path() -> PathBuf {
    std::env::var("XDG_RUNTIME_DIR").map_or_else(
        |_| {
            PathBuf::from("/tmp")
                .join(DEFAULT_SUBDIR)
                .join(DEFAULT_OPERATOR_SOCKET_NAME)
        },
        |runtime_dir| {
            PathBuf::from(runtime_dir)
                .join(DEFAULT_SUBDIR)
                .join(DEFAULT_OPERATOR_SOCKET_NAME)
        },
    )
}

/// Get the default session socket path based on environment.
///
/// Priority:
/// 1. `XDG_RUNTIME_DIR/apm2/session.sock` if `XDG_RUNTIME_DIR` is set
/// 2. `/tmp/apm2/session.sock` as fallback
#[must_use]
pub fn default_session_socket_path() -> PathBuf {
    std::env::var("XDG_RUNTIME_DIR").map_or_else(
        |_| {
            PathBuf::from("/tmp")
                .join(DEFAULT_SUBDIR)
                .join(DEFAULT_SESSION_SOCKET_NAME)
        },
        |runtime_dir| {
            PathBuf::from(runtime_dir)
                .join(DEFAULT_SUBDIR)
                .join(DEFAULT_SESSION_SOCKET_NAME)
        },
    )
}

/// Configuration for the dual-socket manager.
#[derive(Debug, Clone)]
pub struct SocketManagerConfig {
    /// Operator socket path (mode 0600).
    pub operator_socket_path: PathBuf,

    /// Session socket path (mode 0660).
    pub session_socket_path: PathBuf,

    /// Maximum concurrent connections across both sockets.
    pub max_connections: usize,

    /// Server info string for handshake.
    pub server_info: String,

    /// Optional policy hash for handshake.
    pub policy_hash: Option<String>,
}

impl Default for SocketManagerConfig {
    fn default() -> Self {
        Self {
            operator_socket_path: default_operator_socket_path(),
            session_socket_path: default_session_socket_path(),
            max_connections: MAX_CONNECTIONS,
            server_info: format!("apm2-daemon/{}", env!("CARGO_PKG_VERSION")),
            policy_hash: None,
        }
    }
}

impl SocketManagerConfig {
    /// Create a new socket manager config with the given socket paths.
    #[must_use]
    pub fn new(
        operator_socket_path: impl Into<PathBuf>,
        session_socket_path: impl Into<PathBuf>,
    ) -> Self {
        Self {
            operator_socket_path: operator_socket_path.into(),
            session_socket_path: session_socket_path.into(),
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

/// Dual-socket manager for privilege separation.
///
/// Manages the lifecycle of both operator and session Unix sockets,
/// routing connections based on which socket they connect to.
///
/// # Invariants
///
/// - [INV-SM-001] Operator socket always has mode 0600
/// - [INV-SM-002] Session socket always has mode 0660
/// - [INV-SM-003] `is_privileged` is determined solely by which socket accepted
/// - [INV-SM-004] Both sockets share the same parent directory (mode 0700)
pub struct SocketManager {
    /// Manager configuration.
    config: SocketManagerConfig,

    /// Operator socket listener (mode 0600, privileged).
    operator_listener: UnixListener,

    /// Session socket listener (mode 0660, unprivileged).
    session_listener: UnixListener,

    /// Connection semaphore for limiting concurrent connections.
    connection_sem: Arc<Semaphore>,
}

impl SocketManager {
    /// Create and bind a new dual-socket manager.
    ///
    /// This will:
    /// 1. Create the parent directory if needed (mode 0700)
    /// 2. Remove any stale socket files
    /// 3. Bind both sockets
    /// 4. Set appropriate permissions (0600 for operator, 0660 for session)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Parent directory cannot be created
    /// - Either socket cannot be bound
    /// - Stale sockets cannot be removed
    /// - Permissions cannot be set
    pub fn bind(config: SocketManagerConfig) -> ProtocolResult<Self> {
        // Ensure parent directories exist and have correct permissions
        if let Some(parent) = config.operator_socket_path.parent() {
            Self::ensure_directory(parent)?;
        }
        if let Some(parent) = config.session_socket_path.parent() {
            // Only create if different from operator socket parent
            if config.session_socket_path.parent() != config.operator_socket_path.parent() {
                Self::ensure_directory(parent)?;
            }
        }

        // Remove stale socket files
        Self::cleanup_socket(&config.operator_socket_path)?;
        Self::cleanup_socket(&config.session_socket_path)?;

        // Bind operator socket
        let operator_listener = UnixListener::bind(&config.operator_socket_path).map_err(|e| {
            ProtocolError::Io(io::Error::new(
                e.kind(),
                format!(
                    "failed to bind operator socket to {}: {e}",
                    config.operator_socket_path.display()
                ),
            ))
        })?;

        // Set operator socket permissions to 0600
        Self::set_socket_permissions(&config.operator_socket_path, OPERATOR_SOCKET_MODE)?;

        // Bind session socket
        let session_listener = UnixListener::bind(&config.session_socket_path).map_err(|e| {
            ProtocolError::Io(io::Error::new(
                e.kind(),
                format!(
                    "failed to bind session socket to {}: {e}",
                    config.session_socket_path.display()
                ),
            ))
        })?;

        // Set session socket permissions to 0660
        Self::set_socket_permissions(&config.session_socket_path, SESSION_SOCKET_MODE)?;

        info!(
            operator_socket = %config.operator_socket_path.display(),
            session_socket = %config.session_socket_path.display(),
            max_connections = config.max_connections,
            "Dual-socket manager bound"
        );

        Ok(Self {
            connection_sem: Arc::new(Semaphore::new(config.max_connections)),
            config,
            operator_listener,
            session_listener,
        })
    }

    /// Ensure a directory exists with appropriate permissions (0700).
    ///
    /// # Safety
    ///
    /// Does **not** modify permissions of existing directories to avoid
    /// clobbering system paths (e.g., `/tmp`) if configured incorrectly.
    /// Only enforces 0700 on directories created by this call.
    ///
    /// # Symlink Protection (RSK-2617)
    ///
    /// Uses `symlink_metadata` to verify path type before any operations.
    /// Rejects symlinks to prevent symlink-based attacks.
    fn ensure_directory(path: &Path) -> ProtocolResult<()> {
        // Check if path exists using symlink_metadata to detect symlinks (RSK-2617)
        match std::fs::symlink_metadata(path) {
            Ok(metadata) => {
                // Path exists - verify it's a directory, not a symlink
                if metadata.file_type().is_symlink() {
                    return Err(ProtocolError::Io(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "security: {} is a symlink, refusing to use as socket directory",
                            path.display()
                        ),
                    )));
                }
                if !metadata.is_dir() {
                    return Err(ProtocolError::Io(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        format!("{} exists but is not a directory", path.display()),
                    )));
                }
                // Directory exists, do NOT modify its permissions (SEC-FS-001)
                Ok(())
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                // Path doesn't exist, create it
                std::fs::create_dir_all(path).map_err(|e| {
                    ProtocolError::Io(io::Error::new(
                        e.kind(),
                        format!("failed to create directory {}: {e}", path.display()),
                    ))
                })?;

                // Only enforce permissions if we created the directory
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let perms = std::fs::Permissions::from_mode(DIRECTORY_MODE);
                    std::fs::set_permissions(path, perms).map_err(|e| {
                        ProtocolError::Io(io::Error::new(
                            e.kind(),
                            format!("failed to set permissions on {}: {e}", path.display()),
                        ))
                    })?;
                }
                Ok(())
            }
            Err(e) => Err(ProtocolError::Io(io::Error::new(
                e.kind(),
                format!("failed to stat {}: {e}", path.display()),
            ))),
        }
    }

    /// Set socket file permissions.
    #[cfg(unix)]
    fn set_socket_permissions(path: &Path, mode: u32) -> ProtocolResult<()> {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(mode);
        std::fs::set_permissions(path, perms).map_err(|e| {
            ProtocolError::Io(io::Error::new(
                e.kind(),
                format!(
                    "failed to set socket permissions on {}: {e}",
                    path.display()
                ),
            ))
        })
    }

    #[cfg(not(unix))]
    fn set_socket_permissions(_path: &Path, _mode: u32) -> ProtocolResult<()> {
        // No-op on non-Unix platforms
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

    /// Accept the next incoming connection from either socket.
    ///
    /// This method uses `tokio::select!` to accept from whichever socket
    /// has a connection available first. The returned `SocketType` indicates
    /// whether the connection came from the operator or session socket.
    ///
    /// # Connection Limiting
    ///
    /// Uses a semaphore to limit concurrent connections across both sockets.
    /// If the limit is reached, this will wait until a slot becomes available.
    ///
    /// # Returns
    ///
    /// A tuple of:
    /// - `Connection`: The framed connection
    /// - `ConnectionPermit`: A permit that must be held while the connection is
    ///   active
    /// - `SocketType`: Whether this is an operator or session connection
    pub async fn accept(&self) -> ProtocolResult<(Connection, ConnectionPermit, SocketType)> {
        // Acquire connection permit
        let permit = self
            .connection_sem
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| ProtocolError::Io(io::Error::other("connection semaphore closed")))?;

        // Accept from whichever socket has a connection first
        let (stream, socket_type) = tokio::select! {
            result = self.operator_listener.accept() => {
                let (stream, _addr) = result?;
                (stream, SocketType::Operator)
            }
            result = self.session_listener.accept() => {
                let (stream, _addr) = result?;
                (stream, SocketType::Session)
            }
        };

        // Extract and validate peer credentials
        let (connection, connection_permit) =
            Self::validate_and_create_connection(stream, permit, socket_type)?;

        Ok((connection, connection_permit, socket_type))
    }

    /// Accept the next connection from the operator socket only.
    ///
    /// # Returns
    ///
    /// A tuple of:
    /// - `Connection`: The framed connection
    /// - `ConnectionPermit`: A permit that must be held while the connection is
    ///   active
    pub async fn accept_operator(&self) -> ProtocolResult<(Connection, ConnectionPermit)> {
        let permit = self
            .connection_sem
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| ProtocolError::Io(io::Error::other("connection semaphore closed")))?;

        let (stream, _addr) = self.operator_listener.accept().await?;

        Self::validate_and_create_connection(stream, permit, SocketType::Operator)
    }

    /// Accept the next connection from the session socket only.
    ///
    /// # Returns
    ///
    /// A tuple of:
    /// - `Connection`: The framed connection
    /// - `ConnectionPermit`: A permit that must be held while the connection is
    ///   active
    pub async fn accept_session(&self) -> ProtocolResult<(Connection, ConnectionPermit)> {
        let permit = self
            .connection_sem
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| ProtocolError::Io(io::Error::other("connection semaphore closed")))?;

        let (stream, _addr) = self.session_listener.accept().await?;

        Self::validate_and_create_connection(stream, permit, SocketType::Session)
    }

    /// Validate peer credentials and create a connection.
    fn validate_and_create_connection(
        stream: UnixStream,
        permit: tokio::sync::OwnedSemaphorePermit,
        socket_type: SocketType,
    ) -> ProtocolResult<(Connection, ConnectionPermit)> {
        use nix::unistd::{getgid, getuid};
        use subtle::ConstantTimeEq;

        // Extract peer credentials (TCK-00248)
        let creds = PeerCredentials::from_stream(&stream).map_err(|e| {
            ProtocolError::Io(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("failed to extract peer credentials: {e}"),
            ))
        })?;

        // Validate UID/GID based on socket type
        // TCK-00249: Privilege Separation Logic
        // - Operator: Strict UID match (Owner only)
        // - Session: UID match (Owner) OR GID match (Group)
        let current_uid = getuid().as_raw();
        let current_gid = getgid().as_raw();

        let uid_bytes = creds.uid.to_ne_bytes();
        let expected_uid_bytes = current_uid.to_ne_bytes();
        let uid_match = uid_bytes.ct_eq(&expected_uid_bytes).unwrap_u8() == 1;

        let authorized = match socket_type {
            SocketType::Operator => uid_match,
            SocketType::Session => {
                let gid_bytes = creds.gid.to_ne_bytes();
                let expected_gid_bytes = current_gid.to_ne_bytes();
                let gid_match = gid_bytes.ct_eq(&expected_gid_bytes).unwrap_u8() == 1;

                uid_match || gid_match
            }
        };

        if !authorized {
            return Err(ProtocolError::Io(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "permission denied",
            )));
        }

        debug!(
            uid = creds.uid,
            gid = creds.gid,
            pid = ?creds.pid,
            socket_type = %socket_type,
            "Accepted new connection"
        );

        let connection = Connection::new_with_credentials(stream, Some(creds));
        let connection_permit = ConnectionPermit::new(permit);

        Ok((connection, connection_permit))
    }

    /// Returns the operator socket path.
    #[must_use]
    pub fn operator_socket_path(&self) -> &Path {
        &self.config.operator_socket_path
    }

    /// Returns the session socket path.
    #[must_use]
    pub fn session_socket_path(&self) -> &Path {
        &self.config.session_socket_path
    }

    /// Returns the manager configuration.
    #[must_use]
    pub const fn config(&self) -> &SocketManagerConfig {
        &self.config
    }

    /// Cleanup both socket files.
    ///
    /// Should be called when the manager is shutting down.
    pub fn cleanup(&self) -> ProtocolResult<()> {
        let mut errors = Vec::new();

        if self.config.operator_socket_path.exists() {
            if let Err(e) = std::fs::remove_file(&self.config.operator_socket_path) {
                errors.push(format!(
                    "failed to remove operator socket {}: {e}",
                    self.config.operator_socket_path.display()
                ));
            } else {
                info!(
                    socket_path = %self.config.operator_socket_path.display(),
                    "Removed operator socket file"
                );
            }
        }

        if self.config.session_socket_path.exists() {
            if let Err(e) = std::fs::remove_file(&self.config.session_socket_path) {
                errors.push(format!(
                    "failed to remove session socket {}: {e}",
                    self.config.session_socket_path.display()
                ));
            } else {
                info!(
                    socket_path = %self.config.session_socket_path.display(),
                    "Removed session socket file"
                );
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(ProtocolError::Io(io::Error::other(errors.join("; "))))
        }
    }
}

impl Drop for SocketManager {
    fn drop(&mut self) {
        // Best-effort cleanup on drop
        if let Err(e) = self.cleanup() {
            warn!("Failed to cleanup sockets on drop: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use tempfile::TempDir;

    use super::*;

    fn test_socket_paths(dir: &TempDir) -> (PathBuf, PathBuf) {
        (
            dir.path().join("operator.sock"),
            dir.path().join("session.sock"),
        )
    }

    #[tokio::test]
    async fn test_socket_manager_bind_and_cleanup() {
        let tmp = TempDir::new().unwrap();
        let (operator_path, session_path) = test_socket_paths(&tmp);

        let config = SocketManagerConfig::new(&operator_path, &session_path);
        let manager = SocketManager::bind(config).unwrap();

        assert!(operator_path.exists());
        assert!(session_path.exists());
        assert_eq!(manager.operator_socket_path(), operator_path);
        assert_eq!(manager.session_socket_path(), session_path);

        manager.cleanup().unwrap();
        assert!(!operator_path.exists());
        assert!(!session_path.exists());
    }

    #[tokio::test]
    async fn test_operator_socket_permissions_0600() {
        let tmp = TempDir::new().unwrap();
        let (operator_path, session_path) = test_socket_paths(&tmp);

        let config = SocketManagerConfig::new(&operator_path, &session_path);
        let _manager = SocketManager::bind(config).unwrap();

        let metadata = std::fs::metadata(&operator_path).unwrap();
        let mode = metadata.permissions().mode() & 0o777;

        assert_eq!(
            mode, OPERATOR_SOCKET_MODE,
            "operator socket permissions should be 0600, got {mode:04o}"
        );
    }

    #[tokio::test]
    async fn test_session_socket_permissions_0660() {
        let tmp = TempDir::new().unwrap();
        let (operator_path, session_path) = test_socket_paths(&tmp);

        let config = SocketManagerConfig::new(&operator_path, &session_path);
        let _manager = SocketManager::bind(config).unwrap();

        let metadata = std::fs::metadata(&session_path).unwrap();
        let mode = metadata.permissions().mode() & 0o777;

        assert_eq!(
            mode, SESSION_SOCKET_MODE,
            "session socket permissions should be 0660, got {mode:04o}"
        );
    }

    #[tokio::test]
    async fn test_socket_type_is_privileged() {
        assert!(SocketType::Operator.is_privileged());
        assert!(!SocketType::Session.is_privileged());
    }

    #[tokio::test]
    async fn test_socket_manager_removes_stale_sockets() {
        let tmp = TempDir::new().unwrap();
        let (operator_path, session_path) = test_socket_paths(&tmp);

        // Create first manager
        {
            let config = SocketManagerConfig::new(&operator_path, &session_path);
            let manager = SocketManager::bind(config).unwrap();
            // Drop without cleanup to leave stale sockets
            std::mem::forget(manager);
        }

        assert!(operator_path.exists());
        assert!(session_path.exists());

        // Second manager should succeed by removing stale sockets
        let config = SocketManagerConfig::new(&operator_path, &session_path);
        let manager = SocketManager::bind(config).unwrap();
        assert!(manager.operator_socket_path().exists());
        assert!(manager.session_socket_path().exists());
    }

    #[tokio::test]
    async fn test_default_socket_paths() {
        let operator_path = default_operator_socket_path();
        let session_path = default_session_socket_path();

        assert!(
            operator_path.ends_with(format!("{DEFAULT_SUBDIR}/{DEFAULT_OPERATOR_SOCKET_NAME}"))
        );
        assert!(session_path.ends_with(format!("{DEFAULT_SUBDIR}/{DEFAULT_SESSION_SOCKET_NAME}")));

        if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
            assert!(operator_path.starts_with(&runtime_dir));
            assert!(session_path.starts_with(&runtime_dir));
        }
    }

    #[tokio::test]
    async fn test_socket_manager_config_builder() {
        let config = SocketManagerConfig::new("/custom/operator.sock", "/custom/session.sock")
            .with_max_connections(50)
            .with_server_info("test-server/1.0")
            .with_policy_hash("abc123");

        assert_eq!(
            config.operator_socket_path,
            PathBuf::from("/custom/operator.sock")
        );
        assert_eq!(
            config.session_socket_path,
            PathBuf::from("/custom/session.sock")
        );
        assert_eq!(config.max_connections, 50);
        assert_eq!(config.server_info, "test-server/1.0");
        assert_eq!(config.policy_hash, Some("abc123".to_string()));
    }

    #[tokio::test]
    async fn test_directory_permissions_preserved_if_existing() {
        let tmp = TempDir::new().unwrap();
        let socket_dir = tmp.path().join("apm2_test_dir");
        let operator_path = socket_dir.join("operator.sock");
        let session_path = socket_dir.join("session.sock");

        // Pre-create directory with loose permissions (simulating existing system dir)
        std::fs::create_dir_all(&socket_dir).unwrap();
        std::fs::set_permissions(&socket_dir, std::fs::Permissions::from_mode(0o777)).unwrap();

        // Verify the directory has loose permissions
        let initial_mode = std::fs::metadata(&socket_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            initial_mode, 0o777,
            "Pre-condition: directory should be 0777"
        );

        // Bind manager - should NOT modify directory permissions
        let config = SocketManagerConfig::new(&operator_path, &session_path);
        let _manager = SocketManager::bind(config).unwrap();

        // Verify directory permissions were preserved (NOT corrected to 0700)
        let preserved_mode = std::fs::metadata(&socket_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            preserved_mode, 0o777,
            "Directory permissions should be preserved, got {preserved_mode:04o}"
        );
    }

    #[tokio::test]
    async fn test_accept_operator_connection() {
        use tokio::net::UnixStream;

        let tmp = TempDir::new().unwrap();
        let (operator_path, session_path) = test_socket_paths(&tmp);

        let config = SocketManagerConfig::new(&operator_path, &session_path);
        let manager = Arc::new(SocketManager::bind(config).unwrap());

        // Spawn accept task for operator socket
        let manager_clone = Arc::clone(&manager);
        let accept_handle = tokio::spawn(async move {
            let (conn, _permit) = manager_clone.accept_operator().await.unwrap();
            conn
        });

        // Connect to operator socket
        let _client = UnixStream::connect(&operator_path).await.unwrap();

        // Verify accept succeeded
        let _conn = accept_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_accept_session_connection() {
        use tokio::net::UnixStream;

        let tmp = TempDir::new().unwrap();
        let (operator_path, session_path) = test_socket_paths(&tmp);

        let config = SocketManagerConfig::new(&operator_path, &session_path);
        let manager = Arc::new(SocketManager::bind(config).unwrap());

        // Spawn accept task for session socket
        let manager_clone = Arc::clone(&manager);
        let accept_handle = tokio::spawn(async move {
            let (conn, _permit) = manager_clone.accept_session().await.unwrap();
            conn
        });

        // Connect to session socket
        let _client = UnixStream::connect(&session_path).await.unwrap();

        // Verify accept succeeded
        let _conn = accept_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_accept_routes_by_socket_type() {
        use tokio::net::UnixStream;

        let tmp = TempDir::new().unwrap();
        let (operator_path, session_path) = test_socket_paths(&tmp);

        let config = SocketManagerConfig::new(&operator_path, &session_path);
        let manager = Arc::new(SocketManager::bind(config).unwrap());

        // Test operator connection
        {
            let manager_clone = Arc::clone(&manager);
            let accept_handle = tokio::spawn(async move { manager_clone.accept().await.unwrap() });

            let _client = UnixStream::connect(&operator_path).await.unwrap();
            let (_conn, _permit, socket_type) = accept_handle.await.unwrap();
            assert_eq!(socket_type, SocketType::Operator);
        }

        // Test session connection
        {
            let manager_clone = Arc::clone(&manager);
            let accept_handle = tokio::spawn(async move { manager_clone.accept().await.unwrap() });

            let _client = UnixStream::connect(&session_path).await.unwrap();
            let (_conn, _permit, socket_type) = accept_handle.await.unwrap();
            assert_eq!(socket_type, SocketType::Session);
        }
    }
}
