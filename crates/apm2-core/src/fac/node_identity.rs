//! FAC node identity primitives.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Default boundary identifier for single-node FAC deployments.
pub const DEFAULT_BOUNDARY_ID: &str = "apm2.fac.local";

/// Maximum allowed boundary identifier length.
pub const MAX_BOUNDARY_ID_LENGTH: usize = 256;

/// Schema identifier for persisted node identity files.
pub const NODE_IDENTITY_SCHEMA_ID: &str = "apm2.fac.node_identity.v1";

/// Relative path inside `$APM2_HOME` for persisted FAC identity artifacts.
const FAC_IDENTITY_DIR: &str = "private/fac";

const NODE_FINGERPRINT_FILE: &str = "node_fingerprint";
const BOUNDARY_ID_FILE: &str = "boundary_id";

const MAX_FILE_SIZE: u64 = 4 * 1024;
const MAX_INPUT_BYTES: u64 = 4096;

const MACHINE_ID_PATHS: &[&str] = &["/etc/machine-id", "/var/lib/dbus/machine-id"];
const HOSTNAME_PATHS: &[&str] = &["/etc/hostname", "/proc/sys/kernel/hostname"];

const NODE_IDENTITY_HASH_DOMAIN: &[u8] = b"apm2.fac.node_identity.v1";

/// Node identity errors.
#[derive(Debug, Error)]
pub enum NodeIdentityError {
    /// A required input (hostname or machine-id) could not be found.
    #[error("missing required identity input: {detail}")]
    MissingInput {
        /// Which input is missing.
        detail: &'static str,
    },

    /// I/O failure.
    #[error("I/O failure while {context}: {source}")]
    Io {
        /// I/O context.
        context: &'static str,
        /// Source error.
        source: io::Error,
        /// Path involved.
        path: Option<PathBuf>,
    },

    /// Invalid identity file content.
    #[error("invalid identity data: {detail}")]
    InvalidData {
        /// Reason.
        detail: &'static str,
    },

    /// File exceeded maximum size.
    #[error("identity file at {} exceeds max size {max} bytes", path.display())]
    FileTooLarge {
        /// File path.
        path: PathBuf,
        /// Limit.
        max: u64,
    },

    /// JSON parse/serialize failure.
    #[error("identity JSON failure: {0}")]
    Json(#[from] serde_json::Error),

    /// Path is malformed for this operation.
    #[error("invalid APM2 home path: {0}")]
    HomeResolution(String),

    /// UTF-8 decode failure.
    #[error("identity data is invalid UTF-8: {0}")]
    Utf8(#[from] std::str::Utf8Error),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedNodeIdentity {
    /// Schema tag.
    schema: String,
    /// Stable node fingerprint.
    node_fingerprint: String,
}

/// Derive a deterministic node fingerprint for this node.
///
/// Uses `blake3` with domain separation and formats as `b3-256:<hex>`.
///
/// # Errors
///
/// Returns `Err` if required identity inputs are missing (hostname or
/// machine-id), if file/path validation fails, or if persistence-related I/O
/// fails.
pub fn derive_node_fingerprint(apm2_home: &Path) -> Result<String, NodeIdentityError> {
    let hostname = read_host_name()?;
    let machine_id = read_machine_id()?;
    Ok(derive_node_fingerprint_from_parts(
        apm2_home,
        &hostname,
        &machine_id,
    ))
}

fn derive_node_fingerprint_from_parts(
    apm2_home: &Path,
    hostname: &str,
    machine_id: &str,
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(NODE_IDENTITY_HASH_DOMAIN);
    hasher.update(hostname.as_bytes());
    hasher.update(b"\0");
    hasher.update(machine_id.as_bytes());
    hasher.update(b"\0");
    hasher.update(apm2_home.to_string_lossy().as_bytes());
    let digest = hasher.finalize();
    format!("b3-256:{}", digest.to_hex())
}

/// Load the node fingerprint from disk, or derive and persist it when missing.
///
/// # Errors
///
/// Returns `Err` if loading/parsing persisted fingerprint fails, or if
/// deriving/persisting a new fingerprint fails.
pub fn load_or_derive_node_fingerprint(apm2_home: &Path) -> Result<String, NodeIdentityError> {
    let path = identity_path(apm2_home, NODE_FINGERPRINT_FILE);
    ensure_fac_directory(path.parent())?;

    if path.exists() {
        return load_node_fingerprint(&path);
    }

    let fingerprint = derive_node_fingerprint(apm2_home)?;
    persist_node_fingerprint(&path, &fingerprint)?;
    Ok(fingerprint)
}

/// Read the boundary id from disk without creating directories or files.
///
/// Returns `Ok(Some(id))` if the boundary id file exists and is valid,
/// `Ok(None)` if the file or parent directory does not exist, or `Err` if
/// the file exists but cannot be read or contains invalid data.
///
/// This is the non-mutating counterpart to [`load_or_default_boundary_id`]
/// and is suitable for read-only introspection paths that must not perform
/// state mutation.
///
/// # Errors
///
/// Returns `Err` if the boundary id file exists but cannot be read (I/O
/// failure, symlink rejection, oversized file) or contains invalid data
/// (empty, non-ASCII, exceeds `MAX_BOUNDARY_ID_LENGTH`).
pub fn read_boundary_id(apm2_home: &Path) -> Result<Option<String>, NodeIdentityError> {
    let path = identity_path(apm2_home, BOUNDARY_ID_FILE);

    if !path.exists() {
        return Ok(None);
    }

    let stored = read_bounded_file(&path, MAX_FILE_SIZE)?;
    let value = trim_identity_value(&stored)?;
    validate_boundary_id(value)?;
    Ok(Some(value.to_string()))
}

/// Load boundary id from disk or persist `DEFAULT_BOUNDARY_ID` if missing.
///
/// # Errors
///
/// Returns `Err` if loading/persisting the boundary id fails, or if a stored
/// value is invalid.
pub fn load_or_default_boundary_id(apm2_home: &Path) -> Result<String, NodeIdentityError> {
    let path = identity_path(apm2_home, BOUNDARY_ID_FILE);
    ensure_fac_directory(path.parent())?;

    if path.exists() {
        let stored = read_bounded_file(&path, MAX_FILE_SIZE)?;
        let value = trim_identity_value(&stored)?;
        validate_boundary_id(value)?;
        return Ok(value.to_string());
    }

    persist_boundary_id(&path, DEFAULT_BOUNDARY_ID)?;
    Ok(DEFAULT_BOUNDARY_ID.to_string())
}

fn load_node_fingerprint(path: &Path) -> Result<String, NodeIdentityError> {
    let raw = read_bounded_file(path, MAX_FILE_SIZE)?;
    let payload: PersistedNodeIdentity = serde_json::from_str(&raw)?;

    if payload.schema != NODE_IDENTITY_SCHEMA_ID {
        return Err(NodeIdentityError::InvalidData {
            detail: "unexpected schema",
        });
    }

    validate_node_fingerprint(&payload.node_fingerprint)?;
    Ok(payload.node_fingerprint)
}

fn persist_node_fingerprint(path: &Path, fingerprint: &str) -> Result<(), NodeIdentityError> {
    validate_node_fingerprint(fingerprint)?;
    let payload = PersistedNodeIdentity {
        schema: NODE_IDENTITY_SCHEMA_ID.to_string(),
        node_fingerprint: fingerprint.to_string(),
    };
    let data = serde_json::to_vec(&payload)?;
    write_restricted_file(path, &data)
}

fn persist_boundary_id(path: &Path, boundary_id: &str) -> Result<(), NodeIdentityError> {
    validate_boundary_id(boundary_id)?;
    write_restricted_file(path, boundary_id.as_bytes())
}

fn validate_node_fingerprint(fingerprint: &str) -> Result<(), NodeIdentityError> {
    if !fingerprint.starts_with("b3-256:") {
        return Err(NodeIdentityError::InvalidData {
            detail: "invalid fingerprint prefix",
        });
    }
    let payload = &fingerprint["b3-256:".len()..];
    if payload.len() != 64 || !payload.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(NodeIdentityError::InvalidData {
            detail: "fingerprint must be b3-256 hex",
        });
    }
    Ok(())
}

#[allow(clippy::missing_const_for_fn)]
fn validate_boundary_id(boundary_id: &str) -> Result<(), NodeIdentityError> {
    if boundary_id.is_empty() {
        return Err(NodeIdentityError::InvalidData {
            detail: "boundary_id is empty",
        });
    }
    if !boundary_id.is_ascii() {
        return Err(NodeIdentityError::InvalidData {
            detail: "boundary_id must be ASCII",
        });
    }
    if boundary_id.len() > MAX_BOUNDARY_ID_LENGTH {
        return Err(NodeIdentityError::InvalidData {
            detail: "boundary_id exceeds MAX_BOUNDARY_ID_LENGTH",
        });
    }
    Ok(())
}

fn identity_path(apm2_home: &Path, name: &str) -> PathBuf {
    apm2_home.join(FAC_IDENTITY_DIR).join(name)
}

fn ensure_fac_directory(path: Option<&Path>) -> Result<(), NodeIdentityError> {
    let Some(path) = path else {
        return Err(NodeIdentityError::HomeResolution(
            "identity path has no parent".to_string(),
        ));
    };
    create_restricted_dir(path)
}

fn read_host_name() -> Result<String, NodeIdentityError> {
    if let Some(value) = read_identity_value_from_sources(HOSTNAME_PATHS) {
        return Ok(value);
    }

    if let Ok(value) = std::env::var("HOSTNAME") {
        if let Ok(trimmed) = trim_identity_value(&value) {
            return Ok(trimmed.to_string());
        }
    }

    Err(NodeIdentityError::MissingInput { detail: "hostname" })
}

fn read_machine_id() -> Result<String, NodeIdentityError> {
    read_identity_value_from_sources(MACHINE_ID_PATHS).ok_or(NodeIdentityError::MissingInput {
        detail: "machine-id",
    })
}

fn read_identity_value_from_sources(sources: &[&str]) -> Option<String> {
    for source in sources {
        if let Ok(value) = read_text_file(source) {
            if let Ok(trimmed) = trim_identity_value(&value) {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

fn read_text_file(path: &str) -> Result<String, NodeIdentityError> {
    let path = Path::new(path);
    let bytes = read_bounded_bytes(path, MAX_INPUT_BYTES)?;
    let value = std::str::from_utf8(&bytes)?;
    Ok(value.to_string())
}

fn read_bounded_file(path: &Path, max_size: u64) -> Result<String, NodeIdentityError> {
    let bytes = read_bounded_bytes(path, max_size)?;
    let value = std::str::from_utf8(&bytes)?;
    Ok(value.to_string())
}

fn read_bounded_bytes(path: &Path, max_size: u64) -> Result<Vec<u8>, NodeIdentityError> {
    ensure_safe_path(path, "read")?;
    let file = open_file_no_follow(path)?;

    let metadata = file.metadata().map_err(|e| NodeIdentityError::Io {
        context: "read metadata",
        source: e,
        path: Some(path.to_path_buf()),
    })?;

    if metadata.len() > max_size {
        return Err(NodeIdentityError::FileTooLarge {
            path: path.to_path_buf(),
            max: max_size,
        });
    }

    let mut buffer = Vec::new();
    file.take(max_size.saturating_add(1))
        .read_to_end(&mut buffer)
        .map_err(|e| NodeIdentityError::Io {
            context: "read bounded file",
            source: e,
            path: Some(path.to_path_buf()),
        })?;
    if buffer.len() as u64 > max_size {
        return Err(NodeIdentityError::FileTooLarge {
            path: path.to_path_buf(),
            max: max_size,
        });
    }

    Ok(buffer)
}

fn trim_identity_value(raw: &str) -> Result<&str, NodeIdentityError> {
    let trimmed = raw.trim_matches(['\n', '\r']);
    if trimmed.is_empty() {
        return Err(NodeIdentityError::InvalidData {
            detail: "identity value is empty",
        });
    }
    Ok(trimmed)
}

fn write_restricted_file(path: &Path, data: &[u8]) -> Result<(), NodeIdentityError> {
    ensure_safe_path(path, "write")?;
    let parent = path.parent().ok_or_else(|| {
        NodeIdentityError::HomeResolution(format!("path has no parent: {}", path.display()))
    })?;
    create_restricted_dir(parent)?;

    let mut temp = tempfile::NamedTempFile::new_in(parent).map_err(|e| NodeIdentityError::Io {
        context: "create temporary identity file",
        source: e,
        path: Some(parent.to_path_buf()),
    })?;

    #[cfg(unix)]
    {
        let perms = fs::Permissions::from_mode(0o600);
        fs::set_permissions(temp.path(), perms).map_err(|e| NodeIdentityError::Io {
            context: "set temporary file permissions",
            source: e,
            path: Some(temp.path().to_path_buf()),
        })?;
    }

    temp.write_all(data).map_err(|e| NodeIdentityError::Io {
        context: "write temporary identity file",
        source: e,
        path: Some(path.to_path_buf()),
    })?;
    temp.as_file()
        .sync_all()
        .map_err(|e| NodeIdentityError::Io {
            context: "fsync temporary identity file",
            source: e,
            path: Some(path.to_path_buf()),
        })?;
    temp.persist(path).map_err(|e| NodeIdentityError::Io {
        context: "rename temporary identity file",
        source: e.error,
        path: Some(path.to_path_buf()),
    })?;

    Ok(())
}

fn create_restricted_dir(path: &Path) -> Result<(), NodeIdentityError> {
    ensure_safe_path(path, "create directory")?;

    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(NodeIdentityError::Io {
                    context: "create directory",
                    source: io::Error::new(io::ErrorKind::InvalidInput, "path is a symlink"),
                    path: Some(path.to_path_buf()),
                });
            }
            if !metadata.is_dir() {
                return Err(NodeIdentityError::Io {
                    context: "create directory",
                    source: io::Error::new(io::ErrorKind::InvalidInput, "path is not a directory"),
                    path: Some(path.to_path_buf()),
                });
            }
            return Ok(());
        },
        Err(e) if e.kind() == io::ErrorKind::NotFound => {},
        Err(e) => {
            return Err(NodeIdentityError::Io {
                context: "create directory",
                source: e,
                path: Some(path.to_path_buf()),
            });
        },
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
            .map_err(|e| NodeIdentityError::Io {
                context: "create directory",
                source: e,
                path: Some(path.to_path_buf()),
            })?;
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(path).map_err(|e| NodeIdentityError::Io {
            context: "create directory",
            source: e,
            path: Some(path.to_path_buf()),
        })?;
    }

    Ok(())
}

fn open_file_no_follow(path: &Path) -> Result<File, NodeIdentityError> {
    #[cfg(unix)]
    {
        let mut options = OpenOptions::new();
        options.read(true);
        options.custom_flags(libc::O_NOFOLLOW);
        options.open(path).map_err(|e| NodeIdentityError::Io {
            context: "open file without symlink follow",
            source: e,
            path: Some(path.to_path_buf()),
        })
    }
    #[cfg(not(unix))]
    {
        OpenOptions::new()
            .read(true)
            .open(path)
            .map_err(|e| NodeIdentityError::Io {
                context: "open file",
                source: e,
                path: Some(path.to_path_buf()),
            })
    }
}

fn ensure_safe_path(path: &Path, context: &'static str) -> Result<(), NodeIdentityError> {
    for component in path.ancestors() {
        if component.as_os_str().is_empty() {
            continue;
        }

        match fs::symlink_metadata(component) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(NodeIdentityError::Io {
                        context,
                        source: io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("symlink component: {}", component.display()),
                        ),
                        path: Some(component.to_path_buf()),
                    });
                }

                if component != path && !metadata.is_dir() {
                    return Err(NodeIdentityError::Io {
                        context,
                        source: io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("non-directory path component: {}", component.display()),
                        ),
                        path: Some(component.to_path_buf()),
                    });
                }
            },
            Err(e) if e.kind() == io::ErrorKind::NotFound => {},
            Err(e) => {
                return Err(NodeIdentityError::Io {
                    context,
                    source: e,
                    path: Some(component.to_path_buf()),
                });
            },
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn node_fingerprint_derivation_is_deterministic_for_same_inputs() {
        let home = tempdir().expect("tempdir");
        let first = derive_node_fingerprint_from_parts(home.path(), "test-host", "machine-01");
        let second = derive_node_fingerprint_from_parts(home.path(), "test-host", "machine-01");

        assert_eq!(first, second);
    }

    #[cfg(unix)]
    #[test]
    fn node_fingerprint_persistence_creates_private_fac_path_and_reuses_value() {
        use std::os::unix::fs::PermissionsExt;

        let home = tempdir().expect("tempdir");
        let first = load_or_derive_node_fingerprint(home.path()).expect("derive fingerprint");
        let second = load_or_derive_node_fingerprint(home.path()).expect("reload fingerprint");

        assert_eq!(first, second);

        let fac_dir = home.path().join("private/fac");
        let dir_mode = fac_dir.metadata().expect("fac dir").permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700);

        let file_mode = fac_dir
            .join("node_fingerprint")
            .metadata()
            .expect("node fingerprint file")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(file_mode, 0o600);
    }

    #[test]
    fn boundary_id_is_defaulted_when_missing() {
        let home = tempdir().expect("tempdir");
        let first = load_or_default_boundary_id(home.path()).expect("default boundary");
        let second = load_or_default_boundary_id(home.path()).expect("reuse boundary");

        assert_eq!(first, DEFAULT_BOUNDARY_ID);
        assert_eq!(second, DEFAULT_BOUNDARY_ID);
    }

    #[test]
    fn read_identity_sources_fallback_to_later_candidate_when_first_is_empty() {
        let dir = tempdir().expect("tempdir");
        let first = dir.path().join("first");
        let second = dir.path().join("second");
        std::fs::write(&first, "\n").expect("write empty");
        std::fs::write(&second, "node-02\n").expect("write valid");
        let first = first.to_string_lossy().into_owned();
        let second = second.to_string_lossy().into_owned();
        let sources: Vec<&str> = vec![&first, &second];

        let value = read_identity_value_from_sources(&sources).expect("candidate fallback");
        assert_eq!(value, "node-02");
    }

    #[test]
    fn boundary_id_custom_value_is_persisted() {
        let home = tempdir().expect("tempdir");
        let _ = load_or_default_boundary_id(home.path()).expect("seed default boundary");

        let boundary_path = home.path().join("private/fac/boundary_id");
        let custom = "boundary.custom.example";
        std::fs::write(&boundary_path, custom).expect("write custom");

        let loaded = load_or_default_boundary_id(home.path()).expect("load custom boundary");
        assert_eq!(loaded, custom);
    }

    #[test]
    fn boundary_id_validation_rejects_invalid_values() {
        let home = tempdir().expect("tempdir");
        let _ = load_or_default_boundary_id(home.path()).expect("seed default boundary");

        let boundary_path = home.path().join("private/fac/boundary_id");
        std::fs::write(&boundary_path, "").expect("write invalid boundary");
        assert!(matches!(
            load_or_default_boundary_id(home.path()),
            Err(NodeIdentityError::InvalidData { .. })
        ));

        let oversized = "x".repeat(MAX_BOUNDARY_ID_LENGTH + 1);
        std::fs::write(&boundary_path, oversized).expect("write oversized boundary");
        assert!(matches!(
            load_or_default_boundary_id(home.path()),
            Err(NodeIdentityError::InvalidData { .. })
        ));
    }

    #[test]
    fn node_fingerprint_file_is_schema_versioned() {
        let home = tempdir().expect("tempdir");
        let _ = load_or_derive_node_fingerprint(home.path()).expect("derive fingerprint");

        let path = home.path().join("private/fac/node_fingerprint");
        let raw = std::fs::read_to_string(path).expect("read node fingerprint");
        let parsed: serde_json::Value = serde_json::from_str(&raw).expect("parse json");

        assert_eq!(
            parsed
                .get("schema")
                .and_then(|value| value.as_str())
                .expect("schema"),
            NODE_IDENTITY_SCHEMA_ID
        );
        let fp = parsed
            .get("node_fingerprint")
            .and_then(|value| value.as_str())
            .expect("node fingerprint");
        assert!(fp.starts_with("b3-256:"));
        assert_eq!(fp.len(), 71);
    }

    /// `read_boundary_id` must return `None` when no `boundary_id` file or
    /// parent directory exists, and must NOT create any files or
    /// directories.
    #[test]
    fn read_boundary_id_returns_none_on_empty_home_without_mutation() {
        let home = tempdir().expect("tempdir");
        let fac_dir = home.path().join("private/fac");

        // Pre-condition: no FAC identity directory exists.
        assert!(
            !fac_dir.exists(),
            "precondition: private/fac must not exist"
        );

        let result = read_boundary_id(home.path()).expect("read_boundary_id must not error");
        assert_eq!(result, None, "must return None when boundary_id is absent");

        // Post-condition: no directory or file was created.
        assert!(
            !fac_dir.exists(),
            "read_boundary_id must NOT create private/fac directory"
        );
        assert!(
            !home.path().join("private").exists(),
            "read_boundary_id must NOT create private/ directory"
        );
    }

    /// `read_boundary_id` must return the stored value when it exists.
    #[test]
    fn read_boundary_id_returns_stored_value() {
        let home = tempdir().expect("tempdir");
        // Seed a boundary_id using the mutating helper.
        let _ = load_or_default_boundary_id(home.path()).expect("seed");

        let result = read_boundary_id(home.path()).expect("read");
        assert_eq!(
            result,
            Some(DEFAULT_BOUNDARY_ID.to_string()),
            "must return the persisted default boundary_id"
        );
    }

    /// `read_boundary_id` must return an error for invalid stored data.
    #[test]
    fn read_boundary_id_rejects_invalid_stored_data() {
        let home = tempdir().expect("tempdir");
        let _ = load_or_default_boundary_id(home.path()).expect("seed");

        // Overwrite with empty content (invalid).
        let boundary_path = home.path().join("private/fac/boundary_id");
        std::fs::write(&boundary_path, "").expect("write invalid");

        assert!(
            matches!(
                read_boundary_id(home.path()),
                Err(NodeIdentityError::InvalidData { .. })
            ),
            "read_boundary_id must reject empty boundary_id"
        );
    }

    #[test]
    fn read_bounded_file_rejects_oversized_data() {
        let dir = tempdir().expect("tempdir");
        let identity = dir.path().join("identity");
        let oversized_len = usize::try_from(MAX_FILE_SIZE).expect("MAX_FILE_SIZE should fit usize");
        std::fs::write(&identity, vec![b'x'; oversized_len + 1]).expect("write identity");

        let result = read_bounded_file(&identity, MAX_FILE_SIZE - 1);
        assert!(matches!(
            result,
            Err(NodeIdentityError::FileTooLarge { .. })
        ));
    }
}
