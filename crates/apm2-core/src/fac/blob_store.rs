//! Content-addressed patch byte blob store.
//!
//! Layout:
//! ` $APM2_HOME/private/fac/blobs/<2hex_prefix>/<remaining_hex>.blob `
//!
//! All blobs are addressed by `blake3-256` and validated on read.
//! Writes are bounded by `MAX_BLOB_SIZE` and use `temp -> rename` for
//! atomicity.

use std::collections::HashSet;
use std::io::{self, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use subtle::ConstantTimeEq;
use thiserror::Error;

/// Maximum serialized size for a single blob in bytes.
pub const MAX_BLOB_SIZE: usize = 10_485_760;
/// Global cap on blobs returned by `list_all`.
pub const MAX_BLOB_LIST_ENTRIES: usize = 100_000;

/// Blob directory under `private/fac`.
pub const BLOB_DIR: &str = "blobs";
const MAX_BLOB_WRITE_RETRIES: usize = 32;

/// A content-addressed store for bounded patch bytes.
#[derive(Debug, Clone)]
pub struct BlobStore {
    /// Root blob directory: `$APM2_HOME/private/fac/blobs`.
    root: PathBuf,
}

impl BlobStore {
    /// Creates a new blob store rooted at `<fac_root>/blobs`.
    #[must_use]
    pub fn new(fac_root: &Path) -> Self {
        Self {
            root: fac_root.join(BLOB_DIR),
        }
    }

    /// Store bytes and return the content hash.
    ///
    /// If bytes already exist under the computed hash, no write occurs.
    ///
    /// # Errors
    ///
    /// Returns `TooLarge` for size violation and `Io` for filesystem failures.
    #[allow(clippy::disallowed_methods)]
    pub fn store(&self, data: &[u8]) -> Result<[u8; 32], BlobStoreError> {
        if data.len() > MAX_BLOB_SIZE {
            return Err(BlobStoreError::TooLarge {
                size: data.len(),
                max: MAX_BLOB_SIZE,
            });
        }

        let hash = blake3::hash(data);
        let hash_bytes = *hash.as_bytes();
        let blob_path = validate_blob_path(&self.root, &hash_bytes)?;
        ensure_secure_dir_mode(&self.root, 0o700)?;

        if let Ok(metadata) = blob_path.symlink_metadata() {
            if metadata.len() > MAX_BLOB_SIZE as u64 {
                std::fs::remove_file(&blob_path)?;
            } else if metadata.is_file() {
                let mut file = open_blob_file_no_follow_for_write(&blob_path)?;
                // Check size from fd metadata (not path-based — no TOCTOU)
                let fd_meta = file.metadata().map_err(BlobStoreError::Io)?;
                if fd_meta.len() > MAX_BLOB_SIZE as u64 {
                    drop(file); // Close fd before path operations
                    std::fs::remove_file(&blob_path)?;
                } else {
                    let cap = usize::try_from(fd_meta.len()).unwrap_or(0);
                    let mut existing = Vec::with_capacity(cap);
                    Read::take(&mut file, MAX_BLOB_SIZE as u64 + 1)
                        .read_to_end(&mut existing)
                        .map_err(BlobStoreError::Io)?;
                    if existing.len() > MAX_BLOB_SIZE {
                        drop(file); // Close fd before path operations
                        std::fs::remove_file(&blob_path)?;
                    } else if blake3::hash(&existing)
                        .as_bytes()
                        .ct_eq(&hash_bytes)
                        .unwrap_u8()
                        == 1
                    {
                        file.set_modified(std::time::SystemTime::now())?;
                        return Ok(hash_bytes);
                    } else {
                        drop(file); // Close fd before path operations
                        std::fs::remove_file(&blob_path)?;
                    }
                }
            } else {
                return Err(BlobStoreError::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "blob path exists but is not a regular file",
                )));
            }
        }

        let shard_dir = blob_path.parent().ok_or_else(|| {
            BlobStoreError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "computed blob path has no parent",
            ))
        })?;
        ensure_secure_dir_mode(shard_dir, 0o700)?;

        let temp_path = unique_temp_path(shard_dir, &hash_bytes)?;
        write_atomic(data, &temp_path, &blob_path, &hash_bytes)?;

        Ok(hash_bytes)
    }

    /// Retrieve blob bytes by hash and verify integrity.
    ///
    /// # Errors
    ///
    /// Returns `NotFound`, `TooLarge`, `IntegrityMismatch`, or `Io`.
    pub fn retrieve(&self, hash: &[u8; 32]) -> Result<Vec<u8>, BlobStoreError> {
        let path = validate_blob_path(&self.root, hash)?;
        let metadata = match path.symlink_metadata() {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(BlobStoreError::NotFound);
            },
            Err(error) => return Err(BlobStoreError::Io(error)),
        };
        if metadata.file_type().is_symlink() {
            return Err(BlobStoreError::SymlinkDetected);
        }
        if !metadata.is_file() {
            return Err(BlobStoreError::NotFound);
        }
        if metadata.len() > MAX_BLOB_SIZE as u64 {
            return Err(BlobStoreError::TooLarge {
                size: MAX_BLOB_SIZE + 1,
                max: MAX_BLOB_SIZE,
            });
        }

        let mut file = open_blob_file_no_follow_for_read(&path)?;
        // Check size from fd metadata (not path-based — no TOCTOU)
        let fd_meta = file.metadata().map_err(BlobStoreError::Io)?;
        if fd_meta.len() > MAX_BLOB_SIZE as u64 {
            return Err(BlobStoreError::TooLarge {
                size: MAX_BLOB_SIZE + 1,
                max: MAX_BLOB_SIZE,
            });
        }
        let cap = usize::try_from(fd_meta.len()).unwrap_or(0);
        let mut bytes = Vec::with_capacity(cap);
        Read::take(&mut file, MAX_BLOB_SIZE as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(BlobStoreError::Io)?;

        if bytes.len() > MAX_BLOB_SIZE {
            return Err(BlobStoreError::TooLarge {
                size: bytes.len(),
                max: MAX_BLOB_SIZE,
            });
        }

        let actual_hash = blake3::hash(&bytes);
        if actual_hash.as_bytes().ct_eq(hash).unwrap_u8() != 1 {
            return Err(BlobStoreError::IntegrityMismatch);
        }
        Ok(bytes)
    }

    /// Check if a blob exists by hash.
    #[must_use]
    pub fn exists(&self, hash: &[u8; 32]) -> bool {
        let Ok(path) = validate_blob_path(&self.root, hash) else {
            return false;
        };
        existing_regular_file(&path)
    }

    /// List all known blob hashes.
    ///
    /// Directory traversal is bounded by `MAX_DIR_ENTRIES` per shard.
    ///
    /// # Errors
    ///
    /// Returns `BlobStoreError` for I/O failures while listing.
    pub fn list_all(&self) -> Result<Vec<[u8; 32]>, BlobStoreError> {
        let _ = validate_blob_path(&self.root, &[0u8; 32])?;
        let read_dir = match std::fs::read_dir(&self.root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(BlobStoreError::Io(error)),
        };

        let mut hashes = HashSet::new();
        let mut shard_count = 0usize;
        let mut total_blob_count = 0usize;
        for entry in read_dir.flatten() {
            shard_count += 1;
            if shard_count > crate::fac::safe_rmtree::MAX_DIR_ENTRIES {
                break;
            }
            let Ok(metadata) = entry.path().symlink_metadata() else {
                continue;
            };
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                continue;
            }
            let shard = entry.file_name();
            let Some(shard) = shard.to_str() else {
                continue;
            };
            if shard.len() != 2 || !is_hex(shard.as_bytes()) {
                continue;
            }
            let Ok(shard_byte) = u8::from_str_radix(shard, 16) else {
                continue;
            };
            let mut hash_prefix = [0u8; 32];
            hash_prefix[0] = shard_byte;
            let _ = validate_blob_path(&self.root, &hash_prefix)?;

            let Ok(blob_dir_entries) = std::fs::read_dir(entry.path()) else {
                continue;
            };
            let mut blob_count = 0usize;
            for blob_entry in blob_dir_entries.flatten() {
                blob_count += 1;
                if blob_count > crate::fac::safe_rmtree::MAX_DIR_ENTRIES {
                    break;
                }
                let blob_path = blob_entry.path();
                let Ok(blob_metadata) = blob_path.symlink_metadata() else {
                    continue;
                };
                if !blob_metadata.is_file() || blob_metadata.file_type().is_symlink() {
                    continue;
                }
                if blob_path.extension().and_then(|ext| ext.to_str()) != Some("blob") {
                    continue;
                }
                let Some(file_name) = blob_path.file_name().and_then(|name| name.to_str()) else {
                    continue;
                };
                if let Some(hash) = parse_blob_name(shard, file_name) {
                    hashes.insert(hash);
                    total_blob_count += 1;
                    if total_blob_count >= MAX_BLOB_LIST_ENTRIES {
                        break;
                    }
                }
            }
            if total_blob_count >= MAX_BLOB_LIST_ENTRIES {
                break;
            }
        }

        let mut out = hashes.into_iter().collect::<Vec<_>>();
        out.sort_unstable();
        Ok(out)
    }

    /// Returns the filesystem path where a blob with the given hash would be
    /// stored.
    #[must_use]
    pub fn blob_path(&self, hash: &[u8; 32]) -> PathBuf {
        let hex = hex::encode(hash);
        self.root
            .join(&hex[..2])
            .join(format!("{}.blob", &hex[2..]))
    }
}

fn parse_blob_name(shard: &str, filename: &str) -> Option<[u8; 32]> {
    let (stem, _) = filename.split_once(".blob")?;
    if stem.len() != 62 {
        return None;
    }
    if !is_hex(stem.as_bytes()) {
        return None;
    }
    let mut hex = String::with_capacity(64);
    hex.push_str(shard);
    hex.push_str(stem);
    parse_hash_hex(&hex)
}

fn parse_hash_hex(hex_string: &str) -> Option<[u8; 32]> {
    if hex_string.len() != 64 {
        return None;
    }
    let bytes = hex::decode(hex_string).ok()?;
    bytes.try_into().ok()
}

fn is_hex(bytes: &[u8]) -> bool {
    bytes.iter().all(u8::is_ascii_hexdigit)
}

fn existing_regular_file(path: &Path) -> bool {
    let Ok(metadata) = path.symlink_metadata() else {
        return false;
    };
    metadata.is_file() && !metadata.file_type().is_symlink()
}

fn ensure_secure_dir_mode(path: &Path, mode: u32) -> Result<(), BlobStoreError> {
    match path.symlink_metadata() {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(BlobStoreError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "path is symlink",
                )));
            }
            if !metadata.is_dir() {
                return Err(BlobStoreError::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "path exists but is not a directory",
                )));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
                    .map_err(BlobStoreError::Io)?;
            }
            Ok(())
        },
        Err(error) => {
            if error.kind() != io::ErrorKind::NotFound {
                return Err(BlobStoreError::Io(error));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                let mut builder = std::fs::DirBuilder::new();
                builder.recursive(true);
                builder.mode(mode);
                builder.create(path).map_err(BlobStoreError::Io)
            }
            #[cfg(not(unix))]
            {
                std::fs::create_dir_all(path).map_err(BlobStoreError::Io)
            }
        },
    }
}

fn unique_temp_path(shard_dir: &Path, hash: &[u8; 32]) -> Result<PathBuf, BlobStoreError> {
    let hash_prefix = hex::encode(hash);
    let process_id = std::process::id();
    for attempt in 0..MAX_BLOB_WRITE_RETRIES {
        let suffix = format!(".tmp.{process_id:x}.{attempt}.{}", &hash_prefix[2..10]);
        let path = shard_dir.join(suffix);
        if path.exists() {
            continue;
        }
        return Ok(path);
    }
    Err(BlobStoreError::Io(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "unable to allocate unique temp file path",
    )))
}

fn write_atomic(
    data: &[u8],
    temp_path: &Path,
    final_path: &Path,
    hash_bytes: &[u8; 32],
) -> Result<(), BlobStoreError> {
    use std::fs::OpenOptions;

    #[allow(clippy::disallowed_methods)]
    let mut file = {
        #[cfg(unix)]
        {
            let mut options = OpenOptions::new();
            options.write(true);
            options.create_new(true);
            options.truncate(true);
            options.custom_flags(libc::O_NOFOLLOW);
            options.mode(0o600);
            options.open(temp_path).map_err(|error| {
                if error.raw_os_error() == Some(libc::ELOOP) {
                    BlobStoreError::SymlinkDetected
                } else {
                    BlobStoreError::Io(error)
                }
            })?
        }
        #[cfg(not(unix))]
        {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .truncate(true)
                .open(temp_path)
                .map_err(BlobStoreError::Io)?
        }
    };
    file.write_all(data).map_err(BlobStoreError::Io)?;
    file.flush().map_err(BlobStoreError::Io)?;

    match std::fs::rename(temp_path, final_path) {
        Ok(()) => Ok(()),
        Err(error) if final_path.exists() => {
            let _ = std::fs::remove_file(temp_path);
            let meta = final_path.symlink_metadata()?;
            if meta.len() > MAX_BLOB_SIZE as u64 {
                let size = usize::try_from(meta.len()).unwrap_or(usize::MAX);
                return Err(BlobStoreError::TooLarge {
                    size,
                    max: MAX_BLOB_SIZE,
                });
            }
            let mut existing_file = open_blob_file_no_follow_for_read(final_path)?;
            let fd_meta = existing_file.metadata().map_err(BlobStoreError::Io)?;
            if fd_meta.len() > MAX_BLOB_SIZE as u64 {
                return Err(BlobStoreError::TooLarge {
                    size: usize::try_from(fd_meta.len()).unwrap_or(usize::MAX),
                    max: MAX_BLOB_SIZE,
                });
            }
            let mut existing = Vec::with_capacity(usize::try_from(fd_meta.len()).unwrap_or(0));
            Read::take(&mut existing_file, MAX_BLOB_SIZE as u64 + 1)
                .read_to_end(&mut existing)
                .map_err(BlobStoreError::Io)?;
            if existing.len() > MAX_BLOB_SIZE {
                return Err(BlobStoreError::TooLarge {
                    size: existing.len(),
                    max: MAX_BLOB_SIZE,
                });
            }
            let actual = blake3::hash(&existing);
            if actual.as_bytes().ct_eq(hash_bytes).unwrap_u8() == 1 {
                Ok(())
            } else {
                Err(BlobStoreError::IntegrityMismatch)
            }
        },
        Err(error) => {
            let _ = std::fs::remove_file(temp_path);
            Err(BlobStoreError::Io(error))
        },
    }
}

#[cfg(unix)]
fn open_blob_file_no_follow_for_read(path: &Path) -> Result<std::fs::File, BlobStoreError> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    options.custom_flags(libc::O_NOFOLLOW);
    options.open(path).map_err(|error| {
        if error.raw_os_error() == Some(libc::ELOOP) {
            BlobStoreError::SymlinkDetected
        } else {
            BlobStoreError::Io(error)
        }
    })
}

#[cfg(not(unix))]
fn open_blob_file_no_follow_for_read(path: &Path) -> Result<std::fs::File, BlobStoreError> {
    std::fs::File::open(path).map_err(BlobStoreError::Io)
}

#[cfg(unix)]
fn open_blob_file_no_follow_for_write(path: &Path) -> Result<std::fs::File, BlobStoreError> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    options.write(true);
    options.custom_flags(libc::O_NOFOLLOW);
    options.open(path).map_err(|error| {
        if error.raw_os_error() == Some(libc::ELOOP) {
            BlobStoreError::SymlinkDetected
        } else {
            BlobStoreError::Io(error)
        }
    })
}

#[cfg(not(unix))]
fn open_blob_file_no_follow_for_write(path: &Path) -> Result<std::fs::File, BlobStoreError> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(BlobStoreError::Io)
}

#[derive(Debug, Error)]
#[non_exhaustive]
/// Blob-store operation errors.
pub enum BlobStoreError {
    /// Blob exceeds configured maximum payload size.
    #[error("blob size {size} exceeds maximum {max}")]
    TooLarge {
        /// Actual size of data.
        size: usize,
        /// Maximum configured size.
        max: usize,
    },

    /// Blob does not exist.
    #[error("blob not found")]
    NotFound,

    /// Stored content does not match expected hash.
    #[error("stored blob hash mismatch")]
    IntegrityMismatch,

    /// Filesystem access failure.
    #[error("I/O failure: {0}")]
    Io(#[from] std::io::Error),

    /// Symlink encountered in blob store path.
    #[error("symlink detected in blob store path")]
    SymlinkDetected,
}

fn validate_blob_path(root: &Path, hash: &[u8; 32]) -> Result<PathBuf, BlobStoreError> {
    let hex = hex::encode(hash);
    let shard = &hex[..2];
    let filename = format!("{}.blob", &hex[2..]);
    let shard_dir = root.join(shard);

    if let Ok(meta) = root.symlink_metadata() {
        if meta.file_type().is_symlink() {
            return Err(BlobStoreError::SymlinkDetected);
        }
    }

    if let Ok(meta) = shard_dir.symlink_metadata() {
        if meta.file_type().is_symlink() {
            return Err(BlobStoreError::SymlinkDetected);
        }
    }

    Ok(shard_dir.join(filename))
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::fs;

    use tempfile::tempdir;

    use super::*;
    use crate::fac::safe_rmtree::MAX_DIR_ENTRIES;

    fn hash_path(root: &Path, hash: &[u8; 32]) -> PathBuf {
        let hex = hex::encode(hash);
        root.join(BLOB_DIR)
            .join(&hex[..2])
            .join(format!("{}.blob", &hex[2..]))
    }

    #[test]
    fn test_store_and_retrieve_round_trip() {
        let temp = tempdir().expect("tempdir");
        let store = BlobStore::new(temp.path());
        let input = b"hello patch";
        let hash = store.store(input).expect("store");
        let out = store.retrieve(&hash).expect("retrieve");
        assert_eq!(out, input);
    }

    #[test]
    fn test_store_duplicate_is_idempotent() {
        let temp = tempdir().expect("tempdir");
        let store = BlobStore::new(temp.path());
        let input = b"patch duplicate";
        let first = store.store(input).expect("first store");
        let second = store.store(input).expect("second store");
        assert_eq!(first, second);
        let all = store.list_all().expect("list");
        assert_eq!(all.len(), 1);
    }

    #[test]
    fn test_retrieve_nonexistent_blob() {
        let temp = tempdir().expect("tempdir");
        let store = BlobStore::new(temp.path());
        assert!(matches!(
            store.retrieve(&[0u8; 32]),
            Err(BlobStoreError::NotFound)
        ));
    }

    #[test]
    fn test_store_oversized_blob() {
        let temp = tempdir().expect("tempdir");
        let store = BlobStore::new(temp.path());
        let oversized = vec![0u8; MAX_BLOB_SIZE + 1];
        let result = store.store(&oversized);
        assert!(matches!(
            result,
            Err(BlobStoreError::TooLarge {
                size,
                max,
            }) if size == MAX_BLOB_SIZE + 1 && max == MAX_BLOB_SIZE
        ));
    }

    #[test]
    fn test_retrieve_tampered_blob_fails_integrity() {
        let temp = tempdir().expect("tempdir");
        let store = BlobStore::new(temp.path());
        let input = b"critical patch";
        let hash = store.store(input).expect("store");
        let path = hash_path(temp.path(), &hash);
        fs::write(&path, b"tampered payload").expect("tamper");

        assert!(matches!(
            store.retrieve(&hash),
            Err(BlobStoreError::IntegrityMismatch)
        ));
    }

    #[test]
    fn test_list_all_blobs() {
        let temp = tempdir().expect("tempdir");
        let store = BlobStore::new(temp.path());
        let first = store.store(b"patch 1").expect("store1");
        let second = store.store(b"patch 2").expect("store2");
        let third = store.store(b"patch 3").expect("store3");
        let hashes = store.list_all().expect("list all");
        let set: HashSet<_> = hashes.into_iter().collect();
        assert!(set.contains(&first));
        assert!(set.contains(&second));
        assert!(set.contains(&third));
        assert_eq!(set.len(), 3);
        let dir_entry_count = temp
            .path()
            .join(BLOB_DIR)
            .read_dir()
            .expect("read shard root")
            .flatten()
            .count();
        assert!(dir_entry_count <= MAX_DIR_ENTRIES);
    }

    #[test]
    fn test_exists_checks_bound_and_content() {
        let temp = tempdir().expect("tempdir");
        let store = BlobStore::new(temp.path());
        let bytes = b"existence";
        let hash = blake3::hash(bytes);
        assert!(!store.exists(hash.as_bytes()));
        let stored = store.store(bytes).expect("store");
        assert!(store.exists(&stored));
    }

    #[cfg(unix)]
    #[test]
    fn test_store_rejects_symlinked_shard() {
        use std::os::unix::fs::symlink;

        let temp = tempdir().expect("tempdir");
        let store = BlobStore::new(temp.path());
        let data = b"symlinked shard";
        let hash = blake3::hash(data);
        let blob_path = hash_path(temp.path(), hash.as_bytes());
        let attacker_target = temp.path().join("attacker-shard-target");
        let shard_parent = blob_path.parent().expect("blob parent");
        std::fs::create_dir_all(shard_parent.parent().expect("shard root"))
            .expect("mkdir shard root");

        std::fs::create_dir_all(&attacker_target).expect("mkdir attacker target");
        symlink(&attacker_target, shard_parent).expect("create symlink");

        let result = store.store(data);
        assert!(matches!(result, Err(BlobStoreError::SymlinkDetected)));
    }

    #[cfg(unix)]
    #[test]
    fn test_retrieve_rejects_symlinked_blob_path() {
        use std::os::unix::fs::symlink;

        let temp = tempdir().expect("tempdir");
        let store = BlobStore::new(temp.path());
        let data = b"symlinked blob";
        let hash = blake3::hash(data);
        let blob_path = hash_path(temp.path(), hash.as_bytes());
        let attacker_target = temp.path().join("attacker-file-target");
        std::fs::create_dir_all(blob_path.parent().expect("blob parent"))
            .expect("mkdir blob parent");
        std::fs::write(&attacker_target, b"attacker data").expect("write attacker");
        symlink(&attacker_target, &blob_path).expect("create symlink");

        let result = store.retrieve(hash.as_bytes());
        assert!(matches!(result, Err(BlobStoreError::SymlinkDetected)));
    }
}
