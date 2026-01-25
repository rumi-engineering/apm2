# Crypto Module

> Cryptographic primitives for hash-chain integrity and event authentication in the APM2 event ledger.

## Overview

The `apm2_core::crypto` module provides the cryptographic foundation for APM2's event-sourced architecture. Every event in the ledger is cryptographically linked to its predecessor via BLAKE3 hashing and authenticated via Ed25519 signatures, ensuring immutability and non-repudiation.

This module implements two core security properties:

1. **Hash-chain integrity**: Events form a tamper-evident chain where each event's hash incorporates the previous event's hash. Modifying any historical event breaks the chain.

2. **Signature authentication**: Events are signed by actor-specific Ed25519 keys, providing authenticity and preventing unauthorized event injection.

## Key Types

### `Hash`

```rust
/// Size of a Blake3 hash in bytes.
pub const HASH_SIZE: usize = 32;

/// Type alias for a 32-byte hash.
pub type Hash = [u8; HASH_SIZE];
```

**Invariants:**
- [INV-0001] Hash outputs are always exactly 32 bytes
- [INV-0002] Hash function is deterministic: identical inputs produce identical outputs

### `EventHasher`

```rust
/// Hasher for kernel events using Blake3.
pub struct EventHasher;
```

**Invariants:**
- [INV-0003] Genesis events use `GENESIS_PREV_HASH` (32 zero bytes) as their previous hash
- [INV-0004] Hash chain is computed as `BLAKE3(prev_hash || content)`

**Contracts:**
- [CTR-0001] `hash_event()` must receive a 32-byte `prev_hash`; other lengths cause undefined behavior in chain verification
- [CTR-0002] Different storage layers may represent genesis `prev_hash` as NULL (SQLite) or empty bytes (protobuf); use `normalize_prev_hash()` at API boundaries

### `HashChainError`

```rust
#[derive(Debug, Error)]
pub enum HashChainError {
    /// The previous hash doesn't match the expected value.
    #[error("hash chain broken: expected {expected}, got {actual}")]
    ChainBroken {
        expected: String,
        actual: String,
    },

    /// The event hash doesn't match the computed value.
    #[error("event hash mismatch: expected {expected}, got {actual}")]
    HashMismatch {
        expected: String,
        actual: String,
    },
}
```

### `Signer`

```rust
/// A signer that holds an Ed25519 keypair for signing events.
///
/// The secret key is zeroized when the signer is dropped.
pub struct Signer {
    signing_key: SigningKey,
}
```

**Invariants:**
- [INV-0005] Secret keys are zeroized on drop via the `zeroize` crate
- [INV-0006] Ed25519 signatures are deterministic: same key + message = same signature

**Contracts:**
- [CTR-0003] Signatures are 64 bytes (`SIGNATURE_SIZE`)
- [CTR-0004] Public keys are 32 bytes (`PUBLIC_KEY_SIZE`)
- [CTR-0005] Secret keys are 32 bytes (`SECRET_KEY_SIZE`)

### `SignerError`

```rust
#[derive(Debug, Error)]
pub enum SignerError {
    /// Invalid key format or length.
    #[error("invalid key: {0}")]
    InvalidKey(String),

    /// Signature verification failed.
    #[error("signature verification failed")]
    VerificationFailed,

    /// The signature is malformed.
    #[error("malformed signature: {0}")]
    MalformedSignature(String),
}
```

### `KeyManager`

```rust
/// Manager for storing and retrieving signing keys.
///
/// Keys can be stored in memory (for testing) or on disk with secure
/// file permissions (0600).
pub struct KeyManager {
    storage: KeyStorage,
}
```

**Invariants:**
- [INV-0007] File-based keys are stored with 0600 permissions (owner read/write only)
- [INV-0008] Key directory is created with 0700 permissions
- [INV-0009] Actor IDs are validated: 1-128 chars, alphanumeric with hyphens/underscores, no leading hyphen

**Contracts:**
- [CTR-0006] `generate_keypair()` fails with `KeyAlreadyExists` if actor ID already has a key
- [CTR-0007] `store_keypair()` does not allow overwrites; use `delete_keypair()` first
- [CTR-0008] Path traversal attempts in actor IDs are rejected (`../`, `/`, `\`)

### `KeyManagerError`

```rust
#[derive(Debug, Error)]
pub enum KeyManagerError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("key not found: {actor_id}")]
    KeyNotFound { actor_id: String },

    #[error("key already exists for actor: {actor_id}")]
    KeyAlreadyExists { actor_id: String },

    #[error("invalid key format: {0}")]
    InvalidKeyFormat(String),

    #[error("insecure permissions on key file: {path}")]
    InsecurePermissions { path: String },

    #[error("invalid actor ID: {actor_id} (must be alphanumeric with hyphens/underscores, 1-128 chars)")]
    InvalidActorId { actor_id: String },
}
```

### `StoredKeypair`

```rust
/// A stored keypair with metadata.
#[derive(Clone)]
pub struct StoredKeypair {
    /// The actor ID this keypair belongs to.
    pub actor_id: String,

    /// The signing key (secret key).
    signing_key: SigningKey,

    /// The public key bytes.
    pub public_key: [u8; PUBLIC_KEY_SIZE],
}
```

**Contracts:**
- [CTR-0009] `secret_key_bytes()` returns a `Zeroizing` container for secure handling

## Public API

### Hashing

| Function | Description |
|----------|-------------|
| `EventHasher::hash_event(content, prev_hash)` | Hash content with chain linking |
| `EventHasher::hash_content(content)` | Hash raw content without chain linking (for CAS) |
| `EventHasher::verify_hash(content, prev_hash, expected)` | Verify a single event hash |
| `EventHasher::verify_chain_link(current_prev, previous_hash)` | Verify link between two events |
| `EventHasher::verify_chain(events)` | Verify an entire chain of events |
| `is_genesis_prev_hash(bytes)` | Check if bytes represent genesis prev_hash |
| `normalize_prev_hash(bytes)` | Normalize empty/zero bytes to canonical form |

### Signing

| Function | Description |
|----------|-------------|
| `Signer::new(signing_key)` | Create signer from existing key |
| `Signer::from_bytes(secret_key_bytes)` | Create signer from raw bytes |
| `Signer::generate()` | Generate new random keypair |
| `Signer::sign(message)` | Sign a message |
| `Signer::verify(message, signature)` | Verify with signer's public key |
| `Signer::verifying_key()` | Get the public key |
| `verify_signature(verifying_key, message, signature)` | Verify with any public key |
| `parse_signature(bytes)` | Parse signature from 64 bytes |
| `parse_verifying_key(bytes)` | Parse public key from 32 bytes |

### Key Management

| Function | Description |
|----------|-------------|
| `KeyManager::in_memory()` | Create in-memory manager (testing) |
| `KeyManager::new(keys_dir)` | Create file-based manager |
| `KeyManager::generate_keypair(actor_id)` | Generate and store new keypair |
| `KeyManager::store_keypair(actor_id, signing_key)` | Store existing keypair |
| `KeyManager::get_keypair(actor_id)` | Retrieve keypair |
| `KeyManager::delete_keypair(actor_id)` | Delete keypair |
| `KeyManager::list_actors()` | List all actor IDs with keys |

## Examples

### Event Signing Workflow

```rust
use apm2_core::crypto::{EventHasher, KeyManager, Signer};

fn sign_event() -> Result<(), Box<dyn std::error::Error>> {
    // Create a key manager and generate a keypair
    let key_manager = KeyManager::in_memory();
    let keypair = key_manager.generate_keypair("actor-1")?;

    // Hash event content with chain linking
    let content = b"session.start: session-123";
    let prev_hash = EventHasher::GENESIS_PREV_HASH; // First event
    let event_hash = EventHasher::hash_event(content, &prev_hash);

    // Sign the hash
    let signer = Signer::new(keypair);
    let signature = signer.sign(&event_hash);

    // Verify the signature
    assert!(signer.verify(&event_hash, &signature));
    Ok(())
}
```

### Hash Chain Verification

```rust
use apm2_core::crypto::{EventHasher, Hash, HASH_SIZE};

fn verify_chain() {
    let events = [b"event-1", b"event-2", b"event-3"];

    let mut chain: Vec<(Vec<u8>, Hash, Hash)> = Vec::new();
    let mut prev_hash = EventHasher::GENESIS_PREV_HASH;

    for content in &events {
        let event_hash = EventHasher::hash_event(*content, &prev_hash);
        chain.push((content.to_vec(), prev_hash, event_hash));
        prev_hash = event_hash;
    }

    // Verify entire chain
    let refs: Vec<_> = chain.iter()
        .map(|(c, p, h)| (c.as_slice(), p, h))
        .collect();
    EventHasher::verify_chain(refs).unwrap();
}
```

### Tamper Detection

```rust
use apm2_core::crypto::{EventHasher, Signer, HashChainError};

fn detect_tampering() {
    let signer = Signer::generate();
    let original = b"original content";
    let prev_hash = EventHasher::GENESIS_PREV_HASH;

    let event_hash = EventHasher::hash_event(original, &prev_hash);
    let signature = signer.sign(&event_hash);

    // Attempt to verify tampered content
    let tampered = b"tampered content";
    let tampered_hash = EventHasher::hash_event(tampered, &prev_hash);

    // Signature fails verification with tampered hash
    assert!(!signer.verify(&tampered_hash, &signature));
}
```

### File-Based Key Storage

```rust
use apm2_core::crypto::KeyManager;
use std::path::Path;

fn persistent_keys() -> Result<(), Box<dyn std::error::Error>> {
    // Keys stored in ~/.apm2/keys/ with 0600 permissions
    let key_manager = KeyManager::new("/home/user/.apm2/keys")?;

    // Generate key for actor (persisted to disk)
    key_manager.generate_keypair("agent-claude")?;

    // Later: retrieve the key
    let keypair = key_manager.get_keypair("agent-claude")?;
    println!("Public key: {:?}", keypair.public_key);

    Ok(())
}
```

## Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `HASH_SIZE` | 32 | BLAKE3 output size in bytes |
| `SIGNATURE_SIZE` | 64 | Ed25519 signature size in bytes |
| `SECRET_KEY_SIZE` | 32 | Ed25519 secret key size in bytes |
| `PUBLIC_KEY_SIZE` | 32 | Ed25519 public key size in bytes |
| `EventHasher::GENESIS_PREV_HASH` | `[0u8; 32]` | Canonical genesis previous hash |

## Security Considerations

1. **Key Zeroization**: Secret keys use `Zeroizing<T>` wrappers to ensure memory is cleared on drop, mitigating cold-boot attacks.

2. **File Permissions**: The `KeyManager` enforces 0600 permissions on key files and 0700 on key directories. It refuses to read keys with insecure permissions.

3. **Actor ID Validation**: Actor IDs are strictly validated to prevent path traversal attacks. Only alphanumeric characters, hyphens, and underscores are allowed.

4. **No Key Overwrites**: The `store_keypair()` method refuses to overwrite existing keys, preventing accidental key loss.

5. **Deterministic Signatures**: Ed25519 signatures are deterministic (RFC 8032), avoiding randomness-related vulnerabilities.

## Related Modules

- [`apm2_core::ledger`](../ledger/AGENTS.md) - Event storage using hash chains and signatures
- [`apm2_core::evidence`](../evidence/AGENTS.md) - Content-addressed storage using BLAKE3 hashes
- [`apm2_core::events`](../events/AGENTS.md) - Event types that include hash and signature fields
