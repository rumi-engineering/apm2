# Security Checklist

This checklist covers security-critical patterns for APM2 development. Reference when handling secrets, paths, or cryptographic data.

---

## Sensitive Data Handling

Use `SecretString` from the `secrecy` crate to hold sensitive data, preventing accidental logging.

```rust
use secrecy::SecretString;

pub enum AuthMethod {
    ApiKey {
        key: SecretString,  // Never logged
    },
}
```

**Accessing the secret:**
```rust
use secrecy::ExposeSecret;
let key: &str = api_key.expose_secret();
```

**Checklist:**
- [ ] API keys, tokens, passwords use `SecretString`
- [ ] Sensitive data is never logged (check `Debug` impls)
- [ ] Secrets are not serialized to disk in plaintext

---

## Path Traversal Prevention

Never interpolate user-provided identifiers directly into file paths.

**Unsafe:**
```rust
// actor_id could be "../../../etc/passwd"
let path = PathBuf::from("keys").join(actor_id);
```

**Safe:**
```rust
// Validate the identifier format
if !actor_id.chars().all(|c| c.is_ascii_alphanumeric()) {
    return Err(Error::InvalidId);
}
let path = PathBuf::from("keys").join(actor_id);
```

**Checklist:**
- [ ] All external input used in paths is validated
- [ ] Paths don't contain `..`, `/`, or `\` from user input
- [ ] Canonicalize paths before access if needed

---

## Secure Directory Creation

Use platform-specific extensions to set restrictive permissions *atomically* during directory creation.

```rust
#[cfg(unix)]
{
    use std::os::unix::fs::DirBuilderExt;
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    builder.mode(0o700);  // Private to the user
    builder.create(path)?;
}
```

**Checklist:**
- [ ] Directories for keys/credentials use 0o700 permissions
- [ ] Permissions are set atomically (not create-then-chmod)
- [ ] Non-Unix platforms have appropriate handling

---

## Cryptographic Canonicalization

When signing or hashing collections, always apply deterministic sort order before serialization.

```rust
pub fn prepare_for_signing(mut items: Vec<Item>) -> Vec<u8> {
    items.sort_by(|a, b| a.id.cmp(&b.id));
    serialize(&items)
}
```

**Checklist:**
- [ ] Collections are sorted before hashing/signing
- [ ] Sort key is stable and deterministic
- [ ] Canonical representations are used for "null" values (e.g., `[0u8; 32]`)

---

## Atomic File Operations

Use write-then-rename for files that must not be corrupted on crash.

```rust
let temp_path = path.with_extension("tmp");
std::fs::write(&temp_path, content)?;
std::fs::rename(&temp_path, path)?;  // Atomic on POSIX
```

**Checklist:**
- [ ] State/config files use write-then-rename
- [ ] Temp files are in the same directory as target (for same-filesystem atomicity)
- [ ] Error handling cleans up temp files on failure

---

## Quick Security Review

Before merging code that handles sensitive data:

1. [ ] **Secrets**: All secrets use `SecretString`
2. [ ] **Paths**: All user input in paths is validated
3. [ ] **Permissions**: Sensitive directories use restrictive permissions
4. [ ] **Crypto**: Collections are sorted before signing
5. [ ] **Atomicity**: Critical file writes use rename pattern
6. [ ] **Logging**: No sensitive data in logs or error messages
