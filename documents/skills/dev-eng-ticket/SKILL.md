---
name: dev-eng-ticket
description: Orchestrate development work for an engineering ticket, with paths for new work or existing PR follow-up.
argument-hint: "[TCK-XXXXX | RFC-XXXX | empty]"
---

orientation: "You are an autonomous senior engineer tasked with implementing a critical engineering ticket. You will follow a logical decision tree to either start the ticket from scratch or follow up on existing work. Your task is scoped purely to working on the ticket. Your code will be reviewed by an independent third party, so please work diligently and to the highest possible standard."

note: "Module-specific documentation and invariants live in AGENTS.md files colocated with the code you are editing. Always read the root README.md to identify the relevant modules and their corresponding AGENTS.md files before making changes. Update AGENTS.md when module invariants or public behavior changes."

title: Dev Engineering Ticket Workflow
protocol:
  id: DEV-ENG-TICKET
  version: 2.0.0
  type: executable_specification
  inputs[1]:
    - TICKET_ID_OPTIONAL
  outputs[3]:
    - WorktreePath
    - PR_URL
    - MergeStatus

variables:
  TICKET_ID_OPTIONAL: "$1"

references[2]:
  - path: references/dev-eng-ticket-workflow.md
    purpose: "Primary decision tree for new ticket vs existing PR follow-up."
  - path: references/commands.md
    purpose: "Command reference with flags and examples."

decision_tree:
  entrypoint: WORKFLOW
  nodes[1]:
    - id: WORKFLOW
      action: invoke_reference
      reference: references/dev-eng-ticket-workflow.md

## Useful Rust Skills (Reviewer Alignment)

## APM2 Rust PR Review Style Guide

Ultra-specific Rust implementation patterns to avoid recurring code-quality and security review findings. These patterns enforce the [APM2 Rust Textbook](/documents/skills/rust-textbook/) contracts.

### 0. Global Conventions

1. **Adversarial Input:** Treat all external input (files, paths, JSON, env vars) as adversarial ([CTR-2401]).
2. **Streaming over Buffering:** Prefer streaming. Buffering requires a hard maximum known before allocation ([RSK-1601], [RSK-2415]).
3. **Atomic State Changes:** Writes that update mutable state MUST be atomic (temp file + rename). Never write directly to target path ([CTR-1502], [CTR-2607]).
4. **Workspace Confinement:** Paths derived from input must be confined to a root and symlink-aware ([CTR-2609], [RSK-1501]).

---

## 1. Bounded Reads and Allocation Control (`RSK-2415`, `RSK-1601`)

### 1.1 Bounded File Read

Use when the full content is required in memory. Check `metadata().len()` on the **handle** to prevent TOCTOU races.

```rust
use std::{fs::File, io::{self, Read}, path::Path};

#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    #[error("file too large: {size} > {max}")]
    TooLarge { size: u64, max: u64 },
    #[error(transparent)]
    Io(#[from] io::Error),
}

pub fn read_file_bounded(path: &Path, max_bytes: u64) -> Result<Vec<u8>, ReadError> {
    let file = File::open(path)?;
    let meta = file.metadata()?; // Contract: CTR-1502
    let size = meta.len();
    if size > max_bytes {
        return Err(ReadError::TooLarge { size, max: max_bytes });
    }

    let mut buf = Vec::with_capacity(size as usize);
    let mut r = io::BufReader::new(file);
    r.read_to_end(&mut buf)?;
    Ok(buf)
}
```

*   **Reject if:** `Vec::with_capacity` is called before the size check.
*   **Reject if:** `read_to_string` is used on a file of unknown size.

### 1.2 Streaming Bounded Read (Preferred)

Use for incremental processing (hashing, parsing).

```rust
pub fn read_stream_bounded<R: io::Read>(mut r: R, out: &mut Vec<u8>, max: usize) -> Result<(), StreamLimitError> {
    out.clear();
    // Pre-allocate a reasonable buffer, not the attacker-controlled 'max'
    out.reserve(std::cmp::min(max, 64 * 1024));

    let mut buf = [0u8; 8192];
    let mut total: usize = 0;

    loop {
        let n = r.read(&mut buf)?;
        if n == 0 { break; }

        total = total.saturating_add(n);
        if total > max { return Err(StreamLimitError::TooLarge { max }); }
        out.extend_from_slice(&buf[..n]);
    }
    Ok(())
}
```

---

## 2. Atomic Writes and Crash-Safe Persistence (`CTR-1502`, `CTR-2607`)

### 2.1 Atomic Overwrite (Temp File + Persist)

Use for any write that updates persistent state.

```rust
use tempfile::NamedTempFile;

pub fn atomic_write_bytes(target: &Path, bytes: &[u8]) -> Result<(), AtomicWriteError> {
    let dir = target.parent().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no parent dir"))?;
    // new_in(dir) ensures atomic rename on the same filesystem
    let mut tmp = NamedTempFile::new_in(dir)?;
    tmp.write_all(bytes)?;
    tmp.flush()?;
    // Optional: fsync if durability is required (CTR-1502)
    // tmp.as_file().sync_all()?;
    tmp.persist(target)?;
    Ok(())
}
```

---

## 3. Workspace Confinement and Path Handling (`CTR-2609`, `RSK-1501`)

### 3.1 Path Sanitization

Reject `..` traversal and absolute paths at the boundary.

```rust
pub fn sanitize_relative_path(p: &Path) -> Result<PathBuf, RelPathError> {
    if p.is_absolute() { return Err(RelPathError::NotRelative); }
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::Normal(seg) => out.push(seg),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(RelPathError::ForbiddenComponent)
            }
        }
    }
    Ok(out)
}
```

### 3.2 Symlink Awareness

For security-sensitive operations, use `symlink_metadata` to detect and reject symlinks to avoid `RSK-1501`.

```rust
pub fn reject_if_any_symlink(path: &Path) -> io::Result<()> {
    let metadata = std::fs::symlink_metadata(path)?; // Invariant: CTR-2611
    if metadata.file_type().is_symlink() {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "symlink disallowed"));
    }
    // ... walk ancestors if necessary ...
    Ok(())
}
```

---

## 4. Control Enforcement Pattern (`CTR-1205`, `CTR-2603`)

### 4.1 Authoritative Apply Function

Never expose a configuration that can be partially applied. Use a single function that returns a fully prepared command or errors out.

```rust
pub fn command_with_sandbox(mut cmd: Command, profile: &SandboxProfile) -> Result<Command, SandboxError> {
    // SINGLE authoritative application point.
    apply_sandbox_controls(&mut cmd, profile)?;
    Ok(cmd)
}
```

---

## 5. Typed Error Model (`CTR-2606`, `CTR-0703`)

Use `thiserror` to separate policy rejections from I/O failures.

```rust
#[derive(Debug, thiserror::Error)]
pub enum FsEditError {
    #[error("path rejected: {0}")]
    PathRejected(String),
    #[error("payload too large: {size} > {max}")]
    TooLarge { size: u64, max: u64 },
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
```

---

## 6. Serialization in Crypto Contexts (`CTR-0701`, `RSK-2415`)

**Never swallow serialization errors** when the output feeds into a hash or signature.

```rust
// WRONG: Silent failure corrupts hash chain integrity
// let bytes = serde_jcs::to_vec(&event).unwrap_or_default();

// CORRECT: Propagate serialization failures
fn hash_event(event: &LedgerEvent) -> Result<EventHash, CryptoError> {
    let bytes = serde_jcs::to_vec(event)
        .map_err(|e| CryptoError::SerializationFailed(e.to_string()))?;
    Ok(compute_hash(&bytes))
}
```

---

## 7. Builder Validation Scope (`CTR-1205`)

Builders must validate **ALL** input fields that affect logic, not just identifiers.

```rust
impl SpawnConfigBuilder {
    pub fn build(self) -> Result<SpawnConfig, ConfigError> {
        validate_id(&self.work_id, "work_id")?;
        validate_id(&self.issuer_id, "issuer_id")?;
        // Vital: Validate specs/configs, not just IDs!
        validate_goal_spec(&self.goal_spec)?;
        Ok(SpawnConfig { ... })
    }
}
```

---

## 8. Hash Chain Integrity (`CTR-2601`)

Hash chains must commit to **ALL** related state (lifecycle events, data payloads). Disjoint chains require an RFC reference.

```rust
// CORRECT: Commit to ALL related events
let episode_hash = compute_aggregate_hash(&episode_events)?;
let committed_hash = combine_hashes(lease_issued_hash, episode_hash);
let work_completed = LedgerEvent::new(committed_hash, ...);
```

---

## 9. Non-Critical Error Visibility (`HARD-PRINT`)

Do not use `eprintln!` in library code. Use `tracing` for non-critical failures.

```rust
// Pattern: Log warnings for non-critical failures
if let Err(e) = work.set_metadata("key", value) {
    tracing::warn!(error = %e, "metadata set failed");
}
```

---

## 10. PR Checklist for Review Readiness

1.  **Bounded Reads:** All reads checked against `max` before allocation (`RSK-2415`).
2.  **Atomic Writes:** State updates use `NamedTempFile` + `persist` (`CTR-1502`).
3.  **Path Safety:** `ParentDir` (`..`) rejected; `symlink_metadata` used if sensitive.
4.  **Negative Tests:** Oversize input fails; traversal fails; forbidden actions denied (`RSK-0701`).
5.  **Miri Validation:** If `unsafe` is used, `// SAFETY:` comment is present and Miri passes (`RSK-2401`).
6.  **Textbook Alignment:** Check your changes against the [Hazard Catalog](/documents/skills/rust-textbook/24_hazard_catalog_checklists.md).
7.  **Serialization Safety:** All `serde` operations in crypto contexts propagate errors (`RSK-2415`).
8.  **Builder Completeness:** Builder validates ALL inputs (strings, specs, configs), not just IDs.
9.  **Chain Integrity:** Hash chains commit to all related events.
