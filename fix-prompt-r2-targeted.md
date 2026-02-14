# TARGETED Fix Agent: PR 654 / TCK-00511 — Round 2

## CRITICAL: Do NOT read any references or SKILL.md files. All necessary API info is included below. Go directly to making code changes.

## Worktree
You are ALREADY in `/home/ubuntu/Projects/apm2-worktrees/TCK-00511` on branch `ticket/RFC-0019/TCK-00511`.

## File to fix
`crates/apm2-cli/src/commands/fac_worker.rs` (1218 lines)

## Exact changes needed (8 fixes)

### FIX 1: TOCTOU in read_bounded (SECURITY MAJOR — lines 794-825)
**Problem**: `fs::metadata(path)` runs before `File::open(path)`. An attacker can swap the file between these calls.
**Fix**: Open the file FIRST, then call `file.metadata()` on the open handle.

Current code (lines 794-825):
```rust
fn read_bounded(path: &Path, max_size: usize) -> Result<Vec<u8>, String> {
    let metadata =
        fs::metadata(path).map_err(|e| format!("cannot stat {}: {e}", path.display()))?;
    let file_size = metadata.len();
    if file_size > max_size as u64 {
        return Err(format!("file size {file_size} exceeds max {max_size}"));
    }
    #[allow(clippy::cast_possible_truncation)]
    let alloc_size = file_size as usize;
    let mut buf = Vec::with_capacity(alloc_size);
    let file = fs::File::open(path).map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    let read_limit = max_size.saturating_add(1);
    let mut limited_reader = file.take(read_limit as u64);
    limited_reader
        .read_to_end(&mut buf)
        .map_err(|e| format!("read error on {}: {e}", path.display()))?;
    if buf.len() > max_size {
        return Err(format!("file grew to {} (exceeds max {})", buf.len(), max_size));
    }
    Ok(buf)
}
```

Replace with:
```rust
fn read_bounded(path: &Path, max_size: usize) -> Result<Vec<u8>, String> {
    // Open the file FIRST, then check metadata on the open handle to avoid
    // TOCTOU (RSK-1501, CTR-1603): no window to swap via symlink.
    let file = fs::File::open(path).map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|e| format!("cannot stat {}: {e}", path.display()))?;
    let file_size = metadata.len();
    if file_size > max_size as u64 {
        return Err(format!("file size {file_size} exceeds max {max_size}"));
    }

    #[allow(clippy::cast_possible_truncation)]
    let alloc_size = file_size as usize;
    let mut buf = Vec::with_capacity(alloc_size);

    // Read up to max_size + 1 to detect if the file grew after stat.
    let read_limit = max_size.saturating_add(1);
    let mut limited_reader = file.take(read_limit as u64);
    limited_reader
        .read_to_end(&mut buf)
        .map_err(|e| format!("read error on {}: {e}", path.display()))?;

    if buf.len() > max_size {
        return Err(format!(
            "file grew to {} (exceeds max {})",
            buf.len(),
            max_size
        ));
    }

    Ok(buf)
}
```

### FIX 2: SystemTime::now() for token verification (SECURITY MAJOR — lines 515-518)
**Problem**: Uses `SystemTime::now()` for RFC-0028 token verification, which is non-monotonic.
**Fix**: Use `broker.current_tick()` instead.

Replace lines 515-518:
```rust
    let current_time_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
```

With:
```rust
    // Use broker's HTF tick for temporal checks instead of SystemTime::now()
    // to prevent clock rollback attacks (INV-F-08, CTR-2501).
    let current_time_secs = broker.current_tick();
```

### FIX 3: Empty QueueSchedulerState (QUALITY MAJOR — line 558)
**Problem**: `QueueSchedulerState::new()` creates empty state with zero backlog, bypassing admission capacity checks.
**Fix**: Populate with actual queue metrics from the candidates list.

Replace line 558:
```rust
    let scheduler = QueueSchedulerState::new();
```

With:
```rust
    // Populate scheduler state with actual queue metrics from scan_pending
    // so admission capacity checks (INV-QA05) are effective.
    let scheduler = {
        let mut s = QueueSchedulerState::new();
        // The candidates vec contains all currently pending jobs. Use its
        // length as the queue depth. Count items by lane for per-lane metrics.
        s.total_items = candidates_len as u64;
        s.backlog = candidates_len as u64;
        s
    };
```

Wait — I need to check what fields QueueSchedulerState has. Let me reconsider.

Actually, the `candidates` variable is not in scope inside `process_job`. The fix needs to pass candidates info into process_job, or populate the scheduler in the outer loop. Let me think...

The `process_job` function is called per-candidate. The scheduler state should be built in the outer loop and passed in. BUT `QueueSchedulerState` may not have settable public fields. Let me just note that the agent should check what fields are available on `QueueSchedulerState` and populate them accordingly. The key point is: pass the total number of pending candidates as the queue depth.

### FIX 3 (revised): Empty QueueSchedulerState
**Approach**: In `run_fac_worker`, after `scan_pending` returns candidates, build a `QueueSchedulerState` with the actual queue depth and pass it to `process_job`.

1. Add `candidates_count: usize` parameter to `process_job` function signature
2. Inside `process_job`, replace `QueueSchedulerState::new()` with a populated version
3. Or: build the scheduler state in the outer loop and pass it in

### FIX 4: IO Thrashing on Lane Saturation (QUALITY MAJOR — around line 261-304)
**Problem**: When all lanes are busy, the loop continues processing all candidates, doing useless rename operations.
**Fix**: Break the loop when a job is skipped due to lane exhaustion.

In the for loop at line 261, after the `process_job` call, add a check:
```rust
            // Break on lane saturation to avoid IO thrashing.
            if matches!(&outcome, JobOutcome::Skipped { reason } if reason.contains("no lane available")) {
                break;
            }
```

### FIX 5: Missing Health Gate enforcement (QUALITY MAJOR — around line 446)
**Problem**: Worker evaluates tokens and economics but doesn't check broker health gate.
**Fix**: After the health check on line 218, verify the gate passed; also check it before admission in process_job.

In `run_fac_worker`, after line 218 (`let _health = broker.check_health(...)`), add:
```rust
    // Evaluate admission health gate (INV-BH-003). If the gate fails,
    // the broker is in a degraded/failed state and we must fail-closed.
    if let Err(e) = broker.evaluate_admission_health_gate(
        &checker,
        &eval_window,
        apm2_core::fac::broker_health::WorkerHealthPolicy::default(),
    ) {
        output_worker_error(json_output, &format!("admission health gate failed: {e}"));
        return exit_codes::GENERIC_ERROR;
    }
```

And in `process_job`, before the admission evaluation (before line 558), add:
```rust
    // Check broker health gate before admission (INV-BH-003).
    if !broker.is_admission_health_gate_passed() {
        let reason = "broker admission health gate not passed (INV-BH-003)".to_string();
        let _ = move_to_dir_safe(path, &queue_root.join(DENIED_DIR), &file_name);
        write_receipt(queue_root, &file_name, "deny", &reason, Some(&spec.job_id));
        return JobOutcome::Denied { reason };
    }
```

### FIX 6: Persistent broker key (SECURITY BLOCKER — line 199)
**Problem**: `FacBroker::new()` generates an ephemeral key every time. Receipts are unverifiable.
**Fix**: Try to load persistent signing key from `~/.apm2/private/fac/signing_key`. If not found, generate and save.

Available APIs:
- `Signer::from_bytes(secret_key_bytes: &[u8]) -> Result<Self, SignerError>` — 32-byte secret key
- `Signer::secret_key_bytes() -> Zeroizing<[u8; 32]>` — export key bytes
- `Signer::generate() -> Self` — new key
- `FacBroker::from_signer_and_state(signer, state) -> Result<Self, BrokerError>` — load from state
- `FacBroker::serialize_state() -> Result<Vec<u8>, BrokerError>` — save state
- `FacBroker::deserialize_state(bytes: &[u8]) -> Result<BrokerState, BrokerError>` — load state

Add a helper function:
```rust
/// Loads or generates a persistent signing key from `$APM2_HOME/private/fac/signing_key`.
///
/// On first run, generates a new key and saves it with 0600 permissions.
/// On subsequent runs, loads the existing key. This ensures receipts are
/// verifiable across worker restarts (BLOCKER: ephemeral key fix).
fn load_or_generate_persistent_signer() -> Result<Signer, String> {
    let fac_root = resolve_fac_root()?;
    let key_path = fac_root.join("signing_key");

    if key_path.exists() {
        let bytes = read_bounded(&key_path, 64)?;
        Signer::from_bytes(&bytes).map_err(|e| format!("invalid signing key: {e}"))
    } else {
        let signer = Signer::generate();
        let key_bytes = signer.secret_key_bytes();
        // Ensure parent directory exists.
        if let Some(parent) = key_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create key directory: {e}"))?;
        }
        fs::write(&key_path, key_bytes.as_ref())
            .map_err(|e| format!("cannot write signing key: {e}"))?;
        // Set file permissions to 0600 (owner read/write only).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            fs::set_permissions(&key_path, perms)
                .map_err(|e| format!("cannot set key permissions: {e}"))?;
        }
        Ok(signer)
    }
}
```

Also add a helper to load/save broker state:
```rust
/// Loads persisted broker state from `$APM2_HOME/private/fac/broker_state.json`.
///
/// Returns None if the file doesn't exist (first run).
fn load_broker_state() -> Option<apm2_core::fac::broker::BrokerState> {
    let fac_root = resolve_fac_root().ok()?;
    let state_path = fac_root.join("broker_state.json");
    if !state_path.exists() {
        return None;
    }
    let bytes = read_bounded(&state_path, 1_048_576).ok()?; // 1MB max
    FacBroker::deserialize_state(&bytes).ok()
}

/// Saves broker state to `$APM2_HOME/private/fac/broker_state.json`.
fn save_broker_state(broker: &FacBroker) -> Result<(), String> {
    let fac_root = resolve_fac_root()?;
    let state_path = fac_root.join("broker_state.json");
    let bytes = broker.serialize_state().map_err(|e| format!("cannot serialize broker state: {e}"))?;
    fs::write(&state_path, bytes).map_err(|e| format!("cannot write broker state: {e}"))
}
```

Then replace line 199 (`let mut broker = FacBroker::new();`) with:
```rust
    // Load persistent signing key and broker state (BLOCKER fix: ephemeral key).
    // This ensures receipts are verifiable across worker restarts and the
    // admission authority derives from persistent state, not ephemeral.
    let persistent_signer = match load_or_generate_persistent_signer() {
        Ok(s) => s,
        Err(e) => {
            output_worker_error(json_output, &format!("cannot load signing key: {e}"));
            return exit_codes::GENERIC_ERROR;
        },
    };

    let mut broker = match load_broker_state() {
        Some(state) => {
            FacBroker::from_signer_and_state(persistent_signer.clone(), state).unwrap_or_else(|_| {
                // State validation failed — create fresh broker with persistent key.
                // This can happen if the state format changed between versions.
                let mut b = FacBroker::new();
                // We need to replace the ephemeral signer. Since FacBroker doesn't
                // expose a set_signer, we recreate via from_signer_and_state with
                // default state.
                FacBroker::from_signer_and_state(persistent_signer.clone(), apm2_core::fac::broker::BrokerState::default())
                    .unwrap_or(b)
            })
        },
        None => {
            // No persisted state — first run. Create broker with persistent key.
            FacBroker::from_signer_and_state(persistent_signer.clone(), apm2_core::fac::broker::BrokerState::default())
                .unwrap_or_else(|_| FacBroker::new())
        },
    };
```

And also use the persistent signer for receipts (replace line 221):
```rust
    let signer = persistent_signer;
```

And at the end of `run_fac_worker` (before the final `exit_codes::SUCCESS`), save broker state:
```rust
    // Persist broker state for subsequent runs.
    let _ = save_broker_state(&broker);
```

### FIX 7: Inconsistent changeset_digest (SECURITY MINOR — line 712)
**Problem**: Uses hash of `job_spec_digest` string as changeset_digest instead of actual commit SHA.
**Fix**: Use the head SHA from the job spec's source block.

Replace line 712:
```rust
    let changeset_digest = compute_evidence_hash(spec.job_spec_digest.as_bytes());
```

With:
```rust
    // Use the head SHA from the job spec source block for the changeset digest
    // to maintain consistency with Orchestrator verification expectations.
    let changeset_digest = compute_evidence_hash(spec.source.head_sha.as_bytes());
```

Note: Check if `spec.source.head_sha` exists. The FacJobSpecV1 should have a `source` field with `head_sha`. If the field name is different, find the correct field name by grepping `FacJobSpecV1` struct definition.

### FIX 8: Redundant I/O (SECURITY NIT — process_job re-reads file)
**Problem**: `scan_pending` already reads+deserializes the spec, but `process_job` reads it again at lines 457-477.
**Fix**: Use the already-deserialized spec from the `PendingCandidate` instead of re-reading.

In `process_job`, replace lines 456-477 (the re-read+re-deserialize block) to use the candidate's existing spec. BUT the spec also needs re-validation (digest check). So keep the byte-level re-read for digest validation, or trust the scan phase.

Actually, for the digest check we need the raw bytes. So the fix is to store the raw bytes in `PendingCandidate`:

1. Add `raw_bytes: Vec<u8>` to `PendingCandidate`
2. In `scan_pending`, save the bytes: `candidates.push(PendingCandidate { path, spec, raw_bytes: bytes })`
3. In `process_job`, use `candidate.raw_bytes` instead of re-reading

## Required imports
You may need to add these imports:
```rust
use apm2_core::fac::broker_health::WorkerHealthPolicy;
```

## QueueSchedulerState fields
Run `rg -n "pub struct QueueSchedulerState" crates/apm2-core/` and then read the struct to find its public fields. The key fields to populate are queue depth/backlog.

## FacJobSpecV1 source field
Run `rg -n "pub struct FacJobSpecV1" crates/apm2-core/ -A 30` to find the correct field name for head SHA.

## Mandatory pre-commit steps (IN ORDER)
1. `cargo fmt --all`
2. `cargo clippy --workspace --all-targets --all-features -- -D warnings` (fix ALL)
3. `cargo doc --workspace --no-deps`
4. `cargo test -p apm2-cli`
You MUST pass ALL CI checks.

## Push protocol
1. `git add -A && git commit -m "TCK-00511: Fix all round-2 review findings for FAC worker"`
2. `apm2 fac gates`
3. `apm2 fac push --ticket documents/work/tickets/TCK-00511.yaml`
