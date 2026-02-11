# Fix Task: PR #597 (TCK-00466) — Round 2: Security Review Findings

Branch: `ticket/RFC-0028/TCK-00466`, worktree: `/home/ubuntu/Projects/apm2-TCK-00466`
HEAD: `e4bdc53b`

## REQUIRED READING (read ALL before editing any code)

- `documents/security/AGENTS.cac.json`
- `documents/security/THREAT_MODEL.cac.json`
- `documents/skills/rust-standards/references/34_security_adjacent_rust.md`
- `documents/skills/rust-standards/references/39_hazard_catalog_checklists.md`
- `documents/skills/rust-standards/references/41_apm2_safe_patterns_and_anti_patterns.md`

You MUST pass ALL CI checks. Before committing, run IN ORDER:
1. `cargo fmt --all`
2. `cargo clippy --workspace --all-targets --all-features -- -D warnings` — fix ALL warnings
3. `cargo doc --workspace --no-deps` — fix any doc warnings
4. `cargo test -p apm2-core` — core tests
5. `cargo test -p apm2-daemon` — daemon tests (timeout 260s)

After all checks pass: `git add -A && git commit -m "fix(TCK-00466): durable receipt retrieval for verifier concordance, length-framed subject_effect_id" && git push`

---

## Fix 1 (MAJOR): Build verifier inputs from durable retrieval, not in-memory clones

**File:** `crates/apm2-daemon/src/protocol/session_dispatch.rs` (around line 3073, 3165)
**File:** `crates/apm2-core/src/evidence/acceptance_package.rs` (around line 358)

**Problem:** `emit_portable_acceptance_package` populates both CAS and Ledger receipt providers from in-memory payload bytes (`payload.clone()` / returned event payload) and immediately verifies those maps. The `ReceiptProvider` falls back to digest lookup even when pointer locators are present, masking locator resolution failures. This means local reverification passes even when durable receipt pointers are not actually replay-resolvable by independent counterparties.

**Required fix (3 parts):**

### Part A: Read-back verification from durable storage

After persisting receipts to CAS/ledger, build verifier inputs by reading back from the durable store, not from the in-memory write buffer:

For each `ReceiptPointer` in the acceptance package:
1. If `cas_address` is `Some`, retrieve from CAS via that address
2. If `ledger_event_id` is `Some`, retrieve from ledger via that event ID
3. Verify the retrieved content matches the `receipt_digest`
4. Fail closed if retrieval fails or digest mismatches

### Part B: Remove or gate digest-only fallback

When a `ReceiptPointer` has a `cas_address` or `ledger_event_id` locator field, the verifier MUST use that locator to retrieve the receipt. Only fall back to digest-based lookup when NO locator is present. If a locator is present but retrieval fails, that is an error (fail closed), not a fallback to digest.

```rust
// In ReceiptProvider implementations:
fn resolve_receipt(&self, pointer: &ReceiptPointer) -> Result<Vec<u8>, ReceiptResolutionError> {
    // If locator present, MUST resolve via locator
    if let Some(ref cas_addr) = pointer.cas_address {
        let content = self.cas.retrieve(cas_addr)
            .ok_or(ReceiptResolutionError::LocatorNotFound {
                locator: cas_addr.clone()
            })?;
        // Verify digest matches
        let actual_digest = blake3::hash(&content);
        if actual_digest.as_bytes() != &pointer.receipt_digest {
            return Err(ReceiptResolutionError::DigestMismatch);
        }
        return Ok(content);
    }
    // Only fall back to digest when no locator present
    self.digest_map.get(&pointer.receipt_digest)
        .cloned()
        .ok_or(ReceiptResolutionError::NotFound)
}
```

### Part C: Add regression tests

Add tests verifying:
1. **Locator-present but retrieval fails → deny** (not fallback to digest)
2. **Locator-present, retrieval succeeds but digest mismatches → deny**
3. **No locator, digest-only lookup succeeds → pass**
4. **Read-back from durable store produces same verification result as write-buffer** (concordance with real CAS/ledger)

---

## Fix 2 (MINOR): Length-framed subject_effect_id hashing

**File:** `crates/apm2-daemon/src/protocol/session_dispatch.rs` (around line 3135)

**Problem:** `subject_effect_id` is computed by concatenating variable-length fields (`session_id || lease_id || request_id || tool_class || effect_digest`) without length prefixes. This allows tuple-collision constructions if component formats change.

**Required fix:** Add explicit length framing:

```rust
// Length-prefix each field before hashing
let mut hasher = blake3::Hasher::new();
for field in &[
    session_id.as_bytes(),
    lease_id.as_bytes(),
    request_id.as_bytes(),
    tool_class.as_bytes(),
    &effect_digest,
] {
    let len = (field.len() as u32).to_be_bytes();
    hasher.update(&len);
    hasher.update(field);
}
let subject_effect_id = *hasher.finalize().as_bytes();
```

Add a test verifying that swapping parts of adjacent field values produces a different `subject_effect_id`.

---

## CRITICAL: Pre-commit checklist

After ALL fixes:
1. `cargo fmt --all`
2. `cargo clippy --workspace --all-targets --all-features -- -D warnings` — fix ALL warnings
3. `cargo doc --workspace --no-deps`
4. `cargo test -p apm2-core`
5. `cargo test -p apm2-daemon` — ALL daemon tests must pass (timeout 260s)
6. `git add -A && git commit -m "fix(TCK-00466): durable receipt retrieval for verifier concordance, length-framed subject_effect_id" && git push`
