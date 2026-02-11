<<<<<<< HEAD
# Fix Task: PR #597 (TCK-00466) — Round 2: Security Review Findings

Branch: `ticket/RFC-0028/TCK-00466`, worktree: `/home/ubuntu/Projects/apm2-TCK-00466`
HEAD: `e4bdc53b`
=======
# Fix Task: PR #598 (TCK-00467) — Round 2: Security + Quality Review Findings

Branch: `ticket/RFC-0028/TCK-00467`, worktree: `/home/ubuntu/Projects/apm2-TCK-00467`
HEAD: `f0060a4f`
>>>>>>> origin/main

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

<<<<<<< HEAD
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
=======
After all checks pass: `git add -A && git commit -m "fix(TCK-00467): fail-closed disclosure evidence, authority-bound snapshot issuer" && git push`

---

## Fix 1 (BLOCKER): Remove fail-open on missing disclosure evidence for Tier2+

**Both security and quality reviews flagged this independently.**

**Files:**
- `crates/apm2-daemon/src/protocol/session_dispatch.rs:2494, 2534, 2539`

**Problem:** When `required_for_effect == true` (Tier2+ authoritative effects), the code:
1. Defaults `disclosure_channel_class` to `Internal` when missing — untrusted requester omits the field and bypasses policy checks
2. Synthesizes a disclosure policy snapshot (`synthesize_disclosure_policy_snapshot`) when not supplied — auto-generating evidence defeats external evidence requirement
3. Falls back to `snapshot.policy_digest` when `authoritative_policy_root_digest` is absent — accepting caller-controlled digest as admitted policy

**Required fix (3 parts):**

### Part A: Remove implicit Internal default for required_for_effect

When `required_for_effect == true`, deny on missing `disclosure_channel_class`:

```rust
let disclosure_channel_class = if required_for_effect {
    boundary_flow.disclosure_channel_class
        .ok_or_else(|| /* emit structured defect + deny */)?
} else {
    boundary_flow.disclosure_channel_class
        .unwrap_or(DisclosureChannelClass::Internal)
};
```

### Part B: Remove snapshot synthesis fallback for required_for_effect

When `required_for_effect == true`, deny on missing disclosure snapshot:

```rust
let disclosure_snapshot = if required_for_effect {
    boundary_flow.disclosure_policy_snapshot
        .ok_or_else(|| /* emit structured defect + deny */)?
} else {
    boundary_flow.disclosure_policy_snapshot
        .unwrap_or_else(|| synthesize_disclosure_policy_snapshot(/* ... */))
};
```

### Part C: Remove `unwrap_or(snapshot.policy_digest)` fallback for admitted digest

When `required_for_effect == true`, deny on missing authoritative policy root:

```rust
let admitted_policy_digest = if required_for_effect {
    authoritative_policy_root_digest
        .ok_or_else(|| /* emit structured defect + deny */)?
} else {
    authoritative_policy_root_digest
        .unwrap_or(snapshot.policy_digest)
};
```

### Regression tests (CRITICAL)

Add these tests:
1. **Missing channel class + required_for_effect → DENY** (not default to Internal)
2. **Missing snapshot + required_for_effect → DENY** (not synthesized)
3. **Missing authoritative digest + required_for_effect → DENY** (not caller-controlled)
4. **All present + required_for_effect → PASS** (happy path)
5. **Non-required: missing fields → use defaults** (existing behavior preserved)

---

## Fix 2 (MAJOR): Bind snapshot issuer to trusted authority key set

**Both security and quality reviews flagged this independently.**

**Files:**
- `crates/apm2-core/src/disclosure.rs:128, 261`
- `crates/apm2-daemon/src/protocol/session_dispatch.rs:2548`

**Problem:** `validate_disclosure_policy` reads the verifying key from the snapshot itself (`snapshot.issuer_verifying_key`) and verifies the signature against it. Any actor can generate a keypair, sign arbitrary disclosure state, and pass validation. The signature is correct but the issuer is not authorized.

**Required fix:**

### Part A: Accept trusted issuer key as parameter

Change `validate_disclosure_policy` to accept a trusted issuer verifying key from the caller (from authoritative policy state), NOT from the snapshot itself:

```rust
pub fn validate_disclosure_policy(
    snapshot: &DisclosurePolicySnapshot,
    trusted_issuer_key: &[u8; 32],  // From daemon signing identity or PCAC authority
    current_phase_id: &str,
    current_time_ns: u64,
) -> Result<(), DisclosurePolicyError> {
    // Verify signature against TRUSTED key, not snapshot's self-declared key
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(trusted_issuer_key)
        .map_err(|_| DisclosurePolicyError::InvalidIssuerKey)?;
    // ... verify canonical bytes against this key
}
```

### Part B: Wire trusted key from daemon identity

In session_dispatch.rs where `validate_disclosure_policy` is called, pass the daemon's own verifying key (or the PCAC authority key) as the trusted issuer:

```rust
let trusted_key = self.verifying_key().to_bytes();
validate_disclosure_policy(&snapshot, &trusted_key, phase_id, current_time_ns)?;
```

### Part C: Add negative test for unauthorized issuer

```rust
#[test]
fn test_unauthorized_issuer_snapshot_denied() {
    let rogue_signing = ed25519_dalek::SigningKey::generate(&mut OsRng);
    let rogue_snapshot = /* sign snapshot with rogue key */;
    let trusted_key = /* daemon's actual verifying key */;
    let result = validate_disclosure_policy(&rogue_snapshot, &trusted_key, phase_id, now);
    assert!(result.is_err(), "unauthorized issuer must be denied");
}
```
>>>>>>> origin/main

---

## CRITICAL: Pre-commit checklist

After ALL fixes:
1. `cargo fmt --all`
2. `cargo clippy --workspace --all-targets --all-features -- -D warnings` — fix ALL warnings
3. `cargo doc --workspace --no-deps`
4. `cargo test -p apm2-core`
5. `cargo test -p apm2-daemon` — ALL daemon tests must pass (timeout 260s)
<<<<<<< HEAD
6. `git add -A && git commit -m "fix(TCK-00466): durable receipt retrieval for verifier concordance, length-framed subject_effect_id" && git push`
=======
6. `git add -A && git commit -m "fix(TCK-00467): fail-closed disclosure evidence, authority-bound snapshot issuer" && git push`
>>>>>>> origin/main
