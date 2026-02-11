# Fix Task: PR #598 (TCK-00467) — Round 2: Security + Quality Review Findings

Branch: `ticket/RFC-0028/TCK-00467`, worktree: `/home/ubuntu/Projects/apm2-TCK-00467`
HEAD: `f0060a4f`

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

---

## CRITICAL: Pre-commit checklist

After ALL fixes:
1. `cargo fmt --all`
2. `cargo clippy --workspace --all-targets --all-features -- -D warnings` — fix ALL warnings
3. `cargo doc --workspace --no-deps`
4. `cargo test -p apm2-core`
5. `cargo test -p apm2-daemon` — ALL daemon tests must pass (timeout 260s)
6. `git add -A && git commit -m "fix(TCK-00467): fail-closed disclosure evidence, authority-bound snapshot issuer" && git push`
