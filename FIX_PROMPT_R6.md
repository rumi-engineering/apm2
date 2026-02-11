# Fix Task: PR #593 (TCK-00468) — Round 7

Branch: `ticket/RFC-0028/TCK-00468`, HEAD: `14d0614f`
Quality: PASS. Security: FAIL — 1 BLOCKER, 1 MAJOR.

## REQUIRED READING (before editing any code)

Read these files first:
- `documents/theory/glossary/glossary.json`
- `documents/security/AGENTS.cac.json`
- `documents/security/THREAT_MODEL.cac.json`
- `documents/skills/rust-standards/references/15_errors_panics_diagnostics.md`
- `documents/skills/rust-standards/references/34_security_adjacent_rust.md`
- `documents/skills/rust-standards/references/41_apm2_safe_patterns_and_anti_patterns.md`

## BLOCKER 1: Shell-chain bypass via background operator `&`

**Paths:**
- `crates/apm2-daemon/src/protocol/session_dispatch.rs:2323`
- `crates/apm2-daemon/src/protocol/session_dispatch.rs:2348`
- `crates/apm2-daemon/src/protocol/session_dispatch.rs:2372`
- `crates/apm2-daemon/src/protocol/session_dispatch.rs:2827`

**Problem:** The command parser only segments on `;`, newline, `&&`, and `||`/pipe. It does NOT handle the single `&` (background operator). A command like `true & gh api /repos/owner/repo` is split only at recognized delimiters, so `gh` in the backgrounded segment is never detected.

**Exploit:** `true & gh api /repos/owner/repo` — the `& gh api` part is not recognized as a gh invocation. Also: subshell forms like `(gh api /repos/owner/repo)` and control-flow forms where the first token is not the invoked binary.

**Required Fix:**
1. Add `&` (single ampersand, NOT `&&`) as a command separator in `split_command_chain` or equivalent parser function. This is a shell syntax variant that separates commands just like `;` — the preceding command runs in the background.
2. Also handle `(` and `)` (subshell forms): when a segment starts with `(`, strip the parens and analyze the inner command.
3. Ensure ALL recognized shell separators are covered: `;`, `&&`, `||`, `|`, `&`, newline, `(...)`, and backtick substitution.
4. Add regression tests for:
   - `true & gh api /repos/owner/repo` → DENY
   - `(gh api /repos/owner/repo)` → DENY
   - `cmd & curl https://api.github.com/repos/o/r` → DENY
   - Existing tests still pass (no false positives)

## MAJOR 1: Projection receipt linkage is structural-only

**Paths:**
- `crates/apm2-daemon/src/projection/worker.rs:176`, `:196`
- `crates/apm2-daemon/src/projection/worker.rs:1770`, `:1860`

**Problem:** `validate_projection_receipt_linkage` checks field presence/shape (hex length, non-zero) but doesn't verify that linkage hashes resolve to authoritative state.

**Required Fix:**
1. For each linkage hash (`artifact_bundle_hash`, `capability_manifest_hash`, `context_pack_hash`, `role_spec_hash`, `identity_proof_hash`), add a resolution step that verifies the hash exists in the appropriate authoritative store (CAS, ledger, or manifest store).
2. Verify lineage consistency: `work_id`, `lease_id`, `receipt_id` in the receipt must match the current projection context.
3. On any missing or mismatched hash: DENY the projection with a structured error.
4. Add test: forged linkage hash → DENY with specific error. Valid linkage → PASS.

## CRITICAL PATTERNS

- **Fail-closed semantics**: When in doubt about command intent, DENY. Better false positive than false negative.
- **Binding test evidence**: Tests must assert specific deny reasons and defect evidence.
- **Wire production paths**: Every new detection branch must be exercised by a test.

## Pre-Commit Steps (MANDATORY — do ALL of these)
```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo doc --workspace --no-deps
cargo test -p apm2-core -p apm2-daemon
```

You MUST pass ALL CI checks. Do NOT skip any step.

## Push
```bash
git add -A && git commit -m "fix(TCK-00468): background-operator bypass, subshell detection, authoritative receipt linkage" && apm2 fac push --ticket documents/work/tickets/TCK-00468.yaml
```
