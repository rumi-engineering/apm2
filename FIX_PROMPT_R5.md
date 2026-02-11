# Fix Task: PR #593 (TCK-00468) — Round 6

Branch: `ticket/RFC-0028/TCK-00468`, HEAD: `7231e1d8`
Quality: FAIL — 1 MAJOR. Security: FAIL — 1 BLOCKER.

## REQUIRED READING (before editing any code)

Read these files first to understand the project context:
- `documents/theory/glossary/glossary.json`
- `documents/security/AGENTS.cac.json`
- `documents/security/THREAT_MODEL.cac.json`
- `documents/skills/rust-standards/references/15_errors_panics_diagnostics.md`
- `documents/skills/rust-standards/references/34_security_adjacent_rust.md`
- `documents/skills/rust-standards/references/41_apm2_safe_patterns_and_anti_patterns.md`

## BLOCKER 1 (Security): REQ-0008 bypass via shell/API indirection gaps

**Three distinct exploit vectors remain. ALL must be fixed:**

### Vector A: Shell variable propagation across command segments
**Path:** `crates/apm2-daemon/src/protocol/session_dispatch.rs:2802`, `:2862`
**Exploit:** `url=https://api.github.com/repos/owner/repo; curl "$url"` — variable assignment in one segment, use in another. `command_targets_github_api_inner` only inspects literal arguments.
**Fix:** Track variable assignments across command segments. When a variable is assigned a value containing `api.github.com` (or GitHub API host patterns), and later that variable is referenced (`$var`, `"$var"`, `${var}`), classify the command as `github_api`. Alternatively: deny ANY command that assigns a variable containing a GitHub API host AND later uses that variable in a network-capable command (curl, wget, etc.).

### Vector B: Backtick command substitution not modeled
**Path:** `crates/apm2-daemon/src/protocol/session_dispatch.rs:2653`
**Exploit:** `` cmd=`echo gh`; $cmd api /repos `` — `command_substitution_contains_gh_reference` only handles `$()` but NOT backtick substitution.
**Fix:** Extend `command_substitution_contains_gh_reference` to also detect backtick substitution patterns (`` `...` ``). Parse for backtick-delimited regions and apply the same `gh` reference detection as `$()`.

### Vector C: Trailing-dot FQDN bypass
**Path:** `crates/apm2-daemon/src/protocol/session_dispatch.rs:2754`, `:2898`
**Exploit:** `https://api.github.com./repos/...` — trailing dot is valid DNS but `host_targets_github_api` does exact string match.
**Fix:** Canonicalize hostnames before comparison: strip trailing dot, lowercase, then compare. Apply this normalization in `host_targets_github_api` and in `command_targets_github_api_inner` for URL-based detection.

## MAJOR 1 (Quality): Shell-variable indirection not covered in `command_targets_github_api_inner`
**Path:** `crates/apm2-daemon/src/protocol/session_dispatch.rs:2802`
**Same as Security Vector A above.** The quality reviewer independently flagged the same gap.

## Regression Tests Required (for EACH vector)

1. **Variable propagation test**: `url=https://api.github.com/repos/example/repo; curl "$url"` → DENY with `SessionErrorToolNotAllowed` + projection-isolation defect evidence
2. **Backtick substitution test**: `` cmd=`echo gh`; $cmd api /repos `` → DENY
3. **Trailing-dot FQDN test**: `curl https://api.github.com./repos/owner/repo` → DENY
4. **No false positive test**: `echo "the URL api.github.com is documented here"` → ALLOW (echo is not network-capable)
5. **Existing tests**: All existing projection-isolation tests must continue to pass

## CRITICAL PATTERNS

- **Fail-closed semantics**: When in doubt about whether a command targets GitHub, DENY. False positives are better than false negatives for security.
- **Binding test evidence**: Tests must assert specific deny reasons and defect evidence emission, not just "deny happened".
- **Wire production paths**: Every detection function must be exercised by at least one test.

## Pre-Commit Steps (MANDATORY — do ALL of these)
```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo doc --workspace --no-deps
cargo test -p apm2-core -p apm2-daemon
```

You MUST pass ALL CI checks. Do NOT skip any pre-commit step.

## Push
```bash
git add -A && git commit -m "fix(TCK-00468): close variable-indirection, backtick, and trailing-dot bypass vectors" && apm2 fac push --ticket documents/work/tickets/TCK-00468.yaml
```
