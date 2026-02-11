# Fix Task: PR #593 (TCK-00468) — Review Round 2

## Context
You are fixing security review findings for PR #593 (TCK-00468: RFC-0028 REQ-0008 projection isolation and direct-GitHub authority elimination).

Branch: `ticket/RFC-0028/TCK-00468`
Worktree: `/home/ubuntu/Projects/apm2-TCK-00468`
Current HEAD: `657239d8`

## Review Results
- **Quality Review: PASS** — no action needed
- **Security Review: FAIL** — 2 MAJOR, 1 MINOR

## MAJOR 1: Panic-on-input in deny path (UTF-8 byte slicing)

**Path:** `crates/apm2-daemon/src/protocol/session_dispatch.rs` — `truncate_attempt_detail` function

**Problem:** `truncate_attempt_detail` slices UTF-8 strings by byte index (`&detail[..truncated_len]`). A crafted long non-ASCII command/URL (e.g., direct `gh` attempt with multibyte payload) can trigger a non-char-boundary slice panic before deny response/defect emission.

**Required Fix:**
1. Replace byte slicing with char-boundary-safe truncation
2. Use `char_indices` to find the last valid char boundary before the truncation point
3. Example: `detail.char_indices().take_while(|(i, _)| *i < max_len).last().map(|(i, c)| &detail[..i + c.len_utf8()]).unwrap_or("")`
4. Add tests covering multibyte Unicode command/URL truncation on direct GitHub deny paths

## MAJOR 2: Direct GitHub deny logic bypassable via shell/program indirection

**Path:** `crates/apm2-daemon/src/protocol/session_dispatch.rs` — `command_invokes_gh_cli_inner` and `command_targets_github_api`

**Problem:** Command-text heuristics use `split_whitespace` and literal host substring checks. Commands using shell substitution/indirection or interpreter-mediated invocation can bypass these heuristics.

**Required Fix:**
1. **Keep the existing command-text detection as a defense-in-depth layer** (do NOT remove it)
2. Add adversarial tests for substitution/interpreter indirection patterns:
   - `bash -c "$(echo gh) api /repos"` (command substitution)
   - `eval "gh api /repos"` (eval indirection)
   - Shell variable expansion: `cmd=gh; $cmd api /repos`
3. Acknowledge in code comments that command-text detection is a heuristic layer — primary security boundary is RoleSpec capability rejection at the capability/egress boundary
4. Consider adding an additional check: scan all argument strings (not just the primary command) for GitHub API hostnames

## MINOR: Freshness evidence can be omitted while stage remains permissive

**Path:** `crates/apm2-daemon/src/protocol/session_dispatch.rs`

**Problem:** Stage evaluation treats `refreshed_at_ns` as optional. When unset, Stage0/Stage1 can remain active without freshness enforcement.

**Required Fix:**
1. For production stages (Stage0/Stage1), require freshness timestamp
2. If `refreshed_at_ns` is missing in production, fail closed to Stage2 (hard deny)
3. Add test: missing freshness → Stage2

## MANDATORY Pre-Commit Steps (in this exact order)

You MUST run ALL of these and fix any issues BEFORE committing:
```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo doc --workspace --no-deps
cargo test -p apm2-core -p apm2-daemon
```

You MUST pass ALL CI checks. Do not push code that fails any of these.

## Push Workflow

After all pre-commit steps pass:
```bash
git add -A
git commit -m "fix(TCK-00468): char-safe truncation, freshness enforcement, adversarial bypass tests"
apm2 fac push --ticket documents/work/tickets/TCK-00468.yaml
```
