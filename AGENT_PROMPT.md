# Implementation Task: TCK-00465 — RFC-0028 REQ-0004 Boundary-Flow Integrity and Declassification Receipt Enforcement

## REQUIRED READING (read these files BEFORE writing any code)

Read these files in order:
1. `documents/theory/glossary/glossary.json` — APM2 terminology
2. `documents/rfcs/RFC-0028/00_meta.yaml` — RFC meta
3. `documents/rfcs/RFC-0028/HOLONIC_EXTERNAL_IO_SECURITY.md` — Full RFC draft (especially Sections 5-6 on boundary flow)
4. `documents/rfcs/RFC-0028/requirements/REQ-0004.yaml` — This ticket's requirement
5. `documents/work/tickets/TCK-00465.yaml` — Ticket details
6. `documents/work/tickets/TCK-00462.yaml` — Predecessor ticket (already merged, provides lifecycle receipt typing baseline)
7. `documents/reviews/CI_EXPECTATIONS.md` — CI contract
8. `documents/security/AGENTS.cac.json` — Security posture
9. `documents/security/THREAT_MODEL.cac.json` — Threat model
10. `crates/apm2-daemon/AGENTS.md` — Daemon architecture
11. `crates/apm2-core/AGENTS.md` — Core crate architecture

## Ticket Summary

**TCK-00465**: Implement strict `boundary_admit` predicate checks (capability, taint, classification, declassification receipt validity). Enforce REDUNDANCY_PURPOSE declassification constraints and explicit deny for unknown/unscoped intents. Add typed leakage-budget receipts (`leakage_bits`, estimator family, confidence metadata). Emit structured defects and quarantine paths for leakage or timing-channel budget violations.

## Requirement (REQ-0004)

Boundary interactions MUST preserve context integrity and dual-lattice taint/confidentiality semantics end-to-end. Confidentiality downgrade MUST require explicit declassification policy and receipt emission.

### Acceptance Criteria
- Out-of-pack or TOCTOU-violating context access denies.
- Tier3+ actuators reject untrusted or over-confidential inputs by policy.
- No boundary downgrade occurs without declassification receipt.

## Implementation Plan

1. Bind boundary-flow policy digest and canonicalizer tuple checks to gate decisions.
2. Add declassification receipt validation and denial paths for plaintext semantics leakage.
3. Implement timing-channel release-bucketing checks and quarantine behavior.
4. Add adversarial integration tests for boundary downgrade and leakage overrun.

## Key RFC-0028 Invariants

- `boundary_flow_admissible` predicate must be satisfied for all external flows
- Dual-lattice: taint floor (max = most restrictive) and confidentiality ceiling (min = most restrictive)
- Declassification requires: valid policy binding, explicit receipt, redundancy-purpose constraints
- Unknown/unscoped intents → explicit deny (fail-closed)
- Leakage budget: `leakage_bits` tracked per channel with estimator family and confidence
- Timing-channel violations → quarantine affected channel
- `INV-SIO28-08`: disclosure-control policy constraints are non-regressible hard constraints

## Existing Code Context

Look at the already-merged TCK-00462 work for the baseline:
- `git log --oneline | grep TCK-00462` to find relevant commits
- The lifecycle intent typing baseline is already in place
- Build ON TOP of that, don't duplicate

Key crates to work in:
- `crates/apm2-core/src/fac/` — boundary flow, declassification, taint/confidentiality lattice
- `crates/apm2-core/src/fac/context_firewall.rs` — context integrity checks
- `crates/apm2-daemon/src/protocol/` — boundary admission in dispatcher paths

## Common Review Findings — MUST AVOID

1. **Missing Production Wiring**: Every `with_X()` builder method MUST be called in ALL production constructor paths in `state.rs` and `main.rs`.
2. **Fail-Open Authorization**: All ambiguous/error states MUST resolve to DENY/FAILURE (fail-closed). Never default to pass.
3. **Unbounded Resources**: Every collection MUST have a hard `MAX_*` constant with deterministic eviction.
4. **Missing Integration Tests**: Tests MUST exercise real production wiring paths, not manual dependency injection.
5. **Serde Default on Security Fields**: Never use `#[serde(default)]` on security-critical enum fields where default is least restrictive.
6. **Missing Caller Authorization**: Every IPC handler MUST bind caller identity to resource authorization.
7. **Proto Workflow**: NEVER edit `apm2.daemon.v1.rs` directly. Edit `.proto`, run `cargo build -p apm2-daemon`, commit both.

## Daemon Implementation Patterns — MUST FOLLOW

- DispatcherState is the production composition root. Every `with_X()` method MUST be called in the DispatcherState builder chain.
- SqliteLeaseValidator MUST override every method production code depends on.
- SQL queries: Always filter by event_type first, use indexed fields, `ORDER BY rowid DESC LIMIT 1`.
- Caller authorization: Every handler must bind caller identity from `ctx.peer_credentials()`.
- Tests: Must use DispatcherState composition, not manual injection. Side-effect assertions mandatory.

## Branch Hygiene — FIRST STEPS

Before making ANY code changes:
```bash
git fetch origin main
git rebase origin/main
git diff --name-only --diff-filter=U  # Must be empty (no conflicts)
```
If conflicts exist, resolve them ALL before writing code.

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
git commit -m "feat(TCK-00465): boundary-flow integrity and declassification receipt enforcement"
apm2 fac push --ticket documents/work/tickets/TCK-00465.yaml
```

This pushes, creates/updates the PR, enables auto-merge, and triggers reviews automatically.

## Evidence Required

Your implementation MUST produce:
- Boundary downgrade denial without declassification receipt (test evidence)
- Timing-channel budget violation quarantine (test evidence)
- Dual-lattice propagation correctness (unit tests)
- Leakage-budget receipt typed artifacts with estimator metadata
- Adversarial integration tests for overrun and downgrade paths
