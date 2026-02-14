# Fix Agent: PR 654 / TCK-00511 — Round 2

## Invocation
/implementor-default TCK-00511

## Primary Instruction Source
@documents/skills/implementor-default/SKILL.md is your execution contract. Follow its decision tree.

## Context
- **PR**: #654 (TCK-00511: FAC Worker: queue consumer with RFC-0028 authorization + RFC-0029 admission gating)
- **Branch**: `ticket/RFC-0019/TCK-00511`
- **Worktree**: `/home/ubuntu/Projects/apm2-worktrees/TCK-00511`
- **HEAD SHA**: `4375291c4539b43033a04ad7b4fccbd1849b0d08`
- **Ticket**: `documents/work/tickets/TCK-00511.yaml`
- **Responsibility Domains**: DOMAIN_RUNTIME, DOMAIN_SECURITY (fail-closed mandatory)

## Review Round 2 Findings — ALL MUST BE FIXED

### Security Review: FAIL (SHA: 4375291c)

#### BLOCKER 1: Ephemeral and Unverifiable Authority
- **Location**: `crates/apm2-cli/src/commands/fac_worker.rs:180:run_fac_worker`
- **Threat**: The worker initializes a new `FacBroker` with an ephemeral signing key on every execution. All emitted `GateReceipts` are signed by an ephemeral key, making them cryptographically unverifiable by any other system component.
- **Exploit Path**: Worker fails to verify the job's RFC-0028 token because it has a different ephemeral key than the broker that issued the job.
- **Required Remediation**: Implement broker key persistence. The worker must load a trusted, persistent broker key from a secure store (e.g., the daemon's signing key file at `~/.apm2/signing_key` or equivalent) to ensure continuity and verifiability.
- **NOTE**: The quality review WAIVED "broker key sharing" as an MVP limitation (worker and broker sharing a process/key is accepted). The fix should ensure the SAME persistent key is used (loaded from disk/config) rather than generating a fresh ephemeral key each run.

#### BLOCKER 2: Self-Authorized Admission Gating
- **Location**: `crates/apm2-cli/src/commands/fac_worker.rs:193:run_fac_worker`
- **Threat**: The worker uses its own locally-created, ephemeral `FacBroker` instance to issue the time authority envelope, freshness horizon, and revocation frontier used for its own RFC-0029 admission evaluation. A malicious worker can advance its own horizon to force "Allow" on any job.
- **Required Remediation**: The worker must obtain authoritative admission artifacts from a trusted system-wide authority (e.g., the daemon via IPC, or a persistent global broker state file) rather than issuing them from its own ephemeral state. For MVP: load broker state from the daemon's persistent artifacts so the time authority is externally verifiable.

#### MAJOR 1: Non-Monotonic Wall-Clock Time
- **Location**: `crates/apm2-cli/src/commands/fac_worker.rs:460:process_job`
- **Threat**: Worker uses `SystemTime::now()` for RFC-0028 token verification (`issued_at` check). Clock rollback can re-authorize expired tokens.
- **Required Remediation**: Use the broker's HTF `current_tick()` or a monotonic clock source for all security-critical temporal checks. Reference: INV-F-08, CTR-2501.

#### MAJOR 2: TOCTOU in read_bounded
- **Location**: `crates/apm2-cli/src/commands/fac_worker.rs:1001:read_bounded`
- **Threat**: `read_bounded` performs `fs::metadata(path)` before `File::open(path)`. An attacker can replace the file with a symlink between the metadata() check and the open() call.
- **Required Remediation**: Open the file FIRST using `File::open`, then call `file.metadata()` on the resulting file handle to verify size before reading. Reference: RSK-1501, CTR-1603.

#### MAJOR 3: Missing PCAC Lifecycle
- **Location**: `crates/apm2-cli/src/commands/fac_worker.rs:400:process_job`
- **Threat**: Worker performs authority-bearing actions (claiming jobs, emitting GateReceipts) without the mandatory 4-step PCAC lifecycle (join → revalidate → consume → effect).
- **Required Remediation**: Implement the full PCAC lifecycle for the worker's execution using `PrivilegedPcacInputBuilder` and canonical lifecycle gate calls before performing the job claim and receipt emission. Reference: RFC-0027, LAW-01.

#### MINOR: Inconsistent changeset_digest
- **Location**: `crates/apm2-cli/src/commands/fac_worker.rs:610:process_job`
- **Issue**: Worker uses a hash of the `job_spec_digest` string as the `changeset_digest` in the emitted receipt.
- **Required Remediation**: Use the actual commit SHA (`source.head_sha`) or the canonical changeset digest from the job spec.

#### NIT: Redundant I/O and deserialization
- **Location**: `crates/apm2-cli/src/commands/fac_worker.rs:410:process_job`
- **Issue**: `scan_pending` already reads and deserializes the spec; `process_job` repeats this.
- **Remediation**: Pass the already-deserialized `FacJobSpecV1` from scan to processing.

### Code Quality Review: FAIL (SHA: 4375291c)

#### MAJOR 1: Empty QueueSchedulerState bypasses admission capacity
- **Location**: `crates/apm2-cli/src/commands/fac_worker.rs:660`
- **Issue**: `QueueSchedulerState::new()` creates an empty scheduler state for every job, rendering backpressure and anti-starvation logic ineffective (zero backlog, zero total items).
- **Required Remediation**: Populate `QueueSchedulerState` with actual queue metrics from `scan_pending` (e.g., count of pending jobs, total items) before evaluating admission.

#### MAJOR 2: IO Thrashing on Lane Saturation
- **Location**: `crates/apm2-cli/src/commands/fac_worker.rs:260`
- **Issue**: When all lanes are locked, the worker loop continues processing candidates. Each candidate is renamed pending→claimed, fails to acquire a lane, and renamed back claimed→pending. This causes 2*N filesystem renames per cycle with zero progress.
- **Required Remediation**: Break the candidate processing loop immediately when a job is skipped due to lane exhaustion (all lanes busy).

#### MAJOR 3: Missing Worker Health Gate
- **Location**: `crates/apm2-cli/src/commands/fac_worker.rs:446`
- **Issue**: Worker evaluates RFC-0028 tokens and RFC-0029 economics but fails to check broker health (INV-BH-003). Jobs may be admitted when broker is Failed/Degraded.
- **Required Remediation**: Call `broker.evaluate_admission_health_gate()` (or equivalent) in the validation pipeline before queue admission.

#### WAIVED (no fix needed)
- **Broker Key Sharing**: The worker and broker sharing a process/key is a documented MVP limitation and accepted for this stage.

## Mandatory Pre-Commit Steps (IN ORDER)
You MUST pass ALL CI checks. Run these in order before committing:
1. `cargo fmt --all` (actually format — not just --check)
2. `cargo clippy --workspace --all-targets --all-features -- -D warnings` (fix ALL warnings)
3. `cargo doc --workspace --no-deps` (fix any doc warnings/errors)
4. `cargo test -p apm2-cli` (run relevant tests)

## Push Protocol
After committing all changes:
1. Run `apm2 fac gates` (full gates, clean tree required)
2. Run `apm2 fac push --ticket documents/work/tickets/TCK-00511.yaml`

## Critical Patterns to Follow
- Transactional state mutations: check admission BEFORE mutating state
- Fail-closed semantics: never default to pass on missing/unknown state
- HTF timestamps: never SystemTime::now() in security-critical event paths
- Wire production paths: no dead code / unused methods
- Atomic event emission: per-invocation Vec, no shared buffers
- Deterministic SQL ordering: rowid tiebreaker
- Binding test evidence: no zero-count assertions
- Every in-memory collection must have hard MAX_* bounds
- Open-then-metadata pattern for all file reads (no TOCTOU)
