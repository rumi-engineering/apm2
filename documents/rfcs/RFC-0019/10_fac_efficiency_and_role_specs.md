# RFC-0019 Addendum — FAC operational milestones, role tool-call map, and efficiency roadmap

This file is an implementation-facing companion to RFC-0019. It is intentionally pragmatic:
it describes (1) when FAC is usable, (2) what each role actually does in terms of kernel tools and
CAS/ledger interactions, and (3) the post-v0 efficiency workstream aligned to holonic boundary discipline.

## 1) When can we start using automated FAC?

There are three practical thresholds:

### Threshold A — “FAC review + projection works end-to-end”
**After TCK-00324 (xtask cutover stage 1)** you can run:
- PR ingestion → reviewer episode → ReviewReceiptRecorded → projection worker → GitHub status/comment

This is usable for *automated review* even if implementer loops are still manual.

### Threshold B — “FAC works with real-world CLIs under adapter profiles”
**After TCK-00330 (adapter conformance tests + ledger attribution)** you can run review episodes using:
- `claude-code`, `gemini-cli`, `codex-cli`, and `local-inference` profiles
- kernel-side tool execution remains authoritative; agent output is untrusted hints

This is the minimum viable “heterogeneous agent runtime” milestone.

### Threshold C — “Closed-loop autonomy through repeated revisions”
**After TCK-00332 (orchestration loop 1..100 revision cycles)** you can run:
- implementer + reviewer cycles in a closed loop until PASS/BLOCKED/BUDGET_EXHAUSTED

This is the milestone that validates “autonomous factory” rather than “autonomous reviewer”.

## 2) Ticket DAG (post-threshold B)

Notation: A -> B means B depends on A.

P0 / P1 efficiency (first investment area):
- TCK-00331 (Tool-call matrix + RoleSpecV1 + instruction conformance)
  -> TCK-00332 (Orchestrator revision loop 1..100 cycles)
      -> TCK-00333 (FAC productivity CLI/scripts)
      -> TCK-00334 (Horizontal specialization: more roles + context slicing)
      -> TCK-00335 (Caching + context deltas + summary-first iteration economics)

P1 refactors (after loop stability):
- TCK-00336 (Remove legacy allow/bypass paths; no unsafe-by-default handlers)
  -> TCK-00337 (Remove dead/unused protocols/modules; keep xtask for now)

P2 security hardening (after throughput is proven):
- TCK-00338 (Broker hardening: allowlists, timeouts, env/pwd controls)
  -> TCK-00339 (Prompt-injection hardening: evidence taint tracking + policies)
  -> TCK-00340 (Multi-holon policy inheritance + attestation tightening)

## 3) Role tool-call map (what actually happens)

This section enumerates the kernel-side tools and how they interact with CAS + ledger.

### Shared invariants (all roles)
Every tool call MUST follow:
1. Agent emits a tool request (ToolIntent or structured request event).
2. Kernel evaluates policy + capability manifest (ToolDecided).
3. Kernel executes tool (ToolExecuted) and stores outputs in CAS.
4. Kernel returns a bounded ToolResult envelope referencing CAS hashes.
5. Receipts index tool activity (ToolExecutionReceipt + ToolLogIndexV1).

### Orchestrator
**Primary job:** allocate work, enforce budgets/stop conditions, drive iterations.

Typical kernel operations:
- ArtifactFetch: pull ChangeSetBundleV1, prior receipts, ContextPack selectors
- PublishEvidence: store ContextPacks, plans, and summaries in CAS
- EmitEvent: record WorkTransitioned, iteration boundaries, termination reason
- GitOperation (read): fetch PR base/head refs and compute canonical diffs
- (internal) Projection worker: posts status/comment from durable receipts

### Implementer (code writer)
**Primary job:** generate a new ChangeSetBundleV1 addressing reviewer feedback.

Typical kernel tools:
- ListFiles/Search/FileRead: discover relevant code paths under workspace root
- FileWrite/FileEdit: apply changes deterministically in workspace
- ShellExec: run tests/linters as terminal verifiers (bounded)
- PublishEvidence: publish new ChangeSetBundleV1 (patch digest + file list)
- EmitEvent: ChangeSetPublished + iteration metadata

CAS reads:
- ContextPack (selectors), prior diffs, prior test outputs, reviewer finding summaries

CAS writes:
- patch bundle, tool receipts, test outputs, summary receipts

### Code Quality Reviewer
**Primary job:** assess correctness, style, maintainability.

Typical kernel tools:
- ArtifactFetch: retrieve ChangeSetBundleV1 + tool indices
- FileRead/Search: inspect touched files and surrounding context
- ShellExec: targeted tests or linters (avoid full CI by default)
- PublishEvidence: review artifact bundle (findings, references)
- EmitEvent: ReviewReceiptRecorded

### Security Reviewer
**Primary job:** detect unsafe patterns, dangerous APIs, policy violations.

Typical kernel tools:
- ArtifactFetch + FileRead/Search: focus on security-sensitive code paths
- ShellExec: security checks (where available) or targeted tests
- PublishEvidence + EmitEvent: ReviewReceiptRecorded with structured security findings

## 4) Productivity scripts (operator- and agent-facing)

The goal is to make common operations 1 command away, without reading raw logs.

Minimum CLI surface:
- `apm2 fac work status <work_id>`
- `apm2 fac pr ingest <repo> <pr_number>`
- `apm2 fac episode inspect <episode_id> --tool ShellExec`
- `apm2 fac receipt show <receipt_hash>`
- `apm2 fac context build --role <role_id> --episode <episode_id>`
- `apm2 fac resume <work_id>` (crash-only restart from ledger anchor)

## 5) Horizontal specialization strategy (holonic slicing)

Start with 4 roles (orchestrator/implementer/security/code-quality). As soon as iteration stability exists,
add specialists to reduce context and increase reliability, e.g.:
- “Rust compiler error fixer”
- “Test flake stabilizer”
- “Dependency update reviewer”
- “API boundary reviewer”
- “Perf regression spotter”

Each specialist role MUST have:
- a narrowly scoped RoleSpecV1 (hash-addressed)
- a small ContextPack template
- explicit tool budgets

## 6) Verifying correctness of role instructions (RoleSpecV1 conformance)

Role instructions drift is inevitable; treat it as a first-class defect surface.

Conformance harness principles:
- schema validation of role outputs (receipt kinds, required fields)
- deny-by-default tool allowlists and budgets enforced by RoleSpec
- replay tests: run the same RoleSpec against a small corpus of toy tasks and verify:
  - deterministic tool-call envelope behavior
  - no forbidden tools used
  - terminal receipt produced or structured failure emitted

Failures become defects that update RoleSpec or context compilation rules.
