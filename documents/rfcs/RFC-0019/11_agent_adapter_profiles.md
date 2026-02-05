# RFC-0019 Addendum — AgentAdapterProfileV1 and real-world CLI integration notes

This addendum captures the *practical* adapter integration contract required to run heterogeneous
third-party coding agents (Claude Code, Gemini CLI, Codex CLI) under holonic boundary discipline.

## 1) Design posture (Markov blanket / boundary discipline)

- The agent process is treated as an **untrusted black-box proposer**.
- The **kernel** is the only actuator: all tools are executed kernel-side under policy, budgets, and
  durable ledger events.
- Adapter output is advisory; the ledger is authoritative.

This is consistent with the holonic boundary model (private state is ephemeral; only committed receipts
and CAS artifacts are durable truth).

## 2) AgentAdapterProfileV1 (normative recap)

AgentAdapterProfileV1 is a CAS-addressed artifact. Profile selection is explicit by hash; ambient defaults are forbidden.

Minimum fields (normative):
- profile_id (stable string)
- adapter_mode: black_box | structured_output | mcp_bridge | hooked_vendor
- command
- args_template (ordered)
- env_template (ordered allowlist)
- cwd
- requires_pty (bool)
- input_mode: arg | stdin | file | stream-json
- output_mode: raw | json | jsonl | stream-json
- permission_mode_map (policy tiers -> CLI flags; ordered encoding)
- tool_bridge (see below)
- capability_map (external tool intents -> kernel tool classes)
- version_probe (command + regex)
- health_checks (timeouts, stall thresholds)
- budget_defaults (tool_calls, tokens, wall_clock, evidence)
- evidence_policy (what is recorded vs discarded)

Tickets:
- Schema + canonicalization + registry selection: TCK-00328
- Profiles for claude-code/gemini-cli/codex-cli/local-inference: TCK-00329
- Conformance tests + ledger attribution: TCK-00330

## 3) Tool bridging options

### Option C — Black-box ledger-mediated driver (default)
Preferred for FAC v0.

- Agent is run with native tools disabled/restricted.
- Agent emits a minimal, bounded **ToolIntent** grammar (not vendor JSONL).
- Kernel validates, policy-checks, and executes tools; results are injected back as ToolResult envelopes.
- Ledger emits ToolRequested/ToolDecided/ToolExecuted events; ToolExecutionReceipt + ToolLogIndexV1 index the episode.

**ToolIntentV1 (recommended shape)**
Single-line, delimiter-framed, nonce-gated, bounded size:

- Request:
  - `⟦TI1 <nonce>⟧ <request_id> <tool_name> <args_b64url>`
- Response:
  - `⟦TR1 <nonce>⟧ <request_id> ok <cas_result_hash>`
  - `⟦TR1 <nonce>⟧ <request_id> denied <reason_code>`

Notes:
- `<args_b64url>` is base64url(canonical JSON) for deterministic parsing.
- Results flow by CAS hash; payload excerpts are optional and bounded.

### Option B — Structured output parsing (JSONL / stream-json)
Allowed only when vendor output format is stable and version-pinned.

- Agent runs in vendor structured mode.
- Adapter parses tool request events from stdout.
- Kernel executes tools and injects results back (stdin or continuation).

Risks:
- output drift across vendor versions
- JSON parsing failures under partial writes
- fragile coupling to vendor semantics

### Option A — MCP bridge
Allowed, not preferred for v0.

- Kernel exposes MCP tool schemas.
- Agent connects via MCP client configuration.

Risks:
- heavy per-agent install/config surface
- client behavior differences across CLIs

## 4) Practical CLI-specific guidance for profiles (non-interactive)

The goal is **headless episodes**, deterministic enough for conformance tests, with kernel-side tools.

### Claude Code
Recommended posture:
- run non-interactive print mode
- disable built-in tools
- disable session persistence when possible

Profile notes (example flags; pin to actual installed version via version_probe):
- `claude -p ...`
- `--tools ""`
- `--no-session-persistence`
- set output mode appropriate for your adapter (raw preferred for ToolIntent)

### Gemini CLI
Recommended posture:
- run headless prompt mode
- disable extensions (treat extensions as tool surface)
- avoid file auto-inclusion flags

Profile notes:
- `gemini -p ...`
- `-e none` (disable extensions)
- do NOT use `--all-files` (unledgered reads)

### Codex CLI
Recommended posture:
- run `codex exec` non-interactive mode
- disable shell/web tools via config where possible
- disable history persistence

Profile notes:
- `codex exec ...`
- set config overrides: `features.shell_tool=false`, `web_search=disabled`, `history.persistence=none`
- avoid relying on `--json` event stream unless using Option B

## 5) Conformance tests (TCK-00330) — what must be proven

For each profile:
1. version_probe passes and pins an expected major/minor.
2. Adapter runs a full non-interactive episode:
   - agent emits at least one ToolIntent
   - kernel executes tool(s) and records ToolExecutionReceipt
   - agent terminates with a structured final output
3. ReviewReceiptRecorded exists and is verifiable from CAS+ledger.
4. Ledger attribution includes: (work_id, episode_id, session_id, adapter_profile_hash).

Failure cases MUST fail closed with:
- ReviewBlockedRecorded(reason=ADAPTER_MISCONFIGURED) or ADAPTER_PROTOCOL_VIOLATION
