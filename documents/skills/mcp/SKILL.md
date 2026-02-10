---
name: mcp
description: Never use MCP.
---

# MCP Low-Level Primitive (Rust) — SKILL.md

## Purpose
Implement a low-level, high-performance **Model Context Protocol (MCP)** core suitable for:
- Running **APM2 as an MCP server** (so external Coding Agents/CLIs can connect).
- Optionally running **APM2 as an MCP client** (bridge mode).
- Supporting **real-time**, duplex request/notification traffic over:
  - `stdio` (newline-delimited JSON-RPC 2.0)
  - `streamable HTTP` (SSE + POST)

Target protocol revision: `2025-11-25`.

## Non-Goals
- High-level product UX, agent personas, or client UI semantics.
- Bundling provider-specific SDKs; instead, produce a portable transport + protocol core.
- Reproducing the entire MCP schema in prose; refer to `references/spec_schema_reference.md`.

## Protocol Contract (normative)
- JSON-RPC 2.0 message envelope and error handling.
- MCP lifecycle: `initialize` MUST be first; `notifications/initialized` gates normal ops.
- Capabilities MUST be negotiated; methods not negotiated MUST NOT be used.
- Transport compliance for `stdio` and `streamable HTTP`, including session management headers.
- Security posture:
  - Default-deny for authority surfaces exposed by tools/resources.
  - HTTP authorization behavior per MCP auth spec; stdio credentials from environment.

See `references/spec_mcp_contract.md`.

## Rust Primitive Contract (normative)
### Core abstractions
- `Transport` (async read/write + close): stdio, streamable HTTP.
- `Session` (state machine): lifecycle, negotiated protocol version, negotiated capabilities.
- `Router` (method dispatch): request -> handler; notification -> handler.
- `IdGen` (monotone, collision-free per session).
- `Cancellation` + `Progress` (cross-cutting).
- `Tasks` (optional feature): task-augmented execution + polling.
- **Schema Sanitizer**: Provider-aware visitor for Gemini/Codex compatibility.

See:
- `references/rust_api_surface.md`
- `references/rust_concurrency.md`
- `references/rust_framing_codec.md`
- `references/rust_schema_sanitization.md`

### Performance invariants
- Zero-copy buffering where possible (`bytes::Bytes/BytesMut`).
- Bounded allocations per message; avoid per-message `String` churn for hot paths.
- Backpressure at transport boundary.
- Structured logging to stderr / side-channel, never to stdio protocol stream.

See `references/perf_transport.md`.

## Provider Compatibility Targets (as of 2026-01-27)
- Claude Code MCP client: stdio, HTTP, (SSE deprecated) and list_changed refresh semantics.
- OpenAI Codex MCP client: stdio + streamable HTTP; config in `config.toml`; tool allow/deny lists.
- Gemini CLI MCP client: stdio + streamable HTTP + SSE; schema sanitization; `settings.json` config.

See `references/provider_compatibility.md`.

## Files
- `references/references_index.md`: machine-readable index + provenance.
- `references/spec_tasks_state_machine.md`: lifecycle and notifications for long-running tasks.
- `references/patterns_agent_to_agent.md`: patterns for agent-to-agent messaging over MCP (APM2 hub/federation).
- `references/rust_*`: crate layout, APIs, parsing, testing.
- `references/provider_*`: integration notes for major clients.
- `references/test_*`: conformance + fuzz + golden vectors.
- `references/perf_*`: context and throughput budgets; overhead minimization patterns.

## Sources
Canonical spec sources and provider docs are enumerated in `references/sources.md`.
