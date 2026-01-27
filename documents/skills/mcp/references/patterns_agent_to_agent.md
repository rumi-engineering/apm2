# MCP for Agent-to-Agent Communication (APM2 Patterns)

MCP is a **client ↔ server** protocol. “Agents talking to each other via MCP” therefore requires choosing a topology and then mapping “message passing” onto MCP primitives (tools/resources/prompts/tasks).

This document focuses on patterns that keep interop high (Claude Code / Codex / Gemini CLI) while making security boundaries explicit.

## Topology Options

### 1) Hub-and-spoke (recommended for APM2)
- **APM2 daemon = MCP server** (single authority + policy enforcement point).
- **Each agent process = MCP client** (stdio for local, streamable HTTP for remote).
- Pros: centralized audit log, consistent policy, simpler routing.
- Cons: APM2 becomes a critical dependency; you must harden session isolation.

### 2) Federated (agents run servers)
- Each agent exposes an MCP server; peers connect as clients (direct or via APM2 bridge).
- Pros: avoids single hub bottleneck; agents can expose specialized capabilities.
- Cons: complex trust graph; higher chance of confused-deputy mistakes; tool naming conflicts.

### 3) Bridge mode (APM2 as both server and client)
- APM2 exposes an MCP server to agents, and also connects as a client to external MCP servers (databases, ticketing, etc.).
- Treat the bridge as a **privilege boundary**: never “reflect” external tools 1:1 without policy and schema sanitization.

## Mapping “Messaging” onto MCP

### Prefer “tool to enqueue” + “resource to read” (push/pull split)
**Send path** (write side):
- Provide a tool that enqueues a message, e.g. `apm2.message.send`.
- Tool args should be minimal and schema-stable:
  - `to` (agent id)
  - `thread` (thread id or `"new"`)
  - `text` (string)
  - optional `attachments` (array of `resource_link` URIs, not inline blobs)

**Receive path** (read side):
- Represent inboxes/threads as resources:
  - `apm2://agents` (list agents)
  - `apm2://agents/<agentId>` (agent metadata + status)
  - `apm2://threads/<threadId>` (conversation transcript / recent messages)
- Use `resources/subscribe` + `notifications/resources/updated` to signal “new messages available”.
- Keep transcripts **paged or chunked** to avoid blowing context; use `resource_link` returns for large artifacts.

Why this works well:
- Tools are naturally **write** operations (auditable, permissioned).
- Resources are naturally **read** operations (can be cached, pulled on demand).
- Subscriptions give “push-like” UX without forcing the model to ingest every update.

### When to use `tasks`
Use task-augmented operations for anything that can exceed typical tool timeouts:
- cross-agent “ask/await reply” workflows
- fan-out broadcasts with aggregation
- expensive summarization or retrieval

Patterns:
- `apm2.message.send` returns `CreateTaskResult` for slow delivery/ack.
- Include `_meta.io.modelcontextprotocol/model-immediate-response` in `CreateTaskResult` for host apps that want an immediate tool result while the task runs.
- Expose task progress via `notifications/tasks/status` (optional) plus `tasks/get` polling.

## Interop Constraints (non-obvious)

### Tool naming and collisions
- MCP recommends tool names be **1..128 chars** and use only `[A-Za-z0-9_.-]`.
- Gemini CLI may normalize names and resolve collisions by prefixing `serverName__toolName`.
- To reduce surprises:
  - keep names short and already namespaced (e.g., `apm2.message.send`, `apm2.thread.read`)
  - avoid relying on tool name identity across clients; treat it as a display identifier, not a security boundary

### Schema lowest-common-denominator
To keep tools available across clients:
- avoid `$ref`
- avoid deep `anyOf`/`oneOf`
- keep `inputSchema` root as `{ "type": "object", ... }`
- prefer optional fields (omit from `required`) over nullable unions

### Don’t stream “logs” into the model
Use MCP logging (`logging/setLevel`, `notifications/message`) for host/UI log sinks; keep stdout protocol clean.
Don’t inject logs into the model’s context by default: it is both noisy and an injection surface.

## Security Boundaries (must-have for hub pattern)

### Session isolation is the root primitive
Treat each MCP session as a principal:
- bind `MCP-Session-Id` (HTTP) or process identity (stdio) to an APM2 “client identity”
- enforce ACLs for every tool/resource based on that identity
- never allow a session to read another session’s private resources unless explicitly authorized

### Confused deputy hazards
If APM2 bridges to external systems:
- do not reuse APM2’s own credentials for a client request unless the client is authorized to act as that principal
- prefer explicit “capability grants” (leases) per session, with a narrow scope and TTL

### Transport hardening (HTTP)
- validate `Origin` to mitigate DNS rebinding (spec requirement)
- treat `MCP-Session-Id` as a bearer secret; don’t log it, rotate on suspicion, enforce idle timeouts
- for remote deployments: implement OAuth 2.1 per MCP authorization spec

## Example Flow (hub pattern)
1. Agent A connects to APM2 MCP server and discovers `apm2.message.send`.
2. Agent A calls `apm2.message.send` to Agent B (optionally as a task).
3. APM2 appends the message to `apm2://threads/<id>` and emits `notifications/resources/updated`.
4. Agent B (subscribed) receives the update signal, then explicitly calls `resources/read` to fetch the new message chunk.

