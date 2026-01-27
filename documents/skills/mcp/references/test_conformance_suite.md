# MCP Conformance Suite

```yaml
# conformance_suite.yaml
revision: "2025-11-25"
suites:
  - id: "CONF-001"
    name: "Lifecycle handshake"
    cases:
      - "initialize -> initialize_response -> notifications/initialized"
      - "reject non-initialize request before init complete"
      - "version negotiation: server selects supported version"
  - id: "CONF-002"
    name: "Capabilities gating"
    cases:
      - "server omits tools capability -> client invoking tools/list yields method-not-found or policy error"
      - "client omits roots capability -> server does not send roots/list"
  - id: "CONF-003"
    name: "List changed notifications"
    cases:
      - "notifications/tools/list_changed triggers cache invalidation"
      - "notifications/prompts/list_changed"
      - "notifications/resources/list_changed"
  - id: "CONF-004"
    name: "Pagination"
    cases:
      - "tools/list cursor/nextCursor"
      - "resources/list cursor/nextCursor"
      - "prompts/list cursor/nextCursor"
  - id: "CONF-005"
    name: "stdio framing"
    cases:
      - "single-line JSON required"
      - "overlong line -> hard fail/close"
  - id: "CONF-006"
    name: "streamable HTTP"
    cases:
      - "MCP-Session-Id issuance and enforcement"
      - "MCP-Protocol-Version header required post-init"
      - "SSE message event parsing"
      - "Last-Event-ID reconnect cursor handling (best-effort)"
  - id: "CONF-007"
    name: "Tasks (optional)"
    cases:
      - "task augmented tools/call yields CreateTaskResult"
      - "tasks/result returns ToolResult for that task"
      - "tasks/cancel transitions to cancelled and returns empty result"
```
