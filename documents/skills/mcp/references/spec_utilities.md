# MCP Utilities

```yaml
# utilities.yaml
revision: "2025-11-25"

pagination:
  request_param: "cursor (opaque)"
  response_field: "nextCursor (opaque)"
  invariants:
    - "cursor values are opaque to clients"
    - "absence of nextCursor indicates end of enumeration"
  implementation_patterns:
    stateless: "Encrypted/signed token containing 'offset', 'limit', and 'timestamp'. Recommended to avoid server-side state leaks."
    stateful: "Server-side session-bound lookup ID. Requires TTL and cleanup logic."

tool_to_resource_bridge:
  purpose: "Handle large tool outputs (CSV, logs, images) without context bloating."
  mechanism:
    1. "tools/call returns a result.content array containing a 'resource_link' type."
    2. "The LLM receives the metadata and URI."
    3. "The LLM decides whether to fetch the full content via a subsequent 'resources/read' request."
  benefits: ["Reduced token cost", "Auditable data access", "Improved security gating"]

cancellation:
  notification: "notifications/cancelled"
  params:
    requestId: "original JSON-RPC id of the request being cancelled"
    reason: "optional string"
  semantics:
    - "best-effort; receiver may ignore if already completed"
    - "cancellation does not imply transport close"

progress:
  notification: "notifications/progress"
  params:
    progressToken: "token associated with the operation"
    progress: "number"
    total: "optional number"
  association:
    - "progressToken is typically provided by requestor via params._meta.progressToken"

ping:
  method: "ping"
  semantics:
    - "can be used pre-initialization as keepalive/liveness probe"

logging:
  set_level_method: "logging/setLevel"
  message_notification: "notifications/message"
  notes:
    - "logging over MCP is distinct from process stderr logs; intended for structured log forwarding"

completion:
  method: "completion/complete"
  note: "argument auto-completion for prompts/tools/resource templates"

tasks:
  note: "tasks are experimental in 2025-11-25; see spec + references/spec/methods_registry.yaml"
```
