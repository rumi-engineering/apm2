# MCP Lifecycle

```yaml
# lifecycle.yaml
revision: "2025-11-25"

state_machine:
  states:
    - DISCONNECTED
    - INITIALIZING
    - AWAITING_INITIALIZED_NOTIFICATION
    - OPERATIONAL
    - SHUTTING_DOWN
  transitions:
    - from: DISCONNECTED
      on: "transport_open"
      to: INITIALIZING
    - from: INITIALIZING
      on: "initialize_request_received"
      to: AWAITING_INITIALIZED_NOTIFICATION
    - from: AWAITING_INITIALIZED_NOTIFICATION
      on: "notifications/initialized_received"
      to: OPERATIONAL
    - from: "*"
      on: "transport_close"
      to: DISCONNECTED

init_gating_rules:
  - "client MUST send initialize as first message"
  - "client SHOULD NOT send requests other than ping before initialize response"
  - "INITIALIZED BARRIER: server MUST NOT process standard requests (tools/list, resources/list, etc.) until notifications/initialized is received. Early requests SHOULD be rejected with -32600 (Invalid Request) or buffered until the barrier is cleared."
  - "server SHOULD NOT send requests other than ping and logging before receiving notifications/initialized"

experimental_features:
  tasks:
    status: "Experimental (2025-11-25)"
    usage_guidance: "Should be gated behind feature flags. Requires 'sampling' or 'elicitation' capability to provide meaningful utility. Implementation subject to breaking changes in subsequent protocol revisions."

timeouts:
  - name: "transport_connect_timeout"
    note: "implementation-defined; ensure bounded waits for subprocess startup / HTTP session establishment"
  - name: "initialize_timeout"
    note: "fail session if initialize handshake does not complete in bounded time"
```
