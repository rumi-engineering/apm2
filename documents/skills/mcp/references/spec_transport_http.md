# MCP Transports: Streamable HTTP

```yaml
# transports_streamable_http.yaml
revision: "2025-11-25"

transport: "streamable_http"
endpoint_model:
  mcp_endpoint: "single HTTP endpoint handling POST/GET/DELETE"
sending_messages_to_server:
  method: "POST"
  content_type: "application/json"
  accept:
    - "text/event-stream"
    - "application/json"
listening_for_messages_from_server:
  method: "GET"
  response_content_type: "text/event-stream"
  notes:
    - "GET opens an SSE stream; server can send JSON-RPC requests/notifications on this stream"
    - "server MUST NOT send JSON-RPC responses on the stream unless resuming a stream for a previous client request"
multiple_connections:
  allowed: true
  constraint: "server must send each JSON-RPC message on exactly one connected stream (no broadcast)"
sse_resumability:
  event_id:
    - "server MAY include SSE event 'id'"
    - "id MUST be globally unique across all streams within a session"
    - "Sequence Requirement: IDs SHOULD be monotonically increasing (e.g., integers or KSUIDs) to facilitate range-based replay."
  reconnect:
    client_header: "Last-Event-ID"
    rules:
      - "client SHOULD reconnect via GET with Last-Event-ID to resume"
      - "REPLAY BUFFER: server SHOULD maintain a per-session ring buffer (e.g., last 50 events)."
      - "Buffer Miss: If Last-Event-ID is provided but NOT in the buffer (expired), the server MUST NOT replay; it should start the stream from the current real-time cursor and MAY emit a warning notification."
      - "Session Scope: A change in Mcp-Session-Id invalidates the Last-Event-ID; the client MUST reset its event cursor."
      - "server MUST NOT replay messages from other sessions or other clients."
      - "server SHOULD prime clients with an initial event 'id' + empty data upon GET connection to establish a baseline for subsequent reconnects."

cors_requirements:
  usage: "Required for web-based MCP clients (e.g., browser-based IDEs)"
  exposed_headers:
    - "Mcp-Session-Id"
    - "MCP-Protocol-Version"
  allowed_methods: ["GET", "POST", "DELETE", "OPTIONS"]
  allowed_headers: ["Content-Type", "Authorization", "Mcp-Session-Id", "MCP-Protocol-Version"]
session_management:
  header: "Mcp-Session-Id"
  server_assignment:
    - "server MAY include MCP-Session-Id in initialize response"
    - "session id SHOULD be globally unique and cryptographically secure"
    - "session id MUST be visible ASCII 0x21..0x7E"
  client_behavior:
    - "if provided, client MUST send MCP-Session-Id on all subsequent requests"
    - "if server requires session id, requests missing it SHOULD be rejected with HTTP 400"
  termination:
    - "server may invalidate a session; then requests with that session id MUST return HTTP 404"
    - "on HTTP 404 for a session id, client MUST start a new session (new initialize without session id)"
    - "client SHOULD send HTTP DELETE with MCP-Session-Id to terminate sessions (server MAY return 405)"
protocol_version_header:
  header: "MCP-Protocol-Version"
  requirement: "client MUST include on all requests after initialization"
  backwards_compat:
    - "if absent and no other identification, server SHOULD assume 2025-03-26"
    - "invalid/unsupported header MUST yield HTTP 400"
backwards_compat_old_http_sse:
  notes:
    - "spec defines guidance for supporting deprecated HTTP+SSE transport from 2024-11-05"
```
