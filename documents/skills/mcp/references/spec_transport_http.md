# MCP Transports: Streamable HTTP

```yaml
# transports_streamable_http.yaml
revision: "2025-11-25"

transport: "streamable_http"
endpoint_model:
  mcp_endpoint: "single HTTP endpoint path supporting POST and GET (DELETE MAY be supported for session termination)"
sending_messages_to_server:
  method: "POST"
  content_type: "application/json"
  body: "one JSON-RPC message (request|response|notification)"
  accept:
    - "text/event-stream"
    - "application/json"
  server_behavior:
    notification_or_response:
      - "if accepted: MUST return HTTP 202 Accepted with no body"
      - "if rejected: MUST return an HTTP error status (e.g., 400); body MAY include a JSON-RPC error response with no id"
    request:
      - "server MUST respond with either Content-Type: application/json (single JSON response) OR Content-Type: text/event-stream (SSE stream)"
      - "client MUST support both cases"
      - "if SSE is used, the stream SHOULD eventually include the JSON-RPC response for the request in the POST body"
      - "server MAY send JSON-RPC requests/notifications before the response; these SHOULD relate to the originating client request"
      - "after the JSON-RPC response has been sent, server SHOULD terminate the SSE stream"
listening_for_messages_from_server:
  method: "GET"
  response_content_type: "text/event-stream"
  notes:
    - "GET opens an SSE stream for server->client JSON-RPC messages (requests/notifications/responses)"
    - "client MAY close the stream at any time; disconnection MUST NOT be interpreted as request cancellation"
    - "if the server closes the connection without terminating the stream, it SHOULD send an SSE 'retry' field and allow the client to reconnect (polling pattern)"
    - "client MUST respect SSE 'retry' delays when reconnecting"
multiple_connections:
  allowed: true
  constraint: "server MUST send each JSON-RPC message on only one connected SSE stream; MUST NOT broadcast the same message across multiple streams"
sse_resumability:
  priming:
    - "if the server initiates an SSE stream (POST response): it SHOULD immediately send an SSE event with an event ID and an empty data field to prime reconnection"
  event_id:
    - "server MAY include SSE event 'id'"
    - "if present, id MUST be globally unique across all streams within a session (or across all streams with that specific client if session management is not in use)"
    - "event IDs SHOULD encode enough information to identify the originating stream (so the server can correlate a Last-Event-ID to the correct stream)"
  reconnect:
    client_header: "Last-Event-ID"
    rules:
      - "client SHOULD reconnect via GET with Last-Event-ID to resume"
      - "server MAY use Last-Event-ID to replay messages that would have been delivered on the disconnected stream after that event ID"
      - "server MUST NOT replay messages that would have been delivered on a different stream"
      - "resumption is always via HTTP GET with Last-Event-ID (regardless of how the original stream was initiated)"

cors_requirements:
  usage: "Required for web-based MCP clients (e.g., browser-based IDEs)"
  exposed_headers:
    - "MCP-Session-Id"
    - "MCP-Protocol-Version"
  allowed_methods: ["GET", "POST", "DELETE", "OPTIONS"]
  allowed_headers: ["Content-Type", "Authorization", "MCP-Session-Id", "MCP-Protocol-Version"]
session_management:
  header: "MCP-Session-Id"
  server_assignment:
    - "server MAY assign a session ID at initialization by including MCP-Session-Id on the HTTP response containing the InitializeResult"
    - "session id SHOULD be globally unique and cryptographically secure"
    - "session id MUST be visible ASCII 0x21..0x7E"
    - "server MUST validate the Origin header on all incoming connections to prevent DNS rebinding attacks; invalid Origin MUST yield HTTP 403 (body MAY include JSON-RPC error response with no id)"
    - "when running locally, servers SHOULD bind only to localhost (127.0.0.1) and SHOULD implement authentication"
  client_behavior:
    - "if provided, client MUST include MCP-Session-Id on all subsequent HTTP requests"
    - "if server requires session id, requests missing it SHOULD be rejected with HTTP 400"
  termination:
    - "server may invalidate a session; then requests with that session id MUST return HTTP 404"
    - "on HTTP 404 for a session id, client MUST start a new session (new initialize without session id)"
    - "client MAY send HTTP DELETE with MCP-Session-Id to terminate sessions (server MAY return 405)"
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
