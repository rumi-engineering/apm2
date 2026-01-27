# Streamable HTTP message flow (sequence)

1. Client opens a session by POSTing the `initialize` JSON-RPC request to the MCP endpoint (`Content-Type: application/json`).
2. Server returns the JSON-RPC response (either `Content-Type: application/json` or `Content-Type: text/event-stream`).
   - If session management is used, the server may include `MCP-Session-Id` on the HTTP response containing the `InitializeResult`.
3. Client may open an SSE stream via GET to receive server→client JSON-RPC messages:
   - GET MCP endpoint
   - includes `MCP-Session-Id` (if present)
4. Client sends subsequent JSON-RPC messages via POST:
   - includes `MCP-Session-Id` (if present/required)
   - includes `MCP-Protocol-Version` (post-init)
   - notifications/responses get HTTP `202 Accepted` when accepted
5. Server sends server→client requests/notifications/responses over SSE streams (event type may be omitted; JSON lives in `data:`).
   - If multiple SSE streams are open, each JSON-RPC message is delivered on exactly one stream (no broadcast).
6. On disconnect, client reconnects SSE with `Last-Event-ID` (via GET); server may replay messages from the originating stream cursor per spec.
