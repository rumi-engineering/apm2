# Streamable HTTP message flow (sequence)

1. Client opens a session by POSTing the `initialize` JSON-RPC request to the MCP endpoint.
2. Server returns JSON-RPC response (optionally includes `Mcp-Session-Id` header).
3. Client opens an SSE stream:
   - GET MCP endpoint
   - includes `Mcp-Session-Id` (if present)
4. Client sends further JSON-RPC requests via POST:
   - includes `Mcp-Session-Id`
   - includes `MCP-Protocol-Version`
5. Server sends async requests/notifications over the SSE stream (`event: message`, `data: <json>`).
6. Client reconnects SSE with `Last-Event-ID` where supported; server may replay prior stream messages per spec.
