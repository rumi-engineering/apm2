# Error Model

## JSON-RPC layer
- Parse errors, invalid requests, method not found, invalid params, internal errors.
- **Null ID Enforcement**: 
  - **Requests**: MCP strictly forbids `id: null` for client-initiated requests.
  - **Responses**: If a request is malformed such that an `id` cannot be extracted (Parse Error -32700 or Invalid Request -32600), the response **MUST** use `id: null` to comply with JSON-RPC 2.0. Standard protocol logic should treat these as terminal transport or framing failures.
- Use `serde_json::value::RawValue` for params to allow identifying the `id` and `method` without failing the entire parse if `params` are malformed.

## MCP layer
- Lifecycle violations:
  - non-initialize request before init complete
  - server requests before notifications/initialized (beyond ping/logging)
- Capability violations:
  - method invoked without negotiated capability (treat as -32601 or a domain error)
- Transport violations:
  - stdio: multi-line message / overlong frame
  - HTTP: missing/invalid MCP-Protocol-Version; missing MCP-Session-Id when required

## Tool/resource/prompt domain errors
- Prefer JSON-RPC -32602 for invalid params.
- Use -32603 for internal server failures.
- For tool execution failures that are part of domain behavior, set `result.isError=true` rather than returning JSON-RPC error, if the RPC itself succeeded.
