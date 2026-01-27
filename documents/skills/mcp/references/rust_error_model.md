# Error Model

## JSON-RPC layer
- Parse errors, invalid requests, method not found, invalid params, internal errors.
- **ID rules**:
  - **Requests**: MCP requires `id` to be a string or integer; `id` MUST NOT be `null`.
  - **Responses**:
    - Result responses MUST include the request `id`.
    - Error responses MUST include the request `id`, except when the `id` could not be read due to a malformed request (then the `id` field MAY be omitted).
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
