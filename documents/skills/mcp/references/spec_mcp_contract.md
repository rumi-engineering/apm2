# MCP Protocol Contract

```yaml
# mcp_contract.yaml
# Protocol contract summary for MCP revision 2025-11-25.
# Source-of-truth remains the MCP schema reference; this file is a compact, implementer-oriented contract.

protocol:
  name: "Model Context Protocol"
  revision: "2025-11-25"
  envelope:
    kind: "json-rpc-2.0"
    jsonrpc_field: "MUST be exactly '2.0'"
    message_kinds:
      request:
        required_fields: ["jsonrpc", "id", "method"]
        optional_fields: ["params"]
        id_rules:
          - "id MUST be string|number"
          - "id MUST NOT be null"
          - "id MUST be unique among outstanding requests within a session"
      response:
        required_fields: ["jsonrpc", "id"]
        one_of:
          - result: { required: true }
          - error: { required: true }
      notification:
        required_fields: ["jsonrpc", "method"]
        optional_fields: ["params"]
        id_field: "MUST NOT be present"
    error_object:
      required_fields: ["code", "message"]
      optional_fields: ["data"]
      jsonrpc_standard_codes:
        - { code: -32700, meaning: "Parse error" }
        - { code: -32600, meaning: "Invalid Request" }
        - { code: -32601, meaning: "Method not found" }
        - { code: -32602, meaning: "Invalid params" }
        - { code: -32603, meaning: "Internal error" }

lifecycle:
  phases: ["initialization", "operation", "shutdown"]
  initialization:
    first_message: "client -> server: initialize"
    initialize_request:
      method: "initialize"
      params_required: ["protocolVersion", "capabilities", "clientInfo"]
    initialize_response:
      result_required: ["protocolVersion", "capabilities", "serverInfo"]
      result_optional: ["instructions"]
    gate:
      - "client MUST send notifications/initialized after successful initialize response"
      - "client SHOULD NOT send requests other than ping before initialize response"
      - "server SHOULD NOT send requests other than ping and logging before receiving notifications/initialized"
  version_negotiation:
    rules:
      - "client sends a supported protocolVersion (SHOULD be latest supported by client)"
      - "server responds with same version if supported; otherwise responds with another supported version (SHOULD be latest supported by server)"
      - "if client does not support server-selected version, client SHOULD disconnect"
      - "HTTP: client MUST send MCP-Protocol-Version header on subsequent requests"
  shutdown:
    notes:
      - "No protocol-level shutdown messages; terminate at transport layer"

capabilities:
  negotiation_rule: "Only use features that were declared in peer capabilities during initialize."
  common_client_capabilities:
    roots: { listChanged: "bool (emit notifications/roots/list_changed)" }
    sampling: { supported: "object (empty) means supported" }
    elicitation:
      modes: ["form", "url"]
      compatibility:
        - "empty object == form-only for backwards compatibility"
    tasks:
      requests:
        sampling.createMessage: {}
        elicitation.create: {}
  common_server_capabilities:
    prompts: { listChanged: "bool" }
    resources: { subscribe: "bool", listChanged: "bool" }
    tools: { listChanged: "bool" }
    logging: {}
    completions: {}
    tasks:
      list: {}
      cancel: {}
      requests:
        tools.call: {}

transports:
  stdio:
    framing:
      - "each JSON-RPC message is one line: newline delimits messages"
      - "messages MUST NOT contain embedded newlines outside JSON string escapes"
    streams:
      - "client writes to server stdin; server writes to stdout"
      - "protocol data MUST NOT be interleaved with logs on stdout"
  streamable_http:
    session:
      header: "Mcp-Session-Id"
      rules:
        - "server MAY assign Mcp-Session-Id on initialize response"
        - "client MUST send Mcp-Session-Id on subsequent HTTP requests"
    protocol_version_header:
      header: "MCP-Protocol-Version"
    methods:
      post: "client->server JSON-RPC messages"
      get_sse: "server->client event stream (SSE) for async messages"
    sse:
      - "server should emit messages as SSE 'event: message' with JSON in 'data:'"
      - "client should reconnect with Last-Event-ID where supported"
      - "disconnecting SSE stream does not imply request cancellation"
```
