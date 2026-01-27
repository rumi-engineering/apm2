# MCP Transports: stdio

```yaml
# transports_stdio.yaml
revision: "2025-11-25"

transport: "stdio"
overview:
  - "spawned local process; bidirectional over stdin/stdout"
encoding:
  - "JSON-RPC messages MUST be UTF-8 encoded"
streams:
  client_to_server: "stdin (server side)"
  server_to_client: "stdout (server side)"
  logs_side_channel:
    - "server MAY write UTF-8 strings to stderr for logging (info/debug/error)"
    - "client MAY capture/forward/ignore stderr; MUST NOT treat stderr as protocol"
framing:
  delimiter: "\n"
  requirements:
    - "each message is a single JSON-RPC object serialized on one line"
    - "MUST NOT emit pretty-printed JSON spanning multiple lines"
    - "MUST NOT contain embedded newlines outside JSON string escapes"
    - "implementations SHOULD tolerate optional '\\r' before '\\n' (CRLF), but MUST NOT emit it unless required by the embedding environment"
io_rules:
  - "stdout is reserved for protocol frames only"
  - "any human-readable logging MUST be routed to stderr or an external log sink"
backpressure:
  - "apply bounded buffers on read/write; close session on framing violations"
```
