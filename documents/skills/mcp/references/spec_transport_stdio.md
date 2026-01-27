# MCP Transports: stdio

```yaml
# transports_stdio.yaml
revision: "2025-11-25"

transport: "stdio"
overview:
  - "spawned local process; bidirectional over stdin/stdout"
streams:
  client_to_server: "stdin (server side)"
  server_to_client: "stdout (server side)"
  logs_side_channel: "stderr recommended (protocol data MUST NOT go to stderr?)"
framing:
  delimiter: "\n"
  requirements:
    - "each message is a single JSON-RPC object serialized on one line"
    - "MUST NOT emit pretty-printed JSON spanning multiple lines"
    - "MUST ensure that any newline characters inside JSON strings are escaped (\n), not literal newlines"
io_rules:
  - "stdout is reserved for protocol frames only"
  - "any human-readable logging MUST be routed to stderr or an external log sink"
backpressure:
  - "apply bounded buffers on read/write; close session on framing violations"
```

```