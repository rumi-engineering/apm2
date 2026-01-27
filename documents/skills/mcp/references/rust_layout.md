# Suggested Crate Layout

```
crates/
  mcp-core/
    src/
      jsonrpc/
        message.rs        # envelope enums + RawValue params
        error.rs
        codec.rs          # shared helpers (NOT stdio framing)
      mcp/
        lifecycle.rs
        capabilities.rs
        methods.rs        # method constants
        types.rs          # shared structs (Tool, Resource, Prompt, ...)
      router.rs
      session.rs
      id.rs
      util/
        cancel.rs
        progress.rs
        pagination.rs
        tasks.rs
  mcp-transport-stdio/
    src/
      stdio.rs            # tokio::io framed read/write
      codec.rs            # newline framing + max line length
  mcp-transport-http/
    src/
      client.rs           # POST + SSE GET
      server.rs           # hyper/axum server
      sse.rs              # event framing + Last-Event-ID support
      session.rs          # MCP-Session-Id + protocol version header enforcement
  mcp-server/
    src/
      builder.rs
      tools.rs
      resources.rs
      prompts.rs
      logging.rs
      completion.rs
  mcp-testkit/
    src/
      vectors.rs
      conformance.rs
      fuzz.rs
```

Compatibility constraints:
- `mcp-core` must be `no_std`-incompatible due to JSON parsing; keep dependencies minimal.
- `mcp-transport-http` SHOULD support HTTP/1.1 keep-alive; MAY support h2.
