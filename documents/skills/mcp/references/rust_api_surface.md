# Rust API Surface (low-level MCP primitive)

## Crate split (recommended)
- `mcp-core`: JSON-RPC + MCP types, lifecycle state machine, router, id generation.
- `mcp-transport-stdio`: newline-delimited framing over async stdin/stdout.
- `mcp-transport-http`: streamable HTTP (POST + SSE GET) client/server.
- `mcp-server`: ergonomic server builder for tools/resources/prompts/logging/completion/tasks.
- `mcp-client`: optional; for bridge mode (consume other MCP servers).
- `mcp-testkit`: golden vectors, fuzz targets, protocol conformance harness.

## Core traits
### Transport
- `async fn send(&self, msg: JsonRpcMessage) -> Result<()>`
- `async fn recv(&self) -> Result<JsonRpcMessage>`
- `async fn close(&self) -> Result<()>`
- Required properties:
  - backpressure (bounded queues)
  - ordered delivery within a stream
  - explicit close semantics

### Session
- Holds:
  - negotiated `protocol_version`
  - negotiated `capabilities_local`, `capabilities_peer`
  - `state: LifecycleState`
- Enforces gating rules:
  - `initialize` must be first (client->server)
  - `notifications/initialized` required before server sends non-(ping,logging) requests

### Router
- `fn register_request(method: &'static str, handler: impl RequestHandler)`
- `fn register_notification(method: &'static str, handler: impl NotificationHandler)`

#### RequestHandler Trait
```rust
#[async_trait]
pub trait RequestHandler: Send + Sync {
    /// Dispatched after method identification. 
    /// Implementations should deserialize `params` into a specific DTO.
    async fn handle(
        &self, 
        params: Option<Box<serde_json::value::RawValue>>, 
        ctx: CallContext
    ) -> Result<serde_json::Value, JsonRpcError>;
}
```

## High-performance type notes
- **Lazy / Double-Pass Parsing**:
  1.  **Pass 1 (Router)**: Deserialize the outer envelope (`id`, `method`) while keeping `params` as a `RawValue`. This allows rapid dispatch or rejection (e.g., Method Not Found) without paying for full param deserialization.
  2.  **Pass 2 (Handler)**: The specific handler deserializes the `RawValue` into its expected typed structure.
- Parse input into an owned message enum:
  - `JsonRpcRequest { id, method, params: Option<Box<RawValue>> }`
  - `JsonRpcNotification { method, params: Option<Box<RawValue>> }`
  - `JsonRpcResponse { id, result_or_error: ResponsePayload }`
- Serialize output with compact JSON; never pretty-print (stdio framing constraint).

## Cross-cutting utilities
- Cancellation:
  - track `inflight: HashMap<RequestId, CancelToken>`
  - on `notifications/cancelled`, signal cancel; handlers should poll or be cooperative.
- Progress:
  - accept `progressToken` via `params._meta` and emit `notifications/progress`.

## Tool execution contract
- Normalize tool calls to:
  - `fn call(name: ToolName, args: JsonValue, ctx: CallContext) -> ToolResult`
- ToolResult should support:
  - `content: Vec<ContentItem>`
  - `structuredContent: Option<JsonValue>`
  - `isError: Option<bool>`

## Tasks (optional feature gate)
- Represent task-augmented requests as a separate execution path:
  - immediate `CreateTaskResult { task: TaskDescriptor, _meta? }`
  - deferred `tasks/result` returns category-specific result.
- Store tasks in a bounded TTL cache keyed by `taskId` with access control per session.
