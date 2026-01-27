# Testing and Fuzzing

## Conformance
- Golden vectors for:
  - initialize/initialized lifecycle
  - listChanged notifications
  - pagination cursors
  - streamable HTTP: session id + protocol version header enforcement
  - tasks: CreateTaskResult -> tasks/result

- Harness should run against:
  - local stdio client/server pair
  - HTTP server with an SSE client

## In-Memory Virtual Transports
For unit testing the protocol state machine without process or network overhead, use `tokio::io::duplex`:
- Create a `duplex(chunk_size)` pair.
- Wrap one end in an `McpTransport` implementation for the client, the other for the server.
- This allows deterministic, high-speed testing of:
  - Interleaved request/notification streams.
  - Race conditions between `notifications/cancelled` and request completion.
  - Large message framing behavior (up to MBs) without OS pipe buffer limitations.

## Property tests
- JSON-RPC decode/encode round-trip for all message shapes.
- Id uniqueness: never reuse outstanding ids.
- Backpressure: queues never exceed configured bounds.

## Fuzz targets
- stdio framing: random byte streams -> ensure no panics, bounded memory growth.
- JSON parsing: malformed inputs -> correct JSON-RPC parse errors and session termination where appropriate.
- SSE parsing: malformed events -> bounded failure behavior.

## Differential tests
- Compare serde_json vs simd-json parsing results for a curated corpus (if simd-json is enabled).
