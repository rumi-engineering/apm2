# Transport Performance Notes

## stdio
- Serialization:
  - MUST be single-line JSON; avoid pretty-print.
  - Prefer streaming serializer (`to_writer`) to avoid intermediate string allocations.
- Parsing:
  - Use line framing; parse per line into `serde_json::Deserializer`.
  - Use `RawValue` for `params` to defer parsing.
- Limits:
  - enforce maximum line length; close on violations.
  - explicit buffering to prevent deadlocks when peer stalls.

## streamable HTTP
- POST path:
  - keep-alive connections; reuse client.
  - request batching is host-controlled; protocol is message-based.
- SSE path:
  - parse incrementally; handle large `data:` lines.
  - support `retry:` and `id:`; store last event id for reconnect.
- Session state:
  - session lookup by `MCP-Session-Id` must be O(1) and bounded.
  - invalidate sessions on idle timeout to prevent resource leaks.

## Common
- Avoid per-message dynamic dispatch where possible:
  - pre-hash method strings or use perfect-hash map for router.
- Use structured error payloads for deterministic handling by clients.
