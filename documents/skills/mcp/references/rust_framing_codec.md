# Framing and Codecs

## stdio framing
- One JSON-RPC object per line.
- Delimiter: `\n` (LF).
- Serializer must be compact (no pretty formatting).
- Decoder must enforce:
  - UTF-8 validity
  - maximum frame size (configurable; default should be conservative)
  - hard fail on embedded newline delimiters (outside JSON string escapes) via line framing

Implementation options:
- `tokio_util::codec::LinesCodec` with `max_length` tuned (beware default limits).
- Custom codec over `BytesMut` for:
  - fewer reallocations
  - stable error reporting on overlong lines

## streamable HTTP (SSE) 
- For server->client messages: SSE event stream:
  - `event: message`
  - `data: <json>`
  - optional `id: <event-id>`
  - optional `retry: <ms>`
- Implement reconnect:
  - client reconnects with `Last-Event-ID`
  - server may replay only messages from the originating stream cursor

## Canonicalization for signing (optional)
- If message digests are required (e.g., internal receipts), canonicalize JSON before hashing (e.g., JCS).
- Do NOT replace MCP wire encoding; canonicalization is for internal integrity only.

