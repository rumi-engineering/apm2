# Context Overhead Drivers (MCP)

Primary context consumers (host/model side):
- Tool catalog:
  - `tools/list` tool definitions: `name`, `description`, `inputSchema`, optional `outputSchema`.
  - Long JSON Schemas are high-token overhead.
- Prompt catalogs (`prompts/list`, `prompts/get`) and embedded resources.
- Resource contents (`resources/read`) when inlined rather than linked.
- Logging (`notifications/message`) if forwarded into the model stream.
- Repeated re-listing triggered by list_changed without caching.

Protocol-level mitigation levers:
- Use pagination cursors to avoid sending full catalogs.
- Use `resource_link` results for large artifacts; require explicit `resources/read` pull.
- Prefer minimal schemas; restrict `additionalProperties` and keep property names short.
- Use `outputSchema` + `structuredContent` to reduce verbose natural language results.

Implementation-level mitigation levers:
- Cache catalogs by digest; only refresh on list_changed.
- Provide stable tool IDs and split large surfaces into multiple MCP servers (capability partitioning).
- Apply policy gating to avoid exporting high-risk or rarely used tools by default.

Reference: MCP spec server/tools, server/resources, server/prompts.
