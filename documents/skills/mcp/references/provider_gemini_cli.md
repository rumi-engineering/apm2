# Gemini CLI MCP Integration Notes

## Supported transports
- stdio (subprocess via stdin/stdout).
- SSE.
- streamable HTTP.

## Discovery and execution (implementation shape)
- Discovery iterates configured servers (`settings.json` → `mcpServers`).
- Establishes transport connections and fetches tool definitions (`tools/list`).
- Sanitizes and validates tool schemas for Gemini API compatibility.
- Registers tools globally with conflict resolution.
- Discovers resources via `resources/list`; resources can be referenced with `@<uri>` syntax and fetched via `resources/read`.

## Configuration (`settings.json`)
Two layers:
- Global `mcp` object:
  - `mcp.serverCommand`
  - `mcp.allowed` (allowlist of server names)
  - `mcp.excluded` (exclude list)

- Per-server `mcpServers` object:
  - required (exactly one): `command` (stdio) OR `url` (SSE) OR `httpUrl` (streamable HTTP)
  - optional:
    - `args`, `headers`, `env`, `cwd`
    - `timeout` (ms; default 600000)
    - `trust` (bool): bypass confirmations
    - `includeTools` / `excludeTools` (exclude takes precedence)
    - OAuth options exist for remote servers; automatic discovery supported for servers that publish OAuth discovery metadata.

Source: https://geminicli.com/docs/tools/mcp-server/
