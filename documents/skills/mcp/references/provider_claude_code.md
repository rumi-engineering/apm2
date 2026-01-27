# Claude Code MCP Integration Notes

## Supported transports
- HTTP (recommended for remote servers).
- SSE (deprecated transport; supported).
- stdio (local subprocess servers).

## Configuration locations
- Project scope: `.mcp.json` at project root.
- User / local scope: `~/.claude.json` (also stores local-scoped servers per project path).
- Managed (Linux/WSL): `/etc/claude-code/managed-mcp.json` (exclusive control).

## `.mcp.json` format (project scope)
Top-level key: `mcpServers`.
Each entry includes one of:
- stdio: `command`, `args`, `env`
- http: `type=http`, `url`, `headers`
- sse: `type=sse`, `url`, `headers`

Environment variable expansion supported in: `command`, `args`, `env`, `url`, `headers` using:
- `${VAR}`
- `${VAR:-default}`

## CLI management
- `claude mcp add --transport http|sse|stdio ...`
- `claude mcp list|get|remove`
- In-session command: `/mcp` (status + auth flows).

## Dynamic tool updates
- Supports MCP `list_changed` notifications; on receipt, client refreshes available tools/prompts/resources.

## Policy controls (enterprise)
- `managed-mcp.json`: fixed server set; users cannot modify.
- Managed settings allow:
  - `allowedMcpServers` and `deniedMcpServers`
  - restriction by `serverName` OR exact `serverCommand` OR `serverUrl` wildcard pattern.
  - denylist precedence over allowlist.

Source: https://code.claude.com/docs/en/mcp
