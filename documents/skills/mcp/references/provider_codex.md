# OpenAI Codex MCP Integration Notes

## Supported transports
- stdio servers (local subprocess).
- streamable HTTP servers.

## Configuration
- Default user config: `~/.codex/config.toml`.
- Project config: `.codex/config.toml` (trusted projects).
- Table per server: `[mcp_servers.<server-name>]`.

## STDIO server fields
- `command` (required)
- `args` (optional)
- `env` (optional)
- `env_vars` (optional): allow+forward selected environment variables
- `cwd` (optional)

## Streamable HTTP server fields
- `url` (required)
- `bearer_token_env_var` (optional): env var name used to populate `Authorization: Bearer ...`
- `http_headers` (optional): static header map
- `env_http_headers` (optional): header map where values are loaded from environment variables

## Per-server controls
- `startup_timeout_sec` (default 10)
- `tool_timeout_sec` (default 60)
- `enabled` (default true)
- `enabled_tools` (allowlist)
- `disabled_tools` (denylist; applied after enabled_tools)

## OAuth
- For OAuth-capable servers: `codex mcp login <server-name>`.
- `mcp_oauth_callback_port` (top-level) for static callback port requirements.

Source: https://developers.openai.com/codex/mcp
