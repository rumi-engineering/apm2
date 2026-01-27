# Gemini CLI MCP Integration Notes

## Supported transports
- stdio (subprocess via stdin/stdout).
- SSE.
- streamable HTTP.

## Discovery and execution (implementation shape)
- Discovery iterates configured servers (`settings.json` → `mcpServers`).
- Establishes transport connections and fetches tool definitions (`tools/list`).
- Discovers resources via `resources/list`.
- Sanitizes and validates tool schemas for Gemini API compatibility.
- Registers tools globally with conflict resolution and name normalization.

## Resources in chat (`@` syntax)
- Gemini CLI supports referencing MCP resources using `@server://resource/path`.
- On message submission, Gemini CLI calls `resources/read` and injects the resource content into the prompt it sends to the model.

## Tool registration details (non-obvious interop)
### Tool name normalization
Gemini CLI normalizes tool names when registering them:
- Invalid characters (non-alphanumeric, underscore, dot, hyphen) are replaced with underscores.
- Names longer than 63 characters are truncated with a middle replacement marker (`___`).

### Conflict resolution across servers
When multiple servers expose the same tool name:
1. First registration wins the unprefixed name.
2. Subsequent registrations are prefixed as `serverName__toolName`.
3. The tool registry tracks mappings between server names and the tools that were actually registered.

### Schema processing (Gemini API compatibility)
Gemini CLI applies schema sanitization during discovery, including:
- removing `$schema` properties
- stripping `additionalProperties`
- removing default values in certain `anyOf` shapes (Vertex AI compatibility)

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
