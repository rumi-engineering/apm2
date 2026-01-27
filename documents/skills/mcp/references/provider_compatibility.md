# MCP Provider Compatibility Matrix

```yaml
# compatibility_matrix.yaml
# Interop targets for APM2 MCP server/client cores.

as_of: "2026-01-27"
mcp_protocol_revision_target: "2025-11-25"

clients:
  claude_code:
    docs: "https://code.claude.com/docs/en/mcp"
    transports:
      http: { supported: true, recommended: true }
      sse: { supported: true, deprecated: true }
      stdio: { supported: true, local_only: true }
    dynamic_updates:
      list_changed: { tools: true, resources: true, prompts: true }
    config:
      project_file: ".mcp.json"
      user_file: "~/.claude.json"
      managed_file_linux: "/etc/claude-code/managed-mcp.json"
    controls:
      allowlist_denylist: { supported: true, keys: ["allowedMcpServers", "deniedMcpServers"] }
      env_var_expansion: { supported: true, syntax: ["${VAR}", "${VAR:-default}"] }
    notes:
      - "MCP tool output warning threshold and environment override exist (client-side)."

  openai_codex:
    docs: "https://developers.openai.com/codex/mcp"
    transports:
      streamable_http: { supported: true }
      stdio: { supported: true }
    config:
      user_file: "~/.codex/config.toml"
      project_file: ".codex/config.toml (trusted projects)"
      table: "[mcp_servers.<name>]"
    controls:
      tool_allow_deny:
        enabled_tools: "allowlist"
        disabled_tools: "denylist (applied after enabled_tools)"
      timeouts:
        startup_timeout_sec: { default: 10 }
        tool_timeout_sec: { default: 60 }
      http_auth:
        bearer_token_env_var: true
        http_headers: true
        env_http_headers: true
      oauth:
        login_command: "codex mcp login <server-name>"
        callback_port_key: "mcp_oauth_callback_port"

  gemini_cli:
    docs: "https://geminicli.com/docs/tools/mcp-server/"
    transports:
      stdio: { supported: true }
      sse: { supported: true }
      streamable_http: { supported: true }
    config:
      file: "settings.json"
      servers_key: "mcpServers"
      global_key: "mcp"
      per_server_required_one_of: ["command", "url", "httpUrl"]
    controls:
      trust_flag: "trust=true bypasses confirmations"
      include_exclude_tools: ["includeTools", "excludeTools (precedence)"]
      global_allow_exclude: ["mcp.allowed", "mcp.excluded"]
      timeouts:
        per_server_timeout_ms: { default: 600000 }
      env_var_expansion: { supported: true, syntax: ["$VAR", "${VAR}"] }

schema_sanitization_quirks:
  gemini:
    - "Often rejects 'additionalProperties: true' or '$ref' in tool input schemas."
    - "Prefers explicit property types; 'anyOf' / 'oneOf' may cause degradation."
  codex:
    - "May truncate long 'description' fields in tool definitions."
    - "Requires 'type: object' for inputSchema even if no properties are defined."
  claude:
    - "Robust JSON Schema support, but excessive schema complexity increases token overhead significantly."
    - "Supports 'outputSchema' for structured results."
```
