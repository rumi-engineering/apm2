# MCP Security Best Practices (extract)

## Threat classes
- **Confused deputy in MCP proxy servers**: occurs when a server uses its own credentials to perform actions on behalf of a client without validating the client's authority for that specific resource.
- Token passthrough hazards (MCP server acting as credential relay).
- Session hijacking + prompt injection on multiplexed sessions (notably HTTP sessions).
- Local MCP server compromise (servers run with client privileges).
- Scope inflation (over-broad scopes increase blast radius).

## Controls (transport and protocol)
- Prefer least-privilege scopes; use incremental scope challenges rather than requesting entire catalogs up front.
- **Tool-to-Resource Bridge**: To reduce "Context Poisoning" and large output hazards, tools SHOULD return `resource_link` items for large artifacts instead of inlining data. This forces the client (and the LLM) to make an explicit, auditable `resources/read` request, providing a natural choke point for security policy enforcement.
- For HTTP sessions: treat `MCP-Session-Id` as a security-sensitive bearer; handle as secret; terminate on suspicious conditions.
- For local servers:
  - Favor `stdio` to constrain access to the single spawning client.
  - If HTTP is used locally, restrict endpoint access (auth tokens, unix domain sockets, IPC ACLs).

## Controls (implementation / UX)
- Surface warnings for dangerous server commands (privilege escalation, destructive filesystem operations, network exfiltration).
- Run locally spawned servers in restrictive sandboxes by default; allow explicit elevation for additional privileges.
- For proxy servers:
  - Maintain per-user registry of approved OAuth client IDs and enforce per-client consent.
  - Validate redirect URIs by exact string match; use cryptographically strong OAuth state tracking.

## References
- MCP Security Best Practices: https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices
- MCP Authorization: https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization
