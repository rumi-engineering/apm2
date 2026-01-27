# Context Minimization Patterns

```yaml
# context_minimization_patterns.yaml

patterns:
  - id: "CTX-PAT-01"
    name: "Catalog pagination + caching"
    mechanism:
      - "server supports cursor+nextCursor on list endpoints"
      - "client caches per-session; refresh only on list_changed"
    reduces: ["catalog_tokens", "repeated_context"]
  - id: "CTX-PAT-02"
    name: "Resource-link over inline content"
    mechanism:
      - "tools/call returns resource_link for large artifacts"
      - "client fetches via resources/read only when needed"
    reduces: ["tool_result_tokens"]
  - id: "CTX-PAT-03"
    name: "Structured results + outputSchema"
    mechanism:
      - "provide outputSchema for tools"
      - "return structuredContent + short serialized text"
    reduces: ["verbose_text_outputs", "parsing_ambiguity"]
  - id: "CTX-PAT-04"
    name: "Partition by authority (multiple servers)"
    mechanism:
      - "separate high-risk tools into distinct MCP servers"
      - "connect only when needed"
    reduces: ["default_surface_size", "blast_radius"]
  - id: "CTX-PAT-05"
    name: "Disable log-to-model by default"
    mechanism:
      - "treat notifications/message as UI log sink, not model context"
    reduces: ["log_tokens", "injection_surface"]
```
