# MCP Authorization: OAuth 2.1

```yaml
# authorization_oauth2_1.yaml
revision: "2025-11-25"
scope: "HTTP-based transports only (stdio uses environment credentials)"

requirements:
  optionality: "Authorization OPTIONAL overall; if supported on HTTP transport, should conform to this spec"
  base_standards:
    - "OAuth 2.1 draft-ietf-oauth-v2-1-13"
    - "RFC8414 (AS metadata)"
    - "RFC7591 (Dynamic Client Registration) [MAY]"
    - "RFC9728 (Protected Resource Metadata) [MUST for servers]"
    - "Client ID Metadata Documents draft (draft-ietf-oauth-client-id-metadata-document-00) [SHOULD for clients/servers]"
roles:
  mcp_server: "OAuth 2.1 resource server"
  mcp_client: "OAuth 2.1 client"
  authorization_server: "issues access tokens"

authorization_server_discovery:
  protected_resource_metadata: "RFC9728"
  server_must:
    - "publish Protected Resource Metadata including authorization_servers[]"
  discovery_mechanisms_server_must_support_one_of:
    - "WWW-Authenticate 401 header with resource_metadata=<url>"
    - "well-known: /.well-known/oauth-protected-resource/<mcp-endpoint-path> OR /.well-known/oauth-protected-resource"
  client_must:
    - "support both discovery mechanisms; prefer resource_metadata URL from WWW-Authenticate when present"
  scope_guidance:
    - "server SHOULD include scope challenge in WWW-Authenticate; client treats it as authoritative for satisfying the request"

client_registration:
  approaches:
    preregistration:
      - "static client credentials provisioned out-of-band"
    client_id_metadata_documents:
      notes:
        - "URL-form client_id implies metadata document fetch"
        - "client MUST validate fetched client_id matches URL exactly"
        - "client MUST validate redirect_uris against metadata document"
        - "client SHOULD cache respecting HTTP caching headers"
    dynamic_client_registration:
      optional: true
      note: "included for backwards compatibility"

token_usage:
  transport: "Authorization header (Bearer token) or negotiated equivalent"
  server_side:
    - "validate token audience + scopes"
    - "support incremental scope via WWW-Authenticate challenges where applicable"

stdio_note:
  - "stdio transport SHOULD NOT implement OAuth flows; credentials come from environment"
```
