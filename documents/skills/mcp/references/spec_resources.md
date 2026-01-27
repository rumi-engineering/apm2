# MCP Server Features: Resources

```yaml
# server_features_resources.yaml
revision: "2025-11-25"

capability:
  name: "resources"
  fields:
    subscribe: "bool (supports resources/subscribe + notifications/resources/updated)"
    listChanged: "bool (server may emit notifications/resources/list_changed)"

methods:
  - "resources/list"
  - "resources/read"
  - "resources/subscribe"
  - "resources/unsubscribe"
  - "resources/templates/list"
  - "notifications/resources/list_changed"
  - "notifications/resources/updated"

resource_definition:
  required: ["uri", "name"]
  optional: ["title", "description", "icons[]", "mimeType", "size", "annotations"]
resource_contents:
  content_items:
    text:
      fields: ["uri", "mimeType?", "text"]
    blob:
      fields: ["uri", "mimeType?", "blob(base64)"]
resource_templates:
  uriTemplate: "RFC6570 URI template"
  completion_integration: "template arguments may be auto-completed via completion/complete"
annotations:
  fields:
    audience: "array of {'user','assistant'}"
    priority: "float 0.0..1.0"
    lastModified: "RFC3339/ISO8601 timestamp"
uri_scheme_guidance:
  https:
    - "use only when client can fetch directly; otherwise prefer other/custom scheme"
  file:
    - "filesystem-like; may represent virtual fs; may use XDG MIME types (e.g., inode/directory)"
  git: ["git version control integration"]
  custom:
    - "must conform to RFC3986"

subscription_behavior:
  - "resources/subscribe registers interest in changes for a specific uri"
  - "notifications/resources/updated notifies subscribers that content changed for a uri"
```
