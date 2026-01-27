# MCP Server Features: Tools

```yaml
# server_features_tools.yaml
revision: "2025-11-25"

capability:
  name: "tools"
  fields:
    listChanged: "bool (server may emit notifications/tools/list_changed)"

methods:
  - "tools/list"
  - "tools/call"
  - "notifications/tools/list_changed"

tool_definition:
  required:
    - name
    - description
    - inputSchema
  optional:
    - title
    - icons[]
    - outputSchema
    - annotations
    - execution.taskSupport   # tasks utility integration (required|optional|forbidden)
  inputSchema_rules:
    - "defaults to JSON Schema 2020-12 if $schema is absent"
    - "MUST be a JSON Schema object; MUST NOT be null"
    - "no-params recommended form: {type: object, additionalProperties: false}"
  outputSchema_rules:
    - "optional; defaults to JSON Schema 2020-12 if $schema absent"
    - "if present: server MUST emit structuredContent conforming to outputSchema"
    - "client SHOULD validate structuredContent against outputSchema"
  naming_guidance:
    length: "1..128 (SHOULD)"
    charset: "A-Z a-z 0-9 _ - . (SHOULD be only allowed characters)"
    case_sensitive: true
    uniqueness: "unique within a server (SHOULD)"

tool_result:
  fields:
    content: "array of content items (text|image|audio|resource_link|resource)"
    isError: "bool (optional; indicates tool-level failure)"
    structuredContent: "object (optional)"
  structured_content_backcompat:
    - "tools returning structuredContent SHOULD also include a serialized form in a text content item"
  content_item_types:
    text: { fields: ["type=text", "text", "annotations?"] }
    image: { fields: ["type=image", "data(base64)", "mimeType", "annotations?"] }
    audio: { fields: ["type=audio", "data(base64)", "mimeType", "annotations?"] }
    resource_link: { fields: ["type=resource_link", "uri", "name?", "description?", "mimeType?", "annotations?"] }
    resource: { fields: ["type=resource", "resource:{uri,mimeType?,text?|blob?,annotations?}"] }
  notes:
    - "resource_link URIs returned by tools are not guaranteed to appear in resources/list"

tasks_integration:
  negotiation:
    - "receiver must declare tasks.requests.tools.call in capabilities"
    - "per-tool execution.taskSupport refines whether task augmentation is forbidden|optional|required"
  request_shape:
    tools_call_task_augmented:
      params_additions:
        task:
          ttl: "ms (optional): requested lifetime"
```
