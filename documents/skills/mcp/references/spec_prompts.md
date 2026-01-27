# MCP Server Features: Prompts

```yaml
# server_features_prompts.yaml
revision: "2025-11-25"

capability:
  name: "prompts"
  fields:
    listChanged: "bool (server may emit notifications/prompts/list_changed)"

methods:
  - "prompts/list"
  - "prompts/get"
  - "notifications/prompts/list_changed"

prompt_definition:
  required: ["name"]
  optional: ["title", "description", "icons[]", "arguments[]"]
prompt_argument:
  fields: ["name", "description?", "required?"]
prompt_messages:
  message:
    fields: ["role(user|assistant)", "content(one-of content types)", "annotations?"]
  content_types:
    - text
    - image
    - audio
    - resource  # embedded resource
completion_integration:
  - "prompts/get arguments may be auto-completed via completion/complete"
pagination:
  - "prompts/list supports cursor + nextCursor"
```
