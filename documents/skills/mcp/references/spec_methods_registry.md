# MCP Methods Registry

```yaml
# methods_registry.yaml
# Compact implementer-oriented method catalog for MCP revision 2025-11-25.
# Source of truth for exact request/response shapes: the MCP schema reference.

revision: "2025-11-25"
jsonrpc: "2.0"

methods:
  # Lifecycle
  initialize:
    kind: request
    direction: client_to_server
    params_required: ["protocolVersion", "capabilities", "clientInfo"]
    result_required: ["protocolVersion", "capabilities", "serverInfo"]
    result_optional: ["instructions"]
    spec: "basic/lifecycle"
  notifications/initialized:
    kind: notification
    direction: client_to_server
    spec: "basic/lifecycle"

  # Base utilities
  ping:
    kind: request
    direction: either
    params: "none"
    result: "empty object"
    spec: "basic/utilities/ping"
  notifications/cancelled:
    kind: notification
    direction: either
    params_required: ["requestId"]
    params_optional: ["reason"]
    spec: "basic/utilities/cancellation"
  notifications/progress:
    kind: notification
    direction: either
    params_required: ["progressToken", "progress"]
    params_optional: ["total", "message"]
    spec: "basic/utilities/progress"
  # (progressToken often travels in params._meta on the request that creates work)

  # Server features
  tools/list:
    kind: request
    direction: client_to_server
    capability: "tools"
    params_optional: ["cursor"]
    result_required: ["tools"]
    result_optional: ["nextCursor"]
    spec: "server/tools"
  tools/call:
    kind: request
    direction: client_to_server
    capability: "tools"
    params_required: ["name", "arguments"]
    params_optional: ["_meta", "task"]
    result_normal: "CallToolResult"
    result_task_augmented: "CreateTaskResult (task)"
    spec: "server/tools + basic/utilities/tasks"
  notifications/tools/list_changed:
    kind: notification
    direction: server_to_client
    capability: "tools.listChanged"
    spec: "server/tools"

  resources/list:
    kind: request
    direction: client_to_server
    capability: "resources"
    params_optional: ["cursor"]
    result_required: ["resources"]
    result_optional: ["nextCursor"]
    spec: "server/resources"
  resources/read:
    kind: request
    direction: client_to_server
    capability: "resources"
    params_required: ["uri"]
    result_required: ["contents"]
    spec: "server/resources"
  resources/subscribe:
    kind: request
    direction: client_to_server
    capability: "resources.subscribe"
    params_required: ["uri"]
    result: "empty object"
    spec: "server/resources"
  resources/unsubscribe:
    kind: request
    direction: client_to_server
    capability: "resources.subscribe"
    params_required: ["uri"]
    result: "empty object"
    spec: "server/resources"
  resources/templates/list:
    kind: request
    direction: client_to_server
    capability: "resources"
    params: "none"
    result_required: ["resourceTemplates"]
    spec: "server/resources"
  notifications/resources/list_changed:
    kind: notification
    direction: server_to_client
    capability: "resources.listChanged"
    spec: "server/resources"
  notifications/resources/updated:
    kind: notification
    direction: server_to_client
    capability: "resources.subscribe"
    params_required: ["uri"]
    spec: "server/resources"

  prompts/list:
    kind: request
    direction: client_to_server
    capability: "prompts"
    params_optional: ["cursor"]
    result_required: ["prompts"]
    result_optional: ["nextCursor"]
    spec: "server/prompts"
  prompts/get:
    kind: request
    direction: client_to_server
    capability: "prompts"
    params_required: ["name"]
    params_optional: ["arguments"]
    result_required: ["messages"]
    result_optional: ["description"]
    spec: "server/prompts"
  notifications/prompts/list_changed:
    kind: notification
    direction: server_to_client
    capability: "prompts.listChanged"
    spec: "server/prompts"

  completion/complete:
    kind: request
    direction: client_to_server
    capability: "completions"
    params_required: ["ref", "argument"]
    params_optional: ["context"]
    result_required: ["completion"]
    spec: "server/utilities/completion"

  logging/setLevel:
    kind: request
    direction: client_to_server
    capability: "logging"
    params_required: ["level"]
    result: "empty object"
    spec: "server/utilities/logging"
  notifications/message:
    kind: notification
    direction: server_to_client
    capability: "logging"
    params_required: ["level", "data"]
    params_optional: ["logger"]
    spec: "server/utilities/logging"

  # Client features (server-initiated requests)
  roots/list:
    kind: request
    direction: server_to_client
    capability: "roots"
    params: "none"
    result_required: ["roots"]
    spec: "client/roots"
  notifications/roots/list_changed:
    kind: notification
    direction: client_to_server
    capability: "roots.listChanged"
    spec: "client/roots"

  sampling/createMessage:
    kind: request
    direction: server_to_client
    capability: "sampling"
    params_required: ["messages"]
    params_optional:
      - "systemPrompt"
      - "includeContext"
      - "maxTokens"
      - "temperature"
      - "stopSequences"
      - "metadata"
      - "modelPreferences"
      - "tools"
      - "toolChoice"
    result_required: ["role", "content", "model", "stopReason"]
    spec: "client/sampling"
  elicitation/create:
    kind: request
    direction: server_to_client
    capability: "elicitation"
    params_required: ["mode", "message"]
    params_optional: ["requestedSchema", "url", "elicitationId"]
    result_required: ["action"]
    result_optional: ["content"]
    spec: "client/elicitation"

  notifications/elicitation/complete:
    kind: notification
    direction: server_to_client
    params_required: ["elicitationId"]
    spec: "client/elicitation"

  # Tasks utility (experimental in 2025-11-25)
  tasks/list:
    kind: request
    direction: either
    capability: "tasks.list"
    params_optional: ["cursor"]
    result_required: ["tasks"]
    result_optional: ["nextCursor"]
    spec: "basic/utilities/tasks"
  tasks/get:
    kind: request
    direction: either
    capability: "tasks"
    params_required: ["taskId"]
    result: "Task"
    spec: "basic/utilities/tasks"
  tasks/result:
    kind: request
    direction: either
    capability: "tasks"
    params_required: ["taskId"]
    result: "Domain result (e.g., CallToolResult) after task completes (may block until terminal status)"
    spec: "basic/utilities/tasks"
  tasks/cancel:
    kind: request
    direction: either
    capability: "tasks.cancel"
    params_required: ["taskId"]
    result: "Task"
    spec: "basic/utilities/tasks"
  notifications/tasks/status:
    kind: notification
    direction: receiver_to_requestor
    params: "Task (full task object)"
    spec: "basic/utilities/tasks"
```
