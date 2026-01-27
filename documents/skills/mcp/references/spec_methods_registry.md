# MCP Methods Registry

```yaml
# methods_registry.yaml
# Compact method catalog for MCP revision 2025-11-25.

revision: "2025-11-25"
jsonrpc: "2.0"

methods:
  # Lifecycle
  initialize:
    kind: request
    direction: client_to_server
    params: ["protocolVersion", "capabilities", "clientInfo"]
    result: ["protocolVersion", "capabilities", "serverInfo", "instructions?"]
  notifications/initialized:
    kind: notification
    direction: client_to_server

  # Base utilities
  ping:
    kind: request
    direction: either
    params: []
    result: {}
  notifications/cancelled:
    kind: notification
    direction: either
    params: ["requestId", "reason?"]
  notifications/progress:
    kind: notification
    direction: either
    params: ["progressToken", "progress", "total?"]
  # (progressToken often travels in params._meta on the request that creates work)

  # Server features
  tools/list:
    kind: request
    direction: client_to_server
    params: ["cursor?"]
    result: ["tools[]", "nextCursor?"]
  tools/call:
    kind: request
    direction: client_to_server
    params: ["name", "arguments", "_meta?", "task?"]
    result:
      normal: ["content[]", "isError?", "structuredContent?"]
      task_augmented: ["task"]
  notifications/tools/list_changed:
    kind: notification
    direction: server_to_client

  resources/list:
    kind: request
    direction: client_to_server
    params: ["cursor?"]
    result: ["resources[]", "nextCursor?"]
  resources/read:
    kind: request
    direction: client_to_server
    params: ["uri"]
    result: ["contents[]"]
  resources/subscribe:
    kind: request
    direction: client_to_server
    params: ["uri"]
    result: {}
  resources/unsubscribe:
    kind: request
    direction: client_to_server
    params: ["uri"]
    result: {}
  resources/templates/list:
    kind: request
    direction: client_to_server
    params: ["cursor?"]
    result: ["resourceTemplates[]", "nextCursor?"]
  notifications/resources/list_changed:
    kind: notification
    direction: server_to_client
  notifications/resources/updated:
    kind: notification
    direction: server_to_client
    params: ["uri"]

  prompts/list:
    kind: request
    direction: client_to_server
    params: ["cursor?"]
    result: ["prompts[]", "nextCursor?"]
  prompts/get:
    kind: request
    direction: client_to_server
    params: ["name", "arguments?"]
    result: ["messages[]", "description?"]
  notifications/prompts/list_changed:
    kind: notification
    direction: server_to_client

  completion/complete:
    kind: request
    direction: client_to_server
    params: ["ref", "argument", "value"]
    result: ["completion"]

  logging/setLevel:
    kind: request
    direction: client_to_server
    params: ["level"]
    result: {}
  notifications/message:
    kind: notification
    direction: server_to_client
    params: ["level", "logger?", "data"]

  # Client features (server-initiated requests)
  roots/list:
    kind: request
    direction: server_to_client
    params: []
    result: ["roots[]"]
  notifications/roots/list_changed:
    kind: notification
    direction: client_to_server

  sampling/createMessage:
    kind: request
    direction: server_to_client
    params: ["messages[]", "systemPrompt?", "maxTokens?", "temperature?", "stopSequences?", "metadata?", "modelPreferences?"]
    result: ["role", "content", "model", "stopReason?"]
  elicitation/create:
    kind: request
    direction: server_to_client
    params:
      common: ["message", "mode?"]
      form_mode: ["requestedSchema"]
      url_mode: ["url", "elicitationId"]
    result: ["action", "content?"]

  notifications/elicitation/complete:
    kind: notification
    direction: server_to_client
    params: ["elicitationId"]

  # Tasks utility (experimental in 2025-11-25)
  tasks/list:
    kind: request
    direction: either
    params: ["cursor?"]
    result: ["tasks[]", "nextCursor?"]
  tasks/get:
    kind: request
    direction: either
    params: ["taskId"]
    result: ["task"]
  tasks/result:
    kind: request
    direction: either
    params: ["taskId"]
    result: ["result"]   # category-specific (e.g., ToolResult for tools/call tasks)
  tasks/cancel:
    kind: request
    direction: either
    params: ["taskId"]
    result: {}
  notifications/tasks/status:
    kind: notification
    direction: receiver_to_requestor
    params: ["taskId", "status", "statusMessage?"]
```
