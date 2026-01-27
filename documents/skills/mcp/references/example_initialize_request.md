# Example: Initialize Request

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "initialize",
  "params": {
    "protocolVersion": "2025-11-25",
    "capabilities": {
      "roots": {
        "listChanged": true
      },
      "sampling": {},
      "elicitation": {},
      "tasks": {
        "requests": {
          "sampling/createMessage": {},
          "elicitation/create": {}
        }
      }
    },
    "clientInfo": {
      "name": "apm2-mcp-client",
      "version": "0.1.0"
    }
  }
}
```
