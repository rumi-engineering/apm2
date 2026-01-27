# Example: Tools List Response

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "tools": [
      {
        "name": "apm2.kernel.query",
        "description": "Query APM2 kernel projections (read-only).",
        "inputSchema": {
          "type": "object",
          "properties": {
            "query": {
              "type": "string"
            },
            "args": {
              "type": "object"
            }
          },
          "required": [
            "query"
          ],
          "additionalProperties": false
        }
      }
    ]
  }
}
```
