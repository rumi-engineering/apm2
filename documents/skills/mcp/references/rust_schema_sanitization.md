# Rust Schema Sanitization (Provider Interop)

## Purpose
MCP servers must often serve tools to multiple clients (Claude, Gemini, Codex) with varying levels of JSON Schema support. This document outlines the sanitization patterns required to ensure tool availability across the provider matrix.

## The Visitor Pattern
Implement a recursive visitor for `serde_json::Value` (representing the JSON Schema) that transforms non-compliant features into safe alternatives.

### Gemini-specific Sanitization
Gemini CLI performs server-side discovery and then sanitizes tool schemas before exposing them to the model. Design schemas assuming the client may rewrite them.

| Problematic Feature | Safe Alternative | Why? |
| :--- | :--- | :--- |
| `$schema` keywords | Omit `$schema` entirely | Gemini CLI strips `$schema` keys during schema processing. |
| `additionalProperties` | Avoid relying on it for semantics | Gemini CLI strips `additionalProperties` during schema processing. |
| `$ref` (internal) | Inline the definition | Many clients do not implement a schema resolver for MCP tool catalogs. |
| `anyOf` / `oneOf` | Prefer simple `type` + `properties` | Some clients degrade or reject complex unions; also increases model confusion. |
| `default` inside `anyOf` branches | Avoid defaults that change meaning | Gemini CLI removes defaults inside certain `anyOf` shapes (Vertex AI compatibility). |
| “Nullable” unions (`type: ["T","null"]`) | Model optionality via `required` | Keeps schemas closer to the lowest common denominator. |
| No-parameter tools | `{ "type": "object", "additionalProperties": false }` | Spec-recommended; accepted by major clients. |

### Codex-specific Sanitization
- **Description Length**: Codex may truncate descriptions longer than 1024 characters.
- **Top-level type**: Always ensure `type: "object"` is present at the root of `inputSchema`.

## Implementation Example (Pseudo-Rust)
```rust
pub trait SchemaSanitizer {
    fn sanitize(&self, schema: &mut serde_json::Value);
}

pub struct GeminiSanitizer;

impl SchemaSanitizer for GeminiSanitizer {
    fn sanitize(&self, schema: &mut serde_json::Value) {
        if let Some(obj) = schema.as_object_mut() {
            // Match Gemini CLI sanitization tendencies: remove `$schema` and `additionalProperties`.
            obj.remove("$schema");
            obj.remove("additionalProperties");

            // Vertex/Gemini compatibility: remove `default` fields inside anyOf branches.
            if let Some(any_of) = obj.get_mut("anyOf").and_then(|v| v.as_array_mut()) {
                for branch in any_of {
                    if let Some(branch_obj) = branch.as_object_mut() {
                        branch_obj.remove("default");
                    }
                }
            }
            
            // Recurse into properties
            if let Some(props) = obj.get_mut("properties").and_then(|p| p.as_object_mut()) {
                for (_, subschema) in props {
                    self.sanitize(subschema);
                }
            }
        }
    }
}
```

## Policy Recommendation
- **Detection**: Use the `clientInfo.name` from the `initialize` request to select the appropriate `SchemaSanitizer`.
- **Global Minimum**: Always remove `$schema` keys and ensure every tool `inputSchema` is a JSON Schema object with a stable top-level `type: "object"` (even when there are no parameters).
