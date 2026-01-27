# Rust Schema Sanitization (Provider Interop)

## Purpose
MCP servers must often serve tools to multiple clients (Claude, Gemini, Codex) with varying levels of JSON Schema support. This document outlines the sanitization patterns required to ensure tool availability across the provider matrix.

## The Visitor Pattern
Implement a recursive visitor for `serde_json::Value` (representing the JSON Schema) that transforms non-compliant features into safe alternatives.

### Gemini-specific Sanitization
Gemini's tool engine is sensitive to specific JSON Schema keywords.

| Problematic Feature | Safe Alternative | Why? |
| :--- | :--- | :--- |
| `additionalProperties: true` | `additionalProperties: false` | Gemini requires closed schemas for deterministic tool calling. |
| `type: ["string", "null"]` | `type: "string", nullable: true` | Array-form types often cause "Invalid Schema" errors. |
| `$ref` (internal) | Inline the definition | Many clients do not implement a schema resolver for MCP tool catalogs. |
| `anyOf` / `oneOf` | Flatten to the most specific type | Can lead to "ambiguous schema" errors or model confusion. |
| Empty `inputSchema` | `{ type: "object", properties: {} }` | Some clients reject `null` or empty schemas for tools. |

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
            // Force additionalProperties: false
            obj.insert("additionalProperties".into(), false.into());
            
            // Handle array-form types
            if let Some(t) = obj.get_mut("type") {
                if t.is_array() {
                    // logic to extract first non-null type and set nullable: true
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
- **Global Minimum**: Always apply a "Global Minimum" sanitizer that removes `$schema` keywords (often ignored/problematic) and ensures `type` fields are visible ASCII.
