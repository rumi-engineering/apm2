---
id: LAW-06
name: MDL as a Gated Budget
effective_date: 2026-01-27
citation: apm2://skills/laws-of-holonic-agent-systems
status: active
---

# Law 06: MDL as a Gated Budget

## The Law
Minimal Description Length (MDL) is a hard resource constraint enforced by gates. If the description of "how to work" exceeds the context window ($W$), the agent will fail.

## Operationalization
1. **API Brief Limits:** Public API surfaces must be describable in $\le X$ tokens.
2. **ContextPack Ceilings:** Total token count for a ContextPack must not exceed $Y$.
3. **Triggered Refactoring:** When MDL exceeds budget, the system MUST emit a refactoring task to decompose the primitive or optimize the interface.

## Rationale
In agent-native engineering, "clean code" is not aesthetic; it is a functional requirement for cognitive reach. A codebase that cannot fit in a context window is effectively broken.
