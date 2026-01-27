---
id: LAW-13
name: Semantic Contracting
effective_date: 2026-01-27
citation: apm2://skills/laws-of-holonic-agent-systems
status: active
---

# Law 13: Semantic Contracting

## The Law
All quantitative and protocol-relevant fields MUST be typed, unitful, and canonicalized; ambiguous strings are defects at the boundary.

## Operationalization
1. **Typed Quantities:** Use standard (value + unit + scale) encoding for all numbers.
2. **Stable Enums:** Protocol states must use versioned enums, not free-form text.
3. **Canonicalization:** Objects must be canonicalized (e.g., JCS) before hashing or signing to avoid spurious diffs.

## Rationale
Ambiguity is the enemy of automation. By forcing strict semantic typing, the system reduces the probability of misinterpretation between different agents and tools.
