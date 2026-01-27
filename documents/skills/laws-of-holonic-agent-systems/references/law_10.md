---
id: LAW-10
name: Anti-Entropy & Merge Semantics
effective_date: 2026-01-27
citation: apm2://skills/laws-of-holonic-agent-systems
status: active
---

# Law 10: Anti-Entropy & Merge Semantics

## The Law
Convergence in a distributed holarchy requires an **explicit anti-entropy protocol** to resolve forked truths.

## Operationalization
1. **Merge Operators:** Define how conflicting facts are resolved (e.g., LWW, authority-tier selection).
2. **Conflict Recording:** Reconciliation failures must be recorded as explicit defects, not silent drops.
3. **Consistency Tiers:** Allow local divergence but mandate periodic global reconciliation to maintain a single source of truth.

## Rationale
In a system of billions of holons, local copies of state will inevitably drift. Without a formal protocol for convergence, the network will dissolve into inconsistent "local realities" that cannot coordinate.
