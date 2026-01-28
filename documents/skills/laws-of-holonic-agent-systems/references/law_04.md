---
id: LAW-04
name: Stochastic Stability
effective_date: 2026-01-27
citation: apm2://skills/laws-of-holonic-agent-systems
status: active
---

# Law 04: Stochastic Stability

## The Law
Since both transducers (agents) and verifiers (tests) are stochastic, stability is achieved only through the binding of three elements: **Stability = (Contract + Receipt + Evidence).**

## Operationalization
1. **Determinism Classes:** Every contract MUST specify if it is deterministic or probabilistic.
2. **Flakiness Management:** Nondeterministic (flaky) failures are treated as first-class defects that puncture the determinism envelope.
3. **Binding:** Authority is never granted to a claim alone; it must be bound to a signed receipt and the underlying raw evidence.
4. **Causal Determinism (HLC):** Event ordering MUST rely on Hybrid Logical Clocks (HLC) to preserve causal determinism across distributed nodes, preventing state divergence during network partitions.

## Rationale
Trusting the "word" of an agent is mathematically unsound. Stability requires grounding cognitive outputs in deterministic, repeatable evidence.
