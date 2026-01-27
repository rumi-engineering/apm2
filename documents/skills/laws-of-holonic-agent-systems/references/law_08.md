---
id: LAW-08
name: Verifier Economics (Goodhart Resistance)
effective_date: 2026-01-27
citation: apm2://skills/laws-of-holonic-agent-systems
status: active
---

# Law 08: Verifier Economics (Goodhart Resistance)

## The Law
Optimization pressure will exploit proxy gaps; therefore, **only gate what you can defend.**

## Operationalization
1. **Adversarial Suites:** Use rotating evaluation sets and adversarial tests to prevent "gaming" the gates.
2. **Hard Constraints:** Separate safety and SoD invariants from performance objectives.
3. **Holdouts:** Maintain out-of-band evaluation samples to detect model overfitting to specific codebase patterns.

## Rationale
"When a measure becomes a target, it ceases to be a good measure." The system must assume the agent network will optimize for whatever proxies are set, requiring robust, non-gameable verification.
