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
4. **Monitorability Conservation:** Oversight and interpretability signals MUST NOT be directly incorporated into optimization objectives. Monitor channels must be structurally isolated from reward/training signals. Violation produces MONITOR_GAMING defect.
5. **Audit Channel Integrity:** If a monitor is used for accountability/safety (not performance), its features must be excluded from gradient updates.

## Rationale
"When a measure becomes a target, it ceases to be a good measure." The system must assume the agent network will optimize for whatever proxies are set, requiring robust, non-gameable verification. Monitoring channels are themselves optimization targets; training that rewards monitor evasion destroys the very interpretability needed for oversight.
