---
id: LAW-12
name: Bounded Search and Termination Discipline
effective_date: 2026-01-27
citation: apm2://skills/laws-of-holonic-agent-systems
status: active
---

# Law 12: Bounded Search and Termination Discipline

## The Law
Any exploration MUST run under a lease with a termination policy; failure to converge within budget is a defect.

## Operationalization
1. **Budgets:** Every plan carries a hard resource budget (time, tokens, cost).
2. **Progress Signals:** Periodic telemetry to detect "looping" or stagnant reasoning.
3. **Stop Conditions:** Explicit criteria for success or "give up" states.
4. **Defect Tracking:** Non-convergent loops produce a `UNBOUNDED_SEARCH` DefectRecord.
5. **Repetition Detection:** Progress telemetry MUST detect template-like repetitive reasoning (entropy collapse, reward variance flatlining) as a termination trigger and defect signal.
6. **Degeneration as Defect:** Detected echo-trap patterns produce `REASONING_DEGENERATION` DefectRecords.

## Rationale
Stochastic planners can easily enter infinite feedback loops or unproductive search paths. Forcing termination discipline protects the system's resource availability.
