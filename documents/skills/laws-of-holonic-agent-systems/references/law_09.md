---
id: LAW-09
name: Temporal Pinning & Freshness
effective_date: 2026-01-27
citation: apm2://skills/laws-of-holonic-agent-systems
status: active
---

# Law 09: Temporal Pinning & Freshness

## The Law
The universe is non-stationary (dependencies update, model behavior drifts). **All authoritative artifacts are versioned and time-scoped; freshness is a policy.**

## Operationalization
1. **Source Snapshots:** Agents must reason against a "frozen" moment in time using content-addressed snapshots.
2. **Freshness Policy:** Define explicit expiration dates or drift thresholds for different artifact kinds.
3. **Drift Deltas:** Explicitly manage the gap between "frozen truth" and "current reality" when reconciling state.

## Rationale
Agent reasoning is brittle across time if the environment shifts during an episode. Stability requires pinning the world state so reasoning remains valid throughout the plan execution.
