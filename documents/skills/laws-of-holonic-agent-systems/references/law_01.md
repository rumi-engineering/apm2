---
id: LAW-01
name: Loop Closure & Gated Promotion
effective_date: 2026-01-27
citation: apm2://skills/laws-of-holonic-agent-systems
status: active
---

# Law 01: Loop Closure & Gated Promotion

## The Law
Exploratory actions may be open-loop within a sandbox, but **no state transition becomes authoritative until it is verified under the appropriate gate set.**

## Operationalization
Loop closure is **risk-tiered**:
1. **Low-Risk Actions:** Allow batched sensing and verification to preserve throughput.
2. **High-Risk/Authoritative Transitions:** Promotion to "shared truth" (mainline) requires explicit, receipt-backed gates.
3. **Receipts:** Every successful gate must produce a machine-readable receipt stored in CAS and linked via the ledger.
4. **Hierarchical Gate Separation:** Planners and Executors MAY operate under distinct gate sets. Planner outputs are verified against capability/feasibility constraints before Executor admission.
5. **Layer-Specific Budgets:** Each control layer carries its own resource budget (LAW-12) and determinism class (LAW-04).

## Rationale
In a stochastic agent environment, unverified transitions lead to state divergence and hallucinated progress. Risk-tiered gating balances the need for exploratory speed with the requirement for system-wide integrity.
