---
id: LAW-02
name: Observable Context Sufficiency
effective_date: 2026-01-27
citation: apm2://skills/laws-of-holonic-agent-systems
status: active
---

# Law 02: Observable Context Sufficiency

## The Law
"Mutual Information" in the context channel is optimized via **measurable surrogates**, as sufficiency cannot be tested directly.

## Operationalization
The system must track and optimize for the following control objectives:
1. **Pack-Miss Rate:** Frequency of agents requesting context not present in their ContextPack.
2. **Unplanned Tool Calls:** Unauthorized discovery actions taken to compensate for missing information.
3. **Defect Escape Rate:** Correlating missing context with downstream logic errors.
4. **Agent "Stuck" Proxies:** Tracking rollbacks and task resets as indicators of context poverty.
5. **Subtask Isolation:** Decomposed subtasks MUST receive scoped ContextPacks; monolithic trace injection across subtask boundaries is a context defect (CONTEXT_BLEED).
6. **Explicit Inter-Subtask Interface:** State shared between subtasks flows via typed summaries/receipts (LAW-07), not implicit context bleed.

## Rationale
Since context windows are finite and precious, the "quality" of a context pack is not subjective. It is a measurable engineering parameter that determines the probability of task success.
