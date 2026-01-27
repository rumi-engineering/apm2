---
id: LAW-03
name: Monotone Ledger vs. Overwritable Projection
effective_date: 2026-01-27
citation: apm2://skills/laws-of-holonic-agent-systems
status: active
---

# Law 03: Monotone Ledger vs. Overwritable Projection

## The Law
The **substrate ledger of facts** (patches, receipts, decisions) is monotone and commutative within a declared merge algebra; the **system state** (codebase, workspace) is a non-monotone projection.

## Operationalization
1. **Fact Submission:** Agents produce patches and evidence, not final state rewrites.
2. **Merge Algebra:** Every fact MUST declare its merge operator or conflict rule class to eliminate hidden ordering dependencies.
3. **Compaction/GC:** The system must implement periodic compaction to keep the ledger within the context window ($W$) limits while preserving provenance.

## Rationale
Separating the append-only substrate from the derived projection allows for perfect auditability and recovery. It transforms "editing" into a series of verifiable additions, which is more robust for distributed agents.
