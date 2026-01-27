---
id: LAW-07
name: Verifiable Summaries
effective_date: 2026-01-27
citation: apm2://skills/laws-of-holonic-agent-systems
status: active
---

# Law 07: Verifiable Summaries

## The Law
Hierarchical summaries are lossy claims and must be treated as **"Summary Receipts" with explicit evidence pointers.**

## Operationalization
1. **Evidence Pointers:** Every summary must contain stable-ID pointers to the atomic facts it represents.
2. **Deterministic Zoom-In:** A consumer holon must be able to verify any summary part by following pointers to the raw evidence.
3. **Claim Status:** Summaries are treated as claims until their pointers are validated.

## Rationale
Hierarchies compress information, but compression introduces distortion. To prevent error propagation, the path back to the "ground truth" must always be deterministic and traversable.
