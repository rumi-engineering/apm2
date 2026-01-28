---
id: LAW-15
name: Measurement Integrity
effective_date: 2026-01-27
citation: apm2://skills/laws-of-holonic-agent-systems
status: active
---

# Law 15: Measurement Integrity

## The Law
Measurements and receipts MUST be tamper-evident; omission of required evidence is a defect.

## Operationalization
1. **Tamper-Evidence:** All receipts must be signed and hash-chained.
2. **Mandatory Fields:** Admission fails if mandatory evidence fields are empty.
3. **Fail-Closed:** If the measurement pipeline itself is compromised or offline, high-risk transitions must be blocked.
4. **Evaluator Validity:** Gate evaluators MUST be periodically audited for false negatives (cases where correct work is rejected) and instruction-checker alignment.
5. **Evaluator Brittleness as Defect:** Non-deterministic or misaligned evaluators produce `EVALUATOR_DRIFT` DefectRecords; measured performance deltas must account for evaluator uncertainty.

## Rationale
If the evidence can be forged or selectively ignored, the entire holonic SDLC becomes gameable. Measurement integrity is the ultimate substrate of trust.
