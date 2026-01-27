# Defects in Holonic Agent Systems: An Evidence-First Textbook
## Defect Theory, Taxonomy, Schemas, Gates, and Closed-Loop Remediation for Agent-Native Networks
**v1.0 (draft)** — 2026-01-26

> Normative keywords (MUST, SHOULD, MAY) are interpreted as described in RFC 2119.


# VOLUME 8 — Tooling Reference: CLI, Schemas, Playbooks

## 8.1 Defect CLI Surface
The defect CLI MUST support: submit, attach evidence, compute fingerprint, merge duplicates, generate reports, and compile remediation plans. The CLI MUST have a stable structured-output mode for agents and a human-readable mode for audits. Output contracts are versioned and golden-tested.

## 8.2 ContextPack Tooling
Tooling MUST support: build pack, lint pack, enforce pack at runtime, and measure pack token size. Packs must include explicit allowlists for files, commands, and network access. Pack enforcement is deny-by-default.

## 8.3 Gate and Receipt Tooling
Gate tooling MUST generate receipts and store them in evidence stores. Receipts MUST include all inputs needed to validate claims of execution. Receipt verification MUST be available as a deterministic CLI command.

## 8.4 Operational Playbooks
Playbooks are executable remediation sequences for runtime incidents, capability revocation, rollback, and quarantine. Playbooks MUST declare inputs, outputs, permissions, evidence requirements, and stop conditions. A playbook that cannot emit evidence is defective.

## 8.5 Reporting and Aggregation
Reports are generated from defect events, not from free-form summaries. Reports MUST include: top clusters, recurrence rates, time-to-detection, time-to-fix, verifier flake rate, and context inefficiency metrics. Reports drive roadmap selection and refinement compiler updates.
