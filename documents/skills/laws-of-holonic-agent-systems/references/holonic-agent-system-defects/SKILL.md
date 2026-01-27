---
name: holonic-agent-system-defects
description: Defect Theory, Taxonomy, Schemas, Gates, and Closed-Loop Remediation for Agent-Native Networks. Interpret any evidence-backed counterexample that causes avoidable work or risk as a defect.
argument-hint: "[query | TCK-XXXXX | PR-XXXX]"
allowed-tools:
  - Read
  - Grep
  - Glob
---

# Defects in Holonic Agent Systems: An Evidence-First Textbook

A *defect* is any evidence-backed counterexample that causes the system to expend avoidable work or accept avoidable risk. This skill provides the normative framework for identifying, recording, and remediating defects within holonic agent networks.

## Core Mandates

- **Evidence-First**: Every defect MUST be backed by an EvidenceBundle (content-addressed artifacts).
- **Zero-Tool Ideal (ZTI)**: Minimize tool calls for context discovery; treat discovery as an inefficiency defect.
- **Contract-Driven**: A defect is a falsifying instance of a contract, intent, or verifier.
- **Closed-Loop**: A defect is only closed when a strengthened verifier is implemented and passes.

## Progressive Disclosure (Reference Modules)

Use the following modules for detailed implementation guidance:

### 1. Theory and Principles
- **[Theory & Core Principles](references/theory.md)**: Definitions, Holonic Constraints, Core Objects, and the Universal Defect Principle.
- **[Zero-Tool Ideal (ZTI)](references/zero_tool_ideal.md)**: Guidance on ContextPacks and minimizing exploration-as-defect.

### 2. Taxonomy and Substrate
- **[Defect Taxonomy](references/taxonomy.md)**: Classification by Domains, Stages, and Surfaces.
- **[Substrate & Discipline](references/substrate.md)**: Normative rules for Schemas, Ledgers, Evidence, and Fingerprinting.

### 3. Execution Workflows
- **[Detection, Triage, and Remediation](references/workflows.md)**: Procedures for GateRuns, Root Cause analysis, and Closure rules.

### 4. Detailed Volumes
- **[Volumes 0-9](references/)**: Search the `references/VOLUME_*.md` files for specific deep-dives and case studies.

## Assets and Schemas
- **[Defect Record Schema](assets/schemas/defect_record_schema.yaml)**: Canonical structure for recording defects.
- **[Taxonomy Schema](assets/schemas/taxonomy.yaml)**: Enforced enumerations for classification.
