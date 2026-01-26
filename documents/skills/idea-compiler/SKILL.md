---
name: idea-compiler
description: Compile a PRD or RFC into CCP-grounded outputs (anti-cousin by default) using the Idea Compiler pipeline, with explicit model routing and reproducible run manifests.
user-invocable: true
argument-hint: "[--prd PRD-XXXX | --rfc RFC-XXXX] [--path <dir>] [--profile <routing_profile>] [--dry-run]"
---

# Idea Compiler Skill

This skill drives the PRD->RFC "Idea Compiler" compilation pipeline. The pipeline is intended to be the default route from high-level intent to implementation-ready tickets.

## When to use

Use this skill when:
- You have a PRD (or existing RFC) that needs to become low-noise, codebase-aware tickets.
- You want RFCs/tickets grounded in the existing codebase (no invented extension points).
- You want deterministic re-runs, provenance, and controlled model routing.

## Invocation

```bash
/idea-compiler --prd PRD-XXXX [--path <dir>] [--profile <profile>] [--dry-run]
/idea-compiler --rfc RFC-XXXX [--path <dir>] [--profile <profile>] [--dry-run]
```

## Core doctrine

1. Repository truth is a mandatory input: always generate/refresh the Codebase Context Pack (CCP) before drafting RFCs.
2. Reuse-by-default: requirements must map to existing components/extension points or be explicitly adjudicated as net-new.
3. Determinism envelope: outputs are canonicalized and written atomically; re-runs must be stable or require explicit acceptance for material diffs.
4. Mechanism-first gating: fail-closed only on existential invariants (bad references, missing mappings, invalid manifests). Advisory lints ratchet over time.

## Procedure

### 1) Validate inputs

- If using `--prd`, ensure `documents/prds/PRD-XXXX/` exists (or `--path` points at the PRD root).
- If using `--rfc`, ensure `documents/rfcs/RFC-XXXX/` exists (or `--path` points at the RFC root).
- Default posture: write outputs to `evidence/` first; only update governed `documents/` via an explicit promote step.

### 2) Run compilation

Preferred (end-to-end):

```bash
apm2 factory compile --prd PRD-XXXX --profile <profile>
# or
apm2 factory compile --rfc RFC-XXXX --profile <profile>
```

Or stage-by-stage:

```bash
apm2 factory ccp build --prd PRD-XXXX
apm2 factory impact-map build --prd PRD-XXXX
apm2 factory rfc frame --prd PRD-XXXX --rfc RFC-XXXX
apm2 factory tickets emit --rfc RFC-XXXX
apm2 factory skill sync
apm2 factory promote --run <RUN_ID> --to documents/
```

Notes:
- MVP emphasis is anti-cousin: CCP + Impact Map + tickets. RFC framing and Skill Sync can be deferred when not needed.
- Prefer a local routing profile by default (no network) and only opt into external providers via explicit profiles.

### 3) Handle findings

If the pipeline fails, it will emit typed findings and a run manifest.

Common cases:
- Missing/invalid file references: update the Impact Map or CCP; do not guess.
- Unmappable requirement: record adjudication for net-new substrate before proceeding.
- Non-deterministic model output: retry with stricter routing profile or canary compare.

### 4) Output review

Confirm the compiler produced:
- CCP index + artifacts
- Impact Map
- RFC draft
- Tickets with file paths + verification commands
- Run manifest and NDJSON logs

### 5) Hand-off to implementation

Use `dev-eng-ticket` skill with the emitted tickets. Implementers must follow the referenced AGENTS.md invariants and the ticket verification commands.

## References

- `references/pipeline_stages.md`: Stage definitions, inputs/outputs, and completion predicates.
- `references/determinism_envelope.md`: Canonicalization and diff acceptance rules.
- `references/model_routing.md`: Routing profile design and canary process.
