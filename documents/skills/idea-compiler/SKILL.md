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

Use `ticket` skill with the emitted tickets. Implementers must follow the referenced AGENTS.md invariants and the ticket verification commands.

## CLI Integration

The idea-compiler skill orchestrates the `apm2 factory compile` pipeline. This section provides the complete CLI reference for all pipeline operations.

### End-to-End Compilation

```bash
# Full compilation from PRD to tickets (recommended)
apm2 factory compile --prd PRD-0005

# Specify RFC identifier (auto-generated if omitted)
apm2 factory compile --prd PRD-0005 --rfc RFC-0011

# With routing profile for model selection
apm2 factory compile --prd PRD-0005 --profile production

# Sign the run manifest for provenance
apm2 factory compile --prd PRD-0005 --sign

# Force rebuild even if artifacts are up to date
apm2 factory compile --prd PRD-0005 --force
```

### Dry-Run Mode

Dry-run mode validates the pipeline without writing any files. Use this for:
- Previewing changes before committing
- CI validation of PRD structure
- Debugging pipeline failures

```bash
# Dry-run to preview changes without writing files
apm2 factory compile --prd PRD-0005 --dry-run

# Combine with NDJSON output for programmatic analysis
apm2 factory compile --prd PRD-0005 --dry-run --format json
```

### Stage-by-Stage Execution

For debugging or selective rebuilds, run individual stages:

```bash
# Stage 1: Build CCP index
apm2 factory ccp build --prd PRD-0005

# Stage 2: Build Impact Map (requires CCP)
apm2 factory impact-map build --prd PRD-0005

# Stage 3: Frame RFC (requires Impact Map)
apm2 factory rfc frame --prd PRD-0005 --rfc RFC-0011

# Stage 4: Emit tickets (requires RFC)
apm2 factory tickets emit --rfc RFC-0011

# Stage 5: Sync skills (optional)
apm2 factory skill sync

# Stage 6: Promote to documents/ (requires run manifest)
apm2 factory promote --run <RUN_ID> --to documents/
```

### NDJSON Output Format

Use `--format json` to emit structured NDJSON (newline-delimited JSON) events for programmatic consumption:

```bash
apm2 factory compile --prd PRD-0005 --format json
```

Each line is a JSON object with event type and payload:

```json
{"event":"stage_start","stage":"ccp","timestamp":"2026-01-26T10:00:00Z"}
{"event":"artifact_written","path":"evidence/prd/PRD-0005/ccp/ccp_index.json"}
{"event":"stage_complete","stage":"ccp","duration_ms":1500}
{"event":"compile_complete","run_id":"RUN-20260126-100000","success":true}
```

### CLI Flags Reference

| Flag | Description | Default |
|------|-------------|---------|
| `--prd <PRD>` | PRD identifier (required) | - |
| `--rfc <RFC>` | RFC identifier | Auto-generated |
| `--profile <PROFILE>` | Routing profile name | `local` |
| `--dry-run` | Report intended writes without modifying files | false |
| `--sign` | Sign run manifest with configured key | false |
| `--force` | Force rebuild even if artifacts are up to date | false |
| `--format <FORMAT>` | Output format: `text` or `json` (NDJSON) | `text` |
| `--output-dir <DIR>` | Override default output directory | - |
| `--repo-root <PATH>` | Path to repository root | Current directory |

### Troubleshooting

**Missing CCP index**
```
Error: CCP index not found at evidence/prd/PRD-0005/ccp/ccp_index.json
```
Solution: Run `apm2 factory ccp build --prd PRD-0005` first.

**Invalid file references in Impact Map**
```
Finding: BLOCKER - File path 'src/missing.rs' does not exist in CCP
```
Solution: Update the Impact Map to reference only files present in the CCP, or update the codebase first.

**Non-deterministic model output**
```
Warning: Output differs from previous run (hash mismatch)
```
Solution: Retry with `--force` or use a stricter routing profile.

**Stale artifacts**
```
Info: Skipping stage 'ccp' - artifacts up to date
```
Solution: Use `--force` to rebuild all stages.

## References

- `documents/theory/glossary/glossary.json`: REQUIRED READING: APM2 terminology and ontology.
- `references/pipeline_stages.md`: Stage definitions, inputs/outputs, and completion predicates.
- `references/determinism_envelope.md`: Canonicalization and diff acceptance rules.
- `references/model_routing.md`: Routing profile design and canary process.
