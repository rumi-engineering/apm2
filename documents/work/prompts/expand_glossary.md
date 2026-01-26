You are an expert Systems Architect for the APM2 Holonic Factory. Your task is to expand the `glossary` skill with high-fidelity definitions for core architectural concepts.

## Context
The `glossary` skill (`documents/skills/glossary/SKILL.md`) serves as the "Repository Truth" for agent terminology. We have identified 6 critical terms that are missing detailed reference definitions.

## Task
1.  **Create 6 new reference files** in `documents/skills/glossary/references/`:
    *   `episode.md`
    *   `artifact.md`
    *   `gate.md`
    *   `ledger.md`
    *   `policy.md`
    *   `finding.md`

2.  **Update the Index** in `documents/skills/glossary/SKILL.md` to include these new terms in the table.

## Definition Requirements
Do not use generic dictionary definitions. Use the specific "Agent-Native" definitions from `apm2` doctrine (`principia-holonic.md`, `agent-native-software.md`, `PRD-0004`).

*   **Episode**: Define as a "Bounded Context Window" with `EpisodeContext`, `EpisodeResult`, and `StopCondition`. Mention `max_episodes` and budget.
*   **Artifact**: Define as "Content-Addressed Evidence". Mention `CAS`, `BLAKE3`, and `EvidenceBundle`.
*   **Gate**: Define as a "Holonic Verification Protocol". Mention `GateRun`, `GateReceipt`, and the difference between TRUSTED (schema/lint) and DETERMINISTIC (traceability) gates.
*   **Ledger**: Define as the "Topology of Truth". Append-only, signed, hash-chained `SQLite` WAL. Mention `EventRecord`.
*   **Policy**: Define as "Governance as Code". Default-deny, `PolicyEngine`, `PolicyEvent`.
*   **Finding**: Define as "Structured Defect". Mention `FindingSignature` for recurrence tracking and `Countermeasure` triggers.

## Reference Paths
*   `crates/apm2-holon/src/episode/` (Episode)
*   `crates/apm2-holon/src/artifact.rs` (Artifact)
*   `crates/apm2-core/src/evidence/receipt.rs` (Gate)
*   `crates/apm2-core/src/ledger/` (Ledger)
*   `crates/apm2-core/src/policy/` (Policy)
*   `documents/prds/PRD-0004/` (Finding)

Execute this task now.
