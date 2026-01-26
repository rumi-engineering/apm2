---
name: rsi
description: Recursive Skill Improvement - Protocol for evolving agent methodologies through self-observation and standard-refinement.
---

# Recursive Skill Improvement (RSI) Protocol

This skill codifies the "Evolutionary Mandate." Every task performed under this protocol must result in both a **Work Product** and a **Methodological Upgrade**.

## The Evolutionary Mandate

1.  **Execute**: Perform the assigned task (e.g., defining a Glossary term) to the current highest standard.
2.  **Observe**: Maintain a "Meta-Log" of friction:
    *   Where did you have to guess?
    *   Which tool calls (grep/find) were redundant or produced too much noise?
    *   Where was the existing documentation/template vague?
3.  **Refine**: Update the 'Lead Archivist Mandate' or relevant Skill reference to make the next agent 20% more efficient.
4.  **Codify**: If you find a "Source of Truth" (e.g., a specific directory for error enums), add it to the **Path Cheat Sheet**.

## Glossary Sharpening Layer (Lead Archivist)

To achieve high-density, "Normative Standard" definitions, every entry MUST include:

*   **Layer 1: Protobuf Mapping**: Link to the message in `proto/kernel_events.proto` or `proto/tool_protocol.proto`.
*   **Layer 2: Error Domain**: Link to the `Error` enum (e.g., `LedgerError`) that enforces the concept's invariants.
*   **Layer 3: Event Lifecycle**: State which Tool Request "births" the concept and which Reducer persists it.

## Path Cheat Sheet (Code-as-Truth)

*   **Core Logic**: `crates/apm2-core/src/`
*   **Protobufs**: `proto/*.proto`
*   **Events**: `crates/apm2-core/src/events/mod.rs`
*   **Errors**: Look for `error.rs` or `mod.rs` within each sub-module of `apm2-core`.