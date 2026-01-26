# Artifact

**Agent-Native Definition**: An **Artifact** is "Content-Addressed Evidence" produced during a Holon's execution. Unlike transient logs, artifacts are persistent, verifiable, and typed outputs that serve as the building blocks of the system's audit trail and integrity proofs.

Artifacts are the concrete "proof of work" that enable the system to verify that an agent actually did what it claims to have done.

## Core Concepts

### Content-Addressed Storage (CAS)
Artifacts are stored and referenced by the cryptographic hash (typically **BLAKE3**) of their content. This ensures:
*   **Immutability**: Once created, an artifact cannot be changed without changing its ID/hash.
*   **Deduplication**: Identical content produced by different agents results in the same artifact storage.
*   **Integrity**: Any tampering is immediately detectable by hash mismatch.

### Evidence Bundle
A collection of artifacts related to a specific unit of work (like a Pull Request or a Security Scan) is aggregated into an `EvidenceBundle`. This bundle is what gets verified by a **Gate**.

### Artifact Kinds
Artifacts are strongly typed to allow for automated processing. Common kinds include:
*   `code_change`: A patch or diff applied to the codebase.
*   `document`: A generated report, RFC, or PRD.
*   `test_result`: Output from a test runner.
*   `lint_report`: Output from static analysis tools.
*   `security_scan`: Results from security auditing tools.
*   `decision`: A record of the agent's reasoning process (Chain of Thought).

## Data Structure References
*   **`Artifact`** (`crates/apm2-holon/src/artifact.rs`): The struct containing metadata (`id`, `kind`, `work_id`, `content_hash`) and content.
*   **`EvidenceBundle`** (`crates/apm2-core/src/evidence/state.rs`): A container for multiple artifacts.
*   **`DataClassification`** (`crates/apm2-core/src/evidence/classification.rs`): Enum defining sensitivity levels (`Public`, `Internal`, `Confidential`, `Restricted`).
*   **`ContentAddressedStore`** (`crates/apm2-core/src/evidence/mod.rs`): The trait defining the interface for storing and retrieving artifacts by hash.

## See Also
*   **Gate**: The protocol that verifies artifacts.
*   **Ledger**: Where artifact references are recorded.
