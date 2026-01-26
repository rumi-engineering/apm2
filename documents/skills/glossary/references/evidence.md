# Evidence

**Agent-Native Definition**: **Evidence** is a "Cryptographic Proof of Work" that captures the immutable output of a Holon's activity. It consists of a content-addressed artifact stored in a `CAS` (Content-Addressed Store) and signed metadata that links the artifact to a specific `Work` item. Evidence is the fundamental unit of quality and compliance in the system, transforming unverifiable claims into machine-verifiable proofs.

## Core Concepts

### Content-Addressable Storage (CAS)
Artifacts are stored and retrieved by their BLAKE3 hash, ensuring perfect integrity and automatic deduplication. The hash is the unique identifier for the content itself, meaning if the content changes, the ID changes.

### Data Classification
Every piece of evidence is classified to enforce security policies and progressive disclosure.
*   **PUBLIC**: No restrictions.
*   **INTERNAL**: Default classification for factory-internal work.
*   **CONFIDENTIAL**: Restricted to authorized actors; requires progressive disclosure.
*   **RESTRICTED**: Highly sensitive; strict access control.

### Evidence Bundle
A collection of related `Evidence` artifacts for a single work item. Bundles are the atomic inputs for `Gate` verification, ensuring that all required quality artifacts (e.g., tests, lints, scans) are reviewed together.

## Data Structure References
*   **`Evidence`** (`crates/apm2-core/src/evidence/state.rs`): The primary record for a published artifact, including its hash, classification, and publisher metadata.
*   **`EvidenceBundle`** (`crates/apm2-core/src/evidence/state.rs`): A container for multiple `Evidence` items associated with a work item.
*   **`EvidenceCategory`** (`crates/apm2-core/src/evidence/category.rs`): Enum defining the type of work captured (e.g., `TEST_RESULTS`, `LINT_REPORTS`, `SECURITY_SCANS`).
*   **`DataClassification`** (`crates/apm2-core/src/evidence/classification.rs`): Enum defining the sensitivity and handling rules for the artifact.

## See Also
*   **Gate**: The verification function that consumes Evidence.
*   **Ledger**: Stores the `EvidencePublished` events.
*   **Artifact**: The raw binary content referenced by Evidence.
