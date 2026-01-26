# Gate

**Agent-Native Definition**: A **Gate** is a "Holonic Verification Protocol" that enforces quality, security, and compliance standards. It acts as a checkpoint where `EvidenceBundles` are cryptographically verified against a set of requirements before work can proceed to the next stage.

Gates transform subjective "reviews" into objective, machine-verifiable proofs of quality.

## Core Concepts

### Gate Verification Process
1.  **Input**: An `EvidenceBundle` containing Artifacts from a work item.
2.  **Verification**: The `GateReceiptGenerator` checks the bundle against `GateRequirements` (e.g., "Must have passing test results", "Must have zero critical security findings").
3.  **Output**: A signed `GateReceipt`.

### Gate Receipt
The `GateReceipt` is the cryptographic proof of the gate's outcome. It includes:
*   `result`: `PASS` or `FAIL`.
*   `reason_code`: Why it passed or failed (e.g., `MISSING_REQUIRED_CATEGORY`).
*   `signature`: Signed using Ed25519 by the `GateReceiptGenerator`'s private key.
*   `bundle_hash`: Links the receipt to the specific evidence bundle verified.

### Types of Gates
*   **TRUSTED Gates**: Rely on the authority of the tool running them (e.g., a linter, a compiler, a security scanner). The gate verifies the *presence* and *result* of the tool's output.
*   **DETERMINISTIC Gates**: Rely on pure computation that can be re-run by anyone to get the same result (e.g., checking that a file hash matches a manifest).

## Data Structure References
*   **`GateReceipt`** (`crates/apm2-core/src/evidence/receipt.rs`): The signed output record proving gate passage or failure.
*   **`GateRequirements`** (`crates/apm2-core/src/evidence/receipt.rs`): The configuration defining which `EvidenceCategory` items and counts are needed to pass.
*   **`GateResult`** (`crates/apm2-core/src/evidence/receipt.rs`): Enum indicating `Pass` or `Fail`.
*   **`GateReasonCode`** (`crates/apm2-core/src/evidence/receipt.rs`): Enum explaining the specific reason for the gate's outcome.
*   **`GateReceiptGenerator`** (`crates/apm2-core/src/evidence/receipt.rs`): The engine that evaluates bundles and signs receipts.

## See Also
*   **Evidence**: The input to a gate.
*   **Finding**: Structured defects produced when a gate fails.
*   **ChangeSet**: The unit of work that must pass through gates before being merged.