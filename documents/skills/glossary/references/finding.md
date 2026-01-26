# Finding

**Agent-Native Definition**: A **Finding** is a "Structured Defect". Unlike unstructured log messages or prose comments, a Finding is a typed data object that represents a specific issue, violation, or defect detected by a Gate or an Agent.

Findings are the primary mechanism for feedback loops in the system, driving the transition from "problem detection" to "remediation".

## Core Concepts

### Structured Fields
Every finding contains machine-parseable fields:
*   **Category**: The type of issue (e.g., `SECURITY`, `LINT`, `TEST_FAILURE`).
*   **Severity**: Criticality level (e.g., `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
*   **Location**: Precise pointers (file, line, span).
*   **Remediation**: Instructions or code actions to fix the issue.

### Finding Signature
A cryptographic hash computed from the canonical fields of the finding (category, rule ID, normalized code snippet).
*   **Purpose**: Enables **Recurrence Tracking**. The system can identify if the *same* logical issue is appearing across different contexts or times.
*   **Clustering**: Allows grouping of identical findings.

### Countermeasures
When the system detects that a specific `FindingSignature` has recurred beyond a configurable threshold, it triggers a **Countermeasure**. This is an automated work item designed to implement a systemic fix (e.g., updating a lint rule, refactoring a common pattern) to prevent the finding from ever occurring again.

## Data Structure References
*   **`Finding`**: The data object.
*   **`FindingSignature`**: The hash used for identity.
*   **`Countermeasure`**: The work item triggered by recurring findings.

## See Also
*   **Gate**: The primary producer of findings.
*   **Artifact**: Findings are often stored as artifacts.
