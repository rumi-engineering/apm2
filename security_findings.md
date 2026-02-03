## Security Review: FAIL

### Summary
The security review for PR 376 (TCK-00311) has **FAILED**. While the PR correctly implements hardening for the navigation tools (`ListFiles`, `Search`) and adds defense-in-depth against path traversal, a critical data integrity defect was identified in the `ReviewBlockedRecorded` event implementation. The numeric mapping of failure reason codes in Rust is misaligned with the ProtoBuf schema, which will lead to incorrect failure classification in the durable ledger and potential malfunction of automated retry/recovery logic.

### SCP Determination
**SCP: YES**. This PR touches multiple Security-Critical Path areas:
- **Cryptography**: Implements domain-separated signing for `ReviewBlockedRecorded`.
- **Ledger Persistence**: Adds a new event type to the kernel ledger.
- **Tool Execution**: Implements new filesystem navigation tools with sandbox boundary enforcement.
- **Protocol/IPC**: Updates kernel and tool protocols with new message types and enums.

### Markov Blanket Analysis
- **Inputs**: `ListFiles` and `Search` tool requests accept paths, glob patterns, and queries.
- **Validation**: Path traversal sequences (`..`) are blocked at both the validation and execution layers.
- **Limits**: Output size limits (max entries, lines, bytes) are strictly enforced to prevent DoS.
- **Failure Behavior**: Workspace apply failures are mapped to `ReasonCode` and recorded in the ledger with signed evidence.

### **BLOCKER FINDINGS**
1. **Issue: ReasonCode Numeric Mismatch between Rust and ProtoBuf**
   - **Details**: In `crates/apm2-core/src/fac/review_blocked.rs`, the `ReasonCode::to_code` method uses 0-indexed values (e.g., `ApplyFailed = 0`, `ToolFailed = 1`). However, `proto/kernel_events.proto` defines `ReviewBlockedReasonCode` with `REVIEW_BLOCKED_REASON_UNSPECIFIED = 0` and `REVIEW_BLOCKED_REASON_APPLY_FAILED = 1`. 
   - **Impact**: When a review is blocked due to an apply failure, it will be recorded in the ledger with code `0`, which consumers will interpret as `UNSPECIFIED`. This corrupts the audit trail and breaks automated systems relying on failure classification.
   - **Consequence**: Violation of LAW-07 (Verifiable Summaries) and LAW-08 (Goodhart Resistance) due to inaccurate ledger evidence.
   - **Required Fix**: Update `ReasonCode::to_code` and `ReasonCode::from_code` in `review_blocked.rs` to start at `1` for `ApplyFailed`, aligning with the ProtoBuf definition.

### **MAJOR FINDINGS**
1. **Issue: Incomplete Robustness in Workspace Path Validation**
   - **Details**: The `validate_path` function in `crates/apm2-daemon/src/episode/workspace.rs` (marked as a stub) uses a simple prefix check and `components()` collection. While it checks for `..` sequences in the input string, it does not use `canonicalize()` to resolve potential symlink escapes at the OS level.
   - **Impact**: Potential for more complex path escape attacks if symlinks are present in the workspace.
   - **Consequence**: Reduced assurance for workspace isolation during changeset apply.
   - **Required Fix**: Use `canonicalize()` for boundary verification in `workspace.rs` once the implementation moves beyond the stub phase, similar to the hardening applied in `fs.rs`.

### **POSITIVE OBSERVATIONS (PASS)**
- **Navigation Tool Hardening**: The `Search` and `ListFiles` tools in `crates/apm2-core/src/tool/fs.rs` have been robustly hardened. They now include `Self::contains_path_traversal` checks and use `canonicalize()` on matched paths to ensure they remain within the `workspace_root` boundary, effectively preventing symlink-based sandbox escapes.
- **Domain Separation**: `ReviewBlockedRecorded` signatures correctly use the `REVIEW_BLOCKED_RECORDED:` domain prefix, preventing cross-protocol replay attacks.
- **Dependency Hygiene**: The update of the `bytes` crate to `1.11.1` to address `RUSTSEC-2026-0007` is noted and commended.

### Assurance Case
- **Claim**: `ReviewBlockedRecorded` events provide an accurate and durable record of blocked reviews.
- **Argument**: While the protocol structure and signing logic are sound, the data representation is flawed. The numeric mismatch in reason codes invalidates the claim of accurate recording.
- **Evidence**: `ReasonCode::to_code` implementation vs. `ReviewBlockedReasonCode` proto definition.

---
Reviewed commit: e568be76ad2f3e4da6ec7c9b49e06078eba8b0e5
