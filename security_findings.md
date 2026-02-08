## Security Review: FAIL

SCP: **YES**  
Severity summary: **3 blocker / 0 major / 0 minor / 0 nit**

### Summary
This PR introduces a substantial `PermeabilityReceipt` model and meet-based delegation checks in `crates/apm2-core/src/policy/permeability.rs`, including canonical hashing and admission validation. The change clearly targets RFC-0020 delegation safety and authority narrowing.

However, the reviewed commit `b2575293cf2c657e2f8dbade02666783e7ac2fb4` still leaves three security-critical invariant gaps: chain-level strict-subset continuity can be bypassed, issuance-time freshness is incomplete, and consumption-path enforcement is not wired into daemon actuation gates. Because these gaps violate RFC-0020/REQ-0027 fail-closed delegation requirements, verdict is **FAIL**.

### Worktree Resolution
Reused local worktree: `/home/ubuntu/Projects/apm2-TCK-00373`  
Branch match basis: exact match on `headRefName = ticket/RFC-0020/TCK-00373` and `HEAD = b2575293cf2c657e2f8dbade02666783e7ac2fb4`.  
Note: worktree contained additional unstaged local edits; audit findings were computed against `reviewed_sha` via `git show`/PR diff, not ambient unstaged state.

### SCP Determination
SCP = **YES**.

Touched areas:
- **CRYPTO**: canonical BLAKE3 authority/receipt hashing and hash binding logic in `crates/apm2-core/src/policy/permeability.rs`.
- **Identity/Authorization semantics**: strict-subset delegation admission and chain validation in security-sensitive authority path.

### Markov Blanket Analysis
Boundary 1: `PermeabilityReceipt::validate_admission`
- Inputs: receipt fields + `now_ms`.
- Validation present: meet equality, subset checks, hash checks, depth bounds, parent-hash linkage, expiry/revocation.
- Gap: missing issuance-window lower-bound check (`issued_at_ms` not validated against `now_ms` / non-zero).
- Outputs: `Ok(())` or fail-closed `PermeabilityError`.
- Limits: id-length bounds + delegation depth bound.

Boundary 2: `validate_delegation_chain`
- Inputs: ordered receipt chain + `now_ms`.
- Validation present: per-receipt admission, root anchoring, parent hash linkage, non-widening subset, depth monotonicity, expiry narrowing.
- Gap: no continuity check that `child.parent_authority` equals `parent.delegated`; chain check uses non-strict subset (`<=`) instead of strict subset (`<`) relative to actual parent authority.
- Outputs: chain accepted/denied.
- Limits: max depth check.

Boundary 3: delegated actuation consumption path
- Inputs: envelope `permeability_receipt_hash`, runtime required authority.
- Validation implemented in helper: `validate_consumption_binding`.
- Gap: helper is not wired to daemon production actuation path; delegated spawn currently validates only hash presence/non-zero.
- Outputs: delegated path allowed/denied.
- Limits: missing runtime resolution/validation gate = fail-open risk relative to unverifiable hashes.

### **BLOCKER FINDINGS**
1. Issue: Chain-level strict-subset/continuity can be bypassed in reviewed commit.
Impact: `validate_delegation_chain` checks `child.delegated.is_subset_of(&parent.delegated)` but does not enforce `child.parent_authority == parent.delegated` linkage.
Consequence: A child can set `parent_authority` to a stronger value, satisfy per-receipt strict-subset against that forged parent, and keep effective delegated authority equal to true parent authority across hops.
Required Fix: In chain validation, enforce parent-authority continuity (`child.parent_authority_hash == parent.delegated_hash` or equivalent structural equality) and require strict subset relative to actual parent (`child.delegated.is_strict_subset_of(&parent.delegated)`). Add explicit regression tests.
Evidence: `crates/apm2-core/src/policy/permeability.rs:1247`, `crates/apm2-core/src/policy/permeability.rs:1249`, `crates/apm2-core/src/policy/permeability.rs:1230`.

2. Issue: Issuance-time freshness is incomplete.
Impact: Admission enforces `now_ms <= expires_at_ms` but does not reject zero/future issuance timestamps.
Consequence: Pre-issuance replay (receipt used before issuance time) and malformed issuance anchors can pass admission, violating temporal pinning/freshness semantics.
Required Fix: In `validate_admission` (and unchecked test variant as appropriate), enforce `issued_at_ms != 0` and `issued_at_ms <= now_ms`; optionally assert `issued_at_ms <= expires_at_ms` for internal consistency. Add tests for zero and future issuance.
Evidence: `crates/apm2-core/src/policy/permeability.rs:792`, `crates/apm2-core/src/policy/permeability.rs:847`, `crates/apm2-core/src/policy/permeability.rs:851`.

3. Issue: Consumption binding verification is not enforced on production daemon path.
Impact: `validate_consumption_binding` exists but is left as TODO for daemon wiring; delegated envelope validation currently checks only presence/non-zero of hash.
Consequence: An arbitrary 32-byte hash can satisfy delegated-spawn envelope checks without proving receipt authenticity, freshness, or authority sufficiency.
Required Fix: Wire receipt resolution + `validate_consumption_binding` into delegated spawn/resume and authoritative receipt emission gates; fail-closed when resolution/validation fails.
Evidence: `crates/apm2-core/src/policy/permeability.rs:1371`, `crates/apm2-core/src/policy/permeability.rs:1385`, `crates/apm2-daemon/src/episode/envelope.rs:1554`.

### **MAJOR FINDINGS**
None.

### **POSITIVE OBSERVATIONS (PASS)**
1. Receipt hashing is length-prefixed for variable fields, reducing framing ambiguity.
2. Admission includes strong fail-closed checks for revoked/expired receipts, hash integrity, and depth/linkage bounds.
3. The module adds broad deterministic/unit/property coverage for lattice behavior and laundering-related cases.

### Machine-Readable Metadata (REQUIRED)
<!-- apm2-review-metadata:v1:security -->
```json
{
  "schema": "apm2.review.metadata.v1",
  "review_type": "security",
  "pr_number": 498,
  "head_sha": "b2575293cf2c657e2f8dbade02666783e7ac2fb4",
  "verdict": "FAIL",
  "severity_counts": {
    "blocker": 3,
    "major": 0,
    "minor": 0,
    "nit": 0
  },
  "reviewer_id": "apm2-codex-security"
}
```

### Assurance Case
Claim: The reviewed commit is **not** safe to approve for security gate.

Argument:
- A1: Delegation-chain semantics must enforce strict narrowing against the *actual* parent authority; current chain validator allows non-strict subset and lacks parent-authority continuity proof.
- A2: Authority-bearing delegation must be time-window valid; current admission omits issuance-time checks.
- A3: Runtime actuation must verify bound receipt authenticity/freshness/authority; current daemon path validates hash presence only.

Evidence:
- Chain validation logic at `crates/apm2-core/src/policy/permeability.rs:1230` and `crates/apm2-core/src/policy/permeability.rs:1249`.
- Admission freshness logic at `crates/apm2-core/src/policy/permeability.rs:792` and `crates/apm2-core/src/policy/permeability.rs:847`.
- Unwired runtime TODO and current delegated spawn check at `crates/apm2-core/src/policy/permeability.rs:1371` and `crates/apm2-daemon/src/episode/envelope.rs:1554`.

---
Reviewed commit: b2575293cf2c657e2f8dbade02666783e7ac2fb4 (resolved from PR_URL at review start for auditability)
