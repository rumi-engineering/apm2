# M06: Rust soundness and unsafe

```yaml
module_id: M06
domain: memory_safety
inputs: [ChangeSetBundle, InvariantMap, QCP_Result]
outputs: [Finding[]]
```

This module is a review adapter over the normative unsafe rules in:
- `references/19_unsafe_rust_obligations.md` (CTR-0901..0904, INV-0902, INV-0903)

---

## Review protocol

```mermaid
flowchart TD
    START[Begin] --> A[Safe Rust quality scan]
    A --> B{unsafe changes in diff?}
    B -->|NO| Z[Emit findings]
    B -->|YES| C[For each unsafe site]
    C --> D[Check unsafe policy + SAFETY comment]
    D --> E[Run obligation checklist (INV-0902)]
    E --> F[Scan for UB footguns]
    F --> G[Check Send/Sync and cross-thread invariants]
    G --> H[Next unsafe site]
    H --> C
    H --> Z
```

---

## State: Safe Rust quality scan

```yaml
assertions:
  - id: SAFE-OWN
    predicate: "ownership boundaries are obvious and type-enforced"
    on_fail:
      severity: MAJOR
      remediation: "Clarify ownership with types (newtypes, lifetimes, RAII guards)."

  - id: SAFE-LIFE
    predicate: "lifetimes prevent use-after-free by construction"
    on_fail:
      severity: MAJOR
      remediation: "Tighten lifetime bounds; avoid 'static unless required."

  - id: SAFE-INV
    predicate: "invariants encoded as types, not only comments"
    on_fail:
      severity: MINOR
      remediation: "Prefer constructors that validate; hide invalid states."

red_flags:
  - id: SAFE-LEAK
    pattern: "leaky lifetimes that force unsafe downstream"
    severity: MAJOR

  - id: SAFE-INTERIOR
    pattern: "interior mutability without a reentrancy/thread-safety story"
    severity: MAJOR
```

---

## State: Unsafe site structure checks

Definitions:
- **unsafe site**: `unsafe { ... }`, `unsafe fn`, `unsafe trait`, `unsafe impl`.

```yaml
FOR EACH unsafe_site IN diff:

  - id: UNSAFE-SCOPE
    predicate: "unsafe isolated to the smallest possible expression/block"
    on_fail:
      EMIT Finding:
        id: RUST-UNSAFE-SCOPE
        severity: MAJOR
        location: {unsafe_site.location}
        remediation:
          type: CODE
          specification: "Reduce the unsafe scope to wrap only the unsafe operation."

  - id: UNSAFE-COMMENT
    predicate: "// SAFETY: comment exists adjacent to the unsafe block/op (CTR-0902)"
    on_fail:
      EMIT Finding:
        id: RUST-UNSAFE-001
        severity: BLOCKER
        location: {unsafe_site.location}
        remediation:
          type: DOC
          specification: |
            Add a local `// SAFETY:` comment that states:
            - required preconditions (validity, alignment, provenance, aliasing)
            - why the preconditions hold at this callsite
            - what would break the proof (regression risks)

  - id: UNSAFE-COMMENT-QUALITY
    predicate: |
      safety_comment.mentions(aliasing OR lifetimes OR validity OR provenance)
      AND NOT safety_comment.is_trivial("because it works")
    on_fail:
      EMIT Finding:
        id: RUST-UNSAFE-002
        severity: BLOCKER
        location: {unsafe_site.location}
        remediation:
          type: DOC
          specification: "Safety comment must address concrete obligations, not restate the code."

  - id: UNSAFE-LINT-DISCIPLINE
    predicate: |
      IF workspace_lints.unsafe_code == "warn" THEN
        unsafe_site.has_local_allow_with_justification
    on_fail:
      EMIT Finding:
        id: RUST-UNSAFE-LINT-001
        severity: MAJOR
        location: {unsafe_site.location}
        remediation:
          type: DOC
          specification: |
            Add `#[allow(unsafe_code)]` with a justification comment explaining:
            - why unsafe is necessary here
            - what invariant defends it
            - where tool evidence exists (tests/Miri)

  - id: UNSAFE-SCP-DCP
    predicate: |
      IF unsafe_site.in_path_map(SCP_OR_DCP) THEN
        justification.is_extraordinary AND tool_evidence.includes_miri
    on_fail:
      EMIT Finding:
        id: RUST-UNSAFE-SCP
        severity: BLOCKER
        location: {unsafe_site.location}
        remediation:
          type: TEST
          specification: |
            Unsafe in SCP/DCP is presumptively merge-blocking unless defended by:
            - a strong local SAFETY proof, and
            - Miri coverage (or an explicitly approved, equivalent tool justification).
```

---

## State: Proof obligations checklist (INV-0902)

```yaml
FOR EACH unsafe_site:
  REQUIRE answers to all relevant checklist items:

  - PTR_VALID: "non-null / non-dangling / dereferenceable"
  - PTR_INIT: "initialized before typed read"
  - PTR_ALIVE: "object lives for access duration"
  - ALIGN: "typed access is aligned (or uses unaligned ops)"
  - ALIAS: "no mutable aliasing violations"
  - SHARED: "no shared refs during mutation (unless interior mutability rules apply)"
  - PROV: "pointer provenance preserved (no invalid int roundtrips)"
  - BOUNDS: "bounds + size math checked (len * size_of)"
  - DROP: "drop/init occurs exactly-once"
  - UNWIND: "panic/unwind cannot expose later UB"

qcp_rule:
  IF qcp.qcp == true AND any_required_answer_missing:
    EMIT Finding(severity=BLOCKER, id=RUST-UNSAFE-PROOF-001)
```

---

## State: UB footgun detection

```yaml
high_suspicion_patterns:
  - id: UB-TRANSMUTE
    pattern: "mem::transmute"
    severity: BLOCKER
    remediation: |
      Prefer explicit conversions.
      If proposing a helper crate (e.g., bytemuck) this is a supply-chain change
      and must pass `M12` dependency review + have an explicit safety proof.

  - id: UB-ZEROED
    pattern: "mem::zeroed"
    severity: BLOCKER
    remediation: "Use `MaybeUninit` or explicit initialization; most types are not safely zeroable."

  - id: UB-PACKED
    pattern: "repr(packed)"
    severity: BLOCKER
    remediation: "Avoid creating references to packed fields; use raw reads/copies to an aligned buffer."

  - id: UB-SETLEN
    pattern: "Vec::set_len"
    severity: BLOCKER
    remediation: "Requires rigorous initialization proof for all elements; prefer safe constructors."

  - id: UB-ASSUME
    pattern: "MaybeUninit::assume_init"
    severity: BLOCKER
    remediation: "Requires exhaustive initialization proof; defend with tests + Miri when applicable."

  - id: UB-RAWOPS
    pattern: "ptr::read|ptr::write|copy_nonoverlapping"
    severity: BLOCKER
    remediation: "Requires aliasing + bounds proof; avoid references until validity holds."

  - id: UB-STATIC
    pattern: "static mut"
    severity: BLOCKER
    remediation: "Almost never acceptable; use atomics or a lock. Any exception must be narrowly scoped and justified."
```

---

## State: Send/Sync correctness

```yaml
assertions:
  - id: SEND-IMPL
    predicate: |
      IF unsafe impl Send THEN
        explicit_concurrency_invariant_comment EXISTS
    on_fail:
      EMIT Finding:
        id: RUST-SEND-001
        severity: BLOCKER
        remediation:
          type: DOC
          specification: "Add a concurrency safety invariant comment + tests (Loom if non-trivial)."

  - id: SYNC-IMPL
    predicate: |
      IF unsafe impl Sync THEN
        explicit_concurrency_invariant_comment EXISTS
    on_fail:
      EMIT Finding:
        id: RUST-SYNC-001
        severity: BLOCKER
        remediation:
          type: DOC
          specification: "Add a concurrency safety invariant comment + tests (Loom if non-trivial)."
```

---

## Output schema

```typescript
interface SoundnessFinding extends Finding {
  proof_obligation?: ProofObligation;
  ub_pattern?: UBPattern;
}

type ProofObligation =
  | "PTR_VALID"
  | "PTR_INIT"
  | "PTR_ALIVE"
  | "ALIGN"
  | "ALIAS"
  | "SHARED"
  | "PROV"
  | "BOUNDS"
  | "DROP"
  | "UNWIND";

type UBPattern =
  | "TRANSMUTE"
  | "ZEROED"
  | "PACKED"
  | "SET_LEN"
  | "ASSUME_INIT"
  | "RAW_OPS"
  | "STATIC_MUT";
```

---

## Unsafe review template (copy/paste)

```text
Unsafe site: <file:line>
Operation: <what unsafe operation is performed>
Preconditions: <validity/alignment/provenance/aliasing/etc>
Why they hold here: <local reasoning>
Postcondition: <what is now safe/true>
Defended by: <test name(s), Miri, Loom, fuzz, etc>
Regression risks: <what future refactor could break this proof>
```
