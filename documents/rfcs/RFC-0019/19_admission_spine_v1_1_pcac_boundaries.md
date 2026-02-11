**Path:** `documents/rfcs/RFC-0019/19_admission_spine_v1_1_pcac_boundaries.md`

This addendum is **implementation-binding**: changes MUST be reviewed as security-critical.

Last updated: 2026-02-11

# RFC-0019 Addendum — Admission Spine v1.1 (PCAC/AJC-Boundary Binding + Ledger Trust Stack)

Status: DRAFT (implementation-binding addendum)
Scope: FAC/Admission, authoritative handlers, boundary-flow, governance/policy derivation, replay safety
Audience: runtime/daemon implementers, security reviewers, admission/gate owners, verification authors

## 0. Why this addendum exists (Non-Normative)

PCAC/AJC is expanding from "privileged handler guardrail" into the **universal admission spine** that binds:
- authority issuance and consumption,
- boundary-flow admissibility,
- governance/policy-root trust,
- ledger integrity as a prerequisite for "as_of_ledger_anchor".

This is the correct direction. But as PCAC surfaces expand, any architecture that embeds admission logic inside large dispatch handlers will continue to generate monolithic PRs and reviewer failure cycles. This addendum turns cross-RFC traceability into a **single enforced composition contract** with a narrow kernel API and no-bypass rules.

This addendum is NOT a rewrite of RFC-0027/0028. It is the glue contract that makes them compose.

### 0.1 Goals and non-goals (Non-Normative)

Goals:
- Define a **minimal trusted computing base (TCB)** for admission decisions and effect execution.
- Make "no-bypass" a **mechanical property**, not a reviewer convention.
- Make authoritative admission safe under **replay/crash/reset**, **ledger tamper**, and **policy confusion**.
- Ensure **bounded-work** behavior (request-time bounded, startup checkpoint-bounded).
- Ensure **crypto-agility** (including a feasible hybrid PQ migration path) without redesigning admission semantics.
- Ensure incremental rollout is **safe by default**: un-migrated endpoints MUST NOT silently remain effect-capable in authoritative mode.

Non-goals (for v1.1):
- Redesign the ledger storage engine (only add required seals/verification surfaces).
- Define the global policy language (we only bind to the policy-root digest/epoch contract).
- Provide exactly-once semantics against external systems that do not support idempotency keys (we require fail-closed handling of in-doubt windows).

## 1. Normative imports

Admission Spine v1.1 composes and is constrained by:

- RFC-0020 (HSI): contract binding, envelope binding, digest-first boundary semantics.
- RFC-0027 (PCAC/AJC): canonical authority lifecycle, semantic laws, join input completeness, durable single-consume.
- RFC-0028 (Boundary-flow integrity / EIO Security Profile): authoritative boundary evidence, quarantine semantics, fail-closed enforcement tiers.
- RFC-0029 (EIO Efficiency Profile): verifier-economics constraints and temporal predicate arbitration.
- RFC-0019 ch17/ch18: CAC/traceability overlay requirements (promotion-critical evidence closure).
- Holonic Time + Holonic Event frameworks (HT/HE): time anchoring, event identity, canonical event digesting, and event-class taxonomy as used by Ledger and boundary evidence.
  - Implementations MUST reuse the existing HT/HE crates/modules and MUST NOT introduce parallel "event" or "time" types at the admission boundary.
  - Where this addendum names a type with `V1`, code SHOULD type-alias to the existing canonical type if one already exists.

**Ledger signing and signature envelope note (Normative):**
- This addendum intentionally does NOT define new signature envelope formats.
- Ledger event signing, signature encoding, and canonical digest computation MUST reuse the authoritative ledger/HE implementation already used by the system.

**Conflict rule (Normative):**
- If this addendum introduces stricter requirements within RFC-0019 scope, the stricter requirement applies.
- If an imported RFC defines a type/field name or serialization, that imported definition is authoritative.

## 1.1 Terminology and notation (Normative)

The keywords **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are to be interpreted as described in RFC 2119.

This addendum uses the following terms. If another RFC defines the term, that RFC's definition governs; the text below is a binding *interpretation* for Spine composition.

- **Authoritative mode**: the daemon/runtime is the *policy and trust source-of-record* for admission decisions. In authoritative mode, admission MUST be fail-closed for enforcement tiers.
- **Authoritative flow**: any request path that can (a) consume authority, (b) execute an effect, (c) emit an authoritative receipt/event, or (d) cross a boundary that is governed by RFC-0028 enforcement tiers.
- **Non-authoritative mode**: the daemon/runtime is not the trust source-of-record; it MAY run monitor-only or best-effort paths. Non-authoritative behavior MUST NOT share code paths with authoritative effect execution unless the authoritative invariants are still enforced.
- **Enforcement tier**: a policy-derived enforcement level (e.g., Tier0–TierN). Tiers are **not** a compile-time constant; they MUST be derived from policy root (and tool_class / boundary profile) and MUST be bound into admission intent.
  - In this addendum, **Fail-Closed Tier** means "tiers configured to deny on missing authoritative prerequisites."
  - "Tier2+" in this addendum means "fail-closed tiers" (the exact tier numbers are policy-defined).
- **Holonic Time (HT)**: the canonical time abstraction used for security predicates and anchoring. Time used for enforcement MUST be HT-based (not raw wall-clock) and MUST be bound to a ledger anchor for authoritative decisions.
- **Holonic Event (HE)**: the canonical event abstraction used by Ledger and evidence emissions. Any event used for trust derivation (ledger integrity, governance policy root, boundary evidence) MUST be representable as (or reducible to) an HE with canonical digest rules.
- **Ledger**: an append-only sequence of HE instances (or an HE-compatible event model) that is tamper-evident and signature-verified in authoritative mode.
- **LedgerId**: a stable identifier for the ledger chain/namespace (e.g., chain id, deployment id). LedgerId MUST be committed anywhere a LedgerAnchor is committed to prevent cross-ledger replay.
- **LedgerAnchorV1**: the minimal ledger snapshot identifier used by admission:
  `{ ledger_id, event_hash, height (or equivalent), he_time }`.
  The anchor MUST refer to an event that is within the validated portion of the ledger.
- **PolicyRootDigest**: the digest of the authoritative policy root state derived from governance-class events.
- **RequestId**: a stable identifier for a single admission attempt. RequestId MUST be included in authority intent and in all authoritative receipts/events. RequestId SHOULD be an HE id (or derived from it) to preserve cross-system traceability.
- **Effect**: any authority-bearing side effect (tool/broker call, mutation, outbound boundary crossing, declassification emission, quarantine insertion, etc.). "Effect execution" in phases refers to the externalized action; the consume barrier MUST occur before the externalized action.
- **Witness seed**: a pre-effect binding object created by the daemon that commits the request to a future witness object (without requiring knowledge of post-effect measurements).
- **Witness evidence**: a post-effect object containing measured/derived boundary evidence (e.g., leakage or timing metrics), bound to the witness seed and stored as evidence (CAS and/or ledger-referenced).
- **AdmissionBundleDigest**: the digest of the sealed `AdmissionBundleV1` CAS object.
- **AdmissionBindingHash**: an alias for AdmissionBundleDigest in v1.1.
  - Rationale: avoid two "almost the same" digests with ambiguous semantics.
  - Future versions MAY define AdmissionBindingHash as a domain-separated derivation of AdmissionBundleDigest, but v1.1 uses equality.
- **IdempotencyKey**: an opaque key derived from RequestId (and optionally boundary/tool identity) that MUST be propagated to external systems that support idempotency.
- **BoundarySpanV1**: an in-kernel boundary mediation span that buffers/governs outputs until post-effect checks complete (for fail-closed tiers).
- **TCB**: trusted computing base for admission decisions and effect execution; in v1.1 the TCB MUST be reduced to AdmissionKernel + injected verifier/resolver providers.

## 1.2 Threat model and security goals (Normative)

Admission Spine v1.1 MUST be safe under the following threat assumptions:

1) **Bypass attempts**: adversaries (or accidental code paths) attempt to invoke effect execution, durable consumes, declassification, quarantine insertion, or policy-root derivation outside AdmissionKernel.
2) **Replay + crash-reset**: adversaries exploit restarts, retries, or concurrency to re-use authority, re-use receipts, or re-order lifecycle steps.
3) **Ledger tamper / rollback / fork**: adversaries with filesystem/DB write access attempt to alter ledger history, roll back state, or create divergent histories.
4) **Governance/policy confusion**: adversaries attempt to source "policy root" from non-governance events, local broker state, or unverifiable provenance.
5) **Boundary exfiltration**: adversaries attempt leakage through output channels, timing channels, streaming partials, or side-effect surfaces.
6) **Resource exhaustion**: adversaries attempt to force unbounded ledger scans, unbounded decode work, quarantine saturation/starvation, or witness object blowups.
7) **Supply-chain / measurement substitution**: adversaries attempt to substitute witness providers/instrumentation or bypass deterministic hashing rules.
8) **Cryptographic break / quantum**: long-term adversaries may break classical signature schemes; the system MUST support crypto-agility so it can migrate without redesigning trust derivations.
9) **Downgrade + mode confusion**: adversaries attempt to force non-authoritative paths, lower tiers, or "monitor-only" behavior while still causing effects.
10) **Cross-tenant confusion (confused deputy)**: adversaries attempt to mix session/tenant identities across admission intents, receipts, or quarantine actions.
11) **Observability exfiltration**: adversaries attempt to leak sensitive material via logs, metrics, traces, or debug endpoints.
12) **Canonicalization ambiguity**: adversaries exploit non-canonical serialization / hash computation to create digest collisions or verification disagreements.
13) **Capability forgery**: adversaries exploit `unsafe` or reflection to construct capability tokens and bypass AdmissionKernel.
14) **Time source tampering**: adversaries manipulate wall-clock/NTP or inject forged HT values to bypass temporal predicates.

Therefore, Admission Spine v1.1 MUST provide:
- **Mechanical no-bypass** (preferred) or at minimum enforceable and testable no-bypass rules.
- **Replay safety across restart** for authority consumption and receipt consumption.
- **Fail-closed enforcement tiers** when authoritative prerequisites are missing or unverifiable.
- **Bounded-work admission**: request-time operations MUST be bounded independent of total ledger history size (via indexes/caches), and startup validation MUST be checkpoint-bounded.
- **Downgrade resistance**: enforcement tier, boundary profile, and authoritative vs non-authoritative behavior MUST be policy-derived and MUST NOT be client-controlled.
- **Crypto-agility**: signatures, key identifiers, and verification logic MUST be algorithm-agile (algorithm id is explicit and bound into digests). Hybrid PQ migration MUST be possible without changing admission semantics.
- **Observability hygiene**: logs/metrics/traces for authoritative flows MUST be redaction-safe; sensitive digests/ids MAY appear, but raw sensitive payloads MUST NOT.

**Anti-rollback realism (Normative):**
- Purely local tamper-evidence does NOT fully solve rollback if an adversary can rewrite both ledger and local state.
- Therefore, fail-closed tiers MUST require an **anti-rollback anchor** (see §2.4) that is external to the adversary's local write scope (e.g., remote witness log, hardware monotonic counter, or quorum replication).
- If anti-rollback anchoring is not configured and verified, fail-closed tiers MUST deny.

## 1.3 Compatibility, versioning, and migration (Normative)

1) **Do not mutate versioned evidence structs in-place.**
   - If `AuthorityJoinInputV1` (or any V* type) is serialized/stored/verified anywhere, adding required fields to it is a compatibility break.
   - Spine v1.1 MUST use either:
     - an explicit new version (`AuthorityJoinInputV2`), or
     - a versioned extension object whose digest is committed by the existing join input (preferred when the base type already has a "supplemental commitment" slot).

2) **All Spine-introduced objects MUST be versioned and deny unknown fields.**
   - `deny_unknown_fields` (or equivalent) is REQUIRED for any object whose digest is used for replay verification.

3) **Incremental rollout is REQUIRED.**
   - Endpoints MAY be migrated one-by-one to AdmissionKernel (see ticketing).
   - However, in **authoritative mode**, any endpoint that can execute an Effect MUST either:
     - be fully routed through AdmissionKernel, OR
     - be explicitly disabled / fail-closed for fail-closed tiers.
   - Rationale: incremental rollout MUST NOT leave effect-capable bypass surfaces in authoritative mode.

4) **Canonical digest stability (Normative):**
   - Any digest referenced by admission intent, join commitment, consume barrier, witness, quarantine, or AdmissionBundle MUST use the canonical digest and canonical serialization rules defined by the imported RFCs (HSI/HE).
   - The digest domain-separation label MUST be included in the hashed preimage (no "implicit domain").
   - Any hash computation MUST reject non-canonical encodings.

5) **AdmissionKernel API stability (Normative):**
   - AdmissionKernel request/plan/result structs that cross crate/module boundaries MUST be versioned (`V1`, `V2`, …).
   - Kernel-facing structs whose digests are used for verification MUST be bounded and deny unknown fields, even if they are "internal only".

## 2. Trust stack (Normative)

Admission Spine v1.1 defines a strict trust stack. Higher layers MUST NOT "paper over" failures in lower layers.

### 2.1 Ledger integrity is below PCAC (Normative)
PCAC's `as_of_ledger_anchor` is meaningful only if the ledger is tamper-evident and startup validation is not bypassable.

Authoritative mode MUST:
- treat the ledger as an HE-compatible append-only sequence with canonical event digests and signature verification,
- validate hash-chain continuity AND verify ledger event signatures against a trusted key set (RootTrustBundle),
- validate monotonic HT constraints required by policy (e.g., no HT regression across a chain segment),
- perform checkpoint-based incremental startup validation (bounded by checkpoint-to-tip distance),
- provide an admin-triggered full-chain validation path for integrity audits.

If ledger integrity cannot be established, authoritative admission MUST deny (or refuse startup in authoritative mode).

**RootTrustBundle (Normative):**
- Authoritative mode MUST have a configured RootTrustBundle that contains the initial trust anchors needed to verify:
  - ledger event signatures, and
  - governance/policy-root signatures (see §2.2).
- RootTrustBundle MUST be crypto-agile: key identifiers MUST include algorithm id and key id (`kid`), and verification MUST dispatch on algorithm id.
- RootTrustBundle update/rotation MUST itself be governed (e.g., governance-signed keyset events) and MUST be auditable via ledger.
  - Revocation semantics MUST be explicit: "key removed" events MUST specify an effective anchor/epoch.
  - Verification MUST apply the correct keyset as-of the anchor being verified (no "always latest keyset").

**Checkpoint/Seal requirements (Normative):**
- "Checkpoint-based startup validation" MUST NOT rely on an unauthenticated local pointer.
- Startup MUST validate from the most recent **trusted seal** to tip, where a trusted seal is:
  - a ledger event (HE) whose payload commits to a prior ledger anchor (hash+height+HT), and
  - whose signature provenance chains to RootTrustBundle.
- If the distance from the trusted seal to current tip exceeds a configured bound, authoritative mode MUST either:
  - refuse startup (fail closed), or
  - fall back to full-chain validation (operator-triggered), depending on policy.

**Bounded-work constraint (Normative):**
- Admission hot paths MUST NOT scan unbounded ledger history.
- All per-request ledger reads MUST be indexable by digest/id and bounded by configuration.
- Ledger append paths in authoritative mode MUST verify new events at append-time (or before they are considered "validated"), so request-time does not degrade into "validate while admitting".

### 2.2 Authoritative policy-root derivation is below PCAC (Normative)
PCAC join inputs that depend on policy root MUST chain to a policy root derived only from **trusted governance-class events** with verified signature provenance.

Requirements:
- The ledger event namespace MUST classify events at minimum into `Governance`, `Session`, `System` (names illustrative).
- Event classification MUST be part of the signed event payload (or be committed by the signed digest); it MUST NOT be mutable local metadata.
- `resolve_authoritative_policy_root_digest` MUST read ONLY from `Governance` events and MUST verify signature provenance against a governance/policy-root key.
- Any broker-local fallback ("compare broker hash to broker hash") is forbidden for authoritative policy-root sourcing.
- Missing or unverifiable governance policy-root state MUST fail closed for enforcement tiers.

**Policy root determinism (Normative):**
- The policy root digest MUST be derived deterministically from governance events up to a specific LedgerAnchorV1.
- The resolver MUST return both:
  - `policy_root_digest`, and
  - the `policy_root_epoch` (or equivalent monotonic generation) used for revalidation.
- Policy root caching is permitted ONLY if the cache entry is bound to (a) the ledger anchor and (b) verified governance provenance.

### 2.3 `as_of_ledger_anchor` semantics and HT binding (Normative)

- `as_of_ledger_anchor` MUST be represented as a LedgerAnchorV1 and MUST be produced only by a ledger verifier after validating signatures and chain continuity up to that anchor.
- Admission decisions that reference HT MUST bind the HT predicate inputs to the same LedgerAnchorV1 (no "time from one source, policy from another").
- Revalidation MUST detect rollback/fork attempts where the ledger tip changes but the validated anchor does not chain to the new tip.

**Anchor selection rule (Normative):**
- For authoritative admission, AdmissionKernel MUST select `as_of_ledger_anchor` from `LedgerTrustVerifier.validated_state()` (or equivalent).
- Clients MUST NOT be allowed to supply an arbitrary `as_of_ledger_anchor`.
- If an API requires reproducibility, the client MAY supply a **minimum anchor** (`min_as_of_anchor`) and the kernel MAY choose an anchor >= min_as_of_anchor, but only if:
  - min_as_of_anchor is within the validated portion of the ledger, AND
  - the chosen anchor remains within configured bounded-work limits (no unbounded catch-up).

### 2.4 Anti-rollback anchoring (Normative)

To satisfy the rollback portion of the threat model in fail-closed tiers, the validated ledger state MUST be anchored outside the adversary's local write scope.

Fail-closed tiers MUST require at least one configured anti-rollback anchor mechanism:
- **Remote witness log** (append-only transparency log / witness service),
- **Hardware monotonic counter / TPM NV index** (if available),
- **Quorum replication** where the ledger is validated against a majority (or threshold) of peers.

Requirements:
- Startup MUST verify that the most recent trusted seal is also committed to (or derivable from) the external anchor mechanism.
- If the external anchor is unavailable or does not match local seals/anchors, fail-closed tiers MUST deny.
- If only monitor tiers are configured, the system MAY run without anti-rollback anchoring, but MUST mark itself as non-authoritative for fail-closed tiers.

## 3. Canonical authority lifecycle (Normative)

All authority-bearing side effects MUST obey:
`join -> revalidate -> consume -> effect`

This is not advisory. Deviations are structural defects.

Reviewer contract:
- Implementors MUST follow the canonical integration pattern described in the PCAC/AJC integration guide.
- Manual assembly of join inputs in privileged handler code (outside tests) is a MAJOR finding unless explicitly justified and equivalently complete.

### 3.1 Request identity + retry safety (Normative)

- Every authoritative flow MUST have a stable RequestId.
- RequestId MUST be committed into the authority intent digest and into any single-consume markers (AJC consume records, receipt-consumed events, etc.).
- AdmissionKernel MUST provide deterministic behavior under retries:
  - If a request with the same RequestId is retried, AdmissionKernel MUST NOT execute the externalized effect more than once unless the effect is explicitly declared idempotent and bound to the same RequestId at the boundary.

**RequestId source rule (Normative):**
- RequestId MUST be generated by the daemon or derived from an authenticated HSI envelope identity.
- RequestId MUST NOT be an unconstrained client-chosen value.
- If the transport requires client-supplied idempotency tokens, the kernel MUST bind that token to the authenticated session identity and MUST reject cross-session reuse.

### 3.2 Crash-consistency and "in-doubt" effects (Normative)

Because consume occurs before effect, crashes can create an "in-doubt" window.

- AdmissionKernel MUST persist an effect execution journal (or equivalent) sufficient to classify each RequestId as one of:
  - **NotStarted**, **Started**, **Completed**, **Unknown** (if the boundary cannot confirm).
- If the state is **Unknown** for an enforcement tier flow, AdmissionKernel MUST fail closed:
  - deny output release, and
  - trigger quarantine or session containment as policy dictates.
- Effect execution to external systems MUST carry an idempotency key derived from RequestId (or an HE id) whenever feasible.

**Journal completeness rule (Normative):**
- The journal MUST also persist enough pre-effect bindings to resume safely after restart:
  - request digest,
  - selected as_of_ledger_anchor,
  - policy_root_digest + epoch,
  - witness seed objects (or their deterministic derivation parameters),
  - boundary profile id + enforcement tier.
- Rationale: without this, a restart can silently rebuild join inputs with different bindings.

### 3.3 Plan/execute split and staging safety (Normative)

If the implementation uses a split API (e.g., `plan()` then `execute()`):
- The combined behavior MUST still satisfy `join -> revalidate -> consume -> effect`.
- `AdmissionPlanV1` MUST be:
  - single-use (execute MUST reject re-execution),
  - non-serializable across trust boundaries (no JSON/Proto round-trip),
  - non-cloneable (or execute MUST enforce monotonic state transitions with durable guards).
- Any plan that includes a joined authority MUST be durably staged so that retries after restart can resume or deny deterministically.

## 4. AuthorityJoinInput completeness (Normative)

### 4.1 Join hash commits to ALL required fields
The join commitment (join hash / join digest) MUST commit to all join input fields required for replay safety and semantic non-collision. Omitting any field is equivalent to allowing colliding join hashes for semantically distinct authority requests.

### 4.1.1 Spine join extension object (Normative)

To avoid mutating existing join input structs in-place (see §1.3), Spine v1.1 introduces a versioned join extension object:
- `AdmissionSpineJoinExtV1` (name illustrative; MUST be versioned/bounded/deny-unknown-fields).

Requirements:
- The join commitment MUST commit to the digest of AdmissionSpineJoinExtV1.
- If the existing join input already has a "supplemental commitment" slot, that slot MUST commit to `hash(AdmissionSpineJoinExtV1)`.
- Otherwise, a new join input version MUST be introduced (e.g., `AuthorityJoinInputV2`).

AdmissionSpineJoinExtV1 MUST commit to (minimum):
- RequestId,
- session_id / tenant_id (as applicable),
- tool_class and boundary_profile_id,
- enforcement tier (policy-derived),
- HSI contract manifest digest + envelope binding digest(s),
- canonical request digest (see §5.3),
- effect descriptor digest (tool identity + arguments/content digest + declared idempotency),
- stop/budget digest(s) used for boundary arbitration (RFC-0028/0029),
- selected LedgerAnchorV1 (including ledger_id),
- policy_root_digest + policy_root_epoch,
- witness seed digests (and explicit waiver codes, if any),
- crypto suite identifiers used for verification (algorithm id(s) are explicit, not implicit).

### 4.2 Boundary-flow witness binding is mandatory (seed-at-join, evidence-post-effect)

**Problem being fixed (Normative):** post-effect witness measurements are not available at join time. Requiring final witness hashes at join time creates either (a) impossible ordering, or (b) incentives for "placeholder hashes" that destroy integrity.

Therefore Spine v1.1 splits witness binding into:
- **Join-time witness seeds** (commitment created pre-effect), and
- **Post-effect witness evidence** (measured/derived objects created after effect).

#### 4.2.1 Join-time witness seed commitments (Normative)

The authority join commitment MUST commit to a versioned witness-seed object for each required witness class:

- `leakage_witness_seed_hash`
- `timing_witness_seed_hash`

The witness seed object MUST:
- be created by the daemon (not the client),
- bind at minimum: `{RequestId, session_id, tool_class, boundary_profile_id, LedgerAnchorV1, HT_start}` plus a nonce,
- be hashed with domain separation, and
- be stored or derivable for audit (CAS object, journal staging record, or HE event payload).

**Witness provider provenance (Normative):**
- Witness seed objects MUST also commit to witness provider identity and version (e.g., build digest / module id).
- Rationale: defend against measurement substitution and instrumentation drift.

For enforcement tiers, missing/unknown witness seed commitments MUST deny at join time.

#### 4.2.2 Post-effect witness evidence (Normative)

After effect execution, AdmissionKernel MUST materialize witness evidence objects (e.g., `LeakageWitnessV1`, `TimingWitnessV1`) that:
- include the corresponding witness seed (or a reference to it),
- include measured/derived values (budgets used, observed counts/durations, channel outputs),
- are hashed deterministically with domain separation, and
- are referenced from the AdmissionBundleV1 (see §8).

For enforcement tiers, missing witness evidence MUST deny output release and MUST trigger containment/quarantine per policy.

#### 4.2.3 Waivers (Normative)

For non-enforcement tiers, a waiver path MAY exist, but it MUST be:
- explicit (a typed waiver code, not "missing == ok"),
- committed into the authority intent digest,
- logged in structured form, and
- forbidden for promotion-critical paths unless RFC-0019 explicitly allows it.

## 5. Admission Spine composition contract (Normative)

### 5.1 Admission kernel requirement
All authoritative handlers MUST route admission through a single kernel API ("AdmissionKernel") that owns:
- lifecycle ordering,
- PCAC join input assembly (via canonical builder),
- revalidation reads,
- durable consume barrier,
- effect invocation,
- boundary-flow admissibility and quarantine actions,
- receipt emission and evidence closure.

Handlers may own only:
- bounded decode,
- transport/session plumbing,
- observability (metrics/logging),
- translation between protocol structs and kernel request structs.

**TCB minimization rule (Normative):**
- AdmissionKernel SHOULD be implemented as a small, dependency-minimized module/crate.
- AdmissionKernel MUST NOT depend directly on handler/transport crates.
- AdmissionKernel MUST NOT dynamically load code for authoritative flows (no plugin DL opens) unless the dynamic module is itself measured/verified as part of trust (out-of-scope for v1.1).

### 5.2 Mechanical no-bypass via capabilities (Normative)

Where the implementation language permits (e.g., Rust module privacy / capabilities), authoritative effect surfaces MUST be capability-gated:
- The effect executor/broker client MUST require an `EffectCapability` token that is only constructible by AdmissionKernel.
- Ledger writes for authoritative receipts/events MUST require a `LedgerWriteCapability` token only constructible by AdmissionKernel.
- Quarantine insertion MUST require a `QuarantineCapability` token only constructible by AdmissionKernel.

If capability-gating cannot be implemented, the project MUST provide an equivalent mechanical barrier (link-time restriction, dependency inversion with sealed traits, etc.) plus conformance tests that prove no-bypass.

**Unsafe/capability hardening (Normative):**
- Capability token construction MUST be impossible via safe APIs.
- For Rust implementations, AdmissionKernel (and capability types) SHOULD be `#![forbid(unsafe_code)]` unless an explicit, reviewed exception exists.

### 5.3 Fixed phases and ordering
AdmissionKernel MUST implement phases in this order:

A) Bounded decode (bounded size/time) + parse into a versioned KernelRequestV1
B) HSI session + envelope binding resolution (contract manifest + envelope bindings)
C) Derive boundary context (tool_class, boundary_profile_id, candidate enforcement tier inputs)
D) Resolve ledger validated state + select `as_of_ledger_anchor` (fail closed if missing for fail-closed tiers)
E) Resolve authoritative policy-root state for `as_of_ledger_anchor` (fail closed if missing for fail-closed tiers)
F) Compute canonical request digest:
   - MUST commit to HSI bindings, boundary context, effect descriptor digest, stop/budget digests, and RequestId
G) Create witness seeds + initialize BoundarySpan/output gate
   - witness seed hashes are computed here and committed in the join extension in the next step
H) Build PCAC join input using canonical builder (including AdmissionSpineJoinExtV1 digest)
I) PCAC Join
J) PCAC Revalidate (fresh authoritative inputs; fail-closed tiers MUST check ledger anchor + policy epoch sovereignty)
K) Boundary-flow preconditions (read-only):
   - quarantine pre-checks,
   - output buffer bounds pre-checks,
   - confirm anti-rollback anchor is still valid (fail-closed tiers).
L) Durable consume barrier (and any consume-adjacent durable guards):
   - PCAC Consume (durable single-use barrier; intent equality enforced at consume boundary),
   - effect journal transition to Started,
   - if policy requires mandatory quarantine-on-violation, record a durable reservation token or capacity guard that prevents "cannot quarantine later".
M) Effect execution (tool/broker/etc) THROUGH boundary mediation (no direct release to caller)
N) Post-effect boundary-flow admissibility + witness finalization:
   - materialize authoritative witness evidence objects,
   - apply declassification rules,
   - apply leakage/timing budgets using authoritative witnesses,
   - trigger quarantine/containment if violated,
   - release/withhold output as dictated by enforcement tier and policy.
O) Seal AdmissionBundleV1 (CAS) and obtain AdmissionBundleDigest
P) Emit authoritative receipts/events that reference AdmissionBundleDigest + RequestId
Q) Optional: emit a forward index object/event (e.g., AdmissionOutcomeIndexV1) that references the already-sealed bundle and emitted receipts/events

**Consume conditionality (Normative):**
- Consume MUST be bound to the revalidation state (e.g., by passing a `revalidate_token` to consume, or by making consume revalidate internally).
- It MUST be impossible to consume using stale policy root epoch / stale ledger anchor for enforcement tiers.

**Streaming/output rule (Normative):**
- For fail-closed tiers, it MUST be impossible to stream or release any effect output across a governed boundary before phase N completes.
- If the transport is streaming, fail-closed tiers MUST buffer until post-effect checks complete, unless RFC-0028 explicitly defines chunk-level witness/declassification that is enforced per chunk (out-of-scope for v1.1 unless already specified).

### 5.4 No-bypass rule
The following MUST NOT occur outside AdmissionKernel for authoritative flows:
- invoking the effect executor/broker,
- performing durable consume writes,
- consuming declassification receipts,
- inserting quarantine entries,
- deriving authoritative policy root.
- releasing effect output across a governed boundary without boundary mediation (including streaming partials).

Any direct call sites are security defects.

## 6. Declassification receipt consumption model (Normative)

Declassification (redundancy) receipt consumption MUST be represented as a **PCAC-gated effect** with:
- durable single-use enforced via AJC consumption,
- request-scoped binding in the authority intent digest, including at minimum:
  - receipt hash/id,
  - tool_class,
  - channel_key,
  - argument/content digest,
  - request_id.

Ledger event payloads for "receipt consumed" MUST carry sufficient binding fields to support replay verification and postmortem attribution.

Additionally (Normative):
- "receipt consumed" events MUST include AdmissionBundleDigest (aka AdmissionBindingHash) to make cross-artifact correlation O(1) without ledger scanning.

Uniqueness constraints MUST NOT collide across unrelated receipt event types (scope uniqueness to event_type or use dedicated indexes).

## 7. Quarantine containment semantics (Normative)

If boundary policy mandates quarantine on a violation, quarantine MUST actually occur.

Requirements:
- Quarantine insertion MUST be saturation-safe: if the quarantine table is full and no evictable entry exists, AdmissionKernel MUST deny the request (fail closed).
- Quarantine eviction MUST be priority-aware:
  - active unexpired quarantines triggered by MAJOR+ violations MUST NOT be evicted by lower-priority entries.
  - expired entries are evicted first.
- Quarantine capacity MUST be isolated per session/tenant to prevent cross-session starvation.

**Reservation requirement (Normative):**
- If a policy requires quarantine on violation for a fail-closed tier, AdmissionKernel MUST ensure quarantine capacity is available **before** executing the externalized effect.
- This guarantee MUST be enforced via a durable guard:
  - either a durable reservation token recorded as part of the consume barrier (preferred), OR
  - an equivalent mechanism that makes "cannot quarantine later" structurally impossible for fail-closed tiers.
- If the durable guard cannot be established, AdmissionKernel MUST deny before executing the externalized effect (fail closed).

**Persistence rule (Normative):**
- For fail-closed tiers, quarantine state MUST be restart-safe (persistent). If quarantine state is not persistent/available, fail-closed tiers MUST deny.

**Ledger/audit binding (Normative):**
- Quarantine insertions and evictions MUST be representable as HE events (or have an HE-reducible representation) and MUST include AdmissionBindingHash/RequestId for audit.

## 8. Admission evidence bundle (Normative)

To prevent "missing one hash field" regressions, AdmissionKernel MUST emit a single CAS-stored bundle object (e.g., `AdmissionBundleV1`) referenced by receipts/events.

### 8.1 Digest cycle avoidance (Normative)

Receipts/events referencing the bundle, and the bundle referencing receipts/events, creates a digest cycle.

Therefore:
- `AdmissionBundleV1` MUST be sealed **before** emitting authoritative receipts/events that reference it.
- `AdmissionBundleV1` MUST NOT include hashes/ids of receipts/events that are only created after the bundle is sealed.
- Discovery of "what receipts/events were emitted" MUST be supported by querying for receipts/events that carry the bundle digest (reverse edge).

If a forward index is required for operations, it MUST be a separate object (e.g., an HE event `AdmissionOutcomeIndexV1`) emitted after receipts/events, and it MUST reference the already-sealed bundle digest.

### 8.2 Bundle content (Normative)

Bundle MUST include (at minimum):
- session + HSI envelope binding digests,
- authoritative policy-root digest reference + provenance,
- AJC id and join/consume selector digests,
- intent digest and consume-time intent digest,
- leakage/timing witness **seed** hashes, plus post-effect witness evidence hashes and references to the witness objects,
- effect digest,
- quarantine actions (if any),
- HT/HE anchors necessary to reproduce time predicates and policy-root selection.

Promotion-critical paths MUST also include the CAC overlay objects required by RFC-0019 traceability.

**CAC digest-cycle guard (Normative):**
- If a CAC overlay object would introduce a digest cycle (e.g., it requires receipt ids emitted after bundle sealing), it MUST NOT be included in AdmissionBundleV1.
- Instead, it MUST be emitted as a post-bundle object/event that references AdmissionBundleDigest (reverse-edge discoverable).

### 8.3 Confidentiality + bounds (Normative)

- AdmissionBundleV1 MUST be a bounded object (size limits on strings/arrays; no unbounded blobs).
- AdmissionBundleV1 MUST deny unknown fields.
- If AdmissionBundleV1 contains sensitive material (tool arguments, content digests, witness details), it MUST be stored with access control consistent with RFC-0019 evidence handling. If the CAS supports encryption-at-rest or envelope encryption, it SHOULD be used.
- AdmissionKernel MUST ensure observability output does not leak sensitive bundle fields (see §1.2 #11).

## 9. Conformance tests (Normative)

A conformance suite MUST exist that fails CI if:
- any authoritative endpoint bypasses AdmissionKernel,
- lifecycle ordering is violated,
- consume can occur without durable persistence,
- replay is possible across restart,
- enforcement tiers accept missing authoritative policy-root or missing witness commitments,
- quarantine-mandated actions can be dropped ("log and proceed") OR quarantine reservation is bypassed,
- admission hot paths scan unbounded ledger history.

Additionally (Normative), CI MUST fail if:
- an enforcement-tier flow can release any effect output across a governed boundary before post-effect boundary checks complete (including streaming partials),
- witness seed commitments can be supplied by the client or altered post-join,
- AdmissionBundle digest cycles are introduced (bundle depends on receipt ids that depend on bundle),
- capability-gated effect surfaces can be invoked from outside AdmissionKernel (where capability gating exists).
- fail-closed tiers can run without a verified anti-rollback anchor (§2.4),
- enforcement tier or mode can be downgraded by client-controlled inputs,
- cross-tenant/session identity confusion is possible (RequestId/session_id mismatch accepted).

## Appendix A — Required kernel-facing interfaces (Normative)

This appendix exists to eliminate underspecified seams. Implementations MAY vary, but the invariants MUST be expressible by these interfaces.

```rust
/// Produced only after ledger startup verification establishes trust.
pub struct ValidatedLedgerStateV1 {
    pub validated_anchor: LedgerAnchorV1,
    pub tip_anchor: LedgerAnchorV1,
    pub ledger_keyset_digest: Digest,
    pub root_trust_bundle_digest: Digest,
}

pub trait LedgerTrustVerifier {
    fn validated_state(&self) -> Result<ValidatedLedgerStateV1, TrustError>;
}

/// External anti-rollback anchoring for fail-closed tiers.
pub trait AntiRollbackAnchor {
    /// Returns the most recently verified external anchor state, if available.
    fn latest(&self) -> Result<ExternalAnchorStateV1, TrustError>;

    /// Verifies that `anchor` is committed externally (or that external state is >= anchor).
    fn verify_committed(&self, anchor: &LedgerAnchorV1) -> Result<(), TrustError>;
}

pub struct PolicyRootStateV1 {
    pub policy_root_digest: Digest,
    pub policy_root_epoch: u64,
    pub anchor: LedgerAnchorV1,
    pub provenance: GovernanceProvenanceV1,
}

pub trait PolicyRootResolver {
    fn resolve(&self, as_of: &LedgerAnchorV1) -> Result<PolicyRootStateV1, PolicyError>;
}

pub struct WitnessSeedV1 { /* bounded, deny_unknown_fields */ }
pub struct LeakageWitnessV1 { /* bounded, deny_unknown_fields */ }
pub struct TimingWitnessV1 { /* bounded, deny_unknown_fields */ }

pub trait WitnessProvider {
    fn make_seeds(&self, req: &KernelRequestV1, as_of: &LedgerAnchorV1) -> Result<WitnessSeedsV1, WitnessError>;
    fn finalize(&self, span: &BoundarySpanV1) -> Result<WitnessEvidenceV1, WitnessError>;
}

/// Mediates governed boundary output (buffering/gating) and yields a span for witness finalization.
pub trait BoundaryMediator {
    fn begin(&self, req: &KernelRequestV1) -> Result<BoundarySpanV1, BoundaryError>;
    fn finish(&self, span: BoundarySpanV1) -> Result<BoundaryOutcomeV1, BoundaryError>;
}

pub struct AdmissionPlanV1 { /* join_id, intent_digest, revalidate inputs, etc. */ }
pub struct AdmissionResultV1 { /* bundle_digest, receipts, response */ }

pub trait AdmissionKernel {
    fn plan(&self, req: KernelRequestV1) -> Result<AdmissionPlanV1, AdmitError>;
    fn execute(&self, plan: AdmissionPlanV1) -> Result<AdmissionResultV1, AdmitError>;
}
```