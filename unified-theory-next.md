# Unified Theory vNext — Proof‑Admitted Stigmergic Morphogenesis (PASM)

```json
{
  "cac": {
    "doc": "v1",
    "id": "dcp://apm2.local/documents/theory/unified_theory_vnext_pasm@v1",
    "title": "Unified Theory vNext — Proof‑Admitted Stigmergic Morphogenesis (PASM)",
    "status": "DRAFT",
    "derives_from": [
      "Stigmergic Holonic Kernel Theory",
      "Verifiable Morphogenetic Kernel (Codex)",
      "Proof‑Admitted Morphogenetic Economy",
      "Verifiable Morphogenetic Kernel (Opus)",
      "APM2 Unified Theory + Laws + Principles + HSI + HTF"
    ],
    "supersedes_intent": [
      "documents/theory/unified_theory.json (as the primary ontology narrative)",
      "documents/theory/laws.json (as a peer-axiom catalogue)"
    ],
    "non_goals": [
      "This is not a transport RFC.",
      "This is not an implementation plan for a single architecture family.",
      "This is not a backwards compatible migration guide (APM2 is pre‑live)."
    ]
  }
}
```

## 0. Thesis

APM2 should be modeled as a **proof‑admitted stigmergic morphogenesis**:

- **Stigmergic:** holons coordinate primarily by **modifying a shared environment** (ledger + CAS), not by direct messaging as a primitive.
- **Proof‑admitted:** nothing becomes authoritative without **receipt‑bound, replayable closure**.
- **Morphogenetic:** specialization and hierarchy are not assigned; they **emerge** under scarcity from local rules, like tissues differentiating under gradients.

This rewrite targets a **genome** (minimal generative principles), not another taxonomy. The existing APM2 theory is largely correct; it is just **not organized around its generators**.

The convergence across the four candidate theories is genuine. Disagreements are mostly about:

- **axiom vs theorem** (especially MDL/compression), and
- **global vs local computability** (emergence requires local objectives).

---

## 1. Convergence across the four theories

### 1.1 Hard convergence (the shared load‑bearing core)

All four theories independently converge on these invariants:

1) **Boundary / Markov blanket** is non‑negotiable.
   - Internal state is private and ephemeral; only typed commitments cross the boundary.

2) **Monotone truth substrate** is non‑negotiable.
   - Truth is append‑only, tamper‑evident, content‑addressed evidence pointers.
   - Convergence is explicit: you must declare a merge algebra (CRDT / join‑semilattice family).

3) **Authority attenuation + scarcity** is non‑negotiable.
   - Capabilities are default‑deny and can only attenuate by delegation.
   - Budgets/stop conditions are mandatory; unbounded search/actuation is a defect.

4) **Promotion is closure under receipts**.
   - Authoritativeness is not “decided”; it is **admitted** by a closure operator over facts.

5) **Composition/self‑assembly must itself be gated**.
   - “A composite holon exists” must be an authoritative fact admitted by receipts, not a runtime convention.

6) **Anti‑Goodhart must be structural**.
   - “Pair each metric with countermetrics” is necessary but insufficient; the admissibility calculus must require independent evidence channels and dynamic adversarial updating.

### 1.2 Real disagreements (and explicit resolutions)

**Disagreement A: Is MDL/compression an axiom?**
- Some drafts treat “compression selection pressure” as an axiom.
- Opus argues MDL is a theorem: scarcity (budgets) + receipt requirements implies compression pressure.

**Resolution:** MDL/compression is a theorem.
- Making MDL an axiom over‑specifies the kernel and tempts you into encoding global objectives that are not locally computable.

**Disagreement B: Is the emergence objective global?**
- Multiple drafts define a global objective `J(u)`.
- Opus is correct: self‑organization requires **local computability**.

**Resolution:** the kernel defines **local fitness** (computable from boundary‑available signals and receipted outcomes). Global structure is emergent.

### 1.3 The reframes that survive a rewrite

1) **Ledger ≠ log. Ledger = world.**
   The ledger/CAS pair is the stigmergic environment. “Messaging protocols” collapse into “write facts / read facts,” with direct messaging treated as a performance optimization.

2) **Orchestration dissolves with intelligence.**
   Supervisory state machines are scaffolding. The irreducible infrastructure is boundary + substrate + authority + closure.

3) **Formation is a high‑leverage actuation.**
   Hierarchy formation changes failure modes, externalities, and verification economics. It must be proof‑admitted like merges/deploys.

---

## 2. Kernel genome

The genome is deliberately small:

- **One meta‑constraint**: dominance ordering (containment/security > correctness > liveness).
- **Four axioms**: Boundary, Substrate, Authority, Closure.

Everything else (MDL pressure, specialization, hierarchy, morphogenetic fields, quorum promotion, anti‑Goodhart ecology, counterexample ratchet) is derived.

### 2.Ω Meta‑constraint: Dominance ordering

> **Containment/Security constraints** > **Verification/Correctness constraints** > **Liveness/Progress objectives**.

This is already APM2 invariant **INV‑F‑14**. vNext makes it the explicit top‑level ordering for all disputes.

Operational rule:
- If security/containment can’t be satisfied: **deny**, **decompose**, **escalate**, **record**.
- If correctness can’t be satisfied: **deny**, **record**.
- Only optimize liveness inside the admissible region.

### 2.1 Axiom 1: Boundary

> A holon is a Markov‑blanketed actor with sealed, typed boundary channels; internal state is private and ephemeral; only deliberate commitments cross the boundary.

**Formal object:**

A holon `h` is a tuple:

`h = (Id_h, ∂h, X_h, K_h)`

- `Id_h`: self‑certifying identity (public‑key rooted)
- `∂h`: boundary contract (typed channels + schemas + policy epoch pins)
- `X_h`: private ephemeral state (dies with the process)
- `K_h`: commitment filter selecting which outputs become durable facts

**Hard constraints:**
- Untyped/ad‑hoc boundary content is forbidden.
- Any state crossing the boundary must be canonicalized before hashing/signing.
- Boundary surfaces must be stable under composition (scale invariance).

**What this buys you:**
- Scale invariance: the same contract holds at every recursion depth.
- Mechanical enforcement: boundary commitments become admissible objects for closure.

**APM2 alignment:**
- HB‑01..HB‑06, LAW‑16, INV‑F‑03, INV‑F‑11; HSI “no ambient authority” + canonicalization.

### 2.2 Axiom 2: Substrate

> Authoritative facts live in a monotone truth substrate: an append‑only, tamper‑evident event DAG with content‑addressed evidence pointers; convergence is explicit via a declared merge algebra.

**Formal object:**

Let `(L, ⊔)` be a join‑semilattice of facts.
- `⊔` is commutative, associative, idempotent.
- Partial order `x ⊑ y` defined by `x ⊔ y = y`.

Facts are stored as:
- **Ledger**: hash‑chained signed events
- **CAS**: content‑addressed artifacts referenced by hash

**CRDT interpretation:**
The semilattice is the algebraic core of CRDTs. Anti‑entropy is the operationalization.

**Bounded views (critical):**
Holons operate on bounded `ViewCommitment`s (ContextPacks/snapshots/summaries) that pin ledger heads and provide selectors for omitted referenced facts.

**Time authority:**
Normative ordering/expiry is anchored to HTF envelopes (LedgerTime + MonotonicTicks + CausalTime), not wall clocks.

**APM2 alignment:**
- TRUTH‑AX‑01..07, LAW‑03, LAW‑10, INV‑F‑01, INV‑F‑07, INV‑F‑12, INV‑F‑13; RFC‑0016 (HTF); HSI digest‑first.

### 2.3 Axiom 3: Authority

> Authority is attenuable, capability‑scoped, and budget‑bounded. There is no ambient authority. Stop conditions are mandatory and fail‑closed.

**Formal object:**

Let `(C, ≤)` be a poset of capabilities (authority lattice).

Delegation obeys:

`cap_child ≤ cap_parent`

Budgets form an ordered commutative monoid `(B, +, 0, ≤)`.

Every effectful action consumes budget and must check stop state.

**Hard constraints:**
- Default‑deny capabilities.
- Time/budget bounds are mandatory.
- Missing/unverifiable stop state is deny/terminate.

**Scarcity note:**
Scarcity is the conserved quantity that creates selection pressure. Without budgets, there is no comparative advantage and no forced compression.

**APM2 alignment:**
- LAW‑05, LAW‑12, LAW‑18; INV‑F‑05, INV‑F‑09, INV‑F‑11; HSI PermeabilityReceiptV1.

### 2.4 Axiom 4: Closure

> No authoritative transition exists outside proof‑admitted closure: gate predicates applied to facts must produce machine‑checkable, replayable receipts bound to evidence.

**Formal object:**

Define a closure operator `Cl_P : L → L` parameterized by policy/gates `P`.

Closure must be:
- **extensive**: `x ⊑ Cl(x)`
- **monotone**: `x ⊑ y ⇒ Cl(x) ⊑ Cl(y)`
- **idempotent**: `Cl(Cl(x)) = Cl(x)`

A claim is authoritative iff it lies in the image of `Cl_P`.

**Verdict semilattice (Gemini‑class bug prevention):**

Define verdicts as a semilattice:

`FAIL ⊒ PENDING ⊒ PASS`

Join is `max` (FAIL dominates).

**Rule:**
- If any authoritative FAIL exists → overall FAIL.
- Else if required evidence categories are missing/invalid → PENDING (or FAIL for Tier2+ by policy).
- Else → PASS.

Missing evidence must never mask a present FAIL.

**APM2 alignment:**
- LAW‑01, LAW‑14, LAW‑15, LAW‑17, LAW‑19, LAW‑20; INV‑F‑02, INV‑F‑10, INV‑F‑15.

---

## 3. Minimal mathematical substrate

Enough math to make recursion and emergence provable; not enough to become performative.

### 3.1 Core algebra

The kernel lives on four algebraic objects:

1) `L`: join‑semilattice of facts (CRDT algebra)
2) `C`: poset of capabilities/authority
3) `B`: ordered commutative monoid of budgets
4) `Cl`: closure operator over `L`

Everything else is construction.

### 3.2 Categorical view (optional but useful)

Define a category `Hol`:
- Objects: holons
- Morphisms: boundary‑typed interactions (receipt‑bound when effectful)
- Monoidal product `⊗`: holon composition

Define a functor `Commit: Hol → Sub(L)` mapping each holon to the subset of facts it commits.

Functoriality constraint:

`Commit(h1 ⊗ h2) = Commit(h1) ⊔ Commit(h2) ⊔ Commit(boundary_receipts)`

Define `Cl` as a monad/closure on `L`. If `Commit` is functorial and `Cl` is a monad on a semilattice, then closure under composition (LAW‑16) is structural: nested holons preserve admissibility.

---

## 4. Emergence theorems

The point of the rewrite: emergence should be an expected equilibrium class under the axioms, not a wish.

### 4.1 Theorem: MDL/compression pressure is forced

**Claim:** Under bounded budgets (Axiom 3) and receipt‑bound promotion (Axiom 4), holons are forced to compress their internal models. MDL pressure is a theorem; it is the Lagrange multiplier of scarcity.

Sketch:
- Let `R(M, π)` be expected receipt quality from model/policy `(M, π)`.
- Let `C(M, π)` be cost under budget `B`.
- Maximize `R` subject to `C ≤ B` ⇒ Lagrangian `R − λ·C`.
- `λ` is the shadow price of budget scarcity.
- Decomposing `C` yields description length + coordination + verification cost terms.

### 4.2 Theorem: specialization emerges from comparative advantage

**Claim:** With heterogeneous cost structures and non‑zero delegation overhead, specialization emerges when delegation cost falls below comparative advantage margin.

This yields a measurable phase transition:
- Small scale/high per‑delegation overhead ⇒ generalism.
- Large scale/amortized overhead ⇒ specialization.

### 4.3 Theorem: hierarchical self‑assembly emerges from coordination cost

Model holons as nodes in an interaction graph `G=(V,E,w)` where `w(i,j)` is boundary‑crossing coordination cost.

A subset `S` forms a composite `Φ(S)` when:

`I(S) − B(S) − F(S) > τ(risk)`

- `I(S)`: internal coordination cost
- `B(S)`: composite boundary maintenance cost
- `F(S)`: formation proof cost
- `τ(risk)`: risk‑tier threshold (dominance can veto)

Hierarchy depth is discovered from multi‑scale clustering in `G`; it is not designed.

### 4.4 Theorem: morphogenetic fields are derived substrate observables

Morphogens are not “new infrastructure.” They are low‑dimensional observables computed from bounded views `V_h ⊂ L`.

Examples:
- Density `ρ`: facts admitted per ledger window
- Tension `σ`: conflict/fork fraction
- Flow `φ`: evidence bytes crossing boundary per tick
- Pressure `P`: budget_consumed / budget_available
- Temperature `T`: variance of receipt quality
- Gradient `∇f`: difference of any scalar field across neighbors

Holons read gradients and self‑specialize.

### 4.5 Theorem: quorum sensing is a closure predicate

A quorum predicate is just:

“Do N independent attestations exist for subject_hash X within freshness bound, excluding conflicts of interest, from ≥K verifier families?”

When true, closure admits `Promoted(X)`.

Supervisor state machines are an optimization layer, not a primitive.

### 4.6 Theorem: two‑speed truth is required at scale

Two loops exist:
- **Fast private loop:** ephemeral reasoning, high‑frequency
- **Slow public settlement loop:** receipts, closure, invariants

The settlement loop must export invariant checks, not just outcomes.

### 4.7 Theorem: crystallization is an economic necessity

Repeated “hot reasoning” without producing a reusable “cold artifact” is a budget leak.

A usable promotion rule:

`PromoteArtifact iff E[N_future] * (C_reason − C_exec) > C_build + C_verify + C_maint`

A thaw path is mandatory: drift triggers artifact retirement/retraining with receipts.

---

## 5. Derived primitives (biology + frontier)

Not axioms: mechanisms that become inevitable at scale.

### 5.1 Apoptosis as containment

Holons must self‑terminate on internal integrity failure (containment), not only crash/restart as recovery.

Example triggers:
- own outputs fail signature/seal self‑verification
- capability manifest hash mismatch vs policy root
- view commitment staleness beyond risk policy
- stop state missing/unverifiable
- sustained pack‑miss rate (operating blind)

Action:
- publish ApoptosisReceipt (why)
- revoke/return delegated capabilities
- terminate immediately

Cancer is what happens when self‑termination fails.

### 5.2 Horizontal knowledge transfer (plasmids)

Authority remains hierarchical; knowledge should be horizontal.

Define a `KnowledgeArtifact` (CAS object) with:
- content hash
- provenance (origin holon)
- effectiveness evidence (receipts)
- adoption prerequisites (capability refs)

Holons adopt locally; no authority transfer occurs.

### 5.3 Immune memory as counterexample compilation

Defects must compile into admission filters:
- detect recurring failure patterns
- encode as typed predicates
- require predicates in future gate sets

This mechanizes LAW‑01 (convert failures into stronger primitives).

### 5.4 Dynamic anti‑Goodhart (beyond static countermetrics)

Static metric+countermetric pairs are necessary but insufficient: any finite metric set can be gamed.

Kernel‑compatible defense:
- randomized audits
- holdout/adversarial suites updated by counterexample ratchet
- verifier family diversity constraints
- influence decay without fresh receipts

### 5.5 VDF/VRF for delay and unbiased sampling (optional implementation family)

When you need “challenge windows” or unbiased audit sampling without wall‑clock authority:

- Use a VDF seeded by a ledger anchor to create a verifiable delay barrier.
- Use VRF‑style sampling keyed by policy root to select auditors.

This is not required for Phase 1, but becomes valuable under adversarial federation.

---

## 6. Admission calculus: formation and specialization

### 6.1 Formation is just another closure event

A composite holon exists iff closure admits a `CompositeAdmission` fact.

Formation receipt must prove:
- membership set (identities + proofs)
- boundary contract hash
- authority meet proof (no inflation)
- budget envelope + stop semantics
- compression/coordination gain witness
- risk envelope satisfaction
- replay package hash

### 6.2 Specialization claims are closure‑admitted

A specialization claim “I am now a verifier/synthesizer for X” must carry:
- performance receipts on holdout traces
- countermetric receipts
- verifier diversity witnesses
- freshness/expiry rules (decay)

No receipts → no influence.

---

## 7. Scale envelope: evidence economics and recoverability

At civilizational scale, the bottleneck is verification economics + bandwidth locality + durability.

### 7.1 Evidence tiering

Define evidence tiers with explicit retention/replication policies:

- Hot: high‑frequency, small receipts, replicated
- Warm: medium artifacts, erasure‑coded
- Cold: archival, deep erasure + geo distribution

Summaries are allowed for planning, but exact gates must zoom to underlying evidence (INV‑F‑04).

### 7.2 Recoverability contracts

For artifacts at required risk tiers (INV‑F‑16), each artifact must carry a recoverability contract:
- K‑of‑N threshold, redundancy family
- failure domain model
- unrecoverable probability bound
- repair receipts

Missing/stale recoverability evidence is fail‑closed.

---

## 8. Threat model extensions (emergence‑specific)

Emergence introduces novel attack surfaces:

- Composite spoofing
- Delegation laundering (authority inflation via recursion)
- Summary inflation (lossy claims masquerading as exact)
- Formation storms (churn as DoS)
- Objective capture (corrupting selection pressure)

Kernel defenses:
- closure‑admitted formation with authority meet proofs
- mandatory replayability and holdouts
- rate‑limited formation under budgets
- dynamic anti‑Goodhart audits

---

## 9. Falsifiable hypotheses (system‑level tests)

1) **Orchestration LOC decreases with agent capability.**
2) **Quorum closure scales better than supervisor aggregation.**
3) **Apoptosis reduces corruption propagation delay.**
4) **Gradient self‑specialization adapts faster than role assignment.**
5) **Formation receipts prevent authority inflation.**

Each hypothesis needs: intervention, metric, falsifier.

---

## 10. Engineering rewrite milestones (safe rollout)

This is theory‑driven engineering. The rewrite is meaningless without a safe execution path.

### Milestone 0 — Genome extraction and proof sketching

**Deliverables**
- This kernel doc + a LAW/INV mapping matrix.
- Axioms vs theorems reclassification.
- A “minimum admissible object set” (fact kinds, receipt kinds, canonical hashes).

**Acceptance**
- Every INV‑F is either an axiom clause or a derived theorem.
- No theorem contradicts HSI enforcement constraints.

### Milestone 1 — Verdict lattice + fail‑closed semantics (Gemini‑class fixes)

**Purpose**
Make the closure layer physically executable: no ambiguous or optimistic aggregation.

**Subtasks**
- Encode verdict semilattice join (`FAIL ⊒ PENDING ⊒ PASS`) in gate reducers.
- Ensure missing evidence cannot mask an existing FAIL.
- Decide policy for invalid/mismatched artifacts:
  - Tier0–Tier1: may treat as PENDING with explicit defect.
  - Tier2+: should likely FAIL‑closed.
- Update fixtures to cover:
  - missing artifacts
  - invalid artifacts (parse error, mismatched PR, stale SHA)
  - untrusted reviewer
- Workflow output mapping:
  - unknown/missing gate_state must default to failure
  - do not assume outputs are set
- CI drift hardening:
  - evaluate `needs` results programmatically (avoid hand lists)

**Acceptance**
- Property tests: FAIL dominates PENDING across all combinations.
- Fixtures encode semantics explicitly.

### Milestone 2 — Closure reducer as a pure function

**Purpose**
Make “promotion” a query over facts, not a privileged orchestrator action.

**Subtasks**
- Implement closure predicates as deterministic reducers over ledger facts.
- Enforce reducer purity:
  - no wall‑clock reads
  - no network calls
  - no randomness (unless seeded and receipted)
- Expose closure as:
  - `evaluate(facts, policy_root) -> admitted_facts + receipts`

**Acceptance**
- Replay determinism: same inputs ⇒ same outputs.
- Idempotence: repeated evaluation yields identical admitted sets.

### Milestone 3 — CompositeHolonAdmission receipts

**Purpose**
Make holon formation/dissolution governed facts.

**Subtasks**
- Define receipt schemas:
  - FormationIntent
  - FormationEvidenceBundle
  - FormationReceipt
  - DissolutionReceipt
- Admission predicate enforces:
  - authority meet proof
  - budget/stop binding
  - formation gain witness
  - risk envelope compliance
- Add formation rate limiting (budgeted fanout)

**Acceptance**
- No composition event can widen authority.
- Formation storm attempts are bounded by budgets.

### Milestone 4 — Morphogenetic field signals

**Purpose**
Replace explicit role assignment with endogenous gradients.

**Subtasks**
- Define field schemas (ρ, σ, φ, P, T, ∇f).
- Emit fields as derived facts (monotone).
- Implement subscription narrowing:
  - `ScopeEntropy ≤ WindowBudget` must be enforced
- Add sentinel reconciliation channels to prevent global coherence collapse.

**Acceptance**
- Under workload shifts, holons re‑orient without supervisor commands.

### Milestone 5 — Specialization market (proof‑admitted)

**Purpose**
Turn “I am a specialist” into a mechanically audited claim.

**Subtasks**
- Define specialization receipts with:
  - holdout performance evidence
  - countermetric evidence
  - verifier family diversity witnesses
  - decay schedule + revocation hooks
- Add randomized audits (VRF/VDF optional)

**Acceptance**
- Specialists cannot maintain influence without fresh receipts.

### Milestone 6 — Apoptosis triggers

**Purpose**
Reduce corruption propagation delay to near‑zero.

**Subtasks**
- Implement intrinsic termination conditions in holon runtime.
- Require ApoptosisReceipt publication on termination.
- Integrate with stop state / capability revocation.

**Acceptance**
- Injected integrity failures are detected at the source earlier than external monitoring.

### Milestone 7 — Exabyte‑scale verifier economics

**Purpose**
Make verification and storage viable at extreme scale.

**Subtasks**
- Add proof compression:
  - Merkle batch attestations
  - O(1) signature/quorum checks per batch
- Add explicit evidence tiering policies.
- Add recoverability receipts + repair receipts.

**Acceptance**
- Verification cost scales sublinearly with receipt volume.

### Milestone 8 — Remove scaffolding

**Purpose**
Let intelligence collapse orchestration.

**Subtasks**
- De‑emphasize OrchestrationState in favor of closure queries.
- Replace supervisor coordination with quorum predicates where safe.
- Treat direct messaging as optimization only.

**Acceptance**
- Equivalent workloads run with less orchestration logic and equal or better safety.

---

## Appendix A — Mapping to existing APM2 theory

The kernel aligns tightly with current invariants and laws:

- Boundary ↔ HB‑01..06, LAW‑16, INV‑F‑03
- Substrate ↔ TRUTH‑AX‑01..07, LAW‑03, LAW‑10, INV‑F‑01, INV‑F‑07, INV‑F‑12, INV‑F‑13
- Authority ↔ LAW‑05, LAW‑12, LAW‑18, INV‑F‑05, INV‑F‑09, INV‑F‑11
- Closure ↔ LAW‑01, LAW‑14, LAW‑15, LAW‑19, LAW‑20, INV‑F‑02, INV‑F‑15
- Dominance ↔ INV‑F‑14

Rewrite goal: reorganize the existing doctrine into:
- **Axioms** (genome)
- **Theorems** (derived laws)
- **Mechanisms** (implementations)

---

## Appendix B — Active inference interpretation (optional, but high‑leverage)

This appendix is *not* normative. It is an interpretation layer that helps reason about specialization and hierarchy as inevitable.

### B.1 Markov blankets are already the boundary axiom

Active inference starts with a Markov blanket separating internal state from external state. That is exactly Axiom 1.

### B.2 Free energy maps onto APM2 scarcity + verification

Let a holon maintain a variational belief `q(s)` over latent state `s` given observations `o` (its ContextPack/view).

Variational free energy:

`F(q) = E_q[-log p(o,s)] + KL(q(s) || p(s))`

- The first term corresponds to prediction error/surprise.
- The KL term corresponds to model complexity.

Under APM2, **receipts** and **gate outcomes** are the only durable feedback signals. Budgets bound computation. The local objective becomes:

`minimize: Complexity + ExpectedReceiptFailure + CoordinationCost`

This is the same functional that appears as “MDL pressure” in §4.1.

### B.3 Hierarchical self‑assembly as nested blankets

In active inference, nested systems are modeled as nested Markov blankets. That gives a clean mental model for holon composition:

- sub‑holons are internal dynamics behind a composite boundary
- the composite exports a lower‑dimensional interface (summary receipts) that reduces boundary entropy

### B.4 Morphogenetic fields as prediction‑error gradients

Field signals (ρ, σ, T, etc.) can be interpreted as low‑dimensional proxies for:

- uncertainty (variance of receipt quality)
- prediction error (conflict/tension)
- energetic pressure (budget burn rate)

Holons “follow gradients” because doing so reduces expected free energy under budget.

### B.5 Discriminating test

If this mapping is correct:
- specialization should correlate with reduction in local free energy proxies (lower receipt failure variance, lower coordination fraction)
- composite formation should correlate with reduced boundary entropy per accepted promotion

---

## Appendix C — Implementation families (solution‑neutral stance)

PASM constrains semantics, not architecture. Multiple implementation families remain admissible:

- Ledger replication: RAFT, BFT for control plane, convergent replication for data plane
- Evidence store: object store + erasure coding, content‑addressed filesystem, CAS over log‑structured storage
- Quorum predicates: on‑ledger reducers, map‑reduce over index snapshots, incremental materialized views
- Audit randomness: VRF, VDF, or policy‑driven deterministic sampling

Hard constraint: whichever family you choose must preserve the axioms and admit replayable receipts.
