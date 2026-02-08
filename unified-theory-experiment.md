Below is the smallest **engineering demo** I’d put into the APM2 repo that still genuinely tests the PASM/VMK claims: stigmergic coordination, proof‑admitted transitions, morphogenetic specialization, and hierarchical self‑assembly—**without baking in orchestration**. It is deliberately a **laboratory harness**, not “production APM2.” It must be:

* **mechanically checkable**
* **parameterizable**
* **observable**
* **fail‑closed by default**
* **cheap enough to run repeatedly** (so you can explore phase changes)

This design treats “unified theory” as a **machine-readable genome** (spec) and the demo as the **interpreter** of that genome.   

---

## 0) What this demo must prove (and what it must not fake)

### The thesis we’re testing

PASM claims: **stigmergic substrate + proof‑admitted closure + scarcity-driven morphogenesis** is sufficient to produce specialization and hierarchy as an attractor, not as an assignment. 

VMK adds: **composition itself must be a closure‑admitted event** with explicit admissibility (compression/verification economics + risk envelope + replay evidence). 

### What the demo must demonstrate, minimally

1. **Specialization emerges** from local decision rules under scarcity (not from role assignment).
2. **Hierarchy emerges** via **closure‑admitted composition** (not “manager scheduling”).
3. **Governance remains mechanical**: anything “authoritative” is admitted by receipts and quorum predicates; fail-closed beats throughput. 

### What the demo must not do (avoid fake emergence)

* No hard-coded “you are a verifier” / “you are an implementer” assignments.
* No central planner that “forms teams” because you programmed it to.
* No hidden global state that agents read besides the ledger/CAS projections.

---

## 1) Minimal mathematical kernel the demo actually executes

This is the minimal math that creates emergence while remaining verifiable and scale-invariant. It is essentially the “VMK algebra” put under a microscope. 

### 1.1 Objects (types)

* **Truth substrate**: `(L, ⊔)` a **join‑semilattice** of facts (monotone; append-only); implemented as ledger + CAS pointers.
* **Authority**: `(A, ≤)` a **poset** (capability attenuation). No escalation.
* **Budget**: `(B, +, ≤)` a **monoid** with order (resource scarcity).
* **Closure operator**: `Cl_P : L → L` (idempotent, monotone, extensive) that admits facts only with valid receipts + quorum.

### 1.2 Operators (the “genome primitives”)

1. **Accumulate**: `x ⊔ y` (facts accumulate; never delete)
2. **Attenuate**: `a_child ≤ a_parent`
3. **Close**: `Cl_P(claim) = admitted_fact` iff receipts satisfy predicate `P`
4. **Differentiate**: `Diff(h, scope)` creates a new holon with narrower contract
5. **Compose**: `Φ(S)` proposes a composite holon from a set `S`
6. **Ratchet**: `Ratchet(counterexample) → stronger P` (defect → stronger gate)

### 1.3 The one inequality that triggers self-assembly

A composite `H = Φ(S)` is closure‑admissible iff it proves (on replayable traces):

[
\Delta = (DL(S) + VC(S)) - (DL(H) + VC(H)) \ge \tau
]

subject to:

* authority safety: `A_H ≤ meet(A_s_delegable)`
* risk envelope: `Risk(H) ≤ ParentRiskBudget`
* replayability: all claimed deltas are receipted on holdout traces

This is the “composition is an admitted theorem, not a social convention” move. 

---

## 2) The minimal demo you can run inside the repo

### Name it explicitly

Add a lab command:

* `apm2 lab morphogenesis --spec documents/lab/pasm_demo_spec.v1.json`

This is a CLI-only harness; it does not touch daemon prod paths.

### Use APM2 primitives, not a parallel universe

Reuse these existing modules (you already have the pieces):

* `apm2-core::ledger::Ledger` (in-memory is fine for v0)
* `apm2-core::evidence::MemoryCas`
* `apm2-core::work::WorkReducer` (optional, but useful)
* `apm2-core::budget::BudgetTracker`
* `apm2-core::crypto::Signer` for holon identities (even if you don’t enforce `append_verified` for every event type yet)
* (optional) `apm2-core::capsule::AdmissionGate` for “Tier3 requires admitted capsule profile”

This keeps the demo aligned with your real kernel instead of inventing new scaffolding.

---

## 3) Machine-readable spec: the “genome” for the demo

You want a spec that:

* is **small**
* exposes **tunable parameters**
* is **interpretable** (not a narrative doc)
* can be versioned and hashed for replay

### 3.1 Spec file shape

Create `documents/lab/pasm_demo_spec.v1.json`:

```json
{
  "kind": "apm2.lab.pasm_demo_spec",
  "meta": {
    "id": "dcp://apm2.local/lab/pasm_demo_spec@v1",
    "classification": "INTERNAL",
    "integrity": { "attestation_required_for_enforcement": false }
  },
  "payload": {
    "theory_refs": [
      "documents/theory/unified_theory.json",
      "documents/theory/laws.json",
      "documents/theory/principles.json"
    ],
    "kernel": {
      "dominance_order": "containment > verification > liveness",
      "closure": {
        "quorum_k": 2,
        "quorum_n": 3,
        "fail_closed": true,
        "pending_semantics": "pending_only_if_missing_receipts_and_no_authoritative_fail"
      },
      "composition": {
        "tau_compression_gain": 0.15,
        "require_holdout_replay": true,
        "max_composite_size": 8
      }
    },
    "world": {
      "seed": 1,
      "ticks": 2000,
      "work_arrival_rate_per_tick": 4,
      "replicas": 1,
      "anti_entropy_interval_ticks": 0
    },
    "holons": {
      "population": 24,
      "window_budget": 128,
      "initial_budget": { "token": 100000, "tool_calls": 1000, "time_ms": 600000 },
      "apoptosis": {
        "on_invariant_violation": true,
        "on_budget_exceeded": true,
        "on_pack_miss_rate_gt": 0.25
      },
      "learning": {
        "policy_family": "active_inference_softmax",
        "temperature": 0.7,
        "learning_rate": 0.05,
        "exploration_floor": 0.02,
        "artifact_crystallization": {
          "enabled": true,
          "reuse_horizon": 20,
          "crystallize_threshold": 0.6,
          "thaw_if_drift": true,
          "drift_window": 200
        }
      }
    },
    "work_model": {
      "types": [
        { "id": "A", "value": 1.0, "complexity": 16, "skills_required": ["a"] },
        { "id": "B", "value": 1.0, "complexity": 16, "skills_required": ["b"] },
        { "id": "C", "value": 3.0, "complexity": 64, "skills_required": ["a", "b", "integrate"] }
      ]
    },
    "objective": {
      "hard_constraints": [
        "no_authority_escalation",
        "receipt_bound_promotion",
        "budget_enforced"
      ],
      "score": {
        "value_completed": 1.0,
        "penalty_fail": 2.0,
        "penalty_policy_violation": 10.0,
        "cost_tokens": 0.00001,
        "cost_verification": 0.1,
        "cost_description_length": 0.05
      },
      "countermetrics": [
        { "id": "defect_recurrence", "max": 0.02, "penalty_multiplier": 4.0 },
        { "id": "audit_fail_rate", "max": 0.001, "penalty_multiplier": 50.0 }
      ]
    },
    "outputs": {
      "metrics_path": "out/pasm_demo_metrics.jsonl",
      "graph_path": "out/pasm_demo_graph.dot",
      "ledger_dump_path": "out/pasm_demo_ledger.jsonl"
    }
  }
}
```

Key point: you’re encoding PASM/VMK “laws” as **interpretable closure+composition predicates and objective weights**, not prose.  

### 3.2 Why the “pending semantics” line matters

Gemini’s critique is correct in general: **PENDING must not mask FAIL**. In the demo spec, explicitly encode:

> pending only if missing receipts **and** no authoritative FAIL exists

That becomes a kernel test vector for fail-closed closure. (You want this in the demo because it’s the same class of bug that will Goodhart your emergence engine into nonsense.)

---

## 4) Runtime architecture: the smallest stigmergic morphogenesis loop

This is the minimal set of moving parts.

### 4.1 Components

1. **World** (event generator):

   * emits `WorkOpened` facts (or your existing work events)
   * can inject “adversarial” work items as audits

2. **Holons** (agents):

   * read ledger projection
   * pick actions (claim, verify, specialize, compose, rest)
   * publish claims + evidence pointers + receipts

3. **Verifiers** (can be holons too):

   * produce `GateReceipt` on work claims
   * quorum threshold admits work completion

4. **Closure reducer** (pure function over ledger facts):

   * computes “authoritative state” from admitted receipts
   * in the demo, this can run centrally, but semantics must be decentralized (anyone can recompute)

5. **Budget allocator** (economy):

   * updates holon budgets/credit based on objective outcomes

### 4.2 The only permitted communication path

All coordination is mediated by the substrate:

* **publish fact → observe fact → react**

No direct messaging primitive. (If you later add direct messaging as an optimization, it must be reducible to “ledger‑equivalent” semantics.) 

---

## 5) Objective function for recursive self-improvement

You need an objective that:

* enforces dominance ordering (hard constraints)
* creates specialization pressure (MDL + context cost + verification economics)
* is resistant to “reward gaming” (countermetrics + audits)

This is exactly what your kernel reduction analysis says is missing from canon: a first-class morphogenesis law as an attractor. 

### 5.1 Hard constraints (lexicographic)

Define a feasibility predicate:

[
\text{Feasible}(x) =
\bigwedge_{c \in C_\text{hard}} c(x)
]

If infeasible, score is `-∞` (or terminate via apoptosis, depending on violation).

Hard constraints in demo:

* no authority escalation
* budget enforced
* receipt‑bound promotion
* integrity checks (hash/signature shape)

### 5.2 Soft score (within feasible region)

A linear+countermetric score is sufficient for the demo:

[
J = w_v \cdot V - w_f \cdot F - w_t \cdot T - w_{vc} \cdot VC - w_{dl} \cdot DL
]

Where:

* `V` = total completed work value (admitted by closure)
* `F` = admitted failures
* `T` = token/time cost proxy
* `VC` = verification cost (verifier load + proof size)
* `DL` = description length proxy (context + interface complexity)

Then apply countermetric multipliers:

* if recurrence rises, penalize sharply
* if audits fail, penalize catastrophically

This captures “Proof‑admitted morphogenetic economy” without overfitting the initial demo. 

---

## 6) How specialization emerges (active inference light)

The simplest active-inference-like policy that will actually show phase changes:

Each holon maintains beliefs:

* competence estimate per work type `μ_i(k)`
* uncertainty per type `σ_i(k)`
* local context cost estimate `c_i(k)`

Compute a utility-like quantity:

[
U_i(k) = \mathbb{E}[value_k \cdot success] - \alpha \cdot cost - \beta \cdot verification_overhead - \gamma \cdot context_cost
]

Then choose action with softmax:

[
\pi_i(k) \propto \exp\left(\frac{U_i(k)}{\tau}\right)
]

Update beliefs from admitted receipts (not from private fantasies).

This is enough to produce:

* emergent specialization (π concentrates)
* exploration/exploitation dynamics (τ + exploration floor)

It also naturally supports “free energy” framing: you’re minimizing expected surprise (failure) while controlling complexity (context/verification cost).

---

## 7) How hierarchy emerges (composition as a closure-admitted fact)

You need exactly two triggers:

### 7.1 Differentiation trigger (context window wall)

Compute scope entropy:

* Let `π_i(k)` be holon i’s action distribution over k work types.
* Scope entropy:

[
H_i = -\sum_k \pi_i(k)\log \pi_i(k)
]

Require:

[
H_i \le H_\text{max}(\text{window_budget})
]

If violated, holon must either:

* narrow subscriptions (specialize), or
* spawn a child holon with narrower contract

That’s morphogenesis via scarcity, not assignment.

### 7.2 Composition trigger (latency/coordination wall)

When a compound work type `C` repeatedly fails due to window budget or coordination cost, holons can propose a composite:

* Candidate set `S = {h_a, h_b, h_int}` (specialists + integrator)
* Formation claim includes:

  * membership attestations
  * boundary contract hashes
  * authority meet proof
  * replayable performance evidence on holdout trace set

Closure admits composite iff the VMK inequality holds (compression+verification economics improvement beyond τ) and risk constraints hold. 

---

## 8) Tunable parameters that will actually change emergent behavior

These are the knobs that produce distinct regimes (you want phase transitions):

### 8.1 Core emergence knobs

* `w_dl` (description length pressure): higher → more specialization and deeper hierarchies
* `w_vc` (verification cost): higher → fewer promotions / more “crystallization” incentives
* `tau_temperature` (softmax temperature): higher → more exploration, slower specialization
* `work_arrival_rate`: higher → stronger gradient fields, faster differentiation
* `window_budget`: lower → forced decomposition and hierarchy

### 8.2 Governance knobs

* `quorum_k/quorum_n`: higher → slower but safer; can suppress emergence if too strict
* `audit_rate`: higher → kills gaming but adds overhead; can prevent “cheap emergence”

### 8.3 Crystallization knobs (inference cost wall)

* `reuse_horizon`: longer → more incentive to crystallize artifacts
* `crystallize_threshold`: lower → earlier freezing; risk of rigidity
* `drift_window`: shorter → faster thaw; risk of oscillation

These correspond directly to the “inference/latency/context/bootstrapping walls” critique: the demo must let you *see* those tradeoffs as behavior, not as prose. 

---

## 9) Observability: what you must log to claim anything

If you don’t instrument this, you will hallucinate emergence.

### Outputs (minimum)

1. **Metrics JSONL per tick**

   * specialization entropy (global + per holon)
   * hierarchy depth distribution
   * completion throughput
   * verification load (receipts per admitted completion)
   * defect recurrence
   * budget utilization

2. **Graph snapshot**

   * parent→child edges
   * composite membership
   * “influence weights” (if you model them)

3. **Ledger dump**

   * to replay and independently recompute closure

If someone can’t replay your run from ledger+CAS and recompute the same admitted facts, the demo is invalid by your own theory.

---

## 10) Engineering milestones and subtasks (safe rollout)

You asked for a minimal demo, but you also asked for safe rollout. Here is the smallest plan that keeps your invariants intact.

### Milestone 1 — Lab harness + spec loader

* Add `apm2 lab morphogenesis`
* Add serde structs for `PasmDemoSpec`
* Validate spec (fail-closed defaults)

**Exit criteria**

* Can load spec, print derived config hash, refuse invalid configs.

### Milestone 2 — In-memory substrate + deterministic replay

* Instantiate `Ledger::in_memory()` and `MemoryCas`
* Deterministic RNG seeded from spec
* Emit work items to ledger
* Produce ledger dump + replay mode (`--replay ledger.jsonl`)

**Exit criteria**

* Replay recomputes identical closure-admitted state.

### Milestone 3 — Minimal holons + budgets + apoptosis

* Implement holon loop:

  * observe ledger → select action → publish facts
* Enforce budgets with `BudgetTracker`
* Apoptosis triggers:

  * invariant violation
  * budget exceed
  * integrity mismatch

**Exit criteria**

* Budget exceed always halts behavior (no “best effort continue”).

### Milestone 4 — Closure + quorum gating (with correct PENDING semantics)

* Implement quorum rule evaluation for “work completion admitted”
* Explicitly implement: authoritative FAIL cannot be masked by missing other category
* Add adversarial holon that tries to publish “fake completions”

**Exit criteria**

* Adversary never gets an admitted completion without receipts.
* PENDING never overrides FAIL.

### Milestone 5 — Differentiation + composition

* Implement scope entropy computation and differentiation trigger
* Implement composition proposal + formation receipts + admission inequality test

**Exit criteria**

* In at least one parameter regime, composites form.
* In at least one regime, they do *not* form (demonstrates non-triviality).

### Milestone 6 — Recursive self-improvement (artifact crystallization + thaw)

* Add “policy artifacts” stored in CAS (serialized parameter vectors)
* Admit policy updates only via closure (holdout improvement receipts)
* Add thaw when drift detected

**Exit criteria**

* At least one run shows: exploration → crystallization → drift → thaw → re-adaptation.

### Milestone 7 — Parameter sweeps + phase map

* Add `apm2 lab sweep --grid ...`
* Output “phase diagram” summary: specialization entropy vs hierarchy depth vs defects

**Exit criteria**

* You can empirically locate the boundaries:

  * no emergence
  * specialization only
  * specialization + hierarchy
  * unstable thrash / over-specialization

---

## 11) What you’ll learn fast (the real point of the demo)

If PASM/VMK are correct, you will see:

* a **critical window budget** below which hierarchy becomes unavoidable
* a **verification cost threshold** above which crystallization dominates
* a **quorum threshold** above which emergence is suppressed
* a **temperature range** where specialization is stable (not oscillatory)

And you’ll see the failure modes you already called out:

* over-crystallization rigidity
* over-encapsulation hidden faults
* over-specialization global incoherence
* bootstrap bias lock-in

The demo should make those failure modes measurable, not rhetorical.  

---

## The bottom line design choice

If you want the **minimal** demo that’s still meaningful, do **not** start with LLM agents. Start with **toy agents with explicit skill vectors + active-inference-like policy updates**, because:

* it isolates the morphogenetic kernel dynamics from model quirks
* it makes phase changes reproducible and interpretable
* it forces you to mechanize closure, composition admission, and Goodhart defenses

Then you can swap in frontier LLM-backed holons behind the same boundary contract later—without changing the kernel.

That’s the correct “physics-first” approach.
