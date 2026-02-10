# RFC-0019 Addendum - FAC vNext Autonomic Concept Set

Status: Draft (concept synthesis phase)

Primary objective: define evidence-backed concept families for FAC vNext that improve security and efficiency under public adversarial pressure, while integrating FAC with HSI, HTF, HEF, CAC, and consensus surfaces.

This addendum is intentionally pre-implementation. It proposes testable concepts, invariants, and evidence contracts to guide the next RFC drafting pass.

## 1. Context and quality bar

This synthesis was derived from:
- RFC-0019 core and addenda, including requirement set `REQ-0001..0016` and evidence registry `EVID-0001..0016`.
- RFC-0020 HSI requirements, especially `REQ-0018`, `REQ-0019`, `REQ-0028`, `REQ-0029`, `REQ-0030`, `REQ-0032`, `REQ-0034`, `REQ-0035`.
- RFC-0016 HTF requirement `REQ-HTF-0003`.
- RFC-0018 HEF cutover requirements `REQ-HEF-0012..0018`.
- Threat model classes, especially `TM-CLASS-05` (prompt injection and leakage), `TM-CLASS-03` (fact forgery/verification DoS), and `TM-CLASS-06` (availability/economic attacks).
- Theory source: `unified-theory-v2.json`.
- Alien engineering protocol (`documents/prompts/instruction.alien_engineering_protocol.v1.json`) and strategy constraints.
- RFC6330 (`documents/rfcs/RFC-0019/reference/rfc6330.txt`) as a rigor benchmark for explicit recovery and failure-bound contracts.

## 2. Non-negotiable theory anchors

The concept set is constrained by:
- `LAW-05`, `INV-F-05`: no ambient authority; least-privilege capability boundaries.
- `LAW-15`, `INV-F-15`: authoritative promotion requires replayable terminal-verifier evidence.
- `LAW-14`, `INV-F-14`: precedence ordering is security/containment > verification/correctness > liveness/progress.
- `LAW-09`, `INV-F-08`, `REQ-HTF-0003`: time authority from HTF envelopes/ticks; no wall-time authority.
- `LAW-17`: high-risk promotion requires verifier independence.
- `INV-F-16`, `MECH-REPAIRABLE-REDUNDANCY`: explicit recoverability contracts with quantitative bounds.
- `LAW-03`, `REQ-HEF-0012`: runtime authority is ledger/CAS truth, never filesystem or projection truth.

## 3. Divergent theory frames (AEP novelty method)

### Frame A: control-theoretic FAC

Treat FAC as a multi-rate controller:
- fast loop: tool mediation and stop-state checks;
- medium loop: role adaptation and context sufficiency;
- slow loop: policy/rule evolution from defect counterexamples.

Primary value: stability under noisy, delayed, adversarial observations.

### Frame B: coding-theoretic FAC

Treat gate evidence as recoverable codewords:
- independent verifier families are "symbols";
- promotion requires `K` symbols and improves reliability with `K+delta` overhead;
- replay and repair are first-class, quantified, and audited.

Primary value: explicit reliability math and graceful degradation under verifier/storage loss.

### Frame C: adversarial-economics FAC

Assume daily high-volume adversarial probing at public boundaries:
- optimize "bytes moved per verified transition";
- force digest-first emission;
- make leakage attempts expensive and detection cheap.

Primary value: sustainable verification economics under live pentesting pressure.

### Synthesis result

Combine all three frames into one cohesive system:
- control stability from Frame A,
- recoverability math from Frame B,
- boundary economics from Frame C.

The resulting concept is the **FAC Autonomic Boundary Mesh (FABM)**.

## 4. FAC Autonomic Boundary Mesh (FABM)

FABM has five core planes:
- Truth plane: `AdmissionWorkObjectV1` and receipts on ledger+CAS.
- Policy plane: RoleSpecs, capability overlays, and declassification policy.
- Verification plane: independent gate families with erasure-style quorum envelopes.
- Projection plane: non-authoritative external emissions only.
- Repair plane: defect-driven self-modification of RoleSpecs, gates, and context compilers.

## 5. Evidence-backed concept set

Each concept below includes: problem targets, theory alignment, requirement alignment, falsifiable hypothesis, and evidence contract.

### `C-FAC-01` AdmissionWorkObject-first lifecycle (post-PR successor)

Claim:
- Replace PR as the canonical control object with `AdmissionWorkObjectV1` (AWO).
- GitHub becomes a pure projection sink fed by projection receipts.

Problem targets:
- `PL-GH-001..005`, `PL-HEF-002`, `PL-GOV-003`.

Theory alignment:
- `LAW-03`, `LAW-16`, `INV-F-02`, `INV-F-13`.

Requirement alignment:
- RFC-0019 `REQ-0006`, `REQ-0007`.
- RFC-0018 `REQ-HEF-0012`, `REQ-HEF-0013`, `REQ-HEF-0017`.

Falsifiable hypothesis:
- With AWO as sole authority source, zero runtime lifecycle decisions require PR metadata.

Evidence contract:
- Existing anchors: `EVID-0006`, `EVID-0007`, `EVID-GROUND-004`.
- Proposed: `EVID-VNEXT-0001` (authority path audit), `EVID-VNEXT-0002` (PR-decoupling replay proof).

Fail posture:
- Any authority path reading PR state is a blocking defect (`POLICY_VIOLATION`).

### `C-FAC-02` RoleSpec speciation engine (autonomic specialization)

Claim:
- FAC continuously compiles narrower RoleSpecs from defect and telemetry signals.
- Specialization is promoted only when it improves throughput and defect outcomes.

Problem targets:
- `PL-QOL-001..005`, `PL-CAC-001..003`, `PL-ECO-002`.

Theory alignment:
- `LAW-02`, `LAW-06`, `LAW-12`, `LAW-14`, `PRIN-007`, `PRIN-053`.

Requirement alignment:
- RFC-0019 `REQ-0011`, `REQ-0012`, `REQ-0014`.

Falsifiable hypothesis:
- Over a fixed 20-iteration corpus, specialized RoleSpecs reduce pack-miss and unplanned tool calls by >=30% without higher severe-defect escape rate.

Evidence contract:
- Existing anchors: `EVID-0012`, `EVID-0014`.
- Proposed: `EVID-VNEXT-0003` (RoleSpec lineage DAG), `EVID-VNEXT-0004` (before/after budget and quality deltas).

Fail posture:
- If specialization reduces verifiability or increases severe escapes, auto-rollback RoleSpec to last accepted hash.

### `C-FAC-03` Projection-coupling detector (including `--pr` class behavior)

Claim:
- Detect and block projection-specific logic from contaminating authority-critical paths.

Core invariant:
- For identical authoritative inputs:
  `Hash(authority_events | projection_mode=A) == Hash(authority_events | projection_mode=B)`
- Only projection receipts may differ.

Problem targets:
- `PL-GH-002`, `PL-GH-004`, `PL-HEF-001`, `PL-HEF-004`.

Theory alignment:
- `LAW-03`, `LAW-13`, `LAW-15`, `INV-F-03`.

Requirement alignment:
- RFC-0018 `REQ-HEF-0014`, `REQ-HEF-0016`.
- RFC-0019 `REQ-0007`.

Falsifiable hypothesis:
- Differential replay across projection flags (for example `--pr`) yields zero authoritative divergence events.

Evidence contract:
- Existing anchor: `EVID-0007` (flag precedence and authority reduction staging).
- Proposed: `EVID-VNEXT-0005` (projection-coupling differential test corpus).

Fail posture:
- Any authoritative divergence under projection toggles is stop-the-line (`S0_STOP_THE_LINE`).

### `C-FAC-04` Semi-formal boundary non-leakage case

Claim:
- Enforce a machine-checkable non-leakage predicate for every untrusted boundary emission while preserving operational readability via digest-first summaries.

Semi-formal predicate family:
- `AllowEmit(msg, sink) := taint(msg) <= sink.max_taint`
  `AND conf(msg) <= sink.max_conf`
  `AND (downgrade -> has_valid_declass_receipt)`
- `Readable(msg) := has(summary_receipt) AND has(selector_set) AND selectors_resolve`
- Boundary emission admissible only if `AllowEmit AND Readable AND signed_gate_receipt`.

Problem targets:
- `PL-SEC-001..005`, `PL-ECO-001`.

Theory alignment:
- `LAW-05`, `LAW-07`, `LAW-15`, `LAW-19`, `INV-F-04`, `INV-F-05`, `INV-F-15`.

Requirement alignment:
- RFC-0020 `REQ-0028`, `REQ-0029`, `REQ-0030`, `REQ-0032`, `REQ-0034`.
- RFC-0019 `REQ-0010`, `REQ-0016`.

Falsifiable hypothesis:
- In adversarial red-team suites, unauthorized high-confidentiality tokens are never emitted to untrusted sinks, while operator triage remains possible from summary receipts alone.

Evidence contract:
- Existing anchor: threat model `TM-CLASS-05`.
- Existing RFC-0019 anchor: `KickoffArgs.public_projection_only` and receipt surfaces.
- Proposed: `EVID-VNEXT-0006` (non-leakage gate conformance), `EVID-VNEXT-0007` (declassification receipt audit).

Fail posture:
- Missing taint/confidentiality proof or missing declassification receipt is mandatory deny.

### `C-FAC-05` Verifier erasure quorum (RaptorQ-inspired reliability envelope)

Claim:
- Model high-risk promotion with a `K-of-(K+delta)` independent verifier envelope.
- Add overhead verifiers (`delta`) to reduce unrecoverable promotion uncertainty.

Rigor bar inspired by RFC6330:
- baseline overhead target family:
  - `delta=0`: unresolved-or-wrong acceptance probability <= 1e-2
  - `delta=1`: <= 1e-4
  - `delta=2`: <= 1e-6
- Bound claims are admissible only with explicit independence assumptions and empirical validation.

Problem targets:
- `PL-SEC-001`, `PL-ECO-002`, `PL-ECO-003`, `PL-GOV-001`.

Theory alignment:
- `LAW-17`, `LAW-20`, `INV-F-15`, `INV-F-16`, `MECH-VERIFIER-INDEPENDENCE`, `MECH-REPAIRABLE-REDUNDANCY`.

Requirement alignment:
- RFC-0020 `REQ-0034`, `REQ-0035`.
- RFC-0019 `REQ-0010`.

Falsifiable hypothesis:
- Under injected verifier outages and Byzantine noise, promotions continue correctly when quorum and independence constraints are met, and fail closed otherwise.

Evidence contract:
- Proposed: `EVID-VNEXT-0008` (verifier independence score report), `EVID-VNEXT-0009` (quorum reliability Monte Carlo + replay receipts).

Fail posture:
- If independence evidence is stale or unavailable, Tier2+ promotion blocks.

### `C-FAC-06` CVE reflex arc (detect -> reproduce -> patch -> verify)

Claim:
- FAC operates a standing CVE repair loop with specialized RoleSpecs and independent exploit replay verification.

Required role families:
- `cve_intake_analyst`
- `exploit_reproducer`
- `patch_synthesizer`
- `regression_guardian`
- `supply_chain_reviewer`

Problem targets:
- `PL-SEC-005`, `PL-SEC-006`, `PL-QOL-002`, `PL-GOV-002`.

Theory alignment:
- `LAW-01`, `LAW-08`, `LAW-15`, `LAW-20`, `PRIN-044`, `PRIN-067`, `PRIN-092`.

Requirement alignment:
- RFC-0019 `REQ-0012`, `REQ-0016`.
- RFC-0020 `REQ-0030`, `REQ-0032`.

Falsifiable hypothesis:
- For seeded CVE corpus and live pentest findings, FAC reduces median time-to-patch and preserves replayable exploit-block evidence without bypass paths.

Evidence contract:
- Existing anchor: `EVID-0016`.
- Proposed: `EVID-VNEXT-0010` (CVE detection receipts), `EVID-VNEXT-0011` (exploit replay pass/fail receipts), `EVID-VNEXT-0012` (patch durability over N replays).

Fail posture:
- Patch promotion is denied if exploit replay evidence is missing or non-replayable.

### `C-FAC-07` HTF-bound authority tempo and stop-state dominance

Claim:
- All authoritative FAC transitions, retries, and timeout semantics are driven by HTF envelopes/ticks with explicit freshness pins.

Problem targets:
- `PL-HTF-001..004`, `PL-GOV-002`.

Theory alignment:
- `LAW-09`, `LAW-12`, `INV-F-08`, `INV-F-11`.

Requirement alignment:
- RFC-0016 `REQ-HTF-0003`.
- RFC-0020 `REQ-0018`, `REQ-0019`.
- RFC-0018 `REQ-HEF-0015`.

Falsifiable hypothesis:
- Perturbing wall clock cannot change admission outcomes for the same envelope/tick inputs.

Evidence contract:
- Proposed: `EVID-VNEXT-0013` (wall-time perturbation invariance test), `EVID-VNEXT-0014` (freshness pinset replay audit).

Fail posture:
- Missing/ambiguous freshness authority at Tier2+ is deny-actuation.

### `C-FAC-08` Evidence-economics thermostat (digest-first by default)

Claim:
- Enforce summary/index-first interaction surfaces so supervisory loops can operate without transcript fan-out.

Problem targets:
- `PL-ECO-001..003`, `PL-CAC-001`, `PL-QOL-002`.

Theory alignment:
- `LAW-06`, `LAW-07`, `LAW-08`, `PRIN-005`, `PRIN-013`, `PRIN-066`.

Requirement alignment:
- RFC-0019 `REQ-0010`, `REQ-0014`.
- RFC-0018 `REQ-HEF-0018`.
- RFC-0020 `REQ-0034`, `REQ-0035`.

Falsifiable hypothesis:
- At equal defect quality, digest-first surfaces reduce bytes moved and p95 verifier work per transition by >=40%.

Evidence contract:
- Existing anchor: `EVID-0010`.
- Proposed: `EVID-VNEXT-0015` (evidence economics benchmark).

Fail posture:
- When digest-first constraints are violated, emit explicit budget defects and block scale-up gates.

### `C-FAC-09` Revocation shockwave for public-boundary incidents

Claim:
- On suspected leakage or compromised delegation, propagate revocation receipts across affected cells and RoleSpecs within bounded latency envelopes.

Problem targets:
- `PL-SEC-001`, `PL-SEC-006`, `PL-GOV-002`.

Theory alignment:
- `LAW-05`, `LAW-18`, `LAW-19`, `INV-F-05`.

Requirement alignment:
- RFC-0020 `REQ-0014`, `REQ-0018`, `REQ-0019`.

Falsifiable hypothesis:
- In simulated compromise drills, revoked authority cannot be used after the configured p99 revocation window.

Evidence contract:
- Proposed: `EVID-VNEXT-0016` (revocation propagation latency proof), `EVID-VNEXT-0017` (revocation-wins convergence proof).

Fail posture:
- If revocation propagation evidence is missing/stale, high-risk promotion is denied.

## 6. Requested emergent cybernetic behaviors

### Behavior 1: RoleSpec creation for increasingly specific FAC tasks

Mechanism:
- `C-FAC-02` plus defect-driven compilation.

Observable signals:
- increasing count of accepted specialized RoleSpecs per quarter;
- decreasing context size and unplanned tool calls per successful transition;
- stable or improved severe-defect escape rate.

### Behavior 2: identification of projection-specific behavior in core logic (`--pr` class)

Mechanism:
- `C-FAC-03` differential replay and static coupling lint.

Observable signals:
- non-zero detection of projection-coupled branches early in migration;
- monotonic decline to zero before post-PR cutover gate.

### Behavior 3: identification and patching of CVEs (especially FAC)

Mechanism:
- `C-FAC-06` reflex arc + independent exploit replay gates.

Observable signals:
- lower median CVE detect-to-fix ticks;
- rising fraction of patches with replay-backed exploit closure receipts;
- no growth in bypass-path defect class.

## 7. Quantitative hypothesis set for the next drafting round

Proposed hypothesis IDs:
- `H-FABM-01`: zero authoritative dependence on PR/projection state.
- `H-FABM-02`: non-leakage gate blocks 100% of seeded secret egress tests at untrusted sinks.
- `H-FABM-03`: RoleSpec specialization reduces pack-miss and unplanned context reads by >=30%.
- `H-FABM-04`: projection-coupling differential hash mismatches are zero at promotion gate.
- `H-FABM-05`: verifier erasure envelope meets <=1e-4 unresolved probability at `delta=1` under modeled independence assumptions.
- `H-FABM-06`: CVE median detect-to-patch ticks improve quarter-over-quarter with replayable exploit closure evidence.
- `H-FABM-07`: digest-first evidence surfaces reduce p95 bytes moved per verified transition by >=40%.

Anti-Goodhart countermetrics (mandatory):
- Pair throughput metrics with leakage/containment metrics.
- Pair specialization gains with severe-defect escape metrics.
- Pair faster patch metrics with exploit replay and regression durability metrics.

## 8. Integration matrix (FAC boundary alignment)

- FAC x HSI:
  - containment, taint, no-bypass, digest-first classes (`REQ-0028/0029/0030/0032/0034/0035`).
- FAC x HTF:
  - authoritative timing via envelopes and freshness pins (`REQ-HTF-0003`, `REQ-0018`, `REQ-0019`).
- FAC x HEF:
  - work object authority and event parity (`REQ-HEF-0012..0018`).
- FAC x CAC:
  - context compilation as bounded sufficient-statistics pipeline with defect hooks.
- FAC x consensus substrate:
  - monotone authority facts and anti-entropy boundedness under adversarial replication.

## 9. Drafting guidance for the next RFC revision pass

1. Keep `12_fac_vnext_problem_landscape.md` as the canonical problem-only surface.
2. Use this addendum as the concept/options surface with explicit falsifiability.
3. Convert accepted concepts into requirement-level language only after:
   - typed receipt schema drafts exist,
   - at least one discriminating test per concept is defined,
   - fail-closed behavior is explicit for missing evidence.

## 10. Open technical questions to carry forward

- What minimum verifier-family diversity score is sufficient for each risk tier in `C-FAC-05`?
- Which declassification policy language gives strongest machine-checkability with lowest operator burden for `C-FAC-04`?
- Should AWO carry a built-in reversible alias field for legacy PR references during bounded observation windows, or should aliasing remain projection-only?
- Which CVE classes should be auto-patchable versus always human-adjudicated under current attestation floor?

## 11. Summary

The FABM concept set gives a cohesive path to:
- improve FAC operator/agent quality of life through specialization and digest-first ergonomics;
- provide semi-formal, machine-checkable non-leakage guarantees for untrusted boundaries;
- fully decouple FAC authority from GitHub/PR semantics;
- integrate FAC with HSI, HTF, HEF, and CAC using shared invariants and receipt contracts;
- induce observable cybernetic behavior in RoleSpec specialization, projection-coupling elimination, and CVE reflex hardening.
