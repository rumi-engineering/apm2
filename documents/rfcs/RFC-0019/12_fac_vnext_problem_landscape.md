# RFC-0019 Addendum — FAC vNext Problem Landscape (Cross-Boundary)

Status: Draft (problem-definition phase)

Primary objective: Establish a complete, explicit, and cross-system statement of the problems FAC vNext must solve before proposing design decisions.

This document is intentionally solution-agnostic. It names defects, mismatches, and risk surfaces across FAC, HSI, HTF, HEF, CAC, daemon control plane, consensus substrate, and external projections.

## 1. Scope and framing

In scope:
- FAC workflow semantics from intent/work ingestion through review, gate, and projection.
- Agent/operator quality-of-life in day-to-day FAC execution.
- Information-flow safety across trusted and untrusted boundaries.
- Replacement of GitHub PR-centered control flow with an internal canonical workflow object.
- Alignment with HSI, HTF, and digest-first civilizational-scale constraints.

Out of scope for this phase:
- Final protocol/schema designs.
- Ticket decomposition.
- Performance tuning details beyond identifying bottlenecks and economics failures.

## 2. Non-negotiable constraints (problem framing constraints)

These are existing system constraints that any future solution must satisfy:
- Internal truth is ledger + CAS; external systems are projections.
- Containment/security precedence outranks verification, which outranks liveness.
- No bypass actuation paths; missing enforcement dependency must fail closed.
- Delegation is explicit, hash-addressed, and strict-subset only.
- Authoritative time semantics are HTF-bound; wall-clock authority is forbidden.
- Interfaces at scale are digest-first and selector-driven.

## 3. Current-state diagnosis summary

FAC v0 established critical primitives but leaves systemic gaps for vNext goals:
- FAC remains partially coupled to GitHub/PR-era assumptions and workflows.
- Security controls do not yet provide mechanical, end-to-end non-leakage guarantees for untrusted outputs.
- Cross-RFC semantic alignment (FAC/HSI/HTF/HEF/CAC) is incomplete at boundary contracts.
- Operator and agent workflow ergonomics remain fragmented across daemon APIs, projections, scripts, and historical `xtask` paths.

## 4. Comprehensive problem inventory

### 4.1 Agent and operator QoL problems

`PL-QOL-001` Workflow control plane fragmentation
- Problem: Daily FAC operation is spread across multiple surfaces (`apm2`, daemon internals, projections, and historical `xtask` patterns).
- Impact: Slower execution, operator confusion, and accidental authority misuse.

`PL-QOL-002` Poor introspection ergonomics for long-running loops
- Problem: Iteration-level state, causal history, and receipt lineage are costly to inspect without raw artifact hunting.
- Impact: High cognitive load and slower recovery/debug cycles.

`PL-QOL-003` Context rehydration friction between episodes and roles
- Problem: Reconstructing role-scoped context for N+1 iteration often requires manual retrieval and interpretation.
- Impact: Throughput loss, repeated tool calls, and higher drift risk.

`PL-QOL-004` RoleSpec and adapter operational drift
- Problem: Role instructions, adapter profile behavior, and runtime enforcement can diverge without immediate visibility.
- Impact: Inconsistent behavior across agents and brittle autonomy.

`PL-QOL-005` Crash/resume operational uncertainty
- Problem: Operators lack a single, authoritative, ergonomic restart narrative for ongoing work loops.
- Impact: Duplicate effort, replay anxiety, and accidental side-effect duplication.

### 4.2 Information-flow security and semi-formal assurance problems

`PL-SEC-001` Missing end-to-end non-leakage proof surface for untrusted boundaries
- Problem: The system lacks a unified, machine-checkable argument that sensitive data cannot leak to untrusted sinks (GitHub, logs, external channels).
- Impact: High confidentiality risk and governance deadlocks for higher-risk automation.

`PL-SEC-002` Taint and confidentiality controls are not yet uniformly enforced across FAC pipeline stages
- Problem: Dual-lattice semantics are defined but not uniformly guaranteed across context compilation, tool mediation, summary generation, and projection.
- Impact: Integrity contamination and confidentiality violations can cross boundaries undetected.

`PL-SEC-003` Declassification semantics are under-specified operationally
- Problem: Declassification receipts and downgrade pathways are not yet a ubiquitous operational contract in FAC.
- Impact: Silent or ad-hoc downgrade behavior can leak protected information.

`PL-SEC-004` Logging payload discipline is insufficiently formalized
- Problem: Boundary-emitted logs and receipts can mix operational value with sensitive payload risk without a strict minimum-safe schema posture.
- Impact: “Useful logs” can become exfiltration channels.

`PL-SEC-005` Prompt-injection and context poisoning remain practical attack paths
- Problem: Adversarial diffs/tool outputs can still influence high-authority decisions without universally enforced sanitization and taint gates.
- Impact: Unsafe actions and corrupted review outcomes.

`PL-SEC-006` Runtime no-bypass posture not fully converged
- Problem: Historical bypass patterns and transitional pathways remain a regression risk surface.
- Impact: Any bypass invalidates proof-carrying safety claims.

### 4.3 GitHub dependency and PR-concept coupling problems

`PL-GH-001` GitHub PR remains overloaded as workflow anchor
- Problem: The PR object still implicitly carries identity, progression, and state semantics that should live in internal truth structures.
- Impact: External platform coupling, adversarial surface expansion, and replay ambiguity.

`PL-GH-002` Projection and authority semantics remain socially, not mechanically, separated in some workflows
- Problem: Humans and automation still treat some projection signals as quasi-authoritative.
- Impact: Split-brain decisions between internal truth and external states.

`PL-GH-003` No finalized internal successor concept to PR as canonical merge/work unit
- Problem: The system lacks a universally adopted internal primitive replacing PR-centric lifecycle reasoning.
- Impact: Conceptual ambiguity, migration stalls, and inconsistent tooling.

`PL-GH-004` Lifecycle progression still references PR-era naming and assumptions
- Problem: Commands, artifacts, and operator language can remain branch/PR-centric rather than work-object and receipt-centric.
- Impact: Partial migration with hidden legacy dependencies.

`PL-GH-005` External write-path minimization is incomplete
- Problem: Direct-write patterns and partial demotion paths still exist in operational memory and scripts.
- Impact: Harder to guarantee projection-only posture and safe rollback.

### 4.4 FAC to HSI contract integration problems

`PL-HSI-001` HSI contract adoption is incomplete in FAC runtime paths
- Problem: Not all FAC boundaries are yet governed by explicit HSI contract objects and hash bindings.
- Impact: Interface entropy under recursion and weaker admission invariants.

`PL-HSI-002` Permeability/authority meet semantics are not uniformly visible in FAC transitions
- Problem: Delegation strict-subset checks are not yet universally surfaced as first-class transition evidence.
- Impact: Latent capability widening risk under composition.

`PL-HSI-003` Capsule and context-firewall guarantees are not uniformly enforced across all adapters and tiers
- Problem: Containment semantics can vary by adapter/runtime mode.
- Impact: Uneven security posture and brittle assurance at scale.

`PL-HSI-004` ToolIntent mediation consistency gap
- Problem: Adapter outputs and tool mediation contracts can drift across vendor/runtime profiles.
- Impact: Parsing ambiguity, bypass risk, and non-deterministic behavior.

`PL-HSI-005` Digest-first message class discipline not yet fully normalized in FAC-adjacent flows
- Problem: Some workflow surfaces still depend on transcript-heavy operational behavior.
- Impact: Scaling limits, higher bandwidth cost, and weaker replay ergonomics.

### 4.5 FAC to HTF integration problems

`PL-HTF-001` Authoritative FAC transitions are not uniformly envelope-bound
- Problem: Not every critical lifecycle decision is guaranteed to bind a resolvable HTF `time_envelope_ref` with admissible `clock_profile_hash`.
- Impact: Freshness ambiguity and reduced replay confidence.

`PL-HTF-002` Residual wall-time authority leakage risk
- Problem: Legacy semantics and operator habits can reintroduce wall-time assumptions into authoritative decisions.
- Impact: Manipulable time authority and determinism regressions.

`PL-HTF-003` Freshness policy handling under uncertainty is operationally uneven
- Problem: Tiered stale/unknown handling is not yet consistently visible and test-proven across all FAC actuation points.
- Impact: Either unsafe admission or unnecessary liveness collapse.

`PL-HTF-004` Stop-path time SLO coupling remains immature
- Problem: Stop uncertainty handling and latency guarantees are not yet fully operationalized across all critical paths.
- Impact: Safety-critical control degradation under incident conditions.

### 4.6 FAC to HEF and work-object cutover problems

`PL-HEF-001` Pulse-plane and truth-plane semantics are still easy to misinterpret operationally
- Problem: Pulses are defined as wakeups, but human and automation behavior can still over-trust pulse signals.
- Impact: Admission and routing mistakes.

`PL-HEF-002` Work lifecycle authority not yet fully converged on ledger-native work objects
- Problem: Filesystem ticket era concepts, core work reducer semantics, and holon work object semantics remain partially divergent.
- Impact: Migration complexity and runtime ambiguity.

`PL-HEF-003` Event-family semantic drift risk
- Problem: Underscore, dotted, and typed event families can drift unless parity is continuously enforced.
- Impact: Replay mismatch and projection inconsistency.

`PL-HEF-004` Instruction-plane lockstep is incomplete
- Problem: Runtime changes and instruction/RoleSpec updates can ship at different speeds.
- Impact: Agents execute stale lifecycle assumptions.

### 4.7 FAC to CAC and evidence pipeline problems

`PL-CAC-001` Context sufficiency feedback loops are still too expensive
- Problem: Context miss handling can trigger expensive, repeated refinement cycles without robust economics controls.
- Impact: Throughput collapse and budget burn.

`PL-CAC-002` Context provenance and policy provenance are not always jointly obvious at operator surfaces
- Problem: It is hard to answer “which policy + which context + which delegation produced this outcome?” in one view.
- Impact: Slow governance and forensic workflows.

`PL-CAC-003` Deterministic context delta pathways remain under-utilized
- Problem: Iterative FAC loops still over-fetch or over-transmit context where deltas and summaries should dominate.
- Impact: unnecessary latency and cost.

### 4.8 Verification economics and scaling problems

`PL-ECO-001` Raw evidence volume threatens operability
- Problem: Without strict summary/index-first discipline, evidence growth overwhelms human and machine consumers.
- Impact: Auditability degradation and reduced responsiveness.

`PL-ECO-002` Verification workload is not uniformly bounded by risk tier and policy
- Problem: Over-verification and under-verification can coexist in different pathways.
- Impact: Either inefficiency or unsafe promotion.

`PL-ECO-003` Replay and anti-entropy readiness is uneven across projections and auxiliary systems
- Problem: Some operational paths are still not routinely validated for full rebuild under partial loss.
- Impact: brittle recovery behavior.

### 4.9 Governance and rollout control problems

`PL-GOV-001` Gate posture across FAC-adjacent systems is not centrally legible
- Problem: Architectural/security/formal/perf gate status and dependencies are distributed and hard to reason over as a single migration program.
- Impact: hidden blockers and weak sequencing.

`PL-GOV-002` Waiver and breakglass semantics can outpace operational guardrails
- Problem: Temporary exceptions risk becoming de facto behavior if not tightly bounded and observed.
- Impact: security and consistency erosion.

`PL-GOV-003` Multi-RFC dependency management is under-modeled as a single program
- Problem: FAC vNext depends on coupled delivery across RFC-0019/0020/0016/0018/0017/0011/0014.
- Impact: local optimization with global integration debt.

## 5. Systemic coupling map (why these problems cannot be solved independently)

Coupling chain A:
- No PR successor concept (`PL-GH-003`) blocks ledger-native lifecycle convergence (`PL-HEF-002`) and keeps projection leakage risk high (`PL-GH-002`).

Coupling chain B:
- Incomplete taint/confidentiality enforcement (`PL-SEC-002`) blocks strong non-leakage claims (`PL-SEC-001`) and delays high-tier automation acceptance.

Coupling chain C:
- Partial HTF envelope enforcement (`PL-HTF-001`) undermines HSI freshness/authority assertions in high-risk actuation paths.

Coupling chain D:
- QoL fragmentation (`PL-QOL-001`) amplifies governance risk (`PL-GOV-003`) because operational behavior drifts faster than policy and contract updates.

Coupling chain E:
- Weak summary/index-first discipline (`PL-ECO-001`) directly limits supervisory visibility and slows incident response, increasing breakglass pressure (`PL-GOV-002`).

## 6. Problem statements explicitly requested for this initiative

### 6.1 Agent QoL uplift problem statement

Current FAC operation requires too much reconstruction effort per work unit. Agents and operators spend excessive cycles on state discovery, context rehydration, and tool/result tracing rather than decision work. Until FAC provides first-class, digest-first operational introspection and role-stable execution surfaces, autonomy gains will plateau.

### 6.2 Semi-formal non-leakage problem statement

FAC currently lacks a compositional, machine-checkable non-leakage argument proving that confidential or insufficiently trusted data cannot cross into untrusted boundaries while preserving sufficient readability for safe operation. Without that proof surface, either security posture remains weak or usability degrades through over-redaction. This is a core assurance gap, not an implementation detail.

### 6.3 Complete de-GitHub / post-PR problem statement

The system still carries PR-era conceptual load in lifecycle control. As long as PR semantics remain first-class, FAC cannot fully realize internal truth sovereignty, deterministic replay, and projection-only externalization. A canonical internal work/admission concept must replace PR as control object, with GitHub reduced to a non-authoritative output sink.

## 7. Traceability index (problem cluster to source RFC surfaces)

- FAC v0 gaps and post-v0 backlog: RFC-0019 sections `01`, `03`, `08`, `10`, `11`, `06`.
- HSI substrate obligations: RFC-0020 sections `0.1`, `1.4`, `1.8`, `4.5`, `5.4.1`, `6.4`, `7.3`, `8.3`, `10`.
- HTF authority obligations: RFC-0016 sections `01`, `02`, `03`, `08`.
- Pulse/work-object cutover and staged de-PR direction: RFC-0018 requirement set `REQ-HEF-0012..0018` and `TECHNICAL_PROPOSAL_WORKOBJECT_LEDGER_CUTOVER.md`.
- Daemon control-plane containment and xtask demotion baseline: RFC-0017 sections `00`, `01`.
- Context governance and deterministic packs: RFC-0011 sections `00`, `01`.
- Consensus and anti-entropy substrate constraints: RFC-0014 section `01`.

## 8. Exit criteria for this problem-definition phase

This phase is complete when:
- Every high-impact FAC vNext risk can be mapped to one or more problem IDs above.
- No major migration/security/ergonomics concern remains implicit or prose-only.
- The problem landscape is sufficient to derive requirements without re-opening scope.

