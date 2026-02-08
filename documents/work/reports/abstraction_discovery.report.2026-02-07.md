# Abstraction Discovery Report (2026-02-07)

## Bootstrap: Dependencies & Reasoning Mode Selection
- Executed protocol: `documents/prompts/instruction.abstraction_discovery.v1.json`
- Loaded dependencies:
  - `documents/prompts/instruction.alien_engineering_protocol.v1.json`
  - `documents/skills/modes-of-reasoning/assets/selector.json`
  - `documents/skills/modes-of-reasoning/assets/40-mechanistic.json`
  - `documents/skills/modes-of-reasoning/assets/70-engineering-design.json`
  - theory bundle touchpoints for self-check: `documents/theory/{principles.json,laws.json,unified_theory.json,defects.json}`, plus `documents/theory/AGENTS.md`

### Reasoning Mode Selection
- DIAGNOSE selected mode: `40-mechanistic` (`dcp://apm2.agents/mor/mode/mechanistic@1`)
  - Rationale: only mode that jointly matched `task=diagnosis` and `patterns.codebase_grounding`, and it provides explicit component/interface/bottleneck tracing needed for structural duplication diagnosis.
- GENERALIZE selected mode: `70-engineering-design` (`dcp://apm2.agents/mor/mode/engineering-design@1`)
  - Rationale: `task=design` candidate set tied; selected `70` as the design-first mode that outputs buildable interfaces, tradeoff matrices, and migration/test obligations required by Phases 4-5.

### AEP Overlay Applied
- Active clauses internalized: `AEP_03`, `AEP_04`, `AEP_06`, `AEP_08`
- Dominance order enforced in selection/validation: `containment/security > verification/correctness > liveness/progress`

## PR Survey Table
Window used: last 48h merged PRs from `gh pr list --state merged --limit 50` on `guardian-intelligence/apm2`; then top 15 by approximate Rust changed lines (`gh pr diff --name-only` + change-line count approximation).

| PR | Approx Rust Changed Lines | New Types (sample) | New Impls (sample) | Error Patterns | Builder/Constructor Patterns | Test Scaffolding |
|---|---:|---|---|---|---|---|
| #450 | 13245 | `DelegateSubleaseRequest`, `DelegateSubleaseResponse` | `Deserialize<...>` | `map_err:6`, `error_kw:5` | `build:0`, `with_:1`, `new:0` | `#[test]:28`, `assert*:61` |
| #460 | 12985 | - | - | `map_err:0`, `error_kw:2` | `build:40`, `with_:8`, `new:0` | `#[test]:0`, `assert*:35` |
| #456 | 5471 | `BudgetStatus`, `PreActuationGate`, `ReplayEntry` | `GovernanceFreshnessMonitor`, `PreActuationReceipt` | `map_err:7`, `error_kw:15` | `build:5`, `with_:87`, `new:2` | `#[test]:94`, `assert*:237` |
| #435 | 4272 | - | - | `map_err:0`, `error_kw:0` | `build:0`, `with_:8`, `new:0` | `#[test]:7`, `assert*:28` |
| #437 | 4084 | `EndSessionRequest`, `TerminationOutcome` | `TerminationOutcome` | `map_err:16`, `error_kw:4` | `build:0`, `with_:12`, `new:0` | `#[test]:11`, `assert*:50` |
| #462 | 3789 | `DirectoryProofV1`, `IdentityProofV1`, `LedgerAnchorV1` | `DirectoryProofV1`, `From<...Error>` | `map_err:18`, `error_kw:11` | `build:0`, `with_:8`, `new:3` | `#[test]:39`, `assert*:52` |
| #433 | 3493 | `SessionTelemetry`, `TelemetrySnapshot` | `SessionTelemetryStore` | `map_err:3`, `error_kw:11` | `build:2`, `with_:67`, `new:2` | `#[test]:54`, `assert*:241` |
| #434 | 3256 | `CrashRecoveryError`, `CrashRecoveryOutcome` | - | `map_err:14`, `context:6`, `error_kw:8` | `build:0`, `with_:16`, `new:0` | `#[test]:42`, `assert*:154` |
| #457 | 3010 | `PublicKeyIdV1`, `KeySetIdV1`, `KeyIdError` | `FromStr`, `Display` | `map_err:2`, `error_kw:2` | `build:0`, `with_:2`, `new:0` | `#[test]:97`, `assert*:138` |
| #455 | 2943 | `CapabilityManifestV1`, `PolicyMintToken` | `From<CapabilityError>` | `map_err:0`, `error_kw:23` | `build:36`, `with_:51`, `new:1` | `#[test]:58`, `assert*:104` |
| #427 | 2898 | `ProcessInfo`, `ProcessStatusResponse` | `ProcessErrorCode`, `ProcessStateEnum` | `map_err:51`, `context:19`, `error_kw:27` | `build:14`, `with_:9`, `new:0` | `#[test]:31`, `assert*:124` |
| #459 | 2665 | `CellCertificateV1`, `HolonCertificateV1`, `SessionKeyDelegationV1` | `CellCertificateV1`, `RevocationPointer` | `map_err:6`, `error_kw:3` | `build:0`, `with_:5`, `new:2` | `#[test]:46`, `assert*:53` |
| #431 | 2503 | - | - | `map_err:7`, `error_kw:17` | `build:0`, `with_:56`, `new:0` | `#[test]:30`, `assert*:47` |
| #436 | 2475 | `TerminationReason` | `SessionRegistry`, `Display` | `map_err:2`, `error_kw:6` | `build:0`, `with_:33`, `new:0` | `#[test]:44`, `assert*:149` |
| #451 | 2468 | `HsiContractManifestV1`, `HsiRouteEntry` | `HsiRouteEntry`, `Display` | `map_err:2`, `error_kw:4` | `build:0`, `with_:1`, `new:0` | `#[test]:51`, `assert*:92` |

Cross-PR aggregate signals (top 15):
- `map_err` lines: 134 across 12/15 PRs
- `with_*` setter-style lines: 364 across 15/15 PRs
- test attributes/assert scaffolding: `#[test]` 632 and `assert*` 1565 across 14-15/15 PRs

## Duplication Clusters
| Cluster ID | Pattern Description | Instance Count | Files (representative) | Estimated Shared SLOC |
|---|---|---:|---|---:|
| C1 | Session dispatch test setup repeated (`make_session_ctx`, `test_minter`, `dispatch(&frame,&ctx)`, `register_session`) | 145 weighted repeated lines across 9 PRs | `crates/apm2-daemon/src/protocol/dispatch.rs`, `crates/apm2-daemon/src/protocol/session_dispatch.rs`, `crates/apm2-daemon/src/session/mod.rs`, `crates/apm2-daemon/tests/protocol_integration.rs` | 310 |
| C2 | Response error envelope mapping repeats (`SessionResponse::error`, `PrivilegedResponse::error`, capability rejection arms) | 28 weighted repeated lines across 8 PRs | `crates/apm2-daemon/src/protocol/dispatch.rs`, `crates/apm2-daemon/src/protocol/session_dispatch.rs`, `crates/apm2-daemon/src/governance.rs` | 120 |
| C3 | Policy/capability field initialization repeats (`policy_resolved_ref`, `capability_manifest_hash`, related scope fields) | 37 repeated lines + 1373 policy/capability keyword hits across 13 PRs | `crates/apm2-daemon/src/episode/capability.rs`, `crates/apm2-daemon/src/governance.rs`, `crates/apm2-daemon/src/state.rs` | 190 |
| C4 | Registry cleanup/rollback mutation sequences repeat (`retain/remove/by_handle`, rollback warnings, lock/write boilerplate) | 24 weighted repeated lines across 6 PRs | `crates/apm2-daemon/src/episode/registry.rs`, `crates/apm2-daemon/src/session/mod.rs`, `crates/apm2-daemon/src/episode/crash_recovery.rs` | 95 |
| C5 | Identity/proof typed artifact boilerplate repeats (newtype defs + `Display`/`FromStr`/`From<...Error>`) | 22 conversion-impl lines + 760 identity-keyword hits across 4 PRs | `crates/apm2-daemon/src/identity/public_key_id.rs`, `crates/apm2-daemon/src/identity/certificate.rs`, `crates/apm2-daemon/src/identity/directory_proof.rs` | 160 |
| C6 | High-volume assertion/test scaffolding repeats in protocol and lifecycle tests | 1346 test/assert pattern hits across 14 PRs | `crates/apm2-daemon/tests/tck_00387_crash_recovery.rs`, `crates/apm2-daemon/tests/tck_00383_cas_wiring.rs`, `crates/apm2-daemon/src/protocol/dispatch.rs` (unit tests) | 210 |

Containment-driven skip note:
- Duplication in some cryptographic proof checks was treated as partially intentional for audit clarity and explicit trust-boundary visibility; those paths were not selected for aggressive runtime abstraction.

## Diagnosis
Mechanistic mode (`40`) applied per cluster: decomposed components, traced interfaces, identified bottlenecks, and predicted abstraction levers.

| Cluster ID | Best Hypothesis | Score (0-10) | Predicted Abstraction | Containment Risk |
|---|---|---:|---|---|
| C1 | Fast ticket velocity caused repeated per-test fixture reassembly because no canonical session/dispatch harness exists. | 9.4 | `DispatchFixtureHarnessV1` test harness module | Low |
| C2 | Error mapping logic is spread across handlers due missing shared typed adapter between domain errors and wire envelopes. | 8.7 | `ProtocolErrorEnvelopeMapper` trait/module | Medium-Low |
| C3 | Capability/policy structs evolved independently; repeated field wiring is compensating for missing canonical baseline object. | 8.5 | `SessionPolicyContextBuilder` | Medium |
| C4 | Registry lifecycle mutations repeat because rollback/remove/retain are embedded in call sites instead of an invariant-preserving primitive. | 7.9 | `RegistryMutationOps` | Medium |
| C5 | Identity artifact growth outpaced shared canonicalization utilities, causing repeated conversions and parser/display boilerplate. | 7.8 | `IdentityNewtypeDerive` proc-macro | Medium |
| C6 | Tests are authored case-by-case with hand-rolled setup/assert chains due lack of table-driven protocol contract harness. | 8.8 | `DispatchContractMatrix` harness | Low |

## Top 10 Abstraction Candidates
| ID | Name | Kind | Source Exemplar | Mechanism | Scope Conditions | Boundary Conditions | Estimated Dedup SLOC | Adoption Sites (initial) | Risk Notes |
|---|---|---|---|---|---|---|---:|---|---|
| A01 | `DispatchFixtureHarnessV1` | harness | PRs #433, #456 | Single fixture API for session registry, token minting, ctx creation, request dispatch, and typed response assertions. | Protocol/session tests in daemon crate. | Test-only; cannot alter runtime authority decisions. | 280 | `crates/apm2-daemon/src/protocol/dispatch.rs`, `crates/apm2-daemon/src/protocol/session_dispatch.rs`, `crates/apm2-daemon/tests/protocol_integration.rs` | Risk is over-general fixture hiding case-specific preconditions. |
| A02 | `ProtocolErrorEnvelopeMapper` | module | PRs #427, #437, #456 | Trait maps domain errors into canonical `SessionResponse`/`PrivilegedResponse` envelopes with stable codes. | Privileged + session handlers. | Keep explicit code mapping for containment-sensitive denials. | 150 | `crates/apm2-daemon/src/protocol/dispatch.rs`, `crates/apm2-daemon/src/protocol/session_dispatch.rs`, `crates/apm2-daemon/src/governance.rs` | Incorrect mapping could blur security semantics. |
| A03 | `SessionPolicyContextBuilder` | module | PRs #455, #456 | Canonical builder for policy/capability/context digest fields with validation hooks. | Policy resolution and capability minting flows. | Must fail-closed on missing digests/scope evidence. | 140 | `crates/apm2-daemon/src/governance.rs`, `crates/apm2-daemon/src/episode/capability.rs`, `crates/apm2-daemon/src/state.rs` | Risk of accidental default broadening if builder has permissive defaults. |
| A04 | `RegistryMutationOps` | module | PRs #433, #434, #436 | Encapsulates remove/retain/rollback state mutation sequences with invariant checks. | Session lifecycle + crash recovery. | Lock ordering and telemetry side effects stay explicit and test-verified. | 95 | `crates/apm2-daemon/src/episode/registry.rs`, `crates/apm2-daemon/src/session/mod.rs`, `crates/apm2-daemon/src/episode/crash_recovery.rs` | Hidden side effects if abstraction becomes opaque. |
| A05 | `ReceiptAnchorFields` | module | PRs #434, #455, #462 | Shared digest anchor struct (`resolved_policy_hash`, `context_pack_hash`, `capability_manifest_hash`) + validation. | Receipt and response payload constructors. | Fixed-size digest semantics only; no dynamic maps. | 110 | `crates/apm2-daemon/src/protocol/apm2.daemon.v1.rs`, `crates/apm2-daemon/src/ledger.rs`, `crates/apm2-daemon/src/governance.rs` | Must not weaken hash presence requirements. |
| A06 | `IdentityNewtypeDerive` | macro | PRs #457, #459, #462 | Proc-macro derives canonical parse/display/serde/hash patterns for identity/proof newtypes. | Identity/certificate/proof artifact family. | Requires explicit encoding/tag metadata; no implicit formatting. | 160 | `crates/apm2-daemon/src/identity/public_key_id.rs`, `crates/apm2-daemon/src/identity/certificate.rs`, `crates/apm2-daemon/src/identity/directory_proof.rs` | Macro misuse could hide canonicalization drift. |
| A07 | `TypedConversionErrorKit` | module | PRs #451, #457, #459 | Shared conversion traits and helpers for `From<...Error>` and stable diagnostic metadata. | Identity + HSI manifest modules. | Do not collapse distinct security-relevant error classes. | 85 | `crates/apm2-daemon/src/hsi_contract/manifest.rs`, `crates/apm2-daemon/src/identity/mod.rs`, `crates/apm2-daemon/src/identity/session_delegation.rs` | Over-normalization can erase actionable differences. |
| A08 | `WithSetterAuditMacro` | macro | PRs #433, #455, #456 | Generates `with_*` methods with required invariant checks and audit annotations. | Builder-heavy internal structs. | Generated setters must preserve least-authority and digest requirements. | 80 | `crates/apm2-daemon/src/state.rs`, `crates/apm2-daemon/src/episode/capability.rs`, `crates/apm2-daemon/src/episode/preactuation.rs` | Macro can create superficial uniformity without reducing logic drift. |
| A09 | `DispatchContractMatrix` | harness | PRs #427, #431, #437, #450 | Table-driven request/response/error + ledger side-effect assertions for protocol contracts. | Protocol integration + persistence tests. | Must keep explicit expected receipts for high-risk paths. | 220 | `crates/apm2-daemon/tests/protocol_integration.rs`, `crates/apm2-daemon/tests/protocol_persistence.rs`, `crates/apm2-daemon/src/protocol/dispatch.rs` tests | Risk of broad tables missing bespoke edge assertions. |
| A10 | `PreActuationCheckPipeline` | trait/module | PRs #435, #456 | Ordered composable check chain (stop/budget/freshness) with typed denial receipts. | Gate orchestrator + pre-actuation checks. | Deterministic check ordering by containment precedence. | 90 | `crates/apm2-daemon/src/episode/preactuation.rs`, `crates/apm2-daemon/src/gate/orchestrator.rs`, `crates/apm2-daemon/src/protocol/session_dispatch.rs` | Ordering bugs can alter deny/allow semantics. |

## Decision Matrix
Weights used (per protocol):
- dedup_sloc_saved: 25%
- future_pr_size_reduction: 25%
- containment_safety: 20%
- adoption_friction (higher = easier adoption): 15%
- composability: 15%

| ID | dedup | future_pr_reduction | containment_safety | adoption_friction | composability | Weighted Score |
|---|---:|---:|---:|---:|---:|---:|
| A01 | 9.0 | 9.0 | 9.5 | 8.0 | 8.5 | **8.88** |
| A09 | 8.2 | 8.4 | 9.2 | 7.8 | 8.4 | **8.43** |
| A02 | 7.8 | 8.3 | 8.8 | 7.4 | 8.0 | **8.08** |
| A03 | 7.6 | 8.0 | 9.1 | 7.2 | 8.2 | **8.01** |
| A06 | 7.1 | 7.7 | 8.9 | 6.8 | 8.8 | **7.82** |
| A05 | 6.8 | 7.5 | 9.0 | 7.0 | 8.1 | **7.65** |
| A10 | 6.5 | 7.6 | 9.3 | 6.9 | 7.6 | **7.54** |
| A04 | 6.4 | 7.3 | 8.7 | 7.1 | 7.5 | **7.35** |
| A07 | 5.9 | 6.8 | 8.8 | 7.3 | 7.9 | **7.17** |
| A08 | 5.6 | 6.5 | 8.4 | 6.7 | 7.3 | **6.83** |

## Winner: The Single Best Abstraction
```yaml
winner:
  id: A01
  name: DispatchFixtureHarnessV1
  kind: harness
  trait_or_api_sketch: |
    // crates/apm2-daemon/src/protocol/testing/dispatch_fixture.rs
    pub struct DispatchFixture {
        pub registry: Arc<InMemorySessionRegistry>,
        pub minter: TestMinter,
        pub ctx: SessionCtx,
    }

    impl DispatchFixture {
        pub fn standard() -> Self;
        pub fn with_session(self, role: WorkRole) -> Self;
        pub fn with_policy(self, policy: PolicyResolution) -> Self;
        pub fn dispatch(self, frame: &[u8]) -> DispatchOutcome;
    }

    pub enum DispatchOutcome {
        Session(SessionResponse),
        Privileged(PrivilegedResponse),
    }

    impl DispatchOutcome {
        pub fn expect_ok(self) -> Self;
        pub fn expect_session_error(self, code: SessionErrorCode) -> Self;
        pub fn expect_privileged_error(self, code: PrivilegedErrorCode) -> Self;
    }
  migration_path:
    - "Adopt in `crates/apm2-daemon/src/protocol/dispatch.rs` unit tests by replacing hand-rolled `make_session_ctx`/`test_minter`/dispatch boilerplate."
    - "Adopt in `crates/apm2-daemon/src/protocol/session_dispatch.rs` tests and centralize shared setup + response assertions."
    - "Adopt in `crates/apm2-daemon/tests/protocol_integration.rs` and `crates/apm2-daemon/tests/protocol_persistence.rs` for table-driven fixture reuse."
  expected_improvement_claim: |
    Across the next 10 daemon protocol/session PRs, repeated session-dispatch test setup lines should drop >=55%,
    and median changed Rust lines in protocol/session test files should drop >=18% without increasing containment/security findings.
  falsification_criteria:
    - "After 10 relevant PRs, duplicated setup motifs (`make_session_ctx`, `test_minter`, direct `dispatcher.dispatch`) are reduced by <55%."
    - "Median Rust test diff size in touched protocol/session files does not improve by at least 18%."
    - "Containment/security regressions appear that are attributable to fixture abstraction hiding required checks."
```

Runner-up:
```yaml
runner_up:
  id: A09
  name: DispatchContractMatrix
  score_delta: 0.45
  why_not_first: "Higher upfront migration cost and greater risk of table overgeneralization before fixture-level primitives are in place."
```

## Validation Report
```yaml
validation_report:
  checks_passed:
    - "DOMINANCE_ORDER respected: winner is test-harness scoped and does not widen runtime authority."
    - "No new crate dependency or circular dependency required; can live under existing daemon protocol test support modules."
    - "Directly targets known defect classes from `documents/theory/defects.json`: INTERFACE_PROLIFERATION, ABSTRACTION_BREAK, and inefficiency classes (EXTRA_TOOL_CALLS / UNNECESSARY_REVIEW_CYCLES)."
    - "Generalization scope matches explanation: repeated session/dispatch setup and assertions are the dominant duplication mechanism."
    - "Boundary conditions are explicit (test-only, explicit error-code expectations, no hidden policy defaults)."
  checks_failed: []
  final_recommendation: "Proceed with A01 first; stage A09 second after A01 adoption on first three sites."
```

## Appendix: Full Ranking
| Rank | ID | Name | Kind | Weighted Score |
|---:|---|---|---|---:|
| 1 | A01 | DispatchFixtureHarnessV1 | harness | 8.88 |
| 2 | A09 | DispatchContractMatrix | harness | 8.43 |
| 3 | A02 | ProtocolErrorEnvelopeMapper | module | 8.08 |
| 4 | A03 | SessionPolicyContextBuilder | module | 8.01 |
| 5 | A06 | IdentityNewtypeDerive | macro | 7.82 |
| 6 | A05 | ReceiptAnchorFields | module | 7.65 |
| 7 | A10 | PreActuationCheckPipeline | trait/module | 7.54 |
| 8 | A04 | RegistryMutationOps | module | 7.35 |
| 9 | A07 | TypedConversionErrorKit | module | 7.17 |
| 10 | A08 | WithSetterAuditMacro | macro | 6.83 |
