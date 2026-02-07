# Abstraction Discovery Report - 2026-02-07

Scope: `crates/apm2-core/src`, `crates/apm2-daemon/src`, `crates/apm2-holon/src`, `crates/apm2-cli/src`, `xtask/src`

Lookback: 48h default window (cutoff `2026-02-05T02:01:47Z` to `2026-02-07T02:01:47Z`)

PR discovery method:
- `gh pr list --state merged --limit 50 --json number,title,mergedAt`
- Rust SLOC metric from `gh api repos/rumi-engineering/apm2/pulls/<N>/files --paginate` and summing `.additions + .deletions` for `*.rs`
- Top 15 selected by Rust SLOC

## Reasoning Mode Selection

Selector file: `documents/skills/modes-of-reasoning/assets/selector.json`

Scoring method used for selection:
- Heuristic rank score (task-specific) weighted x2
- Pattern rank score weighted x1
- Candidate score = heuristic_score + pattern_score

DIAGNOSE selection (`task=diagnosis` + `patterns.codebase_grounding`):
- Heuristic set: `[13, 40, 41, 52]`
- Pattern set: `[61, 40, 14, 6]`
- Top score: `40 mechanistic` (present in both sets; composite score 9)

GENERALIZE selection (`task=design` + `patterns.architectural_discovery`):
- Heuristic set: `[70, 6, 46, 36]`
- Pattern set: `[78, 44, 63, 13]`
- Top score: `70 engineering-design` (highest task-design score; composite score 8)

Loaded mode assets:
- `documents/skills/modes-of-reasoning/assets/40-mechanistic.json`
- `documents/skills/modes-of-reasoning/assets/70-engineering-design.json`

Rationale summary:
- `mechanistic` best matches causal decomposition of repeated code paths (components, interfaces, failure propagation, intervention points).
- `engineering-design` best matches conversion of repeated patterns into buildable abstractions with explicit tradeoffs, scope, and verification paths.

## PR Survey Table

| PR | Rust LOC | New Types (short) | New Impls | Error Patterns (map_err/ok_or_else/return Err) | Builder Patterns (new/with/build) | Test Scaffolding (tokio/test/assert) |
|---|---:|---|---:|---:|---:|---:|
| #450 | 13800 | `DelegateSubleaseRequest`, `DelegateSubleaseResponse` | 1 | 14 / 1 / 6 | 0 / 1 / 0 | 2 / 92 / 458 |
| #435 | 4792 | `GateOrchestratorError`, `GateOrchestratorEvent`, `GateStatus`, +6 | 7 | 4 / 9 / 17 | 1 / 3 / 0 | 74 / 4 / 155 |
| #437 | 4404 | `PolicyResolutionError`, `TerminationOutcome`, `EndSessionRequest`, +3 | 3 | 19 / 2 / 11 | 0 / 0 / 0 | 2 / 35 / 174 |
| #433 | 3865 | `TelemetryStoreError`, `SessionTelemetry`, `SessionTelemetryStore`, +1 | 3 | 1 / 0 / 4 | 2 / 3 / 0 | 0 / 54 / 231 |
| #434 | 3645 | `CrashRecoveryError`, `CollectedSessions`, `CrashRecoveryOutcome` | 0 | 13 / 0 / 8 | 0 / 1 / 0 | 3 / 39 / 153 |
| #416 | 3254 | `BlockedReasonCode`, `IterationOutcome`, `OrchestrationEvent`, +7 | 18 | 0 / 2 / 32 | 4 / 4 / 0 | 0 / 46 / 183 |
| #455 | 3189 | `ManifestV1Error`, `CapabilityManifestV1`, `PolicyMintToken`, +3 | 6 | 0 / 0 / 11 | 1 / 2 / 0 | 0 / 57 / 101 |
| #457 | 3180 | `AlgorithmTag`, `ExpectedError`, `KeyIdError`, +7 | 12 | 2 / 2 / 19 | 0 / 0 / 0 | 0 / 97 / 131 |
| #419 | 3018 | `ChangeType`, `EfficiencyError`, `ZoomSelectorType`, +13 | 14 | 0 / 1 / 24 | 8 / 6 / 2 | 2 / 24 / 66 |
| #415 | 3016 | `ConformanceError`, `RoleSpecError`, `RoleType`, +10 | 15 | 4 / 0 / 21 | 4 / 7 / 1 | 0 / 62 / 161 |
| #459 | 2886 | `CertificateError`, `RevocationPointer`, `CellCertificateV1`, +4 | 5 | 6 / 0 / 45 | 2 / 0 / 0 | 0 / 46 / 53 |
| #427 | 2884 | `ProcessErrorCode`, `ProcessStateEnum`, `ListProcessesRequest`, +15 | 2 | 49 / 11 / 21 | 0 / 2 / 0 | 0 / 31 / 108 |
| #436 | 2785 | `TerminationReason` | 2 | 2 / 0 / 1 | 0 / 1 / 0 | 11 / 33 / 146 |
| #458 | 2649 | `HolonPurpose`, `PolicyRootId`, `CellGenesisV1`, +5 | 14 | 0 / 2 / 23 | 2 / 0 / 0 | 0 / 87 / 136 |
| #452 | 2609 | `ContractBindingError`, `MismatchOutcome`, `RiskTier`, +4 | 8 | 0 / 0 / 3 | 0 / 7 / 0 | 5 / 58 / 177 |

## Duplication Clusters

| Cluster | Pattern Description | Instance Count | Files (representative) | Estimated Shared SLOC |
|---|---|---:|---|---:|
| C1 | Versioned/tagged digest ID codec boilerplate (`parse_text`, `from_binary`, `to_text`, `FromStr`, `Display`) | 12 function instances | `crates/apm2-daemon/src/identity/cell_id.rs`, `crates/apm2-daemon/src/identity/holon_id.rs`, `crates/apm2-daemon/src/identity/public_key_id.rs`, `crates/apm2-daemon/src/identity/keyset_id.rs` | 180 |
| C2 | IPC handler error-mapping pipeline duplication (`map_err`, `ok_or_else`, envelope conversion, `return Err`) | 141 repeated added lines (8 PRs) | `crates/apm2-daemon/src/protocol/dispatch.rs`, `crates/apm2-daemon/src/protocol/session_dispatch.rs` | 340 |
| C3 | Repeated constructor/builder surfaces (`new`, `with_*`, `build`) across config/state structs | 46 repeated added lines (14 files) | `crates/apm2-core/src/fac/role_spec.rs`, `crates/apm2-core/src/fac/efficiency_primitives.rs`, `crates/apm2-daemon/src/state.rs`, `crates/apm2-daemon/src/protocol/session_dispatch.rs` | 220 |
| C4 | Canonical token enum wrappers (`Display`, `FromStr`, `as_str`-like mapping) | 18 added impl lines (13 files) | `crates/apm2-daemon/src/identity/public_key_id.rs`, `crates/apm2-daemon/src/identity/keyset_id.rs`, `crates/apm2-daemon/src/identity/holon_id.rs`, `crates/apm2-daemon/src/hsi_contract/handshake_binding.rs` | 110 |
| C5 | Integration-test scaffolding repetition (fixture setup + assertion sequences) | 95 repeated added lines (6 PRs) | `crates/apm2-daemon/tests/protocol_integration.rs`, `crates/apm2-daemon/tests/tck_00387_crash_recovery.rs`, `crates/apm2-daemon/tests/hef_redteam.rs` | 260 |

Additional similarity evidence (C1):
- `CellIdV1::parse_text` vs `HolonIdV1::parse_text`: 100% line Jaccard
- `CellIdV1::from_binary` vs `HolonIdV1::from_binary`: 100% line Jaccard
- `CellIdV1::to_text` vs `HolonIdV1::to_text`: 77% line Jaccard

## Diagnosis

Mechanistic application summary (mode 40):
- Decomposed each cluster into code components (codec, dispatch guard, error envelope, builder surface, test harness).
- Mapped interfaces (callers, invariants, and boundary modules).
- Traced causal chain from high-velocity PR delivery to repeated implementations.
- Identified bottlenecks (no shared primitive at seam, repeated security-envelope translation).
- Derived intervention points as candidate abstractions with explicit containment gates.

Hypothesis generation and ranking (best hypothesis shown):

| Cluster | Best Hypothesis | Score | Predicted Abstraction | Containment Risk |
|---|---|---:|---|---|
| C1 | No shared identity codec primitive exists at the daemon identity boundary, so each new ID type re-implements the same fail-closed text/binary contract. | 0.93 | Typed digest codec trait + macro kit | Low |
| C2 | Endpoint handlers evolved independently with repeated decode/validate/map-error/emit-response chains because there is no reusable guarded endpoint kernel. | 0.91 | Guarded endpoint pipeline module | Medium-High |
| C3 | Repeated `new/with_*` patterns arise from hand-written state/config constructors without a constrained builder helper with validation hooks. | 0.84 | Guarded builder toolkit | Low |
| C4 | Canonical token enums repeatedly implement near-identical display/parse logic due missing enum token macro. | 0.79 | Canonical token enum macro | Low |
| C5 | Integration tests repeat setup/assert structure because no shared daemon integration harness captures the canonical fixture lifecycle. | 0.86 | Shared daemon integration harness | Low-Medium |

Intentional-duplication gate decision:
- No cluster was excluded as purely intentional for containment.
- C2 carries the highest containment sensitivity; any abstraction must preserve explicit deny paths and error-code determinism.

## Top 10 Abstraction Candidates

| ID | Name | Kind | Source Exemplar | Mechanism | Scope Conditions | Boundary Conditions | Est. Dedup SLOC | Adoption Sites | Risk Notes |
|---|---|---|---|---|---|---|---:|---|---|
| A01 | CanonicalDigestIdKit | trait+macro | `identity/cell_id.rs` + `identity/holon_id.rs` | Shared codec core + declarative ID spec macro | Canonical text+binary digest IDs with fail-closed parsing | Keep domain-specific derivation/semantic checks outside macro | 320 | `identity/cell_id.rs`, `identity/holon_id.rs`, `identity/public_key_id.rs` | Must preserve exact error semantics |
| A02 | GuardedEndpointKernel | module | `protocol/dispatch.rs` | Generic decode->authorize->apply->emit pipeline with typed error mapping | Privileged/session request handlers with bounded decode and envelope errors | Exclude streaming/long-lived handshake loops | 380 | `protocol/dispatch.rs`, `protocol/session_dispatch.rs`, `protocol/mod.rs` | High blast radius if abstraction mis-specified |
| A03 | DaemonIntegrationHarness | harness | `tests/protocol_integration.rs` | Fixture builder + standardized assertions + deterministic clock/ledger wiring | Integration tests requiring daemon state, ledger, and IPC | Keep scenario-specific assertions in local tests | 260 | `tests/protocol_integration.rs`, `tests/tck_00387_crash_recovery.rs`, `tests/hef_redteam.rs` | Low runtime risk; mainly test coupling risk |
| A04 | CanonicalTokenEnumMacro | macro | `identity/public_key_id.rs` enums | Macro generating `Display`, `FromStr`, token mapping, unknown-token errors | Closed enums with canonical wire tokens | Not for externally versioned free-form enums | 140 | `identity/*`, `hsi_contract/*`, `protocol/messages.rs` | Overuse can hide per-enum invariants |
| A05 | GuardedBuilderKit | macro+module | `fac/role_spec.rs`, `fac/efficiency_primitives.rs` | Builder derive with required-fields and invariant validators | Config/state structs with explicit construction contracts | Avoid performance-critical hot paths with custom lifetimes | 210 | `fac/role_spec.rs`, `fac/efficiency_primitives.rs`, `state.rs` | Validation hooks must remain explicit |
| A06 | ErrorEnvelopeMapper | module | `protocol/dispatch.rs` | Central mapping helpers from domain errors to protocol envelopes | API boundary translation only | Do not collapse domain error types internally | 190 | `protocol/dispatch.rs`, `protocol/session_dispatch.rs`, `protocol/messages.rs` | Potential to over-flatten error taxonomy |
| A07 | TransitionEventEmitter | module | `protocol/dispatch.rs` work transitions | Typed transition command object + standard ledger event emission | State transitions that always emit kernel event | Keep idempotency/retry policy at caller boundary | 170 | `protocol/dispatch.rs`, `gate/orchestrator.rs`, `session/mod.rs` | Event ordering assumptions must stay explicit |
| A08 | TaggedDigestCodec | module | `identity/public_key_id.rs`, `identity/keyset_id.rs` | Shared tagged digest parser/serializer with sentinel support | 1-byte tag + 32-byte hash IDs | Descriptor-specific canonicalization remains custom | 230 | `identity/public_key_id.rs`, `identity/keyset_id.rs`, `identity/mod.rs` | Tag semantics vary; must avoid over-generalization |
| A09 | SessionStateMutationTemplate | module | `state.rs`, `session/mod.rs` | Closure-based mutation helper with telemetry hooks | Session lifecycle updates with common lock/validate/update pattern | Exclude multi-aggregate transactions | 160 | `session/mod.rs`, `episode/runtime.rs`, `state.rs` | Locking semantics can be obscured |
| A10 | CapabilityManifestAccessor | module | `episode/reviewer_manifest.rs`, `governance.rs` | Typed accessor for manifest policy baseline checks | Capability minting/lookup/resolve flows | Policy engine behavior stays external | 150 | `episode/reviewer_manifest.rs`, `governance.rs`, `protocol/dispatch.rs` | Scope creep into policy decisions |

## Decision Matrix

Weights:
- dedup_sloc_saved: 25%
- future_pr_size_reduction: 25%
- containment_safety: 20%
- adoption_friction: 15%
- composability: 15%

Scoring scale: 1.0 (low) to 5.0 (high). `Total = 0.25*dedup + 0.25*future + 0.20*containment + 0.15*adoption + 0.15*composability`.

| Rank | ID | dedup | future | containment | adoption | composability | Total |
|---:|---|---:|---:|---:|---:|---:|---:|
| 1 | A01 | 4.6 | 4.8 | 4.9 | 4.1 | 4.8 | 4.67 |
| 2 | A02 | 4.9 | 5.0 | 3.4 | 3.0 | 4.7 | 4.31 |
| 3 | A03 | 3.8 | 4.0 | 4.7 | 4.4 | 4.0 | 4.15 |
| 4 | A05 | 3.8 | 4.1 | 4.4 | 3.8 | 4.3 | 4.07 |
| 5 | A06 | 3.6 | 4.0 | 4.2 | 3.7 | 4.4 | 3.96 |
| 6 | A08 | 3.9 | 3.8 | 4.5 | 3.4 | 4.0 | 3.94 |
| 7 | A04 | 3.1 | 3.4 | 4.9 | 4.6 | 4.1 | 3.91 |
| 8 | A07 | 3.4 | 3.9 | 4.5 | 3.8 | 4.0 | 3.90 |
| 9 | A09 | 3.3 | 3.7 | 4.3 | 3.5 | 3.9 | 3.72 |
| 10 | A10 | 3.2 | 3.6 | 4.7 | 3.4 | 3.8 | 3.72 |

## Winner: The Single Best Abstraction

Winner:
- `id`: A01
- `name`: CanonicalDigestIdKit
- `kind`: trait+macro

Why first:
- High dedup now and stronger compounding closure for incoming identity artifacts.
- Best containment profile among high-impact options: centralizes fail-closed parse invariants without centralizing runtime authority checks.
- Directly targets the strongest high-overlap cluster (C1), with objective >70% token overlap evidence.

Trait/API sketch:

```rust
pub trait CanonicalDigestId: Sized {
    const PREFIX: &'static str;
    const VERSION_TAG: u8;

    type Error;

    fn from_hash_bytes(hash: [u8; 32]) -> Self;
    fn hash_bytes(&self) -> &[u8; 32];

    fn parse_text(input: &str) -> Result<Self, Self::Error>;
    fn from_binary(bytes: &[u8]) -> Result<Self, Self::Error>;
    fn to_text(&self) -> String;
    fn to_binary(&self) -> [u8; 33];
}

canonical_digest_id! {
    name: CellIdV1,
    prefix: "cell:v1:blake3:",
    version_tag: 0x01,
    error: KeyIdError
}

canonical_digest_id! {
    name: HolonIdV1,
    prefix: "holon:v1:blake3:",
    version_tag: 0x01,
    error: KeyIdError
}
```

Migration path (top 3 adoption sites):
1. `crates/apm2-daemon/src/identity/cell_id.rs`
2. `crates/apm2-daemon/src/identity/holon_id.rs`
3. `crates/apm2-daemon/src/identity/public_key_id.rs`

Expected improvement claim (falsifiable):
- Claim: introducing A01 will reduce identity-codec implementation churn by >=30% Rust LOC across the next 8 identity-adjacent PRs while preserving current parse-error behavior.
- Falsification criteria:
  - LOC reduction <30% across those PRs, or
  - any golden-vector/test regression in canonical text/binary roundtrips, or
  - any change in externally visible error code/message mapping for existing ID types.

Runner-up:
- `id`: A02
- `name`: GuardedEndpointKernel
- `score_delta`: 0.36
- `why_not_first`: higher immediate dedup potential but worse containment safety due centralization of security-critical endpoint logic in a single abstraction seam.

## Validation Report

Checks:
1. DOMINANCE_ORDER compliance (`containment/security > verification/correctness > liveness/progress`)
- PASS for A01. It strengthens containment by consolidating fail-closed codec invariants; does not widen authority boundaries.

2. New crate dependency or circular dependency introduction
- PASS. Proposed as internal module/macro in existing crate; no new crate edges required.

3. Would it have prevented any known defect in `documents/theory/defects.json`?
- PARTIAL PASS. File is a normative defect framework, not a concrete incident ledger. A01 directly mitigates recurrence risk for violation classes `INTERFACE_PROLIFERATION` and `ABSTRACTION_BREAK`.

4. Generalization scope vs explanation tree consistency
- PASS. Scope is restricted to codec-level duplication and does not absorb domain-specific derivation semantics.

5. Boundary conditions explicit
- PASS. Domain separators, trust semantics, and authority checks remain outside the abstraction.

Validation summary:
- checks_passed: [1, 2, 4, 5]
- checks_failed: []
- checks_partial: [3]
- final_recommendation: keep A01 as final winner; schedule A02 as follow-on once explicit security property tests for endpoint-kernelization exist.

## Appendix: Full Ranking

| Rank | ID | Name | Kind | Total | Notes |
|---:|---|---|---|---:|---|
| 1 | A01 | CanonicalDigestIdKit | trait+macro | 4.67 | Best balance of dedup, compounding closure, and containment safety |
| 2 | A02 | GuardedEndpointKernel | module | 4.31 | High leverage, but security abstraction risk requires stronger proof harness |
| 3 | A03 | DaemonIntegrationHarness | harness | 4.15 | Strong reduction in repetitive integration setup/assert sequences |
| 4 | A05 | GuardedBuilderKit | macro+module | 4.07 | Good medium-leverage cleanup across config/state surfaces |
| 5 | A06 | ErrorEnvelopeMapper | module | 3.96 | Useful standardization at protocol boundary |
| 6 | A08 | TaggedDigestCodec | module | 3.94 | Valuable but overlaps with A01 scope |
| 7 | A04 | CanonicalTokenEnumMacro | macro | 3.91 | Low-risk quality uplift, moderate leverage |
| 8 | A07 | TransitionEventEmitter | module | 3.90 | Improves consistency of transition-event publication |
| 9 | A09 | SessionStateMutationTemplate | module | 3.72 | Moderate gain, lock/flow complexity limits scope |
| 10 | A10 | CapabilityManifestAccessor | module | 3.72 | Useful hygiene, lower marginal leverage than higher-ranked items |
