# RFC-0025: Autonomous Service Operation — Seed

## Required context files

Read all of these before generating output:

- documents/theory/unified-theory-v2.json
- documents/theory/unified-theory-v2.json
- documents/theory/unified-theory-v2.json
- documents/theory/unified-theory-v2.json
- documents/strategy/MASTER_STRATEGY.json
- documents/strategy/BUSINESS_PLAN.json
- documents/strategy/ROADMAP.json
- documents/rfcs/RFC-0020/HOLONIC_SUBSTRATE_INTERFACE.md
- documents/rfcs/RFC-0021/HOLONIC_VENTURE_PROVING_INTERFACE.md
- documents/rfcs/RFC-0024/RESOURCE_PROVISIONING.md
- proto/kernel_events.proto

## Why this RFC matters

Once agents are provisioned and instructed, they need to operate: deploy services, monitor health, respond to incidents, meet SLAs, and generate evidence of business value. Traditional operations (SRE, DevOps, ITIL) assumes human operators and static infrastructure. This RFC must define what operations looks like when both the operators and the operated-upon are autonomous agents in a holarchy. Incident response becomes a protocol, not a runbook. SLAs become machine-checkable predicates, not contractual prose. Revenue is evidence-bound, not self-reported. The frontier here is active-inference-based anomaly detection, formal incident containment protocols, and operational survivability under Byzantine conditions.

## Priority innovation vectors

- **Active inference for monitoring**: use the free energy principle to define 'normal' as a generative model prediction, with anomalies as prediction errors that trigger containment before diagnosis.
- **Formal incident containment**: incident response as a typed protocol with containment-first triage — bound the blast radius before you understand the cause.
- **SLA as proof obligation**: machine-checkable SLA predicates evaluated against evidence under HTF time authority, not wall-clock approximations.
- **Revenue as evidence**: business value claims bound to AAT-BIZ verification receipts — the system doesn't just report revenue, it proves it.
- **Operational survivability under partition**: define safe degradation modes when cells lose connectivity, including which operations continue, which pause, and which fail-closed.

## Problem (PHY-03, PHY-04, INV-F-15)

The system must eventually generate revenue (BSP_01: value requires state transformation; BSP_04: physical cost floors are non-zero). RFC-0021 VPHI defines the Venture Proving Holon with AAT-BIZ verification and strategy coupling to MSC-03/MSC-05/MSC-06. RFC-0019 FAC v0 automates admission. RFC-0018 HEF provides the event fabric. RFC-0017 defines daemon-as-control-plane.

But there is no normative protocol for deploying a live service, monitoring it, responding to incidents, enforcing SLAs, collecting revenue evidence, or managing the service lifecycle. The system can build and verify code; it cannot operate a production service. This RFC closes the gap between "code passes FAC" and "customers are using it and paying."

## What already exists

| Artifact | Provides | Gap |
|---|---|---|
| RFC-0019 FAC v0 | Automated admission (ingestion -> review -> receipt -> projection) | Admits code, doesn't deploy or operate it |
| RFC-0021 VPHI | Venture proving with business verification | Verifies strategy claims, doesn't run services |
| RFC-0018 HEF | Pulse plane for event routing | Carries events, doesn't define operational events |
| RFC-0017 Daemon | Control plane with capability-minted episodes | Controls episodes, doesn't manage long-running services |
| apm2d_runtime_v1.proto Process Management | ListProcesses, Start/Stop/Restart/Reload | Manages daemon processes, not deployed services |
| BSP_01-BSP_04 | Physics-of-value axioms | Axioms without operational protocol |
| HSI §11 Business Continuity | RPO/RTO targets, backup/restore, chaos drills | Defined for the platform itself, not for services the platform operates |

## Machine-checkable objectives

**OBJ-ASO-01**: Deployment is receipt-gated: No service deployment without a FAC admission receipt AND a VPHI strategy-alignment receipt. Services deployed without both are S0 defects.
- Predicate: `∀ deployment: ∃ fac_receipt ∧ ∃ vphi_receipt: both.valid = true`

**OBJ-ASO-02**: Health is continuously attested: Every running service must produce health attestations at a configurable interval. Missing attestation triggers incident protocol within one interval.
- Predicate: `∀ service ∈ RUNNING: health_attestation present per interval`

**OBJ-ASO-03**: Incident response is autonomous and bounded: The system must detect, diagnose, and either remediate or escalate incidents within a declared SLO. Remediation actions are logged as evidence.
- Predicate: `∀ incident: (remediated ∨ escalated) within incident_slo`

**OBJ-ASO-04**: Revenue events are evidence-grade: Every revenue-generating transaction must produce a ReceiptV1 with the transaction details, bound to the service's deployment receipt and the VPHI strategy coupling.
- Predicate: `∀ revenue_event: ∃ receipt: receipt.links = {deployment_receipt, vphi_receipt}`

**OBJ-ASO-05**: SLA is a contract object: Every deployed service must have a machine-readable SLA. SLA violations are DefectRecords, not soft alerts.
- Predicate: `∀ service: ∃ sla ∈ ServiceLevelAgreementV1 ∧ violation → DefectRecord`

**OBJ-ASO-06**: Rollback is always available: Every service deployment must maintain a rollback target. Rollback to the previous known-good version must complete within the deployment SLO.
- Predicate: `∀ deployment: ∃ rollback_target ∧ rollback_latency ≤ deployment_slo`

**OBJ-ASO-07**: Cost attribution is per-service: Every resource consumed by a service must be attributed to that service's budget (from RFC-0024 ResourceBudgetV1). Services exceeding their budget trigger the exhaustion policy.
- Predicate: `∀ resource ∈ consumed: ∃ service: resource.attributed_to = service.id`

## Protocol objects (seed schemas)

These are starting points — refine, extend, or restructure as your analysis requires.

```
ServiceManifestV1 {
    service_id: CasDigest,
    name: str,
    version: SemVer,
    deployment_artifact: CasDigest,
    fac_admission_receipt: CasDigest,
    vphi_alignment_receipt: CasDigest,
    instruction_spec_refs: Vec<CasDigest>,
    sla: ServiceLevelAgreementV1,
    resource_budget: ResourceBudgetV1,
    rollback_target: Option<CasDigest>,
    health_check: HealthCheckSpecV1,
    created_at: TimeEnvelopeRef,
    principal_seal: AuthoritySealV1,
}

ServiceLevelAgreementV1 {
    availability_target: Quantity,
    latency_p99: Quantity,
    error_rate_ceiling: Quantity,
    data_durability: Quantity,
    measurement_window: Duration,
    violation_severity: Severity,
    goodhart_surface: str,
}

DeploymentReceiptV1 {
    manifest_digest: CasDigest,
    target_holon: HolonIdV1,
    deployed_at: TimeEnvelopeRef,
    deployment_evidence: Vec<CasDigest>,
    previous_deployment: Option<CasDigest>,
    deployer_seal: AuthoritySealV1,
}

HealthAttestationV1 {
    service_id: CasDigest,
    holon_id: HolonIdV1,
    epoch: TimeEnvelopeRef,
    status: ServiceStatus,
    metrics: ServiceMetricsV1,
    sla_compliance: SlaComplianceV1,
    attestation_seal: AuthoritySealV1,
}

ServiceStatus { DEPLOYING | RUNNING | DEGRADED | DOWN | ROLLING_BACK | TERMINATED }

IncidentRecordV1 {
    incident_id: CasDigest,
    service_id: CasDigest,
    detected_at: TimeEnvelopeRef,
    detection_method: str,
    severity: Severity,
    diagnosis: DiagnosisV1,
    remediation_actions: Vec<RemediationActionV1>,
    resolution: IncidentResolution,
    resolved_at: Option<TimeEnvelopeRef>,
    defect_record: CasDigest,
    evidence_chain: Vec<CasDigest>,
}

RevenueEventV1 {
    service_id: CasDigest,
    transaction_id: str,
    amount: Quantity,
    customer_id_hash: CasDigest,
    occurred_at: TimeEnvelopeRef,
    deployment_receipt: CasDigest,
    vphi_coupling: CasDigest,
    receipt: ReceiptV1,
}

RemediationActionV1 {
    action_type: RemediationType,
    executed_at: TimeEnvelopeRef,
    result: RemediationResult,
    evidence: CasDigest,
    autonomy_level_required: AutonomyLevel,
}
```

## Trust boundaries and threat model

Trust boundary: Deployed services run in provisioned holons (RFC-0024). The monitoring and incident response system runs in a SEPARATE holon from the service — you do not let the patient diagnose themselves (LAW-08, verifier economics). Revenue events must be attested by the service AND independently verifiable by the monitoring holon.

Threats:
1. **False health attestation (PHY-05)**: Service reports healthy when degraded. Mitigation: independent health probing from monitoring holon, not self-report only.
2. **SLA gaming (AEP_07)**: Metrics are optimized to pass SLA checks without actual quality. Mitigation: goodhart_surface declaration on every SLA; multi-signal health (not single metric).
3. **Revenue fabrication (PHY-05)**: Service claims revenue that didn't occur. Mitigation: revenue events require external payment processor confirmation; double-entry evidence.
4. **Incident suppression (PHY-05)**: System auto-remediates and hides incidents from principal. Mitigation: all incidents produce DefectRecords in the append-only ledger; sovereign audit (RFC-0022) can discover them.
5. **Deployment of unverified code (INV-F-02)**: Code deployed without FAC admission. Mitigation: OBJ-ASO-01 — dual receipt gate.

## Theory bindings

- LAW-01 (Loop Closure): Service lifecycle is a loop (deploy -> monitor -> incident -> remediate -> re-verify -> operate)
- LAW-08 (Verifier Economics): Monitoring holon is economically independent of the service it monitors
- LAW-14 (Proportionality): Incident response is proportional to severity
- LAW-15 (Measurement Integrity): Health metrics have declared measurement contracts
- INV-F-02 (No transition without gate receipt): Deployment requires FAC + VPHI receipts
- INV-F-09 (Budgets mandatory): Every service has resource and cost budgets
- INV-F-14 (containment > verification > liveness): Service liveness never overrides containment; a service that violates containment is terminated, not kept alive
- INV-F-15 (Authoritative promotion requires terminal verifier): Revenue claims require terminal verification

## Rollout

- S0: ServiceManifestV1 and DeploymentReceiptV1 — structured deployment with receipt
- S1: HealthAttestationV1 — basic health checking with attestation
- S2: SLA contracts — machine-readable SLA with violation -> DefectRecord
- S3: Incident detection and autonomous remediation (restart, rollback)
- S4: RevenueEventV1 — revenue tracking with evidence-grade receipts
- S5: Full autonomous service lifecycle — deploy, monitor, remediate, scale, retire
- S6: Multi-service orchestration — dependency management between services
- S7: Cost optimization — budget-aware placement and scaling decisions
