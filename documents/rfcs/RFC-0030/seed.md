# RFC-0030 — Forge Refinement Pipeline: Mechanized Plan Admission from Intent to Pinned Plan-of-Record

## Abstract

This document specifies the Forge Refinement Pipeline (FRP), a
repeatable, budgeted, adversarially-reviewed pipeline that converts an
intent brief into two admitted planning documents — a Technical
Specification (TechSpec) and an Implementation Plan (ImplPlan) — and
pins their content-addressed digests as plan-of-record inputs for
subsequent work.

FRP replaces template-driven document generation with patch-admitted
document production. Agents do not complete forms. They draft sectioned
content, propose explicit amendments as unified diffs, and provide
receipts that mechanical gates evaluate. Every transition in the
pipeline is ledger-anchored, CAS-backed, and deterministically
replayable. Admission requires receipt-bound closure under a quorum of
diverse reviewers; missing evidence is treated as failure.

The pipeline is a single WorkItem with explicit substages. It composes
with the Forge Admission Cycle (RFC-0019) evidence substrate, the
Holonic Substrate Interface (RFC-0020) capability model, and the
Context-as-Code pipeline (RFC-0011) for artifact serialization.


## 1.  Requirements Notation

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119.

Additionally:

   o  "fail-closed" means that a missing, stale, ambiguous, or
      unverifiable input causes denial, not degraded continuation.

   o  "content-addressed" means identified by the cryptographic digest
      (BLAKE3 unless otherwise specified) of the canonical byte
      representation.

   o  "ledger-anchored" means referenced by a KernelEvent appended to
      the append-only ledger after the corresponding CAS artifact
      exists (CAS-before-ledger invariant).


## 2.  Definitions

   DocPack:  A sectioned Markdown document directory with a machine-
      readable manifest. A DocPack is the unit of admission for FRP.
      Each DocPack contains one manifest, one or more section files,
      and an assembly ordering. DocPacks are never "filled in" from
      templates; they are produced by drafting, amended by explicit
      diffs, and admitted by mechanical gates.

   Section:  A single Markdown file within a DocPack. Every section
      begins with a machine-readable header block that binds it to a
      known base digest and document identity (Section 4.3). Sections
      are the unit of parallel drafting, review, and diff application.

   Amendment:  A proposed change to a DocPack expressed as a unified
      diff plus structured findings. An amendment without a diff is
      invalid (FRP-INV-007). Amendments are the sole mechanism by
      which a DocPack transitions between revisions.

   Intent Brief:  The single authoritative description of what is
      being built and why. The Intent Brief MAY be produced by a
      human, by an upstream pipeline, or by any autonomous process
      that can satisfy the IntentBriefV1 schema. The origin is not
      privileged; only schema conformance and immutability matter.
      The Intent Brief is immutable once a refinement cycle begins;
      modifications require a new cycle with a new intent_id.

   Admitted:  A DocPack whose gate receipts, reviewer quorum receipts,
      and diversity constraints all satisfy the admission policy. Only
      admitted DocPacks may be pinned as plan-of-record.

   Plan-of-Record Pin:  A ledger-anchored evidence artifact that
      declares a pair of admitted DocPack digests (TechSpec +
      ImplPlan) as the authoritative planning basis for subsequent
      implementation work.

   Verdict Semilattice:  The ordering FAIL > PENDING > PASS with
      FAIL dominating. The join of any set containing FAIL is FAIL.
      Missing evidence yields PENDING, which MUST NOT mask a co-
      occurring FAIL.

   Delta Report:  A deterministic comparison artifact produced after
      each patch application. Contains before/after digests, gate
      outcome changes, structural metric changes, and regression
      detection results.


## 3.  Invariants

FRP does not introduce new governance semantics. It operates within
the vNext kernel constraint surface. The following invariants are
normative for all FRP implementations.

   FRP-INV-001  Monotone truth substrate.
      Authoritative facts are append-only and backed by content-
      addressed evidence pointers (ledger + CAS). FRP MUST NOT
      mutate admitted artifacts; it MUST produce new revisions.

   FRP-INV-002  Authority attenuation and scarcity.
      Capabilities are default-deny. Budgets (token, wall-time,
      tool-call, iteration) and stop conditions are mandatory for
      every agent invocation. Unbounded search or actuation is a
      defect.

   FRP-INV-003  Promotion is closure under receipts.
      Nothing becomes authoritative (admitted, pinned) without
      receipt-bound closure. The set of required receipts is defined
      by the admission policy and MUST include gate receipts and
      reviewer quorum receipts.

   FRP-INV-004  Dominance ordering.
      Containment/security > verification/correctness > liveness/
      progress. When constraints conflict, FRP MUST deny, decompose,
      or escalate. FRP MUST NOT "push through" a security or
      correctness concern to preserve pipeline progress.

   FRP-INV-005  Fail-closed verdict lattice.
      FAIL > PENDING > PASS. Missing evidence yields PENDING.
      PENDING MUST NOT mask a co-occurring FAIL. For plan-of-record
      pinning, PENDING is treated as FAIL unless explicitly allowed
      by a risk-tier-dependent policy waiver.

   FRP-INV-006  Bounded views.
      Agents operate on bounded ContextPacks with committed view
      selectors. Direct messaging between agents is not a primitive;
      coordination occurs through the stigmergic substrate
      (ledger + CAS artifacts).

   FRP-INV-007  Amendment validity.
      An amendment without a unified diff is invalid and MUST be
      rejected. Prose-only critique is not an admissible work
      product. Every finding in an amendment MUST reference specific
      patch hunks.

   FRP-INV-008  Deterministic patch application.
      Patch application MUST be deterministic and fail-closed. If a
      patch does not apply cleanly against the declared base digest,
      the PatchApplies gate MUST emit FAIL. No silent fuzzing,
      offset tolerance, or approximate matching is permitted.

   FRP-INV-009  Critic context isolation.
      Critics MUST NOT receive prior iteration history — no previous
      amendment bundles, delta reports, gate receipts, or iteration
      counters. Each critic operates as if it is the first reviewer
      of a fresh document. This prevents anchoring, effort diffusion,
      and lazy agreement with prior reviewers.


## 4.  Artifacts and Schemas

FRP operates on the APM2 ledger + CAS substrate and emits evidence
artifacts for every stage. All artifacts MUST be content-addressed,
referenced from ledger events, and attributable to an identity and
role specification.

### 4.1.  Intent Brief

The Intent Brief is the input that initiates a refinement cycle. It
is a CAC JSON artifact with schema `frp.intent_brief.v1`. The Intent
Brief MAY originate from any source — human, upstream pipeline, or
autonomous agent — provided it satisfies the schema. FRP is
source-agnostic; it validates structure, not provenance.

Fields:

   intent_id:  Stable identifier (REQUIRED). Format:
      `dcp://apm2.local/intents/<project_id>@v<N>`.

   title:  Human-readable title (REQUIRED).

   problem_statement:  Description of the problem to be solved
      (REQUIRED).

   goals:  Array of testable outcome statements (REQUIRED, non-empty).

   non_goals:  Array of explicit exclusions (REQUIRED, MAY be empty).

   constraints:  Array of security, correctness, compliance, or
      ecosystem constraints (REQUIRED, non-empty).

   risk_tier:  Risk classification (REQUIRED). Values: LOW, MEDIUM,
      HIGH, CRITICAL.

   acceptance_criteria:  Array of project-level acceptance predicates
      (REQUIRED, non-empty). These are outcome criteria, not
      implementation criteria.

   references:  Array of repository paths, prior RFC IDs, or external
      references (OPTIONAL).

Immutability rule: Once an FRP cycle begins (WorkOpened event
references intent_hash), the Intent Brief MUST NOT be modified.
Changes to intent require a new intent_id and a new cycle. No
human-in-the-loop is required or assumed at any point after the
Intent Brief is provided.

### 4.2.  Document Manifest

Each document (TechSpec, ImplPlan) has a manifest with schema
`frp.doc_manifest.v1`.

Fields:

   doc_id:  Stable identifier (REQUIRED). Format:
      `dcp://apm2.local/docs/<project_id>/<doc_kind>@v<N>`.

   doc_kind:  One of: TECH_SPEC, IMPL_PLAN (REQUIRED).

   classification:  Document classification (REQUIRED).

   inputs:  Binding structure (REQUIRED):

      intent_hash:  Content-addressed digest of the Intent Brief.

      policy_root_hash:  Digest of the governing policy tree.

      doctrine_refs:  Array of law/invariant/RFC identifiers that
         this document must satisfy.

   sections:  Array of section descriptors (REQUIRED, non-empty):

      section_id:  Stable identifier (e.g., TS-0001). MUST be
         unique within the manifest.

      title:  Human-readable section title.

      path:  Relative file path within the DocPack directory.

      required_checks:  Array of gate identifiers that apply to
         this section.

   assembly:  Deterministic ordering specification (REQUIRED):

      section_order:  Ordered array of section_id values defining
         the canonical document order.

   admission_policy:  Admission requirements (REQUIRED):

      required_reviewer_roles:  Array of role identifiers.

      quorum_rule:  Quorum specification (e.g., "k-of-n with
         diversity constraint d").

      required_gates:  Array of gate identifiers that MUST PASS
         for admission.

### 4.3.  Section Header

Every section file MUST begin with a machine-readable header as an
HTML comment block. The header binds the section to a known base
for deterministic diff application.

Format:

```
<!--
frp.section.v1:
  section_id: <section_id>
  doc_id: <doc_id>
  base_digest: <algorithm>:<hex>
  last_admitted_at: <ledger_time_ref | null>
-->
```

   section_id:  MUST match the section_id in the parent manifest.

   doc_id:  MUST match the doc_id in the parent manifest.

   base_digest:  Content-addressed digest of the section content
      (excluding the header block itself) at the last admitted
      revision. For initial drafts, this is the digest of the
      empty string.

   last_admitted_at:  Ledger time reference (HTF boundary ID) of
      the last admission, or null for initial drafts.

Stale patch detection: A diff whose declared target base_digest
does not match the current section content digest MUST be rejected
(FRP-INV-008).

### 4.4.  Amendment Bundle

Every critique MUST produce an amendment bundle with schema
`frp.doc_amendment_bundle.v1`. An amendment without a changeset
(unified diff) is invalid (FRP-INV-007).

Fields:

   amendment_id:  Stable identifier (REQUIRED).

   target_doc_id:  The doc_id of the DocPack being amended (REQUIRED).

   target_base_digest:  Content-addressed digest of the full DocPack
      at the base revision (REQUIRED).

   changeset_bundle_hash:  Digest of a ChangesetBundleV1 artifact
      stored in CAS containing the unified diff (REQUIRED).

   review_artifact_hash:  Digest of a ReviewArtifactBundleV1 in
      CAS containing the critique narrative and tool logs
      (REQUIRED).

   findings:  Array of finding structures (REQUIRED, non-empty):

      finding_id:  Stable within this amendment.

      severity:  One of: BLOCKER, HIGH, MEDIUM, LOW.

      class:  Defect taxonomy key (OPTIONAL; from
         documents/theory/unified-theory-v2.json when available).

      evidence:  Structure containing section_id, start_line,
         end_line identifying the problematic region.

      expected_fix:  Array of patch hunk references within the
         changeset_bundle that address this finding.

   declared_intent:  One of: CORRECTNESS_FIX, SECURITY_HARDENING,
      COMPLETENESS_EXPANSION, CONSISTENCY_REPAIR, CLARITY_REWRITE,
      RISK_REDUCTION (REQUIRED).

### 4.5.  Delta Report

After each patch application, FRP MUST produce a delta report with
schema `frp.doc_delta_report.v1`.

Fields:

   before_digest:  DocPack digest before patch application.

   after_digest:  DocPack digest after patch application.

   structural_metrics:  Structure containing:

      sections_present:  Count of non-empty sections.

      sections_required:  Count from manifest.

      placeholder_count:  Count of forbidden placeholder strings.

      cross_ref_resolution_rate:  Fraction of section_id references
         that resolve to existing sections.

   gate_outcomes:  Array of (gate_id, verdict) pairs.

   reviewer_receipt_set:  Array of receipt digests.

   regressions:  Array of (metric_name, before_value, after_value)
      for any metric that worsened.


### 4.6.  DocPack Directory Structure

A DocPack is a directory with the following layout:

```
documents/forge/<project_id>/
  intent.intent_brief.v1.cac.json
  tech_spec/
    manifest.doc_manifest.v1.cac.json
    sections/
      TS-0001_problem_and_goals.md
      TS-0002_non_goals.md
      TS-0003_system_context.md
      TS-0004_architecture.md
      TS-0005_data_model.md
      TS-0006_interfaces.md
      TS-0007_security_model.md
      TS-0008_correctness_model.md
      TS-0009_operational_model.md
      TS-0010_governance.md
      TS-0011_migration.md
      TS-0012_open_questions.md
      TS-0013_appendices.md
  impl_plan/
    manifest.doc_manifest.v1.cac.json
    sections/
      IP-0001_milestones.md
      IP-0002_work_breakdown.md
      IP-0003_dependency_graph.md
      IP-0004_risk_register.md
      IP-0005_verification_plan.md
      IP-0006_resource_budgets.md
      IP-0007_backout_procedures.md
      IP-0008_acceptance_mapping.md
```


## 5.  Pipeline State Machine

FRP is implemented as a single parent WorkItem with schema
`frp.refinement_work.v1`. The work item progresses through nine
ordered substages. Each substage transition MUST be driven by
ledger-visible events and MUST produce evidence artifacts.

### 5.1.  Substage Definitions

#### 5.1.1.  INTAKE

   Precondition:  A valid IntentBriefV1 exists at the specified path.

   Actions:
      1. Validate Intent Brief against schema.
      2. Store Intent Brief in CAS; obtain intent_hash.
      3. Open refinement WorkItem referencing intent_hash.

   Evidence emitted:
      o  WorkOpened(work_id, intent_hash)
      o  EvidencePublished(intent_brief, intent_hash)

   Failure mode:  Schema validation failure -> WorkItem not opened.

#### 5.1.2.  FRAME

   Precondition:  INTAKE complete.

   Actions:
      1. Resolve governing policy (laws, invariants, RFCs).
      2. Generate DocManifests for TechSpec and ImplPlan.
      3. Generate section skeleton files with headers (base_digest
         of empty content).
      4. Store manifests and skeletons in CAS.

   Evidence emitted:
      o  EvidencePublished(doc_manifest, tech_spec_manifest_hash)
      o  EvidencePublished(doc_manifest, impl_plan_manifest_hash)

   Failure mode:  Policy resolution failure -> FAIL with
      PolicyResolutionBlocked event.

#### 5.1.3.  DRAFT

   Precondition:  FRAME complete.

   Actions:
      1. For each section in each DocPack, invoke a Drafter agent
         with bounded context (ContextPack containing intent,
         manifest, doctrine refs, and relevant prior artifacts).
      2. Drafter produces section content.
      3. Store each drafted section snapshot in CAS.

   Evidence emitted:
      o  For each section: EvidencePublished(draft_section_snapshot,
         section_hash)

   Failure mode:  Budget exhaustion -> FAIL with
      BudgetExhausted event.

#### 5.1.4.  CRITIQUE

   Precondition:  DRAFT complete (working draft exists).

   Context isolation rule:  Each critic MUST receive the current
      working DocPack as if it were the initial draft. The critic's
      ContextPack MUST NOT contain: previous iteration amendment
      bundles, prior delta reports, prior gate receipts, or any
      indicator of which iteration this is. The critic must believe
      it is the first and only reviewer. This prevents anchoring to
      prior reviews, lazy "agree with predecessor" behavior, and
      effort reduction from perceived review-chain diffusion.
      The intent brief, manifest, and doctrine refs ARE included.

   Actions:
      1. Invoke critic agents with adversarial framing
         (Section 6.2) and context isolation (above).
      2. Each critic MUST produce a DocAmendmentBundleV1 with
         unified diff and structured findings.
      3. Store amendment bundles in CAS.

   Verifier diversity requirement:  At least K=2 independent
      reviewer families MUST produce amendment bundles. Diversity
      is achieved through model selection (Section 6.3), not
      through prompt or configuration variation of the same model.

   Evidence emitted:
      o  For each critique:
         - EvidencePublished(review_artifact_bundle, review_hash)
         - EvidencePublished(changeset_bundle, changeset_hash)
         - EvidencePublished(doc_amendment_bundle, amendment_hash)

   Failure mode:  Critic produces amendment without diff ->
      amendment rejected (FRP-INV-007). Budget exhaustion ->
      FAIL.

#### 5.1.5.  APPLY

   Precondition:  CRITIQUE complete (amendment bundles exist).

   Single-amendment rule:  Although multiple critics produce
      amendment bundles independently (a prompting technique for
      diverse coverage), only ONE amendment bundle is selected for
      application per iteration. Merging parallel diffs is
      explicitly prohibited — it introduces conflict resolution
      complexity for no structural benefit.

   Actions:
      1. Score amendment bundles by: (a) count of BLOCKER findings
         addressed, then (b) count of HIGH findings addressed,
         then (c) total finding count. Select the highest-scoring
         bundle. Ties are broken by earliest submission timestamp.
      2. Apply the selected changeset using a deterministic patch
         engine.
      3. Produce a Delta Report.
      4. Non-selected amendment bundles are retained in CAS as
         evidence but are not applied. Findings from non-selected
         bundles that survive into the next iteration's working
         DocPack will be independently rediscovered by fresh
         critics (Section 5.1.4, context isolation rule).

   Determinism requirement:  Patch application MUST use a
      deterministic engine (e.g., `git apply --check` followed by
      `git apply`). If the selected patch does not apply cleanly,
      APPLY emits FAIL for this iteration and the next CRITIQUE
      cycle operates on the unchanged DocPack. Model-based
      rewriting and conflict resolution subtasks are not permitted.

   Evidence emitted:
      o  EvidencePublished(delta_report, delta_hash)
      o  Updated DocPack snapshot:
         - EvidencePublished(docpack_snapshot, snapshot_hash)

   Failure mode:  Patch does not apply cleanly -> PatchApplies
      gate emits FAIL -> DocPack unchanged, next iteration begins.

#### 5.1.6.  VERIFY

   Precondition:  APPLY complete (updated DocPack exists).

   Actions:
      1. Run Tier 0 gates (structural).
      2. Run Tier 1 gates (mechanical-semantic).
      3. Run Tier 2 gates (LLM-assisted audits, receipted).
      4. Evaluate plateau detection (Section 8.3).

   Gate evaluation is described in Section 7.

   Evidence emitted:
      o  For each gate:
         - GateReceiptGenerated(gate_id, verdict, evidence_ids[])

   Failure mode:  Any Tier 0 or Tier 1 gate FAIL -> loop back to
      CRITIQUE with failure context. Plateau detected -> halt
      with PipelineStalled event.

#### 5.1.7.  ADMIT

   Precondition:  VERIFY complete with all required gates PASS
      (or explicitly waived per policy).

   Actions:
      1. Evaluate admission closure: verify all required gate
         receipts exist and are PASS.
      2. Verify reviewer quorum: required number of reviewers from
         required number of distinct families have produced PASS
         receipts for each gate category.
      3. Store admitted DocPack snapshot in CAS.

   Evidence emitted:
      o  EvidencePublished(admitted_docpack_snapshot,
         admitted_digest)

   Failure mode:  Quorum not met -> FAIL. Gate receipt missing ->
      FAIL (FRP-INV-005). Any FAIL in required gate set -> FAIL.

#### 5.1.8.  PIN

   Precondition:  ADMIT complete for both TechSpec and ImplPlan.

   Actions:
      1. Construct plan-of-record pin artifact binding:
         - admitted TechSpec digest
         - admitted ImplPlan digest
         - intent_hash
         - admission receipt set
      2. Store pin artifact in CAS.
      3. Anchor pin to ledger.

   Evidence emitted:
      o  EvidencePublished(plan_of_record_pin, pin_hash)

   Failure mode:  Missing admission for either document -> FAIL.

#### 5.1.9.  HANDOFF

   Precondition:  PIN complete.

   Actions:
      1. Construct handoff manifest containing:
         - pin_hash
         - techspec_doc_id + digest
         - implplan_doc_id + digest
         - ticket decomposition pointers (if generated)
         - suggested implementer context pack selectors
      2. Store handoff manifest in CAS.
      3. Anchor to ledger.

   Evidence emitted:
      o  EvidencePublished(handoff_manifest, handoff_hash)

   Terminal state. The refinement WorkItem is closed.

### 5.2.  Iteration Loop

Substages CRITIQUE, APPLY, and VERIFY form an iteration loop. The
pipeline MUST repeat this loop until one of the following conditions
holds:

   a) All required gates PASS and quorum is satisfied (proceed to
      ADMIT).

   b) Maximum iteration count reached (halt with
      IterationLimitReached event).

   c) Budget exhausted (halt with BudgetExhausted event).

   d) Plateau detected for N consecutive iterations (halt with
      PipelineStalled event).

   e) Safety gate FAIL persists after M retries (halt with
      SafetyHalt event; pipeline cannot self-resolve).

The iteration counter, budget consumption, and plateau state MUST
be recorded in each Delta Report.

### 5.3.  Ledger Event Summary

The following ledger events MUST be emitted at minimum. Each event
references one or more CAS artifact digests.

```
WorkOpened(work_id, intent_hash)
EvidencePublished(kind, artifact_hash)         -- per artifact
GateReceiptGenerated(gate_id, verdict, [evidence_hash])
PipelineStalled(work_id, iteration, reason)    -- on halt
BudgetExhausted(work_id, dimension, consumed, limit)
SafetyHalt(work_id, gate_id, iteration)
WorkClosed(work_id, outcome, pin_hash | failure_report_hash)
```

### 5.4.  Fail-Closed Semantics

FRP uses the verdict semilattice FAIL > PENDING > PASS.

   o  The join of any set of verdicts containing FAIL is FAIL.

   o  Missing evidence yields PENDING.

   o  PENDING MUST NOT mask a co-occurring FAIL.

   o  For plan-of-record pinning, PENDING is treated as FAIL
      unless explicitly allowed by a risk-tier-dependent policy
      waiver recorded as a ledger event.


## 6.  Role System

FRP employs a multi-agent adversarial protocol. Agents are assigned
roles via RoleSpecV1 artifacts (RFC-0019 REQ-0012). Each role
carries a capability manifest that defines tool access.

### 6.1.  Required Roles

Every FRP execution MUST include agents in the following roles:

   Drafter:  Produces section content for a DocPack. Read access to
      intent, manifest, doctrine refs, and relevant prior artifacts.
      Write access limited to a sandbox output directory.

   Red-Team Critic:  Identifies flaws and proposes corrections as
      amendment bundles. Instructed with adversarial framing
      (Section 6.3). Read access to the working DocPack and
      doctrine refs. Write access limited to amendment output.

   Consistency Auditor:  Evaluates cross-section and cross-document
      consistency. Produces amendment bundles for contradictions,
      broken references, and semantic drift between TechSpec and
      ImplPlan.

   Security Auditor:  Evaluates threat coverage, boundary
      constraints, least-privilege adherence, and attack surface.
      Produces amendment bundles for security deficiencies.

   Patch Applier:  Applies amendment diffs to the working DocPack
      using a deterministic patch engine. This role SHOULD be
      implemented as a deterministic tool, not a model. If model
      involvement is required (conflict resolution), it MUST
      produce a new amendment bundle subject to standard gates.

   Gate Runner:  Executes mechanical gate checks (Section 7).
      Read-only access to the DocPack and gate definitions.
      Produces gate receipts.

### 6.2.  Adversarial Critique Protocol

Every critic (Red-Team, Consistency Auditor, Security Auditor) MUST
receive the following system-level instruction framing:

   "Assume this document was produced by a less capable agent under
   time pressure. It contains contradictions, missing constraints,
   weak threat coverage, underspecified interfaces, and implicit
   assumptions. Your task is to find every deficiency and propose
   an explicit fix as a unified diff. Do not praise, hedge, or
   agree. State what is wrong and fix it."

This framing is a normative requirement, not a suggestion. Critique
sessions that do not apply adversarial framing MUST be treated as
non-compliant and their outputs rejected.

#### 6.2.1.  Critique Output Format

Critic output MUST be a single structured document in two mandatory
sections, emitted in order: FINDINGS followed by PATCH. The output
MUST be parseable by a deterministic extractor into a
DocAmendmentBundleV1 (Section 4.4) without model assistance.

The output format is:

```
---BEGIN FINDINGS---
- id: F-001
  severity: BLOCKER | HIGH | MEDIUM | LOW
  class: <defect_taxonomy_key | UNCLASSIFIED>
  section: <section_id>
  lines: <start_line>-<end_line>
  description: |
    <concise description of the deficiency>
  fix_hunks: [1]

- id: F-002
  severity: HIGH
  class: MISSING_CONSTRAINT
  section: TS-0007
  lines: 42-58
  description: |
    <concise description of the deficiency>
  fix_hunks: [2, 3]

...
---END FINDINGS---

---BEGIN PATCH---
<unified diff against the declared base_digest, with standard
 unified diff headers per section file>
---END PATCH---
```

Field definitions for each finding:

   id:  Finding identifier, unique within this critique. Format:
      F-NNN, monotonically increasing.

   severity:  One of BLOCKER, HIGH, MEDIUM, LOW. Severity
      determines application priority (Section 5.1.5).

   class:  Defect taxonomy key from documents/theory/unified-theory-v2.json
      when a match exists. UNCLASSIFIED otherwise. Parsers MUST
      accept both known keys and UNCLASSIFIED.

   section:  The section_id (from the DocManifest) where the
      deficiency occurs.

   lines:  Line range within the section file (excluding the
      header block). Format: <start>-<end>, inclusive, 1-indexed.
      For findings that span the entire section, use 1-<last_line>.

   description:  Plain text description of the deficiency. MUST
      state what is wrong, not what is right. MUST NOT contain
      praise, hedging, or qualifications. Maximum 500 tokens.

   fix_hunks:  Array of 1-indexed hunk numbers within the PATCH
      section that address this finding. Every hunk in the PATCH
      MUST be referenced by at least one finding. Every finding
      MUST reference at least one hunk.

Patch section requirements:

   o  The patch MUST be a valid unified diff (output of
      `diff -u` or equivalent).

   o  Diff headers MUST use the section file's relative path
      within the DocPack (e.g., `sections/TS-0007_security_model.md`).

   o  Hunks are numbered sequentially starting at 1, in the order
      they appear in the diff output. This numbering is implicit
      (determined by position) and is used by fix_hunks references.

   o  The patch MUST apply cleanly against the section content at
      the base_digest declared in the section header. A patch that
      references stale content is invalid (FRP-INV-008).

Validation rules for the extraction pipeline:

   o  Output that omits either the FINDINGS or PATCH section MUST
      be rejected.

   o  Output where any finding has zero fix_hunks MUST be rejected
      (FRP-INV-007: findings without diffs are invalid).

   o  Output where any hunk is unreferenced by any finding MUST be
      rejected (orphan hunks indicate untraced changes).

   o  Output where severity is not one of the four enumerated values
      MUST be rejected.

   o  Output where section does not match a section_id in the
      DocManifest MUST be rejected.

   o  Findings with description exceeding 500 tokens MUST be
      truncated with a parser warning, not rejected.

### 6.3.  Verifier Diversity

To reduce correlated failure modes (e.g., shared model blind spots),
FRP MUST enforce verifier diversity:

   o  At least K=2 independent reviewer families MUST produce PASS
      receipts for each required gate category.

   o  "Independent reviewer family" means distinct frontier-tier
      models from different providers (e.g., different model families
      with independent training runs). Prompt variation, temperature
      variation, or tool-configuration variation of the same model
      does NOT constitute a distinct family — these share the same
      blind spots.

   o  Model selection for each reviewer slot MUST include a random
      component drawn from a curated frontier-model roster. The
      roster is maintained as a policy artifact and MUST contain
      only models assessed as frontier-capable for the critique
      task. This prevents ossification around a single model and
      ensures genuine diversity.

   o  The diversity constraint is parameterized in the admission
      policy and MAY be increased for higher risk tiers.


## 7.  Gate Specification

Gates are mechanical checks that evaluate DocPack quality. Gates
are organized into three tiers by automation level.

### 7.1.  Tier 0: Structural Gates

Tier 0 gates are fully deterministic and require no model
involvement.

   GATE-T0-SECTIONS:  All sections declared in the manifest exist
      as files with non-empty content (excluding header).

   GATE-T0-HEADERS:  Every section file begins with a valid
      frp.section.v1 header block. Header section_id and doc_id
      match the parent manifest.

   GATE-T0-PLACEHOLDERS:  No section contains forbidden placeholder
      strings. The forbidden set is: "TBD", "TODO", "FIXME",
      "PLACEHOLDER", "LOREM", "[INSERT", "XXX". Matching is
      case-insensitive.

   GATE-T0-CROSSREFS:  All section_id references within document
      content resolve to sections declared in the manifest.

### 7.2.  Tier 1: Mechanical-Semantic Gates

Tier 1 gates are deterministic but require parsing structured
content within sections.

   GATE-T1-SCHEMA-VALID:  All embedded schema blocks (JSON Schema,
      Protobuf, TypeScript interface definitions) parse and
      validate.

   GATE-T1-TRACEABILITY:  Every ImplPlan milestone references at
      least one TechSpec section_id. Every TechSpec gate or
      invariant declaration has a corresponding verification point
      in the ImplPlan.

   GATE-T1-INTENT-COVERAGE:  Every goal in the Intent Brief is
      referenced by at least one TechSpec section and at least one
      ImplPlan milestone.

   GATE-T1-CONSTRAINT-COVERAGE:  Every constraint in the Intent
      Brief is addressed in the TechSpec security model or
      correctness model section.

### 7.3.  Tier 2: Receipted Audit Gates

Tier 2 gates are LLM-assisted but MUST produce structured,
receipted output. Tier 2 gate results are evidence categories
whose absence yields PENDING (not PASS).

   GATE-T2-CONSISTENCY:  An auditor identifies contradictions
      across sections within a document and across documents.
      Output: structured findings with section references.

   GATE-T2-THREAT-MODEL:  An auditor enumerates attack surfaces
      and evaluates whether mitigations are specified for each.
      Output: threat/mitigation coverage matrix.

   GATE-T2-INVARIANT-VERIFICATION:  An auditor lists all stated
      invariants and evaluates whether each has a verification
      procedure in the ImplPlan. Output: invariant coverage matrix.

For all Tier 2 gates:

   o  The auditor MUST produce a ReviewArtifactBundleV1 stored in
      CAS.

   o  The gate receipt MUST reference the review artifact hash.

   o  Tier 2 gate FAIL does not automatically block admission for
      LOW risk-tier projects, but MUST be recorded and visible.

   o  Tier 2 gate FAIL MUST block admission for HIGH and CRITICAL
      risk-tier projects.


## 8.  Budgeting and Stop Conditions

Unbounded refinement is a failure mode. FRP MUST enforce budgets
and stop conditions for every agent invocation and for the pipeline
as a whole.

### 8.1.  Budget Dimensions

The following budgets MUST be enforced:

   Per-agent budgets:

      token_budget:  Maximum input + output tokens per invocation.

      wall_time_budget:  Maximum wall-clock duration per invocation.

      tool_call_budget:  Maximum tool invocations per agent session.

   Per-cycle budgets:

      max_iterations:  Maximum CRITIQUE-APPLY-VERIFY loops.

      max_concurrent_reviewers:  Maximum simultaneous critic agents.

      total_token_budget:  Maximum tokens across all agent
         invocations in the cycle.

      total_wall_time_budget:  Maximum wall-clock duration for the
         entire cycle.

### 8.2.  Stop Conditions

The pipeline MUST halt when any of the following is true:

   a) max_iterations reached.

   b) Any per-cycle budget exhausted.

   c) Plateau detected for N consecutive iterations (Section 8.3).

   d) Safety gate FAIL persists after M retries (terminal halt).

   e) Agent invocation exceeds its per-agent budget (that agent's
      output is discarded; cycle may continue with remaining budget).

### 8.3.  Plateau Detection

A patch set is considered "improving" if and only if at least one
of the following holds:

   a) The count of FAILing gates decreases.

   b) At least one BLOCKER or HIGH finding is resolved (finding
      present in previous iteration, absent in current).

   c) Structural completeness increases (sections_present increases
      or placeholder_count decreases) without introducing new gate
      FAILs.

If none of these conditions holds for N consecutive iterations
(configurable; default N=3), the pipeline MUST halt with a
PipelineStalled event. Discarding non-improving amendments
prevents budget waste on noise.


## 9.  Security Model

FRP produces high-leverage artifacts that downstream agents treat
as authoritative guidance. The pipeline itself is an attack surface
and MUST be treated accordingly.

### 9.1.  Capability Scoping

All FRP agents MUST run with capability-scoped tool access
(default-deny, per FRP-INV-002).

   Drafter and Critic agents:
      o  Read: intent brief, manifest, doctrine refs, working
         DocPack, designated context artifacts.
      o  Write: sandbox output directory only.
      o  No network access.
      o  No arbitrary command execution.

   Patch Applier:
      o  Read: amendment bundle, working DocPack.
      o  Write: working DocPack directory (patch application).
      o  Tool: deterministic patch engine only.

   Gate Runner:
      o  Read: DocPack, gate definitions.
      o  Execute: deterministic lint/parse tools from allowlist.
      o  Write: gate receipt output only.

   No agent role in FRP is granted network access, shell access
   beyond the tool allowlist, or write access outside its designated
   output scope.

### 9.2.  Prompt Injection Hardening

   o  Downstream agents that consume admitted DocPacks MUST treat
      document content as data, not as instructions.

   o  ContextPacks MUST label DocPack content as untrusted payload.

   o  System prompts MUST override any in-document "instructions"
      regardless of formatting or framing.

### 9.3.  Dominance Ordering Enforcement

If a security constraint is unclear, unsatisfied, or in conflict
with a liveness concern, FRP MUST:

   1. Deny the current operation.
   2. Record a SecurityEscalation event.
   3. Decompose into a subtask that addresses the security concern.
   4. Resume only after the security subtask produces a PASS receipt.

FRP MUST NOT proceed with a known security gap to maintain pipeline
throughput.


## 10.  Document Content Requirements

FRP is useful only if the produced documents are actionable,
exhaustive, and audit-friendly. This section specifies the
mandatory content structure.

### 10.1.  TechSpec Required Sections

A TechSpec DocPack MUST contain the following sections:

   TS-0001  Problem and Goals.
      Trace to Intent Brief goals. State the problem precisely.
      Include testable success criteria.

   TS-0002  Non-Goals and Exclusions.
      Explicit enumeration of what is out of scope. Each non-goal
      MUST state why it is excluded.

   TS-0003  System Context.
      Boundaries, external dependencies, integration points.
      Include a boundary diagram or equivalent structured
      description.

   TS-0004  Architecture Overview.
      Components, their contracts, data flows, and composition
      rules. Include component interaction diagrams or equivalent.

   TS-0005  Data Model.
      Schemas, invariants, versioning strategy, migration rules.
      All schemas MUST be machine-parseable.

   TS-0006  Interfaces.
      Typed contracts for all APIs, protocols, and inter-component
      boundaries. Error semantics MUST be specified for every
      interface.

   TS-0007  Security Model.
      Threat enumeration, mitigations, least-privilege analysis,
      trust boundaries. MUST reference specific threats and their
      countermeasures.

   TS-0008  Correctness Model.
      Invariants, failure modes, recovery procedures, consistency
      guarantees. Each invariant MUST have a falsification
      condition.

   TS-0009  Operational Model.
      Observability (metrics, logs, traces), alerting thresholds,
      capacity planning assumptions.

   TS-0010  Governance and Gating.
      What becomes authoritative and through what closure procedure.
      Gate definitions for the system being specified.

   TS-0011  Migration and Rollout.
      Phases, reversibility criteria, rollback procedures, feature
      flag strategy.

   TS-0012  Open Questions.
      Explicit, enumerated. Each question MUST state the decision
      deadline and the default resolution if no decision is made.

   TS-0013  Appendices.
      Glossary, references, test vectors, supplementary diagrams.

### 10.2.  ImplPlan Required Sections

An ImplPlan DocPack MUST contain the following sections:

   IP-0001  Milestones.
      Ordered sequence with exit criteria per milestone. Each
      milestone MUST reference one or more TechSpec section_ids.

   IP-0002  Work Breakdown.
      Ticket or epic decomposition. Each unit MUST be independently
      verifiable.

   IP-0003  Dependency Graph.
      Explicit ordering constraints between work units. Critical
      path identification.

   IP-0004  Risk Register.
      Risks including security and correctness risks. Each risk
      MUST state likelihood, impact, and mitigation.

   IP-0005  Verification Plan.
      Tests, gates, audits mapped to TechSpec invariants and
      acceptance criteria. Every TechSpec invariant MUST have a
      verification point.

   IP-0006  Resource Budgets.
      Time, compute, and review bandwidth estimates per milestone.

   IP-0007  Backout Procedures.
      Rollback procedures per milestone. Criteria for triggering
      rollback.

   IP-0008  Acceptance Mapping.
      Mapping from Intent Brief acceptance_criteria to specific
      deliverables and verification points. Every acceptance
      criterion MUST trace to at least one milestone and one
      verification point.

### 10.3.  Traceability Requirements

   o  Every ImplPlan milestone MUST reference at least one TechSpec
      section_id (GATE-T1-TRACEABILITY).

   o  Every TechSpec invariant or gate declaration MUST have a
      corresponding verification point in the ImplPlan
      (GATE-T1-TRACEABILITY).

   o  Every Intent Brief goal MUST be referenced by at least one
      TechSpec section and one ImplPlan milestone
      (GATE-T1-INTENT-COVERAGE).

   o  Every Intent Brief constraint MUST be addressed in the
      TechSpec security or correctness model
      (GATE-T1-CONSTRAINT-COVERAGE).

Failure of any traceability requirement is a Tier 1 gate FAIL.


## 11.  Observability and Replay

### 11.1.  Artifact Publication

For every FRP execution, the following artifacts MUST be published
to CAS and referenced from ledger events:

   o  Intent Brief
   o  DocManifests (one per document)
   o  Every drafted section snapshot (per iteration)
   o  Every amendment bundle
   o  Every patch application result (Delta Report)
   o  Every gate receipt
   o  Admitted DocPack snapshots (on admission)
   o  Plan-of-record pin (on pinning)
   o  Handoff manifest (on handoff)
   o  Failure report (on pipeline failure)

### 11.2.  Replay Contract

A third party with access to:

   o  the ledger event stream for the refinement WorkItem, and
   o  the CAS blobs referenced by those ledger events

MUST be able to reconstruct:

   o  the exact drafts produced at each iteration,
   o  the exact diffs proposed by each critic,
   o  the exact gate results at each iteration,
   o  the final admitted state (or the failure state and reason).

This is the "substrate as world" requirement: the ledger + CAS
constitute a complete, deterministically replayable record of the
refinement process.

### 11.3.  Per-Iteration Metrics

Each Delta Report MUST include the following metrics:

   o  Completeness score: sections_present / sections_required.
   o  Placeholder count.
   o  Gate pass/fail counts by tier.
   o  Finding counts by severity.
   o  Patch size: lines added, lines removed.
   o  Reviewer diversity: number of distinct families that produced
      receipts.
   o  Cost: token consumption, wall-clock time.


## 12.  CLI Interface

FRP MUST be operable as CLI commands that produce an auditable
workspace directory plus ledger evidence.

### 12.1.  Init

```
apm2 forge refine init --project <id> --intent <path_to_intent.cac.json>
```

   o  Validates Intent Brief against schema.
   o  Generates DocManifests and section skeletons.
   o  Publishes intent + manifests as evidence.
   o  Creates DocPack directory structure.

### 12.2.  Run

```
apm2 forge refine run --project <id> \
    --max-iters <N> \
    --policy <policy_ref> \
    [--token-budget <T>] \
    [--wall-time-budget <seconds>]
```

   o  Executes DRAFT -> CRITIQUE -> APPLY -> VERIFY loop.
   o  Publishes all artifacts per iteration.
   o  Halts fail-closed on budget exhaustion, plateau, or
      persistent safety FAIL.
   o  Exits with non-zero status on any terminal failure.

### 12.3.  Admit and Pin

```
apm2 forge refine admit --project <id>
```

   o  Evaluates admission closure (quorum + gates).
   o  On PASS: emits plan-of-record pin evidence, generates
      handoff manifest.
   o  On FAIL: emits failure report evidence with specific
      gate/quorum deficiencies.

### 12.4.  Replay

```
apm2 forge refine replay --project <id> \
    --ledger <ledger.jsonl> \
    --cas <cas_path>
```

   o  Reconstructs the full refinement history from ledger + CAS.
   o  Verifies all artifact digests.
   o  Verifies all gate receipts.
   o  Reports any discrepancies.


## 13.  YAML Template Migration

FRP replaces template-driven document generation. Migration is
incremental.

### 13.1.  Migration Steps

   1. Existing RFC/PRD skeleton generation tools output DocPack
      skeletons (sectioned Markdown with manifest), not YAML
      forms.

   2. A parser/linter for DocPack manifests and section headers
      is implemented as a Tier 0 gate.

   3. Amendment diffs become the primary work product of critics.
      Critics no longer "fill in" template fields.

   4. YAML projections MAY be generated from admitted DocPacks
      for legacy tooling compatibility. YAML projections are
      derived artifacts, not authoritative.

### 13.2.  Why This Addresses Rubber-Stamping

   o  Agents are not rewarded for completing fields. They are
      evaluated on the quality of content and the specificity of
      amendments.

   o  Gates enforce completeness mechanically. Structural gates
      catch missing sections and placeholders; Tier 2 audits
      evaluate substantive coverage.

   o  Critics are structurally incentivized to find defects
      (adversarial framing + quorum requirement + diversity
      constraint).

   o  Every transition is auditable. "Rubber stamping" produces
      a visible, replayable evidence trail of low-quality
      amendments and perfunctory gate passes.


## 14.  Acceptance Criteria

FRP v1 is acceptable when all of the following hold:

   AC-01:  Given an IntentBriefV1, the pipeline produces both an
      admitted TechSpec DocPack and an admitted ImplPlan DocPack.

   AC-02:  Both admitted DocPacks have deterministic content-
      addressed digests, published gate receipts for all required
      gates, and reviewer quorum receipts satisfying diversity
      constraints.

   AC-03:  A replay runner reconstructs the admitted outputs from
      ledger + CAS alone, with no external state.

   AC-04:  The pipeline halts fail-closed on: missing/stale
      evidence, patch application conflicts, gate FAILs that
      exceed retry limits, and budget exhaustion.

   AC-05:  The pipeline is fully autonomous. No human intervention
      is required between providing the Intent Brief and consuming
      the admitted outputs. The pipeline halts on unresolvable
      failures rather than escalating to a human.

   AC-06:  Traceability gates (GATE-T1-TRACEABILITY,
      GATE-T1-INTENT-COVERAGE, GATE-T1-CONSTRAINT-COVERAGE) pass
      for both admitted documents.

   AC-07:  No agent in the pipeline has capabilities beyond its
      designated role allowlist.

   AC-08:  The pipeline demonstrates measurable improvement across
      iterations (at least one CRITIQUE-APPLY-VERIFY cycle reduces
      gate failures or resolves BLOCKER/HIGH findings).


## 15.  References

   RFC-0011   Context-as-Code (CAC) Pipeline.
   RFC-0015   Forge Admission Cycle Gate Hardening Basis.
   RFC-0016   Holonic Time Fabric (HTF).
   RFC-0018   Holonic Event Fabric (HEF) Pulse Plane.
   RFC-0019   Automated FAC v0.
   RFC-0020   Holonic Substrate Interface (HSI).
   RFC 2119    Key words for use in RFCs to Indicate Requirement
               Levels.

   documents/theory/unified-theory-v2.json
   documents/theory/unified-theory-v2.json
   documents/theory/unified-theory-v2.json
   documents/theory/unified-theory-v2.json
