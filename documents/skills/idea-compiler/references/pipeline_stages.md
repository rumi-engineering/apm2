# Idea Compiler Pipeline Stages

**Run outputs:** Compiler stages write to a per-run root under `evidence/` first (for reproducibility and replay). Governed `documents/` updates happen only via an explicit promote step.

## Stage: CCP_Build

**Goal:** Generate a Codebase Context Pack (CCP) for the current repository checkout.

**Inputs:**
- Repository working tree
- `AGENTS.md` files colocated with crates/modules
- `cargo metadata` output

**Outputs (examples):**
- `evidence/prd/<PRD-ID>/ccp/ccp_index.json`
- `evidence/prd/<PRD-ID>/ccp/component_atlas.yaml`
- `evidence/prd/<PRD-ID>/ccp/crate_graph.json`
- `evidence/prd/<PRD-ID>/ccp/public_api_inventory.yaml`
- `evidence/prd/<PRD-ID>/ccp/hotspots.yaml`
- `evidence/prd/<PRD-ID>/ccp/prior_decisions_index.yaml`

**Completion predicate:**
- CCP index exists; all referenced sub-artifacts exist and match hashes; stable IDs validate.

## Stage: Impact_Map

**Goal:** Map each PRD requirement to existing components and extension points.

**Inputs:**
- `documents/prds/<PRD-ID>/`
- CCP index + artifacts

**Outputs (examples):**
- `evidence/prd/<PRD-ID>/impact_map/impact_map.yaml`

**Completion predicate:**
- 100% requirements mapped or classified as net-new with adjudication required.

## Stage: RFC_Frame

**Goal:** Emit an RFC draft grounded in CCP + Impact Map.

**Inputs:**
- CCP
- Impact Map
- RFC template

**Outputs:**
- `evidence/prd/<PRD-ID>/runs/<RUN_ID>/rfcs/RFC-XXXX/` (template-conformant draft)

**Completion predicate:**
- RFC references valid paths; new abstractions justified; lint passes at configured maturity level.

## Stage: Ticket_Emit

**Goal:** Emit atomic tickets from RFC decomposition.

**Inputs:**
- RFC files
- CCP for file references and extension point validation

**Outputs:**
- `evidence/prd/<PRD-ID>/runs/<RUN_ID>/tickets/TCK-*.yaml`

**Completion predicate:**
- Ticket lint passes: file paths exist; verification commands present; dependencies consistent.

## Stage: Skill_Sync

**Goal:** Ensure skills instruct agents to use the compiler pipeline and consume CCP guidance.

**Inputs:**
- Skill library under `documents/skills/`
- PipelineSpec

**Outputs:**
- Proposed skill updates under `evidence/prd/<PRD-ID>/runs/<RUN_ID>/skills/` and/or a promotion bundle.

**Completion predicate:**
- `apm2 factory skill verify` passes; no divergent instructions.

## Stage: Refactor_Radar (optional)

**Goal:** Produce bounded refactor recommendations and/or maintenance tickets.

**Inputs:**
- CCP (hotspots, cycles, duplication signals)
- Recurrence signatures (if available)

**Outputs:**
- `evidence/prd/<PRD-ID>/refactor_radar/radar.yaml` and optional tickets

**Completion predicate:**
- Output bounded; signatures stable; proposed outcomes measurable.
