1. Template adoption
   - Copy this template suite into the repository (e.g., `specs/templates_v2/`).
   - Linter MUST distinguish:
     - Template files (path contains `/template/`): empty strings/arrays and unresolved refs allowed.
     - Instance files: fail-closed on empty required fields and unresolved refs.

2. Standards updates (required)
   - Enums:
     - Additions: responsibility domains include DOMAIN_PRODUCT; evidence categories include RECORDINGS, LINT_REPORTS, CHAOS_TEST_RESULTS.
     - New enums: document_status, ticket_status, contract_types, versioning_schemes, schema_formats, command_shells, quality_applicability, quality_disposition, protocol_profile_ids, network_access, waiver_status.
   - Schemas:
     - Evidence artifact schema v2 requires verification.commands[*].network_access.
     - Quality coverage schema v2 externalizes applicability/disposition enums.
     - New schemas: ticket_meta, waiver, gate_review, prd_meta, rfc_meta.

3. PRD migration (v1 -> v2)
   1) Create `documents/prds/<PRD-ID>/` and copy the PRD template directory contents.
   2) Move requirements to one-file-per-requirement:
      - For each v1 requirement object previously under `prd_traceability.requirement_registry.requirements`:
        - Create `documents/prds/<PRD-ID>/requirements/<REQ-####>.yaml` with root key `prd_requirement`.
        - Preserve the existing requirement_id.
      - Update `documents/prds/<PRD-ID>/07_traceability.yaml`:
        - Set `mode: FILE_PER_REQUIREMENT`.
        - Replace inline requirements with `local_requirements[*].requirement_ref`.
   3) Move evidence artifact definitions to one-file-per-artifact:
      - For each v1 artifact object previously under `prd_evidence_bundle.bundle.artifacts`:
        - Create `documents/prds/<PRD-ID>/evidence_artifacts/<EVID-####>.yaml` with root key `prd_evidence_artifact`.
        - Add `verification.commands[*].network_access` (DISALLOWED unless explicitly needed).
      - Update `documents/prds/<PRD-ID>/12_evidence_bundle.yaml`:
        - Set `artifact_registry.mode: FILE_PER_ARTIFACT`.
        - Replace inline artifacts with `local_artifacts[*].artifact_ref`.
   4) Quality framework completeness:
      - Update `10_quality_framework.yaml` to include all quality dimensions exactly once.
   5) Gates/waivers:
      - Ensure gate ids align with `GATE-*` canonical format and governance definitions.
      - Waivers must be explicit records with required authority signoffs and non-expired expiration_date.
   6) Protocol profiles:
      - If `prd_meta.protocol_profile.applies=true`, populate:
        - `prd_traceability.requirement_registry.imports` for profile requirements.
        - `prd_evidence_bundle.bundle.artifact_registry.imports` for profile evidence.
      - Lint MUST fail if a profile is declared but not imported.

4. RFC migration (v1 -> v2)
   1) Create `documents/rfcs/<RFC-ID>/` and copy the RFC template directory contents.
   2) Bind to PRD:
      - Set `rfc_meta.binds_to_prd.prd_id` and `prd_base_path`.
      - Keep imported PRD refs in `01_problem_and_imports.yaml` relative to `prd_base_path`.
   3) RFC-only requirements/evidence:
      - Place RFC-only requirements in `documents/rfcs/<RFC-ID>/requirements/`.
      - Place RFC evidence artifact definitions in `documents/rfcs/<RFC-ID>/evidence_artifacts/`.
   4) Governance:
      - Populate `09_governance_and_gates.yaml` with gate reviews and waivers for RFC-level approvals.
   5) Evidence:
      - `07_test_and_evidence.yaml` is the RFC evidence bundle index; tickets should reference evidence ids that resolve across PRD + RFC + imported profile evidence.

5. Ticket migration (v1 -> v2)
   - Ticket storage root is `work/tickets/` (repo-root relative by default).
   - For each ticket:
     - Create `work/tickets/<TCK-#####>.md`.
     - Create `work/tickets/<TCK-#####>.yaml` using the new `ticket_meta` structure:
       - Replace `binds.requirement_ids` with `binds.requirements[*].{requirement_id, requirement_ref}`.
       - Replace `binds.evidence_ids` with `binds.evidence_artifacts[*].{evidence_id, artifact_ref}`.
     - Ensure `definition_of_done.evidence_ids` is non-empty and resolvable.
   - Update `rfc_ticket_decomposition.ticket_plan.ticket_storage_root` and `ticket_files` refs accordingly.

6. Enforcement ordering (fail-closed)
   - PRD instances MUST lint clean before any RFC is considered valid.
   - RFC instances MUST lint clean before ticket execution.
   - Tickets MUST lint clean (including resolvable requirement/evidence refs) before merge/release gates.
