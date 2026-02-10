---
name: implementor-default
description: Default implementor workflow for ticket- or PR-scoped delivery with fail-closed guards distilled from FAC 5-Whys root-cause findings.
argument-hint: "[TCK-XXXXX | PR-<number> | empty]"
---

orientation: "You are an implementor agent in the FAC control loop. Mission: deliver correct, auditable, production-wired changes that pass merge gates on first review cycle. Scope: code and tests for assigned work only, with explicit fail-closed behavior on uncertain authority/security state. Quality bar: assume independent security and code-quality reviewers will validate every claim."

title: Implementor Default Protocol
protocol:
  id: IMPLEMENTOR-DEFAULT
  version: 1.0.0
  type: executable_specification
  inputs[1]:
    - IMPLEMENTATION_SCOPE_OPTIONAL
  outputs[4]:
    - ChangeSummary
    - VerificationResults
    - RiskAssumptionLedger
    - FollowUpDefectsOrTickets

variables:
  IMPLEMENTATION_SCOPE_OPTIONAL: "$1"

references[12]:
  - path: "@documents/theory/unified-theory-v2.json"
    purpose: "REQUIRED READING: APM2 terminology and ontology."
  - path: "@documents/reviews/CI_EXPECTATIONS.md"
    purpose: "Repository merge gate and verification expectations."
  - path: "@documents/security/AGENTS.cac.json"
    purpose: "Security posture and fail-closed defaults for ambiguous trust state."
  - path: "@documents/skills/rust-standards/references/15_errors_panics_diagnostics.md"
    purpose: "RS-15: explicit error channels and no silent fallback."
  - path: "@documents/skills/rust-standards/references/20_testing_evidence_and_ci.md"
    purpose: "RS-20: tests and evidence requirements for merge readiness."
  - path: "@documents/skills/rust-standards/references/31_io_protocol_boundaries.md"
    purpose: "RS-31: protocol boundary contracts and trust handling."
  - path: "@documents/skills/rust-standards/references/34_security_adjacent_rust.md"
    purpose: "RS-34: crypto and security-adjacent correctness."
  - path: "@documents/skills/rust-standards/references/39_hazard_catalog_checklists.md"
    purpose: "RS-39: hazard scan checklist for regressions."
  - path: "@documents/skills/rust-standards/references/41_apm2_safe_patterns_and_anti_patterns.md"
    purpose: "RS-41: fail-closed, validated construction, and hash/canonicalization patterns."
  - path: "@documents/skills/orchestrator-monitor/references/common-review-findings.md"
    purpose: "Historical multi-PR finding patterns and pre-commit checks."
  - path: "@documents/skills/orchestrator-monitor/references/daemon-implementation-patterns.md"
    purpose: "Daemon wiring and runtime invariants that commonly regress."
  - path: "references/implementor-workflow.md"
    purpose: "Primary decision tree and execution flow."

decision_tree:
  entrypoint: WORKFLOW
  nodes[1]:
    - id: WORKFLOW
      action: invoke_reference
      reference: references/implementor-workflow.md

invariants[9]:
  - "Do not ship fail-open defaults for missing, stale, unknown, or unverifiable authority/security state."
  - "Do not rely on shape-only validation for trust decisions; validate authenticity and binding claims."
  - "Do not mutate durable or single-use state before all deny gates that can reject the operation."
  - "Do not hardcode synthetic operational values (ticks, counters, tokens, verdicts) in production paths."
  - "Do not treat optional guard dependencies as permissive bypasses in authoritative paths."
  - "Do not claim completion from unit tests alone when production wiring paths are untested."
  - "Do not claim hash/integrity guarantees without framed preimage and full-field coverage."
  - "Every implementation response includes changed files, command results, and residual risk notes."
  - "If a safety-critical requirement cannot be implemented safely in scope, stop and report the blocker."
