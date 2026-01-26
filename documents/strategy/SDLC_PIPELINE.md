# Agent-Native SDLC Pipeline

This document defines the normative SDLC pipeline for the APM2 project, spanning from initial idea to merged code. Every phase is governed by specialized agent skills that enforce rigor, security, and architectural integrity (anti-cousin discipline).

---

## Pipeline Overview

| Phase | Input | Output | Primary Skill |
|-------|-------|--------|---------------|
| **1. Idea** | Rough Intent | Draft PRD / RFC | `idea-compiler` |
| **2. PRD** | Draft PRD | Approved PRD | `prd-review` |
| **3. RFC & Tickets** | Approved PRD | Agent-Ready Tickets | `rfc-council` |
| **4. Implementation** | Engineering Ticket | Pull Request | `dev-eng-ticket` |
| **5. Verification** | Pull Request | AAT Evidence Bundle | `aat` |
| **6. Merge** | AAT + Code Review | Merged Code | GitHub CI |

---

## 1. Idea Compilation (`idea-compiler`)

The entry point for any change. This phase grounds a high-level intent into the existing codebase context to prevent "Cousin Abstractions" (duplicate work).

*   **Process:** Builds a **Codebase Context Pack (CCP)** and **Impact Map**.
*   **Key Output:** A structured PRD or RFC that references existing components and extension points.
*   **Command:** `/idea-compiler --prd PRD-XXXX`

## 2. PRD Governance (`prd-review`)

Ensures that requirements are falsifiable, testable, and aligned with the North Star vision.

*   **Protocol:** Executes 7 formal gates, including semantic multi-angle analysis (Technical Feasibility, Customer Value, Implementation Risk, etc.).
*   **Depth:** Scales from `LIGHT` to `COUNCIL` (3-agent deliberation) based on the change's blast radius.
*   **Command:** `/prd-review [refine|review] PRD-XXXX`

## 3. RFC & Ticket Orchestration (`rfc-council`)

The technical blueprinting phase. Decomposes the PRD into "Agent-Native" engineering tickets.

*   **Constraint:** Enforces **Atomicity** (each ticket must be completable in a single PR) and **Implementability** (no ambiguity for implementation agents).
*   **Anti-Cousin Gate:** Every file path in a ticket MUST be mapped to the CCP atlas or explicitly justified as a net-new substrate.
*   **Command:** `/rfc-council [create|refine|review] RFC-XXXX`

## 4. Implementation (`dev-eng-ticket`)

The autonomous engineering phase where the heavy lifting happens.

*   **Doctrine:** Implementers must adhere to the **APM2 Rust Textbook** (safety, error handling, API design) and module-specific `AGENTS.md` invariants.
*   **Output:** Functional code, unit tests, and an **Evidence Script** documenting successful implementation.
*   **Command:** `/dev-eng-ticket TCK-XXXXX`

## 5. Verification (`aat`)

Agent Acceptance Testing (AAT) uses hypothesis-driven testing to verify the PR before it can be merged.

*   **Protocol:** The AAT agent forms 3+ falsifiable hypotheses *before* execution.
*   **Anti-Gaming:** Actively checks for hardcoded values, mock-gaming, or undocumented TODOs.
*   **Verdict:** Produces a machine-readable JSON Evidence Bundle that satisfies the `aat/acceptance` GitHub status check.

## 6. Merge & Promotion

Final reconciliation and deployment.

*   **Reconciliation:** Post-merge, the `GATE-PRD-RECONCILIATION` protocol detects any variance between the implementation and the original specification.
*   **Evidence Ledger:** All artifacts (PRDs, RFCs, AAT Bundles, CCPs) are committed to the `evidence/` directory as a permanent record of the project's integrity.

---

## Core Principles

1.  **Repository Truth:** The Codebase Context Pack (CCP) is the source of truth for all designs. No guessing allowed.
2.  **Waste is Sin:** "Cousin Abstractions" (duplication) are blockers. Reuse-by-default is the law.
3.  **Falsifiability:** If a requirement cannot be tested by a single shell command, it is a defect.
4.  **Agent-Native:** Software is designed to be understood and edited by both humans and agents with equal efficiency.
