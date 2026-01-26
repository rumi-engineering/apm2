# Agent Skills Index

This directory contains the executable specifications and protocols for the specialized agents operating within the APM2 ecosystem. These skills define how agents perform complex tasks like PRD review, technical design, and autonomous engineering.

## The SDLC Pipeline

The core engineering workflow is governed by a sequence of skills. For a detailed walkthrough of the idea-to-code flow, see:

👉 **[SDLC_PIPELINE.md](./SDLC_PIPELINE.md)**

## Skill Categories

### Governance & Review
*   [prd-review](./prd-review/SKILL.md) - Rigorous PRD validation and gating.
*   [rfc-council](./rfc-council/SKILL.md) - RFC orchestration and ticket quality enforcement.
*   [aat](./aat/SKILL.md) - Hypothesis-driven Agent Acceptance Testing.

### Design & Compilation
*   [idea-compiler](./idea-compiler/SKILL.md) - PRD to RFC compilation with anti-cousin grounding.
*   [holonic-agent-network](./holonic-agent-network/SKILL.md) - Principles of the agent hierarchy.

### Execution & Engineering
*   [dev-eng-ticket](./dev-eng-ticket/SKILL.md) - Autonomous engineering ticket implementation.
*   [coding](./coding/SKILL.md) - General coding assistance and idioms.
*   [review-rust](./review-rust/SKILL.md) - Specialized Rust code review protocols.

### Reasoning & Infrastructure
*   [modes-of-reasoning](./modes-of-reasoning/SKILL.md) - The 80 reasoning modes used by Council agents.
*   [agent-native-software](./agent-native-software/SKILL.md) - The foundational doctrine of agent-native design.
*   [rust-textbook](./rust-textbook/) - Normative Rust contracts and safety invariants.

## Usage

Skills are invoked by agents using the `/skill-name` syntax or via direct tool-loops. Each skill contains a `SKILL.md` file that defines its protocol, inputs, outputs, and decision trees.
