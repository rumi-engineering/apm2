---
name: human-docs-update
description: Orchestrate ad-hoc documentation updates through git normalization, local checks, PR creation, and review automation.
argument-hint: "[branch-name]"
user-invocable: true
holon:
  # ============================================================================
  # Contract Definition
  # ============================================================================
  contract:
    input_type: DocsUpdateRequest
    output_type: DocsUpdateResult
    state_type: DocsUpdateProgress

  # ============================================================================
  # Stop Conditions
  # ============================================================================
  stop_conditions:
    # Maximum episodes: Simple linear workflow
    max_episodes: 15

    # Timeout: 10 minutes for docs updates
    timeout_ms: 600000

    # Budget limits
    budget:
      tokens: 100000
      tool_calls: 100

    # Stall detection
    max_stall_episodes: 3

  # ============================================================================
  # Tool Permissions
  # ============================================================================
  tools:
    - Read         # Read files to understand changes
    - Glob         # Find modified files
    - Grep         # Search file contents
    - Bash         # Git operations, pre-commit, xtask commands
---

orientation: "You are a documentation update agent. Your job is to shepherd ad-hoc documentation changes through the complete git workflow: normalize state, run checks, commit, sync, create PR, and request reviews. You handle any starting git state gracefully."

title: Human Docs Update Workflow
protocol:
  id: HUMAN-DOCS-UPDATE
  version: 1.0.0
  type: executable_specification
  inputs[1]:
    - BRANCH_NAME_OPTIONAL
  outputs[2]:
    - PR_URL
    - Verdict

variables:
  BRANCH_NAME_OPTIONAL: "$1"

references[3]:
  - path: references/workflow.md
    purpose: "Primary decision tree for the complete update workflow."
  - path: references/git-normalize.md
    purpose: "Git state normalization procedures for any starting state."
  - path: references/commands.md
    purpose: "CLI command reference."

decision_tree:
  entrypoint: WORKFLOW
  nodes[1]:
    - id: WORKFLOW
      action: invoke_reference
      reference: references/workflow.md

## Overview

This skill handles the complete workflow for getting documentation updates reviewed and merged:

1. **Normalize Git State** - Handle any starting state (uncommitted changes, behind remote, etc.)
2. **Run Local Checks** - Execute pre-commit hooks and formatting.
3. **Stage & Commit** - Stage changes and create a conventional commit.
4. **Sync & Push** - Sync with origin/main, push the branch, and create a pull request.
5. **Review & Merge** - Request AI reviews and enable auto-merge.

## Prerequisites

1. **Git repository**: Must be in a git repository with remote `origin`
2. **Changes exist**: Must have uncommitted or staged changes to process
3. **Branch**: Optionally on a feature branch (will create one if on main)

## Holon Configuration

### Stop Conditions

| Condition | Value | Rationale |
|-----------|-------|-----------|
| max_episodes | 15 | Linear workflow |
| timeout_ms | 600,000 | 10 minutes |
| budget.tokens | 100,000 | Token limit |
| budget.tool_calls | 100 | Tool limit |
| max_stall_episodes | 3 | Stall detection |

### Tool Permissions

- `Read` - Read files to understand changes
- `Glob` - Find modified files
- `Grep` - Search contents
- `Bash` - Git operations, pre-commit, gh cli

## Success Criteria

- PR created with descriptive title and body
- All local checks pass (via `pre-commit`)
- Branch synced with origin/main (via `git rebase`)
- AI reviews requested and auto-merge enabled (via `cargo xtask review` and `gh pr`)
