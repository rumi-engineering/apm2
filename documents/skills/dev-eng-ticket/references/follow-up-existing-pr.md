title: Follow Up on Existing PR

decision_tree:
  entrypoint: FOLLOW_UP_EXISTING_PR
  nodes[1]:
    - id: FOLLOW_UP_EXISTING_PR
      purpose: "Continue work on an existing PR with emphasis on feedback, correctness, and clear evidence."
      steps[13]:
        - id: NOTE_VARIABLE_SUBSTITUTION
          action: "References do not interpolate variables; replace <TICKET_ID>, <RFC_ID>, and <PR_URL> with values extracted from start-ticket output."
        - id: READ_TICKET_CONTEXT
          action: "Read the ticket definition and any bound requirements. Capture scope, constraints, and definition of done."
          context_files[3]:
            - path: "documents/work/tickets/<TICKET_ID>.yaml"
              purpose: "Ticket metadata, scope, plan, criteria."
            - path: "documents/work/tickets/<TICKET_ID>.md"
              purpose: "Expanded notes, edge cases, and acceptance criteria (if present)."
            - path: "documents/rfcs/<RFC_ID>/06_ticket_decomposition.yaml"
              purpose: "Ticket scope and dependencies (if RFC exists)."
        - id: READ_LOCAL_INVARIANTS
          action: "Read AGENTS.md, mod.rs, and relevant tests for each touched module to understand local invariants."
        - id: READ_PR_METADATA
          action: command
          run: "gh pr view <PR_URL> --json number,title,body,author,baseRefName,headRefName,commits,files,additions,deletions"
          capture_as: pr_metadata_json
        - id: READ_PR_DIFF
          action: command
          run: "gh pr diff <PR_URL>"
          capture_as: diff_content
        - id: READ_REVIEW_FEEDBACK
          action: command
          run: "gh pr view <PR_URL> --comments"
          capture_as: pr_comments
        - id: SELECT_RELEVANT_RUST_FRAMEWORKS
          action: "Based on the diff, select the Rust domains that matter (ownership, lifetimes, async, unsafe, API design, errors, performance, security) and read the relevant rust-textbook sections."
        - id: IMPLEMENT_AND_TEST
          action: "Address review feedback and improve correctness, tests, and docs as needed. Apply the selected frameworks rather than a fixed checklist."
        - id: UPDATE_DOCS
          action: "Update documentation if public behavior, invariants, or operational procedures changed (README/CONTRIBUTING/docs)."
        - id: UPDATE_AGENTS_DOCS
          action: "Update all relevant AGENTS.md files to reflect the latest changes and invariants before committing."
        - id: VERIFY_AND_COMMIT
          action: command
          run: "cargo xtask commit \"<message>\""
        - id: PUSH_CHANGES
          action: command
          run: "cargo xtask push"
        - id: MONITOR_STATUS
          action: command
          run: "timeout 30s cargo xtask check"
      decisions[2]:
        - id: REVIEW_DENIED
          if: "status indicates review denied or changes requested"
          then:
            next_reference: references/review-denial-remediation.md
        - id: MERGED
          if: "status indicates merged"
          then:
            next_reference: references/post-merge-cleanup.md
