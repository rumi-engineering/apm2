title: Review Denial Remediation

decision_tree:
  entrypoint: REVIEW_DENIAL_REMEDIATION
  nodes[1]:
    - id: REVIEW_DENIAL_REMEDIATION
      purpose: "Address review feedback before re-requesting reviews."
      steps[9]:
        - id: NOTE_VARIABLE_SUBSTITUTION
          action: "References do not interpolate variables; replace <PR_URL>, <OWNER>, <REPO>, and <PR_NUMBER> before running commands."
        - id: FETCH_PR_COMMENTS
          action: command
          run: "gh pr view <PR_URL> --comments"
          capture_as: pr_comments
        - id: FETCH_REVIEW_THREADS
          action: command
          run: "gh api repos/<OWNER>/<REPO>/pulls/<PR_NUMBER>/comments"
          capture_as: pr_review_threads
        - id: TRIAGE_FINDINGS
          action: "List each required change and map it to code locations, tests, or documentation updates."
        - id: IMPLEMENT_FIXES
          action: "Apply fixes and improvements; update tests and docs as needed."
        - id: UPDATE_AGENTS_DOCS
          action: "Update all relevant AGENTS.md files to reflect the latest changes and invariants before committing."
        - id: VERIFY_AND_COMMIT
          action: command
          run: "cargo xtask commit \"<message>\""
        - id: RE_REQUEST_REVIEW
          action: command
          run: "cargo xtask push --force-review"
        - id: MONITOR_STATUS
          action: command
          run: "timeout 30s cargo xtask check"
      decisions[1]:
        - id: MERGED
          if: "status indicates merged"
          then:
            next_reference: references/post-merge-cleanup.md
