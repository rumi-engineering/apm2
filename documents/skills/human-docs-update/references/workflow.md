title: Human Docs Update Workflow

decision_tree:
  entrypoint: VALIDATE_AND_NORMALIZE
  nodes[5]:
    - id: VALIDATE_AND_NORMALIZE
      purpose: "Validate we're in a git repo and normalize the starting state."
      steps[3]:
        - id: CHECK_GIT_REPO
          action: |
            Verify we're in a git repository:
            ```bash
            git rev-parse --is-inside-work-tree
            ```
            If not a git repo, HALT with error.

        - id: INVOKE_GIT_NORMALIZE
          action: invoke_reference
          reference: references/git-normalize.md

        - id: CHECK_CHANGES_EXIST
          action: |
            Verify there are changes to process:
            ```bash
            git status --porcelain
            ```
            If no output (no changes), HALT with message "No changes to commit."
      decisions[1]:
        - id: PROCEED_TO_CHECKS
          if: "changes exist and on feature branch"
          then:
            next_node: RUN_LOCAL_CHECKS

    - id: RUN_LOCAL_CHECKS
      purpose: "Run formatting and linting checks before committing."
      steps[2]:
        - id: RUN_PRECOMMIT
          action: |
            Run pre-commit hooks on all files:
            ```bash
            pre-commit run --all-files
            ```
            If pre-commit not installed, skip this step.
            Note: pre-commit may auto-fix some issues (trailing whitespace, etc.)

        - id: CHECK_YAML_VALID
          action: |
            Validate any changed YAML files using `check-yaml` if available.
      decisions[1]:
        - id: PROCEED_TO_COMMIT
          if: "checks pass"
          then:
            next_node: STAGE_AND_COMMIT

    - id: STAGE_AND_COMMIT
      purpose: "Stage changes and create a conventional commit."
      steps[3]:
        - id: STAGE_CHANGES
          action: |
            Stage all modified and new files:
            ```bash
            git add <changed-files>
            ```

        - id: COMPOSE_COMMIT_MESSAGE
          action: "Analyze changes to create a conventional commit message (docs: ...)."

        - id: CREATE_COMMIT
          action: |
            Create the commit with co-author:
            ```bash
            git commit -m "<message>"
            ```
      decisions[1]:
        - id: PROCEED_TO_SYNC
          if: "commit created successfully"
          then:
            next_node: SYNC_AND_PUSH

    - id: SYNC_AND_PUSH
      purpose: "Sync with main and push branch."
      steps[2]:
        - id: REBASE_ON_MAIN
          action: |
            Fetch and rebase:
            ```bash
            git fetch origin main && git rebase origin/main
            ```

        - id: PUSH_BRANCH
          action: |
            Push branch with tracking:
            ```bash
            git push -u origin <branch-name>
            ```
      decisions[1]:
        - id: PROCEED_TO_PR
          if: "push successful"
          then:
            next_node: CREATE_PR_AND_REVIEW

    - id: CREATE_PR_AND_REVIEW
      purpose: "Create PR, request reviews, and enable auto-merge using gh CLI."
      steps[4]:
        - id: CREATE_PR
          action: |
            Create pull request:
            ```bash
            gh pr create --title "<title>" --body "<summary>"
            ```

        - id: REQUEST_REVIEWS
          action: |
            Request AI reviews using xtask:
            ```bash
            cargo xtask review quality <PR_URL>
            cargo xtask review security <PR_URL>
            ```
            These commands initiate the specialized AI review workflows for the given PR.

        - id: ENABLE_AUTO_MERGE
          action: |
            Enable squash auto-merge:
            ```bash
            gh pr merge --auto --squash
            ```

        - id: CAPTURE_PR_URL
          action: |
            Get PR URL for output:
            ```bash
            gh pr view --json url -q .url
            ```
      decisions[1]:
        - id: WORKFLOW_COMPLETE
          if: "PR created"
          then:
            verdict: SUCCESS
            output: PR_URL