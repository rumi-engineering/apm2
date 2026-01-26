# PRD to RFC Workflow

This document defines the deterministic orchestration logic for the PRD-to-RFC pipeline.

## Decision Tree

decision_tree:
  entrypoint: VALIDATE_AND_INITIALIZE
  nodes[5]:
    # ========================================================================
    # Node 1: VALIDATE_AND_INITIALIZE
    # ========================================================================
    - id: VALIDATE_AND_INITIALIZE
      purpose: "Validate prerequisites and session configuration."
      steps[5]:
        - id: PARSE_AND_VALIDATE_ARGS
          action: "Verify PRD_ID format /^PRD-[0-9]{4}$/. Parse --max-iterations, --council, --dry-run."
        - id: PREREQUISITE_CHECK
          action: "Confirm PRD exists at documents/prds/{PRD_ID}/ and CCP exists at evidence/prd/{PRD_ID}/ccp/."
        - id: DETECT_EXISTING_RFC
          action: "Search documents/rfcs/ for any RFC bound to {PRD_ID}. If found, set RFC_ID and SKIP_CREATE=true."
        - id: INIT_SESSION_STATE
          action: "Initialize iteration counter (0), history bundle, and start timestamp."
        - id: AFFIRM_ORIENTATION
          action: "Affirm orientation: 'Automate high-quality RFC/ticket delivery with minimal human touch.'"
      decisions[2]:
        - id: GO_CREATE
          if: "SKIP_CREATE is false"
          then: "goto: CREATE_RFC"
        - id: GO_REVIEW
          if: "SKIP_CREATE is true"
          then: "goto: RESUME_ORCHESTRATION"

    # ========================================================================
    # Node 2: CREATE_RFC
    # ========================================================================
    - id: CREATE_RFC
      purpose: "Invoke rfc-council to generate initial RFC and tickets."
      steps[3]:
        - id: INVOKE_CREATE
          action: "Execute /rfc-council create {PRD_ID}. Stop if dry-run."
        - id: CAPTURE_RFC_ID
          action: "Extract RFC_ID from newly created documents/rfcs/ metadata."
        - id: VERIFY_ARTIFACTS
          action: "Confirm RFC files and TCK-*.yaml tickets are present."
      decisions[2]:
        - id: CREATE_SUCCESS
          if: "RFC_ID captured and artifacts present"
          then: "goto: REVIEW_LOOP"
        - id: CREATE_FAILURE
          if: "rfc-council failed or artifacts missing"
          then: "terminate: FAILED (CREATE_FAILED)"

    # ========================================================================
    # Node 3: RESUME_ORCHESTRATION
    # ========================================================================
    - id: RESUME_ORCHESTRATION
      purpose: "Initialize from an existing RFC state."
      steps[2]:
        - id: LOAD_RFC_CONTEXT
          action: "Load RFC_ID metadata and existing ticket list."
        - id: SYNC_ITERATION_HISTORY
          action: "Load any previous evidence/rfc/{RFC_ID}/reviews/ bundles to sync iteration count."
      decisions[1]:
        - id: RESUME_COMPLETE
          if: "always"
          then: "goto: REVIEW_LOOP"

    # ========================================================================
    # Node 4: REVIEW_LOOP
    # ========================================================================
    - id: REVIEW_LOOP
      purpose: "Iteratively refine RFC until approval or exhaustion."
      steps[5]:
        - id: PRE_LOOP_CHECK
          action: "If iteration_count >= max_iterations, terminate: REJECTED (MAX_ITERATIONS_EXCEEDED)."
        - id: INVOKE_REVIEW
          action: "Execute /rfc-council review {RFC_ID} [options]. Use --council if requested or for system-wide blast radius."
        - id: EXTRACT_RESULT
          action: "Parse latest evidence bundle for 'verdict' and 'findings_summary'."
        - id: UPDATE_HISTORY
          action: "Append iteration result to orchestration state. Increment iteration counter."
        - id: ANALYZE_STALL
          action: "If findings are identical to previous iteration, flag as STALLED."
      decisions[4]:
        - id: VERDICT_APPROVED
          if: "verdict in [APPROVED, APPROVED_WITH_REMEDIATION]"
          then: "goto: EMIT_FINAL_BUNDLE"
        - id: VERDICT_NEEDS_ADJUDICATION
          if: "verdict == NEEDS_ADJUDICATION or STALLED"
          then: "terminate: NEEDS_ADJUDICATION"
        - id: VERDICT_REJECTED_RETRY
          if: "verdict == REJECTED and iteration_count < max_iterations"
          then: "goto: REVIEW_LOOP"
        - id: VERDICT_REJECTED_TERMINAL
          if: "verdict == REJECTED and iteration_count >= max_iterations"
          then: "goto: EMIT_FINAL_BUNDLE"

    # ========================================================================
    # Node 5: EMIT_FINAL_BUNDLE
    # ========================================================================
    - id: EMIT_FINAL_BUNDLE
      purpose: "Consolidate orchestration evidence and finalize session."
      steps[4]:
        - id: AGGREGATE_METRICS
          action: "Compute total elapsed time, total findings remediated, and final ticket count."
        - id: GENERATE_BUNDLE
          action: "Write orchestration evidence to evidence/prd/{PRD_ID}/orchestration/."
        - id: GIT_COMMIT
          action: "If success, commit evidence and any remaining artifacts."
        - id: EMIT_SUMMARY
          action: "Output final status report with PRD/RFC IDs and verdict."
      decisions[1]:
        - id: ORCHESTRATION_COMPLETE
          if: "always"
          then: "terminate: SUCCESS"
