#!/usr/bin/env bash
set -euo pipefail

# Oracle PRD Template Review Script (Web Mode + Xvfb)
# Runs 5 rounds of GPT-5.2 Pro review via browser automation
# Focuses on ensuring PRD template sets up RFC for success

PROJECT_DIR="/home/ubuntu/Projects/apm2"
TEMPLATE_DIR="$PROJECT_DIR/documents/prds/template"
AIP_DIR="$PROJECT_DIR/documents/prds/AIP-0001"
RFC_DIR="$PROJECT_DIR/documents/rfcs/template"
OUTPUT_DIR="/tmp/oracle-prd-review"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

# Check for claude CLI
if ! command -v claude &> /dev/null; then
    echo "ERROR: claude CLI not found"
    exit 1
fi

# Setup Xvfb for headless browser (SSH environment)
if [[ -z "${DISPLAY:-}" ]]; then
    log "Setting up Xvfb virtual display for headless browser..."

    # Kill any existing Xvfb on :99
    pkill -f "Xvfb :99" 2>/dev/null || true

    # Start Xvfb
    Xvfb :99 -screen 0 1920x1080x24 &
    XVFB_PID=$!
    export DISPLAY=:99

    # Cleanup on exit
    trap "kill $XVFB_PID 2>/dev/null || true" EXIT

    # Give Xvfb time to start
    sleep 2
    log "Xvfb started on DISPLAY=:99"
fi

mkdir -p "$OUTPUT_DIR"

ROUND_FOCUSES=(
    "PRD authority structure - ensure PRD clearly defines what RFC cannot change"
    "Acceptance criteria and evidence requirements - testable criteria for RFC fulfillment"
    "Constraints/invariants that flow to RFC - fail-closed defaults, security posture"
    "Completeness checklist and traceability - machine-readable RFC validation"
    "Overall coherence - does this PRD template set up RFC for success?"
)

# Base prompt with PRD<->RFC authority model
BASE_PROMPT='You are reviewing a PRD (Product Requirements Document) YAML template designed for
AI agent communication. This template serves as the authoritative contract that
RFC (Request for Comments) documents must implement.

## PRD<->RFC AUTHORITY MODEL (Critical Context)

**PRD is authoritative for** (the "what/why"):
- Customer segments and problem statements
- Goals, scope boundaries, and out-of-scope items
- Non-negotiable invariants (security posture, fail-closed behavior, threat model)
- Measurable outcomes and acceptance criteria
- REQ/DELIV/E2E inventory and required evidence shape

**RFC is authoritative for** (the "how"):
- Design decisions, interfaces, data models, protocols
- Decomposition into implementable work items
- Concrete verification commands, selectors, rollout/rollback mechanics
- Detailed risk mitigations and control mappings

**No-drift rules**:
1. PRD -> RFC is one-way for authority (RFC cannot redefine PRD)
2. RFC -> PRD is a controlled feedback loop via explicit prd_amendments_required section
3. RFC must NOT add new MUST requirements without PRD amendment
4. PRD owns IDs (REQ-*, DELIV-*, E2E-*); RFC must map every PRD ID exactly once
5. RFC can refine requirements into testable constraints only as interpretation of existing PRD requirement

## REVIEW CONTEXT

Files provided:
- PRD template: documents/prds/template/*.yaml (10 files)
- RFC template: documents/rfcs/template/*.yaml (9 files)
- AIP-0001: documents/prds/AIP-0001/*.yaml (concrete PRD instance)

## REVIEW GOALS

1. **Acceptance criteria completeness**: PRD must define testable criteria RFC must satisfy
2. **Constraints -> Invariants flow**: PRD constraints must flow directly to RFC invariants
3. **Completeness checklist**: PRD should include machine-readable validation checklist for RFC
4. **Metrics -> Evidence mapping**: Each PRD success metric must have RFC evidence strategy
5. **Failure modes coverage**: PRD should list failure scenarios RFC must address
6. **Traceability enforcement**: PRD ID scheme (REQ/DELIV/E2E) must support RFC mapping'

for ROUND in {1..5}; do
    log "=========================================="
    log "ROUND $ROUND/5: ${ROUND_FOCUSES[$((ROUND-1))]}"
    log "=========================================="

    PROMPT="${BASE_PROMPT}

## ROUND $ROUND/5 FOCUS: ${ROUND_FOCUSES[$((ROUND-1))]}

## OUTPUT FORMAT

For each file that needs changes, provide:
1. **File name**
2. **Specific changes** (with before/after YAML snippets)
3. **Rationale** explaining how this improves PRD->RFC contract enforcement

End with:
- Summary of key improvements for this round
- Any gaps where PRD template fails to set up RFC for success"

    OUTPUT_FILE="$OUTPUT_DIR/round-${ROUND}-feedback.md"
    SLUG="prd-review-round-${ROUND}"

    log "Running oracle (browser mode) for round $ROUND..."
    log "This will open a browser window for ChatGPT interaction..."

    npx -y @steipete/oracle \
        --engine browser \
        --model gpt-5.2-pro \
        --slug "$SLUG" \
        --prompt "$PROMPT" \
        --file "$TEMPLATE_DIR/"*.yaml \
        --file "$RFC_DIR/"*.yaml \
        --file "$AIP_DIR/"*.yaml \
        --browser-manual-login \
        --write-output "$OUTPUT_FILE"

    log "Oracle feedback saved to: $OUTPUT_FILE"

    # Apply changes using Claude Code (non-interactive)
    log "Applying feedback using Claude Code..."

    APPLY_PROMPT="Read the GPT-5.2 review feedback from $OUTPUT_FILE and apply all recommended changes to:
1. The PRD template files in $TEMPLATE_DIR/
2. The AIP-0001 files in $AIP_DIR/ (update to match revised template structure)

IMPORTANT:
- Apply the YAML changes exactly as specified in the feedback
- Preserve YAML syntax validity
- If a change is unclear, skip it and note why
- After applying changes, verify YAML files are valid
- Focus on changes that improve PRD->RFC contract enforcement

This is round $ROUND of 5. Focus on the changes specific to this round."

    cd "$PROJECT_DIR"
    claude --print --dangerously-skip-permissions "$APPLY_PROMPT" 2>&1 | tee "$OUTPUT_DIR/round-${ROUND}-apply.log"

    log "Round $ROUND complete. Changes applied."
    log ""
done

log "=========================================="
log "All 5 rounds complete!"
log "=========================================="
log "Feedback files: $OUTPUT_DIR/round-*-feedback.md"
log "Apply logs: $OUTPUT_DIR/round-*-apply.log"
log "=========================================="
