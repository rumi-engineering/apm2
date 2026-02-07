#!/usr/bin/env bash
# run_rfc_codex_loop.sh — Codex-driven RFC drafting and refinement pipeline
#
# Each RFC has a seed file (documents/rfcs/RFC-NNNN/seed.md) containing all
# RFC-specific context: framing, innovation vectors, required reading,
# objectives, protocol objects, threat model, theory bindings, and rollout.
#
# The pipeline is two-phase per refinement pass:
#   Phase A: Codex reads seed + current draft → produces analysis artifact (diffs + rationale)
#   Phase B: Separate Codex session reads analysis artifact → applies diffs to produce updated RFC
#
# Usage:
#   ./run_rfc_codex_loop.sh [--rfc 0022] [--passes 12] [--dry-run] [--skip-init]
#   ./run_rfc_codex_loop.sh --all
#
# Requires: codex CLI in PATH, jq, rg

set -euo pipefail

# ─── Configuration ───────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$SCRIPT_DIR"
RFCS_DIR="$REPO_ROOT/documents/rfcs"
EVIDENCE_DIR="$REPO_ROOT/evidence/rfcs"
DEFAULT_PASSES=12
CODEX_CMD="${CODEX_CMD:-codex}"

RFC_ORDER=(0022 0023 0024 0025 0026)

declare -A RFC_TITLE=(
  [0022]="Principal Sovereignty Interface"
  [0023]="Instruction Lifecycle"
  [0024]="Resource Provisioning"
  [0025]="Service Operation"
  [0026]="Self-Modification Governance"
)

declare -A RFC_FILENAME=(
  [0022]="PRINCIPAL_SOVEREIGNTY_INTERFACE.md"
  [0023]="INSTRUCTION_LIFECYCLE.md"
  [0024]="RESOURCE_PROVISIONING.md"
  [0025]="SERVICE_OPERATION.md"
  [0026]="SELF_MODIFICATION_GOVERNANCE.md"
)

# ─── Helpers ─────────────────────────────────────────────────────────────────

log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*"; }
ensure_dir() { mkdir -p "$1"; }

commit_progress() {
  local rfc_num="$1" label="$2"
  git -C "$REPO_ROOT" add -A "documents/rfcs/RFC-${rfc_num}/" "evidence/rfcs/RFC-${rfc_num}/" 2>/dev/null || true
  git -C "$REPO_ROOT" diff --cached --quiet 2>/dev/null && { log "Nothing to commit"; return 0; }
  git -C "$REPO_ROOT" commit -m "auto: RFC-${rfc_num} ${label}" --no-verify 2>/dev/null || true
  log "Committed: RFC-${rfc_num} ${label}"
}

seed_path() { echo "$RFCS_DIR/RFC-${1}/seed.md"; }

read_seed() {
  local path
  path="$(seed_path "$1")"
  if [[ ! -f "$path" ]]; then
    echo "ERROR: seed file not found: $path" >&2
    exit 1
  fi
  cat "$path"
}

# ─── Shared prompt fragments ────────────────────────────────────────────────

AEP_PREAMBLE='You are working under the Alien Engineering Protocol. The core idea is simple: draw from whatever field of human knowledge best solves the problem at hand — category theory, active inference, CRDTs, formal verification, thermodynamic computation, topological data analysis, sheaf theory, verifiable delay functions, or anything else. The system you are designing is a globally distributed holarchic network of autonomous agents. You understand which principles apply and how to combine them better than we could prescribe. Treat every concept as a tool to be evaluated on its merits, never as a checkbox.'

MANDATORY_READING='The seed below lists the context files that define the project'\''s theoretical and strategic foundations. Read and internalize all of them before writing anything. The glossary establishes shared terminology. The holonic principles (PRIN-001..PRIN-102), laws (LAW-01..LAW-15), and unified theory invariants (INV-F-01..INV-F-15) form the axiomatic bedrock — every design decision should be traceable to at least one principle and one law. When files conflict, the more fundamental constraint prevails: physics over theory, theory over strategy, strategy over convention.

One insight deserves special attention: the protocol primitives used when two agents collaborate on a single line of code are identical to those used when two branches of millions of agents coordinate at civilizational scale. This self-similarity across scale is the defining property of the holarchic approach, and the document you produce should embody it naturally.'

CROSS_RFC_DEPS='The system'\''s RFCs follow a strict dependency chain rooted in a dominance order: containment before verification, verification before liveness.

- RFC-0022 (Principal Sovereignty) ships first as the containment-tier foundation.
- RFC-0023 (Instruction Lifecycle) depends on the principal seal introduced in 0022.
- RFC-0024 (Resource Provisioning) depends on sovereignty and instructions.
- RFC-0025 (Service Operation) depends on provisioning, instructions, and sovereignty.
- RFC-0026 (Self-Modification) depends on all four preceding RFCs.

Your document should be consistent with this dependency structure, referencing sibling RFCs where appropriate but never depending on something that has not yet been defined.'

GUARDRAILS='A few hard constraints to respect:
- The normative guarantees in RFC-0020 are a floor, not a ceiling: fail-closed enforcement, proof-carrying effects, digest-first operation, canonicalization, bounded decoding, and strict delegation narrowing. Preserve or strengthen them.
- Every new concept needs to be operationalized into mechanically checkable artifacts — schema fields, proof obligations, bounded complexity targets, rollout gates. Ideas without mechanisms are interesting but insufficient.
- Security reasoning should cover prompt-injection resilience, confidentiality and integrity labeling, replay and staleness handling, Byzantine peers, and revocation correctness.'

SUCCESS_CRITERIA='When evaluating your own output, consider whether it:
- Defines verification at O(log n) or better for systems scaling to 10^12 holons, where applicable.
- Maintains semantic equivalence across 10+ levels of holonic nesting (bisimulation for N <= 12).
- Is compatible with or strengthens BFT consensus (RFC-0014) at less than 1% overhead.
- Is compatible with or strengthens the Holonic Time Fabric (RFC-0016).
- Meets or exceeds the depth and rigor of RFC-0020 and RFC-0021.
- Maintains the security posture documented in documents/security/.'

# ─── Prompt Builders ─────────────────────────────────────────────────────────

build_init_prompt() {
  local rfc_num="$1"
  local seed
  if ! seed="$(read_seed "$rfc_num")"; then
    return 1
  fi

  cat <<PROMPT
# Alien Engineering Protocol

${AEP_PREAMBLE}

## What we need from you

We need a complete, publication-ready RFC for the APM2 holarchic agent system. The seed material below describes the problem we are trying to solve, the design space we have explored so far, and a wishlist of properties we would like the solution to have. It includes starter protocol objects, objectives, a threat model, theory bindings, and a rollout sketch.

All of this is raw material for your thinking, not a specification to implement. The names, the structure, the framing — all of it is yours to reshape. If you see a better way to decompose the problem, a more elegant set of protocol objects, a tighter threat model, or a different rollout order, follow your judgment. The only things that are non-negotiable are the foundational constraints from the theory files and the dependency relationships between RFCs.

Think deeply about the problem before you begin writing. Consider multiple approaches. Discard the ones that don't hold up. What survives your own scrutiny is what we want to read.

## Foundational context

${MANDATORY_READING}

RFC-0020 (Holonic Substrate Interface) and RFC-0021 (Holonic Venture Proving Interface) are the best existing examples of the depth and rigor we expect. Read them as structural references.

## Seed material

${seed}

## Dependency context

${CROSS_RFC_DEPS}

## Quality bar

${SUCCESS_CRITERIA}

## Hard constraints

${GUARDRAILS}

## Practical notes

- The target is Ubuntu-only, agent software with no consumer UI. We control the full stack.
- Existing unified theory documents can be modified — discard what does not work and create what is necessary.
- Daemon-enforced semantics and trust-boundary contracts must remain internally consistent; any intentional break requires explicit versioning and a migration path.
- Post-quantum cryptography is out of scope for now.

## Output

Produce a single, complete Markdown document. Choose a title that precisely captures what this RFC defines. Include protocol objects with full field definitions, trust boundaries, governance gates, a phased rollout plan, and acceptance criteria. Do not leave sections as stubs or summaries — every section should be thorough enough to implement from.

Take as much space as the subject demands. Depth and completeness matter far more than brevity.
PROMPT
}

build_analysis_prompt() {
  local rfc_num="$1"
  local pass_num="$2"
  local total_passes="$3"
  local rfc_path="$4"
  local prev_validation="$5"
  local filename="${RFC_FILENAME[$rfc_num]}"
  local seed
  if ! seed="$(read_seed "$rfc_num")"; then
    return 1
  fi

  cat <<PROMPT
# Alien Engineering Protocol — Final Review

${AEP_PREAMBLE}

## Your role

You are performing the final technical review of an RFC before it ships. The document at the path below is a near-complete draft. Your job is to find everything that is missing, underspecified, inconsistent, or insufficiently grounded — and to produce precise diffs that bring it to publication quality.

You are producing an analysis document only. A colleague will read your analysis and apply the changes. Be precise enough that they can do so mechanically.

## Foundational context

${MANDATORY_READING}

## The RFC under review

Read the current draft from this path:
- ${rfc_path}

## Original problem statement and design intent

The seed below describes the problem this RFC was designed to solve, the properties we wanted, and the starter material the original author worked from. Use it to evaluate whether the draft fully addresses the problem. Anything in the seed that is not adequately reflected in the draft is a gap worth closing.

${seed}

## Automated check results

The following are results from automated structural checks. Failures indicate missing content.

${prev_validation}

## Hard constraints

${GUARDRAILS}

## What good changes look like

Your changes should primarily add substance — deeper analysis, missing protocol objects, additional threat coverage, stronger theory bindings, new verification artifacts. Rephrasing existing text without adding information is not useful. The document should get more thorough as a result of your review, not just differently worded.

Format each proposed change as:

### Change N: [brief title]

**Rationale**: What is missing or wrong, and why the proposed change fixes it. Reference specific principles, laws, or invariants where relevant.

**Constraints preserved**: Which guarantees from RFC-0020, the theory, or the strategy this upholds or strengthens.

**Threat coverage**: What failure or attack modes this addresses.

**Verification**: How this change can be validated — tests, proofs, benchmarks, or gates.

\`\`\`diff
--- a/documents/rfcs/RFC-${rfc_num}/${filename}
+++ b/documents/rfcs/RFC-${rfc_num}/${filename}
@@ context @@
-old line
+new line
\`\`\`

After all changes, include a brief assessment of any remaining gaps.
PROMPT
}

build_apply_prompt() {
  local rfc_num="$1"
  local pass_num="$2"
  local rfc_path="$3"
  local analysis_path="$4"

  local analysis_content=""
  if [[ -f "$analysis_path" ]]; then
    analysis_content="$(cat "$analysis_path")"
  fi

  cat <<PROMPT
A technical reviewer has analyzed an RFC and produced a set of changes with rationale and diffs. Your job is to apply those changes to produce the final, complete document.

1. Read the current RFC from: ${rfc_path}
2. Apply every proposed change below. Where the surrounding context has shifted slightly, apply the intent faithfully rather than failing on exact line matching.
3. Preserve all existing content unless a diff explicitly removes it. The document should grow, not shrink.
4. Produce the complete RFC as a single Markdown document — every section, every protocol object, every table. Not a summary, not a partial document.

## Reviewer analysis

${analysis_content}

## Output

The complete, updated RFC as a single Markdown document.
PROMPT
}

# ─── Validation ──────────────────────────────────────────────────────────────

validate_rfc() {
  local rfc_num="$1"
  local rfc_path="$2"
  local result_file="$3"
  local checks=()
  local pass_count=0
  local fail_count=0

  log "Validating RFC-${rfc_num}..."

  run_check() {
    local name="$1" pattern="$2"
    if rg -q "$pattern" "$rfc_path" 2>/dev/null; then
      checks+=("{\"check\":\"${name}\",\"status\":\"PASS\"}")
      ((pass_count++))
    else
      checks+=("{\"check\":\"${name}\",\"status\":\"FAIL\"}")
      ((fail_count++))
    fi
  }

  [[ -s "$rfc_path" ]] && { checks+=('{"check":"file_exists","status":"PASS"}'); ((pass_count++)); } || { checks+=('{"check":"file_exists","status":"FAIL"}'); ((fail_count++)); }

  run_check "protocol_objects"    "Protocol Objects"
  run_check "trust_boundaries"    "Trust Boundar"
  run_check "governance_gates"    "(Governance.*Gate|Gate Portfolio)"
  run_check "rollout_plan"        "(Rollout Plan|Implementation [Mm]ilestones)"
  run_check "fail_closed"         "(fail-closed|fail.closed)"
  run_check "htf_time_authority"  "HTF"
  run_check "jq_predicates"       "jq -e"
  run_check "dominance_order"     "(dominance.*order|Dominance.*Order|containment.*verification.*liveness)"
  run_check "theory_bindings"     "(LAW-|INV-F-|PRIN-)"
  run_check "scale_envelope"      "(10.*12|trillion|[Ss]cale.*[Ee]nvelope)"
  run_check "acceptance_bar"      "[Aa]cceptance"
  run_check "ticket_decomposition" "(Ticket Decomposition|TCK-|implementation.*milestone)"

  local checks_json
  checks_json="$(printf '%s\n' "${checks[@]}" | jq -s '.')"

  jq -n \
    --arg rfc "RFC-${rfc_num}" \
    --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --argjson pass "$pass_count" \
    --argjson fail "$fail_count" \
    --argjson total "$((pass_count + fail_count))" \
    --argjson checks "$checks_json" \
    '{rfc: $rfc, timestamp: $ts, pass_count: $pass, fail_count: $fail, total_checks: $total, all_pass: ($fail == 0), checks: $checks}' \
    > "$result_file"

  log "Validation: ${pass_count}/$((pass_count + fail_count)) checks passed (${fail_count} failures)"
  return "$fail_count"
}

# ─── Codex Invocation ────────────────────────────────────────────────────────

invoke_codex() {
  local prompt="$1"
  local output_file="$2"
  local dry_run="${3:-false}"

  if [[ "$dry_run" == "true" ]]; then
    log "[DRY-RUN] Would invoke codex with prompt (${#prompt} chars)"
    echo "[DRY-RUN] Prompt length: ${#prompt} chars" > "$output_file"
    echo "[DRY-RUN] First 200 chars:" >> "$output_file"
    echo "${prompt:0:200}" >> "$output_file"
    return 0
  fi

  log "Invoking Codex (prompt: ${#prompt} chars)..."

  local prompt_file log_file
  prompt_file="$(mktemp)"
  log_file="${output_file%.md}.log"
  echo "$prompt" > "$prompt_file"

  "$CODEX_CMD" exec \
    -m "${CODEX_MODEL:-gpt-5.3-codex}" \
    --dangerously-bypass-approvals-and-sandbox \
    -o "$output_file" \
    - < "$prompt_file" > "$log_file" 2>&1 || {
    log "WARNING: Codex returned non-zero exit code (see $log_file)"
  }

  rm -f "$prompt_file"

  if [[ -f "$output_file" ]]; then
    log "Codex output: $output_file ($(wc -c < "$output_file") bytes)"
  else
    log "WARNING: No output file produced — copying log as fallback"
    cp "$log_file" "$output_file"
  fi
}

# ─── Apply output ────────────────────────────────────────────────────────────

apply_output() {
  local rfc_path="$1"
  local codex_output="$2"
  local pass_dir="$3"

  if rg -q "(no.changes.needed|no.changes.required|no.further.changes)" "$codex_output" 2>/dev/null; then
    log "No changes needed — preserving current draft"
    cp "$rfc_path" "${pass_dir}/output.md"
    return 0
  fi

  if head -5 "$codex_output" | rg -q "^# RFC-|^# [A-Z]" 2>/dev/null; then
    log "Codex produced complete RFC — replacing draft"
    cp "$codex_output" "$rfc_path"
    cp "$codex_output" "${pass_dir}/output.md"
  else
    log "Output does not start with RFC header — preserving as-is"
    cp "$codex_output" "${pass_dir}/output.md"
  fi
}

# ─── Main RFC Processing ────────────────────────────────────────────────────

process_rfc() {
  local rfc_num="$1"
  local num_passes="${2:-$DEFAULT_PASSES}"
  local dry_run="${3:-false}"
  local skip_init="${4:-false}"
  local title="${RFC_TITLE[$rfc_num]}"
  local filename="${RFC_FILENAME[$rfc_num]}"
  local rfc_dir="${RFCS_DIR}/RFC-${rfc_num}"
  local rfc_path="${rfc_dir}/${filename}"
  local evidence_base="${EVIDENCE_DIR}/RFC-${rfc_num}/codex_refinement"

  log "=== Processing RFC-${rfc_num}: ${title} ==="
  ensure_dir "$rfc_dir"
  ensure_dir "$evidence_base"

  # ── Pass 0: Initial draft ──────────────────────────────────────────────

  if [[ "$skip_init" != "true" ]] || [[ ! -f "$rfc_path" ]]; then
    local pass0_dir="${evidence_base}/pass_00"
    ensure_dir "$pass0_dir"

    log "Pass 0: Generating initial draft..."
    local init_prompt
    if ! init_prompt="$(build_init_prompt "$rfc_num")"; then
      log "ERROR: failed to build initial prompt for RFC-${rfc_num}"
      return 1
    fi
    echo "$init_prompt" > "${pass0_dir}/prompt.txt"
    invoke_codex "$init_prompt" "${pass0_dir}/raw_output.md" "$dry_run"

    if [[ "$dry_run" != "true" ]]; then
      apply_output "$rfc_path" "${pass0_dir}/raw_output.md" "$pass0_dir"
      validate_rfc "$rfc_num" "$rfc_path" "${pass0_dir}/validation.json" || true
      commit_progress "$rfc_num" "pass 0 — initial draft"
    fi
  else
    log "Skipping init (--skip-init or draft exists)"
  fi

  # ── Passes 1..N: Two-phase (Analysis → Apply) ─────────────────────────

  for ((pass = 1; pass <= num_passes; pass++)); do
    local pass_dir
    pass_dir="$(printf '%s/pass_%02d' "$evidence_base" "$pass")"
    ensure_dir "$pass_dir"

    log "── Pass ${pass}/${num_passes} ──"

    [[ -f "$rfc_path" ]] && cp "$rfc_path" "${evidence_base}/prev_draft.md"

    local prev_pass_dir
    prev_pass_dir="$(printf '%s/pass_%02d' "$evidence_base" "$((pass - 1))")"
    local prev_validation="(no previous validation)"
    [[ -f "${prev_pass_dir}/validation.json" ]] && prev_validation="$(cat "${prev_pass_dir}/validation.json")"

    # Phase A: Analysis
    log "Phase A: Analysis..."
    local analysis_prompt
    if ! analysis_prompt="$(build_analysis_prompt "$rfc_num" "$pass" "$num_passes" "$rfc_path" "$prev_validation")"; then
      log "ERROR: failed to build analysis prompt for RFC-${rfc_num} pass ${pass}"
      return 1
    fi
    echo "$analysis_prompt" > "${pass_dir}/analysis_prompt.txt"
    local analysis_output="${pass_dir}/analysis.md"
    invoke_codex "$analysis_prompt" "$analysis_output" "$dry_run"

    # Phase B: Apply
    log "Phase B: Apply..."
    local apply_prompt
    if ! apply_prompt="$(build_apply_prompt "$rfc_num" "$pass" "$rfc_path" "$analysis_output")"; then
      log "ERROR: failed to build apply prompt for RFC-${rfc_num} pass ${pass}"
      return 1
    fi
    echo "$apply_prompt" > "${pass_dir}/apply_prompt.txt"
    invoke_codex "$apply_prompt" "${pass_dir}/raw_output.md" "$dry_run"

    if [[ "$dry_run" != "true" ]]; then
      apply_output "$rfc_path" "${pass_dir}/raw_output.md" "$pass_dir"

      validate_rfc "$rfc_num" "$rfc_path" "${pass_dir}/validation.json" || true
      commit_progress "$rfc_num" "pass ${pass} — review and apply"

      if rg -q "(no.changes.needed|no.changes.required|no.further.changes)" "$analysis_output" 2>/dev/null; then
        log "Analysis reports no further changes — stopping early"
        break
      fi
    fi
  done

  # ── Final validation ───────────────────────────────────────────────────

  if [[ "$dry_run" != "true" ]] && [[ -f "$rfc_path" ]]; then
    local final_dir="${evidence_base}/final"
    ensure_dir "$final_dir"
    validate_rfc "$rfc_num" "$rfc_path" "${final_dir}/validation.json" || true
    log "Final RFC: ${rfc_path}"
    log "Evidence: ${evidence_base}/"
  fi

  log "RFC-${rfc_num} complete"
}

# ─── CLI ─────────────────────────────────────────────────────────────────────

usage() {
  cat <<EOF
Usage: $0 [OPTIONS]

Options:
  --rfc NUM        Process a single RFC (e.g., 0022)
  --passes N       Number of refinement passes (default: $DEFAULT_PASSES)
  --all            Process all RFCs (0022..0026) sequentially
  --dry-run        Build prompts without invoking Codex
  --skip-init      Skip initial draft generation
  --help           Show this help
EOF
}

main() {
  local rfc_num="" passes="$DEFAULT_PASSES" run_all=false dry_run=false skip_init=false

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --rfc)       rfc_num="$2"; shift 2 ;;
      --passes)    passes="$2"; shift 2 ;;
      --all)       run_all=true; shift ;;
      --dry-run)   dry_run=true; shift ;;
      --skip-init) skip_init=true; shift ;;
      --help)      usage; exit 0 ;;
      *)           echo "Unknown: $1"; usage; exit 1 ;;
    esac
  done

  if [[ "$run_all" == "true" ]]; then
    for num in "${RFC_ORDER[@]}"; do
      process_rfc "$num" "$passes" "$dry_run" "$skip_init"
      if [[ "$dry_run" != "true" ]]; then
        log "RFC-${num} complete. Review before continuing."
        read -rp "Press Enter for next RFC (Ctrl+C to stop)..."
      fi
    done
  elif [[ -n "$rfc_num" ]]; then
    [[ -z "${RFC_TITLE[$rfc_num]+x}" ]] && { echo "Unknown RFC: $rfc_num"; exit 1; }
    process_rfc "$rfc_num" "$passes" "$dry_run" "$skip_init"
  else
    echo "Specify --rfc NUM or --all"; usage; exit 1
  fi
}

main "$@"
