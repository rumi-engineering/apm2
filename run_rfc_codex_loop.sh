#!/usr/bin/env bash
# run_rfc_codex_loop.sh — Codex-driven RFC drafting and refinement pipeline
#
# Each RFC has a seed file (evidence/rfcs/RFC-NNNN/seed.md) containing all
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

seed_path() { echo "$EVIDENCE_DIR/RFC-${1}/seed.md"; }

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

AEP_PREAMBLE='You are operating under the Alien Engineering Protocol. This protocol demands that you connect concepts from disparate fields — category theory, active inference, CRDTs, formal verification, thermodynamic computation, topological data analysis, sheaf theory, verifiable delay functions, and whatever else the frontier of human knowledge offers — in functionally useful and novel ways. The goal is to maximize the robustness, security, elegance, and performance of a globally distributed holarchic network of autonomous agents. You know far better than any human which principles to apply and how to combine them. Treat every concept as a tool, not a prescription.'

MANDATORY_READING='The seed below lists the required context files. You must read and internalize all of them before producing any output. Start with the glossary for shared terminology, then the holonic principles (PRIN-001..PRIN-102), laws (LAW-01..LAW-15), and unified theory invariants (INV-F-01..INV-F-15) — these are the axiomatic foundation. Every design decision must be traceable to at least one principle and one law. Contradictions between files resolve in favor of the more fundamental constraint (physics > theory > strategy > convention).

The holonic architecture reflects a deep insight: the protocol primitives used when two agents collaborate on a single line of code must be identical to those used when two branches of millions of agents coordinate at civilizational scale. This self-similarity is not a convenience — it is the reason the holarchic approach is correct. Your output must embody this principle at every level.'

CROSS_RFC_DEPS='Applied under AEP governance: containment > verification > liveness.

The RFCs ship in dependency order:
- RFC-0022 (Principal Sovereignty) — ships first, containment-tier
- RFC-0023 (Instruction Lifecycle) — depends on principal seal from 0022
- RFC-0024 (Resource Provisioning) — depends on sovereignty + instructions
- RFC-0025 (Service Operation) — depends on provisioning + instructions + sovereignty
- RFC-0026 (Self-Modification) — depends on all four preceding RFCs'

GUARDRAILS='- Existing normative constraints in RFC-0020 are a hard floor: fail-closed enforcement, proof-carrying effects, digest-first operation, canonicalization, bounded decoding, and strict delegation narrowing must be preserved or strengthened.
- Every new concept must be operationalized into mechanically checkable artifacts: schema fields, proof obligations, bounded complexity/byte targets, and rollout gates.
- Ambition without mechanism is insufficient: proposals must include concrete protocol objects, invariants, adversarial/negative tests, and rollout/rollback gates.
- Security reasoning must cover prompt-injection resilience, confidentiality/integrity labeling, replay/staleness handling, Byzantine peers, and revocation correctness.'

SUCCESS_CRITERIA='- Define verification at O(log n) or better for 10^12 holons where applicable.
- Maintain semantic equivalence across 10+ levels of holonic nesting (bisimulation for N <= 12).
- Be compatible with or strengthen BFT (RFC-0014) with <1% overhead.
- Be compatible with or strengthen the Holonic Time Fabric (RFC-0016).
- Match or exceed the quality bar of RFC-0020 and RFC-0021.
- Maintain the security bar (see documents/security/).'

# ─── Prompt Builders ─────────────────────────────────────────────────────────

build_init_prompt() {
  local rfc_num="$1"
  local title="${RFC_TITLE[$rfc_num]}"
  local seed
  seed="$(read_seed "$rfc_num")"

  cat <<PROMPT
# Alien Engineering Protocol — RFC-${rfc_num}: ${title}

${AEP_PREAMBLE}

Your task: create RFC-${rfc_num} — ${title}. Internally generate multiple parallel candidate designs that explore different theoretical framings, then synthesize a master design that represents the best of each as a novel, groundbreakingly advanced protocol for autonomous agentic software at civilizational scale.

## Foundational context — mandatory reading

${MANDATORY_READING}

Use RFC-0020 (Holonic Substrate Interface) and RFC-0021 (Holonic Venture Proving Interface) as structural and quality references. Match or exceed their depth, rigor, and mechanization.

## RFC seed

The following seed contains everything specific to this RFC: the problem statement, required context files, innovation vectors, machine-checkable objectives, seed protocol objects, trust model, theory bindings, and rollout plan. These are starting points — synthesize them into a complete, frontier-quality RFC. Refine, extend, restructure, or replace anything that your analysis reveals as insufficient.

${seed}

## Cross-RFC dependency context

${CROSS_RFC_DEPS}

## Success criteria

${SUCCESS_CRITERIA}

## Guardrails

${GUARDRAILS}

## Acceptable tradeoffs

- Single OS/runtime target (currently Ubuntu). Agent-only software — no consumer UI. We control the full stack.
- We can modify existing unified theory documents — discard what doesn't work and create whatever is necessary.
- Daemon-enforced semantics and trust-boundary contracts must remain internally consistent; any intentional break requires explicit versioning and migration path.
- PQC is out of scope.

## Execution

- Phase 1: Read all required context. Identify gaps. Propose theoretical frameworks to yourself.
- Phase 2: Synthesize into a unified approach honoring holonic self-similarity, the dominance order, and every applicable principle and law.
- Phase 3: Produce the complete RFC as a single Markdown document with protocol objects, trust boundaries, governance gates, rollout plan, and acceptance criteria.

Allocate maximum reasoning depth. Do not summarize prematurely. Draw from the absolute frontier of research on autonomous agents, distributed systems, formal methods, and computational physics. Spare no technical detail.
PROMPT
}

build_analysis_prompt() {
  local rfc_num="$1"
  local pass_num="$2"
  local total_passes="$3"
  local rfc_path="$4"
  local prev_validation="$5"
  local title="${RFC_TITLE[$rfc_num]}"
  local filename="${RFC_FILENAME[$rfc_num]}"
  local seed
  seed="$(read_seed "$rfc_num")"

  cat <<PROMPT
# Alien Engineering Protocol — Analysis Pass ${pass_num}/${total_passes}
# RFC-${rfc_num}: ${title}

${AEP_PREAMBLE}

Your task in this phase is analysis only: read the current RFC draft, the foundational theory, and the seed, then produce a precise set of line-by-line diffs with detailed rationale for each change. You do not produce the updated RFC — a separate session will apply your diffs. Your output is the analysis artifact.

## Foundational context — mandatory reading

${MANDATORY_READING}

## Current RFC draft

Read the current draft from this file path:
- ${rfc_path}

## RFC seed (objectives, protocol objects, threat model, theory bindings)

Use this seed as ground truth for what the RFC must achieve. If the current draft is missing any objective, protocol object, trust boundary, or theory binding below, propose changes to add them.

${seed}

## Previous pass validation results

${prev_validation}

## Guardrails

${GUARDRAILS}

## Your output: analysis artifact

Produce a series of proposed changes to the RFC. The document should grow with each pass — diffs should primarily add new content (deeper analysis, missing protocol objects, additional threat coverage, stronger theory bindings, new verification artifacts) rather than merely rephrase existing text.

Format each change as:

### Change N: [brief title]

**Rationale**: Your detailed reasoning — what frontier concepts inform it, which holonic principles/laws/invariants it serves.

**Constraints preserved/strengthened**: Which constraints from RFC-0020, theory, or strategy this upholds.

**Threat modes addressed**: What failure/attack modes this prevents, and fail-closed behavior under ambiguity.

**Verification evidence**: What tests, proofs, benchmarks, or canary gates validate this change.

\`\`\`diff
--- a/documents/rfcs/RFC-${rfc_num}/${filename}
+++ b/documents/rfcs/RFC-${rfc_num}/${filename}
@@ context @@
-old line
+new line
\`\`\`

After all changes, include a gap assessment: what remains to be strengthened in subsequent passes.

Allocate maximum reasoning depth. Propose your best revisions.
PROMPT
}

build_apply_prompt() {
  local rfc_num="$1"
  local pass_num="$2"
  local rfc_path="$3"
  local analysis_path="$4"
  local title="${RFC_TITLE[$rfc_num]}"

  local analysis_content=""
  if [[ -f "$analysis_path" ]]; then
    analysis_content="$(cat "$analysis_path")"
  fi

  cat <<PROMPT
# Apply Pass ${pass_num} — RFC-${rfc_num}: ${title}

Take the analysis artifact below and apply its diffs to the current RFC draft to produce an updated, complete RFC document.

1. Read the current RFC draft from: ${rfc_path}
2. Apply every proposed diff below. Where context has shifted, apply the intent faithfully.
3. The document should grow — preserve all existing content unless a diff explicitly removes it.
4. Produce the complete, updated RFC as a single Markdown document. Not a summary. Not a partial document.

## Analysis artifact

${analysis_content}

## Output

Produce the complete updated RFC-${rfc_num} as a single Markdown document starting with the RFC title header. Include every section, every protocol object, every table.
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
  run_check "governance_gates"    "Governance.*Gate\|Gate Portfolio"
  run_check "rollout_plan"        "Rollout Plan\|Implementation [Mm]ilestones"
  run_check "fail_closed"         "fail-closed\|fail.closed"
  run_check "htf_time_authority"  "HTF"
  run_check "jq_predicates"       "jq -e"
  run_check "dominance_order"     "dominance.*order\|Dominance.*Order\|containment.*verification.*liveness"
  run_check "theory_bindings"     "LAW-\|INV-F-\|PRIN-"
  run_check "scale_envelope"      "10.*12\|trillion\|scale.*envelope\|Scale.*Envelope"
  run_check "acceptance_bar"      "Acceptance\|acceptance"
  run_check "ticket_decomposition" "Ticket Decomposition\|TCK-\|implementation.*milestone"

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

  local prompt_file
  prompt_file="$(mktemp)"
  echo "$prompt" > "$prompt_file"

  CODEX_HEADLESS=1 NO_COLOR=1 "$CODEX_CMD" exec \
    "$(cat "$prompt_file")" \
    --approval never \
    > "$output_file" 2>&1 || {
    log "WARNING: Codex returned non-zero exit code"
  }

  rm -f "$prompt_file"
  log "Codex output: $output_file ($(wc -c < "$output_file") bytes)"
}

# ─── Apply output ────────────────────────────────────────────────────────────

apply_output() {
  local rfc_path="$1"
  local codex_output="$2"
  local pass_dir="$3"

  if rg -q "no.changes.needed\|no.changes.required\|no.further.changes" "$codex_output" 2>/dev/null; then
    log "No changes needed — preserving current draft"
    cp "$rfc_path" "${pass_dir}/output.md"
    return 0
  fi

  if head -5 "$codex_output" | rg -q "^# RFC-" 2>/dev/null; then
    log "Codex produced complete RFC — replacing draft"
    cp "$codex_output" "$rfc_path"
    cp "$codex_output" "${pass_dir}/output.md"
  else
    cp "$codex_output" "${pass_dir}/output.md"
    local patch_file="${pass_dir}/changes.patch"
    sed -n '/^```diff$/,/^```$/p' "$codex_output" | sed '/^```/d' > "$patch_file" || true
    if [[ -s "$patch_file" ]]; then
      log "Attempting to apply extracted diffs..."
      if patch -p1 --forward --no-backup-if-mismatch < "$patch_file" 2>/dev/null; then
        log "Diffs applied successfully"
      else
        log "WARNING: Patch failed — manual review needed (saved: ${patch_file})"
      fi
    else
      log "No extractable diffs found"
    fi
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
    init_prompt="$(build_init_prompt "$rfc_num")"
    echo "$init_prompt" > "${pass0_dir}/prompt.txt"
    invoke_codex "$init_prompt" "${pass0_dir}/raw_output.md" "$dry_run"

    if [[ "$dry_run" != "true" ]]; then
      apply_output "$rfc_path" "${pass0_dir}/raw_output.md" "$pass0_dir"
      validate_rfc "$rfc_num" "$rfc_path" "${pass0_dir}/validation.json" || true
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
    analysis_prompt="$(build_analysis_prompt "$rfc_num" "$pass" "$num_passes" "$rfc_path" "$prev_validation")"
    echo "$analysis_prompt" > "${pass_dir}/analysis_prompt.txt"
    local analysis_output="${pass_dir}/analysis.md"
    invoke_codex "$analysis_prompt" "$analysis_output" "$dry_run"

    # Phase B: Apply
    log "Phase B: Apply..."
    local apply_prompt
    apply_prompt="$(build_apply_prompt "$rfc_num" "$pass" "$rfc_path" "$analysis_output")"
    echo "$apply_prompt" > "${pass_dir}/apply_prompt.txt"
    invoke_codex "$apply_prompt" "${pass_dir}/raw_output.md" "$dry_run"

    if [[ "$dry_run" != "true" ]]; then
      apply_output "$rfc_path" "${pass_dir}/raw_output.md" "$pass_dir"

      [[ -f "${evidence_base}/prev_draft.md" ]] && \
        diff -u "${evidence_base}/prev_draft.md" "$rfc_path" > "${pass_dir}/diff.patch" 2>/dev/null || true

      validate_rfc "$rfc_num" "$rfc_path" "${pass_dir}/validation.json" || true

      if rg -q "no.changes.needed\|no.changes.required\|no.further.changes" "$analysis_output" 2>/dev/null; then
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
