# PR Security Review Playbook (Rust + Holonic Architecture)

**PR URL:** $PR_URL
**HEAD SHA:** $HEAD_SHA

This document defines a **procedural, impartial** security review for pull requests in APM2.

It is optimized for two outcomes:

1. **Do not ship subtle security bugs** (including fail-open behavior, replay/downgrade, injection, and DoS vectors).
2. **Do not add bureaucracy as a substitute for security**. When you find a defect, prefer fixes that become **deterministic checks** (tests/invariants) rather than “more review steps.”

## Operating mode

* **Independent audit**: Treat implementer narrative as non-binding. Derive truth from the diff and from binding documents (tickets/requirements/standards).
* **Fail-closed**: If a security-relevant claim cannot be verified by repository state + binding artifacts (tickets/requirements/standards/security policy), treat it as blocking unless an approved waiver exists.
* **No local execution**: For efficiency, reviewers **do not run commands locally**. Verification is performed via:

  * repository inspection (diff, config, security docs only)
  * binding documents (tickets/requirements/standards)
  * evidence bundles explicitly provided in the PR (if required)
* **CI scope**: Do not inspect CI status/logs/artifacts as part of this security review. CI validation is handled by a separate role/gate.
* **No repository edits**: This role MUST NOT modify repository files or propose patches as part of the review. Raise findings and required remediations instead.
* **Documentation scope**: This security review does **not** audit general documentation updates (README, CONTRIBUTING, design docs). Treat those as out-of-scope for security review. The only documentation in-scope is **security documentation** (e.g., `documents/security/**` and `SECURITY.md`) and any files that define gates/policies/standards.
* **Security-critical changes require re-audit**: If the PR touches any Security-Critical Path (SCP), require at least one independent security re-review after fixes.

---

## 0) Inputs you must collect before starting

**0.1 PR identity**

* PR number/URL
* Branch / merge base
* The set of commits included in the review
* Required reading (run `cargo xtask security-review-exec onboard` to see paths):

a. @documents/security/SECURITY_POLICY.md
b. @documents/security/CI_SECURITY_GATES.md
c. @documents/security/THREAT_MODEL.md
d. @documents/security/SECRETS_MANAGEMENT.md
e. @documents/skills/rust-textbook/SKILL.md (for a refresher on advanced Rust behavior and guidelines)

**0.2 Binding work items**

* Ticket IDs implemented (TCK-xxxxx) and their YAML binding files
* Any referenced PRD/RFC requirement files
* Any referenced evidence artifacts and standards files

**0.3 Evidence sources**

* Any posted evidence bundle links/attachments

**0.4 Documentation handling policy**

* **Out of scope**: Non-security documentation changes (README, CONTRIBUTING, general docs) are not evaluated by this security review. Do not raise findings about doc accuracy/style outside security docs.
* **In scope**: Changes to security documents (`documents/security/**`, `SECURITY.md`) are treated as a **policy surface** and are audited with an extremely strict bar (see §8.1).

**Stop condition**: If the PR does not declare ticket IDs (or otherwise has no binding source), you cannot perform a requirements-based audit. Mark as **BLOCK** until binding exists.

---

## 0.5) Historical Issue Patterns (Check First)

Before diving into the full review, **scan the diff for these recurring patterns** that have caused issues in past PRs (PR #58, #59). These are high-signal checks that often catch subtle bugs early.

### 0.5.1 State Machine Restart Logic

**What to look for:**
* Session/process restart or recovery code paths
* State reducers handling transitions from terminal states
* Fields tracking restart attempts, resume cursors, or recovery state

**Why it's a problem:**
* **Session ID collision** (B1): Reducer may reject valid restarts of terminal sessions if it doesn't distinguish "new session" from "resume session"
* **Missing state tracking fields** (B2): New fields like `resume_cursor` or `restart_attempt` may not be added to all relevant state structs
* **Monotonicity violation** (B3): Restart counters must be strictly increasing to prevent replay/confusion attacks

**How to verify:**
* Check that terminal state transitions explicitly handle restart scenarios
* Confirm new state fields are present in all state structs and all match arms
* Verify restart counter comparisons use strict inequality (`>` not `>=`)

### 0.5.2 Temp File Handling

**What to look for:**
* Uses of `std::env::temp_dir()` or direct `/tmp/` paths
* File creation with predictable names
* Missing cleanup on error paths or panics

**Why it's a problem:**
* **Predictable names** (A3): Allows symlink attacks or information disclosure via race conditions
* **World-readable permissions**: Default file creation may expose sensitive data (prompts, credentials, state)
* **Missing cleanup**: Temp files persist after crashes, leaking state or filling disk

**How to verify:**
* Confirm use of `tempfile::NamedTempFile` or equivalent which provides: unpredictable names, 0600 permissions, automatic cleanup
* Check for explicit cleanup in error handlers if manual temp files are used
* Verify no sensitive data is written to predictable paths

### 0.5.3 Shell/Process Spawning

**What to look for:**
* `Command::new()` calls with user-controlled or complex arguments
* Prompts or markdown passed as CLI arguments
* Environment variable inheritance or headless mode execution

**Why it's a problem:**
* **Argument escaping** (A2): Markdown content with backticks, quotes, or special chars breaks when passed as CLI args
* **Environment inheritance** (A1): Child processes may inherit sensitive env vars or conflicting config
* **Headless mode failures** (A1): Some tools filter capabilities in headless mode (e.g., no shell access)

**How to verify:**
* Complex strings (prompts, markdown) should be written to temp files and redirected via stdin
* Explicitly manage environment: clear or allowlist specific vars
* Test headless execution path if the code may run in CI or automated contexts

### 0.5.4 Struct Field Addition

**What to look for:**
* New fields added to structs that appear in `match` expressions
* Enums with new variants
* State objects with added tracking fields

**Why it's a problem:**
* **Incomplete pattern matches** (C1): Rust compiler may not catch all cases if patterns use `..` or default arms
* **Missing field handling**: New fields may not be initialized, compared, or serialized in all code paths

**How to verify:**
* Search for all `match` expressions on the modified struct/enum
* Confirm each arm explicitly handles or acknowledges the new field
* Check serialization, comparison, and clone implementations include the new field

---

## 1) Determine whether this PR is Security-Critical Path (SCP)

A PR is SCP if it **touches any** of the following areas (directly or by dependency):

### 1.1 Identity, keys, cryptography

* key generation, key storage, signing, verification
* canonicalization, hashing, “wire format” encoding/decoding

### 1.2 Network and IPC boundary

* HTTP/gRPC handlers, socket listeners, IPC servers/clients
* peer discovery, handshake, sync/replication endpoints
* any changes to egress / allowlists

### 1.3 Ledger / evidence / persistence boundary

* append-only logs, hash chains, signature chains
* replay logic, event ordering, cursor logic
* recovery logic after crash

### 1.4 Tool / command execution boundary

* any `Command` spawn, shelling out, plugin/provider interfaces
* filesystem writes outside a strictly controlled root
* environment inheritance

### 1.5 Gate and policy surfaces

* standards, schemas, lint policies, evidence requirements
* CI workflows and enforcement logic
* any change that alters what “passes” or “fails”
* security documentation under `documents/security/**` and `SECURITY.md` (policy surface)

**Record**: `SCP = YES/NO`. If YES, apply stricter severity and require a second pass after fixes.

---

## 2) Build the “Markov blanket” map for every touched boundary

For each externally influenced interface touched by this PR, write down:

1. **Inputs**

   * What untrusted data enters here? (bytes → parse → validate)
2. **Validation**

   * Where is validation performed? Is it strict? Are unknown fields rejected?
3. **Outputs / side effects**

   * What can this interface cause? (disk writes, network calls, tool invocation)
4. **Failure behavior**

   * How does it fail? Is it fail-closed? Are partial writes possible?
5. **Limits**

   * What are maximum sizes, depths, timeouts, rate limits?

**Stop condition**: If you cannot identify validation and limits for an untrusted input boundary, treat as **HIGH** severity at minimum.

---

## 3) Rust-specific security audit (diff-wide)

Perform these searches/inspections across the PR diff (and adjacent modules it affects).

### 3.1 Unsafe and FFI

* Any use of: `unsafe`, `extern`, raw pointers, `transmute`, `zeroed`, `MaybeUninit` patterns, FFI bindings.
* Requirements:

  * Unsafe must be **justified locally in code** (comment explains invariant).
  * Unsafe in SCP code is **CRITICAL** unless proven necessary and defended by tests.

### 3.2 Panics as denial-of-service

* Look for: `unwrap()`, `expect()`, `panic!()`, `todo!()`, `unreachable!()`
* In SCP paths, panics are usually **DoS vulnerabilities**.
* Required posture:

  * Replace with structured errors and fail-closed handling.
  * If truly unreachable, require a proof-by-construction explanation and a test that exercises the boundary.

### 3.3 Serialization and parsing pitfalls (Serde)

For any struct parsed from untrusted input (network/IPC/files/config):

* Prefer strict parsing:

  * reject unknown fields (e.g., `deny_unknown_fields` where appropriate)
  * avoid `serde(untagged)` and permissive enums at boundaries
  * avoid `flatten` on untrusted objects unless strictly required and guarded
* Ensure optional fields do not introduce fail-open behavior via defaults.

### 3.4 Integer and allocation hazards

* Look for casts, indexing, slicing, `Vec::with_capacity` from untrusted sizes.
* Require explicit bounds:

  * max message size
  * max ledger line size
  * max recursion depth
  * max batch sizes for sync

---

## 4) Concurrency and async correctness audit (DoS and corruption vectors)

### 4.1 Locking rules

* Identify locks (`Mutex`, `RwLock`, `DashMap`, etc.) in async contexts.
* **Block** on “lock held across `.await`” in SCP unless explicitly proven safe.

### 4.2 Cancellation safety

* Any function that writes durable state must be cancellation-safe:

  * no partial/half-written state that is later treated as valid
  * atomic write patterns for critical files
* If cancellation can corrupt state, treat as **HIGH**.

### 4.3 Unbounded task creation

* Identify any loops that spawn tasks based on untrusted input or peer messages.
* Require boundedness:

  * max concurrent tasks per peer
  * backpressure
  * timeouts
  * lease/budget gates if applicable

---

## 5) Protocol and wire semantics audit (holonic messaging)

### 5.1 Canonicalization and signing/hashing (critical)

If the PR touches signing, verification, hashing, canonicalization, or “wire format”:

* Verify canonicalization is deterministic and occurs **before** signing/hashing.
* Verify verification uses the exact canonical bytes.
* Look for ambiguity:

  * multiple encodings producing the same semantic object
  * field ordering differences
  * float/number normalization problems

### 5.2 Replay and downgrade

* If any message/command has security impact, check replay semantics:

  * Is there a monotonic cursor/sequence? A lease window? A nonce?
  * If no replay protection exists, the system must be explicitly safe under replay (rare).
* Check version negotiation:

  * no silent downgrade to weaker versions
  * explicit policy for minimum supported versions

### 5.3 Confusion attacks

* Ensure message types are unambiguously tagged and cannot be interpreted as another type.
* Ensure correlation IDs / routing fields cannot cause cross-thread privilege bleed.

---

## 6) Ledger and persistence audit (truth boundary)

### 6.1 Append-only integrity

* Ensure ledger writes do not rewrite history.
* Ensure events are ordered deterministically and replay is deterministic.

### 6.2 Partial write / crash recovery

* Confirm atomicity patterns for critical state:

  * write temp → fsync (where needed) → rename
* Ensure recovery fails closed on corruption:

  * do not “best effort continue” when integrity checks fail in SCP.

### 6.3 Log injection and evidence integrity

* Treat any data reflected into logs/ledger as untrusted:

  * guard against newline injection and misleading log formatting
  * avoid logging raw untrusted payloads in a way that confuses auditors

---

## 7) Filesystem, paths, and secrets

### 7.1 Path traversal and symlink races

* Any file read/write influenced by untrusted input must be:

  * normalized
  * constrained to an allowed root
  * protected against `..` traversal and symlink tricks where relevant

### 7.2 Permissions and secret leakage

* Secret material must never appear in logs.
* Key files must be created with restrictive permissions.
* Error paths must not dump sensitive internal state.

---

## 8) Gate preservation audit (self-degradation prevention)

If the PR touches any gate/policy surface (standards, evidence rules, CI enforcement):

* Treat as SCP automatically.
* Assume adversarial posture: gate weakening is suspicious by default.
* Require:

  * explicit binding ticket/requirement authorizing the change
  * evidence that detection power did not decrease (e.g., failure corpus still fails, or equivalent)
* **Block** if the PR makes checks easier to pass without compensating controls.

### 8.1 Security documentation strictness policy (extremely strict)

If the PR changes security documentation (including `documents/security/**` or `SECURITY.md`):

* Treat as SCP automatically.
* Classify the change as one of:
  * **STRICTNESS_DECREASE (LOOSENING)**: reduces requirements, allows bypasses, weakens gates, narrows threat model, or changes MUST/SHALL/REQUIRED into weaker language.
  * **STRICTNESS_INCREASE (TIGHTENING)**: introduces new requirements, new MUST/SHALL/REQUIRED language, new gates, or tighter acceptance criteria.
  * **CLARIFICATION**: wording/structure improvements that do not change requirements.

**Rules:**

* STRICTNESS_DECREASE:
  * **Block** unless there is an **approved human waiver** with an unexpired `waiver_id` (WVR-####) recorded in-repo and explicitly referenced by the PR.
  * The waiver record MUST conform to `documents/standards/schemas/05_waiver.schema.yaml#waiver_schema` and SHOULD be stored at `documents/work/waivers/WVR-####.yaml`.
  * The waiver MUST be unexpired, MUST include `AUTH_SECURITY` in `required_signoffs`, MUST have status `APPROVED`, and MUST include `evidence_ids[]` supporting the exception and mitigation plan.
  * The security reviewer MUST NOT author or modify the waiver record. If the waiver does not exist or is invalid/expired, block the PR.
* STRICTNESS_INCREASE:
  * Require a bound **RFC** that describes how the new strictness will be implemented as deterministic checks (tests, invariants, CI gates). If no RFC is referenced, raise a blocking finding requesting one.
  * Ensure the documentation includes a clear rationale aligned with the threat model and specifies what enforcement is expected.
* CLARIFICATION:
  * Allowed if it does not change requirements; still review for precision and non-ambiguity.

---

## 9) Dependency and supply chain audit (no local execution)

Without running commands, you can still do a meaningful audit:

* Inspect `Cargo.toml` and `Cargo.lock` diffs.
* For any new dependency or feature flag change:

  * Is the dependency necessary?
  * Are default features pulling in large/unnecessary surfaces?
  * Does it introduce build scripts (`build.rs`) or native components?
* Treat build scripts and proc-macros as elevated risk:

  * they execute code during build and can widen attack surface.

**Stop condition**: If the PR introduces a new dependency in an SCP area without clear justification and scoping, request changes.

---

## 11) Findings: severity rubric (simple and strict)

### CRITICAL (block merge)

* authn/authz bypass or trust confusion
* signature verification weakness / canonicalization ambiguity
* replay/downgrade enabling of security-relevant messages
* RCE/tool injection pathways
* secret exfiltration via logs/errors
* fail-open behavior in SCP

### HIGH (block unless explicitly waived)

* DoS vectors in SCP (panic on untrusted input, unbounded loops/spawns, missing limits)
* corruption recovery that proceeds instead of fail-stop
* widened network/egress without strict allowlists and explicit policy

### MEDIUM (request changes)

* missing strict parsing/unknown field rejection on untrusted objects
* missing boundedness/timeouts on non-critical but exposed surfaces
* missing negative tests for newly introduced parsing/verification logic

### LOW (non-blocking if scoped)

* non-SCP hygiene issues that do not change security posture
* refactors with no boundary change (still must not weaken gates)

---

## 12) Required output: Security Review Notes (what you must leave on the PR)

Your review must be auditable and actionable. Post a comment containing:

1. `SCP = YES/NO` and why
2. Boundaries reviewed (network/IPC, ledger, tool exec, etc.)
3. Findings table with:

   * severity
   * file/path + exact concern
   * required remediation
   * required proof (what code/test/doc/policy change will demonstrate the fix)

Avoid vague guidance. Every finding must come with a concrete “how to prove fixed” statement.

---

## 13) Re-audit rule (mandatory for SCP)

If SCP = YES and changes were made in response to findings:

* Perform a second pass focusing only on:

  * the remediations
  * whether they introduced new attack surface
  * whether they added deterministic checks / negative tests
* Only then approve.

---

## 14) Anti-bureaucracy rule (non-negotiable)

When you find a class of issue:

* Do **not** propose adding review steps.
* Propose:

  * a stricter parser
  * explicit limits/timeouts
  * a deterministic test / invariant / negative case
  * a policy default that fails closed
  * or an attack-surface reduction

This is how security improvements compound without destroying throughput.

---

## 15) Required Actions (comment + status)

**CRITICAL: If you skip this step, the PR will be permanently blocked from merging—no code can ship without the `ai-review/security` status being set.**

After completing your review, you MUST ensure:

1. A security review comment exists on the PR with your full findings and required remediations.
2. The `ai-review/security` status check is updated.

### 15.1 If the review PASSED (no CRITICAL or HIGH findings)

Post your review as a PR comment (because `approve` does NOT leave a comment):

```bash
gh pr comment $PR_URL --body "$(cat <<'EOF'
## Security Review

[Your full review here, including SCP status, boundaries reviewed, findings table, and required remediations]
EOF
)"
```

Then update the status check:

```bash
cargo xtask security-review-exec approve $PR_URL
```

### 15.2 If the review FAILED (any CRITICAL or HIGH findings)

Do NOT post a separate `gh pr comment`. Instead, fold your full review comment into `--reason` because `deny` posts a comment:

```bash
cargo xtask security-review-exec deny $PR_URL --reason "$(cat <<'EOF'
## Security Review

[Your full review here, including SCP status, boundaries reviewed, findings table, and required remediations]
EOF
)"
```

Use `--dry-run` to preview the actions without making API calls.


## 16.0 Complete

Thank you for your thorough analysis and review and hard work! You are all done now, no summary necessary. Output only "Done" and yield.
