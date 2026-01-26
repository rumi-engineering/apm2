## 1. Epistemic Vulnerabilities

The current `ANGLE_PROMPTS.md` contains prompts that are susceptible to "lazy" LLM responses (compliance without reasoning).

*   **Vulnerability A: The "Yes-Man" Check (Customer Value)**
    *   *Current Prompt:* "Is the customer segment specific enough to identify real users?"
    *   *Failure Mode:* A lazy agent sees "Developers" and answers "Yes".
    *   *Fix:* Require the agent to "Identify the specific exclusion criteria. Who is *not* a customer?" If the exclusion set is empty or generic, the segment is invalid.

*   **Vulnerability B: The Checklist Illusion (Implementation Risk)**
    *   *Current Prompt:* "Are external dependencies explicitly called out with fallback strategies?"
    *   *Failure Mode:* Agent checks for the *presence* of a list, not the *causal validity* of the fallback.
    *   *Fix:* Require "Failure Mode Simulation". "Trace the execution path if Dependency X returns 503. Does the system enter a defined state or an undefined state?"

*   **Vulnerability C: The "Best of Both Worlds" Fallacy (Tradeoff Analysis)**
    *   *Current Prompt:* "What was optimized...?"
    *   *Failure Mode:* Agent accepts "We optimized everything" (Naive Optimization).
    *   *Fix:* Force a "Zero-Sum Proof". "Identify the metric that was *degraded* to achieve this optimization. If no metric is degraded, prove why this is a Pareto improvement and not a trade-off."

## 2. Process Bottlenecks

*   **Bottleneck A: The "Alert Fatigue" of 8-Angle Review**
    *   *Analysis:* `GATE-PRD-CONTENT` mandates 8 angles for *every* review. For minor iterations or low-risk features, this burns tokens and time, encouraging users to bypass the tool or ignore the massive output.
    *   *Impact:* High latency -> User friction -> "Shadow IT" (manual reviews).

*   **Bottleneck B: Broken Feedback Loop (LOOP-TICKET)**
    *   *Analysis:* `LOOP-TICKET` relies on engineers voluntarily filing a "Deviation Report" after ticket completion.
    *   *Why it breaks:* "Waste is Sin". Engineers will close the ticket and move on. The feedback signal is high-friction and low-reward for the individual.
    *   *Fix:* Replace voluntary reporting with **Variance Triggering**. If `actual_effort > 1.5 * estimated_effort`, automatically schedule a "Retrospective" task for the `prd-review` agent to analyze the diff between PRD and Code.

## 3. Proposed Amendments

### Amendment A: Diff for `ANGLE_PROMPTS.md` (Deepening the Reasoning)

```markdown
<<<<
## TRADEOFF_ANALYSIS

**Focus:** What was optimized, what was sacrificed, and is the choice justified?

### Evaluation Questions

1. What was optimized (Speed, Consistency, Availability, Cost)?
2. What was sacrificed to achieve that optimization? (If nothing, look harder).
3. Is the sacrifice acceptable given the business constraints?
4. **Pareto Check:** Are we on the efficient frontier, or just picking a bad point?
5. Why was the alternative rejected?
====
## TRADEOFF_ANALYSIS

**Focus:** What was optimized, what was sacrificed, and is the choice justified?

### Evaluation Questions

1. **The Zero-Sum Test:** Identify the specific metric that was *degraded* to achieve the stated benefit. (e.g., "Increased memory usage to reduce CPU latency"). If the PRD claims "no downsides," flag as `NAIVE_OPTIMIZATION` unless a genuine Pareto improvement is proven.
2. **Constraint Boundary:** Does the design push a variable (e.g., latency, consistency) to its theoretical limit? If so, verify the *cost function* of that limit.
3. **The "Why Not" Inversion:** Why was the obvious alternative *rejected*? (e.g., "Why not use the existing slower system?"). If the rejection reason is "it's old" rather than "it violates Constraint X," flag as `SPEC_DEFECT`.
4. **Pareto Check:** Are we moving *along* the curve (tradeoff) or *shifting* the curve (innovation)? Evidence required.
>>>>
```

```markdown
<<<<
## SYSTEM_DYNAMICS

**Focus:** Feedback loops, delays, and second-order effects on the ecosystem.

### Evaluation Questions

1. Does the feature create a reinforcing loop? (e.g., auto-scaling triggered by load -> more connections -> more load).
2. Are there time delays that could cause oscillation?
3. How does this affect the shared resource budget of the Holarchy?
4. What happens if every agent does this simultaneously?
====
## SYSTEM_DYNAMICS

**Focus:** Feedback loops, delays, and second-order effects on the ecosystem.

### Evaluation Questions

1. **Loop Simulation:** Simulate the system state at t+1, t+10, and t+100 iterations. Does the state variable (e.g., queue length, retry count) converge to a constant or diverge?
2. **The "Thundering Herd" Check:** If all clients trigger this logic simultaneously (e.g., after a restart), what is the peak resource demand?
3. ** Tragedy of the Commons:** Does this feature consume a shared resource (bandwidth, pool connections) without a global quota?
4. **Oscillation Risk:** Is there a delay between *measurement* and *actuation*? (e.g., scaling based on 5-minute old metrics).
>>>>
```

### Amendment B: Diff for `SKILL.md` (Optimizing the Flow)

```markdown
<<<<
## Gate Order (Invariant)

Gate ordering is fixed:

1. TRUSTED: `GATE-PRD-SCHEMA`
2. TRUSTED: `GATE-PRD-LINT`
3. DETERMINISTIC: `GATE-PRD-TRACEABILITY`
4. DETERMINISTIC: `GATE-PRD-QUALITY-COVERAGE`
5. DETERMINISTIC: `GATE-PRD-EVIDENCE-STANDARDS`
6. LLM-ASSISTED: `GATE-PRD-CONTENT` (multi-angle)
====
## Gate Order (Invariant)

Gate ordering is fixed:

1. TRUSTED: `GATE-PRD-SCHEMA`
2. TRUSTED: `GATE-PRD-LINT`
3. DETERMINISTIC: `GATE-PRD-TRACEABILITY`
4. DETERMINISTIC: `GATE-PRD-QUALITY-COVERAGE`
5. DETERMINISTIC: `GATE-PRD-EVIDENCE-STANDARDS`
6. LLM-ASSISTED: `GATE-PRD-CONTENT` (Variable Depth)

## Review Depth Selection

The `GATE-PRD-CONTENT` depth is determined by the `review_depth` argument or PRD metadata:

- **LIGHT** (Default for draft/minor): Runs `VERIFIABILITY`, `TECHNICAL_FEASIBILITY`, `CUSTOMER_VALUE`.
- **STANDARD** (Required for Approval): Runs all 8 required angles.
- **DEEP** (High Risk): Runs all 10 angles + `SECURITY_POSTURE` deep dive.
>>>>
```

## 4. The "Anti-Fragile" Vision

This skill becomes anti-fragile when it stops being a "Gate" (a static hurdle) and becomes a "Gym" (a strengthening process). By introducing **Variance-Triggered Feedback**, the system learns from its own prediction errors. If a PRD passes review but the resulting code requires 2x the estimated effort, the `prd-review` skill should treat that as a "Review Failure" event, ingest the diff, and update its own `IMPLEMENTATION_RISK` prompts to catch that specific blind spot next time. The skill thus gains "muscle" from every missed estimate, turning waste (variance) into structural asset (better prompts).
