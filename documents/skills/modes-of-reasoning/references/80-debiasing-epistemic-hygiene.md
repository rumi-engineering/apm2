# Debiasing / Epistemic Hygiene Reasoning

**Category:** Meta-Level and Reflective Modes

## What it is

A meta-discipline applying specific checks *before* committing to conclusions: base-rate anchoring, alternative-hypothesis generation, premortem analysis, and active disconfirmation search. Not a new inference pattern—a **constraint layer** that intercepts and stress-tests outputs from other reasoning modes.

Debiasing treats your own cognition as an unreliable instrument that produces predictable errors. Just as a scientist calibrates a thermometer, you calibrate your judgment by systematically checking for known failure modes.

Key characteristics:
- **Meta-level:** Operates on outputs from other reasoning modes, not directly on problems
- **Preventive:** Applied *before* commitment, not as post-hoc rationalization
- **Specific:** Targets named biases with concrete countermeasures (not vague "think harder")
- **Lightweight:** 10-15 minutes, not a research project—overhead that pays for itself

## What it outputs

| Artifact | Description | Produced by step |
|----------|-------------|------------------|
| **Base-rate anchor** | Reference-class frequency before inside-view adjustment | Step 1 |
| **Alternative-hypothesis list** | ≥3 competing explanations with relative plausibility | Step 2 |
| **Premortem report** | "Assume we failed—why?" with top 3 causes and addressability | Step 3 |
| **Disconfirmation tests** | Specific observations that would falsify the favored view | Step 4 |
| **Bias audit log** | Named biases checked with pass/flag status + rationale | Step 5 |
| **Residual uncertainty statement** | What remains uncertain and why | Step 6 |

## Procedure (decision steps)

1. **Anchor on base rate** — Before analyzing specifics, ask: "What's the reference-class frequency for outcomes like this?" Write it down.
   - Find a relevant reference class (similar projects, decisions, predictions)
   - Look up or estimate the base rate of success/failure in that class
   - *Test:* If you had no inside information, what would you predict based on base rate alone?
   - *Output:* "Base rate: X% of [reference class] achieve [outcome]."

2. **Generate alternatives** — List ≥3 hypotheses/options that could explain the same evidence or achieve the same goal. Assign rough plausibility to each.
   - Include at least one "boring" alternative (status quo, coincidence, simpler explanation)
   - Include at least one alternative favored by someone who disagrees with you
   - *Test:* Would a reasonable skeptic accept these as genuine alternatives, not strawmen?
   - *Output:* Numbered list with plausibility estimates (high/medium/low or %).

3. **Run premortem** — Assume the decision failed. Brainstorm top 3 reasons it could fail. Identify which are addressable now.
   - Mentally travel to the future where this decision led to a bad outcome
   - Ask: "What went wrong?" without anchoring on your current optimism
   - Categorize causes: (a) controllable now, (b) observable later (early warning), (c) uncontrollable
   - *Test:* Do the failure causes feel uncomfortably plausible?
   - *Output:* Ranked failure causes with addressability status.

4. **Seek disconfirmation** — For your favored conclusion, specify 2–3 observations that would change your mind. Actively look for them.
   - What evidence would make you abandon this conclusion?
   - What evidence would shift probability significantly (not just marginally)?
   - *Test:* Have you actually searched for disconfirming evidence, or just specified it?
   - *Output:* Written disconfirmation criteria + search results.

5. **Audit for specific biases** — Check the judgment against the most common cognitive biases:

   | Bias | Detection question | Countermeasure |
   |------|-------------------|----------------|
   | **Anchoring** | Did I adjust enough from my first estimate or first piece of information? | Re-estimate from scratch without looking at original; compare |
   | **Availability** | Am I overweighting recent, vivid, or emotionally charged examples? | Seek statistical data over anecdotes |
   | **Confirmation** | Did I search for evidence that supports my view more than evidence against? | Explicitly search for disconfirming evidence (step 4) |
   | **Overconfidence** | Would I bet at the odds implied by my confidence? | Estimate confidence interval; check calibration history |
   | **Planning fallacy** | Is my timeline/cost estimate based on inside view without reference class? | Use base rate (step 1); add buffer for unknown unknowns |
   | **Sunk cost** | Am I continuing because of past investment rather than future value? | Evaluate as if starting fresh today |
   | **Hindsight** | (Post-hoc) Did the outcome seem "obvious" only after I knew it? | Record predictions before outcomes; compare |
   | **Authority** | Am I deferring because of status rather than expertise? | Evaluate argument quality independent of source |
   | **Groupthink** | Did we converge too quickly? Are dissenters silent? | Elicit individual views before group discussion |

   - *Test:* For each bias, can you explain why it doesn't apply, or flag it if it might?
   - *Output:* Bias audit log with pass/flag status.

6. **Document residual uncertainty** — Record what you're still uncertain about and why. This prevents false confidence and creates an audit trail.
   - What would you want to know but can't determine now?
   - What assumptions are you making that could be wrong?
   - *Output:* Written uncertainty statement.

7. **Check cognitive load (meta-check)** — If rushed, tired, or emotionally invested, flag the judgment as provisional and schedule re-evaluation.
   - *Triggers:* Time pressure, sleep deprivation, personal stake in outcome, strong emotional reaction
   - *Output:* Provisional flag + scheduled re-evaluation date, or cleared for commitment.

## Quick checklist (pre-decision gate)

- [ ] Base rate written before inside-view analysis
- [ ] ≥3 alternative hypotheses/options listed (including "boring" and "dissenter" alternatives)
- [ ] Premortem completed (top 3 failure causes with addressability)
- [ ] ≥2 disconfirming observations specified and searched for
- [ ] Anchoring / availability / confirmation / overconfidence explicitly checked
- [ ] Sunk cost and planning fallacy checked (if relevant)
- [ ] Residual uncertainty documented
- [ ] Cognitive-load flag set if impaired conditions

## Micro-example

**Situation:** Team proposes a new caching layer to fix performance.

| Step | Action | Output |
|------|--------|--------|
| 1. Base rate | "What % of caching projects actually solve the performance problem?" → Search past incidents: ~40% of caching additions hit root cause | Base rate: 40% |
| 2. Alternatives | (a) Caching helps (team favorite), (b) N+1 query is real bottleneck (DBA's view), (c) GC pauses dominate, (d) Network latency | 4 alternatives; (b) rated "high plausibility" |
| 3. Premortem | "Cache deployed, latency unchanged—why?" → Didn't profile first (addressable); cache hit rate low (observable); cached wrong layer (addressable) | Top causes: profiling gap, hit rate |
| 4. Disconfirmation | Profile shows cache-relevant queries are <20% of latency → abandon caching; N+1 pattern visible in traces → pursue (b) | Searched: profile data needed |
| 5. Bias audit | Anchoring: team anchored on "caching worked before" → FLAG. Availability: recent success story → FLAG. Confirmation: only searched for cache-friendly patterns → FLAG | 3 flags raised |
| 6. Residual uncertainty | "We don't know actual cache hit rate without prototype; we haven't profiled at scale" | Uncertainty documented |
| 7. Decision | Profile first before committing to caching; revisit after profiling data | Provisional; re-evaluate in 1 week |

**Outcome:** Profiling revealed N+1 query pattern causing 60% of latency. Caching would have been wasted effort.

## How it differs

| Mode | Debiasing differs because... |
|------|------------------------------|
| [Meta-reasoning](75-meta-reasoning.md) | Meta-reasoning selects *which* mode to use; debiasing audits *any* mode's output for predictable errors. Meta-reasoning is upstream (mode selection); debiasing is downstream (output validation). |
| [Calibration](76-calibration-epistemic-humility.md) | Calibration measures accuracy over many judgments (long-run feedback); debiasing applies corrective checks to a single judgment (pre-decision intervention). Calibration tells you *how wrong you tend to be*; debiasing helps you *be less wrong this time*. |
| [Red-teaming](79-adversarial-red-team.md) | Red-teaming assumes an external adversary attacking your system; debiasing assumes your own cognition is the adversary. Red-teaming is about external threats; debiasing is about internal errors. |
| [Heuristic reasoning](53-heuristic.md) | Heuristics are the System 1 shortcuts that produce biases; debiasing is the System 2 audit that catches them. Heuristics are fast and often wrong; debiasing is slow and corrective. |
| [Reflective equilibrium](77-reflective-equilibrium.md) | Reflective equilibrium seeks coherence among beliefs, principles, and judgments. Debiasing seeks accuracy by checking for known error patterns. Equilibrium is about internal consistency; debiasing is about external validity. |
| [Abductive reasoning](13-abductive.md) | Abduction generates hypotheses; debiasing checks whether you're favoring a hypothesis for bad reasons (story bias, confirmation). Debiasing applies *to* abductive outputs. |

**Common confusions:**

1. *Debiasing vs. calibration:* Calibration tracks long-run accuracy ("my 80% predictions come true 80% of the time"); debiasing intervenes on a single decision ("am I anchoring on the first estimate?"). You can be well-calibrated on average but still need debiasing on any specific high-stakes call. Calibration is retrospective feedback; debiasing is prospective intervention.

2. *Debiasing vs. red-teaming:* Red-teaming asks "how would an attacker break this?" Debiasing asks "how is my own reasoning broken?" Both are adversarial, but the threat model differs: red-teaming defends against external adversaries; debiasing defends against your own cognitive shortcuts. A system can pass red-teaming but fail debiasing (sound design, biased evaluation).

3. *Debiasing vs. critical thinking:* "Critical thinking" is vague; debiasing is specific. Debiasing names particular biases (anchoring, availability, confirmation) and applies particular countermeasures (base rates, premortem, disconfirmation search). Telling someone to "think critically" is unhelpful; telling them to "check for anchoring by re-estimating from scratch" is actionable.

4. *Debiasing vs. skepticism:* Skepticism doubts everything; debiasing doubts systematically. Debiasing doesn't say "doubt your conclusion"—it says "check whether your conclusion is contaminated by these specific, predictable error patterns." The goal is accurate belief, not paralysis.

## Best for

- **High-stakes one-shot decisions** — where you can't rely on averaging over many trials
- **Forecasting and estimation** — where base-rate neglect and overconfidence dominate errors
- **Incident postmortems** — where hindsight bias distorts root-cause analysis
- **Investment / resource allocation** — where confirmation bias anchors on early signals
- **Leadership reviews** — where authority gradients suppress disconfirmation
- **Hiring decisions** — where availability bias (recent candidates) and halo effects distort
- **Strategic planning** — where planning fallacy and inside-view optimism dominate
- **Performance reviews** — where recency bias and halo/horn effects corrupt evaluation
- **Technical design reviews** — where anchoring on first proposal suppresses alternatives

## Common failure mode

**Ritualized checklists that don't change conclusions.** Going through the motions—writing "base rate: N/A" or "alternatives: none convincing"—without genuine consideration. The form is completed, but the cognition is unchanged.

### Detection signals

- Checklist items are copy-pasted from previous decisions
- Alternative hypotheses are strawmen dismissed in one sentence
- Premortem lists only external/uncontrollable causes
- No decision was ever reversed or modified by the checklist
- Same person always plays devil's advocate (role has become theatrical)
- Base rate is always "N/A" or "not applicable to our situation"
- Disconfirming evidence is "searched for" but never found
- The debiasing step takes <2 minutes on high-stakes decisions
- People treat debiasing as bureaucratic overhead rather than cognitive hygiene

### Mitigations

1. **Require at least one judgment change per quarter** — Track whether debiasing ever shifted a decision. If never, the process is theatrical.
   - *Test:* In the last 10 decisions, how many were modified by debiasing?

2. **Rotate devil's advocate** — Assign someone to argue for the second-best alternative; rotate the role so it's not always the same skeptic.
   - *Test:* Who argued the dissenting view last time? Is it always the same person?

3. **Blind elicitation** — Collect individual base-rate estimates and confidence levels before group discussion to prevent anchoring on the first speaker.
   - *Test:* Did everyone submit estimates before seeing others' views?

4. **Time-box but enforce** — Debiasing should take 10–15 min, not 2 hours—but those 10 min must happen before commitment, not after.
   - *Test:* When in the decision process did debiasing occur?

5. **Spot-audit checklist quality** — Periodically review completed checklists: Are alternatives genuine? Are base rates researched? Are disconfirmation criteria specific?
   - *Test:* Could a skeptical reviewer distinguish real debiasing from box-checking?

6. **Make debiasing high-status** — Reward catching biases, not just reaching conclusions. Celebrate when debiasing changes a decision ("we almost made a bad call but caught it").
   - *Test:* Is it career-safe to flag a bias in a senior person's reasoning?

7. **Use prediction tracking** — Log predictions with confidence levels; compare to outcomes. This provides feedback on whether debiasing is improving accuracy.
   - *Test:* Do you have a record of past predictions and outcomes?

## Anti-patterns to avoid

| Anti-pattern | What it looks like | Fix |
|--------------|-------------------|-----|
| **Checkbox debiasing** | Form completed, cognition unchanged | Require specific, non-copy-paste entries |
| **Strawman alternatives** | "Alternatives: (a) our plan, (b) do nothing stupid, (c) crazy idea" | Require at least one alternative a reasonable skeptic would endorse |
| **Retroactive premortem** | Premortem done after commitment, to document "due diligence" | Enforce premortem before decision meeting |
| **Universal N/A** | Base rate marked "N/A—our situation is unique" | Require reference class even if imperfect; "unique" is rarely true |
| **Bias theater** | Long discussion of biases with no concrete countermeasure | Each flagged bias must have a specific corrective action |
| **Solo debiasing** | Individual thinks they've debiased themselves | External check: share with someone who will challenge |

## Related modes

- [Heuristic reasoning](53-heuristic.md) — the System 1 shortcuts debiasing corrects
- [Calibration and epistemic humility](76-calibration-epistemic-humility.md) — long-run accuracy tracking that validates debiasing effectiveness
- [Adversarial / red-team reasoning](79-adversarial-red-team.md) — structured external criticism (vs. debiasing's internal audit)
- [Meta-reasoning](75-meta-reasoning.md) — choosing reasoning modes (debiasing audits their outputs)
- [Reference-class forecasting](18-reference-class-outside-view.md) — base-rate anchoring technique used in step 1
- [Abductive reasoning](13-abductive.md) — hypothesis generation that benefits from debiasing checks
- [Decision-theoretic reasoning](45-decision-theoretic.md) — expected-value calculations that need bias audits on probability and utility estimates
- [Reflective equilibrium](77-reflective-equilibrium.md) — coherence-seeking (vs. debiasing's error-checking)
