# Reference-Class / "Outside View" Reasoning

**Category:** Ampliative Reasoning

## What it is

Predict by comparing to a base rate distribution of similar past cases ("what usually happens to projects like this?") rather than analyzing the specific case from the inside ("what will happen to *this* project given its details?").

The core move: Before constructing a detailed inside-view estimate, anchor on the historical frequency for a reference class of comparable cases. Then adjust from that anchor only with explicit justification.

Reference-class forecasting is the primary antidote to the **planning fallacy**—the systematic tendency to underestimate time, cost, and risk when planning from the inside view. It's grounded in Kahneman and Tversky's research showing that inside-view predictions are consistently overconfident, while outside-view predictions are better calibrated.

Key insight: Your project feels unique, but statistically it's probably much like others in its reference class. Start with what typically happens, then adjust.

## What it outputs

| Artifact | Description | Produced by step |
|----------|-------------|------------------|
| **Reference class definition** | Category of similar past cases with inclusion/exclusion criteria | Step 1 |
| **Base rate distribution** | Historical outcomes for the reference class (mean, median, spread, failure rate) | Step 2 |
| **Similarity assessment** | How this case compares to the reference class (better/worse/typical on key factors) | Step 3 |
| **Adjustment rationale** | Explicit reasons for deviating from base rate, with direction and magnitude | Step 4 |
| **Final forecast** | Estimate anchored on base rate with documented adjustments | Step 5 |

## Procedure (decision steps)

1. **Define the reference class** — What category of past cases is this instance a member of? Be specific enough to be relevant but broad enough to have adequate data.
   - *Too broad:* "software projects" (includes everything from scripts to operating systems)
   - *Too narrow:* "our team's React projects started in Q4" (too few cases for reliable statistics)
   - *Just right:* "web application rewrites at companies our size" or "FDA approval processes for medical devices in this category"
   - *Test:* Do you have ≥10 cases in this class? If not, broaden. Do the cases share key structural features with yours? If not, narrow.
   - *Output:* "Reference class: [definition]. Inclusion criteria: [X, Y]. Exclusion criteria: [Z]."

2. **Gather base rate statistics** — What actually happened to cases in this reference class?
   - Collect: mean, median, standard deviation, range, failure/success rate
   - *Sources:* Internal historical data, industry benchmarks, academic studies, public datasets
   - *Test:* Are you using actual outcomes, not planned outcomes? (Planned timelines ≠ actual timelines)
   - *Output:* "Base rate: median = X, mean = Y, SD = Z, failure rate = W%"

3. **Assess similarity to reference class** — How typical is your case? Rate on key factors:
   - Factors that make outcomes better: experienced team, proven technology, smaller scope, strong sponsor
   - Factors that make outcomes worse: novel technology, larger scope, external dependencies, regulatory complexity
   - *Test:* Would an outside observer rate your case as above-average, average, or below-average for this class?
   - *Output:* "Similarity: [above/at/below] average. Key factors: [list with direction]."

4. **Adjust from base rate with justification** — Only deviate from the base rate if you have specific, defensible reasons.
   - **Conservative adjustment rule:** Adjust by no more than 25% unless you have strong evidence. Most "unique" factors don't justify large deviations.
   - **Regression to the mean:** If past performance was extreme, expect future performance to be closer to average.
   - *Test:* Would a skeptical outsider accept your adjustment? If "we have a great team" is your main reason, that's weak—everyone thinks their team is great.
   - *Output:* "Adjustment: +/- X% because [specific reason]. Final estimate: [value]."

5. **Document uncertainty and conditions** — State the range and what would change your estimate.
   - Provide a range (e.g., 80% confidence interval), not a point estimate
   - List conditions that would push toward high or low end
   - *Output:* "80% CI: [low] to [high]. Would revise toward high if [condition]; toward low if [condition]."

## Quick checklist

- [ ] Reference class defined with inclusion/exclusion criteria
- [ ] Base rate statistics gathered from actual outcomes (not plans)
- [ ] ≥10 cases in reference class (or noted as limited data)
- [ ] Similarity to reference class assessed (above/at/below average)
- [ ] Adjustments justified with specific reasons (not "we're special")
- [ ] Total adjustment ≤25% unless strongly justified
- [ ] Uncertainty range provided, not just point estimate
- [ ] Inside-view estimate compared to outside-view estimate

## Micro-example

**Situation:** Estimate time to complete a backend API rewrite.

| Step | Action | Output |
|------|--------|--------|
| 1. Reference class | "Backend API rewrites at mid-size tech companies (50-500 engineers)" | Defined class |
| 2. Base rate | Industry data: median = 9 months, mean = 12 months, SD = 6 months, 30% exceed 18 months | Base rate: 9-12 months |
| 3. Similarity | Team: experienced (+), Tech: familiar framework (+), Scope: larger than typical (-), Dependencies: external API integrations (-) | Net: slightly below average |
| 4. Adjustment | Base 12 months + 15% for scope/dependencies = ~14 months. (Not adjusting down for team—everyone thinks their team is good.) | Adjusted: 14 months |
| 5. Uncertainty | 80% CI: 10-20 months. Would push higher if external API changes; lower if scope is cut. | Range documented |

**Compare:** Inside-view estimate from team was 6 months. Outside-view estimate is 14 months. History suggests the outside view is more likely correct.

## How it differs

| Mode | Reference-class reasoning differs because... |
|------|---------------------------------------------|
| [Inductive reasoning](09-inductive.md) | Induction generalizes from observations to patterns. Reference-class reasoning applies a known base rate to a specific case. Induction builds the pattern; reference-class uses it. |
| [Case-based reasoning](15-case-based.md) | Case-based reasoning retrieves specific similar cases and adapts their solutions. Reference-class reasoning uses the *statistical distribution* of many cases, not individual case details. Case-based asks "what did similar cases do?"; reference-class asks "what happened to similar cases overall?" |
| [Bayesian reasoning](11-bayesian-probabilistic.md) | Bayesian reasoning updates beliefs with evidence using Bayes' theorem. Reference-class forecasting provides the *prior* (base rate) that Bayesian reasoning starts from. They're complementary: reference-class sets the anchor, Bayesian updates from it. |
| [Analogical reasoning](14-analogical.md) | Analogical reasoning maps structure from a source case to a target case. Reference-class reasoning doesn't map structure—it applies statistical regularities. Analogies can mislead when surface similarity doesn't imply deep similarity; base rates are more robust. |
| [Decision-theoretic reasoning](45-decision-theoretic.md) | Decision theory combines probabilities with utilities to choose actions. Reference-class reasoning provides better probability estimates for decision theory to use. It improves the inputs to decision theory. |

**Common confusions:**

1. *Reference-class vs. inside-view:* Inside-view analyzes specific case details to build up an estimate. Reference-class starts with what typically happens and adjusts. Both produce estimates; reference-class is usually more accurate because it's less susceptible to optimism and uniqueness bias.

2. *Reference-class vs. precedent:* Precedent says "X happened before, so X will happen again." Reference-class says "in cases like this, the distribution of outcomes is D, so expect something from D." Precedent is a single case; reference-class is a distribution.

3. *Reference-class as pessimism:* Reference-class forecasting isn't pessimistic—it's realistic. If the base rate shows 80% success, you should expect success. The point is anchoring on data, not assuming the worst.

## Best for

- **Project timelines** — most projects take longer than planned; base rates correct optimism
- **Budgets and cost estimation** — cost overruns are the norm; anchor on actual past costs
- **Risk forecasting** — failure rates are often higher than insiders expect
- **Portfolio-level planning** — across many projects, base rates dominate individual adjustments
- **Debiasing optimistic estimates** — when inside-view estimates seem too good to be true
- **Startup success rates** — founders are systematically overconfident; industry base rates correct
- **Medical prognosis** — survival rates by diagnosis provide anchors for individual cases
- **Legal case outcomes** — historical verdict distributions inform case evaluation

## Common failure mode

**Choosing the wrong reference class:** Too broad obscures relevant variation; too narrow leaves insufficient data. The forecast is only as good as the comparison group.

### Detection signals

- Reference class is chosen to support a desired conclusion (cherry-picking)
- Class is so narrow there are only 2-3 cases (insufficient for statistics)
- Class is so broad it includes obviously dissimilar cases
- Key structural differences between your case and the class are ignored
- You can't find data on actual outcomes (only planned outcomes)
- The reference class keeps shifting as new information arrives

### Mitigations

1. **Define the reference class before seeing the data** — Pick your comparison group based on structural similarity, not based on which class gives the answer you want.
   - *Test:* Did you define the class before or after looking at base rates?

2. **Use multiple reference classes** — If uncertain, gather base rates from several plausible classes (narrower and broader) and see if they converge.
   - *Test:* What do adjacent reference classes suggest?

3. **Require minimum sample size** — Don't use a reference class with fewer than 10 cases. With small samples, one outlier skews the statistics.
   - *Test:* How many cases are in your reference class?

4. **Distinguish actual vs. planned outcomes** — Historical *plans* are biased; historical *actuals* are not. Use outcome data, not intention data.
   - *Test:* Are you using what actually happened or what was supposed to happen?

5. **Explicit similarity scoring** — Rate your case on key factors vs. the reference class. Don't just assert "we're different"—quantify how different.
   - *Test:* On which specific factors is your case above/below average?

6. **Cap adjustments by default** — Unless you have strong evidence, limit adjustments to ±25%. Large adjustments usually reflect inside-view optimism creeping back.
   - *Test:* If your total adjustment exceeds 25%, what's the specific evidence?

## Anti-patterns to avoid

| Anti-pattern | What it looks like | Fix |
|--------------|-------------------|-----|
| **Uniqueness bias** | "Our situation is different" without specific factors | Require explicit factor-by-factor comparison |
| **Class shopping** | Trying multiple classes until one supports the desired estimate | Pre-commit to class definition before seeing data |
| **Ignoring base rates** | Going straight to inside-view analysis | Force base-rate step before any detail analysis |
| **Fake precision** | "Historical average is 8.3 months, so we'll take 8.3 months" | Use ranges; account for variance |
| **Success bias** | Reference class includes only successful cases | Include failures; track failure rate |
| **Planning data as outcomes** | "Past projects planned for 6 months" (but took 12) | Use actual durations, not planned durations |

## Related modes

- [Case-based reasoning](15-case-based.md) — retrieves specific cases rather than base rates
- [Bayesian probabilistic reasoning](11-bayesian-probabilistic.md) — base rates serve as priors for Bayesian updating
- [Calibration and epistemic humility](76-calibration-epistemic-humility.md) — tracks forecast accuracy over time
- [Debiasing / epistemic hygiene](80-debiasing-epistemic-hygiene.md) — reference-class is a debiasing technique
- [Inductive reasoning](09-inductive.md) — generalization that produces base rates
- [Fermi / order-of-magnitude reasoning](19-fermi-order-of-magnitude.md) — approximate estimation (reference-class is more precise)
- [Statistical reasoning (frequentist)](10-statistical-frequentist.md) — formal treatment of base rate inference
