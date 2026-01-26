# Search-Based / Algorithmic Reasoning

**Category:** Practical Reasoning

## What it is

Systematically explore possibilities (tree search, dynamic programming), guided by heuristics and pruning.

## What it outputs

- Candidate solutions
- Best-found solutions
- Sometimes optimality proofs
- Explored search space

## How it differs

Computational method that can realize planning, proof, or optimization. The reasoning is in the search strategy.

## Best for

- Large combinatorial spaces
- Automated reasoning
- "Try options" problems
- Game playing
- Route planning

## Common failure mode

Search blowup without good heuristics/structure. Exponential spaces require smart pruning.

## Related modes

- [Planning / policy reasoning](47-planning-policy.md) — search for plans
- [Optimization reasoning](48-optimization.md) — search for optima
- [Constraint / satisfiability reasoning](06-constraint-satisfiability.md) — search for satisfying assignments
