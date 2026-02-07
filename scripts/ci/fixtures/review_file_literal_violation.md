# This is a fixture file simulating a review artifact that contains
# the ai-review/security literal in non-comment code.
# It should be REJECTED by the primary gate check.

## Steps
1. Assign the context variable:
ctx="ai-review/security"
2. Then later call gh api "$endpoint" -f context="$ctx"
