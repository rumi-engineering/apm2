# This is a fixture file simulating a review artifact that constructs
# the ai-review/security context via split-token concatenation.
# The literal "ai-review/security" never appears, but both components do.
# It should be REJECTED by the primary gate defense-in-depth check.

## Steps
1. Assign the context components:
ctx_a="ai-review"
ctx_b="security"
ctx="${ctx_a}/${ctx_b}"
2. Then later call the API with the constructed context.
