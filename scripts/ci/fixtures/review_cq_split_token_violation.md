# Regression fixture: CODE_QUALITY_PROMPT.md with split-token construction
# of ai-review/security.  The known-good ai-review/code-quality lines are
# stripped, but the split-token construction targets the SECURITY context
# and must be CAUGHT.

## Steps

1. Post code-quality status (known-good, should be stripped):
gh api --method POST "/repos/{owner}/{repo}/statuses/$reviewed_sha" -f state="success" -f context="ai-review/code-quality"

2. Construct security context via split tokens:
ctx_a="ai-review"
ctx_b="security"
ctx="${ctx_a}/${ctx_b}"
gh api "$endpoint" -f context="$ctx"
