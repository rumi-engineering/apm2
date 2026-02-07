# Regression fixture: CODE_QUALITY_PROMPT.md with ONLY the known-good
# gh api pattern (writes ai-review/code-quality status).  This should
# be PERMITTED by all gates after known-good line stripping.

## Steps

1. Post code-quality status:
gh api --method POST "/repos/{owner}/{repo}/statuses/$reviewed_sha" -f state="success" -f context="ai-review/code-quality" -f description="Code quality review passed"
gh api --method POST "/repos/{owner}/{repo}/statuses/$reviewed_sha" -f state="failure" -f context="ai-review/code-quality" -f description="Code quality review found issues"
