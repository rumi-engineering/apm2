# Code Quality Review Prompt

**PR URL:** $PR_URL
**HEAD SHA:** $HEAD_SHA

Review the pull request at $PR_URL for code quality.

## Context

This is a Rust crate for arena-based memory management with pool allocation. Code quality standards are high as this is a foundational library.

## Focus Areas

### Rust Idioms
- Proper use of ownership, borrowing, and lifetimes
- Appropriate use of `Option`, `Result`, and error handling
- Idiomatic iterator usage over manual loops where applicable
- Correct trait implementations (`Clone`, `Debug`, `Default`, etc.)

### API Design
- Clear and consistent naming conventions
- Appropriate visibility modifiers (`pub`, `pub(crate)`, private)
- Well-designed function signatures with sensible defaults
- Proper use of generics and trait bounds

### Documentation
- Public items have doc comments explaining purpose and usage
- Complex logic has inline comments explaining "why" not "what"
- Examples in doc comments where helpful
- Safety comments for all `unsafe` blocks

### Error Handling
- Errors are descriptive and actionable
- Error types are appropriate (custom errors vs standard library)
- Panic conditions are documented and minimized

### Testing
- New functionality has corresponding tests
- Edge cases are covered
- Tests are clear and well-named
- Integration tests for public API changes

### Performance Considerations
- No obvious performance issues (unnecessary allocations, copies)
- Appropriate use of `#[inline]` for hot paths
- Benchmark coverage for performance-critical changes

## Output Format

Provide a structured review with:
1. **Summary**: Brief overview of code quality
2. **Issues Found**: List each issue with severity (Major/Minor/Nitpick)
3. **Suggestions**: Improvements that would enhance the code
4. **Positive Observations**: Good practices observed

## Required Actions (MUST complete both)

After completing your review, you MUST perform both of these actions:

### 1. Post your review as a PR comment

Post your complete review findings to the PR so the author knows what to address:

```bash
gh pr comment $PR_URL --body "## Code Quality Review

**Summary:** [Brief overview]

**Issues Found:**
[List each issue with severity]

**Suggestions:**
[Improvements that would enhance the code]

**Verdict:** [PASSED or FAILED]
"
```

### 2. Update the status check

Based on your findings, update the `ai-review/code-quality` status check:

**If no Major issues (review passed):**
```bash
gh api --method POST "/repos/{owner}/{repo}/statuses/$HEAD_SHA" \
  -f state="success" \
  -f context="ai-review/code-quality" \
  -f description="Code quality review passed"
```

**If any Major issues (review failed):**
```bash
gh api --method POST "/repos/{owner}/{repo}/statuses/$HEAD_SHA" \
  -f state="failure" \
  -f context="ai-review/code-quality" \
  -f description="Code quality review found issues - see PR comments"
```

**IMPORTANT:** You must execute both commands. The PR comment provides actionable feedback to the author. The status check gates the merge.
