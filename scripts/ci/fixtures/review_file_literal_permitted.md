# This is a fixture file simulating a review artifact that references
# ai-review/security ONLY in comments.
# It should be PERMITTED by the primary gate check.

## Steps
# The security context ai-review/security is handled by the xtask.
# See: cargo xtask security-review-exec approve
cargo xtask security-review-exec approve
