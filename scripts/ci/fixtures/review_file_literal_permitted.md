# This is a fixture file simulating a review artifact that does NOT
# reference the forbidden security context literal anywhere in the file.
# It should be PERMITTED by the primary gate check.

## Steps
# The security review context is handled exclusively by the xtask.
# See: cargo xtask security-review-exec approve
cargo xtask security-review-exec approve
