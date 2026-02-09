# This is a fixture file simulating a review artifact that does NOT
# reference the forbidden security context literal anywhere in the file.
# It should be PERMITTED by the primary gate check.

## Steps
# The security review context is handled exclusively by the FAC.
# See: apm2 fac review dispatch --type security
apm2 fac review dispatch 123 --type security
