# This is a fixture file simulating a review artifact that does NOT
# reference the forbidden security context literal anywhere in the file.
# It should be PERMITTED by the primary gate check.

## Steps
# The security review context is handled exclusively by the FAC.
# See: apm2 fac restart --pr 123
apm2 fac restart --pr 123
