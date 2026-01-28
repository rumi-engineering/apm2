# Attestation

**Attestation** is the mechanism that binds a receipt or evidence artifact to an identifiable execution environment, reducing "someone said it passed" into "this predicate ran in that environment over these inputs."

## Why It Matters

Receipts prove *who* claimed an outcome. Attestation helps prove *where/how* the outcome was produced (toolchain, runner image, policy version), which is required to make verification replayable and to prevent verifier regress.

## Minimal Attestation Fields (Practical)

- **environment identity**: runner image digest / container digest / host identity
- **toolchain versions**: compiler/test tool versions (or digests)
- **policy version**: which policy allowed the run
- **command transcript**: exact commands (or transcript hash with CAS pointer)

## Example Encodings

```json
{
  "schema": "apm2.attestation.v1",
  "schema_version": "1.0.0",
  "attestation_level": "L1",
  "runner_image_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "toolchain": {
    "rustc": "1.85.0",
    "cargo": "1.85.0"
  },
  "policy_version": "policy@2026-01-27",
  "command_transcript_hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
}
```

## Attestation Strength Levels (Suggested)

- **L0 - Signature-only**: receipt is signed by an identity key. Proves authorship, not runtime environment.
- **L1 - Declarative environment**: include immutable runner image digest + toolchain versions + transcript hashes. Strong enough for most internal CI.
- **L2 - Hardware-backed**: TPM/TEE-backed remote attestation that the claimed image actually ran. Reserved for high-risk (T3) flows.

## Mapping to Git/CI

- In CI, environment identity maps naturally to a pinned runner/container image digest (plus workflow run ID as a convenience pointer).
- For repo state, include a pinned commit/tree selector (see **View Commitment**).

## See Also

- **Terminal Verifier**: the machine-checkable predicate the environment ran.
- **Receipt** / **Evidence**: what is being attested.
