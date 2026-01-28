# Terminal Verifier

A **Terminal Verifier** is a verification mechanism whose acceptance predicate is **machine-checkable** and **replayable** (within an explicitly declared determinism envelope), producing evidence that can be audited independently of any agent's narrative.

Terminal verifiers are the point where "stochasticity stops" for authoritative promotion: LLMs may propose, but terminal verifiers decide.

## Properties

- **Machine-checkable**: PASS/FAIL reduces to a mechanical predicate over artifacts.
- **Replayable**: another actor can re-run the verifier on the same pinned inputs and get the same (or bounded) result.
- **Evidence-bearing**: outputs include transcripts, versions, and input/output digests (or pointers to them).
- **Attestable**: runs in an environment that can be identified/attested (at least by runner/toolchain digest).

## Example Evidence Shape (Conceptual)

```json
{
  "verifier": "cargo test",
  "inputs": { "git_commit": "deadbeef...", "lock_digest": "blake3:..." },
  "result": { "exit_code": 0 },
  "outputs": { "test_report_hash": "blake3:..." },
  "attestation": { "runner_image_digest": "sha256:..." }
}
```

## Examples (Software Factory)

- `cargo test` / `cargo clippy` / `cargo fmt --check` with pinned toolchain
- compiler/typechecker exit codes + diagnostics
- static analyzers and SBOM/security scanners (when their results are recorded as artifacts with versions)
- policy evaluation in a small deterministic engine (not an LLM)
- signature verification of receipts/artifacts
- reproducible build checks (artifact hash equality)

## Non-Examples (Advisory Verifiers)

- free-form LLM review without terminal evidence
- AAT-style stochastic evaluation unless it reduces to terminal-verifier evidence (e.g., generates deterministic tests and those tests pass)

## See Also

- **Attestation**: how verifier runs are bound to an execution environment.
- **Gate**: orchestrates verifiers and emits receipts.
