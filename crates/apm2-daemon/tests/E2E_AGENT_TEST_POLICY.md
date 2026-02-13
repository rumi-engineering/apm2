# E2E Agent Test Policy

E2E agent tests that spawn full agent lifecycles are excluded from the default
test suite and may only run behind an explicit feature gate.

## Rationale

- Token cost from autonomous multi-agent runs is too high for default CI/test loops.
- Misconfiguration risk can cause writes/comments against real GitHub pull requests.
- Test state can leak into real operator home paths (`~/.apm2`) when not isolated.

## Mandatory Controls For Any Re-Introduced Lifecycle E2E Test

1. Set `APM2_HOME` to a test-local temporary directory.
2. Use mock GitHub adapters and preserve EVID-HEF-0012 constraints.
3. Gate execution behind `#[ignore]` or an explicit feature flag.

## Gated Replacement Harness

The FAC agent lifecycle E2E harness is available behind
`--features e2e-agent-tests`:

```bash
cargo test -p apm2-daemon --features e2e-agent-tests --test fac_autonomous_e2e -- --nocapture
cargo test -p apm2-daemon --features e2e-agent-tests --test hef_fac_v0_e2e -- --nocapture
```
