# CI Security Gates

All pull requests must pass these security gates before merge.

## Gate Summary

| Gate | Tool | Runs On | Blocking | Purpose |
|------|------|---------|----------|---------|
| Lint | `cargo clippy` | All PRs | Yes | Code quality and security lints |
| Tests | `cargo test` | All PRs | Yes | Functionality verification |
| Security Audit | `cargo-audit` | All PRs | Yes | Known vulnerability check |
| Dependency Check | `cargo-deny` | All PRs | Yes | License/ban/advisory checks |
| Formal Proofs | `kani` / `prusti` | Unsafe-touching PRs | Yes | Formal safety proofs for unsafe blocks |
| Agent Complexity | `clippy::cognitive_complexity` | Agent-authored PRs | Yes | Complexity cap for agent-written modules |
| SBOM Generation | `syft` | Release | Yes | Software bill of materials |
| Vulnerability Scan | `grype` | Release | High/Critical | Container/artifact scanning |
| SLSA L4 Provenance | `slsa-github-generator` | Release | Yes | Hermetic build + two-person review provenance |
| Rekor Transparency | `rekor-cli` / `cosign` | Dependency updates + Release | Yes | Binary transparency verification |
| OIDC Claim Lock | `cosign` / policy | Release | Yes | OIDC issuer/subject/audience enforcement |

## Gate Details

### Clippy (Security Lints)

Runs `cargo clippy` with warnings as errors:

```yaml
- name: Clippy
  run: cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Key security lints enabled:
- `clippy::unwrap_used` - Prevents panics from unwrap
- `clippy::expect_used` - Prevents panics from expect
- `clippy::panic` - Prevents explicit panics
- `clippy::todo` - Catches incomplete code
- `clippy::unimplemented` - Catches stub code

### Security Audit

Uses RustSec Advisory Database:

```yaml
- name: Security Audit
  uses: rustsec/audit-check@v2
  with:
    token: ${{ secrets.GITHUB_TOKEN }}
```

Checks for:
- Known vulnerabilities in dependencies
- Unmaintained crates
- Yanked versions

### Formal Proofs (Unsafe Code)

Unsafe code must include formal proofs using Kani or Prusti in `apm2-core` and `apm2-daemon`.

```bash
rg "unsafe" crates/apm2-core crates/apm2-daemon -l | xargs -r rg -L "kani::proof|prusti::"
```

Any output from the command indicates a missing proof annotation.

Unsafe blocks must also include a machine-parseable SAFETY-PROOF block:

```bash
rg -n "// SAFETY-PROOF:" crates/
```

**CI Gate**: The `safety-proof-coverage` job in CI verifies that every `unsafe {}` block has a corresponding `// SAFETY-PROOF:` comment. This is a release-blocking security invariant—unsafe code without documented safety proofs is a security risk.

```yaml
safety-proof-coverage:
  name: Safety Proof Coverage
  runs-on: ubuntu-24.04
  steps:
    - uses: actions/checkout@v4
    - name: Check SAFETY-PROOF documentation
      run: |
        # Count unsafe blocks vs SAFETY-PROOF comments per file
        # Fail if any file has more unsafe blocks than proofs
```

### Agent Complexity (Cognitive Complexity <= 10)

Agent-authored modules must include an `AGENT-AUTHORED` marker and pass the clippy cognitive complexity cap.

```bash
rg -n "AGENT-AUTHORED" crates/
cargo clippy -- -A clippy::all -W clippy::cognitive_complexity
```

### Cargo Deny

Comprehensive dependency checking:

```yaml
- name: Cargo Deny
  uses: EmbarkStudios/cargo-deny-action@v2
  with:
    command: check all
```

Checks:
- **advisories**: Security vulnerabilities (RustSec)
- **bans**: Forbidden crates (e.g., openssl)
- **licenses**: Only approved licenses
- **sources**: Only trusted registries

### SBOM Generation (Release Only)

Generates Software Bill of Materials:

```yaml
- name: Generate SBOM
  uses: anchore/sbom-action@v0
  with:
    artifact-name: sbom.spdx.json
    output-file: sbom.spdx.json
```

Produces:
- SPDX format SBOM
- CycloneDX format SBOM
- Complete dependency tree

### Vulnerability Scanning (Release Only)

Scans artifacts for vulnerabilities:

```yaml
- name: Vulnerability Scan
  uses: anchore/scan-action@v4
  with:
    path: "."
    fail-build: true
    severity-cutoff: high
```

### SLSA L4 Provenance (Release Only)

Releases must satisfy SLSA L4 requirements (two-person review + hermetic build) and generate provenance.

```yaml
- name: SLSA Provenance
  uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2
```

Policy requires L4 controls even if the generator is L3-compatible; branch protection and hermetic build constraints must be enforced alongside provenance.

### Rekor Transparency Verification (CTR-1913)

Binary transparency verification is mandatory for dependency updates and releases. All signed release artifacts must have verifiable Rekor inclusion entries.

**CI Gate**: The release workflow includes a `Verify Rekor transparency entries` step that runs after artifact signing:

```yaml
- name: Verify Rekor transparency entries
  run: |
    cd artifacts
    OIDC_ISSUER="https://token.actions.githubusercontent.com"
    CERT_IDENTITY="https://github.com/${{ github.repository }}/.*"

    for file in *.sig; do
      base="${file%.sig}"
      if [[ -f "$base" && -f "${base}.pem" ]]; then
        cosign verify-blob \
          --certificate "${base}.pem" \
          --signature "${file}" \
          --certificate-identity-regexp "$CERT_IDENTITY" \
          --certificate-oidc-issuer "$OIDC_ISSUER" \
          "$base" || exit 1
      fi
    done
```

For manual verification:

```bash
rekor-cli verify --artifact <artifact> --signature <sig> --public-key <key>
```

For keyless signatures, use `cosign verify-blob` with issuer + identity constraints and confirm Rekor inclusion.

### OIDC Claim Lock (CTR-1912)

Release workflows must lock OIDC issuer, subject, and audience (where supported). Verification must enforce these claims.

**CI Gate**: OIDC claim enforcement is combined with Rekor verification above. The `cosign verify-blob` command enforces both Rekor verification AND OIDC claim constraints via:
- `--certificate-oidc-issuer`: Ensures the certificate was issued for GitHub Actions workflows
- `--certificate-identity-regexp`: Ensures the signing identity matches the repository

Manual verification:

```bash
cosign verify-blob \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate-identity-regexp "https://github.com/.*/apm2/.*" \
  <artifact>
```

## Local Verification

Run all gates locally before pushing:

```bash
# Format check
cargo fmt --check

# Clippy
cargo clippy --workspace --all-targets --all-features -- -D warnings

# Tests
cargo test --workspace --all-features

# Security audit
cargo audit

# Dependency check
cargo deny check

# Cognitive complexity for agent-authored code
cargo clippy -- -A clippy::all -W clippy::cognitive_complexity
```

## Pre-commit Hooks

The project uses `cargo-husky` to automatically manage git hooks. These are installed when you first run `cargo test`.

Hooks include:
- `pre-commit`: Runs formatting, clippy, proto verification, typos, and TOML/YAML/JSON/Markdown linting.
- `pre-push`: Runs the full workspace test suite and documentation checks.
- `commit-msg`: Enforces Conventional Commits.

To manually trigger the hooks, you can run the respective scripts in `.cargo-husky/hooks/`.

Hooks include:
- Format checking
- Clippy lints
- Large file prevention

## Bypassing Gates

Gates should **never** be bypassed for production code.

For legitimate emergencies:
1. Document the reason in the PR
2. Get explicit approval from a maintainer
3. Create a follow-up issue to address the bypass
4. The bypass will be visible in the audit log

## Adding New Gates

When adding a new security gate:

1. Add to CI workflow
2. Update this document
3. Add local verification command
4. Consider adding pre-commit hook
5. Communicate to team

## Gate Failure Response

### Clippy Failure

```
error: use of `unwrap()` is not allowed
```

Fix: Replace `unwrap()` with proper error handling.

### Audit Failure

```
Crate:  vulnerable-crate
Version: 1.0.0
Warning: RUSTSEC-2024-0001
```

Fix: Update the dependency or find an alternative.

### Deny Failure (License)

```
error[L001]: license not in allowlist: GPL-3.0
```

Fix: Find an alternative crate with approved license.
