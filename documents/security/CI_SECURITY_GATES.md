# CI Security Gates

All pull requests must pass these security gates before merge.

## Gate Summary

| Gate | Tool | Runs On | Blocking | Purpose |
|------|------|---------|----------|---------|
| Lint | `cargo clippy` | All PRs | Yes | Code quality and security lints |
| Tests | `cargo test` | All PRs | Yes | Functionality verification |
| Security Audit | `cargo-audit` | All PRs | Yes | Known vulnerability check |
| Dependency Check | `cargo-deny` | All PRs | Yes | License/ban/advisory checks |
| Secret Scan | `gitleaks` | All PRs | Yes | Detect committed secrets |
| SBOM Generation | `syft` | Release | Yes | Software bill of materials |
| Vulnerability Scan | `grype` | Release | High/Critical | Container/artifact scanning |

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

### Secret Scanning (Gitleaks)

Detects secrets in code and git history:

```yaml
- name: Secret Scan
  uses: gitleaks/gitleaks-action@v2
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

Detects:
- API keys and tokens
- Private keys and certificates
- AWS/GCP/Azure credentials
- Generic passwords and secrets

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

# Secret scan
gitleaks detect
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
- Secret detection
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

### Gitleaks Failure

```
Secret detected: AWS Access Key ID
File: config.rs:42
```

Fix:
1. Remove the secret from code
2. Rotate the compromised credential
3. Use proper secret management (env vars, keyring)
