# APM2 Security Documentation

This directory contains security guidelines and procedures for the APM2 project.

## Security Philosophy

- **Fail-closed**: When in doubt, deny access or abort operations
- **Defense in depth**: Multiple layers of protection
- **Minimal secrets**: Use keyless signing to eliminate stored secrets
- **Transparent verification**: All releases are publicly verifiable

## Quick Reference

### For Developers

```bash
# Run all security checks locally
cargo clippy --all-targets -- -D warnings
cargo deny check
cargo audit
```

### For Users

Verify a release artifact:

```bash
cosign verify-blob \
  --certificate apm2.pem \
  --signature apm2.sig \
  --certificate-identity-regexp "https://github.com/.*/apm2/.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  apm2
```

## Personal GitHub Account Constraints

This project operates within the constraints of a GitHub Free personal account:

| Feature | Public Repos | Private Repos |
|---------|--------------|---------------|
| GitHub Actions minutes | Unlimited | 2,000/month |
| Repository secrets | 100 max | 100 max |
| OIDC tokens | Yes | Yes |
| Dependabot alerts | Yes | Yes |
| Code scanning (CodeQL) | Yes | No |
| Secret scanning | Yes | No |

### Workarounds

- **No CodeQL in private repos**: Use `cargo clippy` with security-focused lints and `cargo-audit`
- **No secret scanning in private repos**: Use targeted `git log -p -S` searches for suspected patterns
- **No environment secrets**: Use repository secrets with job-level filtering

## Documents

| Document | Purpose |
|----------|---------|
| [SECURITY_POLICY.md](SECURITY_POLICY.md) | Security modes and invariants |
| [SIGNING_AND_VERIFICATION.md](SIGNING_AND_VERIFICATION.md) | Keyless signing procedure |
| [CI_SECURITY_GATES.md](CI_SECURITY_GATES.md) | PR blocking gates |
| [RELEASE_PROCEDURE.md](RELEASE_PROCEDURE.md) | Complete release checklist |
| [SECRETS_MANAGEMENT.md](SECRETS_MANAGEMENT.md) | Credential handling |
| [INCIDENT_RESPONSE.md](INCIDENT_RESPONSE.md) | What to do when things go wrong |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Attack scenarios and mitigations |
| [PQC_TRANSITION_PLAN.cac.json](PQC_TRANSITION_PLAN.cac.json) | Forward-looking post-quantum migration plan |

## Key Insight: Keyless Signing

**Cosign keyless signing eliminates the key storage problem entirely.**

Traditional approach:
1. Generate signing keys
2. Store private key securely (hard!)
3. Rotate keys periodically
4. Risk of key compromise

Keyless approach:
1. GitHub Actions gets an OIDC identity token
2. Sigstore/Fulcio issues a short-lived certificate
3. Artifact is signed with ephemeral key
4. Signing event logged in Rekor transparency log

**No keys to store, rotate, or protect.** The signature is tied to your GitHub Actions workflow identity.

## Sources

- [Sigstore Cosign Keyless Signing](https://docs.sigstore.dev/cosign/signing/overview/)
- [GitHub Actions Security Best Practices](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- [SLSA Framework](https://slsa.dev/)
