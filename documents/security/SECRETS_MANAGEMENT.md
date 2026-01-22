# Secrets Management

How credentials and sensitive data are handled in APM2.

## Types of Secrets

### 1. User Credentials (Runtime)

Managed by the `apm2-core` credentials module.

| Credential Type | Storage | Access |
|----------------|---------|--------|
| Claude API Key | OS Keyring | Injected to managed processes |
| OpenAI API Key | OS Keyring | Injected to managed processes |
| Session Tokens | OS Keyring (encrypted) | Auto-refreshed |
| OAuth Tokens | OS Keyring (encrypted) | Auto-refreshed |

### 2. CI/CD Secrets

Stored in GitHub Actions secrets.

| Secret | Purpose | Rotation |
|--------|---------|----------|
| `CARGO_REGISTRY_TOKEN` | Publish to crates.io | 90 days |
| `CODECOV_TOKEN` | Upload coverage | On compromise |
| `GITHUB_TOKEN` | Auto-provided | Per-workflow |

### 3. Signing Keys

**None required** - we use keyless signing with Sigstore.

## Credential Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                         User Input                               │
│                    (apm2 creds set)                              │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                       SecretString                               │
│              (In-memory, zeroized on drop)                       │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                        OS Keyring                                │
│         (macOS Keychain / Windows Credential Manager /           │
│                   Linux Secret Service)                          │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      apm2-daemon                                 │
│              (Reads from keyring on demand)                      │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Managed Process                               │
│            (Credentials injected via env vars)                   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Log Redaction                               │
│             (SecretRedactor filters output)                      │
└─────────────────────────────────────────────────────────────────┘
```

## Security Rules

### Rule 1: Never Commit Secrets

- No API keys in code
- No tokens in configuration files
- No credentials in test fixtures
- Use environment variables or keyring

Enforced by: `gitleaks` in CI and pre-commit hooks

### Rule 2: Never Log Secrets

- All log output passes through `SecretRedactor`
- Sensitive environment variable names trigger redaction
- API response bodies are filtered

```rust
// Sensitive patterns are automatically redacted
log::info!("Response: {}", response); // API keys masked
```

### Rule 3: Scan Before Persistence

- All file writes are scanned for secrets
- Artifacts are checked before release
- SBOM does not contain credential values

### Rule 4: Use SecretString for Sensitive Data

```rust
use secrecy::{SecretString, ExposeSecret};

struct Credentials {
    api_key: SecretString,  // Not String!
}

// Access only when needed
fn make_request(creds: &Credentials) {
    let key = creds.api_key.expose_secret();
    // Use key, then it goes out of scope
}
```

`SecretString` provides:
- `Debug` impl that shows `[REDACTED]`
- Automatic zeroization on drop
- Clear intent in code

### Rule 5: Rotate Regularly

| Secret Type | Rotation Period | Trigger |
|-------------|-----------------|---------|
| CI tokens | 90 days | Scheduled |
| User API keys | User discretion | On compromise |
| OAuth tokens | Auto-refresh | Token expiry |

## GitHub Actions Secrets

### Setting Secrets

```bash
# Using GitHub CLI
gh secret set CARGO_REGISTRY_TOKEN --body "crates-io-token-here"
```

### Accessing in Workflows

```yaml
env:
  CARGO_REGISTRY_TOKEN: ${{ secrets.CARGO_REGISTRY_TOKEN }}
```

### Secret Hygiene

- Secrets are masked in logs automatically
- Never echo secrets, even accidentally
- Use `--silent` flags for commands that might print tokens

## Environment Variable Handling

### Sensitive Variable Names

These patterns trigger automatic redaction:

- `*_KEY`
- `*_TOKEN`
- `*_SECRET`
- `*_PASSWORD`
- `*_CREDENTIAL`
- `ANTHROPIC_*`
- `OPENAI_*`
- `AWS_*`
- `GOOGLE_*`

### Safe Environment Injection

```rust
// In apm2-daemon, credentials are injected securely
let mut cmd = Command::new(process_path);
cmd.env("ANTHROPIC_API_KEY", key.expose_secret());
```

## Incident Response

If a secret is leaked:

1. **Revoke immediately** - Don't wait
2. **Rotate** - Generate new credentials
3. **Audit** - Check for unauthorized use
4. **Clean history** - Remove from git if committed
5. **Document** - Record in incident log

See [INCIDENT_RESPONSE.md](INCIDENT_RESPONSE.md) for full procedure.

## Testing with Secrets

### In CI

Use GitHub Actions secrets:

```yaml
- name: Integration tests
  env:
    TEST_API_KEY: ${{ secrets.TEST_API_KEY }}
  run: cargo test --features integration
```

### Locally

Use a `.env` file (gitignored):

```bash
# .env (never commit!)
TEST_API_KEY=test-key-here
```

Load with `dotenv` or shell:

```bash
source .env && cargo test
```

## Compliance

This secret management approach addresses:

- **OWASP Top 10**: A02:2021 - Cryptographic Failures
- **CIS Controls**: 3.10 - Encrypt Sensitive Data at Rest
- **SLSA L3**: Secrets isolated from build process
