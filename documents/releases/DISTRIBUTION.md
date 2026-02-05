# Distribution

This document describes how users can obtain APM2 releases and verify their integrity.

## Download Locations

### GitHub Releases (Primary)

All channels are distributed through GitHub Releases:

| Channel | URL Pattern |
|---------|-------------|
| Stable (latest) | `https://github.com/USER/apm2/releases/latest/download/apm2-linux-x86_64` |
| Stable (specific) | `https://github.com/USER/apm2/releases/download/v0.2.0/apm2-linux-x86_64` |
| Beta | `https://github.com/USER/apm2/releases/download/v0.2.0-beta.1/apm2-linux-x86_64` |
| Dev | `https://github.com/USER/apm2/releases/download/dev/apm2-linux-x86_64` |

### Available Binaries

| Platform | Binary Name | Daemon Name |
|----------|-------------|-------------|
| Linux x86_64 | `apm2-linux-x86_64` | `apm2-linux-x86_64-daemon` |
| Linux ARM64 | `apm2-linux-aarch64` | `apm2-linux-aarch64-daemon` |

### crates.io (Stable Only)

Stable releases are published to crates.io:

```bash
cargo install apm2-cli
cargo install apm2-daemon
```

## Verification

### Dev and Beta Channels (Checksum Verification)

Dev and beta releases provide SHA256 checksums for integrity verification:

```bash
# Download binary and checksums
curl -LO https://github.com/USER/apm2/releases/download/dev/apm2-linux-x86_64
curl -LO https://github.com/USER/apm2/releases/download/dev/checksums-sha256.txt

# Verify checksum
sha256sum -c checksums-sha256.txt --ignore-missing
# Expected: apm2-linux-x86_64: OK
```

Or verify manually:

```bash
# Get expected hash from checksums file
grep apm2-linux-x86_64 checksums-sha256.txt
# Output: a1b2c3d4... apm2-linux-x86_64

# Calculate actual hash
sha256sum apm2-linux-x86_64
# Should match the expected hash
```

### Stable Channel (Sigstore Verification)

Stable releases include Sigstore signatures that cryptographically prove the artifacts came from the official GitHub Actions build.

#### Prerequisites

Install cosign:

```bash
# Using Go
go install github.com/sigstore/cosign/v2/cmd/cosign@latest

# Or download binary
# See: https://docs.sigstore.dev/cosign/installation/
```

#### Full Verification

```bash
# Download all verification artifacts
VERSION=v0.2.0
BASE_URL="https://github.com/USER/apm2/releases/download/${VERSION}"

curl -LO "${BASE_URL}/apm2-linux-x86_64"
curl -LO "${BASE_URL}/apm2-linux-x86_64.sig"
curl -LO "${BASE_URL}/apm2-linux-x86_64.pem"

# Verify signature
cosign verify-blob \
  --certificate apm2-linux-x86_64.pem \
  --signature apm2-linux-x86_64.sig \
  --certificate-identity-regexp "https://github.com/.*/apm2/.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  apm2-linux-x86_64
```

Expected output:

```
Verified OK
```

#### What Verification Proves

When `cosign verify-blob` succeeds, it proves:

1. **Authenticity**: The binary was signed by GitHub Actions
2. **Integrity**: The binary has not been modified since signing
3. **Origin**: The signature came from the APM2 repository's workflow
4. **Non-repudiation**: The signing event is recorded in Rekor transparency log

#### SLSA Provenance Verification

For additional supply chain security, verify SLSA provenance:

```bash
# Install slsa-verifier
go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@latest

# Download provenance
curl -LO "${BASE_URL}/provenance.intoto.jsonl"

# Verify
slsa-verifier verify-artifact \
  --provenance-path provenance.intoto.jsonl \
  --source-uri github.com/USER/apm2 \
  apm2-linux-x86_64
```

See [../security/SIGNING_AND_VERIFICATION.cac.json](../security/SIGNING_AND_VERIFICATION.cac.json) for complete verification details.

## Quick Download Scripts

### Latest Stable (Verified)

```bash
#!/bin/bash
set -euo pipefail

REPO="USER/apm2"
BINARY="apm2-linux-x86_64"
BASE_URL="https://github.com/${REPO}/releases/latest/download"

# Download
curl -fLO "${BASE_URL}/${BINARY}"
curl -fLO "${BASE_URL}/${BINARY}.sig"
curl -fLO "${BASE_URL}/${BINARY}.pem"

# Verify
cosign verify-blob \
  --certificate "${BINARY}.pem" \
  --signature "${BINARY}.sig" \
  --certificate-identity-regexp "https://github.com/.*/apm2/.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  "${BINARY}"

# Install
chmod +x "${BINARY}"
mv "${BINARY}" ~/.local/bin/apm2
rm -f "${BINARY}.sig" "${BINARY}.pem"

echo "Installed apm2 to ~/.local/bin/apm2"
```

### Latest Dev (Checksum Verified)

```bash
#!/bin/bash
set -euo pipefail

REPO="USER/apm2"
BINARY="apm2-linux-x86_64"
BASE_URL="https://github.com/${REPO}/releases/download/dev"

# Download
curl -fLO "${BASE_URL}/${BINARY}"
curl -fLO "${BASE_URL}/checksums-sha256.txt"

# Verify
sha256sum -c checksums-sha256.txt --ignore-missing

# Install
chmod +x "${BINARY}"
mv "${BINARY}" ~/.local/bin/apm2
rm -f checksums-sha256.txt

echo "Installed apm2 (dev) to ~/.local/bin/apm2"
```

## Which Channel to Use?

| Scenario | Recommended Channel | Reason |
|----------|---------------------|--------|
| Production deployment | **Stable** | Full security guarantees, tested |
| Security-sensitive environment | **Stable** + verify signatures | Cryptographic proof of origin |
| Testing upcoming features | Beta | Pre-release validation |
| Integration testing | Beta or Dev | Early access to changes |
| Developing APM2 | Dev | Latest changes |
| AI agent in worktree | Dev | Fastest iteration |
| Automated CI/CD | Stable (pinned version) | Reproducibility |

## Artifact Manifest

### Stable Release Contents

```
apm2-linux-x86_64           # Linux x86_64 binary
apm2-linux-x86_64.sig       # Cosign signature
apm2-linux-x86_64.pem       # Signing certificate
apm2-linux-aarch64          # Linux ARM64 binary
apm2-linux-aarch64.sig      # Cosign signature
apm2-linux-aarch64.pem      # Signing certificate
apm2-linux-x86_64-daemon    # Daemon binary (x86_64)
apm2-linux-x86_64-daemon.sig
apm2-linux-x86_64-daemon.pem
apm2-linux-aarch64-daemon   # Daemon binary (ARM64)
apm2-linux-aarch64-daemon.sig
apm2-linux-aarch64-daemon.pem
checksums-sha256.txt        # SHA256 checksums
sbom.spdx.json              # Software bill of materials
provenance.intoto.jsonl     # SLSA L3 provenance
```

### Dev/Beta Release Contents

```
apm2-linux-x86_64           # Linux x86_64 binary
apm2-linux-aarch64          # Linux ARM64 binary
apm2-linux-x86_64-daemon    # Daemon binary (x86_64)
apm2-linux-aarch64-daemon   # Daemon binary (ARM64)
checksums-sha256.txt        # SHA256 checksums
```

## Troubleshooting

### Signature Verification Failed

**"certificate has expired"**

Sigstore certificates are short-lived (10 minutes). Verification checks the Rekor transparency log to confirm the signature was created while valid. Ensure you have a recent version of cosign:

```bash
cosign version
# Update if needed
```

**"identity mismatch"**

The certificate identity doesn't match. Check:

- Repository name in `--certificate-identity-regexp`
- OIDC issuer is `https://token.actions.githubusercontent.com`

### Checksum Mismatch

If checksum verification fails:

1. Re-download the file (partial download?)
2. Check you downloaded from the correct release
3. Verify the checksums file itself hasn't been tampered with

### Download Failed

GitHub rate limits anonymous downloads. If you hit limits:

```bash
# Use GitHub CLI (authenticates automatically)
gh release download dev --repo USER/apm2 --pattern 'apm2-linux-x86_64'
```

## Related Documentation

- [Release Channels](RELEASE_CHANNELS.md) - Channel details and comparison
- [Artifact Promotion](ARTIFACT_PROMOTION.md) - How artifacts flow through channels
- [Signing & Verification](../security/SIGNING_AND_VERIFICATION.cac.json) - Sigstore details
- [Release Procedure](../security/RELEASE_PROCEDURE.cac.json) - Stable release process
