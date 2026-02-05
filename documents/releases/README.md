# APM2 Release Infrastructure

## Overview

APM2 uses a three-channel release pipeline with artifact promotion. Binaries are built once at the dev stage and promoted unchanged through beta and stable channels, ensuring consistency and traceability.

## Channels at a Glance

| Channel | Trigger | Tag Format | Security | Audience |
|---------|---------|------------|----------|----------|
| Dev | Merge to `main` | `dev` (rolling) | SHA256 checksums | Developers, AI agents |
| Beta | Manual dispatch | `vX.Y.Z-beta.N` | SHA256 checksums | Early adopters |
| Stable | release-plz PR merge | `vX.Y.Z` | Sigstore + SLSA L3 | Production users |

## Quick Links

### Release Documentation

- [Release Channels](RELEASE_CHANNELS.md) - Detailed channel descriptions and comparison
- [Artifact Promotion](ARTIFACT_PROMOTION.md) - How binaries flow through channels
- [Distribution & Verification](DISTRIBUTION.md) - How to obtain and verify releases

### Security Documentation

- [Signing & Verification](../security/SIGNING_AND_VERIFICATION.cac.json) - Sigstore keyless signing details
- [Release Procedure](../security/RELEASE_PROCEDURE.cac.json) - Complete stable release checklist

## Release Artifacts

Each release includes:

| Artifact | Description |
|----------|-------------|
| `apm2-linux-x86_64` | Linux x86_64 binary |
| `apm2-linux-aarch64` | Linux ARM64 binary |
| `apm2-linux-x86_64-daemon` | Daemon binary (x86_64) |
| `apm2-linux-aarch64-daemon` | Daemon binary (ARM64) |
| `checksums-sha256.txt` | SHA256 checksums for all binaries |
| `*.sig` | Cosign signatures (stable only) |
| `*.pem` | Signing certificates (stable only) |
| `sbom.spdx.json` | Software bill of materials (stable only) |
| `provenance.intoto.jsonl` | SLSA L3 provenance (stable only) |

## Quick Start

### For Production Use

Download the latest stable release:

```bash
# Download binary
curl -LO https://github.com/USER/apm2/releases/latest/download/apm2-linux-x86_64
chmod +x apm2-linux-x86_64

# Verify (recommended)
curl -LO https://github.com/USER/apm2/releases/latest/download/apm2-linux-x86_64.sig
curl -LO https://github.com/USER/apm2/releases/latest/download/apm2-linux-x86_64.pem
cosign verify-blob \
  --certificate apm2-linux-x86_64.pem \
  --signature apm2-linux-x86_64.sig \
  --certificate-identity-regexp "https://github.com/.*/apm2/.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  apm2-linux-x86_64
```

### For Development/Testing

Download the latest dev build:

```bash
curl -LO https://github.com/USER/apm2/releases/download/dev/apm2-linux-x86_64
chmod +x apm2-linux-x86_64

# Verify checksum
curl -LO https://github.com/USER/apm2/releases/download/dev/checksums-sha256.txt
sha256sum -c checksums-sha256.txt --ignore-missing
```
