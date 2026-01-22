# Signing and Verification

## Overview

APM2 uses **Sigstore keyless signing** for all releases. This eliminates the need to store, rotate, or protect signing keys.

## How Keyless Signing Works

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│ GitHub Actions  │────▶│  Sigstore/Fulcio│────▶│  Rekor Log      │
│ (OIDC Token)    │     │  (Certificate)  │     │  (Transparency) │
└─────────────────┘     └─────────────────┘     └─────────────────┘
         │                      │                       │
         │                      │                       │
         ▼                      ▼                       ▼
    Workflow ID           Ephemeral Key          Permanent Record
    verified              signs artifact         of signing event
```

1. **GitHub Actions requests OIDC token** - Proves the workflow identity
2. **Fulcio issues certificate** - Short-lived certificate tied to identity
3. **Cosign signs artifact** - Uses ephemeral key from certificate
4. **Rekor logs signing event** - Immutable transparency log

## Release Workflow Configuration

The release workflow must have these permissions:

```yaml
permissions:
  id-token: write    # Required for OIDC token
  contents: write    # Required to upload release assets
  attestations: write # Required for provenance
```

## Signing Process

### Install Cosign

```yaml
- uses: sigstore/cosign-installer@v3
```

### Sign Binary Artifacts

```yaml
- name: Sign artifacts with Cosign (keyless)
  run: |
    for file in artifacts/*; do
      if [[ -f "$file" && ! "$file" =~ \.(sig|pem|txt)$ ]]; then
        cosign sign-blob --yes \
          --output-signature "${file}.sig" \
          --output-certificate "${file}.pem" \
          "$file"
      fi
    done
```

### Sign Container Images

```yaml
- name: Sign container image
  run: |
    cosign sign --yes ghcr.io/${{ github.repository }}:${{ github.ref_name }}
```

## Verification

### Verify Binary Artifacts

Users can verify downloaded artifacts:

```bash
# Download artifact, signature, and certificate
curl -LO https://github.com/USER/apm2/releases/download/v1.0.0/apm2-linux-x86_64
curl -LO https://github.com/USER/apm2/releases/download/v1.0.0/apm2-linux-x86_64.sig
curl -LO https://github.com/USER/apm2/releases/download/v1.0.0/apm2-linux-x86_64.pem

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

### Verify Container Images

```bash
cosign verify \
  --certificate-identity-regexp "https://github.com/.*/apm2/.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/USER/apm2:v1.0.0
```

### Verify SLSA Provenance

```bash
slsa-verifier verify-artifact \
  --provenance-path provenance.intoto.jsonl \
  --source-uri github.com/USER/apm2 \
  apm2-linux-x86_64
```

## Certificate Identity

The certificate contains the workflow identity:

```json
{
  "Issuer": "https://token.actions.githubusercontent.com",
  "Subject": "https://github.com/USER/apm2/.github/workflows/release.yml@refs/tags/v1.0.0",
  "Extensions": {
    "GithubWorkflowRepository": "USER/apm2",
    "GithubWorkflowRef": "refs/tags/v1.0.0",
    "GithubWorkflowSha": "abc123..."
  }
}
```

This proves:
- The artifact was signed by GitHub Actions
- The workflow came from this repository
- The exact commit that produced the artifact

## Transparency Log (Rekor)

All signing events are recorded in the Rekor transparency log:

```bash
# Search for entries
rekor-cli search --email "github-actions@github.com"

# Get entry details
rekor-cli get --uuid <entry-uuid>
```

## Security Properties

| Property | Provided By |
|----------|-------------|
| Authenticity | Certificate ties signature to GitHub Actions |
| Integrity | SHA256 hash in signature |
| Non-repudiation | Rekor log entry is immutable |
| Provenance | SLSA attestation proves build origin |

## Key Storage

**There are no keys to store.** That's the point of keyless signing.

- Private keys are ephemeral (exist only during signing)
- Certificates are short-lived (10 minutes)
- Verification uses public Fulcio root of trust
- Transparency log provides audit trail

## Troubleshooting

### "certificate has expired"

Certificates are short-lived. Verification checks the Rekor log to confirm the signature was created while the certificate was valid.

Ensure you're using a recent version of cosign:
```bash
cosign version
```

### "identity mismatch"

The certificate identity doesn't match your verification pattern. Check:
- Repository name is correct
- Workflow path is correct
- Using correct OIDC issuer

### "signature not found in transparency log"

The signature might have been created before Rekor logging was enabled. For artifacts signed after Rekor was made mandatory, this indicates a problem.
