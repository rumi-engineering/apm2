# Release Procedure

Complete checklist for creating a secure APM2 release.

## Pre-Release Checklist

### Code Quality

- [ ] All CI gates pass on `main` branch
- [ ] `cargo clippy --all-targets -- -D warnings` passes
- [ ] `cargo test --workspace --all-features` passes
- [ ] No open security advisories for dependencies

### Dependency Audit

- [ ] `cargo deny check` passes
- [ ] `cargo audit` passes
- [ ] Review any new dependencies added since last release
- [ ] Verify licenses of new dependencies

### Version and Documentation

- [ ] release-plz PR is up to date (version bump + changelog handled automatically)
- [ ] `CHANGELOG.md` updated via release-plz
- [ ] Breaking changes documented
- [ ] Migration guide if needed
- [ ] **Do not** manually edit versions or create tags

## Release Process

### 1. Promote Through Channels

APM2 uses a three-channel, promotion-based release pipeline. See
[`/documents/releases/RELEASE_CHANNELS.md`](../releases/RELEASE_CHANNELS.md) and
[`/documents/releases/ARTIFACT_PROMOTION.md`](../releases/ARTIFACT_PROMOTION.md).

#### Dev (automatic)

- Merges to `main` trigger CI.
- After CI succeeds, the Dev Release workflow builds binaries and publishes the
  rolling `dev` release with checksums.

#### Beta (manual)

- Maintainer dispatches the Beta Release workflow with a version like
  `0.2.0-beta.1`.
- The workflow downloads artifacts from `dev`, verifies checksums, and creates
  `vX.Y.Z-beta.N` without rebuilding.

#### Stable (automated via release-plz)

- release-plz creates a release PR with version bumps and changelog.
- When that PR is merged, release-plz creates a `vX.Y.Z` tag.
- The Stable Release workflow promotes artifacts from the latest matching beta
  release (or falls back to `dev`), signs them, generates SBOM + SLSA provenance,
  and publishes to crates.io.

### 2. GitHub Actions Release Workflow

The release workflow automatically:

1. **Promotes binaries** (no rebuild) from beta/dev:
   - Linux x86_64
   - Linux aarch64

2. **Signs all artifacts** with Cosign keyless:
   - Each binary gets `.sig` signature file
   - Each binary gets `.pem` certificate file

3. **Generates SLSA provenance**:
   - Creates `provenance.intoto.jsonl`
   - Proves artifacts came from this repository

4. **Generates SBOM**:
   - Creates `sbom.spdx.json` (SPDX format)
   - Lists all dependencies

5. **Creates GitHub Release**:
   - Attaches all artifacts
   - Generates release notes
   - Includes checksums

6. **Publishes to crates.io** (if configured)

### 3. Workflow Configuration

```yaml
# .github/workflows/release.yml
name: Release

on:
  push:
    tags:
      - 'v*'
    tags-ignore:
      - 'v*-*'

permissions:
  contents: write
  id-token: write
  attestations: write

jobs:
  release:
    # Promote artifacts from beta/dev, verify checksums, sign, SBOM
    steps:
      - uses: sigstore/cosign-installer@v3
      - name: Sign artifacts
        run: |
          # sign promoted artifacts
          ...

  provenance:
    needs: release
    permissions:
      actions: read
      id-token: write
      contents: write
    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.0.0
    with:
      base64-subjects: "${{ needs.release.outputs.hashes }}"
      upload-assets: true
```

See `/documents/releases/README.md` for full channel and artifact details.

## Post-Release Verification

### 1. Verify Signatures

```bash
# Download release artifacts
VERSION=v0.1.0
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

# Expected: Verified OK
```

### 2. Verify Checksums

```bash
# Download checksums
curl -LO "${BASE_URL}/checksums-sha256.txt"

# Verify
sha256sum -c checksums-sha256.txt
```

### 3. Verify SLSA Provenance

```bash
# Download provenance
curl -LO "${BASE_URL}/provenance.intoto.jsonl"

# Verify with slsa-verifier
slsa-verifier verify-artifact \
  --provenance-path provenance.intoto.jsonl \
  --source-uri github.com/USER/apm2 \
  apm2-linux-x86_64
```

### 4. Check GitHub Release

Verify the release includes:
- [ ] All platform binaries (Linux x86_64, Linux aarch64)
- [ ] Signature files (`.sig`)
- [ ] Certificate files (`.pem`)
- [ ] Checksums (`checksums-sha256.txt`)
- [ ] SLSA provenance (`provenance.intoto.jsonl`)
- [ ] SBOM (`sbom.spdx.json`)
- [ ] Generated release notes

### 5. Verify crates.io Publication

```bash
cargo search apm2
# Should show new version
```

## Announcement

After verification:

1. Update project documentation with new version
2. Announce on relevant channels
3. Monitor for issues

## Rollback Procedure

If a release has critical issues:

1. **Do NOT delete the release** - transparency log has the signing record
2. Yank the crates.io release: `cargo yank --version 0.1.0 apm2`
3. Create a new patch release with fix
4. Update release notes to warn about affected version

## Release Artifacts Summary

| Artifact | Purpose | Format |
|----------|---------|--------|
| `apm2-<platform>` | Binary executable | ELF/Mach-O/PE |
| `*.sig` | Cosign signature | Base64 |
| `*.pem` | Signing certificate | PEM |
| `checksums-sha256.txt` | Integrity verification | Text |
| `provenance.intoto.jsonl` | SLSA provenance | JSON |
| `sbom.spdx.json` | Software bill of materials | SPDX JSON |
