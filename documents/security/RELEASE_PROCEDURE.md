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

- [ ] Version bumped in `Cargo.toml` files
- [ ] `CHANGELOG.md` updated with release notes
- [ ] Breaking changes documented
- [ ] Migration guide if needed

## Release Process

### 1. Create Signed Git Tag

```bash
# Ensure you're on main and up to date
git checkout main
git pull origin main

# Create annotated tag
git tag -a v0.1.0 -m "Release v0.1.0"

# Push tag to trigger release workflow
git push origin v0.1.0
```

### 2. GitHub Actions Release Workflow

The release workflow automatically:

1. **Builds binaries** for all platforms:
   - Linux (x86_64, aarch64, musl)
   - macOS (x86_64, aarch64)
   - Windows (x86_64)

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

permissions:
  contents: write
  id-token: write
  attestations: write

jobs:
  build:
    # ... build steps ...

  sign:
    needs: build
    steps:
      - uses: sigstore/cosign-installer@v3
      - name: Sign artifacts
        run: |
          for file in artifacts/*; do
            cosign sign-blob --yes \
              --output-signature "${file}.sig" \
              --output-certificate "${file}.pem" \
              "$file"
          done

  provenance:
    needs: build
    permissions:
      actions: read
      id-token: write
      contents: write
    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.0.0
    with:
      base64-subjects: "${{ needs.build.outputs.hashes }}"
      upload-assets: true
```

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
- [ ] All platform binaries
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
