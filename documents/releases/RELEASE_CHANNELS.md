# Release Channels

APM2 uses three release channels to balance rapid iteration with stability and security.

## Channel Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                                                                         │
│  main branch ──┬── Dev Channel ──┬── Beta Channel ──┬── Stable Channel  │
│                │   (automatic)   │   (manual)       │   (release-plz)   │
│                │                 │                  │                   │
│                ▼                 ▼                  ▼                   │
│             `dev` tag      `v0.2.0-beta.1`     `v0.2.0`                 │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

## Dev Channel

The dev channel provides bleeding-edge builds for developers and AI agents working with APM2.

| Property | Value |
|----------|-------|
| **Trigger** | Every merge to `main` branch |
| **Tag** | `dev` (rolling, overwritten on each build) |
| **Build time target** | <5 minutes |
| **Tests** | Full test suite runs before artifacts are created |
| **Security** | SHA256 checksums only |
| **Audience** | AI agents, developers, worktree testing |

### Characteristics

- **Fast iteration**: New builds available within minutes of merge
- **Rolling tag**: The `dev` tag always points to the latest build
- **Full test coverage**: All CI gates must pass before merge
- **No signatures**: Checksums provide integrity verification only
- **Potentially unstable**: May contain breaking changes or bugs

### Use Cases

- AI agents that need the latest features
- Development environments and worktrees
- Integration testing against latest changes
- Rapid prototyping

## Beta Channel

The beta channel provides pre-release builds for early adopters and integration testing.

| Property | Value |
|----------|-------|
| **Trigger** | Manual workflow dispatch |
| **Tag** | `vX.Y.Z-beta.N` (e.g., `v0.2.0-beta.1`) |
| **Tests** | None (promoted from dev without rebuild) |
| **Security** | SHA256 checksums only |
| **Audience** | Early adopters, integration testing |

### Characteristics

- **Promotion-based**: Same binaries as dev, no rebuild
- **Semantic versioning**: Beta tags indicate the target stable version
- **Manual gating**: Maintainer must explicitly promote
- **Pre-release period**: Time for community testing before stable
- **Checksum verification**: Proves artifacts match dev build

### Use Cases

- Testing upcoming stable releases before general availability
- Validating compatibility with downstream projects
- Early access to new features
- Regression testing before stable promotion

### Creating a Beta Release

Beta releases are created via manual workflow dispatch:

1. Navigate to Actions > Beta Release workflow
2. Click "Run workflow"
3. Enter the target version (e.g., `0.2.0-beta.1`)
4. The workflow downloads dev artifacts and creates the beta release

## Stable Channel

The stable channel provides production-ready releases with full security guarantees.

| Property | Value |
|----------|-------|
| **Trigger** | release-plz PR merged (creates tag automatically) |
| **Tag** | `vX.Y.Z` (e.g., `v0.2.0`) |
| **Tests** | None (promoted from beta without rebuild) |
| **Security** | Sigstore keyless signing + SLSA L3 provenance |
| **Audience** | Production users |

### Characteristics

- **Full security**: Sigstore signatures and SLSA provenance
- **Automated changelog**: release-plz generates release notes from commits
- **Promotion-based**: Same binaries as beta (and dev)
- **crates.io publishing**: Automatically published to crates.io
- **Long-term support**: Stable releases receive security fixes

### Security Features

Stable releases include:

- **Sigstore signatures** (`.sig` files): Keyless cryptographic signatures
- **Signing certificates** (`.pem` files): Prove GitHub Actions origin
- **SLSA L3 provenance**: Attestation of build origin and process
- **SBOM**: Software bill of materials for dependency transparency

See [../security/SIGNING_AND_VERIFICATION.cac.json](../security/SIGNING_AND_VERIFICATION.cac.json) for verification details.

### Creating a Stable Release

Stable releases are automated via release-plz:

1. release-plz runs on every push to `main`
2. It creates/updates a release PR with version bumps and changelog
3. When the release PR is merged, release-plz creates a version tag
4. The tag triggers the release workflow

See [../security/RELEASE_PROCEDURE.cac.json](../security/RELEASE_PROCEDURE.cac.json) for the complete checklist.

## Channel Comparison

| Aspect | Dev | Beta | Stable |
|--------|-----|------|--------|
| **Trigger** | Auto (merge) | Manual | Auto (release-plz) |
| **Tag style** | Rolling `dev` | `vX.Y.Z-beta.N` | `vX.Y.Z` |
| **Rebuild** | Yes (fresh build) | No (promoted) | No (promoted) |
| **Test suite** | Run before build | Inherited | Inherited |
| **Checksums** | Yes | Yes | Yes |
| **Signatures** | No | No | Yes (Sigstore) |
| **SLSA provenance** | No | No | Yes (L3) |
| **SBOM** | No | No | Yes |
| **crates.io** | No | No | Yes |
| **Stability** | Unstable | Pre-release | Production-ready |

## Choosing a Channel

| You are... | Recommended Channel |
|------------|---------------------|
| Running in production | **Stable** |
| Testing upcoming release | Beta |
| Developing APM2 features | Dev |
| AI agent in worktree | Dev |
| Integration testing | Beta or Dev |
| Security-sensitive deployment | **Stable** (verify signatures) |

## Workflow Files

The release infrastructure is implemented in these workflow files:

| Workflow | File | Purpose |
|----------|------|---------|
| CI | `.github/workflows/ci.yml` | Tests and gates |
| Dev Release | `.github/workflows/dev-release.yml` | Dev channel builds |
| Beta Release | `.github/workflows/beta-release.yml` | Beta promotion |
| Stable Release | `.github/workflows/release.yml` | Stable release + signing |
| Release-plz | `.github/workflows/release-plz.yml` | Automated version management |
