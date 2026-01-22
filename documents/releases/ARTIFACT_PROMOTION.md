# Artifact Promotion

APM2 uses a "build once, promote twice" model where binary artifacts are built only at the dev stage and promoted unchanged through beta and stable channels.

## Build Once, Promote Twice

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│  PR merged to main                                                          │
│       │                                                                     │
│       ▼                                                                     │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        DEV STAGE                                     │   │
│  │  • Build binaries for all platforms                                  │   │
│  │  • Run full test suite                                               │   │
│  │  • Generate SHA256 checksums                                         │   │
│  │  • Create release with `dev` tag                                     │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│       │                                                                     │
│       │ Manual workflow dispatch                                            │
│       ▼                                                                     │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        BETA STAGE                                    │   │
│  │  • Download artifacts from dev release                               │   │
│  │  • Verify checksums match                                            │   │
│  │  • Create release with `vX.Y.Z-beta.N` tag                           │   │
│  │  • NO REBUILD - same bytes as dev                                    │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│       │                                                                     │
│       │ release-plz creates tag                                             │
│       ▼                                                                     │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                       STABLE STAGE                                   │   │
│  │  • Download artifacts from beta release                              │   │
│  │  • Verify checksums match                                            │   │
│  │  • Sign with Sigstore (keyless)                                      │   │
│  │  • Generate SLSA L3 provenance                                       │   │
│  │  • Generate SBOM                                                     │   │
│  │  • Create release with `vX.Y.Z` tag                                  │   │
│  │  • Publish to crates.io                                              │   │
│  │  • NO REBUILD - same bytes as beta/dev                               │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Why Promotion?

### 1. Consistency

The exact same bytes that passed all tests in dev reach production users in stable. There is no risk of subtle differences from separate builds.

### 2. Speed

Promotion is fast because there is no compilation. Beta and stable releases complete in seconds, not minutes.

### 3. Traceability

Checksums prove artifact identity across all channels:

```
Dev checksum     = Beta checksum     = Stable checksum
(before signing)   (before signing)    (before signing)
```

### 4. Test Once, Trust Everywhere

Tests run at the dev stage. Since artifacts are promoted unchanged, test results apply to all channels.

## Promotion Workflow

### Dev to Beta

When a maintainer triggers a beta release:

1. **Download**: Fetch all artifacts from the `dev` release
2. **Verify**: Compare checksums against dev release manifest
3. **Tag**: Create `vX.Y.Z-beta.N` release with same artifacts
4. **Document**: Auto-generate release notes from commits

### Beta to Stable

When release-plz creates a version tag:

1. **Download**: Fetch all artifacts from the latest beta
2. **Verify**: Compare checksums against beta release manifest
3. **Sign**: Apply Sigstore keyless signatures to all binaries
4. **Attest**: Generate SLSA L3 provenance attestation
5. **SBOM**: Generate software bill of materials
6. **Release**: Create `vX.Y.Z` release with all artifacts
7. **Publish**: Upload crates to crates.io

## Verifying Promotion

### Checksum Consistency

To verify that beta artifacts match dev:

```bash
# Download dev checksums
curl -LO https://github.com/USER/apm2/releases/download/dev/checksums-sha256.txt
mv checksums-sha256.txt dev-checksums.txt

# Download beta checksums
curl -LO https://github.com/USER/apm2/releases/download/v0.2.0-beta.1/checksums-sha256.txt
mv checksums-sha256.txt beta-checksums.txt

# Compare (should be identical)
diff dev-checksums.txt beta-checksums.txt
```

### Binary Comparison

To verify byte-for-byte identity:

```bash
# Download binaries from both channels
curl -LO https://github.com/USER/apm2/releases/download/dev/apm2-linux-x86_64
mv apm2-linux-x86_64 apm2-dev

curl -LO https://github.com/USER/apm2/releases/download/v0.2.0-beta.1/apm2-linux-x86_64
mv apm2-linux-x86_64 apm2-beta

# Compare SHA256 hashes
sha256sum apm2-dev apm2-beta
# Should show identical hashes
```

## Artifacts at Each Stage

| Artifact | Dev | Beta | Stable |
|----------|-----|------|--------|
| Binary executables | Built | Promoted | Promoted |
| `checksums-sha256.txt` | Generated | Copied | Copied |
| `*.sig` (signatures) | - | - | Generated |
| `*.pem` (certificates) | - | - | Generated |
| `sbom.spdx.json` | - | - | Generated |
| `provenance.intoto.jsonl` | - | - | Generated |

## Security Implications

### Build Environment Consistency

Since binaries are built only once:

- Single build environment to secure and audit
- Consistent compiler flags across all channels
- Reproducibility concerns limited to one stage

### Trust Chain

```
Tests pass in CI → Dev build created → Checksum locks content
       ↓                                       ↓
Beta promoted (checksum verified) ← ─ ─ ─ ─ ─ ┘
       ↓
Stable promoted (checksum verified, then signed)
       ↓
Users verify signature + provenance
```

### What Signing Adds

Stable releases add cryptographic guarantees:

| Property | Checksum (Dev/Beta) | Signature (Stable) |
|----------|---------------------|-------------------|
| Integrity | Yes | Yes |
| Origin proof | No | Yes (certificate shows GitHub Actions) |
| Tamper evidence | Limited | Strong (Rekor log) |
| Non-repudiation | No | Yes |

## Rollback and Recovery

### Promoting a Hotfix

If a critical issue is found in stable:

1. Fix is merged to `main`
2. New dev build is created automatically
3. Maintainer promotes to beta for quick testing
4. release-plz creates new stable tag
5. Hotfix release goes through full promotion chain

### Skipping Beta (Emergency)

In extreme cases, a release-plz stable release can be created directly from main without explicit beta testing. This is discouraged but the automation supports it.

## Implementation Details

### Artifact Storage

Artifacts are stored as GitHub Release assets. Each release contains the same set of files, with stable releases having additional signature files.

### Workflow Triggers

| Event | Workflow | Result |
|-------|----------|--------|
| Push to main | CI + Dev Release | Tests run, dev release created |
| Manual dispatch | Beta Release | Artifacts promoted to beta |
| release-plz tag | Stable Release | Artifacts signed and released |

### Checksum Format

The `checksums-sha256.txt` file uses the standard format:

```
a1b2c3d4e5...  apm2-linux-x86_64
f6e7d8c9b0...  apm2-linux-aarch64
...
```

This format is compatible with `sha256sum -c` for verification.
