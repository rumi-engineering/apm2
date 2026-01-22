# Threat Model

Security analysis of APM2 attack surface and mitigations.

## Assets

What we're protecting:

| Asset | Description | Sensitivity |
|-------|-------------|-------------|
| User Credentials | API keys, OAuth tokens, session tokens | Critical |
| Managed Processes | Claude Code, other AI tools | High |
| Audit Logs | Records of all operations | Medium |
| Configuration | Process definitions, settings | Medium |
| Release Artifacts | Binaries distributed to users | Critical |
| Source Code | Repository contents | Medium |

## Threat Actors

| Actor | Capability | Motivation |
|-------|------------|------------|
| External Attacker | Network access, public info | Steal credentials, compromise systems |
| Malicious Dependency | Code execution during build | Supply chain attack |
| Compromised CI | Access to build environment | Inject malware into releases |
| Insider | Direct access to systems | Data theft, sabotage |

## Threats and Mitigations

### T1: Credential Theft

**Scenario**: Attacker gains access to stored API keys or tokens.

**Attack Vectors**:
- Memory dump of running process
- File system access to credential store
- Environment variable leakage in logs
- Process listing showing command line args

**Mitigations**:
| Mitigation | Status | Notes |
|------------|--------|-------|
| OS Keyring storage | Implemented | Uses platform secure storage |
| SecretString (zeroized memory) | Implemented | Secrets cleared on drop |
| Log redaction | Implemented | Sensitive patterns filtered |
| Env injection (not CLI args) | Implemented | Credentials not visible in `ps` |

**Residual Risk**: Memory forensics on running daemon. Accepted - requires privileged access.

### T2: Supply Chain Attack

**Scenario**: Malicious code injected via compromised dependency.

**Attack Vectors**:
- Typosquatting crate names
- Compromised maintainer account
- Malicious build script
- Dependency confusion

**Mitigations**:
| Mitigation | Status | Notes |
|------------|--------|-------|
| cargo-deny | Implemented | Bans known bad crates |
| cargo-audit | Implemented | Checks RustSec database |
| License allowlist | Implemented | Only approved licenses |
| Source restrictions | Implemented | Only crates.io allowed |
| SBOM generation | Implemented | Full dependency visibility |
| SLSA provenance | Implemented | Build attestation |

**Residual Risk**: Zero-day in trusted dependency. Mitigated by defense in depth.

### T3: Malicious Release

**Scenario**: Attacker publishes a release containing malware.

**Attack Vectors**:
- Compromised GitHub Actions
- Stolen publishing credentials
- Man-in-the-middle on download

**Mitigations**:
| Mitigation | Status | Notes |
|------------|--------|-------|
| Sigstore keyless signing | Implemented | No keys to steal |
| SLSA L3 provenance | Implemented | Build verified from source |
| SHA256 checksums | Implemented | Integrity verification |
| HTTPS downloads | GitHub default | Transport security |
| Reproducible builds | Planned | Verify builds independently |

**Residual Risk**: Compromised GitHub infrastructure. Mitigated by Sigstore's independent verification.

### T4: Log Exfiltration

**Scenario**: Attacker extracts sensitive data from log files.

**Attack Vectors**:
- Log file access on compromised system
- Log aggregation service compromise
- Backup containing logs

**Mitigations**:
| Mitigation | Status | Notes |
|------------|--------|-------|
| Secret redaction | Implemented | Patterns filtered before logging |
| Log rotation | Implemented | Limits exposure window |
| No credential logging | Policy | Never log credentials |

**Residual Risk**: Novel secret patterns not in filter. Mitigated by regular pattern updates.

### T5: Process Injection

**Scenario**: Attacker injects malicious code into managed processes.

**Attack Vectors**:
- DLL injection (Windows)
- LD_PRELOAD attack (Linux)
- Code signing bypass

**Mitigations**:
| Mitigation | Status | Notes |
|------------|--------|-------|
| Process isolation | OS provided | Separate process space |
| Verified process paths | Planned | Only run known binaries |
| Integrity monitoring | Planned | Detect tampering |

**Residual Risk**: Kernel-level attacks. Out of scope - requires OS hardening.

### T6: Rollback Attack

**Scenario**: Attacker tricks user into running older, vulnerable version.

**Attack Vectors**:
- Serve old release from malicious mirror
- Downgrade via package manager manipulation

**Mitigations**:
| Mitigation | Status | Notes |
|------------|--------|-------|
| Version comparison in updater | Planned | Refuse downgrades |
| Signed version manifest | Planned | Verify version info |
| SLSA provenance verification | Implemented | Verify build timestamp |

**Residual Risk**: Manual download of old version. User education needed.

### T7: CI/CD Compromise

**Scenario**: Attacker gains access to GitHub Actions environment.

**Attack Vectors**:
- Malicious PR with workflow changes
- Stolen GitHub token
- Actions marketplace supply chain

**Mitigations**:
| Mitigation | Status | Notes |
|------------|--------|-------|
| Pinned action versions | Implemented | Use SHA, not tags |
| CODEOWNERS protection | Implemented | Review required for workflows |
| Minimal token permissions | Implemented | Least privilege |
| Keyless signing | Implemented | No secrets to exfiltrate |

**Residual Risk**: Compromised GitHub infrastructure. Accepted - industry standard.

## Attack Trees

### Steal User Credentials

```
Steal User Credentials
├── Access Memory [Hard]
│   ├── Process dump (requires privileges)
│   └── Core dump analysis (if enabled)
├── Access Keyring [Medium]
│   ├── User session access (login required)
│   └── Keyring backup extraction
├── Extract from Logs [Mitigated]
│   └── Blocked by SecretRedactor
└── Intercept in Transit [Mitigated]
    └── Blocked by HTTPS + cert pinning
```

### Compromise Release

```
Compromise Release
├── Inject Malware in Build [Hard]
│   ├── Compromise GitHub Actions
│   │   └── Blocked by keyless signing attestation
│   └── Compromise dependency
│       └── Detected by cargo-audit, cargo-deny
├── Replace Binary After Build [Hard]
│   └── Detected by signature verification
└── Trick User into Wrong Binary [Medium]
    └── Mitigated by verification instructions
```

## Security Controls Summary

| Control | Purpose | Implementation |
|---------|---------|----------------|
| OS Keyring | Credential storage | `keyring` crate |
| SecretString | Memory protection | `secrecy` crate |
| SecretRedactor | Log filtering | Custom tracing layer |
| cargo-deny | Dependency policy | CI gate |
| cargo-audit | Vulnerability check | CI gate |
| gitleaks | Secret scanning | CI gate + pre-commit |
| Sigstore | Release signing | GitHub Actions |
| SLSA | Build provenance | slsa-github-generator |
| SBOM | Dependency tracking | syft |

## Review Schedule

This threat model should be reviewed:
- When new features are added
- After security incidents
- At least annually
