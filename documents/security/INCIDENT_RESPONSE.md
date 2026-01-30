# Incident Response

Procedures for handling security incidents.

## Incident Classification

### Severity Levels

| Level | Description | Examples | Response Time |
|-------|-------------|----------|---------------|
| Critical | Active exploitation or imminent threat | Secret leaked publicly, RCE vulnerability | Immediate |
| High | Significant security impact | Dependency vulnerability (CVSS 7+), credential exposure | 24 hours |
| Medium | Moderate security impact | Medium vulnerability, policy violation | 7 days |
| Low | Minor security impact | Low severity advisory, process improvement | 30 days |

## Incident Response Procedures

### Secret Leaked

**Immediate Actions (within 1 hour):**

1. **Revoke the credential**
   ```bash
   # Example: Revoke GitHub token
   gh auth logout
   # Example: Regenerate API key in provider dashboard
   ```

2. **Rotate related credentials**
   - Any credential that could be derived from the leaked one
   - Any credential in the same keyring/vault
   - Any credential used alongside the leaked one

3. **Audit recent activity**
   - Check API logs for unauthorized access
   - Review git history for when the secret was committed
   - Check if secret was accessed before leak was discovered

**Investigation:**

4. **Determine scope**
   ```bash
   # Search git history for the secret pattern
   git log -p -S '<secret-pattern>'

   # Check if secret exists in any branch
   git branch -a | xargs -I{} git log {} -p -S '<secret-pattern>'
   ```

5. **Remove from history** (if committed)
   ```bash
   # Using git-filter-repo (recommended)
   git filter-repo --invert-paths --path path/to/file/with/secret

   # Force push (coordinate with team first!)
   git push --force-with-lease origin main
   ```

6. **Document the incident**
   - What was leaked
   - How it was discovered
   - Timeline of response
   - Root cause
   - Preventive measures

### Vulnerability Discovered

**Assessment:**

1. **Determine exploitability**
   - Is the vulnerable code path reachable?
   - What inputs trigger the vulnerability?
   - What's the impact if exploited?

2. **Check if exploited**
   - Review logs for exploitation attempts
   - Check for unusual activity

**Response:**

3. **Do not release** until patched
   - Block any pending releases
   - Mark affected versions

4. **Develop patch**
   - Create fix on private branch
   - Write regression test
   - Review patch for completeness

5. **Coordinate disclosure**
   - If external report: agree on disclosure timeline
   - Prepare advisory text
   - Notify affected users if needed

6. **Release patch**
   ```bash
   # Create patch release
   git tag -a v1.0.1 -m "Security patch for CVE-XXXX-XXXX"
   git push origin v1.0.1
   ```

7. **Publish advisory**
   - GitHub Security Advisory
   - RustSec advisory (if applicable)
   - Announce on relevant channels

### Dependency Vulnerability

1. **Assess impact**
   ```bash
   # Check if vulnerable code path is used
   cargo tree -i vulnerable-crate

   # Review how the crate is used in our code
   grep -r "vulnerable_crate::" src/
   ```

2. **Update dependency**
   ```bash
   # Update to patched version
   cargo update -p vulnerable-crate

   # Or specify exact version in Cargo.toml
   ```

3. **If no patch available:**
   - Consider alternative crate
   - Implement workaround
   - Assess risk of continuing use

### Malicious Dependency (Supply Chain Attack)

1. **Immediately remove the dependency**
   ```bash
   # Remove from Cargo.toml
   # Clear cargo cache
   cargo clean
   rm -rf ~/.cargo/registry/cache/*/malicious-crate-*
   ```

2. **Audit what it accessed**
   - Review build scripts
   - Check for network access
   - Look for file system modifications

3. **Rebuild from clean state**
   ```bash
   cargo clean
   cargo build --release
   ```

4. **Report to RustSec and crates.io**

## Communication Templates

### Internal Notification

```
SECURITY INCIDENT - [SEVERITY]

What: [Brief description]
Impact: [What's affected]
Status: [Investigation/Contained/Resolved]
Actions needed: [What team members should do]

Updates will follow.
```

### External Advisory

```
## Security Advisory

**Severity**: [Critical/High/Medium/Low]
**CVE**: [If assigned]
**Affected versions**: [Version range]
**Patched in**: [Version]

### Description
[What the vulnerability is]

### Impact
[What an attacker could do]

### Mitigation
[How to protect yourself]

### Credit
[Researcher who reported, if they want credit]
```

## Post-Incident

### Retrospective Checklist

- [ ] Timeline documented
- [ ] Root cause identified
- [ ] Detection method recorded
- [ ] Response effectiveness evaluated
- [ ] Preventive measures identified
- [ ] Follow-up tasks created

### Preventive Measures

After each incident, consider:

1. **Can we detect this earlier?**
   - Add monitoring
   - Improve scanning
   - Add alerts

2. **Can we prevent this class of issue?**
   - Add CI gate
   - Update policy
   - Improve tooling

3. **Was response effective?**
   - Update runbooks
   - Improve communication
   - Train team

## Contacts

| Role | Responsibility |
|------|----------------|
| Maintainer | Triage and coordinate response |
| Security contact | Receive external reports |

For security issues, use GitHub Security Advisories (private disclosure).
