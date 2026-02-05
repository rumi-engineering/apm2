{
  "schema": "apm2.security_policy.v1",
  "schema_version": "1.0.0",
  "reporting": {
    "channel": "github_security_advisory",
    "url": "https://github.com/Anveio/apm2/security/advisories/new"
  },
  "response_times": {
    "critical": "immediate",
    "high": "24h",
    "medium": "7d",
    "low": "30d"
  },
  "source_of_truth": {
    "runtime_semantics": "HOLONIC_SUBSTRATE_INTERFACE.md",
    "operational_policy": "documents/security/SECURITY_POLICY.cac.json",
    "incident_playbook": "documents/security/INCIDENT_RESPONSE.cac.json"
  },
  "refs": {
    "security_docs_root": "documents/security/",
    "security_policy": "documents/security/SECURITY_POLICY.cac.json",
    "threat_model": "documents/security/THREAT_MODEL.cac.json",
    "signing_and_verification": "documents/security/SIGNING_AND_VERIFICATION.cac.json"
  }
}
