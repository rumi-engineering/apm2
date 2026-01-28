{
  "schema": "apm2.repo_agents.v1",
  "schema_version": "1.0.0",
  "project": {
    "name": "APM2 - Holonic AI Process Manager",
    "version": "0.3.0",
    "edition": "2024",
    "msrv": "1.85"
  },
  "runtime": {
    "os": "linux",
    "ipc": "uds_len_prefixed_json",
    "default_config": "ecosystem.toml"
  },
  "binaries": [
    {
      "name": "apm2",
      "crate": "apm2-cli",
      "role": "cli_client"
    },
    {
      "name": "apm2-daemon",
      "crate": "apm2-daemon",
      "role": "daemon"
    },
    {
      "name": "xtask",
      "crate": "xtask",
      "role": "dev_automation"
    }
  ],
  "commands": {
    "test": [
      "cargo test -q"
    ],
    "fmt": [
      "cargo fmt --all"
    ],
    "clippy": [
      "cargo clippy --all-targets --all-features -- -D warnings"
    ],
    "capabilities_json": [
      "cargo xtask capabilities --json"
    ],
    "selftest": [
      "cargo xtask selftest"
    ]
  },
  "crates": [
    {
      "name": "apm2-holon",
      "path": "crates/apm2-holon",
      "role": "holon trait + resources + work lifecycle",
      "loc_approx": 4500
    },
    {
      "name": "apm2-core",
      "path": "crates/apm2-core",
      "role": "daemon runtime + reducers + adapters + evidence",
      "loc_approx": 35000
    },
    {
      "name": "apm2-daemon",
      "path": "crates/apm2-daemon",
      "role": "unix socket server + IPC handlers",
      "loc_approx": 1000
    },
    {
      "name": "apm2-cli",
      "path": "crates/apm2-cli",
      "role": "command-line interface",
      "loc_approx": 1200
    },
    {
      "name": "xtask",
      "path": "xtask",
      "role": "development automation",
      "loc_approx": 2000
    }
  ],
  "system_model": {
    "layers": [
      "apm2-cli",
      "apm2-daemon",
      "apm2-core",
      "apm2-holon"
    ],
    "patterns": [
      "event_sourcing",
      "reducer_projections",
      "content_addressed_evidence",
      "capability_based_control"
    ]
  },
  "protocol_refs": {
    "ipc_docs": "crates/apm2-core/src/ipc/AGENTS.md",
    "event_schema": "proto/kernel_events.proto",
    "tool_protocol": "proto/tool_protocol.proto"
  },
  "doc_refs": {
    "root_onboarding": "ROOT_ONBOARDING.cac.md",
    "documents_index": "documents/README.md",
    "skills_root": "documents/skills/",
    "glossary_root": "documents/skills/glossary/",
    "holonic_unified_theory": "documents/skills/laws-of-holonic-agent-systems/references/unified-theory.md",
    "security_policy": "SECURITY.md",
    "security_docs_root": "documents/security/",
    "schemas_root": "schemas/apm2/"
  },
  "governance": {
    "dominance_order": [
      "containment_security",
      "verification_correctness",
      "liveness_progress"
    ],
    "worktree": {
      "dirty_expected": true,
      "git_clean_required": false,
      "unrelated_changes_policy": "ignore_unless_blocking_or_hazard"
    }
  }
}
