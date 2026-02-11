{
  "schema": "cac.agent_user_guide.v1",
  "schema_version": "1.0.0",
  "kind": "agent.user_guide",
  "meta": {
    "stable_id": "dcp://apm2/doc/agent-user-guide@v1",
    "classification": "PUBLIC",
    "created_at": "2026-02-06T00:00:00Z",
    "updated_at": "2026-02-06T00:00:00Z",
    "canonicalizer": {
      "canonicalizer_id": "apm2.canonicalizer.jcs",
      "canonicalizer_version": "1.0.0",
      "vectors_ref": "dcp://apm2.cac/canonicalizer/vectors@v1"
    },
    "provenance": {
      "actor_id": "HOLON-DOC-GOVERNANCE",
      "work_id": "DOC-AGENT-USER-GUIDE-20260206",
      "source_receipts": []
    }
  },
  "payload": {
    "purpose": "Agent guide for APM2 architecture, governance, and workflow patterns. CLI command surfaces are intentionally discovered at runtime via --help; for daemon operator reference, see DAEMON.md.",
    "project": {
      "name": "APM2",
      "full_name": "APM2 — Holonic AI Process Manager rooted in Proof-Admitted Stigmergic Morphogenesis (PASM) theory.",
      "version": "0.3.0",
      "description": "Daemon-supervised, event-sourced process manager for AI agents. Organizes agents in hierarchical part-whole (holonic) relationships with capability-based security, content-addressed evidence, and reducer/projection patterns.",
      "edition": "2024",
      "msrv": "1.85"
    },
    "architecture": {
      "layers": [
        {
          "name": "apm2-cli",
          "role": "Command-line interface. User-facing entry point. Sends IPC requests to the daemon.",
          "crate": "crates/apm2-cli"
        },
        {
          "name": "apm2-daemon",
          "role": "Unix domain socket server. Receives IPC requests, dispatches to core, manages sessions and telemetry.",
          "crate": "crates/apm2-daemon"
        },
        {
          "name": "apm2-core",
          "role": "Daemon runtime. Reducers, adapters, evidence engine, FAC, HTF, consensus, policy, and all domain logic.",
          "crate": "crates/apm2-core"
        },
        {
          "name": "apm2-holon",
          "role": "Holon trait, resources (budget, lease, scope), work lifecycle, artifact model, and spawn protocol.",
          "crate": "crates/apm2-holon"
        }
      ],
      "patterns": [
        "event_sourcing",
        "reducer_projections",
        "content_addressed_evidence",
        "capability_based_control"
      ],
      "ipc": {
        "transport": "unix_domain_socket",
        "sockets": {
          "operator": "Mode 0600. Privileged operations (spawn episodes, issue capabilities, kill daemon).",
          "session": "Mode 0660. Session-scoped operations (tool requests, evidence publish, event emit). Requires session token."
        },
        "protocol_def": "proto/apm2d_runtime_v1.proto"
      }
    },
    "governance": {
      "dominance_order": [
        "containment_security",
        "verification_correctness",
        "liveness_progress"
      ],
      "dominance_note": "When objectives conflict, higher-ranked concerns override lower-ranked ones. Security always wins."
    },
    "build_commands": {
      "build": "cargo build --workspace",
      "test": "cargo test --workspace",
      "fmt": "cargo fmt --all",
      "fmt_check": "cargo fmt --all -- --check",
      "clippy": "cargo clippy --workspace --all-targets --all-features -- -D warnings",
      "doc": "cargo doc --workspace --no-deps"
    },
    "agent_workflows": {
      "description": "Common agent workflows (illustrative only). Resolve exact command/flag syntax via --help in the current runtime.",
      "typical_session_lifecycle": [
        "1. Claim work: apm2 work claim --actor-id <id> --role implementer",
        "2. Spawn episode: apm2 episode spawn --work-id <id> --workspace-root /path",
        "3. Execute tools: apm2 tool request --tool-id file_read --arguments '{...}'",
        "4. Emit events: apm2 event emit --event-type work.progress --payload '{...}'",
        "5. Publish evidence: apm2 evidence publish --path artifact.log --kind pty-transcript",
        "6. Stop episode: apm2 episode stop <episode-id> --reason success"
      ],
      "factory_pipeline": [
        "1. Build CCP index: apm2 factory ccp build --prd PRD-0005",
        "2. Build impact map: apm2 factory impact-map build --prd PRD-0005",
        "3. Frame RFC: apm2 factory rfc frame --prd PRD-0005 --rfc RFC-0011",
        "4. Emit tickets: apm2 factory tickets emit --rfc RFC-0011",
        "Or run the full pipeline: apm2 factory compile --prd PRD-0005"
      ],
      "debug_and_resume": [
        "1. Check work status: apm2 fac work status <work-id>",
        "2. Inspect episode: apm2 fac episode inspect <episode-id>",
        "3. View receipt: apm2 fac receipt show <hash>",
        "4. Rebuild context: apm2 fac context rebuild <role> <episode-id>",
        "5. Resume from anchor: apm2 fac resume <work-id>"
      ]
    },
    "security_notes": {
      "session_tokens": "Always use APM2_SESSION_TOKEN environment variable instead of --session-token CLI flag. CLI arguments are visible in process listings on multi-user systems (CWE-214).",
      "operator_socket": "Mode 0600. Only the daemon owner can send operator commands (spawn, capability issue, kill).",
      "session_socket": "Mode 0660. Session-scoped operations require valid session tokens.",
      "credential_signatures": "Work claims require Ed25519 signatures computed over (actor_id || role || nonce) for replay protection.",
      "replay_protection": "CAC patch operations require --expected-base BLAKE3 hash to prevent stale overwrites."
    }
  }
}
