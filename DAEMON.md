{
  "schema": "cac.daemon_reference.v1",
  "schema_version": "1.0.0",
  "kind": "daemon.reference",
  "meta": {
    "stable_id": "dcp://apm2/doc/daemon-reference@v1",
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
      "work_id": "DOC-DAEMON-REFERENCE-20260206",
      "source_receipts": []
    }
  },
  "payload": {
    "purpose": "Operator reference for the apm2-daemon binary. Covers configuration, startup, socket security, persistence, and metrics. For the CLI agent user guide, see README.md.",

    "binary": {
      "name": "apm2-daemon",
      "version": "0.3.0",
      "description": "Daemon binary for apm2 - AI CLI process manager",
      "crate": "crates/apm2-daemon"
    },

    "usage": "apm2-daemon [OPTIONS]",

    "options": {
      "-c, --config <CONFIG>": {
        "description": "Path to ecosystem configuration file",
        "default": "ecosystem.toml"
      },
      "--no-daemon": {
        "description": "Run in foreground (don't daemonize). Useful for debugging and container deployments."
      },
      "--pid-file <PID_FILE>": {
        "description": "Path to PID file. Used for process management and preventing duplicate daemons."
      },
      "--operator-socket <OPERATOR_SOCKET>": {
        "description": "Path to operator Unix socket (mode 0600, privileged operations). Only the daemon owner can connect.",
        "security": "Privileged operations: spawn episodes, issue capabilities, kill daemon. Socket created with mode 0600."
      },
      "--session-socket <SESSION_SOCKET>": {
        "description": "Path to session Unix socket (mode 0660, session-scoped operations). Requires session token authentication.",
        "security": "Session-scoped operations: tool requests, evidence publish, event emit. Socket created with mode 0660."
      },
      "--state-file <STATE_FILE>": {
        "description": "Path to state file for persistent session registry (TCK-00266). Enables session state survival across daemon restarts."
      },
      "--ledger-db <LEDGER_DB>": {
        "description": "Path to ledger database file (SQLite). Stores event-sourced ledger for tamper-evident audit trail."
      },
      "--cas-path <CAS_PATH>": {
        "description": "Path to durable content-addressed storage (CAS) directory (TCK-00383). When provided with --ledger-db, enables full session dispatcher wiring via with_persistence_and_cas(). Directory created with mode 0700 if it does not exist."
      },
      "--log-level <LOG_LEVEL>": {
        "description": "Log level (trace, debug, info, warn, error)",
        "default": "info"
      },
      "--log-file <LOG_FILE>": {
        "description": "Log to file instead of stdout. Useful for daemonized operation."
      },
      "--metrics-port <METRICS_PORT>": {
        "description": "Port for Prometheus metrics HTTP endpoint (TCK-00268)",
        "default": "9100"
      },
      "--no-metrics": {
        "description": "Disable Prometheus metrics HTTP endpoint entirely."
      }
    },

    "socket_architecture": {
      "description": "The daemon exposes two Unix domain sockets with different permission models, implementing a split-privilege design.",
      "operator_socket": {
        "mode": "0600",
        "access": "Daemon owner only",
        "operations": [
          "Spawn episodes (episode spawn)",
          "Issue capabilities to sessions (capability issue)",
          "Kill daemon (kill)",
          "Claim work from queue (work claim)"
        ],
        "cli_commands": ["apm2 daemon", "apm2 kill", "apm2 episode spawn", "apm2 capability issue", "apm2 work claim", "apm2 coordinate"]
      },
      "session_socket": {
        "mode": "0660",
        "access": "Session token holders",
        "authentication": "APM2_SESSION_TOKEN environment variable or --session-token flag",
        "operations": [
          "Request tool execution (tool request)",
          "Emit ledger events (event emit)",
          "Publish evidence to CAS (evidence publish)",
          "Query session status (episode session-status)"
        ],
        "cli_commands": ["apm2 tool request", "apm2 event emit", "apm2 evidence publish", "apm2 episode session-status"]
      }
    },

    "persistence": {
      "state_file": {
        "purpose": "Persistent session registry. Enables session state survival across daemon restarts.",
        "ticket": "TCK-00266",
        "format": "Binary serialized session state"
      },
      "ledger_db": {
        "purpose": "Event-sourced ledger for tamper-evident audit trail. Stores all work claims, episode lifecycle events, tool executions, and evidence publications.",
        "format": "SQLite database",
        "cli_access": "apm2 fac work|episode|receipt|context|resume commands can query the ledger directly without a running daemon."
      },
      "cas_directory": {
        "purpose": "Durable content-addressed storage for evidence artifacts and receipts.",
        "ticket": "TCK-00383",
        "mode": "0700 (created automatically if missing)",
        "addressing": "BLAKE3 content hashes",
        "cli_access": "apm2 fac receipt show <hash> retrieves artifacts by hash."
      }
    },

    "metrics": {
      "endpoint": "http://localhost:{metrics-port}/metrics",
      "format": "Prometheus exposition format",
      "ticket": "TCK-00268",
      "default_port": 9100,
      "disable": "--no-metrics flag",
      "infrastructure": {
        "grafana_dashboards": "deploy/grafana/",
        "prometheus_config": "deploy/prometheus/"
      }
    },

    "startup_modes": {
      "daemonized": {
        "command": "apm2-daemon --config ecosystem.toml",
        "description": "Default mode. Forks to background, writes PID file, creates sockets."
      },
      "foreground": {
        "command": "apm2-daemon --no-daemon --config ecosystem.toml",
        "description": "Runs in foreground. Useful for debugging, containers, and systemd Type=simple services."
      },
      "full_persistence": {
        "command": "apm2-daemon --config ecosystem.toml --ledger-db /var/lib/apm2/ledger.db --cas-path /var/lib/apm2/cas --state-file /var/lib/apm2/state.bin",
        "description": "Full persistence mode with ledger, CAS, and session state."
      },
      "via_cli": {
        "command": "apm2 daemon [--no-daemon]",
        "description": "Start daemon through the CLI wrapper. Passes through --no-daemon flag."
      }
    },

    "shutdown": {
      "graceful": "apm2 kill — sends graceful shutdown signal via operator socket.",
      "signal": "SIGTERM — daemon handles gracefully, flushing ledger and closing sockets.",
      "force": "SIGKILL — immediate termination, may leave stale PID file and sockets."
    },

    "key_refs": {
      "cli_user_guide": "README.md",
      "context_router": "AGENTS.md",
      "crate_source": "crates/apm2-daemon/",
      "crate_agents": "crates/apm2-daemon/AGENTS.md",
      "protocol_def": "proto/apm2d_runtime_v1.proto",
      "ci_config": ".github/workflows/ci.yml"
    }
  }
}
