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
    "purpose": "Comprehensive agent user guide for the APM2 system. This is the one-stop reference for everything an agent does through the apm2 CLI. For daemon operator reference, see DAEMON.md.",

    "project": {
      "name": "APM2",
      "full_name": "APM2 — Holonic AI Process Manager",
      "version": "0.3.0",
      "description": "Daemon-supervised, event-sourced process manager for AI agents. Organizes agents in hierarchical part-whole (holonic) relationships with capability-based security, content-addressed evidence, and reducer/projection patterns.",
      "edition": "2024",
      "msrv": "1.85",
      "license": "MIT OR Apache-2.0"
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
      "patterns": ["event_sourcing", "reducer_projections", "content_addressed_evidence", "capability_based_control"],
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
      "dominance_order": ["containment_security", "verification_correctness", "liveness_progress"],
      "dominance_note": "When objectives conflict, higher-ranked concerns override lower-ranked ones. Security always wins."
    },

    "build_commands": {
      "build": "cargo build --workspace",
      "test": "cargo test --workspace",
      "fmt": "cargo fmt --all",
      "fmt_check": "cargo fmt --all -- --check",
      "clippy": "cargo clippy --workspace --all-targets --all-features -- -D warnings",
      "doc": "cargo doc --workspace --no-deps",
      "selftest": "cargo xtask selftest",
      "capabilities": "cargo xtask capabilities --json"
    },

    "cli_reference": {
      "binary": "apm2",
      "version": "0.3.0",
      "description": "CLI client for apm2 - AI CLI process manager",
      "global_options": {
        "--config <CONFIG>": "Path to ecosystem configuration file [default: ecosystem.toml]",
        "--socket <SOCKET>": "Path to Unix socket",
        "--log-level <LOG_LEVEL>": "Log level (trace, debug, info, warn, error) [default: warn]"
      },

      "commands": {
        "daemon": {
          "summary": "Start the daemon (background by default)",
          "usage": "apm2 daemon [OPTIONS]",
          "options": {
            "--no-daemon": "Run in foreground (don't daemonize)"
          }
        },

        "kill": {
          "summary": "Stop the daemon (graceful shutdown)",
          "usage": "apm2 kill"
        },

        "start": {
          "summary": "Start a configured process (all instances)",
          "usage": "apm2 start <NAME>",
          "arguments": {
            "<NAME>": "Process name"
          }
        },

        "stop": {
          "summary": "Stop a configured process (all instances)",
          "usage": "apm2 stop <NAME>",
          "arguments": {
            "<NAME>": "Process name"
          }
        },

        "restart": {
          "summary": "Restart a configured process (stop then start)",
          "usage": "apm2 restart <NAME>",
          "arguments": {
            "<NAME>": "Process name"
          }
        },

        "reload": {
          "summary": "Graceful reload (rolling restart) [daemon support pending]",
          "usage": "apm2 reload <NAME>",
          "arguments": {
            "<NAME>": "Process name"
          }
        },

        "list": {
          "summary": "List configured processes",
          "usage": "apm2 list"
        },

        "status": {
          "summary": "Show process details",
          "usage": "apm2 status <NAME>",
          "arguments": {
            "<NAME>": "Process name"
          }
        },

        "logs": {
          "summary": "Tail process logs [daemon support pending]",
          "usage": "apm2 logs [OPTIONS] <NAME>",
          "arguments": {
            "<NAME>": "Process name"
          },
          "options": {
            "-n, --lines <LINES>": "Number of lines to show [default: 20]",
            "-f, --follow": "Follow mode (stream new lines)"
          }
        },

        "creds": {
          "summary": "Credential management [daemon support pending]",
          "usage": "apm2 creds <COMMAND>",
          "subcommands": {
            "list": {
              "summary": "List credential profiles",
              "usage": "apm2 creds list"
            },
            "add": {
              "summary": "Add a new credential profile",
              "usage": "apm2 creds add [OPTIONS] --provider <PROVIDER> <PROFILE_ID>",
              "arguments": {
                "<PROFILE_ID>": "Profile ID"
              },
              "options": {
                "-p, --provider <PROVIDER>": "Provider (claude, gemini, openai)",
                "-a, --auth-method <AUTH_METHOD>": "Auth method (api_key, session_token, oauth) [default: api_key]"
              }
            },
            "remove": {
              "summary": "Remove a credential profile",
              "usage": "apm2 creds remove <PROFILE_ID>",
              "arguments": {
                "<PROFILE_ID>": "Profile ID"
              }
            },
            "refresh": {
              "summary": "Force refresh a credential profile",
              "usage": "apm2 creds refresh <PROFILE_ID>",
              "arguments": {
                "<PROFILE_ID>": "Profile ID"
              }
            },
            "switch": {
              "summary": "Switch credentials for a running process",
              "usage": "apm2 creds switch <PROCESS> <PROFILE>",
              "arguments": {
                "<PROCESS>": "Process name",
                "<PROFILE>": "New profile ID"
              }
            },
            "login": {
              "summary": "Print provider login instructions (does not store credentials)",
              "usage": "apm2 creds login [OPTIONS] <PROVIDER>",
              "arguments": {
                "<PROVIDER>": "Provider (claude, gemini, openai)"
              },
              "options": {
                "-p, --profile-id <PROFILE_ID>": "Profile ID to reference in printed instructions"
              }
            }
          }
        },

        "cac": {
          "summary": "Context-as-Code (CAC) commands",
          "usage": "apm2 cac <COMMAND>",
          "subcommands": {
            "apply-patch": {
              "summary": "Apply a patch to a CAC artifact with replay protection",
              "usage": "apm2 cac apply-patch [OPTIONS] --expected-base <EXPECTED_BASE> --base <BASE> --schema <SCHEMA> --dcp-id <DCP_ID>",
              "description": "Reads a patch document (JSON Patch RFC 6902 or Merge Patch RFC 7396) and applies it to a base document. Requires --expected-base for replay protection to prevent stale overwrites. NOTE: This command validates the patch and computes an admission receipt but does NOT persist the resulting artifact. The in-memory CAS is used for validation only.",
              "options": {
                "--expected-base <EXPECTED_BASE>": "Expected BLAKE3 hash of the base document (required for replay protection). Must match the hash of the current base document; fails with exit code 2 on mismatch (replay violation).",
                "--patch <PATCH>": "Path to the patch file. Use '-' or omit to read from stdin.",
                "--base <BASE>": "Path to the base document file.",
                "--schema <SCHEMA>": "Path to the JSON Schema file for validation.",
                "--dcp-id <DCP_ID>": "DCP ID for the artifact being patched.",
                "--artifact-kind <ARTIFACT_KIND>": "Artifact kind being patched [default: generic].",
                "--patch-type <PATCH_TYPE>": "Patch type: json-patch (RFC 6902) or merge-patch (RFC 7396) [default: json-patch].",
                "--dry-run": "Validate without committing to CAS.",
                "--format <FORMAT>": "Output format for the admission receipt: json or yaml [default: json]."
              }
            }
          }
        },

        "pack": {
          "summary": "Pack commands (compile and manage ContextPacks)",
          "usage": "apm2 pack <COMMAND>",
          "subcommands": {
            "compile": {
              "summary": "Compile a ContextPack specification into a manifest",
              "usage": "apm2 pack compile [OPTIONS] --spec <SPEC>",
              "description": "Reads a pack spec file, resolves dependencies through the DCP index, enforces budget constraints, and outputs a deterministic manifest. Exit codes: 0 success, 1 budget exceeded, 2 validation error.",
              "options": {
                "--spec <SPEC>": "Path to the pack spec file (JSON or YAML).",
                "--index <INDEX>": "Path to a DCP index file (JSON). Contains artifact metadata mapping stable IDs to content hashes. Required for compilation.",
                "--profile <PROFILE>": "Target profile override (replaces target_profile in spec).",
                "--budget-check": "Validation-only mode (check budget without full compilation).",
                "-o, --output <OUTPUT>": "Output path for the manifest (default: stdout).",
                "--format <FORMAT>": "Output format: json or yaml [default: json]."
              }
            }
          }
        },

        "export": {
          "summary": "Export a compiled context pack to target profile layout",
          "usage": "apm2 export [OPTIONS] --profile <PROFILE> --output-dir <OUTPUT_DIR> --index <INDEX>",
          "options": {
            "--profile <PROFILE>": "Path to the target profile file (YAML or JSON). Defines output format, budget policies, and delivery constraints.",
            "--pack <PACK>": "Path to the context pack file (YAML or JSON), or '-' for stdin.",
            "--output-dir <OUTPUT_DIR>": "Output directory for exported files. Must exist. Files written to subdirectories based on artifact stable IDs.",
            "--verify": "Run conformance tests after export. Outputs an ExportReceipt instead of just an ExportManifest.",
            "--format <FORMAT>": "Output format for manifest/receipt: json or yaml [default: json].",
            "--index <INDEX>": "Path to a DCP index file (JSON). Required for export operations."
          }
        },

        "coordinate": {
          "summary": "Coordinate work queue processing with budget enforcement",
          "usage": "apm2 coordinate [OPTIONS] --max-episodes <MAX_EPISODES>",
          "description": "Orchestrates multi-episode work processing. Claims work from the queue, spawns episodes with budget envelopes, and tracks completion. Stops when budget limits are reached.",
          "options": {
            "--work-ids <WORK_IDS>": "Work item IDs to process (comma-separated).",
            "--work-query <WORK_QUERY>": "Work query filter. Path to file with work IDs (one per line) or JSON array. Use '-' for stdin.",
            "--max-episodes <MAX_EPISODES>": "Maximum sessions to spawn (required). Coordination stops when this many sessions have been spawned.",
            "--max-duration-ticks <MAX_DURATION_TICKS>": "Maximum duration in ticks (HTF compliant). Takes precedence over max_duration_ms.",
            "--max-duration-ms <MAX_DURATION_MS>": "Maximum wall-clock time in milliseconds [default: 60000].",
            "--max-tokens <MAX_TOKENS>": "Maximum tokens to consume. Tracked but not limited if not specified.",
            "--max-attempts <MAX_ATTEMPTS>": "Maximum attempts per work item [default: 3].",
            "--max-work-queue <MAX_WORK_QUEUE>": "Maximum work items in queue [default: 1000]. Rejects larger queues to prevent memory exhaustion.",
            "--json": "Output as JSON receipt on completion.",
            "--quiet": "Suppress progress events, output only the final receipt.",
            "--actor-id <ACTOR_ID>": "Actor ID for work claiming (display hint) [default: apm2-coordinator].",
            "--workspace-root <WORKSPACE_ROOT>": "Workspace root directory for spawned episodes. All file operations confined to this directory."
          }
        },

        "episode": {
          "summary": "Episode commands for bounded execution management",
          "usage": "apm2 episode [OPTIONS] <COMMAND>",
          "common_options": {
            "--json": "Output format as JSON"
          },
          "subcommands": {
            "create": {
              "summary": "Create an episode from an envelope YAML file",
              "usage": "apm2 episode create --envelope <ENVELOPE>",
              "description": "The envelope defines immutable episode configuration: budget (tokens, tool calls, time limits), stop conditions, risk tier, determinism class, and capability manifest. Returns the created episode ID.",
              "options": {
                "--envelope <ENVELOPE>": "Path to the envelope YAML file."
              }
            },
            "start": {
              "summary": "Start a created episode (CREATED → RUNNING)",
              "usage": "apm2 episode start [OPTIONS] <EPISODE_ID>",
              "arguments": {
                "<EPISODE_ID>": "Episode ID to start"
              },
              "options": {
                "--lease-id <LEASE_ID>": "Lease ID authorizing execution (optional, daemon may generate)."
              }
            },
            "stop": {
              "summary": "Stop a running episode (RUNNING → TERMINATED)",
              "usage": "apm2 episode stop [OPTIONS] <EPISODE_ID>",
              "arguments": {
                "<EPISODE_ID>": "Episode ID to stop"
              },
              "options": {
                "--reason <REASON>": "Reason: success, cancelled, failure [default: success].",
                "--message <MESSAGE>": "Custom reason message."
              }
            },
            "status": {
              "summary": "Show episode status, budget remaining, and telemetry summary",
              "usage": "apm2 episode status <EPISODE_ID>",
              "arguments": {
                "<EPISODE_ID>": "Episode ID to query"
              }
            },
            "list": {
              "summary": "List episodes with optional state filter",
              "usage": "apm2 episode list [OPTIONS]",
              "options": {
                "--state <STATE>": "Filter: all, created, running, terminated, quarantined [default: all].",
                "--limit <LIMIT>": "Maximum number of episodes to return [default: 100]."
              }
            },
            "spawn": {
              "summary": "Spawn an episode for work execution (TCK-00288)",
              "usage": "apm2 episode spawn [OPTIONS] --work-id <WORK_ID> --workspace-root <WORKSPACE_ROOT>",
              "description": "Uses protocol-based IPC via OperatorClient::spawn_episode. Returns session ID and token for subsequent session-scoped operations.",
              "options": {
                "--work-id <WORK_ID>": "Work identifier from a prior ClaimWork.",
                "--role <ROLE>": "Role: implementer, gate-executor, reviewer, coordinator [default: implementer].",
                "--lease-id <LEASE_ID>": "Lease ID (required for GATE_EXECUTOR role).",
                "--workspace-root <WORKSPACE_ROOT>": "Workspace root directory. All file operations confined here. Must be absolute path to existing directory."
              }
            },
            "session-status": {
              "summary": "Query session-scoped episode status (TCK-00288)",
              "usage": "apm2 episode session-status [OPTIONS]",
              "description": "Uses session socket with session token for authentication. Returns current session state and telemetry summary.",
              "options": {
                "--session-token <SESSION_TOKEN>": "Session token for authentication. Security (CWE-214): prefer APM2_SESSION_TOKEN env var. [env: APM2_SESSION_TOKEN=]"
              }
            }
          }
        },

        "consensus": {
          "summary": "Consensus commands for cluster status and diagnostics",
          "usage": "apm2 consensus [OPTIONS] <COMMAND>",
          "common_options": {
            "--json": "Output format as JSON"
          },
          "subcommands": {
            "status": {
              "summary": "Show cluster health and leader info",
              "usage": "apm2 consensus status [OPTIONS]",
              "description": "Displays current epoch, round, leader, validator count, and health status.",
              "options": {
                "--verbose": "Show detailed information including QC details."
              }
            },
            "validators": {
              "summary": "List validators in the consensus cluster",
              "usage": "apm2 consensus validators [OPTIONS]",
              "description": "Shows validator IDs, public keys, and active status.",
              "options": {
                "--active-only": "Show only active validators."
              }
            },
            "byzantine-evidence": {
              "summary": "Byzantine fault evidence commands",
              "usage": "apm2 consensus byzantine-evidence <COMMAND>",
              "subcommands": {
                "list": {
                  "summary": "List detected Byzantine fault evidence",
                  "usage": "apm2 consensus byzantine-evidence list [OPTIONS]",
                  "description": "Shows equivocation, invalid signatures, and other detected faults.",
                  "options": {
                    "--fault-type <FAULT_TYPE>": "Filter by: equivocation, invalid_signature, quorum_forgery, or replay.",
                    "--limit <LIMIT>": "Maximum entries to return (max 1000) [default: 100]."
                  }
                }
              }
            },
            "metrics": {
              "summary": "Show consensus metrics summary",
              "usage": "apm2 consensus metrics [OPTIONS]",
              "description": "Displays key metrics from the consensus layer for quick diagnostics.",
              "options": {
                "--period <PERIOD>": "Time period for rate calculations in seconds [default: 60]."
              }
            }
          }
        },

        "work": {
          "summary": "Work queue commands (claim work from queue)",
          "usage": "apm2 work [OPTIONS] <COMMAND>",
          "common_options": {
            "--json": "Output format as JSON"
          },
          "subcommands": {
            "claim": {
              "summary": "Claim work from the daemon's work queue",
              "usage": "apm2 work claim [OPTIONS] --actor-id <ACTOR_ID>",
              "description": "Requests a work assignment with policy-resolved capabilities. The daemon validates the credential signature and returns work details.",
              "options": {
                "--actor-id <ACTOR_ID>": "Actor ID (display hint, authoritative ID derived from credential).",
                "--role <ROLE>": "Role: implementer, gate-executor, reviewer, coordinator [default: implementer].",
                "--signature <SIGNATURE>": "Credential signature (hex-encoded Ed25519). Computed over (actor_id || role || nonce).",
                "--nonce <NONCE>": "Nonce (hex-encoded) for replay protection."
              }
            },
            "status": {
              "summary": "Query work status (projection-backed, TCK-00288/TCK-00415)",
              "usage": "apm2 work status --work-id <WORK_ID>",
              "description": "Returns current lifecycle status derived from ledger event projection. Authority is rebuilt from ledger events only; filesystem ticket state is not consulted.",
              "options": {
                "--work-id <WORK_ID>": "Work identifier to query."
              }
            },
            "list": {
              "summary": "List work items from projection (TCK-00415)",
              "usage": "apm2 work list [OPTIONS]",
              "description": "Lists work items known to the runtime projection. Supports filtering by claimable status, cursor-based pagination, and a hard server-side cap of 500 rows.",
              "options": {
                "--claimable-only": "Only show claimable work items.",
                "--limit <LIMIT>": "Maximum rows to return (clamped to 500).",
                "--cursor <CURSOR>": "Last work_id from previous page (exclusive start for pagination)."
              }
            }
          }
        },

        "tool": {
          "summary": "Tool commands (request tool execution via session socket)",
          "usage": "apm2 tool [OPTIONS] <COMMAND>",
          "common_options": {
            "--json": "Output format as JSON"
          },
          "subcommands": {
            "request": {
              "summary": "Request tool execution within session capability bounds",
              "usage": "apm2 tool request [OPTIONS] --tool-id <TOOL_ID>",
              "description": "The daemon validates the session token and checks capabilities before allowing tool execution.",
              "options": {
                "--session-token <SESSION_TOKEN>": "Session token. Security (CWE-214): prefer APM2_SESSION_TOKEN env var. [env: APM2_SESSION_TOKEN=]",
                "--tool-id <TOOL_ID>": "Tool identifier (e.g., file_read, shell_exec).",
                "--arguments <ARGUMENTS>": "Tool arguments as JSON string [default: {}].",
                "--dedupe-key <DEDUPE_KEY>": "Deduplication key for idempotent requests."
              }
            }
          }
        },

        "event": {
          "summary": "Event commands (emit events to ledger via session socket)",
          "usage": "apm2 event [OPTIONS] <COMMAND>",
          "common_options": {
            "--json": "Output format as JSON"
          },
          "subcommands": {
            "emit": {
              "summary": "Emit a signed event to the ledger",
              "usage": "apm2 event emit [OPTIONS] --event-type <EVENT_TYPE>",
              "description": "Events are recorded in the daemon's ledger with cryptographic signatures for tamper-evidence.",
              "options": {
                "--session-token <SESSION_TOKEN>": "Session token. Security (CWE-214): prefer APM2_SESSION_TOKEN env var. [env: APM2_SESSION_TOKEN=]",
                "--event-type <EVENT_TYPE>": "Event type identifier (e.g., work.started, tool.executed).",
                "--payload <PAYLOAD>": "Event payload as JSON string [default: {}].",
                "--correlation-id <CORRELATION_ID>": "Correlation ID for event tracing."
              }
            }
          }
        },

        "capability": {
          "summary": "Capability commands (issue capabilities to sessions via operator socket)",
          "usage": "apm2 capability [OPTIONS] <COMMAND>",
          "common_options": {
            "--json": "Output format as JSON"
          },
          "subcommands": {
            "issue": {
              "summary": "Issue a capability to a session",
              "usage": "apm2 capability issue [OPTIONS] --session-id <SESSION_ID> --tool-class <TOOL_CLASS>",
              "description": "Grants additional tool access or path patterns to an existing session. Requires operator privileges.",
              "options": {
                "--session-id <SESSION_ID>": "Target session identifier.",
                "--tool-class <TOOL_CLASS>": "Tool class to grant (e.g., file_read, shell_exec).",
                "--read-pattern <READ_PATTERN>": "Path patterns for read access (repeatable).",
                "--write-pattern <WRITE_PATTERN>": "Path patterns for write access (repeatable).",
                "--duration-secs <DURATION_SECS>": "Duration in seconds for the capability grant [default: 3600]."
              }
            }
          }
        },

        "evidence": {
          "summary": "Evidence commands (publish evidence artifacts via session socket)",
          "usage": "apm2 evidence [OPTIONS] <COMMAND>",
          "common_options": {
            "--json": "Output format as JSON"
          },
          "subcommands": {
            "publish": {
              "summary": "Publish evidence artifact to content-addressed storage",
              "usage": "apm2 evidence publish [OPTIONS] --path <PATH>",
              "description": "Uploads the artifact content and returns the content hash.",
              "options": {
                "--session-token <SESSION_TOKEN>": "Session token. Security (CWE-214): prefer APM2_SESSION_TOKEN env var. [env: APM2_SESSION_TOKEN=]",
                "--kind <KIND>": "Evidence kind: pty-transcript, tool-io, telemetry-raw, adapter-failure, incident-snapshot [default: pty-transcript].",
                "--path <PATH>": "Path to the artifact file.",
                "--retention <RETENTION>": "Retention hint: ephemeral, standard, archival [default: ephemeral]."
              }
            }
          }
        },

        "fac": {
          "summary": "FAC commands (ledger/CAS oriented debug UX)",
          "usage": "apm2 fac [OPTIONS] <COMMAND>",
          "description": "Forge Admission Cycle debug commands. Operate directly on ledger and CAS without requiring a running daemon.",
          "common_options": {
            "--json": "Output format as JSON",
            "--ledger-path <LEDGER_PATH>": "Path to ledger database (defaults to $APM2_DATA_DIR/ledger.db)",
            "--cas-path <CAS_PATH>": "Path to CAS directory (defaults to $APM2_DATA_DIR/cas)"
          },
          "subcommands": {
            "work": {
              "summary": "Work lifecycle queries (projection-backed, TCK-00415)",
              "description": "Queries work lifecycle state via daemon projection or direct ledger scan. The `status` subcommand returns projection-derived authority state; `list` enumerates known work items with pagination.",
              "subcommands": {
                "status": {
                  "usage": "apm2 fac work status [OPTIONS] <WORK_ID>",
                  "description": "Displays projection-derived lifecycle status for a work item, including state, claimability, transition count, and timestamps. Routes through the daemon's shared ProjectionWorkAuthority.",
                  "arguments": {
                    "<WORK_ID>": "Work identifier to query"
                  }
                },
                "list": {
                  "usage": "apm2 fac work list [OPTIONS]",
                  "description": "Lists all projection-known work items via the daemon. Supports --claimable-only filtering and cursor-based pagination with a hard cap of 500 rows.",
                  "options": {
                    "--claimable-only": "Only show claimable work items.",
                    "--limit <LIMIT>": "Maximum rows to return (clamped to 500).",
                    "--cursor <CURSOR>": "Last work_id from previous page for pagination."
                  }
                }
              }
            },
            "episode": {
              "summary": "Inspect episode details and tool log index",
              "usage": "apm2 fac episode inspect [OPTIONS] <EPISODE_ID>",
              "description": "Shows episode metadata and tool execution summary from ledger events.",
              "arguments": {
                "<EPISODE_ID>": "Episode identifier to inspect"
              },
              "options": {
                "--full": "Show full tool log index (default: summary only).",
                "--limit <LIMIT>": "Maximum events to scan [default: 10000]."
              }
            },
            "receipt": {
              "summary": "Show receipt from CAS",
              "usage": "apm2 fac receipt show <RECEIPT_HASH>",
              "description": "Retrieves and displays a receipt artifact from content-addressed storage. Supports gate receipts, review receipts, and summary receipts.",
              "arguments": {
                "<RECEIPT_HASH>": "Receipt hash (hex-encoded BLAKE3)"
              }
            },
            "context": {
              "summary": "Rebuild role-scoped context deterministically",
              "usage": "apm2 fac context rebuild [OPTIONS] <ROLE> <EPISODE_ID>",
              "description": "Reconstructs the context pack for a role+episode combination from ledger events and CAS artifacts. Useful for debugging and replay.",
              "arguments": {
                "<ROLE>": "Role for context rebuild (implementer, reviewer, etc.)",
                "<EPISODE_ID>": "Episode identifier"
              },
              "options": {
                "--output-dir <OUTPUT_DIR>": "Output directory for rebuilt context.",
                "--limit <LIMIT>": "Maximum events to scan [default: 10000]."
              }
            },
            "resume": {
              "summary": "Show crash-only resume helpers from ledger anchor",
              "usage": "apm2 fac resume [OPTIONS] <WORK_ID>",
              "description": "Analyzes ledger to determine restart point for interrupted work. Returns last committed anchor and pending operations.",
              "arguments": {
                "<WORK_ID>": "Work identifier to analyze for resume point"
              },
              "options": {
                "--limit <LIMIT>": "Maximum events to scan [default: 10000]."
              }
            }
          }
        },

        "factory": {
          "summary": "Factory commands (runs Markdown specs)",
          "usage": "apm2 factory <COMMAND>",
          "description": "The factory subsystem compiles PRDs into RFCs and tickets through a deterministic pipeline. Each stage produces content-addressed artifacts.",
          "subcommands": {
            "run": {
              "summary": "Run a Markdown spec with an agent CLI (currently Claude Code)",
              "usage": "apm2 factory run [OPTIONS] <SPEC_FILE>",
              "arguments": {
                "<SPEC_FILE>": "Path to the spec file (PRD, RFC, or Ticket)"
              },
              "options": {
                "--format <FORMAT>": "Output format: text or json [default: text]."
              }
            },
            "ccp": {
              "summary": "CCP (Code Context Protocol) commands",
              "usage": "apm2 factory ccp build [OPTIONS] --prd <PRD>",
              "description": "Build the CCP index for a PRD. Maps codebase structure for requirement grounding.",
              "options": {
                "--prd <PRD>": "PRD identifier (e.g., PRD-0001).",
                "--repo-root <REPO_ROOT>": "Path to repository root [default: current directory].",
                "--force": "Force rebuild even if index hash hasn't changed.",
                "--dry-run": "Compute but don't write output.",
                "--format <FORMAT>": "Output format: text or json [default: text]."
              }
            },
            "impact-map": {
              "summary": "Impact Map commands (PRD requirement to CCP component mapping)",
              "usage": "apm2 factory impact-map build [OPTIONS] --prd <PRD>",
              "description": "Build the impact map for a PRD. Maps requirements to codebase components.",
              "options": {
                "--prd <PRD>": "PRD identifier (e.g., PRD-0005).",
                "--repo-root <REPO_ROOT>": "Path to repository root [default: current directory].",
                "--force": "Force rebuild even if inputs haven't changed.",
                "--dry-run": "Compute but don't write output.",
                "--format <FORMAT>": "Output format: text or json [default: text]."
              }
            },
            "rfc": {
              "summary": "RFC commands (RFC framing from Impact Map and CCP)",
              "usage": "apm2 factory rfc frame [OPTIONS] --prd <PRD> --rfc <RFC>",
              "description": "Frame an RFC from Impact Map and CCP artifacts.",
              "options": {
                "--prd <PRD>": "PRD identifier (e.g., PRD-0005).",
                "--rfc <RFC>": "RFC identifier (e.g., RFC-0011).",
                "--repo-root <REPO_ROOT>": "Path to repository root [default: current directory].",
                "--force": "Force overwrite if RFC already exists.",
                "--dry-run": "Compute but don't write output.",
                "--skip-validation": "Skip path validation against CCP (not recommended).",
                "--format <FORMAT>": "Output format: text or json [default: text]."
              }
            },
            "tickets": {
              "summary": "Ticket commands (emit tickets from RFC decomposition)",
              "usage": "apm2 factory tickets emit [OPTIONS] --rfc <RFC>",
              "description": "Emit tickets from an RFC's ticket decomposition section.",
              "options": {
                "--rfc <RFC>": "RFC identifier (e.g., RFC-0010).",
                "--prd <PRD>": "PRD identifier for CCP validation (optional).",
                "--repo-root <REPO_ROOT>": "Path to repository root [default: current directory].",
                "--force": "Force overwrite if tickets already exist.",
                "--dry-run": "Compute but don't write output.",
                "--skip-validation": "Skip path validation (not recommended).",
                "--format <FORMAT>": "Output format: text or json [default: text]."
              }
            },
            "compile": {
              "summary": "Compile pipeline (end-to-end PRD to tickets)",
              "usage": "apm2 factory compile [OPTIONS] --prd <PRD>",
              "description": "End-to-end pipeline: PRD → CCP → Impact Map → RFC → Tickets. Each stage produces content-addressed artifacts.",
              "options": {
                "--prd <PRD>": "PRD identifier (e.g., PRD-0005). Required.",
                "--rfc <RFC>": "RFC identifier (e.g., RFC-0011). Auto-generated if omitted.",
                "--profile <PROFILE>": "Routing profile name [default: local].",
                "--dry-run": "Report intended writes without modifying files.",
                "--output-dir <OUTPUT_DIR>": "Override default output directory.",
                "--sign": "Sign the run manifest with configured key.",
                "--repo-root <REPO_ROOT>": "Path to repository root [default: current directory].",
                "--force": "Force rebuild even if artifacts are up to date.",
                "--format <FORMAT>": "Output format: text or json (NDJSON events) [default: text]."
              }
            },
            "refactor": {
              "summary": "Refactor radar (maintenance recommendations)",
              "usage": "apm2 factory refactor radar [OPTIONS]",
              "description": "Analyzes codebase for refactoring opportunities and outputs prioritized recommendations.",
              "options": {
                "--window <WINDOW>": "Time window for analysis (e.g., 7d, 30d) [default: 7d].",
                "--max-items <MAX_ITEMS>": "Maximum recommendations to output [default: 10].",
                "--ignore-breaker": "Force output even if circuit breaker is tripped.",
                "--backlog-threshold <BACKLOG_THRESHOLD>": "Backlog threshold for circuit breaker [default: 20].",
                "--repo-root <REPO_ROOT>": "Path to repository root [default: current directory].",
                "--format <FORMAT>": "Output format: yaml, json, or text [default: yaml]."
              }
            }
          }
        }
      }
    },

    "agent_workflows": {
      "description": "Common workflows an agent follows when interacting with the apm2 system.",
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

    "environment_variables": {
      "APM2_SESSION_TOKEN": "Session token for authentication. Preferred over --session-token flag for security (CWE-214).",
      "APM2_DATA_DIR": "Data directory for ledger and CAS. Used by fac commands when --ledger-path / --cas-path not specified."
    },

    "developer_environment": {
      "nix_dev_shell": {
        "enter": "nix develop",
        "update_lockfile": "nix --extra-experimental-features 'nix-command flakes' flake lock"
      },
      "skills_runtime_sync": {
        "source_of_truth": "documents/skills/",
        "sync_command": "scripts/dev/skills_runtime_sync.sh sync",
        "check_command": "scripts/dev/skills_runtime_sync.sh --check",
        "global_runtime_path_pattern": "${XDG_STATE_HOME:-$HOME/.local/state}/apm2/skills/<repo_id>/<worktree_id>",
        "worktree_layout": ".claude/skills -> ${XDG_STATE_HOME:-$HOME/.local/state}/apm2/skills/<repo_id>/<worktree_id>",
        "migration_note": "Legacy .claude/sync-skills.sh is retired. Use scripts/dev/skills_runtime_sync.sh."
      }
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
