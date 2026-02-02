# CLI Usability Plan (Agent Interface)

## Evidence-Based Diagnosis (Current Failures)
- Legacy socket default: CLI uses a single `--socket` and defaults to `config.daemon.socket` or
  `/tmp/apm2/apm2d.sock`, while config rejects `daemon.socket` and expects operator/session sockets.
  Evidence: `crates/apm2-cli/src/main.rs:27-29`, `crates/apm2-cli/src/main.rs:248-260`,
  `crates/apm2-core/src/config/mod.rs:50-64`, `ecosystem.example.toml:4-7`.
- JSON protocol mismatch: CLI serializes JSON `IpcRequest`/`IpcResponse` over the daemon socket.
  Evidence: `crates/apm2-cli/src/client/daemon.rs:214-256`, `crates/apm2-cli/src/client/daemon.rs:414-447`.
  ProtocolServer dispatchers use tag-based frames, not JSON. Evidence:
  `crates/apm2-daemon/src/protocol/session_dispatch.rs:336-340`.
- Episode commands are wired to JSON IPC but daemon JSON handler returns NotSupported for non-process
  requests. Evidence: `crates/apm2-cli/src/client/daemon.rs:214-256`,
  `crates/apm2-daemon/src/handlers.rs:23-36`.
- Multiple CLI commands are marked "daemon support pending" (logs/creds/reload), so the UX implies
  supported capabilities that are not wired. Evidence: `crates/apm2-cli/src/main.rs:71-105`,
  `crates/apm2-cli/src/main.rs:137-169`.
- Export path uses placeholder content instead of CAS-backed artifacts. Evidence:
  `crates/apm2-cli/src/commands/export.rs:386-407`.
- Coordination runs local `apm2_core::coordination` logic (no daemon integration), so it is a dev-only
  workflow today. Evidence: `crates/apm2-cli/src/commands/coordinate.rs:48-51`.

## Minimal Agent Command Set (v0)
Operator (operator_socket):
- `apm2 work claim --work-id <id> --role <role>`
- `apm2 work status --work-id <id>`
- `apm2 episode spawn --work-id <id> --role <role>` (returns session_id + token)
- `apm2 capability issue --session-id <id> --cap <manifest>`

Session (session_socket):
- `apm2 tool request --session-token <token> --tool <id> --args <json>`
- `apm2 evidence publish --session-token <token> --kind <kind> --path <file>`
- `apm2 event emit --session-token <token> --type <type> --payload <json>`
- `apm2 episode status --session-token <token>` (session-scoped status)

Reviewer (session_socket):
- `apm2 review fetch-changeset --changeset-digest <digest>` (CAS-only)
- `apm2 review receipt --changeset-digest <digest> --artifact <cas_hash>`
- `apm2 review blocked --changeset-digest <digest> --reason <code> --logs <cas_hash>`

## Socket + Protocol Selection Rules
1. operator_socket is the only path for privileged commands (ClaimWork/SpawnEpisode/IssueCapability).
2. session_socket is the only path for session-scoped commands (RequestTool/EmitEvent/PublishEvidence).
3. ProtocolServer tag-based frames are mandatory on operator/session sockets; JSON IPC is rejected.
4. `--socket` is deprecated; it maps to operator_socket only and prints a deterministic warning.
5. `daemon.socket` is ignored; config must provide operator_socket/session_socket only.

## Deterministic Exit Codes (Agent-Parseable)
Proposed exit codes (apply uniformly across new agent commands):
- 0: success
- 10: validation error (invalid args/format)
- 11: permission denied (capability/ACL)
- 12: not found (work_id/session_id/changeset)
- 20: daemon unavailable (socket connect failure)
- 21: protocol error (decode/unknown tag)
- 22: policy deny (explicit governance/policy rejection)

## Dev-Only/BYPASS Gating
Commands that are not authoritative or bypass the daemon must require explicit dev mode and print
`NON-AUTHORITATIVE`:
- `apm2 factory ...` (spec pipeline)
- `apm2 coordinate ...` (local coordination)
- `apm2 consensus ...` (cluster diagnostics)
- `apm2 export ...` (placeholder content)

Dev-only gating rule:
- Require `--dev` (or `APM2_DEV_MODE=1`) for any command above.
- In dev mode, print a banner and never emit truth-plane artifacts.
