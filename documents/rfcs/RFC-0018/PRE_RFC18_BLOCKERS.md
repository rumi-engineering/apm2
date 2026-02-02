# Pre-RFC18 Blocker Inventory (Autonomous FAC Usability)

Baseline:
- Repo: /home/ubuntu/Projects/apm2-rfc18
- HEAD: d30df2c82aaeb5b43b736a0860ced2dfc11b86f4
- Date: 2026-02-02 (America/Los_Angeles)

## Explicit Rejection: Extending Legacy JSON Handlers
DD-009 establishes privileged/session separation and tag-based protocol dispatchers on
operator.sock/session.sock; legacy daemon.socket is explicitly rejected in config, and
protocol dispatchers are documented for DD-009 control-plane IPC. `SessionDispatcher`
frames are tag-based (`[tag: u8][payload: protobuf]`), not JSON. Extending the legacy JSON
path would violate DD-009 and keep a bypass surface alive. Evidence:
- Privileged dispatcher per DD-009, operator-only: `crates/apm2-daemon/src/protocol/dispatch.rs:1-6`
- Tag-based session frame format: `crates/apm2-daemon/src/protocol/session_dispatch.rs:336-340`
- Legacy daemon.socket key rejected; operator/session sockets required: `crates/apm2-core/src/config/mod.rs:50-64`

## Current Control Loop (Authoritative vs Used)
```
            (intended authority)                   (current practice)
   +---------------------------+          +-------------------------------+
   | Ledger + CAS (truth)     |          | xtask -> GitHub statuses      |
   | - ledger events          |          | (non-authoritative signals)   |
   | - CAS evidence           |          +-------------------------------+
   +---------------------------+
            ^        ^
            |        |
   +---------------------------+          +-------------------------------+
   | Protocol dispatchers     |          | CLI JSON IPC -> handlers::dispatch |
   | (Privileged/Session)     |          | (process mgmt only)            |
   +---------------------------+          +-------------------------------+
```
Evidence for non-authoritative xtask status writes: `xtask/src/tasks/aat.rs:172-208`,
`xtask/src/tasks/review.rs:351-367`, `xtask/src/tasks/push.rs:353-390`,
`xtask/src/tasks/security_review_exec.rs:402-417`.

Evidence for stub/durable gaps in truth-plane: stub policy/CAS in tool broker and in-memory
CAS implementation (`crates/apm2-daemon/src/episode/broker.rs:155-180`,
`crates/apm2-daemon/src/episode/broker.rs:196-212`, `crates/apm2-core/src/evidence/cas.rs:187-190`).

## Reachability Map (Daemon Control Plane)
Status legend: REACHABLE, STUBBED, UNREACHABLE, BYPASS.

| Endpoint | Required for | Current status | Evidence |
| --- | --- | --- | --- |
| Ping/Status/Process ops | dev/ops | REACHABLE (JSON handler) | `crates/apm2-daemon/src/main.rs:458-516`, `crates/apm2-daemon/src/handlers.rs:23-36` |
| ClaimWork (operator) | WF-ORCH | UNREACHABLE (JSON dispatch only) | `crates/apm2-daemon/src/main.rs:458-516`, `crates/apm2-daemon/src/handlers.rs:23-36` |
| SpawnEpisode (operator) | WF-ORCH/WF-IMPL/WF-REV | UNREACHABLE (JSON dispatch only) | `crates/apm2-daemon/src/main.rs:458-516`, `crates/apm2-daemon/src/handlers.rs:23-36` |
| IssueCapability (operator) | WF-ORCH | UNREACHABLE + STUB | `crates/apm2-daemon/src/main.rs:458-516`, `crates/apm2-daemon/src/protocol/dispatch.rs:1971-2023` |
| RequestTool (session) | WF-IMPL/WF-REV | UNREACHABLE + STUB ALLOW | `crates/apm2-daemon/src/main.rs:458-516`, `crates/apm2-daemon/src/protocol/session_dispatch.rs:544-551` |
| EmitEvent (session) | WF-IMPL/WF-REV | UNREACHABLE + STUB | `crates/apm2-daemon/src/main.rs:458-516`, `crates/apm2-daemon/src/protocol/session_dispatch.rs:554-605` |
| PublishEvidence (session) | WF-IMPL/WF-REV | UNREACHABLE + STUB | `crates/apm2-daemon/src/main.rs:458-516`, `crates/apm2-daemon/src/protocol/session_dispatch.rs:608-653` |

## Blocker Inventory (Prioritized, Grouped by Workflow + Subsystem)

### WF-ORCH (Orchestrator)
#### Daemon control plane
- BLK-01 (BLOCKER): operator.sock/session.sock are still parsed as JSON `IpcRequest` and sent to
  `handlers::dispatch`, so ProtocolServer dispatchers are unreachable. Blocks all privileged endpoints.
  Evidence: `crates/apm2-daemon/src/main.rs:458-516`. Blocks REQ-HEF-0002/0008 (protocol transport relies
  on tag-based dispatch) and FAC v0 prerequisites (ChangeSetBundle/Review receipts).
  Requirement refs: `documents/rfcs/RFC-0018/requirements/REQ-HEF-0002.yaml:6-14`,
  `documents/rfcs/RFC-0018/requirements/REQ-HEF-0008.yaml:6-12`.
- BLK-02 (BLOCKER): JSON `handlers::dispatch` only supports process ops; all other requests return
  NotSupported. Evidence: `crates/apm2-daemon/src/handlers.rs:23-36`. Blocks workflow control actions.
- BLK-03 (BLOCKER): Privileged dispatcher uses stub dependencies (policy resolver/work registry/ledger
  emitter/lease validator) and IssueCapability is explicitly stubbed. Evidence:
  `crates/apm2-daemon/src/protocol/dispatch.rs:1220-1235`,
  `crates/apm2-daemon/src/protocol/dispatch.rs:1971-2023`. Blocks IssueCapability/ClaimWork integrity.

#### CLI
- BLK-04 (BLOCKER): CLI uses single `--socket` and defaults to `config.daemon.socket` or
  `/tmp/apm2/apm2d.sock`, while config rejects `daemon.socket` and expects operator/session sockets.
  Evidence: `crates/apm2-cli/src/main.rs:27-29`, `crates/apm2-cli/src/main.rs:248-260`,
  `crates/apm2-core/src/config/mod.rs:50-64`, `ecosystem.example.toml:4-7`. Blocks operator control-plane access.

#### Authority surfaces
- BLK-05 (MAJOR): xtask writes GitHub statuses directly (non-authoritative bypass surface).
  Evidence: `xtask/src/tasks/aat.rs:172-208`, `xtask/src/tasks/review.rs:351-367`,
  `xtask/src/tasks/push.rs:353-390`, `xtask/src/tasks/security_review_exec.rs:402-417`.
  Conflicts with REQ-HEF-0001 non-authoritative pulse-plane posture. `documents/rfcs/RFC-0018/requirements/REQ-HEF-0001.yaml:6-13`.

### WF-IMPL (Implementor)
#### Session + tool plane
- BLK-01 (BLOCKER): Protocol dispatchers unreachable because JSON dispatch is used for both sockets.
  Evidence: `crates/apm2-daemon/src/main.rs:458-516`. Blocks RequestTool/EmitEvent/PublishEvidence path.
- BLK-06 (BLOCKER): Session dispatcher is fail-open when no manifest store is configured and returns
  an Allow decision with stub policy hash; EmitEvent/PublishEvidence/StreamTelemetry are stub handlers.
  Evidence: `crates/apm2-daemon/src/protocol/session_dispatch.rs:282-303`,
  `crates/apm2-daemon/src/protocol/session_dispatch.rs:544-551`,
  `crates/apm2-daemon/src/protocol/session_dispatch.rs:554-699`. Blocks tool execution and ledger/CAS evidence.
- BLK-07 (BLOCKER): ToolBroker uses StubPolicyEngine (always allows) and StubContentAddressedStore
  (retrieve returns None). Evidence: `crates/apm2-daemon/src/episode/broker.rs:155-180`,
  `crates/apm2-daemon/src/episode/broker.rs:196-212`,
  `crates/apm2-daemon/src/episode/broker.rs:321-376`. Blocks fail-closed enforcement and evidence durability.
- BLK-08 (BLOCKER): Core tool handlers (Read/Write/Execute) are stubbed and return mock outputs
  without real I/O or execution. Evidence: `crates/apm2-daemon/src/episode/handlers.rs:1-136`,
  `crates/apm2-daemon/src/episode/handlers.rs:187-334`. Blocks actual work execution.

#### Evidence durability
- BLK-09 (BLOCKER): CAS is in-memory only (not durable). Evidence:
  `crates/apm2-core/src/evidence/cas.rs:10-12`, `crates/apm2-core/src/evidence/cas.rs:187-190`.
  Blocks durable ChangeSetBundle/Review artifacts. REQ-HEF-0009/0010. `documents/rfcs/RFC-0018/requirements/REQ-HEF-0009.yaml:6-13`, `documents/rfcs/RFC-0018/requirements/REQ-HEF-0010.yaml:6-20`.

#### CLI
- BLK-10 (BLOCKER): Episode CLI uses JSON `IpcRequest` (Create/Start/Stop/List), but the JSON daemon
  handler rejects non-process requests. Evidence: `crates/apm2-cli/src/client/daemon.rs:214-256`,
  `crates/apm2-daemon/src/handlers.rs:23-36`. Episode lifecycle commands fail.

### WF-REV (Reviewer)
#### Diff/evidence surfaces
- BLK-11 (BLOCKER): Kernel event schema lacks ChangeSetPublished/ReviewReceipt/ReviewBlocked payloads
  (only existing payload list is present). Evidence: `proto/kernel_events.proto:73-93`.
  Blocks REQ-HEF-0009/0010/0011 (ChangeSetBundle + ReviewReceipt/ReviewBlocked). `documents/rfcs/RFC-0018/requirements/REQ-HEF-0009.yaml:6-13`, `documents/rfcs/RFC-0018/requirements/REQ-HEF-0010.yaml:6-20`, `documents/rfcs/RFC-0018/requirements/REQ-HEF-0011.yaml:6-16`.
- BLK-12 (MAJOR): Tool protocol does not define ListFiles/Search; only FileRead/FileWrite/FileEdit/ShellExec/etc are present.
  Evidence: `proto/tool_protocol.proto:41-51`. Blocks reviewer navigation in REQ-HEF-0010. `documents/rfcs/RFC-0018/requirements/REQ-HEF-0010.yaml:6-20`.
- BLK-13 (MAJOR): Export CLI uses placeholder content (not CAS-backed). Evidence:
  `crates/apm2-cli/src/commands/export.rs:386-407`. Reviewer diff/context cannot rely on this path.

#### Capability enforcement
- BLK-14 (MAJOR): CapabilityManifest only includes tool/write/shell allowlists; no pulse topic allowlist or
  CAS hash allowlist fields. Evidence: `crates/apm2-daemon/src/episode/capability.rs:645-702`.
  Blocks REQ-HEF-0003/0005 (deny-by-default topic + CAS allowlists). `documents/rfcs/RFC-0018/requirements/REQ-HEF-0003.yaml:6-18`, `documents/rfcs/RFC-0018/requirements/REQ-HEF-0005.yaml:6-15`.

## Crosswalk: RFC-0018 Preconditions -> Blockers
| RFC-0018 item | Missing code surface | Blocker IDs | Evidence |
| --- | --- | --- | --- |
| REQ-HEF-0002 (PulseEnvelope bounds) | ProtocolServer tag-based path unreachable; JSON dispatch still active | BLK-01 | `crates/apm2-daemon/src/main.rs:458-516`, `crates/apm2-daemon/src/protocol/session_dispatch.rs:336-340`, `documents/rfcs/RFC-0018/requirements/REQ-HEF-0002.yaml:6-14` |
| REQ-HEF-0008 (ledger cursor resume) | Session EmitEvent/PublishEvidence are stubs (no ledger/CAS anchoring) | BLK-06 | `crates/apm2-daemon/src/protocol/session_dispatch.rs:554-653`, `documents/rfcs/RFC-0018/requirements/REQ-HEF-0008.yaml:6-12` |
| REQ-HEF-0003/0005 (topic + CAS allowlists) | CapabilityManifest lacks topic/CAS allowlist fields; policy enforcement stubs | BLK-14, BLK-07 | `crates/apm2-daemon/src/episode/capability.rs:645-702`, `crates/apm2-daemon/src/episode/broker.rs:155-180`, `documents/rfcs/RFC-0018/requirements/REQ-HEF-0003.yaml:6-18`, `documents/rfcs/RFC-0018/requirements/REQ-HEF-0005.yaml:6-15` |
| REQ-HEF-0009 (ChangeSetBundle) | Durable CAS missing; ChangeSetPublished event missing | BLK-09, BLK-11 | `crates/apm2-core/src/evidence/cas.rs:187-190`, `proto/kernel_events.proto:73-93`, `documents/rfcs/RFC-0018/requirements/REQ-HEF-0009.yaml:6-13` |
| REQ-HEF-0010 (Reviewer viability) | RequestTool stub, tool handlers stub, navigation tools missing | BLK-06, BLK-08, BLK-12 | `crates/apm2-daemon/src/protocol/session_dispatch.rs:544-551`, `crates/apm2-daemon/src/episode/handlers.rs:1-136`, `proto/tool_protocol.proto:41-51`, `documents/rfcs/RFC-0018/requirements/REQ-HEF-0010.yaml:6-20` |
| REQ-HEF-0011 (ReviewBlocked durability) | ReviewBlocked event missing; PublishEvidence stub; CAS not durable | BLK-11, BLK-06, BLK-09 | `proto/kernel_events.proto:73-93`, `crates/apm2-daemon/src/protocol/session_dispatch.rs:608-653`, `crates/apm2-core/src/evidence/cas.rs:187-190`, `documents/rfcs/RFC-0018/requirements/REQ-HEF-0011.yaml:6-16` |

## Notes on Evidence Hygiene
- Where a blocker is inferred from absence (e.g., missing ChangeSetPublished/ReviewReceipt in
  `KernelEvent` payload list), the evidence points to the explicit payload list so the omission is
  verifiable. `proto/kernel_events.proto:73-93`.
