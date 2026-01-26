# Tool

**Agent-Native Definition**: A **Tool** is a discrete, privileged capability exposed by the Kernel to agents. It represents the only mechanism by which an agent can affect the outside world or access restricted resources (filesystem, network, git). All Tool usage is mediated by **Policy**, authenticated via **Leases**, and auditable via the **Ledger**.

## Core Concepts

### Default-Deny Security
Agents have no inherent capabilities beyond pure computation. To read a file or run a command, they must construct a `ToolRequest`. The Kernel validates this request against the active Policy and the agent's Lease. If not explicitly allowed, the request is denied.

### Protocol Buffer Interface
Tools are defined strictly via Protocol Buffers (`apm2.tool.v1`). This ensures a language-agnostic, strongly typed contract between the agent (client) and the kernel (server). There are no "magic" internal APIs; everything flows through this explicit message bus.

### Ledger Accountability
Every tool execution is an event. The request, the decision (allow/deny), and the result (success/failure) are cryptographically recorded. This allows complete reconstruction of an agent's actions and side effects.

## Data Structure References

*   **`apm2_core::tool::ToolRequest`** (`crates/apm2-core/src/tool/apm2.tool.v1.rs`): The envelope structure for all tool calls, containing the request ID, session token, and specific tool payload.
*   **`apm2_core::tool::tool_request::Tool`** (`crates/apm2-core/src/tool/apm2.tool.v1.rs`): The enum defining available tools (e.g., `FileRead`, `ShellExec`, `GitOp`).
*   **`apm2_core::tool::ToolResponse`** (`crates/apm2-core/src/tool/apm2.tool.v1.rs`): The result returned to the agent.

## See Also

*   **[Policy](policy.md)**: The rules engine that adjudicates Tool requests.
*   **[Lease / Budget](lease_and_budget.md)**: The authority grant that permits Tool usage.
*   **[Ledger](ledger.md)**: The record of all Tool executions.
