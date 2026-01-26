# Adapter

**Agent-Native Definition**: An **Adapter** is a "Markov Blanket Implementation" that translates between the APM2 Holonic Protocol and external, non-native agent interfaces. It provides the translation layer necessary for the Kernel to supervise agents like Claude Code or Gemini CLI as if they were native Holons, normalizing their I/O, signals, and resource consumption.

## Core Concepts

### Normalization
Adapters convert agent-specific artifacts (like prose logs or tool calls) into the typed, content-addressed format expected by the **Work Substrate**. This allows the system to remain agent-agnostic while still providing strong supervision.

### BlackBoxAdapter
The `BlackBoxAdapter` is a specific implementation used for agents where the internal reasoning is opaque or the interface is primarily via a CLI. It observes the agent through its "Sensory" (stdin/events) and "Active" (stdout/artifacts) states, enforcing budgets and capturing evidence without requiring modification of the agent's code.

### Protocol Translation
Adapters handle the translation of **ToolRequests** from the agent's native format into the Kernel's Protobuf-based tool protocol, ensuring that policy enforcement is uniform across all agent types.

## Data Structure References

*   **`BlackBoxAdapter`** (`crates/apm2-core/src/adapter/black_box.rs`): The adapter implementation for CLI-based agents.
*   **`Adapter`** (`crates/apm2-core/src/adapter/traits.rs`): The trait defining the interface for all adapters.

## See Also
*   **Holon**: The abstraction that the Adapter implements.
*   **Tool**: The capability interface that Adapters help mediate.
