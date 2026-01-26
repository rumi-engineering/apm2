# CLI (Command Line Interface)

**Agent-Native Definition**: The **CLI** (`apm2`) is the "Primary Interface" for humans and external scripts to interact with the APM2 Kernel. It serves as the bridge between the user's intent and the **Daemon State**, serializing commands into the IPC protocol and rendering the kernel's responses into human-readable or machine-parsable formats.

## Core Concepts

### Argument Parsing
The CLI uses a strictly typed argument parser (`Cli`) to ensure that all user inputs are validated before being sent to the daemon. This prevents malformed requests from reaching the core supervision logic.

### Command Dispatch
The `Commands` enum defines the full vocabulary of the system (e.g., `start`, `stop`, `list`, `factory run`). Each variant corresponds to a specific IPC request or a local execution path (like `factory`).

### Credential Management
A specialized subset of commands (`CredsCommands`) handles the lifecycle of agent credentials, including login, profile switching, and secure token storage in the OS keychain.

## Data Structure References

*   **`Cli`** (`crates/apm2-cli/src/main.rs`): The top-level argument parser struct (using `clap`).
*   **`Commands`** (`crates/apm2-cli/src/main.rs`): The primary enumeration of all top-level CLI subcommands.
*   **`CredsCommands`** (`crates/apm2-cli/src/commands/creds.rs`): The enumeration of credential-specific subcommands.

## See Also
*   **Daemon State**: The target of most CLI commands.
*   **Credential Profile**: The data managed by `CredsCommands`.
