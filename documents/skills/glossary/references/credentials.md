# Credentials

**Agent-Native Definition**: **Credentials** are the "Identity and Authority" tokens required for agents to interact with external AI providers (e.g., Anthropic, Google, OpenAI). In APM2, credentials are managed through **CredentialProfiles**, which bind an agent's identity to specific providers and secure storage locations.

## Core Concepts

### Credential Profile
A `CredentialProfile` defines the configuration for a specific provider. It includes the provider type, the associated account or environment, and the current active status. Profiles allow users to switch between different sets of credentials (e.g., `dev` vs. `prod`) without manual environment variable hacking.

### Secure Storage
APM2 is designed to use the OS keychain (via the `keyring` crate) to store sensitive API keys. This ensures that secrets are never stored in plain text on disk or in the `ecosystem.toml` configuration.

### Hot-Swapping
The credential system supports hot-swapping, allowing the daemon to update the active credentials for a running agent session without requiring a full process restart.

## Data Structure References

*   **`CredentialProfile`** (`crates/apm2-core/src/credentials/profile.rs`): The struct defining an agent's credential configuration.
*   **`CredentialStore`** (`crates/apm2-core/src/credentials/store.rs`): The interface for managing and retrieving secrets from secure storage.

## See Also
*   **CLI**: Commands used to manage these profiles (`apm2 creds`).
*   **Tool**: Inference tools that consume these credentials.
