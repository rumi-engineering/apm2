# fac_pr

> GitHub App credential management and PR operations for headless Linux systems.

## Overview

The `fac_pr` module implements the `apm2 fac pr` subcommands for bootstrapping and verifying GitHub App credentials. It targets headless VPS environments where the OS keyring is session-scoped, providing secure credential storage with keyring-first resolution and optional PEM file fallback.

The module contains four sub-files:
- **`mod.rs`**: CLI argument types, dispatcher, and error output helper.
- **`auth_setup.rs`**: `apm2 fac pr auth-setup` -- stores GitHub App private key in OS keyring (default) or file-only mode (`--for-systemd`) and writes `~/.apm2/github_app.toml`.
- **`auth_check.rs`**: `apm2 fac pr auth-check` -- verifies that GitHub App credentials are configured and resolvable.
- **`types.rs`**: Shared response types.
- **`ruleset_sync.rs`**: `apm2 fac pr ruleset-sync` -- syncs GitHub required-status rulesets.

### Credential Resolution Order

1. Environment variable (e.g., `APM2_GITHUB_APP_ID`)
2. Config file (`~/.apm2/github_app.toml`)
3. Error if neither is available (error message includes remediation guidance for `--for-systemd` and systemd credentials)

### Private Key Resolution Order

1. Environment variable (`APM2_GITHUB_APP_PRIVATE_KEY`)
2. Systemd credential (`$CREDENTIALS_DIRECTORY/github-app-key`, via `LoadCredential=`)
3. OS keyring (`keyring_service` / `keyring_account`)
4. PEM file fallback (only if `allow_private_key_file_fallback` is enabled)

### Headless Setup (`--for-systemd`)

The `--for-systemd` flag on `auth-setup` enables headless provisioning for systemd-managed compute hosts:
- Skips OS keyring entirely (no desktop session required)
- Copies private key PEM to `$APM2_HOME/app-{app_id}.pem` with mode 0600
- Writes `github_app.toml` with `allow_private_key_file_fallback = true`
- Compatible with systemd `LoadCredential=github-app-key:/path/to/key.pem` injection

## Key Types

### `PrArgs`

```rust
#[derive(Debug, Args)]
pub struct PrArgs {
    pub subcommand: PrSubcommand,
}
```

### `PrSubcommand`

```rust
#[derive(Debug, Subcommand)]
pub enum PrSubcommand {
    AuthCheck(PrAuthCheckCliArgs),
    AuthSetup(PrAuthSetupCliArgs),
}
```

### `PrAuthCheckCliArgs`

```rust
#[derive(Debug, Args)]
pub struct PrAuthCheckCliArgs {
    #[arg(long, default_value = "guardian-intelligence/apm2")]
    pub repo: String,
}
```

### `PrAuthSetupCliArgs`

```rust
#[derive(Debug, Args)]
pub struct PrAuthSetupCliArgs {
    #[arg(long)]
    pub app_id: String,
    #[arg(long)]
    pub installation_id: String,
    #[arg(long)]
    pub private_key_file: PathBuf,
    #[arg(long, default_value = "apm2.github.app")]
    pub keyring_service: String,
    #[arg(long)]
    pub keyring_account: Option<String>,
    #[arg(long, default_value_t = false)]
    pub allow_private_key_file_fallback: bool,
    #[arg(long, default_value_t = false)]
    pub keep_private_key_file: bool,
    #[arg(long, default_value_t = false)]
    pub for_systemd: bool,
    #[arg(long, default_value_t = false)]
    pub json: bool,
}
```

**Invariants:**
- [INV-SETUP-001] Private key is stored in OS keyring before any config file is written (keyring mode).
- [INV-SETUP-002] Config file and fallback PEM are written with mode 0600 (owner read/write only).
- [INV-SETUP-003] Symlink targets are rejected for private key paths via `O_NOFOLLOW` at open time (CWE-61, no TOCTOU gap). All private key reads use the open-once bounded strategy: open with `O_NOFOLLOW`, validate metadata on the handle, read bounded content from the same descriptor (INV-0910/CTR-0901 pattern).
- [INV-SETUP-004] Source PEM file is deleted after keyring import unless `--keep-private-key-file` is specified. When source and destination paths alias the same file, deletion is skipped to avoid removing the just-written PEM.
- [INV-SETUP-005] In `--for-systemd` mode, keyring is skipped entirely and PEM is written to `$APM2_HOME/app-{app_id}.pem`.
- [INV-SETUP-006] `app_id` and `installation_id` are validated as strict numeric-only GitHub identifiers before use in filesystem paths or TOML config content (CTR-2609). Path separators, dot-segments, quotes, control characters, and whitespace are rejected.
- [INV-SETUP-007] `github_app.toml` is generated via typed TOML serialization (`GitHubAppTomlConfig` struct), not manual string interpolation, to prevent config injection.
- [INV-SETUP-008] Private key reads are bounded to 16 KiB (`MAX_PRIVATE_KEY_FILE_SIZE`) to prevent resource exhaustion (CTR-1603, RSK-1601).

### `AuthInfo` (types.rs)

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthInfo {
    pub authenticated: bool,
    pub login: String,
}
```

Shared response type representing forge provider authentication status.

## Public API

| Function | Description |
|----------|-------------|
| `run_pr(args, json_output) -> u8` | Dispatch `auth-check` or `auth-setup` subcommand |

### Internal Functions

| Function (auth_check.rs) | Description |
|--------------------------|-------------|
| `run_pr_auth_check(repo, json)` | Verify GitHub App auth material is configured |

| Function (auth_setup.rs) | Description |
|--------------------------|-------------|
| `run_pr_auth_setup(args, json)` | Store private key in keyring or file-only mode, write config, optionally delete source PEM |
| `run_pr_auth_setup_headless(args, json)` | Headless file-only setup for `--for-systemd` (skips keyring) |

## Related Modules

- [`commands/`](../AGENTS.md) -- Parent command module
- [`fac_review/`](../fac_review/AGENTS.md) -- Review orchestration (consumes GitHub App credentials)
- [`apm2_core::github`](../../../../apm2-core/src/github/) -- `GitHubAppTokenProvider` and `load_github_app_config`

## References

- `~/.apm2/github_app.toml`: Persistent GitHub App configuration file
- CWE-61: UNIX Symbolic Link Following (mitigated by symlink rejection)
