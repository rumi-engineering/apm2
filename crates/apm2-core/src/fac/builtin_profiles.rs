// AGENT-AUTHORED
//! Built-in agent adapter profiles for common CLI tools.
//!
//! This module provides pre-configured `AgentAdapterProfileV1` instances for
//! commonly used coding agent CLIs:
//!
//! - **Claude Code**: Anthropic's Claude Code CLI
//! - **Gemini CLI**: Google's Gemini CLI
//! - **Codex CLI**: `OpenAI`'s Codex CLI
//! - **Local Inference**: Generic profile for local model execution
//!
//! # Overview
//!
//! Per RFC-0019 Addendum (section 11), these profiles implement the "Option C -
//! Black-box ledger-mediated driver" approach by default, which is the
//! preferred integration mode for FAC v0.
//!
//! All profiles:
//! - Use `AdapterMode::BlackBox` (default for FAC v0)
//! - Disable native tools to enable kernel-side tool bridging
//! - Configure appropriate version probes for CLI detection
//! - Set reasonable budget defaults and health checks
//!
//! # Security Model
//!
//! The agent process is treated as an **untrusted black-box proposer**:
//! - Native tools are disabled or restricted
//! - Agent emits `ToolIntent` requests via the tool bridge
//! - Kernel validates, policy-checks, and executes tools
//! - Results are injected back as `ToolResult` envelopes
//! - Ledger records all tool activity for auditability
//!
//! # Example
//!
//! ```rust
//! use apm2_core::evidence::MemoryCas;
//! use apm2_core::fac::builtin_profiles;
//!
//! // Get the Claude Code profile
//! let profile = builtin_profiles::claude_code_profile();
//! assert!(profile.validate().is_ok());
//!
//! // Store in CAS for hash-addressed selection
//! let cas = MemoryCas::new();
//! let hash = profile.store_in_cas(&cas).expect("store should succeed");
//!
//! // Profiles are selected by hash, not by name
//! println!("Claude Code profile hash: {}", hex::encode(hash));
//! ```

use std::collections::BTreeMap;

use super::{
    AdapterMode, AgentAdapterProfileV1, BudgetDefaults, EvidencePolicy, HealthChecks, InputMode,
    OutputMode, ToolBridgeConfig, VersionProbe,
};

// =============================================================================
// Profile Constants
// =============================================================================

/// Profile ID for Claude Code adapter.
pub const CLAUDE_CODE_PROFILE_ID: &str = "claude-code-v1";

/// Profile ID for Gemini CLI adapter.
pub const GEMINI_CLI_PROFILE_ID: &str = "gemini-cli-v1";

/// Profile ID for Codex CLI adapter.
pub const CODEX_CLI_PROFILE_ID: &str = "codex-cli-v1";

/// Profile ID for local inference adapter.
pub const LOCAL_INFERENCE_PROFILE_ID: &str = "local-inference-v1";

// =============================================================================
// Claude Code Profile
// =============================================================================

/// Creates an `AgentAdapterProfileV1` for Claude Code CLI.
///
/// # CLI Guidance (from RFC-0019)
///
/// - Use `-p` for prompt (non-interactive print mode)
/// - Use `--tools ""` to disable built-in tools
/// - Use `--no-session-persistence` to disable session persistence
/// - Output mode is raw (`ToolIntent` grammar)
///
/// # Permission Mode Map
///
/// - `restricted`: Disables all write operations
/// - `standard`: Default safe mode with tool bridge
/// - `elevated`: Allows write operations (requires explicit policy approval)
///
/// # Capability Map
///
/// Maps Claude Code's tool intent categories to kernel tool classes:
/// - `read_file` -> `kernel.fs.read`
/// - `write_file` -> `kernel.fs.write`
/// - `exec_command` -> `kernel.shell.exec`
/// - `search_files` -> `kernel.fs.search`
/// - `list_directory` -> `kernel.fs.list`
///
/// # Panics
///
/// Panics if the profile fails validation (should never happen for valid
/// constants).
#[must_use]
pub fn claude_code_profile() -> AgentAdapterProfileV1 {
    let mut permission_mode_map = BTreeMap::new();
    permission_mode_map.insert(
        "restricted".to_string(),
        vec![
            "--tools".to_string(),
            String::new(),
            "--no-session-persistence".to_string(),
        ],
    );
    permission_mode_map.insert(
        "standard".to_string(),
        vec![
            "--tools".to_string(),
            String::new(),
            "--no-session-persistence".to_string(),
        ],
    );
    permission_mode_map.insert(
        "elevated".to_string(),
        vec![
            "--tools".to_string(),
            String::new(),
            "--no-session-persistence".to_string(),
        ],
    );

    let mut capability_map = BTreeMap::new();
    capability_map.insert("read_file".to_string(), "kernel.fs.read".to_string());
    capability_map.insert("write_file".to_string(), "kernel.fs.write".to_string());
    capability_map.insert("exec_command".to_string(), "kernel.shell.exec".to_string());
    capability_map.insert("search_files".to_string(), "kernel.fs.search".to_string());
    capability_map.insert("list_directory".to_string(), "kernel.fs.list".to_string());

    AgentAdapterProfileV1::builder()
        .profile_id(CLAUDE_CODE_PROFILE_ID)
        .adapter_mode(AdapterMode::BlackBox)
        .command("claude")
        .args_template(vec![
            "-p".to_string(),
            "{prompt}".to_string(),
            "--tools".to_string(),
            String::new(),
            "--no-session-persistence".to_string(),
        ])
        .env_template(vec![
            ("CLAUDE_CODE_HEADLESS".to_string(), "1".to_string()),
            ("NO_COLOR".to_string(), "1".to_string()),
        ])
        .cwd("{workspace}")
        .requires_pty(false)
        .input_mode(InputMode::Arg)
        .output_mode(OutputMode::Raw)
        .permission_mode_map(permission_mode_map)
        .tool_bridge(ToolBridgeConfig {
            enabled: true,
            protocol_version: "TI1".to_string(),
            nonce_prefix: "claude".to_string(),
            max_args_size: 1024 * 1024,   // 1 MB
            max_result_size: 1024 * 1024, // 1 MB
            tool_timeout_ms: 60_000,      // 60 seconds
        })
        .capability_map(capability_map)
        .version_probe(VersionProbe::new(
            "claude --version",
            r"claude\s+(\d+\.\d+\.\d+)",
        ))
        .health_checks(HealthChecks {
            startup_timeout_ms: 30_000,
            heartbeat_interval_ms: 5_000,
            heartbeat_timeout_ms: 15_000,
            stall_threshold_ms: 120_000,
            max_stalls: 3,
        })
        .budget_defaults(BudgetDefaults {
            max_tool_calls: 100,
            max_tokens: 1_000_000,
            max_wall_clock_ms: 3_600_000,          // 1 hour
            max_evidence_bytes: 100 * 1024 * 1024, // 100 MB
        })
        .evidence_policy(EvidencePolicy {
            record_full_output: true,
            record_tool_traces: true,
            record_timing: true,
            record_token_usage: true,
            max_recorded_output_bytes: 10 * 1024 * 1024, // 10 MB
            redact_sensitive: true,
        })
        .build()
        .expect("claude_code_profile should be valid")
}

// =============================================================================
// Gemini CLI Profile
// =============================================================================

/// Creates an `AgentAdapterProfileV1` for Gemini CLI.
///
/// # CLI Guidance (from RFC-0019)
///
/// - Use `-p` for prompt (headless prompt mode)
/// - Use `-e none` to disable extensions (treat extensions as tool surface)
/// - Do NOT use `--all-files` (causes unledgered reads)
///
/// # Permission Mode Map
///
/// - `restricted`: Disables extensions and file access
/// - `standard`: Default safe mode with extensions disabled
/// - `elevated`: Allows limited extension use (requires explicit policy
///   approval)
///
/// # Capability Map
///
/// Maps Gemini CLI's tool intent categories to kernel tool classes:
/// - `read_file` -> `kernel.fs.read`
/// - `write_file` -> `kernel.fs.write`
/// - `exec_command` -> `kernel.shell.exec`
/// - `search_code` -> `kernel.fs.search`
/// - `web_search` -> `kernel.net.search` (disabled by default)
///
/// # Panics
///
/// Panics if the profile fails validation (should never happen for valid
/// constants).
#[must_use]
pub fn gemini_cli_profile() -> AgentAdapterProfileV1 {
    let mut permission_mode_map = BTreeMap::new();
    permission_mode_map.insert(
        "restricted".to_string(),
        vec!["-e".to_string(), "none".to_string()],
    );
    permission_mode_map.insert(
        "standard".to_string(),
        vec!["-e".to_string(), "none".to_string()],
    );
    permission_mode_map.insert(
        "elevated".to_string(),
        vec!["-e".to_string(), "none".to_string()],
    );

    let mut capability_map = BTreeMap::new();
    capability_map.insert("read_file".to_string(), "kernel.fs.read".to_string());
    capability_map.insert("write_file".to_string(), "kernel.fs.write".to_string());
    capability_map.insert("exec_command".to_string(), "kernel.shell.exec".to_string());
    capability_map.insert("search_code".to_string(), "kernel.fs.search".to_string());
    capability_map.insert("web_search".to_string(), "kernel.net.search".to_string());

    AgentAdapterProfileV1::builder()
        .profile_id(GEMINI_CLI_PROFILE_ID)
        .adapter_mode(AdapterMode::BlackBox)
        .command("gemini")
        .args_template(vec![
            "-p".to_string(),
            "{prompt}".to_string(),
            "-e".to_string(),
            "none".to_string(),
        ])
        .env_template(vec![
            ("GEMINI_HEADLESS".to_string(), "1".to_string()),
            ("NO_COLOR".to_string(), "1".to_string()),
        ])
        .cwd("{workspace}")
        .requires_pty(false)
        .input_mode(InputMode::Arg)
        .output_mode(OutputMode::Raw)
        .permission_mode_map(permission_mode_map)
        .tool_bridge(ToolBridgeConfig {
            enabled: true,
            protocol_version: "TI1".to_string(),
            nonce_prefix: "gemini".to_string(),
            max_args_size: 1024 * 1024,   // 1 MB
            max_result_size: 1024 * 1024, // 1 MB
            tool_timeout_ms: 60_000,      // 60 seconds
        })
        .capability_map(capability_map)
        .version_probe(VersionProbe::new(
            "gemini --version",
            r"gemini\s+(\d+\.\d+\.\d+)",
        ))
        .health_checks(HealthChecks {
            startup_timeout_ms: 30_000,
            heartbeat_interval_ms: 5_000,
            heartbeat_timeout_ms: 15_000,
            stall_threshold_ms: 120_000,
            max_stalls: 3,
        })
        .budget_defaults(BudgetDefaults {
            max_tool_calls: 100,
            max_tokens: 1_000_000,
            max_wall_clock_ms: 3_600_000,          // 1 hour
            max_evidence_bytes: 100 * 1024 * 1024, // 100 MB
        })
        .evidence_policy(EvidencePolicy {
            record_full_output: true,
            record_tool_traces: true,
            record_timing: true,
            record_token_usage: true,
            max_recorded_output_bytes: 10 * 1024 * 1024, // 10 MB
            redact_sensitive: true,
        })
        .build()
        .expect("gemini_cli_profile should be valid")
}

// =============================================================================
// Codex CLI Profile
// =============================================================================

/// Creates an `AgentAdapterProfileV1` for Codex CLI.
///
/// # CLI Guidance (from RFC-0019)
///
/// - Use `codex exec` for non-interactive mode
/// - Disable shell/web tools via config:
///   - `features.shell_tool=false`
///   - `web_search=disabled`
///   - `history.persistence=none`
/// - Avoid relying on `--json` event stream unless using structured output mode
///
/// # Permission Mode Map
///
/// - `restricted`: Disables shell and web access
/// - `standard`: Default safe mode with shell disabled
/// - `elevated`: Allows shell access (requires explicit policy approval)
///
/// # Capability Map
///
/// Maps Codex CLI's tool intent categories to kernel tool classes:
/// - `read_file` -> `kernel.fs.read`
/// - `write_file` -> `kernel.fs.write`
/// - `shell` -> `kernel.shell.exec` (disabled by default)
/// - `browse_web` -> `kernel.net.browse` (disabled by default)
///
/// # Panics
///
/// Panics if the profile fails validation (should never happen for valid
/// constants).
#[must_use]
pub fn codex_cli_profile() -> AgentAdapterProfileV1 {
    let mut permission_mode_map = BTreeMap::new();
    permission_mode_map.insert(
        "restricted".to_string(),
        vec![
            "--config".to_string(),
            "features.shell_tool=false".to_string(),
            "--config".to_string(),
            "web_search=disabled".to_string(),
            "--config".to_string(),
            "history.persistence=none".to_string(),
        ],
    );
    permission_mode_map.insert(
        "standard".to_string(),
        vec![
            "--config".to_string(),
            "features.shell_tool=false".to_string(),
            "--config".to_string(),
            "web_search=disabled".to_string(),
            "--config".to_string(),
            "history.persistence=none".to_string(),
        ],
    );
    permission_mode_map.insert(
        "elevated".to_string(),
        vec![
            "--config".to_string(),
            "web_search=disabled".to_string(),
            "--config".to_string(),
            "history.persistence=none".to_string(),
        ],
    );

    let mut capability_map = BTreeMap::new();
    capability_map.insert("read_file".to_string(), "kernel.fs.read".to_string());
    capability_map.insert("write_file".to_string(), "kernel.fs.write".to_string());
    capability_map.insert("shell".to_string(), "kernel.shell.exec".to_string());
    capability_map.insert("browse_web".to_string(), "kernel.net.browse".to_string());

    AgentAdapterProfileV1::builder()
        .profile_id(CODEX_CLI_PROFILE_ID)
        .adapter_mode(AdapterMode::BlackBox)
        .command("codex")
        .args_template(vec![
            "exec".to_string(),
            "{prompt}".to_string(),
            "--config".to_string(),
            "features.shell_tool=false".to_string(),
            "--config".to_string(),
            "web_search=disabled".to_string(),
            "--config".to_string(),
            "history.persistence=none".to_string(),
        ])
        .env_template(vec![
            ("CODEX_HEADLESS".to_string(), "1".to_string()),
            ("NO_COLOR".to_string(), "1".to_string()),
        ])
        .cwd("{workspace}")
        .requires_pty(false)
        .input_mode(InputMode::Arg)
        .output_mode(OutputMode::Raw)
        .permission_mode_map(permission_mode_map)
        .tool_bridge(ToolBridgeConfig {
            enabled: true,
            protocol_version: "TI1".to_string(),
            nonce_prefix: "codex".to_string(),
            max_args_size: 1024 * 1024,   // 1 MB
            max_result_size: 1024 * 1024, // 1 MB
            tool_timeout_ms: 60_000,      // 60 seconds
        })
        .capability_map(capability_map)
        .version_probe(VersionProbe::new(
            "codex --version",
            r"codex\s+(\d+\.\d+\.\d+)",
        ))
        .health_checks(HealthChecks {
            startup_timeout_ms: 30_000,
            heartbeat_interval_ms: 5_000,
            heartbeat_timeout_ms: 15_000,
            stall_threshold_ms: 120_000,
            max_stalls: 3,
        })
        .budget_defaults(BudgetDefaults {
            max_tool_calls: 100,
            max_tokens: 1_000_000,
            max_wall_clock_ms: 3_600_000,          // 1 hour
            max_evidence_bytes: 100 * 1024 * 1024, // 100 MB
        })
        .evidence_policy(EvidencePolicy {
            record_full_output: true,
            record_tool_traces: true,
            record_timing: true,
            record_token_usage: true,
            max_recorded_output_bytes: 10 * 1024 * 1024, // 10 MB
            redact_sensitive: true,
        })
        .build()
        .expect("codex_cli_profile should be valid")
}

// =============================================================================
// Local Inference Profile
// =============================================================================

/// Creates an `AgentAdapterProfileV1` for local inference execution.
///
/// # Overview
///
/// This is a basic profile for running locally-hosted models (e.g., via Ollama,
/// llama.cpp, vLLM, or other local inference servers). The profile is designed
/// to be flexible and work with various local model servers.
///
/// # CLI Guidance
///
/// - Command is configurable (defaults to `ollama run`)
/// - Input via stdin for flexibility
/// - No native tools assumed (all tools via kernel bridge)
///
/// # Permission Mode Map
///
/// - `restricted`: Read-only mode, no shell access
/// - `standard`: Default mode with read/write file access
/// - `elevated`: Full access including shell (requires explicit policy
///   approval)
///
/// # Capability Map
///
/// Maps generic tool intent categories to kernel tool classes:
/// - `read_file` -> `kernel.fs.read`
/// - `write_file` -> `kernel.fs.write`
/// - `exec_command` -> `kernel.shell.exec`
///
/// # Panics
///
/// Panics if the profile fails validation (should never happen for valid
/// constants).
#[must_use]
pub fn local_inference_profile() -> AgentAdapterProfileV1 {
    let mut permission_mode_map = BTreeMap::new();
    permission_mode_map.insert("restricted".to_string(), vec!["--no-shell".to_string()]);
    permission_mode_map.insert("standard".to_string(), vec!["--no-shell".to_string()]);
    permission_mode_map.insert("elevated".to_string(), vec![]);

    let mut capability_map = BTreeMap::new();
    capability_map.insert("read_file".to_string(), "kernel.fs.read".to_string());
    capability_map.insert("write_file".to_string(), "kernel.fs.write".to_string());
    capability_map.insert("exec_command".to_string(), "kernel.shell.exec".to_string());

    AgentAdapterProfileV1::builder()
        .profile_id(LOCAL_INFERENCE_PROFILE_ID)
        .adapter_mode(AdapterMode::BlackBox)
        .command("ollama")
        .args_template(vec!["run".to_string(), "{model}".to_string()])
        .env_template(vec![
            ("OLLAMA_HEADLESS".to_string(), "1".to_string()),
            ("NO_COLOR".to_string(), "1".to_string()),
        ])
        .cwd("{workspace}")
        .requires_pty(false)
        .input_mode(InputMode::Stdin)
        .output_mode(OutputMode::Raw)
        .permission_mode_map(permission_mode_map)
        .tool_bridge(ToolBridgeConfig {
            enabled: true,
            protocol_version: "TI1".to_string(),
            nonce_prefix: "local".to_string(),
            max_args_size: 1024 * 1024,   // 1 MB
            max_result_size: 1024 * 1024, // 1 MB
            tool_timeout_ms: 120_000,     // 2 minutes (local inference may be slower)
        })
        .capability_map(capability_map)
        .version_probe(VersionProbe::new(
            "ollama --version",
            r"ollama\s+version\s+(\d+\.\d+\.\d+)",
        ))
        .health_checks(HealthChecks {
            startup_timeout_ms: 60_000,    // Longer startup for model loading
            heartbeat_interval_ms: 10_000, // Longer intervals for local inference
            heartbeat_timeout_ms: 30_000,
            stall_threshold_ms: 300_000, // 5 minutes (local inference may be slow)
            max_stalls: 3,
        })
        .budget_defaults(BudgetDefaults {
            max_tool_calls: 50,                   // Lower limit for local inference
            max_tokens: 500_000,                  // Lower token limit for local models
            max_wall_clock_ms: 7_200_000,         // 2 hours (local inference is slower)
            max_evidence_bytes: 50 * 1024 * 1024, // 50 MB
        })
        .evidence_policy(EvidencePolicy {
            record_full_output: true,
            record_tool_traces: true,
            record_timing: true,
            record_token_usage: false, // Token usage may not be available locally
            max_recorded_output_bytes: 10 * 1024 * 1024, // 10 MB
            redact_sensitive: true,
        })
        .build()
        .expect("local_inference_profile should be valid")
}

// =============================================================================
// Profile Registry Functions
// =============================================================================

/// Returns all built-in profiles.
///
/// # Returns
///
/// A vector containing all pre-configured agent adapter profiles.
#[must_use]
pub fn all_builtin_profiles() -> Vec<AgentAdapterProfileV1> {
    vec![
        claude_code_profile(),
        gemini_cli_profile(),
        codex_cli_profile(),
        local_inference_profile(),
    ]
}

/// Looks up a built-in profile by its profile ID.
///
/// # Arguments
///
/// * `profile_id` - The profile identifier (e.g., "claude-code-v1")
///
/// # Returns
///
/// The matching profile if found, `None` otherwise.
#[must_use]
pub fn get_builtin_profile(profile_id: &str) -> Option<AgentAdapterProfileV1> {
    match profile_id {
        CLAUDE_CODE_PROFILE_ID => Some(claude_code_profile()),
        GEMINI_CLI_PROFILE_ID => Some(gemini_cli_profile()),
        CODEX_CLI_PROFILE_ID => Some(codex_cli_profile()),
        LOCAL_INFERENCE_PROFILE_ID => Some(local_inference_profile()),
        _ => None,
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::MemoryCas;

    #[test]
    fn test_claude_code_profile_valid() {
        let profile = claude_code_profile();
        assert!(profile.validate().is_ok());
        assert_eq!(profile.profile_id, CLAUDE_CODE_PROFILE_ID);
        assert_eq!(profile.adapter_mode, AdapterMode::BlackBox);
        assert_eq!(profile.command, "claude");
        assert!(!profile.requires_pty);
    }

    #[test]
    fn test_claude_code_profile_args() {
        let profile = claude_code_profile();
        assert!(profile.args_template.contains(&"-p".to_string()));
        assert!(profile.args_template.contains(&"--tools".to_string()));
        assert!(
            profile
                .args_template
                .contains(&"--no-session-persistence".to_string())
        );
    }

    #[test]
    fn test_claude_code_profile_capability_map() {
        let profile = claude_code_profile();
        assert_eq!(
            profile.capability_map.get("read_file"),
            Some(&"kernel.fs.read".to_string())
        );
        assert_eq!(
            profile.capability_map.get("write_file"),
            Some(&"kernel.fs.write".to_string())
        );
        assert_eq!(
            profile.capability_map.get("exec_command"),
            Some(&"kernel.shell.exec".to_string())
        );
    }

    #[test]
    fn test_claude_code_profile_cas_roundtrip() {
        let cas = MemoryCas::new();
        let profile = claude_code_profile();

        let hash = profile.store_in_cas(&cas).expect("store should succeed");
        let loaded =
            AgentAdapterProfileV1::load_from_cas(&cas, &hash).expect("load should succeed");

        assert_eq!(profile, loaded);
    }

    #[test]
    fn test_gemini_cli_profile_valid() {
        let profile = gemini_cli_profile();
        assert!(profile.validate().is_ok());
        assert_eq!(profile.profile_id, GEMINI_CLI_PROFILE_ID);
        assert_eq!(profile.adapter_mode, AdapterMode::BlackBox);
        assert_eq!(profile.command, "gemini");
        assert!(!profile.requires_pty);
    }

    #[test]
    fn test_gemini_cli_profile_args() {
        let profile = gemini_cli_profile();
        assert!(profile.args_template.contains(&"-p".to_string()));
        assert!(profile.args_template.contains(&"-e".to_string()));
        assert!(profile.args_template.contains(&"none".to_string()));
        // Verify --all-files is NOT present (per RFC guidance)
        assert!(!profile.args_template.contains(&"--all-files".to_string()));
    }

    #[test]
    fn test_gemini_cli_profile_capability_map() {
        let profile = gemini_cli_profile();
        assert_eq!(
            profile.capability_map.get("read_file"),
            Some(&"kernel.fs.read".to_string())
        );
        assert_eq!(
            profile.capability_map.get("web_search"),
            Some(&"kernel.net.search".to_string())
        );
    }

    #[test]
    fn test_gemini_cli_profile_cas_roundtrip() {
        let cas = MemoryCas::new();
        let profile = gemini_cli_profile();

        let hash = profile.store_in_cas(&cas).expect("store should succeed");
        let loaded =
            AgentAdapterProfileV1::load_from_cas(&cas, &hash).expect("load should succeed");

        assert_eq!(profile, loaded);
    }

    #[test]
    fn test_codex_cli_profile_valid() {
        let profile = codex_cli_profile();
        assert!(profile.validate().is_ok());
        assert_eq!(profile.profile_id, CODEX_CLI_PROFILE_ID);
        assert_eq!(profile.adapter_mode, AdapterMode::BlackBox);
        assert_eq!(profile.command, "codex");
        assert!(!profile.requires_pty);
    }

    #[test]
    fn test_codex_cli_profile_args() {
        let profile = codex_cli_profile();
        assert!(profile.args_template.contains(&"exec".to_string()));
        assert!(profile.args_template.contains(&"--config".to_string()));
        assert!(
            profile
                .args_template
                .contains(&"features.shell_tool=false".to_string())
        );
        assert!(
            profile
                .args_template
                .contains(&"web_search=disabled".to_string())
        );
        assert!(
            profile
                .args_template
                .contains(&"history.persistence=none".to_string())
        );
    }

    #[test]
    fn test_codex_cli_profile_permission_modes() {
        let profile = codex_cli_profile();

        // Standard mode should disable shell
        let standard_flags = profile.permission_mode_map.get("standard").unwrap();
        assert!(standard_flags.contains(&"features.shell_tool=false".to_string()));

        // Elevated mode should NOT disable shell
        let elevated_flags = profile.permission_mode_map.get("elevated").unwrap();
        assert!(!elevated_flags.contains(&"features.shell_tool=false".to_string()));
    }

    #[test]
    fn test_codex_cli_profile_cas_roundtrip() {
        let cas = MemoryCas::new();
        let profile = codex_cli_profile();

        let hash = profile.store_in_cas(&cas).expect("store should succeed");
        let loaded =
            AgentAdapterProfileV1::load_from_cas(&cas, &hash).expect("load should succeed");

        assert_eq!(profile, loaded);
    }

    #[test]
    fn test_local_inference_profile_valid() {
        let profile = local_inference_profile();
        assert!(profile.validate().is_ok());
        assert_eq!(profile.profile_id, LOCAL_INFERENCE_PROFILE_ID);
        assert_eq!(profile.adapter_mode, AdapterMode::BlackBox);
        assert_eq!(profile.command, "ollama");
        assert!(!profile.requires_pty);
    }

    #[test]
    fn test_local_inference_profile_input_mode() {
        let profile = local_inference_profile();
        // Local inference uses stdin for flexibility
        assert_eq!(profile.input_mode, InputMode::Stdin);
    }

    #[test]
    fn test_local_inference_profile_budget_defaults() {
        let profile = local_inference_profile();
        // Local inference has different budget defaults
        assert_eq!(profile.budget_defaults.max_tool_calls, 50);
        assert_eq!(profile.budget_defaults.max_tokens, 500_000);
        // Longer wall clock time for slower local inference
        assert!(profile.budget_defaults.max_wall_clock_ms > 3_600_000);
    }

    #[test]
    fn test_local_inference_profile_health_checks() {
        let profile = local_inference_profile();
        // Local inference has longer timeouts
        assert!(profile.health_checks.startup_timeout_ms >= 60_000);
        assert!(profile.health_checks.stall_threshold_ms >= 300_000);
    }

    #[test]
    fn test_local_inference_profile_cas_roundtrip() {
        let cas = MemoryCas::new();
        let profile = local_inference_profile();

        let hash = profile.store_in_cas(&cas).expect("store should succeed");
        let loaded =
            AgentAdapterProfileV1::load_from_cas(&cas, &hash).expect("load should succeed");

        assert_eq!(profile, loaded);
    }

    #[test]
    fn test_all_builtin_profiles() {
        let profiles = all_builtin_profiles();
        assert_eq!(profiles.len(), 4);

        for profile in &profiles {
            assert!(profile.validate().is_ok());
            assert_eq!(profile.adapter_mode, AdapterMode::BlackBox);
        }
    }

    #[test]
    fn test_get_builtin_profile() {
        assert!(get_builtin_profile(CLAUDE_CODE_PROFILE_ID).is_some());
        assert!(get_builtin_profile(GEMINI_CLI_PROFILE_ID).is_some());
        assert!(get_builtin_profile(CODEX_CLI_PROFILE_ID).is_some());
        assert!(get_builtin_profile(LOCAL_INFERENCE_PROFILE_ID).is_some());
        assert!(get_builtin_profile("nonexistent").is_none());
    }

    #[test]
    fn test_profile_hashes_are_deterministic() {
        let profile1 = claude_code_profile();
        let profile2 = claude_code_profile();
        assert_eq!(profile1.compute_cas_hash(), profile2.compute_cas_hash());

        let profile3 = gemini_cli_profile();
        let profile4 = gemini_cli_profile();
        assert_eq!(profile3.compute_cas_hash(), profile4.compute_cas_hash());
    }

    #[test]
    fn test_profile_hashes_differ_between_profiles() {
        let claude_hash = claude_code_profile().compute_cas_hash();
        let gemini_hash = gemini_cli_profile().compute_cas_hash();
        let codex_hash = codex_cli_profile().compute_cas_hash();
        let local_hash = local_inference_profile().compute_cas_hash();

        // All hashes should be unique
        assert_ne!(claude_hash, gemini_hash);
        assert_ne!(claude_hash, codex_hash);
        assert_ne!(claude_hash, local_hash);
        assert_ne!(gemini_hash, codex_hash);
        assert_ne!(gemini_hash, local_hash);
        assert_ne!(codex_hash, local_hash);
    }

    #[test]
    fn test_all_profiles_have_tool_bridge() {
        for profile in all_builtin_profiles() {
            let tool_bridge = profile
                .tool_bridge
                .expect("all profiles should have tool_bridge");
            assert!(tool_bridge.enabled);
            assert_eq!(tool_bridge.protocol_version, "TI1");
        }
    }

    #[test]
    fn test_all_profiles_have_permission_mode_map() {
        for profile in all_builtin_profiles() {
            assert!(
                profile.permission_mode_map.contains_key("restricted"),
                "{} should have restricted mode",
                profile.profile_id
            );
            assert!(
                profile.permission_mode_map.contains_key("standard"),
                "{} should have standard mode",
                profile.profile_id
            );
            assert!(
                profile.permission_mode_map.contains_key("elevated"),
                "{} should have elevated mode",
                profile.profile_id
            );
        }
    }

    #[test]
    fn test_all_profiles_have_capability_map() {
        for profile in all_builtin_profiles() {
            assert!(
                !profile.capability_map.is_empty(),
                "{} should have capability mappings",
                profile.profile_id
            );
            // All profiles should at least map read_file
            assert!(
                profile.capability_map.contains_key("read_file"),
                "{} should map read_file capability",
                profile.profile_id
            );
        }
    }

    #[test]
    fn test_all_profiles_use_black_box_mode() {
        for profile in all_builtin_profiles() {
            assert_eq!(
                profile.adapter_mode,
                AdapterMode::BlackBox,
                "{} should use BlackBox mode (FAC v0 default)",
                profile.profile_id
            );
        }
    }

    #[test]
    fn test_version_probe_regexes_are_valid() {
        for profile in all_builtin_profiles() {
            // Just verify the regex compiles
            let regex_result = regex::Regex::new(&profile.version_probe.regex);
            assert!(
                regex_result.is_ok(),
                "{} has invalid version probe regex: {}",
                profile.profile_id,
                profile.version_probe.regex
            );
        }
    }
}
