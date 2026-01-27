//! Implementation of the `capabilities` command.
//!
//! This command generates a capability manifest for the current binary,
//! describing all available CLI commands and their capabilities.
//!
//! # Output Formats
//!
//! - Human-readable (default): Pretty-printed summary
//! - JSON (`--json`): Machine-readable capability manifest
//!
//! # Example
//!
//! ```bash
//! # Human-readable output
//! cargo xtask capabilities
//!
//! # JSON output
//! cargo xtask capabilities --json
//!
//! # Write to file
//! cargo xtask capabilities --json --output manifest.json
//! ```

use std::io::Write;
use std::path::PathBuf;

use anyhow::{Context, Result};
use apm2_core::cac::manifest::{
    Capability, CapabilityManifest, Command, ManifestConfig, VerificationMethod,
};
use clap::Parser;

// ============================================================================
// Arguments
// ============================================================================

/// Arguments for the capabilities command.
#[derive(Parser, Debug, Clone)]
pub struct CapabilitiesArgs {
    /// Output in JSON format instead of human-readable.
    #[arg(long)]
    pub json: bool,

    /// Write output to a file instead of stdout.
    ///
    /// Uses atomic write (tempfile + rename) to ensure data integrity.
    #[arg(long, short = 'o')]
    pub output: Option<PathBuf>,
}

// ============================================================================
// Implementation
// ============================================================================

/// Runs the capabilities command.
///
/// Generates a capability manifest describing all CLI commands and
/// capabilities.
///
/// # Arguments
///
/// * `args` - The capabilities command arguments
///
/// # Errors
///
/// Returns an error if:
/// - Manifest generation fails
/// - File output fails (when `--output` is specified)
pub fn run(args: CapabilitiesArgs) -> Result<()> {
    // Generate the manifest configuration from environment
    let config = ManifestConfig::from_env();

    // Generate base manifest
    let mut manifest = CapabilityManifest::generate(&config);

    // Populate commands from CLI structure
    populate_commands(&mut manifest);

    // Populate capabilities
    populate_capabilities(&mut manifest);

    // Format output
    let output_content = if args.json {
        manifest
            .to_canonical_json()
            .context("Failed to serialize manifest to JSON")?
    } else {
        format_human_readable(&manifest)
    };

    // Write output
    if let Some(output_path) = args.output {
        write_atomic(&output_path, &output_content)?;
        println!("Capability manifest written to: {}", output_path.display());
    } else {
        println!("{output_content}");
    }

    Ok(())
}

/// Populates the manifest with CLI commands.
fn populate_commands(manifest: &mut CapabilityManifest) {
    // Main xtask commands
    let commands = vec![
        Command::builder()
            .name("start-ticket")
            .description("Start work on the next unblocked ticket")
            .build()
            .expect("valid command"),
        Command::builder()
            .name("commit")
            .description("Run checks and create a commit")
            .build()
            .expect("valid command"),
        Command::builder()
            .name("push")
            .description("Push branch and create PR with AI reviews")
            .build()
            .expect("valid command"),
        Command::builder()
            .name("check")
            .description("Show ticket and PR status")
            .build()
            .expect("valid command"),
        Command::builder()
            .name("finish")
            .description("Clean up after PR merge")
            .build()
            .expect("valid command"),
        Command::builder()
            .name("review")
            .description("Run AI reviews for a PR")
            .subcommand(
                Command::builder()
                    .name("security")
                    .description("Run security review")
                    .build()
                    .expect("valid command"),
            )
            .subcommand(
                Command::builder()
                    .name("quality")
                    .description("Run code quality review")
                    .build()
                    .expect("valid command"),
            )
            .subcommand(
                Command::builder()
                    .name("uat")
                    .description("Run UAT sign-off")
                    .build()
                    .expect("valid command"),
            )
            .build()
            .expect("valid command"),
        Command::builder()
            .name("security-review-exec")
            .description("Security review execution commands")
            .subcommand(
                Command::builder()
                    .name("approve")
                    .description("Approve PR after security review")
                    .build()
                    .expect("valid command"),
            )
            .subcommand(
                Command::builder()
                    .name("deny")
                    .description("Deny PR with reason")
                    .build()
                    .expect("valid command"),
            )
            .subcommand(
                Command::builder()
                    .name("onboard")
                    .description("Show required reading for reviewers")
                    .build()
                    .expect("valid command"),
            )
            .build()
            .expect("valid command"),
        Command::builder()
            .name("aat")
            .description("Run Agent Acceptance Testing on a PR")
            .build()
            .expect("valid command"),
        Command::builder()
            .name("lint")
            .description("Check for anti-patterns in the codebase")
            .build()
            .expect("valid command"),
        Command::builder()
            .name("capabilities")
            .description("Generate capability manifest for this binary")
            .build()
            .expect("valid command"),
        Command::builder()
            .name("selftest")
            .description("Run CAC capability selftests")
            .build()
            .expect("valid command"),
    ];

    for cmd in commands {
        manifest.add_command(cmd);
    }
}

/// Populates the manifest with capabilities.
fn populate_capabilities(manifest: &mut CapabilityManifest) {
    let capabilities = vec![
        Capability::builder()
            .id("cac:patch:apply")
            .description("Apply JSON patches to CAC artifacts with replay protection")
            .verification_method(VerificationMethod::Selftest)
            .selftest_id("test_patch_apply_valid")
            .build()
            .expect("valid capability"),
        Capability::builder()
            .id("cac:admission:validate")
            .description("Validate artifacts through admission pipeline")
            .verification_method(VerificationMethod::Selftest)
            .selftest_id("test_admission_valid_artifact")
            .build()
            .expect("valid capability"),
        Capability::builder()
            .id("cac:manifest:generate")
            .description("Generate capability manifests with binary hash binding")
            .verification_method(VerificationMethod::Selftest)
            .selftest_id("test_manifest_deterministic")
            .build()
            .expect("valid capability"),
        Capability::builder()
            .id("cac:receipt:sign")
            .description("Sign AAT receipts with Ed25519")
            .verification_method(VerificationMethod::Selftest)
            .selftest_id("test_receipt_sign_verify")
            .build()
            .expect("valid capability"),
        Capability::builder()
            .id("aat:hypothesis:execute")
            .description("Execute hypothesis-driven tests")
            .verification_method(VerificationMethod::Declared)
            .build()
            .expect("valid capability"),
        Capability::builder()
            .id("aat:evidence:bundle")
            .description("Generate evidence bundles from test execution")
            .verification_method(VerificationMethod::Declared)
            .build()
            .expect("valid capability"),
    ];

    for cap in capabilities {
        // Add selftest ref if applicable (before moving cap)
        if cap.verification_method == VerificationMethod::Selftest {
            if let Some(selftest_id) = &cap.selftest_id {
                manifest.add_selftest_ref(selftest_id, &cap.id);
            }
        }
        manifest.add_capability(cap);
    }
}

/// Formats the manifest as human-readable text.
fn format_human_readable(manifest: &CapabilityManifest) -> String {
    use std::fmt::Write;
    let sorted = manifest.to_sorted();

    let mut output = String::new();

    output.push_str("=== Capability Manifest ===\n\n");

    let _ = writeln!(output, "Version:     {}", sorted.version);
    let _ = writeln!(output, "Target:      {}", sorted.target);
    let _ = writeln!(output, "Profile:     {}", sorted.profile);
    let _ = writeln!(output, "Binary Hash: {}", sorted.binary_hash);
    let _ = writeln!(output, "Schema:      {}", sorted.schema_version);

    output.push_str("\n--- Commands ---\n\n");
    for cmd in &sorted.commands {
        format_command(&mut output, cmd, 0);
    }

    output.push_str("\n--- Capabilities ---\n\n");
    for cap in &sorted.capabilities {
        let _ = writeln!(
            output,
            "  {} [{}]",
            cap.id,
            cap.verification_method.as_str()
        );
        if let Some(desc) = &cap.description {
            let _ = writeln!(output, "    {desc}");
        }
        if let Some(selftest) = &cap.selftest_id {
            let _ = writeln!(output, "    Selftest: {selftest}");
        }
    }

    let _ = writeln!(
        output,
        "\nTotal: {} commands, {} capabilities",
        count_commands(&sorted.commands),
        sorted.capabilities.len()
    );

    output
}

/// Formats a single command with indentation.
fn format_command(output: &mut String, cmd: &Command, depth: usize) {
    use std::fmt::Write;
    let indent = "  ".repeat(depth + 1);
    let _ = write!(output, "{indent}{}", cmd.name);
    if let Some(desc) = &cmd.description {
        let _ = write!(output, " - {desc}");
    }
    output.push('\n');

    for subcmd in &cmd.subcommands {
        format_command(output, subcmd, depth + 1);
    }
}

/// Counts total commands including subcommands.
fn count_commands(commands: &[Command]) -> usize {
    commands
        .iter()
        .map(|c| 1 + count_commands(&c.subcommands))
        .sum()
}

/// Writes content to a file atomically using tempfile + rename.
///
/// This follows CTR-2607: State Files Use Atomic Write.
fn write_atomic(path: &PathBuf, content: &str) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));

    // Create a tempfile in the same directory for atomic rename
    let mut temp_file =
        tempfile::NamedTempFile::new_in(parent).context("Failed to create temp file")?;

    temp_file
        .write_all(content.as_bytes())
        .context("Failed to write to temp file")?;

    temp_file
        .persist(path)
        .context("Failed to persist temp file")?;

    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capabilities_args_default() {
        let args = CapabilitiesArgs {
            json: false,
            output: None,
        };
        assert!(!args.json);
        assert!(args.output.is_none());
    }

    #[test]
    fn test_capabilities_args_json() {
        let args = CapabilitiesArgs {
            json: true,
            output: None,
        };
        assert!(args.json);
    }

    #[test]
    fn test_capabilities_args_output() {
        let args = CapabilitiesArgs {
            json: true,
            output: Some(PathBuf::from("manifest.json")),
        };
        assert_eq!(args.output, Some(PathBuf::from("manifest.json")));
    }

    #[test]
    fn test_populate_commands() {
        let config = ManifestConfig::builder()
            .version("0.1.0")
            .target("x86_64-unknown-linux-gnu")
            .profile("debug")
            .build()
            .unwrap();

        let mut manifest = CapabilityManifest::generate(&config);
        populate_commands(&mut manifest);

        assert!(!manifest.commands.is_empty());

        // Check for expected commands
        let cmd_names: Vec<&str> = manifest.commands.iter().map(|c| c.name.as_str()).collect();
        assert!(cmd_names.contains(&"capabilities"));
        assert!(cmd_names.contains(&"selftest"));
        assert!(cmd_names.contains(&"lint"));
    }

    #[test]
    fn test_populate_capabilities() {
        let config = ManifestConfig::builder()
            .version("0.1.0")
            .target("x86_64-unknown-linux-gnu")
            .profile("debug")
            .build()
            .unwrap();

        let mut manifest = CapabilityManifest::generate(&config);
        populate_capabilities(&mut manifest);

        assert!(!manifest.capabilities.is_empty());

        // Check for expected capabilities
        let cap_ids: Vec<&str> = manifest
            .capabilities
            .iter()
            .map(|c| c.id.as_str())
            .collect();
        assert!(cap_ids.contains(&"cac:patch:apply"));
        assert!(cap_ids.contains(&"cac:admission:validate"));
    }

    #[test]
    fn test_format_human_readable() {
        let config = ManifestConfig::builder()
            .version("0.1.0")
            .target("x86_64-unknown-linux-gnu")
            .profile("debug")
            .build()
            .unwrap();

        let mut manifest = CapabilityManifest::generate(&config);
        populate_commands(&mut manifest);
        populate_capabilities(&mut manifest);

        let output = format_human_readable(&manifest);

        assert!(output.contains("Capability Manifest"));
        assert!(output.contains("Version:"));
        assert!(output.contains("Commands"));
        assert!(output.contains("Capabilities"));
    }

    #[test]
    fn test_count_commands() {
        let commands = vec![
            Command::builder().name("simple").build().unwrap(),
            Command::builder()
                .name("parent")
                .subcommand(Command::builder().name("child1").build().unwrap())
                .subcommand(Command::builder().name("child2").build().unwrap())
                .build()
                .unwrap(),
        ];

        assert_eq!(count_commands(&commands), 4);
    }

    #[test]
    fn test_write_atomic() {
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("test_output.txt");

        write_atomic(&path, "test content").unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content, "test content");
    }
}
