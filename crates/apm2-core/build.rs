//! Build script for generating Rust code from Protocol Buffer definitions
//! and the bootstrap schema manifest.

use std::collections::BTreeMap;
use std::fmt::Write as FmtWrite;
use std::fs;
use std::io::Write;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Tell Cargo to re-run if proto files change
    println!("cargo:rerun-if-changed=../../proto/kernel_events.proto");
    println!("cargo:rerun-if-changed=../../proto/tool_protocol.proto");

    // Tell Cargo to re-run if bootstrap schemas change
    println!("cargo:rerun-if-changed=bootstrap/");

    // Compile the kernel events proto
    prost_build::Config::new()
        // Generate BTreeMap instead of HashMap for deterministic ordering
        .btree_map(["."])
        // Derive additional traits for messages (including oneof enums via type_attribute)
        // Note: Regular enums already have Eq, Hash from prost, but we need to skip them
        // by using specific message patterns to avoid duplication
        .message_attribute(".", "#[derive(Eq, Hash)]")
        // Add Eq, Hash to oneof enums (they don't get these by default)
        // Use a broad pattern that matches all oneof inner modules
        .type_attribute(".apm2.kernel.v1.KernelEvent.payload", "#[derive(Eq, Hash)]")
        .type_attribute(".apm2.kernel.v1.SessionEvent.event", "#[derive(Eq, Hash)]")
        .type_attribute(".apm2.kernel.v1.WorkEvent.event", "#[derive(Eq, Hash)]")
        .type_attribute(".apm2.kernel.v1.ToolEvent.event", "#[derive(Eq, Hash)]")
        .type_attribute(".apm2.kernel.v1.LeaseEvent.event", "#[derive(Eq, Hash)]")
        .type_attribute(".apm2.kernel.v1.PolicyEvent.event", "#[derive(Eq, Hash)]")
        .type_attribute(".apm2.kernel.v1.AdjudicationEvent.event", "#[derive(Eq, Hash)]")
        .type_attribute(".apm2.kernel.v1.EvidenceEvent.event", "#[derive(Eq, Hash)]")
        .type_attribute(".apm2.kernel.v1.CapabilityEvent.event", "#[derive(Eq, Hash)]")
        .type_attribute(".apm2.kernel.v1.KeyEvent.event", "#[derive(Eq, Hash)]")
        .type_attribute(".apm2.kernel.v1.GitHubLeaseEvent.event", "#[derive(Eq, Hash)]")
        // Output to src/events/
        .out_dir("src/events")
        .compile_protos(&["../../proto/kernel_events.proto"], &["../../proto"])?;

    // Ensure src/tool directory exists
    let tool_dir = Path::new("src/tool");
    if !tool_dir.exists() {
        fs::create_dir_all(tool_dir)?;
    }

    // Compile the tool protocol proto
    prost_build::Config::new()
        // Generate BTreeMap instead of HashMap for deterministic ordering
        .btree_map(["."])
        // Derive additional traits for messages (including oneof enums via type_attribute)
        .message_attribute(".", "#[derive(Eq, Hash)]")
        // Add Eq, Hash to oneof enums (they don't get these by default)
        .type_attribute(".apm2.tool.v1.ToolRequest.tool", "#[derive(Eq, Hash)]")
        .type_attribute(".apm2.tool.v1.ToolResponse.result", "#[derive(Eq, Hash)]")
        // Output to src/tool/
        .out_dir("src/tool")
        .compile_protos(&["../../proto/tool_protocol.proto"], &["../../proto"])?;

    // Generate bootstrap schema manifest
    generate_bootstrap_manifest()?;

    // Manually link commit-msg hook since cargo-husky 1.5.0 doesn't support it.
    // Also ensure core.hooksPath is unset to allow standard hooks to run.
    #[cfg(unix)]
    {
        use std::process::Command;

        // Unset core.hooksPath if it exists, as it can block cargo-husky hooks
        let _ = Command::new("git")
            .args(["config", "--unset", "core.hooksPath"])
            .status();

        let git_hooks_dir = Path::new("../../.git/hooks");
        let custom_hooks_dir = Path::new("../../.cargo-husky/hooks");
        let commit_msg_hook = custom_hooks_dir.join("commit-msg");

        if git_hooks_dir.exists() && commit_msg_hook.exists() {
            let target = git_hooks_dir.join("commit-msg");
            if !target.exists() {
                // Use a relative symlink so it works across different checkouts.
                // The link is created in .git/hooks/, so it needs to point back to the root.
                let _ = std::os::unix::fs::symlink("../../.cargo-husky/hooks/commit-msg", target);
            }
        }
    }

    Ok(())
}

/// Generates the bootstrap schema manifest with content hashes.
///
/// This function:
/// 1. Reads all .schema.json files from bootstrap/schemas/
/// 2. Computes BLAKE3 hashes for each schema
/// 3. Generates a Rust module with embedded schema bytes and hashes
/// 4. Computes a bundle hash over all schemas for integrity verification
fn generate_bootstrap_manifest() -> Result<(), Box<dyn std::error::Error>> {
    let bootstrap_dir = Path::new("bootstrap/schemas");
    let out_dir = std::env::var("OUT_DIR")?;
    let manifest_path = Path::new(&out_dir).join("bootstrap_manifest.rs");

    // Collect all schema files, sorted for deterministic ordering
    let mut schemas: BTreeMap<String, (String, [u8; 32])> = BTreeMap::new();

    if bootstrap_dir.exists() {
        let mut entries: Vec<_> = fs::read_dir(bootstrap_dir)?
            .filter_map(std::result::Result::ok)
            .filter(|e| e.path().extension().is_some_and(|ext| ext == "json"))
            .collect();

        // Sort by filename for deterministic ordering
        entries.sort_by_key(std::fs::DirEntry::file_name);

        for entry in entries {
            // Security: Reject symlinks to prevent directory traversal attacks
            if entry.file_type()?.is_symlink() {
                return Err(format!(
                    "Symlinks not allowed in bootstrap/schemas: {}",
                    entry.path().display()
                )
                .into());
            }

            let path = entry.path();
            let filename = entry.file_name().to_string_lossy().to_string();
            let content = fs::read_to_string(&path)?;

            // Validate JSON at build time to fail early on malformed schemas
            serde_json::from_str::<serde_json::Value>(&content).map_err(|e| {
                format!("Invalid JSON in bootstrap schema {}: {}", path.display(), e)
            })?;

            // Compute BLAKE3 hash
            let hash = blake3::hash(content.as_bytes());
            let hash_bytes: [u8; 32] = *hash.as_bytes();

            // Extract stable_id from filename
            // e.g., "bootstrap.common.v1.schema.json" -> "bootstrap:common.v1"
            let stable_id = filename.strip_suffix(".schema.json").map_or_else(
                || filename.clone(),
                |s| {
                    // Split on first dot to get "bootstrap" and "common.v1"
                    s.find('.').map_or_else(
                        || s.to_string(),
                        |dot_pos| {
                            let (prefix, rest) = s.split_at(dot_pos);
                            format!("{prefix}:{}", &rest[1..]) // Skip the dot in rest
                        },
                    )
                },
            );

            schemas.insert(stable_id, (content, hash_bytes));
        }
    }

    // Compute bundle hash over all schema hashes (sorted by stable_id)
    let mut bundle_hasher = blake3::Hasher::new();
    for (stable_id, (_, hash)) in &schemas {
        bundle_hasher.update(stable_id.as_bytes());
        bundle_hasher.update(hash);
    }
    let bundle_hash: [u8; 32] = *bundle_hasher.finalize().as_bytes();

    // Generate the Rust module
    let mut output = String::new();
    output.push_str("// Auto-generated bootstrap schema manifest.\n");
    output.push_str("// DO NOT EDIT - generated by build.rs from bootstrap/schemas/\n\n");

    // Bundle hash constant
    output.push_str("/// BLAKE3 hash of the entire bootstrap bundle.\n");
    output.push_str("/// Used for runtime integrity verification.\n");
    writeln!(
        output,
        "pub const BOOTSTRAP_BUNDLE_HASH: [u8; 32] = {bundle_hash:?};\n"
    )?;

    // Schema count
    let count = schemas.len();
    write!(
        output,
        "/// Number of schemas in the bootstrap bundle.\n\
         pub const BOOTSTRAP_SCHEMA_COUNT: usize = {count};\n\n"
    )?;

    // Generate schema entries
    output.push_str("/// Bootstrap schema entries.\n");
    output.push_str("/// Each entry contains (`stable_id`, content, `content_hash`).\n");
    output.push_str("pub const BOOTSTRAP_SCHEMAS: &[(&str, &str, [u8; 32])] = &[\n");

    for (stable_id, (content, hash)) in &schemas {
        // Security: Use debug formatting ({:?}) to properly escape string content
        // This prevents code injection if content contains sequences like `"#`
        let content_escaped = format!("{content:?}");
        writeln!(
            output,
            "    (\n        \"{stable_id}\",\n        {content_escaped},\n        {hash:?},\n    ),",
        )?;
    }

    output.push_str("];\n\n");

    // Generate stable ID list for quick lookup
    output.push_str("/// List of all bootstrap stable IDs.\n");
    output.push_str("pub const BOOTSTRAP_STABLE_IDS: &[&str] = &[\n");
    for stable_id in schemas.keys() {
        writeln!(output, "    \"{stable_id}\",")?;
    }
    output.push_str("];\n");

    // Write the manifest
    let mut file = fs::File::create(&manifest_path)?;
    file.write_all(output.as_bytes())?;

    Ok(())
}
