//! Build script for generating Rust code from Protocol Buffer definitions.

use std::fs;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Tell Cargo to re-run if proto files change
    println!("cargo:rerun-if-changed=../../proto/kernel_events.proto");
    println!("cargo:rerun-if-changed=../../proto/tool_protocol.proto");

    // Compile the kernel events proto
    prost_build::Config::new()
        // Generate BTreeMap instead of HashMap for deterministic ordering
        .btree_map(["."])
        // Derive additional traits for all types
        .type_attribute(".", "#[derive(Eq, Hash)]")
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
        // Derive additional traits for all types
        .type_attribute(".", "#[derive(Eq, Hash)]")
        // Output to src/tool/
        .out_dir("src/tool")
        .compile_protos(&["../../proto/tool_protocol.proto"], &["../../proto"])?;

    Ok(())
}
