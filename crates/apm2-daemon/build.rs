//! Build script for generating Rust code from Protocol Buffer definitions.
//!
//! This compiles the daemon runtime protocol messages defined in
//! `proto/apm2d_runtime_v1.proto` into Rust types using prost.

use std::fs;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Tell Cargo to re-run if proto files change
    println!("cargo:rerun-if-changed=../../proto/apm2d_runtime_v1.proto");

    // Ensure src/protocol directory exists
    let protocol_dir = Path::new("src/protocol");
    if !protocol_dir.exists() {
        fs::create_dir_all(protocol_dir)?;
    }

    // Compile the daemon runtime protocol proto
    // Note: We don't add #[derive(Eq, Hash)] globally because:
    // 1. Enums already derive these via prost::Enumeration
    // 2. PromoteTrigger has an f64 field which doesn't implement Eq/Hash
    prost_build::Config::new()
        // Generate BTreeMap instead of HashMap for deterministic ordering
        // (Note: HelloAck has a map, which is allowed for non-signed messages)
        .btree_map(["."])
        // Output to src/protocol/
        .out_dir("src/protocol")
        .compile_protos(&["../../proto/apm2d_runtime_v1.proto"], &["../../proto"])?;

    Ok(())
}
