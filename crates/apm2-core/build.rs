//! Build script for generating Rust code from Protocol Buffer definitions.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Tell Cargo to re-run if proto files change
    println!("cargo:rerun-if-changed=../../proto/kernel_events.proto");

    // Compile the protobuf files
    prost_build::Config::new()
        // Generate BTreeMap instead of HashMap for deterministic ordering
        .btree_map(["."])
        // Derive additional traits for all types
        .type_attribute(".", "#[derive(Eq, Hash)]")
        // Output to src/events/generated.rs
        .out_dir("src/events")
        .compile_protos(&["../../proto/kernel_events.proto"], &["../../proto"])?;

    Ok(())
}
