//! Common benchmark fixtures and utilities.
//!
//! Provides shared test data creation functions used across benchmarks.

#![allow(dead_code)]
#![allow(clippy::cast_possible_truncation)]

use std::collections::HashMap;

use apm2_core::process::ProcessSpec;

/// Create a process spec with a configurable number of environment variables.
pub fn create_process_spec(name: &str, env_count: usize) -> ProcessSpec {
    let mut builder = ProcessSpec::builder()
        .name(name)
        .command("/usr/bin/echo")
        .args(["hello", "world"])
        .cwd("/tmp")
        .instances(1);

    for i in 0..env_count {
        builder = builder.env(format!("VAR_{i}"), format!("value_{i}"));
    }

    builder.build()
}

/// Create a batch of process specs for supervisor benchmarks.
pub fn create_process_specs(count: usize) -> Vec<ProcessSpec> {
    (0..count)
        .map(|i| create_process_spec(&format!("process-{i}"), 5))
        .collect()
}

/// Create sample environment variables map.
#[allow(dead_code)]
pub fn create_env_map(count: usize) -> HashMap<String, String> {
    (0..count)
        .map(|i| {
            (
                format!("ENV_VAR_{i}"),
                format!("value_{i}_with_some_content"),
            )
        })
        .collect()
}
