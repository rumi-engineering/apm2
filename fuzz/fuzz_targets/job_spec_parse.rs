#![no_main]
//! Fuzz target for FacJobSpecV1 bounded parsing and validation.
//!
//! Feeds arbitrary bytes through `deserialize_job_spec` and, when
//! deserialization succeeds, through `validate_job_spec`.  The goal is
//! to verify that no combination of crafted input can cause a panic,
//! unbounded allocation, or stack overflow.
//!
//! # Security invariants under test
//!
//! - [INV-JS-003] Validation is fail-closed (errors, never panics).
//! - [RSK-1601] Parsing is a DoS surface: size cap enforced before JSON parse.
//! - [RSK-0701] No `unwrap`/`expect`/indexing panic on untrusted input.

use apm2_core::fac::{
    JobSpecValidationPolicy, deserialize_job_spec, validate_job_spec,
    validate_job_spec_with_policy,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Phase 1: bounded deserialization — must never panic.
    let spec = match deserialize_job_spec(data) {
        Ok(s) => s,
        Err(_) => return, // Expected for most fuzz inputs.
    };

    // Phase 2: structural + digest + token validation — must never panic.
    let _ = validate_job_spec(&spec);

    // Phase 3: policy-driven validation with open policy — exercises the
    // full pipeline including `reject_filesystem_paths` and allowlist
    // checks.  Must never panic.
    let _ = validate_job_spec_with_policy(&spec, &JobSpecValidationPolicy::open());

    // Phase 4: digest computation — must never panic.
    let _ = spec.compute_digest();
});
