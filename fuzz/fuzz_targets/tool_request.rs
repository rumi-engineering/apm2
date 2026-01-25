//! Fuzz target for tool request parsing and validation.
//!
//! This fuzzer tests that:
//! 1. Arbitrary bytes can be decoded without panicking
//! 2. Decoded requests can be validated without panicking
//! 3. Successfully decoded requests can be re-encoded
//!
//! The goal is to find inputs that cause crashes, hangs, or memory issues.

#![no_main]
use apm2_core::tool::{ToolRequest, Validator};
use libfuzzer_sys::fuzz_target;
use prost::Message;

fuzz_target!(|data: &[u8]| {
    // Try to decode arbitrary bytes as a ToolRequest
    // This should never panic, only return an error for invalid input
    if let Ok(request) = ToolRequest::decode(data) {
        // If decoding succeeded, validation should not panic
        let _ = request.validate();

        // Re-encoding should always succeed and produce identical bytes
        // (canonical encoding property)
        let re_encoded = request.encode_to_vec();

        // Decoding re-encoded bytes should produce identical request
        if let Ok(re_decoded) = ToolRequest::decode(re_encoded.as_slice()) {
            assert_eq!(request, re_decoded, "roundtrip mismatch");
        }
    }
});
