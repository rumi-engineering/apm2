//! Fuzz harness for `PublicKeyIdV1::parse_text`.
//!
//! This target exercises the parser with arbitrary byte sequences converted
//! to UTF-8 strings, ensuring no panics occur on malformed Unicode,
//! overlong payloads, non-canonical encodings, or percent-encoded forms.
//!
//! # Contract References
//!
//! - REQ-0007: Canonical key identifier formats
//! - EVID-0007: Canonical key identifier conformance evidence

#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Only test valid UTF-8 strings (parse_text takes &str)
    if let Ok(s) = std::str::from_utf8(data) {
        // The parser must never panic, regardless of input.
        // It should always return Ok or Err.
        let _ = apm2_daemon::identity::PublicKeyIdV1::parse_text(s);
        let _ = apm2_daemon::identity::PublicKeyIdV1::parse_text_with_state(s);
    }

    // Also test with raw bytes via from_binary
    let _ = apm2_daemon::identity::PublicKeyIdV1::from_binary(data);
    let _ = apm2_daemon::identity::PublicKeyIdV1::from_binary_with_state(data);

    // Exercise explicit tagged-33 parsing path with arbitrary hash payload.
    if data.len() >= 32 {
        let mut binary = [0u8; 33];
        binary[0] = 0x01; // Ed25519 tag
        binary[1..].copy_from_slice(&data[..32]);
        let _ = apm2_daemon::identity::PublicKeyIdV1::from_binary(&binary);
        let _ = apm2_daemon::identity::PublicKeyIdV1::from_binary_with_state(&binary);
    }
});
