//! Fuzz harness for `KeySetIdV1::parse_text`.
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
use apm2_daemon::identity::{
    KeyIdError, KeySetDigestResolver, ResolvedKeySetSemantics, SetTag,
};
use libfuzzer_sys::fuzz_target;

struct MissingDescriptorResolver;

impl KeySetDigestResolver for MissingDescriptorResolver {
    fn resolve_by_digest(
        &self,
        _merkle_root: &[u8; 32],
    ) -> Result<ResolvedKeySetSemantics, KeyIdError> {
        Err(KeyIdError::InvalidDescriptor {
            reason: "missing descriptor".to_string(),
        })
    }
}

struct MalformedDescriptorResolver;

impl KeySetDigestResolver for MalformedDescriptorResolver {
    fn resolve_by_digest(
        &self,
        _merkle_root: &[u8; 32],
    ) -> Result<ResolvedKeySetSemantics, KeyIdError> {
        Err(KeyIdError::InvalidDescriptor {
            reason: "malformed descriptor".to_string(),
        })
    }
}

struct StaleDescriptorResolver;

impl KeySetDigestResolver for StaleDescriptorResolver {
    fn resolve_by_digest(
        &self,
        _merkle_root: &[u8; 32],
    ) -> Result<ResolvedKeySetSemantics, KeyIdError> {
        Ok(ResolvedKeySetSemantics {
            merkle_root: [0xFF; 32],
            set_tag: SetTag::Threshold,
        })
    }
}

struct EchoDigestResolver(SetTag);

impl KeySetDigestResolver for EchoDigestResolver {
    fn resolve_by_digest(
        &self,
        merkle_root: &[u8; 32],
    ) -> Result<ResolvedKeySetSemantics, KeyIdError> {
        Ok(ResolvedKeySetSemantics {
            merkle_root: *merkle_root,
            set_tag: self.0,
        })
    }
}

fuzz_target!(|data: &[u8]| {
    // Only test valid UTF-8 strings (parse_text takes &str)
    if let Ok(s) = std::str::from_utf8(data) {
        // The parser must never panic, regardless of input.
        // It should always return Ok or Err.
        let _ = apm2_daemon::identity::KeySetIdV1::parse_text(s);
        let _ = apm2_daemon::identity::KeySetIdV1::parse_text_with_state(s);
    }

    // Also test with raw bytes via from_binary
    let _ = apm2_daemon::identity::KeySetIdV1::from_binary(data);
    let _ = apm2_daemon::identity::KeySetIdV1::from_binary_with_state(data);

    // Mixed wire forms + resolver paths.
    if data.len() >= 32 {
        let mut hash_only = [0u8; 32];
        hash_only.copy_from_slice(&data[..32]);

        if let Ok(unresolved) = apm2_daemon::identity::KeySetIdV1::from_binary(&hash_only) {
            let _ = unresolved.resolve_with(&MissingDescriptorResolver);
            let _ = unresolved.resolve_with(&MalformedDescriptorResolver);
            let _ = unresolved.resolve_with(&StaleDescriptorResolver);
            let _ = unresolved.resolve_with(&EchoDigestResolver(SetTag::Multisig));
        }

        let mut tagged = [0u8; 33];
        tagged[1..].copy_from_slice(&hash_only);
        tagged[0] = match data.get(32).copied().unwrap_or(0) % 4 {
            0 => SetTag::Multisig.to_byte(),
            1 => SetTag::Threshold.to_byte(),
            2 => 0x00, // unresolved compatibility tag
            _ => 0xFF, // unknown tag (must fail closed)
        };
        let _ = apm2_daemon::identity::KeySetIdV1::from_binary(&tagged);
        let _ = apm2_daemon::identity::KeySetIdV1::from_binary_with_state(&tagged);
    }
});
