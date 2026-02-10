// AGENT-AUTHORED
//! VDF delay profile for adversarial federation links (TCK-00366, RFC-0020
//! §1.9).
//!
//! This module provides a bounded, fail-closed VDF profile contract used by
//! `EpochSealV1`.

use std::fmt;

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

/// Maximum VDF output length in bytes (`DoS` protection).
pub const MAX_VDF_OUTPUT_LENGTH: usize = 256;

/// Maximum VDF difficulty (bounded sequential work).
pub const MAX_VDF_DIFFICULTY: u64 = 1_000_000;

/// Minimum VDF difficulty (must be meaningful).
pub const MIN_VDF_DIFFICULTY: u64 = 1;

/// Domain separator for deterministic challenge derivation.
const VDF_CHALLENGE_DOMAIN: &[u8] = b"apm2:vdf_profile_v1:challenge:v1\0";

/// Domain separator for the Sloth-v1 iterated hash proxy.
const VDF_SLOTH_V1_DOMAIN: &[u8] = b"apm2:vdf_profile_v1:sloth:v1\0";

/// Sloth-v1 proxy output length in bytes.
const SLOTH_V1_OUTPUT_LENGTH: usize = 32;

/// VDF scheme identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VdfScheme {
    /// Sloth-based iterated squaring (implemented as iterated BLAKE3 proxy in
    /// this phase).
    SlothV1,

    /// Pietrzak VDF with efficient verification.
    PietrzakV1,
}

impl fmt::Display for VdfScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SlothV1 => write!(f, "sloth-v1"),
            Self::PietrzakV1 => write!(f, "pietrzak-v1"),
        }
    }
}

/// Validation errors for [`VdfProfileV1`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum VdfProfileError {
    /// Input challenge hash must be non-zero.
    #[error("vdf input hash must be non-zero")]
    ZeroInputHash,

    /// VDF output must be present.
    #[error("vdf output must be non-empty")]
    EmptyOutput,

    /// VDF output exceeds configured cap.
    #[error("vdf output too long: {length} > {max}")]
    OutputTooLong {
        /// Actual output length.
        length: usize,
        /// Maximum allowed length.
        max: usize,
    },

    /// Difficulty is below allowed minimum.
    #[error("vdf difficulty too low: {difficulty} < {min}")]
    DifficultyTooLow {
        /// Provided difficulty.
        difficulty: u64,
        /// Minimum allowed difficulty.
        min: u64,
    },

    /// Difficulty is above allowed maximum.
    #[error("vdf difficulty too high: {difficulty} > {max}")]
    DifficultyTooHigh {
        /// Provided difficulty.
        difficulty: u64,
        /// Maximum allowed difficulty.
        max: u64,
    },
}

/// Verification errors returned by [`VdfVerifier`] implementations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum VdfVerificationError {
    /// Profile failed invariant checks.
    #[error(transparent)]
    InvalidProfile(#[from] VdfProfileError),

    /// Verifier received a profile for the wrong scheme.
    #[error("vdf scheme mismatch: expected {expected}, got {actual}")]
    SchemeMismatch {
        /// Expected scheme for this verifier.
        expected: VdfScheme,
        /// Actual profile scheme.
        actual: VdfScheme,
    },

    /// Scheme-specific output shape mismatch.
    #[error("invalid vdf output length for {scheme}: expected {expected} bytes, got {actual}")]
    OutputLengthMismatch {
        /// Scheme under verification.
        scheme: VdfScheme,
        /// Expected output length.
        expected: usize,
        /// Actual output length.
        actual: usize,
    },

    /// Output does not match recomputed expected value.
    #[error("vdf output mismatch")]
    OutputMismatch,

    /// Scheme exists but verifier support is not yet implemented.
    #[error("vdf verification unsupported: {scheme}")]
    UnsupportedScheme {
        /// Human-readable unsupported scheme reason.
        scheme: String,
    },
}

/// A VDF delay profile attached to an epoch seal.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VdfProfileV1 {
    /// VDF scheme identifier.
    scheme: VdfScheme,

    /// Deterministic challenge hash derived from `(cell_id,
    /// prior_epoch_root, quorum_anchor)`.
    input_hash: [u8; 32],

    /// VDF output bytes (bounded by [`MAX_VDF_OUTPUT_LENGTH`]).
    output: Vec<u8>,

    /// Sequential work parameter.
    difficulty: u64,
}

impl VdfProfileV1 {
    /// Creates a new VDF profile after validating all invariants.
    ///
    /// # Errors
    ///
    /// Returns [`VdfProfileError`] when any field is invalid.
    pub fn new(
        scheme: VdfScheme,
        input_hash: [u8; 32],
        output: Vec<u8>,
        difficulty: u64,
    ) -> Result<Self, VdfProfileError> {
        let profile = Self {
            scheme,
            input_hash,
            output,
            difficulty,
        };
        profile.validate()?;
        Ok(profile)
    }

    /// Validates profile invariants.
    ///
    /// # Errors
    ///
    /// Returns [`VdfProfileError`] when any field is invalid.
    pub fn validate(&self) -> Result<(), VdfProfileError> {
        if self.input_hash == [0u8; 32] {
            return Err(VdfProfileError::ZeroInputHash);
        }
        if self.output.is_empty() {
            return Err(VdfProfileError::EmptyOutput);
        }
        if self.output.len() > MAX_VDF_OUTPUT_LENGTH {
            return Err(VdfProfileError::OutputTooLong {
                length: self.output.len(),
                max: MAX_VDF_OUTPUT_LENGTH,
            });
        }
        if self.difficulty < MIN_VDF_DIFFICULTY {
            return Err(VdfProfileError::DifficultyTooLow {
                difficulty: self.difficulty,
                min: MIN_VDF_DIFFICULTY,
            });
        }
        if self.difficulty > MAX_VDF_DIFFICULTY {
            return Err(VdfProfileError::DifficultyTooHigh {
                difficulty: self.difficulty,
                max: MAX_VDF_DIFFICULTY,
            });
        }
        Ok(())
    }

    /// Returns the VDF scheme.
    #[must_use]
    pub const fn scheme(&self) -> VdfScheme {
        self.scheme
    }

    /// Returns the deterministic challenge hash.
    #[must_use]
    pub const fn input_hash(&self) -> &[u8; 32] {
        &self.input_hash
    }

    /// Returns the VDF output bytes.
    #[must_use]
    pub fn output(&self) -> &[u8] {
        &self.output
    }

    /// Returns the configured VDF difficulty.
    #[must_use]
    pub const fn difficulty(&self) -> u64 {
        self.difficulty
    }

    /// Derives deterministic challenge input hash from
    /// `(cell_id, prior_epoch_root, quorum_anchor)`.
    #[must_use]
    pub fn derive_challenge(
        cell_id: &str,
        prior_epoch_root: &[u8; 32],
        quorum_anchor: &[u8; 32],
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(VDF_CHALLENGE_DOMAIN);
        let cell_bytes = cell_id.as_bytes();
        hasher.update(&(cell_bytes.len() as u64).to_le_bytes());
        hasher.update(cell_bytes);
        hasher.update(prior_epoch_root);
        hasher.update(quorum_anchor);
        *hasher.finalize().as_bytes()
    }

    /// Verifies this profile using the default scheme-dispatch verifier.
    ///
    /// # Errors
    ///
    /// Returns [`VdfVerificationError`] if verification fails.
    pub fn verify(&self) -> Result<(), VdfVerificationError> {
        DefaultVdfVerifier::default().verify_vdf(self)
    }
}

/// Trait for VDF proof verification (fail-closed).
pub trait VdfVerifier: fmt::Debug + Send + Sync {
    /// Verifies the provided VDF profile.
    ///
    /// # Errors
    ///
    /// Returns [`VdfVerificationError`] on any verification failure.
    fn verify_vdf(&self, profile: &VdfProfileV1) -> Result<(), VdfVerificationError>;
}

/// Sloth-v1 verifier.
///
/// This implementation uses a bounded iterated-BLAKE3 proxy for the current
/// delivery phase. Verification cost is O(difficulty) and bounded by
/// [`MAX_VDF_DIFFICULTY`].
#[derive(Debug, Default)]
pub struct SlothV1Verifier;

impl SlothV1Verifier {
    /// Evaluates the Sloth-v1 delay function proxy.
    #[must_use]
    pub fn evaluate(input_hash: &[u8; 32], difficulty: u64) -> [u8; 32] {
        let mut state = *input_hash;
        for _ in 0..difficulty {
            let mut hasher = blake3::Hasher::new();
            hasher.update(VDF_SLOTH_V1_DOMAIN);
            hasher.update(&state);
            state = *hasher.finalize().as_bytes();
        }
        state
    }
}

impl VdfVerifier for SlothV1Verifier {
    fn verify_vdf(&self, profile: &VdfProfileV1) -> Result<(), VdfVerificationError> {
        profile.validate()?;
        if profile.scheme() != VdfScheme::SlothV1 {
            return Err(VdfVerificationError::SchemeMismatch {
                expected: VdfScheme::SlothV1,
                actual: profile.scheme(),
            });
        }

        if profile.output().len() != SLOTH_V1_OUTPUT_LENGTH {
            return Err(VdfVerificationError::OutputLengthMismatch {
                scheme: VdfScheme::SlothV1,
                expected: SLOTH_V1_OUTPUT_LENGTH,
                actual: profile.output().len(),
            });
        }

        let expected = Self::evaluate(profile.input_hash(), profile.difficulty());
        let actual = profile.output();
        if expected.as_slice().ct_eq(actual).unwrap_u8() != 1 {
            return Err(VdfVerificationError::OutputMismatch);
        }

        Ok(())
    }
}

/// Pietrzak-v1 verifier placeholder.
#[derive(Debug, Default)]
pub struct PietrzakV1Verifier;

impl VdfVerifier for PietrzakV1Verifier {
    fn verify_vdf(&self, profile: &VdfProfileV1) -> Result<(), VdfVerificationError> {
        profile.validate()?;
        if profile.scheme() != VdfScheme::PietrzakV1 {
            return Err(VdfVerificationError::SchemeMismatch {
                expected: VdfScheme::PietrzakV1,
                actual: profile.scheme(),
            });
        }
        Err(VdfVerificationError::UnsupportedScheme {
            scheme: "PietrzakV1 verification not implemented; fail-closed per RFC-0020 §1.9".into(),
        })
    }
}

/// Default verifier that dispatches to a scheme-specific implementation.
#[derive(Debug, Default)]
pub struct DefaultVdfVerifier {
    sloth: SlothV1Verifier,
    pietrzak: PietrzakV1Verifier,
}

impl VdfVerifier for DefaultVdfVerifier {
    fn verify_vdf(&self, profile: &VdfProfileV1) -> Result<(), VdfVerificationError> {
        match profile.scheme() {
            VdfScheme::SlothV1 => self.sloth.verify_vdf(profile),
            VdfScheme::PietrzakV1 => self.pietrzak.verify_vdf(profile),
        }
    }
}

/// VDF enforcement policy per-link or per-cell.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum VdfPolicy {
    /// VDF is not required (local mode).
    #[default]
    Optional,

    /// VDF is required for this link/cell (adversarial federation).
    Required {
        /// Minimum acceptable sequential work.
        min_difficulty: u64,
    },
}

/// Resolves a VDF policy for a specific link/cell key.
pub trait VdfPolicyResolver: fmt::Debug + Send + Sync {
    /// Returns the effective policy for `key`.
    fn resolve_policy(&self, key: &str) -> VdfPolicy;
}

/// Backward-compatible resolver that always returns one configured default
/// policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DefaultVdfPolicyResolver {
    default_policy: VdfPolicy,
}

impl DefaultVdfPolicyResolver {
    /// Creates a resolver with `default_policy`.
    #[must_use]
    pub const fn new(default_policy: VdfPolicy) -> Self {
        Self { default_policy }
    }

    /// Returns the configured default policy.
    #[must_use]
    pub const fn default_policy(&self) -> &VdfPolicy {
        &self.default_policy
    }
}

impl VdfPolicyResolver for DefaultVdfPolicyResolver {
    fn resolve_policy(&self, _key: &str) -> VdfPolicy {
        self.default_policy.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_anchor(seed: u8) -> [u8; 32] {
        let mut h = [seed; 32];
        h[0] |= 0x01;
        h
    }

    fn build_valid_sloth_profile(difficulty: u64) -> VdfProfileV1 {
        let input =
            VdfProfileV1::derive_challenge("cell-alpha", &test_anchor(0x11), &test_anchor(0x22));
        let output = SlothV1Verifier::evaluate(&input, difficulty).to_vec();
        VdfProfileV1::new(VdfScheme::SlothV1, input, output, difficulty)
            .expect("valid sloth profile")
    }

    #[test]
    fn challenge_derivation_is_deterministic() {
        let c1 =
            VdfProfileV1::derive_challenge("cell-alpha", &test_anchor(0x11), &test_anchor(0x22));
        let c2 =
            VdfProfileV1::derive_challenge("cell-alpha", &test_anchor(0x11), &test_anchor(0x22));
        assert_eq!(c1, c2);
    }

    #[test]
    fn challenge_derivation_binds_all_inputs() {
        let base =
            VdfProfileV1::derive_challenge("cell-alpha", &test_anchor(0x11), &test_anchor(0x22));
        let different_cell =
            VdfProfileV1::derive_challenge("cell-beta", &test_anchor(0x11), &test_anchor(0x22));
        let different_prior =
            VdfProfileV1::derive_challenge("cell-alpha", &test_anchor(0x33), &test_anchor(0x22));
        let different_quorum =
            VdfProfileV1::derive_challenge("cell-alpha", &test_anchor(0x11), &test_anchor(0x44));

        assert_ne!(base, different_cell);
        assert_ne!(base, different_prior);
        assert_ne!(base, different_quorum);
        assert_ne!(different_cell, different_prior);
        assert_ne!(different_prior, different_quorum);
    }

    #[test]
    fn profile_new_rejects_zero_input_hash() {
        let result = VdfProfileV1::new(VdfScheme::SlothV1, [0u8; 32], vec![1u8; 32], 4);
        assert!(matches!(result, Err(VdfProfileError::ZeroInputHash)));
    }

    #[test]
    fn profile_new_rejects_empty_output() {
        let result = VdfProfileV1::new(VdfScheme::SlothV1, test_anchor(0x11), Vec::new(), 4);
        assert!(matches!(result, Err(VdfProfileError::EmptyOutput)));
    }

    #[test]
    fn profile_new_rejects_oversized_output() {
        let result = VdfProfileV1::new(
            VdfScheme::SlothV1,
            test_anchor(0x11),
            vec![0xAA; MAX_VDF_OUTPUT_LENGTH + 1],
            4,
        );
        assert!(matches!(result, Err(VdfProfileError::OutputTooLong { .. })));
    }

    #[test]
    fn profile_new_rejects_zero_difficulty() {
        let result = VdfProfileV1::new(VdfScheme::SlothV1, test_anchor(0x11), vec![0xAA; 32], 0);
        assert!(matches!(
            result,
            Err(VdfProfileError::DifficultyTooLow { .. })
        ));
    }

    #[test]
    fn profile_new_rejects_difficulty_above_max() {
        let result = VdfProfileV1::new(
            VdfScheme::SlothV1,
            test_anchor(0x11),
            vec![0xAA; 32],
            MAX_VDF_DIFFICULTY + 1,
        );
        assert!(matches!(
            result,
            Err(VdfProfileError::DifficultyTooHigh { .. })
        ));
    }

    #[test]
    fn sloth_verify_accepts_valid_profile() {
        let profile = build_valid_sloth_profile(5);
        assert!(profile.verify().is_ok());
    }

    #[test]
    fn sloth_verify_rejects_forged_output() {
        let profile = build_valid_sloth_profile(5);
        let mut forged = profile.output().to_vec();
        forged[0] ^= 0x01;

        let forged_profile = VdfProfileV1::new(
            VdfScheme::SlothV1,
            *profile.input_hash(),
            forged,
            profile.difficulty(),
        )
        .expect("forged profile still structurally valid");

        let err = forged_profile
            .verify()
            .expect_err("forged output must fail");
        assert!(matches!(err, VdfVerificationError::OutputMismatch));
    }

    #[test]
    fn profile_input_hash_matches_derived_challenge() {
        let prior = test_anchor(0x55);
        let quorum = test_anchor(0x66);
        let input = VdfProfileV1::derive_challenge("cell-alpha", &prior, &quorum);
        let output = SlothV1Verifier::evaluate(&input, 3).to_vec();
        let profile =
            VdfProfileV1::new(VdfScheme::SlothV1, input, output, 3).expect("valid profile");

        let derived = VdfProfileV1::derive_challenge("cell-alpha", &prior, &quorum);
        assert_eq!(profile.input_hash(), &derived);
    }

    #[test]
    fn pietrzak_verifier_fails_closed_until_implemented() {
        let input =
            VdfProfileV1::derive_challenge("cell-alpha", &test_anchor(0x11), &test_anchor(0x22));
        let profile = VdfProfileV1::new(VdfScheme::PietrzakV1, input, vec![0xAB; 48], 7)
            .expect("valid profile");

        let verifier = PietrzakV1Verifier;
        let err = verifier
            .verify_vdf(&profile)
            .expect_err("PietrzakV1 must fail closed until verification is implemented");
        match err {
            VdfVerificationError::UnsupportedScheme { scheme } => {
                assert_eq!(
                    scheme,
                    "PietrzakV1 verification not implemented; fail-closed per RFC-0020 §1.9"
                );
            },
            _ => panic!("unexpected error variant"),
        }
    }

    #[test]
    fn default_verifier_rejects_pietrzak_profiles_fail_closed() {
        let input =
            VdfProfileV1::derive_challenge("cell-alpha", &test_anchor(0x11), &test_anchor(0x22));
        let profile = VdfProfileV1::new(VdfScheme::PietrzakV1, input, vec![0xAB; 48], 7)
            .expect("valid profile");

        let verifier = DefaultVdfVerifier::default();
        let err = verifier
            .verify_vdf(&profile)
            .expect_err("DefaultVdfVerifier must reject unimplemented PietrzakV1");
        match err {
            VdfVerificationError::UnsupportedScheme { scheme } => {
                assert_eq!(
                    scheme,
                    "PietrzakV1 verification not implemented; fail-closed per RFC-0020 §1.9"
                );
            },
            _ => panic!("unexpected error variant"),
        }
    }

    #[test]
    fn default_policy_resolver_returns_configured_policy() {
        let resolver = DefaultVdfPolicyResolver::new(VdfPolicy::Required { min_difficulty: 9 });

        let policy_alpha = resolver.resolve_policy("cell-alpha");
        let policy_beta = resolver.resolve_policy("cell-beta");

        assert_eq!(policy_alpha, VdfPolicy::Required { min_difficulty: 9 });
        assert_eq!(policy_beta, VdfPolicy::Required { min_difficulty: 9 });
    }
}
