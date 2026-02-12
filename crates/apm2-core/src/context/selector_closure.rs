//! RFC-0029 REQ-0002: Digest-first selector closure completeness and
//! deterministic replay zoom-in.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::evidence::{CasError, ContentAddressedStore};
use crate::pcac::RiskTier;

/// Maximum number of selector digest entries.
pub const MAX_SELECTOR_DIGESTS: usize = 10_000;

/// Maximum number of loss-profile entries per claim.
pub const MAX_LOSS_PROFILE_ENTRIES: usize = 256;

/// Maximum replay evidence package size in bytes.
pub const MAX_REPLAY_EVIDENCE_BYTES: usize = 4 * 1024 * 1024;

/// Domain separator for replay zoom-in hash addressing.
pub const REPLAY_ZOOM_DOMAIN: &[u8] = b"apm2-replay-zoom-v1";

/// Risk tier threshold: tiers at or above this require complete loss profiles.
const HIGH_RISK_THRESHOLD: RiskTier = RiskTier::Tier1;

/// Structured defect for selector closure violations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectorClosureDefect {
    /// Machine-readable defect code.
    pub code: SelectorClosureDefectCode,
    /// Human-readable detail.
    pub message: String,
    /// Offending selector digest (hex) when available.
    pub selector_digest_hex: Option<String>,
}

/// Machine-readable defect codes for selector closure violations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SelectorClosureDefectCode {
    /// Selector digest set is empty.
    EmptySelectorDigests,
    /// Selector digest set exceeds maximum size.
    TooManySelectorDigests,
    /// Loss profile is missing for a high-risk claim.
    MissingLossProfile,
    /// Loss profile exceeds maximum entry count.
    TooManyLossProfileEntries,
    /// Loss profile digest does not match provided content.
    LossProfileDigestMismatch,
    /// Replay evidence hash not found in CAS.
    ReplayEvidenceMissing,
    /// Replay evidence exceeds maximum size.
    ReplayEvidenceTooLarge,
    /// Replay evidence content hash mismatch after retrieval.
    ReplayEvidenceHashMismatch,
    /// Selector digest not found in provided digest set.
    UnresolvedSelectorDigest,
    /// Risk tier is unknown or ambiguous - fail closed.
    UnknownRiskTier,
}

/// Errors for selector closure operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SelectorClosureError {
    /// Selector closure completeness check failed.
    #[error("selector closure defect: {0:?}")]
    Defect(SelectorClosureDefect),
    /// CAS operation failed.
    #[error("CAS error during selector closure check: {0}")]
    Cas(#[from] CasError),
}

/// A declared loss profile for a high-risk claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LossProfileDeclaration {
    /// BLAKE3 digest of the loss profile content.
    pub digest: [u8; 32],
    /// Number of entries in the loss profile.
    pub entry_count: u32,
    /// Risk tier this profile covers.
    pub risk_tier: RiskTier,
}

/// Input for selector closure completeness verification.
#[derive(Debug, Clone)]
pub struct SelectorClosureInput {
    /// Selector digests keyed by selector path.
    pub selector_digests: BTreeMap<String, [u8; 32]>,
    /// Loss profile declarations keyed by selector path.
    pub loss_profiles: BTreeMap<String, LossProfileDeclaration>,
    /// Resolved risk tier for this claim.
    pub resolved_risk_tier: RiskTier,
}

/// Result of a completeness check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompletenessVerdict {
    /// All selectors are complete with required loss profiles.
    Complete {
        /// Number of selectors verified.
        selector_count: usize,
        /// Number of loss profiles verified.
        loss_profile_count: usize,
    },
    /// Selector closure is incomplete - contains structured defects.
    Incomplete {
        /// Ordered list of defects found.
        defects: Vec<SelectorClosureDefect>,
    },
}

/// Verifies selector closure completeness for admission decisions.
///
/// Fail-closed: unknown/ambiguous state always produces `Incomplete`.
#[must_use]
pub fn verify_selector_completeness(input: &SelectorClosureInput) -> CompletenessVerdict {
    verify_selector_completeness_impl(input, None)
}

/// Verifies selector closure completeness and validates loss-profile digest
/// bindings against CAS for high-risk tiers.
#[must_use]
pub fn verify_selector_completeness_with_cas(
    input: &SelectorClosureInput,
    cas: &dyn ContentAddressedStore,
) -> CompletenessVerdict {
    verify_selector_completeness_impl(input, Some(cas))
}

fn verify_selector_completeness_impl(
    input: &SelectorClosureInput,
    cas: Option<&dyn ContentAddressedStore>,
) -> CompletenessVerdict {
    let mut defects = Vec::new();

    if input.selector_digests.is_empty() {
        defects.push(SelectorClosureDefect {
            code: SelectorClosureDefectCode::EmptySelectorDigests,
            message: "selector digest set must not be empty".into(),
            selector_digest_hex: None,
        });
        return CompletenessVerdict::Incomplete { defects };
    }

    if input.selector_digests.len() > MAX_SELECTOR_DIGESTS {
        defects.push(SelectorClosureDefect {
            code: SelectorClosureDefectCode::TooManySelectorDigests,
            message: format!(
                "selector digest count {} exceeds maximum {}",
                input.selector_digests.len(),
                MAX_SELECTOR_DIGESTS
            ),
            selector_digest_hex: None,
        });
        return CompletenessVerdict::Incomplete { defects };
    }

    let requires_loss_profiles = is_high_risk(input.resolved_risk_tier);

    if requires_loss_profiles {
        for (path, digest) in &input.selector_digests {
            match input.loss_profiles.get(path) {
                None => {
                    defects.push(SelectorClosureDefect {
                        code: SelectorClosureDefectCode::MissingLossProfile,
                        message: format!(
                            "high-risk claim requires loss profile for selector '{path}'"
                        ),
                        selector_digest_hex: Some(hex::encode(digest)),
                    });
                },
                Some(lp) => {
                    let entry_count = usize::try_from(lp.entry_count).unwrap_or(usize::MAX);
                    if entry_count > MAX_LOSS_PROFILE_ENTRIES {
                        defects.push(SelectorClosureDefect {
                            code: SelectorClosureDefectCode::TooManyLossProfileEntries,
                            message: format!(
                                "loss profile for '{path}' has {} entries (max {})",
                                lp.entry_count, MAX_LOSS_PROFILE_ENTRIES
                            ),
                            selector_digest_hex: Some(hex::encode(digest)),
                        });
                    }

                    if let Some(cas) = cas {
                        match cas.exists(&lp.digest) {
                            Ok(true) => {},
                            Ok(false) | Err(CasError::NotFound { .. }) => {
                                defects.push(SelectorClosureDefect {
                                    code: SelectorClosureDefectCode::LossProfileDigestMismatch,
                                    message: format!(
                                        "loss profile digest for '{path}' does not match CAS content"
                                    ),
                                    selector_digest_hex: Some(hex::encode(digest)),
                                });
                            },
                            Err(err) => {
                                defects.push(SelectorClosureDefect {
                                    code: SelectorClosureDefectCode::LossProfileDigestMismatch,
                                    message: format!(
                                        "unable to verify loss profile digest for '{path}' in CAS: {err}"
                                    ),
                                    selector_digest_hex: Some(hex::encode(digest)),
                                });
                            },
                        }
                    }
                },
            }
        }
    }

    // Reverse-set validation: orphan loss-profile keys are invalid at all risk
    // tiers.
    for lp_path in input.loss_profiles.keys() {
        if !input.selector_digests.contains_key(lp_path) {
            defects.push(SelectorClosureDefect {
                code: SelectorClosureDefectCode::UnresolvedSelectorDigest,
                message: format!("loss profile for '{lp_path}' does not match any selector digest"),
                selector_digest_hex: None,
            });
        }
    }

    if defects.is_empty() {
        CompletenessVerdict::Complete {
            selector_count: input.selector_digests.len(),
            loss_profile_count: input.loss_profiles.len(),
        }
    } else {
        CompletenessVerdict::Incomplete { defects }
    }
}

/// Determines whether a risk tier requires loss-profile completeness.
#[must_use]
pub const fn is_high_risk(tier: RiskTier) -> bool {
    match HIGH_RISK_THRESHOLD {
        RiskTier::Tier1 => matches!(tier, RiskTier::Tier1 | RiskTier::Tier2Plus),
        RiskTier::Tier2Plus => matches!(tier, RiskTier::Tier2Plus),
        RiskTier::Tier0 => true,
    }
}

/// Deterministic replay zoom-in: resolves evidence by hash from CAS.
///
/// Fail-closed: missing or corrupt evidence returns an error.
///
/// # Errors
///
/// Returns [`SelectorClosureError::Cas`] if retrieval fails, or
/// [`SelectorClosureError::Defect`] if retrieved evidence exceeds size limits
/// or does not hash to the requested digest.
pub fn replay_zoom_in(
    cas: &dyn ContentAddressedStore,
    evidence_hash: &[u8; 32],
) -> Result<Vec<u8>, SelectorClosureError> {
    let evidence_hash_hex = hex::encode(evidence_hash);

    let size = match cas.size(evidence_hash) {
        Ok(size) => size,
        Err(CasError::NotFound { .. }) => {
            return Err(SelectorClosureError::Defect(SelectorClosureDefect {
                code: SelectorClosureDefectCode::ReplayEvidenceMissing,
                message: format!("replay evidence '{evidence_hash_hex}' not found in CAS"),
                selector_digest_hex: Some(evidence_hash_hex),
            }));
        },
        Err(err) => return Err(SelectorClosureError::Cas(err)),
    };

    if size > MAX_REPLAY_EVIDENCE_BYTES {
        return Err(SelectorClosureError::Defect(SelectorClosureDefect {
            code: SelectorClosureDefectCode::ReplayEvidenceTooLarge,
            message: format!(
                "replay evidence {size} bytes exceeds max {MAX_REPLAY_EVIDENCE_BYTES}"
            ),
            selector_digest_hex: Some(evidence_hash_hex),
        }));
    }

    let bytes = match cas.retrieve(evidence_hash) {
        Ok(bytes) => bytes,
        Err(CasError::NotFound { .. }) => {
            return Err(SelectorClosureError::Defect(SelectorClosureDefect {
                code: SelectorClosureDefectCode::ReplayEvidenceMissing,
                message: format!("replay evidence '{evidence_hash_hex}' not found in CAS"),
                selector_digest_hex: Some(evidence_hash_hex),
            }));
        },
        Err(err) => return Err(SelectorClosureError::Cas(err)),
    };

    // Re-check size after retrieval for TOCTOU defense across backends.
    if bytes.len() > MAX_REPLAY_EVIDENCE_BYTES {
        return Err(SelectorClosureError::Defect(SelectorClosureDefect {
            code: SelectorClosureDefectCode::ReplayEvidenceTooLarge,
            message: format!(
                "replay evidence {} bytes exceeds max {MAX_REPLAY_EVIDENCE_BYTES}",
                bytes.len()
            ),
            selector_digest_hex: Some(evidence_hash_hex),
        }));
    }

    // Verify hash binding: recompute and compare.
    let computed = blake3::hash(&bytes);
    if computed.as_bytes() != evidence_hash {
        return Err(SelectorClosureError::Defect(SelectorClosureDefect {
            code: SelectorClosureDefectCode::ReplayEvidenceHashMismatch,
            message: "replay evidence content hash does not match requested hash".into(),
            selector_digest_hex: Some(evidence_hash_hex),
        }));
    }

    Ok(bytes)
}

/// Batch replay zoom-in: resolves multiple evidence hashes deterministically.
///
/// Returns results in the same order as input hashes. Fail-closed on any
/// missing or corrupt entry.
///
/// # Errors
///
/// Returns the first error encountered from [`replay_zoom_in`].
pub fn replay_zoom_in_batch(
    cas: &dyn ContentAddressedStore,
    evidence_hashes: &[[u8; 32]],
) -> Result<Vec<Vec<u8>>, SelectorClosureError> {
    let mut results = Vec::with_capacity(evidence_hashes.len());
    for hash in evidence_hashes {
        results.push(replay_zoom_in(cas, hash)?);
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::evidence::{ContentAddressedStore, MemoryCas};

    fn make_input(
        tier: RiskTier,
        paths: &[&str],
        with_loss_profiles: bool,
    ) -> SelectorClosureInput {
        let mut selector_digests = BTreeMap::new();
        let mut loss_profiles = BTreeMap::new();
        for (i, path) in paths.iter().enumerate() {
            let mut digest = [0u8; 32];
            digest[0] = u8::try_from(i).expect("test index fits in u8");
            selector_digests.insert(path.to_string(), digest);
            if with_loss_profiles {
                loss_profiles.insert(
                    path.to_string(),
                    LossProfileDeclaration {
                        digest,
                        entry_count: 3,
                        risk_tier: tier,
                    },
                );
            }
        }
        SelectorClosureInput {
            selector_digests,
            loss_profiles,
            resolved_risk_tier: tier,
        }
    }

    #[test]
    fn complete_high_risk_with_loss_profiles() {
        let input = make_input(RiskTier::Tier2Plus, &["a.rs", "b.rs"], true);
        let verdict = verify_selector_completeness(&input);
        assert!(matches!(
            verdict,
            CompletenessVerdict::Complete {
                selector_count: 2,
                loss_profile_count: 2,
            }
        ));
    }

    #[test]
    fn incomplete_high_risk_missing_loss_profiles() {
        let input = make_input(RiskTier::Tier1, &["a.rs", "b.rs"], false);
        let verdict = verify_selector_completeness(&input);
        match verdict {
            CompletenessVerdict::Incomplete { defects } => {
                assert_eq!(defects.len(), 2);
                assert_eq!(
                    defects[0].code,
                    SelectorClosureDefectCode::MissingLossProfile
                );
                assert_eq!(
                    defects[1].code,
                    SelectorClosureDefectCode::MissingLossProfile
                );
            },
            CompletenessVerdict::Complete { .. } => panic!("expected Incomplete verdict"),
        }
    }

    #[test]
    fn tier0_does_not_require_loss_profiles() {
        let input = make_input(RiskTier::Tier0, &["a.rs"], false);
        let verdict = verify_selector_completeness(&input);
        assert!(matches!(
            verdict,
            CompletenessVerdict::Complete {
                selector_count: 1,
                loss_profile_count: 0,
            }
        ));
    }

    #[test]
    fn empty_selectors_fail_closed() {
        let input = SelectorClosureInput {
            selector_digests: BTreeMap::new(),
            loss_profiles: BTreeMap::new(),
            resolved_risk_tier: RiskTier::Tier0,
        };
        let verdict = verify_selector_completeness(&input);
        match verdict {
            CompletenessVerdict::Incomplete { defects } => {
                assert_eq!(defects.len(), 1);
                assert_eq!(
                    defects[0].code,
                    SelectorClosureDefectCode::EmptySelectorDigests
                );
            },
            CompletenessVerdict::Complete { .. } => {
                panic!("expected Incomplete for empty selectors")
            },
        }
    }

    #[test]
    fn replay_zoom_in_round_trip() {
        let cas = MemoryCas::new();
        let data = b"deterministic evidence payload";
        let result = cas.store(data).expect("store should succeed");
        let retrieved = replay_zoom_in(&cas, &result.hash).expect("zoom-in should succeed");
        assert_eq!(retrieved, data);
    }

    #[test]
    fn replay_zoom_in_missing_evidence_fails_closed() {
        let cas = MemoryCas::new();
        let missing = [0xAB; 32];
        let err = replay_zoom_in(&cas, &missing).expect_err("should fail for missing evidence");
        assert!(matches!(
            err,
            SelectorClosureError::Defect(SelectorClosureDefect {
                code: SelectorClosureDefectCode::ReplayEvidenceMissing,
                ..
            })
        ));
    }

    #[test]
    fn orphan_loss_profile_keys_emit_unresolved_defect() {
        let mut input = make_input(RiskTier::Tier0, &["a.rs"], false);
        input.loss_profiles.insert(
            "orphan.rs".into(),
            LossProfileDeclaration {
                digest: [0x11; 32],
                entry_count: 1,
                risk_tier: RiskTier::Tier0,
            },
        );

        let verdict = verify_selector_completeness(&input);
        match verdict {
            CompletenessVerdict::Incomplete { defects } => {
                assert_eq!(defects.len(), 1);
                assert_eq!(
                    defects[0].code,
                    SelectorClosureDefectCode::UnresolvedSelectorDigest
                );
            },
            CompletenessVerdict::Complete { .. } => panic!("expected orphan profile defect"),
        }
    }

    #[test]
    fn replay_zoom_in_oversized_evidence_fails_before_retrieve() {
        let cas = MemoryCas::new();
        let oversized = vec![0xEE; MAX_REPLAY_EVIDENCE_BYTES + 1];
        let stored = cas
            .store(&oversized)
            .expect("storing oversized replay artifact should succeed in CAS");

        let err =
            replay_zoom_in(&cas, &stored.hash).expect_err("oversized replay must fail closed");
        assert!(matches!(
            err,
            SelectorClosureError::Defect(SelectorClosureDefect {
                code: SelectorClosureDefectCode::ReplayEvidenceTooLarge,
                ..
            })
        ));
    }

    #[test]
    fn loss_profile_digest_mismatch_detected() {
        let cas = MemoryCas::new();
        let mut input = make_input(RiskTier::Tier2Plus, &["a.rs"], true);
        input
            .loss_profiles
            .get_mut("a.rs")
            .expect("path exists")
            .digest = [0xFE; 32];

        let verdict = verify_selector_completeness_with_cas(&input, &cas);
        match verdict {
            CompletenessVerdict::Incomplete { defects } => {
                assert_eq!(defects.len(), 1);
                assert_eq!(
                    defects[0].code,
                    SelectorClosureDefectCode::LossProfileDigestMismatch
                );
            },
            CompletenessVerdict::Complete { .. } => panic!("expected digest mismatch defect"),
        }
    }

    #[test]
    fn replay_zoom_in_batch_preserves_order() {
        let cas = MemoryCas::new();
        let data_a = b"evidence-a";
        let data_b = b"evidence-b";
        let hash_a = cas.store(data_a.as_slice()).expect("store a").hash;
        let hash_b = cas.store(data_b.as_slice()).expect("store b").hash;
        let results = replay_zoom_in_batch(&cas, &[hash_a, hash_b]).expect("batch should succeed");
        assert_eq!(results.len(), 2);
        assert_eq!(results[0], data_a);
        assert_eq!(results[1], data_b);
    }
}
