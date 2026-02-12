//! TCK-00471: RFC-0029 REQ-0002 integration tests for selector closure
//! completeness and deterministic replay zoom-in.

use std::collections::BTreeMap;

use apm2_core::context::selector_closure::{
    CompletenessVerdict, LossProfileDeclaration, MAX_REPLAY_EVIDENCE_BYTES, SelectorClosureDefect,
    SelectorClosureDefectCode, SelectorClosureError, SelectorClosureInput, replay_zoom_in,
    replay_zoom_in_batch, verify_selector_completeness,
};
use apm2_core::evidence::{ContentAddressedStore, MemoryCas};
use apm2_core::pcac::RiskTier;

fn make_selector_input(
    tier: RiskTier,
    selector_count: usize,
    with_loss_profiles: bool,
) -> SelectorClosureInput {
    let mut selector_digests = BTreeMap::new();
    let mut loss_profiles = BTreeMap::new();
    for i in 0..selector_count {
        let path = format!("selector_{i}.rs");
        let mut digest = [0u8; 32];
        let bytes = i.to_le_bytes();
        digest[0] = bytes[0];
        digest[1] = bytes[1];
        selector_digests.insert(path.clone(), digest);
        if with_loss_profiles {
            loss_profiles.insert(
                path,
                LossProfileDeclaration {
                    digest,
                    entry_count: 5,
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
fn high_risk_complete_selectors_admit() {
    let input = make_selector_input(RiskTier::Tier2Plus, 5, true);
    let verdict = verify_selector_completeness(&input);
    match verdict {
        CompletenessVerdict::Complete {
            selector_count,
            loss_profile_count,
        } => {
            assert_eq!(selector_count, 5);
            assert_eq!(loss_profile_count, 5);
        },
        CompletenessVerdict::Incomplete { .. } => panic!("expected Complete verdict"),
    }
}

#[test]
fn high_risk_incomplete_selectors_deny() {
    let input = make_selector_input(RiskTier::Tier1, 3, false);
    let verdict = verify_selector_completeness(&input);
    match verdict {
        CompletenessVerdict::Incomplete { defects } => {
            assert_eq!(defects.len(), 3);
            for defect in &defects {
                assert_eq!(defect.code, SelectorClosureDefectCode::MissingLossProfile);
                assert!(defect.selector_digest_hex.is_some());
            }
        },
        CompletenessVerdict::Complete { .. } => panic!("expected Incomplete verdict"),
    }
}

#[test]
fn tier0_admits_without_loss_profiles() {
    let input = make_selector_input(RiskTier::Tier0, 2, false);
    let verdict = verify_selector_completeness(&input);
    assert!(matches!(
        verdict,
        CompletenessVerdict::Complete {
            selector_count: 2,
            loss_profile_count: 0,
        }
    ));
}

#[test]
fn empty_selector_set_denied() {
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
        CompletenessVerdict::Complete { .. } => panic!("expected Incomplete verdict"),
    }
}

#[test]
fn replay_zoom_in_deterministic_round_trip() {
    let cas = MemoryCas::new();
    let evidence = b"deterministic-evidence-payload-for-tck-00471";
    let stored = cas.store(evidence.as_slice()).expect("CAS store");

    let resolved_1 = replay_zoom_in(&cas, &stored.hash).expect("first zoom-in");
    let resolved_2 = replay_zoom_in(&cas, &stored.hash).expect("second zoom-in");

    assert_eq!(resolved_1, evidence);
    assert_eq!(resolved_2, evidence);
    assert_eq!(
        resolved_1, resolved_2,
        "replay zoom-in must be deterministic"
    );
}

#[test]
fn replay_zoom_in_missing_hash_fails_closed() {
    let cas = MemoryCas::new();
    let missing_hash = [0xFF; 32];
    let result = replay_zoom_in(&cas, &missing_hash);
    let err = result.expect_err("missing evidence must fail closed");
    assert!(matches!(
        err,
        SelectorClosureError::Defect(SelectorClosureDefect {
            code: SelectorClosureDefectCode::ReplayEvidenceMissing,
            ..
        })
    ));
}

#[test]
fn replay_zoom_in_batch_order_preserved() {
    let cas = MemoryCas::new();
    let payloads: Vec<Vec<u8>> = (0..4)
        .map(|i| format!("evidence-payload-{i}").into_bytes())
        .collect();

    let hashes: Vec<[u8; 32]> = payloads
        .iter()
        .map(|p| cas.store(p).expect("store").hash)
        .collect();

    let results = replay_zoom_in_batch(&cas, &hashes).expect("batch zoom-in");
    assert_eq!(results.len(), 4);
    for (i, result) in results.iter().enumerate() {
        assert_eq!(
            result, &payloads[i],
            "batch result {i} must match input order"
        );
    }
}

#[test]
fn partial_loss_profiles_still_deny_missing_entries() {
    let mut input = make_selector_input(RiskTier::Tier2Plus, 3, true);
    // Remove one loss profile to make it incomplete.
    let first_key = input
        .loss_profiles
        .keys()
        .next()
        .expect("at least one key")
        .clone();
    input.loss_profiles.remove(&first_key);

    let verdict = verify_selector_completeness(&input);
    match verdict {
        CompletenessVerdict::Incomplete { defects } => {
            assert_eq!(defects.len(), 1);
            assert_eq!(
                defects[0].code,
                SelectorClosureDefectCode::MissingLossProfile
            );
        },
        CompletenessVerdict::Complete { .. } => panic!("expected Incomplete verdict"),
    }
}

#[test]
fn orphan_loss_profile_detected_in_integration() {
    let mut input = make_selector_input(RiskTier::Tier0, 1, false);
    input.loss_profiles.insert(
        "orphan_selector.rs".into(),
        LossProfileDeclaration {
            digest: [0xAA; 32],
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
        CompletenessVerdict::Complete { .. } => panic!("expected unresolved selector defect"),
    }
}

#[test]
fn oversized_replay_evidence_rejected() {
    let cas = MemoryCas::new();
    let oversized = vec![0xCC; MAX_REPLAY_EVIDENCE_BYTES + 1];
    let stored = cas
        .store(&oversized)
        .expect("CAS store for oversized replay evidence");

    let err = replay_zoom_in(&cas, &stored.hash).expect_err("oversized replay should fail closed");
    assert!(matches!(
        err,
        SelectorClosureError::Defect(SelectorClosureDefect {
            code: SelectorClosureDefectCode::ReplayEvidenceTooLarge,
            ..
        })
    ));
}
