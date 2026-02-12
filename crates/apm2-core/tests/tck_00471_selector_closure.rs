//! TCK-00471: RFC-0029 REQ-0002 integration tests for selector closure
//! completeness and deterministic replay zoom-in.

use std::collections::{BTreeMap, BTreeSet};

use apm2_core::context::selector_closure::{
    CompletenessVerdict, LossProfileDeclaration, MAX_REPLAY_EVIDENCE_BYTES, SelectorClosureDefect,
    SelectorClosureDefectCode, SelectorClosureError, SelectorClosureInput, replay_zoom_in,
    replay_zoom_in_batch, verify_selector_completeness,
};
use apm2_core::context::{
    ContextPackRecipeCompiler, ContextPackSelectorInput, RecipeCompilerReasonCode,
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

// ---------------------------------------------------------------------------
// Compile-path integration: selector closure wired into admission
// ---------------------------------------------------------------------------

fn setup_compile_workspace() -> tempfile::TempDir {
    let workspace = tempfile::tempdir().expect("tempdir should be created");
    std::fs::create_dir_all(workspace.path().join("src")).expect("src dir should be created");
    std::fs::write(workspace.path().join("src/lib.rs"), b"pub fn main() {}\n")
        .expect("src/lib.rs should be created");
    std::fs::write(workspace.path().join("README.md"), b"# test\n")
        .expect("README.md should be created");
    workspace
}

fn selector_for_compile(
    paths: &[&str],
    risk_tier: RiskTier,
    loss_profiles: BTreeMap<String, LossProfileDeclaration>,
) -> ContextPackSelectorInput {
    let mut required_read_paths = BTreeSet::new();
    let mut required_read_digests = BTreeMap::new();
    for path in paths {
        let owned = (*path).to_string();
        required_read_paths.insert(owned.clone());
        required_read_digests.insert(owned.clone(), *blake3::hash(owned.as_bytes()).as_bytes());
    }
    ContextPackSelectorInput {
        role_spec_hash: [0x11; 32],
        required_read_paths,
        required_read_digests,
        context_manifest_hash: [0x22; 32],
        budget_profile_hash: [0x33; 32],
        loss_profiles,
        resolved_risk_tier: risk_tier,
    }
}

#[test]
fn compile_tier1_missing_loss_profiles_denied() {
    let workspace = setup_compile_workspace();
    let compiler =
        ContextPackRecipeCompiler::new(workspace.path()).expect("compiler should initialize");

    // Tier1 with no loss profiles must be denied.
    let selector = selector_for_compile(&["README.md"], RiskTier::Tier1, BTreeMap::new());

    let error = compiler
        .compile(&selector)
        .expect_err("Tier1 with missing loss profiles must fail selector closure");
    assert_eq!(
        error.reason_code(),
        RecipeCompilerReasonCode::SelectorClosureIncomplete
    );
}

#[test]
fn compile_tier0_no_loss_profiles_succeeds() {
    let workspace = setup_compile_workspace();
    let compiler =
        ContextPackRecipeCompiler::new(workspace.path()).expect("compiler should initialize");

    // Tier0 without loss profiles should succeed (backward compat).
    let selector = selector_for_compile(&["README.md"], RiskTier::Tier0, BTreeMap::new());

    let result = compiler.compile(&selector);
    assert!(
        result.is_ok(),
        "Tier0 compilation without loss profiles must succeed for backward compatibility"
    );
}

#[test]
fn compile_tier1_with_complete_loss_profiles_succeeds() {
    let workspace = setup_compile_workspace();
    let compiler =
        ContextPackRecipeCompiler::new(workspace.path()).expect("compiler should initialize");

    let path = "README.md";
    let digest = *blake3::hash(path.as_bytes()).as_bytes();
    let mut loss_profiles = BTreeMap::new();
    loss_profiles.insert(
        path.to_string(),
        LossProfileDeclaration {
            digest,
            entry_count: 3,
            risk_tier: RiskTier::Tier1,
        },
    );

    let selector = selector_for_compile(&[path], RiskTier::Tier1, loss_profiles);

    let result = compiler.compile(&selector);
    assert!(
        result.is_ok(),
        "Tier1 compilation with complete loss profiles must succeed"
    );
}

#[test]
fn compile_tier2plus_partial_loss_profiles_denied() {
    let workspace = setup_compile_workspace();
    std::fs::write(workspace.path().join("extra.txt"), b"extra\n")
        .expect("extra.txt should be created");
    let compiler =
        ContextPackRecipeCompiler::new(workspace.path()).expect("compiler should initialize");

    let path_a = "README.md";
    let digest_a = *blake3::hash(path_a.as_bytes()).as_bytes();
    let mut loss_profiles = BTreeMap::new();
    // Only provide loss profile for one of two paths.
    loss_profiles.insert(
        path_a.to_string(),
        LossProfileDeclaration {
            digest: digest_a,
            entry_count: 2,
            risk_tier: RiskTier::Tier2Plus,
        },
    );

    let selector = selector_for_compile(&[path_a, "extra.txt"], RiskTier::Tier2Plus, loss_profiles);

    let error = compiler
        .compile(&selector)
        .expect_err("Tier2Plus with partial loss profiles must fail");
    assert_eq!(
        error.reason_code(),
        RecipeCompilerReasonCode::SelectorClosureIncomplete
    );
}

#[test]
fn loss_profile_cas_retrieve_and_verify_integrity() {
    // When CAS contains the loss profile content,
    // verify_selector_completeness_with_cas retrieves and validates hash
    // integrity (not just existence).
    use apm2_core::context::selector_closure::verify_selector_completeness_with_cas;

    let cas = MemoryCas::new();

    let content = b"loss-profile-content-for-verification";
    let stored = cas.store(content.as_slice()).expect("CAS store");

    let mut selector_digests = BTreeMap::new();
    let path = "verified.rs".to_string();
    selector_digests.insert(path.clone(), stored.hash);

    let mut loss_profiles = BTreeMap::new();
    loss_profiles.insert(
        path,
        LossProfileDeclaration {
            digest: stored.hash,
            entry_count: 1,
            risk_tier: RiskTier::Tier1,
        },
    );

    let input = SelectorClosureInput {
        selector_digests,
        loss_profiles,
        resolved_risk_tier: RiskTier::Tier1,
    };

    let verdict = verify_selector_completeness_with_cas(&input, &cas);
    assert!(
        matches!(verdict, CompletenessVerdict::Complete { .. }),
        "valid loss profile in CAS must yield Complete verdict"
    );
}

#[test]
fn loss_profile_cas_missing_content_detected() {
    use apm2_core::context::selector_closure::verify_selector_completeness_with_cas;

    let cas = MemoryCas::new();

    let mut selector_digests = BTreeMap::new();
    let path = "missing.rs".to_string();
    let fake_digest = [0xBB; 32];
    selector_digests.insert(path.clone(), fake_digest);

    let mut loss_profiles = BTreeMap::new();
    loss_profiles.insert(
        path,
        LossProfileDeclaration {
            digest: fake_digest,
            entry_count: 1,
            risk_tier: RiskTier::Tier1,
        },
    );

    let input = SelectorClosureInput {
        selector_digests,
        loss_profiles,
        resolved_risk_tier: RiskTier::Tier1,
    };

    let verdict = verify_selector_completeness_with_cas(&input, &cas);
    match verdict {
        CompletenessVerdict::Incomplete { defects } => {
            assert_eq!(defects.len(), 1);
            assert_eq!(
                defects[0].code,
                SelectorClosureDefectCode::LossProfileDigestMismatch
            );
            assert!(
                defects[0].message.contains("not found in CAS"),
                "message should indicate CAS absence: {}",
                defects[0].message
            );
        },
        CompletenessVerdict::Complete { .. } => {
            panic!("missing CAS content must yield Incomplete verdict")
        },
    }
}
