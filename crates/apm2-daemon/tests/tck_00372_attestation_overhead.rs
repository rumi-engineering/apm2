//! TCK-00372: Attestation overhead contract and fallback safety.
//!
//! This harness measures direct vs batched receipt verification envelopes,
//! evaluates the `<1%` overhead gate at directly measured `10^3`/`10^4`/`10^5`,
//! then uses a bootstrap statistical model for `10^6`/`10^8` and projects to
//! `10^12`, and validates automatic batched->direct fallback behavior.

use std::time::Instant;

use apm2_core::consensus::{
    AttestationOverheadGate, AttestationProjectionModel, AttestationScaleMeasurement,
    SCALE_EFFECTS_10E6, SCALE_EFFECTS_10E8, SCALE_EFFECTS_10E12,
};
use apm2_core::crypto::{HASH_SIZE, Signer};
use apm2_daemon::identity::{
    AlgorithmTag, AuthoritySealV1, BatchFallbackReason, BatchOverheadPolicy, BatchSealVerifier,
    CellGenesisV1, CellIdV1, DirectVerificationFallback, IssuerId, KeySetIdV1, LedgerAnchorV1,
    MerkleInclusionProof, MerkleProofSibling, PolicyRootId, PublicKeyIdV1, ReceiptMultiProofV1,
    ReceiptPointerError, ReceiptPointerV1, ReceiptPointerVerifier, SealKind, SetTag, SubjectKind,
    ZERO_TIME_ENVELOPE_REF, compute_receipt_leaf_hash,
};

const TEST_SUBJECT_KIND: &str = "apm2.tool_execution_receipt.v1";
const BATCH_SIZE: usize = 256;
const SCALE_EFFECTS_10E3: u64 = 1_000;
const SCALE_EFFECTS_10E4: u64 = 10_000;
const SCALE_EFFECTS_10E5: u64 = 100_000;
// Keep verification workload representative but bounded for CI runtime SLO.
const MAX_BATCH_SAMPLES_PER_SCALE: usize = 24;
const BOOTSTRAP_REPLICATES: usize = 128;
const P99_Z_SCORE: f64 = 2.326_347_874_040_840_8;

#[derive(Debug, Clone, Copy)]
struct BootstrapP99Envelope {
    point_p99: f64,
    ci95_lower: f64,
    ci95_upper: f64,
}

#[derive(Debug)]
struct ScaleRun {
    effects: u64,
    direct_total_elapsed_us_estimate: u64,
    batched_total_elapsed_us_estimate: u64,
    direct_batch_samples_us: Vec<u64>,
    batched_batch_samples_us: Vec<u64>,
    sampled_batches: usize,
    total_batches: usize,
}

struct ScaleMeasurementFixture<'a> {
    direct_material: &'a [(ReceiptPointerV1, AuthoritySealV1)],
    full_multiproof: &'a ReceiptMultiProofV1,
    batch_root: [u8; 32],
    batch_seal_hash: [u8; 32],
    proofs: &'a [MerkleInclusionProof],
    receipt_hashes: &'a [[u8; 32]],
    batch_seal: &'a AuthoritySealV1,
    signer: &'a Signer,
}

#[derive(Debug, Clone, Copy)]
struct DeterministicRng {
    state: u64,
}

impl DeterministicRng {
    const fn new(seed: u64) -> Self {
        Self {
            state: seed ^ 0x9E37_79B9_7F4A_7C15,
        }
    }

    const fn next_u64(&mut self) -> u64 {
        self.state = self
            .state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.state
    }

    fn sample_index(&mut self, len: usize) -> usize {
        let len_u64 = u64::try_from(len).unwrap_or(u64::MAX).max(1);
        let idx_u64 = self.next_u64() % len_u64;
        usize::try_from(idx_u64).unwrap_or(0)
    }
}

fn u64_to_f64(value: u64) -> f64 {
    f64::from(u32::try_from(value).unwrap_or(u32::MAX))
}

fn usize_to_f64(value: usize) -> f64 {
    f64::from(u32::try_from(value).unwrap_or(u32::MAX))
}

fn elapsed_us(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX)
}

const fn percentile_index(len: usize, numerator: usize, denominator: usize) -> usize {
    ((len * numerator).div_ceil(denominator)).saturating_sub(1)
}

fn bootstrap_p99_envelope(
    per_batch_samples_us: &[u64],
    batches_per_scale: usize,
    seed: u64,
) -> BootstrapP99Envelope {
    assert!(
        !per_batch_samples_us.is_empty(),
        "bootstrap requires non-empty sample set",
    );
    let resample_len = per_batch_samples_us.len();
    let resample_len_f64 = usize_to_f64(resample_len.max(1));
    let batches_f64 = usize_to_f64(batches_per_scale.max(1));
    let sqrt_batches = batches_f64.sqrt();
    let mut modeled_p99_totals_us = Vec::with_capacity(BOOTSTRAP_REPLICATES);
    let mut rng = DeterministicRng::new(seed);

    for _ in 0..BOOTSTRAP_REPLICATES {
        let mut sum = 0.0;
        let mut sum_sq = 0.0;
        for _ in 0..resample_len {
            let sample = u64_to_f64(per_batch_samples_us[rng.sample_index(resample_len)].max(1));
            sum += sample;
            sum_sq = sample.mul_add(sample, sum_sq);
        }
        let mean = sum / resample_len_f64;
        let variance = mean.mul_add(-mean, sum_sq / resample_len_f64).max(0.0);
        let std_dev = variance.sqrt();
        let modeled_p99 = batches_f64.mul_add(mean, P99_Z_SCORE * sqrt_batches * std_dev);
        modeled_p99_totals_us.push(modeled_p99.max(1.0));
    }

    modeled_p99_totals_us.sort_by(f64::total_cmp);
    let len = modeled_p99_totals_us.len();
    let p50_idx = percentile_index(len, 500, 1_000);
    let ci95_lower_idx = percentile_index(len, 25, 1_000);
    let ci95_upper_idx = percentile_index(len, 975, 1_000);

    BootstrapP99Envelope {
        point_p99: modeled_p99_totals_us[p50_idx],
        ci95_lower: modeled_p99_totals_us[ci95_lower_idx],
        ci95_upper: modeled_p99_totals_us[ci95_upper_idx],
    }
}

fn batch_count_for_effects(effects: u64) -> usize {
    let effects_usize = usize::try_from(effects).unwrap_or(usize::MAX);
    effects_usize.div_ceil(BATCH_SIZE).max(1)
}

fn verify_direct_slice(
    direct_material: &[(ReceiptPointerV1, AuthoritySealV1)],
    count: usize,
    verifying_key: &ed25519_dalek::VerifyingKey,
) {
    for (ptr, seal) in direct_material.iter().take(count) {
        ReceiptPointerVerifier::verify_direct(ptr, seal, verifying_key, TEST_SUBJECT_KIND, true)
            .expect("direct verification baseline");
    }
}

fn build_partial_multiproof(
    batch_root: [u8; 32],
    receipt_hashes: &[[u8; 32]],
    batch_seal_hash: [u8; 32],
    proofs: &[MerkleInclusionProof],
    count: usize,
) -> ReceiptMultiProofV1 {
    ReceiptMultiProofV1::new(
        batch_root,
        receipt_hashes[..count].to_vec(),
        batch_seal_hash,
        proofs[..count].to_vec(),
    )
    .expect("partial multiproof must remain structurally valid")
}

fn estimate_total_elapsed_us(batch_samples_us: &[u64], total_batches: usize) -> u64 {
    if batch_samples_us.is_empty() || total_batches == 0 {
        return 0;
    }
    let sample_sum: u128 = batch_samples_us.iter().copied().map(u128::from).sum();
    let sample_count = u128::try_from(batch_samples_us.len()).unwrap_or(1);
    let total_batches_u128 = u128::try_from(total_batches).unwrap_or(0);
    let rounded = sample_sum
        .saturating_mul(total_batches_u128)
        .saturating_add(sample_count / 2)
        / sample_count;
    u64::try_from(rounded).unwrap_or(u64::MAX)
}

fn sampled_batch_sizes(full_batches: usize, remainder: usize) -> Vec<usize> {
    let total_batches = full_batches + usize::from(remainder > 0);
    if total_batches == 0 {
        return Vec::new();
    }
    if total_batches <= MAX_BATCH_SAMPLES_PER_SCALE {
        let mut exact = vec![BATCH_SIZE; full_batches];
        if remainder > 0 {
            exact.push(remainder);
        }
        return exact;
    }

    let mut sampled = Vec::with_capacity(MAX_BATCH_SAMPLES_PER_SCALE);
    if full_batches > 0 {
        let reserve_for_remainder = usize::from(remainder > 0);
        let sampled_full = MAX_BATCH_SAMPLES_PER_SCALE
            .saturating_sub(reserve_for_remainder)
            .max(1)
            .min(full_batches);
        sampled.extend(std::iter::repeat_n(BATCH_SIZE, sampled_full));
    }
    if remainder > 0 && sampled.len() < MAX_BATCH_SAMPLES_PER_SCALE {
        sampled.push(remainder);
    }
    sampled
}

fn measure_scale_run(effects: u64, fixture: &ScaleMeasurementFixture<'_>) -> ScaleRun {
    let effects_usize = usize::try_from(effects).unwrap_or(usize::MAX);
    let full_batches = effects_usize / BATCH_SIZE;
    let remainder = effects_usize % BATCH_SIZE;
    let total_batches = full_batches + usize::from(remainder > 0);
    let batch_sizes = sampled_batch_sizes(full_batches, remainder);
    let batch_samples = batch_sizes.len();
    let verifying_key = fixture.signer.verifying_key();

    let mut direct_batch_samples_us = Vec::with_capacity(batch_samples);
    for count in &batch_sizes {
        let start = Instant::now();
        verify_direct_slice(fixture.direct_material, *count, &verifying_key);
        direct_batch_samples_us.push(elapsed_us(start));
    }

    let mut batched_batch_samples_us = Vec::with_capacity(batch_samples);
    for count in &batch_sizes {
        let start = Instant::now();
        if *count == BATCH_SIZE {
            ReceiptPointerVerifier::verify_multiproof(
                fixture.full_multiproof,
                fixture.batch_seal,
                BatchSealVerifier::SingleKey(&verifying_key),
                TEST_SUBJECT_KIND,
                true,
            )
            .expect("batched multiproof verification");
        } else {
            let partial = build_partial_multiproof(
                fixture.batch_root,
                fixture.receipt_hashes,
                fixture.batch_seal_hash,
                fixture.proofs,
                *count,
            );
            ReceiptPointerVerifier::verify_multiproof(
                &partial,
                fixture.batch_seal,
                BatchSealVerifier::SingleKey(&verifying_key),
                TEST_SUBJECT_KIND,
                true,
            )
            .expect("partial batched multiproof verification");
        }
        batched_batch_samples_us.push(elapsed_us(start));
    }

    ScaleRun {
        effects,
        direct_total_elapsed_us_estimate: estimate_total_elapsed_us(
            &direct_batch_samples_us,
            total_batches,
        ),
        batched_total_elapsed_us_estimate: estimate_total_elapsed_us(
            &batched_batch_samples_us,
            total_batches,
        ),
        direct_batch_samples_us,
        batched_batch_samples_us,
        sampled_batches: batch_samples,
        total_batches,
    }
}

fn conservative_scale_measurement(
    effects: u64,
    direct_envelope: BootstrapP99Envelope,
    batched_envelope: BootstrapP99Envelope,
    direct_bytes_per_effect: f64,
    batched_bytes_per_effect: f64,
) -> AttestationScaleMeasurement {
    let scale_f64 = u64_to_f64(effects);
    AttestationScaleMeasurement::new(
        effects,
        direct_envelope.ci95_lower.max(1.0),
        batched_envelope.ci95_upper.max(1.0),
        direct_bytes_per_effect * scale_f64,
        batched_bytes_per_effect * scale_f64,
    )
    .expect("scale measurement must be valid")
}

fn test_cell_id() -> CellIdV1 {
    let genesis_hash = [0xAA; HASH_SIZE];
    let policy_root_key = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xBB; 32]);
    let policy_root = PolicyRootId::Single(policy_root_key);
    let genesis = CellGenesisV1::new(genesis_hash, policy_root, "tck-00372.local").unwrap();
    CellIdV1::from_genesis(&genesis)
}

fn make_direct_seal_with_time_ref(
    signer: &Signer,
    receipt_hash: &[u8; 32],
    time_envelope_ref: [u8; 32],
) -> AuthoritySealV1 {
    let cell_id = test_cell_id();
    let pkid = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &signer.public_key_bytes());
    let subject_kind = SubjectKind::new(TEST_SUBJECT_KIND).unwrap();
    let ledger_anchor = LedgerAnchorV1::ConsensusIndex { index: 1 };

    let seal_unsigned = AuthoritySealV1::new(
        cell_id.clone(),
        IssuerId::PublicKey(pkid.clone()),
        subject_kind.clone(),
        *receipt_hash,
        ledger_anchor.clone(),
        time_envelope_ref,
        SealKind::SingleSig,
        vec![vec![0u8; 64]],
    )
    .unwrap();

    let signature = signer.sign(&seal_unsigned.domain_separated_preimage());
    AuthoritySealV1::new(
        cell_id,
        IssuerId::PublicKey(pkid),
        subject_kind,
        *receipt_hash,
        ledger_anchor,
        time_envelope_ref,
        SealKind::SingleSig,
        vec![signature.to_bytes().to_vec()],
    )
    .unwrap()
}

fn make_batch_seal_with_time_ref(
    signer: &Signer,
    batch_root: &[u8; 32],
    time_envelope_ref: [u8; 32],
) -> AuthoritySealV1 {
    let cell_id = test_cell_id();
    let pkid = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &signer.public_key_bytes());
    let subject_kind = SubjectKind::new(TEST_SUBJECT_KIND).unwrap();
    let ledger_anchor = LedgerAnchorV1::ConsensusIndex { index: 1 };

    let seal_unsigned = AuthoritySealV1::new(
        cell_id.clone(),
        IssuerId::PublicKey(pkid.clone()),
        subject_kind.clone(),
        *batch_root,
        ledger_anchor.clone(),
        time_envelope_ref,
        SealKind::MerkleBatch,
        vec![vec![0u8; 64]],
    )
    .unwrap();

    let signature = signer.sign(&seal_unsigned.domain_separated_preimage());
    AuthoritySealV1::new(
        cell_id,
        IssuerId::PublicKey(pkid),
        subject_kind,
        *batch_root,
        ledger_anchor,
        time_envelope_ref,
        SealKind::MerkleBatch,
        vec![signature.to_bytes().to_vec()],
    )
    .unwrap()
}

fn build_merkle_tree(receipt_hashes: &[[u8; 32]]) -> ([u8; 32], Vec<MerkleInclusionProof>) {
    let leaf_hashes: Vec<[u8; 32]> = receipt_hashes
        .iter()
        .map(compute_receipt_leaf_hash)
        .collect();
    let n = leaf_hashes.len().next_power_of_two();
    let mut layer = leaf_hashes.clone();
    layer.resize(n, [0u8; 32]);

    let mut layers: Vec<Vec<[u8; 32]>> = vec![layer.clone()];
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len() / 2);
        for chunk in layer.chunks(2) {
            let mut hasher = blake3::Hasher::new();
            hasher.update(&chunk[0]);
            hasher.update(&chunk[1]);
            next.push(*hasher.finalize().as_bytes());
        }
        layers.push(next.clone());
        layer = next;
    }

    let root = layer[0];
    let mut proofs = Vec::with_capacity(receipt_hashes.len());
    for (leaf_idx, leaf_hash) in leaf_hashes.iter().enumerate().take(receipt_hashes.len()) {
        let mut siblings = Vec::new();
        let mut idx = leaf_idx;
        for layer in &layers[..layers.len() - 1] {
            let sibling_idx = idx ^ 1;
            if sibling_idx < layer.len() {
                siblings.push(MerkleProofSibling {
                    hash: layer[sibling_idx],
                    is_left: sibling_idx < idx,
                });
            }
            idx /= 2;
        }
        proofs.push(MerkleInclusionProof {
            leaf_hash: *leaf_hash,
            siblings,
        });
    }

    (root, proofs)
}

fn make_receipt_hashes(seed: u8, count: usize) -> Vec<[u8; 32]> {
    let mut hashes: Vec<[u8; 32]> = (0..count)
        .map(|idx| {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&(idx as u64).to_le_bytes());
            let mut hasher = blake3::Hasher::new();
            hasher.update(&[seed]);
            hasher.update(&bytes);
            *hasher.finalize().as_bytes()
        })
        .collect();
    hashes.sort_unstable();
    hashes
}

#[test]
fn tck_00372_attestation_overhead_contract_scales_and_projection() {
    let signer = Signer::generate();
    let receipt_hashes = make_receipt_hashes(0x42, BATCH_SIZE);
    let (batch_root, batch_proofs) = build_merkle_tree(&receipt_hashes);

    let batch_seal = make_batch_seal_with_time_ref(&signer, &batch_root, [0xAA; 32]);
    let batch_seal_hash = *blake3::hash(&batch_seal.canonical_bytes()).as_bytes();
    let multiproof = ReceiptMultiProofV1::new(
        batch_root,
        receipt_hashes.clone(),
        batch_seal_hash,
        batch_proofs.clone(),
    )
    .unwrap();

    let mut direct_material = Vec::with_capacity(receipt_hashes.len());
    for receipt_hash in &receipt_hashes {
        let seal = make_direct_seal_with_time_ref(&signer, receipt_hash, [0xAA; 32]);
        let seal_hash = *blake3::hash(&seal.canonical_bytes()).as_bytes();
        let ptr = ReceiptPointerV1::new_direct(*receipt_hash, seal_hash).unwrap();
        direct_material.push((ptr, seal));
    }

    let direct_bytes_per_batch: f64 = direct_material
        .iter()
        .map(|(ptr, seal)| {
            usize_to_f64(
                ptr.canonical_bytes()
                    .len()
                    .saturating_add(seal.canonical_bytes().len()),
            )
        })
        .sum();
    let batched_bytes_per_batch = usize_to_f64(
        multiproof
            .canonical_bytes()
            .len()
            .saturating_add(batch_seal.canonical_bytes().len()),
    );
    let batch_size_f64 = usize_to_f64(BATCH_SIZE);
    let direct_bytes_per_effect = direct_bytes_per_batch / batch_size_f64;
    let batched_bytes_per_effect = batched_bytes_per_batch / batch_size_f64;

    let fixture = ScaleMeasurementFixture {
        direct_material: &direct_material,
        full_multiproof: &multiproof,
        batch_root,
        batch_seal_hash,
        proofs: &batch_proofs,
        receipt_hashes: &receipt_hashes,
        batch_seal: &batch_seal,
        signer: &signer,
    };

    let measured_runs = [
        measure_scale_run(SCALE_EFFECTS_10E3, &fixture),
        measure_scale_run(SCALE_EFFECTS_10E4, &fixture),
        measure_scale_run(SCALE_EFFECTS_10E5, &fixture),
    ];

    let gate = AttestationOverheadGate::default();

    let mut measured_scale_measurements = Vec::with_capacity(measured_runs.len());
    let mut pooled_direct_batch_samples_us = Vec::new();
    let mut pooled_batched_batch_samples_us = Vec::new();

    for run in &measured_runs {
        let batches = batch_count_for_effects(run.effects);
        let direct_envelope = bootstrap_p99_envelope(
            &run.direct_batch_samples_us,
            batches,
            0xD1CE_0000_0000_0000 ^ run.effects,
        );
        let batched_envelope = bootstrap_p99_envelope(
            &run.batched_batch_samples_us,
            batches,
            0xB47C_0000_0000_0000 ^ run.effects,
        );
        let measured = conservative_scale_measurement(
            run.effects,
            direct_envelope,
            batched_envelope,
            direct_bytes_per_effect,
            batched_bytes_per_effect,
        );
        gate.enforce(&measured)
            .expect("directly measured scale must satisfy <1% gate");
        measured_scale_measurements.push((run.effects, measured));

        pooled_direct_batch_samples_us.extend_from_slice(&run.direct_batch_samples_us);
        pooled_batched_batch_samples_us.extend_from_slice(&run.batched_batch_samples_us);

        println!(
            "TCK-00372 scale={} methodology=sampled_measurement sampled_batches={} total_batches={} direct_elapsed_us_estimate={} batched_elapsed_us_estimate={} direct_p99_model_us={:.3} direct_ci95=[{:.3},{:.3}] batched_p99_model_us={:.3} batched_ci95=[{:.3},{:.3}] cpu_overhead_ratio={:.6} network_overhead_ratio={:.6}",
            run.effects,
            run.sampled_batches,
            run.total_batches,
            run.direct_total_elapsed_us_estimate,
            run.batched_total_elapsed_us_estimate,
            direct_envelope.point_p99,
            direct_envelope.ci95_lower,
            direct_envelope.ci95_upper,
            batched_envelope.point_p99,
            batched_envelope.ci95_lower,
            batched_envelope.ci95_upper,
            measured.cpu_overhead_ratio(),
            measured.network_overhead_ratio(),
        );
    }

    let modeled_10e6_direct = bootstrap_p99_envelope(
        &pooled_direct_batch_samples_us,
        batch_count_for_effects(SCALE_EFFECTS_10E6),
        0xD1CE_10E6_0000_0001,
    );
    let modeled_10e6_batch = bootstrap_p99_envelope(
        &pooled_batched_batch_samples_us,
        batch_count_for_effects(SCALE_EFFECTS_10E6),
        0xB47C_10E6_0000_0001,
    );
    let modeled_10e6 = conservative_scale_measurement(
        SCALE_EFFECTS_10E6,
        modeled_10e6_direct,
        modeled_10e6_batch,
        direct_bytes_per_effect,
        batched_bytes_per_effect,
    );
    gate.enforce(&modeled_10e6)
        .expect("10^6 statistical model must satisfy <1% gate");

    let modeled_10e8_direct = bootstrap_p99_envelope(
        &pooled_direct_batch_samples_us,
        batch_count_for_effects(SCALE_EFFECTS_10E8),
        0xD1CE_10E8_0000_0001,
    );
    let modeled_10e8_batch = bootstrap_p99_envelope(
        &pooled_batched_batch_samples_us,
        batch_count_for_effects(SCALE_EFFECTS_10E8),
        0xB47C_10E8_0000_0001,
    );
    let modeled_10e8 = conservative_scale_measurement(
        SCALE_EFFECTS_10E8,
        modeled_10e8_direct,
        modeled_10e8_batch,
        direct_bytes_per_effect,
        batched_bytes_per_effect,
    );
    gate.enforce(&modeled_10e8)
        .expect("10^8 statistical model must satisfy <1% gate");

    println!(
        "TCK-00372 scale=1000000 methodology=statistical_model direct_p99_model_us={:.3} direct_ci95=[{:.3},{:.3}] batched_p99_model_us={:.3} batched_ci95=[{:.3},{:.3}] cpu_overhead_ratio={:.6} network_overhead_ratio={:.6}",
        modeled_10e6_direct.point_p99,
        modeled_10e6_direct.ci95_lower,
        modeled_10e6_direct.ci95_upper,
        modeled_10e6_batch.point_p99,
        modeled_10e6_batch.ci95_lower,
        modeled_10e6_batch.ci95_upper,
        modeled_10e6.cpu_overhead_ratio(),
        modeled_10e6.network_overhead_ratio(),
    );
    println!(
        "TCK-00372 scale=100000000 methodology=statistical_model direct_p99_model_us={:.3} direct_ci95=[{:.3},{:.3}] batched_p99_model_us={:.3} batched_ci95=[{:.3},{:.3}] cpu_overhead_ratio={:.6} network_overhead_ratio={:.6}",
        modeled_10e8_direct.point_p99,
        modeled_10e8_direct.ci95_lower,
        modeled_10e8_direct.ci95_upper,
        modeled_10e8_batch.point_p99,
        modeled_10e8_batch.ci95_lower,
        modeled_10e8_batch.ci95_upper,
        modeled_10e8.cpu_overhead_ratio(),
        modeled_10e8.network_overhead_ratio(),
    );

    let model = AttestationProjectionModel::new(modeled_10e6, modeled_10e8).unwrap();
    let projected_10e12 = model.project_10e12();
    assert_eq!(projected_10e12.effects, SCALE_EFFECTS_10E12);
    gate.enforce(&projected_10e12)
        .expect("10^12 projection must satisfy <1% gate");
    println!(
        "TCK-00372 scale=1000000000000 methodology=statistical_model_projection cpu_overhead_ratio={:.6} network_overhead_ratio={:.6}",
        projected_10e12.cpu_overhead_ratio(),
        projected_10e12.network_overhead_ratio()
    );

    for (_, measured) in &measured_scale_measurements {
        assert!(measured.cpu_overhead_ratio() <= 0.01);
        assert!(measured.network_overhead_ratio() <= 0.01);
    }
    assert!(modeled_10e6.cpu_overhead_ratio() <= 0.01);
    assert!(modeled_10e6.network_overhead_ratio() <= 0.01);
    assert!(modeled_10e8.cpu_overhead_ratio() <= 0.01);
    assert!(modeled_10e8.network_overhead_ratio() <= 0.01);
    assert!(projected_10e12.cpu_overhead_ratio() <= 0.01);
    assert!(projected_10e12.network_overhead_ratio() <= 0.01);
}

#[test]
fn tck_00372_integrity_failure_triggers_automatic_direct_fallback() {
    let signer = Signer::generate();
    let receipt_hashes = make_receipt_hashes(0x61, 2);
    let (batch_root, proofs) = build_merkle_tree(&receipt_hashes);

    let batch_seal = make_batch_seal_with_time_ref(&signer, &batch_root, [0xAA; 32]);
    let batch_seal_hash = *blake3::hash(&batch_seal.canonical_bytes()).as_bytes();
    let mut tampered = proofs[0].clone();
    tampered.siblings[0].hash = [0xFE; 32];
    let batch_ptr =
        ReceiptPointerV1::new_batch(receipt_hashes[0], batch_seal_hash, tampered).unwrap();

    let direct_seal = make_direct_seal_with_time_ref(&signer, &receipt_hashes[0], [0xAA; 32]);
    let direct_seal_hash = *blake3::hash(&direct_seal.canonical_bytes()).as_bytes();
    let direct_ptr = ReceiptPointerV1::new_direct(receipt_hashes[0], direct_seal_hash).unwrap();

    let result = ReceiptPointerVerifier::verify_batch_with_fallback(
        &batch_ptr,
        &batch_seal,
        BatchSealVerifier::SingleKey(&signer.verifying_key()),
        TEST_SUBJECT_KIND,
        true,
        Some(DirectVerificationFallback {
            pointer: &direct_ptr,
            seal: &direct_seal,
            verifying_key: &signer.verifying_key(),
        }),
        None,
    )
    .expect("integrity failure should fallback to direct");

    assert_eq!(result.receipt_hash, receipt_hashes[0]);
}

#[test]
fn tck_00372_freshness_and_degradation_fallback_are_fail_closed() {
    let signer = Signer::generate();
    let receipt_hashes = make_receipt_hashes(0x71, 2);
    let (batch_root, proofs) = build_merkle_tree(&receipt_hashes);

    // Freshness failure on batch path: zero temporal binding.
    let stale_batch_seal =
        make_batch_seal_with_time_ref(&signer, &batch_root, ZERO_TIME_ENVELOPE_REF);
    let stale_batch_hash = *blake3::hash(&stale_batch_seal.canonical_bytes()).as_bytes();
    let batch_ptr =
        ReceiptPointerV1::new_batch(receipt_hashes[0], stale_batch_hash, proofs[0].clone())
            .unwrap();

    let temporal_direct_seal =
        make_direct_seal_with_time_ref(&signer, &receipt_hashes[0], [0xAB; 32]);
    let temporal_direct_hash = *blake3::hash(&temporal_direct_seal.canonical_bytes()).as_bytes();
    let direct_ptr = ReceiptPointerV1::new_direct(receipt_hashes[0], temporal_direct_hash).unwrap();

    let fresh_result = ReceiptPointerVerifier::verify_batch_with_fallback(
        &batch_ptr,
        &stale_batch_seal,
        BatchSealVerifier::SingleKey(&signer.verifying_key()),
        TEST_SUBJECT_KIND,
        true,
        Some(DirectVerificationFallback {
            pointer: &direct_ptr,
            seal: &temporal_direct_seal,
            verifying_key: &signer.verifying_key(),
        }),
        None,
    )
    .expect("freshness failure must fallback to direct");
    assert_eq!(fresh_result.receipt_hash, receipt_hashes[0]);

    // Degradation failure with no fallback must fail closed.
    let valid_batch_seal = make_batch_seal_with_time_ref(&signer, &batch_root, [0xAA; 32]);
    let valid_batch_hash = *blake3::hash(&valid_batch_seal.canonical_bytes()).as_bytes();
    let valid_batch_ptr =
        ReceiptPointerV1::new_batch(receipt_hashes[0], valid_batch_hash, proofs[0].clone())
            .unwrap();
    let degraded_policy = BatchOverheadPolicy::new(0.001, 0.001, 0.01, 0.01);

    let err = ReceiptPointerVerifier::verify_batch_with_fallback(
        &valid_batch_ptr,
        &valid_batch_seal,
        BatchSealVerifier::SingleKey(&signer.verifying_key()),
        TEST_SUBJECT_KIND,
        false,
        None,
        Some(degraded_policy),
    )
    .expect_err("degradation without direct fallback must deny");

    assert!(matches!(
        err,
        ReceiptPointerError::FallbackUnavailable {
            reason: BatchFallbackReason::Degradation,
            ..
        }
    ));
}

#[test]
fn tck_00372_quorum_batch_fallback_still_fail_closed_when_direct_material_mismatched() {
    let signer_a = Signer::generate();
    let signer_b = Signer::generate();
    let signer_c = Signer::generate();

    let receipt_hashes = make_receipt_hashes(0x81, 2);
    let (batch_root, proofs) = build_merkle_tree(&receipt_hashes);

    let member_a =
        PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &signer_a.public_key_bytes());
    let member_b =
        PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &signer_b.public_key_bytes());
    let member_c =
        PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &signer_c.public_key_bytes());
    let keyset_id = KeySetIdV1::from_descriptor(
        "ed25519",
        SetTag::Threshold,
        2,
        &[member_a, member_b, member_c],
        None,
    )
    .unwrap();

    let subject_kind = SubjectKind::new(TEST_SUBJECT_KIND).unwrap();
    let ledger_anchor = LedgerAnchorV1::ConsensusIndex { index: 7 };
    let cell_id = test_cell_id();
    let seal_unsigned = AuthoritySealV1::new(
        cell_id.clone(),
        IssuerId::Quorum(keyset_id.clone()),
        subject_kind.clone(),
        batch_root,
        ledger_anchor.clone(),
        [0xAA; 32],
        SealKind::MerkleBatch,
        vec![vec![0u8; 64], vec![0u8; 64]],
    )
    .unwrap();
    let preimage = seal_unsigned.domain_separated_preimage();
    let sig_a = signer_a.sign(&preimage).to_bytes().to_vec();
    let sig_b = signer_b.sign(&preimage).to_bytes().to_vec();
    let quorum_batch_seal = AuthoritySealV1::new(
        cell_id,
        IssuerId::Quorum(keyset_id),
        subject_kind,
        batch_root,
        ledger_anchor,
        [0xAA; 32],
        SealKind::MerkleBatch,
        vec![sig_a, sig_b],
    )
    .unwrap();

    let seal_hash = *blake3::hash(&quorum_batch_seal.canonical_bytes()).as_bytes();
    let mut tampered = proofs[0].clone();
    tampered.siblings[0].hash = [0xDD; 32];
    let batch_ptr = ReceiptPointerV1::new_batch(receipt_hashes[0], seal_hash, tampered).unwrap();

    let wrong_direct_seal =
        make_direct_seal_with_time_ref(&signer_a, &receipt_hashes[1], [0xAA; 32]);
    let wrong_direct_hash = *blake3::hash(&wrong_direct_seal.canonical_bytes()).as_bytes();
    let wrong_direct_ptr =
        ReceiptPointerV1::new_direct(receipt_hashes[1], wrong_direct_hash).unwrap();
    let quorum_keys = vec![
        signer_a.verifying_key(),
        signer_b.verifying_key(),
        signer_c.verifying_key(),
    ];

    let err = ReceiptPointerVerifier::verify_batch_with_fallback(
        &batch_ptr,
        &quorum_batch_seal,
        BatchSealVerifier::QuorumThreshold {
            verifying_keys: &quorum_keys,
            threshold: 2,
            weights: None,
        },
        TEST_SUBJECT_KIND,
        true,
        Some(DirectVerificationFallback {
            pointer: &wrong_direct_ptr,
            seal: &wrong_direct_seal,
            verifying_key: &signer_a.verifying_key(),
        }),
        None,
    )
    .expect_err("mismatched direct fallback material must fail closed");

    assert!(matches!(
        err,
        ReceiptPointerError::FallbackVerificationFailed {
            reason: BatchFallbackReason::IntegrityFailure,
            ..
        }
    ));
}
