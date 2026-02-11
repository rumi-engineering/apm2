#[cfg(test)]
mod tests {
    use crate::pcac::AuthorityJoinInputV1;

    #[test]
    fn test_legacy_v1_deserialization_success() {
        let zero_hash = vec![0u8; 32];
        
        // Corrected JSON payload matching AuthorityJoinInputV1 fields (minus new ones)
        let legacy_json = serde_json::json!({
            "session_id": "session-123",
            "holon_id": null,
            // "intent_id" -> intent_digest
            "intent_digest": zero_hash,
            "boundary_intent_class": "observe", // Optional with default, but good to include
            "capability_manifest_hash": zero_hash,
            // "scope_witness_hash" -> scope_witness_hashes
            "scope_witness_hashes": [],
            "lease_id": "lease-123",
            // "permeability_receipt_hash": null, // Optional
            "identity_proof_hash": zero_hash,
            "identity_evidence_level": "verified",
            // "pointer_only_waiver_hash": null, // Optional
            "directory_head_hash": zero_hash,
            "freshness_policy_hash": zero_hash,
            "freshness_witness_tick": 100,
            "stop_budget_profile_digest": zero_hash,
            "pre_actuation_receipt_hashes": [],
            // MISSING: leakage_witness_hash, timing_witness_hash
            "risk_tier": "tier1",
            "determinism_class": "deterministic",
            "time_envelope_ref": zero_hash,
            "as_of_ledger_anchor": zero_hash
        });

        let result = serde_json::from_value::<AuthorityJoinInputV1>(legacy_json);
        
        if let Err(e) = &result {
            println!("Deserialization error: {}", e);
        }
        assert!(result.is_ok(), "Legacy V1 payload should deserialize successfully with defaults");
    }
}
