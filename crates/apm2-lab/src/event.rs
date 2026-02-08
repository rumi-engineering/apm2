use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use apm2_core::crypto::{
    EventHasher, Hash, Signer, parse_signature, parse_verifying_key, verify_signature,
};
use serde::{Deserialize, Serialize};

use crate::verdict::Verdict;

/// Canonical identifier for a lab agent/holon.
pub type HolonId = String;

/// Work classes used in the lab.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WorkType {
    Analyze,
    Synthesize,
    Compound,
}

impl fmt::Display for WorkType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Analyze => write!(f, "analyze"),
            Self::Synthesize => write!(f, "synthesize"),
            Self::Compound => write!(f, "compound"),
        }
    }
}

/// Authoritative and non-authoritative events for the lab ledger.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EventKind {
    WorkOpened {
        work_id: String,
        work_type: WorkType,
        value: f64,
        description: String,
    },
    WorkClaimed {
        work_id: String,
        agent_id: HolonId,
    },
    WorkSubmitted {
        work_id: String,
        agent_id: HolonId,
        solution: String,
        cost_tokens: u64,
    },
    VerifyAttestation {
        work_id: String,
        verifier_id: HolonId,
        verdict: Verdict,
        reasoning: String,
    },
    FormationIntent {
        composite_id: HolonId,
        members: Vec<HolonId>,
        rationale: String,
    },
    FormationAttestation {
        composite_id: HolonId,
        attester_id: HolonId,
        approve: bool,
        rationale: String,
    },
    WorkAdmitted {
        work_id: String,
        receipt_hash: Hash,
    },
    WorkRejected {
        work_id: String,
        reason: String,
        receipt_hash: Hash,
    },
    CompositeAdmitted {
        composite_id: HolonId,
        members: Vec<HolonId>,
        receipt_hash: Hash,
        gain_delta: f64,
    },
    SubTaskDelegated {
        composite_id: HolonId,
        work_id: String,
        delegate_to: HolonId,
        sub_task: String,
    },
    AuditChallenge {
        work_id: String,
        challenge_id: String,
        prompt: String,
    },
    AuditResult {
        work_id: String,
        challenge_id: String,
        pass: bool,
        notes: String,
    },
}

#[derive(Debug, Clone, Serialize)]
struct EventForHash<'a> {
    seq: u64,
    author_id: &'a str,
    timestamp_ms: u64,
    prev_hash: Hash,
    event: &'a EventKind,
}

/// Signed event stored in the append-only lab ledger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedEvent {
    pub seq: u64,
    pub author_id: String,
    pub author_public_key: [u8; 32],
    pub timestamp_ms: u64,
    pub prev_hash: Hash,
    pub event_hash: Hash,
    pub signature: Vec<u8>,
    pub event: EventKind,
}

impl SignedEvent {
    #[must_use]
    pub fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    pub fn new(
        seq: u64,
        author_id: impl Into<String>,
        signer: &Signer,
        prev_hash: Hash,
        event: EventKind,
        timestamp_ms: u64,
    ) -> Result<Self> {
        let author_id = author_id.into();
        let canonical = EventForHash {
            seq,
            author_id: &author_id,
            timestamp_ms,
            prev_hash,
            event: &event,
        };
        let canonical_bytes = serde_json::to_vec(&canonical).context("serialize event for hash")?;
        let event_hash = EventHasher::hash_event(&canonical_bytes, &prev_hash);
        let signature = signer.sign(&event_hash).to_bytes().to_vec();

        Ok(Self {
            seq,
            author_id,
            author_public_key: signer.public_key_bytes(),
            timestamp_ms,
            prev_hash,
            event_hash,
            signature,
            event,
        })
    }

    pub fn verify(&self) -> Result<()> {
        let canonical = EventForHash {
            seq: self.seq,
            author_id: &self.author_id,
            timestamp_ms: self.timestamp_ms,
            prev_hash: self.prev_hash,
            event: &self.event,
        };
        let canonical_bytes =
            serde_json::to_vec(&canonical).context("serialize event for verify")?;
        let expected = EventHasher::hash_event(&canonical_bytes, &self.prev_hash);
        if expected != self.event_hash {
            return Err(anyhow!(
                "event hash mismatch at seq {} (expected {}, got {})",
                self.seq,
                hash_hex(&expected),
                hash_hex(&self.event_hash)
            ));
        }

        let sig = parse_signature(&self.signature).context("parse signature")?;
        let vk = parse_verifying_key(&self.author_public_key).context("parse public key")?;
        verify_signature(&vk, &self.event_hash, &sig).context("signature verification")
    }

    pub fn receipt_hash(event: &EventKind) -> Result<Hash> {
        let bytes = serde_json::to_vec(event).context("serialize event for receipt hash")?;
        Ok(EventHasher::hash_content(&bytes))
    }
}

#[must_use]
pub fn hash_hex(hash: &Hash) -> String {
    hash.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

#[cfg(test)]
mod tests {
    use apm2_core::crypto::Signer;

    use super::{EventKind, SignedEvent, WorkType};

    #[test]
    fn signing_round_trip() {
        let signer = Signer::generate();
        let event = SignedEvent::new(
            1,
            "alpha",
            &signer,
            [0u8; 32],
            EventKind::WorkOpened {
                work_id: "w-001".to_string(),
                work_type: WorkType::Analyze,
                value: 1.0,
                description: "decompose topic".to_string(),
            },
            123,
        )
        .expect("event signed");

        event.verify().expect("event verified");
    }

    #[test]
    fn tampered_event_fails_verification() {
        let signer = Signer::generate();
        let mut event = SignedEvent::new(
            1,
            "alpha",
            &signer,
            [0u8; 32],
            EventKind::WorkOpened {
                work_id: "w-001".to_string(),
                work_type: WorkType::Analyze,
                value: 1.0,
                description: "decompose topic".to_string(),
            },
            123,
        )
        .expect("event signed");

        event.author_id = "tampered".to_string();
        assert!(event.verify().is_err());
    }
}
