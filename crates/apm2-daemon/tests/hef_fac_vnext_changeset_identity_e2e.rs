#![allow(missing_docs)]

use std::sync::{Arc, Mutex};

use apm2_core::crypto::Signer;
use apm2_daemon::gate::{
    GateOrchestrator, GateOrchestratorConfig, GateStartKernel, GateStartKernelConfig, GateType,
};
use apm2_daemon::ledger::SqliteLedgerEventEmitter;
use apm2_daemon::protocol::dispatch::LedgerEventEmitter;
use rusqlite::Connection;
use tempfile::TempDir;

fn make_emitter(conn: Arc<Mutex<Connection>>, key_seed: u8) -> SqliteLedgerEventEmitter {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[key_seed; 32]);
    SqliteLedgerEventEmitter::new(conn, signing_key)
}

#[tokio::test]
async fn hef_fac_vnext_changeset_identity_e2e() {
    let sqlite = Arc::new(Mutex::new(
        Connection::open_in_memory().expect("open in-memory sqlite"),
    ));
    {
        let guard = sqlite.lock().expect("lock sqlite for schema init");
        SqliteLedgerEventEmitter::init_schema_for_test(&guard).expect("initialize ledger schema");
    }
    let publish_emitter = make_emitter(Arc::clone(&sqlite), 0x11);
    let kernel_emitter = make_emitter(Arc::clone(&sqlite), 0x12);

    let gate_orchestrator = Arc::new(GateOrchestrator::new(
        GateOrchestratorConfig::default(),
        Arc::new(Signer::generate()),
    ));
    let fac_root = TempDir::new().expect("create temp fac root");
    let mut gate_start_kernel = GateStartKernel::new(
        Arc::clone(&gate_orchestrator),
        Some(&sqlite),
        Some(kernel_emitter),
        fac_root.path(),
        GateStartKernelConfig::default(),
    )
    .expect("create gate start kernel");

    let work_id = "W-hef-fac-vnext-csid-e2e";
    let published_digest = [0x44; 32];
    let bundle_cas_hash = [0x55; 32];
    let published_event = publish_emitter
        .emit_changeset_published(
            work_id,
            &published_digest,
            &bundle_cas_hash,
            "actor:publish",
            1_706_000_000_123_000_000,
        )
        .expect("emit changeset_published");
    assert_eq!(published_event.event_type, "changeset_published");

    let report = gate_start_kernel
        .tick()
        .await
        .expect("gate start kernel tick succeeds");
    assert_eq!(
        report.completed_intents, 1,
        "one changeset publication should complete"
    );

    for gate_type in GateType::all() {
        let lease = gate_orchestrator
            .gate_lease(work_id, gate_type)
            .await
            .expect("gate lease should exist after gate start");
        assert_eq!(
            lease.changeset_digest, published_digest,
            "gate lease digest must match ChangeSetPublished digest"
        );
    }

    let guard = sqlite.lock().expect("lock sqlite for assertions");
    let changeset_count: i64 = guard
        .query_row(
            "SELECT COUNT(*) FROM ledger_events WHERE event_type = 'changeset_published'",
            [],
            |row| row.get(0),
        )
        .expect("count changeset_published events");
    assert_eq!(changeset_count, 1, "expected one changeset_published event");

    let lease_count: i64 = guard
        .query_row(
            "SELECT COUNT(*) FROM ledger_events WHERE event_type = 'gate_lease_issued'",
            [],
            |row| row.get(0),
        )
        .expect("count gate_lease_issued events");
    assert_eq!(
        lease_count,
        i64::try_from(GateType::all().len()).expect("gate type length fits i64"),
        "expected one gate_lease_issued per gate type"
    );

    let mut hasher = blake3::Hasher::new();
    hasher.update(b"S-regression-sentinel");
    hasher.update(work_id.as_bytes());
    let synthetic_digest: [u8; 32] = *hasher.finalize().as_bytes();

    let mut stmt = guard
        .prepare("SELECT payload FROM ledger_events ORDER BY timestamp_ns ASC, event_id ASC")
        .expect("prepare payload query");
    let rows = stmt
        .query_map([], |row| row.get::<_, Vec<u8>>(0))
        .expect("query payload rows");

    let mut observed_digests = Vec::new();
    for row in rows {
        let payload = row.expect("decode payload row");
        if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&payload) {
            collect_changeset_digests(&json, &mut observed_digests);
        }
    }

    assert!(
        !observed_digests.is_empty(),
        "expected to observe changeset digests in persisted event stream"
    );
    for digest in observed_digests {
        assert_ne!(
            digest, synthetic_digest,
            "event stream must not contain synthetic BLAKE3(session_id || work_id) digest"
        );
    }
}

fn collect_changeset_digests(value: &serde_json::Value, out: &mut Vec<[u8; 32]>) {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(candidate) = map.get("changeset_digest") {
                if let Some(digest) = decode_digest_value(candidate) {
                    out.push(digest);
                }
            }
            for nested in map.values() {
                collect_changeset_digests(nested, out);
            }
        },
        serde_json::Value::Array(items) => {
            for nested in items {
                collect_changeset_digests(nested, out);
            }
        },
        _ => {},
    }
}

fn decode_digest_value(value: &serde_json::Value) -> Option<[u8; 32]> {
    match value {
        serde_json::Value::String(hex_value) => {
            let raw = hex::decode(hex_value).ok()?;
            if raw.len() != 32 {
                return None;
            }
            let mut digest = [0u8; 32];
            digest.copy_from_slice(&raw);
            Some(digest)
        },
        serde_json::Value::Array(values) => {
            if values.len() != 32 {
                return None;
            }
            let mut digest = [0u8; 32];
            for (idx, item) in values.iter().enumerate() {
                let n = item.as_u64()?;
                digest[idx] = u8::try_from(n).ok()?;
            }
            Some(digest)
        },
        _ => None,
    }
}
