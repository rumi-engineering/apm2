//! TCK-00403: End-to-end FAC lifecycle integration test.
//!
//! This test exercises the full lifecycle through real operator/session
//! protocol frames against an in-process daemon accept loop:
//! claim -> spawn -> tool -> event -> evidence -> ledger/CAS verify
//! -> terminate -> shutdown.

use std::collections::BTreeSet;
use std::fmt::{Display, Formatter};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use apm2_core::Supervisor;
use apm2_core::config::{AdapterRotationConfig, EcosystemConfig};
use apm2_core::schema_registry::InMemorySchemaRegistry;
use apm2_daemon::cas::{DurableCas, DurableCasConfig};
use apm2_daemon::episode::InMemorySessionRegistry;
use apm2_daemon::episode::tool_handler::{ReadArgs, ToolArgs};
use apm2_daemon::ledger::{SqliteLedgerEventEmitter, SqliteWorkRegistry};
use apm2_daemon::protocol::connection_handler::{HandshakeConfig, perform_handshake};
use apm2_daemon::protocol::dispatch::{
    ConnectionContext, encode_claim_work_request, encode_end_session_request,
    encode_shutdown_request, encode_spawn_episode_request,
};
use apm2_daemon::protocol::messages::{
    BoundedDecode, ClaimWorkRequest, ClaimWorkResponse, DecodeConfig, EmitEventRequest,
    EmitEventResponse, EndSessionRequest, EndSessionResponse, PrivilegedError, PrivilegedErrorCode,
    PublishEvidenceRequest, PublishEvidenceResponse, RequestToolRequest, RequestToolResponse,
    SessionError, SessionErrorCode, SessionStatusRequest, SessionStatusResponse, ShutdownRequest,
    ShutdownResponse, SpawnEpisodeRequest, SpawnEpisodeResponse, TerminationOutcome, WorkRole,
};
use apm2_daemon::protocol::session_dispatch::{
    encode_emit_event_request, encode_publish_evidence_request, encode_request_tool_request,
    encode_session_status_request,
};
use apm2_daemon::protocol::socket_manager::{SocketManager, SocketManagerConfig, SocketType};
use apm2_daemon::protocol::{
    ClientHandshake, FrameCodec, HandshakeMessage, PrivilegedMessageType, SessionMessageType,
    serialize_handshake_message,
};
use apm2_daemon::session::SessionRegistry;
use apm2_daemon::state::{DaemonStateHandle, DispatcherState, SharedState};
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use rusqlite::{Connection, params};
use tempfile::TempDir;
use tokio::net::UnixStream;
use tokio::time::{sleep, timeout};
use tokio_util::codec::Framed;

const TEST_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
struct DaemonError {
    code: String,
    message: String,
}

impl DaemonError {
    fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

impl Display for DaemonError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

fn make_sqlite_conn(ledger_dir: &Path) -> Arc<Mutex<Connection>> {
    let db_path = ledger_dir.join("fac_lifecycle.db");
    let conn = Connection::open(&db_path).expect("open SQLite database");
    SqliteLedgerEventEmitter::init_schema(&conn).expect("initialize ledger schema");
    SqliteWorkRegistry::init_schema(&conn).expect("initialize work schema");
    Arc::new(Mutex::new(conn))
}

fn create_shared_state() -> SharedState {
    let supervisor = Supervisor::new();
    let config = EcosystemConfig::default();
    let schema_registry = InMemorySchemaRegistry::new();
    Arc::new(DaemonStateHandle::new(
        config,
        supervisor,
        schema_registry,
        None,
    ))
}

fn create_dispatcher_state(
    shared_state: &SharedState,
    sqlite_conn: Arc<Mutex<Connection>>,
    cas_path: &Path,
) -> Arc<DispatcherState> {
    let session_registry: Arc<dyn SessionRegistry> = Arc::new(InMemorySessionRegistry::new());
    let dispatcher = DispatcherState::with_persistence_and_cas_and_key(
        session_registry,
        None,
        sqlite_conn,
        cas_path,
        None,
        AdapterRotationConfig::default(),
    )
    .expect("create persistent dispatcher state")
    .with_daemon_state(Arc::clone(shared_state));
    Arc::new(dispatcher)
}

fn write_stub_cli_command(command_path: &Path) {
    let script = "#!/usr/bin/env bash\nset -euo pipefail\nexec sleep 600\n";
    fs::write(command_path, script).expect("write stub adapter command");
    let mut perms = fs::metadata(command_path)
        .expect("stat stub adapter command")
        .permissions();
    perms.set_mode(0o755);
    fs::set_permissions(command_path, perms).expect("chmod stub adapter command");
}

fn store_stub_adapter_profile(cas_path: &Path, command_path: &Path) -> [u8; 32] {
    let mut profile = apm2_core::fac::claude_code_profile();
    profile.profile_id = "tck-00403-claude-stub".to_string();
    profile.command = command_path.display().to_string();

    let cas = DurableCas::new(DurableCasConfig::new(cas_path.to_path_buf()))
        .expect("create CAS handle for profile seeding");
    profile
        .store_in_cas(&cas)
        .expect("store custom adapter profile in CAS")
}

fn cas_object_path(cas_root: &Path, hash: &[u8; 32]) -> PathBuf {
    let hex_hash = hex::encode(hash);
    let (prefix, suffix) = hex_hash.split_at(4);
    cas_root.join("objects").join(prefix).join(suffix)
}

fn ledger_event_types_for_work(
    sqlite_conn: &Arc<Mutex<Connection>>,
    work_id: &str,
) -> BTreeSet<String> {
    let conn = sqlite_conn
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut stmt = conn
        .prepare("SELECT event_type FROM ledger_events WHERE work_id = ?1")
        .expect("prepare ledger query");
    let rows = stmt
        .query_map(params![work_id], |row| row.get::<_, String>(0))
        .expect("query ledger events");

    rows.map(|row| row.expect("read event row")).collect()
}

fn decode_privileged_response<T: BoundedDecode>(
    frame: &Bytes,
    expected: PrivilegedMessageType,
) -> Result<T, DaemonError> {
    if frame.is_empty() {
        return Err(DaemonError::new(
            "decode",
            "empty privileged response frame",
        ));
    }

    let tag = frame[0];
    let payload = &frame[1..];

    if tag == 0 {
        let err = PrivilegedError::decode_bounded(payload, &DecodeConfig::default())
            .map_err(|e| DaemonError::new("decode", format!("decode privileged error: {e}")))?;
        let code = PrivilegedErrorCode::try_from(err.code)
            .map_or_else(|_| err.code.to_string(), |code| format!("{code:?}"));
        return Err(DaemonError::new(code, err.message));
    }

    if tag != expected.tag() {
        return Err(DaemonError::new(
            "unexpected_response",
            format!("expected privileged tag {}, got {tag}", expected.tag()),
        ));
    }

    T::decode_bounded(payload, &DecodeConfig::default())
        .map_err(|e| DaemonError::new("decode", format!("decode privileged payload: {e}")))
}

fn decode_session_response<T: BoundedDecode>(
    frame: &Bytes,
    expected: SessionMessageType,
) -> Result<T, DaemonError> {
    if frame.is_empty() {
        return Err(DaemonError::new("decode", "empty session response frame"));
    }

    let tag = frame[0];
    let payload = &frame[1..];

    if tag == 0 {
        let err = SessionError::decode_bounded(payload, &DecodeConfig::default())
            .map_err(|e| DaemonError::new("decode", format!("decode session error: {e}")))?;
        let code = SessionErrorCode::try_from(err.code)
            .map_or_else(|_| err.code.to_string(), |code| format!("{code:?}"));
        return Err(DaemonError::new(code, err.message));
    }

    if tag != expected.tag() {
        return Err(DaemonError::new(
            "unexpected_response",
            format!("expected session tag {}, got {tag}", expected.tag()),
        ));
    }

    T::decode_bounded(payload, &DecodeConfig::default())
        .map_err(|e| DaemonError::new("decode", format!("decode session payload: {e}")))
}

async fn client_handshake(framed: &mut Framed<UnixStream, FrameCodec>) {
    let mut hs = ClientHandshake::new("tck-00403-client/1.0");
    let hello = hs.create_hello();
    let hello_msg: HandshakeMessage = hello.into();
    let hello_bytes = serialize_handshake_message(&hello_msg).expect("serialize hello");

    framed.send(hello_bytes).await.expect("send hello frame");
    let ack_frame = framed
        .next()
        .await
        .expect("hello ack frame expected")
        .expect("read hello ack frame");
    let response =
        apm2_daemon::protocol::parse_handshake_message(&ack_frame).expect("parse hello ack frame");
    hs.process_response(response)
        .expect("process hello ack response");
}

async fn connect_framed(socket_path: &Path) -> Framed<UnixStream, FrameCodec> {
    let stream = timeout(TEST_TIMEOUT, UnixStream::connect(socket_path))
        .await
        .expect("connection timeout")
        .expect("connect to socket");
    let mut framed = Framed::new(stream, FrameCodec::new());
    client_handshake(&mut framed).await;
    framed
}

struct WireOperatorClient {
    framed: Framed<UnixStream, FrameCodec>,
}

impl WireOperatorClient {
    async fn connect(socket_path: &Path) -> Self {
        Self {
            framed: connect_framed(socket_path).await,
        }
    }

    async fn send_and_receive(&mut self, frame: Bytes) -> Result<Bytes, DaemonError> {
        timeout(TEST_TIMEOUT, self.framed.send(frame))
            .await
            .map_err(|_| DaemonError::new("timeout", "operator send timed out"))?
            .map_err(|e| DaemonError::new("io", format!("operator send failed: {e}")))?;

        let response = timeout(TEST_TIMEOUT, self.framed.next())
            .await
            .map_err(|_| DaemonError::new("timeout", "operator response timed out"))?
            .ok_or_else(|| {
                DaemonError::new(
                    "connection_closed",
                    "operator connection closed unexpectedly",
                )
            })?
            .map_err(|e| DaemonError::new("io", format!("operator receive failed: {e}")))?;

        Ok(Bytes::copy_from_slice(response.as_ref()))
    }

    async fn claim_work(
        &mut self,
        actor_id: &str,
        role: WorkRole,
        credential_signature: &[u8],
        nonce: &[u8],
    ) -> Result<ClaimWorkResponse, DaemonError> {
        let request = ClaimWorkRequest {
            actor_id: actor_id.to_string(),
            role: role.into(),
            credential_signature: credential_signature.to_vec(),
            nonce: nonce.to_vec(),
        };
        let response = self
            .send_and_receive(encode_claim_work_request(&request))
            .await?;
        decode_privileged_response(&response, PrivilegedMessageType::ClaimWork)
    }

    async fn spawn_episode(
        &mut self,
        work_id: &str,
        role: WorkRole,
        lease_id: Option<&str>,
        workspace_root: &str,
        adapter_profile_hash: Option<&[u8; 32]>,
    ) -> Result<SpawnEpisodeResponse, DaemonError> {
        let request = SpawnEpisodeRequest {
            work_id: work_id.to_string(),
            role: role.into(),
            lease_id: lease_id.map(ToString::to_string),
            workspace_root: workspace_root.to_string(),
            adapter_profile_hash: adapter_profile_hash.map(|hash| hash.to_vec()),
            max_episodes: None,
            escalation_predicate: None,
            permeability_receipt_hash: None,
        };
        let response = self
            .send_and_receive(encode_spawn_episode_request(&request))
            .await?;
        decode_privileged_response(&response, PrivilegedMessageType::SpawnEpisode)
    }

    async fn end_session(
        &mut self,
        session_id: &str,
        reason: &str,
    ) -> Result<EndSessionResponse, DaemonError> {
        let request = EndSessionRequest {
            session_id: session_id.to_string(),
            reason: reason.to_string(),
            outcome: TerminationOutcome::Success as i32,
        };
        let response = self
            .send_and_receive(encode_end_session_request(&request))
            .await?;
        decode_privileged_response(&response, PrivilegedMessageType::EndSession)
    }

    async fn shutdown(&mut self, reason: Option<&str>) -> Result<ShutdownResponse, DaemonError> {
        let request = ShutdownRequest {
            reason: reason.map(ToString::to_string),
        };
        let response = self
            .send_and_receive(encode_shutdown_request(&request))
            .await?;
        decode_privileged_response(&response, PrivilegedMessageType::Shutdown)
    }
}

struct WireSessionClient {
    framed: Framed<UnixStream, FrameCodec>,
}

impl WireSessionClient {
    async fn connect(socket_path: &Path) -> Self {
        Self {
            framed: connect_framed(socket_path).await,
        }
    }

    async fn send_and_receive(&mut self, frame: Bytes) -> Result<Bytes, DaemonError> {
        timeout(TEST_TIMEOUT, self.framed.send(frame))
            .await
            .map_err(|_| DaemonError::new("timeout", "session send timed out"))?
            .map_err(|e| DaemonError::new("io", format!("session send failed: {e}")))?;

        let response = timeout(TEST_TIMEOUT, self.framed.next())
            .await
            .map_err(|_| DaemonError::new("timeout", "session response timed out"))?
            .ok_or_else(|| {
                DaemonError::new(
                    "connection_closed",
                    "session connection closed unexpectedly",
                )
            })?
            .map_err(|e| DaemonError::new("io", format!("session receive failed: {e}")))?;

        Ok(Bytes::copy_from_slice(response.as_ref()))
    }

    async fn request_tool(
        &mut self,
        session_token: &str,
        tool_id: &str,
        arguments: &[u8],
        dedupe_key: &str,
    ) -> Result<RequestToolResponse, DaemonError> {
        let request = RequestToolRequest {
            session_token: session_token.to_string(),
            tool_id: tool_id.to_string(),
            arguments: arguments.to_vec(),
            dedupe_key: dedupe_key.to_string(),
            epoch_seal: None,
        };
        let response = self
            .send_and_receive(encode_request_tool_request(&request))
            .await?;
        decode_session_response(&response, SessionMessageType::RequestTool)
    }

    async fn emit_event(
        &mut self,
        session_token: &str,
        event_type: &str,
        payload: &[u8],
        correlation_id: &str,
    ) -> Result<EmitEventResponse, DaemonError> {
        let request = EmitEventRequest {
            session_token: session_token.to_string(),
            event_type: event_type.to_string(),
            payload: payload.to_vec(),
            correlation_id: correlation_id.to_string(),
        };
        let response = self
            .send_and_receive(encode_emit_event_request(&request))
            .await?;
        decode_session_response(&response, SessionMessageType::EmitEvent)
    }

    async fn publish_evidence(
        &mut self,
        session_token: &str,
        artifact: &[u8],
        kind: i32,
        retention_hint: i32,
    ) -> Result<PublishEvidenceResponse, DaemonError> {
        let request = PublishEvidenceRequest {
            session_token: session_token.to_string(),
            artifact: artifact.to_vec(),
            kind,
            retention_hint,
        };
        let response = self
            .send_and_receive(encode_publish_evidence_request(&request))
            .await?;
        decode_session_response(&response, SessionMessageType::PublishEvidence)
    }

    async fn session_status_with_termination(
        &mut self,
        session_token: &str,
    ) -> Result<SessionStatusResponse, DaemonError> {
        let request = SessionStatusRequest {
            session_token: session_token.to_string(),
        };
        let response = self
            .send_and_receive(encode_session_status_request(&request))
            .await?;
        decode_session_response(&response, SessionMessageType::SessionStatus)
    }
}

fn spawn_server_loop(
    manager: Arc<SocketManager>,
    shared_state: SharedState,
    dispatcher_state: Arc<DispatcherState>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            if shared_state.is_shutdown_requested() {
                break;
            }

            let accept_result = timeout(Duration::from_millis(100), manager.accept()).await;
            if let Ok(Ok((mut connection, _permit, socket_type))) = accept_result {
                let conn_state = Arc::clone(&shared_state);
                let conn_dispatcher = Arc::clone(&dispatcher_state);

                tokio::spawn(async move {
                    let hs_cfg = HandshakeConfig::default()
                        .with_risk_tier(apm2_daemon::hsi_contract::RiskTier::Tier1);
                    if perform_handshake(&mut connection, &hs_cfg).await.is_err() {
                        return;
                    }

                    let ctx = match socket_type {
                        SocketType::Operator => ConnectionContext::privileged_session_open(
                            connection.peer_credentials().cloned(),
                        ),
                        SocketType::Session => ConnectionContext::session_open(
                            connection.peer_credentials().cloned(),
                            None,
                        ),
                    };

                    let privileged_dispatcher = conn_dispatcher.privileged_dispatcher();
                    let session_dispatcher = conn_dispatcher.session_dispatcher();

                    while let Some(Ok(frame)) = connection.framed().next().await {
                        if conn_state.is_shutdown_requested() {
                            break;
                        }

                        let frame_bytes = Bytes::copy_from_slice(frame.as_ref());
                        let response = match socket_type {
                            SocketType::Operator => privileged_dispatcher
                                .dispatch(&frame_bytes, &ctx)
                                .map(|r| r.encode()),
                            SocketType::Session => session_dispatcher
                                .dispatch(&frame_bytes, &ctx)
                                .map(|r| r.encode()),
                        };

                        match response {
                            Ok(bytes) => {
                                if connection.framed().send(bytes).await.is_err() {
                                    break;
                                }
                            },
                            Err(_) => break,
                        }
                    }
                });
            }
        }
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tck_00403_fac_lifecycle_end_to_end() {
    let temp = TempDir::new().expect("create temp dir");
    let cas_dir = temp.path().join("cas");
    let ledger_dir = temp.path().join("ledger");
    let workspace_dir = temp.path().join("workspace");
    let operator_socket = temp.path().join("operator.sock");
    let session_socket = temp.path().join("session.sock");
    fs::create_dir_all(&ledger_dir).expect("create ledger temp dir");
    fs::create_dir_all(&workspace_dir).expect("create workspace temp dir");

    let workspace_file = workspace_dir.join("read_me.txt");
    fs::write(&workspace_file, b"tck-00403 workspace payload").expect("write workspace file");

    let stub_cli_path = temp.path().join("stub_claude.sh");
    write_stub_cli_command(&stub_cli_path);
    let custom_adapter_profile_hash = store_stub_adapter_profile(&cas_dir, &stub_cli_path);

    let sqlite_conn = make_sqlite_conn(&ledger_dir);
    let shared_state = create_shared_state();
    let dispatcher_state =
        create_dispatcher_state(&shared_state, Arc::clone(&sqlite_conn), &cas_dir);

    let manager = Arc::new(
        SocketManager::bind(SocketManagerConfig::new(&operator_socket, &session_socket))
            .expect("bind socket manager"),
    );
    let server_handle = spawn_server_loop(
        Arc::clone(&manager),
        Arc::clone(&shared_state),
        Arc::clone(&dispatcher_state),
    );
    sleep(Duration::from_millis(75)).await;

    let mut operator_client = WireOperatorClient::connect(&operator_socket).await;

    let claim = operator_client
        .claim_work(
            "tck-00403-actor",
            WorkRole::Implementer,
            &[0xA1, 0xB2, 0xC3],
            &[0x10, 0x20, 0x30],
        )
        .await
        .expect("claim work");
    assert!(!claim.work_id.is_empty(), "ClaimWork must return work_id");
    assert!(!claim.lease_id.is_empty(), "ClaimWork must return lease_id");

    let workspace_root = workspace_dir.to_string_lossy().to_string();
    let spawn = operator_client
        .spawn_episode(
            &claim.work_id,
            WorkRole::Implementer,
            Some(&claim.lease_id),
            &workspace_root,
            Some(&custom_adapter_profile_hash),
        )
        .await
        .expect("spawn episode");
    assert!(
        !spawn.session_id.is_empty(),
        "SpawnEpisode must return session_id"
    );
    assert!(
        !spawn.session_token.is_empty(),
        "SpawnEpisode must return session_token"
    );

    let mut session_client = WireSessionClient::connect(&session_socket).await;

    let read_args = ToolArgs::Read(ReadArgs {
        path: workspace_file.clone(),
        offset: None,
        limit: None,
    });
    let read_args_bytes = serde_json::to_vec(&read_args).expect("serialize read args");

    let tool_error = session_client
        .request_tool(
            &spawn.session_token,
            "read",
            &read_args_bytes,
            "tck-00403-read-1",
        )
        .await
        .expect_err("minimal harness should fail RequestTool at V1 scope enforcement");
    assert_eq!(
        tool_error.code, "SessionErrorToolNotAllowed",
        "RequestTool must fail with tool-not-allowed when denied by scope enforcement"
    );
    let scope_or_taint_denial = tool_error.message.contains("V1 scope enforcement denied")
        || tool_error.message.contains("taint ingress denied")
        || tool_error.message.contains("taint flow denied");
    assert!(
        scope_or_taint_denial,
        "RequestTool error must be from scope or taint fail-closed enforcement, got: {}",
        tool_error.message
    );
    let message_lower = tool_error.message.to_ascii_lowercase();
    assert!(
        !message_lower.contains("not initialized"),
        "RequestTool denial must not be NotInitialized, got: {}",
        tool_error.message
    );
    assert!(
        !message_lower.contains("policydeny") && !message_lower.contains("policy deny"),
        "RequestTool denial must come from scope enforcement, not broker policy deny: {}",
        tool_error.message
    );

    let emit_response = session_client
        .emit_event(
            &spawn.session_token,
            "test.completed",
            br#"{"ticket":"TCK-00403"}"#,
            "tck-00403-correlation",
        )
        .await
        .expect("emit event");
    assert!(
        !emit_response.event_id.is_empty(),
        "EmitEvent must return event_id"
    );
    assert!(emit_response.seq > 0, "EmitEvent seq must be positive");

    let publish_response = session_client
        .publish_evidence(&spawn.session_token, b"tck-00403-evidence", 0, 0)
        .await
        .expect("publish evidence");
    assert!(
        !publish_response.artifact_hash.is_empty(),
        "PublishEvidence must return artifact_hash"
    );
    let artifact_hash: [u8; 32] = publish_response
        .artifact_hash
        .as_slice()
        .try_into()
        .expect("artifact hash must be 32 bytes");
    let cas_file = cas_object_path(&cas_dir, &artifact_hash);
    assert!(
        cas_file.exists(),
        "CAS object file must exist on disk: {}",
        cas_file.display()
    );

    let event_types = ledger_event_types_for_work(&sqlite_conn, &claim.work_id);
    assert!(
        event_types.contains("work_claimed"),
        "ledger must contain work_claimed for work_id={}",
        claim.work_id
    );
    assert!(
        event_types.contains("session_started"),
        "ledger must contain session_started for work_id={}",
        claim.work_id
    );

    let end_response = operator_client
        .end_session(&spawn.session_id, "integration_test_episode_stop")
        .await
        .expect("end session");
    assert_eq!(end_response.session_id, spawn.session_id);
    session_client
        .session_status_with_termination(&spawn.session_token)
        .await
        .expect("query session status after EndSession");

    let shutdown_response = operator_client
        .shutdown(Some("tck-00403 test complete"))
        .await
        .expect("shutdown daemon");
    assert!(
        shutdown_response.message.contains("Shutdown initiated"),
        "Shutdown response should acknowledge shutdown initiation"
    );
    assert!(
        shared_state.is_shutdown_requested(),
        "shutdown flag must be set after Shutdown request"
    );

    timeout(TEST_TIMEOUT, server_handle)
        .await
        .expect("server loop did not exit after shutdown")
        .expect("server loop task join failed");

    drop(session_client);
    drop(operator_client);

    manager.cleanup().expect("socket cleanup");
    assert!(
        !operator_socket.exists(),
        "operator socket should be removed"
    );
    assert!(!session_socket.exists(), "session socket should be removed");
}
