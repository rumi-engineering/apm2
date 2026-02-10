//! Consensus layer for distributed coordination.
//!
//! This module implements peer discovery, mutual TLS networking, and relay
//! tunneling for the APM2 distributed consensus layer. It provides:
//!
//! - **Network Transport**: TLS 1.3 mutual authentication with connection
//!   pooling
//! - **Peer Discovery**: Bootstrap node connection and peer list management
//! - **Traffic Analysis Mitigation**: Fixed-size control plane frame padding
//! - **Relay Holon**: Message routing to workers behind NAT
//! - **Reverse-TLS Tunnels**: Persistent outbound connections for NAT traversal
//!
//! # Security Properties
//!
//! - All connections use TLS 1.3 with mutual authentication (INV-0015)
//! - Certificates are validated against a network CA (INV-0016)
//! - Control plane frames are padded to fixed size (INV-0017)
//! - Connection pooling prevents traffic analysis (INV-0019)
//! - Tunnel registration requires valid mTLS identity (INV-0021)
//! - Tunnel heartbeats prevent zombie connections (INV-0022)
//! - Relay validates worker identity matches certificate CN (INV-0023)
//! - Anti-entropy sync uses pull-based model (INV-0024)
//! - Sync requests are rate-limited per peer (INV-0025)
//!
//! # Example
//!
//! ```rust,ignore
//! use apm2_core::consensus::{NetworkConfig, PeerDiscovery, TlsConfig};
//!
//! // Configure TLS with network CA
//! let tls_config = TlsConfig::builder()
//!     .ca_cert_pem(ca_cert)
//!     .node_cert_pem(node_cert)
//!     .node_key_pem(node_key)
//!     .build()?;
//!
//! // Create network with bootstrap nodes
//! let config = NetworkConfig::builder()
//!     .tls(tls_config)
//!     .bootstrap_nodes(vec!["node1.example.com:8443".parse()?])
//!     .build()?;
//!
//! let network = Network::new(config).await?;
//! network.connect_to_bootstrap().await?;
//! ```
//!
//! # Relay and Tunnel Example
//!
//! ```rust,ignore
//! use apm2_core::consensus::{ManagedTunnel, RelayConfig, RelayHolon, TlsConfig};
//!
//! // Worker: Create tunnel to relay
//! let tunnel = ManagedTunnel::new(
//!     "tunnel-123".to_string(),
//!     "worker-456".to_string(),
//!     tls_config.clone(),
//! );
//! tunnel.connect(relay_addr, "relay.example.com").await?;
//!
//! // Relay: Accept and route messages
//! let relay_config = RelayConfig::builder("relay-001", tls_config)
//!     .bind_addr("0.0.0.0:8443".parse()?)
//!     .build()?;
//! let relay = RelayHolon::new(relay_config);
//! // ... handle incoming connections
//! ```

pub mod anti_entropy;
pub mod batch_epoch;
pub mod bft;
pub mod bft_machine;
pub mod bisimulation;
pub mod convergence;
pub mod crdt;
pub mod discovery;
pub mod equivocation;
pub mod fact_root;
pub mod functor;
pub mod genesis;
pub mod handlers;
pub mod hsi_anti_entropy;
pub mod merkle;
pub mod metrics;
pub mod network;
pub mod qc_aggregator;
pub mod relay;
pub mod replication;
pub mod tunnel;

// Bisimulation gate for recursive holon composition (TCK-00367)
// BFT consensus (Chained HotStuff)
// Anti-entropy and Merkle tree (TCK-00191)
pub use anti_entropy::{
    AntiEntropyEngine, AntiEntropyError, CompareRequest, CompareResponse, DEFAULT_SYNC_INTERVAL,
    DigestRequest, DigestResponse, EventRequest, EventResponse, MAX_COMPARISON_DEPTH,
    MAX_DIVERGENT_RANGES, MAX_PENDING_REQUESTS_PER_PEER, MAX_REQUESTS_PER_INTERVAL,
    MAX_SYNC_BATCH_SIZE, RATE_LIMIT_INTERVAL, RangeDigestResult, RangeQuery, SyncEvent,
    SyncRateLimiter, SyncSession, event_record_to_sync_event, verify_events_with_proof,
    verify_sync_catchup, verify_sync_events,
};
// BatchEpochRootV1 hierarchical batch forests (TCK-00371)
pub use batch_epoch::{
    BatchEpochError, BatchEpochRootV1, EpochAntiEntropyPointer, EpochRootBuilder, EpochTraverser,
    MAX_EPOCH_BATCH_ROOTS, MAX_TRAVERSAL_EPOCHS,
};
pub use bft::{
    BftError, DEFAULT_ROUND_TIMEOUT, HotStuffConfig, HotStuffConfigBuilder, HotStuffState,
    MAX_PAYLOAD_SIZE, MAX_QC_SIGNATURES, MAX_VALIDATORS, MIN_ROUND_TIMEOUT, NewView, Phase,
    Proposal, QuorumCertificate, TIMEOUT_MULTIPLIER, ValidatorId, ValidatorInfo,
    ValidatorSignature, Vote,
};
// BFT machine driver
pub use bft_machine::{
    BftAction, BftEvent, BftMachine, MAX_BUFFERED_MESSAGES, MAX_PENDING_ACTIONS, MSG_BFT_NEW_VIEW,
    MSG_BFT_PROPOSAL, MSG_BFT_QC, MSG_BFT_VOTE,
};
pub use bisimulation::{
    BisimulationChecker, BisimulationError, BisimulationResult, BlockingDefect, DepthCheckResult,
    FlatteningRelation, HsiOperation, MAX_COUNTEREXAMPLE_LENGTH, MAX_RECURSION_DEPTH,
    MAX_STRING_LEN, MAX_TOTAL_STATES, MAX_TRANSITIONS_PER_STATE, MismatchDirection,
    ObservableSemantics, PromotionGate, PromotionGateResult, StopKind, TraceStep, Transition,
    build_linear_composition, deserialize_and_validate_semantics,
};
pub use convergence::{
    ConvergenceError, ConvergenceReport, ConvergenceRound, ConvergenceSimulator,
    MAX_CELL_ID_LEN as MAX_CONVERGENCE_CELL_ID_LEN, MAX_CONVERGENCE_ROUNDS, MAX_EVENTS_PER_PULL,
    MAX_IDENTITIES_PER_CELL, MAX_LEDGER_EVENTS_PER_CELL, MAX_SIM_CELLS,
};
// HLC-based CRDT merge operators (TCK-00197)
// Revocation-wins signed CRDT merge law (TCK-00360)
pub use crdt::{
    AuthorizationProof, ConflictRecord, CrdtDelta, CrdtMergeError, DirectoryStatus, GCounter, Hlc,
    HlcWithNodeId, LwwRegister, MAX_CONFLICTS_PER_BATCH, MAX_KEY_LEN, MAX_NODE_ID_LEN,
    MAX_READMISSION_ANCHORS, MAX_SET_ELEMENTS, MergeEngine, MergeOperator, MergeResult,
    MergeWinner, NodeId, READMISSION_ANCHOR_DOMAIN, ReAdmissionAnchor, RevocationWinsRegister,
    SetUnion, hash_value, validate_key, validate_node_id,
};
pub use discovery::{
    DiscoveryConfig, DiscoveryError, PeerDiscovery, PeerInfo, PeerList, PeerStatus,
};
// Byzantine equivocation detection (TCK-00196)
pub use equivocation::{
    ConflictingProposal, DOMAIN_PREFIX_EQUIVOCATION, EquivocationCheckResult, EquivocationDetector,
    EquivocationError, EquivocationEvidence, EquivocationType, MAX_CACHED_PROPOSALS,
    MAX_PROPOSAL_AGE_SECS,
};
// FactRootV1 composition with RFC-0014 quorum checkpoints (TCK-00370)
pub use fact_root::{
    CompactMultiProof, FactRootError, FactRootV1, FactRootVerificationResult, FactRootVerifier,
    MAX_BATCH_ROOTS, MAX_COMPACT_MULTIPROOF_LEAVES, MAX_COMPACT_PROOF_NODES,
    MAX_COMPACT_PROOF_STRUCTURE, ProofPathEntry, build_compact_multiproof, compute_qc_anchor_hash,
};
// Functorial observation law checks for admitted rewrites (TCK-00368)
pub use functor::{
    AdmittedRewriteCatalog, FunctorError, FunctorLawChecker, FunctorLawResult, MAX_CATALOG_RULES,
    MAX_DESCRIPTION_LEN, MAX_OBSERVATION_POINTS, MAX_PROOF_REF_LEN, MAX_PROOF_STATUS_REASON_LEN,
    MAX_RULE_ID_LEN, ProofStatus, RewriteBlockingDefect, RewriteDefectKind, RewriteGateResult,
    RewritePromotionGate, RewriteRule, deserialize_and_validate_rule,
};
pub use genesis::{
    Genesis, GenesisConfig, GenesisConfigBuilder, GenesisError, GenesisValidator, InvitationToken,
    JoinRateLimiter, MAX_JOIN_ATTEMPTS_PER_MINUTE, MAX_NAMESPACE_LEN, MAX_QUORUM_SIGNATURES,
    MAX_RATE_LIMIT_SOURCES, QuorumSignature, RATE_LIMIT_WINDOW,
};
// BFT message handlers
pub use handlers::{
    BftMessageEnvelope, HandlerConfig, HandlerError, MAX_EPOCH_AGE, MAX_PENDING_INBOUND,
    MAX_REPLAY_CACHE_SIZE, MessageHandler, PeerEndpoint, PeerManager, REPLAY_CACHE_ROUND_WINDOW,
    ReplayCache,
};
pub use hsi_anti_entropy::{
    AntiEntropyCompare, AntiEntropyDefect, AntiEntropyDefectKind, AntiEntropyDeliver,
    AntiEntropyOffer, AntiEntropyRequestEvents, ByzantineRelayDetector, DeliveredEvent,
    EventAttestationVerifier, HsiAntiEntropyError, MAX_ANTI_ENTROPY_LEAVES, MAX_CELL_ID_LEN,
    MAX_COMPARE_ID_LEN, MAX_DELIVER_PROOF_HASHES, MAX_EVENTS_PER_DELIVER, MAX_OFFER_ID_LEN,
    MAX_OUTSTANDING_REQUESTS, MAX_REPLAY_ISSUERS, MAX_REPLAY_LOG_ENTRIES, MAX_REQUEST_ID_LEN,
    MAX_SESSION_ID_LEN, PullOnlyEnforcer, RelayBudget, RelayBudgetEnforcer, ReplayProtector,
    SessionUsageSnapshot,
};
pub use merkle::{
    DivergentRange, EMPTY_HASH, MAX_PROOF_NODES, MAX_TREE_DEPTH, MAX_TREE_LEAVES, MerkleError,
    MerkleNode, MerkleProof, MerkleTree, RangeDigest, hash_internal, hash_leaf,
};
// Prometheus metrics for consensus health (TCK-00193)
pub use metrics::{
    ByzantineFaultType, ClusterHealth, ClusterStatus, ConflictResolution, ConsensusMetrics,
    DEFAULT_LATENCY_BUCKETS, Histogram, LeaderElectionReason, ProposalOutcome, SyncDirection,
};
pub use network::{
    CONTROL_FRAME_SIZE, Connection, ConnectionPool, ControlFrame, Network, NetworkConfig,
    NetworkError, PooledConnection, TlsConfig, TlsConfigBuilder, apply_dispatch_jitter,
};
// QC aggregation and verification (TCK-00190)
pub use qc_aggregator::{
    MAX_TRACKED_ROUNDS, MAX_VOTES_PER_ROUND, QcAggregator, QcVerificationContext,
    QcVerificationResult, build_vote_message, compute_quorum_threshold, is_quorum, verify_qc,
    verify_qc_with_message,
};
pub use relay::{
    CLEANUP_INTERVAL, MAX_PENDING_MESSAGES, MAX_RELAY_ID_LEN, ROUTE_TIMEOUT, RelayConfig,
    RelayConfigBuilder, RelayError, RelayHolon, RelayStats, TunnelRegistry,
};
// Leader-based replication (TCK-00195)
pub use replication::{
    DEFAULT_ACK_TIMEOUT, MAX_ACKS_PER_PROPOSAL, MAX_PENDING_PROPOSALS,
    MAX_REPLICATION_PAYLOAD_SIZE, MAX_TRACKED_PROPOSALS, MSG_REPLICATION_ACK, MSG_REPLICATION_NACK,
    MSG_REPLICATION_PROPOSAL, NackReason, ReplicatedEvent, ReplicationAck, ReplicationConfig,
    ReplicationEngine, ReplicationError, ReplicationMessage, ReplicationNack, ReplicationProposal,
    ReplicationStats,
};
pub use tunnel::{
    HEARTBEAT_INTERVAL, HEARTBEAT_TIMEOUT, MAX_TUNNEL_ID_LEN, MAX_TUNNELS, MAX_WORKER_ID_LEN,
    MSG_TUNNEL_ACCEPT, MSG_TUNNEL_CLOSE, MSG_TUNNEL_DATA, MSG_TUNNEL_HEARTBEAT,
    MSG_TUNNEL_HEARTBEAT_ACK, MSG_TUNNEL_REGISTER, MSG_TUNNEL_REJECT, ManagedTunnel,
    REGISTRATION_TIMEOUT, TunnelAcceptResponse, TunnelData, TunnelError, TunnelHeartbeat,
    TunnelInfo, TunnelRegisterRequest, TunnelRejectResponse, TunnelState,
};
