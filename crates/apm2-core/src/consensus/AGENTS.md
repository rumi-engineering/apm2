# Consensus Module

> Network transport and peer discovery for the APM2 distributed consensus layer.

## Overview

The `apm2_core::consensus` module provides the networking foundation for distributed consensus. It implements:

1. **Mutual TLS Transport**: TLS 1.3 connections with client certificate authentication
2. **Peer Discovery**: Bootstrap node connection and peer list management
3. **Traffic Analysis Mitigation**: Fixed-size control plane frame padding

## Security Invariants (from RFC-0014)

### TB-0004: Inter-Node Communication Boundary

| ID | Statement | Verification |
|----|-----------|--------------|
| INV-0015 | All inter-node connections use mutual TLS 1.3 | `TlsConfig` requires both client and server certificates |
| INV-0016 | Node certificates chain to network CA | `RootCertStore` validates certificate chain |
| INV-0017 | Control plane messages use fixed-size frames | `CONTROL_FRAME_SIZE = 1024` bytes for all frames |
| INV-0018 | Consensus messages are signed by sender | Signature validation in message handlers (future ticket) |
| INV-0019 | Control plane connections use pooling | `ConnectionPool` with `MAX_TOTAL_CONNECTIONS = 64` |
| INV-0020 | Control plane dispatch uses bounded jitter | `MAX_DISPATCH_JITTER_MS = 50` |

### INV-0013: Join Rate Limiting

Join attempts are rate-limited to `MAX_JOIN_ATTEMPTS_PER_MINUTE = 10` per source to prevent DoS attacks on the discovery service.

## Key Types

### `TlsConfig`

TLS configuration for mutual authentication. Created via builder pattern.

**Contracts:**
- [CTR-NET-0001] CA certificate must be provided
- [CTR-NET-0002] Node certificate must be provided
- [CTR-NET-0003] Node private key must be provided

### `ControlFrame`

Fixed-size (1024 bytes) control plane frame for traffic analysis mitigation.

**Format:**
- Bytes 0-3: Message type (u32 big-endian)
- Bytes 4-7: Payload length (u32 big-endian)
- Bytes 8-1023: Payload + padding (zeros)

**Contracts:**
- [CTR-NET-0004] Payload must not exceed `MAX_PAYLOAD_SIZE = 1016` bytes
- [CTR-NET-0005] All frames are exactly `CONTROL_FRAME_SIZE = 1024` bytes

### `ConnectionPool`

Connection pool for TLS connection reuse.

**Invariants:**
- [INV-NET-0001] Maximum `MAX_CONNECTIONS_PER_PEER = 4` connections per peer
- [INV-NET-0002] Maximum `MAX_TOTAL_CONNECTIONS = 64` total connections
- [INV-NET-0003] Idle connections are removed after `CONNECTION_IDLE_TIMEOUT = 300s`

### `PeerList`

Bounded peer list with automatic stale peer cleanup.

**Invariants:**
- [INV-NET-0004] Maximum `MAX_PEERS = 128` peers
- [INV-NET-0005] Stale peers (not seen for `DEFAULT_PEER_TIMEOUT = 300s`) are removed

### `PeerDiscovery`

Peer discovery service with bootstrap and refresh capabilities.

**Contracts:**
- [CTR-NET-0006] `bootstrap()` connects to configured bootstrap nodes
- [CTR-NET-0007] `refresh()` updates peer list from known peers
- [CTR-NET-0008] `handle_join_request()` enforces rate limiting

## Constants

| Constant | Value | Purpose |
|----------|-------|---------|
| `CONTROL_FRAME_SIZE` | 1024 | Fixed frame size for traffic analysis mitigation |
| `MAX_PAYLOAD_SIZE` | 1016 | Maximum payload within a frame |
| `MAX_CONNECTIONS_PER_PEER` | 4 | Connection pool limit per peer |
| `MAX_TOTAL_CONNECTIONS` | 64 | Total connection pool limit |
| `CONNECTION_IDLE_TIMEOUT` | 300s | Idle connection cleanup threshold |
| `MAX_DISPATCH_JITTER_MS` | 50 | Maximum dispatch jitter |
| `MAX_PEERS` | 128 | Peer list maximum size |
| `DEFAULT_PEER_TIMEOUT` | 300s | Peer staleness threshold |
| `DEFAULT_REFRESH_INTERVAL` | 60s | Peer list refresh interval |
| `MAX_JOIN_ATTEMPTS_PER_MINUTE` | 10 | Rate limit for join attempts |

## Message Types

| Type | Value | Description |
|------|-------|-------------|
| `MSG_PEER_LIST_REQUEST` | 1 | Request peer list from node |
| `MSG_PEER_LIST_RESPONSE` | 2 | Peer list response |
| `MSG_PEER_ANNOUNCE` | 3 | Announce presence to peers |

## Test Requirements

Tests are in `tck_00183_*` modules and verify:

1. **TLS Configuration**: Valid certificate chain creation
2. **Control Frame Padding**: All frames are exactly 1024 bytes
3. **Bounded Stores**: Connection pool and peer list enforce limits
4. **Oversized Rejection**: Payloads exceeding limit are rejected
5. **Rate Limiting**: Join attempts are rate-limited
6. **Peer Validation**: Invalid peer info is rejected
7. **Stale Cleanup**: Stale peers are removed

## Dependencies

- `rustls`: TLS 1.3 implementation
- `tokio-rustls`: Async TLS streams
- `rcgen`: Certificate generation (testing)

## Related Modules

- [`apm2_core::crypto`](../crypto/AGENTS.md) - Signing and hashing primitives
- RFC-0014: Distributed Consensus Layer
