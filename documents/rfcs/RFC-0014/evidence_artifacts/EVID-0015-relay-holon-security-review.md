# EVID-0015: Relay Holon Security Review

## Status
DRAFT (review complete; test execution pending)

## Scope
Relay Holon provides outbound-only management tunnels for nodes behind NAT or
restricted networks (CON-0005). The relay is untrusted for integrity; control-plane
message authenticity is enforced end-to-end between consensus nodes.

## Architecture Summary
- Nodes initiate outbound TLS to Relay (Reverse-TLS tunnel).
- Relay only forwards framed control-plane messages; it cannot sign authority events.
- All control-plane messages are signed by sender and verified by receiver (Ed25519).
- Relay keys are isolated from validator keys; relay compromise does not grant ledger authority.

## Threat Model
- Compromised relay attempting message tampering or injection.
- MITM interception or downgrade during tunnel establishment.
- Traffic analysis via message size/timing.
- Relay DoS or connection squatting.
- Replay of prior control-plane messages.

## Mitigations
- End-to-end message signatures + epoch/round checks reject tampering/injection.
- Mutual TLS with network CA; pinned ALPN; strict protocol versioning.
- Padding + fixed-size frames and randomized jitter (0-50ms) reduce traffic analysis.
- Connection pooling + forced relay rotation limit squatting.
- Replay protection via nonce + epoch/round + dedupe key; expired tokens rejected.
- Relay capabilities limited to NAT traversal; no ledger writes; no policy authority.

## Tests / Evidence Hooks
- TEST-BC-002: Relay tunnel idle timeout closes connection.
- TEST-BC-003: Forced relay rotation after MAX_DURATION.
- TEST-TS-002: Control-plane padding + jitter enforced.
- TEST-MA-003: Invitation token single-use enforced.
- TEST-MA-004: Invitation token expiration enforced.

## Residual Risks
- Coordinated relay DoS can delay control-plane participation for NAT-bound nodes.
- Metadata leakage not eliminated; reduced via padding/jitter and pooling.
- Mitigated by multi-relay configuration and conservative quorum sizing.
