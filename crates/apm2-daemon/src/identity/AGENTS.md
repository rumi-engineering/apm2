# Identity Module

> Canonical identity identifiers for the Holonic Substrate Interface (RFC-0020).

## Overview

The `identity` module implements canonical binary and text forms for all HSI identity types. These identifiers are the foundation of the APM2 identity and trust system: each identity type has domain-separated BLAKE3 derivation, strict canonical text/binary forms, and fail-closed parsing that rejects unknown tags, mixed case, and non-ASCII input.

### Supported Identity Types

- `PublicKeyIdV1` -- Ed25519 public key identifier
- `KeySetIdV1` -- Quorum/threshold multisig verifier identity
- `CellIdV1` -- Cell identity derived from ledger genesis + policy root
- `HolonIdV1` -- Holon identity derived from cell ID + genesis key
- `CellCertificateV1` / `HolonCertificateV1` -- Identity certificates
- `SessionKeyDelegationV1` -- Ephemeral session key delegation
- `HolonDirectoryHeadV1` / `DirectoryProofV1` / `IdentityProofV1` -- Directory proofs

### Canonical Text Form Grammar (RFC-0020 section 1.7.5b)

```text
public_key_id ::= "pkid:v1:ed25519:blake3:" hash64
keyset_id     ::= "kset:v1:blake3:" hash64
cell_id       ::= "cell:v1:blake3:" hash64
holon_id      ::= "holon:v1:blake3:" hash64
hash64        ::= 64 * [0-9a-f]
```

Binary form: 1-byte tag + 32-byte BLAKE3 digest = 33 bytes.

### IdentitySpec Abstraction

V1 identity parsing is implemented through explicit per-type specs with four semantic axes:

- `wire_form`: Binary wire variant (`Tagged33Only` or `Tagged33AndHash32`)
- `tag_semantics`: Tag byte interpretation (fixed, registry, or set-mode)
- `derivation_semantics`: Domain-separated digest computation
- `resolution_semantics`: Self-contained or digest-first requiring resolver

## Key Types

### `PublicKeyIdV1`

Ed25519 public key identifier. Derived via `blake3("apm2:pkid:v1\0" + algorithm_name + "\n" + key_bytes)`.

### `KeySetIdV1`

Quorum/threshold verifier identity. Supports n-of-n multisig and k-of-n threshold.

### `CellIdV1`

Cell identity derived from `blake3("apm2:cell_id:v1\n" + ledger_genesis_hash + policy_root_pkid)`.

### `HolonIdV1`

Holon identity derived from `blake3("apm2:holon_id:v1\0" + cell_id + holon_genesis_pkid)`.

### `AuthoritySealV1`

Authority seal binding a subject to a signed commitment, with Merkle inclusion proofs for batch verification.

**Invariants:**

- [INV-ID01] `reject_free_floating_batch_root()` prevents seals with batch root but no Merkle proof.
- [INV-ID02] Merkle proof depth bounded to `MAX_MERKLE_PROOF_DEPTH`.
- [INV-ID03] Quorum signatures bounded to `MAX_QUORUM_SIGNATURES`.

### `ReceiptPointerV1`

Receipt pointer with batch verification support and multi-proof for amortized verification.

**Invariants:**

- [INV-ID04] Multi-proof leaves bounded to `MAX_MULTIPROOF_LEAVES`.
- [INV-ID05] Direct verification fallback when batch overhead exceeds policy threshold.

### `IdentitySpec`

```rust
pub struct IdentitySpec {
    pub text_prefix: &'static str,
    pub wire_form: IdentityWireFormSemantics,
    pub tag_semantics: IdentityTagSemantics,
    pub derivation_semantics: IdentityDerivationSemantics,
    pub resolution_semantics: IdentityResolutionSemantics,
    pub text_tag_policy: IdentityTextTagPolicy,
    pub unresolved_compat_tag: Option<u8>,
    pub validate_tag: fn(u8) -> Result<IdentitySemanticCompleteness, KeyIdError>,
}
```

### `KeyIdError`

Comprehensive error type for identity parsing failures. Covers: empty input, whitespace, wrong prefix, uppercase, padding, hex errors, unknown tags, length mismatches, and resolution requirements.

**Invariants:**

- [INV-ID06] Fail-closed parsing: unknown algorithm/set tags are rejected, never defaulted.
- [INV-ID07] Strict canonical form: mixed case, whitespace, padding, percent-encoding, and Unicode normalization variants are all rejected.
- [INV-ID08] Bounded length: text forms bounded to `MAX_TEXT_LEN` (96 bytes).
- [INV-ID09] Lossless round-trip: binary-to-text-to-binary produces identical bytes.

## Public API

Key re-exports:

- `PublicKeyIdV1`, `AlgorithmTag`
- `KeySetIdV1`, `KeySetDigestResolver`, `ResolvedKeySetSemantics`, `SetTag`
- `CellIdV1`, `CellGenesisV1`, `PolicyRootId`
- `HolonIdV1`, `HolonGenesisV1`, `HolonPurpose`
- `CellCertificateV1`, `HolonCertificateV1`, `CertificateError`
- `SessionKeyDelegationV1`, `UncheckedSessionDelegation`
- `AuthoritySealV1`, `SealKind`, `SubjectKind`, `MerkleInclusionProof`
- `ReceiptPointerV1`, `ReceiptMultiProofV1`, `ReceiptPointerVerifier`
- `DirectoryProofV1`, `HolonDirectoryHeadV1`, `IdentityProofV1`
- `KeyIdError`, `IdentitySpec`, `IdentityWireVariant`, `IdentityParseProvenance`

### Constants

- `MAX_TEXT_LEN`: 96
- `HASH_LEN`: 32
- `BINARY_LEN`: 33
- `MAX_AUTHORITY_SEAL_BYTES`, `MAX_MERKLE_PROOF_DEPTH`, `MAX_QUORUM_SIGNATURES`

## Related Modules

- [`apm2_daemon::hsi_contract`](../hsi_contract/AGENTS.md) -- HSI contract manifest using identity for binding
- [`apm2_daemon::hmp`](../hmp/AGENTS.md) -- HMP channel addressing with cell/holon identifiers
- [`apm2_daemon::pcac`](../pcac/AGENTS.md) -- PCAC authority chains referencing identity keys
- [`apm2_core::crypto`](../../../apm2-core/src/crypto/AGENTS.md) -- Cryptographic primitives

## References

- RFC-0020 section 1.7.2: `PublicKeyIdV1` canonical key identifiers
- RFC-0020 section 1.7.2a: `KeySetIdV1` quorum/threshold verifier identity
- RFC-0020 section 1.7.3: `CellIdV1`
- RFC-0020 section 1.7.4: `HolonIdV1`
- RFC-0020 section 1.7.5b: ABNF for canonical text forms
- REQ-0007: Canonical key identifier formats
- REQ-0008: Genesis artifacts are hash-addressed in CAS
