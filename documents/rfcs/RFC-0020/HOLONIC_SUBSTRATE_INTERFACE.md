# RFC-0020 — Holonic Substrate Interface (HSI)
**Status:** DRAFT (2026-02-05)  
**Audience:** Security, distributed systems, and platform engineering reviewers  
**Scope:** Cell-local enforcement is normative. Federation-ready wire shapes are specified so that multi-cell deployment can be added without breaking contracts. Cross-cell *policy rooting* and *anti-entropy replication* are staged deliverables (see §10).  
**Spine alignment:** HSI is the contract boundary that enforces the APM2 “truth topology”: facts are (Ledger + CAS + commitments); everything else is a projection. HSI MUST remain stable under arbitrary holonic recursion.  
**Normative foundation:** This RFC is constrained by the Unified Theory laws/invariants and is written to be mechanically checkable against daemon enforcement objects and contracts already specified in RFC-0013 and RFC-0019 (EpisodeEnvelope, CapabilityManifest, CapabilityScope, RiskTier, StopConditions, ToolExecutionReceipt, ToolLogIndexV1, SummaryReceipt, ContextPack/ContextDelta, PermeabilityReceiptV1). See §0.1 and §0.2.

**Compatibility note (normative):** Where the Unified Theory and the current daemon implementation disagree on *names* (e.g., RiskTier taxonomy, quantitative encoding), this RFC:
1) treats **daemon-enforced types** as the immediate operational truth, and
2) specifies a **lossless mapping** to Unified Theory concepts to prevent semantic drift under recursion.
Any future refactor MUST preserve the mapping invariants or explicitly version the affected schemas.

---

## 0. Executive summary (non-normative)

HSI formalizes a single idea: **a holonic agent should only see one *contracted substrate***, and that substrate is
the `apm2-daemon` microkernel interface, projected through the `apm2` CLI.

Whether an agent represents:
- a single reviewer fixing a 1-line bug, or
- an aggregate holon coordinating millions of sub-holons,

…the same primitives apply: **identity, capability delegation, context slicing, tool actuation, receipts, and
digest-first coordination**.

The practical aim is to accelerate the Forge Admission Cycle (FAC) without sacrificing auditability or safety.
The current bottleneck is not “LLM intelligence”; it is interface entropy. Agents fail or waste cycles because:
1) the agent-computer interface is implicit and drifts, and  
2) delegated authority is not explicit, queryable, or uniformly bound into receipts.

HSI makes these explicit via three content-addressed artifacts:

- **HSIContractManifestV1**: “what syscalls exist, what schemas they take/return, and what they mean”
- **CapabilityManifestV1**: “what authority is delegated *right now* (sealed capabilities + scopes + allowlists)”
- **EpisodeEnvelopeV1**: “the immutable execution commitment for an episode (risk tier, budgets, stop conditions,
  pinned reproducibility snapshot, and the hashes of the above manifests)”

All three are stored in CAS and referenced by hash in:
- episode start events,
- tool receipts,
- ContextPacks,
- review artifacts,
- and inter-holon messages.

### 0.1 Non-negotiable constraints (normative)

HSI MUST uphold the following invariants, regardless of recursion depth or deployment scale:

1) **No ambient authority.** Capsules have no unrestricted OS authority. All world effects are daemon-mediated.  
2) **Proof-carrying effects.** If an effect is not proven by a signed receipt bound to CAS evidence digests, it did not happen.  
3) **Digest-first everywhere.** Cross-holon communication is hashes + selectors, not raw payload propagation.  
4) **Fail-closed enforcement.** Contract mismatch, capability mismatch, stop uncertainty, or context firewall violations MUST deny or terminate, not “warn and continue.”  
5) **Canonicalization.** All signed/hashed artifacts MUST be deterministically serialized (no maps in signed messages; repeated fields sorted; stable field presence rules). Unknown fields in **signed/hashed JSON artifacts** MUST be rejected (fail-closed). Unknown fields in **signed/hashed protobuf artifacts** MUST be dropped prior to canonicalization/signing and MUST NOT be forwarded across holonic boundaries. Unknown fields MAY be tolerated in **unsigned discovery** payloads but MUST be ignored and MUST NOT be forwarded across holonic boundaries.  
6) **Policy inheritance.** Delegation is strict subset; a holon cannot delegate authority it does not have.  
7) **Cryptographic agility without semantic drift.** Artifact hashes MUST be algorithm-tagged (e.g., `blake3:<hex>`), and signatures MUST be domain-separated by artifact kind+schema version so that cross-type collisions cannot be used as confused-deputy inputs.
8) **Bounded decoding and bounded collections.** All protocol decoders and artifact parsers MUST be size-bounded *before* decode and MUST enforce per-field count/length bounds *after* decode (especially repeated fields). Any violation MUST fail-closed with a denial/defect, not partial parsing. This is a DoS invariant, not an optimization.
9) **Unitful quantities.** Any quantitative field that can influence enforcement or coordination (budgets, TTLs, byte caps, rates) MUST be encoded so that units are unambiguous and mechanically checkable. Ambiguous strings (e.g., `"5m"`, `"10MB"`) are forbidden in signed/hashed artifacts.
10) **Self-certifying identities + proof-carrying membership.** Any identity value that crosses a holonic boundary (`cell_id`, `holon_id`, `actor_id`, `validator_id`, `*_key_id`) MUST be self-certifying (derivable from public keys) and MUST admit *bounded* verification that is:
   - **O(log n)** in the number of registered identities for the relevant namespace (cell or federation), and
   - **cacheable** (verifiers MUST be able to amortize cost across many artifacts/messages by reusing a small number of verified commitments).
   Verifiers MUST NOT require linear scans of registries, revocation lists, or “search for a matching cert”. Identity MUST travel as **proof-carrying pointers** (hashes + Merkle inclusion proofs + signed head commitments).
10b) **Identity freshness (anti-replay) is a policy surface, not a best-effort.**
   Any proof-carrying identity used to authorize actuation MUST be validated against a directory head whose
   freshness satisfies the cell’s configured FreshnessPolicy for the relevant RiskTier.
   - Tier0/Tier1 MAY accept stale heads (bounded) and downgrade to read-only under uncertainty.
   - Tier2+ MUST fail-closed on staleness (deny actuation), because stale identity ⇒ unverifiable revocation.
   - Freshness authority MUST be HTF-compatible: ledger-anchor lag is mandatory; wall-clock deltas are forbidden as authority inputs.
11) **Proof compression and attestation batching.** High-volume facts (receipts, directory heads, checkpoint summaries) MUST support proof compression:
   - A verifier MUST be able to validate K receipts with **O(1) signature/quorum verifications per batch** and **O(K log B)** hashing work (B=batch size), rather than O(K) signature verifications.
   - Individual per-receipt signatures MAY exist, but MUST NOT be the only admissible format at exabyte scale. “Signed receipt” in HSI includes *direct signatures* **or** *Merkle-batched attestations* (see §1.7.8 and §9.5).
11b) **Batch roots MUST be ledger-anchored (or quorum-certified) facts, not free-floating signatures.**
   Any batch attestation that is relied upon for authoritative verification MUST bind to a ledger anchor (or HTF time envelope ref)
   so that freshness and revocation checks are mechanically defined.
12) **Identity formats are protocol objects, not UI strings.** Any identity crossing a holonic boundary (`pkid`, `cell_id`, `holon_id`, `spiffe_id`) MUST conform to strict canonical grammar + bounded length and MUST have a canonical binary form used for hashing/signing.
13) **Verification economics are first-class policy.** Cells that advertise federation capability MUST publish proof/verification profiles with explicit complexity and byte caps. For identity and receipt verification at `10^12` scale, profiles MUST demonstrate O(log n) (or better) hashing work with bounded proof bytes and amortized O(1) signature/quorum checks per verified batch family.

These constraints are not stylistic preferences; they are the minimum set needed for:
- holonic closure under composition,
- security auditing at scale,
- and business continuity under partial failure.

### 0.2 Alignment with the daemon protocol + APM2 plane model (normative)

HSI is an **interface contract**, not a transport reinvention. In the current codebase, the daemon already enforces:

- **A mandatory Hello/HelloAck handshake** before any privileged/session message exchange.
- **Privilege separation by socket** (operator control plane vs session control plane) and per-request authentication (session tokens).
- **Six-plane separation** (Identity, Capability, Context, Tool, Ledger, Governance) as the stable conceptual decomposition.

HSI therefore specifies:

1) *What must be true* (schemas + semantics + proof obligations), and  
2) *What must be bound into receipts/commitments*,  
—while allowing the daemon’s existing transports to evolve (UDS → multi-cell relay) without changing the contracted meaning.

**Compatibility rule:** When HSI says “route/syscall”, it refers to a **stable semantic operation** in the daemon’s plane model. Implementations MAY map that operation to:
- protobuf tag-dispatch,
- CLI subcommands, or
- RPC routes,
provided that receipts + bindings + canonicalization requirements are preserved.

---

## 1. Normative definitions

### 1.1 Holon, cell, episode, session, capsule

- **Holon:** A recursively composable unit that can act as an agent and/or coordinate sub-holons. A holon can be both
  a part and a whole. A holon may be “virtual” (logical coordinator) or “physical” (process cluster); the interface
  is the same.

- **Cell:** A local APM2 deployment boundary (`daemon + ledger + CAS + policy root`) with a single security/policy root.
  A cell may run on a laptop, a server, or a cluster; HSI specifies cell-local enforcement and federation-ready shapes.

- **Work:** A named unit of change (FAC scope) addressed by `work_id`.

- **Lease:** A time-bounded authority handle issued by policy/governance that allows an actor to spawn an episode.

- **Episode:** A bounded execution attempt by an actor for a work item, addressed by `episode_id` and committed by an
  immutable **EpisodeEnvelopeV1** (see §3.3). All authoritative receipts MUST bind the episode envelope hash.

- **PermeabilityReceiptV1:** The only legal path for authority to cross a holonic boundary. It is the *authority entry object* that binds: delegator→delegatee, delegated handles, budgets, stop conditions, expiry, and view commitment. Any episode or receipt that consumes delegated authority MUST bind the `permeability_receipt_hash` (see §8.3 and §3.3).

- **Session:** A daemon-authenticated IPC connection binding a client process to a `session_id` and a current episode
  (or read-only pre-episode state). Sessions do not define authority; manifests/envelopes do.

- **Agent Capsule:** A contained execution environment in which an agent runtime executes with **no ambient OS authority**
  (no unrestricted filesystem/network/process access). The only actuator is daemon-mediated tools.

### 1.2 Risk tiers and determinism class

HSI uses the daemon-enforced `RiskTier` ladder (stable discriminants; unknown values are invalid):
- **Tier0:** read-only, no side effects.
- **Tier1:** local/dev effects (bounded, reversible).
- **Tier2:** production-adjacent effects (external integration, moderate blast radius).
- **Tier3:** production effects (release, merge, deploy, ticket mutation).
- **Tier4:** critical operations (policy changes, key material rotation, emergency actions).

**Sandboxing requirement (normative):** per baseline security controls, **Tier3+ MUST require sandbox isolation**. Tier1–Tier2 MAY run unsandboxed for developer ergonomics, but MUST remain OCAP-only and receipt-bound.

#### 1.2.1 Unified Theory mapping (normative, conservative+monotone at the policy boundary)

Unified Theory documents a coarser 4-class risk model (`T0..T3`). To prevent semantic drift across docs:
- **UT.T0 (Experimental)** defaults to daemon **Tier1** (allowed set: Tier0/Tier1)
- **UT.T1 (Internal)** defaults to daemon **Tier2** (allowed set: Tier1/Tier2)
- **UT.T2 (Production)** maps to daemon **Tier3**
- **UT.T3 (Security-Critical)** maps to daemon **Tier4**

This mapping is not advisory: any policy object that references Unified Theory risk classes MUST be reducible to a daemon `RiskTier` ceiling for enforcement. Reverse mapping from daemon tier to UT tier is only valid when the originating `ut_tier` witness is retained on policy/receipt objects.

#### 1.2.2 DeterminismClass (normative)

HSI uses the daemon determinism ladder (names aligned to implementation contracts):
- **Deterministic:** replays are expected to be byte-for-byte stable given pinned inputs and deterministic tools.
- **ProbabilisticBounded:** replays are stable at the evidence layer (same receipts + hashes) but may differ in intermediate reasoning; nondeterminism MUST be bounded and disclosed (e.g., sampling allowed but seeds/model profile pinned).
- **NonReplayable:** execution may depend on inherently nondeterministic inputs (external timing, human interaction); the system MUST still emit receipts and must elevate gating for any Tier2+ actuation.

Determinism class is a property of the EpisodeEnvelope and MUST be checked as part of pre-actuation policy evaluation.

#### 1.2.3 Enum decoding contract (normative)

Protocol implementations MUST treat enum decoding as an attack surface:
- Protobuf enum fields MUST be decoded from the full wire integer width (u32) and validated without truncation.
- Unknown/invalid enum values MUST fail-closed (deny actuation, emit defect), never “defaulted” to Tier0 or similar.

### 1.3 “World effects” and proof

A **world effect** is any action that can modify state outside the agent’s ephemeral cognition:
filesystem writes, network calls, process creation, merges, releases, ticket mutations, etc.

Within APM2:
- A world effect MUST be represented by a **signed receipt** bound to **evidence digests** in CAS and the
  **EpisodeEnvelopeV1** hash.
- A receipt MUST additionally bind the **view commitment** (ledger head + pinned snapshot) that defines “what world
  was seen.”
- If an action cannot be proven via a signed receipt + evidence digest + envelope binding, it did not happen within
  the factory.

**Normative clarification:** In HSI, “signed receipt” includes:
1) a receipt carrying a direct signature, OR
2) a receipt hash proven to be included in a Merkle-batched **AuthoritySeal** whose root is authenticated by a trusted issuer
   (`AuthoritySealV1` with `seal_kind=MERKLE_BATCH`). See §1.7.8 and §9.5.

**Terminology guardrail:** This RFC reserves the word **attestation** for *environment/runner attestations*
(aligned with `apm2.attestation.v1` in the Unified Theory catalog).
Authentication of facts/roots is represented by **AuthoritySeal** objects to avoid semantic collision.

### 1.3.1 Proof obligations checklist (normative)

For any claimed effect `E`, a verifier MUST be able to check:

1) The receipt is authenticated by one of:
   - direct signature verification under the declared policy root key, OR
   - verification of a valid `AuthoritySealV1` over a Merkle root, plus an inclusion proof that the receipt hash is a member of that root
     (the seal MUST be verifiable under the declared policy root key or BFT quorum attestation for the cell).
2) `Receipt.envelope_hash` resolves to an `EpisodeEnvelope` whose `risk_tier` authorizes `E`.
3) `EpisodeEnvelope.capability_manifest_hash` resolves to a capability manifest that explicitly permits `E`’s tool class
   and scope.
4) If the episode or tool request is downstream of a holonic delegation, the verifier MUST also be able to resolve and verify a `permeability_receipt_hash` that authorizes the delegated envelope/manifest budget + stop + expiry constraints.
5) `Receipt.details` includes hashes of request+result artifacts (or their indices) stored in CAS.
6) `Receipt.view_commitment_hash` resolves to a `ViewCommitment` that pins:
   - the ledger head (or range root) observed
   - the context pack hash observed
7) Stop conditions and budgets were checked *before* execution (either by explicit `StopChecked`/`BudgetChecked` receipts
   or by mandatory inclusion in the `ToolExecutionReceipt`).

If any step is not verifiable, the effect MUST be treated as non-existent for coordination decisions.

### 1.3.2 Downstream trust unit (normative)

For downstream holons, HSI distinguishes two trust units:

1) **Routing fact:** Event records and message headers are admissible for scheduling/routing/anti-entropy coordination.
2) **Acceptance fact:** Any authoritative claim (state transition, world effect, delegation consumption, cross-cell admission) MUST be justified by receipt-addressable evidence and verifier authentication.

Acceptance verification MUST be possible via:
- direct signature verification on the receipt, OR
- `ReceiptPointerV1` + `AuthoritySealV1` (and inclusion proof when batched), bound to a ledger/quorum anchor.

A downstream holon MUST NOT treat forwarded event bytes alone as acceptance truth.

--- 

### 1.6 Quantities and budgets (normative)

HSI adopts the Unified Theory principle that enforcement-relevant quantities must be unitful and mechanically checkable.

**Rule:** Any schema field representing a quantitative limit MUST be one of:
- A **unit-suffixed scalar field** whose unit is fixed by the field name and schema (e.g., `wall_ms`, `bytes_io`, `token_budget`), OR
- A **Quantity object** with explicit unit and scale (preferred for cross-boundary generic tooling).

**Forbidden in signed/hashed artifacts:** strings with implicit units (`"5m"`, `"10MB"`, `"2h"`), floats for money/bytes/time, and untyped integers where the unit is implied “by convention”.

**Migration stance (normative):**
- v1 schemas MAY continue using unit-suffixed scalar fields if they are unambiguous and unit-fixed by schema.
- Any new cross-cell or federation schema that may be interpreted by heterogeneous tooling SHOULD prefer explicit `Quantity` objects to avoid “unit confusion” attacks under recursion.

### 1.4 Digest-first interfaces

A digest-first interface transmits:
- hashes of authoritative artifacts (CAS hashes, ledger head hashes), and
- deterministic selectors for “zoom-in” retrieval,

instead of raw logs, raw diffs, or full history.

Digest-first is the only scalable interface for deeply recursive holarchies. The cost of “raw payload propagation”
grows faster than linearly with recursion depth; digest-first grows approximately with the number of *relevant deltas*.

HSI additionally requires *index-first* operation at scale:
- Large artifacts MUST be represented by an index artifact (e.g., ToolLogIndexV1) + chunk digests.
- Summaries MUST carry a loss profile and be traceable to source evidence via indices and selectors.

### 1.5 ContentHash, canonical bytes, and artifact identity (normative)

HSI uses a single canonical **ContentHash** concept for all cross-boundary references:

- **Binary/on-wire form:** 32-byte digest (BLAKE3-256 unless explicitly specified otherwise).
- **Text form:** algorithm-prefixed lowercase hex: `blake3:<64-hex>` (default) or `sha256:<64-hex>` (allowed only for explicit interoperability).

**Rule:** any field named `*_hash` or `*_digest` MUST be a ContentHash and MUST carry algorithm identity at the protocol boundary (even if internally represented as raw `[u8;32]`).

#### 1.5.1 Canonicalization regimes

HSI recognizes two canonicalization regimes:

1) **Protobuf canonical bytes** (preferred for kernel-enforced artifacts):
   - `prost`-encoded bytes from a schema with explicit field presence rules (no implicit-default skipping for values that participate in hashing).
   - Repeated fields sorted deterministically when semantics are set-like.
   - **Unknown fields MUST be dropped prior to canonicalization/signing** (so that signature verification is deterministic across decoders).
2) **JSON canonical form** (allowed only for human-facing artifacts):
   - MUST use a single deterministic canonicalization (e.g., JCS) if hashed/signed.
   - MUST use `deny_unknown_fields` semantics for signed/hashed objects.

#### 1.5.2 Domain separation

When hashing bytes of a signed/hashed artifact, the preimage MUST be:
`hash("apm2:" + schema_id + ":" + schema_version + "\n" + canonical_bytes)`

This is required to prevent cross-artifact confused-deputy use of identical byte strings.

---

### 1.7 Identity, naming, and attestation primitives (normative)

HSI cannot remain holonically closed if “who is speaking” and “who attested this fact” are implicit, stringly-typed, or
require linear-time lookups. This section defines:

1) **Self-certifying identities** (IDs derived from keys, not assigned by convention),  
2) **Cell/holon certificates** (key binding + policy-root binding),  
3) **Directory heads + Merkle proofs** (O(log n) membership verification), and  
4) **Attestation envelopes** supporting both *single-signer* and *quorum* attestations, including *Merkle-batched* attestations.

These primitives are used by:
- session handshakes (§5.1),
- cross-cell trust bootstrap (§2.4.7),
- HMP envelopes (§7.3),
- PermeabilityReceiptV1 admission (§8.3),
- and exabyte-scale receipt verification (§9.5).

#### 1.7.1 Security goals (normative)

HSI identity MUST satisfy:

1) **Self-certification:** Given a public key (or threshold verifying key), a verifier can deterministically compute the corresponding ID.  
2) **No global scan:** A verifier never needs “the whole directory” or “the whole CRL”.  
3) **O(log n) membership:** “This holon/cell is admitted under this trust domain” is proven by Merkle inclusion proofs against signed heads.  
4) **Revocation without ambiguity:** Revocation is proven by *state transition* (directory head update / revocation event), not by time guesses.  
5) **Cacheability:** Verifiers can reuse a small number of validated head commitments to verify many identities/receipts.  
6) **Holonic stability:** Identity verification semantics MUST not change under recursion (a sub-holon is verified the same way as a “whole” holon).

#### 1.7.2 Canonical key identifiers (normative)

HSI defines a canonical **PublicKeyIdV1** for verifying keys:

- **key_algorithm:** currently `ed25519` (PQC out of scope).  
- **key_bytes:** canonical verifying key bytes (exact byte string; no PEM ambiguity).  
- **key_id:** `blake3("apm2:pkid:v1\0" + key_algorithm + "\n" + key_bytes)` (32 bytes).

**Text form:** `pkid:v1:ed25519:blake3:<64-hex>`

**Normative rule:** Any field named `*_public_key_id` MUST be a `PublicKeyIdV1` text form (or a binary equivalent carrying algorithm id).

#### 1.7.2a KeySetIdV1 (quorum/threshold verifier identity) (normative)

Single-key identifiers are insufficient for quorum verification economics. HSI therefore standardizes a self-certifying
identifier for a verifier set.

**KeySetDescriptorV1** (canonical bytes object) includes:
- `key_algorithm`
- `mode`: `MULTISIG` | `THRESHOLD`
- `threshold_k`
- `members[]`: list of `PublicKeyIdV1` sorted lexicographically by raw key id bytes
- OPTIONAL `weights[]` aligned 1:1 with `members[]`

**KeySetIdV1 derivation:**
`keyset_id = blake3("apm2:keyset_id:v1\0" + canonical_bytes(KeySetDescriptorV1))`

**Text form:** `kset:v1:blake3:<64-hex>`

**Normative rule:** Any quorum verifier referenced by `*_quorum_id` MUST resolve to a `KeySetDescriptorV1`
in CAS under digest-first lookup.

#### 1.7.2b Identity keys vs session keys (normative)

HSI distinguishes:
1) **Identity root keys**: stable keys that define persistent identity anchors.
2) **Operational identity keys**: rotate-able, directory-admitted keys used for routine authorization.
3) **Session keys**: short-lived keys used for channel security and high-volume message authentication.

**Normative rules:**
- `holon_id` MUST be derived from a root identity key, never a session key.
- Operational key rotation MUST NOT change `holon_id`.
- Session keys MUST be bound via `SessionKeyDelegationV1` signed by the holon operational key (or by equivalent verified handshake binding).

#### 1.7.3 CellIdV1 (self-certifying cell identity) (normative)

The RFC previously defined `cell_id` as derived from current policy-root verifying material while also requiring stability under rotation.
That is inconsistent unless “policy root” means “genesis policy root”.

A cell is therefore identified by a self-certifying **CellIdV1** computed from **cell genesis commitments**:

`cell_id = blake3("apm2:cell_id:v1\n" + ledger_genesis_hash_bytes + genesis_policy_root_public_key_id_bytes)`

**Text form:** `cell:v1:blake3:<64-hex>`

**Normative rule:** `cell_id` MUST be stable for the lifetime of a cell. Policy root rotation MUST NOT change `cell_id`; it is represented
by ledger-anchored KeyRotated events and updated certificate heads.

#### 1.7.3b CellGenesisV1 (normative)

HSI introduces **CellGenesisV1** (`apm2.cell_genesis.v1`, CAS) as the canonical bytes object whose digest inputs
the `cell_id` derivation:
- `ledger_genesis_hash`
- `genesis_policy_root_public_key_id` (single or quorum verifying material id)
- `trust_domain` (string; see §1.7.5)

Rationale: makes `cell_id` computation deterministic, stable, and audit-friendly under key rotation.

#### 1.7.4 HolonIdV1 (stable self-certifying holon identity) (normative)

A holon is identified by a self-certifying **HolonIdV1** scoped to its cell and derived from holon genesis commitments:

`holon_id = blake3("apm2:holon_id:v1\0" + cell_id_bytes + holon_genesis_public_key_id_bytes)`

**Text form:** `holon:v1:blake3:<64-hex>`

**Normative rule:** Any `actor_id` that participates in authority decisions MUST be a `HolonIdV1` (or a lossless mapping to it).
Legacy string IDs MAY exist in local-only projections, but MUST NOT cross holonic boundaries as an authority-bearing identity.

#### 1.7.4b HolonGenesisV1 (normative)

HSI introduces **HolonGenesisV1** (`apm2.holon_genesis.v1`, CAS) as the canonical bytes object whose digest inputs
the `holon_id` derivation:
- `cell_id`
- `holon_genesis_public_key_id` + `holon_genesis_public_key_bytes`
- OPTIONAL `purpose`: `AGENT | RELAY | OPERATOR | VALIDATOR`
- OPTIONAL `created_anchor`

Rationale: keeps `holon_id` stable under operational key rotation and makes long-lived audit graphs replay-stable.

#### 1.7.4c Operational key binding (normative)

Holon operational keys are discovered through authenticated directory state, not by recomputing `holon_id`.

**Normative rule:** any signature authorizing actuation MUST verify under:
- the currently ACTIVE operational key committed by directory state for that `holon_id`, OR
- a session key delegated from that operational key and bound to the active session.

#### 1.7.5 SPIFFE-like naming (normative mapping)

HSI provides a SPIFFE-like naming mapping for interoperability with service-mesh identity, without adopting X.509 as the mandatory substrate:

`spiffe_id = "spiffe://<trust_domain>/apm2/cell/" + <cell_id_text> + "/holon/" + <holon_id_text>`

Constraints:
- `trust_domain` MUST be bound by a CellCertificateV1 (§1.7.6) or federation-root certificate (if used).
- `spiffe_id` is **not** used as a primary identifier in signed/hashed artifacts; it is an auxiliary mapping. Primary IDs remain self-certifying.

#### 1.7.5b Canonical identity text grammar (normative)

Identity parsing is security-critical and MUST be deterministic across implementations.

**ABNF (normative):**

```
HEXDIG-lower = %x30-39 / %x61-66
hash64       = 64HEXDIG-lower

pkid         = "pkid:v1:ed25519:blake3:" hash64
cell_id      = "cell:v1:blake3:" hash64
holon_id     = "holon:v1:blake3:" hash64
spiffe_id    = "spiffe://" trust-domain "/apm2/cell/" cell_id "/holon/" holon_id
```

**Normative rules:**
1) Implementations MUST reject uppercase hex, whitespace, Unicode normalization variants, and percent-decoding tricks.
2) Parsing MUST be single-pass and size-bounded before allocation.
3) Canonical binary encodings for hashing/signing MUST be independent of text forms (text is projection only).
4) Any parser accepting legacy aliases MUST normalize to canonical forms before policy evaluation and MUST emit a migration defect signal.

#### 1.7.6 Certificates (normative)

HSI introduces two certificates as CAS artifacts:

1) **CellCertificateV1** (`apm2.cell_certificate.v1`) — binds a `cell_id` to:
   - `trust_domain`
   - `ledger_genesis_hash` (or consensus genesis)
   - `policy_root` verification parameters:
     - `policy_root_key_id` (single) OR `quorum_key_id` (threshold)
     - OPTIONAL `validators[]` (for multi-sig quorum mode)
   - `revocation_pointer` (how to discover revocation / rotation events)
   - OPTIONAL federation-root attestation pointer (if federation-rooted trust is active)

2) **HolonCertificateV1** (`apm2.holon_certificate.v1`) — binds a `holon_id` to:
   - `cell_id`
   - `holon_genesis_public_key_id` + `holon_genesis_public_key_bytes`
   - `holon_operational_public_key_id` + `holon_operational_public_key_bytes`
   - OPTIONAL `prev_operational_public_key_id` (for overlap during rotation)
   - OPTIONAL `spiffe_id` mapping
   - OPTIONAL endpoint hints (relay endpoints, if the holon is routable)
   - OPTIONAL purpose tags: `AGENT`, `RELAY`, `OPERATOR`, `VALIDATOR`

3) **SessionKeyDelegationV1** (`apm2.session_key_delegation.v1`) — binds a short-lived `session_public_key_id` to:
   - `holon_id`
   - `issuer_operational_public_key_id`
   - `issued_at_envelope_ref` + `expires_at_tick` (HTF references; wall time forbidden)
   - signature by the holon operational key
   - OPTIONAL `channel_binding` (handshake transcript hash)

Normative: Session keys are never directory-admitted. They are validated by delegation or handshake and are cacheable per-session.

**Certificate validity model (normative):**
- Certificates MUST NOT depend on wall-clock time for enforcement.
- Validity and revocation MUST be represented via **ledger-anchored commitments**:
  - a certificate is valid relative to a `HolonDirectoryHeadV1` (see §1.7.7) and the ledger anchor bound into that head.

#### 1.7.7 Directory heads + O(log n) identity proofs (normative)

To prevent O(n) scans and to support revocation at 10^12 scale, each cell maintains an **authenticated dictionary**
(an authenticated map / ADS), not a rebuild-every-epoch ordered list.

**HolonDirectoryHeadV1** (`apm2.holon_directory_head.v1`, CAS) MUST include:
- `cell_id`
- `directory_epoch` (monotone per cell)
- `ledger_anchor` (seq_id + event_hash OR a consensus index)
- `directory_root_hash` (commitment to the directory state)
- `directory_kind`:
  - `SPARSE_MERKLE_256_V1` (allowed; SMT over 256-bit keys)
  - `PATRICIA_TRIE_V1` (allowed; key-compressed authenticated trie)
- `entry_count`
- `max_proof_bytes` (explicit bound; prevents DoS independent of tree shape)
- `identity_proof_profile_hash` (CAS pointer to IdentityProofProfileV1; verification economics contract)
- `authority_seal_hash` (see §1.7.8) by the cell policy root / quorum
- OPTIONAL: `prev_head_hash` (hash-chains head evolution for audit; REQUIRED if cell runs without BFT)

**Default directory kind (normative):** implementations SHOULD default to `PATRICIA_TRIE_V1` at large `n` because proofs are
typically smaller in practice. `SPARSE_MERKLE_256_V1` remains valid but SHOULD use compressed proofs and MUST respect `max_proof_bytes`.

**Directory representation (normative):**
The directory is an authenticated key-value map:
- Key: `K = blake3("apm2:dir_key:v1\n" + holon_id_bytes)` (256-bit)
- Value: `V = holon_certificate_hash || status || effective_from_anchor`
  - `status ∈ {ACTIVE, REVOKED}` (minimum)
  - `effective_from_anchor` is a ledger anchor or HTF ref defining when the status took effect

Updates MUST be incremental (O(log n) node updates) and MUST NOT require rebuilding over all entries.

**IdentityProofV1** (`apm2.identity_proof.v1`, CAS) MUST include:
- `cell_certificate_hash` (unless direct trust is pinned)
- `holon_certificate_hash`
- `holon_directory_head_hash`
- `directory_proof` proving that (K -> V) is committed by the head.
  - proof MUST represent membership (`ACTIVE`/`REVOKED`) or non-membership (`ABSENT`),
  - proof MUST be bounded by `max_proof_bytes` and carry explicit proof byte length pre-decode.
- `as_of_anchor` (copied from the directory head; used for freshness checks)

**Identity verification algorithm (normative):**
Given `(holon_id, identity_proof_hash)`:
1) Fetch and verify `IdentityProofV1` from CAS (bounded decoding).
2) Verify `CellCertificateV1` (direct trust pin or federation-rooted trust per §2.4.7).
3) Verify `HolonCertificateV1` is correctly formed:
   - recompute `holon_genesis_public_key_id` from genesis key material
   - recompute `holon_id` from `(cell_id, holon_genesis_public_key_id)`
   - require equality with claimed `holon_id`
   - verify operational key material is present and well-formed for authorization use
4) Verify `HolonDirectoryHeadV1.authority_seal_hash` under the cell’s policy root/quorum.
5) Verify the ADS proof (`directory_proof`) against `HolonDirectoryHeadV1.directory_root_hash`.
6) Freshness + revocation semantics:
   - The verifier MUST enforce the configured `FreshnessPolicy` for the relevant RiskTier.
   - Tier2+: if head is stale or unverifiable, deny actuation.
7) Require that the head’s `ledger_anchor` is within the verifier’s admitted trust range for that cell (view commitment / admission receipt).

Complexity:
- Proof verification is **O(log n)** hashing work with bounded proof bytes; signature/quorum verification is amortizable by caching the verified directory head.

#### 1.7.7a DirectoryProofV1 (normative shape)

To keep verification bounded and decoder-safe, HSI standardizes an explicit proof object:

`DirectoryProofV1` MUST include:
- `kind`: `SMT_256_COMPRESSED_V1` | `PATRICIA_COMPRESSED_V1`
- `key` (directory key K)
- `value_hash` (membership value hash or default-empty hash for non-membership)
- `proof_nodes[]`
- `proof_structure` (compact encoding needed to reconstruct root deterministically)

**Normative rule:** verifiers MUST reject proofs exceeding `max_proof_bytes` or local `max_nodes` limits, even if cryptographically valid.

#### 1.7.7b IdentityProofProfileV1 (normative)

To make “O(log n)” operational (not rhetorical), each directory head MUST reference an explicit
**IdentityProofProfileV1** (`apm2.identity_proof_profile.v1`, CAS) containing:

- `directory_kind`
- `max_depth`
- `max_proof_bytes`
- `max_non_default_siblings` (if sparse structure is used)
- `supports_membership_multiproof` (bool)
- `supports_non_membership_proof` (bool)
- `verifier_cost_target`:
  - `max_hash_ops_per_membership_proof`
  - `max_signature_or_quorum_checks_per_cached_head`
  - `max_bytes_fetched_for_verification`

**Normative scale target:** For `n <= 10^12` admitted holons in a cell namespace, a conforming profile MUST provide:
1) membership verification with O(log n) (or better) hashing work and bounded proof bytes,
2) non-membership verification under the same asymptotic class,
3) cacheability such that verifying K identities against the same head requires O(1) signature/quorum checks for the head plus O(K log n) hashing.

**Operational floor (recommended baseline profile):**
- `max_proof_bytes <= 8192`
- `max_hash_ops_per_membership_proof <= 96`

Cells MAY use different data structures, but they MUST advertise and enforce a profile that meets the scale target.

#### 1.7.7c Verifier cache contract (normative)

Verifiers MUST treat proof verification as a two-level cache problem:
1) **Head cache** keyed by `holon_directory_head_hash` (signature/quorum-verified commitment),
2) **Proof cache** keyed by `(holon_id, holon_directory_head_hash)` (membership/non-membership proof result).

Cache entries MUST be invalidated when:
- a newer head for the same cell is admitted and FreshnessPolicy requires upgrade, OR
- revocation/rotation events force stricter admissibility for the relevant RiskTier.

This contract is mandatory to keep identity checks amortized under high fanout relay topologies.

#### 1.7.7d IdentityMultiProofV1 (normative shape)

For high fanout verification, implementations SHOULD support shared multiproofs across many identities under one head.

`IdentityMultiProofV1` MUST include:
- `holon_directory_head_hash`
- `holon_ids[]` (canonically sorted)
- `proof_nodes[]`
- `proof_structure`

Complexity target: O(1) head verification plus O(K log n) hashing with shared proof nodes.

#### 1.7.8 Attestation envelopes (normative)

HSI defines an abstract **AuthoritySeal** that can authenticate:
- a single artifact hash, OR
- a Merkle root that commits to many artifacts (batch attestation).

**AuthoritySealV1** (`apm2.authority_seal.v1`, CAS) MUST include:
- `issuer_cell_id`
- `issuer_public_key_id` OR `issuer_quorum_id`
- `subject_kind` (schema id + version)
- `subject_hash` OR `subject_merkle_root_hash`
- `ledger_anchor` (REQUIRED)
- `time_envelope_ref` (HTF; REQUIRED for GOVERNANCE and Tier2+ actuation receipts)
- `seal_kind`:
  - `SINGLE_SIG` (one Ed25519 signature)
  - `QUORUM_MULTISIG` (≥ 2f+1 validator signatures)
  - `QUORUM_THRESHOLD` (one threshold signature; optional implementation)
  - `MERKLE_BATCH` (signature/quorum over `subject_merkle_root_hash`)

**Normative rule:** Any reference in HSI to a “signed receipt / signed head / signed fact” is satisfied if the artifact is
authenticated by a valid `AuthoritySealV1` binding either the artifact hash directly or a Merkle root that includes it (§9.5).

### 1.8 FreshnessPolicyV1 (normative)

Non-stationarity is a security problem: stale identity ⇒ unverifiable revocation; stale policies ⇒ confused deputy.
Therefore HSI defines a machine-checkable freshness contract.

**FreshnessPolicyV1** (`apm2.freshness_policy.v1`, CAS) MUST define, at minimum:
- `max_identity_head_ledger_lag_by_risk_tier` (unitful integer lag from local admitted ledger anchor)
- `max_policy_digest_ledger_lag_by_risk_tier`
- `max_stop_state_ledger_lag_by_risk_tier`
- `staleness_action_by_risk_tier`:
  - `ALLOW_READONLY`
  - `DENY_ACTUATION`
  - `TERMINATE_SESSION`

**Normative rule:** Any verifier enforcing Tier2+ actuation MUST apply FreshnessPolicy. If policy is missing, unverifiable,
or ambiguous, it MUST default to the strictest action (`DENY_ACTUATION`) per constraint precedence.

**Optional (cell-local only, normative when used):**
- `max_identity_head_tick_lag_by_risk_tier` MAY be used only when issuer and verifier share one authoritative HTF tick domain.
- Cross-cell verification MUST NOT compare remote monotonic ticks directly; it MUST rely on ledger-anchor lag + admission evidence.

#### 1.8.1 Freshness Surfaces and Storage (normative)

Freshness is enforced on two distinct surfaces:

1) **Episode reproducibility surface (immutable):** the execution input pinset for an episode.
2) **Authority validity surface (runtime):** freshness of identity/policy/stop-state witnesses at decision time.

HSI therefore requires a canonical pinset artifact:
- **FreshnessPinsetV1** (`apm2.freshness_pinset.v1`, CAS) binds reproducibility-critical pins, including at minimum:
  - repo/lockfile/policy/toolchain/model profile digests,
  - contract/profile attribution digests (`cli_contract_hash`, `adapter_profile_hash`, `role_spec_hash`) when present,
  - view/context commitment pointers (`context_pack_hash` or equivalent view commitment binding).

**Storage rule (normative):**
- Episode envelopes MUST bind the pinset by digest (`freshness_pinset_hash` or an equivalent deterministic pinned-snapshot commitment hash).
- Authoritative receipts MUST bind `episode_envelope_hash`; this transitively binds the pinset.
- Ledger events SHOULD carry pinset/envelope pointers, not duplicated pin payload bytes.

**Runtime rule (normative):**
- For Tier2+ actuation, verifiers MUST evaluate authority freshness (identity head, effective policy digest, stop-state witness) under `FreshnessPolicyV1`.
- Missing, stale, or ambiguous freshness authority at Tier2+ MUST fail-closed (`DENY_ACTUATION` or stricter tier policy action).

### 1.9 HTF-anchored epoch sealing + VDF delay proofs (normative shape)

RFC-0016 establishes HTF as the authoritative time substrate. HSI adds an optional but federation-critical
anti-rollback primitive: **EpochSealV1** (`apm2.epoch_seal.v1`, CAS).

`EpochSealV1` binds:
- `cell_id`
- `directory_epoch` and/or `receipt_batch_epoch`
- `htf_time_envelope_ref` (authoritative time witness per RFC-0016)
- `sealed_root_hash` (directory root or receipt batch-epoch root)
- `quorum_anchor` (RFC-0014 checkpoint / quorum-certified ledger anchor)
- OPTIONAL `vdf_scheme`, `vdf_input_hash`, `vdf_output`, `vdf_difficulty`
- `authority_seal_hash`

**Why VDF here:** in cross-cell adversarial settings, VDF-sealed epochs add an objective sequential-work
barrier against “rapid-fork replay” and equivocation flooding without requiring global synchronous clocks.

**Normative rules:**
1) Tier2+ cross-cell authority claims (identity directory heads, permeability grants, batch roots) MUST reference a verifiable `EpochSealV1` or an equivalent quorum-certified HTF envelope.
2) If `vdf_scheme` is present, verifiers MUST verify the VDF proof before accepting the epoch as freshness authority.
3) Cells running pure local mode MAY omit VDF fields, but MUST still provide HTF + quorum anchors.
4) Epoch seals MUST be monotone in `(htf_time_envelope_ref, quorum_anchor)` for a given `cell_id`; non-monotone seals are replay defects.

---

## 2. System model: microkernel ACI for agentic SDLC

### 2.1 Why “CLI as syscall surface” is foundational

Empirically, specialized agent-computer interfaces (ACIs) can dominate model choice for software engineering tasks:
tool discoverability, state navigation, and feedback loops matter.

HSI commits to a single ACI for all agents:
- not bespoke prompt conventions per vendor,
- not ad-hoc shell access per role,
- not “folklore” glued into memory.

**Design target:** `apm2` commands are ergonomic wrappers around a small, stable syscall vocabulary whose schemas are
machine-checkable and whose semantics are receipt-backed.

**Normative clarification (contract layering):**

- The **trust boundary** is the daemon enforcement layer.
- The **contract boundary** is the daemon’s *HSI syscall ABI* (schemas + semantics), not the CLI’s text UX.
- The CLI is a *projection* that MUST NOT introduce new semantics. CLI output intended for machines MUST be available
  as structured outputs (`--json` / protobuf), and all authoritative outcomes MUST be provable by receipts.

Adapters (vendor CLIs, black-box runtimes) are permitted as untrusted projections, but MUST transit the same syscall
ABI and MUST NOT bypass receipts, budgets, or capability gating.

#### 2.1.1 Session-typed syscall state machine (normative)

HSI interactions MUST conform to a simple session type to prevent “half-handshake” ambiguity:

1) `DISCOVERY` → contract hash + feature negotiation (no evidence, no authority)
2) `HANDSHAKE` → bind session to `cell_id`, policy root, and active envelope/manifest hashes
3) `WORK` → exchange hints, selectors, and intents (advisory unless receipt-backed)
4) `EVIDENCE` → retrieve receipt pointers and indexed evidence chunks (digest-first)
5) `GOVERNANCE` → low-bandwidth, signed control messages (stop orders, policy/contract root updates, revocations)

Implementations MUST reject messages that violate the session type for the declared `channel_class`.

### 2.2 Microkernel decomposition

```
+---------------------------+       +------------------------------+
| Agent Capsule (UNTRUSTED) |  IPC  | apm2-daemon (TRUSTED kernel) |
|  - agent runtime          |<----->|  - policy + leases + OCAP     |
|  - vendor adapter         |       |  - tool broker + sandboxing    |
|  - apm2 client            |       |  - ledger + CAS emission       |
+---------------------------+       +------------------------------+
                                           |
                                           | projections (untrusted)
                                           v
                                +-------------------------+
                                | External systems        |
                                |  - GitHub/forge         |
                                |  - CI runners           |
                                |  - artifact registries  |
                                +-------------------------+
```

**Key claim:** the daemon is the only place enforcement can be trusted. CLI and adapters are projections.

### 2.2.1 Markov blanket interpretation (non-normative, but design-constraining)

For holonic recursion to remain stable, each holon boundary must behave like a **Markov blanket**:
- **Sensory states** (what the holon can observe) map to **context reads** through ContextPack/ContextDelta selectors.
- **Active states** (how the holon can affect the world) map to **tool actuation** through ToolKinds.
- **Internal states** (model reasoning, planning traces) are explicitly *non-authoritative* unless committed into CAS and bound by receipts.

This interpretation is not metaphysics; it is an engineering constraint:
it forces every “interaction with reality” to cross a small number of typed, receipt-backed channels,
which is the only way a recursively nested holarchy can remain auditable and governable at exabyte scale.

### 2.3 Holonic Boundary Model: ordered channels (normative)

HSI recognizes five channel classes. These are not an optimization; they are required to keep recursion tractable and
to prevent “truth leakage” across boundaries.

1) **Discovery channel (D):** “Who are you / what versions / what features exist?”
   - Allowed payloads: version ids, contract hashes, feature flags, directory announcements.
   - Forbidden payloads: raw evidence, raw diffs, raw logs.

2) **Handshake channel (H):** “What is the current trust/authority boundary?”
   - Allowed payloads: `cell_id`, policy-root key ids, session open/close, episode envelope hash, capability manifest
     hash, adapter profile hash, role spec hash, view commitment hash.
   - Forbidden payloads: raw evidence; any new authority not justified by a PermeabilityReceiptV1.

3) **Work channel (W):** “Do work, but treat messages as hints unless backed by receipts.”
   - Allowed payloads: pulses, scheduling hints, context selectors, tool request intents, defect fingerprints.
   - Forbidden payloads: assertions of world state unless bound to receipts/commitments.

4) **Evidence channel (E):** “Zoom-in and verify.”
   - Allowed payloads: receipt pointers, ToolLogIndexV1 pointers, evidence selectors, CAS hashes, summary receipts with
     loss profile.
   - Forbidden payloads: unindexed raw log streams; non-addressed blobs above threshold.

5) **Governance channel (G):** “Stop, revoke, rotate, and ratchet—without ambiguity.”
   - Allowed payloads: stop orders, revocations, policy root rotation announcements, contract ratchet updates.
   - Requirements: MUST be signed/attested, MUST be replay-protected (HLC + monotone sequence per issuer).
   - Forbidden payloads: raw evidence, raw diffs/logs, or any high-bandwidth data.

HSI implementations MUST enforce per-channel budgets (bytes, rate, and fanout) to prevent holonic blowups.

### 2.4 Federation extension: cells, relays, and anti-entropy (normative shape, staged implementation)

HSI is cell-local by enforcement, but federation MUST use stable wire shapes from day 1 so we do not fork the
protocol later.

#### 2.4.0 Control-plane vs data-plane separation (normative)

Federation is only stable at scale if we separate:

- **Control-plane facts** (Ledger events + receipts): require signature/quorum verification; replicated via anti-entropy over bounded ranges; never “trusted because forwarded.”
- **Data-plane evidence** (CAS artifacts): content-addressed, chunked, deduplicated; replicated by hash under explicit allowlists/budgets; integrity is by hash; admissibility is by receipts/commitments.

Relays MUST NOT blur these planes. “Forwarded bytes” are not facts.

#### 2.4.0b Admission receipts (normative)

Cross-cell replication creates a second-order truth hazard: “I saw it in another cell” is not the same as “my cell admits it as fact.”
Therefore, any cross-cell ingestion of:
- ledger event ranges, OR
- policy root/cell certificates, OR
- permeability grants,
MUST emit an **AdmissionReceiptV1** (or ImportReceiptV1) in the receiving cell that binds:

- sender cell id + sender policy root key id (observed),
- the admitted range/hash set (exact),
- verification method (signature/quorum validation result),
- local ledger anchor at time of admission (so admission itself is auditable),
- and any rejection reasons for omitted elements.

Without an AdmissionReceipt, replicated bytes MUST be treated as untrusted cache, not truth-plane facts.

#### 2.4.1 Cell identity

Each cell has:
- `cell_id` (stable self-certifying identifier; see §1.7.3)
- `cell_certificate_hash` (CAS pointer to CellCertificateV1; required for federation)
- `policy_root_key_id` (key id, not private material) OR `quorum_key_id` (threshold/quorum verification key id)
- `ledger_genesis_hash` and `ledger_head_hash`
- `cas_root` (content-addressed namespace root)

**Normative rule:** any cross-cell message that asserts or carries authority MUST be verifiable against a `CellCertificateV1`
chain (direct trust pin or federation-rooted trust) and MUST NOT rely on unauthenticated `cell_id` strings.

#### 2.4.2 Relay holon

A **relay holon** is a constrained gateway process that:
- terminates cross-cell connections,
- performs capability narrowing,
- performs digest-only forwarding by default,
- and emits receipts for cross-cell message forwarding.

Relays MUST NOT have ambient authority over downstream cells. They are policy-enforced routers, not a “global kernel.”

#### 2.4.3 Holon directory

Federation requires a directory primitive (can be cell-local first, then federated) that supports:
- `holon_id -> relay endpoints` mapping (digest-first)
- capability of routing a message to the nearest eligible relay
- partition-tolerant updates (eventual consistency)

Directory announcements MUST be signed and rate-limited.

**Upgrade (normative):** the directory MUST also provide **identity membership proofs** at O(log n) (see §1.7.7):
- directory state MUST bind `holon_id -> holon_certificate_hash` (at minimum),
- and publish a signed `HolonDirectoryHeadV1` that verifiers can cache.

Messages that require authenticated identity MUST carry an `IdentityProofV1` pointer (hash) rather than raw certificates.
This keeps the wire digest-first and keeps verification bounded.

**Sybil and DoS stance (normative):**
- A cell MUST NOT accept directory announcements from unauthenticated issuers.
- Directory announcements MUST be bound to a policy root identity (or a federation-root attestation) and replay-protected.
- Directory replication SHOULD use a signed CRDT (state-based or delta-based) so that partitions converge without a central coordinator, while still rejecting unauthenticated updates.

**Directory CRDT constraint (normative):**
- the CRDT payload MUST NOT be treated as “truth” by forwarding alone.
- truth is the signed head commitment (`HolonDirectoryHeadV1`) plus the ledger/admission anchor that introduced it.

#### 2.4.3b Revocation-wins signed CRDT law (normative)

For identity safety, directory convergence MUST use a **revocation-wins** conflict law.

Let each directory element be:
`Entry = (holon_id, holon_certificate_hash, status, causal_dot, effective_anchor)`
where `status ∈ {ACTIVE, REVOKED}`.

Merge MUST satisfy:
1) Commutative, associative, idempotent (CRDT baseline).
2) If two concurrent entries disagree on status, `REVOKED` dominates unless there is an explicit later re-admission event
   with strictly greater `effective_anchor` and policy-root authorization.
3) Re-admission after revocation MUST bind either:
   - key rotation (`holon_certificate_hash` change), or
   - a policy-root-signed waiver receipt with bounded HTF validity.
4) Every CRDT delta MUST be signed by an admitted issuer and replay-protected (`hlc_timestamp + monotone sequence`).

This law prevents resurrection-by-race under partition and keeps revocation semantics monotone under anti-entropy.

#### 2.4.4 Anti-entropy replication (ledger + CAS pointers)

Cross-cell convergence MUST use anti-entropy, not “push full history”:
- exchange checkpoint commitments (ledger head hashes)
- exchange bloom-like summaries or range digests
- request missing event ranges and referenced CAS artifacts by hash

The protocol MUST be safe under reordering, duplication, partial delivery, and adversarial peers.

**Set reconciliation options (normative shape):**
Implementations MAY use:
- Merkle range trees (baseline),
- Merkle Mountain Range (MMR) over an append-only ledger (preferred for incremental replication), or
- IBLT/Minisketch-style set reconciliation for “missing hash” discovery,
provided all deliveries remain pull-based and bounded by receiver budgets.

Relays MAY provide bandwidth shaping and backpressure signals, but MUST NOT rewrite facts.

#### 2.4.5 Byzantine stance (normative)

HSI MUST assume cross-cell peers and relays may be **Byzantine**. Therefore:

- All cross-cell ledger events MUST be verified by signature / quorum attestation before being admitted as “facts”.
- Anti-entropy MUST be pull-based: a receiver requests specific ranges/hashes; senders MUST NOT be able to force
  large unsolicited payloads.
- Any directory announcement or permeability grant MUST be signed and MUST be replay-protected (HLC timestamp +
  monotone sequence per issuer).

#### 2.4.6 Merkle anti-entropy wire shape (normative)

Anti-entropy negotiation MUST be expressed as:

1) `OFFER`: `(cell_id, ledger_head_seq, ledger_head_hash, merkle_root_hash, range_bounds, max_leaves)`
2) `COMPARE`: request subtree/range digests by `(range_start, range_end, depth)`
3) `REQUEST_EVENTS`: request missing events by `(seq_start, seq_end)` plus expected range digest
4) `DELIVER_EVENTS`: deliver events for the requested range (bounded), each event signed/attested

Bounds:
- `max_leaves` MUST be capped (e.g., ≤ 2^20) to prevent DoS via tree construction.
- Proof sizes MUST be bounded (≤ O(log max_leaves)).

The receiver MUST verify:
- delivered range digest matches requested digest,
- each event’s signature/attestation,
- causal links (parents) where required.

#### 2.4.7 Policy rooting and cross-cell trust bootstrap (normative shape)

Cross-cell verification requires a concrete answer to: “Which keys do I trust for this cell?”

HSI supports two bootstraps (both federation-ready; staged rollout decides which is active):

1) **Direct trust** (small federation / early stages): operators pin `cell_id -> policy_root_key_id` out-of-band.
2) **Federation-rooted trust** (civilizational scale): a federation root (or quorum) issues signed `CellCertificate` objects binding:
   - `cell_id`
   - `policy_root_key_id`
   - `ledger_genesis_hash`
   - validity window + revocation pointers

Cells MUST treat unauthenticated peer keys as Byzantine by default.

#### 2.4.8 Trust-liveness coupling with HTF and VDF (normative shape)

Federation liveness must not undermine freshness/security. Therefore:

1) Cross-cell admission of authority-bearing artifacts MUST enforce both:
   - **Trust validity:** certificate/quorum chain verifies, and
   - **Temporal validity:** referenced `htf_time_envelope_ref` satisfies local FreshnessPolicy.
2) If a peer advertises `EpochSealV1` with VDF, receivers SHOULD prefer the highest verified seal within policy bounds,
   and MUST reject seals that regress in `(htf_time_envelope_ref, quorum_anchor)`.
3) Under partition, receivers MAY continue read-only operations with stale-but-bounded seals (Tier0/Tier1),
   but Tier2+ actuation MUST fail-closed when freshness cannot be re-established.

This couples trust and liveness without introducing wall-clock authority.

### 2.5 Closure under composition (holonic recursion)

A protocol scales holonically if composing holons does not require inventing a new interface layer.

HSI enforces closure by making these artifacts the only cross-boundary primitives:
- `CapabilityManifestV1` for delegated authority (OCAP)
- `ContextPack` and `ContextDelta` for bounded cognition
- `ToolExecutionReceipt` and `ToolLogIndexV1` for actuation evidence
- `SummaryReceipt` for iteration interface
- `HMPMessageV1` envelope for digest-first messaging

Additionally, HSI introduces:
- `EpisodeEnvelopeV1` as the immutable commitment object for an execution attempt
- `ViewCommitmentV1` as the “what world did you see?” boundary for cognition and receipts
- `PermeabilityReceiptV1` as the only admissible cross-holon authority entrance (see §8.3)

A coordinator holon can be implemented as:
- a single process,
- a cluster,
- or a logical wrapper over other holons,

without changing the message shapes or contracts.

### 2.6 Observational equivalence under recursion (bisimulation gate) (normative)

HSI is required to remain stable under arbitrary holonic recursion. Stability here is not rhetorical: it is a *semantic*
constraint that MUST be mechanically checkable.

#### 2.6.1 Observable semantics (normative)

Define the **observable trace** of a holon execution as the sequence of:
- ledger facts admitted by the cell (events + admission receipts),
- CAS artifacts referenced by those facts (by hash),
- and governance actions (stop/revoke/rotate) that are signed/attested.

All WORK-channel messages, pulses, and internal planner traces are **non-authoritative** and are treated as `?` (silent)
steps in the semantic model unless they are explicitly bound into receipts/ledger facts.

#### 2.6.2 Flattening (normative)

Define `flatten(N)` as the transformation that:
1) removes holonic boundaries internal to depth `N`,
2) preserves all ledger/CAS/receipt facts, and
3) preserves delegation semantics by retaining `permeability_receipt_hash` bindings and `delegation_chain_hash` commitments.

Flattening MUST NOT invent authority: the transformed trace is valid iff all effects are still justified by the same
AuthorityVector meet constraints (§8.3.2).

#### 2.6.3 Bisimulation requirement (normative)

For any composed holon system `H` with recursion depth `N ≤ 12`, the observable trace produced by `H` MUST be
**weakly bisimilar** to the observable trace produced by `flatten(N, H)`:

- internal (WORK-channel) steps may differ,
- but the externally observable facts (ledger-admitted events + attested receipts) MUST match up to:
  - **α-renaming of internal holon ids** that do not cross the boundary being observed, and
  - re-chunking/re-batching of attestations that preserves verifiability (e.g., direct signatures vs batched attestations).

This bisimulation is the mechanical statement of “holonic closure under composition” and is required to prevent semantic drift
as recursion depth increases.

#### 2.6.4 Mechanical verification artifact (normative)

Promotion of any enforcement ratchet stage S1+ MUST maintain a checked artifact proving the bisimulation gate for
`N ≤ 12` under a bounded model:
- session-type ordering constraints (§2.1.1 and §2.3),
- stop/budget checks,
- capability gating,
- delegation meet operator correctness,
- and anti-entropy pull-boundedness (§2.4).

Acceptable implementations:
- TLA+/PlusCal model with bounded instantiation + trace equivalence check, OR
- a finite-state abstraction plus an automated weak bisimulation checker, OR
- proof assistant formalization (Lean/Coq) with extracted checker for the bounded case.

#### 2.6.5 Functorial composition law (category-theoretic, normative intent)

To prevent semantic drift across implementation rewrites, HSI adopts a composition law:

- Define a category `HolExec` where:
  - objects are boundary states `(Identity, Capability, Context, Governance)`,
  - morphisms are receipt-producing transitions admitted by policy.
- Define a category `ObsFacts` where objects are fact-sets and morphisms are monotone ledger/CAS extensions.
- Define `Obs : HolExec -> ObsFacts` as the observation functor.

Required properties:
1) **Identity preservation:** `Obs(id_X) = id_Obs(X)`.
2) **Composition preservation:** `Obs(g ∘ f) = Obs(g) ∘ Obs(f)`.
3) **Flattening naturality:** flattening introduces a natural transformation `η_N : Obs∘Nest_N => Obs∘Flatten_N`
   whose components are isomorphisms for `N <= 12` under the bisimulation gate.

Engineering consequence: any optimization (batching, relay routing, planner decomposition, cache rewrite) is admissible
only if it preserves `Obs` under these laws.

--- 

## 3. HSI contracts (normative)

### 3.1 HSIContractManifestV1 (static contract)

**Artifact:** `apm2.hsi_contract.v1` (CAS)

**Purpose:** canonical inventory of syscalls:
- canonical route (e.g., `hsi.context.malloc`)
- request/response schema ids
- semantics: authoritative vs advisory
- idempotency requirements
- receipt obligations and binding fields
- stability classification: experimental/stable/deprecated

#### 3.1.1 Generation and determinism

The contract MUST be generated from the same registry used to dispatch CLI commands and daemon RPC routes.
Missing annotations MUST fail the build.

Determinism requirement:
- identical code + build inputs -> identical `cli_contract_hash`
- any semantic change -> different hash

#### 3.1.2 Binding

`cli_contract_hash` MUST be included in:
- session handshake,
- episode start events,
- tool receipts,
- review artifacts.

#### 3.1.3 Fail-closed behavior

If `cli_contract_hash` mismatches between client expectation and daemon active contract:
- at low risk tiers (Tier0/Tier1): downgrade session to read-only
- at high risk tiers (Tier2+): deny spawn (or require an explicit waiver)

The downgrade/deny policy is controlled by the enforcement ratchet stage.

#### 3.1.4 Example excerpt

```json
{
  "schema": "apm2.hsi_contract.v1",
  "schema_version": "1.0.0",
  "cli_version": { "semver": "0.9.0", "build_hash": "sha256:..." },
  "commands": [
    {
      "id": "CTX_MALLOC",
      "route": "hsi.context.malloc",
      "stability": "STABLE",
      "request_schema": "apm2.context_malloc_request.v1",
      "response_schema": "apm2.context_malloc_response.v1",
      "semantics": { "authoritative": true, "idempotency": "REQUIRED" }
    }
  ],
  "receipts": { "required_for_authoritative_commands": true }
}
```

### 3.2 CapabilityManifestV1 (dynamic delegation)

**Artifact:** `apm2.capability_manifest.v1` (CAS)

**Purpose:** prove what authority is delegated to an episode:
- which sealed capabilities exist (tool classes),
- with what scopes (paths/patterns/size/network),
- which global allowlists apply (tool mediation + HEF),
- TTL/expiry and delegator identity,
- and what minimum risk tier is required for each capability.

#### 3.2.1 Minting

Capability manifests are minted by **policy resolution**, not by requesters.
Episodes cannot self-grant; they can only request execution under already-granted handles.

#### 3.2.2 Constraint language (v1)

To avoid a full policy DSL, v1 constraints are structural and map directly to daemon enforcement types:

- `CapabilityScope.root_paths`: allowed filesystem roots for tool operations
- `CapabilityScope.allowed_patterns`: file glob allowlist within root paths
- `CapabilityScope.size_limits`: bounded read/write/command/response bytes
- `CapabilityScope.network_policy`: host/port allowlist + TLS requirement
- `Capability.risk_tier_required`: minimum RiskTier required to invoke

Additionally, HSI supports *mediation allowlists* at manifest scope:

- `tool_allowlist`: coarse tool class allowlist (fail-closed if empty)
- `write_allowlist`: explicit write paths (fail-closed if empty)
- `shell_allowlist`: explicit shell patterns (fail-closed if empty)
- `topic_allowlist`: allowed pulse topics (HEF, fail-closed)
- `cas_hash_allowlist`: allowed CAS reads (HEF, fail-closed)

All constraint checking is enforced by the daemon/tool broker, not the agent.

#### 3.2.3 Binding into receipts

Every `ToolExecutionReceipt` MUST bind:
- `episode_envelope_hash`
- `capability_manifest_hash`
- `role_spec_hash` (if applicable)
- `adapter_profile_hash` (if applicable)
- `context_pack_hash` (or context refs commitment)
- `cli_contract_hash`
- request hash and result hash

This enables replay and detection of confused-deputy attempts.

#### 3.2.4 Example manifest

```json
{
  "schema": "apm2.capability_manifest.v1",
  "schema_version": "1.0.0",
  "delegator_id": "holon:v1:blake3:...",
  "issued_at_envelope_ref": "blake3:...",
  "expires_at_tick": 9812739182,
  "tool_allowlist": ["GitRead", "GitDiff", "XTaskExec"],
  "topic_allowlist": ["work.W-*.events", "ledger.head"],
  "cas_hash_allowlist": [],
  "capabilities": [
    {
      "capability_id": "CAP-001",
      "tool_class": "GitRead",
      "risk_tier_required": "Tier0",
      "scope": {
        "root_paths": ["/workspace"],
        "allowed_patterns": ["**/*.rs", "**/*.toml", "Cargo.lock"],
        "size_limits": {
          "max_read_bytes": 10485760,
          "max_write_bytes": 0,
          "max_command_bytes": 1048576,
          "max_response_bytes": 10485760
        },
        "network_policy": { "allowed_hosts": [], "allowed_ports": [], "require_tls": true }
      }
    },
    {
      "capability_id": "CAP-002",
      "tool_class": "XTaskExec",
      "risk_tier_required": "Tier1",
      "scope": {
        "root_paths": ["/workspace"],
        "allowed_patterns": ["**/*"],
        "size_limits": {
          "max_read_bytes": 10485760,
          "max_write_bytes": 10485760,
          "max_command_bytes": 65536,
          "max_response_bytes": 10485760
        },
        "network_policy": { "allowed_hosts": [], "allowed_ports": [], "require_tls": true }
      }
    }
  ],
  "attestation_policy": { "min_attestation_level": "SOFT", "required_receipt_kinds": ["ToolExecutionReceipt"] }
}
```

### 3.3 EpisodeEnvelopeV1 (immutable execution commitment)

**Artifact:** `apm2.episode_envelope.v1` (CAS)

**Purpose:** provide a single immutable commitment object that binds:
- identity (`episode_id`, `actor_id`, `work_id`, `lease_id`)
- resource budgets (tool_calls, wall_ms, cpu_ms, bytes_io, evidence_bytes)
- stop conditions (max_episodes + predicates / structured gates)
- pinned snapshot of reproducibility inputs (repo hash, lockfile hash, policy hash, toolchain hash, model profile hash), represented by `freshness_pinset_hash` (or equivalent deterministic pinned-snapshot commitment)
- `capability_manifest_hash`, `cli_contract_hash`, `context_pack_hash` (or context refs)
- `risk_tier` and `determinism_class`
- OPTIONAL: `permeability_receipt_hash` when this episode is executing under delegated authority across a holonic boundary
- OPTIONAL: `delegation_chain_hash` (a compact commitment to the verified chain of delegations, for audit traversal at exabyte scale)

All authoritative receipts MUST bind `episode_envelope_hash`.

---

## 4. Agent Capsule (normative)

### 4.1 Threat being addressed

If the agent runtime can call `bash`, `git`, or `curl` directly, it can bypass all OCAP controls and receipts.
This breaks holonic recursion: higher-order holons can’t reason about the actions of lower-order holons because
side effects become non-replayable and non-indexed.

The capsule turns “use apm2” from a convention into a boundary.

### 4.2 Capsule profile interface

A capsule is defined by a **CapsuleProfile** (content-addressed, referenced by hash) that declares:
- process isolation primitive
- filesystem mapping rules
- network rules
- allowed executables
- environment scrubbing rules
- observability hooks (escape detection)

### 4.2.1 Defense-in-depth requirements (normative)

The capsule profile MUST be layered such that a single escape bug does not imply ambient authority:
- Namespaces (user/mount/pid) or equivalent containment
- syscall filtering (seccomp or equivalent)
- resource cgroups (cpu/mem/pids/io)
- filesystem sandboxing (mount rules + optional Landlock/AppArmor/SELinux)
- network namespace with explicit egress policy
- deterministic kill-switch integration (stop order)

Capsules MUST NOT inherit operator credentials or host environment secrets. Any required credentials MUST be
provisioned as scoped, expiring tool handles via daemon mediation, never as environment variables.

### 4.3 Linux MVP: `linux-ns-v1` profile

Minimum requirements (Tier3+ required; Tier1–Tier2 optional):
- user + mount + pid namespaces
- read-only base filesystem
- bind-mounted workspace root (scoped to the episode)
- tmpfs for `/tmp`
- network namespace with no external routes (deny-by-default)
- allowlisted executable set (adapter runtime + apm2 client)
- environment scrubbing (no credentials)
- timeouts and kill-switch integration

The daemon MUST emit:
- `CapsuleStarted{session_id, capsule_profile_hash, workspace_root_hash, network_policy}`
- `CapsuleViolation{session_id, violation_kind, evidence_refs[]}` on any escape attempt.

### 4.4 Stop-order behavior

Capsule processes MUST honor stop orders:
- `StopOrderIssued` must cause termination within a fixed deadline (e.g., 1–5s)
- missing/unknown stop state must default to deny actuation

Stop is treated as a governance primitive, not a convenience.

### 4.5 Context firewall semantics (normative)

HSI enforces a **context read firewall**:
- The capsule runtime MUST only read context through daemon-mediated context fetch calls.
- Any attempt to read outside the currently committed ContextPackManifest allowlist (or outside the allowed CAS hash
  allowlist) MUST trigger deny-by-default. For Tier3+ episodes, this MUST escalate to fail-closed termination of the
  session/capsule and emit a `CapsuleViolation` + denial receipt.
- “Deny and continue” is forbidden; it creates a covert channel and breaks auditability under adversarial prompts.

**Note:** Tier0/Tier1 MAY run the firewall in soft-fail mode strictly for developer ergonomics, but MUST still emit
receipts for denials and MUST enforce rate limits to prevent covert channels. Tier3+ MUST be hard-fail.

---

## 5. Syscall families (HSI vocabulary)

HSI syscalls are grouped into six families. For each syscall, the contract defines:
- canonical route,
- request/response schema,
- whether it is authoritative,
- required receipts and bindings,
- idempotency requirements.

### 5.1 Session + identity

**Routes (examples)**
- `hsi.session.open`
- `hsi.session.info`
- `hsi.contract.get`
- `hsi.capabilities.get`

**Session open request (example)**
```json
{
  "schema": "apm2.session_open_request.v1",
  "schema_version": "1.0.0",
  "client": {
	    "cli_contract_hash": "sha256:...",
	    "adapter_profile_hash": "sha256:...",
	    "holon_id": "holon:v1:blake3:...",
	    "identity_proof_hash": "blake3:...",
	    "session_key_id": "pkid:v1:ed25519:blake3:..."
	  },
	  "requested_features": ["HMP_V1", "CONTEXT_DELTA_V1"]
	}
```

**Session open response (example)**
```json
{
  "schema": "apm2.session_open_response.v1",
  "schema_version": "1.0.0",
  "session_id": "SES-...",
  "enabled_features": ["HMP_V1", "CONTEXT_DELTA_V1"],
  "daemon": {
    "cli_contract_hash": "sha256:...",
    "policy_version_hash": "sha256:...",
    "cell_id": "cell:v1:blake3:...",
    "cell_certificate_hash": "blake3:...",
    "holon_directory_head_hash": "blake3:...",
    "identity_proof_profile_hash": "blake3:...",
    "epoch_seal_hash": "blake3:..."
  }
}
```

**Normative session identity rules:**
1) `hsi.session.open` MUST fail-closed if `identity_proof_hash` is missing or unverifiable for any non-discovery channel usage.
2) The daemon MUST bind the verified `holon_id` to the `session_id` and MUST ignore any later attempt by the client to “change identity”.
3) If the session key is used for channel security (recommended for relays), `session_key_id` MUST be bound into the session record and into any governance message signatures for replay protection.
4) For Tier2+ sessions, the daemon MUST return a verifiable identity freshness witness (`epoch_seal_hash` or equivalent quorum+HTF witness) bound to the advertised directory head.
5) For Tier2+ sessions, the daemon MUST return a freshness-policy pointer (`freshness_policy_hash` or an equivalent `policy_version_hash` that resolves to FreshnessPolicyV1), and actuation MUST apply that policy fail-closed.

### 5.2 Work lifecycle + orchestration

- `hsi.work.claim`
- `hsi.work.status`
- `hsi.episode.spawn`
- `hsi.episode.resume`
- `hsi.orch.pulse.emit` (wakeups only)

**Important:** orchestration state is ledger-derived (projection), not process memory.

### 5.3 Context compilation (“malloc”)

- `hsi.context.malloc` → returns `context_pack_hash`
- `hsi.context.delta` → returns `context_delta_hash`

Context compilation is itself capability-gated (fetching selectors requires authority).
ContextPacks are sealed in CAS and bound to a view commitment.

#### 5.3.1 ContextPack vs ContextPackManifest (normative)

HSI distinguishes:

- **ContextPackManifest**: the OCAP allowlist for context reads, including per-entry content hashes and access levels.
- **ContextPack**: the materialized, indexed payload slices referenced by the manifest (optionally chunked).

**TOCTOU defense requirement:** any file content returned through context reads MUST be verified against the
manifest’s content hash. If the content hash does not match, the read MUST be denied and a violation receipt MUST
be emitted.

#### 5.3.2 Access levels (normative)

Each manifest entry MUST carry an access level:
- `Read`: permitted to read exactly the sealed bytes associated with the entry.
- `ReadWithZoom`: permitted to request deterministic sub-slices (line ranges / byte ranges) via selectors, bounded by budget.

Zoom-in MUST be selector-based and MUST remain bound to the original content hash.

### 5.4 Tool actuation (only actuator)

- `hsi.tool.request`
- `hsi.tool.result.fetch` (by hash, under capability constraints)

Tool requests MUST include:
- `tool_class` (ToolKind in CLI vocabulary; ToolClass in daemon enforcement)
- `idempotency_key` (required for side effects)
- `args` (schema-validated per tool class)
- `expected_capability_grant_id` (or grant selection rule)
- `taint_tags` (for flows from untrusted evidence)

Tool responses MUST include:
- `tool_execution_receipt_hash`
- `result_hash` (CAS)
- optional `summary_receipt_hash` for large outputs

### 5.4.1 ToolIntentV1 and adapter mediation (normative)

Adapters (vendor CLIs, IDEs, model runtimes) are explicitly untrusted projections.
To keep the syscall ABI stable under recursion, adapters MUST translate model outputs into a **ToolIntentV1** object
that is schema-validated prior to tool execution.

**Rule:** the daemon/tool broker MUST NOT accept raw “tool strings” from adapters for authoritative ToolKinds.

ToolIntentV1 MUST include:
- `tool_class` (ToolKind)
- `args` (typed object; schema version pinned)
- `idempotency_key` (required for any side effect)
- `preconditions[]` (ETag/HEAD/version pins for repeat safety)
- `input_evidence_refs[]` (CAS hashes that the intent depends on)
- `taint_tags` and `classification` (for dual-lattice gating)

**Headless requirement (normative):** Any adapter executing inside a capsule MUST run in a mode that:
- disables implicit tool invocation features (e.g., “auto-run shell”),
- disables background network activity unless mediated by HSI tools,
- emits a deterministic adapter profile hash in the handshake.

**Adapter drift (normative defect):**
If `adapter_profile_hash` differs from the hash pinned in the EpisodeEnvelope or PermeabilityReceipt:
- Tier0–Tier1 MAY downgrade to read-only,
- Tier2+ MUST deny actuation and emit a defect with fingerprint `(adapter_profile_hash, cli_contract_hash, episode_envelope_hash)`.

### 5.5 Evidence publish/fetch

- `hsi.evidence.publish` (CAS)
- `hsi.evidence.fetch` (by hash)

These are controlled by capability grants; context selection does not imply authority to fetch.

### 5.6 Governance/stop

- `hsi.governance.stop.get`
- `hsi.governance.stop.set` (operator-only)
- `hsi.governance.kill` (operator-only)

Stop checks are mandatory preconditions for tool actuation and episode spawn.

---

## 6. ToolKinds (normative)

### 6.1 Why ToolKinds rather than raw shell

ToolKinds define the capability boundary. They make:
- parameter constraints enforceable,
- receipts uniform and indexable,
- caching safe (CAS result hashes),
- and injection surfaces analyzable (taint tags).

Raw shell is treated as a transitional ToolKind (if allowed at all), never as ambient authority.

### 6.1.1 Tool argument safety (normative)

All ToolKinds that wrap external binaries (git, shell bridges, CLIs) MUST:
- treat all user/model-provided strings as hostile,
- reject flag-like arguments when refs are expected,
- validate that all filesystem paths resolve (after symlink resolution) under allowed roots,
- forbid “init-like” operations unless explicitly needed and separately allowlisted,
- and bound output size via index-first chunking.

Rationale: real-world tool servers have shipped with path validation bypass and argument injection vulnerabilities in
git-related tooling. Recent MCP Git server CVEs (CVE-2025-68143 / CVE-2025-68144 / CVE-2025-68145) demonstrate concrete exploit chains via
path traversal and argument injection; HSI MUST assume similar bug classes exist in any mediated tool wrapper and design
for containment by default.

### 6.1.2 Preconditions and idempotency (normative)

Any ToolKind capable of side effects MUST support both:

1) **Idempotency keys**: repeated submission with the same idempotency key MUST be at-most-once at the kernel boundary
   (result may be served from cache), scoped at minimum to `(episode_id, tool_kind, idempotency_key)`.
2) **Precondition guards**: requests MUST include explicit preconditions for external state that would make a repeat unsafe,
   e.g.:
   - expected `git_head_hash`
   - expected `forge_issue_etag`
   - expected `deployment_version`

If a precondition fails, the tool MUST return a denial/failure receipt (not a partial execution).

### 6.2 Minimal git/dev ToolKinds v1

Required in v1 (typed, non-stringly requests):
- `GitReadHistory` (bounded log query)
- `GitShowFileAtCommit` (path + commit; strict ref validation)
- `GitBlame` (path + commit; strict ref validation)
- `GitWorktreeCreate` (worktree name + base; no arbitrary paths)
- `GitDiff` (explicit base/target refs; ref validation + no flag-like args)
- `GitStatus` (no arguments)

**Constraints:**
- all paths must be under the episode workspace root
- git object refs must be validated (no arbitrary refspecs)
- max result sizes must be enforced to prevent context flooding

**Receipts:**
- outputs must be stored in CAS and referenced by hash
- optionally produce a `SummaryReceipt` when output exceeds a configured threshold

### 6.2.1 Git ref and path validation rules (normative)

- Refs MUST be validated using a `rev_parse`-equivalent that rejects:
  - arguments starting with `-`
  - refspec syntax
  - ambiguous revisions unless explicitly allowed
- Paths MUST be normalized and resolved (including symlink resolution) before scope checks.
- Any tool that can write MUST verify the resolved target path is within allowlisted roots after symlink resolution.

### 6.3 xtask bridge ToolKind

`XTaskExec` is a constrained bridge:
- allowlisted subcommands only
- canonical args only
- mandatory idempotency keys
- receipts always

This maintains throughput while preventing bypass.

### 6.4 Taint tracking and prompt-injection resilience (normative)

HSI introduces `taint_tags` as a first-class propagation mechanism.

#### 6.4.1 Taint lattice

Taint is a monotone label applied to evidence and derived artifacts:
- `UNTRUSTED`: unreviewed external content (web, issue text, logs, third-party output)
- `SANITIZED`: processed to remove active payloads (e.g., code blocks rendered inert), still not verified
- `VERIFIED`: checked by deterministic tools/tests or cryptographic verification
- `ATTESTED`: verified and accompanied by strong provenance attestation

#### 6.4.1b Confidentiality lattice (normative)

HSI MUST additionally track **confidentiality classification** on all evidence selectors and CAS artifacts:

- `PUBLIC`
- `INTERNAL`
- `CONFIDENTIAL`
- `RESTRICTED`

Classification is a *non-decreasing* label under aggregation (max over inputs) unless a signed DeclassificationReceipt
explicitly justifies lowering.

#### 6.4.1c Dual-lattice rule (normative)

For any operation that emits data across a boundary (cross-holon message, external tool call, log sink), policy MUST
evaluate both:

1) **Integrity gate**: minimum required taint level (Biba-like).
2) **Confidentiality gate**: maximum allowed classification for the destination (Bell-LaPadula-like).

This is required to prevent:
- prompt injection from “low integrity” sources reaching “high impact” actuators, and
- secret leakage from “high confidentiality” context into “low confidentiality” channels.

#### 6.4.2 Propagation

- Tool outputs inherit the max taint of inputs unless the tool is an approved sanitizer/verifier.
- Summaries MUST declare a loss profile and inherit taint unless produced by a verifier.
- ContextPacks MUST carry a taint index so that higher-risk tool calls can reject tainted inputs.

#### 6.4.3 Policy hooks

Capability manifests MAY require:
- `min_input_taint_level` for a capability (e.g., deployment requires VERIFIED or ATTESTED),
- or `required_sanitizers[]` before a capability can be exercised.
Additionally, capability manifests MUST be able to require:
- `max_output_classification` (e.g., external webhook calls may be capped at INTERNAL),
- `allowed_destinations[]` keyed by classification.

### 6.5 Attestation tightening (normative)

All authoritative receipts MUST include attestation metadata:
- actor identity (holon_id/actor_id)
- environment fingerprint (capsule profile hash, toolchain hash)
- policy root key id
- optional TEE / runner attestations (as required by risk tier)

Risk tiers MUST map to minimum attestation:
- Tier0–Tier1: SOFT allowed
- Tier2: SOFT required, STRONG recommended for external integration
- Tier3+: STRONG required; Tier4 may require additional human/operator co-sign

Delegation MUST be strict-subset: a holon can only delegate capabilities that are a subset of its own manifests.
Delegation MUST be strict-subset across **all constraint dimensions**, including:
- capability scopes,
- risk tier ceilings,
- **budgets** (tool calls, evidence bytes, time),
- and **stop conditions** (no delegation may weaken stop predicates).

---

## 7. FAC integration: pulses, deltas, HMP

### 7.1 Pulses are wakeups (never truth)

Pulse semantics:
- a pulse schedules or suggests
- it does not assert facts
- it must be safe to drop, reorder, or duplicate pulses

Pulse payloads should be digest-first:
- suggested selector sets
- references to recent summary receipts
- no raw logs

### 7.2 Default iteration interface

For iteration N+1, default context should include:
- `SummaryReceipt` from N (loss profile explicit)
- `ToolLogIndexV1` pointer for selective zoom-in
- `ContextDeltaV1` from the last pack to the new pack
- minimal “changes since” digest pointers (git diff hash, build log hash)

### 7.2.1 Escalation is a first-class artifact (normative)

When an agent cannot proceed safely due to missing authority or missing context,
it MUST NOT emit free-form narrative instructions (“please grant me access to X”).
Instead it MUST emit one of the following *receipt-addressable* escalation artifacts:

1) **ContextRefinementRequestV1** (CAS):
   - asks for additional selectors/slices,
   - includes requested selector set + rationale,
   - includes taint/classification requirements (e.g., “need VERIFIED build log excerpt”),
   - is bound to `view_commitment_hash` and the current `episode_envelope_hash`.

2) **CapabilityUpgradeRequestV1** (CAS):
   - asks for additional capability handles or widened scopes,
   - includes explicit “delta requested” (overlay), never an implicit “give me admin”,
   - MUST declare intended ToolKinds and preconditions.

3) **OracleRequestV1** (CAS):
   - requests external human/operator input, policy adjudication, or manual verification,
   - MUST carry a structured question set,
   - MUST be rate-limited and budgeted (to prevent abuse loops).

Each request MUST be referenced by hash in a ledger event (e.g., `ContextRefinementRequested`, `CapabilityUpgradeRequested`, `OracleRequested`)
so supervisory holons can route it without trusting unstructured text.

### 7.3 HMPMessageV1 envelope and classes

HMP message envelope is stable; message classes evolve.

**Required envelope fields:**
- protocol_id, message_class
- message_id, idempotency_key
- hlc_timestamp, parents[]
- sender holon_id/actor_id
- commitments: ledger head hash, context pack hash, manifest hash (as applicable)
- body_ref: CAS hash + content type

**Additional required fields (federation-ready):**
- channel_class: DISCOVERY | HANDSHAKE | WORK | EVIDENCE | GOVERNANCE
- sender_cell_id, receiver_cell_id (or wildcard for broadcast)
- sender_policy_root_key_id (key id only)
- view_commitment_hash (when message affects cognition/claims)
- permeability_receipt_hash (when message conveys delegated authority)

**Message classes (FAC-local starting set):**
- `FAC.PULSE` — wakeup scheduling
- `FAC.CONTEXT_REQUEST` — request selectors/pack compilation
- `FAC.RECEIPT_POINTER` — send receipt/index pointers
- `FAC.DEFECT_SIGNAL` — send defect fingerprints (no raw logs)

**Message classes (federation extension, normative shape):**
- `HSI.DIRECTORY.ANNOUNCE` — signed holon/relay endpoint announcement (DISCOVERY)
- `HSI.ANTI_ENTROPY.OFFER` — offer ledger head + checkpoint digests (EVIDENCE)
- `HSI.ANTI_ENTROPY.REQUEST` — request missing ranges / hashes (EVIDENCE)
- `HSI.ANTI_ENTROPY.DELTA` — transmit missing ledger events by range (EVIDENCE)
- `HSI.CAS.REQUEST` — request CAS artifacts by hash (EVIDENCE)
- `HSI.CAS.DELIVER` — deliver CAS artifact chunks / index pointers (EVIDENCE)
- `HSI.PERMEABILITY.GRANT` — convey PermeabilityReceiptV1 pointer (HANDSHAKE)

### 7.4 Coordination objective: bounded expected free energy (normative shape)

HSI permits sophisticated planner internals, but cross-holon coordination must remain typed and auditable.
Planner policy MAY use an active-inference-style objective to prioritize intents:

`EFE = λ_risk * ExpectedPolicyViolation + λ_uncertainty * ExpectedEvidenceAmbiguity + λ_cost * ExpectedResourceCost`

where:
- `ExpectedPolicyViolation` is estimated from capability/stop/freshness constraints,
- `ExpectedEvidenceAmbiguity` is reduced by context/evidence acquisition,
- `ExpectedResourceCost` is bounded by episode/channel budgets.

**Normative boundaries:**
1) EFE (or any internal objective) is advisory only; it MUST NOT bypass capability, stop, freshness, or attestation gates.
2) Any coordination action chosen due to objective optimization and affecting another holon MUST be emitted as typed artifact
   (`FAC.CONTEXT_REQUEST`, `FAC.RECEIPT_POINTER`, `CapabilityUpgradeRequested`, `OracleRequested`, etc.).
3) Tier3+ repeated escalation loops MUST emit a `CoordinationObjectiveReceiptV1` (or equivalent) containing objective inputs by hash,
   so reviewers can distinguish rational escalation from uncontrolled retry behavior.

This preserves autonomy gains while keeping governance deterministic.

---

## 8. Observability and defect ingestion

### 8.1 What becomes a defect automatically

Machine-detect and ingest as defects:
- tool denied due to missing capability or constraint violation
- schema mismatch for any syscall
- capsule escape attempt
- context firewall denial
- missing stop checks
- contract mismatch / drift between adapter and daemon

Defects MUST carry stable fingerprints:
- cli_contract_hash
- episode_envelope_hash (if applicable)
- capability_manifest_hash
- role_spec_hash
- tool_class + args_hash
- view_commitment_hash
- relevant receipt hashes

This makes it feasible to dispatch FAC iterations to fix systemic issues (not just code bugs).

### 8.2 Observability metrics (examples)

- contract mismatch counter
- capability deny counter
- capsule escape attempts counter
- context delta size histogram
- FAC iteration latency histogram

### 8.3 Permeability receipts (normative)

`PermeabilityReceiptV1` is the only admissible cross-holon authority entrance.

- Any message that conveys delegated authority MUST include a `permeability_receipt_hash` and be sent on the
  HANDSHAKE channel class.
- Relays/daemons MUST treat cross-holon delegation as *deny-by-default* until the referenced receipt is fetched and
  verified against the policy root.
- Delegation MUST be a strict subset: cross-holon grants can only narrow existing manifests/scopes, never widen them.

#### 8.3.1 Required bindings (normative)

PermeabilityReceiptV1 MUST bind, at minimum:
- `permeability_id`
- `from_holon_id`, `to_holon_id`
- `work_id` and `lease_id` (or explicitly scoped wildcard rules governed by policy)
- `capability_manifest_hash` (+ OPTIONAL narrowed overlay hash)
- `context_pack_hash` (or context refs commitment)
- **budgets** (typed quantities): tool_calls, wall_ms, cpu_ms, bytes_io, evidence_bytes, and cross-cell bandwidth/fanout caps where applicable
- **stop_condition_hash** (or stop state commitment reference)
- `issued_at_envelope_ref` and `expires_at_tick` (HTF; REQUIRED for authority-bearing delegation)
- `view_commitment_hash` (or derivation selector bound to ledger head)
- signature/quorum attestation under the delegator’s policy root

#### 8.3.2 Authority lattice and delegation algorithm (normative)

The phrase “delegation MUST be a strict subset” is unenforceable unless it is reduced to a machine-checkable algorithm.
HSI therefore defines *authority* as a multi-dimensional lattice. A delegation is valid iff the delegated authority
is the **meet** (greatest lower bound) of the parent authority and an explicit narrowing overlay.

##### 8.3.2.1 AuthorityVectorV1 (conceptual schema, normative semantics)

An `AuthorityVectorV1` is the tuple:

1) **Risk ceiling:** `risk_tier_ceiling` (daemon `RiskTier`).
2) **Capabilities:** `capability_manifest_hash` (sealed OCAP handles + scopes).
3) **Budgets:** a typed budget vector (tool_calls, wall, cpu, bytes_io, evidence_bytes, tokens; OPTIONAL: usd, joules).
4) **Stop predicates:** `stop_condition_hash` (cannot be weakened downstream).
5) **Attestation floor:** `min_attestation_level` (SOFT/STRONG/…).
6) **Input integrity floor:** `min_input_taint_level` (UNTRUSTED < SANITIZED < VERIFIED < ATTESTED).
7) **Output confidentiality ceiling:** `max_output_classification` (PUBLIC < INTERNAL < CONFIDENTIAL < RESTRICTED).
8) **Expiry window:** `[issued_at_envelope_ref, expires_at_tick]`.
9) **Fanout/bandwidth caps** (for federation only): `max_fanout`, `max_bytes_out`, `max_bytes_in` (typed quantities).

##### 8.3.2.2 Meet operator (normative)

Given a parent `AuthorityVectorV1` = `A` and a proposed delegated overlay = `O`,
the delegated authority is computed as `D = meet(A, O)` where:

- `risk_tier_ceiling(D) = min(risk_tier_ceiling(A), risk_tier_ceiling(O))`
- `budgets(D) = componentwise_min(budgets(A), budgets(O))`
- `expiry_window(D) = intersection(expiry_window(A), expiry_window(O))`
- `min_attestation_level(D) = max(min_attestation_level(A), min_attestation_level(O))`
- `min_input_taint_level(D) = max(min_input_taint_level(A), min_input_taint_level(O))`
- `max_output_classification(D) = min(max_output_classification(A), max_output_classification(O))`
- `stop_condition_hash(D)` MUST be a strengthening of the parent stop predicates:
  - If stop predicates are represented as a DAG, then `D.stop` MUST imply `A.stop` (i.e., no new paths to “continue” are introduced).
  - If stop predicates are represented as a set of terminal conditions, then `D.stop` MUST be a superset of terminal conditions.
- `capabilities(D)` MUST be a strict subset under all scope dimensions (paths, patterns, network, size limits) and MUST NOT widen any allowlist.

If any field cannot be proven to be a narrowing, delegation MUST be rejected.

##### 8.3.2.3 PermeabilityReceipt overlay binding (normative)

PermeabilityReceiptV1 MUST carry either:
- `authority_overlay_hash` (CAS) referencing a canonical narrowing overlay object, or
- an inline overlay (if small), which is hashed as part of the receipt canonical bytes.

The daemon MUST verify: `D == meet(A, O)` prior to admitting the delegation.

##### 8.3.2.4 DelegationChain commitment (normative)

To support exabyte-scale audit traversal, a delegated episode MAY include `delegation_chain_hash`:

`delegation_chain_hash = blake3("apm2:delegation_chain:v1\n" + merkle_root(permeability_receipt_hashes_in_order))`

Where “in order” is the verified parent→child chain order from root delegator to leaf delegatee.
This allows auditors to fetch a single commitment and then selectively traverse the chain by hash.

#### 8.3.3 Consumption rule (normative)

If an episode uses delegated authority:
- `EpisodeEnvelopeV1` MUST include `permeability_receipt_hash`, and
- every authoritative receipt emitted by that episode MUST bind it as well.

If a permeability receipt is missing, unverifiable, expired, or revoked, actuation MUST be denied (fail-closed) and a defect MUST be emitted.

---

## 9. Scaling to exabyte evidence without drowning agents

HSI is digest-first by construction:
- store large artifacts in CAS
- reference them through indices and summaries
- treat context as pointers and selectors, not raw payloads

At exabyte scale, the system survives by making “what is injected into cognition” a scarce resource with explicit
budgets (ContextDelta, SummaryReceipt loss profiles, selector zoom-ins).

### 9.1 Index layers (normative)

For any artifact that can exceed the cognition budget, the system MUST produce:
- an index artifact (ToolLogIndexV1, ContextIndexV1, EvidenceIndexV1) that supports deterministic selectors
- chunk digests for payload retrieval
- summary receipts with loss profile + traceability pointers into the index

Agents MUST NOT receive raw streams as default context; they must request zoom-in slices by selector.

### 9.1.1 Merkle-friendly index invariants (normative)

Any index artifact intended for cross-holon traversal (ToolLogIndexV1, ContextIndexV1, EvidenceIndexV1) MUST:
1) define a **canonical ordering** of leaves (e.g., tool_call_seq asc; context_entry_id asc),
2) support chunking into bounded segments, and
3) define a Merkle commitment rule so a verifier can validate subranges without fetching the full index.

**Minimum requirement:** each index MUST carry either:
- `index_merkle_root_hash`, or
- a deterministic derivation rule from the leaf list hash.

Selectors MUST be deterministic and MUST be validated against the index commitment before payload retrieval.

### 9.2 Evidence tiering + retention (normative)

Evidence MUST be classified and retained under tiered policies:
- hot: recent, frequently accessed; fast retrieval
- warm: compressed, indexed; slower retrieval
- cold: deep archive; retrieval is explicit and audited

Retention MUST be attached to evidence metadata and enforced by the storage plane.

### 9.3 Compaction is a proven transformation (normative)

Compaction (log compaction, summary rollups, context delta rollups) MUST:
- emit a CompactionReceipt that binds input digests -> output digest
- declare loss profile and verification method
- preserve the ability to audit “what happened” by index traversal

#### 9.3.1 Selector coverage is the invariant (normative)

Any lossy transformation (summary, compaction, rollup) MUST preserve **selector coverage**:
- for every claim that can influence coordination decisions, the artifact MUST provide selectors that allow a verifier to retrieve supporting evidence slices (by hash) without requiring full raw payload propagation.

If selector coverage cannot be met within budgets, the system MUST fail-closed and emit an OracleRequest/defect rather than emitting unverifiable narrative.

#### 9.3.2 Rate–distortion fields for SummaryReceipt (normative shape)

SummaryReceipt MUST carry explicit *information economics* fields:
- `rate_bytes`: approximate byte budget of the summary payload
- `source_bytes`: approximate total bytes summarized
- `loss_profile`: structured declaration of what may be omitted/abstracted
- `selector_coverage`: a deterministic index of evidence selectors backing each material claim
- OPTIONAL `distortion_model`: declared metric or verifier used (e.g., “claims backed by tool-verifiable predicates”)

High-risk operations MUST NOT depend solely on lossy artifacts; they require terminal verifier evidence (tests, signatures, deterministic checkers).

### 9.4 Backpressure and admission control (normative)

All channels and syscalls MUST be subject to:
- per-episode budgets (tool calls, wall time, cpu, evidence bytes)
- per-cell budgets (CAS ingress, ledger append rate)
- and per-relay budgets (cross-cell bandwidth, fanout)

When budgets are exceeded, the correct behavior is:
- deny further actuation,
- emit receipts for denials,
- and generate a defect fingerprint.

The purpose of HSI is to ensure that future compaction/tiering pipelines can be added without breaking protocol:
the interfaces already speak in digests, indices, and selectors.

### 9.5 Proof compression at scale: batched attestations (normative)

At multi-exabyte scale, the limiting resource is not storage—it is **verification work** and **receipt fanout**.
If every receipt carries an independent signature, verification cost grows linearly with the number of effects.

HSI therefore requires an admissible proof-compression format: **Merkle-batched attestations**.

#### 9.5.0 Receipt batching MUST compose with BFT QC (normative)

For cells running RFC-0014 BFT, the default high-volume authentication path is:
1) Merkleize receipt hashes into batch roots, then
2) commit batch roots inside quorum-certified ledger checkpoints.

This makes receipt authentication amortized over existing consensus proof work:
- QC verification authenticates checkpoint commitments once,
- per-receipt verification is inclusion-proof hashing.

#### 9.5.0b FactRootV1 (normative shape)

To prevent free-floating commitment semantics in BFT mode, cells SHOULD aggregate authenticated facts per checkpoint via
**FactRootV1** (`apm2.fact_root.v1`):
- `ledger_anchor`
- `fact_root_hash`
- `fact_kinds[]` (e.g., `RECEIPT_BATCH_ROOT`, `DIRECTORY_HEAD`, `ADMISSION_RANGE`)
- `leaf_ordering_rule`
- `leaf_hash_rule`

Leaf hash preimage MUST be domain-separated:
`leaf_hash = blake3("apm2:fact_leaf:v1\0" + kind_tag + stable_key_bytes + subject_hash_bytes)`

The checkpoint QC authenticates `fact_root_hash`; individual facts are proven by `FactInclusionProofV1`.

#### 9.5.1 ReceiptPointerV1 (normative wire shape)

Any cross-holon pointer to an authoritative receipt SHOULD be sent as a `ReceiptPointerV1` object (CAS or inline on E channel):
- `receipt_hash`
- `authority_seal_hash`
- `merkle_inclusion_proof` (only required when the seal is a batch root)
- `ledger_anchor` (where the seal/head was admitted; optional if carried in the seal)

**Normative rule:** a verifier MUST be able to validate a receipt using only:
1) the receipt bytes (from CAS),
2) the authority seal (from CAS),
3) and an inclusion proof when batching is used,
without any additional “search the ledger to find which batch included this receipt”.

**Upgrade (normative for BFT cells):** `ReceiptPointerV1` MUST support an alternate authentication path:
- `fact_root_proof` (proves batch root inclusion in `FactRootV1`)
- `qc_pointer` (checkpoint/block header pointer needed to authenticate `fact_root_hash`)

This allows BFT deployments to avoid distributing independent authority seals per receipt batch.

#### 9.5.2 Batch construction (normative constraints)

Implementations MAY choose batch boundaries by:
- tool-call count (e.g., every 1024 receipts),
- time windows (e.g., every 250ms),
- or lifecycle boundaries (per episode end),
but MUST enforce:
- `max_batch_leaves` cap (e.g., ≤ 2^20),
- bounded proof depth (≤ log2(max_batch_leaves)),
- and deterministic ordering of leaves (by `(episode_id, tool_call_seq)` or other canonical key).

**Leaf hashing rule (normative):**
`receipt_leaf_hash = blake3("apm2:receipt_leaf:v1\0" + receipt_hash_bytes)`

Any authoritative batch root MUST be accompanied by `ReceiptBatchDescriptorV1` binding:
- `cell_id`
- `batch_id`
- `leaf_count`
- `leaf_ordering_rule_id`
- `leaf_hash_rule_id`
- `receipt_batch_root_hash`
- `ledger_anchor`
- `time_envelope_ref`

#### 9.5.3 Verification cost target (normative)

For a batch of size `B`:
- verifying the authority seal is O(1) signature/quorum verifications,
- verifying a receipt is O(log B) hashing,
- verifying K receipts from the same batch is O(1) signatures + O(K log B) hashing.

This is required to prevent verification cost explosion when receipts reach 10^12+ scale.

#### 9.5.4 Interaction with BFT (normative)

If the cell uses RFC-0014 BFT quorum attestations:
- the batch authority seal SHOULD be authenticated by the quorum key,
- and MAY be *piggybacked* on consensus checkpoints (e.g., the batch root committed as part of a quorum-certified ledger block).

**Upgrade (normative for BFT cells):** For cells running RFC-0014 BFT, receipt batch roots MUST be committed
as part of the quorum-certified ledger structure (block header / checkpoint metadata). Standalone batch signatures
SHOULD be treated as optional optimization for non-BFT cells.

This is required to meet the <1% overhead target: it reuses the quorum certificate already required for consensus,
and adds only hashing work for Merkleization (bounded, parallelizable).

#### 9.5.5 Merkle multiproofs (normative shape)

HSI MUST support a compact proof format for verifying many receipt hashes against a single batch root:

**ReceiptMultiProofV1** (CAS or inline on E channel):
- `batch_root_hash`
- `leaf_hashes[]` (K hashes, canonically sorted)
- `proof_nodes[]` (minimal required sibling hashes)
- `proof_structure` (bitmap / indices required to reconstruct)

**Normative rule:** If a sender transmits ≥ K_min receipt pointers from the same batch (implementation-defined threshold),
it SHOULD send a multiproof rather than K independent inclusion proofs, unless prohibited by channel budgets.

This reduces both network fanout and verifier hashing work at high volume.

#### 9.5.6 Hierarchical batch forests (normative shape)

Single-level batching is insufficient once receipt throughput spans many cells and epochs. HSI therefore allows
**BatchEpochRootV1** (`apm2.batch_epoch_root.v1`) as a root-of-roots commitment:

- leaf level: receipt hashes
- batch level: `batch_root_hash` (from `AuthoritySealV1 seal_kind=MERKLE_BATCH` or `FactRootV1` leaf commitment in BFT mode)
- epoch level: `epoch_root_hash = merkle_root(batch_root_hashes_canonical_order)`
- federation view level (optional): `super_root_hash` over epoch roots for anti-entropy checkpointing

Verification for a receipt pointer then becomes:
1) receipt inclusion in `batch_root_hash`,
2) batch inclusion in `epoch_root_hash`,
3) epoch root admission via quorum/ledger/HTF anchor.

This preserves O(log B + log E) hashing and keeps signature/quorum checks amortized at epoch granularity.

#### 9.5.7 Overhead accounting contract (<1% target, normative)

For RFC-0014 BFT cells, batching MUST satisfy an explicit performance contract:

- **CPU overhead target:** p99 additional verifier/issuer CPU <= 1% versus baseline quorum-certified commit path
  (same workload, same hardware class, measured over >= 10^6 effects).
- **Network overhead target:** additional control-plane bytes <= 1% versus baseline quorum certificate dissemination.
- **Failure-mode requirement:** if batching path degrades above target or violates freshness semantics, implementation MUST
  fall back to direct receipt verification for affected flows and emit defect signals.

This contract prevents “theoretical scalability” from masking operational regressions.

--- 

## 10. Implementation milestones (normative intent)

Rollout proceeds as a fail-closed ratchet: each stage increases enforcement by default and MUST NOT
silently relax it. Promotion between stages MUST be gated by objective evidence (tests, receipts,
metrics), and blast radius MUST be controlled via canary-first rollout.

Principles:
- Fail-closed ratchet: each stage increases enforcement, never relaxes by default.
- Evidence-first: each stage has objective receipts/metrics gating promotion.
- Blast-radius control: canary cells first, then progressive widening.

**Gate taxonomy (normative):**
- **G0 (Observe):** emit receipts/defects but do not block.
- **G1 (Warn):** warn + require waiver receipt to proceed.
- **G2 (Enforce):** deny-by-default; no waivers except operator breakglass.

Each stage MUST specify:
- upgrade path (forward/backward compatibility),
- canary scope (single developer cell → staging cell → prod-adj cell),
- rollback trigger (metric thresholds),
- and acceptance evidence (replay tests + fuzz + red-team scenarios).

### Stage 0 (S0) — Contract manifest + observability

Subtasks:
1) Generate `HSIContractManifestV1` from the daemon/CLI dispatch registry (build fails on missing semantics annotations).
2) Extend handshake to exchange `cli_contract_hash` + canonicalizer id/version; store in SessionStarted event.
3) Implement conformance tests:
   - golden contract hash generation under deterministic builds
   - reject/waive matrix per risk tier
4) Observability:
   - mismatch counters, top offenders by adapter_profile_hash and role_spec_hash

Rollout gate:
- Tier0–Tier1: G1 (warn/waive)
- Tier2+: G2 (deny by default)

### Stage 0.5 (S0.5) — AdapterProfile + RoleSpec binding (TCK-00328, TCK-00331)

Subtasks:
1) Implement `AgentAdapterProfileV1` storage + hashing and require `adapter_profile_hash` in handshake and envelopes.
2) Implement `RoleSpecV1` and require `role_spec_hash` binding in EpisodeEnvelope and tool receipts.
3) Conformance tests: “adapter drift” and “role drift” must become deterministic defects.

Rollout gate:
- Tier0–Tier2: G1
- Tier3+: G2

### Stage 0.75 (S0.75) — Self-certifying identity + directory heads (NEW)

Subtasks:
1) Introduce `PublicKeyIdV1`, `KeySetIdV1`, `CellIdV1`, and `HolonIdV1` canonical text/binary forms (§1.7.2–§1.7.4).
   - Introduce `CellGenesisV1` and `HolonGenesisV1`; derive stable ids from genesis commitments.
2) Define and implement CAS artifacts:
   - `CellCertificateV1` (`apm2.cell_certificate.v1`)
   - `HolonCertificateV1` (`apm2.holon_certificate.v1`)
   - `HolonDirectoryHeadV1` (`apm2.holon_directory_head.v1`)
   - `IdentityProofV1` (`apm2.identity_proof.v1`)
   - `FreshnessPolicyV1` (`apm2.freshness_policy.v1`)
   - `SessionKeyDelegationV1` (`apm2.session_key_delegation.v1`)
3) Extend `hsi.session.open` handshake to require:
   - `holon_id` + `identity_proof_hash` from the client
   - `cell_id` + `cell_certificate_hash` + `holon_directory_head_hash` + `identity_proof_profile_hash` from the daemon (§5.1)
4) Implement verifier library + conformance tests:
   - O(log n) ADS proof verification with bounded proof bytes (SMT-256 or Patricia trie)
   - identity self-cert recomputation (stable `holon_id` from genesis key; operational key validated via directory state)
   - caching semantics: one head verification amortizes many identity checks
   - freshness enforcement tests by risk tier (Tier2+ fail-closed on staleness)
5) Negative testing:
   - forged proofs, mismatched ids/keys, replayed heads, over-depth proofs, malformed canonical bytes

Rollout gate:
- Tier0–Tier1: G1 (warn/waive; log identity drift)
- Tier2+: G2 (deny-by-default for any non-discovery message without verified identity)

### Stage 0.9 (S0.9) — Identity grammar + proof economics hardening (NEW)

Subtasks:
1) Freeze canonical identity grammar/parsers (§1.7.5b) with cross-language conformance vectors:
   - reject uppercase/mixed encodings, whitespace, and parser differentials.
2) Introduce `IdentityProofProfileV1` (§1.7.7b) and require `identity_proof_profile_hash` in directory heads.
3) Implement verifier caches per §1.7.7c with explicit invalidation tests under revocation/rotation.
4) Implement revocation-wins signed CRDT merge law (§2.4.3b) with partition/rejoin simulation.
5) Scale gate:
   - synthetic namespace `n = 10^12` (model + benchmark), prove O(log n) verification class and bounded proof bytes.

Rollout gate:
- Tier0–Tier1: G1
- Tier2+: G2

### Stage 1 (S1) — EpisodeEnvelope + receipts bindings

Subtasks:
1) Require `EpisodeEnvelopeV1` at spawn/resume; ensure all tool receipts bind envelope+manifest+view commitment.
2) Enforce stop conditions + budgets pre-tool; record checks as receipts or include in `ToolExecutionReceipt`.
3) Add replay harness:
   - given (ledger range + CAS roots), deterministically re-derive episode decisions and verify receipts.

Rollout gate:
- Tier0–Tier2: G1
- Tier3+: G2

### Stage 2 (S2) — Capability manifests enforced at tool broker

Subtasks:
1) Mint `CapabilityManifestV1` via policy resolver only; no requester minting.
2) Enforce “capabilities are not discoverable”: manifests only enter via policy resolution/permeability receipts.
3) Enforce CapabilityScope checks at daemon/tool broker layer.
4) Negative testing:
   - fuzz manifest parsing/canonicalization
   - capability laundering attempts (overbroad scope, widened risk tier, missing expiry)
   - out-of-scope paths/hosts/size limits
   - mismatched envelope/manifest binding

Rollout gate:
- Tier0–Tier2: G1
- Tier3+: G2

### Stage 2.5 (S2.5) — Attestation envelopes + receipt batching (NEW)

Subtasks:
1) Implement `AuthoritySealV1` as the fact-authentication abstraction (§1.7.8).
   - Keep `apm2.attestation.v1` for environment attestation (separate semantics).
2) Implement `ReceiptPointerV1` and make it the default cross-holon pointer for authoritative receipts (§9.5.1).
3) Produce Merkle-batched attestations for:
   - ToolExecutionReceipt (high volume)
   - directory head publication (already a head object; ensure uniform envelope format)
   - admission receipts for cross-cell ingestion
4) Define batch boundary policy + caps (`max_batch_leaves`, proof depth).
5) Implement `ReceiptMultiProofV1` for compact membership proofs (§9.5.5).
6) Update proof obligations checklist and auditor tooling to accept:
   - direct signatures OR batched attestations (no behavioral drift).
7) Perf gates:
   - demonstrate that verifying 1M receipts from one batch family requires O(1) signature verifications per batch and bounded hashing.
   - demonstrate multiproof bandwidth reduction under realistic FAC fanout patterns.

Rollout gate:
- Tier0–Tier2: G0–G1 (observe/warn)
- Tier3+: G2 (enforcement for high-volume receipt classes once tooling exists)

### Stage 2.6 (S2.6) — Hierarchical attestations + overhead gates (NEW)

Subtasks:
1) Implement `BatchEpochRootV1` (§9.5.6) and epoch-level anti-entropy pointers.
2) For RFC-0014 cells, commit batch/epoch roots inside quorum-certified checkpoints by default.
3) Implement fast-path verifier that reuses cached quorum checkpoints + multiproofs.
4) Build perf harness for the <1% overhead contract (§9.5.7):
   - CPU and network deltas at 10^6, 10^8, and projected 10^12 effect scales.
5) Failure-path tests:
   - auto-fallback to direct signature verification when batch integrity/freshness checks fail.

Rollout gate:
- Tier0–Tier2: G1
- Tier3+: G2 only after measured <=1% p99 overhead in representative production-like cells

### Stage 3 (S3) — Capsule boundary + context firewall

Subtasks:
1) Implement `linux-ns-v1` capsule profile with:
   - user/mount/pid namespaces, seccomp, cgroups, explicit egress deny-by-default
   - workspace root confinement with symlink escape detection
2) Context firewall:
   - enforce ContextPackManifest allowlist + TOCTOU hash verification
   - Tier3+: hard-fail terminate on violation
3) Red-team harness:
   - prompt injection via tool output
   - filesystem traversal attempts
   - covert-channel attempts via repeated denials

Rollout gate:
- Tier3+: G2 required

### Stage 3.5 (S3.5) — No bypass paths (TCK-00338)

Subtasks:
1) Remove any allow-by-manifest fallback that bypasses broker enforcement.
2) Add regression tests that prove: “no tool execution without broker + capability + context firewall initialized from sealed ContextPack”.

Rollout gate:
- Tier2+: G2

### Stage 4 (S4) — ToolKinds hardening

Deliverables:
- Typed Git ToolKinds v1.
- Structured Shell bridge with allowlist only.
- `ToolLogIndexV1` for large outputs (chunked).

Promotion gates:
- Argument injection regression tests (CVE-class harness).
- Path traversal regression tests (symlink + normalization).

### Stage 5 (S5) — Iteration economics

Deliverables:
- Default iteration context = `SummaryReceipt` + `ToolLogIndexV1` pointer + `ContextDeltaV1`.
- Channel budgets + backpressure enforced.

Promotion gates:
- Holonic blowup simulations: fanout bounded under adversarial pulses.
- Evidence bytes budget enforced.

### Stage 6 (S6) — Integrity + confidentiality labeling

Deliverables:
- Taint propagation enforced for evidence and derived artifacts.
- Classification labeling enforced on boundary crossings.
- `DeclassificationReceipt` introduced.

Promotion gates:
- Tier3+ actuators reject UNTRUSTED or too-confidential inputs.
- No secret leakage tests: attempt to emit RESTRICTED data via WORK channel.

### Stage 6.5 (S6.5) — Multi-holon policy inheritance + attestation tightening (TCK-00340)

Subtasks:
1) Implement the delegation meet algorithm (§8.3.2) and require it for PermeabilityReceipt admission.
2) Enforce strict-subset across budgets, stop predicates, taint/classification gates, and attestation floors.
3) Add negative tests for policy laundering across holonic recursion depth ≥ 4.

Rollout gate:
- Tier3+: G2

### Stage 7 (S7) — Federation read-only

Subtasks:
1) Implement directory as signed CRDT with replay protection; enforce per-cell rate limits.
2) Implement anti-entropy (MMR/range proofs) with strict pull-based delivery.
3) Add federation testbed:
   - byzantine relay simulator (drop/duplicate/reorder/lie)
   - partition/rejoin drills with convergence metrics

Rollout gate:
- G0 → G1 only (read-only; no actuation)

### Stage 7.5 (S7.5) — HTF/VDF epoch sealing for federation freshness (NEW)

Subtasks:
1) Implement `EpochSealV1` (§1.9) issuance for directory heads and receipt-batch epochs.
2) Integrate HTF envelope validation from RFC-0016 into federation admission path.
3) Add optional VDF sealing profile for adversarial federation links:
   - deterministic challenge derivation from `(cell_id, prior_epoch_root, quorum_anchor)`,
   - verifiable output attached to epoch seals.
4) Add replay/fast-forward/equivocation adversarial tests:
   - stale seal replay,
   - non-monotone seal sequence,
   - forged VDF output,
   - conflicting seals at same epoch.

Rollout gate:
- Tier0–Tier1 cross-cell reads: G1
- Tier2+ cross-cell authority admission: G2 (deny by default on missing/invalid epoch seals)

### Formal verification gates (normative, applies to S1+ and S7+)

Before promoting any stage that tightens enforcement or adds federation behavior, the project MUST maintain:
1) a session-type state machine model (e.g., TLA+/PlusCal or equivalent) for handshake/work/evidence/governance ordering,
2) an anti-entropy safety model proving pull-based boundedness under byzantine peers,
3) model-checked invariants for:
   - “no actuation without verified stop state”,
   - “no delegation widening”,
   - “no unsigned facts admitted”.
4) a bisimulation artifact proving §2.6 for recursion depth `N ≤ 12` (observational equivalence under flattening).
5) freshness + staleness safety model:
   - prove “Tier2+ actuation implies non-stale identity head + non-stale stop state”
   - prove “staleness triggers deny/terminate actions per FreshnessPolicy”
6) composition + convergence model:
   - prove revocation-wins CRDT merge law cannot resurrect revoked identities without explicit re-admission
   - prove functorial observation law (§2.6.5) for admitted optimization rewrites in the bounded model.

These artifacts are required because unit tests cannot exhaust the state space of recursion + replication.

### Stage 8 (S8) — Federation with relay holons

Subtasks:
1) Relay hardening:
   - enforce channel budgets and fanout caps
   - mandatory evidence receipts for forwarding actions
2) Permeability receipts:
   - bind budgets + stop + expiry + view commitments
   - require envelope/receipt binding on consumption
3) Introduce governance channel usage for stop/rotation across cells.

Rollout gate:
- start in G1 with operator breakglass only; ratchet to G2 after escape rate < threshold for N weeks.

This ordering prioritizes FAC throughput early while steadily tightening the boundary.

---

## 11. Business continuity practices (normative)

HSI must be operable under disaster recovery conditions; otherwise “civilizational scale” is marketing.

### 11.1 Recovery objectives

Each cell MUST define:
- **RPO** (maximum tolerable data loss) for ledger + CAS
- **RTO** (maximum tolerable downtime) for policy root + tool mediation

Baseline targets (initial Tier2+ production posture) SHOULD be:
- ledger: RPO ≤ 5 minutes; RTO ≤ 30 minutes
- CAS: RPO ≤ 15 minutes; RTO ≤ 60 minutes

### 11.2 Backup/restore + drills

- Ledger MUST support point-in-time recovery (checkpoint + event ranges).
- CAS MUST support integrity-checked snapshots (content address verification).
- Restore drills MUST be executed on a fixed cadence and recorded as receipts.

### 11.2.1 Chaos and partition drills (normative)

Because holonic systems assume retries/duplication/partitions as normal, each cell MUST perform chaos drills:
- network partition simulation (relay drop/reorder),
- ledger append latency injection,
- CAS partial unavailability,
- stop-order path degradation.

Each drill MUST emit a **DrillReceiptV1** binding:
- drill scenario id + version,
- observed failure modes,
- recovery time,
- any stop-order failures (must be zero in Tier3+ posture),
- and references to supporting evidence in CAS.

### 11.3 Key rotation + emergency stop

- Policy root keys MUST support rotation with overlapping validity windows.
- Emergency stop MUST be operable even under partial partition; “stop uncertainty” denies actuation.
- Runbooks MUST exist for key rotation drills and emergency stop, and their execution MUST be recorded as receipts.

### 11.3.1 Stop-path SLOs (normative)

For Tier3+ episodes, the stop path is a safety-critical control loop and MUST meet explicit SLOs:
- **Stop propagation:** p99 ≤ 2s from operator stop issuance to capsule termination.
- **Stop uncertainty behavior:** any inability to verify stop state MUST deny actuation within ≤ 250ms at the kernel boundary.

Violations MUST emit defects and MUST block promotion of enforcement ratchet stages.

### 11.4 Observability requirements (normative)

At minimum, each cell MUST emit the following metrics:
- `contract_mismatch_total`
- `capability_denies_total`
- `context_firewall_denies_total`
- `capsule_violations_total`
- `anti_entropy_roundtrip_ms`
- `evidence_bytes_emitted_total`

---

## 12. References (informative)

- SWE-agent: https://arxiv.org/abs/2405.15793
- Agentic Reasoning survey: https://arxiv.org/abs/2601.12538
- SWE-bench Verified: https://openai.com/index/introducing-swe-bench-verified/
- Model Context Protocol (MCP) specification (rev 2025-11-25): https://modelcontextprotocol.io/specification/2025-11-25
- Agentic AI Foundation (AAIF) announcement (AGENTS.md donation context): https://openai.com/index/agentic-ai-foundation/
- AGENTS.md (format + examples): https://agents.md/
- Claude Code docs (overview): https://code.claude.com/docs/en/overview
- CVE examples motivating strict tool mediation (MCP Git server):
  - CVE-2025-68143 (git_init path/repo creation controls): https://nvd.nist.gov/vuln/detail/CVE-2025-68143
  - CVE-2025-68144 (argument injection in git_diff/git_checkout): https://nvd.nist.gov/vuln/detail/CVE-2025-68144
  - CVE-2025-68145 (repo path restriction bypass): https://nvd.nist.gov/vuln/detail/CVE-2025-68145
- NIST SP 800-207 Zero Trust Architecture
- AWS Well-Architected Framework (Reliability + Security pillars)
