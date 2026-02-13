# 43 — APM2 SCP/DCP map (Security- and Determinism-Critical Paths)

This file makes an implicit assumption explicit:

> Some parts of the codebase have *much* higher proof obligations.

The goal is to avoid reviewers guessing what “SCP” means in each document.

---

## Definitions

- **SCP (Security-Critical Path)**: code that can grant/deny authority, handle secrets, produce/verify signatures, enforce sandbox boundaries, or cross trust boundaries (network/IPC/FFI).
- **DCP (Determinism-Critical Path)**: code whose outputs become persisted/canonical bytes (ledger, evidence, hashes, signature payloads) and therefore must be stable across machines and runs.

Rule of thumb:

- If a bug can cause **unauthorized action**, **credential leakage**, **invalid signature acceptance**, or **ledger divergence** → SCP.
- If a bug can cause **hash/signature mismatch** or **non-reproducible evidence** → DCP.

---

## Path map (globs)

These are conservative defaults for the current APM2 workspace structure.

```yaml
scp:
  # Cryptography, keys, credentials
  - crates/apm2-core/src/crypto/**
  - crates/apm2-core/src/credentials/**
  - crates/apm2-core/src/policy/**
  - crates/apm2-core/src/pcac/**
  - crates/apm2-core/src/lease/**
  - crates/apm2-core/src/capsule/**
  - crates/apm2-core/src/adapter/seccomp/**
  - crates/apm2-core/src/syscall/**
  - crates/apm2-core/src/process/**
  - crates/apm2-core/src/evidence/**
  - crates/apm2-core/src/ledger/**
  - crates/apm2-core/src/webhook/**

  # Daemon boundary: gatekeeping, protocol ingress/egress, identity
  - crates/apm2-daemon/src/gate/**
  - crates/apm2-daemon/src/pcac/**
  - crates/apm2-daemon/src/identity/**
  - crates/apm2-daemon/src/protocol/**
  - crates/apm2-daemon/src/evidence/**
  - crates/apm2-daemon/src/cas/**
  - crates/apm2-daemon/src/quarantine_store/**

  # Holon ledger and resource management
  - crates/apm2-holon/src/ledger/**
  - crates/apm2-holon/src/resource/**

dcp:
  - crates/apm2-core/src/determinism/**
  - crates/apm2-core/src/cac/**
  - crates/apm2-core/src/events/**
  - crates/apm2-core/src/ledger/**
  - crates/apm2-core/src/evidence/**
  - crates/apm2-core/src/consensus/**
  - crates/apm2-daemon/src/projection/**
  - crates/apm2-daemon/src/protocol/messages/**

supply_chain_gates:
  # These are "SCP-adjacent": they influence what code we run.
  - deny.toml
  - Cargo.toml
  - Cargo.lock
  - rust-toolchain.toml
  - scripts/ci/**
  - .github/workflows/**
```

---

## Symbol-level triggers (non-exhaustive)

If a change touches these symbols, treat it as SCP/DCP even if the file path is not mapped yet.

```yaml
scp_symbols:
  - "verify_*"
  - "sign_*"
  - "*Key*"
  - "*Credential*"
  - "*Policy*"
  - "*Capability*"
  - "*PCAC*"
  - "*Gate*"
  - "*Seccomp*"
  - "*Sandbox*"

dcp_symbols:
  - "*canonical*"
  - "*hash*"
  - "*digest*"
  - "*ledger*"
  - "*evidence*"
  - "*event*"
```

---

## Update policy

- This map should be updated whenever:
  - a new crate/module becomes security-critical,
  - a boundary moves (e.g., protocol ingress refactor),
  - determinism requirements expand (new canonical artifacts).

- Any removal from `scp`/`dcp` requires a written rationale and threat-model reference.
- When uncertain: **classify as SCP/DCP**; false positives are cheaper than false negatives.
