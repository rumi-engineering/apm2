# Bootstrap Schema Bundle

This directory contains the bootstrap schema bundle that is embedded in the apm2 binary
at build time. These schemas form the foundational trust root for the Context-as-Code
(CAC) system.

## Security Properties

1. **Binary Embedding**: Schemas are embedded via `include_bytes!` to prevent filesystem
   tampering at runtime.

2. **Hash Verification**: A BLAKE3 hash of the entire bundle is computed at build time
   and verified at runtime startup.

3. **Immutability**: Bootstrap schemas cannot be modified, patched, or deleted at runtime.
   Any patch targeting a `bootstrap:*` stable ID is rejected.

## Schema Files

| File | Stable ID | Purpose |
|------|-----------|---------|
| `bootstrap.common.v1.schema.json` | `bootstrap:common.v1` | Common type definitions |
| `bootstrap.envelope.v1.schema.json` | `bootstrap:envelope.v1` | Artifact envelope structure |
| `bootstrap.patch_record.v1.schema.json` | `bootstrap:patch_record.v1` | Patch record format |
| `bootstrap.admission_receipt.v1.schema.json` | `bootstrap:admission_receipt.v1` | Admission receipt format |

## Build Process

The `build.rs` script:

1. Reads all `*.schema.json` files from this directory
2. Computes content hashes for each schema
3. Generates a manifest with all schemas and their hashes
4. Computes a bundle hash over the sorted manifest
5. Writes `bootstrap_manifest.rs` to the build output directory

## Runtime Behavior

At startup:

1. `verify_bootstrap_hash()` recomputes the bundle hash
2. If the hash differs from the embedded expected hash, startup fails with
   `BootstrapVerificationFailed`
3. The bootstrap schemas are exposed read-only to the validator

## Modifying Bootstrap Schemas

**Warning**: Modifying bootstrap schemas is a breaking change.

To modify:

1. Update the schema files in this directory
2. Run `cargo build` to regenerate the manifest
3. Update the expected hash constant if needed
4. All existing artifacts referencing old bootstrap schemas will need migration
