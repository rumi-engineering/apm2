# Lease and Budget

**Definition:**
-   **Lease:** A time-bounded, scope-bounded, revocable authorization to perform work or access resources.
-   **Budget:** A quantified allowance of resources (Compute, Tokens, Time, Tool Calls) attached to a Lease.

**Purpose:**
-   **Bounded Authority (Axiom III):** Agents do not have inherent rights; they "rent" authority from their supervisors.
-   **Resource Control (Axiom IV):** Prevents runaway agents (infinite loops, token exhaustion) by enforcing hard stops when budget reaches zero.
-   **Exclusive Access:** Leases enforce "at-most-one" active worker for a given `WorkID`, preventing race conditions.

## Core Concepts

-   **Lease Scope:** Defines *what* an agent can do (e.g., "read/write in `src/foo/`", "use `cargo` tool").
-   **Expiration:** Leases have a hard timestamp (TTL). Operations after expiration are rejected by the Kernel.
-   **Derivation:** A Holon can sub-lease authority to a child Holon, but the child's lease must be a strict subset of the parent's (lower budget, narrower scope).

## Implementation

-   `Lease` struct (`crates/apm2-holon/src/resource/lease.rs`):
    -   `lease_id`: Unique ID.
    -   `holder`: Actor ID.
    -   `budget`: Remaining resources.
    -   `signature`: Cryptographic proof of issuance.
-   `LeaseReducer` (`crates/apm2-core/src/lease/reducer.rs`):
    -   Tracks active leases and prevents duplicates.

**SDLC Context:**
Every "Episode" of agent execution (e.g., handling a ticket) MUST run under a valid Lease. If the Lease expires or the Budget runs out, the Episode is terminated.
