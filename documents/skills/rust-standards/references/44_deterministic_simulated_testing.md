# 30 — Deterministic Simulated Testing (Test Isolation and Reproducibility)

```yaml
module_id: T30
domain: verification
inputs: [ChangeSetBundle, QCP_Result]
outputs: [Finding[]]
```

---

## Purpose

This module ensures that tests are **deterministic**, **hermetically isolated**, and **reproducible**. A test suite that is flaky, order-dependent, or environment-sensitive is worse than no tests: it erodes trust in the verification pipeline, masks real failures behind noise, and produces spurious red/green signals that waste review and CI cycles.

The core principle is **total input control**: every input to the system under test — time, randomness, I/O, scheduling, environment — must be explicitly provided by the test harness. If a test can produce different results on two runs with the same code, it has an uncontrolled input.

---

## Hermetic Isolation

[CONTRACT: CTR-3001] Tests Must Be Hermetically Isolated.
- REJECT IF: a test's outcome depends on whether other tests have already run, or on the order of test execution.
- REJECT IF: a test mutates process-global state (static variables, environment variables, current working directory, global registries) without exclusive synchronization AND restoration.
- ENFORCE BY:
  - Each test receives its own instance of all mutable state via function parameters or local construction.
  - Shared state between tests uses only immutable/read-only data (constants, `once_cell` with deterministic initialization, compiled-in fixtures).
  - Temp directories use `tempfile::TempDir` (random name, RAII cleanup), never hardcoded paths.
  - If process-global mutation is unavoidable (e.g., logging initialization), use `#[serial_test::serial]` as a last resort with a comment explaining why isolation cannot be achieved through injection.
[PROVENANCE] `cargo test` runs tests in parallel within each binary; shared mutable process state is the primary source of test poisoning.
[VERIFICATION] Run `cargo test` with `--test-threads=1` and with default parallelism; if results differ, isolation is broken.

[HAZARD: RSK-3001] Environment Variable Mutation in Tests.
- `std::env::set_var` and `std::env::remove_var` are **unsound** in multi-threaded programs (per Rust safety docs since 1.66). `cargo test` is multi-threaded by default.
- REJECT IF: test code calls `set_var`/`remove_var` without `#[serial_test::serial]` and a documented reason.
- ENFORCE BY:
  - Inject configuration via struct parameters, not environment reads.
  - If environment reads are necessary in the code under test, abstract behind a `trait EnvProvider` that tests replace with a fake.
  - NEVER call `set_var` in a `#[tokio::test]` or any async test — the runtime is inherently multi-threaded.
[PROVENANCE] Rust std docs: `set_var` is unsafe to call in multi-threaded programs. Stabilization of `unsafe set_var` is tracking.

[HAZARD: RSK-3002] Test Poisoning via Static / Global State.
- FAILURE MODE: Test A writes to a `static Mutex<T>` or `once_cell::Lazy<T>`; Test B reads the mutated value and passes or fails depending on execution order.
- REJECT IF: tests modify `static`, `lazy_static`, `once_cell`, or `thread_local` values that other tests also read.
- ENFORCE BY:
  - Pass state via function parameters, not globals.
  - If a global is necessary for production code, provide a `#[cfg(test)]` reset mechanism or use a per-test instance keyed by test name.
  - Consider `std::sync::OnceLock` for truly one-time initialization that tests should not override.
[PROVENANCE] `cargo test` parallelism; global mutable state is the canonical test-poisoning vector.

---

## Nondeterminism Elimination

[CONTRACT: CTR-3002] External Nondeterminism Must Be Injected and Controlled.
- REJECT IF: test code depends on any of the following without injection/control:
  - Wall-clock time (`SystemTime::now`, `Instant::now`)
  - Randomness (`rand::thread_rng`, `getrandom`)
  - Network availability or latency
  - Filesystem state outside a test-owned temp directory
  - OS-assigned resources (port numbers, PIDs)
  - Thread/task scheduling order
- ENFORCE BY:
  - **Time**: Inject a `Clock` trait or use `tokio::time::pause()` for async code. Never use `std::thread::sleep()` or `tokio::time::sleep()` as a synchronization mechanism — use channels, barriers, or condition variables instead.
  - **Randomness**: Use `rand::SeedableRng` with a fixed seed. Document the seed. If the code under test accepts an `Rng` parameter, pass a seeded `StdRng`.
  - **Network**: Use in-process channels, mock servers, or loopback with OS-assigned ports (bind to `127.0.0.1:0`, read the assigned port).
  - **Filesystem**: Use `tempfile::TempDir` for each test. Never read/write outside the temp dir. Assert cleanup via RAII drop.
  - **Scheduling**: Use deterministic task executors where available. For thread-order-sensitive logic, use `loom` (see RS-32).
[PROVENANCE] CTR-2501 (time as external input); CTR-2503 (controllable clock).

[HAZARD: RSK-3003] Sleep-Based Synchronization ("Timing Tests").
- FAILURE MODE: `sleep(Duration::from_millis(100))` works on the developer's machine but fails under CI load, producing flaky tests.
- REJECT IF: a test uses `sleep` / `tokio::time::sleep` to wait for an asynchronous condition to become true.
- ENFORCE BY:
  - Use explicit synchronization: `tokio::sync::Notify`, `tokio::sync::oneshot`, `std::sync::Barrier`, `std::sync::mpsc`, condition variables.
  - If testing timeout behavior, use `tokio::time::pause()` + `tokio::time::advance()` to control time deterministically.
  - If a real-time delay is genuinely needed (rare), use a generous timeout (10x expected) with a meaningful assertion on timeout failure, and document why synchronization primitives are insufficient.
[PROVENANCE] CI environments have variable scheduling latency; sleep-based tests are the #1 source of flakiness.
[VERIFICATION] Search for `sleep` in test code; each instance must have a justification comment or be replaced.

[HAZARD: RSK-3004] HashMap/HashSet Iteration Order Dependence.
- FAILURE MODE: Test asserts on the order of elements collected from a `HashMap` or `HashSet`. Passes on one build, fails on another (Rust randomizes hash seeds per compilation).
- REJECT IF: test assertions depend on the iteration order of `HashMap`, `HashSet`, or `BTreeMap` (unless the test explicitly sorts before comparison).
- ENFORCE BY:
  - Sort collected results before assertion: `let mut items: Vec<_> = map.values().collect(); items.sort();`
  - Use `BTreeMap`/`BTreeSet` in the code under test when ordering is part of the contract.
  - Assert on membership/count rather than ordered sequences when order is not part of the contract.
[PROVENANCE] Rust `HashMap` uses `RandomState` by default; iteration order is explicitly unspecified.

[HAZARD: RSK-3005] Port Binding Collisions.
- FAILURE MODE: Test binds to a hardcoded port (e.g., `8080`); parallel test or CI neighbor already holds the port.
- REJECT IF: tests use hardcoded port numbers.
- ENFORCE BY: Bind to `127.0.0.1:0` and read the assigned port from the listener's `local_addr()`.
[PROVENANCE] OS port assignment; parallel test execution.

---

## Side-Effect Capture

[CONTRACT: CTR-3003] Tests Must Capture Effects, Not Execute Them Against the Real World.
- REJECT IF: a test sends real HTTP requests to external services, writes to production paths, or executes real subprocesses when the test's purpose is to verify logic (not integration).
- ENFORCE BY:
  - Define I/O traits (`trait HttpClient`, `trait FileSystem`, `trait ProcessRunner`) that the production code uses.
  - Implement `struct FakeHttpClient` / `struct InMemoryFs` that record calls and return canned responses.
  - Assert on the captured call log (method, URL, body, headers) rather than on real responses.
  - For integration tests that genuinely need real I/O, use dedicated test fixtures with unique namespacing and cleanup.
[PROVENANCE] CTR-2622 (centralized configuration); CTR-2501 (external inputs as injected dependencies).

[INVARIANT: INV-3001] Test Side Effects Must Not Persist Beyond Test Scope.
- REJECT IF: a test leaves behind files, running processes, open sockets, or modified environment state after completion — whether it passes or fails.
- ENFORCE BY:
  - Use RAII guards (`TempDir`, `Drop` impls) for all resource acquisition.
  - Use `scopeguard::defer!` or `Drop` for cleanup that must happen even on panic.
  - Do not rely on test teardown logic that runs only in the success path.
[PROVENANCE] Test failures that leave artifacts corrupt subsequent test runs and CI state.

---

## Trait-Based Dependency Injection for Testability

[CONTRACT: CTR-3004] External Dependencies Use Trait Abstractions at Module Boundaries.
- REJECT IF: core logic directly calls `std::fs`, `std::net`, `std::time`, `std::process`, or HTTP clients without an abstraction boundary that tests can substitute.
- ENFORCE BY:
  - Define narrow traits at the boundary: `trait Clock { fn now(&self) -> Instant; }`, `trait Resolver { fn resolve(&self, id: &str) -> Result<T>; }`.
  - Production code is generic over the trait (or uses `&dyn Trait`).
  - Tests provide a deterministic implementation.
  - Keep trait surfaces minimal — one method per concern, not a God trait.
- EXCEPTION: Leaf functions that are themselves the boundary (e.g., a filesystem adapter module) may use `std::fs` directly; their tests use real temp directories.
[PROVENANCE] Dependency inversion principle; testability requires substitutability.

```text
Example: Clock injection pattern

// Production trait
trait Clock: Send + Sync {
    fn now(&self) -> std::time::Instant;
    fn wall_clock(&self) -> std::time::SystemTime;
}

// Production implementation
struct RealClock;
impl Clock for RealClock {
    fn now(&self) -> Instant { Instant::now() }
    fn wall_clock(&self) -> SystemTime { SystemTime::now() }
}

// Test implementation
struct FakeClock {
    instant: Mutex<Instant>,
}
impl FakeClock {
    fn advance(&self, duration: Duration) {
        // Deterministic time control
    }
}

// Usage: fn process_timeout(clock: &dyn Clock, deadline: Duration) -> bool
// Test: create FakeClock, advance past deadline, assert timeout fires
```

---

## Test Reproducibility

[INVARIANT: INV-3002] Every Test Failure Must Be Reproducible.
- REJECT IF: a test failure cannot be reproduced by re-running the exact same test binary with the same seed/inputs.
- ENFORCE BY:
  - Fixed RNG seeds (log the seed on failure for property tests).
  - Deterministic fake clocks.
  - Captured/recorded external responses (not live network calls).
  - For property tests (`proptest`, `quickcheck`): persist the regression file and commit it. These frameworks generate a `proptest-regressions/` directory with minimal failing cases — this MUST be committed to the repository.
[PROVENANCE] Irreproducible failures waste debugging time and erode trust in the test suite.

[HAZARD: RSK-3006] Flaky Tests Left in the Suite.
- FAILURE MODE: A test that fails intermittently is tagged `#[ignore]` or tolerated as "known flaky". Over time, the ignored test rots and real regressions are missed. Other developers learn to distrust test failures, reducing the suite's authority.
- REJECT IF: `#[ignore]` is applied to a flaky test without a linked ticket and a root-cause comment.
- REJECT IF: a test failure is retried in CI to achieve green status (retry-to-green masks real failures).
- ENFORCE BY:
  - Fix the nondeterminism source (see CTR-3002).
  - If the test cannot be fixed immediately, mark `#[ignore]` with `// FLAKY(TCK-XXXXX): <root cause>` and create a ticket.
  - Never add CI retry logic for individual tests.
[PROVENANCE] Test suite authority degrades when failures are normalized; flaky tests are a broken-windows problem.

---

## Async Test Discipline

[CONTRACT: CTR-3005] Async Tests Use Controlled Runtimes.
- REJECT IF: async tests depend on real time advancing, real network responses, or real filesystem I/O for correctness (as distinct from integration tests that intentionally exercise real I/O).
- ENFORCE BY:
  - Use `tokio::time::pause()` at the start of time-sensitive async tests. With time paused, `tokio::time::sleep` and `tokio::time::timeout` advance instantly to the target time — no wall-clock waiting.
  - For channel-based synchronization: use bounded channels with deterministic send/receive ordering.
  - For `select!` branches: test each branch independently; do not rely on scheduling to choose the "right" branch.
[PROVENANCE] Async runtimes introduce scheduling nondeterminism; `tokio::time::pause()` is the canonical mitigation.

```text
Example: Deterministic async timeout test

#[tokio::test]
async fn timeout_fires_deterministically() {
    tokio::time::pause();  // Freeze real time

    let result = tokio::time::timeout(
        Duration::from_secs(30),
        async { /* simulated slow operation */ tokio::time::sleep(Duration::from_secs(60)).await; }
    ).await;

    assert!(result.is_err(), "should have timed out");
    // Test completes instantly — no 30-second wait
}
```

---

## Subprocess and Command Testing

[CONTRACT: CTR-3006] Tests Must Not Execute Real Subprocesses for Logic Verification.
- REJECT IF: a test spawns real `git`, `cargo`, `docker`, or other system commands when the test's purpose is to verify the calling logic (argument construction, output parsing, error handling).
- ENFORCE BY:
  - Abstract subprocess execution behind a `trait CommandRunner { fn run(&self, cmd: &Command) -> Result<Output>; }`.
  - Test implementation records the command and returns canned `Output` (stdout, stderr, exit code).
  - Assert on the command arguments, not on real subprocess behavior.
  - Integration tests that genuinely verify end-to-end subprocess behavior are acceptable when explicitly scoped and labeled.
[PROVENANCE] Real subprocess execution introduces environmental nondeterminism (PATH, installed versions, OS differences) and slows test execution.

---

## Anti-Patterns (Test Reliability Killers)

[HAZARD: RSK-3007] Asserting on Debug/Display Format Strings.
- FAILURE MODE: `assert!(format!("{:?}", val).contains("expected"))` breaks when a field is renamed, reordered, or when the Debug derive changes.
- ENFORCE BY: Assert on typed fields, not string representations. Use pattern matching or field access.

[HAZARD: RSK-3008] Tests That Duplicate Implementation Logic.
- FAILURE MODE: The test re-implements the same algorithm as the production code and asserts equality. Both are wrong in the same way — the test passes but the behavior is incorrect.
- ENFORCE BY: Test against a specification, reference oracle, or known-good precomputed values. For complex transforms, use property-based testing (`proptest`) to verify invariants rather than reimplementing.
- APPLY: ANTITEST-TAUTOLOGY from RS-20.

[HAZARD: RSK-3009] Global Test Fixtures Without Isolation.
- FAILURE MODE: A `lazy_static!` or `once_cell::Lazy` initializes a shared resource (database, temp dir, config) used by all tests. One test modifies the resource; other tests see corrupted state.
- ENFORCE BY: Each test creates its own fixture via a helper function. Share only truly immutable, deterministic data. If expensive setup is needed, use `once_cell` for read-only initialization and ensure no test mutates the shared value.

[HAZARD: RSK-3010] Overly Tight Assertions on Floating-Point Values.
- REJECT IF: `assert_eq!(f64_result, 0.3)` or similar exact equality on computed floats.
- ENFORCE BY: Use epsilon comparison: `assert!((result - expected).abs() < 1e-10, ...)` or the `approx` crate's `assert_relative_eq!`.
[PROVENANCE] IEEE 754 floating-point arithmetic is not associative; computed values rarely equal mathematical expectations exactly.

---

## Simulation Testing for Complex State Machines

[CONTRACT: CTR-3007] Complex State Machines Should Have Simulation Test Harnesses.
- State machines with more than ~4 states and external inputs (I/O, time, concurrent events) benefit from simulation testing: a harness that drives the state machine through randomized-but-reproducible event sequences and asserts invariants at each step.
- ENFORCE BY:
  - Define the state machine's transition function as a pure function: `fn step(state: &State, event: &Event) -> (State, Vec<Effect>)`.
  - Write a simulation harness that generates random events (seeded RNG), applies them via `step()`, and checks invariants after each transition.
  - Invariant checks: no invalid state reached, monotonicity preserved, resource bounds maintained, no deadlocks.
  - On failure, the harness logs the full event sequence and seed for reproduction.
- NOTE: This is a recommendation for high-risk state machines, not a universal requirement. Apply when: the state space is large, real-world event ordering is unpredictable, and bugs in the state machine have high blast radius.
[PROVENANCE] Deterministic simulation testing (FoundationDB-style); property-based testing applied to stateful systems.
[VERIFICATION] `cargo test` with `proptest` or custom harness; seed logging; regression file committed.

```text
Simulation test sketch:

#[test]
fn state_machine_simulation() {
    let seed = 42u64;  // Or read from env for reproduction
    let mut rng = StdRng::seed_from_u64(seed);
    let mut state = State::initial();

    for step in 0..10_000 {
        let event = Event::arbitrary(&mut rng);
        let (next_state, effects) = state_machine::step(&state, &event);

        // Invariant checks after every transition
        assert!(next_state.is_valid(), "invalid state at step {step}, seed {seed}");
        assert!(next_state.sequence >= state.sequence, "monotonicity violated at step {step}");

        state = next_state;
    }
}
```

---

## References (Normative Anchors)

- RS-20 (`20_testing_evidence_and_ci.md`): Test evidence requirements and anti-patterns (ANTITEST-PANIC, ANTITEST-TAUTOLOGY).
- RS-32 (`32_testing_fuzz_miri_evidence.md`): Verification tool requirements (Miri, Loom, Proptest, Kani).
- RS-25 (`40_time_monotonicity_determinism.md`): Time injection, CTR-2501 (time as external input), CTR-2503 (controllable clock).
- RS-26 (`41_apm2_safe_patterns_and_anti_patterns.md`): CTR-2622 (centralized configuration), CTR-2614 (backend semantic equivalence).
- `proptest` crate: https://docs.rs/proptest/
- `tempfile` crate: https://docs.rs/tempfile/
- `tokio::time::pause`: https://docs.rs/tokio/latest/tokio/time/fn.pause.html
- FoundationDB Testing (inspiration): https://apple.github.io/foundationdb/testing.html
