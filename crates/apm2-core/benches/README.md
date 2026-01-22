# Benchmarks

This directory contains Criterion benchmarks for performance-critical code paths in apm2-core.

## Design Philosophy

**Benchmark deterministic code, NOT OS-dependent operations.**

We deliberately avoid benchmarking:
- Actual process spawning (OS scheduling is non-deterministic)
- Real socket I/O (network latency varies)
- File system operations (disk performance varies)

Instead, we benchmark:
- Data structure operations (HashMap lookups, Vec operations)
- Serialization/deserialization (JSON encoding)
- State machine transitions
- Memory allocation patterns

## Benchmark Suites

| Suite | What It Measures | Why It Matters |
|-------|------------------|----------------|
| `ipc_benchmarks` | JSON serialization, frame encoding | IPC is the hot path for every command |
| `supervisor_benchmarks` | HashMap lookups with 10-500 processes | Scales with managed process count |
| `shutdown_benchmarks` | State machine transitions | Called on every process stop |
| `spawn_benchmarks` | ProcessSpec creation with varying env sizes | Called on every process start |
| `state_benchmarks` | RwLock acquisition patterns, state serialization | Lock contention under load |
| `hotswap_benchmarks` | Credential swap state machine | Critical for zero-downtime cred rotation |

## Running Benchmarks

### Run All Benchmarks

```bash
cargo bench --package apm2-core
```

### Run Specific Benchmark Suite

```bash
cargo bench --package apm2-core --bench ipc_benchmarks
cargo bench --package apm2-core --bench supervisor_benchmarks
cargo bench --package apm2-core --bench shutdown_benchmarks
cargo bench --package apm2-core --bench spawn_benchmarks
cargo bench --package apm2-core --bench state_benchmarks
cargo bench --package apm2-core --bench hotswap_benchmarks
```

### Run Specific Benchmark Group

```bash
# Run only IPC serialization benchmarks
cargo bench --package apm2-core --bench ipc_benchmarks -- "ipc/request_serialize"

# Run only supervisor lookup benchmarks
cargo bench --package apm2-core --bench supervisor_benchmarks -- "supervisor/lookup"
```

## Comparing Changes

### Save Baseline Before Changes

```bash
cargo bench --package apm2-core -- --save-baseline before
```

### Run Benchmark After Changes

```bash
cargo bench --package apm2-core -- --save-baseline after
```

### Compare Results

Install `critcmp` first:

```bash
cargo install critcmp
```

Then compare:

```bash
critcmp before after
```

## Interpreting Results

Criterion provides:
- **Mean**: Average execution time
- **Std Dev**: Variation in measurements
- **Throughput**: Operations per second (where applicable)

### What to Look For

1. **Regressions > 20%**: Investigate the cause
2. **Improvements > 20%**: Verify they're real, not noise
3. **High Std Dev**: Results may be unreliable, consider running longer

### CI Variance

GitHub Actions runners have 10-20% variance. Don't set hard regression thresholds.
Instead, use benchmarks for:
- Detecting major regressions (2x+ slower)
- Tracking trends over time
- Validating optimization attempts locally

## Adding New Benchmarks

1. Create a new file in `benches/` (e.g., `new_benchmarks.rs`)
2. Add `[[bench]]` section to `Cargo.toml`:
   ```toml
   [[bench]]
   name = "new_benchmarks"
   harness = false
   ```
3. Use the common fixtures from `common/mod.rs`
4. Follow the pattern of existing benchmarks

### Benchmark Template

```rust
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_something(c: &mut Criterion) {
    let mut group = c.benchmark_group("category/operation");

    group.bench_function("variant_name", |b| {
        b.iter(|| {
            // Code to benchmark
            black_box(operation())
        });
    });

    group.finish();
}

criterion_group!(benches, bench_something);
criterion_main!(benches);
```

## CI Integration

Benchmarks run:
- **On releases** (v* tags): Results stored for historical tracking
- **Manually**: Via workflow_dispatch with configurable baseline
- **On PR comments**: `/benchmark` triggers comparison against main

Benchmarks **never block** releases (continue-on-error: true).

## Output Location

Criterion stores results in:
- `target/criterion/` - Raw benchmark data
- `target/criterion/report/` - HTML reports

Open `target/criterion/report/index.html` for interactive graphs.
