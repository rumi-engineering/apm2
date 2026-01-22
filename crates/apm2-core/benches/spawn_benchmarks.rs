//! Process spawn preparation benchmarks.
//!
//! Benchmarks `ProcessSpec` creation with varying environment sizes.
//! Called on every process start, so spec creation performance matters.
//!
//! NOTE: We benchmark spec creation, NOT actual process spawning, because
//! actual spawning involves OS scheduling which is non-deterministic.

#![allow(missing_docs)]

mod common;

use std::collections::HashMap;

use apm2_core::process::ProcessSpec;
use apm2_core::restart::RestartConfig;
use apm2_core::shutdown::ShutdownConfig;
use common::create_process_spec;
use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};

/// Benchmark `ProcessSpec` creation with varying environment sizes.
fn bench_spec_creation_env_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("spawn/spec_creation_env");

    for env_count in [0, 5, 10, 25, 50, 100] {
        group.bench_with_input(
            BenchmarkId::from_parameter(env_count),
            &env_count,
            |b, &count| {
                b.iter(|| create_process_spec(black_box("test-process"), count));
            },
        );
    }

    group.finish();
}

/// Benchmark `ProcessSpec` builder pattern.
fn bench_spec_builder(c: &mut Criterion) {
    let mut group = c.benchmark_group("spawn/spec_builder");

    // Minimal spec
    group.bench_function("minimal", |b| {
        b.iter(|| {
            ProcessSpec::builder()
                .name(black_box("test"))
                .command(black_box("/usr/bin/echo"))
                .build()
        });
    });

    // Spec with args
    group.bench_function("with_args", |b| {
        b.iter(|| {
            ProcessSpec::builder()
                .name(black_box("test"))
                .command(black_box("/usr/bin/echo"))
                .args(black_box(["arg1", "arg2", "arg3"]))
                .build()
        });
    });

    // Spec with cwd
    group.bench_function("with_cwd", |b| {
        b.iter(|| {
            ProcessSpec::builder()
                .name(black_box("test"))
                .command(black_box("/usr/bin/echo"))
                .cwd(black_box("/home/user/app"))
                .build()
        });
    });

    // Spec with instances
    group.bench_function("with_instances", |b| {
        b.iter(|| {
            ProcessSpec::builder()
                .name(black_box("test"))
                .command(black_box("/usr/bin/echo"))
                .instances(black_box(5))
                .build()
        });
    });

    // Full spec with all options
    group.bench_function("full_spec", |b| {
        b.iter(|| {
            ProcessSpec::builder()
                .name(black_box("test"))
                .command(black_box("/usr/bin/node"))
                .args(black_box(["server.js", "--port", "3000"]))
                .cwd(black_box("/app"))
                .env(black_box("NODE_ENV"), black_box("production"))
                .env(black_box("PORT"), black_box("3000"))
                .instances(black_box(3))
                .restart(RestartConfig::default())
                .shutdown(ShutdownConfig::default())
                .build()
        });
    });

    group.finish();
}

/// Benchmark environment variable insertion.
fn bench_env_insertion(c: &mut Criterion) {
    let mut group = c.benchmark_group("spawn/env_insertion");

    for count in [1, 5, 10, 25, 50] {
        group.bench_with_input(BenchmarkId::from_parameter(count), &count, |b, &count| {
            b.iter(|| {
                let mut builder = ProcessSpec::builder()
                    .name(black_box("test"))
                    .command(black_box("/usr/bin/echo"));

                for i in 0..count {
                    builder = builder.env(
                        black_box(format!("VAR_{i}")),
                        black_box(format!("value_{i}")),
                    );
                }

                builder.build()
            });
        });
    }

    group.finish();
}

/// Benchmark `ProcessSpec` cloning.
fn bench_spec_clone(c: &mut Criterion) {
    let mut group = c.benchmark_group("spawn/spec_clone");

    // Clone minimal spec
    let minimal = ProcessSpec::builder()
        .name("minimal")
        .command("/usr/bin/echo")
        .build();

    group.bench_with_input(BenchmarkId::new("clone", "minimal"), &minimal, |b, spec| {
        b.iter(|| black_box(spec).clone());
    });

    // Clone spec with env
    let with_env = create_process_spec("with_env", 20);
    group.bench_with_input(
        BenchmarkId::new("clone", "with_20_env"),
        &with_env,
        |b, spec| {
            b.iter(|| black_box(spec).clone());
        },
    );

    // Clone large env spec
    let large_env = create_process_spec("large_env", 100);
    group.bench_with_input(
        BenchmarkId::new("clone", "with_100_env"),
        &large_env,
        |b, spec| {
            b.iter(|| black_box(spec).clone());
        },
    );

    group.finish();
}

/// Benchmark `ProcessSpec` serialization (for state persistence).
fn bench_spec_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("spawn/spec_serialize");

    for env_count in [0, 10, 50, 100] {
        let spec = create_process_spec("test", env_count);

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{env_count}_env")),
            &spec,
            |b, spec| {
                b.iter(|| serde_json::to_vec(black_box(spec)));
            },
        );
    }

    group.finish();
}

/// Benchmark `ProcessSpec` deserialization (for state recovery).
fn bench_spec_deserialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("spawn/spec_deserialize");

    for env_count in [0, 10, 50, 100] {
        let spec = create_process_spec("test", env_count);
        let serialized = serde_json::to_vec(&spec).unwrap();

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{env_count}_env")),
            &serialized,
            |b, data| {
                b.iter(|| serde_json::from_slice::<ProcessSpec>(black_box(data)));
            },
        );
    }

    group.finish();
}

/// Benchmark `HashMap` creation for environment variables.
fn bench_env_hashmap_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("spawn/env_hashmap");

    for count in [5, 10, 25, 50, 100] {
        group.bench_with_input(BenchmarkId::from_parameter(count), &count, |b, &count| {
            b.iter(|| {
                let mut map = HashMap::with_capacity(count);
                for i in 0..count {
                    map.insert(format!("VAR_{i}"), format!("value_{i}"));
                }
                black_box(map)
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_spec_creation_env_scaling,
    bench_spec_builder,
    bench_env_insertion,
    bench_spec_clone,
    bench_spec_serialization,
    bench_spec_deserialization,
    bench_env_hashmap_creation,
);

criterion_main!(benches);
