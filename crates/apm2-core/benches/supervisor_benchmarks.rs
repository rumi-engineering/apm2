//! Supervisor benchmarks.
//!
//! Benchmarks `HashMap` lookups and process management operations at various
//! scales. Performance matters here as these operations scale with managed
//! process count.

#![allow(missing_docs)]

mod common;

use apm2_core::process::{ProcessSpec, ProcessState};
use apm2_core::supervisor::Supervisor;
use common::create_process_specs;
use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};

/// Benchmark process registration at various scales.
fn bench_register_process(c: &mut Criterion) {
    let mut group = c.benchmark_group("supervisor/register");

    for count in [10, 50, 100, 250, 500] {
        let specs = create_process_specs(count);

        group.bench_with_input(BenchmarkId::from_parameter(count), &specs, |b, specs| {
            b.iter(|| {
                let mut supervisor = Supervisor::new();
                for spec in specs.iter().cloned() {
                    let _ = supervisor.register(black_box(spec));
                }
                supervisor
            });
        });
    }

    group.finish();
}

/// Benchmark process lookup by name at various scales.
fn bench_lookup_by_name(c: &mut Criterion) {
    let mut group = c.benchmark_group("supervisor/lookup_by_name");

    for count in [10, 50, 100, 250, 500] {
        let mut supervisor = Supervisor::new();
        for spec in create_process_specs(count) {
            let _ = supervisor.register(spec);
        }

        // Lookup process in the middle of the list
        let target_name = format!("process-{}", count / 2);

        group.bench_with_input(
            BenchmarkId::from_parameter(count),
            &(supervisor, target_name),
            |b, (supervisor, name)| {
                b.iter(|| supervisor.get_spec(black_box(name)));
            },
        );
    }

    group.finish();
}

/// Benchmark getting a process handle by name and instance.
fn bench_get_handle(c: &mut Criterion) {
    let mut group = c.benchmark_group("supervisor/get_handle");

    for count in [10, 50, 100, 250, 500] {
        let mut supervisor = Supervisor::new();
        for spec in create_process_specs(count) {
            let _ = supervisor.register(spec);
        }

        let target_name = format!("process-{}", count / 2);

        group.bench_with_input(
            BenchmarkId::from_parameter(count),
            &(supervisor, target_name),
            |b, (supervisor, name)| {
                b.iter(|| supervisor.get_handle(black_box(name), 0));
            },
        );
    }

    group.finish();
}

/// Benchmark getting all handles for a process name.
fn bench_get_handles(c: &mut Criterion) {
    let mut group = c.benchmark_group("supervisor/get_handles");

    // Create specs with multiple instances
    for instance_count in [1, 3, 5, 10] {
        let mut supervisor = Supervisor::new();

        for i in 0..50 {
            let spec = ProcessSpec::builder()
                .name(format!("process-{i}"))
                .command("/usr/bin/echo")
                .instances(instance_count)
                .build();
            let _ = supervisor.register(spec);
        }

        let target_name = "process-25";

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{instance_count}_instances")),
            &(supervisor, target_name),
            |b, (supervisor, name)| {
                b.iter(|| supervisor.get_handles(black_box(name)));
            },
        );
    }

    group.finish();
}

/// Benchmark updating process state.
fn bench_update_state(c: &mut Criterion) {
    let mut group = c.benchmark_group("supervisor/update_state");

    for count in [10, 50, 100, 250, 500] {
        let target_name = format!("process-{}", count / 2);

        group.bench_with_input(
            BenchmarkId::from_parameter(count),
            &target_name,
            |b, name| {
                b.iter_batched(
                    || {
                        let mut supervisor = Supervisor::new();
                        for spec in create_process_specs(count) {
                            let _ = supervisor.register(spec);
                        }
                        supervisor
                    },
                    |mut sup| {
                        sup.update_state(black_box(name), 0, ProcessState::Running);
                        sup
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

/// Benchmark listing all process names.
fn bench_list_names(c: &mut Criterion) {
    let mut group = c.benchmark_group("supervisor/list_names");

    for count in [10, 50, 100, 250, 500] {
        let mut supervisor = Supervisor::new();
        for spec in create_process_specs(count) {
            let _ = supervisor.register(spec);
        }

        group.bench_with_input(
            BenchmarkId::from_parameter(count),
            &supervisor,
            |b, supervisor| {
                b.iter(|| supervisor.list_names());
            },
        );
    }

    group.finish();
}

/// Benchmark counting running processes.
fn bench_running_count(c: &mut Criterion) {
    let mut group = c.benchmark_group("supervisor/running_count");

    for count in [10, 50, 100, 250, 500] {
        let mut supervisor = Supervisor::new();
        for spec in create_process_specs(count) {
            let _ = supervisor.register(spec);
        }

        // Mark half as running
        for i in 0..count / 2 {
            supervisor.update_state(&format!("process-{i}"), 0, ProcessState::Running);
        }

        group.bench_with_input(
            BenchmarkId::from_parameter(count),
            &supervisor,
            |b, supervisor| {
                b.iter(|| supervisor.running_count());
            },
        );
    }

    group.finish();
}

/// Benchmark unregistering a process.
fn bench_unregister(c: &mut Criterion) {
    let mut group = c.benchmark_group("supervisor/unregister");

    for count in [10, 50, 100, 250, 500] {
        let target_name = format!("process-{}", count / 2);

        group.bench_with_input(
            BenchmarkId::from_parameter(count),
            &target_name,
            |b, name| {
                b.iter_batched(
                    || {
                        let mut supervisor = Supervisor::new();
                        for spec in create_process_specs(count) {
                            let _ = supervisor.register(spec);
                        }
                        supervisor
                    },
                    |mut supervisor| {
                        let _ = supervisor.unregister(black_box(name));
                        supervisor
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_register_process,
    bench_lookup_by_name,
    bench_get_handle,
    bench_get_handles,
    bench_update_state,
    bench_list_names,
    bench_running_count,
    bench_unregister,
);

criterion_main!(benches);
