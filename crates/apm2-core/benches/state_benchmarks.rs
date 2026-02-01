//! State persistence benchmarks.
//!
//! Benchmarks state serialization and `HashMap` operations for state tracking.
//! Lock contention patterns are simulated with read/write patterns.

#![allow(missing_docs)]

mod common;

use std::collections::HashMap;
use std::sync::RwLock;

use apm2_core::process::{ProcessId, ProcessState};
use apm2_core::state::{PersistedProcessInstance, PersistedState};
use chrono::{TimeZone, Utc};
use common::create_process_spec;
use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};

/// Benchmark `PersistedState` creation and manipulation.
fn bench_persisted_state(c: &mut Criterion) {
    let mut group = c.benchmark_group("state/persisted_state");

    group.bench_function("new", |b| {
        b.iter(PersistedState::new);
    });

    group.bench_function("add_spec", |b| {
        b.iter_batched(
            PersistedState::new,
            |mut state| {
                let spec = create_process_spec("test", 5);
                state.add_spec(black_box(spec));
                state
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

/// Benchmark state serialization at various sizes.
fn bench_state_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("state/serialize");

    for process_count in [1u32, 10, 50, 100, 250] {
        let mut state = PersistedState::new();

        for i in 0..process_count {
            let spec = create_process_spec(&format!("process-{i}"), 5);
            let spec_id = spec.id;
            state.add_spec(spec);

            // Add instance state
            state.update_instance(PersistedProcessInstance {
                spec_id,
                instance_index: 0,
                state: ProcessState::Running,
                pid: Some(10000 + i),
                started_at: Some(Utc.with_ymd_and_hms(2026, 1, 15, 12, 0, 0).unwrap()),
                restart_count: 2,
                last_restart: Some(Utc.with_ymd_and_hms(2026, 1, 15, 12, 0, 0).unwrap()),
                credential_profile: Some("claude-prod".to_string()),
            });
        }

        group.bench_with_input(
            BenchmarkId::from_parameter(process_count),
            &state,
            |b, state| {
                b.iter(|| serde_json::to_string(black_box(state)));
            },
        );
    }

    group.finish();
}

/// Benchmark state deserialization at various sizes.
fn bench_state_deserialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("state/deserialize");

    for process_count in [1u32, 10, 50, 100, 250] {
        let mut state = PersistedState::new();

        for i in 0..process_count {
            let spec = create_process_spec(&format!("process-{i}"), 5);
            let spec_id = spec.id;
            state.add_spec(spec);

            state.update_instance(PersistedProcessInstance {
                spec_id,
                instance_index: 0,
                state: ProcessState::Running,
                pid: Some(10000 + i),
                started_at: Some(Utc.with_ymd_and_hms(2026, 1, 15, 12, 0, 0).unwrap()),
                restart_count: 2,
                last_restart: Some(Utc.with_ymd_and_hms(2026, 1, 15, 12, 0, 0).unwrap()),
                credential_profile: Some("claude-prod".to_string()),
            });
        }

        let serialized = serde_json::to_string(&state).unwrap();

        group.bench_with_input(
            BenchmarkId::from_parameter(process_count),
            &serialized,
            |b, data| {
                b.iter(|| serde_json::from_str::<PersistedState>(black_box(data)));
            },
        );
    }

    group.finish();
}

/// Benchmark instance state updates.
fn bench_instance_update(c: &mut Criterion) {
    let mut group = c.benchmark_group("state/instance_update");

    for process_count in [10, 50, 100, 250] {
        let mut state = PersistedState::new();

        for i in 0..process_count {
            let spec = create_process_spec(&format!("process-{i}"), 5);
            let spec_id = spec.id;
            state.add_spec(spec);

            state.update_instance(PersistedProcessInstance::new(spec_id, 0));
        }

        // Get a spec_id from the middle
        let target_spec_id = state.specs.keys().nth(process_count / 2).copied().unwrap();

        group.bench_with_input(
            BenchmarkId::from_parameter(process_count),
            &(state, target_spec_id),
            |b, (state, spec_id)| {
                b.iter_batched(
                    || state.clone(),
                    |mut s| {
                        s.update_instance(PersistedProcessInstance {
                            spec_id: *spec_id,
                            instance_index: 0,
                            state: ProcessState::Running,
                            pid: Some(12345),
                            started_at: Some(Utc.with_ymd_and_hms(2026, 1, 15, 12, 0, 0).unwrap()),
                            restart_count: 1,
                            last_restart: None,
                            credential_profile: None,
                        });
                        s
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

/// Benchmark `RwLock` acquisition patterns (simulating `StateManager`).
fn bench_rwlock_patterns(c: &mut Criterion) {
    let mut group = c.benchmark_group("state/rwlock");

    // Read-heavy workload (common case)
    group.bench_function("read_lock", |b| {
        let lock = RwLock::new(PersistedState::new());
        b.iter(|| {
            let guard = lock.read().unwrap();
            black_box(&*guard);
        });
    });

    // Write lock (less common) - actually mutate to measure real write lock cost
    group.bench_function("write_lock", |b| {
        let lock = RwLock::new(PersistedState::new());
        b.iter(|| {
            let mut guard = lock.write().unwrap();
            guard.version += 1;
            black_box(&*guard);
        });
    });

    // Read then access data
    group.bench_function("read_and_access", |b| {
        let mut state = PersistedState::new();
        for i in 0..50 {
            state.add_spec(create_process_spec(&format!("process-{i}"), 5));
        }
        let lock = RwLock::new(state);

        b.iter(|| {
            let guard = lock.read().unwrap();
            black_box(guard.specs.len())
        });
    });

    group.finish();
}

/// Benchmark `HashMap` operations for `ProcessId` lookups.
fn bench_process_id_hashmap(c: &mut Criterion) {
    let mut group = c.benchmark_group("state/process_id_hashmap");

    for count in [10, 50, 100, 250, 500] {
        let mut map: HashMap<ProcessId, String> = HashMap::new();
        let mut ids = Vec::new();

        for i in 0..count {
            let id = ProcessId::new();
            map.insert(id, format!("process-{i}"));
            ids.push(id);
        }

        let target_id = ids[count / 2];

        // Lookup by ProcessId
        group.bench_with_input(
            BenchmarkId::new("lookup", count),
            &(map.clone(), target_id),
            |b, (map, id)| {
                b.iter(|| map.get(black_box(id)));
            },
        );

        // Insert new
        group.bench_with_input(BenchmarkId::new("insert", count), &map, |b, map| {
            b.iter_batched(
                || map.clone(),
                |mut m| {
                    m.insert(ProcessId::new(), "new-process".to_string());
                    m
                },
                criterion::BatchSize::SmallInput,
            );
        });

        // Remove
        group.bench_with_input(
            BenchmarkId::new("remove", count),
            &(map.clone(), target_id),
            |b, (map, id)| {
                b.iter_batched(
                    || map.clone(),
                    |mut m| {
                        m.remove(black_box(id));
                        m
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

/// Benchmark `ProcessState` transitions.
fn bench_process_state_transitions(c: &mut Criterion) {
    let mut group = c.benchmark_group("state/process_state");

    let states = [
        ("starting", ProcessState::Starting),
        ("running", ProcessState::Running),
        ("unhealthy", ProcessState::Unhealthy),
        ("stopping", ProcessState::Stopping),
        ("stopped", ProcessState::Stopped { exit_code: Some(0) }),
        ("crashed", ProcessState::Crashed { exit_code: Some(1) }),
        ("terminated", ProcessState::Terminated),
    ];

    // is_running check
    for (name, state) in &states {
        group.bench_with_input(BenchmarkId::new("is_running", name), state, |b, state| {
            b.iter(|| black_box(state).is_running());
        });
    }

    // has_exited check
    for (name, state) in &states {
        group.bench_with_input(BenchmarkId::new("has_exited", name), state, |b, state| {
            b.iter(|| black_box(state).has_exited());
        });
    }

    // Display formatting
    for (name, state) in &states {
        group.bench_with_input(BenchmarkId::new("display", name), state, |b, state| {
            b.iter(|| format!("{}", black_box(state)));
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_persisted_state,
    bench_state_serialization,
    bench_state_deserialization,
    bench_instance_update,
    bench_rwlock_patterns,
    bench_process_id_hashmap,
    bench_process_state_transitions,
);

criterion_main!(benches);
