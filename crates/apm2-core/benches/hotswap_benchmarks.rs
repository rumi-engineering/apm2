//! Credential hot-swap state machine benchmarks.
//!
//! Benchmarks the `HotSwapManager` state machine transitions.
//! Critical for zero-downtime credential rotation.

#![allow(missing_docs)]

use std::time::Duration;

use apm2_core::credentials::{HotSwapConfig, HotSwapManager, HotSwapState};
use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};

/// Benchmark `HotSwapManager` creation with various configurations.
fn bench_manager_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("hotswap/create_manager");

    group.bench_function("default_config", |b| {
        b.iter(|| {
            let config = HotSwapConfig::default();
            HotSwapManager::new(black_box(config))
        });
    });

    group.bench_function("custom_config", |b| {
        b.iter(|| {
            let config = HotSwapConfig {
                signal: "SIGUSR1".to_string(),
                env_injection: true,
                config_file_path: Some("/etc/app/creds.json".into()),
                graceful_drain: Duration::from_secs(10),
                validate_before_swap: true,
                rollback_on_failure: true,
            };
            HotSwapManager::new(black_box(config))
        });
    });

    group.finish();
}

/// Benchmark complete hot-swap state machine cycle.
fn bench_state_machine_cycle(c: &mut Criterion) {
    let mut group = c.benchmark_group("hotswap/state_machine");

    // Successful swap cycle
    group.bench_function("successful_swap", |b| {
        b.iter(|| {
            let config = HotSwapConfig::default();
            let mut manager = HotSwapManager::new(config);

            manager.start_swap("old-profile".to_string()).unwrap();
            assert_eq!(*manager.state(), HotSwapState::Validating);

            manager.begin_drain();
            assert_eq!(*manager.state(), HotSwapState::Draining);

            manager.begin_apply();
            assert_eq!(*manager.state(), HotSwapState::Applying);

            manager.complete();
            assert_eq!(*manager.state(), HotSwapState::Completed);
        });
    });

    // Failed swap with rollback
    group.bench_function("failed_swap_rollback", |b| {
        b.iter(|| {
            let config = HotSwapConfig {
                rollback_on_failure: true,
                ..Default::default()
            };
            let mut manager = HotSwapManager::new(config);

            manager.start_swap("old-profile".to_string()).unwrap();
            manager.begin_drain();
            manager.fail("validation failed".to_string());

            assert_eq!(*manager.state(), HotSwapState::RollingBack);

            manager.complete_rollback(true);
            assert_eq!(*manager.state(), HotSwapState::Idle);
        });
    });

    // Reset cycle
    group.bench_function("reset_cycle", |b| {
        b.iter(|| {
            let config = HotSwapConfig::default();
            let mut manager = HotSwapManager::new(config);

            manager.start_swap("profile".to_string()).unwrap();
            manager.begin_drain();
            manager.reset();

            assert_eq!(*manager.state(), HotSwapState::Idle);
        });
    });

    group.finish();
}

/// Benchmark state queries.
fn bench_state_queries(c: &mut Criterion) {
    let mut group = c.benchmark_group("hotswap/queries");

    let config = HotSwapConfig::default();
    let manager = HotSwapManager::new(config);

    group.bench_function("state", |b| {
        b.iter(|| black_box(&manager).state());
    });

    group.bench_function("is_in_progress", |b| {
        b.iter(|| black_box(&manager).is_in_progress());
    });

    group.bench_function("config", |b| {
        b.iter(|| black_box(&manager).config());
    });

    group.bench_function("previous_profile", |b| {
        b.iter(|| black_box(&manager).previous_profile());
    });

    group.finish();
}

/// Benchmark individual state transitions.
fn bench_individual_transitions(c: &mut Criterion) {
    let mut group = c.benchmark_group("hotswap/transitions");

    // start_swap
    group.bench_function("start_swap", |b| {
        b.iter_batched(
            || HotSwapManager::new(HotSwapConfig::default()),
            |mut manager: HotSwapManager| {
                let _ = manager.start_swap(black_box("profile".to_string()));
                manager
            },
            criterion::BatchSize::SmallInput,
        );
    });

    // begin_drain
    group.bench_function("begin_drain", |b| {
        b.iter_batched(
            || {
                let mut manager = HotSwapManager::new(HotSwapConfig::default());
                manager.start_swap("profile".to_string()).unwrap();
                manager
            },
            |mut manager: HotSwapManager| {
                manager.begin_drain();
                manager
            },
            criterion::BatchSize::SmallInput,
        );
    });

    // begin_apply
    group.bench_function("begin_apply", |b| {
        b.iter_batched(
            || {
                let mut manager = HotSwapManager::new(HotSwapConfig::default());
                manager.start_swap("profile".to_string()).unwrap();
                manager.begin_drain();
                manager
            },
            |mut manager: HotSwapManager| {
                manager.begin_apply();
                manager
            },
            criterion::BatchSize::SmallInput,
        );
    });

    // complete
    group.bench_function("complete", |b| {
        b.iter_batched(
            || {
                let mut manager = HotSwapManager::new(HotSwapConfig::default());
                manager.start_swap("profile".to_string()).unwrap();
                manager.begin_drain();
                manager.begin_apply();
                manager
            },
            |mut manager: HotSwapManager| {
                manager.complete();
                manager
            },
            criterion::BatchSize::SmallInput,
        );
    });

    // fail
    group.bench_function("fail", |b| {
        b.iter_batched(
            || {
                let mut manager = HotSwapManager::new(HotSwapConfig::default());
                manager.start_swap("profile".to_string()).unwrap();
                manager.begin_drain();
                manager
            },
            |mut manager: HotSwapManager| {
                manager.fail(black_box("error message".to_string()));
                manager
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

/// Benchmark `HotSwapState` display formatting.
fn bench_state_display(c: &mut Criterion) {
    let mut group = c.benchmark_group("hotswap/state_display");

    let states: Vec<(&str, HotSwapState)> = vec![
        ("idle", HotSwapState::Idle),
        ("validating", HotSwapState::Validating),
        ("draining", HotSwapState::Draining),
        ("applying", HotSwapState::Applying),
        ("completed", HotSwapState::Completed),
        ("rolling_back", HotSwapState::RollingBack),
        ("failed", HotSwapState::Failed("error".to_string())),
    ];

    for (name, state) in states {
        group.bench_with_input(BenchmarkId::from_parameter(name), &state, |b, state| {
            b.iter(|| format!("{}", black_box(state)));
        });
    }

    group.finish();
}

/// Benchmark config cloning.
fn bench_config_clone(c: &mut Criterion) {
    let mut group = c.benchmark_group("hotswap/config_clone");

    group.bench_function("default", |b| {
        let config = HotSwapConfig::default();
        b.iter(|| black_box(&config).clone());
    });

    group.bench_function("with_config_path", |b| {
        let config = HotSwapConfig {
            config_file_path: Some("/etc/app/credentials.json".into()),
            ..Default::default()
        };
        b.iter(|| black_box(&config).clone());
    });

    group.finish();
}

/// Benchmark concurrent swap prevention check.
fn bench_concurrent_swap_check(c: &mut Criterion) {
    let mut group = c.benchmark_group("hotswap/concurrent_check");

    // When idle - should succeed
    group.bench_function("when_idle", |b| {
        let manager = HotSwapManager::new(HotSwapConfig::default());
        b.iter(|| black_box(&manager).is_in_progress());
    });

    // When in progress - should fail
    group.bench_function("when_in_progress", |b| {
        let mut manager = HotSwapManager::new(HotSwapConfig::default());
        manager.start_swap("profile".to_string()).unwrap();
        b.iter(|| black_box(&manager).is_in_progress());
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_manager_creation,
    bench_state_machine_cycle,
    bench_state_queries,
    bench_individual_transitions,
    bench_state_display,
    bench_config_clone,
    bench_concurrent_swap_check,
);

criterion_main!(benches);
