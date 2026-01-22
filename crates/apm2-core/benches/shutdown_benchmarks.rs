//! Shutdown state machine benchmarks.
//!
//! Benchmarks shutdown state transitions and configuration handling.
//! Called on every process stop, so state machine performance matters.

#![allow(missing_docs)]

use std::time::Duration;

use apm2_core::shutdown::{ShutdownConfig, ShutdownManager, ShutdownState, parse_signal};
use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};

/// Benchmark creating shutdown manager with various configurations.
fn bench_manager_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("shutdown/create_manager");

    // Default config
    group.bench_function("default_config", |b| {
        b.iter(|| {
            let config = ShutdownConfig::default();
            ShutdownManager::new(black_box(config))
        });
    });

    // Config with pre-shutdown commands
    group.bench_function("with_pre_commands", |b| {
        b.iter(|| {
            let config = ShutdownConfig {
                pre_shutdown_commands: vec![
                    "cleanup.sh".to_string(),
                    "notify-shutdown.sh".to_string(),
                ],
                ..Default::default()
            };
            ShutdownManager::new(black_box(config))
        });
    });

    // Custom config
    group.bench_function("custom_config", |b| {
        b.iter(|| {
            let config = ShutdownConfig {
                timeout: Duration::from_secs(60),
                signal: "SIGINT".to_string(),
                kill_delay: Duration::from_secs(10),
                force_kill: false,
                pre_shutdown_commands: Vec::new(),
            };
            ShutdownManager::new(black_box(config))
        });
    });

    group.finish();
}

/// Benchmark state machine transitions.
fn bench_state_transitions(c: &mut Criterion) {
    let mut group = c.benchmark_group("shutdown/transitions");

    // Simple shutdown path (no pre-commands)
    group.bench_function("simple_shutdown_path", |b| {
        b.iter(|| {
            let config = ShutdownConfig::default();
            let mut manager = ShutdownManager::new(config);

            manager.initiate();
            assert_eq!(manager.state(), ShutdownState::GracefulShutdown);

            manager.complete();
            assert_eq!(manager.state(), ShutdownState::Completed);
        });
    });

    // Full shutdown path with pre-commands
    group.bench_function("full_shutdown_path", |b| {
        b.iter(|| {
            let config = ShutdownConfig {
                pre_shutdown_commands: vec!["cleanup.sh".to_string()],
                ..Default::default()
            };
            let mut manager = ShutdownManager::new(config);

            manager.initiate();
            assert_eq!(manager.state(), ShutdownState::PreShutdown);

            manager.pre_shutdown_complete();
            assert_eq!(manager.state(), ShutdownState::GracefulShutdown);

            manager.initiate_force_kill();
            assert_eq!(manager.state(), ShutdownState::ForceKillPending);

            manager.complete();
            assert_eq!(manager.state(), ShutdownState::Completed);
        });
    });

    // Reset cycle
    group.bench_function("reset_cycle", |b| {
        b.iter(|| {
            let config = ShutdownConfig::default();
            let mut manager = ShutdownManager::new(config);

            manager.initiate();
            manager.complete();
            manager.reset();

            assert_eq!(manager.state(), ShutdownState::Running);
        });
    });

    group.finish();
}

/// Benchmark state queries.
fn bench_state_queries(c: &mut Criterion) {
    let mut group = c.benchmark_group("shutdown/queries");

    let config = ShutdownConfig::default();
    let manager = ShutdownManager::new(config);

    group.bench_function("state", |b| {
        b.iter(|| black_box(&manager).state());
    });

    group.bench_function("is_shutting_down", |b| {
        b.iter(|| black_box(&manager).is_shutting_down());
    });

    group.bench_function("signal", |b| {
        b.iter(|| black_box(&manager).signal());
    });

    group.bench_function("timeout", |b| {
        b.iter(|| black_box(&manager).timeout());
    });

    group.bench_function("force_kill_enabled", |b| {
        b.iter(|| black_box(&manager).force_kill_enabled());
    });

    group.finish();
}

/// Benchmark signal parsing.
fn bench_signal_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("shutdown/parse_signal");

    for signal in [
        "SIGTERM", "TERM", "sigterm", "SIGINT", "SIGHUP", "SIGKILL", "SIGUSR1",
    ] {
        group.bench_with_input(BenchmarkId::from_parameter(signal), signal, |b, sig| {
            b.iter(|| parse_signal(black_box(sig)));
        });
    }

    group.finish();
}

/// Benchmark timeout checking under various conditions.
fn bench_timeout_check(c: &mut Criterion) {
    let mut group = c.benchmark_group("shutdown/timeout_check");

    // Not shutting down - should return false immediately
    group.bench_function("not_shutting_down", |b| {
        let config = ShutdownConfig::default();
        let manager = ShutdownManager::new(config);
        b.iter(|| black_box(&manager).has_timed_out());
    });

    // Shutting down but not timed out
    group.bench_function("shutting_down_not_expired", |b| {
        let config = ShutdownConfig {
            timeout: Duration::from_secs(3600), // 1 hour - won't time out
            ..Default::default()
        };
        let mut manager = ShutdownManager::new(config);
        manager.initiate();
        b.iter(|| black_box(&manager).has_timed_out());
    });

    group.finish();
}

/// Benchmark config cloning (important for creating managers).
fn bench_config_clone(c: &mut Criterion) {
    let mut group = c.benchmark_group("shutdown/config_clone");

    group.bench_function("default", |b| {
        let config = ShutdownConfig::default();
        b.iter(|| black_box(&config).clone());
    });

    group.bench_function("with_commands", |b| {
        let config = ShutdownConfig {
            pre_shutdown_commands: vec![
                "step1.sh".to_string(),
                "step2.sh".to_string(),
                "step3.sh".to_string(),
            ],
            ..Default::default()
        };
        b.iter(|| black_box(&config).clone());
    });

    group.finish();
}

/// Benchmark `ShutdownState` display formatting.
fn bench_state_display(c: &mut Criterion) {
    let mut group = c.benchmark_group("shutdown/state_display");

    let states = [
        ("running", ShutdownState::Running),
        ("pre_shutdown", ShutdownState::PreShutdown),
        ("graceful_shutdown", ShutdownState::GracefulShutdown),
        ("force_kill_pending", ShutdownState::ForceKillPending),
        ("completed", ShutdownState::Completed),
    ];

    for (name, state) in states {
        group.bench_with_input(BenchmarkId::from_parameter(name), &state, |b, state| {
            b.iter(|| format!("{}", black_box(state)));
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_manager_creation,
    bench_state_transitions,
    bench_state_queries,
    bench_signal_parsing,
    bench_timeout_check,
    bench_config_clone,
    bench_state_display,
);

criterion_main!(benches);
