//! IPC serialization and framing benchmarks.
//!
//! Benchmarks JSON serialization/deserialization of IPC messages and frame
//! encoding. IPC is the hot path for every command, so performance here is
//! critical.

#![allow(missing_docs)]

mod common;

use apm2_core::ipc::{IpcRequest, IpcResponse, frame_message, parse_frame_length};
use common::{
    create_ipc_requests, create_ipc_responses, create_log_entries, create_process_summaries,
};
use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};

/// Benchmark serialization of IPC requests.
fn bench_request_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("ipc/request_serialize");

    for (name, request) in create_ipc_requests() {
        group.bench_with_input(BenchmarkId::from_parameter(name), &request, |b, req| {
            b.iter(|| serde_json::to_vec(black_box(req)));
        });
    }

    group.finish();
}

/// Benchmark deserialization of IPC requests.
fn bench_request_deserialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("ipc/request_deserialize");

    let serialized: Vec<_> = create_ipc_requests()
        .into_iter()
        .map(|(name, req)| (name, serde_json::to_vec(&req).unwrap()))
        .collect();

    for (name, data) in &serialized {
        group.throughput(Throughput::Bytes(data.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(name), data, |b, data| {
            b.iter(|| serde_json::from_slice::<IpcRequest>(black_box(data)));
        });
    }

    group.finish();
}

/// Benchmark serialization of IPC responses.
fn bench_response_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("ipc/response_serialize");

    for (name, response) in create_ipc_responses() {
        group.bench_with_input(BenchmarkId::from_parameter(name), &response, |b, resp| {
            b.iter(|| serde_json::to_vec(black_box(resp)));
        });
    }

    group.finish();
}

/// Benchmark deserialization of IPC responses.
fn bench_response_deserialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("ipc/response_deserialize");

    let serialized: Vec<_> = create_ipc_responses()
        .into_iter()
        .map(|(name, resp)| (name, serde_json::to_vec(&resp).unwrap()))
        .collect();

    for (name, data) in &serialized {
        group.throughput(Throughput::Bytes(data.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(name), data, |b, data| {
            b.iter(|| serde_json::from_slice::<IpcResponse>(black_box(data)));
        });
    }

    group.finish();
}

/// Benchmark frame encoding with various payload sizes.
fn bench_frame_encoding(c: &mut Criterion) {
    let mut group = c.benchmark_group("ipc/frame_encode");

    for size in [64, 256, 1024, 4096, 16384] {
        let payload = vec![0u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &payload, |b, data| {
            b.iter(|| frame_message(black_box(data)));
        });
    }

    group.finish();
}

/// Benchmark frame length parsing.
fn bench_frame_length_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("ipc/frame_parse_length");

    for size in [64, 1024, 65536] {
        let payload = vec![0u8; size];
        let framed = frame_message(&payload);
        group.bench_with_input(BenchmarkId::from_parameter(size), &framed, |b, data| {
            b.iter(|| parse_frame_length(black_box(data)));
        });
    }

    group.finish();
}

/// Benchmark serialization with varying response sizes.
fn bench_response_size_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("ipc/response_scaling");

    for count in [1, 10, 50, 100, 500] {
        let response = IpcResponse::ProcessList {
            processes: create_process_summaries(count),
        };

        group.bench_with_input(
            BenchmarkId::new("process_list", count),
            &response,
            |b, resp| {
                b.iter(|| serde_json::to_vec(black_box(resp)));
            },
        );
    }

    for count in [10, 50, 100, 500, 1000] {
        let response = IpcResponse::LogLines {
            lines: create_log_entries(count),
        };

        group.bench_with_input(
            BenchmarkId::new("log_lines", count),
            &response,
            |b, resp| {
                b.iter(|| serde_json::to_vec(black_box(resp)));
            },
        );
    }

    group.finish();
}

/// Benchmark complete round-trip (serialize -> frame -> parse length ->
/// deserialize).
fn bench_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("ipc/roundtrip");

    for (name, request) in create_ipc_requests() {
        group.bench_with_input(BenchmarkId::from_parameter(name), &request, |b, req| {
            b.iter(|| {
                let serialized = serde_json::to_vec(black_box(req)).unwrap();
                let framed = frame_message(&serialized);
                let len = parse_frame_length(&framed).unwrap();
                let payload = &framed[4..4 + len];
                serde_json::from_slice::<IpcRequest>(payload).unwrap()
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_request_serialization,
    bench_request_deserialization,
    bench_response_serialization,
    bench_response_deserialization,
    bench_frame_encoding,
    bench_frame_length_parsing,
    bench_response_size_scaling,
    bench_roundtrip,
);

criterion_main!(benches);
