# Concurrency Model (tokio)

## Session task topology
- `reader_task`: transport.recv() loop -> classify message -> route:
  - responses: fulfill pending `oneshot` by `id`
  - requests: spawn handler task (bounded concurrency)
  - notifications: enqueue to notification handlers (bounded)
- `writer_task`: single ordered sender consuming an MPSC queue to preserve ordering per stream.

## Backpressure and bounds
- Bounded queues:
  - inbound classification queue
  - outbound send queue
- Handler concurrency:
  - semaphore-limited (`max_inflight_handlers`)
  - per-method concurrency caps for high-cost methods (`tools/call`, `resources/read`)

### Transport Deadlock Mitigation
- **The Stalled Peer Problem**: In `stdio` or single-socket transports, if the local process blocks while writing to a full OS buffer (because the peer is slow to read), it may stop reading from the peer. If the peer is also blocked writing, a deadlock occurs.
- **Mitigation**:
  - `reader_task` and `writer_task` **MUST** be strictly independent.
  - The `writer_task` should use a bounded MPSC channel. If the channel is full, the producer (handler) should await, but the `reader_task` must remain unblocked to continue processing inbound cancellations or pings.
  - Use `tokio::select!` in handlers to ensure that a stalled write doesn't prevent responding to a `notifications/cancelled`.

## Cancellation / timeouts
- Per-request timeout:
  - requestor side: timeout waiting for response; then treat as failure and optionally cancel.
  - receiver side: honor `notifications/cancelled` cooperatively via cancel token.
- Transport read timeout for stuck peers (configurable).

## Task-augmented execution
- On task-augmented request:
  - create task record
  - return CreateTaskResult immediately
  - execute operation asynchronously
  - allow polling via tasks/get + tasks/result
  - optional status pushes via notifications/tasks/status

## Streamable HTTP note
- SSE stream may be intermittently closed by server to avoid long-lived connections.
- Client should treat this as polling and reconnect (not as cancellation).
