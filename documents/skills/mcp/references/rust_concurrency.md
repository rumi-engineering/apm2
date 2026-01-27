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

### Transport Deadlock Mitigation (The Stalled Peer Problem)
In `stdio` or single-socket transports, a deadlock occurs if the Server's `stdout` pipe is full (Server blocked on `write`) while the Client's `stdout` pipe is also full (Client blocked on `write` to Server's `stdin`). 

**Implementation Mandates:**
1.  **Strict Task Separation**: The `reader_task` and `writer_task` MUST NOT share a mutex or be awaited sequentially in the same loop. 
2.  **Unblockable Reader**: The `reader_task` MUST continue to drain the transport even if the `writer_task` is blocked.
3.  **Cancellation Bypass**: When the `writer_task`'s MPSC queue is full, the `reader_task` MUST still be able to process `notifications/cancelled`. This is achieved by:
    *   Using a high-priority `cancellation` channel that bypasses the standard outbound queue.
    *   OR, more simply, the `reader_task` triggers a `CancellationToken` shared with the handler. The handler, upon seeing the cancellation, drops its pending write and exits, thus unblocking the `writer_task`'s queue.
4.  **Yielding on Stalls**: Use `tokio::select!` in handlers to wait for *either* the outbound queue to have space *or* a cancellation signal:
    ```rust
    tokio::select! {
        res = outbound_tx.reserve() => { /* proceed with send */ }
        _ = cancel_token.cancelled() => { return Err(Error::cancelled()); }
    }
    ```

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
