---
id: LAW-11
name: Conservation of Work and Idempotent Actuation
effective_date: 2026-01-27
citation: apm2://skills/laws-of-holonic-agent-systems
status: active
---

# Law 11: Conservation of Work and Idempotent Actuation

## The Law
Actuation must be safe under retries, duplication, and partial failure.

## Operationalization
1. **Idempotency:** Every external side effect MUST be idempotent or have an explicit compensation/rollback contract.
2. **Replay Safety:** Every command MUST be replay-safe under at-least-once delivery using dedupe keys.
3. **Execution Receipts:** Tools must emit receipts that bind "this effect happened exactly once" to a specific transaction ID.

## Rationale
Distributed systems are prone to message duplication and partial success. Making actions idempotent ensures that the network can safely retry failed tasks without corrupting state or double-spending resources.
