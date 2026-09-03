---
name: create-worker
description: Add or modify the PostgreSQL-backed OpsComposer worker, queue claiming, leases, host locks, recovery, or retry behavior.
---

Keep PostgreSQL as the only shared runtime dependency. Claim queued Runs with
`FOR UPDATE SKIP LOCKED`, persist state transitions and sequenced RunEvents in Service-owned
transactions, renew the database WorkerLease, and serialize execution with the unique Host lock.
Recovery marks abandoned work `INTERRUPTED`; retry creates a new Run from the immutable snapshot.
Cover concurrent claim, lease expiry, host-lock contention, event order, and crash recovery in tests.
