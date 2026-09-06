# PostgreSQL Run events

M1 has no event broker, relay, consumer group, or outbox-to-Redis pipeline. A Service or the Worker
appends `run_events` in the same PostgreSQL transaction as the related Run transition. Sequence
allocation uses `UPDATE runs ... RETURNING`, and `(run_id, sequence)` is unique.

The SSE endpoint polls for rows after the caller's sequence and emits a single `run-event` event.
Its JSON payload carries the durable event type and sequence. `Last-Event-ID` and the explicit
`after` query allow refresh/reconnect replay; SSE delivery itself is not treated as persistence.

All runner payloads pass secret-key filtering and value redaction before insertion. Event and
per-host output have byte limits. Browser disconnects do not cancel execution, and API process
restarts do not affect queued or running work owned by the Worker lease.

Web Shell is deliberately separate: its binary WebSocket stream is connection-bound and never
enters `run_events`. Terminal input/output is not persisted; only lifecycle audit is durable, and a
browser disconnect terminates its OpenSSH PTY and shared host lock.
