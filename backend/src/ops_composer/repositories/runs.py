from __future__ import annotations

from datetime import datetime
from typing import Protocol
from uuid import UUID

from psycopg import sql
from psycopg.types.json import Jsonb

from ops_composer.domain.errors import ClaimCollisionError
from ops_composer.domain.ops import Run, RunEvent, RunStatus, RunTarget, RunTargetStatus
from ops_composer.repositories.base import BaseRepository, RepositoryConnection, RepositoryRow

RUN_COLUMNS = sql.SQL(
    "run_id, source_run_id, kind, status, target_spec, resolved_targets, "
    "operation_spec, inventory_snapshot, workspace_revision, credential_versions, "
    "timeout_seconds, forks, cancel_requested_at, claimed_by, claimed_at, started_at, "
    "finished_at, return_code, summary, failure_code, failure_message, requested_by, "
    "idempotency_key, request_fingerprint, created_at, updated_at"
)
QUALIFIED_RUN_COLUMNS = sql.SQL(
    "r.run_id, r.source_run_id, r.kind, r.status, r.target_spec, r.resolved_targets, "
    "r.operation_spec, r.inventory_snapshot, r.workspace_revision, r.credential_versions, "
    "r.timeout_seconds, r.forks, r.cancel_requested_at, r.claimed_by, r.claimed_at, "
    "r.started_at, r.finished_at, r.return_code, r.summary, r.failure_code, "
    "r.failure_message, r.requested_by, r.idempotency_key, r.request_fingerprint, "
    "r.created_at, r.updated_at"
)
TARGET_COLUMNS = sql.SQL(
    "run_target_id, run_id, host_id, host_name, host_address, status, return_code, "
    "stdout, stderr, result, output_truncated, changed_count, failed_count, "
    "unreachable_count, started_at, finished_at"
)
EVENT_COLUMNS = sql.SQL(
    "run_event_id, run_id, run_target_id, sequence, event_type, task, stdout, "
    "event_data, created_at"
)


def _run(row: RepositoryRow) -> Run:
    return Run.model_validate(row)


def _target(row: RepositoryRow) -> RunTarget:
    return RunTarget.model_validate(row)


def _event(row: RepositoryRow) -> RunEvent:
    return RunEvent.model_validate(row)


class RunRepository(BaseRepository, Protocol):
    async def create_or_get(self, run: Run, targets: tuple[RunTarget, ...]) -> tuple[Run, bool]: ...
    async def get(self, run_id: UUID) -> Run | None: ...
    async def list(self, *, limit: int, offset: int) -> tuple[Run, ...]: ...
    async def targets(self, run_id: UUID) -> tuple[RunTarget, ...]: ...
    async def request_cancel(self, run_id: UUID, now: datetime) -> Run | None: ...
    async def claim_next(
        self, worker_id: str, now: datetime, lease_expires_at: datetime
    ) -> Run | None: ...
    async def heartbeat(
        self, worker_id: str, run_id: UUID | None, now: datetime, expires_at: datetime
    ) -> None: ...
    async def recover_stale(self, now: datetime) -> int: ...
    async def mark_running(self, run_id: UUID, now: datetime) -> None: ...
    async def finish(
        self,
        run_id: UUID,
        worker_id: str,
        status: RunStatus,
        return_code: int | None,
        summary: dict[str, object],
        failure_code: str | None,
        failure_message: str | None,
        now: datetime,
    ) -> Run | None: ...
    async def finish_target(
        self,
        run_target_id: UUID,
        status: RunTargetStatus,
        return_code: int | None,
        stdout: str,
        stderr: str,
        result: dict[str, object],
        output_truncated: bool,
        changed_count: int,
        failed_count: int,
        unreachable_count: int,
        now: datetime,
    ) -> None: ...
    async def append_event(self, event: RunEvent) -> RunEvent: ...
    async def events_after(
        self, run_id: UUID, sequence: int, limit: int
    ) -> tuple[RunEvent, ...]: ...
    async def cancellation_requested(self, run_id: UUID) -> bool: ...
    async def dashboard(self) -> dict[str, object]: ...


class PostgresRunRepository(BaseRepository):
    def __init__(self, connection: RepositoryConnection) -> None:
        self.connection = connection

    @staticmethod
    def _run_values(run: Run) -> dict[str, object]:
        values = run.model_dump(mode="python")
        for key in (
            "target_spec",
            "resolved_targets",
            "operation_spec",
            "inventory_snapshot",
            "credential_versions",
            "summary",
        ):
            values[key] = Jsonb(values[key])
        return values

    async def create_or_get(self, run: Run, targets: tuple[RunTarget, ...]) -> tuple[Run, bool]:
        row = await self.connection.fetch_one(
            sql.SQL(
                "INSERT INTO runs (run_id, source_run_id, kind, status, target_spec, "
                "resolved_targets, operation_spec, inventory_snapshot, workspace_revision, "
                "credential_versions, timeout_seconds, forks, cancel_requested_at, claimed_by, "
                "claimed_at, started_at, finished_at, return_code, summary, failure_code, "
                "failure_message, requested_by, idempotency_key, request_fingerprint, "
                "created_at, updated_at) VALUES (%(run_id)s, %(source_run_id)s, %(kind)s, "
                "%(status)s, %(target_spec)s, %(resolved_targets)s, %(operation_spec)s, "
                "%(inventory_snapshot)s, %(workspace_revision)s, %(credential_versions)s, "
                "%(timeout_seconds)s, %(forks)s, %(cancel_requested_at)s, %(claimed_by)s, "
                "%(claimed_at)s, %(started_at)s, %(finished_at)s, %(return_code)s, "
                "%(summary)s, %(failure_code)s, %(failure_message)s, %(requested_by)s, "
                "%(idempotency_key)s, %(request_fingerprint)s, %(created_at)s, %(updated_at)s) "
                "ON CONFLICT (requested_by, idempotency_key) DO NOTHING RETURNING {}"
            ).format(RUN_COLUMNS),
            self._run_values(run),
            prepare=True,
        )
        created = row is not None
        if row is None:
            row = await self.connection.fetch_one(
                sql.SQL(
                    "SELECT {} FROM runs WHERE requested_by = %(requested_by)s "
                    "AND idempotency_key = %(idempotency_key)s"
                ).format(RUN_COLUMNS),
                {
                    "requested_by": run.requested_by,
                    "idempotency_key": run.idempotency_key,
                },
                prepare=True,
            )
        if row is None:
            raise RuntimeError("idempotent run lookup returned no row")
        persisted = _run(row)
        if created:
            await self.connection.execute_many(
                sql.SQL(
                    "INSERT INTO run_targets (run_target_id, run_id, host_id, host_name, "
                    "host_address, status, return_code, stdout, stderr, result, output_truncated, "
                    "changed_count, failed_count, unreachable_count, started_at, finished_at) "
                    "VALUES (%(run_target_id)s, %(run_id)s, %(host_id)s, %(host_name)s, "
                    "%(host_address)s, %(status)s, %(return_code)s, %(stdout)s, %(stderr)s, "
                    "%(result)s, %(output_truncated)s, %(changed_count)s, %(failed_count)s, "
                    "%(unreachable_count)s, %(started_at)s, %(finished_at)s)"
                ),
                (
                    {
                        **target.model_dump(mode="python"),
                        "result": Jsonb(target.result),
                    }
                    for target in targets
                ),
            )
        return persisted, created

    async def get(self, run_id: UUID) -> Run | None:
        row = await self.connection.fetch_one(
            sql.SQL("SELECT {} FROM runs WHERE run_id = %(run_id)s").format(RUN_COLUMNS),
            {"run_id": run_id},
            prepare=True,
        )
        return _run(row) if row is not None else None

    async def list(self, *, limit: int, offset: int) -> tuple[Run, ...]:
        rows = await self.connection.fetch_all(
            sql.SQL(
                "SELECT {} FROM runs ORDER BY created_at DESC, run_id DESC "
                "LIMIT %(limit)s OFFSET %(offset)s"
            ).format(RUN_COLUMNS),
            {"limit": limit, "offset": offset},
            prepare=True,
        )
        return tuple(_run(row) for row in rows)

    async def targets(self, run_id: UUID) -> tuple[RunTarget, ...]:
        rows = await self.connection.fetch_all(
            sql.SQL(
                "SELECT {} FROM run_targets WHERE run_id = %(run_id)s ORDER BY host_name"
            ).format(TARGET_COLUMNS),
            {"run_id": run_id},
            prepare=True,
        )
        return tuple(_target(row) for row in rows)

    async def request_cancel(self, run_id: UUID, now: datetime) -> Run | None:
        row = await self.connection.fetch_one(
            sql.SQL(
                "UPDATE runs SET cancel_requested_at = %(now)s, "
                "status = CASE WHEN status = 'QUEUED' THEN 'CANCELED' ELSE status END, "
                "finished_at = CASE WHEN status = 'QUEUED' THEN %(now)s ELSE finished_at END, "
                "updated_at = %(now)s WHERE run_id = %(run_id)s "
                "AND status IN ('QUEUED', 'PREPARING', 'RUNNING') RETURNING {}"
            ).format(RUN_COLUMNS),
            {"run_id": run_id, "now": now},
            prepare=True,
        )
        if row is not None and row["status"] == RunStatus.CANCELED:
            await self.connection.execute(
                sql.SQL(
                    "UPDATE run_targets SET status = 'CANCELED', finished_at = %(now)s "
                    "WHERE run_id = %(run_id)s AND status = 'PENDING'"
                ),
                {"run_id": run_id, "now": now},
                prepare=True,
            )
        return _run(row) if row is not None else None

    async def heartbeat(
        self, worker_id: str, run_id: UUID | None, now: datetime, expires_at: datetime
    ) -> None:
        await self.connection.execute(
            sql.SQL(
                "INSERT INTO worker_leases (worker_id, run_id, heartbeat_at, expires_at) "
                "VALUES (%(worker_id)s, %(run_id)s, %(now)s, %(expires_at)s) "
                "ON CONFLICT (worker_id) DO UPDATE SET run_id = EXCLUDED.run_id, "
                "heartbeat_at = EXCLUDED.heartbeat_at, expires_at = EXCLUDED.expires_at"
            ),
            {
                "worker_id": worker_id,
                "run_id": run_id,
                "now": now,
                "expires_at": expires_at,
            },
            prepare=True,
        )
        await self.connection.execute(
            sql.SQL(
                "UPDATE host_run_locks SET expires_at = %(expires_at)s "
                "WHERE worker_id = %(worker_id)s"
            ),
            {"worker_id": worker_id, "expires_at": expires_at},
            prepare=True,
        )

    async def claim_next(
        self, worker_id: str, now: datetime, lease_expires_at: datetime
    ) -> Run | None:
        row = await self.connection.fetch_one(
            sql.SQL(
                "WITH candidate AS ("
                "SELECT r.run_id FROM runs r WHERE r.status = 'QUEUED' "
                "AND NOT EXISTS (SELECT 1 FROM run_targets rt "
                "JOIN host_run_locks hl ON hl.host_id = rt.host_id "
                "WHERE rt.run_id = r.run_id AND hl.expires_at > %(now)s) "
                "ORDER BY r.created_at, r.run_id FOR UPDATE OF r SKIP LOCKED LIMIT 1"
                ") UPDATE runs r SET status = 'PREPARING', claimed_by = %(worker_id)s, "
                "claimed_at = %(now)s, started_at = %(now)s, updated_at = %(now)s "
                "FROM candidate WHERE r.run_id = candidate.run_id RETURNING {}"
            ).format(QUALIFIED_RUN_COLUMNS),
            {"worker_id": worker_id, "now": now},
            prepare=True,
        )
        if row is None:
            return None
        run = _run(row)
        locked_rows = await self.connection.fetch_all(
            sql.SQL(
                "INSERT INTO host_run_locks (host_id, run_id, worker_id, acquired_at, expires_at) "
                "SELECT host_id, %(run_id)s, %(worker_id)s, %(now)s, %(expires_at)s "
                "FROM run_targets WHERE run_id = %(run_id)s ORDER BY host_id "
                "ON CONFLICT (host_id) DO NOTHING RETURNING host_id"
            ),
            {
                "run_id": run.run_id,
                "worker_id": worker_id,
                "now": now,
                "expires_at": lease_expires_at,
            },
            prepare=True,
        )
        expected = await self.connection.fetch_one(
            sql.SQL("SELECT count(*) AS count FROM run_targets WHERE run_id = %(run_id)s"),
            {"run_id": run.run_id},
            prepare=True,
        )
        if expected is None or len(locked_rows) != int(expected["count"]):
            raise ClaimCollisionError("a target host was locked concurrently")
        return run

    async def recover_stale(self, now: datetime) -> int:
        row = await self.connection.fetch_one(
            sql.SQL(
                "WITH stale AS (DELETE FROM worker_leases WHERE expires_at <= %(now)s "
                "RETURNING worker_id), interrupted AS (UPDATE runs r SET status = 'INTERRUPTED', "
                "finished_at = %(now)s, updated_at = %(now)s, "
                "failure_code = 'WORKER_LEASE_EXPIRED', "
                "failure_message = 'worker lease expired during execution' "
                "WHERE r.claimed_by IN (SELECT worker_id FROM stale) "
                "AND r.status IN ('PREPARING', 'RUNNING') RETURNING r.run_id), "
                "targets AS (UPDATE run_targets SET status = 'INTERRUPTED', "
                "finished_at = %(now)s WHERE run_id IN (SELECT run_id FROM interrupted) "
                "AND status IN ('PENDING', 'RUNNING') RETURNING run_id), "
                "released AS (DELETE FROM host_run_locks WHERE expires_at <= %(now)s "
                "OR run_id IN (SELECT run_id FROM interrupted) RETURNING host_id) "
                "SELECT count(*) AS count FROM interrupted"
            ),
            {"now": now},
            prepare=True,
        )
        if row is None:
            raise RuntimeError("stale-worker recovery returned no row")
        return int(row["count"])

    async def mark_running(self, run_id: UUID, now: datetime) -> None:
        await self.connection.execute(
            sql.SQL(
                "UPDATE runs SET status = 'RUNNING', updated_at = %(now)s "
                "WHERE run_id = %(run_id)s AND status = 'PREPARING'"
            ),
            {"run_id": run_id, "now": now},
            prepare=True,
        )
        await self.connection.execute(
            sql.SQL(
                "UPDATE run_targets SET status = 'RUNNING', started_at = %(now)s "
                "WHERE run_id = %(run_id)s AND status = 'PENDING'"
            ),
            {"run_id": run_id, "now": now},
            prepare=True,
        )

    async def finish(
        self,
        run_id: UUID,
        worker_id: str,
        status: RunStatus,
        return_code: int | None,
        summary: dict[str, object],
        failure_code: str | None,
        failure_message: str | None,
        now: datetime,
    ) -> Run | None:
        fallback_target_status = {
            RunStatus.CANCELED: RunTargetStatus.CANCELED,
            RunStatus.INTERRUPTED: RunTargetStatus.INTERRUPTED,
            RunStatus.SUCCEEDED: RunTargetStatus.SKIPPED,
            RunStatus.PARTIAL: RunTargetStatus.SKIPPED,
        }.get(status, RunTargetStatus.FAILED)
        await self.connection.execute(
            sql.SQL(
                "UPDATE run_targets SET status = %(target_status)s, finished_at = %(now)s "
                "WHERE run_id = %(run_id)s AND status IN ('PENDING', 'RUNNING')"
            ),
            {
                "target_status": fallback_target_status,
                "now": now,
                "run_id": run_id,
            },
            prepare=True,
        )
        row = await self.connection.fetch_one(
            sql.SQL(
                "UPDATE runs SET status = %(status)s, return_code = %(return_code)s, "
                "summary = %(summary)s, failure_code = %(failure_code)s, "
                "failure_message = %(failure_message)s, finished_at = %(now)s, "
                "updated_at = %(now)s WHERE run_id = %(run_id)s "
                "AND claimed_by = %(worker_id)s AND status IN ('PREPARING', 'RUNNING') "
                "RETURNING {}"
            ).format(RUN_COLUMNS),
            {
                "run_id": run_id,
                "worker_id": worker_id,
                "status": status,
                "return_code": return_code,
                "summary": Jsonb(summary),
                "failure_code": failure_code,
                "failure_message": failure_message,
                "now": now,
            },
            prepare=True,
        )
        await self.connection.execute(
            sql.SQL("DELETE FROM host_run_locks WHERE run_id = %(run_id)s"),
            {"run_id": run_id},
            prepare=True,
        )
        await self.connection.execute(
            sql.SQL(
                "UPDATE worker_leases SET run_id = NULL WHERE worker_id = %(worker_id)s "
                "AND run_id = %(run_id)s"
            ),
            {"worker_id": worker_id, "run_id": run_id},
            prepare=True,
        )
        return _run(row) if row is not None else None

    async def finish_target(
        self,
        run_target_id: UUID,
        status: RunTargetStatus,
        return_code: int | None,
        stdout: str,
        stderr: str,
        result: dict[str, object],
        output_truncated: bool,
        changed_count: int,
        failed_count: int,
        unreachable_count: int,
        now: datetime,
    ) -> None:
        await self.connection.execute(
            sql.SQL(
                "UPDATE run_targets SET status = %(status)s, return_code = %(return_code)s, "
                "stdout = %(stdout)s, stderr = %(stderr)s, result = %(result)s, "
                "output_truncated = %(output_truncated)s, changed_count = %(changed_count)s, "
                "failed_count = %(failed_count)s, unreachable_count = %(unreachable_count)s, "
                "finished_at = %(now)s WHERE run_target_id = %(run_target_id)s"
            ),
            {
                "run_target_id": run_target_id,
                "status": status,
                "return_code": return_code,
                "stdout": stdout,
                "stderr": stderr,
                "result": Jsonb(result),
                "output_truncated": output_truncated,
                "changed_count": changed_count,
                "failed_count": failed_count,
                "unreachable_count": unreachable_count,
                "now": now,
            },
            prepare=True,
        )

    async def append_event(self, event: RunEvent) -> RunEvent:
        sequence_row = await self.connection.fetch_one(
            sql.SQL(
                "UPDATE runs SET next_event_sequence = next_event_sequence + 1 "
                "WHERE run_id = %(run_id)s RETURNING next_event_sequence - 1 AS sequence"
            ),
            {"run_id": event.run_id},
            prepare=True,
        )
        if sequence_row is None:
            raise RuntimeError("event sequence allocation returned no row")
        values = event.model_copy(update={"sequence": int(sequence_row["sequence"])}).model_dump(
            mode="python"
        )
        values["event_data"] = Jsonb(values["event_data"])
        row = await self.connection.fetch_one(
            sql.SQL(
                "INSERT INTO run_events (run_event_id, run_id, run_target_id, sequence, "
                "event_type, task, stdout, event_data, created_at) VALUES "
                "(%(run_event_id)s, %(run_id)s, %(run_target_id)s, %(sequence)s, "
                "%(event_type)s, %(task)s, %(stdout)s, %(event_data)s, %(created_at)s) "
                "RETURNING {}"
            ).format(EVENT_COLUMNS),
            values,
            prepare=True,
        )
        if row is None:
            raise RuntimeError("run event insert returned no row")
        return _event(row)

    async def events_after(self, run_id: UUID, sequence: int, limit: int) -> tuple[RunEvent, ...]:
        rows = await self.connection.fetch_all(
            sql.SQL(
                "SELECT {} FROM run_events WHERE run_id = %(run_id)s "
                "AND sequence > %(sequence)s ORDER BY sequence LIMIT %(limit)s"
            ).format(EVENT_COLUMNS),
            {"run_id": run_id, "sequence": sequence, "limit": limit},
            prepare=True,
        )
        return tuple(_event(row) for row in rows)

    async def cancellation_requested(self, run_id: UUID) -> bool:
        row = await self.connection.fetch_one(
            sql.SQL(
                "SELECT cancel_requested_at IS NOT NULL AS requested FROM runs "
                "WHERE run_id = %(run_id)s"
            ),
            {"run_id": run_id},
            prepare=True,
        )
        return bool(row and row["requested"])

    async def dashboard(self) -> dict[str, object]:
        row = await self.connection.fetch_one(
            sql.SQL(
                "SELECT (SELECT count(*) FROM hosts) AS host_count, "
                "(SELECT count(*) FROM hosts WHERE enabled) AS enabled_host_count, "
                "(SELECT count(*) FROM runs WHERE created_at >= date_trunc('day', now())) "
                "AS runs_today, (SELECT count(*) FROM runs WHERE status IN "
                "('FAILED', 'PARTIAL', 'TIMED_OUT', 'INTERRUPTED', 'REJECTED')) AS failed_runs, "
                "(SELECT count(*) FROM runs WHERE status IN ('QUEUED', 'PREPARING', 'RUNNING')) "
                "AS active_runs"
            ),
            prepare=True,
        )
        if row is None:
            raise RuntimeError("dashboard query returned no row")
        return dict(row)
