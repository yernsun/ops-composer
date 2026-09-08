from __future__ import annotations

from datetime import datetime
from typing import Protocol
from uuid import UUID

from psycopg import sql
from psycopg.errors import UniqueViolation

from ops_composer.domain.encryption import (
    EncryptedRecord,
    EncryptedRecordKind,
    EncryptionKeyRecord,
    EncryptionUsage,
    KeyRotationJob,
    SystemSecretEnvelope,
)
from ops_composer.domain.errors import KeyRotationInProgressError
from ops_composer.repositories.base import BaseRepository, RepositoryConnection

# A transaction-scoped lock keeps rotation claiming single-threaded across all
# worker processes while the row lease still provides crash recovery.
_KEY_ROTATION_ADVISORY_LOCK_KEY = 0x04F5053434B5254


class EncryptionRepository(BaseRepository, Protocol):
    async def list_keys(self) -> tuple[EncryptionKeyRecord, ...]: ...
    async def add_key(self, record: EncryptionKeyRecord) -> None: ...
    async def get_system_secret(self, name: str) -> SystemSecretEnvelope | None: ...
    async def put_system_secret(self, envelope: SystemSecretEnvelope) -> None: ...
    async def usage(self) -> tuple[EncryptionUsage, ...]: ...
    async def create_rotation_job(self, job: KeyRotationJob) -> KeyRotationJob: ...
    async def latest_rotation_job(self) -> KeyRotationJob | None: ...
    async def claim_rotation_job(
        self, worker_id: str, now: datetime, lease_expires_at: datetime
    ) -> KeyRotationJob | None: ...
    async def load_rotation_batch(
        self, target_key_version: int, limit: int
    ) -> tuple[EncryptedRecord, ...]: ...
    async def update_rotation_batch(
        self, records: tuple[EncryptedRecord, ...], key_version: int, updated_at: datetime
    ) -> None: ...
    async def update_rotation_job(
        self,
        job_id: UUID,
        *,
        state: str,
        processed_increment: int,
        remaining_count: int,
        now: datetime,
        lease_expires_at: datetime | None,
        error_code: str | None,
    ) -> None: ...


def _job(row: dict[str, object]) -> KeyRotationJob:
    return KeyRotationJob.model_validate(row)


class PostgresEncryptionRepository(BaseRepository):
    def __init__(self, connection: RepositoryConnection) -> None:
        self.connection = connection

    async def list_keys(self) -> tuple[EncryptionKeyRecord, ...]:
        rows = await self.connection.fetch_all(
            sql.SQL(
                "SELECT key_version, verification_envelope, registered_at, retired_at "
                "FROM encryption_key_registry ORDER BY key_version"
            ),
            prepare=True,
        )
        return tuple(EncryptionKeyRecord.model_validate(row) for row in rows)

    async def add_key(self, record: EncryptionKeyRecord) -> None:
        await self.connection.execute(
            sql.SQL(
                "INSERT INTO encryption_key_registry (key_version, verification_envelope, "
                "registered_at, retired_at) VALUES (%(key_version)s, "
                "%(verification_envelope)s, %(registered_at)s, %(retired_at)s) "
                "ON CONFLICT (key_version) DO NOTHING"
            ),
            record.model_dump(mode="python"),
            prepare=True,
        )

    async def get_system_secret(self, name: str) -> SystemSecretEnvelope | None:
        row = await self.connection.fetch_one(
            sql.SQL(
                "SELECT secret_name, encrypted_secret, encryption_key_version, updated_at "
                "FROM system_secret_envelopes WHERE secret_name = %(secret_name)s"
            ),
            {"secret_name": name},
            prepare=True,
        )
        return SystemSecretEnvelope.model_validate(row) if row is not None else None

    async def put_system_secret(self, envelope: SystemSecretEnvelope) -> None:
        await self.connection.execute(
            sql.SQL(
                "INSERT INTO system_secret_envelopes (secret_name, encrypted_secret, "
                "encryption_key_version, updated_at) VALUES (%(secret_name)s, "
                "%(encrypted_secret)s, %(encryption_key_version)s, %(updated_at)s) "
                "ON CONFLICT (secret_name) DO UPDATE SET "
                "encrypted_secret = EXCLUDED.encrypted_secret, "
                "encryption_key_version = EXCLUDED.encryption_key_version, "
                "updated_at = EXCLUDED.updated_at"
            ),
            envelope.model_dump(mode="python"),
            prepare=True,
        )

    async def usage(self) -> tuple[EncryptionUsage, ...]:
        rows = await self.connection.fetch_all(
            sql.SQL(
                "WITH versions AS ("
                "SELECT key_version FROM encryption_key_registry UNION "
                "SELECT encryption_key_version FROM credential_secret_envelopes UNION "
                "SELECT encryption_key_version FROM user_mfa_factors UNION "
                "SELECT encryption_key_version FROM system_secret_envelopes UNION "
                "SELECT encryption_key_version FROM run_secret_inputs) "
                "SELECT v.key_version, "
                "(SELECT count(*) FROM credential_secret_envelopes c "
                "WHERE c.encryption_key_version = v.key_version) AS credential_count, "
                "(SELECT count(*) FROM user_mfa_factors m "
                "WHERE m.encryption_key_version = v.key_version) AS mfa_count, "
                "(SELECT count(*) FROM system_secret_envelopes s "
                "WHERE s.encryption_key_version = v.key_version) AS system_count, "
                "(SELECT count(*) FROM run_secret_inputs r "
                "WHERE r.encryption_key_version = v.key_version) AS run_secret_count "
                "FROM versions v ORDER BY v.key_version"
            ),
            prepare=True,
        )
        return tuple(EncryptionUsage.model_validate(row) for row in rows)

    async def create_rotation_job(self, job: KeyRotationJob) -> KeyRotationJob:
        try:
            row = await self.connection.fetch_one(
                sql.SQL(
                    "INSERT INTO key_rotation_jobs (key_rotation_job_id, target_key_version, "
                    "state, requested_by, claimed_by, lease_expires_at, processed_count, "
                    "remaining_count, error_code, created_at, started_at, finished_at, "
                    "updated_at) VALUES (%(key_rotation_job_id)s, %(target_key_version)s, "
                    "%(state)s, %(requested_by)s, %(claimed_by)s, %(lease_expires_at)s, "
                    "%(processed_count)s, %(remaining_count)s, %(error_code)s, %(created_at)s, "
                    "%(started_at)s, %(finished_at)s, %(updated_at)s) RETURNING *"
                ),
                job.model_dump(mode="python"),
                prepare=True,
            )
        except UniqueViolation as error:
            raise KeyRotationInProgressError() from error
        if row is None:
            raise RuntimeError("key rotation job insert returned no row")
        return _job(row)

    async def latest_rotation_job(self) -> KeyRotationJob | None:
        row = await self.connection.fetch_one(
            sql.SQL(
                "SELECT * FROM key_rotation_jobs ORDER BY created_at DESC, "
                "key_rotation_job_id DESC LIMIT 1"
            ),
            prepare=True,
        )
        return _job(row) if row is not None else None

    async def claim_rotation_job(
        self, worker_id: str, now: datetime, lease_expires_at: datetime
    ) -> KeyRotationJob | None:
        row = await self.connection.fetch_one(
            sql.SQL(
                "WITH gate AS (SELECT pg_try_advisory_xact_lock("
                "%(rotation_lock_key)s) AS acquired), candidate AS ("
                "SELECT j.key_rotation_job_id FROM key_rotation_jobs AS j CROSS JOIN gate "
                "WHERE gate.acquired AND (j.state = 'PENDING' OR (j.state = 'RUNNING' "
                "AND j.lease_expires_at <= %(now)s)) ORDER BY j.created_at, "
                "j.key_rotation_job_id FOR UPDATE OF j SKIP LOCKED LIMIT 1) "
                "UPDATE key_rotation_jobs j SET state = 'RUNNING', claimed_by = %(worker_id)s, "
                "lease_expires_at = %(lease_expires_at)s, started_at = COALESCE(started_at, "
                "%(now)s), updated_at = %(now)s FROM candidate c "
                "WHERE j.key_rotation_job_id = c.key_rotation_job_id RETURNING j.*"
            ),
            {
                "rotation_lock_key": _KEY_ROTATION_ADVISORY_LOCK_KEY,
                "worker_id": worker_id,
                "now": now,
                "lease_expires_at": lease_expires_at,
            },
            prepare=True,
        )
        return _job(row) if row is not None else None

    async def load_rotation_batch(
        self, target_key_version: int, limit: int
    ) -> tuple[EncryptedRecord, ...]:
        credential_rows = await self.connection.fetch_all(
            sql.SQL(
                "SELECT credential_id::text AS record_id, revision AS sub_id, "
                "encrypted_secret AS encrypted_payload, encryption_key_version "
                "FROM credential_secret_envelopes WHERE encryption_key_version <> "
                "%(target_key_version)s ORDER BY credential_id, revision "
                "FOR UPDATE SKIP LOCKED LIMIT %(batch_limit)s"
            ),
            {"target_key_version": target_key_version, "batch_limit": limit},
            prepare=True,
        )
        if credential_rows:
            return tuple(
                EncryptedRecord.model_validate({**row, "kind": EncryptedRecordKind.CREDENTIAL})
                for row in credential_rows
            )
        mfa_rows = await self.connection.fetch_all(
            sql.SQL(
                "SELECT user_id::text AS record_id, NULL::integer AS sub_id, "
                "encrypted_totp_secret AS encrypted_payload, encryption_key_version "
                "FROM user_mfa_factors WHERE encryption_key_version <> %(target_key_version)s "
                "ORDER BY user_id FOR UPDATE SKIP LOCKED LIMIT %(batch_limit)s"
            ),
            {"target_key_version": target_key_version, "batch_limit": limit},
            prepare=True,
        )
        if mfa_rows:
            return tuple(
                EncryptedRecord.model_validate({**row, "kind": EncryptedRecordKind.MFA})
                for row in mfa_rows
            )
        system_rows = await self.connection.fetch_all(
            sql.SQL(
                "SELECT secret_name AS record_id, NULL::integer AS sub_id, "
                "encrypted_secret AS encrypted_payload, encryption_key_version "
                "FROM system_secret_envelopes WHERE encryption_key_version <> "
                "%(target_key_version)s ORDER BY secret_name FOR UPDATE SKIP LOCKED "
                "LIMIT %(batch_limit)s"
            ),
            {"target_key_version": target_key_version, "batch_limit": limit},
            prepare=True,
        )
        if system_rows:
            return tuple(
                EncryptedRecord.model_validate({**row, "kind": EncryptedRecordKind.SYSTEM})
                for row in system_rows
            )
        run_rows = await self.connection.fetch_all(
            sql.SQL(
                "SELECT run_id::text AS record_id, NULL::integer AS sub_id, "
                "encrypted_payload, encryption_key_version FROM run_secret_inputs "
                "WHERE encryption_key_version <> %(target_key_version)s ORDER BY run_id "
                "FOR UPDATE SKIP LOCKED LIMIT %(batch_limit)s"
            ),
            {"target_key_version": target_key_version, "batch_limit": limit},
            prepare=True,
        )
        return tuple(
            EncryptedRecord.model_validate({**row, "kind": EncryptedRecordKind.RUN_SECRET})
            for row in run_rows
        )

    async def update_rotation_batch(
        self, records: tuple[EncryptedRecord, ...], key_version: int, updated_at: datetime
    ) -> None:
        if not records:
            return
        kind = records[0].kind
        if any(record.kind is not kind for record in records):
            raise ValueError("rotation batches must contain one record kind")
        if kind is EncryptedRecordKind.CREDENTIAL:
            await self.connection.execute_many(
                sql.SQL(
                    "UPDATE credential_secret_envelopes SET encrypted_secret = "
                    "%(encrypted_payload)s, encryption_key_version = %(key_version)s, "
                    "updated_at = %(updated_at)s WHERE credential_id = %(record_id)s::uuid "
                    "AND revision = %(sub_id)s"
                ),
                (
                    {
                        "record_id": record.record_id,
                        "sub_id": record.sub_id,
                        "encrypted_payload": record.encrypted_payload,
                        "key_version": key_version,
                        "updated_at": updated_at,
                    }
                    for record in records
                ),
            )
        elif kind is EncryptedRecordKind.MFA:
            await self.connection.execute_many(
                sql.SQL(
                    "UPDATE user_mfa_factors SET encrypted_totp_secret = %(encrypted_payload)s, "
                    "encryption_key_version = %(key_version)s, updated_at = %(updated_at)s "
                    "WHERE user_id = %(record_id)s::uuid"
                ),
                (
                    {
                        "record_id": record.record_id,
                        "encrypted_payload": record.encrypted_payload,
                        "key_version": key_version,
                        "updated_at": updated_at,
                    }
                    for record in records
                ),
            )
        elif kind is EncryptedRecordKind.SYSTEM:
            await self.connection.execute_many(
                sql.SQL(
                    "UPDATE system_secret_envelopes SET encrypted_secret = %(encrypted_payload)s, "
                    "encryption_key_version = %(key_version)s, updated_at = %(updated_at)s "
                    "WHERE secret_name = %(record_id)s"
                ),
                (
                    {
                        "record_id": record.record_id,
                        "encrypted_payload": record.encrypted_payload,
                        "key_version": key_version,
                        "updated_at": updated_at,
                    }
                    for record in records
                ),
            )
        else:
            await self.connection.execute_many(
                sql.SQL(
                    "UPDATE run_secret_inputs SET encrypted_payload = %(encrypted_payload)s, "
                    "encryption_key_version = %(key_version)s WHERE run_id = %(record_id)s::uuid"
                ),
                (
                    {
                        "record_id": record.record_id,
                        "encrypted_payload": record.encrypted_payload,
                        "key_version": key_version,
                    }
                    for record in records
                ),
            )

    async def update_rotation_job(
        self,
        job_id: UUID,
        *,
        state: str,
        processed_increment: int,
        remaining_count: int,
        now: datetime,
        lease_expires_at: datetime | None,
        error_code: str | None,
    ) -> None:
        await self.connection.execute(
            sql.SQL(
                "UPDATE key_rotation_jobs SET state = %(state)s, "
                "processed_count = processed_count + %(processed_increment)s, "
                "remaining_count = %(remaining_count)s, lease_expires_at = %(lease_expires_at)s, "
                "claimed_by = CASE WHEN %(state)s = 'RUNNING' THEN claimed_by ELSE NULL END, "
                "error_code = %(error_code)s, finished_at = CASE WHEN %(state)s IN "
                "('SUCCEEDED', 'FAILED') THEN %(now)s ELSE NULL END, updated_at = %(now)s "
                "WHERE key_rotation_job_id = %(job_id)s"
            ),
            {
                "job_id": job_id,
                "state": state,
                "processed_increment": processed_increment,
                "remaining_count": remaining_count,
                "lease_expires_at": lease_expires_at,
                "error_code": error_code,
                "now": now,
            },
            prepare=True,
        )
