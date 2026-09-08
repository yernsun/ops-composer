from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from datetime import timedelta
from uuid import UUID, uuid4

from ops_composer.auth.models import Permission, SessionPrincipal
from ops_composer.auth.service import require_permission, require_recent_reauthentication
from ops_composer.domain.audit import (
    AuditAction,
    AuditOutcome,
    AuditSeverity,
    AuditSource,
)
from ops_composer.domain.base import utc_now
from ops_composer.domain.encryption import (
    EncryptedRecord,
    EncryptedRecordKind,
    EncryptionKeyRecord,
    EncryptionUsage,
    KeyRotationJob,
    KeyRotationState,
    SystemSecretEnvelope,
)
from ops_composer.domain.errors import KeyVersionMissingError
from ops_composer.services.audit import AuditService, emit_audit_event, new_audit_event
from ops_composer.services.crypto import CredentialCipher, MasterKeyring
from ops_composer.uow.factory import UnitOfWorkFactory

ROTATION_BATCH_SIZE = 100
ROTATION_LEASE = timedelta(seconds=30)
IDEMPOTENCY_SECRET_NAME = "run-idempotency-pepper"


@dataclass(frozen=True, slots=True)
class KeyringStatus:
    primary_version: int
    configured_versions: tuple[int, ...]
    usage: tuple[EncryptionUsage, ...]
    latest_job: KeyRotationJob | None


class EncryptionService:
    def __init__(
        self,
        unit_of_work_factory: UnitOfWorkFactory,
        keyring: MasterKeyring,
        *,
        audit_source: AuditSource = AuditSource.SYSTEM,
    ) -> None:
        self._unit_of_work_factory = unit_of_work_factory
        self._keyring = keyring
        self._audit_source = audit_source

    async def ensure_keyring(self) -> None:
        now = utc_now()
        emitted = []
        async with self._unit_of_work_factory() as unit_of_work:
            registered = {
                record.key_version: record for record in await unit_of_work.encryption.list_keys()
            }
            if not registered:
                legacy = await unit_of_work.assets.get_setting("encryption.master-key-check")
                if legacy is not None:
                    version = legacy.get("version")
                    encoded = legacy.get("envelope")
                    if not isinstance(version, int) or not isinstance(encoded, str):
                        raise ValueError("legacy master-key check metadata is invalid")
                    if not self._keyring.has_version(version):
                        raise KeyVersionMissingError(details={"keyVersion": version})
                    try:
                        envelope = base64.b64decode(encoded, validate=True)
                    except ValueError as error:
                        raise ValueError("legacy master-key check metadata is invalid") from error
                    self._keyring.validate_legacy_check(version, envelope)
            for version in self._keyring.versions:
                current = registered.get(version)
                if current is None:
                    record = EncryptionKeyRecord(
                        key_version=version,
                        verification_envelope=self._keyring.encrypt_check(version),
                        registered_at=now,
                    )
                    await unit_of_work.encryption.add_key(record)
                    emitted.append(
                        new_audit_event(
                            AuditAction.MASTER_KEY_REGISTERED,
                            AuditOutcome.SUCCEEDED,
                            source=AuditSource.SYSTEM,
                            metadata={"key_version": version},
                        )
                    )
                else:
                    self._keyring.validate_check(version, current.verification_envelope)
            usage = await unit_of_work.encryption.usage()
            missing = sorted(
                item.key_version
                for item in usage
                if item.total_count > 0 and not self._keyring.has_version(item.key_version)
            )
            if missing:
                raise KeyVersionMissingError(details={"keyVersions": missing})
            pepper = await unit_of_work.encryption.get_system_secret(IDEMPOTENCY_SECRET_NAME)
            if pepper is None:
                envelope, version = self._keyring.encrypt_bytes(
                    "system-secret", IDEMPOTENCY_SECRET_NAME, os.urandom(32)
                )
                await unit_of_work.encryption.put_system_secret(
                    SystemSecretEnvelope(
                        secret_name=IDEMPOTENCY_SECRET_NAME,
                        encrypted_secret=envelope,
                        encryption_key_version=version,
                        updated_at=now,
                    )
                )
            for event in emitted:
                await unit_of_work.audit.append(event)
        for event in emitted:
            emit_audit_event(event)

    async def idempotency_pepper(self) -> bytes:
        async with self._unit_of_work_factory() as unit_of_work:
            envelope = await unit_of_work.encryption.get_system_secret(IDEMPOTENCY_SECRET_NAME)
        if envelope is None:
            raise RuntimeError("idempotency pepper is not initialized")
        return self._keyring.decrypt_bytes(
            "system-secret",
            envelope.secret_name,
            envelope.encrypted_secret,
            envelope.encryption_key_version,
        )

    async def status(self, actor: SessionPrincipal) -> KeyringStatus:
        require_permission(actor, Permission.KEY_ROTATE)
        async with self._unit_of_work_factory() as unit_of_work:
            return KeyringStatus(
                primary_version=self._keyring.primary_version,
                configured_versions=self._keyring.versions,
                usage=await unit_of_work.encryption.usage(),
                latest_job=await unit_of_work.encryption.latest_rotation_job(),
            )

    async def request_rotation(self, actor: SessionPrincipal) -> KeyRotationJob:
        require_permission(actor, Permission.KEY_ROTATE)
        require_recent_reauthentication(actor)
        now = utc_now()
        async with self._unit_of_work_factory() as unit_of_work:
            usage = await unit_of_work.encryption.usage()
            remaining = sum(
                item.total_count
                for item in usage
                if item.key_version != self._keyring.primary_version
            )
            job = await unit_of_work.encryption.create_rotation_job(
                KeyRotationJob(
                    key_rotation_job_id=uuid4(),
                    target_key_version=self._keyring.primary_version,
                    state=KeyRotationState.PENDING,
                    requested_by=actor.user_id,
                    processed_count=0,
                    remaining_count=remaining,
                    created_at=now,
                    updated_at=now,
                )
            )
            event = new_audit_event(
                AuditAction.MASTER_KEY_ROTATION_REQUESTED,
                AuditOutcome.SUCCEEDED,
                source=self._audit_source,
                actor_user_id=actor.user_id,
                session_id=actor.session_id,
                resource_type="key_rotation_job",
                resource_id=job.key_rotation_job_id,
                metadata={
                    "target_key_version": job.target_key_version,
                    "remaining_count": remaining,
                },
            )
            await unit_of_work.audit.append(event)
        emit_audit_event(event)
        return job

    def _reencrypt(self, record: EncryptedRecord, target_version: int) -> EncryptedRecord:
        if record.kind is EncryptedRecordKind.CREDENTIAL:
            if record.sub_id is None:
                raise ValueError("credential envelope revision is missing")
            cipher = CredentialCipher(self._keyring)
            secret = cipher.decrypt(
                UUID(record.record_id),
                record.sub_id,
                record.encrypted_payload,
                record.encryption_key_version,
            )
            envelope = cipher.encrypt(UUID(record.record_id), record.sub_id, secret)
        else:
            purpose = {
                EncryptedRecordKind.MFA: "totp",
                EncryptedRecordKind.SYSTEM: "system-secret",
                EncryptedRecordKind.RUN_SECRET: "run-parameters",
            }[record.kind]
            plaintext = self._keyring.decrypt_bytes(
                purpose,
                record.record_id,
                record.encrypted_payload,
                record.encryption_key_version,
            )
            envelope, _ = self._keyring.encrypt_bytes(
                purpose, record.record_id, plaintext, key_version=target_version
            )
        return record.model_copy(
            update={"encrypted_payload": envelope, "encryption_key_version": target_version}
        )

    async def process_rotation_batch(self, worker_id: str) -> bool:
        now = utc_now()
        job: KeyRotationJob | None = None
        try:
            async with self._unit_of_work_factory() as unit_of_work:
                job = await unit_of_work.encryption.claim_rotation_job(
                    worker_id, now, now + ROTATION_LEASE
                )
                if job is None:
                    return False
                if job.target_key_version != self._keyring.primary_version:
                    raise KeyVersionMissingError(details={"keyVersion": job.target_key_version})
                batch = await unit_of_work.encryption.load_rotation_batch(
                    job.target_key_version, ROTATION_BATCH_SIZE
                )
                rotated = tuple(self._reencrypt(record, job.target_key_version) for record in batch)
                await unit_of_work.encryption.update_rotation_batch(
                    rotated, job.target_key_version, now
                )
                usage = await unit_of_work.encryption.usage()
                remaining = sum(
                    item.total_count for item in usage if item.key_version != job.target_key_version
                )
                completed = remaining == 0
                await unit_of_work.encryption.update_rotation_job(
                    job.key_rotation_job_id,
                    state=(
                        KeyRotationState.SUCCEEDED.value
                        if completed
                        else KeyRotationState.PENDING.value
                    ),
                    processed_increment=len(rotated),
                    remaining_count=remaining,
                    now=now,
                    lease_expires_at=None,
                    error_code=None,
                )
                event = new_audit_event(
                    (
                        AuditAction.MASTER_KEY_ROTATION_SUCCEEDED
                        if completed
                        else AuditAction.MASTER_KEY_ROTATION_BATCH_COMPLETED
                    ),
                    AuditOutcome.SUCCEEDED,
                    source=AuditSource.WORKER,
                    worker_id=worker_id,
                    resource_type="key_rotation_job",
                    resource_id=job.key_rotation_job_id,
                    metadata={
                        "target_key_version": job.target_key_version,
                        "processed_count": len(rotated),
                        "remaining_count": remaining,
                    },
                )
                await unit_of_work.audit.append(event)
            emit_audit_event(event)
            return True
        except Exception as error:
            if job is not None:
                async with self._unit_of_work_factory() as unit_of_work:
                    usage = await unit_of_work.encryption.usage()
                    remaining = sum(
                        item.total_count
                        for item in usage
                        if item.key_version != job.target_key_version
                    )
                    await unit_of_work.encryption.update_rotation_job(
                        job.key_rotation_job_id,
                        state=KeyRotationState.FAILED.value,
                        processed_increment=0,
                        remaining_count=remaining,
                        now=utc_now(),
                        lease_expires_at=None,
                        error_code="key_rotation_failed",
                    )
                await AuditService(self._unit_of_work_factory).record_best_effort(
                    new_audit_event(
                        AuditAction.MASTER_KEY_ROTATION_FAILED,
                        AuditOutcome.FAILED,
                        source=AuditSource.WORKER,
                        severity=AuditSeverity.ERROR,
                        worker_id=worker_id,
                        resource_type="key_rotation_job",
                        resource_id=job.key_rotation_job_id,
                        error_code="key_rotation_failed",
                        exception_type=type(error).__name__,
                        retryable=True,
                    )
                )
            raise
