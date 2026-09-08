from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from uuid import UUID

from pydantic import Field

from ops_composer.domain.base import StrictDomainModel


class KeyRotationState(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"


class EncryptionKeyRecord(StrictDomainModel):
    key_version: int = Field(ge=1)
    verification_envelope: bytes = Field(repr=False)
    registered_at: datetime
    retired_at: datetime | None = None


class SystemSecretEnvelope(StrictDomainModel):
    secret_name: str
    encrypted_secret: bytes = Field(repr=False)
    encryption_key_version: int = Field(ge=1)
    updated_at: datetime


class EncryptionUsage(StrictDomainModel):
    key_version: int = Field(ge=1)
    credential_count: int = Field(ge=0)
    mfa_count: int = Field(ge=0)
    system_count: int = Field(ge=0)
    run_secret_count: int = Field(ge=0)

    @property
    def total_count(self) -> int:
        return self.credential_count + self.mfa_count + self.system_count + self.run_secret_count


class KeyRotationJob(StrictDomainModel):
    key_rotation_job_id: UUID
    target_key_version: int = Field(ge=1)
    state: KeyRotationState
    requested_by: UUID
    claimed_by: str | None = None
    lease_expires_at: datetime | None = None
    processed_count: int = Field(ge=0)
    remaining_count: int | None = Field(default=None, ge=0)
    error_code: str | None = None
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    updated_at: datetime


class EncryptedRecordKind(StrEnum):
    CREDENTIAL = "CREDENTIAL"
    MFA = "MFA"
    SYSTEM = "SYSTEM"
    RUN_SECRET = "RUN_SECRET"


class EncryptedRecord(StrictDomainModel):
    kind: EncryptedRecordKind
    record_id: str
    sub_id: int | None = None
    encrypted_payload: bytes = Field(repr=False)
    encryption_key_version: int = Field(ge=1)
