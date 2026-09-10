from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, status
from pydantic import AwareDatetime

from ops_composer.api.dependencies import UnitOfWorkFactoryDep
from ops_composer.api.models import StrictApiModel
from ops_composer.auth.api import CurrentSessionDep, UnsafeSessionDep
from ops_composer.domain.encryption import KeyRotationJob, KeyRotationState
from ops_composer.services.crypto import build_master_keyring
from ops_composer.services.encryption import EncryptionService
from ops_composer.services.system import SystemService
from ops_composer.settings import get_settings

router = APIRouter(prefix="/api/v1/system", tags=["system"])
PROJECT_FORGE_COMMIT = "a36fb96da3780b4bb8086cbbdb803e08ec163457"
PROJECT_FORGE_TEMPLATE_DIGEST = (
    "sha256:b500ef54df5fbbfb8daa010123aa5bda70d8d11fbb6b75de075b27a3e1e5d159"
)


class EncryptionUsageResponse(StrictApiModel):
    key_version: int
    credential_count: int
    mfa_count: int
    system_count: int
    run_secret_count: int
    total_count: int
    configured: bool
    primary: bool


class KeyRotationResponse(StrictApiModel):
    key_rotation_job_id: UUID
    target_key_version: int
    state: KeyRotationState
    processed_count: int
    remaining_count: int | None
    error_code: str | None
    created_at: AwareDatetime
    started_at: AwareDatetime | None
    finished_at: AwareDatetime | None
    updated_at: AwareDatetime

    @classmethod
    def from_domain(cls, job: KeyRotationJob) -> KeyRotationResponse:
        return cls.model_validate(job, from_attributes=True)


class KeyringStatusResponse(StrictApiModel):
    primary_version: int
    configured_versions: tuple[int, ...]
    usage: tuple[EncryptionUsageResponse, ...]
    latest_rotation: KeyRotationResponse | None


def _encryption_service(factory: UnitOfWorkFactoryDep) -> EncryptionService:
    settings = get_settings()
    keyring = build_master_keyring(
        keyring_file=settings.master_keyring_file,
        fallback_key=settings.master_key.get_secret_value(),
        fallback_version=settings.master_key_version,
    )
    return EncryptionService(factory, keyring)


@router.get("/info", operation_id="getSystemInfo")
async def system_info(_: CurrentSessionDep) -> dict[str, object]:
    settings = get_settings()
    return {
        "name": "OpsComposer",
        "version": "0.1.1",
        "database": "PostgreSQL 16 / Psycopg 3",
        "queue": "PostgreSQL",
        "projectForgeCommit": PROJECT_FORGE_COMMIT,
        "projectForgeTemplateDigest": PROJECT_FORGE_TEMPLATE_DIGEST,
        "playbookWorkspace": str(settings.playbook_workspace),
        "playbookSourceMode": settings.playbook_source_mode.value,
        "authentication": {
            "totpPolicyEnabled": settings.totp_enabled,
            "securityDegraded": not settings.totp_enabled,
        },
        "webShell": {
            "enabled": True,
            "maxSessions": settings.web_shell_max_sessions,
            "idleTimeoutSeconds": settings.web_shell_idle_timeout_seconds,
            "maxDurationSeconds": settings.web_shell_max_duration_seconds,
        },
    }


@router.get("/doctor", operation_id="getSystemDoctor")
async def system_doctor(factory: UnitOfWorkFactoryDep, _: CurrentSessionDep) -> dict[str, object]:
    settings = get_settings()
    return await SystemService(factory, settings).doctor()


@router.get("/keyring", operation_id="getKeyringStatus")
async def keyring_status(
    factory: UnitOfWorkFactoryDep, principal: CurrentSessionDep
) -> KeyringStatusResponse:
    result = await _encryption_service(factory).status(principal)
    configured = set(result.configured_versions)
    usage_by_version = {item.key_version: item for item in result.usage}
    versions = sorted(configured | set(usage_by_version))
    return KeyringStatusResponse(
        primary_version=result.primary_version,
        configured_versions=result.configured_versions,
        usage=tuple(
            EncryptionUsageResponse(
                **(
                    usage_by_version[version].model_dump()
                    if version in usage_by_version
                    else {
                        "key_version": version,
                        "credential_count": 0,
                        "mfa_count": 0,
                        "system_count": 0,
                        "run_secret_count": 0,
                    }
                ),
                total_count=(
                    usage_by_version[version].total_count if version in usage_by_version else 0
                ),
                configured=version in configured,
                primary=version == result.primary_version,
            )
            for version in versions
        ),
        latest_rotation=(
            KeyRotationResponse.from_domain(result.latest_job)
            if result.latest_job is not None
            else None
        ),
    )


@router.post(
    "/keyring/rotations",
    operation_id="requestKeyRotation",
    status_code=status.HTTP_202_ACCEPTED,
)
async def request_key_rotation(
    factory: UnitOfWorkFactoryDep, principal: UnsafeSessionDep
) -> KeyRotationResponse:
    job = await _encryption_service(factory).request_rotation(principal)
    return KeyRotationResponse.from_domain(job)
