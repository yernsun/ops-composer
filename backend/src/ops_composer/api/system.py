from __future__ import annotations

from fastapi import APIRouter

from ops_composer.api.dependencies import UnitOfWorkFactoryDep
from ops_composer.auth.api import CurrentSessionDep
from ops_composer.services.system import SystemService
from ops_composer.settings import get_settings

router = APIRouter(prefix="/api/v1/system", tags=["system"])
PROJECT_FORGE_COMMIT = "a36fb96da3780b4bb8086cbbdb803e08ec163457"
PROJECT_FORGE_TEMPLATE_DIGEST = (
    "sha256:b500ef54df5fbbfb8daa010123aa5bda70d8d11fbb6b75de075b27a3e1e5d159"
)


@router.get("/info", operation_id="getSystemInfo")
async def system_info(_: CurrentSessionDep) -> dict[str, object]:
    settings = get_settings()
    return {
        "name": "OpsComposer",
        "version": "0.1.0",
        "database": "PostgreSQL 16 / Psycopg 3",
        "queue": "PostgreSQL",
        "projectForgeCommit": PROJECT_FORGE_COMMIT,
        "projectForgeTemplateDigest": PROJECT_FORGE_TEMPLATE_DIGEST,
        "playbookWorkspace": str(settings.playbook_workspace),
    }


@router.get("/doctor", operation_id="getSystemDoctor")
async def system_doctor(factory: UnitOfWorkFactoryDep, _: CurrentSessionDep) -> dict[str, object]:
    settings = get_settings()
    return await SystemService(factory, settings).doctor()
