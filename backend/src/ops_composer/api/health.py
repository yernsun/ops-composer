from __future__ import annotations

from fastapi import APIRouter, HTTPException, status
from pydantic import Field

from ops_composer.api.dependencies import UnitOfWorkFactoryDep
from ops_composer.api.models import StrictApiModel
from ops_composer.services.health import HealthService

router = APIRouter(prefix="/health", tags=["health"])


class HealthResponse(StrictApiModel):
    status: str = Field(description="Current health state")


@router.get("/live")
async def liveness() -> HealthResponse:
    return HealthResponse(status="ok")


@router.get("/ready")
async def readiness(unit_of_work_factory: UnitOfWorkFactoryDep) -> HealthResponse:
    if not await HealthService(unit_of_work_factory).is_ready():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="database is unavailable",
        )
    return HealthResponse(status="ready")
