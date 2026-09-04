from __future__ import annotations

from datetime import datetime
from typing import Self
from uuid import UUID

from fastapi import APIRouter, Query, Response, status
from pydantic import ConfigDict, Field, field_validator, model_validator

from ops_composer.api.dependencies import UnitOfWorkFactoryDep
from ops_composer.api.models import StrictApiModel
from ops_composer.api.runs import PlaybookReferenceRequest
from ops_composer.auth.api import CurrentSessionDep, UnsafeSessionDep
from ops_composer.domain.ops import (
    DatabasePlaybookDocument,
    Playbook,
    PlaybookReference,
    PlaybookSource,
)
from ops_composer.services.playbooks import PlaybookService
from ops_composer.settings import PlaybookSourceMode, get_settings

router = APIRouter(prefix="/api/v1/playbooks", tags=["playbooks"])


class RawPlaybookApiModel(StrictApiModel):
    model_config = ConfigDict(
        **{**StrictApiModel.model_config, "str_strip_whitespace": False}
    )


class PlaybookSummaryResponse(StrictApiModel):
    source: PlaybookSource
    playbook_id: UUID | None = None
    path: str | None = None
    name: str
    description: str
    enabled: bool
    editable: bool
    revision: int | None = Field(default=None, ge=1)
    version: int | None = Field(default=None, ge=1)
    size: int = Field(ge=0)
    modified_at: datetime
    sha256: str

    @classmethod
    def from_domain(cls, playbook: Playbook) -> Self:
        return cls.model_validate(playbook.model_dump())


class DatabasePlaybookDetailResponse(PlaybookSummaryResponse):
    content: str = Field(repr=False)
    validator_version: str
    validated_at: datetime

    @classmethod
    def from_document(cls, document: DatabasePlaybookDocument) -> Self:
        playbook = document.playbook
        revision = document.revision
        return cls(
            source=PlaybookSource.DATABASE,
            playbook_id=playbook.playbook_id,
            path=None,
            name=playbook.name,
            description=playbook.description,
            enabled=playbook.enabled,
            editable=True,
            revision=revision.revision,
            version=playbook.version,
            size=revision.size_bytes,
            modified_at=playbook.updated_at,
            sha256=revision.sha256,
            content=revision.content,
            validator_version=revision.validator_version,
            validated_at=revision.validated_at,
        )


class PlaybookConfigResponse(StrictApiModel):
    source_mode: PlaybookSourceMode
    database_enabled: bool
    database_writable: bool
    mount_enabled: bool
    mount_read_only: bool


class DatabasePlaybookCreateRequest(RawPlaybookApiModel):
    name: str = Field(min_length=1, max_length=128)
    description: str = Field(default="", max_length=1024)
    enabled: bool = True
    content: str = Field(min_length=1, max_length=1024 * 1024, repr=False)

    @field_validator("name", "description", mode="after")
    @classmethod
    def normalize_metadata(cls, value: str) -> str:
        return value.strip()


class DatabasePlaybookUpdateRequest(DatabasePlaybookCreateRequest):
    version: int = Field(ge=1)


class PlaybookValidationRequest(RawPlaybookApiModel):
    content: str | None = Field(
        default=None,
        min_length=1,
        max_length=1024 * 1024,
        repr=False,
    )
    playbook: PlaybookReferenceRequest | None = None
    path: str | None = Field(
        default=None,
        min_length=1,
        max_length=1024,
        json_schema_extra={"deprecated": True},
    )

    @model_validator(mode="after")
    def require_one_validation_target(self) -> PlaybookValidationRequest:
        provided = sum(
            value is not None for value in (self.content, self.playbook, self.path)
        )
        if provided != 1:
            raise ValueError("provide exactly one of content, playbook, or path")
        return self

    def reference(self) -> PlaybookReference | None:
        if self.playbook is not None:
            return self.playbook.to_domain()
        if self.path is not None:
            return PlaybookReference(source=PlaybookSource.MOUNT, path=self.path)
        return None


class PlaybookValidationResponse(StrictApiModel):
    valid: bool
    output: str


def _service(factory: UnitOfWorkFactoryDep) -> PlaybookService:
    settings = get_settings()
    return PlaybookService(factory, settings)


@router.get("", operation_id="listPlaybooks")
async def list_playbooks(
    factory: UnitOfWorkFactoryDep, _: CurrentSessionDep
) -> tuple[PlaybookSummaryResponse, ...]:
    return tuple(
        PlaybookSummaryResponse.from_domain(playbook)
        for playbook in await _service(factory).list()
    )


@router.get("/config", operation_id="getPlaybookConfig")
async def get_playbook_config(_: CurrentSessionDep) -> PlaybookConfigResponse:
    mode = get_settings().playbook_source_mode
    return PlaybookConfigResponse(
        source_mode=mode.value,
        database_enabled=mode.database_enabled,
        database_writable=mode.database_enabled,
        mount_enabled=mode.mount_enabled,
        mount_read_only=True,
    )


@router.get("/detail", operation_id="getMountedPlaybook")
async def get_mounted_playbook(
    path: str,
    factory: UnitOfWorkFactoryDep,
    _: CurrentSessionDep,
) -> PlaybookSummaryResponse:
    return PlaybookSummaryResponse.from_domain(await _service(factory).get_mounted(path))


@router.post(
    "/database",
    status_code=status.HTTP_201_CREATED,
    operation_id="createDatabasePlaybook",
)
async def create_database_playbook(
    request: DatabasePlaybookCreateRequest,
    response: Response,
    factory: UnitOfWorkFactoryDep,
    principal: UnsafeSessionDep,
) -> DatabasePlaybookDetailResponse:
    document = await _service(factory).create_database(
        actor_user_id=principal.user_id,
        name=request.name,
        description=request.description,
        enabled=request.enabled,
        content=request.content,
    )
    response.headers["Cache-Control"] = "no-store"
    return DatabasePlaybookDetailResponse.from_document(document)


@router.get("/database/{playbook_id}", operation_id="getDatabasePlaybook")
async def get_database_playbook(
    playbook_id: UUID,
    response: Response,
    factory: UnitOfWorkFactoryDep,
    _: CurrentSessionDep,
) -> DatabasePlaybookDetailResponse:
    document = await _service(factory).get_database(playbook_id)
    response.headers["Cache-Control"] = "no-store"
    return DatabasePlaybookDetailResponse.from_document(document)


@router.put("/database/{playbook_id}", operation_id="updateDatabasePlaybook")
async def update_database_playbook(
    playbook_id: UUID,
    request: DatabasePlaybookUpdateRequest,
    response: Response,
    factory: UnitOfWorkFactoryDep,
    principal: UnsafeSessionDep,
) -> DatabasePlaybookDetailResponse:
    document = await _service(factory).update_database(
        playbook_id,
        actor_user_id=principal.user_id,
        expected_version=request.version,
        name=request.name,
        description=request.description,
        enabled=request.enabled,
        content=request.content,
    )
    response.headers["Cache-Control"] = "no-store"
    return DatabasePlaybookDetailResponse.from_document(document)


@router.delete(
    "/database/{playbook_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    operation_id="deleteDatabasePlaybook",
)
async def delete_database_playbook(
    playbook_id: UUID,
    factory: UnitOfWorkFactoryDep,
    principal: UnsafeSessionDep,
    version: int = Query(ge=1),
) -> Response:
    await _service(factory).delete_database(
        playbook_id,
        actor_user_id=principal.user_id,
        expected_version=version,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/validate", operation_id="validatePlaybook")
async def validate_playbook(
    request: PlaybookValidationRequest,
    response: Response,
    factory: UnitOfWorkFactoryDep,
    principal: UnsafeSessionDep,
) -> PlaybookValidationResponse:
    service = _service(factory)
    if request.content is not None:
        result = await service.validate_content(
            request.content, actor_user_id=principal.user_id
        )
    else:
        reference = request.reference()
        if reference is None:
            raise ValueError("playbook validation reference is missing")
        result = await service.validate_reference(reference, actor_user_id=principal.user_id)
    response.headers["Cache-Control"] = "no-store"
    return PlaybookValidationResponse(valid=result.valid, output=result.output)
