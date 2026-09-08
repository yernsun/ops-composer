from __future__ import annotations

from datetime import datetime
from typing import Annotated, Self
from uuid import UUID

from fastapi import APIRouter, File, Form, Query, Response, UploadFile, status
from pydantic import ConfigDict, Field, field_validator, model_validator

from ops_composer.api.dependencies import UnitOfWorkFactoryDep
from ops_composer.api.models import StrictApiModel
from ops_composer.api.runs import PlaybookReferenceRequest
from ops_composer.auth.api import CurrentSessionDep, UnsafeSessionDep
from ops_composer.auth.models import Permission
from ops_composer.auth.service import require_permission
from ops_composer.domain.ops import (
    DatabasePlaybookDocument,
    Playbook,
    PlaybookReference,
    PlaybookRevision,
    PlaybookRevisionFile,
    PlaybookRevisionFormat,
    PlaybookSource,
)
from ops_composer.services.playbooks import PlaybookService
from ops_composer.settings import PlaybookSourceMode, get_settings

router = APIRouter(prefix="/api/v1/playbooks", tags=["playbooks"])


class RawPlaybookApiModel(StrictApiModel):
    model_config = ConfigDict(**{**StrictApiModel.model_config, "str_strip_whitespace": False})


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
    revision_format: PlaybookRevisionFormat
    entrypoint: str | None
    supports_check_mode: bool

    @classmethod
    def from_domain(cls, playbook: Playbook) -> Self:
        return cls.model_validate(playbook.model_dump())


class DatabasePlaybookDetailResponse(PlaybookSummaryResponse):
    content: str | None = Field(default=None, repr=False)
    files: tuple[PlaybookRevisionFile, ...] = ()
    parameter_schema: dict[str, object]
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
            files=revision.files,
            revision_format=revision.revision_format,
            entrypoint=revision.entrypoint,
            parameter_schema=revision.parameter_schema,
            supports_check_mode=revision.supports_check_mode,
            validator_version=revision.validator_version,
            validated_at=revision.validated_at,
        )


class PlaybookConfigResponse(StrictApiModel):
    source_mode: PlaybookSourceMode
    database_enabled: bool
    database_writable: bool
    mount_enabled: bool
    mount_read_only: bool


class PlaybookFileRequest(RawPlaybookApiModel):
    path: str = Field(min_length=1, max_length=512)
    content: str = Field(min_length=1, max_length=1024 * 1024, repr=False)


class DatabasePlaybookCreateRequest(RawPlaybookApiModel):
    name: str = Field(min_length=1, max_length=128)
    description: str = Field(default="", max_length=1024)
    enabled: bool = True
    content: str | None = Field(default=None, min_length=1, max_length=1024 * 1024, repr=False)
    files: tuple[PlaybookFileRequest, ...] | None = Field(default=None, max_length=256)
    entrypoint: str | None = Field(default=None, min_length=1, max_length=512)
    parameter_schema: dict[str, object] | None = None
    supports_check_mode: bool = False

    @field_validator("name", "description", mode="after")
    @classmethod
    def normalize_metadata(cls, value: str) -> str:
        return value.strip()

    @model_validator(mode="after")
    def require_one_content_shape(self) -> DatabasePlaybookCreateRequest:
        if (self.content is None) == (self.files is None):
            raise ValueError("provide exactly one of content or files")
        if self.files is not None and self.entrypoint is None:
            raise ValueError("entrypoint is required for project files")
        if self.files is not None and len({item.path.casefold() for item in self.files}) != len(
            self.files
        ):
            raise ValueError("project file paths must be unique ignoring case")
        if self.content is not None and (
            self.entrypoint is not None or self.parameter_schema is not None
        ):
            raise ValueError("legacy content cannot include project fields")
        return self

    def file_map(self) -> dict[str, str] | None:
        if self.files is None:
            return None
        return {item.path: item.content for item in self.files}


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
    files: tuple[PlaybookFileRequest, ...] | None = Field(default=None, max_length=256)
    entrypoint: str | None = Field(default=None, min_length=1, max_length=512)
    parameter_schema: dict[str, object] | None = None
    supports_check_mode: bool = False

    @model_validator(mode="after")
    def require_one_validation_target(self) -> PlaybookValidationRequest:
        provided = sum(
            value is not None for value in (self.content, self.files, self.playbook, self.path)
        )
        if provided != 1:
            raise ValueError("provide exactly one validation target")
        if self.files is not None and self.entrypoint is None:
            raise ValueError("entrypoint is required for project files")
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


class PlaybookRevisionResponse(StrictApiModel):
    revision: int
    revision_format: PlaybookRevisionFormat
    entrypoint: str | None
    sha256: str
    size_bytes: int
    validator_version: str
    validated_at: datetime
    created_by: UUID
    created_at: datetime
    parameter_schema: dict[str, object]
    supports_check_mode: bool
    files: tuple[PlaybookRevisionFile, ...] | None = None
    content: str | None = Field(default=None, repr=False)

    @classmethod
    def from_domain(
        cls, revision: PlaybookRevision, *, include_content: bool
    ) -> PlaybookRevisionResponse:
        values = revision.model_dump(mode="python")
        values.pop("playbook_id", None)
        if not include_content:
            values["content"] = None
            values["files"] = None
        return cls.model_validate(values)


class PlaybookDiffResponse(StrictApiModel):
    revision: int
    against_revision: int
    added: list[str]
    deleted: list[str]
    modified: list[str]
    diff: str


class PlaybookRestoreRequest(StrictApiModel):
    version: int = Field(ge=1)


class PlaybookZipImportResponse(StrictApiModel):
    entrypoint: str
    files: tuple[PlaybookRevisionFile, ...]
    sha256: str
    size_bytes: int


def _service(factory: UnitOfWorkFactoryDep) -> PlaybookService:
    settings = get_settings()
    return PlaybookService(factory, settings)


@router.get("", operation_id="listPlaybooks")
async def list_playbooks(
    factory: UnitOfWorkFactoryDep, _: CurrentSessionDep
) -> tuple[PlaybookSummaryResponse, ...]:
    return tuple(
        PlaybookSummaryResponse.from_domain(playbook) for playbook in await _service(factory).list()
    )


@router.get("/config", operation_id="getPlaybookConfig")
async def get_playbook_config(principal: CurrentSessionDep) -> PlaybookConfigResponse:
    mode = get_settings().playbook_source_mode
    return PlaybookConfigResponse(
        source_mode=mode,
        database_enabled=mode.database_enabled,
        database_writable=(
            mode.database_enabled and Permission.PLAYBOOK_WRITE in principal.permissions
        ),
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
    require_permission(principal, Permission.PLAYBOOK_WRITE)
    if request.content is not None:
        response.headers["Deprecation"] = "true"
        response.headers["Sunset"] = "Wed, 31 Mar 2027 00:00:00 GMT"
    document = await _service(factory).create_database(
        actor_user_id=principal.user_id,
        name=request.name,
        description=request.description,
        enabled=request.enabled,
        content=request.content,
        files=request.file_map(),
        entrypoint=request.entrypoint,
        parameter_schema=request.parameter_schema,
        supports_check_mode=request.supports_check_mode,
        actor=principal,
    )
    response.headers["Cache-Control"] = "no-store"
    return DatabasePlaybookDetailResponse.from_document(document)


@router.post("/database/import", operation_id="importPlaybookProjectZip")
async def import_playbook_project_zip(
    factory: UnitOfWorkFactoryDep,
    principal: UnsafeSessionDep,
    file: Annotated[UploadFile, File()],
    entrypoint: Annotated[str | None, Form()] = None,
) -> PlaybookZipImportResponse:
    require_permission(principal, Permission.PLAYBOOK_WRITE)
    payload = await file.read(12 * 1024 * 1024 + 1)
    project = await _service(factory).import_zip(
        payload,
        entrypoint=entrypoint,
        actor_user_id=principal.user_id,
        actor=principal,
    )
    return PlaybookZipImportResponse(
        entrypoint=project.entrypoint,
        files=project.files,
        sha256=project.sha256,
        size_bytes=project.size_bytes,
    )


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
    require_permission(principal, Permission.PLAYBOOK_WRITE)
    if request.content is not None:
        response.headers["Deprecation"] = "true"
        response.headers["Sunset"] = "Wed, 31 Mar 2027 00:00:00 GMT"
    document = await _service(factory).update_database(
        playbook_id,
        actor_user_id=principal.user_id,
        expected_version=request.version,
        name=request.name,
        description=request.description,
        enabled=request.enabled,
        content=request.content,
        files=request.file_map(),
        entrypoint=request.entrypoint,
        parameter_schema=request.parameter_schema,
        supports_check_mode=request.supports_check_mode,
        actor=principal,
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
    require_permission(principal, Permission.PLAYBOOK_WRITE)
    await _service(factory).delete_database(
        playbook_id,
        actor_user_id=principal.user_id,
        expected_version=version,
        actor=principal,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get(
    "/database/{playbook_id}/revisions",
    operation_id="listPlaybookRevisions",
)
async def list_playbook_revisions(
    playbook_id: UUID,
    factory: UnitOfWorkFactoryDep,
    _: CurrentSessionDep,
) -> tuple[PlaybookRevisionResponse, ...]:
    revisions = await _service(factory).list_revisions(playbook_id)
    return tuple(
        PlaybookRevisionResponse.from_domain(revision, include_content=False)
        for revision in revisions
    )


@router.get(
    "/database/{playbook_id}/revisions/{revision}",
    operation_id="getPlaybookRevision",
)
async def get_playbook_revision(
    playbook_id: UUID,
    revision: int,
    response: Response,
    factory: UnitOfWorkFactoryDep,
    _: CurrentSessionDep,
) -> PlaybookRevisionResponse:
    response.headers["Cache-Control"] = "no-store"
    result = await _service(factory).get_revision(playbook_id, revision)
    return PlaybookRevisionResponse.from_domain(result, include_content=True)


@router.get(
    "/database/{playbook_id}/revisions/{revision}/diff",
    operation_id="diffPlaybookRevisions",
)
async def diff_playbook_revisions(
    playbook_id: UUID,
    revision: int,
    factory: UnitOfWorkFactoryDep,
    _: CurrentSessionDep,
    against_revision: int = Query(alias="againstRevision", ge=1),
) -> PlaybookDiffResponse:
    result = await _service(factory).diff_revisions(
        playbook_id,
        revision,
        against_revision,
    )
    return PlaybookDiffResponse.model_validate(result)


@router.post(
    "/database/{playbook_id}/revisions/{revision}/restore",
    operation_id="restorePlaybookRevision",
)
async def restore_playbook_revision(
    playbook_id: UUID,
    revision: int,
    request: PlaybookRestoreRequest,
    response: Response,
    factory: UnitOfWorkFactoryDep,
    principal: UnsafeSessionDep,
) -> DatabasePlaybookDetailResponse:
    require_permission(principal, Permission.PLAYBOOK_WRITE)
    response.headers["Cache-Control"] = "no-store"
    result = await _service(factory).restore_revision(
        playbook_id,
        revision,
        actor_user_id=principal.user_id,
        expected_version=request.version,
        actor=principal,
    )
    return DatabasePlaybookDetailResponse.from_document(result)


@router.get(
    "/database/{playbook_id}/revisions/{revision}/export",
    operation_id="exportPlaybookProjectZip",
)
async def export_playbook_project_zip(
    playbook_id: UUID,
    revision: int,
    factory: UnitOfWorkFactoryDep,
    principal: CurrentSessionDep,
) -> Response:
    payload = await _service(factory).export_zip(
        playbook_id,
        revision,
        actor_user_id=principal.user_id,
    )
    return Response(
        payload,
        media_type="application/zip",
        headers={
            "Cache-Control": "no-store",
            "Content-Disposition": (
                f'attachment; filename="playbook-{playbook_id}-r{revision}.zip"'
            ),
        },
    )


@router.post("/validate", operation_id="validatePlaybook")
async def validate_playbook(
    request: PlaybookValidationRequest,
    response: Response,
    factory: UnitOfWorkFactoryDep,
    principal: UnsafeSessionDep,
) -> PlaybookValidationResponse:
    service = _service(factory)
    if request.path is not None or request.content is not None:
        response.headers["Deprecation"] = "true"
        response.headers["Sunset"] = "Wed, 31 Mar 2027 00:00:00 GMT"
    if request.content is not None:
        require_permission(principal, Permission.PLAYBOOK_WRITE)
        result = await service.validate_content(
            request.content,
            actor_user_id=principal.user_id,
            actor=principal,
        )
    elif request.files is not None:
        require_permission(principal, Permission.PLAYBOOK_WRITE)
        if request.entrypoint is None:
            raise ValueError("project entrypoint is missing")
        result = await service.validate_project(
            files={item.path: item.content for item in request.files},
            entrypoint=request.entrypoint,
            parameter_schema=request.parameter_schema,
            supports_check_mode=request.supports_check_mode,
            actor_user_id=principal.user_id,
            actor=principal,
        )
    else:
        reference = request.reference()
        if reference is None:
            raise ValueError("playbook validation reference is missing")
        result = await service.validate_reference(reference, actor_user_id=principal.user_id)
    response.headers["Cache-Control"] = "no-store"
    return PlaybookValidationResponse(valid=result.valid, output=result.output)
