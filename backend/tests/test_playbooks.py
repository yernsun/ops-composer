from __future__ import annotations

import asyncio
import hashlib
import importlib.metadata
import stat
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import pytest

from ops_composer.auth.models import SessionPrincipal
from ops_composer.domain.audit import AuditAction, AuditEventDraft
from ops_composer.domain.base import utc_now
from ops_composer.domain.errors import (
    PlaybookInvalidError,
    PlaybookNotFoundError,
    PlaybookProjectInvalidError,
    PlaybookSourceDisabledError,
    PlaybookVersionConflictError,
    ValidationError,
)
from ops_composer.domain.ops import (
    DatabasePlaybook,
    DatabasePlaybookDocument,
    Playbook,
    PlaybookReference,
    PlaybookRevision,
    PlaybookRevisionFormat,
    PlaybookSource,
)
from ops_composer.services.playbook_project import normalize_project, validate_parameter_schema
from ops_composer.services.playbooks import (
    MAX_PLAYBOOK_BYTES,
    PlaybookCatalog,
    PlaybookService,
    PlaybookValidationResult,
    PlaybookValidator,
)
from ops_composer.settings import Settings
from ops_composer.uow.factory import UnitOfWorkFactory

VALID_YAML = "---\n- name: Check\n  hosts: all\n  gather_facts: false\n  tasks: []\n"


def _owner() -> SessionPrincipal:
    return SessionPrincipal(
        session_id=uuid4(),
        user_id=uuid4(),
        username="owner",
        csrf_hash="c" * 64,
        expires_at=utc_now() + timedelta(hours=1),
    )


def test_playbook_reference_requires_exactly_one_source_identifier() -> None:
    playbook_id = uuid4()
    assert PlaybookReference(
        source=PlaybookSource.DATABASE, playbook_id=playbook_id
    ).playbook_id == playbook_id
    assert PlaybookReference(
        source=PlaybookSource.MOUNT, path="playbooks/site.yml"
    ).path == "playbooks/site.yml"
    with pytest.raises(ValueError):
        PlaybookReference(source=PlaybookSource.DATABASE, path="playbooks/site.yml")
    with pytest.raises(ValueError):
        PlaybookReference(source=PlaybookSource.MOUNT, playbook_id=playbook_id)


@pytest.mark.asyncio
async def test_database_playbook_validation_is_isolated_normalized_and_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    validator = PlaybookValidator()
    observed: dict[str, object] = {}

    async def syntax_check(path: Path, *, cwd: Path) -> tuple[bool, str]:
        observed["content"] = path.read_text(encoding="utf-8")
        observed["path_mode"] = stat.S_IMODE(path.stat().st_mode)
        observed["directory_mode"] = stat.S_IMODE(cwd.stat().st_mode)
        observed["same_parent"] = path.parent == cwd
        return True, "syntax check passed"

    monkeypatch.setattr(validator, "_syntax_check", syntax_check)
    result = await validator.validate_content(VALID_YAML.replace("\n", "\r\n"))

    assert result.valid
    assert result.normalized_content == VALID_YAML
    assert result.sha256 == hashlib.sha256(VALID_YAML.encode()).hexdigest()
    assert result.size_bytes == len(VALID_YAML.encode())
    assert observed == {
        "content": VALID_YAML,
        "path_mode": 0o600,
        "directory_mode": 0o700,
        "same_parent": True,
    }

    for content in ("", "- hosts: all\0", "x" * (MAX_PLAYBOOK_BYTES + 1)):
        with pytest.raises(PlaybookInvalidError):
            await validator.validate_content(content)

    syntax = AsyncMock(return_value=(True, "must not run"))
    monkeypatch.setattr(validator, "_syntax_check", syntax)
    invalid = await validator.validate_content("key: value\n")
    assert not invalid.valid
    assert invalid.output == "playbook root must be a list of plays"
    syntax.assert_not_awaited()


class _PlaybookRepository:
    def __init__(self, catalog: tuple[Playbook, ...] = ()) -> None:
        self.catalog = catalog
        self.documents: dict[UUID, DatabasePlaybookDocument] = {}
        self.revisions: dict[tuple[UUID, int], PlaybookRevision] = {}
        self.force_update_conflict = False
        self.force_delete_conflict = False

    async def list_active(self) -> tuple[Playbook, ...]:
        return self.catalog

    async def get_document(
        self,
        playbook_id: UUID,
        *,
        include_deleted: bool = False,
        for_update: bool = False,
    ) -> DatabasePlaybookDocument | None:
        del for_update
        document = self.documents.get(playbook_id)
        if document is None:
            return None
        if document.playbook.deleted_at is not None and not include_deleted:
            return None
        return document

    async def get_revision(
        self, playbook_id: UUID, revision: int
    ) -> PlaybookRevision | None:
        return self.revisions.get((playbook_id, revision))

    async def list_revisions(self, playbook_id: UUID) -> tuple[PlaybookRevision, ...]:
        return tuple(
            revision
            for (current_id, _number), revision in sorted(
                self.revisions.items(), key=lambda item: item[0][1], reverse=True
            )
            if current_id == playbook_id
        )

    async def add(
        self, playbook: DatabasePlaybook, revision: PlaybookRevision
    ) -> DatabasePlaybookDocument:
        document = DatabasePlaybookDocument(playbook=playbook, revision=revision)
        self.documents[playbook.playbook_id] = document
        self.revisions[(playbook.playbook_id, revision.revision)] = revision
        return document

    async def update(
        self,
        playbook: DatabasePlaybook,
        revision: PlaybookRevision,
        *,
        expected_version: int,
    ) -> DatabasePlaybookDocument | None:
        current = self.documents.get(playbook.playbook_id)
        if (
            self.force_update_conflict
            or current is None
            or current.playbook.version != expected_version
        ):
            return None
        document = DatabasePlaybookDocument(playbook=playbook, revision=revision)
        self.documents[playbook.playbook_id] = document
        self.revisions[(playbook.playbook_id, revision.revision)] = revision
        return document

    async def soft_delete(
        self,
        playbook_id: UUID,
        *,
        expected_version: int,
        deleted_at: object,
        updated_by: UUID,
    ) -> DatabasePlaybook | None:
        current = self.documents.get(playbook_id)
        if (
            self.force_delete_conflict
            or current is None
            or current.playbook.version != expected_version
        ):
            return None
        playbook = current.playbook.model_copy(
            update={
                "enabled": False,
                "version": expected_version + 1,
                "deleted_at": deleted_at,
                "updated_at": deleted_at,
                "updated_by": updated_by,
            }
        )
        self.documents[playbook_id] = DatabasePlaybookDocument(
            playbook=playbook,
            revision=current.revision,
        )
        return playbook


class _AuditRepository:
    def __init__(self) -> None:
        self.events: list[AuditEventDraft] = []

    async def append(self, event: AuditEventDraft) -> AuditEventDraft:
        self.events.append(event)
        return event


class _Unit:
    def __init__(self, playbooks: _PlaybookRepository, audit: _AuditRepository) -> None:
        self.playbooks = playbooks
        self.audit = audit


class _UnitContext:
    def __init__(self, unit: _Unit) -> None:
        self.unit = unit

    async def __aenter__(self) -> _Unit:
        return self.unit

    async def __aexit__(self, *_args: object) -> None:
        return None


class _Factory:
    def __init__(self, unit: _Unit) -> None:
        self.unit = unit
        self.calls = 0

    def __call__(self) -> _UnitContext:
        self.calls += 1
        return _UnitContext(self.unit)


class _Validator:
    version = "ansible-core test"

    async def validate_content(self, content: str) -> PlaybookValidationResult:
        if content == "invalid":
            return PlaybookValidationResult(valid=False, output="invalid syntax")
        normalized = content.replace("\r\n", "\n").replace("\r", "\n")
        encoded = normalized.encode()
        return PlaybookValidationResult(
            valid=True,
            output="syntax check passed",
            normalized_content=normalized,
            sha256=hashlib.sha256(encoded).hexdigest(),
            size_bytes=len(encoded),
            validator_version=self.version,
        )

    async def validate_project(
        self,
        files: dict[str, str],
        entrypoint: str,
        parameter_schema: dict[str, object] | None,
        supports_check_mode: bool,
    ) -> PlaybookValidationResult:
        project = normalize_project(files, entrypoint)
        return PlaybookValidationResult(
            valid=True,
            output="syntax check passed",
            sha256=project.sha256,
            size_bytes=project.size_bytes,
            validator_version=self.version,
            normalized_files=project.files,
            entrypoint=project.entrypoint,
            parameter_schema=validate_parameter_schema(parameter_schema),
            supports_check_mode=supports_check_mode,
        )


class _MountedCatalog:
    def __init__(self, playbook: Playbook) -> None:
        self.playbook = playbook
        self.list_calls = 0

    async def list(self) -> tuple[Playbook, ...]:
        self.list_calls += 1
        return (self.playbook,)

    async def get(self, _path: str) -> Playbook:
        return self.playbook

    async def syntax_check(self, _path: str) -> tuple[bool, str]:
        return True, "syntax check passed"


@pytest.mark.asyncio
async def test_playbook_service_creates_immutable_revisions_and_soft_deletes() -> None:
    repository = _PlaybookRepository()
    audit = _AuditRepository()
    factory = _Factory(_Unit(repository, audit))
    service = PlaybookService(
        cast(UnitOfWorkFactory, factory),
        Settings(playbook_source_mode="database"),
        validator=cast(Any, _Validator()),
    )
    administrator = uuid4()

    created = await service.create_database(
        actor_user_id=administrator,
        name="  Site  ",
        description=" first ",
        enabled=True,
        content=VALID_YAML.replace("\n", "\r\n"),
    )
    assert created.playbook.name == "Site"
    assert created.revision.content == VALID_YAML
    assert created.playbook.current_revision == 1

    updated = await service.update_database(
        created.playbook.playbook_id,
        actor_user_id=administrator,
        expected_version=1,
        name="Site",
        description="second",
        enabled=False,
        content=VALID_YAML + "# revision two\n",
    )
    assert updated.playbook.version == 2
    assert updated.playbook.current_revision == 2
    assert repository.revisions[(created.playbook.playbook_id, 1)].content == VALID_YAML
    assert repository.revisions[(created.playbook.playbook_id, 2)].content.endswith(
        "# revision two\n"
    )

    with pytest.raises(PlaybookVersionConflictError):
        await service.update_database(
            created.playbook.playbook_id,
            actor_user_id=administrator,
            expected_version=1,
            name="Site",
            description="stale",
            enabled=True,
            content=VALID_YAML,
        )

    await service.delete_database(
        created.playbook.playbook_id,
        actor_user_id=administrator,
        expected_version=2,
    )
    with pytest.raises(PlaybookNotFoundError):
        await service.get_database(created.playbook.playbook_id)
    assert await repository.get_revision(created.playbook.playbook_id, 1) is not None
    assert [event.event_action for event in audit.events if event.event_action in {
        AuditAction.PLAYBOOK_CREATED,
        AuditAction.PLAYBOOK_UPDATED,
        AuditAction.PLAYBOOK_DELETED,
    }] == [
        AuditAction.PLAYBOOK_CREATED,
        AuditAction.PLAYBOOK_UPDATED,
        AuditAction.PLAYBOOK_DELETED,
    ]
    assert VALID_YAML not in str([event.metadata for event in audit.events])


@pytest.mark.asyncio
async def test_playbook_source_modes_are_independent_and_allow_same_display_name(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    now = utc_now()
    database = Playbook(
        source=PlaybookSource.DATABASE,
        playbook_id=uuid4(),
        name="Site",
        description="database",
        enabled=True,
        editable=True,
        revision=1,
        version=1,
        size=10,
        modified_at=now,
        sha256="a" * 64,
    )
    mounted = Playbook(
        source=PlaybookSource.MOUNT,
        path="playbooks/site.yml",
        name="Site",
        enabled=True,
        editable=False,
        size=10,
        modified_at=now,
        sha256="b" * 64,
    )
    repository = _PlaybookRepository((database,))
    factory = _Factory(_Unit(repository, _AuditRepository()))
    catalog = _MountedCatalog(mounted)

    database_service = PlaybookService(
        cast(UnitOfWorkFactory, factory),
        Settings(playbook_source_mode="database", playbook_workspace=tmp_path),
        mounted_catalog=cast(Any, catalog),
    )
    assert await database_service.list() == (database,)
    assert catalog.list_calls == 0
    with pytest.raises(PlaybookSourceDisabledError):
        await database_service.get_mounted(mounted.path or "")

    def reject_workspace_access(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("database mode must not initialize the mounted catalog")

    monkeypatch.setattr(
        "ops_composer.services.playbooks.PlaybookCatalog", reject_workspace_access
    )
    database_only = PlaybookService(
        cast(UnitOfWorkFactory, factory),
        Settings(playbook_source_mode="database", playbook_workspace=tmp_path / "missing"),
    )
    assert await database_only.list() == (database,)

    mount_service = PlaybookService(
        cast(UnitOfWorkFactory, factory),
        Settings(playbook_source_mode="mount", playbook_workspace=tmp_path),
        mounted_catalog=cast(Any, catalog),
    )
    calls_before = factory.calls
    assert await mount_service.list() == (mounted,)
    assert factory.calls == calls_before

    both_service = PlaybookService(
        cast(UnitOfWorkFactory, factory),
        Settings(playbook_source_mode="both", playbook_workspace=tmp_path),
        mounted_catalog=cast(Any, catalog),
    )
    both = await both_service.list()
    assert {(item.source, item.playbook_id, item.path) for item in both} == {
        (PlaybookSource.DATABASE, database.playbook_id, None),
        (PlaybookSource.MOUNT, None, mounted.path),
    }


@pytest.mark.asyncio
async def test_playbook_validator_reports_missing_binary_timeout_and_read_errors(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    def missing_distribution(_name: str) -> str:
        raise importlib.metadata.PackageNotFoundError

    monkeypatch.setattr(importlib.metadata, "version", missing_distribution)
    validator = PlaybookValidator()
    assert validator.version == "ansible-core unavailable"
    assert validator._validate_document("bad: [") == "playbook YAML is invalid"

    monkeypatch.setattr("ops_composer.services.playbooks.shutil.which", lambda _name: None)
    with pytest.raises(ValidationError, match="not installed"):
        await validator._syntax_check(tmp_path / "site.yml", cwd=tmp_path)

    monkeypatch.setattr(
        "ops_composer.services.playbooks.shutil.which",
        lambda _name: "/usr/bin/ansible-playbook",
    )

    async def missing_exec(*_args: object, **_kwargs: object) -> object:
        raise FileNotFoundError

    monkeypatch.setattr(asyncio, "create_subprocess_exec", missing_exec)
    with pytest.raises(ValidationError, match="not installed"):
        await validator._syntax_check(tmp_path / "site.yml", cwd=tmp_path)

    class _TimedOutProcess:
        returncode = None
        killed = False

        async def communicate(self) -> tuple[bytes, None]:
            return b"never returned", None

        def kill(self) -> None:
            self.killed = True

    process = _TimedOutProcess()

    async def create_process(*_args: object, **_kwargs: object) -> _TimedOutProcess:
        return process

    async def timeout(awaitable: object, *, timeout: int) -> object:
        assert timeout == 30
        cast(Any, awaitable).close()
        raise TimeoutError

    monkeypatch.setattr(asyncio, "create_subprocess_exec", create_process)
    monkeypatch.setattr(asyncio, "wait_for", timeout)
    assert await validator._syntax_check(tmp_path / "site.yml", cwd=tmp_path) == (
        False,
        "syntax check timed out",
    )
    assert process.killed

    missing = await validator.validate_path(tmp_path / "missing.yml", workspace=tmp_path)
    assert not missing.valid and "could not be read" in missing.output
    invalid_path = tmp_path / "invalid.yml"
    invalid_path.write_text("key: value\n", encoding="utf-8")
    invalid = await validator.validate_path(invalid_path, workspace=tmp_path)
    assert not invalid.valid and "root must be" in invalid.output

    project_invalid = await validator.validate_project(
        {"site.yml": "key: value\n"},
        "site.yml",
        None,
        False,
    )
    assert not project_invalid.valid


@pytest.mark.asyncio
async def test_playbook_catalog_lazy_paths_and_invalid_documents(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    catalog = PlaybookCatalog(tmp_path)
    assert catalog.workspace == tmp_path.resolve()
    assert await catalog.list() == ()
    with pytest.raises(PlaybookNotFoundError):
        catalog.resolve("playbooks/missing.yml")

    playbooks = tmp_path / "playbooks"
    playbooks.mkdir()
    broken = playbooks / "broken.yml"
    broken.write_text("bad: [", encoding="utf-8")
    with pytest.raises(PlaybookInvalidError, match="YAML"):
        await catalog.get("playbooks/broken.yml")

    good = playbooks / "good.yml"
    good.write_text(VALID_YAML, encoding="utf-8")
    validator = AsyncMock(return_value=PlaybookValidationResult(valid=True, output="ok"))
    monkeypatch.setattr(catalog._validator, "validate_path", validator)
    assert await catalog.syntax_check("playbooks/good.yml") == (True, "ok")


@pytest.mark.asyncio
async def test_playbook_service_rejects_invalid_mutations_and_records_validation() -> None:
    repository = _PlaybookRepository()
    audit = _AuditRepository()
    factory = _Factory(_Unit(repository, audit))
    validator = _Validator()
    service = PlaybookService(
        cast(UnitOfWorkFactory, factory),
        Settings(playbook_source_mode="database"),
        validator=cast(Any, validator),
    )
    owner = _owner()

    with pytest.raises(PlaybookNotFoundError):
        await service.get_database(uuid4())
    with pytest.raises(PlaybookNotFoundError):
        await service.get_revision(uuid4(), 1)
    with pytest.raises(PlaybookNotFoundError):
        await service.list_revisions(uuid4())
    for values in (
        {"name": " ", "content": VALID_YAML},
        {"name": "Site"},
        {"name": "Site", "content": VALID_YAML, "files": {"site.yml": VALID_YAML}},
        {"name": "Site", "files": {"site.yml": VALID_YAML}},
    ):
        with pytest.raises(PlaybookInvalidError):
            await service.create_database(
                actor_user_id=owner.user_id,
                description="",
                enabled=True,
                actor=owner,
                **values,
            )

    with pytest.raises(PlaybookInvalidError):
        await service.create_database(
            actor_user_id=owner.user_id,
            name="invalid",
            description="",
            enabled=True,
            content="invalid",
            actor=owner,
        )

    project = await service.create_database(
        actor_user_id=owner.user_id,
        name="Project",
        description="",
        enabled=True,
        files={"site.yml": VALID_YAML},
        entrypoint="site.yml",
        supports_check_mode=True,
        actor=owner,
    )
    assert project.revision.revision_format is PlaybookRevisionFormat.PROJECT
    assert (await service.list_revisions(project.playbook.playbook_id))[0].revision == 1

    for values in (
        {"name": " ", "content": VALID_YAML},
        {"name": "Project"},
        {
            "name": "Project",
            "content": VALID_YAML,
            "files": {"site.yml": VALID_YAML},
        },
        {"name": "Project", "files": {"site.yml": VALID_YAML}},
    ):
        with pytest.raises(PlaybookInvalidError):
            await service.update_database(
                project.playbook.playbook_id,
                actor_user_id=owner.user_id,
                expected_version=project.playbook.version,
                description="",
                enabled=True,
                actor=owner,
                **values,
            )

    repository.force_update_conflict = True
    with pytest.raises(PlaybookVersionConflictError):
        await service.update_database(
            project.playbook.playbook_id,
            actor_user_id=owner.user_id,
            expected_version=project.playbook.version,
            name="Project",
            description="",
            enabled=True,
            files={"site.yml": VALID_YAML},
            entrypoint="site.yml",
            actor=owner,
        )
    repository.force_update_conflict = False

    assert (
        await service.validate_content(
            VALID_YAML, actor_user_id=owner.user_id, actor=owner
        )
    ).valid
    assert (
        await service.validate_project(
            files={"site.yml": VALID_YAML},
            entrypoint="site.yml",
            parameter_schema=None,
            supports_check_mode=False,
            actor_user_id=owner.user_id,
            actor=owner,
        )
    ).valid

    raised_validator = SimpleNamespace(
        validate_content=AsyncMock(side_effect=PlaybookInvalidError()),
        validate_project=AsyncMock(side_effect=PlaybookProjectInvalidError()),
    )
    raised_service = PlaybookService(
        cast(UnitOfWorkFactory, factory),
        Settings(playbook_source_mode="database"),
        validator=cast(Any, raised_validator),
    )
    with pytest.raises(PlaybookInvalidError):
        await raised_service.validate_content("bad", actor_user_id=owner.user_id)
    with pytest.raises(PlaybookProjectInvalidError):
        await raised_service.import_zip(b"not-a-zip", entrypoint=None, actor_user_id=owner.user_id)

    repository.force_delete_conflict = True
    with pytest.raises(PlaybookVersionConflictError):
        await service.delete_database(
            project.playbook.playbook_id,
            actor_user_id=owner.user_id,
            expected_version=project.playbook.version,
            actor=owner,
        )
    repository.force_delete_conflict = False
    with pytest.raises(PlaybookVersionConflictError):
        await service.delete_database(
            project.playbook.playbook_id,
            actor_user_id=owner.user_id,
            expected_version=999,
            actor=owner,
        )


@pytest.mark.asyncio
async def test_playbook_reference_validation_and_large_diffs_are_bounded() -> None:
    repository = _PlaybookRepository()
    audit = _AuditRepository()
    factory = _Factory(_Unit(repository, audit))
    mounted = Playbook(
        source=PlaybookSource.MOUNT,
        path="playbooks/site.yml",
        name="Site",
        size=10,
        modified_at=utc_now(),
        sha256="a" * 64,
    )
    service = PlaybookService(
        cast(UnitOfWorkFactory, factory),
        Settings(playbook_source_mode="both"),
        mounted_catalog=cast(Any, _MountedCatalog(mounted)),
        validator=cast(Any, _Validator()),
    )
    actor_id = uuid4()
    mounted_result = await service.validate_reference(
        PlaybookReference(source=PlaybookSource.MOUNT, path=mounted.path),
        actor_user_id=actor_id,
    )
    assert mounted_result.valid
    with pytest.raises(PlaybookNotFoundError):
        await service.validate_reference(
            PlaybookReference.model_construct(source=PlaybookSource.MOUNT, path=None),
            actor_user_id=actor_id,
        )
    with pytest.raises(PlaybookNotFoundError):
        await service.validate_reference(
            PlaybookReference.model_construct(source=PlaybookSource.DATABASE, playbook_id=None),
            actor_user_id=actor_id,
        )

    legacy = await service.create_database(
        actor_user_id=actor_id,
        name="Legacy",
        description="",
        enabled=True,
        content=VALID_YAML,
    )
    assert (
        await service.validate_reference(
            PlaybookReference(
                source=PlaybookSource.DATABASE,
                playbook_id=legacy.playbook.playbook_id,
            ),
            actor_user_id=actor_id,
        )
    ).valid

    old_content = "".join(f"old-{index}-" + "a" * 5000 + "\n" for index in range(40))
    new_content = "".join(f"new-{index}-" + "b" * 5000 + "\n" for index in range(40))
    first = normalize_project({"site.yml": old_content}, "site.yml")
    second = normalize_project({"site.yml": new_content}, "site.yml")
    now = utc_now()
    for number, normalized in ((1, first), (2, second)):
        repository.revisions[(legacy.playbook.playbook_id, number)] = PlaybookRevision(
            playbook_id=legacy.playbook.playbook_id,
            revision=number,
            sha256=normalized.sha256,
            size_bytes=normalized.size_bytes,
            validator_version="test",
            validated_at=now,
            created_by=actor_id,
            created_at=now,
            revision_format=PlaybookRevisionFormat.PROJECT,
            entrypoint="site.yml",
            files=normalized.files,
        )
    diff = await service.diff_revisions(legacy.playbook.playbook_id, 2, 1)
    assert str(diff["diff"]).endswith("... diff truncated ...\n")
