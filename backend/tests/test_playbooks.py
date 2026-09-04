from __future__ import annotations

import hashlib
import stat
from pathlib import Path
from typing import Any, cast
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import pytest

from ops_composer.domain.audit import AuditAction, AuditEventDraft
from ops_composer.domain.base import utc_now
from ops_composer.domain.errors import (
    PlaybookInvalidError,
    PlaybookNotFoundError,
    PlaybookSourceDisabledError,
    PlaybookVersionConflictError,
)
from ops_composer.domain.ops import (
    DatabasePlaybook,
    DatabasePlaybookDocument,
    Playbook,
    PlaybookReference,
    PlaybookRevision,
    PlaybookSource,
)
from ops_composer.services.playbooks import (
    MAX_PLAYBOOK_BYTES,
    PlaybookService,
    PlaybookValidationResult,
    PlaybookValidator,
)
from ops_composer.settings import Settings
from ops_composer.uow.factory import UnitOfWorkFactory

VALID_YAML = "---\n- name: Check\n  hosts: all\n  gather_facts: false\n  tasks: []\n"


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
        if current is None or current.playbook.version != expected_version:
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
        if current is None or current.playbook.version != expected_version:
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
