from __future__ import annotations

from datetime import datetime
from typing import Protocol
from uuid import UUID

from psycopg import sql
from psycopg.errors import UniqueViolation

from ops_composer.domain.errors import ConflictError
from ops_composer.domain.ops import (
    DatabasePlaybook,
    DatabasePlaybookDocument,
    Playbook,
    PlaybookRevision,
    PlaybookSource,
)
from ops_composer.repositories.base import BaseRepository, RepositoryConnection, RepositoryRow

PLAYBOOK_COLUMNS = sql.SQL(
    "playbook_id, name, description, enabled, current_revision, version, created_by, "
    "updated_by, deleted_at, created_at, updated_at"
)
QUALIFIED_PLAYBOOK_COLUMNS = sql.SQL(
    "p.playbook_id, p.name, p.description, p.enabled, p.current_revision, p.version, "
    "p.created_by, p.updated_by, p.deleted_at, p.created_at, p.updated_at"
)
REVISION_COLUMNS = sql.SQL(
    "playbook_id, revision, content, sha256, size_bytes, validator_version, validated_at, "
    "created_by, created_at"
)


def _playbook(row: RepositoryRow) -> DatabasePlaybook:
    return DatabasePlaybook(
        playbook_id=row["playbook_id"],
        name=str(row["name"]),
        description=str(row["description"]),
        enabled=bool(row["enabled"]),
        current_revision=int(row["current_revision"]),
        version=int(row["version"]),
        created_by=row["created_by"],
        updated_by=row["updated_by"],
        deleted_at=row["deleted_at"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _revision(row: RepositoryRow) -> PlaybookRevision:
    return PlaybookRevision.model_validate(row)


def _document(row: RepositoryRow) -> DatabasePlaybookDocument:
    playbook = _playbook(row)
    revision = PlaybookRevision(
        playbook_id=playbook.playbook_id,
        revision=int(row["revision"]),
        content=str(row["content"]),
        sha256=str(row["sha256"]),
        size_bytes=int(row["size_bytes"]),
        validator_version=str(row["validator_version"]),
        validated_at=row["validated_at"],
        created_by=row["revision_created_by"],
        created_at=row["revision_created_at"],
    )
    return DatabasePlaybookDocument(playbook=playbook, revision=revision)


class PlaybookRepository(BaseRepository, Protocol):
    async def list_active(self) -> tuple[Playbook, ...]: ...
    async def get_document(
        self,
        playbook_id: UUID,
        *,
        include_deleted: bool = False,
        for_update: bool = False,
    ) -> DatabasePlaybookDocument | None: ...
    async def get_revision(self, playbook_id: UUID, revision: int) -> PlaybookRevision | None: ...
    async def add(
        self, playbook: DatabasePlaybook, revision: PlaybookRevision
    ) -> DatabasePlaybookDocument: ...
    async def update(
        self,
        playbook: DatabasePlaybook,
        revision: PlaybookRevision,
        *,
        expected_version: int,
    ) -> DatabasePlaybookDocument | None: ...
    async def soft_delete(
        self,
        playbook_id: UUID,
        *,
        expected_version: int,
        deleted_at: datetime,
        updated_by: UUID,
    ) -> DatabasePlaybook | None: ...


class PostgresPlaybookRepository(BaseRepository):
    def __init__(self, connection: RepositoryConnection) -> None:
        self.connection = connection

    async def list_active(self) -> tuple[Playbook, ...]:
        rows = await self.connection.fetch_all(
            sql.SQL(
                "SELECT p.playbook_id, p.name, p.description, p.enabled, p.current_revision, "
                "p.version, p.updated_at AS modified_at, r.sha256, r.size_bytes "
                "FROM playbooks p JOIN playbook_revisions r ON r.playbook_id = p.playbook_id "
                "AND r.revision = p.current_revision WHERE p.deleted_at IS NULL "
                "ORDER BY lower(p.name), p.playbook_id"
            ),
            prepare=True,
        )
        return tuple(
            Playbook(
                source=PlaybookSource.DATABASE,
                playbook_id=row["playbook_id"],
                path=None,
                name=str(row["name"]),
                description=str(row["description"]),
                enabled=bool(row["enabled"]),
                editable=True,
                revision=int(row["current_revision"]),
                version=int(row["version"]),
                size=int(row["size_bytes"]),
                modified_at=row["modified_at"],
                sha256=str(row["sha256"]),
            )
            for row in rows
        )

    async def get_document(
        self,
        playbook_id: UUID,
        *,
        include_deleted: bool = False,
        for_update: bool = False,
    ) -> DatabasePlaybookDocument | None:
        active_predicate = sql.SQL("") if include_deleted else sql.SQL(" AND p.deleted_at IS NULL")
        lock = sql.SQL(" FOR UPDATE OF p") if for_update else sql.SQL("")
        row = await self.connection.fetch_one(
            sql.SQL(
                "SELECT {}, r.revision, r.content, r.sha256, r.size_bytes, "
                "r.validator_version, r.validated_at, r.created_by AS revision_created_by, "
                "r.created_at AS revision_created_at FROM playbooks p "
                "JOIN playbook_revisions r ON r.playbook_id = p.playbook_id "
                "AND r.revision = p.current_revision WHERE p.playbook_id = %(playbook_id)s"
            ).format(QUALIFIED_PLAYBOOK_COLUMNS)
            + active_predicate
            + lock,
            {"playbook_id": playbook_id},
            prepare=False,
        )
        return _document(row) if row is not None else None

    async def get_revision(self, playbook_id: UUID, revision: int) -> PlaybookRevision | None:
        row = await self.connection.fetch_one(
            sql.SQL(
                "SELECT {} FROM playbook_revisions WHERE playbook_id = %(playbook_id)s "
                "AND revision = %(revision)s"
            ).format(REVISION_COLUMNS),
            {"playbook_id": playbook_id, "revision": revision},
            prepare=True,
        )
        return _revision(row) if row is not None else None

    async def add(
        self, playbook: DatabasePlaybook, revision: PlaybookRevision
    ) -> DatabasePlaybookDocument:
        try:
            row = await self.connection.fetch_one(
                sql.SQL(
                    "INSERT INTO playbooks (playbook_id, name, description, enabled, "
                    "current_revision, version, created_by, updated_by, deleted_at, created_at, "
                    "updated_at) VALUES (%(playbook_id)s, %(name)s, %(description)s, "
                    "%(enabled)s, %(current_revision)s, %(version)s, %(created_by)s, "
                    "%(updated_by)s, %(deleted_at)s, %(created_at)s, %(updated_at)s) RETURNING {}"
                ).format(PLAYBOOK_COLUMNS),
                playbook.model_dump(mode="python"),
                prepare=True,
            )
            await self.connection.execute(
                sql.SQL(
                    "INSERT INTO playbook_revisions (playbook_id, revision, content, sha256, "
                    "size_bytes, validator_version, validated_at, created_by, created_at) VALUES "
                    "(%(playbook_id)s, %(revision)s, %(content)s, %(sha256)s, %(size_bytes)s, "
                    "%(validator_version)s, %(validated_at)s, %(created_by)s, %(created_at)s)"
                ),
                revision.model_dump(mode="python"),
                prepare=True,
            )
        except UniqueViolation as error:
            raise ConflictError("playbook name already exists") from error
        if row is None:
            raise RuntimeError("playbook insert returned no row")
        return DatabasePlaybookDocument(playbook=_playbook(row), revision=revision)

    async def update(
        self,
        playbook: DatabasePlaybook,
        revision: PlaybookRevision,
        *,
        expected_version: int,
    ) -> DatabasePlaybookDocument | None:
        try:
            await self.connection.execute(
                sql.SQL(
                    "INSERT INTO playbook_revisions (playbook_id, revision, content, sha256, "
                    "size_bytes, validator_version, validated_at, created_by, created_at) VALUES "
                    "(%(playbook_id)s, %(revision)s, %(content)s, %(sha256)s, %(size_bytes)s, "
                    "%(validator_version)s, %(validated_at)s, %(created_by)s, %(created_at)s)"
                ),
                revision.model_dump(mode="python"),
                prepare=True,
            )
            row = await self.connection.fetch_one(
                sql.SQL(
                    "UPDATE playbooks SET name = %(name)s, description = %(description)s, "
                    "enabled = %(enabled)s, current_revision = %(current_revision)s, "
                    "version = %(version)s, updated_by = %(updated_by)s, "
                    "updated_at = %(updated_at)s "
                    "WHERE playbook_id = %(playbook_id)s AND version = %(expected_version)s "
                    "AND deleted_at IS NULL RETURNING {}"
                ).format(PLAYBOOK_COLUMNS),
                {
                    **playbook.model_dump(mode="python"),
                    "expected_version": expected_version,
                },
                prepare=True,
            )
        except UniqueViolation as error:
            raise ConflictError("playbook name or revision conflicts") from error
        if row is None:
            return None
        return DatabasePlaybookDocument(playbook=_playbook(row), revision=revision)

    async def soft_delete(
        self,
        playbook_id: UUID,
        *,
        expected_version: int,
        deleted_at: datetime,
        updated_by: UUID,
    ) -> DatabasePlaybook | None:
        row = await self.connection.fetch_one(
            sql.SQL(
                "UPDATE playbooks SET deleted_at = %(deleted_at)s, enabled = FALSE, "
                "version = version + 1, updated_by = %(updated_by)s, "
                "updated_at = %(deleted_at)s "
                "WHERE playbook_id = %(playbook_id)s AND version = %(expected_version)s "
                "AND deleted_at IS NULL RETURNING {}"
            ).format(PLAYBOOK_COLUMNS),
            {
                "playbook_id": playbook_id,
                "expected_version": expected_version,
                "deleted_at": deleted_at,
                "updated_by": updated_by,
            },
            prepare=True,
        )
        return _playbook(row) if row is not None else None
