from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Protocol
from uuid import UUID

from psycopg import sql
from psycopg.errors import UniqueViolation
from psycopg.types.json import Jsonb

from ops_composer.domain.errors import ConflictError
from ops_composer.domain.ops import (
    Credential,
    CredentialRevision,
    Host,
    HostGroup,
    HostKey,
    ResolvedHost,
)
from ops_composer.repositories.base import BaseRepository, RepositoryConnection, RepositoryRow


def _credential(row: RepositoryRow) -> Credential:
    return Credential.model_validate(row)


def _revision(row: RepositoryRow) -> CredentialRevision:
    return CredentialRevision.model_validate(row)


def _host(row: RepositoryRow) -> Host:
    return Host.model_validate(row)


def _group(row: RepositoryRow) -> HostGroup:
    return HostGroup.model_validate(row)


def _resolved(row: RepositoryRow) -> ResolvedHost:
    return ResolvedHost.model_validate(row)


CREDENTIAL_COLUMNS = sql.SQL(
    "credential_id, name, credential_type, username, public_config, current_version, "
    "enabled, description, deleted_at, created_at, updated_at"
)
HOST_COLUMNS = sql.SQL(
    "host_id, name, address, ssh_port, credential_id, python_interpreter, enabled, "
    "description, variables, version, created_at, updated_at"
)


class AssetRepository(BaseRepository, Protocol):
    async def list_credentials(self) -> tuple[Credential, ...]: ...
    async def get_credential(
        self, credential_id: UUID, *, for_update: bool = False
    ) -> Credential | None: ...
    async def add_credential(
        self, credential: Credential, revision: CredentialRevision
    ) -> Credential: ...
    async def rotate_credential(
        self, credential_id: UUID, revision: CredentialRevision, now: datetime
    ) -> Credential | None: ...
    async def get_credential_revision(
        self, credential_id: UUID, version: int
    ) -> CredentialRevision | None: ...
    async def delete_credential(self, credential_id: UUID, now: datetime) -> bool: ...
    async def list_hosts(self) -> tuple[Host, ...]: ...
    async def get_host(self, host_id: UUID) -> Host | None: ...
    async def add_host(self, host: Host) -> Host: ...
    async def update_host(self, host: Host, expected_version: int) -> Host | None: ...
    async def delete_host(self, host_id: UUID) -> bool: ...
    async def list_groups(self) -> tuple[HostGroup, ...]: ...
    async def get_group(self, group_id: UUID) -> HostGroup | None: ...
    async def add_group(self, group: HostGroup) -> HostGroup: ...
    async def update_group(self, group: HostGroup) -> HostGroup | None: ...
    async def delete_group(self, group_id: UUID) -> bool: ...
    async def replace_group_members(
        self, group_id: UUID, host_ids: Sequence[UUID], now: datetime
    ) -> None: ...
    async def resolve_all_hosts(self) -> tuple[ResolvedHost, ...]: ...
    async def resolve_host_ids(self, host_ids: Sequence[UUID]) -> tuple[ResolvedHost, ...]: ...
    async def resolve_group_hosts(self, group_id: UUID) -> tuple[ResolvedHost, ...]: ...
    async def list_host_keys(self, host_id: UUID) -> tuple[HostKey, ...]: ...
    async def upsert_host_key(self, host_key: HostKey) -> HostKey: ...
    async def get_setting(self, key: str) -> dict[str, object] | None: ...
    async def put_setting(self, key: str, value: dict[str, object], now: datetime) -> None: ...


class PostgresAssetRepository(BaseRepository):
    def __init__(self, connection: RepositoryConnection) -> None:
        self.connection = connection

    async def list_credentials(self) -> tuple[Credential, ...]:
        rows = await self.connection.fetch_all(
            sql.SQL("SELECT {} FROM credentials WHERE deleted_at IS NULL ORDER BY name").format(
                CREDENTIAL_COLUMNS
            ),
            prepare=True,
        )
        return tuple(_credential(row) for row in rows)

    async def get_credential(
        self, credential_id: UUID, *, for_update: bool = False
    ) -> Credential | None:
        suffix = sql.SQL(" FOR UPDATE") if for_update else sql.SQL("")
        row = await self.connection.fetch_one(
            sql.SQL(
                "SELECT {} FROM credentials WHERE credential_id = %(credential_id)s "
                "AND deleted_at IS NULL"
            ).format(CREDENTIAL_COLUMNS)
            + suffix,
            {"credential_id": credential_id},
            prepare=False,
        )
        return _credential(row) if row is not None else None

    async def add_credential(
        self, credential: Credential, revision: CredentialRevision
    ) -> Credential:
        values = credential.model_dump(mode="python")
        values["public_config"] = Jsonb(values["public_config"])
        try:
            row = await self.connection.fetch_one(
                sql.SQL(
                    "INSERT INTO credentials (credential_id, name, credential_type, username, "
                    "public_config, current_version, enabled, description, deleted_at, "
                    "created_at, updated_at) VALUES (%(credential_id)s, %(name)s, "
                    "%(credential_type)s, %(username)s, %(public_config)s, "
                    "%(current_version)s, %(enabled)s, %(description)s, %(deleted_at)s, "
                    "%(created_at)s, %(updated_at)s) RETURNING {}"
                ).format(CREDENTIAL_COLUMNS),
                values,
                prepare=True,
            )
        except UniqueViolation as error:
            raise ConflictError("credential name already exists") from error
        if row is None:
            raise RuntimeError("credential insert returned no row")
        await self.connection.execute(
            sql.SQL(
                "INSERT INTO credential_revisions (credential_id, version, encrypted_secret, "
                "encryption_key_version, created_at) VALUES (%(credential_id)s, %(version)s, "
                "%(encrypted_secret)s, %(encryption_key_version)s, %(created_at)s)"
            ),
            revision.model_dump(mode="python"),
            prepare=True,
        )
        return _credential(row)

    async def rotate_credential(
        self, credential_id: UUID, revision: CredentialRevision, now: datetime
    ) -> Credential | None:
        await self.connection.execute(
            sql.SQL(
                "INSERT INTO credential_revisions (credential_id, version, encrypted_secret, "
                "encryption_key_version, created_at) VALUES (%(credential_id)s, %(version)s, "
                "%(encrypted_secret)s, %(encryption_key_version)s, %(created_at)s)"
            ),
            revision.model_dump(mode="python"),
            prepare=True,
        )
        row = await self.connection.fetch_one(
            sql.SQL(
                "UPDATE credentials SET current_version = %(version)s, updated_at = %(now)s "
                "WHERE credential_id = %(credential_id)s AND deleted_at IS NULL RETURNING {}"
            ).format(CREDENTIAL_COLUMNS),
            {"credential_id": credential_id, "version": revision.version, "now": now},
            prepare=True,
        )
        return _credential(row) if row is not None else None

    async def get_credential_revision(
        self, credential_id: UUID, version: int
    ) -> CredentialRevision | None:
        row = await self.connection.fetch_one(
            sql.SQL(
                "SELECT credential_id, version, encrypted_secret, encryption_key_version, "
                "created_at FROM credential_revisions WHERE credential_id = %(credential_id)s "
                "AND version = %(version)s"
            ),
            {"credential_id": credential_id, "version": version},
            prepare=True,
        )
        return _revision(row) if row is not None else None

    async def delete_credential(self, credential_id: UUID, now: datetime) -> bool:
        count = await self.connection.execute(
            sql.SQL(
                "UPDATE credentials SET enabled = FALSE, deleted_at = %(now)s, "
                "updated_at = %(now)s WHERE credential_id = %(credential_id)s "
                "AND deleted_at IS NULL AND NOT EXISTS (SELECT 1 FROM hosts "
                "WHERE hosts.credential_id = credentials.credential_id)"
            ),
            {"credential_id": credential_id, "now": now},
            prepare=True,
        )
        return count == 1

    async def list_hosts(self) -> tuple[Host, ...]:
        rows = await self.connection.fetch_all(
            sql.SQL("SELECT {} FROM hosts ORDER BY name").format(HOST_COLUMNS),
            prepare=True,
        )
        return tuple(_host(row) for row in rows)

    async def get_host(self, host_id: UUID) -> Host | None:
        row = await self.connection.fetch_one(
            sql.SQL("SELECT {} FROM hosts WHERE host_id = %(host_id)s").format(HOST_COLUMNS),
            {"host_id": host_id},
            prepare=True,
        )
        return _host(row) if row is not None else None

    async def add_host(self, host: Host) -> Host:
        values = host.model_dump(mode="python")
        values["variables"] = Jsonb(values["variables"])
        try:
            row = await self.connection.fetch_one(
                sql.SQL(
                    "INSERT INTO hosts (host_id, name, address, ssh_port, credential_id, "
                    "python_interpreter, enabled, description, variables, version, created_at, "
                    "updated_at) VALUES (%(host_id)s, %(name)s, %(address)s, %(ssh_port)s, "
                    "%(credential_id)s, %(python_interpreter)s, %(enabled)s, %(description)s, "
                    "%(variables)s, %(version)s, %(created_at)s, %(updated_at)s) RETURNING {}"
                ).format(HOST_COLUMNS),
                values,
                prepare=True,
            )
        except UniqueViolation as error:
            raise ConflictError("host name already exists") from error
        if row is None:
            raise RuntimeError("host insert returned no row")
        return _host(row)

    async def update_host(self, host: Host, expected_version: int) -> Host | None:
        values = host.model_dump(mode="python")
        values["variables"] = Jsonb(values["variables"])
        values["expected_version"] = expected_version
        try:
            row = await self.connection.fetch_one(
                sql.SQL(
                    "UPDATE hosts SET name = %(name)s, address = %(address)s, "
                    "ssh_port = %(ssh_port)s, credential_id = %(credential_id)s, "
                    "python_interpreter = %(python_interpreter)s, enabled = %(enabled)s, "
                    "description = %(description)s, variables = %(variables)s, "
                    "version = version + 1, updated_at = %(updated_at)s "
                    "WHERE host_id = %(host_id)s AND version = %(expected_version)s RETURNING {}"
                ).format(HOST_COLUMNS),
                values,
                prepare=True,
            )
        except UniqueViolation as error:
            raise ConflictError("host name already exists") from error
        return _host(row) if row is not None else None

    async def delete_host(self, host_id: UUID) -> bool:
        count = await self.connection.execute(
            sql.SQL(
                "DELETE FROM hosts WHERE host_id = %(host_id)s AND NOT EXISTS "
                "(SELECT 1 FROM run_targets WHERE run_targets.host_id = hosts.host_id)"
            ),
            {"host_id": host_id},
            prepare=True,
        )
        return count == 1

    async def list_groups(self) -> tuple[HostGroup, ...]:
        rows = await self.connection.fetch_all(
            sql.SQL(
                "SELECT g.group_id, g.name, g.description, g.variables, g.created_at, "
                "g.updated_at, COALESCE(array_agg(m.host_id ORDER BY m.host_id) "
                "FILTER (WHERE m.host_id IS NOT NULL), ARRAY[]::uuid[]) AS host_ids "
                "FROM host_groups g LEFT JOIN host_group_members m ON m.group_id = g.group_id "
                "GROUP BY g.group_id ORDER BY g.name"
            ),
            prepare=True,
        )
        return tuple(_group(row) for row in rows)

    async def get_group(self, group_id: UUID) -> HostGroup | None:
        row = await self.connection.fetch_one(
            sql.SQL(
                "SELECT g.group_id, g.name, g.description, g.variables, g.created_at, "
                "g.updated_at, COALESCE(array_agg(m.host_id ORDER BY m.host_id) "
                "FILTER (WHERE m.host_id IS NOT NULL), ARRAY[]::uuid[]) AS host_ids "
                "FROM host_groups g LEFT JOIN host_group_members m ON m.group_id = g.group_id "
                "WHERE g.group_id = %(group_id)s GROUP BY g.group_id"
            ),
            {"group_id": group_id},
            prepare=True,
        )
        return _group(row) if row is not None else None

    async def add_group(self, group: HostGroup) -> HostGroup:
        values = group.model_dump(mode="python")
        values["variables"] = Jsonb(values["variables"])
        try:
            row = await self.connection.fetch_one(
                sql.SQL(
                    "INSERT INTO host_groups (group_id, name, description, variables, "
                    "created_at, updated_at) VALUES (%(group_id)s, %(name)s, %(description)s, "
                    "%(variables)s, %(created_at)s, %(updated_at)s) RETURNING group_id, name, "
                    "description, variables, created_at, updated_at, ARRAY[]::uuid[] AS host_ids"
                ),
                values,
                prepare=True,
            )
        except UniqueViolation as error:
            raise ConflictError("group name already exists") from error
        if row is None:
            raise RuntimeError("group insert returned no row")
        return _group(row)

    async def update_group(self, group: HostGroup) -> HostGroup | None:
        values = group.model_dump(mode="python")
        values["variables"] = Jsonb(values["variables"])
        try:
            row = await self.connection.fetch_one(
                sql.SQL(
                    "UPDATE host_groups SET name = %(name)s, description = %(description)s, "
                    "variables = %(variables)s, updated_at = %(updated_at)s "
                    "WHERE group_id = %(group_id)s RETURNING group_id, name, description, "
                    "variables, created_at, updated_at, ARRAY[]::uuid[] AS host_ids"
                ),
                values,
                prepare=True,
            )
        except UniqueViolation as error:
            raise ConflictError("group name already exists") from error
        return _group(row) if row is not None else None

    async def delete_group(self, group_id: UUID) -> bool:
        return (
            await self.connection.execute(
                sql.SQL("DELETE FROM host_groups WHERE group_id = %(group_id)s"),
                {"group_id": group_id},
                prepare=True,
            )
            == 1
        )

    async def replace_group_members(
        self, group_id: UUID, host_ids: Sequence[UUID], now: datetime
    ) -> None:
        await self.connection.execute(
            sql.SQL("DELETE FROM host_group_members WHERE group_id = %(group_id)s"),
            {"group_id": group_id},
            prepare=True,
        )
        await self.connection.execute_many(
            sql.SQL(
                "INSERT INTO host_group_members (group_id, host_id, created_at) "
                "VALUES (%(group_id)s, %(host_id)s, %(created_at)s)"
            ),
            ({"group_id": group_id, "host_id": host_id, "created_at": now} for host_id in host_ids),
        )

    async def resolve_all_hosts(self) -> tuple[ResolvedHost, ...]:
        rows = await self.connection.fetch_all(
            sql.SQL(
                "SELECT h.host_id, h.name, h.address, h.ssh_port, h.credential_id, "
                "c.current_version AS credential_version, c.username AS credential_username, "
                "c.public_config AS credential_public_config, h.python_interpreter, "
                "h.variables AS host_variables, '{}'::jsonb AS group_variables "
                "FROM hosts h JOIN credentials c ON c.credential_id = h.credential_id "
                "WHERE h.enabled = TRUE AND c.enabled = TRUE AND c.deleted_at IS NULL "
                "ORDER BY h.name"
            ),
            prepare=True,
        )
        return tuple(_resolved(row) for row in rows)

    async def resolve_host_ids(self, host_ids: Sequence[UUID]) -> tuple[ResolvedHost, ...]:
        rows = await self.connection.fetch_all(
            sql.SQL(
                "SELECT h.host_id, h.name, h.address, h.ssh_port, h.credential_id, "
                "c.current_version AS credential_version, c.username AS credential_username, "
                "c.public_config AS credential_public_config, h.python_interpreter, "
                "h.variables AS host_variables, '{}'::jsonb AS group_variables "
                "FROM hosts h JOIN credentials c ON c.credential_id = h.credential_id "
                "WHERE h.host_id = ANY(%(host_ids)s) AND h.enabled = TRUE "
                "AND c.enabled = TRUE AND c.deleted_at IS NULL ORDER BY h.name"
            ),
            {"host_ids": list(host_ids)},
            prepare=True,
        )
        return tuple(_resolved(row) for row in rows)

    async def resolve_group_hosts(self, group_id: UUID) -> tuple[ResolvedHost, ...]:
        rows = await self.connection.fetch_all(
            sql.SQL(
                "SELECT h.host_id, h.name, h.address, h.ssh_port, h.credential_id, "
                "c.current_version AS credential_version, c.username AS credential_username, "
                "c.public_config AS credential_public_config, h.python_interpreter, "
                "h.variables AS host_variables, "
                "g.variables AS group_variables FROM host_groups g "
                "JOIN host_group_members m ON m.group_id = g.group_id "
                "JOIN hosts h ON h.host_id = m.host_id "
                "JOIN credentials c ON c.credential_id = h.credential_id "
                "WHERE g.group_id = %(group_id)s AND h.enabled = TRUE AND c.enabled = TRUE "
                "AND c.deleted_at IS NULL ORDER BY h.name"
            ),
            {"group_id": group_id},
            prepare=True,
        )
        return tuple(_resolved(row) for row in rows)

    async def list_host_keys(self, host_id: UUID) -> tuple[HostKey, ...]:
        rows = await self.connection.fetch_all(
            sql.SQL(
                "SELECT host_id, algorithm, public_key, fingerprint, trusted_by, trusted_at "
                "FROM host_keys WHERE host_id = %(host_id)s ORDER BY algorithm"
            ),
            {"host_id": host_id},
            prepare=True,
        )
        return tuple(HostKey.model_validate(row) for row in rows)

    async def upsert_host_key(self, host_key: HostKey) -> HostKey:
        row = await self.connection.fetch_one(
            sql.SQL(
                "INSERT INTO host_keys (host_id, algorithm, public_key, fingerprint, "
                "trusted_by, trusted_at) VALUES (%(host_id)s, %(algorithm)s, %(public_key)s, "
                "%(fingerprint)s, %(trusted_by)s, %(trusted_at)s) "
                "ON CONFLICT (host_id, algorithm) DO UPDATE SET public_key = EXCLUDED.public_key, "
                "fingerprint = EXCLUDED.fingerprint, trusted_by = EXCLUDED.trusted_by, "
                "trusted_at = EXCLUDED.trusted_at RETURNING host_id, algorithm, public_key, "
                "fingerprint, trusted_by, trusted_at"
            ),
            host_key.model_dump(mode="python"),
            prepare=True,
        )
        if row is None:
            raise RuntimeError("host-key upsert returned no row")
        return HostKey.model_validate(row)

    async def get_setting(self, key: str) -> dict[str, object] | None:
        row = await self.connection.fetch_one(
            sql.SQL("SELECT value FROM settings WHERE setting_key = %(key)s"),
            {"key": key},
            prepare=True,
        )
        if row is None:
            return None
        value = row["value"]
        if not isinstance(value, dict):
            raise RuntimeError("setting value is not a JSON object")
        return value

    async def put_setting(self, key: str, value: dict[str, object], now: datetime) -> None:
        await self.connection.execute(
            sql.SQL(
                "INSERT INTO settings (setting_key, value, updated_at) "
                "VALUES (%(key)s, %(value)s, %(now)s) "
                "ON CONFLICT (setting_key) DO UPDATE SET value = EXCLUDED.value, "
                "updated_at = EXCLUDED.updated_at"
            ),
            {"key": key, "value": Jsonb(value), "now": now},
            prepare=True,
        )
