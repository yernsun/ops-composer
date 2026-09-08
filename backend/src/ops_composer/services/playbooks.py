from __future__ import annotations

import asyncio
import difflib
import hashlib
import importlib.metadata
import os
import shutil
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from uuid import UUID, uuid4

import yaml

from ops_composer.auth.models import Permission, SessionPrincipal
from ops_composer.auth.service import require_permission
from ops_composer.domain.audit import (
    AuditAction,
    AuditOutcome,
    AuditSeverity,
    AuditSource,
)
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
    PlaybookRevisionFile,
    PlaybookRevisionFormat,
    PlaybookSource,
)
from ops_composer.services.audit import AuditService, emit_audit_event, new_audit_event
from ops_composer.services.playbook_project import (
    NormalizedProject,
    export_project_zip,
    import_project_zip,
    normalize_project,
    validate_parameter_schema,
)
from ops_composer.settings import PlaybookSourceMode, Settings
from ops_composer.uow.factory import UnitOfWorkFactory

MAX_PLAYBOOK_BYTES = 1024 * 1024
MAX_VALIDATION_OUTPUT_BYTES = 16 * 1024
VALIDATION_TIMEOUT_SECONDS = 30


@dataclass(frozen=True, slots=True)
class PlaybookValidationResult:
    valid: bool
    output: str
    normalized_content: str | None = field(default=None, repr=False)
    sha256: str | None = None
    size_bytes: int | None = None
    validator_version: str | None = None
    normalized_files: tuple[PlaybookRevisionFile, ...] = field(default=(), repr=False)
    entrypoint: str | None = None
    parameter_schema: dict[str, object] | None = None
    supports_check_mode: bool = False


class PlaybookValidator:
    def __init__(self) -> None:
        try:
            version = importlib.metadata.version("ansible-core")
        except importlib.metadata.PackageNotFoundError:
            version = "unavailable"
        self.version = f"ansible-core {version}"

    @staticmethod
    def normalize(content: str) -> tuple[str, bytes]:
        normalized = content.replace("\r\n", "\n").replace("\r", "\n")
        encoded = normalized.encode("utf-8")
        if not encoded:
            raise PlaybookInvalidError("playbook content must not be empty")
        if b"\x00" in encoded:
            raise PlaybookInvalidError("playbook content must not contain NUL bytes")
        if len(encoded) > MAX_PLAYBOOK_BYTES:
            raise PlaybookInvalidError(
                "playbook content exceeds the 1 MiB limit",
                details={"maxBytes": MAX_PLAYBOOK_BYTES},
            )
        return normalized, encoded

    @staticmethod
    def _validate_document(content: str) -> str | None:
        try:
            document = yaml.safe_load(content)
        except yaml.YAMLError:
            return "playbook YAML is invalid"
        if not isinstance(document, list):
            return "playbook root must be a list of plays"
        return None

    async def _syntax_check(self, path: Path, *, cwd: Path) -> tuple[bool, str]:
        executable = shutil.which("ansible-playbook")
        if executable is None:
            raise ValidationError("ansible-playbook is not installed")
        config_fd, config_name = tempfile.mkstemp(
            prefix="ops-composer-ansible-",
            suffix=".cfg",
        )
        config_path = Path(config_name)
        try:
            os.write(
                config_fd,
                b"[defaults]\nretry_files_enabled = False\nhost_key_checking = True\n",
            )
        finally:
            os.close(config_fd)
        environment = {
            "PATH": f"{Path(executable).parent}:/usr/local/bin:/usr/bin:/bin",
            "HOME": str(cwd),
            "LANG": "C.UTF-8",
            "ANSIBLE_CONFIG": str(config_path),
            "ANSIBLE_RETRY_FILES_ENABLED": "False",
            "ANSIBLE_ROLES_PATH": str(cwd / "roles"),
        }
        try:
            try:
                process = await asyncio.create_subprocess_exec(
                    executable,
                    "--syntax-check",
                    str(path),
                    cwd=cwd,
                    env=environment,
                    stdin=asyncio.subprocess.DEVNULL,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT,
                )
            except FileNotFoundError as error:
                raise ValidationError("ansible-playbook is not installed") from error
            try:
                output, _ = await asyncio.wait_for(
                    process.communicate(), timeout=VALIDATION_TIMEOUT_SECONDS
                )
            except TimeoutError:
                process.kill()
                await process.communicate()
                return False, "syntax check timed out"
            text = output.decode("utf-8", errors="replace")[-MAX_VALIDATION_OUTPUT_BYTES:]
            return process.returncode == 0, text
        finally:
            config_path.unlink(missing_ok=True)

    async def validate_path(self, path: Path, *, workspace: Path) -> PlaybookValidationResult:
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            return PlaybookValidationResult(valid=False, output="playbook could not be read")
        structural_error = self._validate_document(content)
        if structural_error is not None:
            return PlaybookValidationResult(valid=False, output=structural_error)
        valid, output = await self._syntax_check(path, cwd=workspace)
        return PlaybookValidationResult(valid=valid, output=output, validator_version=self.version)

    async def validate_content(self, content: str) -> PlaybookValidationResult:
        normalized, encoded = self.normalize(content)
        structural_error = self._validate_document(normalized)
        if structural_error is not None:
            return PlaybookValidationResult(valid=False, output=structural_error)
        with tempfile.TemporaryDirectory(prefix="ops-composer-playbook-validation-") as directory:
            workspace = Path(directory)
            os.chmod(workspace, 0o700)
            path = workspace / "playbook.yml"
            path.write_text(normalized, encoding="utf-8")
            path.chmod(0o600)
            valid, output = await self._syntax_check(path, cwd=workspace)
        return PlaybookValidationResult(
            valid=valid,
            output=output,
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
        schema = validate_parameter_schema(parameter_schema)
        entry = next(item for item in project.files if item.path == project.entrypoint)
        structural_error = self._validate_document(entry.content)
        if structural_error is not None:
            return PlaybookValidationResult(valid=False, output=structural_error)
        with tempfile.TemporaryDirectory(prefix="ops-composer-project-validation-") as directory:
            workspace = Path(directory)
            os.chmod(workspace, 0o700)
            for item in project.files:
                path = workspace / item.path
                path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                path.write_text(item.content, encoding="utf-8")
                path.chmod(0o600)
            valid, output = await self._syntax_check(
                workspace / project.entrypoint,
                cwd=workspace,
            )
        return PlaybookValidationResult(
            valid=valid,
            output=output,
            sha256=project.sha256,
            size_bytes=project.size_bytes,
            validator_version=self.version,
            normalized_files=project.files,
            entrypoint=project.entrypoint,
            parameter_schema=schema,
            supports_check_mode=supports_check_mode,
        )


class PlaybookCatalog:
    """Read-only, traversal-safe adapter for mounted Playbook files."""

    def __init__(self, workspace: Path, validator: PlaybookValidator | None = None) -> None:
        self._workspace = workspace.resolve()
        self._playbooks = self._workspace / "playbooks"
        self._validator = validator or PlaybookValidator()

    @property
    def workspace(self) -> Path:
        return self._workspace

    def resolve(self, requested_path: str) -> Path:
        candidate = Path(requested_path)
        if candidate.is_absolute() or candidate.suffix.casefold() not in {".yml", ".yaml"}:
            raise ValidationError("playbook path must be a relative .yml or .yaml file")
        resolved = (self._workspace / candidate).resolve()
        try:
            resolved.relative_to(self._playbooks.resolve())
        except ValueError as error:
            raise ValidationError(
                "playbook path escapes the read-only playbook directory"
            ) from error
        if not resolved.is_file():
            raise PlaybookNotFoundError()
        return resolved

    @staticmethod
    def _describe(path: Path, workspace: Path) -> Playbook:
        data = path.read_bytes()
        stat = path.stat()
        return Playbook(
            source=PlaybookSource.MOUNT,
            playbook_id=None,
            path=path.relative_to(workspace).as_posix(),
            name=path.stem.replace("-", " ").replace("_", " ").title(),
            description="",
            enabled=True,
            editable=False,
            revision=None,
            version=None,
            size=len(data),
            modified_at=__import__("datetime").datetime.fromtimestamp(
                stat.st_mtime, __import__("datetime").UTC
            ),
            sha256=hashlib.sha256(data).hexdigest(),
        )

    async def list(self) -> tuple[Playbook, ...]:
        if not self._playbooks.is_dir():
            return ()
        paths = sorted({*self._playbooks.rglob("*.yml"), *self._playbooks.rglob("*.yaml")})
        valid: list[Playbook] = []
        for path in paths:
            try:
                resolved = self.resolve(path.relative_to(self._workspace).as_posix())
                document = yaml.safe_load(resolved.read_text(encoding="utf-8"))
                if isinstance(document, list):
                    valid.append(self._describe(resolved, self._workspace))
            except (OSError, UnicodeError, yaml.YAMLError, ValidationError):
                continue
        return tuple(valid)

    async def get(self, requested_path: str) -> Playbook:
        path = self.resolve(requested_path)
        try:
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, yaml.YAMLError) as error:
            raise PlaybookInvalidError("playbook YAML is invalid") from error
        if not isinstance(document, list):
            raise PlaybookInvalidError("playbook root must be a list of plays")
        return self._describe(path, self._workspace)

    async def syntax_check(self, requested_path: str) -> tuple[bool, str]:
        path = self.resolve(requested_path)
        result = await self._validator.validate_path(path, workspace=self._workspace)
        return result.valid, result.output


class PlaybookService:
    def __init__(
        self,
        unit_of_work_factory: UnitOfWorkFactory,
        settings: Settings,
        mounted_catalog: PlaybookCatalog | None = None,
        validator: PlaybookValidator | None = None,
    ) -> None:
        self._unit_of_work_factory = unit_of_work_factory
        self._settings = settings
        self._validator = validator or PlaybookValidator()
        self._mounted = mounted_catalog

    @property
    def mode(self) -> PlaybookSourceMode:
        return self._settings.playbook_source_mode

    def _require_source(self, source: PlaybookSource) -> None:
        enabled = (
            self.mode.database_enabled
            if source is PlaybookSource.DATABASE
            else self.mode.mount_enabled
        )
        if not enabled:
            raise PlaybookSourceDisabledError(
                details={"source": source.value, "sourceMode": self.mode.value}
            )

    def _mounted_catalog(self) -> PlaybookCatalog:
        if self._mounted is None:
            self._mounted = PlaybookCatalog(self._settings.playbook_workspace, self._validator)
        return self._mounted

    async def list(self) -> tuple[Playbook, ...]:
        items: list[Playbook] = []
        if self.mode.database_enabled:
            async with self._unit_of_work_factory() as unit_of_work:
                items.extend(await unit_of_work.playbooks.list_active())
        if self.mode.mount_enabled:
            items.extend(await self._mounted_catalog().list())
        return tuple(
            sorted(
                items,
                key=lambda item: (
                    item.name.casefold(),
                    item.source.value,
                    str(item.playbook_id or item.path),
                ),
            )
        )

    async def get_database(self, playbook_id: UUID) -> DatabasePlaybookDocument:
        self._require_source(PlaybookSource.DATABASE)
        async with self._unit_of_work_factory() as unit_of_work:
            document = await unit_of_work.playbooks.get_document(playbook_id)
        if document is None:
            raise PlaybookNotFoundError()
        return document

    async def get_mounted(self, path: str) -> Playbook:
        self._require_source(PlaybookSource.MOUNT)
        return await self._mounted_catalog().get(path)

    async def create_database(
        self,
        *,
        actor_user_id: UUID,
        name: str,
        description: str,
        enabled: bool,
        content: str | None = None,
        files: dict[str, str] | None = None,
        entrypoint: str | None = None,
        parameter_schema: dict[str, object] | None = None,
        supports_check_mode: bool = False,
        actor: SessionPrincipal | None = None,
    ) -> DatabasePlaybookDocument:
        if actor is not None:
            require_permission(actor, Permission.PLAYBOOK_WRITE)
        self._require_source(PlaybookSource.DATABASE)
        normalized_name = name.strip()
        if not normalized_name:
            raise PlaybookInvalidError("playbook name must not be empty")
        if (content is None) == (files is None):
            raise PlaybookInvalidError("provide exactly one legacy content or project files")
        if content is not None:
            validation = await self._validate_for_save(
                content,
                actor_user_id=actor_user_id,
                playbook_id=None,
            )
            revision_format = PlaybookRevisionFormat.LEGACY_SINGLE_YAML
        else:
            if entrypoint is None:
                raise PlaybookInvalidError("project entrypoint is required")
            validation = await self._validate_project_for_save(
                files or {},
                entrypoint,
                parameter_schema,
                supports_check_mode,
                actor_user_id=actor_user_id,
                playbook_id=None,
            )
            revision_format = PlaybookRevisionFormat.PROJECT
        now = utc_now()
        playbook_id = uuid4()
        playbook = DatabasePlaybook(
            playbook_id=playbook_id,
            name=normalized_name,
            description=description.strip(),
            enabled=enabled,
            current_revision=1,
            version=1,
            created_by=actor_user_id,
            updated_by=actor_user_id,
            created_at=now,
            updated_at=now,
        )
        revision = self._revision(
            playbook_id=playbook_id,
            revision=1,
            actor_user_id=actor_user_id,
            validation=validation,
            now=now,
            revision_format=revision_format,
        )
        event = new_audit_event(
            AuditAction.PLAYBOOK_CREATED,
            AuditOutcome.SUCCEEDED,
            source=AuditSource.API,
            actor_user_id=actor_user_id,
            resource_type="playbook",
            resource_id=playbook_id,
            metadata={
                "playbook_source": PlaybookSource.DATABASE.value,
                "revision": 1,
                "size_bytes": revision.size_bytes,
                "enabled": enabled,
                "revision_format": revision.revision_format.value,
                "file_count": len(revision.files),
            },
        )
        async with self._unit_of_work_factory() as unit_of_work:
            document = await unit_of_work.playbooks.add(playbook, revision)
            await unit_of_work.audit.append(event)
        emit_audit_event(event)
        return document

    async def update_database(
        self,
        playbook_id: UUID,
        *,
        actor_user_id: UUID,
        expected_version: int,
        name: str,
        description: str,
        enabled: bool,
        content: str | None = None,
        files: dict[str, str] | None = None,
        entrypoint: str | None = None,
        parameter_schema: dict[str, object] | None = None,
        supports_check_mode: bool = False,
        actor: SessionPrincipal | None = None,
        _audit_action: AuditAction = AuditAction.PLAYBOOK_UPDATED,
        _audit_metadata: dict[str, object] | None = None,
    ) -> DatabasePlaybookDocument:
        if actor is not None:
            require_permission(actor, Permission.PLAYBOOK_WRITE)
        self._require_source(PlaybookSource.DATABASE)
        normalized_name = name.strip()
        if not normalized_name:
            raise PlaybookInvalidError("playbook name must not be empty")
        if (content is None) == (files is None):
            raise PlaybookInvalidError("provide exactly one legacy content or project files")
        if content is not None:
            validation = await self._validate_for_save(
                content,
                actor_user_id=actor_user_id,
                playbook_id=playbook_id,
            )
            revision_format = PlaybookRevisionFormat.LEGACY_SINGLE_YAML
        else:
            if entrypoint is None:
                raise PlaybookInvalidError("project entrypoint is required")
            validation = await self._validate_project_for_save(
                files or {},
                entrypoint,
                parameter_schema,
                supports_check_mode,
                actor_user_id=actor_user_id,
                playbook_id=playbook_id,
            )
            revision_format = PlaybookRevisionFormat.PROJECT
        now = utc_now()
        updated: DatabasePlaybookDocument | None = None
        event = None
        async with self._unit_of_work_factory() as unit_of_work:
            current = await unit_of_work.playbooks.get_document(playbook_id, for_update=True)
            if current is None:
                raise PlaybookNotFoundError()
            if current.playbook.version != expected_version:
                raise PlaybookVersionConflictError()
            revision_number = current.playbook.current_revision + 1
            playbook = current.playbook.model_copy(
                update={
                    "name": normalized_name,
                    "description": description.strip(),
                    "enabled": enabled,
                    "current_revision": revision_number,
                    "version": expected_version + 1,
                    "updated_by": actor_user_id,
                    "updated_at": now,
                }
            )
            revision = self._revision(
                playbook_id=playbook_id,
                revision=revision_number,
                actor_user_id=actor_user_id,
                validation=validation,
                now=now,
                revision_format=revision_format,
            )
            updated = await unit_of_work.playbooks.update(
                playbook,
                revision,
                expected_version=expected_version,
            )
            if updated is None:
                raise PlaybookVersionConflictError()
            metadata: dict[str, object] = {
                "playbook_source": PlaybookSource.DATABASE.value,
                "revision_before": current.playbook.current_revision,
                "revision_after": revision_number,
                "version_before": expected_version,
                "version_after": expected_version + 1,
                "size_bytes": revision.size_bytes,
                "enabled_before": current.playbook.enabled,
                "enabled_after": enabled,
                "revision_format": revision.revision_format.value,
                "file_count": len(revision.files),
            }
            if _audit_metadata:
                metadata.update(_audit_metadata)
            event = new_audit_event(
                _audit_action,
                AuditOutcome.SUCCEEDED,
                source=AuditSource.API,
                actor_user_id=actor_user_id,
                resource_type="playbook",
                resource_id=playbook_id,
                metadata=metadata,
            )
            await unit_of_work.audit.append(event)
        if updated is None or event is None:
            raise RuntimeError("playbook update completed without a result")
        emit_audit_event(event)
        return updated

    async def delete_database(
        self,
        playbook_id: UUID,
        *,
        actor_user_id: UUID,
        expected_version: int,
        actor: SessionPrincipal | None = None,
    ) -> None:
        if actor is not None:
            require_permission(actor, Permission.PLAYBOOK_WRITE)
        self._require_source(PlaybookSource.DATABASE)
        now = utc_now()
        event = None
        async with self._unit_of_work_factory() as unit_of_work:
            current = await unit_of_work.playbooks.get_document(playbook_id, for_update=True)
            if current is None:
                raise PlaybookNotFoundError()
            if current.playbook.version != expected_version:
                raise PlaybookVersionConflictError()
            deleted = await unit_of_work.playbooks.soft_delete(
                playbook_id,
                expected_version=expected_version,
                deleted_at=now,
                updated_by=actor_user_id,
            )
            if deleted is None:
                raise PlaybookVersionConflictError()
            event = new_audit_event(
                AuditAction.PLAYBOOK_DELETED,
                AuditOutcome.SUCCEEDED,
                source=AuditSource.API,
                actor_user_id=actor_user_id,
                resource_type="playbook",
                resource_id=playbook_id,
                metadata={
                    "playbook_source": PlaybookSource.DATABASE.value,
                    "revision": current.playbook.current_revision,
                    "version_before": expected_version,
                    "version_after": expected_version + 1,
                },
            )
            await unit_of_work.audit.append(event)
        if event is None:
            raise RuntimeError("playbook deletion completed without an audit event")
        emit_audit_event(event)

    async def validate_content(
        self,
        content: str,
        *,
        actor_user_id: UUID,
        actor: SessionPrincipal | None = None,
    ) -> PlaybookValidationResult:
        if actor is not None:
            require_permission(actor, Permission.PLAYBOOK_WRITE)
        self._require_source(PlaybookSource.DATABASE)
        try:
            validation = await self._validator.validate_content(content)
        except PlaybookInvalidError:
            await self._record_validation(
                valid=False,
                actor_user_id=actor_user_id,
                source=PlaybookSource.DATABASE,
            )
            raise
        await self._record_validation(
            valid=validation.valid,
            actor_user_id=actor_user_id,
            source=PlaybookSource.DATABASE,
            size_bytes=validation.size_bytes,
        )
        return validation

    async def validate_project(
        self,
        *,
        files: dict[str, str],
        entrypoint: str,
        parameter_schema: dict[str, object] | None,
        supports_check_mode: bool,
        actor_user_id: UUID,
        actor: SessionPrincipal | None = None,
    ) -> PlaybookValidationResult:
        if actor is not None:
            require_permission(actor, Permission.PLAYBOOK_WRITE)
        self._require_source(PlaybookSource.DATABASE)
        validation = await self._validator.validate_project(
            files,
            entrypoint,
            parameter_schema,
            supports_check_mode,
        )
        await self._record_validation(
            valid=validation.valid,
            actor_user_id=actor_user_id,
            source=PlaybookSource.DATABASE,
            size_bytes=validation.size_bytes,
        )
        return validation

    async def list_revisions(self, playbook_id: UUID) -> tuple[PlaybookRevision, ...]:
        self._require_source(PlaybookSource.DATABASE)
        async with self._unit_of_work_factory() as unit_of_work:
            if await unit_of_work.playbooks.get_document(playbook_id, include_deleted=True) is None:
                raise PlaybookNotFoundError()
            return await unit_of_work.playbooks.list_revisions(playbook_id)

    async def get_revision(self, playbook_id: UUID, revision: int) -> PlaybookRevision:
        self._require_source(PlaybookSource.DATABASE)
        async with self._unit_of_work_factory() as unit_of_work:
            result = await unit_of_work.playbooks.get_revision(playbook_id, revision)
        if result is None:
            raise PlaybookNotFoundError("Playbook revision was not found")
        return result

    @staticmethod
    def _as_project(revision: PlaybookRevision) -> NormalizedProject:
        if revision.revision_format is PlaybookRevisionFormat.PROJECT:
            assert revision.entrypoint is not None
            return NormalizedProject(
                revision.files,
                revision.entrypoint,
                revision.sha256,
                revision.size_bytes,
            )
        assert revision.content is not None
        return normalize_project({"playbook.yml": revision.content}, "playbook.yml")

    async def diff_revisions(
        self,
        playbook_id: UUID,
        revision: int,
        against_revision: int,
    ) -> dict[str, object]:
        before = self._as_project(await self.get_revision(playbook_id, against_revision))
        after = self._as_project(await self.get_revision(playbook_id, revision))
        before_files = {item.path: item for item in before.files}
        after_files = {item.path: item for item in after.files}
        added = sorted(set(after_files) - set(before_files))
        deleted = sorted(set(before_files) - set(after_files))
        modified = sorted(
            path
            for path in set(before_files) & set(after_files)
            if before_files[path].sha256 != after_files[path].sha256
        )
        lines: list[str] = []
        for path in sorted(set(added + deleted + modified)):
            old = (
                before_files[path].content.splitlines(keepends=True) if path in before_files else []
            )
            new = after_files[path].content.splitlines(keepends=True) if path in after_files else []
            lines.extend(
                difflib.unified_diff(
                    old,
                    new,
                    fromfile=f"a/{path}",
                    tofile=f"b/{path}",
                    n=3,
                )
            )
            if len(lines) > 2000:
                lines = [*lines[:2000], "\n... diff truncated ...\n"]
                break
        text = "".join(lines)
        if len(text.encode("utf-8")) > 256 * 1024:
            text = text.encode("utf-8")[: 256 * 1024].decode("utf-8", errors="ignore")
            text += "\n... diff truncated ...\n"
        return {
            "revision": revision,
            "againstRevision": against_revision,
            "added": added,
            "deleted": deleted,
            "modified": modified,
            "diff": text,
        }

    async def restore_revision(
        self,
        playbook_id: UUID,
        revision: int,
        *,
        actor_user_id: UUID,
        expected_version: int,
        actor: SessionPrincipal | None = None,
    ) -> DatabasePlaybookDocument:
        if actor is not None:
            require_permission(actor, Permission.PLAYBOOK_WRITE)
        source = await self.get_revision(playbook_id, revision)
        current = await self.get_database(playbook_id)
        project = self._as_project(source)
        restored = await self.update_database(
            playbook_id,
            actor_user_id=actor_user_id,
            expected_version=expected_version,
            name=current.playbook.name,
            description=current.playbook.description,
            enabled=current.playbook.enabled,
            files={item.path: item.content for item in project.files},
            entrypoint=project.entrypoint,
            parameter_schema=source.parameter_schema,
            supports_check_mode=source.supports_check_mode,
            _audit_action=AuditAction.PLAYBOOK_REVISION_RESTORED,
            _audit_metadata={"source_revision": revision},
        )
        return restored

    async def import_zip(
        self,
        payload: bytes,
        *,
        entrypoint: str | None,
        actor_user_id: UUID,
        actor: SessionPrincipal | None = None,
    ) -> NormalizedProject:
        if actor is not None:
            require_permission(actor, Permission.PLAYBOOK_WRITE)
        self._require_source(PlaybookSource.DATABASE)
        try:
            project = import_project_zip(payload, entrypoint)
        except PlaybookInvalidError:
            await self._record_validation(
                valid=False,
                actor_user_id=actor_user_id,
                source=PlaybookSource.DATABASE,
            )
            raise
        await AuditService(self._unit_of_work_factory).record_best_effort(
            new_audit_event(
                AuditAction.PLAYBOOK_IMPORTED,
                AuditOutcome.SUCCEEDED,
                source=AuditSource.API,
                actor_user_id=actor_user_id,
                resource_type="playbook_draft",
                metadata={
                    "file_count": len(project.files),
                    "size_bytes": project.size_bytes,
                },
            )
        )
        return project

    async def export_zip(self, playbook_id: UUID, revision: int, *, actor_user_id: UUID) -> bytes:
        project = self._as_project(await self.get_revision(playbook_id, revision))
        payload = export_project_zip(project)
        await AuditService(self._unit_of_work_factory).record_best_effort(
            new_audit_event(
                AuditAction.PLAYBOOK_EXPORTED,
                AuditOutcome.SUCCEEDED,
                source=AuditSource.API,
                actor_user_id=actor_user_id,
                resource_type="playbook",
                resource_id=playbook_id,
                metadata={
                    "revision": revision,
                    "file_count": len(project.files),
                    "size_bytes": project.size_bytes,
                },
            )
        )
        return payload

    async def validate_reference(
        self, reference: PlaybookReference, *, actor_user_id: UUID
    ) -> PlaybookValidationResult:
        self._require_source(reference.source)
        if reference.source is PlaybookSource.MOUNT:
            if reference.path is None:
                raise PlaybookNotFoundError()
            catalog = self._mounted_catalog()
            playbook = await catalog.get(reference.path)
            valid, output = await catalog.syntax_check(reference.path)
            result = PlaybookValidationResult(valid=valid, output=output)
            await self._record_validation(
                valid=valid,
                actor_user_id=actor_user_id,
                source=reference.source,
                path=reference.path,
                size_bytes=playbook.size,
            )
            return result
        if reference.playbook_id is None:
            raise PlaybookNotFoundError()
        document = await self.get_database(reference.playbook_id)
        if document.revision.revision_format is PlaybookRevisionFormat.PROJECT:
            assert document.revision.entrypoint is not None
            result = await self._validator.validate_project(
                {item.path: item.content for item in document.revision.files},
                document.revision.entrypoint,
                document.revision.parameter_schema,
                document.revision.supports_check_mode,
            )
        else:
            assert document.revision.content is not None
            result = await self._validator.validate_content(document.revision.content)
        await self._record_validation(
            valid=result.valid,
            actor_user_id=actor_user_id,
            source=reference.source,
            playbook_id=reference.playbook_id,
            size_bytes=document.revision.size_bytes,
        )
        return result

    async def _validate_for_save(
        self,
        content: str,
        *,
        actor_user_id: UUID,
        playbook_id: UUID | None,
    ) -> PlaybookValidationResult:
        try:
            validation = await self._validator.validate_content(content)
        except PlaybookInvalidError:
            await self._record_validation(
                valid=False,
                actor_user_id=actor_user_id,
                source=PlaybookSource.DATABASE,
                playbook_id=playbook_id,
            )
            raise
        if not validation.valid or validation.normalized_content is None:
            await self._record_validation(
                valid=False,
                actor_user_id=actor_user_id,
                source=PlaybookSource.DATABASE,
                playbook_id=playbook_id,
                size_bytes=validation.size_bytes,
            )
            raise PlaybookInvalidError()
        return validation

    async def _validate_project_for_save(
        self,
        files: dict[str, str],
        entrypoint: str,
        parameter_schema: dict[str, object] | None,
        supports_check_mode: bool,
        *,
        actor_user_id: UUID,
        playbook_id: UUID | None,
    ) -> PlaybookValidationResult:
        try:
            validation = await self._validator.validate_project(
                files,
                entrypoint,
                parameter_schema,
                supports_check_mode,
            )
        except PlaybookInvalidError:
            await self._record_validation(
                valid=False,
                actor_user_id=actor_user_id,
                source=PlaybookSource.DATABASE,
                playbook_id=playbook_id,
            )
            raise
        if not validation.valid:
            await self._record_validation(
                valid=False,
                actor_user_id=actor_user_id,
                source=PlaybookSource.DATABASE,
                playbook_id=playbook_id,
                size_bytes=validation.size_bytes,
            )
            raise PlaybookProjectInvalidError()
        return validation

    @staticmethod
    def _revision(
        *,
        playbook_id: UUID,
        revision: int,
        actor_user_id: UUID,
        validation: PlaybookValidationResult,
        now: datetime,
        revision_format: PlaybookRevisionFormat = PlaybookRevisionFormat.LEGACY_SINGLE_YAML,
    ) -> PlaybookRevision:
        if (
            validation.sha256 is None
            or validation.size_bytes is None
            or validation.validator_version is None
        ):
            raise RuntimeError("valid Playbook content is missing validation metadata")
        if (
            revision_format is PlaybookRevisionFormat.LEGACY_SINGLE_YAML
            and validation.normalized_content is None
        ):
            raise RuntimeError("valid legacy Playbook content is missing")
        if revision_format is PlaybookRevisionFormat.PROJECT and (
            not validation.normalized_files or validation.entrypoint is None
        ):
            raise RuntimeError("valid Playbook project content is missing")
        return PlaybookRevision(
            playbook_id=playbook_id,
            revision=revision,
            content=validation.normalized_content,
            sha256=validation.sha256,
            size_bytes=validation.size_bytes,
            validator_version=validation.validator_version,
            validated_at=now,
            created_by=actor_user_id,
            created_at=now,
            revision_format=revision_format,
            entrypoint=validation.entrypoint,
            parameter_schema=validation.parameter_schema or validate_parameter_schema(None),
            supports_check_mode=validation.supports_check_mode,
            files=validation.normalized_files,
        )

    async def _record_validation(
        self,
        *,
        valid: bool,
        actor_user_id: UUID,
        source: PlaybookSource,
        playbook_id: UUID | None = None,
        path: str | None = None,
        size_bytes: int | None = None,
    ) -> None:
        await AuditService(self._unit_of_work_factory).record_best_effort(
            new_audit_event(
                (
                    AuditAction.PLAYBOOK_VALIDATION_SUCCEEDED
                    if valid
                    else AuditAction.PLAYBOOK_VALIDATION_FAILED
                ),
                AuditOutcome.SUCCEEDED if valid else AuditOutcome.FAILED,
                source=AuditSource.API,
                severity=AuditSeverity.INFO if valid else AuditSeverity.WARNING,
                actor_user_id=actor_user_id,
                resource_type="playbook",
                resource_id=playbook_id or path,
                error_code=None if valid else "playbook_invalid",
                failure_stage=None if valid else "playbook_validation",
                retryable=False if not valid else None,
                metadata={
                    "playbook_source": source.value,
                    "size_bytes": size_bytes,
                },
            )
        )
