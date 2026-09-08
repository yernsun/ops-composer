from __future__ import annotations

import copy
import hashlib
import hmac
import json
from datetime import timedelta
from uuid import UUID, uuid4

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
    ClaimCollisionError,
    HostKeyConfirmationRequiredError,
    IdempotencyConflictError,
    NotFoundError,
    OpsError,
    PlaybookDisabledError,
    PlaybookNotFoundError,
    PlaybookSourceDisabledError,
    RunNotCancelableError,
    SecretParametersRequiredError,
    ValidationError,
)
from ops_composer.domain.ops import (
    TERMINAL_RUN_STATUSES,
    CommandMode,
    PlaybookReference,
    PlaybookRevisionFormat,
    PlaybookSource,
    RequestFingerprintScheme,
    ResolvedHost,
    Run,
    RunEvent,
    RunKind,
    RunStatus,
    RunTarget,
    RunTargetStatus,
    TargetKind,
)
from ops_composer.services.audit import AuditService, emit_audit_event, new_audit_event
from ops_composer.services.crypto import MasterKeyring, build_master_keyring
from ops_composer.services.encryption import EncryptionService
from ops_composer.services.inventory import build_inventory
from ops_composer.services.playbook_project import validate_parameters
from ops_composer.services.playbooks import PlaybookCatalog
from ops_composer.settings import Settings
from ops_composer.uow.factory import UnitOfWorkFactory
from ops_composer.uow.unit import UnitOfWork


def _fingerprint(payload: dict[str, object]) -> str:
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _hmac_fingerprint(payload: dict[str, object], pepper: bytes) -> str:
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    return hmac.new(pepper, encoded, hashlib.sha256).hexdigest()


def _validate_extra_vars(value: object, path: str = "extraVars") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = str(key).casefold().replace("-", "_")
            if normalized.startswith("ansible_") or any(
                token in normalized
                for token in ("password", "passwd", "secret", "token", "private_key", "passphrase")
            ):
                raise ValidationError(
                    "secret and Ansible connection Extra Vars are not supported; "
                    "use declared sensitive parameters",
                    details={"field": f"{path}.{key}"},
                )
            _validate_extra_vars(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _validate_extra_vars(item, f"{path}[{index}]")


def _safe_operation_metadata(kind: RunKind, operation_spec: dict[str, object]) -> dict[str, object]:
    if kind is RunKind.COMMAND:
        command = str(operation_spec.get("command", ""))
        return {
            "command_mode": str(operation_spec.get("mode", "COMMAND")),
            "command_length": len(command),
            "become": str(operation_spec.get("become", "CREDENTIAL_DEFAULT")),
        }
    if kind is RunKind.PLAYBOOK:
        variables = operation_spec.get("extraVars", {})
        tags = operation_spec.get("tags", [])
        skip_tags = operation_spec.get("skipTags", [])
        reference = operation_spec.get("playbook", {})
        reference = reference if isinstance(reference, dict) else {}
        return {
            "playbook_source": str(reference.get("source", PlaybookSource.MOUNT.value)),
            "playbook_id": reference.get("playbookId"),
            "playbook_path": reference.get("path") or operation_spec.get("playbookPath"),
            "variable_names": sorted(variables) if isinstance(variables, dict) else [],
            "tag_count": len(tags) if isinstance(tags, list) else 0,
            "skip_tag_count": len(skip_tags) if isinstance(skip_tags, list) else 0,
        }
    return {"module": "ansible.builtin.ping"}


def _playbook_source(operation_spec: dict[str, object]) -> PlaybookSource:
    reference = operation_spec.get("playbook")
    if isinstance(reference, dict):
        raw_source = reference.get("source")
        try:
            return PlaybookSource(str(raw_source))
        except ValueError as error:
            raise PlaybookNotFoundError("playbook source is invalid") from error
    if operation_spec.get("playbookPath") is not None:
        return PlaybookSource.MOUNT
    raise PlaybookNotFoundError("playbook reference is missing")


class RunService:
    def __init__(
        self,
        unit_of_work_factory: UnitOfWorkFactory,
        settings: Settings,
        playbooks: PlaybookCatalog | None = None,
        *,
        audit_source: AuditSource = AuditSource.API,
        keyring: MasterKeyring | None = None,
    ) -> None:
        self._unit_of_work_factory = unit_of_work_factory
        self._settings = settings
        self._playbooks = playbooks
        self._audit_source = audit_source
        self._keyring = keyring or build_master_keyring(
            keyring_file=settings.master_keyring_file,
            fallback_key=settings.master_key.get_secret_value(),
            fallback_version=settings.master_key_version,
        )

    def _mounted_playbooks(self) -> PlaybookCatalog:
        if self._playbooks is None:
            self._playbooks = PlaybookCatalog(self._settings.playbook_workspace)
        return self._playbooks

    def _require_playbook_source(self, source: PlaybookSource) -> None:
        enabled = (
            self._settings.playbook_source_mode.database_enabled
            if source is PlaybookSource.DATABASE
            else self._settings.playbook_source_mode.mount_enabled
        )
        if not enabled:
            raise PlaybookSourceDisabledError(
                details={
                    "source": source.value,
                    "sourceMode": self._settings.playbook_source_mode.value,
                }
            )

    @staticmethod
    async def _resolve(
        unit_of_work: UnitOfWork,
        *,
        target_kind: TargetKind,
        host_ids: tuple[UUID, ...],
        group_id: UUID | None,
    ) -> tuple[ResolvedHost, ...]:
        if target_kind is TargetKind.ALL:
            hosts = await unit_of_work.assets.resolve_all_hosts()
        elif target_kind is TargetKind.HOSTS:
            if not host_ids:
                raise ValidationError("at least one host is required")
            hosts = await unit_of_work.assets.resolve_host_ids(host_ids)
            if len(hosts) != len(set(host_ids)):
                raise ValidationError("one or more hosts are missing, disabled, or unusable")
        elif group_id is not None:
            if await unit_of_work.assets.get_group(group_id) is None:
                raise NotFoundError("group not found")
            hosts = await unit_of_work.assets.resolve_group_hosts(group_id)
        else:
            raise ValidationError("groupId is required for a group target")
        if not hosts:
            raise ValidationError("target resolves to no enabled hosts")
        return hosts

    @staticmethod
    async def _require_confirmed_host_keys(
        unit_of_work: UnitOfWork,
        hosts: tuple[tuple[UUID, str], ...],
    ) -> None:
        missing_ids = await unit_of_work.assets.host_ids_without_keys(
            tuple(host_id for host_id, _ in hosts)
        )
        if not missing_ids:
            return
        names = {host_id: name for host_id, name in hosts}
        raise HostKeyConfirmationRequiredError(
            details={
                "hosts": [
                    {"hostId": str(host_id), "name": names[host_id]} for host_id in missing_ids
                ]
            }
        )

    async def create_command(
        self,
        *,
        requested_by: UUID,
        idempotency_key: str,
        target_kind: TargetKind,
        host_ids: tuple[UUID, ...],
        group_id: UUID | None,
        mode: CommandMode,
        command: str,
        become: str,
        shell_confirmed: bool,
        timeout_seconds: int,
        forks: int,
        actor: SessionPrincipal | None = None,
    ) -> Run:
        if actor is not None:
            require_permission(
                actor,
                Permission.RUN_SHELL if mode is CommandMode.SHELL else Permission.RUN_STANDARD,
            )
            requested_by = actor.user_id
        if not command or len(command) > 4096 or "\0" in command:
            raise ValidationError("command must contain 1-4096 characters and no NUL byte")
        if mode is CommandMode.SHELL and not shell_confirmed:
            raise ValidationError("Shell mode requires explicit confirmation")
        if become not in {"CREDENTIAL_DEFAULT", "ENABLED", "DISABLED"}:
            raise ValidationError("invalid privilege escalation selection")
        if not 1 <= timeout_seconds <= 900 or not 1 <= forks <= 20:
            raise ValidationError("timeout or forks is outside the supported range")
        operation: dict[str, object] = {
            "mode": mode.value,
            "command": command,
            "become": become,
        }
        target: dict[str, object] = {
            "kind": target_kind.value,
            "hostIds": [str(value) for value in host_ids],
            "groupId": str(group_id) if group_id else None,
        }
        return await self._create(
            requested_by=requested_by,
            idempotency_key=idempotency_key,
            kind=RunKind.COMMAND,
            target_spec=target,
            operation_spec=operation,
            timeout_seconds=timeout_seconds,
            forks=forks,
            target_kind=target_kind,
            host_ids=host_ids,
            group_id=group_id,
            workspace_revision=None,
        )

    async def create_ping(
        self,
        *,
        requested_by: UUID,
        idempotency_key: str,
        host_id: UUID,
        timeout_seconds: int = 30,
        actor: SessionPrincipal | None = None,
    ) -> Run:
        if actor is not None:
            require_permission(actor, Permission.RUN_STANDARD)
            requested_by = actor.user_id
        target: dict[str, object] = {
            "kind": TargetKind.HOSTS.value,
            "hostIds": [str(host_id)],
            "groupId": None,
        }
        return await self._create(
            requested_by=requested_by,
            idempotency_key=idempotency_key,
            kind=RunKind.PING,
            target_spec=target,
            operation_spec={"module": "ansible.builtin.ping"},
            timeout_seconds=timeout_seconds,
            forks=1,
            target_kind=TargetKind.HOSTS,
            host_ids=(host_id,),
            group_id=None,
            workspace_revision=None,
        )

    async def create_playbook(
        self,
        *,
        requested_by: UUID,
        idempotency_key: str,
        target_kind: TargetKind,
        host_ids: tuple[UUID, ...],
        group_id: UUID | None,
        playbook: PlaybookReference,
        extra_vars: dict[str, object],
        parameters: dict[str, object] | None = None,
        check_mode: bool = False,
        tags: tuple[str, ...],
        skip_tags: tuple[str, ...],
        timeout_seconds: int,
        forks: int,
        actor: SessionPrincipal | None = None,
    ) -> Run:
        if actor is not None:
            require_permission(actor, Permission.RUN_STANDARD)
            requested_by = actor.user_id
        if not 1 <= timeout_seconds <= 86400 or not 1 <= forks <= 20:
            raise ValidationError("timeout or forks is outside the supported range")
        self._require_playbook_source(playbook.source)
        workspace_revision: str | None = None
        database_playbook_id: UUID | None = None
        if playbook.source is PlaybookSource.MOUNT:
            if playbook.path is None:
                raise PlaybookNotFoundError()
            mounted = await self._mounted_playbooks().get(playbook.path)
            workspace_revision = mounted.sha256
            reference: dict[str, object] = {
                "source": PlaybookSource.MOUNT.value,
                "path": mounted.path,
            }
        else:
            if playbook.playbook_id is None:
                raise PlaybookNotFoundError()
            database_playbook_id = playbook.playbook_id
            reference = {
                "source": PlaybookSource.DATABASE.value,
                "playbookId": str(playbook.playbook_id),
            }
        supplied_values = parameters if parameters is not None else extra_vars
        operation: dict[str, object] = {
            "playbook": reference,
            "tags": list(tags),
            "skipTags": list(skip_tags),
            "checkMode": check_mode,
        }
        if playbook.source is PlaybookSource.MOUNT:
            if check_mode:
                raise ValidationError("mounted Playbooks do not declare Check Mode support")
            _validate_extra_vars(supplied_values)
            operation["extraVars"] = supplied_values
            operation["playbookPath"] = reference["path"]
        target: dict[str, object] = {
            "kind": target_kind.value,
            "hostIds": [str(value) for value in host_ids],
            "groupId": str(group_id) if group_id else None,
        }
        return await self._create(
            requested_by=requested_by,
            idempotency_key=idempotency_key,
            kind=RunKind.PLAYBOOK,
            target_spec=target,
            operation_spec=operation,
            timeout_seconds=timeout_seconds,
            forks=forks,
            target_kind=target_kind,
            host_ids=host_ids,
            group_id=group_id,
            workspace_revision=workspace_revision,
            database_playbook_id=database_playbook_id,
            playbook_parameters=(supplied_values if database_playbook_id is not None else None),
        )

    async def preview_playbook(
        self,
        *,
        actor: SessionPrincipal,
        target_kind: TargetKind,
        host_ids: tuple[UUID, ...],
        group_id: UUID | None,
        playbook: PlaybookReference,
        parameters: dict[str, object],
        check_mode: bool,
        tags: tuple[str, ...],
        skip_tags: tuple[str, ...],
    ) -> dict[str, object]:
        require_permission(actor, Permission.RUN_STANDARD)
        self._require_playbook_source(playbook.source)
        async with self._unit_of_work_factory() as unit_of_work:
            hosts = await self._resolve(
                unit_of_work,
                target_kind=target_kind,
                host_ids=host_ids,
                group_id=group_id,
            )
            revision_number: int | None = None
            digest: str
            parameter_names: list[str] = []
            sensitive_fields: list[dict[str, object]] = []
            if playbook.source is PlaybookSource.MOUNT:
                if playbook.path is None:
                    raise PlaybookNotFoundError()
                if check_mode:
                    raise ValidationError("mounted Playbooks do not declare Check Mode support")
                _validate_extra_vars(parameters)
                mounted = await self._mounted_playbooks().get(playbook.path)
                digest = mounted.sha256
            else:
                if playbook.playbook_id is None:
                    raise PlaybookNotFoundError()
                document = await unit_of_work.playbooks.get_document(playbook.playbook_id)
                if document is None:
                    raise PlaybookNotFoundError()
                if not document.playbook.enabled:
                    raise PlaybookDisabledError()
                revision = document.revision
                revision_number = revision.revision
                digest = revision.sha256
                if revision.revision_format is PlaybookRevisionFormat.PROJECT:
                    validated = validate_parameters(revision.parameter_schema, parameters)
                    parameter_names = list(validated.supplied_names)
                    raw_properties = revision.parameter_schema.get("properties", {})
                    if isinstance(raw_properties, dict):
                        sensitive_fields = [
                            {
                                "name": name,
                                "supplied": name in parameters,
                            }
                            for name, definition in sorted(raw_properties.items())
                            if isinstance(definition, dict)
                            and definition.get("x-ops-composer-sensitive") is True
                        ]
                    if check_mode and not revision.supports_check_mode:
                        raise ValidationError(
                            "Playbook revision does not declare Check Mode support"
                        )
                else:
                    if check_mode:
                        raise ValidationError("legacy Playbook revisions do not support Check Mode")
                    _validate_extra_vars(parameters)
                    parameter_names = sorted(parameters)
        await AuditService(self._unit_of_work_factory).record_best_effort(
            new_audit_event(
                AuditAction.PLAYBOOK_PREVIEWED,
                AuditOutcome.SUCCEEDED,
                source=self._audit_source,
                actor_user_id=actor.user_id,
                session_id=actor.session_id,
                resource_type="playbook",
                resource_id=playbook.playbook_id or playbook.path,
                metadata={
                    "playbook_source": playbook.source.value,
                    "target_count": len(hosts),
                    "revision": revision_number,
                    "check_mode": check_mode,
                    "parameter_names": parameter_names,
                    "sensitive_parameter_count": len(sensitive_fields),
                },
            )
        )
        return {
            "targetCount": len(hosts),
            "playbookSource": playbook.source.value,
            "revision": revision_number,
            "digest": digest,
            "checkMode": check_mode,
            "tags": list(tags),
            "skipTags": list(skip_tags),
            "parameterNames": parameter_names,
            "sensitiveParameters": sensitive_fields,
        }

    async def _create(
        self,
        *,
        requested_by: UUID,
        idempotency_key: str,
        kind: RunKind,
        target_spec: dict[str, object],
        operation_spec: dict[str, object],
        timeout_seconds: int,
        forks: int,
        target_kind: TargetKind,
        host_ids: tuple[UUID, ...],
        group_id: UUID | None,
        workspace_revision: str | None,
        database_playbook_id: UUID | None = None,
        source_run_id: UUID | None = None,
        playbook_parameters: dict[str, object] | None = None,
    ) -> Run:
        if not 8 <= len(idempotency_key) <= 200:
            raise ValidationError("Idempotency-Key must contain 8-200 characters")
        request_payload: dict[str, object] = {
            "kind": kind.value,
            "target": target_spec,
            "operation": operation_spec,
            "timeoutSeconds": timeout_seconds,
            "forks": forks,
            "sourceRunId": str(source_run_id) if source_run_id else None,
        }
        fingerprint_scheme = RequestFingerprintScheme.LEGACY_SHA256
        if playbook_parameters:
            request_payload["parameters"] = playbook_parameters
            pepper = await EncryptionService(
                self._unit_of_work_factory, self._keyring
            ).idempotency_pepper()
            fingerprint = _hmac_fingerprint(request_payload, pepper)
            fingerprint_scheme = RequestFingerprintScheme.HMAC_SHA256_V1
        else:
            fingerprint = _fingerprint(request_payload)
        existing: Run | None = None
        replay_event = None
        try:
            async with self._unit_of_work_factory() as unit_of_work:
                existing = await unit_of_work.runs.get_by_idempotency_key(
                    requested_by, idempotency_key
                )
                if existing is not None:
                    if existing.request_fingerprint != fingerprint:
                        raise IdempotencyConflictError()
                    replay_event = new_audit_event(
                        AuditAction.RUN_IDEMPOTENT_REPLAY,
                        AuditOutcome.NOOP,
                        source=self._audit_source,
                        actor_user_id=requested_by,
                        run_id=existing.run_id,
                        resource_type="run",
                        resource_id=existing.run_id,
                        metadata={
                            "operation_kind": kind.value,
                            "target_kind": target_kind.value,
                            **_safe_operation_metadata(kind, operation_spec),
                        },
                    )
                    await unit_of_work.audit.append(replay_event)
        except IdempotencyConflictError as error:
            await AuditService(self._unit_of_work_factory).record_best_effort(
                new_audit_event(
                    AuditAction.RUN_IDEMPOTENCY_CONFLICT,
                    AuditOutcome.DENIED,
                    source=self._audit_source,
                    severity=AuditSeverity.WARNING,
                    actor_user_id=requested_by,
                    error_code=error.code,
                    failure_stage="idempotency",
                    retryable=False,
                    metadata={"operation_kind": kind.value},
                )
            )
            error.audit_recorded = True
            raise
        if existing is not None:
            if replay_event is None:
                raise RuntimeError("idempotent replay completed without an audit event")
            emit_audit_event(replay_event)
            return existing
        now = utc_now()
        failure_stage = "target_resolution"
        try:
            async with self._unit_of_work_factory() as unit_of_work:
                hosts = await self._resolve(
                    unit_of_work,
                    target_kind=target_kind,
                    host_ids=host_ids,
                    group_id=group_id,
                )
                resolved_operation_spec = copy.deepcopy(operation_spec)
                playbook_revision: int | None = None
                secret_inputs: dict[str, str] = {}
                if database_playbook_id is not None:
                    failure_stage = "playbook_resolution"
                    document = await unit_of_work.playbooks.get_document(database_playbook_id)
                    if document is None:
                        raise PlaybookNotFoundError()
                    if not document.playbook.enabled:
                        raise PlaybookDisabledError()
                    playbook_revision = document.revision.revision
                    workspace_revision = document.revision.sha256
                    raw_reference = resolved_operation_spec.get("playbook")
                    if not isinstance(raw_reference, dict):
                        raise PlaybookNotFoundError()
                    raw_reference["revision"] = playbook_revision
                    raw_reference["sha256"] = document.revision.sha256
                    supplied = playbook_parameters or {}
                    if document.revision.revision_format is PlaybookRevisionFormat.PROJECT:
                        validated_parameters = validate_parameters(
                            document.revision.parameter_schema,
                            supplied,
                        )
                        if bool(resolved_operation_spec.get("checkMode")) and not (
                            document.revision.supports_check_mode
                        ):
                            raise ValidationError(
                                "Playbook revision does not declare Check Mode support"
                            )
                        resolved_operation_spec["extraVars"] = validated_parameters.public_values
                        resolved_operation_spec["parameterNames"] = list(
                            validated_parameters.supplied_names
                        )
                        resolved_operation_spec["secretParameterNames"] = sorted(
                            validated_parameters.secret_values
                        )
                        secret_inputs = validated_parameters.secret_values
                    else:
                        if bool(resolved_operation_spec.get("checkMode")):
                            raise ValidationError(
                                "legacy Playbook revisions do not support Check Mode"
                            )
                        _validate_extra_vars(supplied)
                        resolved_operation_spec["extraVars"] = supplied
                failure_stage = "run_persistence"
                safe_inventory = build_inventory(hosts)
                resolved = [
                    {
                        "hostId": str(host.host_id),
                        "name": host.name,
                        "address": host.address,
                        "sshPort": host.ssh_port,
                        "credentialId": str(host.credential_id),
                        "credentialVersion": host.credential_version,
                    }
                    for host in hosts
                ]
                versions: dict[str, object] = {
                    str(host.credential_id): host.credential_version for host in hosts
                }
                run = Run(
                    run_id=uuid4(),
                    source_run_id=source_run_id,
                    kind=kind,
                    status=RunStatus.QUEUED,
                    target_spec=target_spec,
                    resolved_targets=resolved,
                    operation_spec=resolved_operation_spec,
                    inventory_snapshot=safe_inventory,
                    workspace_revision=workspace_revision,
                    playbook_id=database_playbook_id,
                    playbook_revision=playbook_revision,
                    credential_versions=versions,
                    timeout_seconds=timeout_seconds,
                    forks=forks,
                    requested_by=requested_by,
                    idempotency_key=idempotency_key,
                    request_fingerprint=fingerprint,
                    request_fingerprint_scheme=fingerprint_scheme,
                    created_at=now,
                    updated_at=now,
                )
                targets = tuple(
                    RunTarget(
                        run_target_id=uuid4(),
                        run_id=run.run_id,
                        host_id=host.host_id,
                        host_name=host.name,
                        host_address=host.address,
                        status=RunTargetStatus.PENDING,
                    )
                    for host in hosts
                )
                persisted, created = await unit_of_work.runs.create_or_get(run, targets)
                if persisted.request_fingerprint != fingerprint:
                    raise IdempotencyConflictError()
                if created:
                    failure_stage = "host_key_validation"
                    await self._require_confirmed_host_keys(
                        unit_of_work,
                        tuple((host.host_id, host.name) for host in hosts),
                    )
                    failure_stage = "run_persistence"
                    if secret_inputs:
                        encrypted_payload, key_version = self._keyring.encrypt_json(
                            "run-parameters",
                            str(persisted.run_id),
                            secret_inputs,
                        )
                        await unit_of_work.runs.add_secret_inputs(
                            persisted.run_id,
                            encrypted_payload,
                            key_version,
                            tuple(sorted(secret_inputs)),
                            now,
                        )
                    await unit_of_work.runs.append_event(
                        RunEvent(
                            run_event_id=uuid4(),
                            run_id=persisted.run_id,
                            sequence=1,
                            event_type="run_queued",
                            event_data={"hostCount": len(hosts), "kind": kind.value},
                            created_at=now,
                        )
                    )
                audit_action = (
                    AuditAction.RUN_CREATED if created else AuditAction.RUN_IDEMPOTENT_REPLAY
                )
                event = new_audit_event(
                    audit_action,
                    AuditOutcome.SUCCEEDED if created else AuditOutcome.NOOP,
                    source=self._audit_source,
                    actor_user_id=requested_by,
                    run_id=persisted.run_id,
                    resource_type="run",
                    resource_id=persisted.run_id,
                    metadata={
                        "operation_kind": kind.value,
                        "target_kind": target_kind.value,
                        "target_count": len(hosts),
                        "timeout_seconds": timeout_seconds,
                        "forks": forks,
                        **_safe_operation_metadata(kind, resolved_operation_spec),
                    },
                )
                await unit_of_work.audit.append(event)
        except IdempotencyConflictError as error:
            await AuditService(self._unit_of_work_factory).record_best_effort(
                new_audit_event(
                    AuditAction.RUN_IDEMPOTENCY_CONFLICT,
                    AuditOutcome.DENIED,
                    source=self._audit_source,
                    severity=AuditSeverity.WARNING,
                    actor_user_id=requested_by,
                    error_code=error.code,
                    failure_stage="idempotency",
                    retryable=False,
                    metadata={"operation_kind": kind.value},
                )
            )
            error.audit_recorded = True
            raise
        except OpsError as error:
            if failure_stage in {"target_resolution", "host_key_validation"}:
                await AuditService(self._unit_of_work_factory).record_best_effort(
                    new_audit_event(
                        AuditAction.RUN_TARGET_RESOLUTION_FAILED,
                        AuditOutcome.DENIED,
                        source=self._audit_source,
                        severity=AuditSeverity.WARNING,
                        actor_user_id=requested_by,
                        error_code=error.code,
                        failure_stage=failure_stage,
                        retryable=False,
                        metadata={
                            "operation_kind": kind.value,
                            "target_kind": target_kind.value,
                            "details": error.details or {},
                        },
                    )
                )
                error.audit_recorded = True
            raise
        emit_audit_event(event)
        return persisted

    async def get(self, run_id: UUID) -> Run:
        async with self._unit_of_work_factory() as unit_of_work:
            run = await unit_of_work.runs.get(run_id)
            if run is None:
                raise NotFoundError("run not found")
            return run

    async def detail(self, run_id: UUID) -> tuple[Run, tuple[RunTarget, ...]]:
        async with self._unit_of_work_factory() as unit_of_work:
            run = await unit_of_work.runs.get(run_id)
            if run is None:
                raise NotFoundError("run not found")
            return run, await unit_of_work.runs.targets(run_id)

    async def list(self, *, limit: int, offset: int) -> tuple[Run, ...]:
        async with self._unit_of_work_factory() as unit_of_work:
            return await unit_of_work.runs.list(limit=limit, offset=offset)

    async def cancel(
        self,
        run_id: UUID,
        *,
        requested_by: UUID,
        actor: SessionPrincipal | None = None,
    ) -> Run:
        if actor is not None:
            require_permission(actor, Permission.RUN_CANCEL)
            requested_by = actor.user_id
        now = utc_now()
        async with self._unit_of_work_factory() as unit_of_work:
            current = await unit_of_work.runs.get(run_id)
            if current is None:
                raise NotFoundError("run not found")
            if current.status in TERMINAL_RUN_STATUSES:
                raise RunNotCancelableError()
            run = await unit_of_work.runs.request_cancel(run_id, now)
            if run is None:
                raise RunNotCancelableError()
            await unit_of_work.runs.append_event(
                RunEvent(
                    run_event_id=uuid4(),
                    run_id=run_id,
                    sequence=1,
                    event_type="cancel_requested",
                    event_data={},
                    created_at=now,
                )
            )
            event = new_audit_event(
                AuditAction.RUN_CANCEL_REQUESTED,
                AuditOutcome.SUCCEEDED,
                source=self._audit_source,
                actor_user_id=requested_by,
                run_id=run_id,
                resource_type="run",
                resource_id=run_id,
                metadata={"status_before": current.status.value, "status_after": run.status.value},
            )
            await unit_of_work.audit.append(event)
        emit_audit_event(event)
        return run

    async def retry(
        self,
        run_id: UUID,
        *,
        requested_by: UUID,
        idempotency_key: str,
        actor: SessionPrincipal | None = None,
        parameters: dict[str, object] | None = None,
    ) -> Run:
        if not 8 <= len(idempotency_key) <= 200:
            raise ValidationError("Idempotency-Key must contain 8-200 characters")
        now = utc_now()
        async with self._unit_of_work_factory() as unit_of_work:
            source = await unit_of_work.runs.get(run_id)
            if source is None:
                raise NotFoundError("run not found")
            if source.status not in TERMINAL_RUN_STATUSES:
                raise ValidationError("only terminal runs can be retried")
            if actor is not None:
                permission = (
                    Permission.RUN_SHELL
                    if source.kind is RunKind.COMMAND
                    and source.operation_spec.get("mode") == CommandMode.SHELL.value
                    else Permission.RUN_STANDARD
                )
                require_permission(actor, permission)
                requested_by = actor.user_id
            if source.kind is RunKind.PLAYBOOK:
                self._require_playbook_source(_playbook_source(source.operation_spec))
            source_targets = await unit_of_work.runs.targets(run_id)
            if not source_targets:
                raise ValidationError("source run target snapshot is invalid")
            operation_spec = copy.deepcopy(source.operation_spec)
            retry_secret_inputs: dict[str, str] = {}
            raw_secret_names = operation_spec.get("secretParameterNames", [])
            if not isinstance(raw_secret_names, list) or not all(
                isinstance(item, str) for item in raw_secret_names
            ):
                raise ValidationError("source Run parameter metadata is invalid")
            if source.kind is RunKind.PLAYBOOK and source.playbook_id is not None:
                revision = await unit_of_work.playbooks.get_revision(
                    source.playbook_id,
                    source.playbook_revision or 0,
                )
                if revision is None:
                    raise PlaybookNotFoundError("source Playbook revision is unavailable")
                if revision.revision_format is PlaybookRevisionFormat.PROJECT:
                    raw_public = operation_spec.get("extraVars", {})
                    if not isinstance(raw_public, dict):
                        raise ValidationError("source Run parameters are invalid")
                    missing_secret_names = set(raw_secret_names) - set(parameters or {})
                    if missing_secret_names:
                        raise SecretParametersRequiredError(
                            details={"fields": sorted(missing_secret_names)}
                        )
                    supplied = {**raw_public, **(parameters or {})}
                    validated = validate_parameters(revision.parameter_schema, supplied)
                    if set(raw_secret_names) - set(validated.secret_values):
                        raise SecretParametersRequiredError(
                            details={"fields": sorted(raw_secret_names)}
                        )
                    retry_secret_inputs = validated.secret_values
                    operation_spec["extraVars"] = validated.public_values
                    operation_spec["parameterNames"] = list(validated.supplied_names)
                    operation_spec["secretParameterNames"] = sorted(retry_secret_inputs)
                elif parameters:
                    raise ValidationError("legacy Playbook Retry does not accept parameters")
            elif parameters:
                raise ValidationError("this Run type does not accept parameters")
            request_payload: dict[str, object] = {
                "kind": source.kind.value,
                "target": source.target_spec,
                "operation": operation_spec,
                "timeoutSeconds": source.timeout_seconds,
                "forks": source.forks,
                "sourceRunId": str(source.run_id),
            }
            if retry_secret_inputs:
                request_payload["secretParameters"] = retry_secret_inputs
                pepper_envelope = await unit_of_work.encryption.get_system_secret(
                    "run-idempotency-pepper"
                )
                if pepper_envelope is None:
                    raise RuntimeError("idempotency pepper is not initialized")
                pepper = self._keyring.decrypt_bytes(
                    "system-secret",
                    pepper_envelope.secret_name,
                    pepper_envelope.encrypted_secret,
                    pepper_envelope.encryption_key_version,
                )
                fingerprint = _hmac_fingerprint(request_payload, pepper)
                fingerprint_scheme = RequestFingerprintScheme.HMAC_SHA256_V1
            else:
                fingerprint = _fingerprint(request_payload)
                fingerprint_scheme = RequestFingerprintScheme.LEGACY_SHA256
            retried = Run(
                run_id=uuid4(),
                source_run_id=source.run_id,
                kind=source.kind,
                status=RunStatus.QUEUED,
                target_spec=copy.deepcopy(source.target_spec),
                resolved_targets=copy.deepcopy(source.resolved_targets),
                operation_spec=operation_spec,
                inventory_snapshot=copy.deepcopy(source.inventory_snapshot),
                workspace_revision=source.workspace_revision,
                playbook_id=source.playbook_id,
                playbook_revision=source.playbook_revision,
                credential_versions=copy.deepcopy(source.credential_versions),
                timeout_seconds=source.timeout_seconds,
                forks=source.forks,
                requested_by=requested_by,
                idempotency_key=idempotency_key,
                request_fingerprint=fingerprint,
                request_fingerprint_scheme=fingerprint_scheme,
                created_at=now,
                updated_at=now,
            )
            targets = tuple(
                RunTarget(
                    run_target_id=uuid4(),
                    run_id=retried.run_id,
                    host_id=target.host_id,
                    host_name=target.host_name,
                    host_address=target.host_address,
                    status=RunTargetStatus.PENDING,
                )
                for target in source_targets
            )
            persisted, created = await unit_of_work.runs.create_or_get(retried, targets)
            if persisted.request_fingerprint != fingerprint:
                raise IdempotencyConflictError()
            if created:
                await self._require_confirmed_host_keys(
                    unit_of_work,
                    tuple((target.host_id, target.host_name) for target in source_targets),
                )
                if retry_secret_inputs:
                    encrypted_payload, key_version = self._keyring.encrypt_json(
                        "run-parameters",
                        str(persisted.run_id),
                        retry_secret_inputs,
                    )
                    await unit_of_work.runs.add_secret_inputs(
                        persisted.run_id,
                        encrypted_payload,
                        key_version,
                        tuple(sorted(retry_secret_inputs)),
                        now,
                    )
                await unit_of_work.runs.append_event(
                    RunEvent(
                        run_event_id=uuid4(),
                        run_id=persisted.run_id,
                        sequence=1,
                        event_type="run_queued",
                        event_data={
                            "hostCount": len(targets),
                            "kind": persisted.kind.value,
                            "sourceRunId": str(source.run_id),
                        },
                        created_at=now,
                    )
                )
            event = new_audit_event(
                AuditAction.RUN_RETRY_CREATED if created else AuditAction.RUN_IDEMPOTENT_REPLAY,
                AuditOutcome.SUCCEEDED if created else AuditOutcome.NOOP,
                source=self._audit_source,
                actor_user_id=requested_by,
                run_id=persisted.run_id,
                resource_type="run",
                resource_id=persisted.run_id,
                metadata={
                    "source_run_id": source.run_id,
                    "operation_kind": source.kind.value,
                    "target_count": len(targets),
                },
            )
            await unit_of_work.audit.append(event)
        emit_audit_event(event)
        return persisted

    async def events_after(
        self, run_id: UUID, sequence: int, limit: int = 500
    ) -> tuple[RunEvent, ...]:
        async with self._unit_of_work_factory() as unit_of_work:
            if await unit_of_work.runs.get(run_id) is None:
                raise NotFoundError("run not found")
            return await unit_of_work.runs.events_after(run_id, sequence, limit)

    async def consume_secret_inputs(
        self, run_id: UUID, expected_names: tuple[str, ...]
    ) -> dict[str, str]:
        if not expected_names:
            return {}
        event = None
        async with self._unit_of_work_factory() as unit_of_work:
            record = await unit_of_work.runs.consume_secret_inputs(run_id)
            if record is None:
                raise SecretParametersRequiredError(details={"fields": list(expected_names)})
            encrypted_payload = record.get("encrypted_payload")
            key_version = record.get("encryption_key_version")
            parameter_names = record.get("parameter_names")
            if (
                not isinstance(encrypted_payload, bytes)
                or not isinstance(key_version, int)
                or not isinstance(parameter_names, list)
                or sorted(str(item) for item in parameter_names) != sorted(expected_names)
            ):
                raise RuntimeError("encrypted Run parameter metadata is invalid")
            values = self._keyring.decrypt_json(
                "run-parameters",
                str(run_id),
                encrypted_payload,
                key_version,
            )
            if set(values) != set(expected_names) or not all(
                isinstance(value, str) for value in values.values()
            ):
                raise RuntimeError("encrypted Run parameters are invalid")
            event = new_audit_event(
                AuditAction.RUN_SECRET_INPUT_CONSUMED,
                AuditOutcome.SUCCEEDED,
                source=AuditSource.WORKER,
                run_id=run_id,
                resource_type="run",
                resource_id=run_id,
                metadata={"parameter_names": sorted(expected_names)},
            )
            await unit_of_work.audit.append(event)
        emit_audit_event(event)
        return {key: str(value) for key, value in values.items()}

    async def dashboard(self) -> dict[str, object]:
        async with self._unit_of_work_factory() as unit_of_work:
            return await unit_of_work.runs.dashboard()


class WorkerCoordinator:
    def __init__(
        self, unit_of_work_factory: UnitOfWorkFactory, settings: Settings, worker_id: str
    ) -> None:
        self._unit_of_work_factory = unit_of_work_factory
        self._settings = settings
        self.worker_id = worker_id

    async def heartbeat(self, run_id: UUID | None = None) -> None:
        now = utc_now()
        expires = now + timedelta(seconds=self._settings.worker_lease_seconds)
        async with self._unit_of_work_factory() as unit_of_work:
            await unit_of_work.runs.heartbeat(self.worker_id, run_id, now, expires)

    async def recover_stale(self) -> int:
        event = None
        async with self._unit_of_work_factory() as unit_of_work:
            count = await unit_of_work.runs.recover_stale(utc_now())
            if count:
                event = new_audit_event(
                    AuditAction.STALE_RUNS_RECOVERED,
                    AuditOutcome.SUCCEEDED,
                    source=AuditSource.WORKER,
                    worker_id=self.worker_id,
                    metadata={"run_count": count},
                )
                await unit_of_work.audit.append(event)
        if event is not None:
            emit_audit_event(event)
        return count

    async def claim(self) -> Run | None:
        now = utc_now()
        expires = now + timedelta(seconds=self._settings.worker_lease_seconds)
        try:
            async with self._unit_of_work_factory() as unit_of_work:
                await unit_of_work.runs.heartbeat(self.worker_id, None, now, expires)
                run = await unit_of_work.runs.claim_next(self.worker_id, now, expires)
                if run is not None:
                    await unit_of_work.runs.heartbeat(self.worker_id, run.run_id, now, expires)
                    event = new_audit_event(
                        AuditAction.RUN_CLAIMED,
                        AuditOutcome.SUCCEEDED,
                        source=AuditSource.WORKER,
                        worker_id=self.worker_id,
                        run_id=run.run_id,
                        resource_type="run",
                        resource_id=run.run_id,
                        metadata={
                            "operation_kind": run.kind.value,
                            "target_count": len(run.resolved_targets),
                            "lease_seconds": self._settings.worker_lease_seconds,
                        },
                    )
                    await unit_of_work.audit.append(event)
            if run is not None:
                emit_audit_event(event)
            return run
        except ClaimCollisionError as error:
            await AuditService(self._unit_of_work_factory).record_best_effort(
                new_audit_event(
                    AuditAction.HOST_LOCK_COLLISION,
                    AuditOutcome.NOOP,
                    source=AuditSource.WORKER,
                    severity=AuditSeverity.DEBUG,
                    worker_id=self.worker_id,
                    exception_type=type(error).__name__,
                    failure_stage="run_claim",
                    retryable=True,
                )
            )
            return None

    async def mark_running(self, run_id: UUID) -> None:
        event = new_audit_event(
            AuditAction.RUN_STARTED,
            AuditOutcome.SUCCEEDED,
            source=AuditSource.WORKER,
            worker_id=self.worker_id,
            run_id=run_id,
            resource_type="run",
            resource_id=run_id,
        )
        async with self._unit_of_work_factory() as unit_of_work:
            await unit_of_work.runs.mark_running(run_id, utc_now())
            await unit_of_work.audit.append(event)
        emit_audit_event(event)

    async def cancellation_requested(self, run_id: UUID) -> bool:
        async with self._unit_of_work_factory() as unit_of_work:
            return await unit_of_work.runs.cancellation_requested(run_id)

    async def append_event(
        self,
        run_id: UUID,
        *,
        event_type: str,
        stdout: str | None = None,
        task: str | None = None,
        event_data: dict[str, object] | None = None,
        run_target_id: UUID | None = None,
    ) -> RunEvent:
        if stdout is not None:
            data = stdout.encode()
            if len(data) > self._settings.max_event_output_bytes:
                stdout = data[-self._settings.max_event_output_bytes :].decode(
                    "utf-8", errors="replace"
                )
        async with self._unit_of_work_factory() as unit_of_work:
            return await unit_of_work.runs.append_event(
                RunEvent(
                    run_event_id=uuid4(),
                    run_id=run_id,
                    run_target_id=run_target_id,
                    sequence=1,
                    event_type=event_type,
                    task=task,
                    stdout=stdout,
                    event_data=event_data or {},
                    created_at=utc_now(),
                )
            )

    async def finish_target(
        self,
        run_id: UUID,
        run_target_id: UUID,
        *,
        host_id: UUID,
        host_name: str,
        status: RunTargetStatus,
        return_code: int | None,
        stdout: str,
        stderr: str,
        result: dict[str, object],
        output_truncated: bool,
        changed_count: int,
        failed_count: int,
        unreachable_count: int,
    ) -> None:
        event = new_audit_event(
            AuditAction.HOST_COMPLETED,
            (
                AuditOutcome.SUCCEEDED
                if status in {RunTargetStatus.SUCCEEDED, RunTargetStatus.SKIPPED}
                else AuditOutcome.FAILED
            ),
            source=AuditSource.WORKER,
            severity=(
                AuditSeverity.INFO
                if status in {RunTargetStatus.SUCCEEDED, RunTargetStatus.SKIPPED}
                else AuditSeverity.WARNING
            ),
            worker_id=self.worker_id,
            run_id=run_id,
            run_target_id=run_target_id,
            resource_type="host",
            resource_id=host_id,
            metadata={
                "host_name": host_name,
                "status": status.value,
                "return_code": return_code,
                "output_truncated": output_truncated,
                "changed_count": changed_count,
                "failed_count": failed_count,
                "unreachable_count": unreachable_count,
            },
        )
        async with self._unit_of_work_factory() as unit_of_work:
            await unit_of_work.runs.finish_target(
                run_target_id,
                status,
                return_code,
                stdout,
                stderr,
                result,
                output_truncated,
                changed_count,
                failed_count,
                unreachable_count,
                utc_now(),
            )
            await unit_of_work.audit.append(event)
        emit_audit_event(event)

    async def finish(
        self,
        run_id: UUID,
        *,
        status: RunStatus,
        return_code: int | None,
        summary: dict[str, object],
        failure_code: str | None = None,
        failure_message: str | None = None,
        exception_type: str | None = None,
        failure_stage: str | None = None,
    ) -> Run:
        action = {
            RunStatus.SUCCEEDED: AuditAction.RUN_SUCCEEDED,
            RunStatus.PARTIAL: AuditAction.RUN_PARTIAL,
            RunStatus.FAILED: AuditAction.RUN_FAILED,
            RunStatus.CANCELED: AuditAction.RUN_CANCELED,
            RunStatus.TIMED_OUT: AuditAction.RUN_TIMED_OUT,
            RunStatus.INTERRUPTED: AuditAction.RUN_INTERRUPTED,
            RunStatus.REJECTED: AuditAction.RUN_REJECTED,
        }.get(status, AuditAction.RUN_FAILED)
        successful = status is RunStatus.SUCCEEDED
        async with self._unit_of_work_factory() as unit_of_work:
            result = await unit_of_work.runs.finish(
                run_id,
                self.worker_id,
                status,
                return_code,
                summary,
                failure_code,
                failure_message,
                utc_now(),
            )
            if result is None:
                raise RuntimeError("worker no longer owns this run")
            started_at = result.started_at or result.claimed_at
            duration_ms = (
                max(0.0, (result.finished_at - started_at).total_seconds() * 1000)
                if started_at is not None and result.finished_at is not None
                else None
            )
            event = new_audit_event(
                action,
                AuditOutcome.SUCCEEDED if successful else AuditOutcome.FAILED,
                source=AuditSource.WORKER,
                severity=AuditSeverity.INFO if successful else AuditSeverity.WARNING,
                worker_id=self.worker_id,
                run_id=run_id,
                resource_type="run",
                resource_id=run_id,
                duration_ms=duration_ms,
                error_code=failure_code,
                exception_type=exception_type,
                failure_stage=failure_stage or ("run_execution" if failure_code else None),
                retryable=status in {RunStatus.FAILED, RunStatus.TIMED_OUT, RunStatus.INTERRUPTED},
                metadata={
                    "return_code": return_code,
                    "summary": summary,
                    "status": status.value,
                },
            )
            await unit_of_work.runs.append_event(
                RunEvent(
                    run_event_id=uuid4(),
                    run_id=run_id,
                    sequence=1,
                    event_type="run_finished",
                    event_data={
                        "status": status.value,
                        "returnCode": return_code,
                        "summary": summary,
                    },
                    created_at=utc_now(),
                )
            )
            await unit_of_work.audit.append(event)
        emit_audit_event(event)
        return result
