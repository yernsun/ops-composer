from __future__ import annotations

import copy
import hashlib
import json
from datetime import timedelta
from uuid import UUID, uuid4

from ops_composer.domain.audit import (
    AuditAction,
    AuditOutcome,
    AuditSeverity,
    AuditSource,
)
from ops_composer.domain.base import utc_now
from ops_composer.domain.errors import (
    ClaimCollisionError,
    IdempotencyConflictError,
    NotFoundError,
    OpsError,
    RunNotCancelableError,
    ValidationError,
)
from ops_composer.domain.ops import (
    TERMINAL_RUN_STATUSES,
    CommandMode,
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
from ops_composer.services.inventory import build_inventory
from ops_composer.services.playbooks import PlaybookCatalog
from ops_composer.settings import Settings
from ops_composer.uow.factory import UnitOfWorkFactory
from ops_composer.uow.unit import UnitOfWork


def _fingerprint(payload: dict[str, object]) -> str:
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _validate_extra_vars(value: object, path: str = "extraVars") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = str(key).casefold().replace("-", "_")
            if normalized.startswith("ansible_") or any(
                token in normalized
                for token in ("password", "passwd", "secret", "token", "private_key", "passphrase")
            ):
                raise ValidationError(
                    "secret and Ansible connection Extra Vars are not supported in M1",
                    details={"field": f"{path}.{key}"},
                )
            _validate_extra_vars(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _validate_extra_vars(item, f"{path}[{index}]")


def _safe_operation_metadata(
    kind: RunKind, operation_spec: dict[str, object]
) -> dict[str, object]:
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
        return {
            "playbook_path": str(operation_spec.get("playbookPath", "")),
            "variable_names": sorted(variables) if isinstance(variables, dict) else [],
            "tag_count": len(tags) if isinstance(tags, list) else 0,
            "skip_tag_count": len(skip_tags) if isinstance(skip_tags, list) else 0,
        }
    return {"module": "ansible.builtin.ping"}


class RunService:
    def __init__(
        self,
        unit_of_work_factory: UnitOfWorkFactory,
        settings: Settings,
        playbooks: PlaybookCatalog | None = None,
        *,
        audit_source: AuditSource = AuditSource.API,
    ) -> None:
        self._unit_of_work_factory = unit_of_work_factory
        self._settings = settings
        self._playbooks = playbooks or PlaybookCatalog(settings.playbook_workspace)
        self._audit_source = audit_source

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
    ) -> Run:
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
    ) -> Run:
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
        playbook_path: str,
        extra_vars: dict[str, object],
        tags: tuple[str, ...],
        skip_tags: tuple[str, ...],
        timeout_seconds: int,
        forks: int,
    ) -> Run:
        if not 1 <= timeout_seconds <= 86400 or not 1 <= forks <= 20:
            raise ValidationError("timeout or forks is outside the supported range")
        _validate_extra_vars(extra_vars)
        playbook = await self._playbooks.get(playbook_path)
        operation: dict[str, object] = {
            "playbookPath": playbook.path,
            "extraVars": extra_vars,
            "tags": list(tags),
            "skipTags": list(skip_tags),
        }
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
            workspace_revision=playbook.sha256,
        )

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
        source_run_id: UUID | None = None,
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
        fingerprint = _fingerprint(request_payload)
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
                versions = {str(host.credential_id): host.credential_version for host in hosts}
                run = Run(
                    run_id=uuid4(),
                    source_run_id=source_run_id,
                    kind=kind,
                    status=RunStatus.QUEUED,
                    target_spec=target_spec,
                    resolved_targets=resolved,
                    operation_spec=operation_spec,
                    inventory_snapshot=safe_inventory,
                    workspace_revision=workspace_revision,
                    credential_versions=versions,
                    timeout_seconds=timeout_seconds,
                    forks=forks,
                    requested_by=requested_by,
                    idempotency_key=idempotency_key,
                    request_fingerprint=fingerprint,
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
                    AuditAction.RUN_CREATED
                    if created
                    else AuditAction.RUN_IDEMPOTENT_REPLAY
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
                        **_safe_operation_metadata(kind, operation_spec),
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
            if failure_stage == "target_resolution":
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

    async def cancel(self, run_id: UUID, *, requested_by: UUID) -> Run:
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

    async def retry(self, run_id: UUID, *, requested_by: UUID, idempotency_key: str) -> Run:
        if not 8 <= len(idempotency_key) <= 200:
            raise ValidationError("Idempotency-Key must contain 8-200 characters")
        now = utc_now()
        async with self._unit_of_work_factory() as unit_of_work:
            source = await unit_of_work.runs.get(run_id)
            if source is None:
                raise NotFoundError("run not found")
            if source.status not in TERMINAL_RUN_STATUSES:
                raise ValidationError("only terminal runs can be retried")
            source_targets = await unit_of_work.runs.targets(run_id)
            if not source_targets:
                raise ValidationError("source run target snapshot is invalid")
            request_payload: dict[str, object] = {
                "kind": source.kind.value,
                "target": source.target_spec,
                "operation": source.operation_spec,
                "timeoutSeconds": source.timeout_seconds,
                "forks": source.forks,
                "sourceRunId": str(source.run_id),
            }
            fingerprint = _fingerprint(request_payload)
            retried = Run(
                run_id=uuid4(),
                source_run_id=source.run_id,
                kind=source.kind,
                status=RunStatus.QUEUED,
                target_spec=copy.deepcopy(source.target_spec),
                resolved_targets=copy.deepcopy(source.resolved_targets),
                operation_spec=copy.deepcopy(source.operation_spec),
                inventory_snapshot=copy.deepcopy(source.inventory_snapshot),
                workspace_revision=source.workspace_revision,
                credential_versions=copy.deepcopy(source.credential_versions),
                timeout_seconds=source.timeout_seconds,
                forks=source.forks,
                requested_by=requested_by,
                idempotency_key=idempotency_key,
                request_fingerprint=fingerprint,
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
                retryable=status
                in {RunStatus.FAILED, RunStatus.TIMED_OUT, RunStatus.INTERRUPTED},
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
