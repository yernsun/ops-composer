from __future__ import annotations

import asyncio
import copy
import importlib
import json
import os
import shutil
import socket
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from threading import Event
from typing import Any
from uuid import UUID

import yaml

from ops_composer.db.migration_engine import MigrationRunner
from ops_composer.db.pool import create_pool
from ops_composer.db.registry import MIGRATIONS
from ops_composer.domain.audit import (
    AuditAction,
    AuditOutcome,
    AuditSeverity,
    AuditSource,
)
from ops_composer.domain.errors import HostKeyConfirmationRequiredError, OpsError
from ops_composer.domain.ops import Run, RunStatus, RunTarget, RunTargetStatus
from ops_composer.observability import (
    configure_logging,
    log_context,
    log_event,
    safe_exception_fields,
)
from ops_composer.services.assets import AssetService, CredentialService
from ops_composer.services.audit import AuditService, new_audit_event
from ops_composer.services.crypto import CredentialCipher, redact_secrets
from ops_composer.services.playbooks import PlaybookCatalog
from ops_composer.services.runs import RunService, WorkerCoordinator
from ops_composer.settings import Settings
from ops_composer.uow.factory import UnitOfWorkFactory

SENSITIVE_KEYS = ("password", "secret", "private_key", "privatekey", "passphrase")


def _sanitize(value: object, secrets: tuple[str, ...]) -> object:
    if isinstance(value, str):
        return redact_secrets(value, secrets)
    if isinstance(value, dict):
        return {
            str(key): (
                "[REDACTED]"
                if any(token in str(key).casefold() for token in SENSITIVE_KEYS)
                else _sanitize(item, secrets)
            )
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_sanitize(item, secrets) for item in value]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)


@dataclass(slots=True)
class TargetAccumulator:
    target: RunTarget
    chunks: list[str] = field(default_factory=list)
    size: int = 0
    truncated: bool = False
    status: RunTargetStatus = RunTargetStatus.RUNNING
    changed: int = 0
    failed: int = 0
    unreachable: int = 0

    def add_output(self, output: str, limit: int) -> None:
        encoded = output.encode()
        if self.size + len(encoded) <= limit:
            self.chunks.append(output)
            self.size += len(encoded)
            return
        remaining = max(0, limit - self.size)
        if remaining:
            self.chunks.append(encoded[:remaining].decode("utf-8", errors="replace"))
            self.size = limit
        self.truncated = True


class RuntimeDirectory:
    def __init__(self, root: Path, run_id: UUID) -> None:
        self.root = root.resolve()
        self.path = self.root / str(run_id)

    def __enter__(self) -> RuntimeDirectory:
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.root.chmod(0o700)
        if self.path.exists():
            shutil.rmtree(self.path)
        self.path.mkdir(mode=0o700)
        return self

    def write(self, relative: str, content: str) -> Path:
        path = self.path / relative
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        path.chmod(0o600)
        return path

    def __exit__(self, *_: object) -> None:
        if self.path.is_dir() and self.path.parent == self.root:
            shutil.rmtree(self.path)


def cleanup_orphan_runtime(root: Path) -> int:
    resolved = root.resolve()
    if not resolved.is_dir():
        return 0
    removed = 0
    for child in resolved.iterdir():
        try:
            UUID(child.name)
        except ValueError:
            continue
        if child.is_dir() and child.parent == resolved:
            shutil.rmtree(child)
            removed += 1
    return removed


class AnsibleExecutor:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def run(
        self,
        run: Run,
        *,
        inventory_path: Path,
        runtime_path: Path,
        cancel: Event,
        event_handler: Callable[[dict[str, Any]], bool],
    ) -> tuple[int | None, str]:
        ansible_runner: Any = importlib.import_module("ansible_runner")
        common: dict[str, Any] = {
            "private_data_dir": str(runtime_path),
            "ident": str(run.run_id),
            "inventory": str(inventory_path),
            "host_pattern": "all",
            "forks": run.forks,
            "timeout": run.timeout_seconds,
            "quiet": True,
            "event_handler": event_handler,
            "cancel_callback": cancel.is_set,
            "envvars": {
                "ANSIBLE_HOST_KEY_CHECKING": "True",
                "ANSIBLE_RETRY_FILES_ENABLED": "False",
                "ANSIBLE_LOCAL_TEMP": str(runtime_path / "local-tmp"),
                "ANSIBLE_REMOTE_TEMP": "/tmp/.ops-composer-ansible",
                "ANSIBLE_SSH_ARGS": (
                    f"-o UserKnownHostsFile={runtime_path / 'known_hosts'} "
                    "-o StrictHostKeyChecking=yes -o BatchMode=no"
                ),
            },
        }
        if run.kind.value == "PLAYBOOK":
            operation = run.operation_spec
            playbook = PlaybookCatalog(self._settings.playbook_workspace).resolve(
                str(operation["playbookPath"])
            )
            raw_tags = operation.get("tags", [])
            raw_skip_tags = operation.get("skipTags", [])
            tags = raw_tags if isinstance(raw_tags, list) else []
            skip_tags = raw_skip_tags if isinstance(raw_skip_tags, list) else []
            common.update(
                {
                    "project_dir": str(self._settings.playbook_workspace),
                    "playbook": str(playbook),
                    "extravars": operation.get("extraVars", {}),
                    "tags": ",".join(str(item) for item in tags),
                    "skip_tags": ",".join(str(item) for item in skip_tags),
                }
            )
        else:
            if run.kind.value == "PING":
                module = "ansible.builtin.ping"
                module_args = ""
            else:
                mode = str(run.operation_spec["mode"])
                module = "ansible.builtin.command" if mode == "COMMAND" else "ansible.builtin.shell"
                module_args = json.dumps(
                    {"cmd": str(run.operation_spec["command"])},
                    ensure_ascii=False,
                )
            common.update({"module": module, "module_args": module_args})
        result: Any = ansible_runner.run(**common)
        return getattr(result, "rc", None), str(getattr(result, "status", "failed"))


async def _runtime_inventory(
    run: Run,
    credentials: CredentialService,
) -> tuple[dict[str, object], tuple[str, ...]]:
    inventory = copy.deepcopy(run.inventory_snapshot)
    all_value = inventory.get("all")
    if not isinstance(all_value, dict):
        raise ValueError("inventory snapshot is invalid")
    hosts_value = all_value.get("hosts")
    if not isinstance(hosts_value, dict):
        raise ValueError("inventory snapshot hosts are invalid")
    secret_values: list[str] = []
    revisions: dict[tuple[str, int], dict[str, str]] = {}
    for target in run.resolved_targets:
        credential_id = str(target["credentialId"])
        version = int(str(target["credentialVersion"]))
        cache_key = (credential_id, version)
        if cache_key not in revisions:
            revisions[cache_key] = await credentials.decrypt_revision(UUID(credential_id), version)
        secret = revisions[cache_key]
        secret_values.extend(secret.values())
        host_variables = hosts_value.get(str(target["name"]))
        if not isinstance(host_variables, dict):
            raise ValueError("inventory target snapshot is invalid")
        host_variables["ansible_password"] = secret["password"]
        become = (
            str(run.operation_spec.get("become", "CREDENTIAL_DEFAULT"))
            if run.kind.value == "COMMAND"
            else "CREDENTIAL_DEFAULT"
        )
        if become == "DISABLED":
            for key in (
                "ansible_become",
                "ansible_become_method",
                "ansible_become_user",
                "ansible_become_password",
            ):
                host_variables.pop(key, None)
        elif become == "ENABLED":
            host_variables["ansible_become"] = True
            host_variables.setdefault("ansible_become_method", "sudo")
            host_variables.setdefault("ansible_become_user", "root")
            host_variables["ansible_become_password"] = secret.get(
                "becomePassword", secret["password"]
            )
        elif host_variables.get("ansible_become"):
            host_variables["ansible_become_password"] = secret.get(
                "becomePassword", secret["password"]
            )
    return inventory, tuple(secret_values)


async def _known_hosts(run: Run, assets: AssetService) -> str:
    lines: list[str] = []
    for target in run.resolved_targets:
        host_id = UUID(str(target["hostId"]))
        keys = await assets.list_host_keys(host_id)
        if not keys:
            host_name = str(target["name"])
            raise HostKeyConfirmationRequiredError(
                f"SSH host key confirmation is required for host {host_name}",
                details={"hostId": str(host_id), "name": host_name},
            )
        address = str(target["address"])
        port = int(str(target["sshPort"]))
        marker = address if port == 22 else f"[{address}]:{port}"
        lines.extend(f"{marker} {key.algorithm} {key.public_key}" for key in keys)
    return "\n".join(lines) + "\n"


async def execute_run(
    run: Run,
    *,
    factory: UnitOfWorkFactory,
    settings: Settings,
    coordinator: WorkerCoordinator,
) -> None:
    run_service = RunService(factory, settings)
    credentials = CredentialService(
        factory,
        CredentialCipher(settings.master_key.get_secret_value(), settings.master_key_version),
    )
    assets = AssetService(factory)
    audit_service = AuditService(factory)
    try:
        _, targets = await run_service.detail(run.run_id)
        if run.kind.value == "PLAYBOOK":
            path = str(run.operation_spec["playbookPath"])
            playbook = await PlaybookCatalog(settings.playbook_workspace).get(path)
            if playbook.sha256 != run.workspace_revision:
                raise ValueError("playbook content changed after this run was created")
        inventory, secret_values = await _runtime_inventory(run, credentials)
        known_hosts = await _known_hosts(run, assets)
    except (OpsError, ValueError, KeyError) as error:
        failure_code = (
            "HOST_KEY_CONFIRMATION_REQUIRED"
            if isinstance(error, HostKeyConfirmationRequiredError)
            else error.code.upper()
            if isinstance(error, OpsError)
            else "PREPARATION_FAILED"
        )
        failure_message = (
            error.message
            if isinstance(error, HostKeyConfirmationRequiredError)
            else "run preparation failed"
        )
        await audit_service.record_best_effort(
            new_audit_event(
                AuditAction.RUN_PREPARATION_FAILED,
                AuditOutcome.FAILED,
                source=AuditSource.WORKER,
                severity=AuditSeverity.WARNING,
                run_id=run.run_id,
                worker_id=coordinator.worker_id,
                resource_type="run",
                resource_id=run.run_id,
                error_code=(error.code if isinstance(error, OpsError) else "PREPARATION_FAILED"),
                exception_type=type(error).__name__,
                failure_stage="run_preparation",
                retryable=False,
                metadata={
                    "operation_kind": run.kind.value,
                    "target_count": len(run.resolved_targets),
                },
            )
        )
        await coordinator.append_event(
            run.run_id,
            event_type="run_rejected",
            event_data={"code": failure_code, "message": failure_message},
        )
        await coordinator.finish(
            run.run_id,
            status=RunStatus.REJECTED,
            return_code=None,
            summary={},
            failure_code=failure_code,
            failure_message=failure_message,
            exception_type=type(error).__name__,
            failure_stage="run_preparation",
        )
        return

    accumulators = {target.host_name: TargetAccumulator(target=target) for target in targets}
    per_host_limit = min(
        1024 * 1024,
        max(64 * 1024, settings.max_run_output_bytes // max(1, len(targets))),
    )
    event_queue: asyncio.Queue[dict[str, object] | None] = asyncio.Queue()
    loop = asyncio.get_running_loop()
    cancel = Event()
    runtime_path: Path | None = None

    def event_handler(raw_event: dict[str, Any]) -> bool:
        sanitized = _sanitize(raw_event, secret_values)
        if isinstance(sanitized, dict):
            loop.call_soon_threadsafe(event_queue.put_nowait, sanitized)
        return True

    async def monitor(execution: asyncio.Task[tuple[int | None, str]]) -> None:
        interval = max(1.0, settings.worker_lease_seconds / 3)
        while not execution.done():
            await coordinator.heartbeat(run.run_id)
            if await coordinator.cancellation_requested(run.run_id):
                cancel.set()
            await asyncio.sleep(interval)

    try:
        with RuntimeDirectory(settings.runtime_dir, run.run_id) as runtime:
            runtime_path = runtime.path
            await audit_service.record_best_effort(
                new_audit_event(
                    AuditAction.RUNTIME_DIRECTORY_CREATED,
                    AuditOutcome.SUCCEEDED,
                    source=AuditSource.WORKER,
                    run_id=run.run_id,
                    worker_id=coordinator.worker_id,
                    resource_type="run",
                    resource_id=run.run_id,
                    metadata={"file_mode": "0700"},
                )
            )
            inventory_path = runtime.write(
                "inventory.yml",
                yaml.safe_dump(inventory, allow_unicode=True, sort_keys=True),
            )
            runtime.write("known_hosts", known_hosts)
            await coordinator.mark_running(run.run_id)
            await coordinator.append_event(run.run_id, event_type="run_started")
            execution = asyncio.create_task(
                asyncio.to_thread(
                    AnsibleExecutor(settings).run,
                    run,
                    inventory_path=inventory_path,
                    runtime_path=runtime.path,
                    cancel=cancel,
                    event_handler=event_handler,
                )
            )
            monitor_task = asyncio.create_task(monitor(execution))
            while not execution.done() or not event_queue.empty():
                if monitor_task.done() and not monitor_task.cancelled():
                    monitor_error = monitor_task.exception()
                    if monitor_error is not None:
                        cancel.set()
                        await execution
                        raise monitor_error
                try:
                    event = await asyncio.wait_for(event_queue.get(), timeout=0.25)
                except TimeoutError:
                    continue
                if event is None:
                    continue
                event_data = event.get("event_data")
                if not isinstance(event_data, dict):
                    event_data = {}
                event_type = str(event.get("event", "runner_event"))
                stdout = str(event.get("stdout") or "")
                host_name = event_data.get("host")
                accumulator = accumulators.get(str(host_name)) if host_name is not None else None
                if accumulator is not None and stdout:
                    accumulator.add_output(stdout + "\n", per_host_limit)
                if accumulator is not None:
                    if event_type == "runner_on_ok":
                        accumulator.status = RunTargetStatus.SUCCEEDED
                        result = event_data.get("res")
                        if isinstance(result, dict) and result.get("changed"):
                            accumulator.changed += 1
                    elif event_type == "runner_on_failed":
                        accumulator.status = RunTargetStatus.FAILED
                        accumulator.failed += 1
                    elif event_type == "runner_on_unreachable":
                        accumulator.status = RunTargetStatus.UNREACHABLE
                        accumulator.unreachable += 1
                    elif event_type == "runner_on_skipped":
                        accumulator.status = RunTargetStatus.SKIPPED
                safe_event_data = json.loads(
                    json.dumps(event_data, ensure_ascii=False, default=str)
                )
                await coordinator.append_event(
                    run.run_id,
                    event_type=event_type,
                    stdout=stdout or None,
                    task=(
                        str(event_data.get("task")) if event_data.get("task") is not None else None
                    ),
                    event_data=safe_event_data,
                    run_target_id=(
                        accumulator.target.run_target_id if accumulator is not None else None
                    ),
                )
            rc, runner_status = await execution
            monitor_task.cancel()
            await asyncio.gather(monitor_task, return_exceptions=True)
    except Exception as error:
        safe_message = "runner execution failed"
        await coordinator.append_event(
            run.run_id,
            event_type="runner_error",
            event_data={"message": safe_message},
        )
        await coordinator.finish(
            run.run_id,
            status=RunStatus.FAILED,
            return_code=None,
            summary={},
            failure_code="RUNNER_ERROR",
            failure_message=safe_message,
            exception_type=type(error).__name__,
            failure_stage="runner_execution",
        )
        return
    finally:
        if runtime_path is not None:
            cleaned = not runtime_path.exists()
            await audit_service.record_best_effort(
                new_audit_event(
                    AuditAction.RUNTIME_DIRECTORY_CLEANED,
                    AuditOutcome.SUCCEEDED if cleaned else AuditOutcome.FAILED,
                    source=AuditSource.WORKER,
                    severity=(
                        AuditSeverity.INFO if cleaned else AuditSeverity.ERROR
                    ),
                    run_id=run.run_id,
                    worker_id=coordinator.worker_id,
                    resource_type="run",
                    resource_id=run.run_id,
                    error_code=None if cleaned else "runtime_cleanup_failed",
                    failure_stage=None if cleaned else "runtime_cleanup",
                    retryable=False if not cleaned else None,
                )
            )

    success_count = 0
    failure_count = 0
    for accumulator in accumulators.values():
        if cancel.is_set():
            accumulator.status = RunTargetStatus.CANCELED
        elif accumulator.status is RunTargetStatus.RUNNING:
            accumulator.status = RunTargetStatus.SUCCEEDED if rc == 0 else RunTargetStatus.FAILED
        if accumulator.status in {RunTargetStatus.SUCCEEDED, RunTargetStatus.SKIPPED}:
            success_count += 1
        else:
            failure_count += 1
        await coordinator.finish_target(
            run.run_id,
            accumulator.target.run_target_id,
            host_id=accumulator.target.host_id,
            host_name=accumulator.target.host_name,
            status=accumulator.status,
            return_code=rc,
            stdout="".join(accumulator.chunks),
            stderr="",
            result={},
            output_truncated=accumulator.truncated,
            changed_count=accumulator.changed,
            failed_count=accumulator.failed,
            unreachable_count=accumulator.unreachable,
        )
    if cancel.is_set():
        final_status = RunStatus.CANCELED
    elif runner_status.casefold() in {"timeout", "timed_out"}:
        final_status = RunStatus.TIMED_OUT
    elif failure_count and success_count:
        final_status = RunStatus.PARTIAL
    elif failure_count or rc not in {0, None}:
        final_status = RunStatus.FAILED
    else:
        final_status = RunStatus.SUCCEEDED
    await coordinator.finish(
        run.run_id,
        status=final_status,
        return_code=rc,
        summary={
            "total": len(accumulators),
            "succeeded": success_count,
            "failed": failure_count,
        },
    )


async def _purge_expired_audit(
    factory: UnitOfWorkFactory,
    settings: Settings,
    *,
    worker_id: str,
) -> None:
    service = AuditService(factory)
    purged = 0
    acquired = True
    try:
        while True:
            acquired, count = await service.purge_batch(settings.audit_retention_days)
            if not acquired or count == 0:
                break
            purged += count
    except Exception as error:
        log_event(
            AuditAction.AUDIT_RETENTION_PURGED,
            AuditOutcome.FAILED,
            source=AuditSource.WORKER,
            severity=AuditSeverity.ERROR,
            message="audit retention cleanup failed",
            worker_id=worker_id,
            error_code="audit_retention_failed",
            exception_type=type(error).__name__,
            failure_stage="audit_retention",
            retryable=True,
            metadata=safe_exception_fields(error),
            exc_info=True,
        )
        return
    if purged:
        await service.record_best_effort(
            new_audit_event(
                AuditAction.AUDIT_RETENTION_PURGED,
                AuditOutcome.SUCCEEDED,
                source=AuditSource.WORKER,
                worker_id=worker_id,
                metadata={
                    "purged_count": purged,
                    "retention_days": settings.audit_retention_days,
                },
            )
        )
    elif not acquired:
        log_event(
            AuditAction.AUDIT_RETENTION_PURGED,
            AuditOutcome.NOOP,
            source=AuditSource.WORKER,
            severity=AuditSeverity.DEBUG,
            message="audit retention cleanup lock is busy",
            worker_id=worker_id,
        )


async def run_worker(settings: Settings) -> None:
    configure_logging(
        service="worker",
        environment=settings.app_env.value,
        level=settings.log_level.value,
    )
    worker_id = (
        os.environ.get("OPS_COMPOSER_WORKER_ID")
        or f"{socket.gethostname()}-{os.getpid()}-{uuid.uuid4().hex[:8]}"
    )
    log_event(
        AuditAction.WORKER_STARTED,
        AuditOutcome.STARTED,
        source=AuditSource.WORKER,
        message="worker process is starting",
        worker_id=worker_id,
    )
    pool = create_pool(settings.database_url)
    try:
        await pool.open()
    except Exception as error:
        log_event(
            AuditAction.DATABASE_UNAVAILABLE,
            AuditOutcome.FAILED,
            source=AuditSource.WORKER,
            severity=AuditSeverity.CRITICAL,
            message="worker could not open the PostgreSQL connection pool",
            worker_id=worker_id,
            failure_stage="database_pool_open",
            retryable=True,
            exception_type=type(error).__name__,
            metadata=safe_exception_fields(error),
            exc_info=True,
        )
        raise
    factory: UnitOfWorkFactory | None = None
    try:
        with log_context(worker_id=worker_id, correlation_id=worker_id):
            try:
                async with pool.connection() as connection:
                    await MigrationRunner(connection, MIGRATIONS).validate_current()
            except Exception as error:
                log_event(
                    AuditAction.MIGRATION_VALIDATION_FAILED,
                    AuditOutcome.FAILED,
                    source=AuditSource.WORKER,
                    severity=AuditSeverity.CRITICAL,
                    message="worker migration validation failed",
                    failure_stage="migration_validation",
                    retryable=False,
                    exception_type=type(error).__name__,
                    metadata=safe_exception_fields(error),
                    exc_info=True,
                )
                raise
            factory = UnitOfWorkFactory(pool)
            cipher = CredentialCipher(
                settings.master_key.get_secret_value(), settings.master_key_version
            )
            try:
                await CredentialService(factory, cipher).ensure_master_key()
            except Exception as error:
                await AuditService(factory).record_best_effort(
                    new_audit_event(
                        AuditAction.MASTER_KEY_VALIDATION_FAILED,
                        AuditOutcome.FAILED,
                        source=AuditSource.WORKER,
                        severity=AuditSeverity.CRITICAL,
                        worker_id=worker_id,
                        failure_stage="master_key_validation",
                        retryable=False,
                        exception_type=type(error).__name__,
                        metadata=safe_exception_fields(error),
                    )
                )
                raise
            orphan_count = cleanup_orphan_runtime(settings.runtime_dir)
            if orphan_count:
                await AuditService(factory).record_best_effort(
                    new_audit_event(
                        AuditAction.RUNTIME_DIRECTORY_CLEANED,
                        AuditOutcome.SUCCEEDED,
                        source=AuditSource.WORKER,
                        worker_id=worker_id,
                        metadata={"orphan_count": orphan_count},
                    )
                )
            coordinator = WorkerCoordinator(factory, settings, worker_id)
            await coordinator.recover_stale()
            await _purge_expired_audit(factory, settings, worker_id=worker_id)
            await AuditService(factory).record_best_effort(
                new_audit_event(
                    AuditAction.WORKER_READY,
                    AuditOutcome.SUCCEEDED,
                    source=AuditSource.WORKER,
                    worker_id=worker_id,
                )
            )
            next_cleanup = time.monotonic() + 86_400
            failure_count = 0
            first_failure_at: float | None = None
            last_failure_log_at = 0.0
            while True:
                active_run: Run | None = None
                try:
                    if time.monotonic() >= next_cleanup:
                        await _purge_expired_audit(factory, settings, worker_id=worker_id)
                        next_cleanup = time.monotonic() + 86_400
                    await coordinator.heartbeat()
                    active_run = await coordinator.claim()
                    if active_run is None:
                        await asyncio.sleep(settings.worker_poll_interval_seconds)
                    else:
                        with log_context(
                            run_id=active_run.run_id,
                            correlation_id=str(active_run.run_id),
                        ):
                            await execute_run(
                                active_run,
                                factory=factory,
                                settings=settings,
                                coordinator=coordinator,
                            )
                    if first_failure_at is not None:
                        elapsed_ms = round((time.monotonic() - first_failure_at) * 1000, 3)
                        await AuditService(factory).record_best_effort(
                            new_audit_event(
                                AuditAction.DATABASE_RECOVERED,
                                AuditOutcome.SUCCEEDED,
                                source=AuditSource.WORKER,
                                worker_id=worker_id,
                                duration_ms=elapsed_ms,
                                metadata={"failure_count": failure_count},
                            )
                        )
                        failure_count = 0
                        first_failure_at = None
                except asyncio.CancelledError:
                    raise
                except Exception as error:
                    now = time.monotonic()
                    failure_count += 1
                    if first_failure_at is None:
                        first_failure_at = now
                    database_error = bool(getattr(error, "sqlstate", None)) or any(
                        token in type(error).__name__.casefold()
                        for token in ("database", "operational", "pool", "connection")
                    )
                    if now - last_failure_log_at >= 60 or failure_count == 1:
                        log_event(
                            (
                                AuditAction.DATABASE_UNAVAILABLE
                                if database_error
                                else AuditAction.WORKER_LOOP_FAILED
                            ),
                            AuditOutcome.FAILED,
                            source=AuditSource.WORKER,
                            severity=AuditSeverity.ERROR,
                            message="worker loop iteration failed",
                            worker_id=worker_id,
                            run_id=active_run.run_id if active_run is not None else None,
                            failure_stage="worker_loop",
                            retryable=True,
                            exception_type=type(error).__name__,
                            metadata={
                                **safe_exception_fields(error),
                                "failure_count": failure_count,
                            },
                            exc_info=True,
                        )
                        last_failure_log_at = now
                    if active_run is not None:
                        try:
                            await coordinator.finish(
                                active_run.run_id,
                                status=RunStatus.INTERRUPTED,
                                return_code=None,
                                summary={},
                                failure_code="WORKER_LOOP_ERROR",
                                failure_message="worker loop failed during execution",
                                exception_type=type(error).__name__,
                                failure_stage="worker_loop",
                            )
                        except Exception as finish_error:
                            log_event(
                                AuditAction.RUN_INTERRUPTED,
                                AuditOutcome.FAILED,
                                source=AuditSource.WORKER,
                                severity=AuditSeverity.CRITICAL,
                                message="worker could not persist interrupted run state",
                                worker_id=worker_id,
                                run_id=active_run.run_id,
                                failure_stage="run_interruption_persistence",
                                retryable=True,
                                exception_type=type(finish_error).__name__,
                                metadata=safe_exception_fields(finish_error),
                                exc_info=True,
                            )
                            raise
                    await asyncio.sleep(min(30.0, 2.0 ** min(failure_count, 4)))
    finally:
        if factory is not None:
            try:
                await AuditService(factory).record_best_effort(
                    new_audit_event(
                        AuditAction.WORKER_STOPPED,
                        AuditOutcome.SUCCEEDED,
                        source=AuditSource.WORKER,
                        worker_id=worker_id,
                    )
                )
            except asyncio.CancelledError:
                log_event(
                    AuditAction.WORKER_STOPPED,
                    AuditOutcome.SUCCEEDED,
                    source=AuditSource.WORKER,
                    worker_id=worker_id,
                )
        await pool.close()
