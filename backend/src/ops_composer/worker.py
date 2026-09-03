from __future__ import annotations

import asyncio
import copy
import importlib
import json
import os
import shutil
import socket
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
from ops_composer.domain.errors import OpsError
from ops_composer.domain.ops import Run, RunStatus, RunTarget, RunTargetStatus
from ops_composer.services.assets import AssetService, CredentialService
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


def cleanup_orphan_runtime(root: Path) -> None:
    resolved = root.resolve()
    if not resolved.is_dir():
        return
    for child in resolved.iterdir():
        try:
            UUID(child.name)
        except ValueError:
            continue
        if child.is_dir() and child.parent == resolved:
            shutil.rmtree(child)


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
            raise ValueError(f"host {target['name']} has no confirmed SSH host key")
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
        await coordinator.append_event(
            run.run_id,
            event_type="run_rejected",
            event_data={"code": "PREPARATION_FAILED", "message": str(error)},
        )
        await coordinator.finish(
            run.run_id,
            status=RunStatus.REJECTED,
            return_code=None,
            summary={},
            failure_code="PREPARATION_FAILED",
            failure_message=str(error),
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
        safe_message = redact_secrets(str(error), secret_values)
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
        )
        return

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
            accumulator.target.run_target_id,
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


async def run_worker(settings: Settings) -> None:
    pool = create_pool(settings.database_url)
    await pool.open()
    try:
        async with pool.connection() as connection:
            await MigrationRunner(connection, MIGRATIONS).validate_current()
        factory = UnitOfWorkFactory(pool)
        cipher = CredentialCipher(
            settings.master_key.get_secret_value(), settings.master_key_version
        )
        await CredentialService(factory, cipher).ensure_master_key()
        cleanup_orphan_runtime(settings.runtime_dir)
        worker_id = (
            os.environ.get("OPS_COMPOSER_WORKER_ID")
            or f"{socket.gethostname()}-{os.getpid()}-{uuid.uuid4().hex[:8]}"
        )
        coordinator = WorkerCoordinator(factory, settings, worker_id)
        await coordinator.recover_stale()
        while True:
            await coordinator.heartbeat()
            run = await coordinator.claim()
            if run is None:
                await asyncio.sleep(settings.worker_poll_interval_seconds)
                continue
            await execute_run(run, factory=factory, settings=settings, coordinator=coordinator)
    finally:
        await pool.close()
