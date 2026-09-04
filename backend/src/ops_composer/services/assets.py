from __future__ import annotations

import asyncio
import base64
import hashlib
import ipaddress
import re
from typing import Protocol
from uuid import UUID, uuid4

from ops_composer.domain.audit import (
    AuditAction,
    AuditOutcome,
    AuditSeverity,
    AuditSource,
)
from ops_composer.domain.base import utc_now
from ops_composer.domain.errors import (
    ConflictError,
    HostKeyChangedError,
    NotFoundError,
    ValidationError,
)
from ops_composer.domain.ops import (
    Credential,
    CredentialRevision,
    CredentialType,
    Host,
    HostGroup,
    HostKey,
    ResolvedHost,
    TargetKind,
)
from ops_composer.services.audit import AuditService, emit_audit_event, new_audit_event
from ops_composer.services.crypto import CredentialCipher
from ops_composer.uow.factory import UnitOfWorkFactory

HOST_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
GROUP_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
FQDN = re.compile(
    r"^(?=.{1,253}\.?$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$"
)


class _HostLister(Protocol):
    async def list_hosts(self) -> tuple[Host, ...]: ...


RESERVED_VARIABLES = frozenset(
    {
        "ansible_password",
        "ansible_become_password",
        "ansible_private_key_file",
        "ansible_ssh_common_args",
        "ansible_connection",
        "ansible_host",
        "ansible_port",
        "ansible_user",
    }
)


def _validate_variables(variables: dict[str, object]) -> None:
    forbidden = sorted(RESERVED_VARIABLES & variables.keys())
    if forbidden:
        raise ValidationError(
            "reserved Ansible connection variables are not allowed",
            details={"fields": forbidden},
        )


def _validate_address(address: str) -> str:
    normalized = address.strip()
    try:
        ipaddress.ip_address(normalized)
    except ValueError as error:
        if not FQDN.fullmatch(normalized):
            raise ValidationError("address must be an IPv4, IPv6, or FQDN") from error
    return normalized


class CredentialService:
    def __init__(
        self,
        unit_of_work_factory: UnitOfWorkFactory,
        cipher: CredentialCipher,
        *,
        audit_source: AuditSource = AuditSource.API,
    ) -> None:
        self._unit_of_work_factory = unit_of_work_factory
        self._cipher = cipher
        self._audit_source = audit_source

    async def list(self) -> tuple[Credential, ...]:
        async with self._unit_of_work_factory() as unit_of_work:
            return await unit_of_work.assets.list_credentials()

    async def ensure_master_key(self) -> None:
        event = None
        async with self._unit_of_work_factory() as unit_of_work:
            check = await unit_of_work.assets.get_setting("encryption.master-key-check")
            if check is None:
                await unit_of_work.assets.put_setting(
                    "encryption.master-key-check",
                    {
                        "version": self._cipher.key_version,
                        "envelope": self._cipher.encrypt_check(),
                    },
                    utc_now(),
                )
                event = new_audit_event(
                    AuditAction.MASTER_KEY_INITIALIZED,
                    AuditOutcome.SUCCEEDED,
                    source=AuditSource.SYSTEM,
                    metadata={"key_version": self._cipher.key_version},
                )
            else:
                envelope = check.get("envelope")
                version = check.get("version")
                if not isinstance(envelope, str) or version != self._cipher.key_version:
                    raise ValueError(
                        "master-key check metadata is invalid or uses another key version"
                    )
                self._cipher.validate_check(envelope)
                event = new_audit_event(
                    AuditAction.MASTER_KEY_VALIDATED,
                    AuditOutcome.SUCCEEDED,
                    source=AuditSource.SYSTEM,
                    metadata={"key_version": self._cipher.key_version},
                )
            await unit_of_work.audit.append(event)
        emit_audit_event(event)

    async def get(self, credential_id: UUID) -> Credential:
        async with self._unit_of_work_factory() as unit_of_work:
            credential = await unit_of_work.assets.get_credential(credential_id)
            if credential is None:
                raise NotFoundError("credential not found")
            return credential

    async def create(
        self,
        *,
        name: str,
        username: str,
        password: str,
        become_password: str | None,
        become_enabled: bool,
        become_method: str,
        become_user: str,
        description: str,
    ) -> Credential:
        if not name.strip() or not username.strip() or not password:
            raise ValidationError("name, username, and password are required")
        if become_method not in {"sudo", "su", "doas"}:
            raise ValidationError("unsupported privilege escalation method")
        now = utc_now()
        credential_id = uuid4()
        public_config: dict[str, object] = {
            "becomeEnabled": become_enabled,
            "becomeMethod": become_method,
            "becomeUser": become_user.strip() or "root",
        }
        credential = Credential(
            credential_id=credential_id,
            name=name.strip(),
            credential_type=CredentialType.PASSWORD,
            username=username.strip(),
            public_config=public_config,
            current_version=1,
            enabled=True,
            description=description.strip(),
            created_at=now,
            updated_at=now,
        )
        secret = {"password": password}
        if become_password:
            secret["becomePassword"] = become_password
        revision = CredentialRevision(
            credential_id=credential_id,
            version=1,
            encrypted_secret=self._cipher.encrypt(credential_id, 1, secret),
            encryption_key_version=self._cipher.key_version,
            created_at=now,
        )
        event = new_audit_event(
            AuditAction.CREDENTIAL_CREATED,
            AuditOutcome.SUCCEEDED,
            source=self._audit_source,
            resource_type="credential",
            resource_id=credential_id,
            metadata={
                "credential_name": credential.name,
                "credential_type": credential.credential_type.value,
                "version": 1,
                "become_enabled": become_enabled,
            },
        )
        async with self._unit_of_work_factory() as unit_of_work:
            created = await unit_of_work.assets.add_credential(credential, revision)
            await unit_of_work.audit.append(event)
        emit_audit_event(event)
        return created

    async def rotate(
        self,
        credential_id: UUID,
        *,
        password: str,
        become_password: str | None,
    ) -> Credential:
        if not password:
            raise ValidationError("password is required")
        async with self._unit_of_work_factory() as unit_of_work:
            credential = await unit_of_work.assets.get_credential(credential_id, for_update=True)
            if credential is None:
                raise NotFoundError("credential not found")
            version = credential.current_version + 1
            secret = {"password": password}
            if become_password:
                secret["becomePassword"] = become_password
            now = utc_now()
            revision = CredentialRevision(
                credential_id=credential_id,
                version=version,
                encrypted_secret=self._cipher.encrypt(credential_id, version, secret),
                encryption_key_version=self._cipher.key_version,
                created_at=now,
            )
            rotated = await unit_of_work.assets.rotate_credential(credential_id, revision, now)
            if rotated is None:
                raise NotFoundError("credential not found")
            event = new_audit_event(
                AuditAction.CREDENTIAL_ROTATED,
                AuditOutcome.SUCCEEDED,
                source=self._audit_source,
                resource_type="credential",
                resource_id=credential_id,
                metadata={"credential_name": rotated.name, "version": version},
            )
            await unit_of_work.audit.append(event)
        emit_audit_event(event)
        return rotated

    async def decrypt_revision(self, credential_id: UUID, version: int) -> dict[str, str]:
        async with self._unit_of_work_factory() as unit_of_work:
            revision = await unit_of_work.assets.get_credential_revision(credential_id, version)
            if revision is None:
                raise NotFoundError("credential revision not found")
            if revision.encryption_key_version != self._cipher.key_version:
                raise ValidationError(
                    "credential uses an unavailable master-key version",
                    details={"keyVersion": revision.encryption_key_version},
                )
            return self._cipher.decrypt(
                revision.credential_id, revision.version, revision.encrypted_secret
            )

    async def delete(self, credential_id: UUID) -> None:
        event = None
        async with self._unit_of_work_factory() as unit_of_work:
            credential = await unit_of_work.assets.get_credential(credential_id)
            if not await unit_of_work.assets.delete_credential(credential_id, utc_now()):
                raise ConflictError("credential is missing or is still assigned to a host")
            event = new_audit_event(
                AuditAction.CREDENTIAL_DELETED,
                AuditOutcome.SUCCEEDED,
                source=self._audit_source,
                resource_type="credential",
                resource_id=credential_id,
                metadata={
                    "credential_name": credential.name if credential is not None else None,
                    "version": credential.current_version if credential is not None else None,
                },
            )
            await unit_of_work.audit.append(event)
        emit_audit_event(event)


class AssetService:
    def __init__(
        self,
        unit_of_work_factory: UnitOfWorkFactory,
        *,
        audit_source: AuditSource = AuditSource.API,
    ) -> None:
        self._unit_of_work_factory = unit_of_work_factory
        self._audit_source = audit_source

    async def list_hosts(self) -> tuple[Host, ...]:
        async with self._unit_of_work_factory() as unit_of_work:
            return await unit_of_work.assets.list_hosts()

    async def get_host(self, host_id: UUID) -> Host:
        async with self._unit_of_work_factory() as unit_of_work:
            host = await unit_of_work.assets.get_host(host_id)
            if host is None:
                raise NotFoundError("host not found")
            return host

    async def create_host(
        self,
        *,
        name: str,
        address: str,
        ssh_port: int,
        credential_id: UUID,
        python_interpreter: str | None,
        enabled: bool,
        description: str,
        variables: dict[str, object],
    ) -> Host:
        if not HOST_NAME.fullmatch(name):
            raise ValidationError(
                "host name may only contain letters, digits, dot, dash, and underscore"
            )
        _validate_variables(variables)
        now = utc_now()
        host = Host(
            host_id=uuid4(),
            name=name,
            address=_validate_address(address),
            ssh_port=ssh_port,
            credential_id=credential_id,
            python_interpreter=python_interpreter or "/usr/bin/python3",
            enabled=enabled,
            description=description,
            variables=variables,
            version=1,
            created_at=now,
            updated_at=now,
        )
        event = new_audit_event(
            AuditAction.HOST_CREATED,
            AuditOutcome.SUCCEEDED,
            source=self._audit_source,
            resource_type="host",
            resource_id=host.host_id,
            metadata={
                "host_name": host.name,
                "ssh_port": host.ssh_port,
                "credential_id": host.credential_id,
                "enabled": host.enabled,
            },
        )
        async with self._unit_of_work_factory() as unit_of_work:
            credential = await unit_of_work.assets.get_credential(credential_id)
            if credential is None or not credential.enabled:
                raise ValidationError("credential is missing or disabled")
            created = await unit_of_work.assets.add_host(host)
            await unit_of_work.audit.append(event)
        emit_audit_event(event)
        return created

    async def update_host(self, host_id: UUID, *, expected_version: int, **changes: object) -> Host:
        event = None
        async with self._unit_of_work_factory() as unit_of_work:
            current = await unit_of_work.assets.get_host(host_id)
            if current is None:
                raise NotFoundError("host not found")
            data = current.model_dump(mode="python")
            data.update(changes)
            data["host_id"] = host_id
            data["updated_at"] = utc_now()
            variables = data.get("variables")
            if not isinstance(variables, dict):
                raise ValidationError("variables must be an object")
            _validate_variables(variables)
            name = str(data["name"])
            if not HOST_NAME.fullmatch(name):
                raise ValidationError("invalid host name")
            data["address"] = _validate_address(str(data["address"]))
            credential_id = UUID(str(data["credential_id"]))
            credential = await unit_of_work.assets.get_credential(credential_id)
            if credential is None or not credential.enabled:
                raise ValidationError("credential is missing or disabled")
            updated = await unit_of_work.assets.update_host(
                Host.model_validate(data), expected_version
            )
            if updated is None:
                raise ConflictError("host was modified by another request")
            event = new_audit_event(
                AuditAction.HOST_UPDATED,
                AuditOutcome.SUCCEEDED,
                source=self._audit_source,
                resource_type="host",
                resource_id=host_id,
                metadata={
                    "host_name": updated.name,
                    "ssh_port": updated.ssh_port,
                    "version_before": expected_version,
                    "version_after": updated.version,
                    "changed_fields": sorted(changes),
                },
            )
            await unit_of_work.audit.append(event)
        emit_audit_event(event)
        return updated

    async def delete_host(self, host_id: UUID) -> None:
        event = None
        async with self._unit_of_work_factory() as unit_of_work:
            host = await unit_of_work.assets.get_host(host_id)
            if not await unit_of_work.assets.delete_host(host_id):
                raise ConflictError("host is missing or referenced by execution history")
            event = new_audit_event(
                AuditAction.HOST_DELETED,
                AuditOutcome.SUCCEEDED,
                source=self._audit_source,
                resource_type="host",
                resource_id=host_id,
                metadata={"host_name": host.name if host is not None else None},
            )
            await unit_of_work.audit.append(event)
        emit_audit_event(event)

    async def list_groups(self) -> tuple[HostGroup, ...]:
        async with self._unit_of_work_factory() as unit_of_work:
            return await unit_of_work.assets.list_groups()

    async def create_group(
        self,
        *,
        name: str,
        description: str,
        variables: dict[str, object],
        host_ids: tuple[UUID, ...],
    ) -> HostGroup:
        if not GROUP_NAME.fullmatch(name):
            raise ValidationError("invalid group name")
        _validate_variables(variables)
        now = utc_now()
        group = HostGroup(
            group_id=uuid4(),
            name=name,
            description=description,
            variables=variables,
            host_ids=(),
            created_at=now,
            updated_at=now,
        )
        event = new_audit_event(
            AuditAction.GROUP_CREATED,
            AuditOutcome.SUCCEEDED,
            source=self._audit_source,
            resource_type="group",
            resource_id=group.group_id,
            metadata={"group_name": group.name, "host_count": len(host_ids)},
        )
        async with self._unit_of_work_factory() as unit_of_work:
            await self._validate_host_ids(unit_of_work.assets, host_ids)
            created = await unit_of_work.assets.add_group(group)
            await unit_of_work.assets.replace_group_members(created.group_id, host_ids, now)
            result = created.model_copy(update={"host_ids": host_ids})
            await unit_of_work.audit.append(event)
        emit_audit_event(event)
        return result

    async def update_group(
        self,
        group_id: UUID,
        *,
        name: str,
        description: str,
        variables: dict[str, object],
        host_ids: tuple[UUID, ...],
    ) -> HostGroup:
        if not GROUP_NAME.fullmatch(name):
            raise ValidationError("invalid group name")
        _validate_variables(variables)
        event = None
        async with self._unit_of_work_factory() as unit_of_work:
            current = await unit_of_work.assets.get_group(group_id)
            if current is None:
                raise NotFoundError("group not found")
            await self._validate_host_ids(unit_of_work.assets, host_ids)
            updated = await unit_of_work.assets.update_group(
                current.model_copy(
                    update={
                        "name": name,
                        "description": description,
                        "variables": variables,
                        "host_ids": (),
                        "updated_at": utc_now(),
                    }
                )
            )
            if updated is None:
                raise NotFoundError("group not found")
            await unit_of_work.assets.replace_group_members(group_id, host_ids, updated.updated_at)
            result = updated.model_copy(update={"host_ids": host_ids})
            event = new_audit_event(
                AuditAction.GROUP_UPDATED,
                AuditOutcome.SUCCEEDED,
                source=self._audit_source,
                resource_type="group",
                resource_id=group_id,
                metadata={
                    "group_name": result.name,
                    "host_count_before": len(current.host_ids),
                    "host_count_after": len(host_ids),
                    "membership_changed": set(current.host_ids) != set(host_ids),
                },
            )
            await unit_of_work.audit.append(event)
        emit_audit_event(event)
        return result

    @staticmethod
    async def _validate_host_ids(repository: _HostLister, host_ids: tuple[UUID, ...]) -> None:
        if len(set(host_ids)) != len(host_ids):
            raise ValidationError("group membership contains duplicate hosts")
        available = {host.host_id for host in await repository.list_hosts()}
        missing = sorted(str(host_id) for host_id in set(host_ids) - available)
        if missing:
            raise ValidationError("group contains unknown hosts", details={"hostIds": missing})

    async def delete_group(self, group_id: UUID) -> None:
        event = None
        async with self._unit_of_work_factory() as unit_of_work:
            group = await unit_of_work.assets.get_group(group_id)
            if not await unit_of_work.assets.delete_group(group_id):
                raise NotFoundError("group not found")
            event = new_audit_event(
                AuditAction.GROUP_DELETED,
                AuditOutcome.SUCCEEDED,
                source=self._audit_source,
                resource_type="group",
                resource_id=group_id,
                metadata={"group_name": group.name if group is not None else None},
            )
            await unit_of_work.audit.append(event)
        emit_audit_event(event)

    async def resolve(
        self,
        *,
        target_kind: TargetKind,
        host_ids: tuple[UUID, ...] = (),
        group_id: UUID | None = None,
    ) -> tuple[ResolvedHost, ...]:
        async with self._unit_of_work_factory() as unit_of_work:
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

    async def list_host_keys(self, host_id: UUID) -> tuple[HostKey, ...]:
        async with self._unit_of_work_factory() as unit_of_work:
            if await unit_of_work.assets.get_host(host_id) is None:
                raise NotFoundError("host not found")
            return await unit_of_work.assets.list_host_keys(host_id)

    async def scan_host_keys(self, host_id: UUID) -> tuple[dict[str, str], ...]:
        host = await self.get_host(host_id)
        audit = AuditService(self._unit_of_work_factory)
        await audit.record_best_effort(
            new_audit_event(
                AuditAction.HOST_KEY_SCAN_STARTED,
                AuditOutcome.STARTED,
                source=self._audit_source,
                resource_type="host",
                resource_id=host_id,
                metadata={"host_name": host.name, "ssh_port": host.ssh_port},
            )
        )
        try:
            process = await asyncio.create_subprocess_exec(
                "ssh-keyscan",
                "-T",
                "5",
                "-p",
                str(host.ssh_port),
                host.address,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(process.communicate(), timeout=8)
        except (FileNotFoundError, TimeoutError) as error:
            await audit.record_best_effort(
                new_audit_event(
                    AuditAction.HOST_KEY_SCAN_FAILED,
                    AuditOutcome.FAILED,
                    source=self._audit_source,
                    severity=AuditSeverity.WARNING,
                    resource_type="host",
                    resource_id=host_id,
                    error_code="host_key_scan_failed",
                    exception_type=type(error).__name__,
                    failure_stage="ssh_keyscan",
                    retryable=True,
                    metadata={"host_name": host.name, "ssh_port": host.ssh_port},
                )
            )
            raise ValidationError("SSH host-key scan failed") from error
        if process.returncode != 0 or not stdout:
            await audit.record_best_effort(
                new_audit_event(
                    AuditAction.HOST_KEY_SCAN_FAILED,
                    AuditOutcome.FAILED,
                    source=self._audit_source,
                    severity=AuditSeverity.WARNING,
                    resource_type="host",
                    resource_id=host_id,
                    error_code="host_key_scan_empty",
                    failure_stage="ssh_keyscan",
                    retryable=True,
                    metadata={
                        "host_name": host.name,
                        "ssh_port": host.ssh_port,
                        "return_code": process.returncode,
                    },
                )
            )
            raise ValidationError("SSH host-key scan returned no keys")
        keys: dict[str, dict[str, str]] = {}
        for line in stdout.decode("utf-8", errors="replace").splitlines():
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) < 3:
                continue
            algorithm, public_key = parts[1], parts[2]
            try:
                digest = hashlib.sha256(base64.b64decode(public_key)).digest()
            except ValueError:
                continue
            fingerprint = "SHA256:" + base64.b64encode(digest).decode().rstrip("=")
            keys[algorithm] = {
                "algorithm": algorithm,
                "publicKey": public_key,
                "fingerprint": fingerprint,
            }
        if not keys:
            await audit.record_best_effort(
                new_audit_event(
                    AuditAction.HOST_KEY_SCAN_FAILED,
                    AuditOutcome.FAILED,
                    source=self._audit_source,
                    severity=AuditSeverity.WARNING,
                    resource_type="host",
                    resource_id=host_id,
                    error_code="host_key_scan_unusable",
                    failure_stage="host_key_parse",
                    retryable=False,
                    metadata={"host_name": host.name, "ssh_port": host.ssh_port},
                )
            )
            raise ValidationError("SSH host-key scan returned no usable keys")
        result = tuple(keys[name] for name in sorted(keys))
        await audit.record_best_effort(
            new_audit_event(
                AuditAction.HOST_KEY_SCAN_SUCCEEDED,
                AuditOutcome.SUCCEEDED,
                source=self._audit_source,
                resource_type="host",
                resource_id=host_id,
                metadata={
                    "host_name": host.name,
                    "ssh_port": host.ssh_port,
                    "key_count": len(result),
                    "algorithms": sorted(keys),
                },
            )
        )
        return result

    async def confirm_host_key(
        self, host_id: UUID, *, algorithm: str, fingerprint: str, user_id: UUID
    ) -> HostKey:
        scanned = await self.scan_host_keys(host_id)
        match = next(
            (
                item
                for item in scanned
                if item["algorithm"] == algorithm and item["fingerprint"] == fingerprint
            ),
            None,
        )
        if match is None:
            error = HostKeyChangedError(
                "host key changed between scan and confirmation"
            )
            await AuditService(self._unit_of_work_factory).record_best_effort(
                new_audit_event(
                    AuditAction.HOST_KEY_CHANGED,
                    AuditOutcome.DENIED,
                    source=self._audit_source,
                    severity=AuditSeverity.WARNING,
                    actor_user_id=user_id,
                    resource_type="host",
                    resource_id=host_id,
                    error_code="host_key_changed",
                    failure_stage="host_key_confirmation",
                    retryable=False,
                    metadata={"algorithm": algorithm, "fingerprint": fingerprint},
                )
            )
            error.audit_recorded = True
            raise error
        host_key = HostKey(
            host_id=host_id,
            algorithm=algorithm,
            public_key=match["publicKey"],
            fingerprint=fingerprint,
            trusted_by=user_id,
            trusted_at=utc_now(),
        )
        event = new_audit_event(
            AuditAction.HOST_KEY_CONFIRMED,
            AuditOutcome.SUCCEEDED,
            source=self._audit_source,
            actor_user_id=user_id,
            resource_type="host",
            resource_id=host_id,
            metadata={"algorithm": algorithm, "fingerprint": fingerprint},
        )
        async with self._unit_of_work_factory() as unit_of_work:
            result = await unit_of_work.assets.upsert_host_key(host_key)
            await unit_of_work.audit.append(event)
        emit_audit_event(event)
        return result
