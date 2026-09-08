from __future__ import annotations

from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Header, Response, status
from pydantic import Field, SecretStr

from ops_composer.api.dependencies import UnitOfWorkFactoryDep
from ops_composer.api.models import StrictApiModel
from ops_composer.auth.api import CurrentSessionDep, UnsafeSessionDep
from ops_composer.auth.models import Permission
from ops_composer.auth.service import require_permission, require_recent_reauthentication
from ops_composer.domain.ops import (
    Credential,
    CredentialType,
    Host,
    HostGroup,
    HostKey,
    TargetKind,
)
from ops_composer.services.assets import AssetService, CredentialService
from ops_composer.services.crypto import CredentialCipher, build_master_keyring
from ops_composer.services.inventory import build_inventory, render_inventory
from ops_composer.settings import get_settings

router = APIRouter(prefix="/api/v1", tags=["inventory"])


def _assets(factory: UnitOfWorkFactoryDep) -> AssetService:
    return AssetService(factory)


def _credentials(factory: UnitOfWorkFactoryDep) -> CredentialService:
    settings = get_settings()
    keyring = build_master_keyring(
        keyring_file=settings.master_keyring_file,
        fallback_key=settings.master_key.get_secret_value(),
        fallback_version=settings.master_key_version,
    )
    return CredentialService(
        factory,
        CredentialCipher(keyring),
    )


class CredentialCreateRequest(StrictApiModel):
    credential_type: Literal[CredentialType.PASSWORD] = CredentialType.PASSWORD
    name: str = Field(min_length=1, max_length=128)
    username: str = Field(min_length=1, max_length=128)
    password: SecretStr = Field(min_length=1, max_length=4096, repr=False)
    become_password: SecretStr | None = Field(default=None, max_length=4096, repr=False)
    become_enabled: bool = False
    become_method: str = Field(default="sudo", max_length=32)
    become_user: str = Field(default="root", max_length=128)
    description: str = Field(default="", max_length=1024)


class CredentialRotateRequest(StrictApiModel):
    credential_type: Literal[CredentialType.PASSWORD] = CredentialType.PASSWORD
    password: SecretStr = Field(min_length=1, max_length=4096, repr=False)
    become_password: SecretStr | None = Field(default=None, max_length=4096, repr=False)


class SshPrivateKeyCredentialCreateRequest(StrictApiModel):
    credential_type: Literal[CredentialType.SSH_PRIVATE_KEY]
    name: str = Field(min_length=1, max_length=128)
    username: str = Field(min_length=1, max_length=128)
    private_key: SecretStr = Field(min_length=32, max_length=1024 * 1024, repr=False)
    passphrase: SecretStr | None = Field(default=None, max_length=4096, repr=False)
    become_password: SecretStr | None = Field(default=None, max_length=4096, repr=False)
    become_enabled: bool = False
    become_method: str = Field(default="sudo", max_length=32)
    become_user: str = Field(default="root", max_length=128)
    description: str = Field(default="", max_length=1024)


CredentialCreate = Annotated[
    CredentialCreateRequest | SshPrivateKeyCredentialCreateRequest,
    Field(discriminator="credential_type"),
]


class SshPrivateKeyCredentialRotateRequest(StrictApiModel):
    credential_type: Literal[CredentialType.SSH_PRIVATE_KEY]
    private_key: SecretStr = Field(min_length=32, max_length=1024 * 1024, repr=False)
    passphrase: SecretStr | None = Field(default=None, max_length=4096, repr=False)
    become_password: SecretStr | None = Field(default=None, max_length=4096, repr=False)


CredentialRotate = Annotated[
    CredentialRotateRequest | SshPrivateKeyCredentialRotateRequest,
    Field(discriminator="credential_type"),
]


class CredentialUpdateRequest(StrictApiModel):
    name: str = Field(min_length=1, max_length=128)
    username: str = Field(min_length=1, max_length=128)
    description: str = Field(default="", max_length=1024)
    enabled: bool
    become_enabled: bool
    become_method: str = Field(max_length=32)
    become_user: str = Field(max_length=128)
    lock_version: int = Field(ge=1)


class CredentialRevisionResponse(StrictApiModel):
    version: int
    encryption_key_version: int
    created_at: object


class HostCreateRequest(StrictApiModel):
    name: str = Field(min_length=1, max_length=128)
    address: str = Field(min_length=1, max_length=253)
    ssh_port: int = Field(default=22, ge=1, le=65535)
    credential_id: UUID
    python_interpreter: str | None = Field(default="/usr/bin/python3", max_length=512)
    enabled: bool = True
    description: str = Field(default="", max_length=1024)
    variables: dict[str, object] = Field(default_factory=dict)


class HostUpdateRequest(HostCreateRequest):
    version: int = Field(ge=1)


class GroupRequest(StrictApiModel):
    name: str = Field(min_length=1, max_length=128)
    description: str = Field(default="", max_length=1024)
    variables: dict[str, object] = Field(default_factory=dict)
    host_ids: tuple[UUID, ...] = ()


class TargetRequest(StrictApiModel):
    kind: TargetKind
    host_ids: tuple[UUID, ...] = ()
    group_id: UUID | None = None


class InventoryPreviewResponse(StrictApiModel):
    host_count: int
    host_ids: tuple[UUID, ...]
    inventory: dict[str, object]
    yaml: str


class HostKeyScanResponse(StrictApiModel):
    algorithm: str
    public_key: str
    fingerprint: str


class HostKeyConfirmRequest(StrictApiModel):
    algorithm: str
    fingerprint: str


@router.get("/credentials", operation_id="listCredentials")
async def list_credentials(
    factory: UnitOfWorkFactoryDep, _: CurrentSessionDep
) -> tuple[Credential, ...]:
    return await _credentials(factory).list()


@router.post(
    "/credentials",
    status_code=status.HTTP_201_CREATED,
    operation_id="createCredential",
)
async def create_credential(
    request: CredentialCreate,
    factory: UnitOfWorkFactoryDep,
    principal: UnsafeSessionDep,
) -> Credential:
    require_permission(principal, Permission.CREDENTIAL_WRITE)
    require_recent_reauthentication(principal)
    if isinstance(request, SshPrivateKeyCredentialCreateRequest):
        return await _credentials(factory).create_ssh_private_key(
            name=request.name,
            username=request.username,
            private_key=request.private_key.get_secret_value(),
            passphrase=(
                request.passphrase.get_secret_value() if request.passphrase is not None else None
            ),
            become_password=(
                request.become_password.get_secret_value()
                if request.become_password is not None
                else None
            ),
            become_enabled=request.become_enabled,
            become_method=request.become_method,
            become_user=request.become_user,
            description=request.description,
            actor_user_id=principal.user_id,
            session_id=principal.session_id,
            actor=principal,
        )
    return await _credentials(factory).create(
        name=request.name,
        username=request.username,
        password=request.password.get_secret_value(),
        become_password=(
            request.become_password.get_secret_value()
            if request.become_password is not None
            else None
        ),
        become_enabled=request.become_enabled,
        become_method=request.become_method,
        become_user=request.become_user,
        description=request.description,
        actor_user_id=principal.user_id,
        session_id=principal.session_id,
        actor=principal,
    )


@router.get("/credentials/{credential_id}", operation_id="getCredential")
async def get_credential(
    credential_id: UUID,
    factory: UnitOfWorkFactoryDep,
    _: CurrentSessionDep,
) -> Credential:
    return await _credentials(factory).get(credential_id)


@router.post(
    "/credentials/{credential_id}/revisions",
    operation_id="rotateCredential",
)
async def rotate_credential(
    credential_id: UUID,
    request: CredentialRotate,
    factory: UnitOfWorkFactoryDep,
    principal: UnsafeSessionDep,
) -> Credential:
    require_permission(principal, Permission.CREDENTIAL_WRITE)
    require_recent_reauthentication(principal)
    if isinstance(request, SshPrivateKeyCredentialRotateRequest):
        return await _credentials(factory).rotate_ssh_private_key(
            credential_id,
            private_key=request.private_key.get_secret_value(),
            passphrase=(
                request.passphrase.get_secret_value() if request.passphrase is not None else None
            ),
            become_password=(
                request.become_password.get_secret_value()
                if request.become_password is not None
                else None
            ),
            actor_user_id=principal.user_id,
            session_id=principal.session_id,
            actor=principal,
        )
    return await _credentials(factory).rotate(
        credential_id,
        password=request.password.get_secret_value(),
        become_password=(
            request.become_password.get_secret_value()
            if request.become_password is not None
            else None
        ),
        actor_user_id=principal.user_id,
        session_id=principal.session_id,
        actor=principal,
    )


@router.put("/credentials/{credential_id}", operation_id="updateCredential")
async def update_credential(
    credential_id: UUID,
    request: CredentialUpdateRequest,
    factory: UnitOfWorkFactoryDep,
    principal: UnsafeSessionDep,
) -> Credential:
    require_permission(principal, Permission.CREDENTIAL_WRITE)
    require_recent_reauthentication(principal)
    return await _credentials(factory).update(
        credential_id,
        name=request.name,
        username=request.username,
        description=request.description,
        enabled=request.enabled,
        become_enabled=request.become_enabled,
        become_method=request.become_method,
        become_user=request.become_user,
        expected_lock_version=request.lock_version,
        actor_user_id=principal.user_id,
        session_id=principal.session_id,
        actor=principal,
    )


@router.get("/credentials/{credential_id}/revisions", operation_id="listCredentialRevisions")
async def list_credential_revisions(
    credential_id: UUID,
    factory: UnitOfWorkFactoryDep,
    _: CurrentSessionDep,
) -> tuple[CredentialRevisionResponse, ...]:
    revisions = await _credentials(factory).list_revisions(credential_id)
    return tuple(
        CredentialRevisionResponse(
            version=revision.version,
            encryption_key_version=revision.encryption_key_version,
            created_at=revision.created_at,
        )
        for revision in revisions
    )


@router.delete(
    "/credentials/{credential_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    operation_id="deleteCredential",
)
async def delete_credential(
    credential_id: UUID,
    factory: UnitOfWorkFactoryDep,
    principal: UnsafeSessionDep,
) -> Response:
    require_permission(principal, Permission.CREDENTIAL_WRITE)
    require_recent_reauthentication(principal)
    await _credentials(factory).delete(
        credential_id,
        actor_user_id=principal.user_id,
        session_id=principal.session_id,
        actor=principal,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/hosts", operation_id="listHosts")
async def list_hosts(factory: UnitOfWorkFactoryDep, _: CurrentSessionDep) -> tuple[Host, ...]:
    return await _assets(factory).list_hosts()


@router.post("/hosts", status_code=status.HTTP_201_CREATED, operation_id="createHost")
async def create_host(
    request: HostCreateRequest,
    factory: UnitOfWorkFactoryDep,
    principal: UnsafeSessionDep,
) -> Host:
    require_permission(principal, Permission.ASSET_WRITE)
    return await _assets(factory).create_host(
        **request.model_dump(),
        actor_user_id=principal.user_id,
        session_id=principal.session_id,
        actor=principal,
    )


@router.get("/hosts/{host_id}", operation_id="getHost")
async def get_host(host_id: UUID, factory: UnitOfWorkFactoryDep, _: CurrentSessionDep) -> Host:
    return await _assets(factory).get_host(host_id)


@router.put("/hosts/{host_id}", operation_id="updateHost")
async def update_host(
    host_id: UUID,
    request: HostUpdateRequest,
    factory: UnitOfWorkFactoryDep,
    principal: UnsafeSessionDep,
) -> Host:
    require_permission(principal, Permission.ASSET_WRITE)
    values = request.model_dump(exclude={"version"})
    return await _assets(factory).update_host(
        host_id,
        expected_version=request.version,
        actor_user_id=principal.user_id,
        session_id=principal.session_id,
        actor=principal,
        **values,
    )


@router.delete(
    "/hosts/{host_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    operation_id="deleteHost",
)
async def delete_host(
    host_id: UUID, factory: UnitOfWorkFactoryDep, principal: UnsafeSessionDep
) -> Response:
    require_permission(principal, Permission.ASSET_WRITE)
    await _assets(factory).delete_host(
        host_id,
        actor_user_id=principal.user_id,
        session_id=principal.session_id,
        actor=principal,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/groups", operation_id="listGroups")
async def list_groups(factory: UnitOfWorkFactoryDep, _: CurrentSessionDep) -> tuple[HostGroup, ...]:
    return await _assets(factory).list_groups()


@router.post("/groups", status_code=status.HTTP_201_CREATED, operation_id="createGroup")
async def create_group(
    request: GroupRequest,
    factory: UnitOfWorkFactoryDep,
    principal: UnsafeSessionDep,
) -> HostGroup:
    require_permission(principal, Permission.ASSET_WRITE)
    return await _assets(factory).create_group(
        **request.model_dump(),
        actor_user_id=principal.user_id,
        session_id=principal.session_id,
        actor=principal,
    )


@router.put("/groups/{group_id}", operation_id="updateGroup")
async def update_group(
    group_id: UUID,
    request: GroupRequest,
    factory: UnitOfWorkFactoryDep,
    principal: UnsafeSessionDep,
) -> HostGroup:
    require_permission(principal, Permission.ASSET_WRITE)
    return await _assets(factory).update_group(
        group_id,
        **request.model_dump(),
        actor_user_id=principal.user_id,
        session_id=principal.session_id,
        actor=principal,
    )


@router.delete(
    "/groups/{group_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    operation_id="deleteGroup",
)
async def delete_group(
    group_id: UUID, factory: UnitOfWorkFactoryDep, principal: UnsafeSessionDep
) -> Response:
    require_permission(principal, Permission.ASSET_WRITE)
    await _assets(factory).delete_group(
        group_id,
        actor_user_id=principal.user_id,
        session_id=principal.session_id,
        actor=principal,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/inventory/resolve", operation_id="resolveInventory")
@router.post("/inventory/preview", operation_id="previewInventory")
@router.post("/inventory/validate", operation_id="validateInventory")
async def preview_inventory(
    request: TargetRequest,
    factory: UnitOfWorkFactoryDep,
    _: CurrentSessionDep,
) -> InventoryPreviewResponse:
    hosts = await _assets(factory).resolve(
        target_kind=request.kind,
        host_ids=request.host_ids,
        group_id=request.group_id,
    )
    inventory = build_inventory(hosts)
    return InventoryPreviewResponse(
        host_count=len(hosts),
        host_ids=tuple(host.host_id for host in hosts),
        inventory=inventory,
        yaml=render_inventory(inventory),
    )


@router.get("/hosts/{host_id}/host-keys", operation_id="listHostKeys")
async def list_host_keys(
    host_id: UUID,
    factory: UnitOfWorkFactoryDep,
    _: CurrentSessionDep,
) -> tuple[HostKey, ...]:
    return await _assets(factory).list_host_keys(host_id)


@router.post("/hosts/{host_id}/host-keys/scan", operation_id="scanHostKeys")
async def scan_host_keys(
    host_id: UUID,
    factory: UnitOfWorkFactoryDep,
    principal: UnsafeSessionDep,
) -> tuple[HostKeyScanResponse, ...]:
    require_permission(principal, Permission.ASSET_WRITE)
    values = await _assets(factory).scan_host_keys(
        host_id,
        actor_user_id=principal.user_id,
        session_id=principal.session_id,
        actor=principal,
    )
    return tuple(HostKeyScanResponse.model_validate(value) for value in values)


@router.post("/hosts/{host_id}/host-keys/confirm", operation_id="confirmHostKey")
async def confirm_host_key(
    host_id: UUID,
    request: HostKeyConfirmRequest,
    factory: UnitOfWorkFactoryDep,
    principal: UnsafeSessionDep,
    idempotency_key: str = Header(min_length=8, max_length=200),
) -> HostKey:
    require_permission(principal, Permission.ASSET_WRITE)
    del idempotency_key
    return await _assets(factory).confirm_host_key(
        host_id,
        algorithm=request.algorithm,
        fingerprint=request.fingerprint,
        user_id=principal.user_id,
        session_id=principal.session_id,
        actor=principal,
    )
