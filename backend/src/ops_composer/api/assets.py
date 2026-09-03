from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Header, Response, status
from pydantic import Field, SecretStr

from ops_composer.api.dependencies import UnitOfWorkFactoryDep
from ops_composer.api.models import StrictApiModel
from ops_composer.auth.api import CurrentSessionDep, UnsafeSessionDep
from ops_composer.domain.ops import Credential, Host, HostGroup, HostKey, TargetKind
from ops_composer.services.assets import AssetService, CredentialService
from ops_composer.services.crypto import CredentialCipher
from ops_composer.services.inventory import build_inventory, render_inventory
from ops_composer.settings import get_settings

router = APIRouter(prefix="/api/v1", tags=["inventory"])


def _assets(factory: UnitOfWorkFactoryDep) -> AssetService:
    return AssetService(factory)


def _credentials(factory: UnitOfWorkFactoryDep) -> CredentialService:
    settings = get_settings()
    return CredentialService(
        factory,
        CredentialCipher(settings.master_key.get_secret_value(), settings.master_key_version),
    )


class CredentialCreateRequest(StrictApiModel):
    name: str = Field(min_length=1, max_length=128)
    username: str = Field(min_length=1, max_length=128)
    password: SecretStr = Field(min_length=1, max_length=4096, repr=False)
    become_password: SecretStr | None = Field(default=None, max_length=4096, repr=False)
    become_enabled: bool = False
    become_method: str = Field(default="sudo", max_length=32)
    become_user: str = Field(default="root", max_length=128)
    description: str = Field(default="", max_length=1024)


class CredentialRotateRequest(StrictApiModel):
    password: SecretStr = Field(min_length=1, max_length=4096, repr=False)
    become_password: SecretStr | None = Field(default=None, max_length=4096, repr=False)


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
    request: CredentialCreateRequest,
    factory: UnitOfWorkFactoryDep,
    _: UnsafeSessionDep,
) -> Credential:
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
    request: CredentialRotateRequest,
    factory: UnitOfWorkFactoryDep,
    _: UnsafeSessionDep,
) -> Credential:
    return await _credentials(factory).rotate(
        credential_id,
        password=request.password.get_secret_value(),
        become_password=(
            request.become_password.get_secret_value()
            if request.become_password is not None
            else None
        ),
    )


@router.delete(
    "/credentials/{credential_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    operation_id="deleteCredential",
)
async def delete_credential(
    credential_id: UUID,
    factory: UnitOfWorkFactoryDep,
    _: UnsafeSessionDep,
) -> Response:
    await _credentials(factory).delete(credential_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/hosts", operation_id="listHosts")
async def list_hosts(factory: UnitOfWorkFactoryDep, _: CurrentSessionDep) -> tuple[Host, ...]:
    return await _assets(factory).list_hosts()


@router.post("/hosts", status_code=status.HTTP_201_CREATED, operation_id="createHost")
async def create_host(
    request: HostCreateRequest,
    factory: UnitOfWorkFactoryDep,
    _: UnsafeSessionDep,
) -> Host:
    return await _assets(factory).create_host(**request.model_dump())


@router.get("/hosts/{host_id}", operation_id="getHost")
async def get_host(host_id: UUID, factory: UnitOfWorkFactoryDep, _: CurrentSessionDep) -> Host:
    return await _assets(factory).get_host(host_id)


@router.put("/hosts/{host_id}", operation_id="updateHost")
async def update_host(
    host_id: UUID,
    request: HostUpdateRequest,
    factory: UnitOfWorkFactoryDep,
    _: UnsafeSessionDep,
) -> Host:
    values = request.model_dump(exclude={"version"})
    return await _assets(factory).update_host(host_id, expected_version=request.version, **values)


@router.delete(
    "/hosts/{host_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    operation_id="deleteHost",
)
async def delete_host(
    host_id: UUID, factory: UnitOfWorkFactoryDep, _: UnsafeSessionDep
) -> Response:
    await _assets(factory).delete_host(host_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/groups", operation_id="listGroups")
async def list_groups(factory: UnitOfWorkFactoryDep, _: CurrentSessionDep) -> tuple[HostGroup, ...]:
    return await _assets(factory).list_groups()


@router.post("/groups", status_code=status.HTTP_201_CREATED, operation_id="createGroup")
async def create_group(
    request: GroupRequest,
    factory: UnitOfWorkFactoryDep,
    _: UnsafeSessionDep,
) -> HostGroup:
    return await _assets(factory).create_group(**request.model_dump())


@router.put("/groups/{group_id}", operation_id="updateGroup")
async def update_group(
    group_id: UUID,
    request: GroupRequest,
    factory: UnitOfWorkFactoryDep,
    _: UnsafeSessionDep,
) -> HostGroup:
    return await _assets(factory).update_group(group_id, **request.model_dump())


@router.delete(
    "/groups/{group_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    operation_id="deleteGroup",
)
async def delete_group(
    group_id: UUID, factory: UnitOfWorkFactoryDep, _: UnsafeSessionDep
) -> Response:
    await _assets(factory).delete_group(group_id)
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
    _: UnsafeSessionDep,
) -> tuple[HostKeyScanResponse, ...]:
    values = await _assets(factory).scan_host_keys(host_id)
    return tuple(HostKeyScanResponse.model_validate(value) for value in values)


@router.post("/hosts/{host_id}/host-keys/confirm", operation_id="confirmHostKey")
async def confirm_host_key(
    host_id: UUID,
    request: HostKeyConfirmRequest,
    factory: UnitOfWorkFactoryDep,
    principal: UnsafeSessionDep,
    idempotency_key: str = Header(min_length=8, max_length=200),
) -> HostKey:
    del idempotency_key
    return await _assets(factory).confirm_host_key(
        host_id,
        algorithm=request.algorithm,
        fingerprint=request.fingerprint,
        user_id=principal.user_id,
    )
