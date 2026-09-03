from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from uuid import UUID

from pydantic import Field

from ops_composer.domain.base import StrictDomainModel


class CredentialType(StrEnum):
    PASSWORD = "PASSWORD"


class RunKind(StrEnum):
    PING = "PING"
    COMMAND = "COMMAND"
    PLAYBOOK = "PLAYBOOK"


class RunStatus(StrEnum):
    QUEUED = "QUEUED"
    PREPARING = "PREPARING"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    CANCELED = "CANCELED"
    TIMED_OUT = "TIMED_OUT"
    INTERRUPTED = "INTERRUPTED"
    REJECTED = "REJECTED"


TERMINAL_RUN_STATUSES = frozenset(
    {
        RunStatus.SUCCEEDED,
        RunStatus.PARTIAL,
        RunStatus.FAILED,
        RunStatus.CANCELED,
        RunStatus.TIMED_OUT,
        RunStatus.INTERRUPTED,
        RunStatus.REJECTED,
    }
)


class RunTargetStatus(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELED = "CANCELED"
    SKIPPED = "SKIPPED"
    UNREACHABLE = "UNREACHABLE"
    INTERRUPTED = "INTERRUPTED"


class TargetKind(StrEnum):
    ALL = "ALL"
    HOSTS = "HOSTS"
    GROUP = "GROUP"


class CommandMode(StrEnum):
    COMMAND = "COMMAND"
    SHELL = "SHELL"


class Credential(StrictDomainModel):
    credential_id: UUID
    name: str
    credential_type: CredentialType
    username: str
    public_config: dict[str, object] = Field(default_factory=dict)
    current_version: int = Field(ge=1)
    enabled: bool
    description: str
    deleted_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class CredentialRevision(StrictDomainModel):
    credential_id: UUID
    version: int = Field(ge=1)
    encrypted_secret: bytes = Field(repr=False)
    encryption_key_version: int = Field(ge=1)
    created_at: datetime


class Host(StrictDomainModel):
    host_id: UUID
    name: str
    address: str
    ssh_port: int = Field(ge=1, le=65535)
    credential_id: UUID
    python_interpreter: str | None = None
    enabled: bool
    description: str
    variables: dict[str, object] = Field(default_factory=dict)
    version: int = Field(ge=1)
    created_at: datetime
    updated_at: datetime


class HostKey(StrictDomainModel):
    host_id: UUID
    algorithm: str
    public_key: str
    fingerprint: str
    trusted_by: UUID
    trusted_at: datetime


class HostGroup(StrictDomainModel):
    group_id: UUID
    name: str
    description: str
    variables: dict[str, object] = Field(default_factory=dict)
    host_ids: tuple[UUID, ...] = ()
    created_at: datetime
    updated_at: datetime


class ResolvedHost(StrictDomainModel):
    host_id: UUID
    name: str
    address: str
    ssh_port: int
    credential_id: UUID
    credential_version: int
    credential_username: str
    credential_public_config: dict[str, object] = Field(default_factory=dict)
    python_interpreter: str | None = None
    host_variables: dict[str, object] = Field(default_factory=dict)
    group_variables: dict[str, object] = Field(default_factory=dict)


class Run(StrictDomainModel):
    run_id: UUID
    source_run_id: UUID | None = None
    kind: RunKind
    status: RunStatus
    target_spec: dict[str, object]
    resolved_targets: list[dict[str, object]]
    operation_spec: dict[str, object]
    inventory_snapshot: dict[str, object]
    workspace_revision: str | None = None
    credential_versions: dict[str, object]
    timeout_seconds: int
    forks: int
    cancel_requested_at: datetime | None = None
    claimed_by: str | None = None
    claimed_at: datetime | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    return_code: int | None = None
    summary: dict[str, object] = Field(default_factory=dict)
    failure_code: str | None = None
    failure_message: str | None = None
    requested_by: UUID
    idempotency_key: str
    request_fingerprint: str
    created_at: datetime
    updated_at: datetime


class RunTarget(StrictDomainModel):
    run_target_id: UUID
    run_id: UUID
    host_id: UUID
    host_name: str
    host_address: str
    status: RunTargetStatus
    return_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    result: dict[str, object] = Field(default_factory=dict)
    output_truncated: bool = False
    changed_count: int = 0
    failed_count: int = 0
    unreachable_count: int = 0
    started_at: datetime | None = None
    finished_at: datetime | None = None


class RunEvent(StrictDomainModel):
    run_event_id: UUID
    run_id: UUID
    run_target_id: UUID | None = None
    sequence: int = Field(ge=1)
    event_type: str
    task: str | None = None
    stdout: str | None = None
    event_data: dict[str, object] = Field(default_factory=dict)
    created_at: datetime


class Playbook(StrictDomainModel):
    path: str
    name: str
    size: int = Field(ge=0)
    modified_at: datetime
    sha256: str


class WorkerLease(StrictDomainModel):
    worker_id: str
    run_id: UUID | None = None
    heartbeat_at: datetime
    expires_at: datetime
