from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from uuid import UUID

from pydantic import Field, model_validator

from ops_composer.domain.base import StrictDomainModel


class AuditAction(StrEnum):
    REQUEST_COMPLETED = "REQUEST_COMPLETED"
    REQUEST_REJECTED = "REQUEST_REJECTED"
    REQUEST_VALIDATION_FAILED = "REQUEST_VALIDATION_FAILED"
    UNHANDLED_EXCEPTION = "UNHANDLED_EXCEPTION"
    APP_STARTING = "APP_STARTING"
    APP_READY = "APP_READY"
    APP_STOPPED = "APP_STOPPED"
    DATABASE_UNAVAILABLE = "DATABASE_UNAVAILABLE"
    DATABASE_RECOVERED = "DATABASE_RECOVERED"
    MIGRATION_STARTED = "MIGRATION_STARTED"
    MIGRATION_COMPLETED = "MIGRATION_COMPLETED"
    MIGRATION_FAILED = "MIGRATION_FAILED"
    MIGRATION_VALIDATION_FAILED = "MIGRATION_VALIDATION_FAILED"
    MASTER_KEY_INITIALIZED = "MASTER_KEY_INITIALIZED"
    MASTER_KEY_VALIDATED = "MASTER_KEY_VALIDATED"
    MASTER_KEY_VALIDATION_FAILED = "MASTER_KEY_VALIDATION_FAILED"
    PLAYBOOK_WORKSPACE_FAILED = "PLAYBOOK_WORKSPACE_FAILED"
    RUNTIME_DIRECTORY_FAILED = "RUNTIME_DIRECTORY_FAILED"
    AUDIT_PERSIST_FAILED = "AUDIT_PERSIST_FAILED"
    AUDIT_EXPORTED = "AUDIT_EXPORTED"
    AUDIT_RETENTION_PURGED = "AUDIT_RETENTION_PURGED"
    ADMIN_BOOTSTRAPPED = "ADMIN_BOOTSTRAPPED"
    ADMIN_BOOTSTRAP_REJECTED = "ADMIN_BOOTSTRAP_REJECTED"
    AUTH_LOGIN_SUCCEEDED = "AUTH_LOGIN_SUCCEEDED"
    AUTH_LOGIN_FAILED = "AUTH_LOGIN_FAILED"
    AUTH_RATE_LIMITED = "AUTH_RATE_LIMITED"
    AUTH_SESSION_INVALID = "AUTH_SESSION_INVALID"
    AUTH_LOGOUT_SUCCEEDED = "AUTH_LOGOUT_SUCCEEDED"
    ORIGIN_DENIED = "ORIGIN_DENIED"
    CSRF_DENIED = "CSRF_DENIED"
    AUTH_PURGE_COMPLETED = "AUTH_PURGE_COMPLETED"
    CREDENTIAL_CREATED = "CREDENTIAL_CREATED"
    CREDENTIAL_ROTATED = "CREDENTIAL_ROTATED"
    CREDENTIAL_DELETED = "CREDENTIAL_DELETED"
    HOST_CREATED = "HOST_CREATED"
    HOST_UPDATED = "HOST_UPDATED"
    HOST_DELETED = "HOST_DELETED"
    GROUP_CREATED = "GROUP_CREATED"
    GROUP_UPDATED = "GROUP_UPDATED"
    GROUP_DELETED = "GROUP_DELETED"
    HOST_KEY_SCAN_STARTED = "HOST_KEY_SCAN_STARTED"
    HOST_KEY_SCAN_SUCCEEDED = "HOST_KEY_SCAN_SUCCEEDED"
    HOST_KEY_SCAN_FAILED = "HOST_KEY_SCAN_FAILED"
    HOST_KEY_CONFIRMED = "HOST_KEY_CONFIRMED"
    HOST_KEY_CHANGED = "HOST_KEY_CHANGED"
    RUN_CREATED = "RUN_CREATED"
    RUN_IDEMPOTENT_REPLAY = "RUN_IDEMPOTENT_REPLAY"
    RUN_IDEMPOTENCY_CONFLICT = "RUN_IDEMPOTENCY_CONFLICT"
    RUN_TARGET_RESOLUTION_FAILED = "RUN_TARGET_RESOLUTION_FAILED"
    RUN_CANCEL_REQUESTED = "RUN_CANCEL_REQUESTED"
    RUN_CANCEL_REJECTED = "RUN_CANCEL_REJECTED"
    RUN_RETRY_CREATED = "RUN_RETRY_CREATED"
    WORKER_STARTED = "WORKER_STARTED"
    WORKER_READY = "WORKER_READY"
    WORKER_STOPPED = "WORKER_STOPPED"
    WORKER_LOOP_FAILED = "WORKER_LOOP_FAILED"
    STALE_RUNS_RECOVERED = "STALE_RUNS_RECOVERED"
    RUN_CLAIMED = "RUN_CLAIMED"
    HOST_LOCK_COLLISION = "HOST_LOCK_COLLISION"
    RUN_PREPARATION_FAILED = "RUN_PREPARATION_FAILED"
    RUNTIME_DIRECTORY_CREATED = "RUNTIME_DIRECTORY_CREATED"
    RUNTIME_DIRECTORY_CLEANED = "RUNTIME_DIRECTORY_CLEANED"
    RUN_STARTED = "RUN_STARTED"
    HOST_COMPLETED = "HOST_COMPLETED"
    RUN_SUCCEEDED = "RUN_SUCCEEDED"
    RUN_PARTIAL = "RUN_PARTIAL"
    RUN_FAILED = "RUN_FAILED"
    RUN_REJECTED = "RUN_REJECTED"
    RUN_CANCELED = "RUN_CANCELED"
    RUN_TIMED_OUT = "RUN_TIMED_OUT"
    RUN_INTERRUPTED = "RUN_INTERRUPTED"
    PLAYBOOK_CREATED = "PLAYBOOK_CREATED"
    PLAYBOOK_UPDATED = "PLAYBOOK_UPDATED"
    PLAYBOOK_DELETED = "PLAYBOOK_DELETED"
    PLAYBOOK_VALIDATION_SUCCEEDED = "PLAYBOOK_VALIDATION_SUCCEEDED"
    PLAYBOOK_VALIDATION_FAILED = "PLAYBOOK_VALIDATION_FAILED"
    PLAYBOOK_SOURCE_DISABLED = "PLAYBOOK_SOURCE_DISABLED"
    WEB_SHELL_REQUESTED = "WEB_SHELL_REQUESTED"
    WEB_SHELL_STARTED = "WEB_SHELL_STARTED"
    WEB_SHELL_CLOSE_REQUESTED = "WEB_SHELL_CLOSE_REQUESTED"
    WEB_SHELL_CLOSED = "WEB_SHELL_CLOSED"
    WEB_SHELL_DENIED = "WEB_SHELL_DENIED"
    WEB_SHELL_FAILED = "WEB_SHELL_FAILED"
    WEB_SHELL_TIMED_OUT = "WEB_SHELL_TIMED_OUT"
    WEB_SHELL_STALE_RECOVERED = "WEB_SHELL_STALE_RECOVERED"


class AuditOutcome(StrEnum):
    STARTED = "STARTED"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    DENIED = "DENIED"
    NOOP = "NOOP"


class AuditSource(StrEnum):
    API = "API"
    WORKER = "WORKER"
    CLI = "CLI"
    SYSTEM = "SYSTEM"


class AuditSeverity(StrEnum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class AuditEventDraft(StrictDomainModel):
    occurred_at: datetime
    schema_version: int = Field(default=1, ge=1)
    severity: AuditSeverity
    source: AuditSource
    service: str = Field(min_length=1, max_length=32)
    event_action: AuditAction
    event_outcome: AuditOutcome
    request_id: str | None = Field(default=None, max_length=128)
    correlation_id: str | None = Field(default=None, max_length=128)
    actor_user_id: UUID | None = None
    session_id: UUID | None = None
    run_id: UUID | None = None
    run_target_id: UUID | None = None
    worker_id: str | None = Field(default=None, max_length=255)
    resource_type: str | None = Field(default=None, max_length=64)
    resource_id: str | None = Field(default=None, max_length=255)
    duration_ms: float | None = Field(default=None, ge=0)
    error_code: str | None = Field(default=None, max_length=128)
    exception_type: str | None = Field(default=None, max_length=255)
    failure_stage: str | None = Field(default=None, max_length=128)
    retryable: bool | None = None
    metadata: dict[str, object] = Field(default_factory=dict)


class AuditEvent(AuditEventDraft):
    audit_event_id: int = Field(ge=1)


class AuditQuery(StrictDomainModel):
    since: datetime
    until: datetime | None = None
    action: AuditAction | None = None
    outcome: AuditOutcome | None = None
    source: AuditSource | None = None
    run_id: UUID | None = None
    actor_user_id: UUID | None = None
    resource_type: str | None = Field(default=None, max_length=64)
    resource_id: str | None = Field(default=None, max_length=255)
    error_code: str | None = Field(default=None, max_length=128)
    before_id: int | None = Field(default=None, ge=1)
    limit: int = Field(default=200, ge=1, le=10_000)

    @model_validator(mode="after")
    def require_valid_window(self) -> AuditQuery:
        if self.until is not None and self.until <= self.since:
            raise ValueError("until must be later than since")
        return self
