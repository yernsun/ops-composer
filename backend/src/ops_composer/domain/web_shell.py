from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from uuid import UUID

from pydantic import Field, SecretStr

from ops_composer.domain.base import StrictDomainModel


class WebShellState(StrEnum):
    PENDING = "PENDING"
    ACTIVE = "ACTIVE"
    CLOSE_REQUESTED = "CLOSE_REQUESTED"


class WebShellCloseReason(StrEnum):
    CLIENT_DISCONNECTED = "CLIENT_DISCONNECTED"
    USER_REQUESTED = "USER_REQUESTED"
    REMOTE_EXIT = "REMOTE_EXIT"
    IDLE_TIMEOUT = "IDLE_TIMEOUT"
    MAX_DURATION = "MAX_DURATION"
    AUTH_SESSION_INVALID = "AUTH_SESSION_INVALID"
    DATABASE_UNAVAILABLE = "DATABASE_UNAVAILABLE"
    SERVER_SHUTDOWN = "SERVER_SHUTDOWN"
    START_FAILED = "START_FAILED"
    PROTOCOL_ERROR = "PROTOCOL_ERROR"
    SLOW_CONSUMER = "SLOW_CONSUMER"


class WebShellSession(StrictDomainModel):
    web_shell_session_id: UUID
    host_id: UUID
    actor_user_id: UUID
    auth_session_id: UUID
    credential_id: UUID
    credential_version: int = Field(ge=1)
    host_name: str = Field(min_length=1, max_length=128)
    host_address: str = Field(min_length=1, max_length=253)
    ssh_port: int = Field(ge=1, le=65535)
    username: str = Field(min_length=1, max_length=128)
    state: WebShellState
    api_instance_id: str = Field(min_length=1, max_length=255)
    owner_id: str | None = Field(default=None, max_length=255)
    ticket_expires_at: datetime
    lease_expires_at: datetime
    connected_at: datetime | None = None
    last_activity_at: datetime | None = None
    close_requested_at: datetime | None = None
    created_at: datetime


class WebShellLaunch(StrictDomainModel):
    session: WebShellSession
    password: SecretStr = Field(repr=False)
    known_hosts: str = Field(repr=False)
