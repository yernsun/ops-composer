from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from uuid import UUID

from pydantic import Field, SecretStr

from ops_composer.domain.base import StrictDomainModel


class UserStatus(StrEnum):
    ACTIVE = "ACTIVE"
    DISABLED = "DISABLED"


class UserIdentity(StrictDomainModel):
    user_id: UUID
    username: str = Field(min_length=1, max_length=64)
    status: UserStatus
    version: int = Field(ge=1)
    created_at: datetime
    updated_at: datetime


class PasswordCredential(StrictDomainModel):
    user_id: UUID
    password_hash: str = Field(min_length=1, repr=False)
    password_updated_at: datetime


class UserWithCredential(StrictDomainModel):
    identity: UserIdentity
    credential: PasswordCredential = Field(repr=False)


class SessionPrincipal(StrictDomainModel):
    session_id: UUID
    user_id: UUID
    username: str
    csrf_hash: str = Field(repr=False)
    expires_at: datetime


class IssuedSession(StrictDomainModel):
    principal: SessionPrincipal
    session_token: SecretStr = Field(min_length=32, repr=False)
    csrf_token: SecretStr = Field(min_length=32, repr=False)
