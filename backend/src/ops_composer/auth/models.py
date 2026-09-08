from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from uuid import UUID

from pydantic import Field, SecretStr

from ops_composer.domain.base import StrictDomainModel


class UserStatus(StrEnum):
    PENDING_ACTIVATION = "PENDING_ACTIVATION"
    ACTIVE = "ACTIVE"
    DISABLED = "DISABLED"


class UserRole(StrEnum):
    OWNER = "OWNER"
    ADMIN = "ADMIN"
    OPERATOR = "OPERATOR"
    AUDITOR = "AUDITOR"


class Permission(StrEnum):
    ASSET_READ = "asset:read"
    ASSET_WRITE = "asset:write"
    CREDENTIAL_WRITE = "credential:write"
    PLAYBOOK_WRITE = "playbook:write"
    RUN_STANDARD = "run:standard"
    RUN_SHELL = "run:shell"
    RUN_CANCEL = "run:cancel"
    WEB_SHELL = "web-shell:open"
    AUDIT_READ = "audit:read"
    USER_READ = "user:read"
    USER_MANAGE = "user:manage"
    KEY_ROTATE = "key:rotate"


_READ_PERMISSIONS = frozenset({Permission.ASSET_READ})
ROLE_PERMISSIONS: dict[UserRole, frozenset[Permission]] = {
    UserRole.OWNER: frozenset(Permission),
    UserRole.ADMIN: _READ_PERMISSIONS
    | {
        Permission.ASSET_WRITE,
        Permission.CREDENTIAL_WRITE,
        Permission.PLAYBOOK_WRITE,
        Permission.RUN_STANDARD,
        Permission.RUN_SHELL,
        Permission.RUN_CANCEL,
        Permission.WEB_SHELL,
        Permission.AUDIT_READ,
        Permission.USER_READ,
    },
    UserRole.OPERATOR: _READ_PERMISSIONS | {Permission.RUN_STANDARD, Permission.RUN_CANCEL},
    UserRole.AUDITOR: _READ_PERMISSIONS | {Permission.AUDIT_READ, Permission.USER_READ},
}


def permissions_for_role(role: UserRole) -> frozenset[Permission]:
    return ROLE_PERMISSIONS[role]


class UserIdentity(StrictDomainModel):
    user_id: UUID
    username: str = Field(min_length=1, max_length=64)
    status: UserStatus
    role: UserRole = UserRole.OPERATOR
    mfa_enrollment_required: bool = False
    activated_at: datetime | None = None
    version: int = Field(ge=1)
    created_at: datetime
    updated_at: datetime


class PasswordCredential(StrictDomainModel):
    user_id: UUID
    password_hash: str | None = Field(default=None, min_length=1, repr=False)
    password_updated_at: datetime | None = None


class UserWithCredential(StrictDomainModel):
    identity: UserIdentity
    credential: PasswordCredential = Field(repr=False)


class SessionPrincipal(StrictDomainModel):
    session_id: UUID
    user_id: UUID
    username: str
    role: UserRole = UserRole.OWNER
    permissions: frozenset[Permission] = Field(
        default_factory=lambda: permissions_for_role(UserRole.OWNER)
    )
    mfa_enabled: bool = False
    mfa_enrollment_required: bool = False
    mfa_verified_at: datetime | None = None
    reauthenticated_at: datetime | None = None
    elevated_until: datetime | None = None
    csrf_hash: str = Field(repr=False)
    expires_at: datetime


class IssuedSession(StrictDomainModel):
    principal: SessionPrincipal
    session_token: SecretStr = Field(min_length=32, repr=False)
    csrf_token: SecretStr = Field(min_length=32, repr=False)


class ChallengePurpose(StrEnum):
    LOGIN_MFA = "LOGIN_MFA"
    MFA_ENROLLMENT = "MFA_ENROLLMENT"


class IssuedChallenge(StrictDomainModel):
    challenge_id: UUID
    user_id: UUID
    username: str
    purpose: ChallengePurpose
    expires_at: datetime
    challenge_token: SecretStr = Field(min_length=32, repr=False)
    enrollment_secret: SecretStr | None = Field(default=None, repr=False)
    otpauth_uri: SecretStr | None = Field(default=None, repr=False)


class MfaFactor(StrictDomainModel):
    user_id: UUID
    encrypted_totp_secret: bytes = Field(repr=False)
    encryption_key_version: int = Field(ge=1)
    last_accepted_step: int | None = Field(default=None, ge=0)
    confirmed_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class ConsumedChallenge(StrictDomainModel):
    challenge_id: UUID
    user_id: UUID
    purpose: ChallengePurpose


class ActivationGrant(StrictDomainModel):
    activation_token_id: UUID
    user: UserIdentity
