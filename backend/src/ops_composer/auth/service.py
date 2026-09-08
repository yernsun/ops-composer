from __future__ import annotations

import asyncio
import math
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from urllib.parse import quote
from uuid import UUID, uuid4

from pydantic import SecretStr

from ops_composer.auth.errors import (
    ActivationExpiredError,
    AdminAlreadyExistsError,
    AuthRateLimitedError,
    CsrfValidationError,
    InvalidChallengeError,
    InvalidCredentialsError,
    InvalidMfaCodeError,
    InvalidSessionError,
    LastOwnerRequiredError,
    PermissionDeniedError,
    ReauthenticationRequiredError,
    TotpDisabledError,
    UserConflictError,
    UserVersionConflictError,
)
from ops_composer.auth.models import (
    ChallengePurpose,
    IssuedChallenge,
    IssuedSession,
    MfaFactor,
    PasswordCredential,
    Permission,
    SessionPrincipal,
    UserIdentity,
    UserRole,
    UserStatus,
    permissions_for_role,
)
from ops_composer.auth.security import (
    generate_recovery_codes,
    generate_token,
    generate_totp_secret,
    hash_password,
    hash_recovery_code,
    hash_token,
    hmac_subject,
    match_totp_step,
    token_matches,
    verify_password,
)
from ops_composer.domain.audit import AuditAction, AuditEventDraft, AuditOutcome, AuditSource
from ops_composer.domain.base import utc_now
from ops_composer.services.audit import emit_audit_event, new_audit_event
from ops_composer.services.crypto import MasterKeyring, build_master_keyring
from ops_composer.settings import Settings
from ops_composer.uow.factory import UnitOfWorkFactory
from ops_composer.uow.unit import UnitOfWork

AUTH_CHALLENGE_TTL = timedelta(minutes=5)
ACTIVATION_TTL = timedelta(hours=24)
REAUTHENTICATION_TTL = timedelta(minutes=10)
MFA_REQUIRED_ROLES = frozenset({UserRole.OWNER, UserRole.ADMIN})


def canonical_username(username: str) -> str:
    return username.strip().casefold()


def fixed_window(now: datetime, seconds: int) -> tuple[datetime, datetime]:
    epoch = int(now.timestamp())
    start_epoch = epoch - (epoch % seconds)
    start = datetime.fromtimestamp(start_epoch, UTC)
    return start, start + timedelta(seconds=seconds)


def require_permission(principal: SessionPrincipal, permission: Permission) -> None:
    if permission not in principal.permissions:
        error = PermissionDeniedError()
        error.audit_metadata = {
            "permission": permission.value,
            "role": principal.role.value,
            "actor_user_id": str(principal.user_id),
        }
        raise error


def require_recent_reauthentication(principal: SessionPrincipal) -> None:
    if (
        principal.reauthenticated_at is None
        or principal.elevated_until is None
        or principal.elevated_until <= utc_now()
    ):
        raise ReauthenticationRequiredError()


@dataclass(frozen=True, slots=True)
class RateLimitSpec:
    scope: str
    subject: str
    maximum: int
    window_seconds: int


@dataclass(frozen=True, slots=True)
class ConsumedRateLimit:
    scope: str
    subject_hash: str
    window_started_at: datetime
    reset_at: datetime
    count: int
    maximum: int


@dataclass(frozen=True, slots=True)
class CreatedUser:
    user: UserIdentity
    activation_code: str
    activation_expires_at: datetime


@dataclass(frozen=True, slots=True)
class CompletedMfa:
    issued: IssuedSession
    recovery_codes: tuple[str, ...] = ()


AuthResult = IssuedSession | IssuedChallenge


@dataclass(frozen=True, slots=True)
class SecurityStatus:
    totp_policy_enabled: bool
    mfa_enabled: bool
    mfa_enrollment_required: bool
    unused_recovery_codes: int
    elevated_until: datetime | None


class AuthService:
    def __init__(
        self,
        unit_of_work_factory: UnitOfWorkFactory,
        settings: Settings,
        *,
        audit_source: AuditSource = AuditSource.API,
        keyring: MasterKeyring | None = None,
    ) -> None:
        self._unit_of_work_factory = unit_of_work_factory
        self._settings = settings
        self._session_ttl = timedelta(seconds=settings.session_ttl_seconds)
        self._audit_source = audit_source
        self._keyring = keyring or build_master_keyring(
            keyring_file=settings.master_keyring_file,
            fallback_key=settings.master_key.get_secret_value(),
            fallback_version=settings.master_key_version,
        )

    async def bootstrap(self, username: str, password: str) -> UserIdentity:
        normalized = canonical_username(username)
        self._validate_username(normalized)
        self._validate_password(password)
        password_hash = await asyncio.to_thread(hash_password, password)
        now = utc_now()
        identity = UserIdentity(
            user_id=uuid4(),
            username=normalized,
            status=UserStatus.ACTIVE,
            role=UserRole.OWNER,
            mfa_enrollment_required=True,
            activated_at=now,
            version=1,
            created_at=now,
            updated_at=now,
        )
        credential = PasswordCredential(
            user_id=identity.user_id,
            password_hash=password_hash,
            password_updated_at=now,
        )
        event = new_audit_event(
            AuditAction.ADMIN_BOOTSTRAPPED,
            AuditOutcome.SUCCEEDED,
            source=AuditSource.CLI,
            actor_user_id=identity.user_id,
            resource_type="user",
            resource_id=identity.user_id,
            metadata={"role": UserRole.OWNER.value, "mfa_enrollment_required": True},
        )
        async with self._unit_of_work_factory() as unit_of_work:
            if await unit_of_work.auth.count_users() != 0:
                raise AdminAlreadyExistsError()
            created = await unit_of_work.auth.add_admin(identity, credential)
            await unit_of_work.audit.append(event)
        emit_audit_event(event)
        return created

    @staticmethod
    def _validate_username(username: str) -> None:
        if not username or len(username) > 64:
            raise ValueError("username must contain between 1 and 64 characters")

    @staticmethod
    def _validate_password(password: str) -> None:
        if len(password) < 12 or len(password) > 200:
            raise ValueError("password must contain between 12 and 200 characters")

    async def _issue(
        self,
        unit_of_work: UnitOfWork,
        user: UserIdentity,
        *,
        mfa_enabled: bool = False,
        mfa_verified_at: datetime | None = None,
        elevated: bool = False,
    ) -> IssuedSession:
        session_token = generate_token()
        csrf_token = generate_token()
        csrf_hash = hash_token(csrf_token)
        now = utc_now()
        session_id = uuid4()
        expires_at = now + self._session_ttl
        reauthenticated_at = now if elevated else None
        elevated_until = now + REAUTHENTICATION_TTL if elevated else None
        await unit_of_work.auth.add_session(
            session_id=session_id,
            user_id=user.user_id,
            token_hash=hash_token(session_token),
            csrf_hash=csrf_hash,
            expires_at=expires_at,
            created_at=now,
            mfa_verified_at=mfa_verified_at,
            reauthenticated_at=reauthenticated_at,
            elevated_until=elevated_until,
        )
        return IssuedSession(
            principal=SessionPrincipal(
                session_id=session_id,
                user_id=user.user_id,
                username=user.username,
                role=user.role,
                permissions=permissions_for_role(user.role),
                mfa_enabled=mfa_enabled,
                mfa_enrollment_required=user.mfa_enrollment_required,
                mfa_verified_at=mfa_verified_at,
                reauthenticated_at=reauthenticated_at,
                elevated_until=elevated_until,
                csrf_hash=csrf_hash,
                expires_at=expires_at,
            ),
            session_token=SecretStr(session_token),
            csrf_token=SecretStr(csrf_token),
        )

    async def _issue_challenge(
        self,
        unit_of_work: UnitOfWork,
        user: UserIdentity,
        purpose: ChallengePurpose,
        *,
        begin_enrollment: bool,
    ) -> IssuedChallenge:
        self._require_totp_enabled()
        now = utc_now()
        token = generate_token()
        challenge_id = uuid4()
        expires_at = now + AUTH_CHALLENGE_TTL
        secret: str | None = None
        uri: str | None = None
        if begin_enrollment:
            secret = generate_totp_secret()
            envelope, key_version = self._keyring.encrypt_bytes(
                "totp", str(user.user_id), secret.encode("ascii")
            )
            await unit_of_work.auth.put_mfa_factor(
                MfaFactor(
                    user_id=user.user_id,
                    encrypted_totp_secret=envelope,
                    encryption_key_version=key_version,
                    created_at=now,
                    updated_at=now,
                )
            )
            label = quote(f"OpsComposer:{user.username}", safe="")
            uri = (
                f"otpauth://totp/{label}?secret={secret}&issuer=OpsComposer"
                "&algorithm=SHA1&digits=6&period=30"
            )
        await unit_of_work.auth.add_challenge(
            challenge_id=challenge_id,
            user_id=user.user_id,
            token_hash=hash_token(token),
            purpose=purpose,
            expires_at=expires_at,
            created_at=now,
        )
        return IssuedChallenge(
            challenge_id=challenge_id,
            user_id=user.user_id,
            username=user.username,
            purpose=purpose,
            expires_at=expires_at,
            challenge_token=SecretStr(token),
            enrollment_secret=SecretStr(secret) if secret is not None else None,
            otpauth_uri=SecretStr(uri) if uri is not None else None,
        )

    def _require_totp_enabled(self) -> None:
        if not self._settings.totp_enabled:
            error = TotpDisabledError()
            error.audit_metadata = {
                "totp_policy_enabled": False,
                "authentication_factors": [],
            }
            raise error

    async def _consume_rate_limit(self, spec: RateLimitSpec) -> ConsumedRateLimit:
        now = utc_now()
        secret = self._settings.auth_rate_limit_secret.get_secret_value()
        async with self._unit_of_work_factory() as unit_of_work:
            window_start, window_end = fixed_window(now, spec.window_seconds)
            subject_hash = hmac_subject(secret, spec.scope, spec.subject)
            count = await unit_of_work.auth.consume_rate_limit(
                scope=spec.scope,
                subject_hash=subject_hash,
                window_started_at=window_start,
                expires_at=window_end,
            )
        consumed = ConsumedRateLimit(
            scope=spec.scope,
            subject_hash=subject_hash,
            window_started_at=window_start,
            reset_at=window_end,
            count=count,
            maximum=spec.maximum,
        )
        if consumed.count > consumed.maximum:
            retry_after = max(1, math.ceil((consumed.reset_at - now).total_seconds()))
            error = AuthRateLimitedError(retry_after_seconds=retry_after)
            error.audit_metadata = {
                "scope": consumed.scope,
                "subject_hash": consumed.subject_hash,
                "count": consumed.count,
                "limit": consumed.maximum,
                "retry_after_seconds": retry_after,
                "totp_policy_enabled": self._settings.totp_enabled,
                "authentication_factors": [],
            }
            raise error
        return consumed

    async def login(self, username: str, password: str, client_key: str) -> AuthResult:
        normalized = canonical_username(username)
        await self._consume_rate_limit(
            RateLimitSpec(
                scope="login:ip",
                subject=client_key,
                maximum=self._settings.auth_login_ip_limit,
                window_seconds=self._settings.auth_login_ip_window_seconds,
            )
        )
        username_ip_bucket = await self._consume_rate_limit(
            RateLimitSpec(
                scope="login:username_ip",
                subject=f"{normalized}\0{client_key}",
                maximum=self._settings.auth_login_username_ip_limit,
                window_seconds=self._settings.auth_login_username_ip_window_seconds,
            )
        )
        event: AuditEventDraft | None = None
        result: AuthResult | None = None
        async with self._unit_of_work_factory() as unit_of_work:
            user = await unit_of_work.auth.find_user_by_username(normalized)
            password_hash = user.credential.password_hash if user else None
            verification = await asyncio.to_thread(verify_password, password_hash, password)
            if (
                user is None
                or user.identity.status is not UserStatus.ACTIVE
                or not verification.valid
            ):
                error = InvalidCredentialsError()
                error.audit_metadata = {
                    "scope": username_ip_bucket.scope,
                    "subject_hash": username_ip_bucket.subject_hash,
                    "count": username_ip_bucket.count,
                    "limit": username_ip_bucket.maximum,
                    "totp_policy_enabled": self._settings.totp_enabled,
                    "authentication_factors": ["PASSWORD"],
                }
                raise error
            identity = user.identity
            if verification.needs_rehash:
                replacement = await asyncio.to_thread(hash_password, password)
                await unit_of_work.auth.update_password_hash(
                    identity.user_id, replacement, utc_now()
                )
            await unit_of_work.auth.clear_rate_limit(
                scope=username_ip_bucket.scope,
                subject_hash=username_ip_bucket.subject_hash,
                window_started_at=username_ip_bucket.window_started_at,
            )
            factor = await unit_of_work.auth.get_mfa_factor(identity.user_id)
            factor_enabled = factor is not None and factor.confirmed_at is not None
            enrollment_required = identity.mfa_enrollment_required or (
                identity.role in MFA_REQUIRED_ROLES
                and not factor_enabled
            )
            if not self._settings.totp_enabled:
                result = await self._issue(
                    unit_of_work,
                    identity,
                    mfa_enabled=factor_enabled,
                    elevated=True,
                )
            elif enrollment_required:
                result = await self._issue_challenge(
                    unit_of_work,
                    identity,
                    ChallengePurpose.MFA_ENROLLMENT,
                    begin_enrollment=True,
                )
            elif factor_enabled:
                result = await self._issue_challenge(
                    unit_of_work,
                    identity,
                    ChallengePurpose.LOGIN_MFA,
                    begin_enrollment=False,
                )
            else:
                result = await self._issue(unit_of_work, identity, mfa_enabled=False)
            event = new_audit_event(
                AuditAction.AUTH_LOGIN_SUCCEEDED,
                AuditOutcome.SUCCEEDED,
                source=self._audit_source,
                actor_user_id=identity.user_id,
                session_id=(
                    result.principal.session_id if isinstance(result, IssuedSession) else None
                ),
                resource_type=(
                    "session" if isinstance(result, IssuedSession) else "auth_challenge"
                ),
                resource_id=(
                    result.principal.session_id
                    if isinstance(result, IssuedSession)
                    else result.challenge_id
                ),
                metadata={
                    "password_rehashed": verification.needs_rehash,
                    "totp_policy_enabled": self._settings.totp_enabled,
                    "authentication_factors": ["PASSWORD"],
                    "next_step": (
                        "SESSION" if isinstance(result, IssuedSession) else result.purpose.value
                    ),
                },
            )
            await unit_of_work.audit.append(event)
        if result is None or event is None:
            raise RuntimeError("authentication transaction produced no result")
        emit_audit_event(event)
        return result

    def _decrypt_totp(self, factor: MfaFactor) -> str:
        try:
            return self._keyring.decrypt_bytes(
                "totp",
                str(factor.user_id),
                factor.encrypted_totp_secret,
                factor.encryption_key_version,
            ).decode("ascii")
        except (UnicodeError, ValueError) as error:
            raise InvalidMfaCodeError() from error

    async def _verify_mfa_value(
        self,
        unit_of_work: UnitOfWork,
        factor: MfaFactor,
        value: str,
        *,
        allow_recovery: bool,
    ) -> tuple[bool, bool]:
        now = utc_now()
        secret = self._decrypt_totp(factor)
        step = match_totp_step(
            secret,
            value,
            now=now.timestamp(),
            last_accepted_step=factor.last_accepted_step,
        )
        if step is not None:
            return await unit_of_work.auth.accept_totp_step(factor.user_id, step, now), False
        if allow_recovery and await unit_of_work.auth.consume_recovery_code(
            factor.user_id, hash_recovery_code(value), now
        ):
            return True, True
        return False, False

    async def complete_mfa(
        self,
        challenge_token: str,
        value: str,
        *,
        expected_purpose: ChallengePurpose | None = None,
    ) -> CompletedMfa:
        self._require_totp_enabled()
        now = utc_now()
        event: AuditEventDraft | None = None
        completed: CompletedMfa | None = None
        async with self._unit_of_work_factory() as unit_of_work:
            challenge = await unit_of_work.auth.resolve_challenge(hash_token(challenge_token), now)
            if challenge is None:
                raise InvalidChallengeError()
            if expected_purpose is not None and challenge.purpose is not expected_purpose:
                raise InvalidChallengeError()
            user = await unit_of_work.auth.get_user(challenge.user_id)
            factor = await unit_of_work.auth.get_mfa_factor(challenge.user_id)
            if user is None or factor is None:
                raise InvalidChallengeError()
            recovery_codes: tuple[str, ...] = ()
            used_recovery = False
            if challenge.purpose is ChallengePurpose.MFA_ENROLLMENT:
                if factor.confirmed_at is not None:
                    raise InvalidChallengeError()
                secret = self._decrypt_totp(factor)
                step = match_totp_step(secret, value, now=now.timestamp())
                if step is None:
                    error = InvalidMfaCodeError()
                    error.audit_metadata = {
                        "totp_policy_enabled": True,
                        "authentication_factors": ["TOTP"],
                    }
                    raise error
                await unit_of_work.auth.confirm_mfa_factor(user.user_id, now)
                if not await unit_of_work.auth.accept_totp_step(user.user_id, step, now):
                    raise InvalidMfaCodeError()
                recovery_codes = generate_recovery_codes()
                rows = tuple((uuid4(), hash_recovery_code(code)) for code in recovery_codes)
                await unit_of_work.auth.replace_recovery_codes(user.user_id, rows, now)
                user = user.model_copy(update={"mfa_enrollment_required": False})
            else:
                verified, used_recovery = await self._verify_mfa_value(
                    unit_of_work, factor, value, allow_recovery=True
                )
                if not verified:
                    error = InvalidMfaCodeError()
                    error.audit_metadata = {
                        "totp_policy_enabled": True,
                        "authentication_factors": ["TOTP_OR_RECOVERY_CODE"],
                    }
                    raise error
            if not await unit_of_work.auth.mark_challenge_consumed(challenge.challenge_id, now):
                raise InvalidChallengeError()
            await unit_of_work.auth.delete_user_sessions(user.user_id)
            issued = await self._issue(
                unit_of_work,
                user,
                mfa_enabled=True,
                mfa_verified_at=now,
                elevated=True,
            )
            completed = CompletedMfa(issued=issued, recovery_codes=recovery_codes)
            event = new_audit_event(
                (
                    AuditAction.USER_MFA_ENROLLMENT_SUCCEEDED
                    if challenge.purpose is ChallengePurpose.MFA_ENROLLMENT
                    else (
                        AuditAction.AUTH_RECOVERY_USED
                        if used_recovery
                        else AuditAction.AUTH_MFA_SUCCEEDED
                    )
                ),
                AuditOutcome.SUCCEEDED,
                source=self._audit_source,
                actor_user_id=user.user_id,
                session_id=issued.principal.session_id,
                resource_type="user",
                resource_id=user.user_id,
                metadata={
                    "totp_policy_enabled": True,
                    "authentication_factors": [
                        "RECOVERY_CODE" if used_recovery else "TOTP"
                    ],
                },
            )
            await unit_of_work.audit.append(event)
        if completed is None or event is None:
            raise RuntimeError("MFA completion produced no session")
        emit_audit_event(event)
        return completed

    async def begin_mfa_enrollment(self, principal: SessionPrincipal) -> IssuedChallenge:
        self._require_totp_enabled()
        async with self._unit_of_work_factory() as unit_of_work:
            user = await unit_of_work.auth.get_user(principal.user_id)
            if user is None:
                raise InvalidSessionError()
            challenge = await self._issue_challenge(
                unit_of_work,
                user.model_copy(update={"mfa_enrollment_required": True}),
                ChallengePurpose.MFA_ENROLLMENT,
                begin_enrollment=True,
            )
            event = new_audit_event(
                AuditAction.USER_MFA_ENROLLMENT_STARTED,
                AuditOutcome.SUCCEEDED,
                source=self._audit_source,
                actor_user_id=user.user_id,
                session_id=principal.session_id,
                resource_type="user",
                resource_id=user.user_id,
            )
            await unit_of_work.audit.append(event)
        emit_audit_event(event)
        return challenge

    async def reauthenticate(
        self, principal: SessionPrincipal, password: str, mfa_value: str | None
    ) -> SessionPrincipal:
        event: AuditEventDraft | None = None
        elevated: SessionPrincipal | None = None
        async with self._unit_of_work_factory() as unit_of_work:
            user = await unit_of_work.auth.find_user_by_username(principal.username)
            verification = await asyncio.to_thread(
                verify_password, user.credential.password_hash if user else None, password
            )
            if user is None or not verification.valid:
                credentials_error = InvalidCredentialsError()
                credentials_error.audit_metadata = {
                    "totp_policy_enabled": self._settings.totp_enabled,
                    "authentication_factors": ["PASSWORD"],
                }
                raise credentials_error
            used_recovery = False
            authentication_factors = ["PASSWORD"]
            if self._settings.totp_enabled:
                factor = await unit_of_work.auth.get_mfa_factor(principal.user_id)
                if factor is None or factor.confirmed_at is None or mfa_value is None:
                    missing_mfa_error = InvalidMfaCodeError()
                    missing_mfa_error.audit_metadata = {
                        "totp_policy_enabled": True,
                        "authentication_factors": ["PASSWORD"],
                    }
                    raise missing_mfa_error
                verified, used_recovery = await self._verify_mfa_value(
                    unit_of_work, factor, mfa_value, allow_recovery=True
                )
                if not verified:
                    invalid_mfa_error = InvalidMfaCodeError()
                    invalid_mfa_error.audit_metadata = {
                        "totp_policy_enabled": True,
                        "authentication_factors": ["PASSWORD", "TOTP_OR_RECOVERY_CODE"],
                    }
                    raise invalid_mfa_error
                authentication_factors.append("RECOVERY_CODE" if used_recovery else "TOTP")
            reauthenticated_at = utc_now()
            elevated = await unit_of_work.auth.elevate_session(
                principal.session_id,
                reauthenticated_at=reauthenticated_at,
                elevated_until=reauthenticated_at + REAUTHENTICATION_TTL,
            )
            if elevated is None:
                raise InvalidSessionError()
            event = new_audit_event(
                AuditAction.AUTH_REAUTH_SUCCEEDED,
                AuditOutcome.SUCCEEDED,
                source=self._audit_source,
                actor_user_id=principal.user_id,
                session_id=principal.session_id,
                resource_type="session",
                resource_id=principal.session_id,
                metadata={
                    "recovery_code_used": used_recovery,
                    "totp_policy_enabled": self._settings.totp_enabled,
                    "authentication_factors": authentication_factors,
                },
            )
            await unit_of_work.audit.append(event)
        emit_audit_event(event)
        return elevated

    async def activate(self, activation_code: str, password: str) -> AuthResult:
        self._validate_password(password)
        password_hash = await asyncio.to_thread(hash_password, password)
        now = utc_now()
        result: AuthResult | None = None
        async with self._unit_of_work_factory() as unit_of_work:
            grant = await unit_of_work.auth.consume_activation_token(
                hash_token(activation_code), now
            )
            if grant is None:
                raise ActivationExpiredError()
            requires_mfa = grant.user.role in MFA_REQUIRED_ROLES
            user = await unit_of_work.auth.activate_user(
                grant.user.user_id,
                password_hash=password_hash,
                mfa_enrollment_required=requires_mfa,
                activated_at=now,
            )
            result = (
                await self._issue_challenge(
                    unit_of_work,
                    user,
                    ChallengePurpose.MFA_ENROLLMENT,
                    begin_enrollment=True,
                )
                if requires_mfa and self._settings.totp_enabled
                else await self._issue(
                    unit_of_work,
                    user,
                    elevated=not self._settings.totp_enabled,
                )
            )
            event = new_audit_event(
                AuditAction.USER_ACTIVATED,
                AuditOutcome.SUCCEEDED,
                source=self._audit_source,
                actor_user_id=user.user_id,
                resource_type="user",
                resource_id=user.user_id,
                metadata={
                    "role": user.role.value,
                    "mfa_required": requires_mfa and self._settings.totp_enabled,
                    "mfa_enrollment_required": requires_mfa,
                    "totp_policy_enabled": self._settings.totp_enabled,
                },
            )
            await unit_of_work.audit.append(event)
        emit_audit_event(event)
        if result is None:
            raise RuntimeError("activation produced no result")
        return result

    async def list_users(self, actor: SessionPrincipal) -> tuple[UserIdentity, ...]:
        require_permission(actor, Permission.USER_READ)
        async with self._unit_of_work_factory() as unit_of_work:
            return await unit_of_work.auth.list_users()

    async def create_user(
        self, actor: SessionPrincipal, *, username: str, role: UserRole
    ) -> CreatedUser:
        require_permission(actor, Permission.USER_MANAGE)
        require_recent_reauthentication(actor)
        normalized = canonical_username(username)
        self._validate_username(normalized)
        now = utc_now()
        identity = UserIdentity(
            user_id=uuid4(),
            username=normalized,
            status=UserStatus.PENDING_ACTIVATION,
            role=role,
            mfa_enrollment_required=role in MFA_REQUIRED_ROLES,
            version=1,
            created_at=now,
            updated_at=now,
        )
        activation_code = generate_token()
        expires_at = now + ACTIVATION_TTL
        try:
            async with self._unit_of_work_factory() as unit_of_work:
                created = await unit_of_work.auth.add_user(identity)
                await unit_of_work.auth.add_activation_token(
                    activation_token_id=uuid4(),
                    user_id=created.user_id,
                    token_hash=hash_token(activation_code),
                    created_by=actor.user_id,
                    expires_at=expires_at,
                    created_at=now,
                )
                event = new_audit_event(
                    AuditAction.USER_CREATED,
                    AuditOutcome.SUCCEEDED,
                    source=self._audit_source,
                    actor_user_id=actor.user_id,
                    session_id=actor.session_id,
                    resource_type="user",
                    resource_id=created.user_id,
                    metadata={"role": role.value},
                )
                await unit_of_work.audit.append(event)
        except AdminAlreadyExistsError as error:
            raise UserConflictError() from error
        emit_audit_event(event)
        return CreatedUser(created, activation_code, expires_at)

    async def reissue_activation(self, actor: SessionPrincipal, user_id: UUID) -> CreatedUser:
        require_permission(actor, Permission.USER_MANAGE)
        require_recent_reauthentication(actor)
        now = utc_now()
        code = generate_token()
        expires_at = now + ACTIVATION_TTL
        async with self._unit_of_work_factory() as unit_of_work:
            user = await unit_of_work.auth.get_user(user_id)
            if user is None or user.status is not UserStatus.PENDING_ACTIVATION:
                raise ActivationExpiredError()
            await unit_of_work.auth.invalidate_activation_tokens(user_id, now)
            await unit_of_work.auth.add_activation_token(
                activation_token_id=uuid4(),
                user_id=user_id,
                token_hash=hash_token(code),
                created_by=actor.user_id,
                expires_at=expires_at,
                created_at=now,
            )
            event = new_audit_event(
                AuditAction.USER_ACTIVATION_REISSUED,
                AuditOutcome.SUCCEEDED,
                source=self._audit_source,
                actor_user_id=actor.user_id,
                session_id=actor.session_id,
                resource_type="user",
                resource_id=user_id,
            )
            await unit_of_work.audit.append(event)
        emit_audit_event(event)
        return CreatedUser(user, code, expires_at)

    async def update_user(
        self,
        actor: SessionPrincipal,
        user_id: UUID,
        *,
        role: UserRole,
        status: UserStatus,
        expected_version: int,
    ) -> UserIdentity:
        require_permission(actor, Permission.USER_MANAGE)
        require_recent_reauthentication(actor)
        now = utc_now()
        try:
            async with self._unit_of_work_factory() as unit_of_work:
                before = await unit_of_work.auth.get_user(user_id)
                if before is None:
                    raise InvalidCredentialsError()
                if (
                    before.status is UserStatus.PENDING_ACTIVATION
                    and status is UserStatus.ACTIVE
                ):
                    raise UserConflictError()
                if (
                    before.status is not UserStatus.PENDING_ACTIVATION
                    and status is UserStatus.PENDING_ACTIVATION
                ):
                    raise UserConflictError()
                if status is UserStatus.ACTIVE and before.activated_at is None:
                    raise UserConflictError()
                updated = await unit_of_work.auth.update_user(
                    user_id,
                    role=role,
                    status=status.value,
                    expected_version=expected_version,
                    updated_at=now,
                )
                if updated is None:
                    raise UserVersionConflictError()
                await unit_of_work.auth.delete_user_sessions(user_id)
                event = new_audit_event(
                    (
                        AuditAction.USER_DISABLED
                        if status is UserStatus.DISABLED
                        else (
                            AuditAction.USER_ROLE_CHANGED
                            if role is not before.role
                            else AuditAction.USER_UPDATED
                        )
                    ),
                    AuditOutcome.SUCCEEDED,
                    source=self._audit_source,
                    actor_user_id=actor.user_id,
                    session_id=actor.session_id,
                    resource_type="user",
                    resource_id=user_id,
                    metadata={
                        "previous_role": before.role.value,
                        "role": role.value,
                        "previous_status": before.status.value,
                        "status": status.value,
                    },
                )
                await unit_of_work.audit.append(event)
        except Exception as error:
            if (
                getattr(getattr(error, "diag", None), "constraint_name", None)
                == "ck_users_active_owner"
            ):
                raise LastOwnerRequiredError() from error
            raise
        emit_audit_event(event)
        return updated

    async def reset_user_mfa(self, actor: SessionPrincipal, user_id: UUID) -> None:
        require_permission(actor, Permission.USER_MANAGE)
        require_recent_reauthentication(actor)
        if actor.user_id == user_id:
            raise PermissionDeniedError()
        now = utc_now()
        async with self._unit_of_work_factory() as unit_of_work:
            user = await unit_of_work.auth.get_user(user_id)
            if user is None:
                raise InvalidCredentialsError()
            await unit_of_work.auth.reset_mfa(user_id, now)
            event = new_audit_event(
                AuditAction.USER_MFA_RESET,
                AuditOutcome.SUCCEEDED,
                source=self._audit_source,
                actor_user_id=actor.user_id,
                session_id=actor.session_id,
                resource_type="user",
                resource_id=user_id,
            )
            await unit_of_work.audit.append(event)
        emit_audit_event(event)

    async def security_status(self, actor: SessionPrincipal) -> SecurityStatus:
        async with self._unit_of_work_factory() as unit_of_work:
            factor = await unit_of_work.auth.get_mfa_factor(actor.user_id)
            count = await unit_of_work.auth.count_unused_recovery_codes(actor.user_id)
        return SecurityStatus(
            totp_policy_enabled=self._settings.totp_enabled,
            mfa_enabled=factor is not None and factor.confirmed_at is not None,
            mfa_enrollment_required=actor.mfa_enrollment_required,
            unused_recovery_codes=count,
            elevated_until=actor.elevated_until,
        )

    async def regenerate_recovery_codes(
        self, actor: SessionPrincipal
    ) -> tuple[str, ...]:
        self._require_totp_enabled()
        require_recent_reauthentication(actor)
        now = utc_now()
        codes = generate_recovery_codes()
        rows = tuple((uuid4(), hash_recovery_code(code)) for code in codes)
        async with self._unit_of_work_factory() as unit_of_work:
            factor = await unit_of_work.auth.get_mfa_factor(actor.user_id)
            if factor is None or factor.confirmed_at is None:
                raise InvalidMfaCodeError()
            await unit_of_work.auth.replace_recovery_codes(actor.user_id, rows, now)
            event = new_audit_event(
                AuditAction.USER_RECOVERY_CODES_REGENERATED,
                AuditOutcome.SUCCEEDED,
                source=self._audit_source,
                actor_user_id=actor.user_id,
                session_id=actor.session_id,
                resource_type="user",
                resource_id=actor.user_id,
                metadata={"code_count": len(codes)},
            )
            await unit_of_work.audit.append(event)
        emit_audit_event(event)
        return codes

    async def change_password(
        self,
        actor: SessionPrincipal,
        *,
        current_password: str,
        new_password: str,
        mfa_value: str | None,
    ) -> None:
        self._validate_password(new_password)
        now = utc_now()
        async with self._unit_of_work_factory() as unit_of_work:
            user = await unit_of_work.auth.find_user_by_username(actor.username)
            verification = await asyncio.to_thread(
                verify_password,
                user.credential.password_hash if user is not None else None,
                current_password,
            )
            if user is None or user.identity.user_id != actor.user_id or not verification.valid:
                raise InvalidCredentialsError()
            factor = await unit_of_work.auth.get_mfa_factor(actor.user_id)
            if (
                self._settings.totp_enabled
                and factor is not None
                and factor.confirmed_at is not None
            ):
                if mfa_value is None:
                    raise InvalidMfaCodeError()
                verified, _ = await self._verify_mfa_value(
                    unit_of_work, factor, mfa_value, allow_recovery=True
                )
                if not verified:
                    raise InvalidMfaCodeError()
            password_hash = await asyncio.to_thread(hash_password, new_password)
            await unit_of_work.auth.update_password_hash(actor.user_id, password_hash, now)
            await unit_of_work.auth.delete_user_sessions(actor.user_id)
            event = new_audit_event(
                AuditAction.USER_PASSWORD_CHANGED,
                AuditOutcome.SUCCEEDED,
                source=self._audit_source,
                actor_user_id=actor.user_id,
                session_id=actor.session_id,
                resource_type="user",
                resource_id=actor.user_id,
            )
            await unit_of_work.audit.append(event)
        emit_audit_event(event)

    async def break_glass_reset_mfa(self, username: str, confirmation: str) -> UserIdentity:
        normalized = canonical_username(username)
        expected = f"RESET MFA FOR {normalized}"
        if confirmation != expected:
            raise ValueError(f"confirmation must exactly match: {expected}")
        now = utc_now()
        async with self._unit_of_work_factory() as unit_of_work:
            user = await unit_of_work.auth.find_user_by_username(normalized)
            if (
                user is None
                or user.identity.role is not UserRole.OWNER
                or user.identity.status is not UserStatus.ACTIVE
                or await unit_of_work.auth.count_active_owners() != 1
            ):
                raise ValueError(
                    "break-glass is allowed only for the sole active OWNER; use another OWNER"
                )
            await unit_of_work.auth.reset_mfa(user.identity.user_id, now)
            event = new_audit_event(
                AuditAction.USER_MFA_BREAK_GLASS,
                AuditOutcome.SUCCEEDED,
                source=AuditSource.CLI,
                actor_user_id=user.identity.user_id,
                resource_type="user",
                resource_id=user.identity.user_id,
                metadata={"confirmation_phrase_verified": True},
            )
            await unit_of_work.audit.append(event)
        emit_audit_event(event)
        return user.identity.model_copy(
            update={
                "mfa_enrollment_required": True,
                "version": user.identity.version + 1,
                "updated_at": now,
            }
        )

    async def break_glass_reset_password(
        self,
        username: str,
        confirmation: str,
        new_password: str,
    ) -> UserIdentity:
        normalized = canonical_username(username)
        self._validate_username(normalized)
        expected = f"RESET PASSWORD FOR {normalized}"
        if confirmation != expected:
            raise ValueError(f"confirmation must exactly match: {expected}")
        self._validate_password(new_password)
        password_hash = await asyncio.to_thread(hash_password, new_password)
        now = utc_now()
        async with self._unit_of_work_factory() as unit_of_work:
            user = await unit_of_work.auth.find_user_by_username(normalized)
            if (
                user is None
                or user.identity.role is not UserRole.OWNER
                or user.identity.status is not UserStatus.ACTIVE
                or await unit_of_work.auth.count_active_owners() != 1
            ):
                raise ValueError(
                    "break-glass is allowed only for the sole active OWNER; use another OWNER"
                )
            await unit_of_work.auth.update_password_hash(
                user.identity.user_id,
                password_hash,
                now,
            )
            await unit_of_work.auth.delete_user_sessions(user.identity.user_id)
            event = new_audit_event(
                AuditAction.USER_PASSWORD_CHANGED,
                AuditOutcome.SUCCEEDED,
                source=AuditSource.CLI,
                actor_user_id=user.identity.user_id,
                resource_type="user",
                resource_id=user.identity.user_id,
                metadata={
                    "break_glass": True,
                    "confirmation_phrase_verified": True,
                    "sessions_revoked": True,
                },
            )
            await unit_of_work.audit.append(event)
        emit_audit_event(event)
        return user.identity.model_copy(
            update={
                "version": user.identity.version + 1,
                "updated_at": now,
            }
        )

    async def resolve(self, session_token: str) -> SessionPrincipal:
        async with self._unit_of_work_factory() as unit_of_work:
            principal = await unit_of_work.auth.resolve_session(
                hash_token(session_token), utc_now()
            )
            if principal is None:
                raise InvalidSessionError()
            if self._settings.totp_enabled:
                required_without_factor = (
                    principal.role in MFA_REQUIRED_ROLES and not principal.mfa_enabled
                )
                factor_not_verified_for_session = (
                    principal.mfa_enabled and principal.mfa_verified_at is None
                )
                if (
                    principal.mfa_enrollment_required
                    or required_without_factor
                    or factor_not_verified_for_session
                ):
                    raise InvalidSessionError()
            return principal

    async def logout(self, principal: SessionPrincipal) -> None:
        event = new_audit_event(
            AuditAction.AUTH_LOGOUT_SUCCEEDED,
            AuditOutcome.SUCCEEDED,
            source=self._audit_source,
            actor_user_id=principal.user_id,
            session_id=principal.session_id,
            resource_type="session",
            resource_id=principal.session_id,
        )
        async with self._unit_of_work_factory() as unit_of_work:
            await unit_of_work.auth.delete_session(principal.session_id)
            await unit_of_work.audit.append(event)
        emit_audit_event(event)

    @staticmethod
    def require_csrf(principal: SessionPrincipal, csrf_token: str) -> None:
        if not token_matches(csrf_token, principal.csrf_hash):
            raise CsrfValidationError()

    async def purge_expired(self, *, dry_run: bool = False) -> tuple[int, int]:
        now = utc_now()
        async with self._unit_of_work_factory() as unit_of_work:
            if dry_run:
                result = await unit_of_work.auth.count_expired(now)
            else:
                result = await unit_of_work.auth.purge_expired(now)
                event = new_audit_event(
                    AuditAction.AUTH_PURGE_COMPLETED,
                    AuditOutcome.SUCCEEDED,
                    source=AuditSource.CLI,
                    metadata={"sessions": result[0], "rate_limits": result[1]},
                )
                await unit_of_work.audit.append(event)
        if dry_run:
            return result
        emit_audit_event(event)
        return result
