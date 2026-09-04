from __future__ import annotations

import asyncio
import math
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from ops_composer.auth.errors import (
    AdminAlreadyExistsError,
    AuthRateLimitedError,
    CsrfValidationError,
    InvalidCredentialsError,
    InvalidSessionError,
)
from ops_composer.auth.models import (
    IssuedSession,
    PasswordCredential,
    SessionPrincipal,
    UserIdentity,
    UserStatus,
)
from ops_composer.auth.security import (
    generate_token,
    hash_password,
    hash_token,
    hmac_subject,
    token_matches,
    verify_password,
)
from ops_composer.domain.audit import AuditAction, AuditEventDraft, AuditOutcome, AuditSource
from ops_composer.domain.base import utc_now
from ops_composer.services.audit import emit_audit_event, new_audit_event
from ops_composer.settings import Settings
from ops_composer.uow.factory import UnitOfWorkFactory
from ops_composer.uow.unit import UnitOfWork


def canonical_username(username: str) -> str:
    return username.strip().casefold()


def fixed_window(now: datetime, seconds: int) -> tuple[datetime, datetime]:
    epoch = int(now.timestamp())
    start_epoch = epoch - (epoch % seconds)
    start = datetime.fromtimestamp(start_epoch, UTC)
    return start, start + timedelta(seconds=seconds)


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


class AuthService:
    def __init__(
        self,
        unit_of_work_factory: UnitOfWorkFactory,
        settings: Settings,
        *,
        audit_source: AuditSource = AuditSource.API,
    ) -> None:
        self._unit_of_work_factory = unit_of_work_factory
        self._settings = settings
        self._session_ttl = timedelta(seconds=settings.session_ttl_seconds)
        self._audit_source = audit_source

    async def bootstrap(self, username: str, password: str) -> UserIdentity:
        normalized = canonical_username(username)
        if not normalized or len(normalized) > 64:
            raise ValueError("username must contain between 1 and 64 characters")
        if len(password) < 12 or len(password) > 200:
            raise ValueError("password must contain between 12 and 200 characters")
        password_hash = await asyncio.to_thread(hash_password, password)
        now = utc_now()
        identity = UserIdentity(
            user_id=uuid4(),
            username=normalized,
            status=UserStatus.ACTIVE,
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
        )
        async with self._unit_of_work_factory() as unit_of_work:
            if await unit_of_work.auth.count_users() != 0:
                raise AdminAlreadyExistsError()
            created = await unit_of_work.auth.add_admin(identity, credential)
            await unit_of_work.audit.append(event)
        emit_audit_event(event)
        return created

    async def _issue(self, unit_of_work: UnitOfWork, user: UserIdentity) -> IssuedSession:
        session_token = generate_token()
        csrf_token = generate_token()
        csrf_hash = hash_token(csrf_token)
        now = utc_now()
        session_id = uuid4()
        expires_at = now + self._session_ttl
        await unit_of_work.auth.add_session(
            session_id=session_id,
            user_id=user.user_id,
            token_hash=hash_token(session_token),
            csrf_hash=csrf_hash,
            expires_at=expires_at,
            created_at=now,
        )
        return IssuedSession(
            principal=SessionPrincipal(
                session_id=session_id,
                user_id=user.user_id,
                username=user.username,
                csrf_hash=csrf_hash,
                expires_at=expires_at,
            ),
            session_token=session_token,
            csrf_token=csrf_token,
        )

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
            }
            raise error
        return consumed

    async def login(self, username: str, password: str, client_key: str) -> IssuedSession:
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
        issued: IssuedSession | None = None
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
                }
                raise error
            if verification.needs_rehash:
                replacement = await asyncio.to_thread(hash_password, password)
                await unit_of_work.auth.update_password_hash(
                    user.identity.user_id, replacement, utc_now()
                )
            await unit_of_work.auth.clear_rate_limit(
                scope=username_ip_bucket.scope,
                subject_hash=username_ip_bucket.subject_hash,
                window_started_at=username_ip_bucket.window_started_at,
            )
            issued = await self._issue(unit_of_work, user.identity)
            event = new_audit_event(
                AuditAction.AUTH_LOGIN_SUCCEEDED,
                AuditOutcome.SUCCEEDED,
                source=self._audit_source,
                actor_user_id=user.identity.user_id,
                session_id=issued.principal.session_id,
                resource_type="session",
                resource_id=issued.principal.session_id,
                metadata={"password_rehashed": verification.needs_rehash},
            )
            await unit_of_work.audit.append(event)
        if issued is None or event is None:
            raise RuntimeError("authentication transaction produced no session")
        emit_audit_event(event)
        return issued

    async def resolve(self, session_token: str) -> SessionPrincipal:
        async with self._unit_of_work_factory() as unit_of_work:
            principal = await unit_of_work.auth.resolve_session(
                hash_token(session_token), utc_now()
            )
            if principal is None:
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
