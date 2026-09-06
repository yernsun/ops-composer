from __future__ import annotations

from datetime import datetime, timedelta
from uuid import UUID, uuid4

from ops_composer.auth.models import SessionPrincipal
from ops_composer.domain.audit import (
    AuditAction,
    AuditEventDraft,
    AuditOutcome,
    AuditSeverity,
    AuditSource,
)
from ops_composer.domain.base import utc_now
from ops_composer.domain.errors import (
    HostBusyError,
    HostKeyConfirmationRequiredError,
    NotFoundError,
    ValidationError,
    WebShellCapacityError,
    WebShellSessionExpiredError,
    WebShellUnavailableError,
)
from ops_composer.domain.web_shell import (
    WebShellCloseReason,
    WebShellLaunch,
    WebShellSession,
    WebShellState,
)
from ops_composer.services.audit import emit_audit_event, new_audit_event
from ops_composer.services.crypto import CredentialCipher
from ops_composer.settings import Settings
from ops_composer.uow.factory import UnitOfWorkFactory

WEB_SHELL_TICKET_SECONDS = 30
WEB_SHELL_LEASE_SECONDS = 30


class WebShellService:
    def __init__(
        self,
        unit_of_work_factory: UnitOfWorkFactory,
        settings: Settings,
        cipher: CredentialCipher,
    ) -> None:
        self._unit_of_work_factory = unit_of_work_factory
        self._settings = settings
        self._cipher = cipher

    async def create(
        self,
        host_id: UUID,
        principal: SessionPrincipal,
        owner_id: str,
    ) -> WebShellSession:
        now = utc_now()
        ticket_expires_at = now + timedelta(seconds=WEB_SHELL_TICKET_SECONDS)
        session: WebShellSession | None = None
        event = None
        recovered_event = None
        async with self._unit_of_work_factory() as unit_of_work:
            await unit_of_work.web_shell.acquire_admission_lock()
            recovered = await unit_of_work.web_shell.cleanup_expired(now)
            if recovered:
                recovered_event = new_audit_event(
                    AuditAction.WEB_SHELL_STALE_RECOVERED,
                    AuditOutcome.SUCCEEDED,
                    source=AuditSource.API,
                    metadata={"session_count": recovered},
                )
                await unit_of_work.audit.append(recovered_event)
            live_sessions = await unit_of_work.web_shell.count_live(now)
            if live_sessions >= self._settings.web_shell_max_sessions:
                raise WebShellCapacityError(
                    details={"maxSessions": self._settings.web_shell_max_sessions}
                )
            host = await unit_of_work.assets.get_host(host_id)
            if host is None:
                raise NotFoundError("host not found")
            if not host.enabled:
                raise ValidationError("host is disabled", details={"hostId": str(host_id)})
            resolved = await unit_of_work.assets.resolve_host_ids((host_id,))
            if len(resolved) != 1:
                raise ValidationError("host credential is missing or disabled")
            target = resolved[0]
            host_keys = await unit_of_work.assets.list_host_keys(host_id)
            if not host_keys:
                raise HostKeyConfirmationRequiredError(
                    details={"hostId": str(host_id), "name": target.name}
                )
            session = WebShellSession(
                web_shell_session_id=uuid4(),
                host_id=target.host_id,
                actor_user_id=principal.user_id,
                auth_session_id=principal.session_id,
                credential_id=target.credential_id,
                credential_version=target.credential_version,
                host_name=target.name,
                host_address=target.address,
                ssh_port=target.ssh_port,
                username=target.credential_username,
                state=WebShellState.PENDING,
                api_instance_id=owner_id,
                ticket_expires_at=ticket_expires_at,
                lease_expires_at=ticket_expires_at,
                created_at=now,
            )
            session = await unit_of_work.web_shell.add(session)
            acquired = await unit_of_work.web_shell.acquire_host_lock(
                host_id,
                session.web_shell_session_id,
                f"pending:{owner_id}",
                now,
                ticket_expires_at,
            )
            if not acquired:
                raise HostBusyError(details={"hostId": str(host_id)})
            event = new_audit_event(
                AuditAction.WEB_SHELL_REQUESTED,
                AuditOutcome.SUCCEEDED,
                source=AuditSource.API,
                actor_user_id=principal.user_id,
                session_id=principal.session_id,
                resource_type="web_shell_session",
                resource_id=session.web_shell_session_id,
                metadata={
                    "host_id": host_id,
                    "host_name": target.name,
                    "ssh_port": target.ssh_port,
                    "credential_id": target.credential_id,
                    "credential_version": target.credential_version,
                    "ticket_seconds": WEB_SHELL_TICKET_SECONDS,
                },
            )
            await unit_of_work.audit.append(event)
        if recovered_event is not None:
            emit_audit_event(recovered_event)
        if event is None or session is None:
            raise RuntimeError("Web Shell create transaction produced no session")
        emit_audit_event(event)
        return session

    async def claim(
        self,
        web_shell_session_id: UUID,
        principal: SessionPrincipal,
        owner_id: str,
    ) -> WebShellLaunch:
        now = utc_now()
        expires_at = now + timedelta(seconds=WEB_SHELL_LEASE_SECONDS)
        event = None
        launch: WebShellLaunch | None = None
        async with self._unit_of_work_factory() as unit_of_work:
            current = await unit_of_work.web_shell.get(web_shell_session_id, for_update=True)
            if (
                current is None
                or current.actor_user_id != principal.user_id
                or current.auth_session_id != principal.session_id
                or current.state is not WebShellState.PENDING
                or current.ticket_expires_at <= now
            ):
                raise WebShellSessionExpiredError()
            active = await unit_of_work.web_shell.activate(
                web_shell_session_id,
                principal.session_id,
                owner_id,
                now,
                expires_at,
            )
            if active is None:
                raise WebShellSessionExpiredError()
            revision = await unit_of_work.assets.get_credential_revision(
                active.credential_id, active.credential_version
            )
            if revision is None:
                raise WebShellUnavailableError("credential revision is unavailable")
            if revision.encryption_key_version != self._cipher.key_version:
                raise WebShellUnavailableError("credential key version is unavailable")
            secret = self._cipher.decrypt(
                revision.credential_id,
                revision.version,
                revision.encrypted_secret,
            )
            password = secret.get("password")
            if not password or "\x00" in password or "\n" in password or "\r" in password:
                raise WebShellUnavailableError("credential password is unsupported for Web Shell")
            keys = await unit_of_work.assets.list_host_keys(active.host_id)
            if not keys:
                raise HostKeyConfirmationRequiredError(
                    details={"hostId": str(active.host_id), "name": active.host_name}
                )
            marker = (
                active.host_address
                if active.ssh_port == 22
                else f"[{active.host_address}]:{active.ssh_port}"
            )
            known_hosts = "".join(
                f"{marker} {key.algorithm} {key.public_key}\n" for key in keys
            )
            launch = WebShellLaunch(
                session=active,
                password=password,
                known_hosts=known_hosts,
            )
            event = new_audit_event(
                AuditAction.WEB_SHELL_STARTED,
                AuditOutcome.SUCCEEDED,
                source=AuditSource.API,
                actor_user_id=principal.user_id,
                session_id=principal.session_id,
                resource_type="web_shell_session",
                resource_id=web_shell_session_id,
                metadata={
                    "host_id": active.host_id,
                    "host_name": active.host_name,
                    "ssh_port": active.ssh_port,
                    "credential_id": active.credential_id,
                    "credential_version": active.credential_version,
                    "lease_seconds": WEB_SHELL_LEASE_SECONDS,
                },
            )
            await unit_of_work.audit.append(event)
        if launch is None or event is None:
            raise RuntimeError("Web Shell claim transaction produced no launch")
        emit_audit_event(event)
        return launch

    async def heartbeat(
        self,
        web_shell_session_id: UUID,
        owner_id: str,
        last_activity_at: datetime,
    ) -> WebShellCloseReason | None:
        now = utc_now()
        expires_at = now + timedelta(seconds=WEB_SHELL_LEASE_SECONDS)
        async with self._unit_of_work_factory() as unit_of_work:
            refreshed = await unit_of_work.web_shell.heartbeat(
                web_shell_session_id,
                owner_id,
                now,
                expires_at,
                last_activity_at,
            )
        if refreshed:
            return None
        async with self._unit_of_work_factory() as unit_of_work:
            current = await unit_of_work.web_shell.get(web_shell_session_id)
        if (
            current is not None
            and current.owner_id == owner_id
            and current.state is WebShellState.CLOSE_REQUESTED
        ):
            return WebShellCloseReason.USER_REQUESTED
        return WebShellCloseReason.AUTH_SESSION_INVALID

    async def request_close(
        self, web_shell_session_id: UUID, principal: SessionPrincipal
    ) -> None:
        event = None
        async with self._unit_of_work_factory() as unit_of_work:
            current = await unit_of_work.web_shell.get(web_shell_session_id, for_update=True)
            if current is None or current.actor_user_id != principal.user_id:
                return
            if current.state is WebShellState.PENDING:
                await unit_of_work.web_shell.delete(web_shell_session_id)
                event = self._finished_event(
                    current,
                    WebShellCloseReason.USER_REQUESTED,
                    duration_ms=0,
                    exit_code=None,
                )
            elif current.state is WebShellState.ACTIVE:
                updated = await unit_of_work.web_shell.mark_close_requested(
                    web_shell_session_id, principal.user_id, utc_now()
                )
                if updated is not None:
                    event = new_audit_event(
                        AuditAction.WEB_SHELL_CLOSE_REQUESTED,
                        AuditOutcome.SUCCEEDED,
                        source=AuditSource.API,
                        actor_user_id=principal.user_id,
                        session_id=principal.session_id,
                        resource_type="web_shell_session",
                        resource_id=web_shell_session_id,
                        metadata={"host_id": current.host_id, "host_name": current.host_name},
                    )
            if event is not None:
                await unit_of_work.audit.append(event)
        if event is not None:
            emit_audit_event(event)

    async def finish(
        self,
        web_shell_session_id: UUID,
        owner_id: str,
        reason: WebShellCloseReason,
        *,
        duration_ms: float,
        exit_code: int | None,
    ) -> None:
        event = None
        async with self._unit_of_work_factory() as unit_of_work:
            current = await unit_of_work.web_shell.delete(web_shell_session_id, owner_id)
            if current is None:
                return
            event = self._finished_event(
                current,
                reason,
                duration_ms=duration_ms,
                exit_code=exit_code,
            )
            await unit_of_work.audit.append(event)
        if event is not None:
            emit_audit_event(event)

    async def discard_failed_claim(
        self,
        web_shell_session_id: UUID,
        owner_id: str,
        reason: WebShellCloseReason,
    ) -> None:
        await self.finish(
            web_shell_session_id,
            owner_id,
            reason,
            duration_ms=0,
            exit_code=None,
        )

    async def recover_stale(self) -> int:
        event = None
        async with self._unit_of_work_factory() as unit_of_work:
            await unit_of_work.web_shell.acquire_admission_lock()
            count = await unit_of_work.web_shell.cleanup_expired(utc_now())
            if count:
                event = new_audit_event(
                    AuditAction.WEB_SHELL_STALE_RECOVERED,
                    AuditOutcome.SUCCEEDED,
                    source=AuditSource.SYSTEM,
                    metadata={"session_count": count},
                )
                await unit_of_work.audit.append(event)
        if event is not None:
            emit_audit_event(event)
        return count

    @staticmethod
    def _finished_event(
        session: WebShellSession,
        reason: WebShellCloseReason,
        *,
        duration_ms: float,
        exit_code: int | None,
    ) -> AuditEventDraft:
        timed_out = reason in {
            WebShellCloseReason.IDLE_TIMEOUT,
            WebShellCloseReason.MAX_DURATION,
        }
        failed = reason in {
            WebShellCloseReason.AUTH_SESSION_INVALID,
            WebShellCloseReason.DATABASE_UNAVAILABLE,
            WebShellCloseReason.START_FAILED,
            WebShellCloseReason.PROTOCOL_ERROR,
            WebShellCloseReason.SLOW_CONSUMER,
        }
        action = (
            AuditAction.WEB_SHELL_TIMED_OUT
            if timed_out
            else AuditAction.WEB_SHELL_FAILED
            if failed
            else AuditAction.WEB_SHELL_CLOSED
        )
        return new_audit_event(
            action,
            AuditOutcome.FAILED if failed or timed_out else AuditOutcome.SUCCEEDED,
            source=AuditSource.API,
            severity=AuditSeverity.WARNING if failed or timed_out else AuditSeverity.INFO,
            actor_user_id=session.actor_user_id,
            session_id=session.auth_session_id,
            resource_type="web_shell_session",
            resource_id=session.web_shell_session_id,
            duration_ms=duration_ms,
            error_code=reason.value.casefold() if failed or timed_out else None,
            failure_stage="web_shell_session" if failed or timed_out else None,
            retryable=reason is WebShellCloseReason.DATABASE_UNAVAILABLE,
            metadata={
                "host_id": session.host_id,
                "host_name": session.host_name,
                "ssh_port": session.ssh_port,
                "credential_id": session.credential_id,
                "credential_version": session.credential_version,
                "close_reason": reason.value,
                "exit_code": exit_code,
            },
        )
