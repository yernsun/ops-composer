from __future__ import annotations

import asyncio
import json
import time
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID, uuid4

from starlette.websockets import WebSocket, WebSocketDisconnect, WebSocketState

from ops_composer.auth.models import SessionPrincipal
from ops_composer.domain.audit import AuditAction, AuditOutcome, AuditSeverity, AuditSource
from ops_composer.domain.base import utc_now
from ops_composer.domain.errors import OpsError
from ops_composer.domain.web_shell import WebShellCloseReason, WebShellSession
from ops_composer.observability import log_context, log_event, safe_exception_fields
from ops_composer.services.crypto import CredentialCipher
from ops_composer.services.web_shell import WebShellService
from ops_composer.settings import Settings
from ops_composer.ssh_terminal import SshTerminal, SshTerminalStartError
from ops_composer.uow.factory import UnitOfWorkFactory

WEB_SHELL_HEARTBEAT_SECONDS = 10
WEB_SHELL_MAX_FRAME_BYTES = 64 * 1024
WEB_SHELL_OUTPUT_BUFFER_BYTES = 1024 * 1024
WEB_SHELL_SEND_TIMEOUT_SECONDS = 10
WEB_SHELL_MIN_COLUMNS = 20
WEB_SHELL_MAX_COLUMNS = 500
WEB_SHELL_MIN_ROWS = 5
WEB_SHELL_MAX_ROWS = 200


@dataclass
class ActiveWebShell:
    session: WebShellSession
    terminal: SshTerminal
    owner_id: str
    started_monotonic: float
    last_activity_monotonic: float
    last_activity_at: datetime
    requested_close_reason: WebShellCloseReason | None = None
    finished: asyncio.Event | None = None

    def touch(self) -> None:
        self.last_activity_monotonic = time.monotonic()
        self.last_activity_at = utc_now()


class WebShellManager:
    def __init__(
        self,
        factory: UnitOfWorkFactory,
        settings: Settings,
        cipher: CredentialCipher,
    ) -> None:
        self._settings = settings
        self._service = WebShellService(factory, settings, cipher)
        self.instance_id = f"api-{uuid4().hex}"
        self._active: dict[UUID, ActiveWebShell] = {}
        self._active_lock = asyncio.Lock()
        self._shutdown = asyncio.Event()

    async def start(self) -> None:
        await self._service.recover_stale()

    async def stop(self) -> None:
        self._shutdown.set()
        async with self._active_lock:
            active_sessions = tuple(self._active.values())
            for item in active_sessions:
                item.requested_close_reason = WebShellCloseReason.SERVER_SHUTDOWN
            terminals = tuple(item.terminal for item in active_sessions)
        await asyncio.gather(*(terminal.close() for terminal in terminals), return_exceptions=True)
        waiters = tuple(item.finished.wait() for item in active_sessions if item.finished)
        if waiters:
            with suppress(TimeoutError):
                await asyncio.wait_for(asyncio.gather(*waiters), timeout=5)

    async def create(
        self, host_id: UUID, principal: SessionPrincipal
    ) -> WebShellSession:
        return await self._service.create(host_id, principal, self.instance_id)

    async def request_close(
        self, web_shell_session_id: UUID, principal: SessionPrincipal
    ) -> None:
        await self._service.request_close(web_shell_session_id, principal)
        async with self._active_lock:
            active = self._active.get(web_shell_session_id)
            if active is not None and active.session.actor_user_id == principal.user_id:
                active.requested_close_reason = WebShellCloseReason.USER_REQUESTED
        if active is not None and active.session.actor_user_id == principal.user_id:
            await active.terminal.close()

    async def stream(
        self,
        websocket: WebSocket,
        web_shell_session_id: UUID,
        principal: SessionPrincipal,
    ) -> None:
        owner_id = f"{self.instance_id}:{uuid4().hex}"
        terminal: SshTerminal | None = None
        active: ActiveWebShell | None = None
        claimed = False
        reason = WebShellCloseReason.START_FAILED
        exit_code: int | None = None
        started = time.perf_counter()
        with log_context(
            correlation_id=str(web_shell_session_id),
            actor_user_id=principal.user_id,
            session_id=principal.session_id,
            web_shell_session_id=web_shell_session_id,
        ):
            try:
                launch = await self._service.claim(
                    web_shell_session_id, principal, owner_id
                )
                claimed = True
                await websocket.accept()
                terminal = await SshTerminal.start(launch, self._settings.runtime_dir)
                session = launch.session
                del launch
                now = time.monotonic()
                active = ActiveWebShell(
                    session=session,
                    terminal=terminal,
                    owner_id=owner_id,
                    started_monotonic=now,
                    last_activity_monotonic=now,
                    last_activity_at=utc_now(),
                    finished=asyncio.Event(),
                )
                async with self._active_lock:
                    self._active[web_shell_session_id] = active
                await websocket.send_json(
                    {
                        "type": "ready",
                        "webShellSessionId": str(web_shell_session_id),
                    }
                )
                reason, exit_code = await self._serve(websocket, active, owner_id)
            except OpsError as error:
                await self._reject_or_send_error(
                    websocket, error.code, error.public_message
                )
                reason = WebShellCloseReason.START_FAILED
            except SshTerminalStartError as error:
                await self._send_error(
                    websocket,
                    "web_shell_unavailable",
                    "Web Shell could not start the SSH client",
                )
                log_event(
                    AuditAction.WEB_SHELL_FAILED,
                    AuditOutcome.FAILED,
                    source=AuditSource.API,
                    severity=AuditSeverity.ERROR,
                    message="Web Shell local terminal startup failed",
                    web_shell_session_id=web_shell_session_id,
                    resource_type="web_shell_session",
                    resource_id=web_shell_session_id,
                    error_code="web_shell_unavailable",
                    exception_type=type(error).__name__,
                    failure_stage="ssh_terminal_start",
                    retryable=True,
                    metadata=safe_exception_fields(error),
                )
                reason = WebShellCloseReason.START_FAILED
            except WebSocketDisconnect:
                reason = WebShellCloseReason.CLIENT_DISCONNECTED
            except Exception as error:
                await self._reject_or_send_error(
                    websocket,
                    "web_shell_unavailable",
                    "Web Shell connection failed",
                )
                log_event(
                    AuditAction.WEB_SHELL_FAILED,
                    AuditOutcome.FAILED,
                    source=AuditSource.API,
                    severity=AuditSeverity.ERROR,
                    message="Web Shell stream failed",
                    web_shell_session_id=web_shell_session_id,
                    resource_type="web_shell_session",
                    resource_id=web_shell_session_id,
                    error_code="web_shell_unavailable",
                    exception_type=type(error).__name__,
                    failure_stage="web_shell_stream",
                    retryable=True,
                    metadata=safe_exception_fields(error),
                    exc_info=True,
                )
                reason = WebShellCloseReason.DATABASE_UNAVAILABLE
            finally:
                if terminal is not None:
                    await terminal.close()
                    exit_code = terminal.returncode if exit_code is None else exit_code
                    if reason is WebShellCloseReason.REMOTE_EXIT and exit_code == 255:
                        reason = WebShellCloseReason.START_FAILED
                async with self._active_lock:
                    self._active.pop(web_shell_session_id, None)
                duration_ms = round((time.perf_counter() - started) * 1000, 3)
                if claimed:
                    try:
                        await self._service.finish(
                            web_shell_session_id,
                            owner_id,
                            reason,
                            duration_ms=duration_ms,
                            exit_code=exit_code,
                        )
                    except Exception as error:
                        log_event(
                            AuditAction.WEB_SHELL_FAILED,
                            AuditOutcome.FAILED,
                            source=AuditSource.API,
                            severity=AuditSeverity.ERROR,
                            message="Web Shell finalization failed",
                            web_shell_session_id=web_shell_session_id,
                            resource_type="web_shell_session",
                            resource_id=web_shell_session_id,
                            error_code="web_shell_finalize_failed",
                            exception_type=type(error).__name__,
                            failure_stage="web_shell_finalize",
                            retryable=True,
                            metadata=safe_exception_fields(error),
                        )
                if active is not None and active.finished is not None:
                    active.finished.set()
                await self._send_closed(websocket, reason, exit_code)

    async def _serve(
        self,
        websocket: WebSocket,
        active: ActiveWebShell,
        owner_id: str,
    ) -> tuple[WebShellCloseReason, int | None]:
        output_task = asyncio.create_task(self._pump_output(websocket, active))
        input_task = asyncio.create_task(self._pump_input(websocket, active))
        process_task = asyncio.create_task(active.terminal.wait())
        monitor_task = asyncio.create_task(self._monitor(active, owner_id))
        tasks = {output_task, input_task, process_task, monitor_task}
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        reason = WebShellCloseReason.CLIENT_DISCONNECTED
        exit_code: int | None = None
        if process_task in done:
            exit_code = process_task.result()
            reason = (
                WebShellCloseReason.START_FAILED
                if exit_code == 255
                else WebShellCloseReason.REMOTE_EXIT
            )
        elif monitor_task in done:
            reason = monitor_task.result()
        elif input_task in done:
            reason = input_task.result()
        elif output_task in done:
            reason = output_task.result()
        if active.requested_close_reason is not None:
            reason = active.requested_close_reason
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        return reason, exit_code

    async def _pump_output(
        self, websocket: WebSocket, active: ActiveWebShell
    ) -> WebShellCloseReason:
        queue: asyncio.Queue[bytes | None] = asyncio.Queue(
            maxsize=WEB_SHELL_OUTPUT_BUFFER_BYTES // WEB_SHELL_MAX_FRAME_BYTES
        )

        async def read_terminal() -> None:
            while True:
                data = await active.terminal.read(WEB_SHELL_MAX_FRAME_BYTES)
                if not data:
                    await queue.put(None)
                    return
                active.touch()
                await queue.put(data)

        reader = asyncio.create_task(read_terminal())
        try:
            while True:
                data = await queue.get()
                if data is None:
                    await reader
                    return WebShellCloseReason.REMOTE_EXIT
                try:
                    await asyncio.wait_for(
                        websocket.send_bytes(data),
                        timeout=WEB_SHELL_SEND_TIMEOUT_SECONDS,
                    )
                except TimeoutError:
                    return WebShellCloseReason.SLOW_CONSUMER
        finally:
            if not reader.done():
                reader.cancel()
            await asyncio.gather(reader, return_exceptions=True)

    async def _pump_input(
        self, websocket: WebSocket, active: ActiveWebShell
    ) -> WebShellCloseReason:
        try:
            while True:
                message = await websocket.receive()
                if message["type"] == "websocket.disconnect":
                    return WebShellCloseReason.CLIENT_DISCONNECTED
                data = message.get("bytes")
                if isinstance(data, bytes):
                    if len(data) > WEB_SHELL_MAX_FRAME_BYTES:
                        await self._send_error(
                            websocket, "web_shell_frame_too_large", "Terminal input is too large"
                        )
                        return WebShellCloseReason.PROTOCOL_ERROR
                    if data:
                        active.touch()
                        await active.terminal.write(data)
                    continue
                text = message.get("text")
                if (
                    not isinstance(text, str)
                    or len(text.encode("utf-8")) > WEB_SHELL_MAX_FRAME_BYTES
                ):
                    return WebShellCloseReason.PROTOCOL_ERROR
                reason = await self._handle_control(websocket, active, text)
                if reason is not None:
                    return reason
        except WebSocketDisconnect:
            return WebShellCloseReason.CLIENT_DISCONNECTED

    async def _handle_control(
        self,
        websocket: WebSocket,
        active: ActiveWebShell,
        value: str,
    ) -> WebShellCloseReason | None:
        try:
            message = json.loads(value)
        except json.JSONDecodeError:
            message = None
        if not isinstance(message, dict):
            await self._send_error(websocket, "web_shell_protocol_error", "Invalid control frame")
            return WebShellCloseReason.PROTOCOL_ERROR
        message_type = message.get("type")
        if message_type == "close":
            return WebShellCloseReason.USER_REQUESTED
        if message_type != "resize":
            await self._send_error(websocket, "web_shell_protocol_error", "Unknown control frame")
            return WebShellCloseReason.PROTOCOL_ERROR
        columns = message.get("columns")
        rows = message.get("rows")
        if (
            not isinstance(columns, int)
            or isinstance(columns, bool)
            or not WEB_SHELL_MIN_COLUMNS <= columns <= WEB_SHELL_MAX_COLUMNS
            or not isinstance(rows, int)
            or isinstance(rows, bool)
            or not WEB_SHELL_MIN_ROWS <= rows <= WEB_SHELL_MAX_ROWS
        ):
            await self._send_error(websocket, "web_shell_protocol_error", "Invalid terminal size")
            return WebShellCloseReason.PROTOCOL_ERROR
        active.terminal.resize(columns, rows)
        active.touch()
        return None

    async def _monitor(
        self, active: ActiveWebShell, owner_id: str
    ) -> WebShellCloseReason:
        next_heartbeat = time.monotonic()
        while True:
            await asyncio.sleep(1)
            now = time.monotonic()
            if self._shutdown.is_set():
                return WebShellCloseReason.SERVER_SHUTDOWN
            if now - active.started_monotonic >= self._settings.web_shell_max_duration_seconds:
                return WebShellCloseReason.MAX_DURATION
            idle_seconds = now - active.last_activity_monotonic
            if idle_seconds >= self._settings.web_shell_idle_timeout_seconds:
                return WebShellCloseReason.IDLE_TIMEOUT
            if now < next_heartbeat:
                continue
            try:
                close_reason = await self._service.heartbeat(
                    active.session.web_shell_session_id,
                    owner_id,
                    active.last_activity_at,
                )
            except Exception:
                return WebShellCloseReason.DATABASE_UNAVAILABLE
            if close_reason is not None:
                return close_reason
            next_heartbeat = now + WEB_SHELL_HEARTBEAT_SECONDS

    @staticmethod
    async def _reject_or_send_error(
        websocket: WebSocket, code: str, message: str
    ) -> None:
        if websocket.application_state is WebSocketState.CONNECTING:
            with suppress(RuntimeError, WebSocketDisconnect):
                await websocket.close(code=4408, reason=code[:123])
            return
        await WebShellManager._send_error(websocket, code, message)

    @staticmethod
    async def _send_error(websocket: WebSocket, code: str, message: str) -> None:
        if websocket.application_state is not WebSocketState.CONNECTED:
            return
        with suppress(RuntimeError, WebSocketDisconnect):
            await websocket.send_json({"type": "error", "code": code, "message": message})

    @staticmethod
    async def _send_closed(
        websocket: WebSocket,
        reason: WebShellCloseReason,
        exit_code: int | None,
    ) -> None:
        if websocket.application_state is not WebSocketState.CONNECTED:
            return
        try:
            await websocket.send_json(
                {
                    "type": "closed",
                    "reason": reason.value,
                    "exitCode": exit_code,
                }
            )
            await websocket.close(code=1000)
        except (RuntimeError, WebSocketDisconnect):
            pass
