from __future__ import annotations

import asyncio
import json
import logging
import sys
from types import TracebackType
from typing import cast
from uuid import uuid4

import pytest
from pydantic import ValidationError

from ops_composer.domain.audit import (
    AuditAction,
    AuditEvent,
    AuditEventDraft,
    AuditOutcome,
    AuditSeverity,
    AuditSource,
)
from ops_composer.observability import (
    JsonLogFormatter,
    allow_rate_limited_event,
    configure_logging,
    current_log_context,
    log_context,
)
from ops_composer.services import audit as audit_module
from ops_composer.services.audit import AuditService, new_audit_event
from ops_composer.settings import Settings
from ops_composer.uow.factory import UnitOfWorkFactory


def test_json_logging_redacts_nested_secrets_and_uses_safe_stack_frames() -> None:
    sentinel = "sentinel-secret-7pM4"
    try:
        raise RuntimeError(f"database failed password={sentinel}")
    except RuntimeError:
        exception_info = sys.exc_info()

    record = logging.LogRecord(
        name="app.test",
        level=logging.ERROR,
        pathname=__file__,
        lineno=1,
        msg=(
            f"request failed password={sentinel} "
            f"postgresql://admin:{sentinel}@database/ops"
        ),
        args=(),
        exc_info=exception_info,
    )
    record.event_action = AuditAction.RUN_FAILED.value
    record.event_outcome = AuditOutcome.FAILED.value
    record.error_code = "runner_error"
    record.retryable = True
    record.metadata = {
        "password": sentinel,
        "nested": {
            "authToken": sentinel,
            "header": f"Bearer {sentinel}",
        },
        "command": f"printf {sentinel}",
        "inventory": {"host": sentinel},
        "safe_count": 2,
    }

    encoded = JsonLogFormatter(service="worker", environment="test").format(record)
    payload = json.loads(encoded)

    assert sentinel not in encoded
    assert "postgresql://" not in encoded
    assert "[REDACTED_DATABASE_URL]" in payload["message"]
    assert payload["timestamp"]
    assert payload["level"] == "ERROR"
    assert payload["service"] == "worker"
    assert payload["environment"] == "test"
    assert payload["event_action"] == "RUN_FAILED"
    assert payload["event_outcome"] == "FAILED"
    assert payload["metadata"]["password"] == "[REDACTED]"
    assert payload["metadata"]["command"] == "[REDACTED]"
    assert payload["metadata"]["inventory"] == "[REDACTED]"
    assert payload["metadata"]["safe_count"] == 2
    assert payload["metadata"]["stack"]
    assert set(payload["metadata"]["stack"][0]) == {"file", "function", "line"}


@pytest.mark.asyncio
async def test_log_context_is_isolated_between_tasks_and_reliably_reset() -> None:
    actor_a = uuid4()
    actor_b = uuid4()

    async def capture(request_id: str, actor_id: object) -> tuple[str | None, object | None]:
        with log_context(request_id=request_id, actor_user_id=actor_id):
            await asyncio.sleep(0)
            event = new_audit_event(
                AuditAction.REQUEST_COMPLETED,
                AuditOutcome.SUCCEEDED,
                source=AuditSource.API,
            )
            return event.request_id, event.actor_user_id

    first, second = await asyncio.gather(
        capture("request-a", actor_a),
        capture("request-b", actor_b),
    )

    assert first == ("request-a", actor_a)
    assert second == ("request-b", actor_b)
    assert current_log_context() == {}


def test_rate_limited_event_suppresses_repeated_keys() -> None:
    key = f"test-{uuid4()}"
    assert allow_rate_limited_event(key, interval_seconds=60)
    assert not allow_rate_limited_event(key, interval_seconds=60)


def test_logging_level_and_audit_retention_settings_are_bounded() -> None:
    settings = Settings()
    assert settings.log_level.value == "INFO"
    assert settings.audit_retention_days == 180
    assert Settings(log_level="DEBUG", audit_retention_days=1).log_level.value == "DEBUG"
    assert Settings(audit_retention_days=3650).audit_retention_days == 3650
    with pytest.raises(ValidationError):
        Settings(log_level="TRACE")
    with pytest.raises(ValidationError):
        Settings(audit_retention_days=0)
    with pytest.raises(ValidationError):
        Settings(audit_retention_days=3651)

    configure_logging(service="test", environment="test", level="WARNING")
    try:
        logger = logging.getLogger("app.business")
        assert not logger.isEnabledFor(logging.INFO)
        assert logger.isEnabledFor(logging.WARNING)
        assert logging.getLogger("uvicorn.access").disabled
    finally:
        configure_logging(service="application", environment="development", level="INFO")


class _AuditRepository:
    def __init__(self, event: AuditEventDraft, *, fail: bool = False) -> None:
        self._event = event
        self._fail = fail

    async def append(self, _: AuditEventDraft) -> AuditEvent:
        if self._fail:
            raise ConnectionError("postgresql://admin:secret@database/ops")
        return AuditEvent.model_validate(
            {**self._event.model_dump(mode="python"), "audit_event_id": 1}
        )


class _AuditUnit:
    def __init__(self, repository: _AuditRepository, state: dict[str, bool]) -> None:
        self.audit = repository
        self._state = state


class _AuditContext:
    def __init__(self, unit: _AuditUnit, state: dict[str, bool]) -> None:
        self._unit = unit
        self._state = state

    async def __aenter__(self) -> _AuditUnit:
        return self._unit

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        _exc_value: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        self._state["committed"] = exc_type is None


class _AuditFactory:
    def __init__(self, event: AuditEventDraft, *, fail: bool = False) -> None:
        self.state = {"committed": False}
        self._repository = _AuditRepository(event, fail=fail)

    def __call__(self) -> _AuditContext:
        return _AuditContext(_AuditUnit(self._repository, self.state), self.state)


@pytest.mark.asyncio
async def test_best_effort_audit_emits_after_commit_and_never_raises_on_db_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    event = new_audit_event(
        AuditAction.HOST_CREATED,
        AuditOutcome.SUCCEEDED,
        source=AuditSource.API,
        severity=AuditSeverity.INFO,
    )
    factory = _AuditFactory(event)
    emitted_after_commit: list[bool] = []

    def emit(_: AuditEventDraft, *, exc_info: bool = False) -> None:
        del exc_info
        emitted_after_commit.append(factory.state["committed"])

    monkeypatch.setattr(audit_module, "emit_audit_event", emit)
    persisted = await AuditService(cast(UnitOfWorkFactory, factory)).record_best_effort(event)

    assert persisted is not None
    assert emitted_after_commit == [True]

    failed_factory = _AuditFactory(event, fail=True)
    failed = await AuditService(
        cast(UnitOfWorkFactory, failed_factory)
    ).record_best_effort(event)
    assert failed is None
