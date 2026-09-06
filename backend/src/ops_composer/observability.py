from __future__ import annotations

import json
import logging
import re
import traceback
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from contextvars import ContextVar, Token
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from threading import Lock
from time import monotonic
from types import TracebackType
from typing import Final
from uuid import UUID

from ops_composer.domain.audit import (
    AuditAction,
    AuditOutcome,
    AuditSeverity,
    AuditSource,
)

_MAX_STRING_LENGTH: Final = 1_024
_MAX_COLLECTION_ITEMS: Final = 100
_MAX_METADATA_DEPTH: Final = 5
_MAX_METADATA_BYTES: Final = 16 * 1_024
_MAX_STACK_FRAMES: Final = 40

_SAFE_REQUEST_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_DATABASE_URL = re.compile(
    r"(?i)\bpostgres(?:ql)?(?:\+[a-z0-9_.-]+)?://[^\s\"'<>]+"
)
_BEARER_VALUE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)(password|passphrase|secret|token|authorization|csrf|master[_-]?key)"
    r"(\s*[=:]\s*)[^\s,;]+"
)
_PRIVATE_KEY = re.compile(
    r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----",
    re.DOTALL,
)
_SENSITIVE_KEY_PARTS = frozenset(
    {
        "authorization",
        "becomepassword",
        "ciphertext",
        "cookie",
        "csrf",
        "databaseurl",
        "encryptedsecret",
        "extravars",
        "inventory",
        "masterkey",
        "moduleargs",
        "passphrase",
        "password",
        "privatekey",
        "sessiontoken",
        "stderr",
        "stdout",
        "token",
    }
)
_SENSITIVE_EXACT_KEYS = frozenset({"cmd", "command", "public_key", "publickey"})

_CONTEXT_NAMES = (
    "request_id",
    "correlation_id",
    "actor_user_id",
    "session_id",
    "run_id",
    "run_target_id",
    "worker_id",
    "web_shell_session_id",
)
_CONTEXT: dict[str, ContextVar[object | None]] = {
    name: ContextVar(name, default=None) for name in _CONTEXT_NAMES
}
_service_name = "application"
_environment_name = "development"
_event_rate_lock = Lock()
_event_rate_times: dict[str, float] = {}

_LOG_FIELDS = (
    "event",
    "source",
    "event_action",
    "event_outcome",
    "request_id",
    "correlation_id",
    "actor_user_id",
    "session_id",
    "run_id",
    "run_target_id",
    "host_id",
    "group_id",
    "credential_id",
    "worker_id",
    "web_shell_session_id",
    "resource_type",
    "resource_id",
    "operation_kind",
    "target_count",
    "method",
    "path",
    "status",
    "duration_ms",
    "error_code",
    "exception_type",
    "failure_stage",
    "retryable",
    "validation_errors",
)


def valid_request_id(candidate: str) -> bool:
    return bool(_SAFE_REQUEST_ID.fullmatch(candidate))


def current_log_context() -> dict[str, object]:
    return {
        name: value
        for name, variable in _CONTEXT.items()
        if (value := variable.get()) is not None
    }


def current_request_id() -> str | None:
    value = _CONTEXT["request_id"].get()
    return str(value) if value is not None else None


def bind_log_context(**values: object | None) -> None:
    unknown = values.keys() - _CONTEXT.keys()
    if unknown:
        raise ValueError(f"unknown log context: {sorted(unknown)}")
    for name, value in values.items():
        _CONTEXT[name].set(value)


def allow_rate_limited_event(key: str, *, interval_seconds: float = 60.0) -> bool:
    now = monotonic()
    with _event_rate_lock:
        previous = _event_rate_times.get(key)
        if previous is not None and now - previous < interval_seconds:
            return False
        _event_rate_times[key] = now
        return True


@contextmanager
def log_context(**values: object | None) -> Iterator[None]:
    unknown = values.keys() - _CONTEXT.keys()
    if unknown:
        raise ValueError(f"unknown log context: {sorted(unknown)}")
    tokens: list[tuple[ContextVar[object | None], Token[object | None]]] = []
    try:
        for name, value in values.items():
            variable = _CONTEXT[name]
            tokens.append((variable, variable.set(value)))
        yield
    finally:
        for variable, token in reversed(tokens):
            variable.reset(token)


def _sensitive_key(key: object) -> bool:
    text = str(key).casefold()
    normalized = re.sub(r"[^a-z0-9]", "", text)
    return text in _SENSITIVE_EXACT_KEYS or any(
        token in normalized for token in _SENSITIVE_KEY_PARTS
    )


def sanitize_text(value: str, *, limit: int = _MAX_STRING_LENGTH) -> str:
    text = _PRIVATE_KEY.sub("[REDACTED_PRIVATE_KEY]", value)
    text = _DATABASE_URL.sub("[REDACTED_DATABASE_URL]", text)
    text = _BEARER_VALUE.sub("Bearer [REDACTED]", text)
    text = _SECRET_ASSIGNMENT.sub(r"\1\2[REDACTED]", text)
    if len(text) <= limit:
        return text
    return text[:limit] + f"...[TRUNCATED:{len(text) - limit}]"


def _sanitize_value(value: object, *, depth: int, seen: set[int]) -> object:
    if depth > _MAX_METADATA_DEPTH:
        return "[TRUNCATED_DEPTH]"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return sanitize_text(value)
    if isinstance(value, (UUID, Path)):
        return str(value)
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat()
    if isinstance(value, Enum):
        return sanitize_text(str(value.value))
    if isinstance(value, (bytes, bytearray, memoryview)):
        return f"[REDACTED_BYTES:{len(value)}]"
    if isinstance(value, BaseException):
        return type(value).__name__
    if value.__class__.__name__ in {"SecretBytes", "SecretStr"}:
        return "[REDACTED]"

    identity = id(value)
    if identity in seen:
        return "[CYCLE]"
    if isinstance(value, Mapping):
        seen.add(identity)
        try:
            mapping_result: dict[str, object] = {}
            items = list(value.items())
            for key, item in items[:_MAX_COLLECTION_ITEMS]:
                safe_key = sanitize_text(str(key), limit=128)
                mapping_result[safe_key] = (
                    "[REDACTED]"
                    if _sensitive_key(key)
                    else _sanitize_value(item, depth=depth + 1, seen=seen)
                )
            if len(items) > _MAX_COLLECTION_ITEMS:
                mapping_result["metadata_items_truncated"] = (
                    len(items) - _MAX_COLLECTION_ITEMS
                )
            return mapping_result
        finally:
            seen.remove(identity)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        seen.add(identity)
        try:
            values = list(value)
            sequence_result = [
                _sanitize_value(item, depth=depth + 1, seen=seen)
                for item in values[:_MAX_COLLECTION_ITEMS]
            ]
            if len(values) > _MAX_COLLECTION_ITEMS:
                sequence_result.append(
                    f"[TRUNCATED_ITEMS:{len(values) - _MAX_COLLECTION_ITEMS}]"
                )
            return sequence_result
        finally:
            seen.remove(identity)
    return sanitize_text(type(value).__name__)


def sanitize_metadata(metadata: Mapping[str, object] | None) -> dict[str, object]:
    if not metadata:
        return {}
    result = _sanitize_value(metadata, depth=0, seen=set())
    if not isinstance(result, dict):
        return {"metadata_invalid": True}
    encoded = json.dumps(result, ensure_ascii=False, separators=(",", ":"))
    if len(encoded.encode()) <= _MAX_METADATA_BYTES:
        return result
    return {
        "metadata_truncated": True,
        "original_size_bytes": len(encoded.encode()),
    }


def safe_exception_fields(error: BaseException) -> dict[str, object]:
    result: dict[str, object] = {"exception_type": type(error).__name__}
    sqlstate = getattr(error, "sqlstate", None)
    if isinstance(sqlstate, str):
        result["sqlstate"] = sqlstate
    diagnostic = getattr(error, "diag", None)
    if diagnostic is not None:
        constraint_name = getattr(diagnostic, "constraint_name", None)
        table_name = getattr(diagnostic, "table_name", None)
        if isinstance(constraint_name, str):
            result["constraint_name"] = constraint_name
        if isinstance(table_name, str):
            result["table_name"] = table_name
    return result


def _safe_stack(traceback_value: TracebackType | None) -> list[dict[str, object]]:
    if traceback_value is None:
        return []
    frames = traceback.extract_tb(traceback_value, limit=_MAX_STACK_FRAMES)
    return [
        {
            "file": Path(frame.filename).name,
            "function": frame.name,
            "line": frame.lineno,
        }
        for frame in frames
    ]


class JsonLogFormatter(logging.Formatter):
    def __init__(self, *, service: str | None = None, environment: str | None = None) -> None:
        super().__init__()
        self.service = service
        self.environment = environment

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "service": self.service or _service_name,
            "environment": self.environment or _environment_name,
            "logger": record.name,
            "message": sanitize_text(record.getMessage()),
        }
        context = current_log_context()
        for field in _LOG_FIELDS:
            value = getattr(record, field, None)
            if value is None:
                value = context.get(field)
            if value is not None:
                payload[field] = _sanitize_value(value, depth=0, seen=set())
        metadata = sanitize_metadata(getattr(record, "metadata", None))
        if record.exc_info and record.exc_info[0] is not None:
            payload.setdefault("exception_type", record.exc_info[0].__name__)
            stack = _safe_stack(record.exc_info[2])
            if stack:
                metadata["stack"] = stack
        if metadata:
            payload["metadata"] = metadata
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def configure_logging(
    *,
    service: str = "application",
    environment: str = "development",
    level: str = "INFO",
) -> None:
    global _environment_name, _service_name
    _service_name = service
    _environment_name = environment
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    formatter = JsonLogFormatter(service=service, environment=environment)

    logger = logging.getLogger("app")
    handler = next(
        (
            existing
            for existing in logger.handlers
            if getattr(existing, "_ops_composer_json", False)
        ),
        None,
    )
    if handler is None:
        handler = logging.StreamHandler()
        handler._ops_composer_json = True  # type: ignore[attr-defined]
        logger.handlers.clear()
        logger.addHandler(handler)
    handler.setFormatter(formatter)
    handler.setLevel(numeric_level)
    logger.setLevel(numeric_level)
    logger.propagate = False

    logging.getLogger("uvicorn.access").disabled = True
    for name in ("uvicorn.error", "fastapi"):
        owned = logging.getLogger(name)
        owned.handlers.clear()
        owned.addHandler(handler)
        owned.setLevel(numeric_level)
        owned.propagate = False


def log_event(
    action: AuditAction,
    outcome: AuditOutcome,
    *,
    source: AuditSource,
    severity: AuditSeverity = AuditSeverity.INFO,
    message: str | None = None,
    metadata: Mapping[str, object] | None = None,
    exc_info: BaseException | bool | None = None,
    **fields: object,
) -> None:
    numeric_level = getattr(logging, severity.value)
    extra = {
        "source": source.value,
        "event_action": action.value,
        "event_outcome": outcome.value,
        "metadata": sanitize_metadata(metadata),
        **fields,
    }
    logging.getLogger("app.business").log(
        numeric_level,
        message or action.value.casefold().replace("_", " "),
        extra=extra,
        exc_info=exc_info,
    )
