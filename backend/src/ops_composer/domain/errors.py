from __future__ import annotations

from typing import ClassVar


class OpsError(Exception):
    code: ClassVar[str] = "operation_failed"
    status_code: ClassVar[int] = 400
    public_message: ClassVar[str] = "operation failed"

    def __init__(
        self,
        message: str | None = None,
        *,
        details: dict[str, object] | None = None,
    ) -> None:
        self.message = message or self.public_message
        self.details = details
        self.audit_recorded = False
        super().__init__(self.message)


class NotFoundError(OpsError):
    code = "not_found"
    status_code = 404
    public_message = "resource not found"


class ConflictError(OpsError):
    code = "conflict"
    status_code = 409
    public_message = "resource conflict"


class IdempotencyConflictError(ConflictError):
    code = "idempotency_key_reused"
    public_message = "idempotency key was already used for a different request"


class ValidationError(OpsError):
    code = "invalid_operation"
    status_code = 422
    public_message = "operation is invalid"


class HostKeyChangedError(ConflictError):
    code = "host_key_changed"
    public_message = "the SSH host key differs from the trusted key"


class RunNotCancelableError(ConflictError):
    code = "run_not_cancelable"
    public_message = "run is already in a terminal state"


class ClaimCollisionError(RuntimeError):
    """Roll back a queue claim when another run wins a shared Host Lock."""
