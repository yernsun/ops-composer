from __future__ import annotations

from typing import ClassVar


class AuthError(Exception):
    code: ClassVar[str] = "authentication_failed"
    status_code: ClassVar[int] = 401
    public_message: ClassVar[str] = "authentication failed"

    def __init__(self, *, retry_after_seconds: int | None = None) -> None:
        super().__init__(self.public_message)
        self.retry_after_seconds = retry_after_seconds
        self.audit_recorded = False
        self.audit_metadata: dict[str, object] = {}


class AuthenticationRequiredError(AuthError):
    code = "authentication_required"
    public_message = "authentication required"


class InvalidCredentialsError(AuthError):
    code = "invalid_credentials"
    public_message = "invalid credentials"


class InvalidSessionError(AuthError):
    code = "invalid_or_expired_session"
    public_message = "invalid or expired session"


class OriginNotAllowedError(AuthError):
    code = "origin_not_allowed"
    status_code = 403
    public_message = "request origin is not allowed"


class CsrfValidationError(AuthError):
    code = "csrf_failed"
    status_code = 403
    public_message = "CSRF validation failed"


class AdminAlreadyExistsError(AuthError):
    code = "admin_already_exists"
    status_code = 409
    public_message = "the administrator has already been bootstrapped"


class AuthRateLimitedError(AuthError):
    code = "auth_rate_limited"
    status_code = 429
    public_message = "too many authentication attempts"
