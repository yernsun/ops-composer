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


class PermissionDeniedError(AuthError):
    code = "permission_denied"
    status_code = 403
    public_message = "permission denied"


class ReauthenticationRequiredError(AuthError):
    code = "reauthentication_required"
    status_code = 403
    public_message = "recent reauthentication is required"


class MfaRequiredError(AuthError):
    code = "mfa_required"
    status_code = 401
    public_message = "multi-factor authentication is required"


class InvalidMfaCodeError(AuthError):
    code = "invalid_mfa_code"
    public_message = "multi-factor authentication failed"


class TotpDisabledError(AuthError):
    code = "totp_disabled"
    status_code = 409
    public_message = "TOTP authentication is disabled by deployment policy"


class InvalidChallengeError(AuthError):
    code = "invalid_auth_challenge"
    public_message = "authentication challenge is invalid or expired"


class ActivationExpiredError(AuthError):
    code = "activation_expired"
    status_code = 410
    public_message = "activation code is invalid or expired"


class UserConflictError(AuthError):
    code = "user_conflict"
    status_code = 409
    public_message = "user conflicts with an existing account"


class UserVersionConflictError(AuthError):
    code = "version_conflict"
    status_code = 409
    public_message = "user was modified by another request"


class LastOwnerRequiredError(AuthError):
    code = "last_owner_required"
    status_code = 409
    public_message = "at least one active owner is required"
