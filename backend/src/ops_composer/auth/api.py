from __future__ import annotations

import secrets
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit
from uuid import UUID

from fastapi import APIRouter, Depends, Request, Response, status
from pydantic import AwareDatetime, ConfigDict, Field, SecretStr, field_validator

from ops_composer.api.dependencies import UnitOfWorkFactoryDep, prevent_auth_caching
from ops_composer.api.models import StrictApiModel
from ops_composer.auth.errors import (
    AuthenticationRequiredError,
    CsrfValidationError,
    InvalidChallengeError,
    OriginNotAllowedError,
)
from ops_composer.auth.models import (
    ChallengePurpose,
    IssuedChallenge,
    IssuedSession,
    Permission,
    SessionPrincipal,
    UserIdentity,
    UserRole,
    UserStatus,
)
from ops_composer.auth.service import AuthResult, AuthService
from ops_composer.domain.base import to_camel
from ops_composer.observability import bind_log_context
from ops_composer.settings import Settings, get_settings


class AuthApiModel(StrictApiModel):
    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        extra="forbid",
        str_strip_whitespace=False,
    )


class LoginRequest(AuthApiModel):
    username: str = Field(min_length=1, max_length=64)
    password: SecretStr = Field(min_length=1, max_length=200, repr=False)

    @field_validator("username")
    @classmethod
    def normalize_username(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("username cannot be blank")
        return normalized


class SessionResponse(StrictApiModel):
    user_id: UUID
    username: str
    role: UserRole
    permissions: list[Permission]
    totp_policy_enabled: bool
    mfa_enabled: bool
    mfa_enrollment_required: bool
    mfa_verified_at: AwareDatetime | None
    elevated_until: AwareDatetime | None
    expires_at: AwareDatetime


class AuthChallengeResponse(StrictApiModel):
    next_step: Literal["LOGIN_MFA", "MFA_ENROLLMENT"]
    username: str
    expires_at: AwareDatetime
    enrollment_secret: str | None = Field(default=None, repr=False)
    otpauth_uri: str | None = Field(default=None, repr=False)


class MfaVerifyRequest(AuthApiModel):
    value: SecretStr = Field(min_length=6, max_length=64, repr=False)


class MfaCompletionResponse(StrictApiModel):
    session: SessionResponse
    recovery_codes: list[str] = Field(default_factory=list)


class ActivationRequest(AuthApiModel):
    activation_code: SecretStr = Field(min_length=32, max_length=256, repr=False)
    password: SecretStr = Field(min_length=12, max_length=200, repr=False)


class ReauthenticateRequest(AuthApiModel):
    password: SecretStr = Field(min_length=1, max_length=200, repr=False)
    mfa_value: SecretStr | None = Field(default=None, min_length=6, max_length=64, repr=False)


class UserResponse(StrictApiModel):
    user_id: UUID
    username: str
    status: UserStatus
    role: UserRole
    mfa_enrollment_required: bool
    activated_at: AwareDatetime | None
    version: int
    created_at: AwareDatetime
    updated_at: AwareDatetime


class CreateUserRequest(AuthApiModel):
    username: str = Field(min_length=1, max_length=64)
    role: UserRole


class CreatedUserResponse(StrictApiModel):
    user: UserResponse
    activation_code: str = Field(repr=False)
    activation_expires_at: AwareDatetime


class SecurityStatusResponse(StrictApiModel):
    totp_policy_enabled: bool
    mfa_enabled: bool
    mfa_enrollment_required: bool
    unused_recovery_codes: int
    elevated_until: AwareDatetime | None


class RecoveryCodesResponse(StrictApiModel):
    recovery_codes: list[str]


class ChangePasswordRequest(AuthApiModel):
    current_password: SecretStr = Field(min_length=1, max_length=200, repr=False)
    new_password: SecretStr = Field(min_length=12, max_length=200, repr=False)
    mfa_value: SecretStr | None = Field(default=None, min_length=6, max_length=64, repr=False)


class UpdateUserRequest(AuthApiModel):
    role: UserRole
    status: UserStatus
    expected_version: int = Field(ge=1)


class ErrorResponse(StrictApiModel):
    code: str
    message: str
    details: dict[str, object] | None = None
    request_id: str | None = None


AUTH_VALIDATION_RESPONSES: dict[int | str, dict[str, Any]] = {
    422: {"model": ErrorResponse, "description": "Request validation failed"},
}
AUTH_REQUIRED_RESPONSES: dict[int | str, dict[str, Any]] = {
    **AUTH_VALIDATION_RESPONSES,
    401: {"model": ErrorResponse, "description": "Authentication required"},
    403: {"model": ErrorResponse, "description": "Permission denied"},
}
AUTH_UNSAFE_RESPONSES: dict[int | str, dict[str, Any]] = {
    **AUTH_REQUIRED_RESPONSES,
    409: {"model": ErrorResponse, "description": "State conflict"},
}
RATE_LIMIT_RESPONSE: dict[str, Any] = {
    "model": ErrorResponse,
    "description": "Authentication rate limit exceeded",
    "headers": {
        "Retry-After": {
            "description": "Seconds until the fixed window resets",
            "schema": {"type": "integer", "minimum": 1},
        }
    },
}

router = APIRouter(
    prefix="/api/v1",
    tags=["auth"],
    dependencies=[Depends(prevent_auth_caching)],
    responses=AUTH_VALIDATION_RESPONSES,
)


def _service(unit_of_work_factory: UnitOfWorkFactoryDep) -> AuthService:
    return AuthService(unit_of_work_factory, get_settings())


def _set_session_cookies(response: Response, issued: IssuedSession, settings: Settings) -> None:
    max_age = settings.session_ttl_seconds
    response.set_cookie(
        settings.session_cookie_name,
        issued.session_token.get_secret_value(),
        max_age=max_age,
        httponly=True,
        secure=settings.cookies_secure,
        samesite="strict",
        path="/",
    )
    response.set_cookie(
        settings.csrf_cookie_name,
        issued.csrf_token.get_secret_value(),
        max_age=max_age,
        httponly=False,
        secure=settings.cookies_secure,
        samesite="strict",
        path="/",
    )


def _set_challenge_cookie(
    response: Response, challenge: IssuedChallenge, settings: Settings
) -> None:
    response.set_cookie(
        settings.auth_challenge_cookie_name,
        challenge.challenge_token.get_secret_value(),
        max_age=300,
        httponly=True,
        secure=settings.cookies_secure,
        samesite="strict",
        path="/",
    )


def _clear_challenge_cookie(response: Response, settings: Settings) -> None:
    response.delete_cookie(
        settings.auth_challenge_cookie_name,
        path="/",
        secure=settings.cookies_secure,
        httponly=True,
        samesite="strict",
    )


def _source_origin(request: Request) -> str | None:
    origin = request.headers.get("origin")
    if origin:
        return origin.rstrip("/")
    referer = request.headers.get("referer")
    if not referer:
        return None
    parsed = urlsplit(referer)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    return f"{parsed.scheme}://{parsed.netloc}"


def require_allowed_origin(request: Request) -> None:
    if _source_origin(request) not in get_settings().allowed_origins:
        raise OriginNotAllowedError()


AllowedOriginDep = Annotated[None, Depends(require_allowed_origin)]


async def get_current_session(
    request: Request,
    unit_of_work_factory: UnitOfWorkFactoryDep,
) -> SessionPrincipal:
    session_token = request.cookies.get(get_settings().session_cookie_name)
    if not session_token:
        raise AuthenticationRequiredError()
    principal = await _service(unit_of_work_factory).resolve(session_token)
    bind_log_context(actor_user_id=principal.user_id, session_id=principal.session_id)
    return principal


CurrentSessionDep = Annotated[SessionPrincipal, Depends(get_current_session)]


async def get_unsafe_session(
    request: Request,
    unit_of_work_factory: UnitOfWorkFactoryDep,
    principal: CurrentSessionDep,
) -> SessionPrincipal:
    require_allowed_origin(request)
    settings = get_settings()
    csrf_header = request.headers.get("X-CSRF-Token")
    csrf_cookie = request.cookies.get(settings.csrf_cookie_name)
    if not csrf_header or not csrf_cookie or not secrets.compare_digest(csrf_header, csrf_cookie):
        raise CsrfValidationError()
    _service(unit_of_work_factory).require_csrf(principal, csrf_header)
    return principal


UnsafeSessionDep = Annotated[SessionPrincipal, Depends(get_unsafe_session)]


def _response(principal: SessionPrincipal) -> SessionResponse:
    return SessionResponse(
        user_id=principal.user_id,
        username=principal.username,
        role=principal.role,
        permissions=sorted(principal.permissions, key=lambda item: item.value),
        totp_policy_enabled=get_settings().totp_enabled,
        mfa_enabled=principal.mfa_enabled,
        mfa_enrollment_required=principal.mfa_enrollment_required,
        mfa_verified_at=principal.mfa_verified_at,
        elevated_until=principal.elevated_until,
        expires_at=principal.expires_at,
    )


def _user_response(user: UserIdentity) -> UserResponse:
    return UserResponse.model_validate(user.model_dump(mode="python"))


def _client_key(request: Request) -> str:
    return request.client.host if request.client else "unknown-client"


def _auth_result(result: AuthResult, response: Response) -> SessionResponse | AuthChallengeResponse:
    settings = get_settings()
    if isinstance(result, IssuedSession):
        _set_session_cookies(response, result, settings)
        _clear_challenge_cookie(response, settings)
        return _response(result.principal)
    _set_challenge_cookie(response, result, settings)
    return AuthChallengeResponse(
        next_step=result.purpose.value,
        username=result.username,
        expires_at=result.expires_at,
        enrollment_secret=(
            result.enrollment_secret.get_secret_value()
            if result.enrollment_secret is not None
            else None
        ),
        otpauth_uri=(
            result.otpauth_uri.get_secret_value() if result.otpauth_uri is not None else None
        ),
    )


@router.post(
    "/auth/login",
    operation_id="login",
    responses={
        401: {"model": ErrorResponse, "description": "Invalid credentials"},
        403: {"model": ErrorResponse, "description": "Origin denied"},
        429: RATE_LIMIT_RESPONSE,
    },
)
async def login(
    request: LoginRequest,
    raw_request: Request,
    response: Response,
    unit_of_work_factory: UnitOfWorkFactoryDep,
    _: AllowedOriginDep,
) -> SessionResponse | AuthChallengeResponse:
    result = await _service(unit_of_work_factory).login(
        request.username, request.password.get_secret_value(), _client_key(raw_request)
    )
    return _auth_result(result, response)


@router.post("/auth/activate", operation_id="activateUser")
async def activate(
    request: ActivationRequest,
    response: Response,
    unit_of_work_factory: UnitOfWorkFactoryDep,
    _: AllowedOriginDep,
) -> SessionResponse | AuthChallengeResponse:
    result = await _service(unit_of_work_factory).activate(
        request.activation_code.get_secret_value(), request.password.get_secret_value()
    )
    return _auth_result(result, response)


def _challenge_token(request: Request) -> str:
    value = request.cookies.get(get_settings().auth_challenge_cookie_name)
    if not value:
        raise InvalidChallengeError()
    return value


async def _complete_mfa(
    request: MfaVerifyRequest,
    raw_request: Request,
    response: Response,
    unit_of_work_factory: UnitOfWorkFactoryDep,
    *,
    expected_purpose: ChallengePurpose,
) -> MfaCompletionResponse:
    completed = await _service(unit_of_work_factory).complete_mfa(
        _challenge_token(raw_request),
        request.value.get_secret_value(),
        expected_purpose=expected_purpose,
    )
    settings = get_settings()
    _set_session_cookies(response, completed.issued, settings)
    _clear_challenge_cookie(response, settings)
    return MfaCompletionResponse(
        session=_response(completed.issued.principal),
        recovery_codes=list(completed.recovery_codes),
    )


@router.post("/auth/mfa/verify", operation_id="verifyMfa")
async def verify_mfa(
    request: MfaVerifyRequest,
    raw_request: Request,
    response: Response,
    unit_of_work_factory: UnitOfWorkFactoryDep,
    _: AllowedOriginDep,
) -> MfaCompletionResponse:
    return await _complete_mfa(
        request,
        raw_request,
        response,
        unit_of_work_factory,
        expected_purpose=ChallengePurpose.LOGIN_MFA,
    )


@router.post("/auth/mfa/enroll/confirm", operation_id="confirmMfaEnrollment")
async def confirm_mfa_enrollment(
    request: MfaVerifyRequest,
    raw_request: Request,
    response: Response,
    unit_of_work_factory: UnitOfWorkFactoryDep,
    _: AllowedOriginDep,
) -> MfaCompletionResponse:
    return await _complete_mfa(
        request,
        raw_request,
        response,
        unit_of_work_factory,
        expected_purpose=ChallengePurpose.MFA_ENROLLMENT,
    )


@router.post("/auth/mfa/enroll", operation_id="beginMfaEnrollment")
async def begin_mfa_enrollment(
    response: Response,
    unit_of_work_factory: UnitOfWorkFactoryDep,
    principal: UnsafeSessionDep,
) -> AuthChallengeResponse:
    challenge = await _service(unit_of_work_factory).begin_mfa_enrollment(principal)
    _set_challenge_cookie(response, challenge, get_settings())
    return AuthChallengeResponse(
        next_step=challenge.purpose.value,
        username=challenge.username,
        expires_at=challenge.expires_at,
        enrollment_secret=(
            challenge.enrollment_secret.get_secret_value()
            if challenge.enrollment_secret is not None
            else None
        ),
        otpauth_uri=(
            challenge.otpauth_uri.get_secret_value()
            if challenge.otpauth_uri is not None
            else None
        ),
    )


@router.post("/auth/reauthenticate", operation_id="reauthenticate")
async def reauthenticate(
    request: ReauthenticateRequest,
    unit_of_work_factory: UnitOfWorkFactoryDep,
    principal: UnsafeSessionDep,
) -> SessionResponse:
    elevated = await _service(unit_of_work_factory).reauthenticate(
        principal,
        request.password.get_secret_value(),
        request.mfa_value.get_secret_value() if request.mfa_value is not None else None,
    )
    return _response(elevated)


@router.get("/auth/session", operation_id="getSession", responses=AUTH_REQUIRED_RESPONSES)
async def session(principal: CurrentSessionDep) -> SessionResponse:
    return _response(principal)


@router.get(
    "/auth/security",
    operation_id="getSecurityStatus",
    responses=AUTH_REQUIRED_RESPONSES,
)
async def security_status(
    unit_of_work_factory: UnitOfWorkFactoryDep,
    principal: CurrentSessionDep,
) -> SecurityStatusResponse:
    result = await _service(unit_of_work_factory).security_status(principal)
    return SecurityStatusResponse.model_validate(result, from_attributes=True)


@router.post(
    "/auth/recovery-codes",
    operation_id="regenerateRecoveryCodes",
    responses=AUTH_UNSAFE_RESPONSES,
)
async def regenerate_recovery_codes(
    response: Response,
    unit_of_work_factory: UnitOfWorkFactoryDep,
    principal: UnsafeSessionDep,
) -> RecoveryCodesResponse:
    response.headers["Cache-Control"] = "no-store"
    codes = await _service(unit_of_work_factory).regenerate_recovery_codes(principal)
    return RecoveryCodesResponse(recovery_codes=list(codes))


@router.post(
    "/auth/password",
    status_code=status.HTTP_204_NO_CONTENT,
    operation_id="changeOwnPassword",
    responses=AUTH_UNSAFE_RESPONSES,
)
async def change_own_password(
    request: ChangePasswordRequest,
    response: Response,
    unit_of_work_factory: UnitOfWorkFactoryDep,
    principal: UnsafeSessionDep,
) -> None:
    await _service(unit_of_work_factory).change_password(
        principal,
        current_password=request.current_password.get_secret_value(),
        new_password=request.new_password.get_secret_value(),
        mfa_value=(
            request.mfa_value.get_secret_value() if request.mfa_value is not None else None
        ),
    )
    settings = get_settings()
    for name, httponly in (
        (settings.session_cookie_name, True),
        (settings.csrf_cookie_name, False),
    ):
        response.delete_cookie(
            name,
            path="/",
            secure=settings.cookies_secure,
            httponly=httponly,
            samesite="strict",
        )


@router.post(
    "/auth/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    operation_id="logout",
    responses=AUTH_UNSAFE_RESPONSES,
)
async def logout(
    response: Response,
    unit_of_work_factory: UnitOfWorkFactoryDep,
    principal: UnsafeSessionDep,
) -> None:
    await _service(unit_of_work_factory).logout(principal)
    settings = get_settings()
    for name, httponly in (
        (settings.session_cookie_name, True),
        (settings.csrf_cookie_name, False),
        (settings.auth_challenge_cookie_name, True),
    ):
        response.delete_cookie(
            name,
            path="/",
            secure=settings.cookies_secure,
            httponly=httponly,
            samesite="strict",
        )


@router.get("/users", operation_id="listUsers", responses=AUTH_REQUIRED_RESPONSES)
async def list_users(
    unit_of_work_factory: UnitOfWorkFactoryDep, principal: CurrentSessionDep
) -> list[UserResponse]:
    users = await _service(unit_of_work_factory).list_users(principal)
    return [_user_response(user) for user in users]


@router.post(
    "/users",
    operation_id="createUser",
    status_code=status.HTTP_201_CREATED,
    responses=AUTH_UNSAFE_RESPONSES,
)
async def create_user(
    request: CreateUserRequest,
    response: Response,
    unit_of_work_factory: UnitOfWorkFactoryDep,
    principal: UnsafeSessionDep,
) -> CreatedUserResponse:
    response.headers["Cache-Control"] = "no-store"
    created = await _service(unit_of_work_factory).create_user(
        principal, username=request.username, role=request.role
    )
    return CreatedUserResponse(
        user=_user_response(created.user),
        activation_code=created.activation_code,
        activation_expires_at=created.activation_expires_at,
    )


@router.put("/users/{user_id}", operation_id="updateUser", responses=AUTH_UNSAFE_RESPONSES)
async def update_user(
    user_id: UUID,
    request: UpdateUserRequest,
    unit_of_work_factory: UnitOfWorkFactoryDep,
    principal: UnsafeSessionDep,
) -> UserResponse:
    user = await _service(unit_of_work_factory).update_user(
        principal,
        user_id,
        role=request.role,
        status=request.status,
        expected_version=request.expected_version,
    )
    return _user_response(user)


@router.post(
    "/users/{user_id}/activation",
    operation_id="reissueUserActivation",
    responses=AUTH_UNSAFE_RESPONSES,
)
async def reissue_user_activation(
    user_id: UUID,
    response: Response,
    unit_of_work_factory: UnitOfWorkFactoryDep,
    principal: UnsafeSessionDep,
) -> CreatedUserResponse:
    response.headers["Cache-Control"] = "no-store"
    created = await _service(unit_of_work_factory).reissue_activation(principal, user_id)
    return CreatedUserResponse(
        user=_user_response(created.user),
        activation_code=created.activation_code,
        activation_expires_at=created.activation_expires_at,
    )


@router.post(
    "/users/{user_id}/mfa/reset",
    status_code=status.HTTP_204_NO_CONTENT,
    operation_id="resetUserMfa",
    responses=AUTH_UNSAFE_RESPONSES,
)
async def reset_user_mfa(
    user_id: UUID,
    unit_of_work_factory: UnitOfWorkFactoryDep,
    principal: UnsafeSessionDep,
) -> None:
    await _service(unit_of_work_factory).reset_user_mfa(principal, user_id)
