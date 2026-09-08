from __future__ import annotations

from datetime import timedelta
from types import SimpleNamespace
from typing import cast
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from fastapi import Response, UploadFile
from pydantic import ValidationError as PydanticValidationError
from starlette.requests import Request

import ops_composer.api.audit as audit_api
import ops_composer.api.playbooks as playbooks_api
import ops_composer.api.system as system_api
import ops_composer.auth.api as auth_api
from ops_composer.auth.errors import InvalidChallengeError
from ops_composer.auth.models import (
    ChallengePurpose,
    IssuedChallenge,
    IssuedSession,
    SessionPrincipal,
    UserIdentity,
    UserRole,
    UserStatus,
    permissions_for_role,
)
from ops_composer.auth.security import generate_token
from ops_composer.auth.service import CompletedMfa, CreatedUser, SecurityStatus
from ops_composer.domain.audit import (
    AuditAction,
    AuditEvent,
    AuditOutcome,
    AuditQuery,
    AuditSeverity,
    AuditSource,
)
from ops_composer.domain.base import utc_now
from ops_composer.domain.encryption import EncryptionUsage, KeyRotationJob, KeyRotationState
from ops_composer.domain.ops import (
    DatabasePlaybook,
    DatabasePlaybookDocument,
    PlaybookRevision,
    PlaybookRevisionFile,
    PlaybookRevisionFormat,
    PlaybookSource,
)
from ops_composer.services.encryption import KeyringStatus
from ops_composer.services.playbook_project import NormalizedProject
from ops_composer.services.playbooks import PlaybookValidationResult
from ops_composer.settings import Settings
from ops_composer.uow.factory import UnitOfWorkFactory


def _principal(role: UserRole = UserRole.OWNER) -> SessionPrincipal:
    now = utc_now()
    return SessionPrincipal(
        session_id=uuid4(),
        user_id=uuid4(),
        username="owner",
        role=role,
        permissions=permissions_for_role(role),
        mfa_enabled=True,
        mfa_verified_at=now,
        elevated_until=now + timedelta(minutes=10),
        csrf_hash="c" * 64,
        expires_at=now + timedelta(hours=1),
    )


def _request(*, cookies: str = "", referer: str | None = None) -> Request:
    headers: list[tuple[bytes, bytes]] = []
    if cookies:
        headers.append((b"cookie", cookies.encode()))
    if referer:
        headers.append((b"referer", referer.encode()))
    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": "/",
            "raw_path": b"/",
            "query_string": b"",
            "headers": headers,
            "server": ("test", 80),
            "client": ("127.0.0.1", 1),
        }
    )


def _identity(principal: SessionPrincipal) -> UserIdentity:
    now = utc_now()
    return UserIdentity(
        user_id=principal.user_id,
        username=principal.username,
        status=UserStatus.ACTIVE,
        role=principal.role,
        mfa_enrollment_required=False,
        activated_at=now,
        version=2,
        created_at=now,
        updated_at=now,
    )


@pytest.mark.asyncio
async def test_p2_auth_routes_cover_challenges_security_and_user_governance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings(allowed_origins_csv="https://ops.example.test")
    monkeypatch.setattr(auth_api, "get_settings", lambda: settings)
    principal = _principal()
    identity = _identity(principal)
    issued = IssuedSession(
        principal=principal,
        session_token=generate_token(),
        csrf_token=generate_token(),
    )
    challenge = IssuedChallenge(
        challenge_id=uuid4(),
        user_id=principal.user_id,
        username=principal.username,
        purpose=ChallengePurpose.MFA_ENROLLMENT,
        expires_at=utc_now() + timedelta(minutes=5),
        challenge_token=generate_token(),
        enrollment_secret="JBSWY3DPEHPK3PXP",
        otpauth_uri="otpauth://totp/OpsComposer:test?secret=redacted-in-response-test",
    )
    created = CreatedUser(
        user=identity,
        activation_code="activation-code-only-once-1234567890",
        activation_expires_at=utc_now() + timedelta(hours=24),
    )
    service = SimpleNamespace(
        login=AsyncMock(return_value=challenge),
        activate=AsyncMock(return_value=issued),
        complete_mfa=AsyncMock(return_value=CompletedMfa(issued, ("recovery-one",))),
        begin_mfa_enrollment=AsyncMock(return_value=challenge),
        reauthenticate=AsyncMock(return_value=principal),
        security_status=AsyncMock(
            return_value=SecurityStatus(True, False, 9, principal.elevated_until)
        ),
        regenerate_recovery_codes=AsyncMock(return_value=("code-one", "code-two")),
        change_password=AsyncMock(),
        logout=AsyncMock(),
        list_users=AsyncMock(return_value=(identity,)),
        create_user=AsyncMock(return_value=created),
        update_user=AsyncMock(return_value=identity),
        reissue_activation=AsyncMock(return_value=created),
        reset_user_mfa=AsyncMock(),
    )
    monkeypatch.setattr(auth_api, "_service", lambda _factory: service)
    factory = cast(UnitOfWorkFactory, object())

    assert auth_api._source_origin(_request(referer="https://ops.example.test/users")) == (
        "https://ops.example.test"
    )
    assert auth_api._source_origin(_request(referer="file:///tmp/nope")) is None
    assert auth_api._source_origin(_request()) is None
    with pytest.raises(InvalidChallengeError):
        auth_api._challenge_token(_request())

    login_response = Response()
    login_result = await auth_api.login(
        auth_api.LoginRequest(username="owner", password="password"),
        _request(),
        login_response,
        factory,
        None,
    )
    assert login_result.next_step == ChallengePurpose.MFA_ENROLLMENT.value
    assert login_result.enrollment_secret == "JBSWY3DPEHPK3PXP"

    activated = await auth_api.activate(
        auth_api.ActivationRequest(
            activation_code="a" * 32,
            password="a sufficiently long password",
        ),
        Response(),
        factory,
        None,
    )
    assert activated.user_id == principal.user_id

    challenge_cookie = f"{settings.auth_challenge_cookie_name}=opaque-challenge"
    for endpoint, purpose in (
        (auth_api.verify_mfa, ChallengePurpose.LOGIN_MFA),
        (auth_api.confirm_mfa_enrollment, ChallengePurpose.MFA_ENROLLMENT),
    ):
        completed = await endpoint(
            auth_api.MfaVerifyRequest(value="123456"),
            _request(cookies=challenge_cookie),
            Response(),
            factory,
            None,
        )
        assert completed.recovery_codes == ["recovery-one"]
        assert service.complete_mfa.await_args.kwargs["expected_purpose"] is purpose

    enrollment_response = Response()
    enrollment = await auth_api.begin_mfa_enrollment(
        enrollment_response, factory, principal
    )
    assert enrollment.otpauth_uri is not None
    assert settings.auth_challenge_cookie_name in enrollment_response.headers["set-cookie"]

    elevated = await auth_api.reauthenticate(
        auth_api.ReauthenticateRequest(password="password", mfa_value="123456"),
        factory,
        principal,
    )
    assert elevated.elevated_until == principal.elevated_until
    assert (await auth_api.session(principal)).permissions
    security = await auth_api.security_status(factory, principal)
    assert security.unused_recovery_codes == 9
    codes_response = Response()
    codes = await auth_api.regenerate_recovery_codes(codes_response, factory, principal)
    assert codes.recovery_codes == ["code-one", "code-two"]
    assert codes_response.headers["Cache-Control"] == "no-store"

    password_response = Response()
    await auth_api.change_own_password(
        auth_api.ChangePasswordRequest(
            current_password="current-password",
            new_password="next-password-is-long",
            mfa_value="123456",
        ),
        password_response,
        factory,
        principal,
    )
    assert len(password_response.headers.getlist("set-cookie")) == 2
    await auth_api.change_own_password(
        auth_api.ChangePasswordRequest(
            current_password="current-password",
            new_password="another-long-password",
        ),
        Response(),
        factory,
        principal,
    )

    logout_response = Response()
    await auth_api.logout(logout_response, factory, principal)
    assert len(logout_response.headers.getlist("set-cookie")) == 3
    assert (await auth_api.list_users(factory, principal))[0].role is UserRole.OWNER

    created_response = Response()
    created_payload = await auth_api.create_user(
        auth_api.CreateUserRequest(username="operator", role=UserRole.OPERATOR),
        created_response,
        factory,
        principal,
    )
    assert created_payload.activation_code == created.activation_code
    assert created_response.headers["Cache-Control"] == "no-store"
    updated = await auth_api.update_user(
        identity.user_id,
        auth_api.UpdateUserRequest(
            role=UserRole.AUDITOR,
            status=UserStatus.ACTIVE,
            expected_version=2,
        ),
        factory,
        principal,
    )
    assert updated.user_id == identity.user_id
    reissue_response = Response()
    assert (
        await auth_api.reissue_user_activation(
            identity.user_id, reissue_response, factory, principal
        )
    ).activation_code == created.activation_code
    await auth_api.reset_user_mfa(identity.user_id, factory, principal)


def _playbook_document() -> DatabasePlaybookDocument:
    now = utc_now()
    user_id = uuid4()
    playbook_id = uuid4()
    file = PlaybookRevisionFile(
        path="site.yml",
        content="---\n- hosts: all\n  tasks: []\n",
        sha256="a" * 64,
        size_bytes=33,
    )
    return DatabasePlaybookDocument(
        playbook=DatabasePlaybook(
            playbook_id=playbook_id,
            name="Project",
            description="managed in database",
            enabled=True,
            current_revision=2,
            version=2,
            created_by=user_id,
            updated_by=user_id,
            created_at=now,
            updated_at=now,
        ),
        revision=PlaybookRevision(
            playbook_id=playbook_id,
            revision=2,
            sha256="b" * 64,
            size_bytes=file.size_bytes,
            validator_version="ansible-core test",
            validated_at=now,
            created_by=user_id,
            created_at=now,
            revision_format=PlaybookRevisionFormat.PROJECT,
            entrypoint="site.yml",
            parameter_schema={
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
            supports_check_mode=True,
            files=(file,),
        ),
    )


@pytest.mark.asyncio
async def test_p2_playbook_routes_cover_project_crud_revision_zip_and_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    principal = _principal()
    factory = cast(UnitOfWorkFactory, object())
    document = _playbook_document()
    revision = document.revision
    project = NormalizedProject(
        files=revision.files,
        entrypoint="site.yml",
        sha256=revision.sha256,
        size_bytes=revision.size_bytes,
    )
    validation = PlaybookValidationResult(valid=True, output="syntax check passed")
    service = SimpleNamespace(
        create_database=AsyncMock(return_value=document),
        import_zip=AsyncMock(return_value=project),
        get_database=AsyncMock(return_value=document),
        update_database=AsyncMock(return_value=document),
        delete_database=AsyncMock(),
        list_revisions=AsyncMock(return_value=(revision,)),
        get_revision=AsyncMock(return_value=revision),
        diff_revisions=AsyncMock(
            return_value={
                "revision": 2,
                "againstRevision": 1,
                "added": ["site.yml"],
                "deleted": [],
                "modified": [],
                "diff": "+site.yml",
            }
        ),
        restore_revision=AsyncMock(return_value=document),
        export_zip=AsyncMock(return_value=b"PK-test-zip"),
        validate_content=AsyncMock(return_value=validation),
        validate_project=AsyncMock(return_value=validation),
        validate_reference=AsyncMock(return_value=validation),
    )
    monkeypatch.setattr(playbooks_api, "_service", lambda _factory: service)
    monkeypatch.setattr(
        playbooks_api,
        "get_settings",
        lambda: Settings(playbook_source_mode="both"),
    )

    config = await playbooks_api.get_playbook_config(principal)
    assert config.database_writable and config.mount_read_only
    auditor_config = await playbooks_api.get_playbook_config(_principal(UserRole.AUDITOR))
    assert not auditor_config.database_writable

    files = (playbooks_api.PlaybookFileRequest(path="site.yml", content=revision.files[0].content),)
    create_request = playbooks_api.DatabasePlaybookCreateRequest(
        name=" Project ",
        files=files,
        entrypoint="site.yml",
        parameter_schema=revision.parameter_schema,
        supports_check_mode=True,
    )
    assert create_request.name == "Project"
    create_response = Response()
    created = await playbooks_api.create_database_playbook(
        create_request, create_response, factory, principal
    )
    assert created.entrypoint == "site.yml"
    assert create_response.headers["Cache-Control"] == "no-store"

    legacy_response = Response()
    await playbooks_api.create_database_playbook(
        playbooks_api.DatabasePlaybookCreateRequest(
            name="Legacy", content="---\n- hosts: all\n"
        ),
        legacy_response,
        factory,
        principal,
    )
    assert legacy_response.headers["Deprecation"] == "true"

    upload = cast(UploadFile, SimpleNamespace(read=AsyncMock(return_value=b"PK-upload")))
    imported = await playbooks_api.import_playbook_project_zip(
        factory, principal, upload, "site.yml"
    )
    assert imported.entrypoint == "site.yml"
    assert service.import_zip.await_args.args[0] == b"PK-upload"

    detail_response = Response()
    detail = await playbooks_api.get_database_playbook(
        document.playbook.playbook_id, detail_response, factory, principal
    )
    assert detail.revision == 2
    update_response = Response()
    await playbooks_api.update_database_playbook(
        document.playbook.playbook_id,
        playbooks_api.DatabasePlaybookUpdateRequest(
            name="Project",
            version=2,
            files=files,
            entrypoint="site.yml",
        ),
        update_response,
        factory,
        principal,
    )
    assert update_response.headers["Cache-Control"] == "no-store"
    legacy_update_response = Response()
    await playbooks_api.update_database_playbook(
        document.playbook.playbook_id,
        playbooks_api.DatabasePlaybookUpdateRequest(
            name="Legacy",
            version=2,
            content="---\n- hosts: all\n",
        ),
        legacy_update_response,
        factory,
        principal,
    )
    assert legacy_update_response.headers["Deprecation"] == "true"
    assert (
        await playbooks_api.delete_database_playbook(
            document.playbook.playbook_id, factory, principal, version=2
        )
    ).status_code == 204

    revisions = await playbooks_api.list_playbook_revisions(
        document.playbook.playbook_id, factory, principal
    )
    assert revisions[0].content is None and revisions[0].files is None
    revision_response = Response()
    fetched = await playbooks_api.get_playbook_revision(
        document.playbook.playbook_id, 2, revision_response, factory, principal
    )
    assert fetched.files == revision.files
    diff = await playbooks_api.diff_playbook_revisions(
        document.playbook.playbook_id, 2, factory, principal, against_revision=1
    )
    assert diff.added == ["site.yml"]
    restored_response = Response()
    restored = await playbooks_api.restore_playbook_revision(
        document.playbook.playbook_id,
        1,
        playbooks_api.PlaybookRestoreRequest(version=2),
        restored_response,
        factory,
        principal,
    )
    assert restored.revision == 2
    exported = await playbooks_api.export_playbook_project_zip(
        document.playbook.playbook_id, 2, factory, principal
    )
    assert exported.body == b"PK-test-zip"
    assert exported.headers["content-type"] == "application/zip"

    for request in (
        playbooks_api.PlaybookValidationRequest(content="---\n- hosts: all\n"),
        playbooks_api.PlaybookValidationRequest(files=files, entrypoint="site.yml"),
        playbooks_api.PlaybookValidationRequest(
            playbook={
                "source": PlaybookSource.DATABASE,
                "playbookId": document.playbook.playbook_id,
            }
        ),
    ):
        response = Response()
        assert (await playbooks_api.validate_playbook(request, response, factory, principal)).valid
        assert response.headers["Cache-Control"] == "no-store"

    for invalid in (
        {"name": "bad"},
        {"name": "bad", "content": "x", "files": [{"path": "x", "content": "x"}]},
        {"name": "bad", "files": [{"path": "x", "content": "x"}]},
        {"name": "bad", "content": "x", "entrypoint": "site.yml"},
        {
            "name": "bad",
            "files": [
                {"path": "Site.yml", "content": "x"},
                {"path": "site.yml", "content": "x"},
            ],
            "entrypoint": "site.yml",
        },
    ):
        with pytest.raises(PydanticValidationError):
            playbooks_api.DatabasePlaybookCreateRequest.model_validate(invalid)
    for invalid_validation in (
        {},
        {"content": "x", "path": "playbooks/site.yml"},
        {"files": [{"path": "site.yml", "content": "x"}]},
    ):
        with pytest.raises(PydanticValidationError):
            playbooks_api.PlaybookValidationRequest.model_validate(invalid_validation)



def test_playbook_api_service_uses_runtime_source_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        playbooks_api,
        "get_settings",
        lambda: Settings(playbook_source_mode="both"),
    )
    factory = cast(UnitOfWorkFactory, object())
    assert playbooks_api._service(factory).mode.value == "both"


def _audit_event(event_id: int) -> AuditEvent:
    return AuditEvent(
        audit_event_id=event_id,
        occurred_at=utc_now(),
        severity=AuditSeverity.INFO,
        source=AuditSource.API,
        service="api",
        event_action=AuditAction.AUTH_LOGIN_SUCCEEDED,
        event_outcome=AuditOutcome.SUCCEEDED,
        resource_type="user",
        resource_id="safe-id",
        metadata={"count": 1},
    )


@pytest.mark.asyncio
async def test_audit_http_listing_cursor_and_streaming_export(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    principal = _principal(UserRole.AUDITOR)
    factory = cast(UnitOfWorkFactory, object())
    service = SimpleNamespace(list=AsyncMock(), record_best_effort=AsyncMock())
    monkeypatch.setattr(audit_api, "AuditService", lambda _factory: service)
    service.list.return_value = (_audit_event(9),)
    page = await audit_api.list_audit_events(factory, principal, limit=1)
    assert page.next_cursor == 9
    assert page.items[0].resource_id == "safe-id"

    first_page = tuple(_audit_event(index) for index in range(1, 501))

    async def paged(query: AuditQuery) -> tuple[AuditEvent, ...]:
        return first_page if query.before_id is None else (_audit_event(501),)

    service.list = AsyncMock(side_effect=paged)
    since = utc_now() - timedelta(hours=1)
    until = utc_now()
    response = await audit_api.export_audit_events(factory, principal, since, until)
    chunks = [chunk async for chunk in response.body_iterator]
    payload = b"".join(cast(list[bytes], chunks))
    assert len(payload.splitlines()) == 501
    assert b'"resourceId":"safe-id"' in payload
    assert response.headers["Cache-Control"] == "no-store"
    service.record_best_effort.assert_awaited_once()


@pytest.mark.asyncio
async def test_keyring_status_and_rotation_routes_include_unconfigured_usage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    principal = _principal()
    factory = cast(UnitOfWorkFactory, object())
    now = utc_now()
    job = KeyRotationJob(
        key_rotation_job_id=uuid4(),
        target_key_version=2,
        state=KeyRotationState.RUNNING,
        requested_by=principal.user_id,
        processed_count=10,
        remaining_count=2,
        created_at=now,
        started_at=now,
        updated_at=now,
    )
    service = SimpleNamespace(
        status=AsyncMock(
            return_value=KeyringStatus(
                primary_version=2,
                configured_versions=(1, 2),
                usage=(
                    EncryptionUsage(
                        key_version=3,
                        credential_count=1,
                        mfa_count=2,
                        system_count=0,
                        run_secret_count=0,
                    ),
                ),
                latest_job=job,
            )
        ),
        request_rotation=AsyncMock(return_value=job),
    )
    monkeypatch.setattr(system_api, "_encryption_service", lambda _factory: service)

    status = await system_api.keyring_status(factory, principal)
    assert [item.key_version for item in status.usage] == [1, 2, 3]
    assert status.usage[1].primary and status.usage[1].total_count == 0
    assert not status.usage[2].configured and status.usage[2].total_count == 3
    assert status.latest_rotation is not None
    requested = await system_api.request_key_rotation(factory, principal)
    assert requested.key_rotation_job_id == job.key_rotation_job_id


def test_system_encryption_service_builds_from_runtime_settings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings(master_key_version=7)
    monkeypatch.setattr(system_api, "get_settings", lambda: settings)
    factory = cast(UnitOfWorkFactory, object())

    service = system_api._encryption_service(factory)

    assert service._unit_of_work_factory is factory
    assert service._keyring.primary_version == 7
