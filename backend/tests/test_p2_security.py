from __future__ import annotations

import base64
import io
import json
import stat
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from pydantic import SecretStr

from ops_composer.auth.errors import PermissionDeniedError
from ops_composer.auth.models import (
    Permission,
    SessionPrincipal,
    UserRole,
    permissions_for_role,
)
from ops_composer.auth.security import (
    generate_recovery_codes,
    generate_totp_secret,
    hash_recovery_code,
    match_totp_step,
    totp_code,
)
from ops_composer.domain.errors import PlaybookProjectInvalidError, ValidationError
from ops_composer.repositories.base import RepositoryConnection
from ops_composer.repositories.encryption import PostgresEncryptionRepository
from ops_composer.services.assets import CredentialService
from ops_composer.services.crypto import CredentialCipher, MasterKeyring, build_master_keyring
from ops_composer.services.playbook_project import (
    MAX_PROJECT_FILE_BYTES,
    MAX_PROJECT_FILES,
    MAX_PROJECT_PATH_LENGTH,
    MAX_ZIP_BYTES,
    PROJECT_MANIFEST,
    export_project_zip,
    import_project_zip,
    normalize_project,
    normalize_project_path,
    validate_parameter_schema,
    validate_parameters,
)
from ops_composer.settings import Settings
from ops_composer.uow.factory import UnitOfWorkFactory


def _principal(role: UserRole) -> SessionPrincipal:
    now = datetime.now(UTC)
    return SessionPrincipal(
        session_id=uuid4(),
        user_id=uuid4(),
        username=role.value.casefold(),
        role=role,
        permissions=permissions_for_role(role),
        csrf_hash="0" * 64,
        expires_at=now + timedelta(hours=1),
    )


def test_rfc6238_sha1_totp_window_and_replay_protection() -> None:
    # RFC 6238 SHA-1 vector at Unix time 59 is 94287082; this product uses six digits.
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    assert totp_code(secret, 1) == "287082"
    assert match_totp_step(secret, "287082", now=59) == 1
    assert match_totp_step(secret, "287082", now=59, last_accepted_step=1) is None
    assert match_totp_step(secret, totp_code(secret, 2), now=59) == 2
    assert match_totp_step(secret, "not-a-code", now=59) is None


def test_totp_and_recovery_material_has_expected_entropy_and_one_way_hashes() -> None:
    secret = generate_totp_secret()
    assert len(base64.b32decode(secret + "=" * ((8 - len(secret) % 8) % 8))) == 20
    codes = generate_recovery_codes()
    assert len(codes) == len(set(codes)) == 10
    assert all(len(hash_recovery_code(code)) == 64 for code in codes)
    assert hash_recovery_code(codes[0].lower().replace("-", " ")) == hash_recovery_code(codes[0])


def test_fixed_role_permissions_match_governance_boundaries() -> None:
    assert set(permissions_for_role(UserRole.OWNER)) == set(Permission)
    assert Permission.CREDENTIAL_WRITE in permissions_for_role(UserRole.ADMIN)
    assert Permission.RUN_SHELL not in permissions_for_role(UserRole.OPERATOR)
    assert Permission.WEB_SHELL not in permissions_for_role(UserRole.OPERATOR)
    assert permissions_for_role(UserRole.AUDITOR) == {
        Permission.ASSET_READ,
        Permission.AUDIT_READ,
        Permission.USER_READ,
    }


@pytest.mark.asyncio
async def test_key_rotation_claim_uses_transaction_advisory_lock() -> None:
    connection = AsyncMock()
    connection.fetch_one.return_value = None
    repository = PostgresEncryptionRepository(cast(RepositoryConnection, connection))
    now = datetime.now(UTC)

    assert await repository.claim_rotation_job(
        "rotation-worker",
        now,
        now + timedelta(seconds=30),
    ) is None

    query, parameters = connection.fetch_one.call_args.args
    assert "pg_try_advisory_xact_lock" in query.as_string()
    assert "FOR UPDATE OF j SKIP LOCKED" in query.as_string()
    assert parameters["rotation_lock_key"] > 0
    assert connection.fetch_one.call_args.kwargs == {"prepare": True}


@pytest.mark.asyncio
async def test_credential_service_enforces_permission_before_persistence() -> None:
    keyring = MasterKeyring({1: b"k" * 32}, 1)
    service = CredentialService(
        cast(UnitOfWorkFactory, object()),
        CredentialCipher(keyring),
    )
    with pytest.raises(PermissionDeniedError):
        await service.create(
            name="blocked",
            username="ops",
            password="sentinel-password",
            become_password=None,
            become_enabled=False,
            become_method="sudo",
            become_user="root",
            description="",
            actor=_principal(UserRole.OPERATOR),
        )


def test_private_key_metadata_accepts_ed25519_and_rejects_small_rsa() -> None:
    key = ed25519.Ed25519PrivateKey.generate()
    encoded = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption(),
    ).decode()
    metadata = CredentialService._private_key_metadata(encoded, None)
    assert metadata["keyAlgorithm"] == "ssh-ed25519"
    assert metadata["keyBits"] == 256
    assert str(metadata["publicKeyFingerprint"]).startswith("SHA256:")
    assert metadata["hasPassphrase"] is False

    weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    weak_encoded = weak.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    with pytest.raises(ValidationError, match="at least 2048"):
        CredentialService._private_key_metadata(weak_encoded, None)


def test_master_keyring_file_permissions_versions_and_aead(tmp_path: Path) -> None:
    path = tmp_path / "keyring.json"
    path.write_text(
        json.dumps(
            {
                "primaryVersion": 2,
                "keys": {
                    "1": base64.b64encode(b"a" * 32).decode(),
                    "2": base64.b64encode(b"b" * 32).decode(),
                },
            }
        ),
        encoding="utf-8",
    )
    path.chmod(0o644)
    with pytest.raises(ValueError, match="0400 or 0600"):
        MasterKeyring.from_file(path)
    path.chmod(0o600)
    keyring = MasterKeyring.from_file(path)
    assert keyring.primary_version == 2
    assert keyring.versions == (1, 2)
    envelope, version = keyring.encrypt_bytes("test", "subject", b"payload")
    assert version == 2
    assert keyring.decrypt_bytes("test", "subject", envelope, version) == b"payload"
    with pytest.raises(ValueError, match="unavailable"):
        keyring.decrypt_bytes("test", "subject", envelope, 3)


def test_settings_reject_combined_legacy_key_and_keyring(tmp_path: Path) -> None:
    path = tmp_path / "keyring.json"
    with pytest.raises(ValueError, match="cannot be combined"):
        Settings(
            master_keyring_file=path,
            master_key=SecretStr(base64.b64encode(b"x" * 32).decode()),
        )


def test_master_keyring_rejects_malformed_configuration_and_context(tmp_path: Path) -> None:
    encoded = base64.b64encode(b"k" * 32).decode()
    for keys, primary, message in (
        ({1: "not-base64"}, 1, "valid base64"),
        ({1: base64.b64encode(b"short").decode()}, 1, "exactly 32"),
        ({1: b"short"}, 1, "exactly 32"),
        ({0: b"k" * 32}, 1, "versions must be positive"),
        ({1: b"k" * 32}, 0, "primary key version"),
        ({1: b"k" * 32}, 2, "primary key version is missing"),
    ):
        with pytest.raises(ValueError, match=message):
            MasterKeyring(keys, primary)

    keyring = MasterKeyring({1: encoded}, 1)
    for purpose, subject in (("", "id"), ("credential", ""), ("bad\x00purpose", "id")):
        with pytest.raises(ValueError, match="context"):
            keyring.encrypt_bytes(purpose, subject, b"secret")
    with pytest.raises(ValueError, match="unavailable"):
        keyring.encrypt_with_aad(b"secret", b"aad", key_version=2)
    with pytest.raises(ValueError, match="invalid"):
        keyring.decrypt_with_aad(b"short", b"aad", 1)

    path = tmp_path / "keyring.json"
    path.write_text("not-json", encoding="utf-8")
    path.chmod(0o600)
    with pytest.raises(ValueError, match="UTF-8 JSON"):
        MasterKeyring.from_file(path)
    for payload, message in (
        ({"primaryVersion": 1}, "contain only"),
        ({"primaryVersion": True, "keys": {}}, "invalid types"),
        ({"primaryVersion": 1, "keys": {"bad": encoded}}, "positive integers"),
        ({"primaryVersion": 1, "keys": {"01": encoded}}, "entries are invalid"),
        ({"primaryVersion": 1, "keys": {"1": 7}}, "entries are invalid"),
    ):
        path.write_text(json.dumps(payload), encoding="utf-8")
        with pytest.raises(ValueError, match=message):
            MasterKeyring.from_file(path)

    path.write_text(
        json.dumps({"primaryVersion": 1, "keys": {"1": encoded}}),
        encoding="utf-8",
    )
    from_file = build_master_keyring(
        keyring_file=path,
        fallback_key="unused",
        fallback_version=9,
    )
    assert from_file.versions == (1,)


def test_master_keyring_and_credential_cipher_reject_tampered_payload_shapes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keyring = MasterKeyring({1: b"k" * 32}, 1)
    malformed_json, version = keyring.encrypt_bytes("json", "subject", b"not-json")
    with pytest.raises(ValueError, match="JSON payload is invalid"):
        keyring.decrypt_json("json", "subject", malformed_json, version)
    list_json, version = keyring.encrypt_bytes("json", "subject", b"[1,2]")
    with pytest.raises(ValueError, match="must be an object"):
        keyring.decrypt_json("json", "subject", list_json, version)

    monkeypatch.setattr(keyring, "decrypt_bytes", lambda *_args: b"wrong")
    with pytest.raises(ValueError, match="does not match"):
        keyring.validate_check(1, b"x" * 29)
    monkeypatch.undo()
    keyring = MasterKeyring({1: b"k" * 32}, 1)
    monkeypatch.setattr(keyring, "decrypt_with_aad", lambda *_args: b"wrong")
    with pytest.raises(ValueError, match="check value is invalid"):
        keyring.validate_legacy_check(1, b"x" * 29)

    with pytest.raises(ValueError, match="key_version is required"):
        CredentialCipher(base64.b64encode(b"k" * 32).decode())
    cipher = CredentialCipher(MasterKeyring({1: b"k" * 32}, 1))
    credential_id = uuid4()
    assert cipher._subject(credential_id, 2).endswith(":2")
    aad = f"ops-composer:credential:{credential_id}:1".encode()
    bad_json, _ = cipher.keyring.encrypt_with_aad(b"not-json", aad)
    with pytest.raises(ValueError, match="payload is invalid"):
        cipher.decrypt(credential_id, 1, bad_json)
    wrong_shape, _ = cipher.keyring.encrypt_with_aad(b'{"password":1}', aad)
    with pytest.raises(ValueError, match="payload is invalid"):
        cipher.decrypt(credential_id, 1, wrong_shape)
    with pytest.raises(ValueError, match="check value is invalid"):
        cipher.validate_check("not-base64")

    legacy, _ = cipher.keyring.encrypt_with_aad(
        b"ops-composer-master-key-check", b"key-check:v1"
    )
    cipher.validate_check(base64.b64encode(legacy).decode())


def test_project_normalization_and_parameter_separation() -> None:
    project = normalize_project(
        {
            "site.yml": "---\n- hosts: all\n  tasks: []\n",
            "roles/web/tasks/main.yml": "---\n- debug:\n    msg: ready\n",
        },
        "site.yml",
    )
    assert project.entrypoint == "site.yml"
    assert project.size_bytes > 0

    schema = validate_parameter_schema(
        {
            "type": "object",
            "additionalProperties": False,
            "required": ["environment", "apiToken"],
            "properties": {
                "environment": {"type": "string", "enum": ["dev", "prod"]},
                "retries": {"type": "integer", "minimum": 1, "default": 3},
                "apiToken": {
                    "type": "string",
                    "minLength": 8,
                    "x-ops-composer-sensitive": True,
                },
            },
        }
    )
    values = validate_parameters(
        schema,
        {"environment": "prod", "apiToken": "sentinel-secret"},
    )
    assert values.public_values == {"environment": "prod", "retries": 3}
    assert values.secret_values == {"apiToken": "sentinel-secret"}
    assert "sentinel-secret" not in json.dumps(values.public_values)

    with pytest.raises(PlaybookProjectInvalidError):
        validate_parameter_schema(
            {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "secret": {
                        "type": "string",
                        "default": "forbidden",
                        "x-ops-composer-sensitive": True,
                    }
                },
            }
        )


@pytest.mark.parametrize(
    "files,entrypoint",
    [
        ({"../site.yml": "---\n- hosts: all\n"}, "../site.yml"),
        ({"ansible.cfg": "[defaults]\n"}, "ansible.cfg"),
        ({"filter_plugins/custom.py": "x = 1\n"}, "filter_plugins/custom.py"),
        ({"Site.yml": "x\n", "site.yml": "y\n"}, "site.yml"),
        ({"site.yml": "bad\x00value"}, "site.yml"),
    ],
)
def test_project_rejects_unsafe_paths_and_content(
    files: dict[str, str], entrypoint: str
) -> None:
    with pytest.raises(PlaybookProjectInvalidError):
        normalize_project(files, entrypoint)


def test_zip_round_trip_is_deterministic_and_rejects_symlinks() -> None:
    project = normalize_project(
        {"site.yml": "---\n- hosts: all\n  gather_facts: false\n"},
        "site.yml",
    )
    first = export_project_zip(project)
    assert first == export_project_zip(project)
    imported = import_project_zip(first, None)
    assert imported == project

    target = io.BytesIO()
    with zipfile.ZipFile(target, "w") as archive:
        link = zipfile.ZipInfo("site.yml")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(link, "elsewhere.yml")
    with pytest.raises(PlaybookProjectInvalidError, match="symbolic links"):
        import_project_zip(target.getvalue(), "site.yml")


@pytest.mark.parametrize(
    "path,message",
    [
        ("", "invalid path"),
        ("x" * (MAX_PROJECT_PATH_LENGTH + 1), "invalid path"),
        ("roles\\task.yml", "invalid path"),
        ("roles/\x01task.yml", "invalid path"),
        ("/site.yml", "invalid path"),
        ("/".join(["d"] * 17), "invalid path"),
        ("roles/../site.yml", "traversal"),
        (" roles/site.yml", "traversal"),
        (PROJECT_MANIFEST.upper(), "forbidden"),
        ("roles/ansible.cfg", "forbidden"),
        ("roles/action_plugins/main.py", "forbidden"),
        ("roles/custom_plugins/main.py", "forbidden"),
        ("inventory", "forbidden"),
    ],
)
def test_project_path_security_boundaries(path: str, message: str) -> None:
    with pytest.raises(PlaybookProjectInvalidError, match=message):
        normalize_project_path(path)


def test_project_capacity_entrypoint_and_utf8_boundaries() -> None:
    with pytest.raises(PlaybookProjectInvalidError, match="between 1 and 256"):
        normalize_project({}, "site.yml")
    too_many = {f"file-{index}.txt": "x" for index in range(MAX_PROJECT_FILES + 1)}
    with pytest.raises(PlaybookProjectInvalidError, match="between 1 and 256"):
        normalize_project(too_many, "site.yml")
    with pytest.raises(PlaybookProjectInvalidError, match="empty, binary, or oversized"):
        normalize_project({"site.yml": "x" * (MAX_PROJECT_FILE_BYTES + 1)}, "site.yml")
    with pytest.raises(PlaybookProjectInvalidError, match="UTF-8"):
        normalize_project({"site.yml": "\ud800"}, "site.yml")
    with pytest.raises(PlaybookProjectInvalidError, match="YAML"):
        normalize_project({"site.txt": "text"}, "site.txt")
    with pytest.raises(PlaybookProjectInvalidError, match="exactly one"):
        normalize_project({"other.yml": "---\n[]\n"}, "site.yml")


@pytest.mark.parametrize(
    "schema,message",
    [
        ({"type": "object", "additionalProperties": False, "unknown": True}, "root keywords"),
        ({"type": "array", "additionalProperties": False}, "must be an object"),
        ({"type": "object", "additionalProperties": True}, "must be an object"),
        ({"type": "object", "additionalProperties": False, "description": 1}, "description"),
        ({"type": "object", "additionalProperties": False, "properties": []}, "properties"),
        (
            {
                "type": "object",
                "additionalProperties": False,
                "properties": {"known": {"type": "string"}},
                "required": ["missing"],
            },
            "required fields",
        ),
        (
            {
                "type": "object",
                "additionalProperties": False,
                "properties": {"known": {"type": "string"}},
                "required": ["known", "known"],
            },
            "required fields",
        ),
        (
            {
                "type": "object",
                "additionalProperties": False,
                "properties": {"": {"type": "string"}},
            },
            "property name",
        ),
        (
            {
                "type": "object",
                "additionalProperties": False,
                "properties": {"value": {"type": "string", "pattern": ".*"}},
            },
            "unsupported keywords",
        ),
        (
            {
                "type": "object",
                "additionalProperties": False,
                "properties": {"value": {"type": "object"}},
            },
            "type is unsupported",
        ),
        (
            {
                "type": "object",
                "additionalProperties": False,
                "properties": {"value": {"type": "string", "description": 1}},
            },
            "description must be",
        ),
        (
            {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "value": {"type": "string", "x-ops-composer-sensitive": "yes"}
                },
            },
            "marker must be boolean",
        ),
        (
            {
                "type": "object",
                "additionalProperties": False,
                "properties": {"value": {"type": "string", "enum": []}},
            },
            "enum is invalid",
        ),
        (
            {
                "type": "object",
                "additionalProperties": False,
                "properties": {"value": {"type": "string", "enum": ["x", "x"]}},
            },
            "duplicate values",
        ),
        (
            {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "value": {"type": "string", "enum": ["x"], "default": "y"}
                },
            },
            "outside its enum",
        ),
        (
            {
                "type": "object",
                "additionalProperties": False,
                "properties": {"value": {"type": "string", "minLength": -1}},
            },
            "length limits are invalid",
        ),
        (
            {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "value": {"type": "string", "minLength": 5, "maxLength": 2}
                },
            },
            "length limits are reversed",
        ),
        (
            {
                "type": "object",
                "additionalProperties": False,
                "properties": {"value": {"type": "integer", "minLength": 1}},
            },
            "length limits require",
        ),
        (
            {
                "type": "object",
                "additionalProperties": False,
                "properties": {"value": {"type": "number", "minimum": float("inf")}},
            },
            "numeric limits are invalid",
        ),
        (
            {
                "type": "object",
                "additionalProperties": False,
                "properties": {"value": {"type": "integer", "minimum": 5, "maximum": 2}},
            },
            "numeric limits are reversed",
        ),
        (
            {
                "type": "object",
                "additionalProperties": False,
                "properties": {"value": {"type": "boolean", "minimum": 1}},
            },
            "numeric limits require",
        ),
    ],
)
def test_parameter_schema_rejects_unsupported_or_ambiguous_shapes(
    schema: dict[str, object], message: str
) -> None:
    with pytest.raises(PlaybookProjectInvalidError, match=message):
        validate_parameter_schema(schema)


def test_parameter_validation_enforces_types_ranges_and_required_values() -> None:
    schema = validate_parameter_schema(
        {
            "type": "object",
            "additionalProperties": False,
            "required": ["name", "count"],
            "properties": {
                "name": {"type": "string", "minLength": 2, "maxLength": 4},
                "count": {"type": "integer", "minimum": 1, "maximum": 3},
                "mode": {"type": "string", "enum": ["safe", "fast"]},
                "ratio": {"type": "number"},
                "enabled": {"type": "boolean"},
            },
        }
    )
    for values, message in (
        ({"name": "ok", "count": 1, "extra": True}, "unknown"),
        ({"count": 1}, "required"),
        ({"name": 1, "count": 1}, "type"),
        ({"name": "ok", "count": 1, "mode": "other"}, "outside"),
        ({"name": "x", "count": 1}, "too short"),
        ({"name": "excess", "count": 1}, "too long"),
        ({"name": "ok", "count": 0}, "below"),
        ({"name": "ok", "count": 4}, "above"),
    ):
        with pytest.raises(ValidationError, match=message):
            validate_parameters(schema, values)
    valid = validate_parameters(
        schema,
        {"name": "okay", "count": 2, "mode": "safe", "ratio": 1.5, "enabled": True},
    )
    assert valid.secret_values == {}
    assert valid.public_values["ratio"] == 1.5


def _zip(entries: list[tuple[zipfile.ZipInfo | str, bytes | str]]) -> bytes:
    target = io.BytesIO()
    with zipfile.ZipFile(target, "w") as archive:
        for name, value in entries:
            archive.writestr(name, value)
    return target.getvalue()


def test_zip_import_rejects_archive_and_manifest_attack_shapes() -> None:
    for payload, message in (
        (b"", "empty"),
        (b"not-a-zip", "invalid"),
        (b"x" * (MAX_ZIP_BYTES + 1), "upload limit"),
        (_zip([("site.yml", b"\xff")]), "UTF-8"),
        (_zip([(PROJECT_MANIFEST, "not-json"), ("site.yml", "---\n[]\n")]), "manifest"),
        (
            _zip([(PROJECT_MANIFEST, "{}"), ("site.yml", "---\n[]\n")]),
            "manifest",
        ),
        (_zip([("site.yml", "---\n[]\n")]), "entrypoint must be selected"),
    ):
        with pytest.raises(PlaybookProjectInvalidError, match=message):
            import_project_zip(payload, None)

    executable = zipfile.ZipInfo("site.yml")
    executable.create_system = 3
    executable.external_attr = (stat.S_IFREG | 0o700) << 16
    with pytest.raises(PlaybookProjectInvalidError, match="executable"):
        import_project_zip(_zip([(executable, "---\n[]\n")]), "site.yml")

    duplicate = _zip([("site.yml", "one"), ("SITE.yml", "two")])
    with pytest.raises(PlaybookProjectInvalidError, match="duplicate"):
        import_project_zip(duplicate, "site.yml")

    too_many = _zip([(f"f-{index}.txt", "x") for index in range(MAX_PROJECT_FILES + 2)])
    with pytest.raises(PlaybookProjectInvalidError, match="too many"):
        import_project_zip(too_many, "site.yml")
