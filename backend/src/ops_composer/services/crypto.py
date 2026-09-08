from __future__ import annotations

import base64
import json
import os
import shlex
import stat
from collections.abc import Mapping
from pathlib import Path
from urllib.parse import quote, quote_plus
from uuid import UUID

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _decode_key(encoded_key: str, *, label: str) -> bytes:
    try:
        key = base64.b64decode(encoded_key, altchars=b"-_", validate=True)
    except (ValueError, TypeError) as error:
        raise ValueError(f"{label} must be valid base64") from error
    if len(key) != 32:
        raise ValueError(f"{label} must decode to exactly 32 bytes")
    return key


class MasterKeyring:
    """Versioned AES-256-GCM keys loaded only from deployment configuration."""

    def __init__(self, keys: Mapping[int, str | bytes], primary_version: int) -> None:
        if primary_version < 1:
            raise ValueError("primary key version must be positive")
        decoded: dict[int, bytes] = {}
        for version, value in keys.items():
            if version < 1:
                raise ValueError("key versions must be positive")
            if isinstance(value, bytes):
                if len(value) != 32:
                    raise ValueError(f"master key version {version} must be exactly 32 bytes")
                decoded[version] = value
            else:
                decoded[version] = _decode_key(value, label=f"master key version {version}")
        if primary_version not in decoded:
            raise ValueError("primary key version is missing from the keyring")
        self._keys = decoded
        self.primary_version = primary_version

    @classmethod
    def from_file(cls, path: Path) -> MasterKeyring:
        resolved = path.expanduser().resolve(strict=True)
        mode = stat.S_IMODE(resolved.stat().st_mode)
        if not resolved.is_file() or mode not in {0o400, 0o600}:
            raise ValueError("master keyring file must be a regular file with mode 0400 or 0600")
        try:
            raw = json.loads(resolved.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise ValueError("master keyring file is not valid UTF-8 JSON") from error
        if not isinstance(raw, dict) or set(raw) != {"primaryVersion", "keys"}:
            raise ValueError("master keyring must contain only primaryVersion and keys")
        primary = raw["primaryVersion"]
        raw_keys = raw["keys"]
        if (
            not isinstance(primary, int)
            or isinstance(primary, bool)
            or not isinstance(raw_keys, dict)
        ):
            raise ValueError("master keyring fields have invalid types")
        keys: dict[int, str] = {}
        for raw_version, value in raw_keys.items():
            try:
                version = int(raw_version)
            except (TypeError, ValueError) as error:
                raise ValueError("master keyring versions must be positive integers") from error
            if str(version) != str(raw_version) or not isinstance(value, str):
                raise ValueError("master keyring key entries are invalid")
            keys[version] = value
        return cls(keys, primary)

    @property
    def versions(self) -> tuple[int, ...]:
        return tuple(sorted(self._keys))

    def has_version(self, version: int) -> bool:
        return version in self._keys

    @staticmethod
    def _aad(purpose: str, subject: str) -> bytes:
        if not purpose or not subject or "\0" in purpose or "\0" in subject:
            raise ValueError("encryption context is invalid")
        return f"ops-composer:{purpose}:{subject}:v1".encode()

    def encrypt_bytes(
        self,
        purpose: str,
        subject: str,
        plaintext: bytes,
        *,
        key_version: int | None = None,
    ) -> tuple[bytes, int]:
        version = key_version or self.primary_version
        return self.encrypt_with_aad(plaintext, self._aad(purpose, subject), key_version=version)

    def encrypt_with_aad(
        self, plaintext: bytes, aad: bytes, *, key_version: int | None = None
    ) -> tuple[bytes, int]:
        version = key_version or self.primary_version
        key = self._keys.get(version)
        if key is None:
            raise ValueError(f"master key version {version} is unavailable")
        nonce = os.urandom(12)
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
        return nonce + ciphertext, version

    def decrypt_bytes(
        self,
        purpose: str,
        subject: str,
        envelope: bytes,
        key_version: int,
    ) -> bytes:
        return self.decrypt_with_aad(envelope, self._aad(purpose, subject), key_version)

    def decrypt_with_aad(self, envelope: bytes, aad: bytes, key_version: int) -> bytes:
        if len(envelope) < 29:
            raise ValueError("encrypted envelope is invalid")
        key = self._keys.get(key_version)
        if key is None:
            raise ValueError(f"master key version {key_version} is unavailable")
        try:
            return AESGCM(key).decrypt(envelope[:12], envelope[12:], aad)
        except InvalidTag as error:
            raise ValueError("encrypted envelope authentication failed") from error

    def encrypt_json(
        self,
        purpose: str,
        subject: str,
        value: Mapping[str, object],
        *,
        key_version: int | None = None,
    ) -> tuple[bytes, int]:
        encoded = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
        return self.encrypt_bytes(purpose, subject, encoded, key_version=key_version)

    def decrypt_json(
        self,
        purpose: str,
        subject: str,
        envelope: bytes,
        key_version: int,
    ) -> dict[str, object]:
        try:
            value = json.loads(
                self.decrypt_bytes(purpose, subject, envelope, key_version).decode("utf-8")
            )
        except (UnicodeError, json.JSONDecodeError) as error:
            raise ValueError("encrypted JSON payload is invalid") from error
        if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
            raise ValueError("encrypted JSON payload must be an object")
        return value

    def encrypt_check(self, key_version: int) -> bytes:
        envelope, _ = self.encrypt_bytes(
            "key-check", str(key_version), b"ops-composer-master-key-check", key_version=key_version
        )
        return envelope

    def validate_check(self, key_version: int, envelope: bytes) -> None:
        try:
            plaintext = self.decrypt_bytes("key-check", str(key_version), envelope, key_version)
        except ValueError as error:
            raise ValueError("master key does not match the registered key version") from error
        if plaintext != b"ops-composer-master-key-check":
            raise ValueError("master key does not match the registered key version")

    def validate_legacy_check(self, key_version: int, envelope: bytes) -> None:
        plaintext = self.decrypt_with_aad(envelope, b"key-check:v1", key_version)
        if plaintext != b"ops-composer-master-key-check":
            raise ValueError("master key check value is invalid")


def build_master_keyring(
    *, keyring_file: Path | None, fallback_key: str, fallback_version: int
) -> MasterKeyring:
    if keyring_file is not None:
        return MasterKeyring.from_file(keyring_file)
    return MasterKeyring({fallback_version: fallback_key}, fallback_version)


class CredentialCipher:
    """Compatibility facade for credential envelopes backed by a MasterKeyring."""

    def __init__(self, encoded_key: str | MasterKeyring, key_version: int | None = None) -> None:
        if isinstance(encoded_key, MasterKeyring):
            self.keyring = encoded_key
        else:
            if key_version is None:
                raise ValueError("key_version is required for a single master key")
            self.keyring = MasterKeyring({key_version: encoded_key}, key_version)

    @property
    def key_version(self) -> int:
        return self.keyring.primary_version

    @staticmethod
    def _subject(credential_id: UUID, version: int) -> str:
        return f"{credential_id}:{version}"

    def encrypt(self, credential_id: UUID, version: int, secret: dict[str, str]) -> bytes:
        plaintext = json.dumps(secret, sort_keys=True, separators=(",", ":")).encode()
        envelope, _ = self.keyring.encrypt_with_aad(
            plaintext,
            f"ops-composer:credential:{credential_id}:{version}".encode(),
        )
        return envelope

    def decrypt(
        self,
        credential_id: UUID,
        version: int,
        envelope: bytes,
        key_version: int | None = None,
    ) -> dict[str, str]:
        try:
            value = json.loads(
                self.keyring.decrypt_with_aad(
                    envelope,
                    f"ops-composer:credential:{credential_id}:{version}".encode(),
                    key_version or self.key_version,
                )
            )
        except json.JSONDecodeError as error:
            raise ValueError("credential envelope payload is invalid") from error
        if not all(isinstance(item, str) for item in value.values()):
            raise ValueError("credential envelope payload is invalid")
        return {key: str(item) for key, item in value.items()}

    def encrypt_check(self) -> str:
        return base64.b64encode(self.keyring.encrypt_check(self.key_version)).decode()

    def validate_check(self, encoded_envelope: str) -> None:
        try:
            envelope = base64.b64decode(encoded_envelope, validate=True)
        except ValueError as error:
            raise ValueError("master key check value is invalid") from error
        try:
            self.keyring.validate_check(self.key_version, envelope)
        except ValueError:
            try:
                self.keyring.validate_legacy_check(self.key_version, envelope)
            except ValueError as error:
                raise ValueError("master key does not match the registered value") from error


def redact_secrets(value: str, secrets: tuple[str, ...]) -> str:
    redacted = value
    for secret in sorted((item for item in secrets if item), key=len, reverse=True):
        variants = {
            secret,
            shlex.quote(secret),
            quote(secret, safe=""),
            quote_plus(secret, safe=""),
            json.dumps(secret)[1:-1],
        }
        for variant in sorted((item for item in variants if item), key=len, reverse=True):
            redacted = redacted.replace(variant, "[REDACTED]")
    return redacted
