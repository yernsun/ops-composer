from __future__ import annotations

import base64
import json
import os
import shlex
from urllib.parse import quote, quote_plus
from uuid import UUID

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class CredentialCipher:
    """AES-256-GCM envelope encryption for immutable credential revisions."""

    def __init__(self, encoded_key: str, key_version: int) -> None:
        try:
            key = base64.b64decode(encoded_key, altchars=b"-_", validate=True)
        except ValueError as error:
            raise ValueError("OPS_COMPOSER_MASTER_KEY must be valid base64") from error
        if len(key) != 32:
            raise ValueError("OPS_COMPOSER_MASTER_KEY must decode to exactly 32 bytes")
        self._aes = AESGCM(key)
        self.key_version = key_version

    @staticmethod
    def _aad(credential_id: UUID, version: int) -> bytes:
        return f"ops-composer:credential:{credential_id}:{version}".encode()

    def encrypt(self, credential_id: UUID, version: int, secret: dict[str, str]) -> bytes:
        plaintext = json.dumps(secret, sort_keys=True, separators=(",", ":")).encode()
        nonce = os.urandom(12)
        return nonce + self._aes.encrypt(nonce, plaintext, self._aad(credential_id, version))

    def decrypt(self, credential_id: UUID, version: int, envelope: bytes) -> dict[str, str]:
        if len(envelope) < 29:
            raise ValueError("credential envelope is invalid")
        nonce, ciphertext = envelope[:12], envelope[12:]
        try:
            plaintext = self._aes.decrypt(nonce, ciphertext, self._aad(credential_id, version))
        except InvalidTag as error:
            raise ValueError("credential envelope authentication failed") from error
        value = json.loads(plaintext)
        if not isinstance(value, dict) or not all(
            isinstance(key, str) and isinstance(item, str) for key, item in value.items()
        ):
            raise ValueError("credential envelope payload is invalid")
        return value

    def encrypt_check(self) -> str:
        nonce = os.urandom(12)
        value = nonce + self._aes.encrypt(nonce, b"ops-composer-master-key-check", b"key-check:v1")
        return base64.b64encode(value).decode()

    def validate_check(self, encoded_envelope: str) -> None:
        try:
            envelope = base64.b64decode(encoded_envelope, validate=True)
            plaintext = self._aes.decrypt(envelope[:12], envelope[12:], b"key-check:v1")
        except (ValueError, InvalidTag) as error:
            raise ValueError("OPS_COMPOSER_MASTER_KEY does not match the database") from error
        if plaintext != b"ops-composer-master-key-check":
            raise ValueError("OPS_COMPOSER_MASTER_KEY check value is invalid")


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
