from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from dataclasses import dataclass

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from argon2.low_level import Type

# Explicit Argon2id policy. Tune it against the production hardware before raising costs.
PASSWORD_HASHER = PasswordHasher(
    time_cost=2,
    memory_cost=19 * 1024,
    parallelism=1,
    hash_len=32,
    salt_len=16,
    type=Type.ID,
)
DUMMY_PASSWORD_HASH = PASSWORD_HASHER.hash("project-forge-dummy-password")


@dataclass(frozen=True, slots=True)
class PasswordVerification:
    valid: bool
    needs_rehash: bool


def generate_token() -> str:
    return secrets.token_urlsafe(48)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def token_matches(token: str, expected_hash: str) -> bool:
    return secrets.compare_digest(hash_token(token), expected_hash)


def hash_password(password: str) -> str:
    return PASSWORD_HASHER.hash(password)


def verify_password(password_hash: str | None, password: str) -> PasswordVerification:
    """Verify real and missing users with the same Argon2 code path."""

    candidate_hash = password_hash or DUMMY_PASSWORD_HASH
    try:
        PASSWORD_HASHER.verify(candidate_hash, password)
    except (InvalidHashError, VerificationError, VerifyMismatchError):
        return PasswordVerification(valid=False, needs_rehash=False)
    if password_hash is None:
        return PasswordVerification(valid=False, needs_rehash=False)
    return PasswordVerification(
        valid=True,
        needs_rehash=PASSWORD_HASHER.check_needs_rehash(password_hash),
    )


def hmac_subject(secret: str, scope: str, subject: str) -> str:
    """Pseudonymize rate-limit subjects before persistence."""

    payload = f"{scope}\0{subject}".encode()
    return hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()


def generate_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _decode_totp_secret(secret: str) -> bytes:
    padding = "=" * ((8 - len(secret) % 8) % 8)
    try:
        return base64.b32decode(secret.upper() + padding, casefold=True)
    except (ValueError, TypeError) as error:
        raise ValueError("TOTP secret is invalid") from error


def totp_code(secret: str, step: int) -> str:
    digest = hmac.new(_decode_totp_secret(secret), struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{value % 1_000_000:06d}"


def match_totp_step(
    secret: str,
    code: str,
    *,
    now: float | None = None,
    last_accepted_step: int | None = None,
) -> int | None:
    if len(code) != 6 or not code.isascii() or not code.isdigit():
        return None
    current = int((time.time() if now is None else now) // 30)
    for step in (current, current - 1, current + 1):
        if step < 0 or (last_accepted_step is not None and step <= last_accepted_step):
            continue
        if secrets.compare_digest(totp_code(secret, step), code):
            return step
    return None


def generate_recovery_codes() -> tuple[str, ...]:
    values: list[str] = []
    for _ in range(10):
        raw = base64.b32encode(secrets.token_bytes(16)).decode("ascii").rstrip("=")
        values.append("-".join(raw[index : index + 5] for index in range(0, len(raw), 5)))
    return tuple(values)


def normalize_recovery_code(code: str) -> str:
    return "".join(character for character in code.upper() if character.isalnum())


def hash_recovery_code(code: str) -> str:
    return hashlib.sha256(normalize_recovery_code(code).encode("ascii")).hexdigest()
