# Multi-administrator authentication and governance

The first account is created as `OWNER` with `ops-composer admin bootstrap`; the CLI prompts for
the password and never accepts it on argv. Owners create additional users with a one-time,
hash-only activation code. The fixed roles are `OWNER`, `ADMIN`, `OPERATOR`, and `AUDITOR`; there
is no public registration, workspace, membership, custom-role, or resource-ACL API. Users are never
hard deleted, and a deferred database constraint plus advisory lock preserves at least one active
owner across concurrent changes.

Passwords use Argon2id. Login returns an opaque, random session cookie and a separate readable CSRF
cookie; only hashes are stored in PostgreSQL. `GET` reads use `CurrentSessionDep`. Mutating requests
use `UnsafeSessionDep`, which requires an allowed Origin, matching CSRF header/cookie values, and a
token hash bound to the session. Login requires the allowed-Origin dependency too.

Owners and administrators must enroll RFC 6238 SHA-1/6-digit/30-second TOTP; other roles may opt in.
The encrypted seed uses the Master Keyring, the accepted time step is persisted to reject replay,
and ten individually hashed recovery codes are displayed once. Changes to role, status, password,
or MFA revoke the affected sessions. User governance, credential writes, and key rotation require
password plus MFA/recovery-code reauthentication no more than ten minutes old. A guarded, audited
CLI MFA reset is the break-glass route for the sole owner.

`OPS_COMPOSER_TOTP_ENABLED` defaults to `true`. When explicitly disabled, password login and
password-only reauthentication issue sessions without `mfa_verified_at`; `reauthenticated_at`
independently proves the ten-minute sensitive-operation check. Enrollment, verification, and
recovery-code issuance fail with `totp_disabled`, and no seed is generated or returned. Stored
factors remain encrypted. When the setting is re-enabled, a session with an enrolled factor but no
session-local MFA timestamp is rejected, as is an OWNER/ADMIN still requiring enrollment.

Every API dependency and every corresponding business Service enforces the same `Permission`
enum. Frontend visibility is usability only and is never an authorization boundary. Authorization
denials are persisted best-effort without disclosing submitted identity, session, MFA, or secret
values.

Login limits are fixed PostgreSQL windows keyed by HMAC hashes of client and canonical username;
raw submitted identity values are not stored. The IP bucket is consumed first, followed by the
username/IP bucket. Rate-limit transactions commit before a `429`, so multiple API instances share
the same protection without Redis.

Production requires HTTPS origins, Secure host-only cookies, an explicit database URL, an
independent rate-limit secret and versioned AES Master Keyring, plus explicit trusted proxy
addresses. Public errors and logs must never include request bodies, passwords, session values,
CSRF values, MFA seeds/codes, activation codes, recovery codes, or credential material.
