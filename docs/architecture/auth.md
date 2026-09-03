# Single-administrator authentication

M1 has exactly one administrator. There is no public registration, workspace, membership, or role
API. The first account is created with `ops-composer admin bootstrap`; the CLI prompts for the
password and never accepts it on argv.

Passwords use Argon2id. Login returns an opaque, random session cookie and a separate readable CSRF
cookie; only hashes are stored in PostgreSQL. `GET` reads use `CurrentSessionDep`. Mutating requests
use `UnsafeSessionDep`, which requires an allowed Origin, matching CSRF header/cookie values, and a
token hash bound to the session. Login requires the allowed-Origin dependency too.

Login limits are fixed PostgreSQL windows keyed by HMAC hashes of client and canonical username;
raw submitted identity values are not stored. The IP bucket is consumed first, followed by the
username/IP bucket. Rate-limit transactions commit before a `429`, so multiple API instances share
the same protection without Redis.

Production requires HTTPS origins, Secure host-only cookies, an explicit database URL, independent
rate-limit secret and AES master key, plus explicit trusted proxy addresses. Public errors and logs
must never include request bodies, passwords, session values, CSRF values, or credential material.
