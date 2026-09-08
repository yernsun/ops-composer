# OpsComposer FAQ

## Why does startup report pending migrations?

API and worker processes never mutate the schema. Run `ops-composer migrate status`, then execute
`ops-composer migrate up` as a one-shot deployment step. Never edit an applied migration whose
checksum is recorded; add a forward-only migration instead.

## How is the administrator created?

After migration, run `docker compose run --rm api ops-composer admin bootstrap --username admin`.
The password is accepted only through the interactive prompt. This account becomes the first
`OWNER` and must enroll TOTP at its next password login. Owners create other accounts in the Users
page; a 24-hour activation code is shown once and no email service is required.

## What if the sole OWNER forgets the password?

Run this from the server project directory:

```bash
docker compose exec api ops-composer admin password-reset --username admin
```

The command is limited to the sole active OWNER, requires an exact confirmation phrase, and reads
the new password twice from a hidden prompt. It never accepts the password on argv, revokes every
session after success, and leaves MFA unchanged.

## Can TOTP be disabled for a password-only deployment?

Yes. Set `OPS_COMPOSER_TOTP_ENABLED=false` and restart the coordinated API/Worker release. Login,
activation, password changes, and the ten-minute sensitive-operation reauthentication window then
use passwords only; no TOTP seed is generated or returned. Existing encrypted factors and recovery
codes remain in PostgreSQL. Re-enabling the setting rejects sessions created without MFA and
resumes confirmed factors. Production permits this explicit override, but startup logs and System
Doctor report `totp_policy_disabled` and a degraded security state.

If a seed has been exposed, run the audited `ops-composer admin mfa-reset --username <name>` before
re-enabling TOTP. The CLI accepts `-h` as an alias for `--help` at every command level.

## Why does production configuration fail validation?

Production requires a non-default PostgreSQL URL, HTTPS allowed origins, Secure cookies, a unique
rate-limit secret of at least 32 bytes, exactly one valid master-key configuration, and explicit
trusted proxy IPs/CIDRs. Wildcards and all-network proxy ranges are rejected. A keyring file must be
read-only, mode `0400`/`0600`, and readable by container UID `10001`.

## What if the master key no longer matches?

Restore every keyring version that System reports as still referenced. PostgreSQL stores only AEAD
ciphertext and key-check envelopes, so a lost key cannot be recovered. Startup fails closed. To
rotate, add a new version, make it primary, restart the coordinated release, and let an elevated
OWNER start the resumable database rotation job. Remove an old deployment key only after its usage
is zero.

## Why was a Playbook or Run rejected?

Check `OPS_COMPOSER_PLAYBOOK_SOURCE_MODE` first. New Runs and retries reject a reference whose
source is disabled. Database Playbooks must be enabled and pass project limits, YAML, and Ansible
syntax checks; each Run pins an immutable revision. Parameter validation and declared Check Mode
are checked again for Run and Retry. A consumed sensitive parameter is intentionally not
recoverable; retry requires new input. Mounted Playbooks must be `.yml`/`.yaml` files inside the
workspace's `playbooks/` directory. Traversal and escaping symlinks are rejected, and the content
hash must still match the value captured when the Run was created. A worker lease expiry produces
`INTERRUPTED`; modifying operations are never retried automatically.

## Why does System Doctor report a degraded Playbook mount?

In `both` mode, the database and mount sources are diagnosed independently. A missing mount is
degraded, not fatal: database Playbooks remain available. Use `database` mode to ignore the
workspace entirely, or mount the configured directory read-only. `mount` mode intentionally
disables Web-managed database Playbooks.

## Does an SSE disconnect lose events?

No. Events are committed to PostgreSQL with increasing sequence values before SSE delivery.
Refresh and reconnect resume from the highest sequence and the query API can replay history.

## Why can Web Shell not connect?

Verify that the host is enabled, its PASSWORD or SSH_PRIVATE_KEY credential is enabled, and its current SSH host key
was scanned and manually confirmed in Hosts. `host_busy` means a Run or another Web Shell owns the
host lock; `web_shell_capacity_reached` means the global limit is full. A wrong port/password or a
changed host key makes OpenSSH fail closed; OpsComposer never accepts a new fingerprint silently.

If the page opens but the WebSocket immediately closes, ensure the reverse proxy forwards Upgrade
requests, permits a connection longer than `OPS_COMPOSER_WEB_SHELL_MAX_DURATION_SECONDS`, and the
browser Origin is in `APP_ALLOWED_ORIGINS`. Refresh and window close intentionally destroy the PTY;
Reconnect always creates a new session.

## Why did an action return permission_denied or reauthentication_required?

The server checks the fixed role matrix in both its transport and Service layers. Operators cannot
manage assets or open Shell/Web Shell, and auditors are read-only. Credential changes, user
governance, and key rotation additionally require a password plus current TOTP or recovery code
when the TOTP policy is enabled. With the policy disabled they require the password only; either
elevation expires after ten minutes. Reauthenticate and retry instead of relying on a hidden or
cached frontend button.

## Why are integration tests skipped?

PostgreSQL tests require a dedicated `TEST_DATABASE_URL`; Compose and SSH acceptance require a
reachable Docker daemon. Without them, unit/static/frontend gates can pass, but infrastructure
acceptance must remain explicitly unverified.
