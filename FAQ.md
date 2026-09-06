# OpsComposer FAQ

## Why does startup report pending migrations?

API and worker processes never mutate the schema. Run `ops-composer migrate status`, then execute
`ops-composer migrate up` as a one-shot deployment step. Never edit an applied migration whose
checksum is recorded; add a forward-only migration instead.

## How is the administrator created?

After migration, run `docker compose run --rm api ops-composer admin bootstrap --username admin`.
The password is accepted only through the interactive prompt. M1 permits one administrator and has
no registration endpoint.

## Why does production configuration fail validation?

Production requires a non-default PostgreSQL URL, HTTPS allowed origins, Secure cookies, a unique
rate-limit secret of at least 32 bytes, a base64-encoded 32-byte master key, and explicit trusted
proxy IPs/CIDRs. Wildcards and all-network proxy ranges are rejected.

## What if the master key no longer matches?

Restore the original `OPS_COMPOSER_MASTER_KEY`. PostgreSQL stores only AEAD ciphertext and a key
check envelope, so a lost key cannot be recovered. Startup fails closed to protect credentials.

## Why was a Playbook or Run rejected?

Check `OPS_COMPOSER_PLAYBOOK_SOURCE_MODE` first. New Runs and retries reject a reference whose
source is disabled. Database Playbooks must be enabled and pass YAML plus Ansible syntax checks;
each Run pins an immutable revision. Mounted Playbooks must be `.yml`/`.yaml` files inside the
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

Verify that the host is enabled, its PASSWORD credential is enabled, and its current SSH host key
was scanned and manually confirmed in Hosts. `host_busy` means a Run or another Web Shell owns the
host lock; `web_shell_capacity_reached` means the global limit is full. A wrong port/password or a
changed host key makes OpenSSH fail closed; OpsComposer never accepts a new fingerprint silently.

If the page opens but the WebSocket immediately closes, ensure the reverse proxy forwards Upgrade
requests, permits a connection longer than `OPS_COMPOSER_WEB_SHELL_MAX_DURATION_SECONDS`, and the
browser Origin is in `APP_ALLOWED_ORIGINS`. Refresh and window close intentionally destroy the PTY;
Reconnect always creates a new session.

## Why are integration tests skipped?

PostgreSQL tests require a dedicated `TEST_DATABASE_URL`; Compose and SSH acceptance require a
reachable Docker daemon. Without them, unit/static/frontend gates can pass, but infrastructure
acceptance must remain explicitly unverified.
