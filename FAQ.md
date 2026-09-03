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

Playbooks must be `.yml`/`.yaml` files inside the workspace's `playbooks/` directory. Traversal and
escaping symlinks are rejected, YAML and Ansible syntax checks must pass, and the content hash must
still match the value captured when the Run was created. A worker lease expiry produces
`INTERRUPTED`; modifying operations are never retried automatically.

## Does an SSE disconnect lose events?

No. Events are committed to PostgreSQL with increasing sequence values before SSE delivery.
Refresh and reconnect resume from the highest sequence and the query API can replay history.

## Why are integration tests skipped?

PostgreSQL tests require a dedicated `TEST_DATABASE_URL`; Compose and SSH acceptance require a
reachable Docker daemon. Without them, unit/static/frontend gates can pass, but infrastructure
acceptance must remain explicitly unverified.
