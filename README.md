# OpsComposer

[简体中文](README.zh-CN.md) | English

OpsComposer is a single-administrator Ansible operations console. Its M1 runtime depends only on
PostgreSQL 16: business data, the durable queue, worker leases, per-host locks, event replay, and
authentication rate limits all live in PostgreSQL. There is no Redis, Celery, Kafka, object store,
SQLAlchemy, or standalone Nginx service.

The UI uses Vue 3, TypeScript, PrimeVue 4, Vue Router, and vue-i18n. The backend uses FastAPI,
Psycopg 3 async pools, Ansible Runner, OpenSSH PTYs, Argon2id, and AES-256-GCM.

API, worker, CLI, migration, and Uvicorn output is single-line JSON. Durable business audit events
are stored in PostgreSQL, are immutable except for retention deletion, and are kept for 180 days by
default. No external logging or audit service is required.

## Project Forge provenance

The repository was upgraded from exact upstream Project Forge commit
[`a36fb96d`](https://github.com/yernsun/project-forge/commit/a36fb96da3780b4bb8086cbbdb803e08ec163457)
with `fullstack + auth + no-evented + no-sample + zh-CN`. The installed generator version is
`0.3.0`; the recorded template digest is
`sha256:b500ef54df5fbbfb8daa010123aa5bda70d8d11fbb6b75de075b27a3e1e5d159`.
Generator metadata, `.project-forge.yml`, and the template baseline are preserved.

See [docs/ops-composer-design.md](docs/ops-composer-design.md) for the complete product, data, and
security design.

## Production Compose

Production has exactly four services: `db`, one-shot `migrate`, `api`, and `worker`. API and worker
share one multi-stage image; FastAPI serves the compiled Vue application.

```bash
cp .env.example .env
openssl rand -hex 32       # APP_AUTH_RATE_LIMIT_SECRET
openssl rand -base64 32    # OPS_COMPOSER_MASTER_KEY
# Fill the database credentials/URL, HTTPS origin, and trusted proxy, then:
docker compose config
docker compose up -d --build
docker compose run --rm api ops-composer admin bootstrap --username admin
```

Back up `OPS_COMPOSER_MASTER_KEY`: losing or changing it makes existing credentials undecryptable
and startup fails closed. Percent-encode reserved password characters in `DATABASE_URL`. The API
binds to `127.0.0.1:8080` by default and expects deployment-owned TLS termination. The default
Playbook source mode is `both`: database Playbooks are Web-managed, while `playbooks/` is mounted
read-only as the optional filesystem source.

## Playbook sources

Set `OPS_COMPOSER_PLAYBOOK_SOURCE_MODE` to `database`, `mount`, or `both` (default). Database
Playbooks support Web create, validation, edit, enable/disable, and soft delete. Every successful
save creates an immutable revision, and a Run pins that exact revision. A queued or historical Run
therefore remains executable after later edits or deletion. Database Playbooks are isolated
single-file projects and cannot implicitly read roles, templates, files, or vars from the mounted
workspace.

Mounted Playbooks remain read-only. Only `playbooks/**/*.yml` and `playbooks/**/*.yaml` are
discovered; traversal, absolute paths, and escaping symlinks are rejected. In `both` mode, a missing
mount is reported as degraded by System Doctor but does not block database Playbooks. Playbook YAML
is trusted code stored as plaintext in PostgreSQL and must not contain credentials or deployment
secrets.

## Web Shell

The Hosts action can open a dedicated full-screen xterm.js Web Shell after an explicit warning.
It uses a same-origin WebSocket, OpenSSH, `sshpass`, `setsid`, and a local PTY; it does not pass through the Worker and
is not a replayable Run. Terminal input, output, and recordings are never persisted or audited.
Only session lifecycle and safe failure metadata are retained.

Web Shell and Runs share the PostgreSQL host lock, so one host permits only one execution at a
time. Defaults are 5 sessions globally, a 30-minute idle timeout, and an 8-hour hard limit,
configured by `OPS_COMPOSER_WEB_SHELL_MAX_SESSIONS`,
`OPS_COMPOSER_WEB_SHELL_IDLE_TIMEOUT_SECONDS`, and
`OPS_COMPOSER_WEB_SHELL_MAX_DURATION_SECONDS`. A host must be enabled, use an enabled PASSWORD
credential, and have a manually confirmed SSH host key. The password reaches `sshpass -d` only
through an anonymous pipe; it is never placed in arguments, environment variables, or files.

A production reverse proxy must forward WebSocket Upgrade requests and allow connections longer
than the configured maximum duration. The browser Origin must be listed in `APP_ALLOWED_ORIGINS`.

## Operational logs and audit

Set `APP_LOG_LEVEL` to `DEBUG`, `INFO`, `WARNING`, or `ERROR`. Compose uses Docker's `local` logging
driver with `20m × 10` rotation. Structured logs and audit metadata exclude command bodies,
passwords, cookies, tokens, the master key, database URLs, complete inventories, and raw Ansible
payloads. Configure retention with `OPS_COMPOSER_AUDIT_RETENTION_DAYS` (`1..3650`).

Audit access is intentionally CLI-only:

```bash
docker compose run --rm api ops-composer audit list --jsonl
docker compose run --rm api ops-composer audit list --action RUN_FAILED --limit 50
docker compose run --rm api ops-composer audit export \
  --since 2026-09-01T00:00:00Z --until 2026-09-02T00:00:00Z \
  --output /tmp/ops-composer-audit.jsonl
docker compose run --rm api ops-composer audit purge             # dry run
docker compose run --rm api ops-composer audit purge --execute   # use configured retention
```

Exports are created with mode `0600` and refuse overwrite unless `--force` is explicit. Keep them
outside the repository and shared directories.

## Development

```bash
cp .env.dev.example .env.dev
docker compose --env-file .env.dev -f docker-compose.dev.yml up --build
docker compose --env-file .env.dev -f docker-compose.dev.yml \
  exec api ops-composer admin bootstrap --username admin
```

Local backend:

```bash
cd backend
cp .env.example .env
uv sync --frozen --all-groups --extra auth
uv run ops-composer migrate up
uv run ops-composer admin bootstrap --username admin
uv run fastapi dev
# In another terminal:
uv run ops-composer worker
```

Local frontend:

```bash
cd frontend
cp .env.example .env
npm ci
npm run dev
```

## Validation

```bash
python3 harness/check.py
```

Run PostgreSQL integration tests against a dedicated database with
`TEST_DATABASE_URL=postgresql://... uv run pytest 'tests/test_*postgres.py'`. Enable Compose
validation with `HARNESS_DOCKER=1 python3 harness/check.py`.

Real OpenSSH/PTY acceptance uses the separate, disposable `docker-compose.test.yml` stack (never
the production Compose): set a generated `TEST_SSH_PASSWORD`, start its `ssh` service, then run
`TEST_SSH_PASSWORD=<same-value> TEST_SSH_PORT=22222 uv run pytest tests/test_web_shell_ssh.py`.

All external JSON is camelCase; public errors use `code/message/details/requestId`. Mutating APIs
require the opaque session, an allowed Origin, and CSRF validation. Credential plaintext exists
only inside the worker during execution; runtime directories are `0700`, files are `0600`, and are
cleaned on completion. Mounted Playbook paths/hashes and database Playbook revision hashes are
verified before use.
Web Shell tickets are single-use, expire after 30 seconds, and are bound to the creating login
session. Refreshing, disconnecting, or closing the window terminates SSH and releases the host lock.

Read [docs/README.md](docs/README.md) for architectural rules and [AGENTS.md](AGENTS.md) before
performing a Project Forge update.
