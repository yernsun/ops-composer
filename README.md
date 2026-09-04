# OpsComposer

[简体中文](README.zh-CN.md) | English

OpsComposer is a single-administrator Ansible operations console. Its M1 runtime depends only on
PostgreSQL 16: business data, the durable queue, worker leases, per-host locks, event replay, and
authentication rate limits all live in PostgreSQL. There is no Redis, Celery, Kafka, object store,
SQLAlchemy, or standalone Nginx service.

The UI uses Vue 3, TypeScript, PrimeVue 4, Vue Router, and vue-i18n. The backend uses FastAPI,
Psycopg 3 async pools, Ansible Runner, Argon2id, and AES-256-GCM.

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
binds to `127.0.0.1:8080` by default and expects deployment-owned TLS termination. `playbooks/` is
mounted read-only as the Playbook workspace.

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

All external JSON is camelCase; public errors use `code/message/details/requestId`. Mutating APIs
require the opaque session, an allowed Origin, and CSRF validation. Credential plaintext exists
only inside the worker during execution; runtime directories are `0700`, files are `0600`, and are
cleaned on completion. Playbook paths and the creation-time content hash are verified before use.

Read [docs/README.md](docs/README.md) for architectural rules and [AGENTS.md](AGENTS.md) before
performing a Project Forge update.
