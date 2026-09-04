# Documentation index

Use this page to route an engineering change to the rule set that owns it. Start with
`../AGENTS.md` and the repository README, then read the relevant document before editing code.

| Change | Read first | Key boundary |
|---|---|---|
| API, Service, UoW, or Repository | [Service, Repository, and UoW](architecture/service-repository-uow.md) | Services own transactions; API never bypasses Services |
| Filters, sorting, joins, or indexes | [Conditional SQL](architecture/conditional-sql.md) | Values are bound; identifiers and ordering are whitelisted |
| Schema evolution | [Migrations](architecture/migrations.md) | Forward-only DAG; startup requires all migrations applied |
| Vue state, API client, or translations | [Frontend and i18n](architecture/frontend-i18n.md) | Vue Query owns server state; both locales remain complete |
| Login, sessions, cookies, CSRF, or bootstrap | [Authentication](architecture/auth.md) | One CLI-created administrator; PostgreSQL opaque sessions and rate limits |
| Run queue, Lease, Host Lock, or SSE | [OpsComposer design](ops-composer-design.md) | PostgreSQL is the only shared runtime dependency |
| Playbook Web management, revisions, or source mode | [OpsComposer design §9](ops-composer-design.md#9-playbook-设计) | Database revisions are immutable; mounted files stay read-only |
| Compose, Origin, keys, or runtime diagnosis | [FAQ](../FAQ.md) | Compare browser-visible values with resolved container configuration |

Run the governed checks from the repository root after a change:

```bash
python harness/check.py
```

For CI-equivalent tool and Compose requirements:

```bash
HARNESS_STRICT=1 HARNESS_DOCKER=1 python harness/check.py
```

The static architecture, SQL, and i18n harnesses can also be run independently while iterating:

```bash
python harness/check_architecture.py
python harness/check_sql.py
python harness/check_i18n.py
```
