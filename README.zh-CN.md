# OpsComposer

简体中文 | [English](README.md)

OpsComposer 是一个单管理员、轻量级的 Ansible 运维平台。M1 只依赖 PostgreSQL 16：
业务数据、持久化任务队列、Worker Lease、Host Lock、事件回放和认证限流均存放在数据库中。
项目不依赖 Redis、Celery、Kafka、对象存储、SQLAlchemy 或独立 Nginx 服务。

前端使用 Vue 3、TypeScript、PrimeVue 4、Vue Router 和 vue-i18n；后端使用 FastAPI、
Psycopg 3 async pool、Ansible Runner、Argon2id 和 AES-256-GCM。

## Project Forge 基线

工程已升级到 Project Forge 上游 `main` 的精确提交
[`a36fb96d`](https://github.com/yernsun/project-forge/commit/a36fb96da3780b4bb8086cbbdb803e08ec163457)，
选择为 `fullstack + auth + no-evented + no-sample + zh-CN`。生成器版本为 `0.3.0`，
模板摘要为
`sha256:b500ef54df5fbbfb8daa010123aa5bda70d8d11fbb6b75de075b27a3e1e5d159`。
来源、`.project-forge.yml` 和 template baseline 均保留在仓库中。

完整产品与安全设计见 [docs/ops-composer-design.md](docs/ops-composer-design.md)。

## M1 能力

- 单管理员登录；管理员只能通过交互式 CLI 初始化，无注册或 Workspace API。
- Host、Group、PASSWORD Credential 与不可变 Credential Revision。
- SSH Host Key 扫描、指纹确认和每次 Run 的临时 `known_hosts`。
- 主机操作区 Web Shell：新窗口完整 PTY、xterm.js、严格 Host Key 校验，且不保存终端内容。
- Ping、Command、需二次确认的 Shell，以及数据库或只读挂载来源的 Playbook。
- 创建 Run 时固化目标、Inventory、Credential 版本及 Playbook revision/哈希；重试创建带
  `sourceRunId` 的新 Run。
- PostgreSQL `FOR UPDATE SKIP LOCKED` 队列、Lease 失联恢复和按 Host 串行锁。
- 持久化 RunEvent、可按 sequence 回放的 SSE、取消、超时、输出截断和秘密脱敏。
- 单行 JSON 实时日志与 PostgreSQL 不可变业务审计；默认保留 180 天并由 Worker 每日清理。
- PrimeVue 响应式管理界面：概览、主机、分组、凭据、命令、Playbook、执行历史、详情和系统页。

## 生产 Compose

生产配置只包含 `db`、一次性 `migrate`、`api` 和 `worker`。API 与 Worker 使用同一镜像，
Vue 静态资源已构建到镜像并由 FastAPI 提供。

```bash
cp .env.example .env
openssl rand -hex 32       # 填入 APP_AUTH_RATE_LIMIT_SECRET
openssl rand -base64 32    # 填入 OPS_COMPOSER_MASTER_KEY
# 设置数据库密码、URL、外部 HTTPS Origin 和受信代理后：
docker compose config
docker compose up -d --build
docker compose run --rm api ops-composer admin bootstrap --username admin
```

`OPS_COMPOSER_MASTER_KEY` 必须稳定备份；更换或丢失该密钥会使已有凭据不可解密，应用将
fail closed。`DATABASE_URL` 中密码的保留字符必须进行 URL 编码。默认只把 API 暴露到
`127.0.0.1:8080`，应由部署方提供 TLS 终止。

## 业务日志与审计

API、Worker、CLI、Migration 和 Uvicorn 均向 stdout 输出单行 JSON；Compose 使用 Docker
`local` 日志驱动并按 `20m × 10` 轮转。日志只记录动作、结果、关联 ID、耗时、安全错误码和
受控 metadata，不记录命令正文、密码、Cookie、Token、Master Key、数据库 URL、完整
Inventory 或 Ansible 原始载荷。`APP_LOG_LEVEL` 支持 `DEBUG/INFO/WARNING/ERROR`。

关键业务事件同时写入 PostgreSQL `audit_events`，默认保留 180 天，可通过
`OPS_COMPOSER_AUDIT_RETENTION_DAYS=1..3650` 调整。审计仅由本机受控 CLI 访问：

```bash
docker compose run --rm api ops-composer audit list --jsonl
docker compose run --rm api ops-composer audit list --action RUN_FAILED --limit 50
docker compose run --rm api ops-composer audit export \
  --since 2026-09-01T00:00:00Z --until 2026-09-02T00:00:00Z \
  --output /tmp/ops-composer-audit.jsonl
docker compose run --rm api ops-composer audit purge             # dry-run
docker compose run --rm api ops-composer audit purge --execute   # 按保留期清理
```

导出文件权限固定为 `0600`，默认拒绝覆盖；需要覆盖时显式传入 `--force`。请将导出文件放在
仓库和共享目录之外。

## Playbook 来源

`OPS_COMPOSER_PLAYBOOK_SOURCE_MODE` 支持 `database`、`mount` 和默认的 `both`。数据库
Playbook 可在 Web 创建、校验、编辑、启停和软删除；每次成功保存产生不可变 revision，Run
始终固定创建时的 revision，因此排队或历史 Run 不受后续编辑、停用和删除影响。数据库
Playbook 是隔离的单 YAML 项目，不能隐式读取挂载目录中的 roles、templates、files 或 vars。

挂载来源始终只读，仅发现 `playbooks/**/*.yml(yaml)`，拒绝绝对路径、`..` 和越界软链接。
`both` 模式缺少挂载目录时，System Doctor 标记为降级，但数据库来源仍可使用。同名 Playbook
按“来源 + 引用”并存，不会覆盖。Playbook YAML 属于可信代码，以明文保存在 PostgreSQL，
不得写入 Credential 或部署 Secret。不得挂载 Docker Socket。

## Web Shell

在主机列表确认风险后可打开独立全屏 Web Shell。它使用同源 WebSocket、OpenSSH、`sshpass`、`setsid` 和本地 PTY，
不会经过 Worker，也不是可回放 Run。终端输入、输出和录像均不写入数据库、日志或审计；仅记录
会话申请、开始、结束、超时和安全错误等生命周期事件。

Web Shell 与 Run 共用数据库 Host Lock，同一主机同时只允许一个执行。会话默认全局最多 5 个、
空闲 30 分钟关闭、最长 8 小时，可通过以下变量调整：

```text
OPS_COMPOSER_WEB_SHELL_MAX_SESSIONS=5
OPS_COMPOSER_WEB_SHELL_IDLE_TIMEOUT_SECONDS=1800
OPS_COMPOSER_WEB_SHELL_MAX_DURATION_SECONDS=28800
```

连接要求主机已启用、PASSWORD Credential 可用并已人工确认 Host Key。密码仅通过匿名 pipe 交给
`sshpass -d`，不会进入参数、环境变量或文件。生产反向代理必须转发 WebSocket `Upgrade`，并将
连接超时设置为大于 Web Shell 最长会话时间；浏览器 Origin 必须出现在 `APP_ALLOWED_ORIGINS`。

## 开发环境

完整开发栈需要 Docker Engine、Compose v2、Python 3.11+、uv，以及 Node 22/24 LTS。

```bash
cp .env.dev.example .env.dev
docker compose --env-file .env.dev -f docker-compose.dev.yml up --build
docker compose --env-file .env.dev -f docker-compose.dev.yml \
  exec api ops-composer admin bootstrap --username admin
```

- PrimeVue 前端：<http://localhost:5173>
- API 文档：<http://localhost:8000/docs>
- 就绪检查：<http://localhost:8000/health/ready>

直接运行后端：

```bash
cd backend
cp .env.example .env
uv sync --frozen --all-groups --extra auth
uv run ops-composer migrate up
uv run ops-composer admin bootstrap --username admin
uv run fastapi dev
# 另一个终端
uv run ops-composer worker
```

直接运行前端：

```bash
cd frontend
cp .env.example .env
npm ci
npm run dev
```

## 验证

```bash
python3 harness/check.py
```

独立门禁：

```bash
cd backend
uv run --frozen --no-sync ruff check .
uv run --frozen --no-sync mypy src/ops_composer
uv run --frozen --no-sync pytest

cd ../frontend
npm run lint
npm run typecheck
npm run test
npm run build
```

真实 PostgreSQL 集成测试要求专用数据库：

```bash
TEST_DATABASE_URL=postgresql://... uv run pytest 'tests/test_*postgres.py'
```

Web Shell 的真实 OpenSSH/PTY 验收使用独立测试 Compose，不会加入生产栈：

```bash
TEST_SSH_PASSWORD="$(openssl rand -hex 16)" docker compose -f docker-compose.test.yml up -d --build
TEST_SSH_PASSWORD=<同一临时值> TEST_SSH_PORT=22222 uv run pytest tests/test_web_shell_ssh.py
docker compose -f docker-compose.test.yml down
```

启用 Docker Compose 配置门禁：

```bash
HARNESS_DOCKER=1 python3 harness/check.py
```

当前 OpenAPI 合约保存在 `frontend/scripts/openapi/contracts/auth.json`；有意修改 API 后运行
`harness/export_openapi.py` 和 `npm run api:generate`，再执行 `npm run api:check`。

## 安全约束

- 外部 JSON 统一使用 camelCase；错误为 `code/message/details/requestId`。
- 除登录外，写接口均要求 Opaque Session、允许的 Origin 和双提交 CSRF token。
- Credential 明文只在 Worker 内存和权限为 `0600` 的执行期文件中短暂存在；Run 目录为
  `0700`，成功、失败和重启恢复均清理。
- Host/Group variables 禁止覆盖 `ansible_password` 等敏感或控制性字段。
- 挂载 Playbook 验证 Workspace 边界和创建时哈希；数据库 Playbook 执行不可变固定 revision。
- Web Shell 使用一次性、登录 Session 绑定的 30 秒 Ticket；刷新、断线或关窗会终止 SSH 并释放 Host Lock。

架构约束导航见 [docs/README.md](docs/README.md)，Project Forge 更新前请先阅读
[AGENTS.md](AGENTS.md)。
