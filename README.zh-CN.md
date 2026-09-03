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
- Ping、Command、需二次确认的 Shell，以及受 Workspace 边界约束的 Playbook。
- 创建 Run 时固化目标、Inventory、Credential 版本和 Playbook 哈希；重试创建带
  `sourceRunId` 的新 Run。
- PostgreSQL `FOR UPDATE SKIP LOCKED` 队列、Lease 失联恢复和按 Host 串行锁。
- 持久化 RunEvent、可按 sequence 回放的 SSE、取消、超时、输出截断和秘密脱敏。
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

Playbook 默认从根目录 `playbooks/` 只读挂载。不得挂载 Docker Socket。

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
- Playbook 仅允许 Workspace 下的 YAML 文件，执行前验证路径、语法和创建时内容哈希。

架构约束导航见 [docs/README.md](docs/README.md)，Project Forge 更新前请先阅读
[AGENTS.md](AGENTS.md)。
