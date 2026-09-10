# OpsComposer

简体中文 | [English](README.md)

OpsComposer 是一个支持多管理员治理的轻量级 Ansible 运维平台。运行时只依赖 PostgreSQL 16：
业务数据、持久化任务队列、Worker Lease、Host Lock、事件回放和认证限流均存放在数据库中。
项目不依赖 Redis、Celery、Kafka、对象存储、SQLAlchemy 或独立 Nginx 服务。

前端使用 Vue 3、TypeScript、PrimeVue 4、Vue Router 和 vue-i18n；后端使用 FastAPI、
Psycopg 3 async pool、Ansible Runner、Argon2id、RFC 6238 TOTP 和 AES-256-GCM。

## Project Forge 基线

工程已升级到 Project Forge 上游 `main` 的精确提交
[`a36fb96d`](https://github.com/yernsun/project-forge/commit/a36fb96da3780b4bb8086cbbdb803e08ec163457)，
选择为 `fullstack + auth + no-evented + no-sample + zh-CN`。生成器版本为 `0.3.0`，
模板摘要为
`sha256:b500ef54df5fbbfb8daa010123aa5bda70d8d11fbb6b75de075b27a3e1e5d159`。
来源、`.project-forge.yml` 和 template baseline 均保留在仓库中。

完整产品与安全设计见 [docs/ops-composer-design.md](docs/ops-composer-design.md)。

## 许可证、资助与支持

OpsComposer 项目自有代码仅按 GNU Affero General Public License 第 3 版
（`AGPL-3.0-only`）发布，以 [LICENSE](LICENSE) 原文为准。该许可证允许企业和商业场景使用，
AGPL 本身不存在“企业使用必须付费”的附加条件；但分发或通过网络运行修改版时，可能触发源码与
通知义务，包括第 13 条要求向远程用户提供对应源码。第三方组件继续适用各自许可证；发布镜像前
应查看 [NOTICE.md](NOTICE.md)、[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) 和
[依赖合规说明](docs/legal/dependency-compliance.md)。

社区支持仅为尽力而为且没有 SLA。PayPal 资助以及未来启用的 GitHub Sponsors 都属于自愿资助，
不会购买支持、服务、AGPL 例外或商业许可证。部署、迁移和安全加固只可通过另签书面合同单独
报价。本仓库目前不提供商业软件许可证。

- [支持与赞助政策](SUPPORT.zh-CN.md)
- [通过 PayPal 资助项目的一般维护](https://www.paypal.me/yernsun) — 收款账号 `https://www.paypal.me/yernsun`；付款前请再次核对收款人
- [付费专业服务](COMMERCIAL_SERVICES.zh-CN.md)
- [安全漏洞报告](SECURITY.md)
- [参与贡献](CONTRIBUTING.zh-CN.md)
- [CLA 准备政策](CLA_POLICY.zh-CN.md)

CLA 流程目前尚未启用。在接收授权的法律主体、最终条款、隐私声明和签署记录机制正式生效前，
不得合并外部贡献者受著作权保护的内容。该门禁用于保护未来评估双许可证所需的权利链，不会改变
已经授予的 AGPL 权利。

## P2 能力

- `OWNER | ADMIN | OPERATOR | AUDITOR` 固定角色、24 小时一次性激活码、TOTP MFA、恢复码和
  10 分钟敏感操作再认证；禁止硬删除用户并保护最后一个 ACTIVE OWNER。
- Host、Group、PASSWORD/SSH_PRIVATE_KEY Credential 与不可变 Credential Revision。
- SSH Host Key 扫描、指纹确认和每次 Run 的临时 `known_hosts`。
- 主机操作区 Web Shell：新窗口完整 PTY、xterm.js、严格 Host Key 校验，且不保存终端内容。
- Ping、Command、需二次确认的 Shell，以及数据库或只读挂载来源的 Playbook。
- 创建 Run 时固化目标、Inventory、Credential 版本及 Playbook revision/哈希；重试创建带
  `sourceRunId` 的新 Run。
- PostgreSQL `FOR UPDATE SKIP LOCKED` 队列、Lease 失联恢复和按 Host 串行锁。
- 持久化 RunEvent、可按 sequence 回放的 SSE、取消、超时、输出截断和秘密脱敏。
- 单行 JSON 实时日志与 PostgreSQL 不可变业务审计；默认保留 180 天并由 Worker 每日清理。
- 数据库多文件 Playbook、不可变修订历史、Diff/恢复、受限 ZIP、参数 Schema、敏感参数和
  Check Mode 声明。
- 在线 Master Keyring 轮换与版本用量；PrimeVue 增加用户治理、个人安全、审计和轮换页面。

## 生产 Compose

生产配置只包含 `db`、一次性 `migrate`、`api` 和 `worker`。API 与 Worker 使用同一镜像，
Vue 静态资源已构建到镜像并由 FastAPI 提供。

```bash
cp .env.example .env
openssl rand -hex 32       # 填入 APP_AUTH_RATE_LIMIT_SECRET
openssl rand -base64 32    # 生成一个解码后 32 字节的 Keyring Key
# 设置数据库密码、URL、外部 HTTPS Origin 和受信代理后：
docker compose config
docker compose up -d --build
docker compose run --rm api ops-composer admin bootstrap --username admin
```

新部署推荐将版本化 JSON Keyring 写入 `volumes/keyring/keyring.json`，文件由容器 UID
`10001` 可读且权限为 `0400` 或 `0600`，并设置
`OPS_COMPOSER_MASTER_KEYRING_FILE=/run/secrets/ops-composer-keyring/keyring.json`。格式为
`{"primaryVersion": 1, "keys": {"1": "<base64-32-byte-key>"}}`。兼容周期内仍可单独使用
`OPS_COMPOSER_MASTER_KEY` 与版本，但两种方式不可同时配置。所有仍被引用的 Key 版本都必须
稳定备份；缺失时 API/Worker fail closed。`DATABASE_URL` 中密码的保留字符必须进行 URL 编码。默认只把 API 暴露到
`127.0.0.1:8080`，应由部署方提供 TLS 终止。

Bootstrap 用户为首个 OWNER。已有部署升级后会撤销旧 Session，并要求下一次密码登录完成
TOTP 注册。OWNER 创建用户后只展示一次 24 小时激活码；TOTP Seed 和 10 个恢复码也只展示
一次。用户治理、Credential 写入和 Key 轮换要求最近 10 分钟内完成密码加 MFA 再认证。唯一
OWNER 丢失全部因子时，可在服务端使用带确认短语并完整审计的 `ops-composer admin mfa-reset`。
唯一启用的 OWNER 忘记密码时，可使用 `ops-composer admin password-reset --username admin`；
该 break-glass 命令要求精确确认短语并隐藏输入新密码，成功后撤销该用户的全部 Session，且不会
重置 MFA。密码和确认内容都不会通过命令行参数传入。

TOTP 默认启用。仅在明确接受密码单因素风险时设置
`OPS_COMPOSER_TOTP_ENABLED=false`。此模式不会生成或返回 TOTP Seed，不要求验证码或恢复码，
敏感操作的 10 分钟授权仅校验密码。已有加密因子与恢复码会保留；重新启用后，未在当前 Session
完成 MFA 的会话会失效，已确认因子恢复使用。production 允许显式关闭，但启动日志、系统页面和
Doctor 会持续标记安全降级。

## 业务日志与审计

API、Worker、CLI、Migration 和 Uvicorn 均向 stdout 输出单行 JSON；Compose 使用 Docker
`local` 日志驱动并按 `20m × 10` 轮转。日志只记录动作、结果、关联 ID、耗时、安全错误码和
受控 metadata，不记录命令正文、密码、Cookie、Token、Master Key、数据库 URL、完整
Inventory 或 Ansible 原始载荷。`APP_LOG_LEVEL` 支持 `DEBUG/INFO/WARNING/ERROR`。

关键业务事件同时写入 PostgreSQL `audit_events`，默认保留 180 天，可通过
`OPS_COMPOSER_AUDIT_RETENTION_DAYS=1..3650` 调整。OWNER、ADMIN 和 AUDITOR 可在 Web 查询和
导出；本机受控 CLI 继续提供离线查询与清理：

```bash
docker compose run --rm api ops-composer audit list --jsonl
docker compose run --rm api ops-composer audit list --action RUN_FAILED --limit 50
docker compose run --rm api ops-composer audit export \
  --since 2026-09-01T00:00:00Z --until 2026-09-02T00:00:00Z \
  --output /tmp/ops-composer-audit.jsonl
docker compose run --rm api ops-composer audit purge             # dry-run
docker compose run --rm api ops-composer audit purge --execute   # 按保留期清理
```

所有 CLI 层级均同时支持 `-h` 与 `--help`。

导出文件权限固定为 `0600`，默认拒绝覆盖；需要覆盖时显式传入 `--force`。请将导出文件放在
仓库和共享目录之外。

## Playbook 来源

`OPS_COMPOSER_PLAYBOOK_SOURCE_MODE` 支持 `database`、`mount` 和默认的 `both`。数据库
Playbook 可在 Web 创建、校验、编辑、启停和软删除；支持多文件项目、不可变 revision 历史、
受限 Diff、恢复为新 revision，以及确定性 ZIP 导入导出。每个项目最多 256 个 UTF-8 文本文件、
总计 10 MiB，具有唯一 YAML entrypoint；允许安全的 roles/templates/files/vars，拒绝自定义
插件、项目内 collection、inventory、`ansible.cfg`、软链接、可执行文件、路径穿越和网络下载。
Run 始终固定创建时的 revision，项目也不会隐式读取挂载目录。

受控 JSON Schema 可生成参数表单。敏感 string 参数无默认值，独立加密，并在 PREPARING 阶段
原子消费；不会进入操作快照、响应、日志、审计或 RunEvent。消费后失败或恢复为 INTERRUPTED，
Retry 必须重新填写。只有 revision 明确声明支持时才能使用 Check Mode。

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

连接要求主机已启用、PASSWORD 或 SSH_PRIVATE_KEY Credential 可用并已人工确认 Host Key。
密码和私钥口令仅通过匿名 pipe 交给受控 helper；私钥会话使用隔离 `ssh-agent`，退出时清理
进程、Socket、`0600` 文件及 `0700` 目录。生产反向代理必须转发 WebSocket `Upgrade`，并将
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
