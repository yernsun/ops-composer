# OpsComposer

简体中文 | [English](README.md)

**从 SSH 到可治理的 Ansible 运维。**

OpsComposer 为中小运维团队提供一个自托管入口：统一执行 Ansible、处理交互式 SSH 应急操作、
安全共享访问权限，并清楚回答“谁在何时做了什么”。它将 OpenSSH 与 Ansible Runner 封装为
受治理的 Web 工作流，无需 Kubernetes 或独立消息队列。

[![发行版本 v0.1.0](https://img.shields.io/badge/release-v0.1.0-2563eb)](https://github.com/yernsun/ops-composer/releases/tag/v0.1.0)
[![CI](https://github.com/yernsun/ops-composer/actions/workflows/ci.yml/badge.svg)](https://github.com/yernsun/ops-composer/actions/workflows/ci.yml)
[![多架构容器镜像](https://img.shields.io/badge/container-linux%2Famd64%20%7C%20linux%2Farm64-0f766e?logo=docker)](CONTAINER.zh-CN.md)

[本地试用](#本地评估) ·
[Compose 生产部署](#生产-compose) ·
[查看功能](#功能特性) ·
[方案对比](#产品定位与对比) ·
[阅读文档](#文档导航)

![OpsComposer Dashboard：主机概览、PostgreSQL 架构与近期运行](docs/assets/readme/dashboard.png)

## 功能特性

### Compose 友好部署

- 生产环境只有四个服务：PostgreSQL 16、一次性 Migration、API 和 Worker。
- PostgreSQL 是唯一的基础设施依赖，同时承载业务数据、持久化队列、Lease、Host Lock、
  可回放事件、审计记录和认证限流。
- 不需要 Redis、Celery、Kafka、对象存储或独立 Nginx 服务。API 直接提供编译后的 Vue
  应用，TLS 由部署方的反向代理负责。
- 同一个发行镜像在 `linux/amd64` 和 `linux/arm64` 上运行 API、Worker、Migration 与 CLI。

### 主机操作

- 面向主机或主机组执行 Ping、Command、需显式确认的 Shell 和 Playbook。
- 在 PostgreSQL 中管理多文件 Playbook，或使用只读挂载的 Playbook 工作区。
- 通过全屏 xterm.js Web Shell 处理交互式故障。
- 支持 PASSWORD 与 SSH_PRIVATE_KEY Credential，API 响应不暴露明文。

### 团队治理

- 四种固定角色：`OWNER`、`ADMIN`、`OPERATOR` 与 `AUDITOR`。
- 通过短时效激活码邀请成员，并使用 TOTP 与一次性恢复码保护账户。
- 敏感管理操作要求近期完成密码加 MFA 再认证。
- 扫描 SSH Host Key、展示指纹，并要求首次使用前由人工确认。

### 可靠执行

- 创建 Run 时固化目标、Inventory、Credential Revision、Playbook Revision 与内容哈希。
- 通过 PostgreSQL 持久化队列、Worker Lease 和逐主机锁认领并保护任务。
- 支持取消、超时、失联 Lease 恢复，以及以新 Run 形式重试并保留来源关系。
- 持久保存有序 Run Event；浏览器重连后可通过 SSE 从断点回放。

### 安全与审计

- 使用 AES-256-GCM 加密不可变 Credential Revision，并在线轮换版本化 Keyring。
- 敏感 Playbook 参数只消费一次，不进入快照、响应、日志、审计或 Run Event。
- 输出单行结构化日志，并在 PostgreSQL 中保留不可变业务审计事件。
- 在 Web 中检索、导出审计历史，同时保留受控 CLI 供离线管理。

![OpsComposer Run Events：完成状态、目标结果与可回放执行事件](docs/assets/readme/run-events.png)

## 快速开始

### 本地评估

使用开发 Compose 栈在单机上体验 OpsComposer：

```bash
cp .env.dev.example .env.dev
docker compose --env-file .env.dev -f docker-compose.dev.yml up -d --build
docker compose --env-file .env.dev -f docker-compose.dev.yml \
  exec api ops-composer admin bootstrap --username admin
```

打开 <http://localhost:5173>。

> 此配置仅用于开发与评估。服务只绑定到回环地址，默认值也不是生产 Secret。请勿放入真实
> Credential 或生产数据。

### 生产 Compose

生产环境使用已发布的多架构镜像。请将镜像名与部署参数持久写入 `.env`，确保每次 Compose
操作使用同一份配置：

```bash
cp .env.example .env
```

编辑 `.env`，至少设置：

```dotenv
OPS_COMPOSER_IMAGE=ghcr.io/yernsun/ops-composer:v0.1.0
POSTGRES_PASSWORD=<高强度随机密码>
DATABASE_URL=postgresql://ops_composer:<经过-URL-编码的密码>@db:5432/ops_composer
APP_ALLOWED_ORIGINS=https://ops.example.com
APP_AUTH_RATE_LIMIT_SECRET=<64-位十六进制随机值>
FORWARDED_ALLOW_IPS=<受信反向代理地址>
OPS_COMPOSER_MASTER_KEYRING_FILE=/run/secrets/ops-composer-keyring/keyring.json
```

创建并备份版本化 Keyring 文件、配置由部署方管理的 HTTPS，然后校验并启动：

```bash
docker compose --env-file .env config
docker compose --env-file .env pull
docker compose --env-file .env up -d --no-build
docker compose --env-file .env exec api \
  ops-composer admin bootstrap --username admin
```

Master Key 机制只能配置一种。Keyring 创建与轮换、TLS 与 WebSocket 代理、Digest 固定、
SBOM、Provenance、备份和升级流程见[容器部署指南](CONTAINER.zh-CN.md)与
[运维 FAQ](FAQ.zh-CN.md)。

## 工作原理

```text
浏览器 -- REST / SSE --> API ------> PostgreSQL <------ Worker
浏览器 -- WebSocket --> API                              |
                           \-- OpenSSH PTY --> 主机        \-- Ansible Runner -- SSH --> 主机
```

队列状态、不可变执行快照、Worker Lease、逐主机锁、可回放事件和审计记录都在 PostgreSQL
事务边界内协同。Web Shell 刻意不设计为可回放 Run，也不保存终端内容；但它与 Run 共用逐主机
锁，避免交互操作与自动化任务同时修改同一台主机。

## 产品定位与对比

### 裸 SSH、Ansible CLI 与 OpsComposer

| 对比项 | 裸 SSH | Ansible CLI | OpsComposer |
| --- | --- | --- | --- |
| 团队访问 | 每个人分别管理账户、密钥与 Shell 历史 | 依赖团队已有的控制节点、代码仓库或 CI 规范 | 共享 Web 控制台、固定角色、用户生命周期、TOTP 与敏感操作再认证 |
| 批量与可重复执行 | 依靠人工脚本 | 擅长声明式与 Ad-hoc 自动化 | 基于 Ansible 执行，并固化 Run 快照与 Retry-as-New 历史 |
| Credential | 本机密钥文件、Agent 或复制 Secret | Inventory、Vault、Agent 或外部 Secret 工具 | 加密、版本化的 Credential Revision 与受控分配 |
| SSH Host Key | 通常由每位操作者管理 OpenSSH `known_hosts` | 取决于控制节点配置 | 指纹扫描、人工确认，并为每次 Run 或 Shell 生成严格的临时 `known_hosts` |
| 并发保护 | 无团队级协调 | 支持并行 Fork，但默认没有跨操作者的逐主机锁 | Run 与 Web Shell 共用 PostgreSQL 逐主机锁 |
| 日志与审计 | 本地 Shell 历史与服务器日志 | 控制台输出、Callback、CI 或外部工具 | 结构化服务日志、可检索导出的业务审计，以及可回放 Run Event |
| 交互式应急 | 原生强项 | 不是主要工作流 | 全屏 Web Shell；审计生命周期但不保存终端内容 |
| 部署成本 | 除 SSH 访问外几乎没有 | 维护控制节点、Inventory、依赖与协作规范 | 四个 Compose 服务；唯一基础设施依赖为 PostgreSQL |

OpsComposer 不替代 OpenSSH 或 Ansible，而是将二者团队化：补充共享访问、安全默认值、
持久化执行、并发保护与审计轨迹。

### 成熟开源方案

| 项目 | 定位 | 典型自托管部署 | 团队与执行能力 | 更适合 |
| --- | --- | --- | --- | --- |
| **OpsComposer** | 可治理的 Ansible 运维与交互式 SSH | Docker Compose：PostgreSQL、Migration、API、Worker | 固定 RBAC、Host Key 审批、持久 Run、逐主机锁、Web Shell、审计 | 小团队正在告别个人 SSH 或 Ansible CLI，但不需要完整自动化平台 |
| [AWX](https://github.com/ansible/awx) | 完整 Ansible Automation Controller | 通过 [AWX Operator](https://docs.ansible.com/projects/awx-operator/en/latest/installation/basic-install.html) 部署到 Kubernetes | Inventory、Credential、Project、Schedule、Workflow、RBAC 与完整 Controller 能力 | Ansible 是核心平台，且团队能够承担 Kubernetes 运维 |
| [Semaphore UI](https://github.com/semaphoreui/semaphore) | 轻量多工具自动化 UI | 容器、软件包、Snap 或二进制；见[安装方式](https://docs.semaphoreui.com/administration-guide/installation) | Task Template、Repository、Environment、Team、Schedule 与多种自动化工具 | 希望以紧凑 UI 管理 Ansible 及相邻工具，并需要调度 |
| [Rundeck](https://github.com/rundeck/rundeck) | 通用自助式 Runbook 与工作流 | 软件包、Docker 或 Kubernetes；见[安装指南](https://docs.rundeck.com/docs/administration/install/) | Job Workflow、Plugin、Schedule、访问策略与自助运维 | 工作流横跨多种系统，范围明显超出 Ansible |
| [OliveTin](https://github.com/OliveTin/OliveTin) | 预定义 Shell Action 的 Web 面板 | 单服务或容器加配置文件；见 [Docker Compose](https://docs.olivetin.app/install/docker_compose.html) | 易上手的 Action 面板与访问控制 | 主要需要安全的预定义命令按钮，而不是 Ansible 控制面 |

对比口径为社区开源能力与官方自托管文档；商业版本可能不同。

### 适合

- 正从个人 SSH 或 Ansible CLI 升级到共享治理的中小运维团队。
- 希望用一套 Compose 部署，并以 PostgreSQL 提供持久可靠执行的环境。
- 同时需要可重复自动化与严格受控的交互式应急入口。
- 重视 Host Key 人工确认、Credential 加密、并发保护和可查询审计记录的团队。

### 暂不适合

如果你需要高可用或横向扩展、SSO/LDAP/OIDC、定时任务、审批工作流、多租户、完整 CMDB 或
监控套件，或覆盖面广的 GitOps/应用发布系统，应选择更完整的平台。OpsComposer 会明确这些
边界，而不会把不完整实现包装成可用于生产的功能。

## 安全与运行可信度

- SSH 连接要求人工确认 Host Key，并始终启用严格校验。
- Credential 明文只进入受控执行路径；运行目录权限为 `0700`，临时文件为 `0600`，成功、
  失败和恢复后都会清理。
- Web Shell Ticket 一次性且短时有效；终端输入、输出与录像不持久化，只审计安全的生命周期
  元数据。
- Playbook 属于可信代码。挂载来源只读且限制路径；数据库项目限制文件类型，提供不可变
  Revision、确定性导入导出与固定版本执行。
- 生产部署方负责 HTTPS 终止、代理信任、数据库备份、Keyring 备份与审计保留策略。

对外开放服务前，请阅读[安全设计](docs/ops-composer-design.md)、
[容器部署指南](CONTAINER.zh-CN.md)和[安全漏洞报告政策](SECURITY.md)。

## 文档导航

- [产品、数据与安全设计](docs/ops-composer-design.md)
- [容器部署、镜像验证、SBOM 与升级](CONTAINER.zh-CN.md)
- [运维 FAQ 与恢复流程](FAQ.zh-CN.md)
- [架构与工程规范](docs/README.md)
- [安全漏洞报告](SECURITY.md)
- [支持与赞助政策](SUPPORT.zh-CN.md)
- [专业服务](COMMERCIAL_SERVICES.zh-CN.md)
- [参与贡献](CONTRIBUTING.zh-CN.md)

## 开发与贡献

开发 Compose 栈支持日常修改与热更新：

```bash
cp .env.dev.example .env.dev
docker compose --env-file .env.dev -f docker-compose.dev.yml up --build
```

提交修改前运行仓库门禁：

```bash
python3 harness/check.py
```

修改应用行为前请先阅读 [AGENTS.md](AGENTS.md)、[架构规范](docs/README.md)和
[贡献指南](CONTRIBUTING.zh-CN.md)。PostgreSQL 集成、Compose 与真实 OpenSSH 验收属于
显式启用的检查，对应测试栈中提供了运行说明。

## Project Forge 来源

本仓库从 Project Forge 上游精确提交
[`a36fb96d`](https://github.com/yernsun/project-forge/commit/a36fb96da3780b4bb8086cbbdb803e08ec163457)
升级而来，选择为 `fullstack + auth + no-evented + no-sample + zh-CN`。生成器版本为
`0.3.0`，记录的模板摘要为
`sha256:b500ef54df5fbbfb8daa010123aa5bda70d8d11fbb6b75de075b27a3e1e5d159`。
仓库保留 Generator Metadata、`.project-forge.yml` 和 Template Baseline，以便复现升级。

## 支持与资助

社区支持仅为尽力而为且没有 SLA。自愿资助不会购买支持、服务、AGPL 例外或商业许可证。
部署、迁移和安全加固服务只可通过另签书面合同单独报价；本仓库目前不提供商业软件许可证。

- [获取社区支持](SUPPORT.zh-CN.md)
- [通过 PayPal 资助项目的一般维护](https://www.paypal.me/yernsun) — 付款前请核对 PayPal.Me
  个人资料
- [洽谈付费专业服务](COMMERCIAL_SERVICES.zh-CN.md)
- [报告安全问题](SECURITY.md)
- [查看 CLA 准备政策](CLA_POLICY.zh-CN.md)

CLA 流程目前尚未启用。在接收授权的法律主体、最终条款、隐私声明与签署记录机制生效前，
不得合并外部贡献者受著作权保护的内容。

## 许可证

OpsComposer 项目自有代码仅按 GNU Affero General Public License 第 3 版
（`AGPL-3.0-only`）发布，以 [LICENSE](LICENSE) 原文为准。该许可证允许企业与商业场景使用；
分发或通过网络运行修改版时，可能触发源码与通知义务，包括第 13 条要求向远程用户提供对应
源码。

第三方组件继续适用各自许可证。发布镜像前请查看 [NOTICE.md](NOTICE.md)、
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)与
[依赖合规说明](docs/legal/dependency-compliance.md)。
