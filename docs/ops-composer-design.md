# OpsComposer 详细设计文档

> 轻量、Ansible-native 的主机操作与配置编排控制台

- **项目名称**：OpsComposer
- **仓库名称**：`ops-composer`
- **Python 包名**：`ops_composer`
- **CLI 命令**：`ops-composer`
- **文档状态**：Implemented / M1 + database Playbook revisions + Web Shell PTY
- **目标部署形态**：本地 Docker 部署，远程管理物理机或虚拟机集群
- **执行内核**：Ansible Core + Ansible Runner

---

## 目录

- [1. 产品定位](#1-产品定位)
- [2. 设计目标与非目标](#2-设计目标与非目标)
- [3. 核心产品模型](#3-核心产品模型)
- [4. 总体架构](#4-总体架构)
- [5. 核心设计原则](#5-核心设计原则)
- [6. 核心领域对象](#6-核心领域对象)
- [7. Inventory 设计](#7-inventory-设计)
- [8. 快速命令设计](#8-快速命令设计)
- [9. Playbook 设计](#9-playbook-设计)
- [10. Run 执行模型](#10-run-执行模型)
- [11. 每台主机的执行结果](#11-每台主机的执行结果)
- [12. 实时日志与事件流](#12-实时日志与事件流)
- [13. 数据库设计](#13-数据库设计)
- [14. API 设计](#14-api-设计)
- [15. CLI 设计](#15-cli-设计)
- [16. 代码架构](#16-代码架构)
- [17. 技术栈](#17-技术栈)
- [18. 页面与交互设计](#18-页面与交互设计)
- [19. 安全设计](#19-安全设计)
- [20. 日志规范](#20-日志规范)
- [21. Docker 部署设计](#21-docker-部署设计)
- [22. 启动与 Readiness Gate](#22-启动与-readiness-gate)
- [23. 开发阶段划分](#23-开发阶段划分)
- [24. 测试与验收场景](#24-测试与验收场景)
- [25. 关键不变量](#25-关键不变量)
- [26. 最终冻结边界](#26-最终冻结边界)

---

## 1. 产品定位

OpsComposer 是一个：

> **本地优先、无 Agent、基于 Ansible 的轻量主机操作控制面。**

它不是另一个 AWX，也不是完整的监控平台或 CMDB。其核心目标是用尽可能少的平台对象，把以下元素组合成可靠、可追踪的运维执行：

```text
Target
  +
Credential
  +
Command / Playbook
  +
Execution Policy
  ↓
Operation Run
  ↓
Ansible Runner
  ↓
Physical Hosts / Virtual Machines
```

产品核心能力聚焦于六个模块：

```text
Hosts
Groups
Credentials
Quick Commands
Playbooks
Runs
```

典型使用流程：

```text
添加服务器
    ↓
按组组织服务器
    ↓
绑定 SSH 凭据
    ↓
选择一台或一组服务器
    ↓
执行简单命令或 Playbook
    ↓
查看每台服务器执行结果
    ↓
保留可审计的执行记录
```

### 1.1 命名逻辑

OpsComposer 与 TradeComposer 保持一致的命名风格：

```text
TradeComposer
= Trade Intent + Strategy + Execution

OpsComposer
= Target + Credential + Operation + Execution
```

`OpsComposer` 不把产品限制在某种集群或某类节点，也不暗示其承担持续监控、容器编排或资产发现职责。

---

## 2. 设计目标与非目标

### 2.1 M1 设计目标

M1 必须完成：

- 主机、分组、凭据管理；
- 支持密码 SSH；
- 为每次执行生成受控的运行时 Inventory；
- 支持 Ansible Ping；
- 支持最简单的 SSH 命令封装；
- 支持标准 Ansible Playbook 执行；
- 支持目标解析、执行快照、持久化队列；
- 支持每台主机的结果状态；
- 支持实时日志、取消、超时和执行历史；
- 支持独立窗口、连接绑定且不留存内容的 Web Shell PTY；
- 支持 Docker 本地部署；
- 所有敏感凭据加密保存，运行结束后清理运行时秘密。

### 2.2 第一阶段明确不做

```text
定时健康检查
CPU / 内存 / 磁盘持续监控
Prometheus 指标
告警中心
应用发布平台
Docker Stack 管理 UI
Docker Swarm 实时控制面
GitOps
复杂审批流
多租户
企业级 RBAC
完整 CMDB
Ansible Vault 管理平台
```

### 2.3 外部系统职责边界

```text
OpsComposer
负责主机、凭据、目标、命令、配置和 Playbook 执行

Dokploy / Portainer
负责 Docker Swarm 工作负载部署和运行时管理

Forgejo / GitLab
负责代码、Playbook 仓库、Review 和 CI
```

---

## 3. 核心产品模型

OpsComposer 的核心不是“直接发起 SSH”，而是将一次用户操作转换成可持久化、可审计、可恢复查询的 Run。

```text
Host + Group + Credential
            │
            ▼
      Target Resolution
            │
            ▼
      Operation Snapshot
            │
            ▼
        Durable Run
            │
            ▼
      Runtime Inventory
            │
            ▼
       Ansible Runner
            │
            ▼
    Command / Playbook
            │
            ▼
 RunTarget + RunEvent + Result
```

第一版只保留三个执行入口：

```text
1. Test Connection
   → ansible.builtin.ping

2. Quick Command
   → ansible.builtin.command
   → ansible.builtin.shell（显式高级模式）

3. Run Playbook
   → ansible-runner
```

---

## 4. 总体架构

```text
┌─────────────────────────────────────────────────────────┐
│                       Web UI                            │
│                                                         │
│ Hosts │ Groups │ Credentials │ Commands │ Playbooks │ Runs
└──────────────────────────┬──────────────────────────────┘
                           │ REST + SSE + WebSocket（仅 Web Shell）
                           ▼
┌─────────────────────────────────────────────────────────┐
│                    OpsComposer API                      │
│                                                         │
│ Host Service                                            │
│ Group Service                                           │
│ Credential Service                                      │
│ Inventory Renderer                                      │
│ Playbook Catalog                                        │
│ Run Service                                             │
│ Web Shell Manager + OpenSSH PTY                         │
└──────────────────────────┬──────────────────────────────┘
                           │
                           ▼
                       PostgreSQL 16
                           │
                    Durable Run Queue
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│                  OpsComposer Worker                     │
│                                                         │
│ Run Claim                                               │
│ Runtime Inventory                                       │
│ Credential Injection                                    │
│ Ansible Runner Adapter                                  │
│ Event Persistence                                       │
│ Cancellation / Timeout                                  │
└──────────────────────────┬──────────────────────────────┘
                           │
                      Ansible Runner
                           │ SSH
              ┌────────────┼─────────────┐
              ▼            ▼             ▼
           manager01     worker01      worker02
```

### 4.1 进程模型

第一版采用两个进程：

```text
ops-composer-api
ops-composer-worker
```

两者只通过 PostgreSQL 共享持久化状态。数据库 Playbook 也存入 PostgreSQL；可选的
Workspace 是只读输入，运行目录是 Worker 与 API Web Shell 的临时目录：

```text
/tmp/ops-composer/
└── runtime/

/workspace
├── playbooks/
├── roles/
├── collections/
├── group_vars/
├── ansible.cfg
└── ops-composer.yml
```

### 4.2 强制边界

- API 负责请求、查询、Run 创建及连接绑定的 Web Shell PTY；
- Worker 是唯一可以启动 Ansible 的组件；
- API **不得**同步执行 Ansible；Web Shell 仅启动受控 OpenSSH，不调用 Ansible；
- 浏览器断开或刷新不得中止 Run，但必须中止 Web Shell；
- API 重启不得丢失已经持久化的 Run；
- 多次提交必须由幂等键控制，不能因网络重试重复创建操作。

---

## 5. 核心设计原则

### 5.1 数据库管理业务对象，Ansible 管执行

数据库是以下对象的真相源：

```text
Host
Group
Credential
Run
RunTarget
RunEvent
```

Ansible Inventory 是数据库对象生成的运行时投影，不是用户必须手工维护的主数据。

```text
Database Hosts
      ↓
Inventory Renderer
      ↓
Runtime inventory.yml
      ↓
Ansible
```

### 5.2 每次执行必须快照化

Run 创建时必须固定：

```text
目标主机集合
主机地址和 SSH 端口
主机分组关系
Credential ID 和版本
执行命令
命令模式
Playbook 路径
Extra Vars
Tags / Skip Tags
Become 配置
Timeout
Forks
Workspace Revision
```

Run 创建后，即使用户修改 Host、Group 或 Credential，已经创建的 Run 仍按快照语义执行。

### 5.3 重试必须创建新 Run

禁止把失败或中断的 Run 重新改回 `QUEUED`。

```text
Run A
FAILED

    ↓ Retry

Run B
sourceRunId = Run A
QUEUED
```

### 5.4 禁止透传任意 Ansible CLI 参数

用户不得直接提交：

```text
--inventory
--private-key
--connection
--module-path
--extra-vars @file
--vault-password-file
--cmdline
```

API 只接受受控、类型化字段，后端负责转换为 Ansible Runner 参数。

### 5.5 Quick Command 不是终端

支持：

```bash
uname -a
docker ps
systemctl status docker
df -h
apt-get update
```

不支持：

```bash
vim
top
htop
less
ssh another-host
docker login
交互式安装程序
等待 stdin 的 sudo
```

所有执行必须：

```text
非交互
stdin 关闭
不分配 PTY
有最大超时
结果可持久化
```

### 5.6 不自动重试修改性操作

Worker 中断后，系统无法可靠判断远程命令是否已完成。任何中断的修改性操作必须标记为 `INTERRUPTED`，由用户显式决定是否创建新的 Run。

### 5.7 Web Shell 是连接绑定的临时执行

Web Shell 提供完整交互 PTY，但不是 Run，也不进入 Worker、RunTarget、RunEvent 或 SSE。API
进程持有浏览器 WebSocket 与本地 OpenSSH PTY；断线、刷新、关窗、登录失效、数据库失联或
超时会立即终止 SSH 进程组并释放 Host Lock。重连总是创建新会话，不恢复旧 PTY。

Web Shell 与自动化 Run 共用 `host_execution_locks`。终端字节只允许存在于当前 PTY、
WebSocket 和浏览器内存；数据库与审计只保存会话生命周期及安全元数据。

---

## 6. 核心领域对象

## 6.1 Host

Host 表示一台可被 Ansible 管理的服务器。

```text
Host
├── id
├── name
├── address
├── sshPort
├── credentialId
├── enabled
├── pythonInterpreter
├── description
├── variables
├── version
├── createdAt
└── updatedAt
```

### 字段约束

```text
name
  唯一
  作为 Ansible Inventory Alias
  允许 A-Z a-z 0-9 . _ -

address
  IPv4 / IPv6 / FQDN

sshPort
  1–65535
  默认 22

pythonInterpreter
  默认 /usr/bin/python3
```

示例：

```json
{
  "name": "worker01",
  "address": "192.168.1.21",
  "sshPort": 22,
  "credentialId": "credential-uuid",
  "pythonInterpreter": "/usr/bin/python3",
  "enabled": true,
  "variables": {
    "environment": "production",
    "node_role": "swarm_worker"
  }
}
```

### Host Variables 黑名单

用户不得通过 `variables` 设置以下字段：

```text
ansible_password
ansible_become_password
ansible_private_key_file
ansible_ssh_common_args
ansible_connection
ansible_host
ansible_port
ansible_user
```

这些字段由 OpsComposer 统一控制。

---

## 6.2 Host Group

```text
Group
├── id
├── name
├── description
├── createdAt
└── updatedAt
```

关系：

```text
Host * ←→ * Group
```

典型分组：

```text
production
swarm
swarm_managers
swarm_workers
gpu_nodes
database_nodes
```

M1 只支持平面分组，不支持嵌套 Group。

原因：M1 的目标选择语义是：

```text
选择 Group
→ 服务端解析成具体 Host ID
→ 创建确定的目标快照
```

而不是直接开放完整 Ansible Pattern 表达式。

---

## 6.3 Credential

```text
Credential
├── id
├── name
├── type
├── username
├── publicConfig
├── encryptedSecret
├── encryptionKeyVersion
├── enabled
├── version
├── createdAt
└── updatedAt
```

M1 支持：

```text
PASSWORD
```

第一版只实现密码 SSH，不预留 SSH Key Adapter、联合类型或兼容分支；如未来需要
SSH Key，将通过新的 forward-only migration 和显式 API 版本扩展。

### PASSWORD

公开配置：

```json
{
  "username": "ecs-user",
  "becomeEnabled": true,
  "becomeMethod": "sudo",
  "becomeUser": "root"
}
```

加密 Secret：

```json
{
  "password": "ssh-password",
  "becomePassword": "sudo-password"
}
```

### 凭据加密

数据库只保存密文：

```text
AES-256-GCM 或等价 AEAD 密文
```

应用主密钥由环境变量或 Docker Secret 注入：

```text
OPS_COMPOSER_MASTER_KEY
```

Master Key 丢失或无法解密检查值时必须 fail closed，禁止自动生成新 key 后继续运行。

---

## 6.4 Run

Run 是一次已持久化的操作意图和执行记录。

```text
Run
├── id
├── sourceRunId
├── kind
├── status
├── targetSpec
├── resolvedTargets
├── operationSpec
├── inventorySnapshot
├── workspaceRevision
├── credentialVersions
├── timeoutSeconds
├── forks
├── cancelRequestedAt
├── claimedBy
├── claimedAt
├── startedAt
├── finishedAt
├── returnCode
├── resultSummary
├── failureCode
├── failureMessage
├── requestedBy
├── idempotencyKey
├── createdAt
└── updatedAt
```

Run 类型：

```text
PING
COMMAND
PLAYBOOK
```

---

## 7. Inventory 设计

## 7.1 数据库是 Inventory 主数据源

用户通过 UI 创建 Host 和 Group，系统生成 Inventory Preview。

```yaml
all:
  children:
    production:
      hosts:
        worker01: {}

    swarm_workers:
      hosts:
        worker01: {}

  hosts:
    worker01:
      ansible_host: 192.168.1.21
      ansible_port: 22
      ansible_user: ecs-user
      ansible_python_interpreter: /usr/bin/python3
```

Preview 必须不包含任何 Secret。

## 7.2 Runtime Inventory

执行时才生成包含临时连接秘密的 Inventory：

```yaml
all:
  hosts:
    worker01:
      ansible_host: 192.168.1.21
      ansible_port: 22
      ansible_user: ecs-user
      ansible_password: "<runtime-secret>"
      ansible_python_interpreter: /usr/bin/python3
      ansible_become: true
      ansible_become_method: sudo
      ansible_become_user: root
      ansible_become_password: "<runtime-secret>"
```

之所以采用 per-host 运行时变量，是为了支持不同主机使用不同密码。

## 7.3 Runtime Inventory 安全要求

执行目录：

```text
/data/runtime/<run-id>/
```

必须满足：

```text
目录权限：0700
Inventory 文件：0600
Private Key 文件：0600
执行结束后删除
不得进入备份
不得进入持久化 Artifact
不得通过 API 返回
不得记录到日志
```

持久化的只应是：

```text
非秘密 Inventory Snapshot
Credential ID
Credential Version
目标 Host ID
```

## 7.4 目标解析

支持的 Target Spec：

```json
{
  "kind": "host",
  "hostId": "..."
}
```

```json
{
  "kind": "group",
  "groupId": "..."
}
```

```json
{
  "kind": "hosts",
  "hostIds": ["...", "..."]
}
```

```json
{
  "kind": "all"
}
```

服务端解析 Target 后得到固定的 Host ID 列表，再创建 Run。

### 禁止目标扩大

Runner 执行时始终使用：

```text
host_pattern = all
```

因为 Runtime Inventory 中只包含本次已经解析和授权的主机。

用户不得通过自由 Pattern 扩大执行范围。

---

## 8. 快速命令设计

Quick Command 是 Ansible Ad Hoc Command 的轻量封装。

## 8.1 UI 字段

```text
Target
  All Hosts
  Host
  Group
  Multiple Hosts

Mode
  Command
  Shell

Command
  docker ps

Privilege Escalation
  Use Credential Default
  Enabled
  Disabled

Timeout
  60 seconds

Forks
  5
```

## 8.2 Command 模式

默认使用：

```text
ansible.builtin.command
```

适合：

```bash
docker ps
uname -a
df -h
systemctl status docker
```

以下 shell 语义不会生效：

```text
|
&&
>
>>
*
$()
```

Command 模式是默认且相对安全的模式。

## 8.3 Shell 模式

显式选择：

```text
ansible.builtin.shell
```

适合：

```bash
docker ps | grep trade
uptime && df -h
journalctl -u docker | tail -n 100
```

Shell 模式必须展示明确提示，并要求二次确认。

## 8.4 API 请求

```http
POST /api/v1/runs/commands
Idempotency-Key: <uuid>
Content-Type: application/json
```

```json
{
  "target": {
    "kind": "group",
    "groupId": "group-uuid"
  },
  "mode": "command",
  "command": "docker ps",
  "become": "credential_default",
  "timeoutSeconds": 60,
  "forks": 5
}
```

响应：

```json
{
  "id": "run-uuid",
  "kind": "command",
  "status": "queued",
  "createdAt": "2026-09-03T10:00:00Z"
}
```

## 8.5 后端映射

Command：

```python
module = "ansible.builtin.command"
module_args = json.dumps({"cmd": command})
```

Shell：

```python
module = "ansible.builtin.shell"
module_args = json.dumps({"cmd": command})
```

Runner 调用示意：

```python
ansible_runner.run(
    private_data_dir=runtime_dir,
    ident=run_id,
    inventory=runtime_inventory_path,
    host_pattern="all",
    module=module,
    module_args=module_args,
    event_handler=event_handler,
    status_handler=status_handler,
    cancel_callback=cancel_callback,
)
```

## 8.6 执行限制

建议默认值：

```text
最大命令长度：4096 字符
默认执行时间：60 秒
最大执行时间：900 秒
默认 Forks：5
最大 Forks：20
单 Host 输出上限：1 MiB
单 Run 输出上限：10 MiB
stdin：关闭
PTY：关闭
```

禁止命令中出现 NUL 字节。

---

## 9. Playbook 设计

## 9.1 来源模式

`OPS_COMPOSER_PLAYBOOK_SOURCE_MODE` 支持：

```text
database  只启用 PostgreSQL Playbook，完全忽略 Workspace
mount     只启用只读挂载目录，不开放 Web 写入
both      同时启用，默认值
```

两种来源以 `source + reference` 唯一标识。同名、同路径条目可共存，不相互覆盖。`both`
模式缺少挂载目录只在 Doctor 中标记降级，不阻塞数据库 Playbook。

## 9.2 数据库 Playbook

数据库来源只保存一个 YAML 文件。Web 支持创建、校验、编辑、启停和软删除；不支持草稿、
多文件项目、revision 回滚界面、挂载导入或同步。保存前必须满足：

```text
内容非空且不含 NUL
UTF-8 字节数不超过 1 MiB
换行统一为 LF，其他原始空白保持不变
YAML 根节点为 play 列表
隔离临时目录中的 ansible-playbook --syntax-check 成功
```

每次保存生成不可变 revision。Run 创建事务固定 `playbook_id + playbook_revision + sha256`；
后续编辑、停用或删除不改变已创建 Run。历史 Retry 复制原 revision。Worker 把固定 YAML
以 `0600` 写入 Run 专属 `0700` project 目录，结束、失败或恢复时清理。该目录不包含挂载
Workspace，因此不能隐式引用其中的 roles、templates、files 或 vars；只可使用 builtin 和
镜像内 collection。

Playbook 是可信代码，以明文存入 PostgreSQL，不得包含 Credential 或部署 Secret。日志、
`audit_events` 和 RunEvent 不记录 YAML 或 syntax-check 原始载荷。

## 9.3 挂载 Playbook

挂载来源保持只读，只扫描：

```text
/workspace/playbooks/**/*.yml
/workspace/playbooks/**/*.yaml
```

真实路径必须留在 `playbooks/` 边界内；绝对路径、`..`、越界符号链接和非 YAML 文件均拒绝。
Run 创建时固定文件 SHA-256，Worker 执行前再次校验。Workspace 可包含标准 roles、templates、
files 和 vars，但容器挂载必须为只读。

## 9.4 Playbook 执行请求

```http
POST /api/v1/runs/playbooks
```

```json
{
  "playbook": {
    "source": "DATABASE",
    "playbookId": "b51a20c5-2b23-44f6-af68-b243ae53bc22"
  },
  "target": {
    "kind": "GROUP",
    "groupId": "swarm-workers-uuid"
  },
  "extraVars": {
    "reboot_after_upgrade": false
  },
  "tags": [],
  "skipTags": [],
  "timeoutSeconds": 1800,
  "forks": 5
}
```

挂载来源对应 `{"source":"MOUNT","path":"playbooks/system-update.yml"}`。旧
`playbookPath` 暂时按 `MOUNT` 解释，仅用于兼容已有客户端。

## 9.5 Playbook Target 语义

用户选择目标后，Runtime Inventory 中只放入被选中的主机，但保留这些主机原有的分组关系。

例如 Playbook：

```yaml
- hosts: swarm_workers
  tasks:
    - ansible.builtin.ping:
```

用户只选择：

```text
worker01
worker02
```

Runtime Inventory 保留：

```yaml
all:
  children:
    swarm_workers:
      hosts:
        worker01: {}
        worker02: {}
```

未被选择的 `worker03` 不会进入 Runtime Inventory，因此不会被执行。

---

## 10. Run 执行模型

## 10.1 Run 状态机

```text
QUEUED
   │
   ▼
PREPARING
   │
   ▼
RUNNING
   │
   ├──────────────► SUCCEEDED
   ├──────────────► PARTIAL
   ├──────────────► FAILED
   ├──────────────► CANCELED
   ├──────────────► TIMED_OUT
   ├──────────────► INTERRUPTED
   └──────────────► REJECTED
```

### 状态定义

| 状态 | 说明 |
|---|---|
| `QUEUED` | 已持久化，等待 Worker |
| `PREPARING` | 生成 Inventory、解密 Credential、准备 Runtime |
| `RUNNING` | Ansible 已启动 |
| `SUCCEEDED` | 所有目标成功或正常跳过 |
| `PARTIAL` | 部分主机成功，部分失败或不可达 |
| `FAILED` | 整体执行失败 |
| `CANCELED` | 用户取消 |
| `TIMED_OUT` | 超时终止 |
| `INTERRUPTED` | Worker 重启或执行所有权丢失 |
| `REJECTED` | 执行前校验失败 |

所有终态禁止再次修改。

## 10.2 Cancel

取消请求不作为单独主状态，记录：

```text
cancel_requested_at
```

流程：

```text
用户点击 Cancel
       ↓
设置 cancel_requested_at
       ↓
Runner cancel_callback 检查
       ↓
终止 Ansible
       ↓
Run → CANCELED
```

## 10.3 Worker 重启恢复

Worker 启动时扫描当前 Worker 遗留的：

```text
PREPARING
RUNNING
```

统一标记：

```text
INTERRUPTED
failure_code = WORKER_RESTARTED
```

M1 禁止自动重试。

## 10.4 Durable Queue

M1 使用数据库队列，不引入 Redis。

概念流程：

```text
API Transaction
  ├── INSERT runs(status=QUEUED)
  ├── INSERT run_targets
  └── COMMIT

Worker
  ├── Claim oldest QUEUED Run
  ├── Update claimed_by / claimed_at
  ├── Prepare runtime
  └── Execute
```

PostgreSQL 场景默认单 Worker，使用短事务、Worker Lease 和
`FOR UPDATE SKIP LOCKED` 完成安全 Claim，不引入外部队列。

## 10.5 并发控制

默认：

```text
maxConcurrentRuns = 1
```

即使未来支持多并发，也必须有 Host Lock：

```text
Run A → worker01, worker02
Run B → worker02

Run B 必须等待 Run A 释放 worker02
```

锁表：

```text
host_execution_locks
├── host_id
├── run_id XOR web_shell_session_id
├── owner_id
├── acquired_at
└── expires_at
```

Run 与 Web Shell 对同一 Host 使用同一个主键互斥；过期 Lease 可被原子接管，但活跃锁不得覆盖。

获取多个 Host Lock 时，按 Host ID 排序，避免死锁。

---

## 11. 每台主机的执行结果

一个 Run 对应多个 RunTarget：

```text
Run
├── manager01
├── worker01
└── worker02
```

RunTarget 状态：

```text
PENDING
RUNNING
OK
CHANGED
FAILED
UNREACHABLE
SKIPPED
CANCELED
```

RunTarget 字段：

```text
RunTarget
├── id
├── runId
├── hostId
├── hostNameSnapshot
├── addressSnapshot
├── status
├── returnCode
├── stdout
├── stderr
├── changedCount
├── failedCount
├── unreachableCount
├── resultJson
├── startedAt
└── finishedAt
```

### Run 聚合规则

```text
全部为 OK / CHANGED / SKIPPED
→ SUCCEEDED

至少一个成功，且至少一个 FAILED / UNREACHABLE
→ PARTIAL

没有任何成功，存在 FAILED / UNREACHABLE
→ FAILED

运行中用户取消
→ CANCELED

Runner 超时
→ TIMED_OUT
```

不能只依赖 Ansible 进程退出码。必须消费结构化事件：

```text
runner_on_ok
runner_on_failed
runner_on_unreachable
runner_on_skipped
playbook_on_stats
```

---

## 12. 实时日志与事件流

Run 实时事件采用 Server-Sent Events；只有不可回放的 Web Shell PTY 使用同源 WebSocket。

接口：

```http
GET /api/v1/runs/{runId}/events
Accept: text/event-stream
Last-Event-ID: 128
```

示例：

```text
id: 129
event: host_ok
data: {"runId":"...","host":"worker01","task":"Run command","stdout":"..."}
```

采用 SSE 的原因：

```text
数据方向主要是 Server → Browser
支持自动重连
支持 Last-Event-ID
浏览器刷新后可继续读取
取消仍走普通 HTTP POST
```

数据库事件序号约束：

```text
UNIQUE(run_id, sequence)
```

### 事件类型建议

```text
RUN_QUEUED
RUN_PREPARING
RUN_STARTED
RUN_CANCEL_REQUESTED
RUN_FINISHED

HOST_STARTED
HOST_OK
HOST_CHANGED
HOST_FAILED
HOST_UNREACHABLE
HOST_SKIPPED

TASK_STARTED
TASK_OUTPUT
PLAYBOOK_STATS
```

### 输出限制

- 单 Host 输出超过上限时截断；
- 单 Run 总输出超过上限时只保留尾部和结构化摘要；
- 截断必须记录 `outputTruncated=true`；
- 输出截断不得影响 Run 正常终结。

---

## 13. 数据库设计

M1 唯一支持的数据库：

```text
PostgreSQL 16 + Psycopg 3
```

职责：

```text
业务对象持久化
Durable Run Queue
Worker Lease
Host Lock
Run Event / SSE 回放
认证 Session 与限流
业务审计与保留期清理
```

项目不使用 ORM，直接采用 Psycopg 3、显式 SQL、Migration 和 Repository。

## 13.1 hosts

```text
id
name
address
ssh_port
credential_id
python_interpreter
enabled
description
variables_json
version
created_at
updated_at
```

约束：

```text
UNIQUE(name)
CHECK(ssh_port BETWEEN 1 AND 65535)
```

## 13.2 host_groups

```text
id
name
description
created_at
updated_at
```

约束：

```text
UNIQUE(name)
```

## 13.3 host_group_members

```text
host_id
group_id
created_at

PRIMARY KEY(host_id, group_id)
```

## 13.4 credentials

```text
id
name
type
username
public_config_json
encrypted_secret
encryption_key_version
enabled
version
created_at
updated_at
```

## 13.5 runs

```text
id
source_run_id
kind
status

target_spec_json
resolved_targets_json
operation_spec_json
inventory_snapshot_json
workspace_revision
playbook_id (nullable)
playbook_revision (nullable)
credential_versions_json

timeout_seconds
forks

cancel_requested_at
claimed_by
claimed_at
started_at
finished_at

return_code
result_summary_json
failure_code
failure_message

requested_by
idempotency_key

created_at
updated_at
```

建议约束：

```text
UNIQUE(requested_by, idempotency_key)
```

### operation_spec_json：Command

```json
{
  "mode": "command",
  "command": "docker ps",
  "become": "credential_default"
}
```

### operation_spec_json：Playbook

```json
{
  "playbook": {
    "source": "DATABASE",
    "playbookId": "0199c9d4-9c9a-7f59-b301-98d73fcf2447",
    "revision": 3,
    "sha256": "..."
  },
  "extraVars": {},
  "tags": [],
  "skipTags": []
}
```

挂载来源使用 `{ "source": "MOUNT", "path": "playbooks/status.yml", "sha256": "..." }`。
旧客户端提交的 `playbookPath` 仅在创建接口边界转换为挂载引用；持久化后统一使用带来源的引用。
`playbook_id + playbook_revision` 仅在数据库来源时同时非空，并通过复合外键固定不可变 revision。

## 13.6 run_targets

```text
id
run_id
host_id
host_name_snapshot
address_snapshot
status
return_code
stdout
stderr
result_json
changed_count
failed_count
unreachable_count
started_at
finished_at

UNIQUE(run_id, host_id)
```

## 13.7 run_events

```text
id
run_id
run_target_id
sequence
event_type
task_name
stdout
event_data_json
created_at

UNIQUE(run_id, sequence)
```

## 13.8 host_execution_locks

```text
host_id
run_id (nullable)
web_shell_session_id (nullable)
owner_id
acquired_at
expires_at

PRIMARY KEY(host_id)
CHECK(exactly one of run_id / web_shell_session_id is non-null)
```

## 13.9 worker_leases

```text
lease_name
worker_id
heartbeat_at
expires_at
```

## 13.10 users

```text
id
username
password_hash
enabled
created_at
updated_at
```

## 13.11 settings

```text
key
value_json
updated_at
```

## 13.12 schema_migrations

```text
version
checksum
applied_at
```

## 13.13 audit_events

```text
audit_event_id (identity)
occurred_at (timestamptz)
schema_version
severity
source
service
event_action
event_outcome
request_id
correlation_id
actor_user_id
session_id
run_id
run_target_id
worker_id
resource_type
resource_id
duration_ms
error_code
exception_type
failure_stage
retryable
metadata (jsonb)
```

`0040_audit_events` 是 forward-only checksum migration。资源 ID 不设置外键，以便业务对象
删除后仍保留历史；数据库触发器拒绝 `UPDATE`，仅保留期任务可以分批 `DELETE`。时间、动作、
Run、管理员和资源均有查询索引。

## 13.14 playbooks

```text
id
name
description
enabled
current_revision
version
created_by
updated_by
deleted_at
created_at
updated_at
```

活动名称使用大小写不敏感唯一索引。`version` 用于 Web 编辑和启停操作的乐观锁；删除采用软删除，
不会移除历史 Run 所引用的 revision。

## 13.15 playbook_revisions

```text
playbook_id
revision
yaml_content
content_sha256
byte_count
validator_version
created_by
created_at

PRIMARY KEY(playbook_id, revision)
```

revision 只允许插入；数据库触发器拒绝更新或删除。YAML 保存前统一为 LF，并在隔离临时目录中
通过根节点检查和 `ansible-playbook --syntax-check`；数据库仅接受不超过 1 MiB 的单文件
Playbook。

## 13.16 web_shell_sessions

```text
web_shell_session_id
host_id
actor_user_id
auth_session_id
credential_id + credential_version
host_name + host_address + ssh_port + username (fixed snapshot)
state
api_instance_id
owner_id
ticket_expires_at
lease_expires_at
connected_at
last_activity_at
close_requested_at
created_at
```

该表是临时协调状态，不保存密码、命令、终端输入输出或录像。创建事务使用 PostgreSQL
advisory transaction lock 串行计算全局容量，并原子写入固定 Credential revision、Host Lock
和审计。Ticket 30 秒且一次性消费；活动连接每 10 秒刷新 30 秒 Lease。过期行删除时通过外键
级联释放 Web Shell Host Lock，审计资源 ID 不使用外键，因此会话回收后仍保留生命周期记录。

---

## 14. API 设计

统一前缀：

```text
/api/v1
```

## 14.1 Hosts

```text
GET    /hosts
POST   /hosts
GET    /hosts/{id}
PATCH  /hosts/{id}
DELETE /hosts/{id}

POST   /hosts/{id}/test
POST   /hosts/{id}/web-shell-sessions
```

`POST /hosts/{id}/test` 创建一个异步 `PING` Run，返回 `202 Accepted`。

Web Shell 创建返回 `201`、会话 ID、固定 Host 摘要、同源 `streamPath`、Ticket 到期时间及会话
限制。写请求继续要求 Session、Origin 和 CSRF。

## 14.2 Groups

```text
GET    /groups
POST   /groups
GET    /groups/{id}
PATCH  /groups/{id}
DELETE /groups/{id}

PUT    /groups/{id}/members
```

## 14.3 Credentials

```text
GET    /credentials
POST   /credentials
GET    /credentials/{id}
PATCH  /credentials/{id}
DELETE /credentials/{id}
POST   /credentials/{id}/rotate
```

读取接口不得返回 Secret。

返回示例：

```json
{
  "id": "...",
  "name": "production-password",
  "type": "password",
  "username": "ecs-user",
  "hasPassword": true,
  "hasBecomePassword": true,
  "enabled": true
}
```

## 14.4 Inventory

```text
POST /inventory/resolve
POST /inventory/preview
POST /inventory/validate
```

## 14.5 Playbooks

```text
GET    /playbooks
GET    /playbooks/config
POST   /playbooks/database
GET    /playbooks/database/{playbookId}
PUT    /playbooks/database/{playbookId}
DELETE /playbooks/database/{playbookId}
POST   /playbooks/validate
```

目录项和执行请求使用 `{source, playbookId|path}` 判别引用。数据库内容详情和校验响应均返回
`Cache-Control: no-store`；数据库写接口继续要求 Session、Origin 和 CSRF。

## 14.6 Runs

```text
GET  /runs
GET  /runs/{id}

POST /runs/commands
POST /runs/playbooks
POST /runs/{id}/cancel
POST /runs/{id}/retry

GET  /runs/{id}/targets
GET  /runs/{id}/events
```

## 14.7 System

```text
GET /system/info
GET /system/readiness
GET /system/doctor
```

## 14.8 Web Shell

```text
POST   /hosts/{hostId}/web-shell-sessions
DELETE /web-shell-sessions/{sessionId}
WS     /web-shell-sessions/{sessionId}/stream
```

二进制帧承载 PTY 字节；文本 JSON 帧仅允许 `ready`、`resize`、`error`、`closed` 和客户端
`close` 控制消息。连接不接受查询字符串 Token，严格依赖同源 Cookie 与数据库中的一次性 Ticket。

## 14.9 错误格式

```json
{
  "code": "TARGET_EMPTY",
  "message": "No enabled hosts matched the selected target.",
  "details": {},
  "requestId": "request-uuid"
}
```

建议错误码：

```text
HOST_NOT_FOUND
host_busy
web_shell_capacity_reached
host_key_confirmation_required
web_shell_session_expired
web_shell_unavailable
GROUP_NOT_FOUND
CREDENTIAL_NOT_FOUND
CREDENTIAL_DISABLED
TARGET_EMPTY
TARGET_CONTAINS_DISABLED_HOST
PLAYBOOK_NOT_FOUND
PLAYBOOK_INVALID
PLAYBOOK_PATH_ESCAPE
RUN_NOT_FOUND
RUN_NOT_CANCELABLE
WORKER_NOT_READY
MASTER_KEY_INVALID
HOST_KEY_CHANGED
RUNTIME_PREPARATION_FAILED
ANSIBLE_EXECUTION_FAILED
```

---

## 15. CLI 设计

CLI 与 Web API 必须调用同一套 Application Service，不能复制业务逻辑。

## 15.1 进程命令

```bash
ops-composer serve
ops-composer worker
ops-composer migrate
ops-composer doctor
```

## 15.2 主机管理

```bash
ops-composer host list

ops-composer host add \
  --name worker01 \
  --address 192.168.1.21 \
  --credential production
```

## 15.3 Inventory

```bash
ops-composer inventory render
ops-composer inventory validate
```

## 15.4 快速命令

```bash
ops-composer run command \
  --host worker01 \
  -- docker ps
```

```bash
ops-composer run command \
  --group swarm_workers \
  --mode shell \
  -- 'uptime && df -h'
```

## 15.5 Playbook

```bash
ops-composer run playbook \
  --group swarm_workers \
  playbooks/status.yml
```

## 15.6 Run

```bash
ops-composer run list
ops-composer run show <run-id>
ops-composer run cancel <run-id>
ops-composer run retry <run-id>
```

CLI 默认也创建持久化 Run，不得绕过数据库直接执行 Ansible。

---

## 16. 代码架构

采用 Modular Monolith。

```text
ops-composer/
├── backend/
│   ├── pyproject.toml
│   ├── src/
│   │   └── ops_composer/
│   │       ├── domain/
│   │       │   ├── hosts/
│   │       │   ├── groups/
│   │       │   ├── credentials/
│   │       │   └── runs/
│   │       │
│   │       ├── application/
│   │       │   ├── commands/
│   │       │   ├── queries/
│   │       │   ├── services/
│   │       │   └── ports/
│   │       │
│   │       ├── infrastructure/
│   │       │   ├── ansible/
│   │       │   ├── crypto/
│   │       │   ├── db/
│   │       │   ├── runtime/
│   │       │   └── workspace/
│   │       │
│   │       └── interfaces/
│   │           ├── api/
│   │           ├── cli/
│   │           └── worker/
│   │
│   └── tests/
│
├── frontend/
│   ├── src/
│   │   ├── api/
│   │   ├── components/
│   │   ├── views/
│   │   ├── stores/
│   │   ├── router/
│   │   └── locales/
│   └── package.json
│
├── migrations/
│   ├── 001_initial.sql
│   └── 002_worker_lease.sql
│
├── workspace-example/
│   ├── playbooks/
│   ├── roles/
│   └── ops-composer.yml
│
├── deploy/
│   ├── compose.yml
│   └── Dockerfile
│
└── README.md
```

### 16.1 依赖方向

```text
interfaces
    ↓
application
    ↓
domain

infrastructure
    └── implements application ports
```

必须禁止：

```text
domain → FastAPI
domain → PostgreSQL / Psycopg
domain → ansible_runner
domain → HTTP
domain → Docker
```

### 16.2 执行端口

```python
from typing import Protocol

class ExecutionEngine(Protocol):
    def execute(self, request: "ExecutionRequest") -> "ExecutionResult":
        ...
```

具体实现：

```python
class AnsibleRunnerExecutionEngine:
    ...
```

### 16.3 Repository 边界

Application Service 负责事务编排，Repository 只负责持久化。

必须禁止：

```text
Ansible Adapter 查询业务 Repository
Infrastructure 反向调用 API Service
Domain 直接读取 Workspace
Worker 绕过 Application Service 修改 Run 状态
```

---

## 17. 技术栈

## 17.1 后端

```text
Python 3.12+
FastAPI
Pydantic v2
ansible-core
ansible-runner
cryptography
PostgreSQL 16
Psycopg 3
Typer
```

必须固定经过验证的：

```text
Python 版本
ansible-core 版本
ansible-runner 版本
OpenSSH Client 版本范围
```

生产镜像不得使用 `latest` 标签。

## 17.2 前端

```text
Vue 3
Vite
TypeScript
Pinia
PrimeVue
Vue Router
vue-i18n
@xterm/xterm
@xterm/addon-fit
```

约定：

```text
.vue 文件禁止直接写中文
展示文本进入 locales
API 字段使用 camelCase
数据库字段使用 snake_case
```

## 17.3 M1 不引入

```text
Celery
Redis
Kafka
Kubernetes
SQLAlchemy ORM
GraphQL
```

WebSocket 仅用于同源、连接绑定且不可回放的 Web Shell PTY，不承担业务事件总线职责。

---

## 18. 页面与交互设计

## 18.1 Overview

第一阶段不展示健康状态，只展示资产和执行：

```text
Hosts        8
Groups       4
Credentials  2

Runs
Succeeded    28
Failed        2
Running       1
Queued        0

Recent Runs
────────────────────────────────────────
docker ps        swarm_workers  Success
status.yml       all            Success
apt update       worker03       Failed
```

## 18.2 Hosts

列表：

```text
Host       Address          Groups          Credential
manager01  192.168.1.11     manager, prod   production
worker01   192.168.1.21     worker, prod    production
```

详情：

```text
Identity
Connection
Groups
Variables
Recent Runs

[Test Connection]
[Run Command]
[Run Playbook]
```

## 18.3 Groups

```text
swarm_managers    3 hosts
swarm_workers     5 hosts
gpu_nodes         1 host
production        8 hosts
```

## 18.4 Credentials

```text
production-password
Type: Password
User: ecs-user
Sudo: Enabled
Used by: 8 hosts
```

Secret 不显示，只显示存在性和最后更新时间。

## 18.5 Quick Command

```text
Target      [ swarm_workers ▼ ]
Mode        [ Command ▼ ]
Command     [ docker ps                     ]
Become      [ Credential Default ▼ ]
Timeout     [ 60 ]
Forks       [ 5 ]

                         [ Run ]
```

提交后直接进入 Run Detail。

## 18.6 Playbooks

```text
Source  Name                 Status   Revision  Size    Updated
DB      Connectivity Check   Enabled  3         812 B   ...
Mount   status.yml           Readonly —         1.2 KB  ...
```

页面使用 PrimeVue DataTable 和来源筛选。数据库行支持创建、编辑、启停、删除、校验和执行；
挂载行只支持校验和执行，并显示“只读挂载”。创建与编辑 Dialog 使用单文件 YAML Textarea，
客户端可先校验，保存时服务端必须再次校验；并发修改以 `version` 冲突提示管理员刷新。

每个目录项展示：

```text
Source
Name
Description
Validation Status
Enabled / Readonly
Revision
Byte Size
Updated At
```

## 18.7 Run Detail

```text
Run: 0192...
Status: PARTIAL
Kind: Command
Command: docker ps
Target: swarm_workers

Hosts
────────────────────────────────────
worker01    OK
worker02    OK
worker03    UNREACHABLE

Live Output
────────────────────────────────────
[worker01] ...
[worker02] ...
[worker03] SSH connection failed
```

可执行操作：

```text
Cancel
Retry as New Run
Copy Run ID
Download Redacted Log
```

## 18.8 Web Shell

Hosts 操作列仅为启用主机显示可用的“Web Shell”入口。PrimeVue ConfirmDialog 必须说明：这是
交互式远端终端、会独占该主机的执行锁、终端内容不被记录。确认后使用新标签页打开
`/hosts/{hostId}/shell`；弹窗被阻止时显示 Toast。

独立页面不显示控制台侧边栏，顶部只展示 Host、SSH 用户、连接状态、重新连接和关闭。xterm.js
通过二进制 WebSocket 帧收发终端字节，通过 JSON 控制帧发送 resize/close；支持 Ctrl+C、Tab、
方向键和交互程序。断线或刷新立即销毁 PTY；“重新连接”创建全新数据库会话。

---

## 19. 安全设计

## 19.1 MUST

```text
Credential 使用应用 Master Key 加密
使用 AEAD 加密算法
Runtime Secret 文件权限 0600
运行目录权限 0700
运行结束删除 Runtime Inventory
默认使用 command 模式
Shell 模式显式开启并二次确认
启用 SSH Host Key 验证
挂载来源的 Workspace 只读挂载
数据库 Playbook 保存前执行语法检查并固定不可变 revision
所有执行有 timeout
所有执行有审计记录
API 写操作需要认证
Cookie 模式启用 CSRF 防护
日志进行 Secret Redaction
Worker 使用非 root 用户
```

## 19.2 MUST NOT

```text
不得把 SSH 密码写入持久化 Inventory
不得在 URL 中传递密码
不得在进程命令行参数中传递密码
不得向前端返回 decrypted secret
不得允许用户设置 ansible_password
不得接受任意 Ansible Module 名称
不得接受任意 Runner cmdline
不得自动重试中断的修改性操作
不得挂载 Docker Socket
不得允许 Playbook 路径逃逸 Workspace
不得把 Master Key 保存到数据库
```

## 19.3 SSH Host Key

持久化文件：

```text
/data/ssh/known_hosts
```

Host 第一次接入流程：

```text
Scan Host Key
    ↓
展示 Fingerprint
    ↓
管理员确认 Trust
    ↓
写入 known_hosts
```

Host Key 改变时必须失败：

```text
HOST_KEY_CHANGED
```

不允许长期使用：

```text
StrictHostKeyChecking=no
```

## 19.4 Playbook 信任边界

Playbook 本质上是可信代码。任何能修改挂载 Workspace 或数据库 Playbook 的管理员，理论上都能
执行任意远程命令并读取运行时变量。

因此 M1：

```text
挂载 /workspace 只读
数据库 Playbook 仅允许已认证管理员通过受 CSRF 保护的 API 维护
不允许普通用户上传任意 Playbook
每次数据库保存必须通过 YAML 和 Ansible syntax-check，并形成不可变 revision
数据库单文件不得隐式读取挂载 Workspace 的 roles、templates、files 或 vars
Playbook YAML 视为普通敏感业务数据，不得写入 stdout、audit metadata 或 RunEvent
```

## 19.5 Secret Redaction

至少对以下来源建立 Redaction 集合：

```text
SSH Password
Become Password
Private Key Passphrase
Master Key 派生检查值
```

M1 的 Extra Vars 只允许非敏感配置；包含 password、secret、token、private key、
passphrase 或 `ansible_*` 连接控制键的字段直接拒绝。未来如需 Secret Extra Vars，必须先
设计独立的加密信封与脱敏标记，禁止把它们混入 `operation_spec` 明文 JSON。

日志写入前执行：

```text
exact match replacement
常见 shell quote 变体替换
URL encoded 变体替换
```

任何 Redaction 异常不得导致 Secret 原文被记录。

## 19.6 Web Shell 安全边界

创建 REST 请求要求 Opaque Session、Origin 与 CSRF；WebSocket 握手再次校验 Origin、Session
Cookie、创建者登录 Session、一次性 Ticket 与 30 秒有效期。Session ID 只是资源标识，不作为
Bearer Token。密码只经匿名 pipe 传给 `sshpass -d <fd>`，不得进入 argv、env、文件或日志。

OpenSSH 固定 `StrictHostKeyChecking=yes`，使用每会话 `0600 known_hosts`，绝不自动接受未知或
变化的指纹。运行目录权限 `0700`，连接结束后终止整个进程组并清理。输入帧上限 64 KiB、终端
尺寸为 20–500 列和 5–200 行，输出缓冲上限 1 MiB；慢消费者和非法控制帧会被断开。

审计只记录会话 ID、Host、管理员、固定 Credential revision、时间、时长、退出码和安全错误码，
不得记录终端帧、命令、输出、密码或 SSH 原始错误载荷。

---

## 20. 日志规范

运行时采用两层日志：stdout 单行 JSON 用于实时排障，PostgreSQL `audit_events` 用于持久化
业务审计。不依赖 Redis、ELK、Loki 或 Sentry。API、Worker、CLI、Migration 和 Uvicorn 使用
同一字段命名；Uvicorn 默认 access log 关闭，避免重复记录。

结构化日志示例：

```json
{
  "timestamp": "2026-09-04T00:00:00+00:00",
  "level": "INFO",
  "service": "worker",
  "environment": "production",
  "message": "run started",
  "source": "WORKER",
  "event_action": "RUN_STARTED",
  "event_outcome": "SUCCEEDED",
  "request_id": null,
  "correlation_id": "...",
  "run_id": "...",
  "worker_id": "...",
  "duration_ms": 0,
  "metadata": {"operation_kind": "COMMAND", "target_count": 5}
}
```

固定字段包含请求/关联 ID、管理员与 Session、Run/RunTarget、Host/Group/Credential、Worker、
耗时、安全错误码、失败阶段、可重试标记和受控 metadata。ContextVar 在请求与任务边界绑定并
可靠复位，防止并发串号。健康检查成功与空队列轮询不写 INFO；重复基础设施错误只在状态变化
及周期摘要时输出。

审计规则：

```text
成功业务变更与审计记录处于同一数据库事务，提交后才输出成功日志
拒绝和失败事件通过最长 2 秒的独立短事务尽力写入
审计不可用时仍写 stdout，且不得覆盖原始业务异常
RunEvent 保存执行详情；audit_events 只保存生命周期、结果与计数
Worker 启动时及每 24 小时尝试 advisory lock，按 5000 条删除过期审计
默认保留 180 天，可配置 1..3650 天
```

禁止记录：

```text
password
becomePassword
privateKey
完整 Runtime Inventory
包含秘密的 Extra Vars
Master Key
数据库密文原文
命令正文与 Ansible 原始载荷
Token、Cookie、CSRF 与数据库 URL
Web Shell 终端输入、输出与原始 SSH 错误载荷
```

Web Shell 生命周期覆盖申请、开始、主动关闭、拒绝、容量/Host Lock 冲突、认证失效、空闲或
最长时长超时、SSH 启动失败、数据库失联和过期协调记录回收。终端帧永远不进入
`audit_events`、RunEvent 或 JSON stdout。

CLI 运维接口：

```bash
ops-composer audit list
ops-composer audit export --since <UTC> --until <UTC> --output <JSONL>
ops-composer audit purge             # dry-run
ops-composer audit purge --execute
```

`list` 默认查询最近 24 小时、200 条，支持动作、结果、来源、Run、管理员、资源、错误码和游标；
`export` 流式写入权限 `0600` 的 JSONL，默认拒绝覆盖；`purge` 必须显式 `--execute`。

---

## 21. Docker 部署设计

## 21.1 Compose

```yaml
services:
  db:
    image: postgres:16-alpine
    restart: unless-stopped
    environment:
      POSTGRES_DB: ops_composer
      POSTGRES_USER: ops_composer
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      - ./volumes/postgres:/var/lib/postgresql/data
    logging: &local-logging
      driver: local
      options: {max-size: "20m", max-file: "10"}
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ops_composer -d ops_composer"]

  migrate:
    image: ops-composer:local
    command: ["ops-composer", "migrate", "up"]
    environment: &app-env
      DATABASE_URL: postgresql://ops_composer:${POSTGRES_PASSWORD}@db:5432/ops_composer
      OPS_COMPOSER_MASTER_KEY: ${OPS_COMPOSER_MASTER_KEY}
      OPS_COMPOSER_PLAYBOOK_WORKSPACE: /workspace
      OPS_COMPOSER_PLAYBOOK_SOURCE_MODE: both
      OPS_COMPOSER_RUNTIME_DIR: /tmp/ops-composer/runtime
      APP_LOG_LEVEL: INFO
      OPS_COMPOSER_AUDIT_RETENTION_DAYS: 180
      OPS_COMPOSER_WEB_SHELL_MAX_SESSIONS: 5
      OPS_COMPOSER_WEB_SHELL_IDLE_TIMEOUT_SECONDS: 1800
      OPS_COMPOSER_WEB_SHELL_MAX_DURATION_SECONDS: 28800
    depends_on:
      db:
        condition: service_healthy

  api:
    image: ops-composer:local
    command: ["ops-composer", "serve"]
    restart: unless-stopped
    ports:
      - "127.0.0.1:3000:3000"
    volumes:
      - ./ansible-workspace:/workspace:ro
    environment: *app-env
    depends_on:
      migrate:
        condition: service_completed_successfully
    logging: *local-logging

  worker:
    image: ops-composer:local
    command: ["ops-composer", "worker"]
    restart: unless-stopped
    volumes:
      - ./ansible-workspace:/workspace:ro
    environment: *app-env
    depends_on:
      migrate:
        condition: service_completed_successfully
    logging: *local-logging
```

## 21.2 镜像内容

Worker 镜像至少包含：

```text
Python
openssh-client
ansible-core
ansible-runner
sshpass（仅密码 SSH 兼容）
ca-certificates
必要的系统工具
```

API 和 Worker 使用同一镜像，不同启动命令。

## 21.3 容器安全

建议：

```text
非 root 用户运行
禁止 privileged
不挂载 Docker Socket
只读 Root Filesystem（Runtime 目录除外）
cap_drop: ALL
仅开放必要网络
```

密码 SSH 阶段需要 `sshpass`，后续迁移到 SSH Key 后可考虑去除。

生产反向代理必须转发 `/api/v1/web-shell-sessions/*/stream` 的 WebSocket Upgrade，并将读写
超时设为大于最大 Web Shell 会话时长。应用继续只发布一个 HTTP 端口，不增加 Gateway、Redis
或其他服务。

---

## 22. 启动与 Readiness Gate

## 22.1 API Ready Gate

API Ready 前必须验证：

```text
数据库可访问
数据库 Schema 兼容
Master Key 存在
Master Key 能解密检查值
Workspace 可读
配置有效
静态资源可用
OpenSSH Client 与 sshpass 可用（Web Shell）
```

## 22.2 Worker Ready Gate

Worker Ready 前必须验证：

```text
数据库可访问
成功获得 Worker Lease
ansible 可执行
ansible-runner 可导入
ssh 可执行
sshpass 可执行（密码模式启用时）
Runtime 目录可写
Artifact 目录可写
Workspace 可读
known_hosts 可读写
```

## 22.3 Doctor

```bash
ops-composer doctor
```

示例输出：

```text
Database              PASS
Schema                PASS
Master Key            PASS
Workspace             PASS
Ansible Core          PASS
Ansible Runner        PASS
OpenSSH Client        PASS
SSHPass                PASS
Known Hosts           PASS
Web Shell PTY         PASS
Worker Lease          PASS
Runtime Directory     PASS
```

任何硬门禁失败时，进程不得标记 Ready。

---

## 23. 开发阶段划分

## 23.1 M0：基础骨架

完成：

```text
项目结构
配置系统
显式 SQL Migration
PostgreSQL Migration
用户登录
Host CRUD
Group CRUD
Credential 加密存储
Inventory Preview
CLI doctor
```

验收：

```text
添加一台密码 SSH 服务器
数据库无明文密码
能够生成不含秘密的 Inventory Preview
重启容器后数据仍然存在
错误 Master Key 时启动失败
```

## 23.2 M1：可用执行闭环

完成：

```text
Worker Lease
Durable Run Queue
Manual Ansible Ping
Quick Command
Command / Shell 模式
Playbook 扫描
Playbook 执行
Run 状态机
RunTarget
RunEvent
SSE 实时日志
Cancel
Timeout
Retry as New Run
```

验收：

```text
选择一台 Host 执行 docker ps
选择一个 Group 执行 uname -a
不同服务器密码可以同时执行
错误密码正确显示 UNREACHABLE
一台失败时 Run 显示 PARTIAL
浏览器刷新后日志可以继续
Worker 重启后 Run 变成 INTERRUPTED
Cancel 能终止运行中的任务
重复请求不创建重复 Run
```

## 23.3 M1.1：安全与工程硬化

完成：

```text
Host Key Trust
SSH Key Credential
Credential Rotation
Per-host Lock
Artifact Retention
Secret Redaction
Output Truncation
Workspace Revision
Playbook Metadata
完整审计日志
Web Shell PTY、共享 Host Lock 与生命周期审计
```

## 23.4 后续阶段

后续再考虑：

```text
Saved Commands
Schedule
Approval
RBAC
Health Checks
Metrics
Notifications
Multi Worker
```

---

## 24. 测试与验收场景

至少覆盖：

```text
CASE-01 正确密码执行 command 成功
CASE-02 错误密码返回 UNREACHABLE
CASE-03 SSH 端口错误
CASE-04 Host Key 不匹配
CASE-05 sudo 密码正确
CASE-06 sudo 密码错误
CASE-07 command 模式不解析管道
CASE-08 shell 模式正确解析管道
CASE-09 多 Host 全部成功
CASE-10 多 Host 部分失败 → PARTIAL
CASE-11 Playbook syntax error → REJECTED
CASE-12 Playbook 路径逃逸 → REJECTED
CASE-13 执行超时 → TIMED_OUT
CASE-14 运行中取消 → CANCELED
CASE-15 Worker 重启 → INTERRUPTED
CASE-16 重复 Idempotency-Key 不重复创建 Run
CASE-17 两个 Run 操作同一 Host 时串行
CASE-18 Master Key 错误时启动失败
CASE-19 DB/API/日志中不存在明文 Credential
CASE-20 超大 stdout 被截断但 Run 正常终结
CASE-21 禁用 Host 不进入目标解析
CASE-22 禁用 Credential 导致 Run REJECTED
CASE-23 Runtime Inventory 执行后被删除
CASE-24 浏览器刷新后 SSE 从 Last-Event-ID 恢复
CASE-25 Retry 创建新 Run 且保留 sourceRunId
CASE-26 业务写入与对应审计在同一事务提交或回滚
CASE-27 审计不可用时原始业务错误不被覆盖且 stdout 仍有安全日志
CASE-28 审计过滤、游标、advisory lock 与 180 天分批清理正确
CASE-29 stdout、audit_events、RunEvent 与导出中不存在哨兵秘密
CASE-30 局域网 HTTP 环境缺少 crypto.randomUUID 时仍能创建幂等键
```

### 24.1 集成测试环境

Docker Compose 中启动多个 SSH 测试容器：

```text
sshd-good-password
sshd-bad-password
sshd-good-sudo
sshd-bad-sudo
sshd-no-python
sshd-slow-command
sshd-host-key-changed
sshd-unreachable
```

### 24.2 验收证据

M1 交付必须形成：

```text
自动化测试报告
API 集成测试结果
真实 SSH 容器执行日志
PostgreSQL Migration 验证
Secret 扫描结果
Worker 重启恢复证据
超时和取消证据
PARTIAL 聚合证据
Web Shell Origin/Session/Ticket、PTY resize/Ctrl+C、容量与共享 Host Lock 证据
Web Shell 断线、超时、进程组终止、运行目录清理与终端内容哨兵扫描
```

---

## 25. 关键不变量

```text
INV-01 Run 创建后目标集合不可被 Host/Group 后续修改影响。

INV-02 终态 Run 不得再次修改。

INV-03 Retry 必须创建新 Run，不得复用旧 Run。

INV-04 API 不得直接启动 Ansible。

INV-05 只有持有 Worker Lease 的 Worker 可以 Claim Run。

INV-06 Runtime Inventory 不得持久化到普通数据库字段或 Artifact。

INV-07 Credential Secret 不得通过 API、日志或 SSE 返回。

INV-08 Runtime Inventory 只能包含本次已解析目标。

INV-09 用户不得通过 Ansible Pattern 扩大目标范围。

INV-10 用户不得传入任意 Runner cmdline 或任意 Ansible Module。

INV-11 Worker 中断后的修改性操作不得自动重试。

INV-12 同一 Host 同时最多被一个 Run 或 Web Shell 持有。

INV-13 Run 聚合状态必须由 RunTarget 和结构化事件计算。

INV-14 挂载 Playbook 必须位于只读 Workspace 内；数据库 Playbook 必须固定到不可变 revision。

INV-15 Master Key 无效时系统必须 fail closed。

INV-16 所有远程执行必须存在 timeout。

INV-17 所有写请求必须支持幂等键或等价去重机制。

INV-18 浏览器连接状态不得决定 Run 生命周期。

INV-19 Web Shell 终端内容不得持久化到数据库、RunEvent、审计或 stdout 日志。

INV-20 Web Shell 必须绑定创建者登录 Session；Ticket 只可消费一次且 30 秒过期。

INV-21 Web Shell 断开时必须终止整个 SSH 进程组并释放通用 Host Lock。
```

---

## 26. 最终冻结边界

OpsComposer 的长期产品边界：

> 用最少的平台抽象，把主机、凭据、目标、简单命令和标准 Ansible Playbook 组合成可靠、可追踪、可审计的运维执行。

它应保留 Ansible 的标准能力：

```text
Inventory
Group
Playbook
Role
Variables
Tags
Facts
Become
Idempotent Modules
```

同时移除 Semaphore/AWX 一类平台中对当前场景不必要的对象：

```text
复杂 Project 层级
Repository 对象层
Environment 对象层
Template 对象层
完整 Automation Platform 权限体系
执行环境编排平台
```

最终产品模型冻结为：

```text
                         OpsComposer

Host + Group + Credential
            │
            ▼
      Target Resolution
            │
            ▼
      Operation Snapshot
            │
            ▼
        Durable Run
            │
            ▼
      Runtime Inventory
            │
            ▼
       Ansible Runner
            │
            ▼
    Command / Playbook
            │
            ▼
 RunTarget + RunEvent + Result
```

第一版优先顺序：

```text
1. Host / Group / Credential
2. Inventory Projection
3. Ping
4. Quick Command
5. Playbook Run
6. Durable Run + Per-host Result
7. SSE Log
8. Cancel / Timeout / Retry
9. Secret 和 Runtime 安全硬化
```

健康检查、持续监控和告警明确放到后续独立阶段，不进入当前 M1 设计范围。
