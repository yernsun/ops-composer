# OpsComposer 常见问题

## 企业可以不付费使用 OpsComposer 吗？

可以，前提是遵守 `AGPL-3.0-only` 和所有适用的第三方许可证。AGPL 本身不收取企业使用费。
原版内部使用、分发、修改以及通过网络提供修改版属于不同情形，应根据计划的部署方式阅读
[许可证原文](LICENSE)，尤其是对应源码和远程网络交互条款。赞助不能替代许可证合规。

## AGPL 会要求维护者提供售后吗？

不会。OpsComposer 不附带保证；社区协助仅为尽力而为，不提供 SLA，也不承诺响应期限、修复或
持续维护。详见 [SUPPORT.zh-CN.md](SUPPORT.zh-CN.md)。

## GitHub Sponsors 赞助会买到什么？

只提供鸣谢；赞助档位不得承诺专业服务、支持优先级或 SLA。GitHub Sponsors 与 PayPal 付款属于
对一般维护的自愿资助，不会购买顾问服务、安全修复、AGPL 例外、治理权或商业许可证。
PayPal 已配置为确认过的账号 `https://www.paypal.me/yernsun`；GitHub Sponsors 目标在完成入驻和核实前保持
禁用。

## 可以购买部署、迁移或安全加固吗？

可视服务方档期，按独立书面合同和独立费用提供。Issue、赞助或非正式消息都不会自动启动服务或
产生义务。范围、访问权限、交付物、验收、数据处理、知识产权、费用、责任及任何 SLA 都必须写入
签署协议。详见 [COMMERCIAL_SERVICES.zh-CN.md](COMMERCIAL_SERVICES.zh-CN.md)。

## 现在有商业软件许可证吗？

目前没有。项目正在准备 CLA 治理路径，以便未来评估双许可证。CLA 现在尚未生效，在启用前不能
合并外部贡献者受著作权保护的内容。未来商业许可证只能作为许可方实际控制权利的新增选择，不能
撤销已有 AGPL 授权，也不能改授第三方代码。见 [CLA_POLICY.zh-CN.md](CLA_POLICY.zh-CN.md)。

## 为什么 API 启动失败并提示 migration pending？

API 和 Worker 不会自动修改 Schema。先运行 `ops-composer migrate status`，再由一次性部署
步骤执行 `ops-composer migrate up`。已应用 migration 的 checksum 不匹配时不要修改历史
文件，应新增 forward-only migration。

## 如何创建管理员？

数据库迁移完成后执行：

```bash
docker compose run --rm api ops-composer admin bootstrap --username admin
```

密码只能通过交互提示输入。该用户成为首个 `OWNER`，并在下一次密码登录时强制注册 TOTP。
OWNER 可在用户治理页面创建其他账号；系统只展示一次 24 小时激活码，不依赖邮件服务。

## 唯一 OWNER 忘记密码怎么办？

在服务器项目目录中运行：

```bash
docker compose exec api ops-composer admin password-reset --username admin
```

该命令仅允许重置唯一启用的 OWNER，要求输入精确确认短语，并通过隐藏交互提示读取两次新密码；
密码不会出现在 argv 或日志中。成功后全部 Session 会被撤销，MFA 保持不变。

## 为什么生产配置校验失败？

生产模式要求：非默认 PostgreSQL URL、HTTPS `APP_ALLOWED_ORIGINS`、Secure Cookie、至少
32 字节的限流 secret、且仅一种有效 Master Key 配置，以及明确的受信代理 IP/CIDR。Keyring
文件必须只读、权限为 `0400`/`0600`，并可由容器 UID `10001` 读取。
不要在 `FORWARDED_ALLOW_IPS` 中使用 `*` 或全网 CIDR。

## Master Key 不匹配怎么办？

恢复 System 页面仍显示被引用的全部 Keyring 版本。数据库仅保存 AEAD 密文和密钥检查信封，
无法恢复丢失的 Key；应用会 fail closed。轮换时先加入并切换 Primary Key，协调重启同版本
API/Worker，再由完成再认证的 OWNER 启动可恢复轮换 Job；旧版本用量归零后才能从部署文件移除。

## 为什么 Host Key 确认失败？

确认操作会重新扫描目标，只有算法和指纹仍与预览一致才会写入数据库。检查地址、端口、
网络和 SSH 服务；密钥确实变更时先核实远端变更来源，再确认新指纹。

## 为什么 Playbook 被拒绝？

先检查 `OPS_COMPOSER_PLAYBOOK_SOURCE_MODE`。新 Run 和 Retry 引用了未启用来源时会被拒绝。
数据库 Playbook 必须处于启用状态并通过项目限制、YAML 与 Ansible syntax-check，Run 会固定
不可变 revision；创建与 Retry 都会重新检查参数 Schema 和 Check Mode 声明。敏感参数一旦消费
不可恢复，Retry 必须重新填写。挂载 Playbook 只允许 Workspace 的 `playbooks/` 下 `.yml`/`.yaml` 文件，软链接或
`..` 不能越界；创建 Run 后内容哈希发生变化也会拒绝执行。

## 为什么 System Doctor 显示 Playbook 挂载降级？

`both` 模式会分别诊断数据库与挂载来源。挂载目录缺失只表示降级，不会阻塞数据库 Playbook。
若完全不使用目录，可设置 `database` 让进程忽略 Workspace；`mount` 模式则会明确关闭 Web
数据库 Playbook 管理。

## 为什么 Run 显示 INTERRUPTED？

Worker Lease 过期时，数据库恢复流程会把仍在 PREPARING/RUNNING 的 Run 和目标标记为
`INTERRUPTED` 并释放 Host Lock。为避免重复执行修改性操作，系统不会自动重试；管理员可
检查远端状态后选择 Retry as New Run。

## SSE 断线会丢日志吗？

不会。事件先按递增 sequence 写入 PostgreSQL，再通过短轮询 SSE 发送。刷新或重连时前端
从最高 sequence 继续，历史也可通过事件查询接口回放。

## 为什么 Web Shell 无法连接？

先确认主机已启用、PASSWORD 或 SSH_PRIVATE_KEY Credential 有效，并在主机管理中扫描且人工确认了当前 SSH Host
Key。`host_busy` 表示该主机已被 Run 或另一个 Web Shell 占用；
`web_shell_capacity_reached` 表示全局会话已满。错误端口、密码错误或远端 Host Key 变化会使
OpenSSH fail closed，不会自动接受新指纹。

如果页面能打开但 WebSocket 立即断开，请检查反向代理是否转发 `Upgrade`/`Connection` 头、
代理读写超时是否大于 `OPS_COMPOSER_WEB_SHELL_MAX_DURATION_SECONDS`，以及浏览器 Origin 是否在
`APP_ALLOWED_ORIGINS`。刷新和关窗会按设计结束当前 PTY；重新连接始终创建新会话。

## 为什么操作返回 permission_denied 或 reauthentication_required？

后端会在 API 和 Service 两层执行固定角色矩阵。OPERATOR 不能管理资产或使用 Shell/Web Shell，
AUDITOR 只读。Credential 写入、用户治理和 Key 轮换还要求密码加当前 TOTP/恢复码再认证，权限
提升 10 分钟后过期；请重新认证后重试，不应依赖前端按钮是否可见判断权限。

## 为什么真实集成测试被跳过？

设置专用的 `TEST_DATABASE_URL` 才会运行 PostgreSQL 集成测试。Compose/SSH 验收还需要可用
Docker daemon；没有这些条件时，静态、单元和前端门禁可以通过，但不能把真实基础设施验收
标记为通过。
