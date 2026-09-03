# OpsComposer 常见问题

## 为什么 API 启动失败并提示 migration pending？

API 和 Worker 不会自动修改 Schema。先运行 `ops-composer migrate status`，再由一次性部署
步骤执行 `ops-composer migrate up`。已应用 migration 的 checksum 不匹配时不要修改历史
文件，应新增 forward-only migration。

## 如何创建管理员？

数据库迁移完成后执行：

```bash
docker compose run --rm api ops-composer admin bootstrap --username admin
```

密码只能通过交互提示输入。系统只允许一个管理员，不存在注册接口。

## 为什么生产配置校验失败？

生产模式要求：非默认 PostgreSQL URL、HTTPS `APP_ALLOWED_ORIGINS`、Secure Cookie、至少
32 字节的限流 secret、base64 编码的 32 字节 Master Key，以及明确的受信代理 IP/CIDR。
不要在 `FORWARDED_ALLOW_IPS` 中使用 `*` 或全网 CIDR。

## Master Key 不匹配怎么办？

恢复创建 Credential 时使用的原始 `OPS_COMPOSER_MASTER_KEY`。数据库仅保存 AEAD 密文和
密钥检查信封，无法恢复丢失的密钥；应用会 fail closed，避免用错误密钥继续运行。

## 为什么 Host Key 确认失败？

确认操作会重新扫描目标，只有算法和指纹仍与预览一致才会写入数据库。检查地址、端口、
网络和 SSH 服务；密钥确实变更时先核实远端变更来源，再确认新指纹。

## 为什么 Playbook 被拒绝？

只允许 Playbook Workspace 的 `playbooks/` 下 `.yml`/`.yaml` 文件。软链接或 `..` 不能
越界，YAML 和 Ansible syntax-check 必须通过；创建 Run 后内容哈希发生变化也会拒绝执行。

## 为什么 Run 显示 INTERRUPTED？

Worker Lease 过期时，数据库恢复流程会把仍在 PREPARING/RUNNING 的 Run 和目标标记为
`INTERRUPTED` 并释放 Host Lock。为避免重复执行修改性操作，系统不会自动重试；管理员可
检查远端状态后选择 Retry as New Run。

## SSE 断线会丢日志吗？

不会。事件先按递增 sequence 写入 PostgreSQL，再通过短轮询 SSE 发送。刷新或重连时前端
从最高 sequence 继续，历史也可通过事件查询接口回放。

## 为什么真实集成测试被跳过？

设置专用的 `TEST_DATABASE_URL` 才会运行 PostgreSQL 集成测试。Compose/SSH 验收还需要可用
Docker daemon；没有这些条件时，静态、单元和前端门禁可以通过，但不能把真实基础设施验收
标记为通过。
