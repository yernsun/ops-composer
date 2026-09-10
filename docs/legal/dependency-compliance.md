# 依赖与发行许可证合规

> 审计快照：2026-09-10。范围是当前 `backend/uv.lock`、`frontend/package-lock.json`、源码调用
> 路径和 `Dockerfile`。依赖升级或构建方式变化后必须重跑；本文不是法律意见。

## 结论

当前依赖不妨碍 OpsComposer 项目自有代码按 `AGPL-3.0-only` 发布。Pydantic 2.13.4、PrimeVue
4.5.5、PrimeIcons 7.0.0 和 Aura 所属的 `@primeuix/themes` 1.2.5 均按 MIT 提供；未发现
PrimeVue Premium Template 或 Theme Designer 商业素材。

但是，“未来可双许可证”只适用于项目确实控制权利的代码。CLA 不会把第三方组件变成商业代码，
也不会自动修复 CLA 生效前的提交。**当前组合不能直接视为已经完成专有商业发行清权。**

## 关键风险

### 1. Ansible 执行栈是高风险 Copyleft 边界

`ansible-core` 2.19.12 为 GPL-3.0-or-later。`ansible-runner` 2.4.3 的包级元数据和顶层许可证
为 Apache-2.0，但其正常运行时加载的
`ansible_runner/display_callback/callback/awx_display.py` 明示 GPL-3.0-or-later。当前后端在同一
Python 进程中直接调用 Runner，因此不能仅凭包元数据把整个路径标为 Apache-2.0。

AGPL-3.0 与 GPLv3 组合有许可证提供的兼容机制，但未来专有发行必须单独解决这一边界。上线商业
许可证前，应由律师评估，并优先考虑把 Ansible 执行器拆成独立进程/容器和稳定协议、让商业交付物
不包含该实现，或取得明确的额外授权。项目商业许可证不得声称覆盖 Ansible 自身。

### 2. psycopg-binary 与本地库

`psycopg`、`psycopg-pool` 和 `psycopg-binary` 为 LGPL-3.0-only。Binary wheel 还携带多个本地
动态库。发行容器时必须保留通知和许可证，满足 LGPL 对修改、替换/重新链接和对应源码的要求，
并逐一确认 wheel 内本地库的来源。降低风险的技术方向是改用系统 `libpq` 构建，而不是把
`psycopg-binary` 作为长期生产发行依赖；该调整需要另行测试，不能只改许可证声明。

### 3. MPL 与静态前端通知

`certifi` 为 MPL-2.0，修改其覆盖文件时存在文件级源码义务。前端生产 Bundle 会去掉
`node_modules`，所以仅在构建机保留 MIT 文件不够。构建脚本现将非开发 npm 包的许可证/NOTICE
复制到 `dist/legal/npm/`，发行时不得删除该目录。

### 4. 容器不是“只有应用代码”

最终镜像还包含 Python/Debian 基础镜像、OpenSSH、`sshpass`（GPL-2.0-or-later）、tini、
util-linux、CA 证书和从独立镜像复制的 uv/uvx。必须保留 Debian `/usr/share/doc/*/copyright`、
Python `.dist-info` 许可证、uv 双许可证文本和项目第三方通知。公开 OCI 镜像时，还要为适用的
GPL/LGPL/MPL 部件保留可追溯的精确对应源码或有效获取方式。

### 5. 镜像标签与证据留存

基础镜像当前按标签引用而非 Digest。相同标签内容可能变化，导致 SBOM、漏洞和许可证结论不可复现。
正式发行应固定 Digest，并保存构建日志、锁文件、SBOM、扫描报告、上游源码版本和许可证包。

## 每次发行的强制清单

1. 冻结并评审 `uv.lock`、`package-lock.json` 和所有容器 Digest。
2. 生成包含 Python、npm、系统包、本地库和基础镜像的 SBOM；不能只扫直接依赖。
3. 运行许可证扫描，并人工复核 `UNKNOWN`、双许可证、Copyleft、Vendor 与生成代码。
4. 核对 `THIRD_PARTY_NOTICES.md`，并确认所有上游 LICENSE/NOTICE 实际进入源码包和镜像。
5. 对 AGPL 网络部署提供醒目的对应源码入口；对应源码应含构建、安装和修改所需脚本。
6. 对二进制/镜像分发履行 AGPL/GPL/LGPL/MPL 的源码与通知义务，并记录提供期限。
7. 逐提交核实项目自有代码的权利人、雇主许可和 CLA 版本/签署证据。
8. 商业版本逐组件确认“包含、隔离、替换或另行授权”，不得把项目 CLA 当成第三方授权。
9. 由适用司法辖区的律师审查商业许可、CLA、服务合同、隐私和出口/制裁要求。

## 当前发布门禁

- AGPL 源码发布：可行，但必须带完整 `LICENSE`、第三方通知、依赖许可证和对应源码入口。
- 社区容器发布：完成上述容器通知、SBOM、源码留存和 Digest 固定后再发布。
- 专有商业组合发行：**尚未清权**；至少受 Ansible 边界、历史贡献权利链和容器依赖影响。
- 付费部署/迁移/加固：可以按独立服务合同开展，但不会改变客户的软件许可证义务。

依赖名称、版本和主要许可证索引见 [THIRD_PARTY_NOTICES.md](../../THIRD_PARTY_NOTICES.md)。
