# 容器镜像发行

简体中文 | [English](CONTAINER.md)

官方社区镜像发布到 GitHub Container Registry：`ghcr.io/yernsun/ops-composer`。镜像属于 AGPL
源码发行的一部分，不构成商业许可证、保证、托管服务或支持权益。

## 拉取与运行

发行镜像支持 `linux/amd64` 和 `linux/arm64`。当前版本可按以下方式运行：

```bash
docker pull ghcr.io/yernsun/ops-composer:v0.1.1
OPS_COMPOSER_IMAGE=ghcr.io/yernsun/ops-composer:v0.1.1 \
  docker compose up -d --no-build
```

`v0.1.1` 与 `0.1.1` 指向该正式版本，`0.1` 跟随该 minor 系列的最新 patch，`latest` 跟随最新
稳定版本。Tag 只是便捷指针；部署策略要求不可变身份时，应使用对应 GitHub Release 中记录的
Manifest Digest：

```bash
OPS_COMPOSER_IMAGE='ghcr.io/yernsun/ops-composer@sha256:<release-digest>' \
  docker compose up -d --no-build
```

生产 Compose 仍支持本地构建。需要使用已审查的仓库镜像时，不要添加 `--build`。

## 构建与发布门禁

[容器工作流](.github/workflows/container-image.yml)会在 Pull Request 和 `main` 上构建并扫描镜像；
匹配的语义化版本 Tag 才会发布多平台镜像。手动或复用调用只能重新构建一个已经存在的语义化版本
Tag，不能任意选择分支作为发行源码。

发布流程会：

- 核对 Git Tag、后端版本、前端版本、API 版本和系统返回版本完全一致；
- 使用固定完整 Commit SHA 的 GitHub Actions，以及固定 Digest 的 Node、Python、uv 基础镜像；
- 对检测到的 Critical 漏洞阻断发布，并保留完整 Trivy JSON 报告；
- 发布 BuildKit 镜像 SBOM 与 provenance attestations，在镜像内保留完整前端构建依赖 SPDX 清单，
  并生成 GitHub 构建来源证明；
- 将 OCI Manifest Digest、SBOM、扫描报告及其校验值保存到对应 GitHub Release；
- 用准确源码 Commit、源码地址、创建时间、版本和许可证标记镜像。

工作流和基础镜像 Digest 升级时仍须人工审查。自动扫描只是证据，不是法律意见，也不保证不存在
任何漏洞。

## 验证

可将拉取到的 Manifest 与对应 GitHub Release 中的 Digest 文件核对：

```bash
docker buildx imagetools inspect ghcr.io/yernsun/ops-composer:v0.1.1
```

安装 GitHub CLI 后，可验证该仓库签发的 GitHub Artifact Attestation：

```bash
gh attestation verify \
  oci://ghcr.io/yernsun/ops-composer@sha256:<release-digest> \
  --repo yernsun/ops-composer
```

无需执行镜像也可查看 BuildKit 附加在 Registry 中的 SBOM：

```bash
docker buildx imagetools inspect \
  ghcr.io/yernsun/ops-composer@sha256:<release-digest> \
  --format '{{ json .SBOM }}'
```

## 对应源码与通知

OCI `org.opencontainers.image.revision` Label 标明了准确 Commit。镜像内的
`/app/static/legal/frontend-build.spdx.json` 有意同时列出前端构建依赖与运行依赖；Registry 附加的
镜像 SBOM 则描述最终各平台镜像。对应源码包含 Dockerfile、构建
工作流、依赖锁和安装脚本，可从匹配的 Git Tag 获取：
<https://github.com/yernsun/ops-composer/tags>。再次分发镜像或通过网络运行修改版时，必须保留并
履行相应源码义务。

项目与第三方通知保留在 `/app/legal`，Web Bundle 的法律文件同时位于 `/app/static/legal`。
上游组件继续适用各自许可证。再次分发前应阅读
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) 和
[依赖合规说明](docs/legal/dependency-compliance.md)。

社区支持仅为尽力而为且没有 SLA。支持和自愿资助边界见 [SUPPORT.zh-CN.md](SUPPORT.zh-CN.md)。
