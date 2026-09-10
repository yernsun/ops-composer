# Container distribution

[简体中文](CONTAINER.zh-CN.md) | English

Official community images are published to the GitHub Container Registry at
`ghcr.io/yernsun/ops-composer`. They are part of the AGPL source distribution, not a commercial
license, warranty, hosted service, or support entitlement.

## Pull and run

Release images support `linux/amd64` and `linux/arm64`. For the current release:

```bash
docker pull ghcr.io/yernsun/ops-composer:v0.1.1
OPS_COMPOSER_IMAGE=ghcr.io/yernsun/ops-composer:v0.1.1 \
  docker compose up -d --no-build
```

`v0.1.1` and `0.1.1` identify the release, `0.1` follows the newest compatible patch release, and
`latest` follows the newest stable release. Tags are convenient pointers; use the manifest digest
recorded on the GitHub Release when deployment policy requires an immutable identity:

```bash
OPS_COMPOSER_IMAGE='ghcr.io/yernsun/ops-composer@sha256:<release-digest>' \
  docker compose up -d --no-build
```

The production Compose file still supports local builds. Do not add `--build` when the intent is to
run the reviewed registry image.

## Build and publication controls

The [container workflow](.github/workflows/container-image.yml) builds and scans the image for pull
requests and `main`. A matching semantic-version tag publishes a multi-platform image. A manual or
reusable invocation can rebuild only an existing semantic-version tag; it cannot select an
arbitrary branch as release source.

The publication path:

- verifies that the Git tag, backend version, frontend version, API version, and system-reported
  version agree;
- uses full-SHA-pinned GitHub Actions and digest-pinned Node, Python, and uv base images;
- blocks publication on detected critical vulnerabilities and preserves the complete Trivy JSON
  report;
- publishes BuildKit image SBOM and provenance attestations, embeds a complete frontend build-
  dependency SPDX inventory, and adds a GitHub build-provenance attestation;
- records the OCI manifest digest and exports SBOM, scan, and checksum evidence to the matching
  GitHub Release; and
- labels the image with its exact source revision, source URL, creation time, version, and license.

The workflow and pinned base images still require deliberate review when updated. An automated
scan is evidence, not a legal opinion or a guarantee that no vulnerability exists.

## Verification

Compare the pulled manifest with the digest asset on the matching GitHub Release:

```bash
docker buildx imagetools inspect ghcr.io/yernsun/ops-composer:v0.1.1
```

With GitHub CLI installed, verify the GitHub artifact attestation against this repository:

```bash
gh attestation verify \
  oci://ghcr.io/yernsun/ops-composer@sha256:<release-digest> \
  --repo yernsun/ops-composer
```

BuildKit's registry-attached SBOM can also be inspected without executing the image:

```bash
docker buildx imagetools inspect \
  ghcr.io/yernsun/ops-composer@sha256:<release-digest> \
  --format '{{ json .SBOM }}'
```

## Source and notices

The OCI `org.opencontainers.image.revision` label identifies the exact commit. The embedded
`/app/static/legal/frontend-build.spdx.json` intentionally includes frontend build dependencies as
well as runtime dependencies; the registry-attached image SBOM describes the resulting platform
images. Corresponding source,
including the Dockerfile, build workflow, dependency locks, and installation scripts, is available
from the matching Git tag at <https://github.com/yernsun/ops-composer/tags>. Preserve that material
when redistributing the image or running a modified version as a network service.

Project and third-party notices are retained under `/app/legal`; the web bundle also contains its
legal files under `/app/static/legal`. Upstream components remain under their own licenses. Review
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and the
[dependency compliance notes](docs/legal/dependency-compliance.md) before redistribution.

Community support is best-effort and has no SLA. See [SUPPORT.md](SUPPORT.md) for support and
voluntary-funding boundaries.
