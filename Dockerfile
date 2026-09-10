FROM --platform=$BUILDPLATFORM node:24-bookworm-slim@sha256:2fe369e969550cde8e867afc3fe370b260140cab4a23d467074295b42163d553 AS frontend-builder

WORKDIR /build/frontend
ARG VITE_API_BASE_URL=""
ENV VITE_API_BASE_URL=$VITE_API_BASE_URL
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
COPY AGENTS.md LICENSE NOTICE.md THIRD_PARTY_NOTICES.md SUPPORT.md SUPPORT.zh-CN.md /build/
COPY SECURITY.md COMMERCIAL_SERVICES.md COMMERCIAL_SERVICES.zh-CN.md /build/
COPY CONTRIBUTING.md CONTRIBUTING.zh-CN.md CLA_POLICY.md CLA_POLICY.zh-CN.md /build/
COPY CONTAINER.md CONTAINER.zh-CN.md /build/
COPY third_party /build/third_party
COPY docs/legal/dependency-compliance.md /build/docs/legal/dependency-compliance.md
RUN npm run build


FROM ghcr.io/astral-sh/uv:0.12.5@sha256:e85be844203885286c60ffad8a858d48afb6c5a5c237ca0e67f12e74b8f174b1 AS uv-bin


FROM python:3.13-alpine3.23@sha256:75f27d686432419c9d42420b2b9ef605868c7a0682a6be10a6601fad46c2df01 AS runtime

ARG OPS_COMPOSER_VERSION=0.1.1
ARG OPS_COMPOSER_REVISION=unknown
ARG OPS_COMPOSER_CREATED=unknown

LABEL org.opencontainers.image.title="OpsComposer" \
    org.opencontainers.image.description="A multi-administrator Ansible operations console backed by PostgreSQL" \
    org.opencontainers.image.url="https://github.com/yernsun/ops-composer" \
    org.opencontainers.image.source="https://github.com/yernsun/ops-composer" \
    org.opencontainers.image.documentation="https://github.com/yernsun/ops-composer/blob/main/README.md" \
    org.opencontainers.image.licenses="AGPL-3.0-only" \
    org.opencontainers.image.version="$OPS_COMPOSER_VERSION" \
    org.opencontainers.image.revision="$OPS_COMPOSER_REVISION" \
    org.opencontainers.image.created="$OPS_COMPOSER_CREATED" \
    org.opencontainers.image.base.name="docker.io/library/python:3.13-alpine3.23" \
    org.opencontainers.image.base.digest="sha256:75f27d686432419c9d42420b2b9ef605868c7a0682a6be10a6601fad46c2df01"

RUN apk upgrade --no-cache \
    && apk add --no-cache \
        ca-certificates \
        openssh-client \
        sshpass \
        tini \
    && addgroup -S -g 10001 ops-composer \
    && adduser -S -D -H -h /var/lib/ops-composer -u 10001 -G ops-composer ops-composer

COPY --from=uv-bin /uv /uvx /usr/local/bin/
WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    HOME=/var/lib/ops-composer \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src \
    PATH=/app/.venv/bin:$PATH \
    OPS_COMPOSER_STATIC_DIR=/app/static \
    OPS_COMPOSER_PLAYBOOK_WORKSPACE=/workspace \
    OPS_COMPOSER_RUNTIME_DIR=/var/lib/ops-composer/runtime

COPY backend/pyproject.toml backend/uv.lock backend/LICENSE backend/NOTICE.md ./
COPY backend/licenses ./licenses
RUN uv sync --frozen --no-dev --no-install-project --extra auth
COPY backend/src ./src
RUN uv sync --frozen --no-dev --extra auth
COPY --from=frontend-builder /build/frontend/dist ./static
COPY LICENSE NOTICE.md THIRD_PARTY_NOTICES.md SUPPORT.md SUPPORT.zh-CN.md CONTAINER.md CONTAINER.zh-CN.md ./legal/
COPY SECURITY.md COMMERCIAL_SERVICES.md COMMERCIAL_SERVICES.zh-CN.md ./legal/
COPY CONTRIBUTING.md CONTRIBUTING.zh-CN.md CLA_POLICY.md CLA_POLICY.zh-CN.md ./legal/
COPY third_party ./legal/third_party

RUN mkdir -p /workspace /var/lib/ops-composer/runtime \
    && chown ops-composer:ops-composer /workspace \
    && chown -R ops-composer:ops-composer /var/lib/ops-composer \
    && chmod 0700 /var/lib/ops-composer/runtime

USER ops-composer
EXPOSE 8000
ENTRYPOINT ["tini", "--"]
CMD ["fastapi", "run", "--host", "0.0.0.0", "--port", "8000"]
