FROM node:24-bookworm-slim AS frontend-builder

WORKDIR /build/frontend
ARG VITE_API_BASE_URL=""
ENV VITE_API_BASE_URL=$VITE_API_BASE_URL
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build


FROM ghcr.io/astral-sh/uv:0.12.5 AS uv-bin


FROM python:3.13-slim-bookworm AS runtime

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        ca-certificates \
        openssh-client \
        sshpass \
        tini \
        util-linux \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 ops-composer \
    && useradd --system --uid 10001 --gid ops-composer --home-dir /app ops-composer

COPY --from=uv-bin /uv /uvx /usr/local/bin/
WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src \
    PATH=/app/.venv/bin:$PATH \
    OPS_COMPOSER_STATIC_DIR=/app/static \
    OPS_COMPOSER_PLAYBOOK_WORKSPACE=/workspace \
    OPS_COMPOSER_RUNTIME_DIR=/var/lib/ops-composer/runtime

COPY backend/pyproject.toml backend/uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project --extra auth
COPY backend/src ./src
RUN uv sync --frozen --no-dev --extra auth
COPY --from=frontend-builder /build/frontend/dist ./static

RUN mkdir -p /workspace /var/lib/ops-composer/runtime \
    && chown -R ops-composer:ops-composer /app /var/lib/ops-composer \
    && chmod 0700 /var/lib/ops-composer/runtime

USER ops-composer
EXPOSE 8000
ENTRYPOINT ["tini", "--"]
CMD ["fastapi", "run", "--host", "0.0.0.0", "--port", "8000"]
