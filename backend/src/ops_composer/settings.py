from __future__ import annotations

from enum import StrEnum
from functools import lru_cache
from ipaddress import ip_address, ip_network
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

DEVELOPMENT_DATABASE_URL = "postgresql://ops_composer:ops_composer@localhost:5432/ops_composer"
DEVELOPMENT_RATE_LIMIT_SECRET = "development-only-auth-rate-limit-secret"
DEVELOPMENT_MASTER_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
COOKIE_PREFIX = "ops-composer"


class AppEnvironment(StrEnum):
    DEVELOPMENT = "development"
    TEST = "test"
    PRODUCTION = "production"


class Settings(BaseSettings):
    """Validated process configuration shared by the API, CLI, and worker."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore", populate_by_name=True)

    app_env: AppEnvironment = Field(default=AppEnvironment.DEVELOPMENT, validation_alias="APP_ENV")
    database_url: str = Field(default=DEVELOPMENT_DATABASE_URL, validation_alias="DATABASE_URL")
    allowed_origins_csv: str = Field(
        default="http://localhost:5173", validation_alias="APP_ALLOWED_ORIGINS"
    )
    forwarded_allow_ips_csv: str = Field(default="", validation_alias="FORWARDED_ALLOW_IPS")
    session_cookie_secure: bool | None = Field(
        default=None, validation_alias="APP_SESSION_COOKIE_SECURE"
    )
    session_ttl_seconds: int = Field(
        default=60 * 60 * 24 * 14, ge=300, validation_alias="APP_SESSION_TTL_SECONDS"
    )
    auth_rate_limit_secret: SecretStr = Field(
        default=SecretStr(DEVELOPMENT_RATE_LIMIT_SECRET),
        validation_alias="APP_AUTH_RATE_LIMIT_SECRET",
    )
    auth_login_username_ip_limit: int = Field(
        default=5, ge=1, le=1000, validation_alias="APP_AUTH_LOGIN_USERNAME_IP_LIMIT"
    )
    auth_login_username_ip_window_seconds: int = Field(
        default=300,
        ge=10,
        le=86400,
        validation_alias="APP_AUTH_LOGIN_USERNAME_IP_WINDOW_SECONDS",
    )
    auth_login_ip_limit: int = Field(
        default=30, ge=1, le=1000, validation_alias="APP_AUTH_LOGIN_IP_LIMIT"
    )
    auth_login_ip_window_seconds: int = Field(
        default=300,
        ge=10,
        le=86400,
        validation_alias="APP_AUTH_LOGIN_IP_WINDOW_SECONDS",
    )
    master_key: SecretStr = Field(
        default=SecretStr(DEVELOPMENT_MASTER_KEY), validation_alias="OPS_COMPOSER_MASTER_KEY"
    )
    master_key_version: int = Field(
        default=1, ge=1, validation_alias="OPS_COMPOSER_MASTER_KEY_VERSION"
    )
    playbook_workspace: Path = Field(
        default=Path("/workspace"), validation_alias="OPS_COMPOSER_PLAYBOOK_WORKSPACE"
    )
    runtime_dir: Path = Field(
        default=Path("/tmp/ops-composer/runtime"), validation_alias="OPS_COMPOSER_RUNTIME_DIR"
    )
    static_dir: Path = Field(
        default=Path("/app/static"), validation_alias="OPS_COMPOSER_STATIC_DIR"
    )
    worker_poll_interval_seconds: float = Field(
        default=0.75,
        ge=0.1,
        le=30,
        validation_alias="OPS_COMPOSER_WORKER_POLL_INTERVAL_SECONDS",
    )
    worker_lease_seconds: int = Field(
        default=30, ge=5, le=600, validation_alias="OPS_COMPOSER_WORKER_LEASE_SECONDS"
    )
    worker_stale_after_seconds: int = Field(
        default=90,
        ge=10,
        le=3600,
        validation_alias="OPS_COMPOSER_WORKER_STALE_AFTER_SECONDS",
    )
    sse_poll_interval_seconds: float = Field(
        default=0.5,
        ge=0.1,
        le=10,
        validation_alias="OPS_COMPOSER_SSE_POLL_INTERVAL_SECONDS",
    )
    max_event_output_bytes: int = Field(
        default=64 * 1024,
        ge=1024,
        le=1024 * 1024,
        validation_alias="OPS_COMPOSER_MAX_EVENT_OUTPUT_BYTES",
    )
    max_run_output_bytes: int = Field(
        default=5 * 1024 * 1024,
        ge=64 * 1024,
        le=100 * 1024 * 1024,
        validation_alias="OPS_COMPOSER_MAX_RUN_OUTPUT_BYTES",
    )

    @model_validator(mode="after")
    def require_safe_production_settings(self) -> Settings:
        if self.app_env is not AppEnvironment.PRODUCTION:
            return self
        if self.database_url == DEVELOPMENT_DATABASE_URL:
            raise ValueError("production requires an explicit PostgreSQL database URL")
        if not self.database_url.startswith(("postgresql://", "postgresql+psycopg://")):
            raise ValueError("only PostgreSQL database URLs are supported")
        if not self.cookies_secure:
            raise ValueError("production requires secure session cookies")
        origins = self.allowed_origins
        if not origins or any(urlsplit(origin).scheme != "https" for origin in origins):
            raise ValueError("production allowed origins must be non-empty HTTPS origins")
        rate_limit_secret = self.auth_rate_limit_secret.get_secret_value()
        if (
            rate_limit_secret == DEVELOPMENT_RATE_LIMIT_SECRET
            or len(rate_limit_secret.encode()) < 32
        ):
            raise ValueError("production requires a unique 32-byte auth rate-limit secret")
        if self.master_key.get_secret_value() == DEVELOPMENT_MASTER_KEY:
            raise ValueError("production requires an explicit OPS_COMPOSER_MASTER_KEY")
        if not self.forwarded_allow_ips:
            raise ValueError("production requires explicit trusted proxy IPs or CIDRs")
        return self

    @property
    def allowed_origins(self) -> frozenset[str]:
        origins: set[str] = set()
        for value in self.allowed_origins_csv.split(","):
            origin = value.strip().rstrip("/")
            if not origin:
                continue
            parsed = urlsplit(origin)
            try:
                port = parsed.port
            except ValueError as error:
                raise ValueError("allowed origins must use a valid port") from error
            if (
                parsed.scheme not in {"http", "https"}
                or not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
                or parsed.path
                or parsed.query
                or parsed.fragment
                or (port is not None and not 1 <= port <= 65535)
            ):
                raise ValueError(
                    "allowed origins must be HTTP(S) origins without credentials or paths"
                )
            origins.add(origin)
        return frozenset(origins)

    @property
    def cookies_secure(self) -> bool:
        if self.session_cookie_secure is not None:
            return self.session_cookie_secure
        return self.app_env is AppEnvironment.PRODUCTION

    @property
    def forwarded_allow_ips(self) -> tuple[str, ...]:
        addresses = tuple(
            value.strip() for value in self.forwarded_allow_ips_csv.split(",") if value.strip()
        )
        for address in addresses:
            if address == "*":
                raise ValueError("FORWARDED_ALLOW_IPS must not trust every address")
            if "/" in address:
                try:
                    network = ip_network(address)
                except ValueError as error:
                    raise ValueError(
                        "FORWARDED_ALLOW_IPS must contain only valid IP addresses or CIDRs"
                    ) from error
                if network.prefixlen == 0:
                    raise ValueError("FORWARDED_ALLOW_IPS must not trust every address")
            else:
                try:
                    ip_address(address)
                except ValueError as error:
                    raise ValueError(
                        "FORWARDED_ALLOW_IPS must contain only valid IP addresses or CIDRs"
                    ) from error
        return addresses

    def safe_summary(self) -> dict[str, object]:
        return {
            "environment": self.app_env.value,
            "database": "postgresql",
            "database_configured": bool(self.database_url),
            "playbook_workspace": str(self.playbook_workspace),
            "runtime_dir": str(self.runtime_dir),
            "authentication": {
                "mode": "single-administrator",
                "allowed_origins": sorted(self.allowed_origins),
                "cookies_secure": self.cookies_secure,
                "session_ttl_seconds": self.session_ttl_seconds,
                "trusted_proxies": list(self.forwarded_allow_ips),
                "rate_limit_secret_configured": (
                    self.auth_rate_limit_secret.get_secret_value() != DEVELOPMENT_RATE_LIMIT_SECRET
                    and len(self.auth_rate_limit_secret.get_secret_value().encode()) >= 32
                ),
                "master_key_configured": (
                    self.master_key.get_secret_value() != DEVELOPMENT_MASTER_KEY
                ),
            },
        }

    @property
    def session_cookie_name(self) -> str:
        prefix = f"{COOKIE_PREFIX}-session"
        return f"__Host-{prefix}" if self.app_env is AppEnvironment.PRODUCTION else prefix

    @property
    def csrf_cookie_name(self) -> str:
        prefix = f"{COOKIE_PREFIX}-csrf"
        return f"__Host-{prefix}" if self.app_env is AppEnvironment.PRODUCTION else prefix


@lru_cache
def get_settings() -> Settings:
    return Settings()
