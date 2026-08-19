"""Application settings. Secrets never appear in logs or repr()."""

from __future__ import annotations

import logging
import os
from typing import List, Optional

from dotenv import load_dotenv
from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

load_dotenv()

VERSION = "2.2.0"


class Settings(BaseSettings):
    """Environment-driven configuration with safe defaults."""

    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=True,
        extra="ignore",
    )

    DA_URL: str = Field(..., description="DirectAdmin base URL including port")
    DA_USERNAME: str = Field(..., description="DirectAdmin username")
    DA_LOGIN_KEY: SecretStr = Field(..., description="DirectAdmin login key")
    DA_IMPERSONATE: str = Field("", description="Optional default impersonation target")
    DA_SSL_VERIFY: bool = Field(True)
    DA_ALLOW_INSECURE_HTTP: bool = Field(False)
    DA_TIMEOUT: int = Field(45, ge=5, le=300)

    # Backwards compatible alias used by older forks
    SSL_VERIFY: Optional[bool] = Field(None)

    PORT: int = Field(8888, ge=1, le=65535)
    MCP_HOST: str = Field("127.0.0.1")
    LOG_LEVEL: str = Field("INFO")
    DEBUG: bool = Field(False)
    MCP_NAME: str = Field("directadmin")
    MCP_TRANSPORT: str = Field("sse")

    MCP_AUTH_TOKEN: SecretStr = Field(default=SecretStr(""))
    MCP_ALLOW_ANONYMOUS: bool = Field(False)
    MCP_CORS_ORIGINS: str = Field("")
    MCP_ALLOWED_CIDRS: str = Field("")
    MCP_MAX_BODY_BYTES: int = Field(1_048_576, ge=1024, le=16_777_216)

    TOOL_ALLOWLIST: str = Field("")
    TOOL_DENYLIST: str = Field("da_execute,csf_disable")
    REQUIRE_CONFIRM: bool = Field(True)
    ENABLE_EXECUTE: bool = Field(False)
    ENABLE_CSF: bool = Field(True)
    ENABLE_CSF_DISABLE: bool = Field(False)
    RATE_LIMIT_PER_MINUTE: int = Field(60, ge=0)
    AUDIT_LOG: str = Field("logs/audit.jsonl")

    @field_validator("DA_URL")
    @classmethod
    def _strip_slash(cls, value: str) -> str:
        return value.strip().rstrip("/")

    @field_validator("LOG_LEVEL")
    @classmethod
    def _level(cls, value: str) -> str:
        value = value.upper()
        if value not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError("LOG_LEVEL must be a standard logging level")
        return value

    @field_validator("MCP_AUTH_TOKEN")
    @classmethod
    def _token_length(cls, value: SecretStr) -> SecretStr:
        raw = value.get_secret_value() if isinstance(value, SecretStr) else str(value or "")
        if raw and len(raw) < 24:
            raise ValueError("MCP_AUTH_TOKEN must be at least 24 characters")
        return value if isinstance(value, SecretStr) else SecretStr(raw)

    @property
    def ssl_verify(self) -> bool:
        if self.SSL_VERIFY is not None:
            return bool(self.SSL_VERIFY)
        return self.DA_SSL_VERIFY

    @property
    def cors_origins(self) -> List[str]:
        return [item.strip() for item in self.MCP_CORS_ORIGINS.split(",") if item.strip()]

    @property
    def allowed_cidrs(self) -> List[str]:
        return [item.strip() for item in self.MCP_ALLOWED_CIDRS.split(",") if item.strip()]

    @property
    def tool_allowlist(self) -> List[str]:
        return [item.strip() for item in self.TOOL_ALLOWLIST.split(",") if item.strip()]

    @property
    def tool_denylist(self) -> List[str]:
        return [item.strip() for item in self.TOOL_DENYLIST.split(",") if item.strip()]

    def public_dict(self) -> dict:
        """Safe view for logs / /about — secrets replaced."""
        dumped = self.model_dump()
        for key in list(dumped):
            if any(part in key.lower() for part in ("key", "token", "password", "secret")):
                dumped[key] = "********" if dumped[key] else ""
        return dumped


def _load_settings() -> Settings:
    # Allow importing modules (and unit tests) without a live DirectAdmin box.
    if not os.getenv("DA_URL"):
        os.environ.setdefault("DA_URL", "https://127.0.0.1:2222")
        os.environ.setdefault("DA_USERNAME", "admin")
        os.environ.setdefault("DA_LOGIN_KEY", "unset")
    return Settings()


settings = _load_settings()


class _RedactingFormatter(logging.Formatter):
    """Strip login keys / bearer tokens if they ever leak into a log line."""

    def format(self, record: logging.LogRecord) -> str:
        message = super().format(record)
        key = settings.DA_LOGIN_KEY.get_secret_value()
        token = settings.MCP_AUTH_TOKEN.get_secret_value()
        if key and key != "unset":
            message = message.replace(key, "********")
        if token:
            message = message.replace(token, "********")
        return message


def setup_logging() -> logging.Logger:
    """Configure console + rotating file logging with secret redaction."""
    os.makedirs("logs", exist_ok=True)
    level = getattr(logging, settings.LOG_LEVEL)

    console_fmt = _RedactingFormatter(
        "%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    file_fmt = _RedactingFormatter(
        "%(asctime)s %(levelname)s %(name)s %(pathname)s:%(lineno)d: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    console = logging.StreamHandler()
    console.setLevel(level)
    console.setFormatter(console_fmt)

    from logging.handlers import RotatingFileHandler

    file_handler = RotatingFileHandler(
        "logs/directadmin_mcp.log", maxBytes=5 * 1024 * 1024, backupCount=5
    )
    file_handler.setLevel(level)
    file_handler.setFormatter(file_fmt)

    error_handler = RotatingFileHandler(
        "logs/error.log", maxBytes=2 * 1024 * 1024, backupCount=5
    )
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(file_fmt)

    root = logging.getLogger()
    root.setLevel(level)
    for handler in root.handlers[:]:
        root.removeHandler(handler)
    root.addHandler(console)
    root.addHandler(file_handler)
    root.addHandler(error_handler)

    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    return root


logger = logging.getLogger(__name__)
