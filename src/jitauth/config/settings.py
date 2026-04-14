"""JITAuth configuration."""

from __future__ import annotations

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings, loadable from env vars or .env file."""

    # Server
    host: str = "127.0.0.1"
    port: int = 8700
    debug: bool = False

    # Database
    database_url: str = "sqlite:///jitauth.db"

    # Security
    jwt_secret: str = "CHANGE-ME-IN-PRODUCTION"
    jwt_algorithm: str = "HS256"
    default_capability_ttl_seconds: int = 300  # 5 minutes
    max_capability_ttl_seconds: int = 900  # 15 minutes

    # Policy
    policy_dir: str = "policies"

    # Adapters
    adapters_config: str | None = None  # Path to adapters YAML config file

    # Audit
    audit_hash_chain: bool = True

    model_config = {
        "env_prefix": "JITAUTH_",
        "env_file": ".env",
    }


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def override_settings(settings: Settings) -> None:
    """For testing."""
    global _settings
    _settings = settings
