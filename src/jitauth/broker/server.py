"""JITAuth FastAPI broker application."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

from jitauth import __version__
from jitauth.broker.middleware import RateLimiter, RequestSizeLimiter
from jitauth.broker.routes import router
from jitauth.db.session import init_db


def _load_adapters_from_config() -> None:
    """Load adapter configurations from YAML file on startup."""
    import logging
    from pathlib import Path

    import yaml

    from jitauth.config.settings import get_settings
    from jitauth.proxy.base import AdapterConfig
    from jitauth.proxy.gateway import register_adapter_config

    logger = logging.getLogger(__name__)
    settings = get_settings()

    if not settings.adapters_config:
        return

    config_path = Path(settings.adapters_config)
    if not config_path.exists():
        logger.warning("Adapter config file not found: %s", config_path)
        return

    try:
        with open(config_path) as f:
            doc = yaml.safe_load(f)
    except Exception as e:
        logger.error("Failed to load adapter config: %s", e)
        return

    if not doc or "adapters" not in doc:
        return

    for adapter_def in doc["adapters"]:
        config = AdapterConfig(
            system_name=adapter_def["system_name"],
            adapter_type=adapter_def["adapter_type"],
            config=adapter_def.get("config", {}),
            credentials=adapter_def.get("credentials"),
            redact_keys=set(adapter_def.get("redact_keys", [])),
            redact_result=adapter_def.get("redact_result", False),
        )
        register_adapter_config(config)
        logger.info("Loaded adapter config: %s (%s)", config.system_name, config.adapter_type)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize DB and load configs on startup."""
    init_db()
    _load_adapters_from_config()
    yield


def create_app(
    rate_limit: bool = True,
    requests_per_minute: int = 120,
) -> FastAPI:
    """Create the JITAuth broker FastAPI application.

    Args:
        rate_limit: Whether to enable rate limiting middleware.
        requests_per_minute: Max requests per client IP per minute.
    """
    app = FastAPI(
        title="JITAuth Broker",
        description="Just-in-time, task-scoped authentication and authorization for AI agents",
        version=__version__,
        lifespan=lifespan,
    )

    # Security middleware (order matters — size check first, then rate limit)
    app.add_middleware(RequestSizeLimiter, max_body_bytes=1_048_576)
    if rate_limit:
        app.add_middleware(RateLimiter, requests_per_minute=requests_per_minute)

    app.include_router(router)
    return app


app = create_app()
