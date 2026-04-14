"""JITAuth FastAPI broker application."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

from jitauth import __version__
from jitauth.broker.middleware import RateLimiter, RequestSizeLimiter
from jitauth.broker.routes import router
from jitauth.db.session import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize DB on startup."""
    init_db()
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
