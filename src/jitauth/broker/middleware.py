"""Security middleware for the JITAuth broker.

Provides rate limiting and request size limiting.
"""

from __future__ import annotations

import time
from collections import defaultdict
from collections.abc import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse


class RateLimiter(BaseHTTPMiddleware):
    """Simple in-memory sliding-window rate limiter.

    Limits requests per client IP. In production, swap for Redis-backed.

    Args:
        app: The ASGI application.
        requests_per_minute: Maximum requests per client per minute.
        burst: Maximum burst allowance above the per-minute rate.
    """

    def __init__(self, app, requests_per_minute: int = 120, burst: int = 20):
        super().__init__(app)
        self.rpm = requests_per_minute
        self.burst = burst
        self.window = 60.0  # seconds
        self._requests: dict[str, list[float]] = defaultdict(list)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        client_ip = request.client.host if request.client else "unknown"
        now = time.monotonic()

        # Clean old entries
        cutoff = now - self.window
        self._requests[client_ip] = [
            t for t in self._requests[client_ip] if t > cutoff
        ]

        count = len(self._requests[client_ip])
        limit = self.rpm + self.burst

        if count >= limit:
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded. Try again shortly."},
                headers={
                    "Retry-After": "60",
                    "X-RateLimit-Limit": str(self.rpm),
                    "X-RateLimit-Remaining": "0",
                },
            )

        self._requests[client_ip].append(now)

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(self.rpm)
        response.headers["X-RateLimit-Remaining"] = str(max(0, limit - count - 1))
        return response


class RequestSizeLimiter(BaseHTTPMiddleware):
    """Reject request bodies larger than a configured maximum.

    Args:
        app: The ASGI application.
        max_body_bytes: Maximum allowed request body size in bytes.
    """

    def __init__(self, app, max_body_bytes: int = 1_048_576):  # 1MB default
        super().__init__(app)
        self.max_body_bytes = max_body_bytes

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > self.max_body_bytes:
            return JSONResponse(
                status_code=413,
                content={
                    "detail": f"Request body too large. Maximum: {self.max_body_bytes} bytes."
                },
            )
        return await call_next(request)
