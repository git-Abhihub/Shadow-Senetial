"""Optional bearer-token guard for state-changing API requests.

Keep ShadowLens local by default. When SHADOWLENS_API_TOKEN is configured,
all POST routes require the matching Bearer token; the token is never logged.
"""
import hmac
import os

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware


class OptionalLocalAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.method == "POST":
            expected = os.getenv("SHADOWLENS_API_TOKEN", "").strip()
            if expected:
                supplied = request.headers.get("Authorization", "")
                scheme, _, token = supplied.partition(" ")
                if scheme.lower() != "bearer" or not token or not hmac.compare_digest(token, expected):
                    return JSONResponse(
                        status_code=401,
                        content={"detail": "Bearer token required for POST requests"},
                        headers={"WWW-Authenticate": "Bearer"},
                    )
        return await call_next(request)
