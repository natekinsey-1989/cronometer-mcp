"""Remote (HTTP) entry point for cronometer-mcp, for hosting on Railway or similar.

The original package only exposes a stdio transport (see server.main()), meant
for a local MCP client that spawns this as a subprocess. This module runs the
same FastMCP server over Streamable HTTP instead, so it can be reached as a
remote MCP connector (e.g. added to Claude via a URL).

Because this server can read AND write your Cronometer account (diary
entries, biometrics, recurring foods) and holds your real Cronometer login
in its environment, the HTTP endpoint is gated behind a shared-secret token.
Set MCP_AUTH_TOKEN in the deployment environment, then every request to
/mcp must present that token either as `Authorization: Bearer <token>` or
as a `?token=<token>` query parameter.

The query-param form exists because Claude's "Add custom connector" UI only
accepts a URL — there's no field for a custom header — so the token has to
be embeddable directly in the connector URL
(https://your-app/mcp?token=...) to actually be usable there.

If MCP_AUTH_TOKEN is not set, the server refuses to start in HTTP mode —
better to fail loudly than to accidentally expose an unauthenticated,
write-capable endpoint to the internet.
"""

import logging
import os

import uvicorn
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from .server import mcp

logger = logging.getLogger(__name__)


class BearerAuthMiddleware(BaseHTTPMiddleware):
    """Reject any /mcp request that doesn't present the shared-secret token."""

    def __init__(self, app, token: str):
        super().__init__(app)
        self._token = token

    async def dispatch(self, request: Request, call_next):
        # Leave the plain health-check route open so Railway's health check
        # (and a human with the URL) can confirm the service is up without
        # needing the secret.
        if request.url.path == "/":
            return await call_next(request)

        header_ok = request.headers.get("authorization", "") == f"Bearer {self._token}"
        query_ok = request.query_params.get("token", "") == self._token
        if not (header_ok or query_ok):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        return await call_next(request)


def build_app():
    token = os.environ.get("MCP_AUTH_TOKEN")
    if not token:
        raise RuntimeError(
            "MCP_AUTH_TOKEN is not set. Refusing to start the HTTP transport "
            "without an auth token, since this server can write to your "
            "Cronometer account. Set MCP_AUTH_TOKEN in the environment "
            "(e.g. Railway variables) and redeploy."
        )

    app = mcp.streamable_http_app()

    # Plain, unauthenticated health-check route for Railway's health check
    # and for a human sanity-checking that the service is up.
    async def health(request):
        return JSONResponse({"service": "cronometer-mcp", "status": "running"})

    app.routes.append(Route("/", health, methods=["GET"]))

    # Order matters: the middleware added LAST wraps the ones added before
    # it, so CORS (added last, outermost) handles OPTIONS preflight before
    # any request reaches the bearer check underneath it.
    app.add_middleware(BearerAuthMiddleware, token=token)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=[
            "Content-Type",
            "Accept",
            "Authorization",
            "mcp-session-id",
            "Mcp-Session-Id",
        ],
        expose_headers=["mcp-session-id", "Mcp-Session-Id"],
    )

    return app


def main():
    logging.basicConfig(level=logging.INFO)
    port = int(os.environ.get("PORT", "3000"))
    app = build_app()
    logger.info("cronometer-mcp (HTTP) listening on 0.0.0.0:%s, endpoint /mcp", port)
    uvicorn.run(app, host="0.0.0.0", port=port)


if __name__ == "__main__":
    main()
