"""HTTP / SSE / streamable-HTTP entrypoint for the DirectAdmin MCP server."""

from __future__ import annotations

import logging
import os
import secrets
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.routing import Mount

from config import settings, setup_logging
from mcp_instance import mcp
from security import (
    constant_time_token_match,
    ip_in_cidrs,
    rate_limiter,
    write_audit,
)

logger = logging.getLogger(__name__)


def _client_ip(request: Request) -> str:
    # Do not trust X-Forwarded-For unless you terminate TLS on a local proxy
    # and set MCP_TRUST_FORWARDED=true yourself later. Default = socket peer.
    if request.client:
        return request.client.host
    return "0.0.0.0"


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Lock down browser-facing responses. This is an ops API, not a public site."""

    async def dispatch(self, request: Request, call_next):
        length = request.headers.get("content-length")
        if length and length.isdigit() and int(length) > settings.MCP_MAX_BODY_BYTES:
            return JSONResponse({"error": "payload_too_large"}, status_code=413)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Robots-Tag"] = "noindex"
        return response


class GateMiddleware(BaseHTTPMiddleware):
    """Bearer token + CIDR + rate-limit for every HTTP route except /health."""

    PUBLIC = {"/health", "/favicon.ico"}

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if path in self.PUBLIC or path.startswith("/health"):
            return await call_next(request)

        ip = _client_ip(request)
        if settings.allowed_cidrs and not ip_in_cidrs(ip, settings.allowed_cidrs):
            write_audit("http_cidr_deny", ip=ip, path=path)
            return JSONResponse({"error": "forbidden"}, status_code=403)

        identity = ip
        expected = settings.MCP_AUTH_TOKEN.get_secret_value()
        if expected:
            provided = request.headers.get("authorization") or request.query_params.get("token")
            if not constant_time_token_match(provided, expected):
                write_audit("http_auth_fail", ip=ip, path=path)
                return JSONResponse({"error": "unauthorized"}, status_code=401)
            identity = "token"
        elif not settings.MCP_ALLOW_ANONYMOUS:
            write_audit("http_auth_missing_config", ip=ip, path=path)
            return JSONResponse(
                {
                    "error": "server_misconfigured",
                    "message": "Set MCP_AUTH_TOKEN or (dev only) MCP_ALLOW_ANONYMOUS=true",
                },
                status_code=503,
            )

        if not rate_limiter.allow(identity):
            write_audit("http_rate_limited", ip=ip, path=path)
            return JSONResponse({"error": "rate_limited"}, status_code=429)

        return await call_next(request)


@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_logging()
    os.makedirs("logs", exist_ok=True)
    logger.info("=" * 60)
    logger.info("DirectAdmin MCP Server starting")
    logger.info("config=%s", settings.public_dict())
    if not settings.MCP_AUTH_TOKEN.get_secret_value() and not settings.MCP_ALLOW_ANONYMOUS:
        logger.warning(
            "MCP_AUTH_TOKEN is empty. HTTP mode will refuse connections. "
            "Generate one with: python -c \"import secrets; print(secrets.token_urlsafe(48))\""
        )
    import tools

    loaded = tools.load_all_tools()
    logger.info("Loaded %d tool modules: %s", len(loaded), ", ".join(loaded))
    yield
    logger.info("DirectAdmin MCP Server shutting down")


app = FastAPI(
    title="DirectAdmin MCP Server",
    description="Model Context Protocol bridge for the DirectAdmin New API + CSF + SSL.",
    version="2.0.0",
    lifespan=lifespan,
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url=None,
    openapi_url="/openapi.json" if settings.DEBUG else None,
)

if settings.cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type", "Accept"],
    )

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(GateMiddleware)

# SSE transport (legacy MCP)
try:
    from mcp.server.sse import SseServerTransport

    sse = SseServerTransport("/messages/")
    app.router.routes.append(Mount("/messages", app=sse.handle_post_message))
except Exception as exc:  # pragma: no cover
    sse = None
    logger.warning("SSE transport unavailable: %s", exc)


@app.get("/", response_class=HTMLResponse)
async def homepage() -> str:
    return """<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>DirectAdmin MCP</title>
<style>
  :root { color-scheme: dark; }
  body { font: 16px/1.5 ui-sans-serif, system-ui; margin: 0; background: #0c1014; color: #e6edf3; }
  main { max-width: 720px; margin: 0 auto; padding: 3rem 1.25rem; }
  h1 { font-size: 1.75rem; letter-spacing: -0.03em; }
  a { color: #3d9cf0; }
  code { background: #141a21; padding: 0.1em 0.35em; border-radius: 4px; }
  .card { background: #141a21; border: 1px solid #243040; border-radius: 12px; padding: 1.25rem; }
</style></head>
<body><main>
  <h1>DirectAdmin MCP Server</h1>
  <p>Bridge between an AI assistant and a DirectAdmin admin account. Prefer stdio locally; this HTTP port is for SSE / streamable HTTP.</p>
  <div class="card">
    <p><strong>Health</strong> — <a href="/health">/health</a></p>
    <p><strong>SSE</strong> — <code>/sse</code></p>
    <p><strong>Tools</strong> — <a href="/mcp/tools">/mcp/tools</a></p>
  </div>
</main></body></html>"""


@app.get("/health")
async def health():
    from da import DirectAdminError, client

    da_ok = False
    version = None
    error = None
    try:
        version = await client.call_api("/api/version")
        da_ok = True
    except DirectAdminError as exc:
        error = str(exc)
    except Exception as exc:
        error = str(exc)
    tools = []
    try:
        tools = await mcp.list_tools()
    except Exception:
        pass
    status = "healthy" if da_ok else "degraded"
    payload = {
        "status": status,
        "version": "2.0.0",
        "directadmin": {"connected": da_ok, "version": version, "error": error},
        "mcp": {"tools": len(tools)},
    }
    return JSONResponse(payload, status_code=200 if da_ok else 503)


@app.get("/about")
async def about():
    tools = await mcp.list_tools()
    return {
        "name": "DirectAdmin MCP Server",
        "version": "2.0.0",
        "tools": len(tools),
        "config": settings.public_dict(),
    }


@app.get("/mcp/tools")
async def list_tools():
    tools = await mcp.list_tools()
    return {
        "count": len(tools),
        "tools": {
            tool.name: {
                "description": (tool.description or "").split("\n")[0],
            }
            for tool in tools
        },
    }


@app.get("/sse")
async def handle_sse(request: Request):
    if sse is None:
        raise HTTPException(status_code=501, detail="SSE transport not available")
    write_audit("sse_connect", ip=_client_ip(request))
    async with sse.connect_sse(request.scope, request.receive, request._send) as (read, write):
        await mcp._mcp_server.run(
            read,
            write,
            mcp._mcp_server.create_initialization_options(),
        )


def generate_token() -> str:
    return secrets.token_urlsafe(48)


if __name__ == "__main__":
    import uvicorn

    setup_logging()
    host = settings.MCP_HOST
    # Binding 0.0.0.0 without a token is refused
    if host in {"0.0.0.0", "::"} and not settings.MCP_AUTH_TOKEN.get_secret_value():
        raise SystemExit(
            "Refusing to bind 0.0.0.0 without MCP_AUTH_TOKEN. "
            "Set MCP_HOST=127.0.0.1 or provide a token."
        )
    if settings.DA_LOGIN_KEY.get_secret_value() in {"", "unset", "replace-with-login-key"}:
        raise SystemExit(
            "DA_LOGIN_KEY is unset. Create a login key in DirectAdmin and put it in .env."
        )
    logger.info("Starting HTTP MCP on %s:%s", host, settings.PORT)
    uvicorn.run(
        "main:app",
        host=host,
        port=settings.PORT,
        reload=settings.DEBUG,
        proxy_headers=False,
        forwarded_allow_ips="",
        server_header=False,
    )
