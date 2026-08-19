"""DirectAdmin HTTP client — New JSON API + legacy CMD_API_* + plugin posts."""

from __future__ import annotations

import base64
import json
import logging
from typing import Any, Dict, Mapping, Optional, Union
from urllib.parse import parse_qs

import httpx

from config import VERSION, settings
from security import SecurityError, redact, validate_da_url, validate_impersonate, write_audit

logger = logging.getLogger(__name__)


class DirectAdminError(Exception):
    def __init__(
        self,
        message: str,
        status_code: Optional[int] = None,
        response_data: Any = None,
    ) -> None:
        self.status_code = status_code
        self.response_data = response_data
        super().__init__(message)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "success": False,
            "error": True,
            "message": str(self),
            "status_code": self.status_code,
            "response_data": self.response_data,
        }


def _basic_token(username: str, secret: str, impersonate: str = "") -> str:
    account = f"{username}|{impersonate}" if impersonate else username
    raw = f"{account}:{secret}".encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def _parse_legacy(text: str) -> Any:
    """Parse DirectAdmin URL-encoded legacy payloads, including list[]."""
    if not text:
        return {}
    stripped = text.strip()
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            return json.loads(stripped)
        except json.JSONDecodeError:
            pass
    parsed = parse_qs(stripped, keep_blank_values=True)
    out: Dict[str, Any] = {}
    for key, values in parsed.items():
        if key.endswith("[]"):
            out[key[:-2]] = values
        elif len(values) == 1:
            out[key] = values[0]
        else:
            out[key] = values
    if "error" in out and str(out.get("error")) not in {"0", "false", ""}:
        raise DirectAdminError(
            out.get("text") or out.get("details") or "DirectAdmin legacy error",
            response_data=out,
        )
    return out


class DirectAdminClient:
    def __init__(
        self,
        base_url: Optional[str] = None,
        username: Optional[str] = None,
        login_key: Optional[str] = None,
        verify_ssl: Optional[bool] = None,
        impersonate: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> None:
        raw_url = base_url or settings.DA_URL
        self.base_url = validate_da_url(raw_url, settings.DA_ALLOW_INSECURE_HTTP)
        self.username = username or settings.DA_USERNAME
        self.login_key = login_key or settings.DA_LOGIN_KEY.get_secret_value()
        self.verify_ssl = settings.ssl_verify if verify_ssl is None else verify_ssl
        self.impersonate = validate_impersonate(
            impersonate if impersonate is not None else settings.DA_IMPERSONATE
        )
        self.timeout = timeout or settings.DA_TIMEOUT
        self._http: Optional[httpx.AsyncClient] = None

    def _ensure_http(self) -> httpx.AsyncClient:
        if self._http is None or self._http.is_closed:
            self._http = httpx.AsyncClient(
                follow_redirects=False,
                verify=self.verify_ssl,
                timeout=httpx.Timeout(self.timeout),
                limits=httpx.Limits(max_keepalive_connections=8, max_connections=16),
            )
        return self._http

    async def aclose(self) -> None:
        if self._http is not None and not self._http.is_closed:
            await self._http.aclose()
        self._http = None

    def _headers(self, impersonate: Optional[str], json_body: bool) -> Dict[str, str]:
        target = impersonate if impersonate is not None else self.impersonate
        target = validate_impersonate(target)
        headers = {
            "Authorization": f"Basic {_basic_token(self.username, self.login_key, target)}",
            "Accept": "application/json",
            "User-Agent": f"directadmin-mcp/{VERSION}",
        }
        if json_body:
            headers["Content-Type"] = "application/json"
        return headers

    async def request(
        self,
        path: str,
        method: str = "GET",
        data: Optional[Union[Mapping[str, Any], list]] = None,
        params: Optional[Mapping[str, Any]] = None,
        impersonate: Optional[str] = None,
        json_mode: bool = True,
        form: bool = False,
        timeout: Optional[int] = None,
        raw: bool = False,
    ) -> Any:
        if not path.startswith("/"):
            path = "/" + path
        # SSRF: only talk to the configured DirectAdmin origin
        url = f"{self.base_url}{path}"
        method = method.upper()
        if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
            raise SecurityError(f"HTTP method not allowed: {method}")

        logger.debug(
            "DA %s %s params=%s body=%s impersonate=%s",
            method,
            path,
            redact(dict(params or {})),
            redact(dict(data) if isinstance(data, Mapping) else data),
            impersonate or self.impersonate or "-",
        )

        try:
            http = self._ensure_http()
            kwargs: Dict[str, Any] = {
                "method": method,
                "url": url,
                "headers": self._headers(impersonate, json_body=json_mode and not form),
                "params": params,
                "timeout": timeout or self.timeout,
            }
            if method != "GET":
                if form:
                    kwargs["data"] = data
                    kwargs["headers"]["Content-Type"] = "application/x-www-form-urlencoded"
                elif json_mode:
                    kwargs["json"] = data
                else:
                    kwargs["data"] = data
            response = await http.request(**kwargs)
        except httpx.RequestError as exc:
            raise DirectAdminError(f"Cannot reach DirectAdmin: {exc}") from exc

        if response.status_code in {301, 302, 303, 307, 308}:
            location = response.headers.get("location", "unknown")
            raise DirectAdminError(
                f"Redirect from {path} → {location}. Usually a login-key / HTTPS mismatch.",
                status_code=response.status_code,
            )

        body_text = response.text
        parsed: Any
        try:
            parsed = response.json()
        except Exception:
            parsed = _parse_legacy(body_text) if not raw else body_text

        if response.status_code >= 400:
            write_audit(
                "da_http_error",
                method=method,
                path=path,
                status=response.status_code,
            )
            raise DirectAdminError(
                f"DirectAdmin {method} {path} failed ({response.status_code})",
                status_code=response.status_code,
                response_data=parsed if parsed else body_text[:500],
            )

        return parsed if not raw else body_text

    async def call_api(
        self,
        path: str,
        method: str = "GET",
        data: Optional[Dict[str, Any]] = None,
        timeout: int = 30,
        impersonate: Optional[str] = None,
    ) -> Any:
        """New JSON API helper (kept compatible with the original fork)."""
        return await self.request(
            path,
            method=method,
            data=data if method != "GET" else None,
            params=data if method == "GET" else None,
            impersonate=impersonate,
            json_mode=True,
            timeout=timeout,
        )

    async def call_legacy(
        self,
        command: str,
        method: str = "POST",
        data: Optional[Dict[str, Any]] = None,
        impersonate: Optional[str] = None,
    ) -> Any:
        """CMD_API_* / CMD_* helper. Forces json=yes when the command supports it."""
        if not command.startswith("/"):
            command = "/" + command
        payload = dict(data or {})
        payload.setdefault("json", "yes")
        return await self.request(
            command,
            method=method,
            data=payload if method != "GET" else None,
            params=payload if method == "GET" else None,
            impersonate=impersonate,
            json_mode=False,
            form=method != "GET",
        )

    async def call_plugin(
        self,
        plugin_path: str,
        data: Optional[Dict[str, Any]] = None,
        method: str = "POST",
        impersonate: Optional[str] = None,
    ) -> Any:
        """POST/GET a DirectAdmin plugin endpoint (CSF etc.). Returns parsed or raw text."""
        if not plugin_path.startswith("/"):
            plugin_path = "/" + plugin_path
        try:
            return await self.request(
                plugin_path,
                method=method,
                data=data if method != "GET" else None,
                params=data if method == "GET" else None,
                impersonate=impersonate,
                json_mode=False,
                form=method != "GET",
                raw=False,
            )
        except DirectAdminError:
            # Some skins return HTML; retry as raw text so the tool can still report.
            return await self.request(
                plugin_path,
                method=method,
                data=data if method != "GET" else None,
                params=data if method == "GET" else None,
                impersonate=impersonate,
                json_mode=False,
                form=method != "GET",
                raw=True,
            )


client = DirectAdminClient()


async def call_da_api(
    path: str,
    method: str = "GET",
    data: Optional[Dict[str, Any]] = None,
    impersonate: Optional[str] = None,
) -> Any:
    return await client.call_api(path, method, data, impersonate=impersonate)


async def call_da_legacy(
    command: str,
    method: str = "POST",
    data: Optional[Dict[str, Any]] = None,
    impersonate: Optional[str] = None,
) -> Any:
    return await client.call_legacy(command, method, data, impersonate=impersonate)
