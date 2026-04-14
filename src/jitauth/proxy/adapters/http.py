"""HTTP/REST adapter for proxying API calls to downstream services.

This is the workhorse adapter — most SaaS APIs, cloud APIs, CRM/ERP
systems, and internal services can be reached through HTTP.

The adapter handles:
- URL template resolution
- Header injection (auth tokens, API keys)
- Request body construction
- Response sanitization (strip sensitive headers, truncate)
- Timeout enforcement
"""

from __future__ import annotations

import logging
from string import Template
from typing import Any

import httpx

from jitauth.proxy.base import AdapterConfig, AdapterResult, BaseAdapter

logger = logging.getLogger(__name__)

# Headers that should never be returned to the runtime
_SENSITIVE_RESPONSE_HEADERS = {
    "set-cookie",
    "x-api-key",
    "authorization",
    "www-authenticate",
    "proxy-authorization",
}

# Max response body size to return (bytes)
_MAX_RESPONSE_SIZE = 64 * 1024  # 64KB


class HTTPAdapter(BaseAdapter):
    """Adapter for HTTP/REST API targets.

    Config schema:
    ```yaml
    adapters:
      - system_name: crm
        adapter_type: http
        config:
          base_url: "https://api.example.com/v2"
          timeout_seconds: 30
          actions:
            read_account:
              method: GET
              path: "/accounts/${account_id}"
            update_contact:
              method: PATCH
              path: "/contacts/${contact_id}"
              body_template:
                field: "${field}"
                value: "${value}"
        credentials:
          type: bearer
          token: "${VAULT:crm_api_token}"
    ```
    """

    def __init__(self, config: AdapterConfig):
        super().__init__(config)
        self.base_url = config.config.get("base_url", "").rstrip("/")
        self.timeout = config.config.get("timeout_seconds", 30)
        self.actions_config = config.config.get("actions", {})
        self.supported_actions = list(self.actions_config.keys())

    async def execute(
        self,
        action: str,
        arguments: dict[str, Any],
        credential: dict[str, Any] | None = None,
    ) -> AdapterResult:
        if action not in self.actions_config:
            return AdapterResult(
                success=False,
                error=f"Unknown action '{action}' for system '{self.system_name}'",
            )

        action_def = self.actions_config[action]
        method = action_def.get("method", "GET").upper()
        path_template = action_def.get("path", "/")
        body_template = action_def.get("body_template")

        # Resolve path template with arguments
        try:
            path = Template(path_template).safe_substitute(arguments)
        except (KeyError, ValueError) as e:
            return AdapterResult(success=False, error=f"Path template error: {e}")

        url = f"{self.base_url}{path}"

        # Build headers with credential injection
        headers = {"Content-Type": "application/json", "User-Agent": "JITAuth-Proxy/0.1"}
        if credential:
            cred_type = credential.get("type", "bearer")
            if cred_type == "bearer":
                headers["Authorization"] = f"Bearer {credential.get('token', '')}"
            elif cred_type == "api_key":
                header_name = credential.get("header", "X-API-Key")
                headers[header_name] = credential.get("key", "")
            elif cred_type == "basic":
                import base64

                pair = f"{credential.get('username', '')}:{credential.get('password', '')}"
                encoded = base64.b64encode(pair.encode()).decode()
                headers["Authorization"] = f"Basic {encoded}"

        # Build request body
        body = None
        if body_template and method in ("POST", "PUT", "PATCH"):
            body = _resolve_template_dict(body_template, arguments)

        # Execute the request
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.request(
                    method=method,
                    url=url,
                    headers=headers,
                    json=body,
                )

            # Sanitize response
            sanitized_headers = {
                k: v
                for k, v in response.headers.items()
                if k.lower() not in _SENSITIVE_RESPONSE_HEADERS
            }

            # Parse response body
            result_body: dict | str | None = None
            if response.content:
                content_length = len(response.content)
                if content_length > _MAX_RESPONSE_SIZE:
                    result_body = (
                        f"[Response truncated: {content_length} bytes "
                        f"exceeds {_MAX_RESPONSE_SIZE} limit]"
                    )
                else:
                    try:
                        result_body = response.json()
                    except Exception:
                        result_body = response.text[:_MAX_RESPONSE_SIZE]

            success = 200 <= response.status_code < 400

            return AdapterResult(
                success=success,
                result={
                    "status_code": response.status_code,
                    "body": result_body,
                    "headers": sanitized_headers,
                }
                if success
                else None,
                error=f"HTTP {response.status_code}: {result_body}"
                if not success
                else None,
            )

        except httpx.TimeoutException:
            return AdapterResult(success=False, error=f"Request timed out after {self.timeout}s")
        except httpx.ConnectError as e:
            return AdapterResult(success=False, error=f"Connection failed: {e}")
        except Exception as e:
            logger.error("HTTP adapter error for %s/%s: %s", self.system_name, action, e)
            return AdapterResult(success=False, error=f"Adapter error: {type(e).__name__}: {e}")

    async def health_check(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.head(self.base_url)
                return resp.status_code < 500
        except Exception:
            return False


def _resolve_template_dict(template: dict, values: dict) -> dict:
    """Recursively resolve ${var} templates in a dict."""
    result = {}
    for k, v in template.items():
        if isinstance(v, str):
            result[k] = Template(v).safe_substitute(values)
        elif isinstance(v, dict):
            result[k] = _resolve_template_dict(v, values)
        elif isinstance(v, list):
            result[k] = [
                Template(item).safe_substitute(values) if isinstance(item, str) else item
                for item in v
            ]
        else:
            result[k] = v
    return result
