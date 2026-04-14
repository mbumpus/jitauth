"""Tests for the JITAuth MCP server.

Tests the MCP tool registration, governance pipeline, and tool discovery.
Uses the MCP server's internal functions directly (no transport layer needed).
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from jitauth.mcp.server import (
    _build_tool_description,
    _infer_action_class,
    _build_params_schema,
    create_mcp_server,
)
from jitauth.proxy.base import AdapterConfig, AdapterResult, BaseAdapter
from jitauth.proxy.gateway import clear_adapters, register_adapter, register_adapter_config


class MockCRMAdapter(BaseAdapter):
    supported_actions = ["read_account", "update_contact"]

    async def execute(self, action, arguments, credential=None):
        return AdapterResult(
            success=True,
            result={"action": action, "data": arguments},
        )


@pytest.fixture(autouse=True)
def _clean():
    clear_adapters()
    yield
    clear_adapters()


# ---------- Action class inference ----------


def test_infer_read_from_get():
    assert _infer_action_class("get_user", {"method": "GET"}, "http") == "read"


def test_infer_write_from_post():
    assert _infer_action_class("create_user", {"method": "POST"}, "http") == "write"


def test_infer_delete_from_method():
    assert _infer_action_class("remove_user", {"method": "DELETE"}, "http") == "delete"


def test_infer_execute_from_shell():
    assert _infer_action_class("run_build", {}, "shell") == "execute"


def test_infer_from_name_keywords():
    assert _infer_action_class("send_email", {}, "custom") == "send"
    assert _infer_action_class("publish_post", {}, "custom") == "publish"
    assert _infer_action_class("read_data", {}, "custom") == "read"
    assert _infer_action_class("delete_record", {}, "custom") == "delete"


# ---------- Tool description ----------


def test_tool_description_http():
    desc = _build_tool_description("crm", "read_account", {"method": "GET", "path": "/accounts/${id}"}, "http")
    assert "crm.read_account" in desc
    assert "GET" in desc
    assert "governed" in desc.lower()


def test_tool_description_shell():
    desc = _build_tool_description("devtools", "git_log", {"template": "git log -n ${count}"}, "shell")
    assert "devtools.git_log" in desc
    assert "git log" in desc


# ---------- Params schema ----------


def test_params_schema_http():
    schema = _build_params_schema(
        {"method": "GET", "path": "/accounts/${account_id}/contacts/${contact_id}"},
        "http",
    )
    assert "account_id" in schema["properties"]
    assert "contact_id" in schema["properties"]


def test_params_schema_shell():
    schema = _build_params_schema(
        {"template": "git log -n ${count}", "params": {
            "count": {"type": "int", "min": 1, "max": 100},
        }},
        "shell",
    )
    assert "count" in schema["properties"]
    assert schema["properties"]["count"]["type"] == "integer"


# ---------- MCP server creation ----------


def test_create_mcp_server_basic():
    """Server should create without errors."""
    server = create_mcp_server(name="test-jitauth")
    assert server.name == "test-jitauth"


def test_create_mcp_server_with_adapters(tmp_path):
    """Server should register tools from adapter config."""
    config_file = tmp_path / "adapters.yaml"
    config_file.write_text("""
adapters:
  - system_name: testapi
    adapter_type: http
    config:
      base_url: "https://api.example.com"
      actions:
        get_item:
          method: GET
          path: "/items/${item_id}"
        create_item:
          method: POST
          path: "/items"
          body_template:
            name: "${name}"
""")

    server = create_mcp_server(
        name="test-with-adapters",
        adapters_config=str(config_file),
    )
    assert server is not None
