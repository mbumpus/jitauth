"""Tests for the shell adapter — parameter validation and safety checks."""

from __future__ import annotations

import pytest

from jitauth.proxy.adapters.shell import ShellAdapter, _validate_param
from jitauth.proxy.base import AdapterConfig


@pytest.fixture
def shell_adapter():
    config = AdapterConfig(
        system_name="devtools",
        adapter_type="shell",
        config={
            "timeout_seconds": 10,
            "commands": {
                "echo_test": {
                    "template": "echo ${message}",
                    "params": {
                        "message": {
                            "type": "string",
                            "max_length": 50,
                            "pattern": "^[a-zA-Z0-9 ]+$",
                        }
                    },
                },
                "count_lines": {
                    "template": "echo -e 'one\\ntwo\\nthree' | head -n ${count}",
                    "params": {
                        "count": {"type": "int", "min": 1, "max": 10},
                    },
                },
            },
        },
    )
    return ShellAdapter(config)


# ---------- Parameter validation ----------


def test_validate_int_param():
    assert _validate_param("n", 5, {"type": "int", "min": 1, "max": 10}) is None
    assert _validate_param("n", 0, {"type": "int", "min": 1, "max": 10}) is not None
    assert _validate_param("n", 11, {"type": "int", "min": 1, "max": 10}) is not None
    assert _validate_param("n", "abc", {"type": "int"}) is not None


def test_validate_string_param():
    assert _validate_param("s", "hello", {"type": "string", "max_length": 10}) is None
    assert _validate_param("s", "a" * 11, {"type": "string", "max_length": 10}) is not None


def test_validate_dangerous_chars():
    """String params with shell injection chars should be rejected."""
    assert _validate_param("s", "hello; rm -rf /", {"type": "string"}) is not None
    assert _validate_param("s", "hello | cat", {"type": "string"}) is not None
    assert _validate_param("s", "$(whoami)", {"type": "string"}) is not None
    assert _validate_param("s", "hello`id`", {"type": "string"}) is not None


def test_validate_enum_param():
    spec = {"type": "enum", "values": ["asc", "desc"]}
    assert _validate_param("order", "asc", spec) is None
    assert _validate_param("order", "drop", spec) is not None


# ---------- Adapter execution ----------


@pytest.mark.asyncio
async def test_shell_echo(shell_adapter):
    result = await shell_adapter.execute("echo_test", {"message": "hello world"})
    assert result.success is True
    assert "hello world" in result.result["stdout"]


@pytest.mark.asyncio
async def test_shell_int_param(shell_adapter):
    result = await shell_adapter.execute("count_lines", {"count": 2})
    assert result.success is True
    lines = result.result["stdout"].strip().split("\n")
    assert len(lines) == 2


@pytest.mark.asyncio
async def test_shell_rejects_unlisted_command(shell_adapter):
    result = await shell_adapter.execute("rm_everything", {})
    assert result.success is False
    assert "not in the allowlist" in result.error


@pytest.mark.asyncio
async def test_shell_rejects_unexpected_params(shell_adapter):
    result = await shell_adapter.execute("echo_test", {
        "message": "hello",
        "extra_evil": "rm -rf /"
    })
    assert result.success is False
    assert "unexpected" in result.error.lower()


@pytest.mark.asyncio
async def test_shell_rejects_injection_attempt(shell_adapter):
    """Parameters with dangerous chars should be caught by validation."""
    result = await shell_adapter.execute("echo_test", {"message": "hello; rm -rf /"})
    assert result.success is False
