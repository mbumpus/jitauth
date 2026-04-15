"""JITAuth MCP Server.

Exposes JITAuth-governed tools as an MCP server. Any MCP-compatible agent
(Claude, LangChain, CrewAI, etc.) can connect and get governed tool access.

The server:
1. Registers tools from adapter configs
2. On each tool call: creates task → classifies → evaluates policy →
   mints capability → executes → audits
3. Agents see only the tools they're allowed to use
4. Credentials never reach the agent — the broker proxies everything

Usage:
    # As a standalone MCP server:
    jitauth mcp-serve --adapters adapters.yaml --policies policies/

    # Programmatic:
    from jitauth.mcp.server import create_mcp_server
    server = create_mcp_server(adapters_config="adapters.yaml")
    server.run()
"""

from __future__ import annotations

import json
import logging
from typing import Any

from mcp.server.fastmcp import FastMCP

from jitauth.config.settings import get_settings

logger = logging.getLogger(__name__)


def create_mcp_server(
    name: str = "jitauth",
    adapters_config: str | None = None,
    requester_id: str = "mcp_agent",
    runtime_id: str = "mcp_runtime",
    runtime_type: str = "llm_orchestrator",
    runtime_trust_tier: str = "low",
    api_key: str | None = None,
) -> FastMCP:
    """Create an MCP server with JITAuth-governed tools.

    Each adapter action becomes an MCP tool. When an agent calls a tool,
    the full TRSAA lifecycle runs: task → classify → policy → capability → execute → audit.

    Args:
        name: MCP server name
        adapters_config: Path to adapters YAML config
        requester_id: Default requester ID for tasks
        runtime_id: Runtime ID for this MCP server
        runtime_type: Runtime type
        runtime_trust_tier: Trust tier for this runtime

    Returns:
        A configured FastMCP server instance
    """
    mcp = FastMCP(name)

    # Store config for tool handlers
    _server_ctx = {
        "requester_id": requester_id,
        "runtime_id": runtime_id,
        "runtime_type": runtime_type,
        "runtime_trust_tier": runtime_trust_tier,
        "api_key": api_key,
    }

    # Load adapter configs if provided
    if adapters_config:
        from jitauth.config.loader import load_adapter_configs
        configs = load_adapter_configs(adapters_config)
        for config in configs:
            _register_adapter_tools(mcp, config, _server_ctx)

    # Always register governance tools (task management, audit)
    _register_governance_tools(mcp, _server_ctx)

    return mcp


def _register_adapter_tools(
    mcp: FastMCP,
    adapter_config: Any,
    server_ctx: dict,
) -> None:
    """Register MCP tools for each action in an adapter config."""
    system = adapter_config.system_name
    adapter_type = adapter_config.adapter_type

    if adapter_type == "http":
        actions = adapter_config.config.get("actions", {})
    elif adapter_type == "shell":
        actions = adapter_config.config.get("commands", {})
    else:
        logger.warning("Unknown adapter type %s for system %s", adapter_type, system)
        return

    for action_name, action_def in actions.items():
        tool_name = f"{system}__{action_name}"
        description = _build_tool_description(system, action_name, action_def, adapter_type)
        action_class = _infer_action_class(action_name, action_def, adapter_type)

        # Build parameter schema from the action definition
        params_schema = _build_params_schema(action_def, adapter_type)

        # Create the tool handler closure
        _register_tool(
            mcp, tool_name, description, params_schema,
            system, action_name, action_class, server_ctx,
        )

        logger.info(
            "Registered MCP tool: %s (system=%s, action=%s)",
            tool_name, system, action_name,
        )


def _register_tool(
    mcp: FastMCP,
    tool_name: str,
    description: str,
    params_schema: dict,
    system: str,
    action_name: str,
    action_class: str,
    server_ctx: dict,
) -> None:
    """Register a single MCP tool with JITAuth governance."""

    @mcp.tool(name=tool_name, description=description)
    async def governed_tool(**kwargs) -> str:
        """Execute a governed tool call."""
        return await _execute_governed(
            system=system,
            action=action_name,
            action_class=action_class,
            arguments=kwargs,
            server_ctx=server_ctx,
        )


def _register_governance_tools(mcp: FastMCP, server_ctx: dict) -> None:
    """Register meta-tools for task governance (audit, approval, etc.)."""

    @mcp.tool(
        name="jitauth__audit_query",
        description=(
            "Query the JITAuth audit trail for a task. Returns the full lifecycle "
            "of actions, policy decisions, and tool invocations for a given task ID."
        ),
    )
    async def audit_query(task_id: str) -> str:
        """Query audit trail for a task."""
        from jitauth.core.models import AuditEvent
        from jitauth.db.session import get_session_factory, init_db

        init_db()
        db = get_session_factory()()
        try:
            events = (
                db.query(AuditEvent)
                .filter(AuditEvent.task_id == task_id)
                .order_by(AuditEvent.timestamp.asc())
                .all()
            )
            result = [
                {
                    "event_type": e.event_type,
                    "actor": e.actor,
                    "details": e.details,
                    "timestamp": e.timestamp.isoformat(),
                }
                for e in events
            ]
            return json.dumps(result, indent=2)
        finally:
            db.close()

    @mcp.tool(
        name="jitauth__list_tools",
        description=(
            "List all available JITAuth-governed tools and their risk tiers. "
            "Use this to discover what tools are available before attempting to use them."
        ),
    )
    async def list_governed_tools() -> str:
        """List all registered tools."""
        from jitauth.proxy.gateway import _adapter_configs
        tools = []
        for system, config in _adapter_configs.items():
            if config.adapter_type == "http":
                actions = config.config.get("actions", {})
            elif config.adapter_type == "shell":
                actions = config.config.get("commands", {})
            else:
                continue

            for action_name in actions:
                tools.append({
                    "tool": f"{system}__{action_name}",
                    "system": system,
                    "action": action_name,
                    "adapter_type": config.adapter_type,
                })
        return json.dumps(tools, indent=2)


async def _execute_governed(
    system: str,
    action: str,
    action_class: str,
    arguments: dict,
    server_ctx: dict,
) -> str:
    """Execute a tool call through the full TRSAA governance pipeline.

    This is the core of the MCP integration: every tool call creates a task,
    evaluates policy, mints a capability, executes through the proxy, and
    logs everything to the audit trail.
    """
    from jitauth.sdk.client import ApprovalRequiredError, JITAuthClient, TaskDeniedError

    # Use the SDK client pointed at localhost broker
    settings = get_settings()
    broker_url = f"http://{settings.host}:{settings.port}"

    client = JITAuthClient(
        broker_url=broker_url,
        runtime_id=server_ctx["runtime_id"],
        runtime_type=server_ctx["runtime_type"],
        runtime_trust_tier=server_ctx["runtime_trust_tier"],
        api_key=server_ctx.get("api_key"),
    )

    try:
        async with client.task(
            requester=server_ctx["requester_id"],
            objective=f"MCP tool call: {system}.{action}",
            actions=[{
                "system": system,
                "action": action,
                "action_class": action_class,
            }],
            max_actions=1,
            time_limit_seconds=120,
        ) as task:
            result = await task.execute(f"{system}.{action}", arguments)
            return json.dumps({
                "success": True,
                "task_id": task.task_id,
                "result": result,
            }, indent=2, default=str)

    except TaskDeniedError as e:
        return json.dumps({
            "success": False,
            "error": "denied",
            "message": str(e),
            "hint": (
                "This action was denied by JITAuth policy. "
                "Try a less privileged action or contact an admin."
            ),
        }, indent=2)

    except ApprovalRequiredError as e:
        return json.dumps({
            "success": False,
            "error": "approval_required",
            "task_id": e.task_id,
            "message": str(e),
            "hint": (
                f"This action requires human approval. "
                f"Approve via: POST /tasks/{e.task_id}/approve"
            ),
        }, indent=2)

    except Exception as e:
        logger.error("MCP governed execution failed: %s", e)
        return json.dumps({
            "success": False,
            "error": "execution_error",
            "message": str(e),
        }, indent=2)

    finally:
        await client.close()


def _build_tool_description(
    system: str,
    action_name: str,
    action_def: dict,
    adapter_type: str,
) -> str:
    """Build a human-readable tool description."""
    parts = [f"[JITAuth governed] {system}.{action_name}"]

    if adapter_type == "http":
        method = action_def.get("method", "GET")
        path = action_def.get("path", "")
        parts.append(f"HTTP {method} {path}")
    elif adapter_type == "shell":
        template = action_def.get("template", "")
        parts.append(f"Command: {template}")

    parts.append(
        "This tool call is governed by JITAuth policy. "
        "Access is task-scoped and time-limited."
    )
    return " | ".join(parts)


def _infer_action_class(
    action_name: str,
    action_def: dict,
    adapter_type: str,
) -> str:
    """Infer the action class from the action definition."""
    if adapter_type == "http":
        method = action_def.get("method", "GET").upper()
        method_map = {
            "GET": "read",
            "HEAD": "read",
            "OPTIONS": "read",
            "POST": "write",
            "PUT": "write",
            "PATCH": "write",
            "DELETE": "delete",
        }
        return method_map.get(method, "read")

    if adapter_type == "shell":
        return "execute"

    # Keyword-based inference
    name_lower = action_name.lower()
    if any(kw in name_lower for kw in ("read", "get", "list", "fetch", "query")):
        return "read"
    if any(kw in name_lower for kw in ("delete", "remove", "drop")):
        return "delete"
    if any(kw in name_lower for kw in ("send", "email", "notify")):
        return "send"
    if any(kw in name_lower for kw in ("publish", "deploy", "release")):
        return "publish"
    if any(kw in name_lower for kw in ("write", "create", "update", "insert", "add")):
        return "write"

    return "read"  # Safe default


def _build_params_schema(action_def: dict, adapter_type: str) -> dict:
    """Build a JSON schema for tool parameters."""
    if adapter_type == "http":
        # Extract path parameters from URL template
        path = action_def.get("path", "")
        import re
        params = re.findall(r'\$\{(\w+)\}', path)

        # Add body template params
        body = action_def.get("body_template", {})
        if body:
            for v in body.values():
                if isinstance(v, str):
                    params.extend(re.findall(r'\$\{(\w+)\}', v))

        properties = {p: {"type": "string", "description": f"Parameter: {p}"} for p in set(params)}
        return {"type": "object", "properties": properties}

    elif adapter_type == "shell":
        param_specs = action_def.get("params", {})
        properties = {}
        for name, spec in param_specs.items():
            ptype = spec.get("type", "string")
            prop: dict[str, Any] = {
                "description": f"Parameter: {name}",
            }
            if ptype == "int":
                prop["type"] = "integer"
                if "min" in spec:
                    prop["minimum"] = spec["min"]
                if "max" in spec:
                    prop["maximum"] = spec["max"]
            elif ptype == "enum":
                prop["type"] = "string"
                prop["enum"] = spec.get("values", [])
            else:
                prop["type"] = "string"
            properties[name] = prop

        return {"type": "object", "properties": properties}

    return {"type": "object", "properties": {}}
