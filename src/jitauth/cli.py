"""JITAuth CLI entry point."""

from __future__ import annotations

import click


@click.group()
@click.version_option(package_name="jitauth")
def main():
    """JITAuth — Just-in-time, task-scoped auth for AI agents."""
    pass


@main.command()
@click.option("--host", default="127.0.0.1", help="Bind address")
@click.option("--port", default=8700, type=int, help="Bind port")
@click.option("--reload", is_flag=True, help="Enable auto-reload for development")
def serve(host: str, port: int, reload: bool):
    """Start the JITAuth broker server."""
    import uvicorn

    click.echo(f"Starting JITAuth broker on {host}:{port}")
    uvicorn.run(
        "jitauth.broker.server:app",
        host=host,
        port=port,
        reload=reload,
    )


@main.command()
def init_db():
    """Initialize the database (create tables)."""
    from jitauth.db.session import init_db as _init_db

    _init_db()
    click.echo("Database initialized.")


@main.command("mcp-serve")
@click.option("--adapters", default="adapters.yaml", help="Path to adapters YAML config")
@click.option("--transport", default="stdio", type=click.Choice(["stdio", "sse"]))
@click.option("--name", default="jitauth", help="MCP server name")
@click.option("--requester-id", default="mcp_agent", help="Default requester ID")
@click.option("--runtime-id", default="mcp_runtime", help="Runtime ID")
@click.option("--trust-tier", default="low", help="Trust tier for this runtime")
@click.option("--api-key", default=None, envvar="JITAUTH_MCP_API_KEY",
              help="API key for broker authentication (or set JITAUTH_MCP_API_KEY)")
def mcp_serve(
    adapters: str,
    transport: str,
    name: str,
    requester_id: str,
    runtime_id: str,
    trust_tier: str,
    api_key: str | None,
):
    """Start JITAuth as an MCP server.

    Exposes governed tools to any MCP-compatible agent.
    The broker must be running separately (jitauth serve).
    """
    try:
        from jitauth.mcp.server import create_mcp_server
    except ImportError as exc:
        click.echo(
            "MCP support requires the 'mcp' package. "
            "Install with: pip install jitauth[mcp]"
        )
        raise SystemExit(1) from exc

    click.echo(f"Starting JITAuth MCP server ({transport} transport)")
    click.echo(f"  Adapters config: {adapters}")
    click.echo(f"  Runtime: {runtime_id} (trust: {trust_tier})")
    if api_key:
        click.echo("  API key: configured")

    server = create_mcp_server(
        name=name,
        adapters_config=adapters,
        requester_id=requester_id,
        runtime_id=runtime_id,
        runtime_trust_tier=trust_tier,
        api_key=api_key,
    )

    if transport == "stdio":
        import asyncio
        asyncio.run(server.run_stdio_async())
    else:
        import asyncio
        asyncio.run(server.run_sse_async())


@main.command("openapi")
@click.option("--output", "-o", default="openapi.json", help="Output file path")
@click.option("--format", "fmt", default="json", type=click.Choice(["json", "yaml"]))
def export_openapi(output: str, fmt: str):
    """Export the OpenAPI specification."""
    import json

    from jitauth.broker.server import create_app

    app = create_app(rate_limit=False)
    schema = app.openapi()

    if fmt == "yaml":
        import yaml
        content = yaml.dump(schema, default_flow_style=False, sort_keys=False)
    else:
        content = json.dumps(schema, indent=2)

    with open(output, "w") as f:
        f.write(content)

    click.echo(f"OpenAPI spec written to {output}")
    click.echo(f"  Version: {schema['info']['version']}")
    click.echo(f"  Endpoints: {len(schema['paths'])}")


if __name__ == "__main__":
    main()
