"""Entry point for the Janus MCP Proxy."""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import structlog

from janus.mcp.config import ProxyConfig, TransportType
from janus.mcp.proxy import JanusMCPProxy

logger = structlog.get_logger()


async def run_proxy(config_path: str | None = None) -> None:
    """Load config, set up proxy, and run the MCP server."""
    if config_path and Path(config_path).exists():
        config = ProxyConfig.from_toml(config_path)
    else:
        config = ProxyConfig()
        if config_path:
            logger.warning("config_not_found", path=config_path)

    proxy = JanusMCPProxy(config)
    await proxy.setup()

    try:
        if config.transport.type == TransportType.STDIO:
            import mcp.server.stdio

            async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
                await proxy.server.run(
                    read_stream,
                    write_stream,
                    proxy.get_initialization_options(),
                )
        elif config.transport.type == TransportType.HTTP:
            import uvicorn
            from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
            from starlette.applications import Starlette
            from starlette.routing import Mount

            session_manager = StreamableHTTPSessionManager(app=proxy.server)

            from contextlib import asynccontextmanager

            @asynccontextmanager
            async def lifespan(app):  # type: ignore[no-untyped-def]
                async with session_manager.run():
                    yield

            starlette_app = Starlette(
                routes=[Mount("/mcp", app=session_manager.handle_request)],
                lifespan=lifespan,
            )
            uvicorn_config = uvicorn.Config(
                starlette_app,
                host=config.transport.host,
                port=config.transport.port,
            )
            server = uvicorn.Server(uvicorn_config)
            await server.serve()
    finally:
        await proxy.teardown()


def main() -> None:
    """CLI entry point for janus-proxy."""
    try:
        import mcp  # noqa: F401
    except ImportError:
        print(
            "MCP support requires the integrations extra: "
            "pip install janus-security[integrations]"
        )
        sys.exit(1)

    config_path = sys.argv[1] if len(sys.argv) > 1 else "janus-proxy.toml"
    asyncio.run(run_proxy(config_path))


if __name__ == "__main__":
    main()
