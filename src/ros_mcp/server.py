"""MCP stdio entry point for the RouterOS gateway."""

from __future__ import annotations

import argparse
from collections.abc import AsyncIterator, Callable, Sequence
from contextlib import asynccontextmanager
from functools import partial
from pathlib import Path
from typing import cast

from mcp.server.fastmcp import Context, FastMCP
from mcp.types import ToolAnnotations

from ros_mcp.gateway import Gateway, create_gateway_from_env, create_gateway_from_file
from ros_mcp.models import CommandResult, DeviceListResult

GatewayFactory = Callable[[], Gateway]

INSTRUCTIONS = """\
Manage configured MikroTik RouterOS devices over SSH. Call device_list to find device IDs.
Use command_read for print, export, get, and monitor commands; use command_execute for
anything that changes state. Commands are RouterOS CLI lines such as
"/ip address print where interface=ether1". Results with status "unknown" may have taken
effect: inspect the device before retrying a change."""


def create_server(
    gateway_factory: GatewayFactory = create_gateway_from_env,
) -> FastMCP[Gateway]:
    """Create the MCP server without opening stdio or connecting to a device."""

    @asynccontextmanager
    async def lifespan(_: FastMCP[Gateway]) -> AsyncIterator[Gateway]:
        gateway = gateway_factory()
        try:
            yield gateway
        finally:
            await gateway.aclose()

    server = FastMCP[Gateway](
        "ros-mcp",
        instructions=INSTRUCTIONS,
        lifespan=lifespan,
        log_level="ERROR",
    )

    @server.tool(
        structured_output=True,
        annotations=ToolAnnotations(readOnlyHint=True, idempotentHint=True, openWorldHint=False),
    )
    def device_list(*, ctx: Context) -> DeviceListResult:
        """List configured RouterOS devices without connecting to them or exposing credentials."""
        gateway = cast(Gateway, ctx.request_context.lifespan_context)
        return gateway.device_list()

    @server.tool(
        structured_output=True,
        annotations=ToolAnnotations(
            readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True
        ),
    )
    async def command_read(device: str, command: str, *, ctx: Context) -> CommandResult:
        """Run one read-only RouterOS command: print, export, get, monitor, or monitor-traffic.

        Examples: "/ip address print", "/interface print stats where running",
        "/ip firewall filter export terse", "/interface monitor-traffic ether1 once".
        Scripting (; [ ] { } $ :commands) and the file= and show-sensitive arguments are
        rejected. The device checks the command before it runs. Read results are safe to retry.
        """
        gateway = cast(Gateway, ctx.request_context.lifespan_context)
        return await gateway.command_read(device=device, command=command)

    @server.tool(
        structured_output=True,
        annotations=ToolAnnotations(
            readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True
        ),
    )
    async def command_execute(
        device: str,
        command: str,
        dry_run: bool = False,
        *,
        ctx: Context,
    ) -> CommandResult:
        """Run one RouterOS CLI line that may change device state.

        The device first syntax-checks the command; syntax errors return status "rejected"
        without running anything. dry_run=true stops after that check and returns
        "validated" (it does not check values, references, or effects). Status "failed" means
        RouterOS reported an error, and earlier statements in the line may have taken effect.
        Status "unknown" means the command may have taken effect: inspect the device before
        retrying.
        """
        gateway = cast(Gateway, ctx.request_context.lifespan_context)
        return await gateway.command_execute(
            device=device,
            command=command,
            dry_run=dry_run,
        )

    return server


def main(argv: Sequence[str] | None = None) -> None:
    """Run the gateway using MCP's stdio transport."""

    parser = argparse.ArgumentParser(description="Run the RouterOS MCP gateway over stdio.")
    parser.add_argument(
        "--config",
        type=Path,
        metavar="PATH",
        help="read the device registry JSON from PATH instead of ROS_DEVICES_JSON",
    )
    arguments = parser.parse_args(argv)

    gateway_factory: GatewayFactory = create_gateway_from_env
    if arguments.config is not None:
        gateway_factory = partial(create_gateway_from_file, arguments.config)

    create_server(gateway_factory).run(transport="stdio")
