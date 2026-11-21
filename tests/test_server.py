from __future__ import annotations

from pathlib import Path
from typing import Any

from mcp.shared.memory import create_connected_server_and_client_session

import ros_mcp.server as server_module
from ros_mcp.models import CommandResult, CommandStatus, DeviceListResult, DeviceSummary
from ros_mcp.server import create_server


def make_device_list_result() -> DeviceListResult:
    return DeviceListResult(
        devices=(
            DeviceSummary(
                device="main",
                display_name="Main Router",
                description="Internet edge",
                host="192.168.88.1",
                enabled=True,
                tags=("production", "edge"),
            ),
        ),
    )


class FakeGateway:
    def __init__(self) -> None:
        self.list_calls = 0
        self.calls: list[tuple[str, str, str, bool]] = []
        self.close_calls = 0

    def device_list(self) -> DeviceListResult:
        self.list_calls += 1
        return make_device_list_result()

    async def command_read(self, device: str, command: str) -> CommandResult:
        self.calls.append(("read", device, command, False))
        return CommandResult(
            device=device, status=CommandStatus.SUCCEEDED, output="uptime: 1d", duration_ms=12
        )

    async def command_execute(
        self, device: str, command: str, dry_run: bool = False
    ) -> CommandResult:
        self.calls.append(("execute", device, command, dry_run))
        return CommandResult(device=device, status=CommandStatus.VALIDATED, duration_ms=3)

    async def aclose(self) -> None:
        self.close_calls += 1


async def test_server_registers_read_and_change_tools_with_safety_hints() -> None:
    server = create_server(FakeGateway)  # type: ignore[arg-type]

    tools = {tool.name: tool for tool in await server.list_tools()}

    assert set(tools) == {"device_list", "command_read", "command_execute"}
    assert tools["device_list"].inputSchema["properties"] == {}
    assert tools["device_list"].outputSchema == DeviceListResult.model_json_schema()

    read = tools["command_read"]
    assert set(read.inputSchema["properties"]) == {"device", "command"}
    assert read.annotations is not None
    assert read.annotations.readOnlyHint is True
    assert read.annotations.destructiveHint is False

    execute = tools["command_execute"]
    assert execute.inputSchema["properties"]["dry_run"]["default"] is False
    assert execute.inputSchema["required"] == ["device", "command"]
    assert execute.outputSchema == CommandResult.model_json_schema()
    assert execute.annotations is not None
    assert execute.annotations.readOnlyHint is False
    assert execute.annotations.destructiveHint is True


async def test_tools_share_one_gateway_and_close_it_with_the_session() -> None:
    gateway = FakeGateway()
    factory_calls = 0

    def factory() -> FakeGateway:
        nonlocal factory_calls
        factory_calls += 1
        return gateway

    server = create_server(factory)  # type: ignore[arg-type]
    assert factory_calls == 0

    async with create_connected_server_and_client_session(server) as session:
        assert factory_calls == 1

        listed = await session.call_tool("device_list", {})
        read = await session.call_tool(
            "command_read", {"device": "main", "command": "/system resource print"}
        )
        validated = await session.call_tool(
            "command_execute",
            {"device": "main", "command": "/system reboot", "dry_run": True},
        )

        assert listed.isError is False
        assert listed.structuredContent == make_device_list_result().model_dump(mode="json")
        assert read.isError is False
        assert read.structuredContent is not None
        assert read.structuredContent["status"] == "succeeded"
        assert read.structuredContent["output"] == "uptime: 1d"
        assert validated.isError is False
        assert validated.structuredContent is not None
        assert validated.structuredContent["status"] == "validated"

    assert factory_calls == 1
    assert gateway.list_calls == 1
    assert gateway.calls == [
        ("read", "main", "/system resource print", False),
        ("execute", "main", "/system reboot", True),
    ]
    assert gateway.close_calls == 1


def test_main_runs_stdio_without_writing_to_stdout(monkeypatch: Any, capsys: Any) -> None:
    transports: list[str] = []

    class FakeServer:
        def __init__(self, *_: object) -> None:
            pass

        def run(self, *, transport: str) -> None:
            transports.append(transport)

    monkeypatch.setattr(server_module, "create_server", FakeServer)

    server_module.main([])

    assert transports == ["stdio"]
    assert capsys.readouterr().out == ""


def test_main_uses_a_configuration_file_when_requested(monkeypatch: Any) -> None:
    captured_factory: object | None = None
    transports: list[str] = []

    class FakeServer:
        def run(self, *, transport: str) -> None:
            transports.append(transport)

    def fake_create_server(factory: object) -> FakeServer:
        nonlocal captured_factory
        captured_factory = factory
        return FakeServer()

    monkeypatch.setattr(server_module, "create_server", fake_create_server)

    server_module.main(["--config", "/config/devices.json"])

    assert transports == ["stdio"]
    assert captured_factory is not None
    assert captured_factory.func is server_module.create_gateway_from_file
    assert captured_factory.args == (Path("/config/devices.json"),)
