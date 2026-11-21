from __future__ import annotations

import json

import pytest

from ros_mcp.device_registry import DeviceRegistry
from ros_mcp.gateway import MAX_COMMAND_BYTES, Gateway
from ros_mcp.models import CommandStatus, ResolvedDevice
from ros_mcp.routeros import parse_check_script
from ros_mcp.ssh import SSHAdapterError, SSHExecution

FINGERPRINT = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"


def registry(*, enabled: bool = True) -> DeviceRegistry:
    devices = {
        "main": {
            "display_name": "Main Router",
            "host": "192.0.2.1",
            "username": "ai-mgmt",
            "enabled": enabled,
            "auth": {"type": "password", "password_env": "MAIN_PASSWORD"},
            "host_key": {"fingerprint_sha256": FINGERPRINT},
        }
    }
    return DeviceRegistry.from_env(
        {"ROS_DEVICES_JSON": json.dumps(devices), "MAIN_PASSWORD": "secret"}
    )


def completed(output: bytes, *, exit_code: int = 0, truncated: bool = False) -> SSHExecution:
    return SSHExecution(
        completed=True,
        exit_code=exit_code,
        output=output,
        tail=output[-1024:],
        truncated=truncated,
    )


def lost(output: bytes = b"", *, timed_out: bool = True) -> SSHExecution:
    return SSHExecution(
        completed=False,
        exit_code=None,
        output=output,
        tail=output,
        truncated=False,
        timed_out=timed_out,
    )


class FakeSSH:
    """Answer each command from a script; unscripted commands fail the test."""

    def __init__(self, responses: dict[str, SSHExecution | Exception]) -> None:
        self.responses = responses
        self.calls: list[str] = []
        self.closed = 0

    async def execute(
        self,
        device: ResolvedDevice,
        command: str,
        *,
        output_limit_bytes: int | None = None,
    ) -> SSHExecution:
        assert device.device == "main"
        self.calls.append(command)
        response = self.responses[command]
        if isinstance(response, Exception):
            raise response
        return response

    async def aclose(self) -> None:
        self.closed += 1


def parses(command: str, printed: bytes) -> dict[str, SSHExecution | Exception]:
    return {parse_check_script(command): completed(printed + b"\r\n")}


def test_device_list_is_local_and_contains_no_secret() -> None:
    ssh = FakeSSH({})

    result = Gateway(registry(), ssh).device_list()

    assert [device.device for device in result.devices] == ["main"]
    assert result.devices[0].display_name == "Main Router"
    assert "secret" not in result.model_dump_json()
    assert ssh.calls == []


async def test_read_runs_after_the_device_confirms_a_read_verb() -> None:
    command = "/system identity print"
    ssh = FakeSSH(
        {
            **parses(command, b"(evl /system/identity/print)"),
            command: completed(b"  name: CCR1072   \r\n\r\n"),
        }
    )

    result = await Gateway(registry(), ssh).command_read("main", command)

    assert result.status is CommandStatus.SUCCEEDED
    assert result.output == "  name: CCR1072"
    assert result.error is None
    assert ssh.calls == [parse_check_script(command), command]


async def test_read_rejects_a_write_verb_without_running_it() -> None:
    command = "/system reboot"
    ssh = FakeSSH(parses(command, b"(evl /system/reboot)"))

    result = await Gateway(registry(), ssh).command_read("main", command)

    assert result.status is CommandStatus.REJECTED
    assert result.error is not None
    assert result.error.code == "READ_ONLY_VIOLATION"
    assert ssh.calls == [parse_check_script(command)]


async def test_read_rejects_scripting_without_contacting_the_device() -> None:
    ssh = FakeSSH({})

    result = await Gateway(registry(), ssh).command_read("main", "/ip address print; /x")

    assert result.status is CommandStatus.REJECTED
    assert result.error is not None
    assert result.error.code == "READ_ONLY_VIOLATION"
    assert ssh.calls == []


async def test_syntax_errors_are_rejected_before_execution() -> None:
    command = "/foo bar"
    ssh = FakeSSH(parses(command, b"(<%% bad command name foo (line 1 column 2) foo;bar)"))

    result = await Gateway(registry(), ssh).command_execute("main", command)

    assert result.status is CommandStatus.REJECTED
    assert result.error is not None
    assert result.error.code == "SYNTAX_ERROR"
    assert result.error.message == "bad command name foo (line 1 column 2)"
    assert ssh.calls == [parse_check_script(command)]


async def test_dry_run_stops_after_the_syntax_check() -> None:
    command = "/system reboot"
    ssh = FakeSSH(parses(command, b"(evl /system/reboot)"))

    result = await Gateway(registry(), ssh).command_execute("main", command, dry_run=True)

    assert result.status is CommandStatus.VALIDATED
    assert ssh.calls == [parse_check_script(command)]


async def test_routeros_error_text_fails_despite_exit_status_zero() -> None:
    command = "/ip address get 999 address"
    ssh = FakeSSH(
        {
            **parses(command, b"(evl /ip/address/getnumbers=999;value-name=address)"),
            command: completed(b"no such item (/ip/address/get; line 1)\n"),
        }
    )

    result = await Gateway(registry(), ssh).command_execute("main", command)

    assert result.status is CommandStatus.FAILED
    assert result.error is not None
    assert result.error.code == "ROUTEROS_ERROR"
    assert result.error.message == "no such item (/ip/address/get; line 1)"


async def test_error_after_truncated_output_is_still_detected() -> None:
    command = '/ip address print; :error "boom"'
    tail = b"...\r\nboom (:error; line 1)\n"
    ssh = FakeSSH(
        {
            **parses(command, b"(evl /ip/address/print);(evl /errormessage=boom)"),
            command: SSHExecution(
                completed=True, exit_code=0, output=b"head", tail=tail, truncated=True
            ),
        }
    )

    result = await Gateway(registry(), ssh).command_execute("main", command)

    assert result.status is CommandStatus.FAILED
    assert result.output == "head"
    assert result.output_truncated is True


async def test_unknown_change_is_not_retryable_but_unknown_read_is() -> None:
    change = "/system reboot"
    read = "/log print follow"
    ssh = FakeSSH(
        {
            **parses(change, b"(evl /system/reboot)"),
            change: lost(),
            **parses(read, b"(evl /log/printfollow=true)"),
            read: lost(b"partial\r\n"),
        }
    )
    gateway = Gateway(registry(), ssh)

    changed = await gateway.command_execute("main", change)
    observed = await gateway.command_read("main", read)

    assert changed.status is CommandStatus.UNKNOWN
    assert changed.error is not None
    assert changed.error.retryable is False
    assert observed.status is CommandStatus.UNKNOWN
    assert observed.output == "partial"
    assert observed.error is not None
    assert observed.error.retryable is True


async def test_incomplete_syntax_check_never_runs_the_command() -> None:
    command = "/system reboot"
    ssh = FakeSSH({parse_check_script(command): lost()})

    result = await Gateway(registry(), ssh).command_execute("main", command)

    assert result.status is CommandStatus.REJECTED
    assert result.error is not None
    assert result.error.code == "SYNTAX_CHECK_FAILED"
    assert result.error.retryable is True
    assert ssh.calls == [parse_check_script(command)]


async def test_predispatch_ssh_error_is_structured() -> None:
    command = "/system resource print"
    ssh = FakeSSH(
        {parse_check_script(command): SSHAdapterError("SSH_AUTH_FAILED", "SSH auth failed")}
    )

    result = await Gateway(registry(), ssh).command_read("main", command)

    assert result.status is CommandStatus.REJECTED
    assert result.error is not None
    assert result.error.code == "SSH_AUTH_FAILED"


@pytest.mark.parametrize(
    ("device", "command", "code"),
    [
        ("missing", "/system resource print", "DEVICE_NOT_FOUND"),
        ("Main", "/system resource print", "INVALID_DEVICE"),
        ("main", "", "INVALID_COMMAND"),
        ("main", "   ", "INVALID_COMMAND"),
        ("main", "one\ntwo", "INVALID_COMMAND"),
        ("main", "one\x00two", "INVALID_COMMAND"),
        ("main", "x" * (MAX_COMMAND_BYTES + 1), "INVALID_COMMAND"),
    ],
)
async def test_invalid_requests_never_use_ssh(device: str, command: str, code: str) -> None:
    ssh = FakeSSH({})

    result = await Gateway(registry(), ssh).command_execute(device, command)

    assert result.status is CommandStatus.REJECTED
    assert result.error is not None
    assert result.error.code == code
    assert ssh.calls == []


async def test_disabled_device_and_close() -> None:
    ssh = FakeSSH({})
    gateway = Gateway(registry(enabled=False), ssh)

    result = await gateway.command_read("main", "/system resource print")
    await gateway.aclose()

    assert result.error is not None
    assert result.error.code == "DEVICE_DISABLED"
    assert ssh.calls == []
    assert ssh.closed == 1
