"""Core RouterOS gateway behind the MCP tools."""

from __future__ import annotations

import asyncio
import re
import time
from collections.abc import Mapping
from pathlib import Path

from .device_registry import DeviceNotFoundError, DeviceRegistry
from .models import (
    DEVICE_ID_PATTERN,
    CommandError,
    CommandResult,
    CommandStatus,
    DeviceListResult,
    ResolvedDevice,
)
from .routeros import (
    ParsedCommand,
    interpret_parse_output,
    normalize_output,
    parse_check_script,
    read_only_violation,
    read_verb_violation,
    runtime_error,
)
from .ssh import ParamikoSSHAdapter, SSHAdapterError, SSHCommandPort, SSHExecution

MAX_COMMAND_BYTES = 8 * 1024
# A parse of an 8 KiB command with several where-clauses stays far below this.
PARSE_OUTPUT_LIMIT_BYTES = 256 * 1024
_DEVICE_ID_RE = re.compile(DEVICE_ID_PATTERN)


class _Rejected(Exception):
    def __init__(self, code: str, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.error = CommandError(code=code, message=message, retryable=retryable)


class Gateway:
    """Hide device selection, validation, SSH lifecycle, and result mapping."""

    def __init__(self, registry: DeviceRegistry, ssh: SSHCommandPort) -> None:
        self._registry = registry
        self._ssh = ssh

    def device_list(self) -> DeviceListResult:
        """Return configured devices without performing network I/O."""

        return self._registry.list_devices()

    async def command_read(self, device: str, command: str) -> CommandResult:
        """Run one read-only command (print/export/get/monitor)."""

        started = time.perf_counter_ns()
        try:
            resolved = self._resolve(device, command)
            violation = read_only_violation(command)
            if violation is not None:
                raise _Rejected("READ_ONLY_VIOLATION", violation)
            parsed = await self._parse(resolved, command)
            violation = read_verb_violation(parsed)
            if violation is not None:
                raise _Rejected("READ_ONLY_VIOLATION", violation)
            return await self._run(resolved, command, started, read_only=True)
        except _Rejected as rejected:
            return _result(device, CommandStatus.REJECTED, started, error=rejected.error)

    async def command_execute(
        self,
        device: str,
        command: str,
        dry_run: bool = False,
    ) -> CommandResult:
        """Syntax-check one command on the device, then run it unless ``dry_run``."""

        started = time.perf_counter_ns()
        try:
            resolved = self._resolve(device, command)
            await self._parse(resolved, command)
            if dry_run:
                return _result(device, CommandStatus.VALIDATED, started)
            return await self._run(resolved, command, started, read_only=False)
        except _Rejected as rejected:
            return _result(device, CommandStatus.REJECTED, started, error=rejected.error)

    async def aclose(self) -> None:
        """Close all reusable SSH sessions."""

        await self._ssh.aclose()

    def _resolve(self, device: str, command: str) -> ResolvedDevice:
        _validate_request(device, command)
        try:
            resolved = self._registry.get(device)
        except DeviceNotFoundError:
            raise _Rejected("DEVICE_NOT_FOUND", f"Device {device!r} is not configured") from None
        if not resolved.config.enabled:
            raise _Rejected("DEVICE_DISABLED", f"Device {device!r} is disabled")
        return resolved

    async def _parse(self, device: ResolvedDevice, command: str) -> ParsedCommand:
        """Ask RouterOS to compile the command without running it."""

        execution = await self._ssh_execute(
            device,
            parse_check_script(command),
            output_limit_bytes=PARSE_OUTPUT_LIMIT_BYTES,
        )
        if not execution.completed or execution.exit_code != 0 or execution.truncated:
            # Only the parse script was sent, so the command itself has not run.
            raise _Rejected(
                "SYNTAX_CHECK_FAILED",
                "Could not complete the RouterOS syntax check; the command was not run",
                retryable=True,
            )
        parsed = interpret_parse_output(execution.output.decode("utf-8", errors="replace"))
        if parsed.errors:
            raise _Rejected("SYNTAX_ERROR", "; ".join(parsed.errors))
        return parsed

    async def _run(
        self,
        device: ResolvedDevice,
        command: str,
        started: int,
        *,
        read_only: bool,
    ) -> CommandResult:
        execution = await self._ssh_execute(device, command)
        output = normalize_output(execution.output)
        common = {"output": output, "output_truncated": execution.truncated}

        if not execution.completed:
            reason = "timed out" if execution.timed_out else "lost its SSH session"
            if read_only:
                error = CommandError(
                    code="OUTCOME_UNKNOWN",
                    message=f"Read command {reason} before completing; it is safe to retry",
                    retryable=True,
                )
            else:
                error = CommandError(
                    code="OUTCOME_UNKNOWN",
                    message=(
                        f"Command {reason} after it was sent; it may have taken effect. "
                        "Check device state before retrying"
                    ),
                )
            return _result(device.device, CommandStatus.UNKNOWN, started, error=error, **common)

        error_line = runtime_error(execution.tail)
        if error_line is not None:
            error = CommandError(code="ROUTEROS_ERROR", message=error_line)
            return _result(device.device, CommandStatus.FAILED, started, error=error, **common)
        if execution.exit_code != 0:
            error = CommandError(
                code="REMOTE_EXIT_STATUS",
                message=f"Remote command exited with status {execution.exit_code}",
            )
            return _result(device.device, CommandStatus.FAILED, started, error=error, **common)
        return _result(device.device, CommandStatus.SUCCEEDED, started, **common)

    async def _ssh_execute(
        self,
        device: ResolvedDevice,
        command: str,
        *,
        output_limit_bytes: int | None = None,
    ) -> SSHExecution:
        try:
            return await self._ssh.execute(device, command, output_limit_bytes=output_limit_bytes)
        except SSHAdapterError as exc:
            raise _Rejected(exc.code, exc.message, retryable=exc.retryable) from None
        except asyncio.CancelledError:
            raise
        except Exception:
            raise _Rejected(
                "INTERNAL_ERROR", "SSH execution failed before the command was sent"
            ) from None


def create_gateway_from_env(
    environ: Mapping[str, str] | None = None,
) -> Gateway:
    """Build the production Gateway from an environment snapshot."""

    return Gateway(
        registry=DeviceRegistry.from_env(environ),
        ssh=ParamikoSSHAdapter(),
    )


def create_gateway_from_file(
    path: str | Path,
    environ: Mapping[str, str] | None = None,
) -> Gateway:
    """Build the production Gateway from a device registry file and environment secrets."""

    return Gateway(
        registry=DeviceRegistry.from_file(path, environ),
        ssh=ParamikoSSHAdapter(),
    )


def _validate_request(device: object, command: object) -> None:
    if not isinstance(device, str) or _DEVICE_ID_RE.fullmatch(device) is None:
        raise _Rejected("INVALID_DEVICE", f"device must match {DEVICE_ID_PATTERN}")
    if not isinstance(command, str):
        raise _Rejected("INVALID_COMMAND", "command must be a string")
    if not command.strip():
        raise _Rejected("INVALID_COMMAND", "command cannot be empty")
    if any(ord(character) < 32 or ord(character) == 127 for character in command):
        raise _Rejected(
            "INVALID_COMMAND", "command must be a single line without control characters"
        )
    try:
        command_size = len(command.encode("utf-8"))
    except UnicodeEncodeError:
        raise _Rejected("INVALID_COMMAND", "command must be valid UTF-8") from None
    if command_size > MAX_COMMAND_BYTES:
        raise _Rejected("INVALID_COMMAND", f"command exceeds the {MAX_COMMAND_BYTES}-byte limit")


def _result(
    device: object,
    status: CommandStatus,
    started: int,
    *,
    output: str = "",
    output_truncated: bool = False,
    error: CommandError | None = None,
) -> CommandResult:
    return CommandResult(
        device=device if isinstance(device, str) else str(device),
        status=status,
        output=output,
        output_truncated=output_truncated,
        duration_ms=max(0, (time.perf_counter_ns() - started) // 1_000_000),
        error=error,
    )
