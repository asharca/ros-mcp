"""Asynchronous, multi-device SSH command execution over Paramiko."""

from __future__ import annotations

import asyncio
import hmac
import io
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Protocol

import paramiko

from ros_mcp.models import PasswordAuthConfig, ResolvedDevice

TAIL_BYTES = 1024
_RECV_BYTES = 32 * 1024


@dataclass(frozen=True, slots=True)
class SSHExecution:
    """Output of a dispatched command.

    ``completed`` is False when the command was dispatched but the SSH session failed or
    timed out before it finished: the command may or may not have taken effect.
    """

    completed: bool
    exit_code: int | None
    output: bytes
    """stdout and stderr combined, up to the output limit."""
    tail: bytes
    """The last ``TAIL_BYTES`` of the output, kept even when ``output`` is truncated."""
    truncated: bool
    timed_out: bool = False


class SSHAdapterError(RuntimeError):
    """A failure known to have happened before a command was dispatched."""

    def __init__(self, code: str, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.retryable = retryable


class SSHCommandPort(Protocol):
    async def execute(
        self,
        device: ResolvedDevice,
        command: str,
        *,
        output_limit_bytes: int | None = None,
    ) -> SSHExecution: ...

    async def aclose(self) -> None: ...


class _FingerprintMismatch(paramiko.SSHException):
    pass


class _PrivateKeyLoadError(paramiko.SSHException):
    pass


class _FingerprintPolicy(paramiko.MissingHostKeyPolicy):
    """Accept exactly one configured SHA256 host-key fingerprint, before authentication."""

    def __init__(self, expected: str) -> None:
        self._expected = expected

    def missing_host_key(
        self,
        client: paramiko.SSHClient,
        hostname: str,
        key: paramiko.PKey,
    ) -> None:
        del client, hostname
        _verify_fingerprint(key, self._expected)


@dataclass(slots=True)
class _OutputCollector:
    limit: int
    head: bytearray = field(default_factory=bytearray)
    tail: bytearray = field(default_factory=bytearray)
    total: int = 0

    def add(self, chunk: bytes) -> None:
        self.total += len(chunk)
        remaining = self.limit - len(self.head)
        if remaining > 0:
            self.head.extend(chunk[:remaining])
        self.tail.extend(chunk[-TAIL_BYTES:])
        del self.tail[:-TAIL_BYTES]

    def result(
        self, *, completed: bool, exit_code: int | None, timed_out: bool = False
    ) -> SSHExecution:
        return SSHExecution(
            completed=completed,
            exit_code=exit_code,
            output=bytes(self.head),
            tail=bytes(self.tail),
            truncated=self.total > self.limit,
            timed_out=timed_out,
        )


@dataclass(slots=True)
class _DeviceState:
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    waiting: int = 0
    client: Any | None = None
    last_used_at: float = 0.0


@dataclass(slots=True)
class _AttemptFailure(Exception):
    cause: Exception
    dispatched: bool
    output: _OutputCollector


ClientFactory = Callable[[], Any]


class ParamikoSSHAdapter:
    """Reuse one SSH session per device while preserving per-device FIFO order."""

    def __init__(
        self,
        *,
        client_factory: ClientFactory = paramiko.SSHClient,
        max_workers: int = 8,
        max_pending_jobs: int = 16,
        per_device_queue_size: int = 32,
    ) -> None:
        if max_workers < 1:
            raise ValueError("max_workers must be at least 1")
        if max_pending_jobs < 0:
            raise ValueError("max_pending_jobs cannot be negative")
        if per_device_queue_size < 0:
            raise ValueError("per_device_queue_size cannot be negative")

        self._client_factory = client_factory
        self._per_device_queue_size = per_device_queue_size
        self._states: dict[str, _DeviceState] = {}
        self._state_guard = asyncio.Lock()
        self._close_lock = asyncio.Lock()
        self._all_requests_done = asyncio.Event()
        self._all_requests_done.set()
        self._accepted_requests = 0
        self._closing = False
        self._closed = False
        self._executor = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="ros-mcp-ssh",
        )
        # ThreadPoolExecutor's internal queue is unbounded. This gate bounds submitted work.
        self._worker_slots = asyncio.Semaphore(max_workers + max_pending_jobs)

    async def execute(
        self,
        device: ResolvedDevice,
        command: str,
        *,
        output_limit_bytes: int | None = None,
    ) -> SSHExecution:
        """Run one command, defaulting to the device's configured output limit."""

        limit = output_limit_bytes or device.config.output_limit_bytes
        state, counted_waiter = await self._accept_request(device.device)
        acquired = False
        try:
            await state.lock.acquire()
            acquired = True
            if counted_waiter:
                state.waiting -= 1
                counted_waiter = False
            return await self._run_blocking(self._execute_with_retry, state, device, command, limit)
        finally:
            if counted_waiter:
                state.waiting -= 1
            if acquired:
                state.lock.release()
            await self._finish_request()

    async def aclose(self) -> None:
        async with self._close_lock:
            if self._closed:
                return
            async with self._state_guard:
                self._closing = True

            await self._all_requests_done.wait()
            clients = [state.client for state in self._states.values() if state.client is not None]
            for state in self._states.values():
                state.client = None
                state.last_used_at = 0.0
            await self._run_blocking(self._close_clients, clients)
            self._closed = True
            await asyncio.to_thread(self._executor.shutdown, wait=True, cancel_futures=True)

    async def _accept_request(self, device_id: str) -> tuple[_DeviceState, bool]:
        async with self._state_guard:
            if self._closing or self._closed:
                raise SSHAdapterError("SSH_ADAPTER_CLOSED", "SSH executor is closed")
            state = self._states.setdefault(device_id, _DeviceState())
            queued = state.lock.locked() or state.waiting > 0
            if queued and state.waiting >= self._per_device_queue_size:
                raise SSHAdapterError(
                    "DEVICE_QUEUE_FULL",
                    f"SSH command queue is full for device {device_id!r}",
                    retryable=True,
                )
            if queued:
                state.waiting += 1
            self._accepted_requests += 1
            self._all_requests_done.clear()
            return state, queued

    async def _finish_request(self) -> None:
        async with self._state_guard:
            self._accepted_requests -= 1
            if self._accepted_requests == 0:
                self._all_requests_done.set()

    async def _run_blocking(self, function: Callable[..., Any], *args: Any) -> Any:
        async with self._worker_slots:
            loop = asyncio.get_running_loop()
            future = loop.run_in_executor(self._executor, function, *args)
            try:
                return await asyncio.shield(future)
            except asyncio.CancelledError:
                # Do not release a device lock while its Paramiko operation is still running.
                await asyncio.shield(future)
                raise

    def _execute_with_retry(
        self,
        state: _DeviceState,
        device: ResolvedDevice,
        command: str,
        limit: int,
    ) -> SSHExecution:
        for attempt in range(2):
            try:
                return self._execute_once(state, device, command, limit)
            except _AttemptFailure as failure:
                self._drop_client(state)
                if failure.dispatched:
                    return failure.output.result(
                        completed=False,
                        exit_code=None,
                        timed_out=isinstance(failure.cause, TimeoutError),
                    )
                if attempt == 0 and _is_retryable_pre_dispatch(failure.cause):
                    continue
                raise _public_pre_dispatch_error(failure.cause) from failure.cause
        raise AssertionError("unreachable")

    def _execute_once(
        self,
        state: _DeviceState,
        device: ResolvedDevice,
        command: str,
        limit: int,
    ) -> SSHExecution:
        output = _OutputCollector(limit)
        channel: Any | None = None
        dispatched = False
        try:
            client = self._ensure_client(state, device)
            transport = client.get_transport()
            if transport is None or not transport.is_active():
                raise ConnectionError("SSH transport is not active")

            deadline = time.monotonic() + device.config.command_timeout_seconds
            channel = transport.open_session(timeout=_remaining(deadline))
            channel.set_combine_stderr(True)
            # From this point forward, the server may have received the command request.
            dispatched = True
            channel.exec_command(command)
            while True:
                channel.settimeout(_remaining(deadline))
                chunk = channel.recv(_RECV_BYTES)
                if not chunk:
                    break
                output.add(chunk)
            # Paramiko sets status_event when exit-status arrives or the channel closes.
            if not channel.status_event.wait(_remaining(deadline)):
                raise TimeoutError("SSH command timed out")
            exit_code = channel.recv_exit_status()
            if exit_code == -1:
                raise ConnectionError("SSH channel closed without an exit status")
            state.last_used_at = time.monotonic()
            return output.result(completed=True, exit_code=exit_code)
        except Exception as exc:
            raise _AttemptFailure(exc, dispatched, output) from exc
        finally:
            _safe_close(channel)

    def _ensure_client(self, state: _DeviceState, device: ResolvedDevice) -> Any:
        client = state.client
        if client is not None:
            idle_expired = time.monotonic() - state.last_used_at >= device.config.idle_ttl_seconds
            transport = client.get_transport()
            if idle_expired or transport is None or not transport.is_active():
                self._drop_client(state)
                client = None
        if client is None:
            client = self._connect(device)
            state.client = client
            state.last_used_at = time.monotonic()
        return client

    def _connect(self, device: ResolvedDevice) -> Any:
        config = device.config
        fingerprint = config.host_key.fingerprint_sha256
        client = self._client_factory()
        try:
            client.set_missing_host_key_policy(_FingerprintPolicy(fingerprint))
            credentials: dict[str, Any]
            if isinstance(config.auth, PasswordAuthConfig):
                assert device.password is not None
                credentials = {"password": device.password.get_secret_value()}
            else:
                assert device.private_key is not None
                passphrase = device.passphrase
                credentials = {
                    "pkey": _load_private_key(
                        device.private_key.get_secret_value(),
                        None if passphrase is None else passphrase.get_secret_value(),
                    )
                }
            client.connect(
                hostname=config.host,
                port=config.port,
                username=config.username,
                timeout=config.connect_timeout_seconds,
                banner_timeout=config.connect_timeout_seconds,
                auth_timeout=config.connect_timeout_seconds,
                channel_timeout=config.command_timeout_seconds,
                allow_agent=False,
                look_for_keys=False,
                **credentials,
            )
            transport = client.get_transport()
            if transport is None or not transport.is_active():
                raise ConnectionError("SSH transport did not become active")
            _verify_fingerprint(transport.get_remote_server_key(), fingerprint)
            if config.keepalive_seconds > 0:
                transport.set_keepalive(config.keepalive_seconds)
            return client
        except Exception:
            _safe_close(client)
            raise

    @staticmethod
    def _close_clients(clients: list[Any]) -> None:
        for client in clients:
            _safe_close(client)

    @staticmethod
    def _drop_client(state: _DeviceState) -> None:
        client = state.client
        state.client = None
        state.last_used_at = 0.0
        _safe_close(client)


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("SSH command timed out")
    return remaining


def _verify_fingerprint(key: Any, expected: str) -> None:
    actual = getattr(key, "fingerprint", None)
    if not isinstance(actual, str) or not hmac.compare_digest(actual, expected):
        raise _FingerprintMismatch("SSH host-key fingerprint does not match configuration")


def _load_private_key(private_key: str, passphrase: str | None) -> paramiko.PKey:
    errors: list[Exception] = []
    key_types = (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey)
    for key_type in key_types:
        try:
            return key_type.from_private_key(io.StringIO(private_key), password=passphrase)
        except (paramiko.SSHException, ValueError) as exc:
            errors.append(exc)
    message = "private key is invalid, unsupported, or has a wrong passphrase"
    raise _PrivateKeyLoadError(message) from (errors[-1] if errors else None)


def _is_retryable_pre_dispatch(exc: Exception) -> bool:
    if isinstance(
        exc,
        (
            SSHAdapterError,
            _FingerprintMismatch,
            _PrivateKeyLoadError,
            paramiko.AuthenticationException,
            paramiko.BadHostKeyException,
            paramiko.PasswordRequiredException,
        ),
    ):
        return False
    return isinstance(exc, (OSError, TimeoutError, paramiko.SSHException))


def _public_pre_dispatch_error(exc: Exception) -> SSHAdapterError:
    if isinstance(exc, SSHAdapterError):
        return exc
    if isinstance(exc, (_FingerprintMismatch, paramiko.BadHostKeyException)):
        return SSHAdapterError(
            "SSH_HOST_KEY_MISMATCH",
            "SSH host-key fingerprint does not match configuration",
        )
    if isinstance(exc, (_PrivateKeyLoadError, paramiko.PasswordRequiredException)):
        return SSHAdapterError("SSH_PRIVATE_KEY_INVALID", str(exc))
    if isinstance(exc, paramiko.AuthenticationException):
        return SSHAdapterError("SSH_AUTH_FAILED", "SSH authentication failed")
    if isinstance(exc, TimeoutError):
        return SSHAdapterError(
            "SSH_CONNECT_TIMEOUT",
            "SSH connection or channel setup timed out",
            retryable=True,
        )
    return SSHAdapterError(
        "SSH_CONNECT_FAILED",
        "SSH connection or channel setup failed",
        retryable=True,
    )


def _safe_close(resource: Any | None) -> None:
    if resource is not None:
        try:
            resource.close()
        except Exception:
            pass
