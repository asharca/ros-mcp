"""Load and resolve the immutable RouterOS device registry."""

from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType
from typing import Any

from pydantic import SecretStr, ValidationError

from .models import (
    DEVICE_ID_PATTERN,
    DeviceConfig,
    DeviceListResult,
    PasswordAuthConfig,
    ResolvedDevice,
)

DEVICES_ENV_VAR = "ROS_DEVICES_JSON"
_DEVICE_ID_RE = re.compile(DEVICE_ID_PATTERN)


class DeviceRegistryError(ValueError):
    """Raised when device configuration cannot be loaded safely."""


class DeviceNotFoundError(KeyError):
    """Raised when a caller requests an unconfigured device id."""


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DeviceRegistryError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _reject_nonstandard_json_constant(value: str) -> None:
    raise DeviceRegistryError(f"invalid JSON numeric constant: {value}")


class DeviceRegistry:
    """Immutable collection of resolved devices loaded at process startup."""

    __slots__ = ("_devices",)

    def __init__(self, devices: Mapping[str, ResolvedDevice]) -> None:
        if not devices:
            raise DeviceRegistryError("at least one device is required")
        self._devices = MappingProxyType(dict(devices))

    @classmethod
    def from_env(
        cls,
        environ: Mapping[str, str] | None = None,
    ) -> DeviceRegistry:
        """Load from an explicit environment mapping, or a snapshot of ``os.environ``.

        Relative ``private_key_file`` paths resolve against the working directory.
        """

        environment = dict(os.environ if environ is None else environ)
        raw_devices = environment.get(DEVICES_ENV_VAR)
        if raw_devices is None:
            raise DeviceRegistryError(f"required environment variable {DEVICES_ENV_VAR} is missing")
        if not isinstance(raw_devices, str) or not raw_devices.strip():
            raise DeviceRegistryError(f"required environment variable {DEVICES_ENV_VAR} is empty")

        return cls._from_json(raw_devices, environment, source=DEVICES_ENV_VAR, base_dir=None)

    @classmethod
    def from_file(
        cls,
        path: str | Path,
        environ: Mapping[str, str] | None = None,
    ) -> DeviceRegistry:
        """Load a device registry file and resolve its secret references.

        Relative ``private_key_file`` paths resolve against the configuration file's directory.
        """

        environment = dict(os.environ if environ is None else environ)
        if DEVICES_ENV_VAR in environment:
            raise DeviceRegistryError(
                f"configuration file cannot be used when {DEVICES_ENV_VAR} is also set"
            )

        config_path = Path(path)
        read_error: DeviceRegistryError | None = None
        try:
            raw_devices = config_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            read_error = DeviceRegistryError(f"configuration file {config_path!s} must be UTF-8")
        except OSError:
            read_error = DeviceRegistryError(f"cannot read configuration file {config_path!s}")

        if read_error is not None:
            raise read_error

        if not raw_devices.strip():
            raise DeviceRegistryError(f"configuration file {config_path!s} is empty")

        return cls._from_json(
            raw_devices,
            environment,
            source=f"configuration file {config_path!s}",
            base_dir=config_path.parent,
        )

    @classmethod
    def _from_json(
        cls,
        raw_devices: str,
        environment: Mapping[str, str],
        *,
        source: str,
        base_dir: Path | None,
    ) -> DeviceRegistry:
        """Validate a JSON device registry and resolve its secret references."""

        parse_error: DeviceRegistryError | None = None
        try:
            parsed = json.loads(
                raw_devices,
                object_pairs_hook=_reject_duplicate_json_keys,
                parse_constant=_reject_nonstandard_json_constant,
            )
        except DeviceRegistryError:
            raise
        except (json.JSONDecodeError, TypeError, ValueError):
            parse_error = DeviceRegistryError(f"{source} must contain valid JSON")

        if parse_error is not None:
            raise parse_error

        if not isinstance(parsed, dict):
            raise DeviceRegistryError(f"{source} must be a JSON object")
        if not parsed:
            raise DeviceRegistryError("at least one device is required")

        resolved: dict[str, ResolvedDevice] = {}
        for device_id, unvalidated_config in parsed.items():
            if not isinstance(device_id, str) or _DEVICE_ID_RE.fullmatch(device_id) is None:
                raise DeviceRegistryError(
                    f"invalid device id {device_id!r}; expected {DEVICE_ID_PATTERN}"
                )
            if not isinstance(unvalidated_config, dict):
                raise DeviceRegistryError(f"device {device_id!r} must be a JSON object")

            try:
                config = DeviceConfig.model_validate(unvalidated_config)
            except ValidationError as exc:
                locations = (
                    ", ".join(
                        ".".join(str(part) for part in error["loc"])
                        for error in exc.errors(include_input=False)
                    )
                    or "configuration"
                )
            else:
                resolved[device_id] = _resolve_device(device_id, config, environment, base_dir)
                continue

            raise DeviceRegistryError(
                f"invalid configuration for device {device_id!r} at {locations}"
            )

        return cls(resolved)

    def get(self, device_id: str) -> ResolvedDevice:
        try:
            return self._devices[device_id]
        except KeyError as exc:
            raise DeviceNotFoundError(device_id) from exc

    def list_devices(self) -> DeviceListResult:
        return DeviceListResult(
            devices=tuple(device.summary() for device in self._devices.values())
        )

    @property
    def device_ids(self) -> tuple[str, ...]:
        return tuple(self._devices)

    def __contains__(self, device_id: object) -> bool:
        return device_id in self._devices

    def __len__(self) -> int:
        return len(self._devices)


def _resolve_device(
    device_id: str,
    config: DeviceConfig,
    environment: Mapping[str, str],
    base_dir: Path | None,
) -> ResolvedDevice:
    auth = config.auth
    if isinstance(auth, PasswordAuthConfig):
        password = auth.password
        if password is None:
            assert auth.password_env is not None
            password = _resolve_secret(environment, auth.password_env, device_id, "password")
        return ResolvedDevice(device=device_id, config=config, password=password)

    if auth.private_key_file is not None:
        private_key = _read_private_key_file(device_id, auth.private_key_file, base_dir)
    else:
        assert auth.private_key_env is not None
        private_key = _resolve_secret(environment, auth.private_key_env, device_id, "private key")
    _require_complete_private_key(device_id, private_key)

    passphrase = None
    if auth.passphrase_env is not None:
        passphrase = _resolve_secret(
            environment, auth.passphrase_env, device_id, "private-key passphrase"
        )
    return ResolvedDevice(
        device=device_id,
        config=config,
        private_key=private_key,
        passphrase=passphrase,
    )


def _resolve_secret(
    environment: Mapping[str, str],
    variable_name: str,
    device_id: str,
    secret_kind: str,
) -> SecretStr:
    if variable_name not in environment:
        raise DeviceRegistryError(
            f"device {device_id!r} references a missing {secret_kind} environment variable"
        )
    value = environment[variable_name]
    if not isinstance(value, str) or not value.strip():
        raise DeviceRegistryError(f"device {device_id!r} has an empty {secret_kind}")
    return SecretStr(value)


def _read_private_key_file(device_id: str, path_text: str, base_dir: Path | None) -> SecretStr:
    path = Path(path_text)
    if base_dir is not None and not path.is_absolute():
        path = base_dir / path
    read_error: DeviceRegistryError | None = None
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        read_error = DeviceRegistryError(f"device {device_id!r} private key file cannot be read")
    if read_error is not None:
        raise read_error
    if not text.strip():
        raise DeviceRegistryError(f"device {device_id!r} has an empty private key")
    return SecretStr(text)


def _require_complete_private_key(device_id: str, private_key: SecretStr) -> None:
    lines = private_key.get_secret_value().strip().splitlines()
    first_line = lines[0]
    complete = (
        first_line.startswith("-----BEGIN ")
        and first_line.endswith("PRIVATE KEY-----")
        and lines[-1] == first_line.replace("-----BEGIN ", "-----END ", 1)
    )
    if not complete:
        raise DeviceRegistryError(
            f"device {device_id!r} private key must contain complete PEM/OpenSSH key text"
        )
