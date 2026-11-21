"""Domain models for RouterOS devices and command execution results."""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    StrictBool,
    StringConstraints,
    field_validator,
    model_validator,
)

DEVICE_ID_PATTERN = r"^[a-z][a-z0-9_-]{0,63}$"
ENV_NAME_PATTERN = r"^[A-Za-z_][A-Za-z0-9_]*$"

DeviceId = Annotated[
    str,
    StringConstraints(strict=True, pattern=DEVICE_ID_PATTERN),
]
EnvironmentVariableName = Annotated[
    str,
    StringConstraints(strict=True, pattern=ENV_NAME_PATTERN),
]
NonEmptyString = Annotated[str, StringConstraints(strict=True, min_length=1)]
Port = Annotated[int, Field(strict=True, ge=1, le=65535)]
PositiveSeconds = Annotated[int, Field(strict=True, gt=0)]
NonNegativeSeconds = Annotated[int, Field(strict=True, ge=0)]
PositiveByteCount = Annotated[int, Field(strict=True, gt=0)]
NonNegativeMilliseconds = Annotated[int, Field(strict=True, ge=0)]


class StrictModel(BaseModel):
    """Base for immutable models that reject unrecognised fields."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        validate_default=True,
    )


class PasswordAuthConfig(StrictModel):
    type: Literal["password"]
    password: SecretStr | None = Field(default=None, exclude=True, repr=False)
    password_env: EnvironmentVariableName | None = Field(default=None, repr=False)

    @field_validator("password")
    @classmethod
    def reject_empty_password(cls, value: SecretStr | None) -> SecretStr | None:
        if value is not None and not value.get_secret_value().strip():
            raise ValueError("password must be non-blank")
        return value

    @model_validator(mode="after")
    def validate_password_source(self) -> Self:
        if (self.password is None) == (self.password_env is None):
            raise ValueError(
                "password authentication requires exactly one of password or password_env"
            )
        return self


class PrivateKeyAuthConfig(StrictModel):
    type: Literal["private_key"]
    private_key_env: EnvironmentVariableName | None = Field(default=None, repr=False)
    private_key_file: NonEmptyString | None = Field(default=None, repr=False)
    passphrase_env: EnvironmentVariableName | None = Field(default=None, repr=False)

    @model_validator(mode="after")
    def validate_private_key_source(self) -> Self:
        if (self.private_key_env is None) == (self.private_key_file is None):
            raise ValueError(
                "private-key authentication requires exactly one of "
                "private_key_env or private_key_file"
            )
        return self


AuthConfig = Annotated[
    PasswordAuthConfig | PrivateKeyAuthConfig,
    Field(discriminator="type"),
]


class HostKeyConfig(StrictModel):
    fingerprint_sha256: NonEmptyString = Field(repr=False)

    @field_validator("fingerprint_sha256")
    @classmethod
    def validate_fingerprint(cls, value: str) -> str:
        prefix = "SHA256:"
        if not value.startswith(prefix):
            raise ValueError("fingerprint must start with 'SHA256:'")

        encoded = value[len(prefix) :]
        if not encoded or "=" in encoded:
            raise ValueError("fingerprint must be unpadded base64")
        base64_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        if any(character not in base64_alphabet for character in encoded):
            raise ValueError("fingerprint must use standard base64")

        try:
            decoded = base64.b64decode(
                encoded + ("=" * (-len(encoded) % 4)),
                validate=True,
            )
        except (binascii.Error, ValueError) as exc:
            raise ValueError("fingerprint must contain valid base64") from exc

        canonical = base64.b64encode(decoded).decode("ascii").rstrip("=")
        if len(decoded) != 32 or canonical != encoded:
            raise ValueError("fingerprint must encode a 32-byte SHA-256 digest")
        return value


class DeviceConfig(StrictModel):
    """Validated device configuration before secret references are resolved."""

    display_name: NonEmptyString | None = None
    description: str | None = None
    host: NonEmptyString
    port: Port = 22
    username: NonEmptyString
    enabled: StrictBool = True
    tags: tuple[NonEmptyString, ...] = ()
    connect_timeout_seconds: PositiveSeconds = 15
    command_timeout_seconds: PositiveSeconds = 60
    keepalive_seconds: NonNegativeSeconds = 30
    idle_ttl_seconds: NonNegativeSeconds = 300
    output_limit_bytes: PositiveByteCount = 65_536
    auth: AuthConfig
    host_key: HostKeyConfig

    @field_validator("display_name", "host", "username")
    @classmethod
    def reject_blank_or_padded_values(cls, value: str | None) -> str | None:
        if value is not None and (not value.strip() or value != value.strip()):
            raise ValueError("value must be non-blank and have no surrounding whitespace")
        return value

    @field_validator("description")
    @classmethod
    def reject_padded_description(cls, value: str | None) -> str | None:
        if value is not None and value != value.strip():
            raise ValueError("description must have no surrounding whitespace")
        return value

    @field_validator("tags")
    @classmethod
    def validate_tags(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(not tag.strip() or tag != tag.strip() for tag in value):
            raise ValueError("tags must be non-blank and have no surrounding whitespace")
        if len(set(value)) != len(value):
            raise ValueError("tags must be unique")
        return value


class DeviceSummary(StrictModel):
    """Public, non-sensitive device data returned by ``device_list``."""

    device: DeviceId
    display_name: NonEmptyString
    description: str | None = None
    host: NonEmptyString
    enabled: StrictBool
    tags: tuple[str, ...] = ()


class DeviceListResult(StrictModel):
    devices: tuple[DeviceSummary, ...]


@dataclass(frozen=True, slots=True)
class ResolvedDevice:
    """A configured device with its secrets resolved in memory."""

    device: str
    config: DeviceConfig
    password: SecretStr | None = field(default=None, repr=False)
    private_key: SecretStr | None = field(default=None, repr=False)
    passphrase: SecretStr | None = field(default=None, repr=False)

    def summary(self) -> DeviceSummary:
        return DeviceSummary(
            device=self.device,
            display_name=self.config.display_name or self.device,
            description=self.config.description,
            host=self.config.host,
            enabled=self.config.enabled,
            tags=self.config.tags,
        )


class CommandStatus(StrEnum):
    VALIDATED = "validated"
    """dry_run only: RouterOS parsed the command; nothing was executed."""
    REJECTED = "rejected"
    """The command was not executed."""
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    """The command ran and RouterOS reported an error; earlier statements may have taken effect."""
    UNKNOWN = "unknown"
    """The command was sent but its outcome is unknown; it may have taken effect."""


class CommandError(StrictModel):
    code: Annotated[str, StringConstraints(strict=True, pattern=r"^[A-Z][A-Z0-9_]*$")]
    message: NonEmptyString
    retryable: StrictBool = False


class CommandResult(StrictModel):
    # Echo the caller's target even when it is not a valid configured DeviceId.
    device: Annotated[str, StringConstraints(strict=True)]
    status: CommandStatus
    output: str = ""
    output_truncated: StrictBool = False
    duration_ms: NonNegativeMilliseconds
    error: CommandError | None = None

    @model_validator(mode="after")
    def validate_error_presence(self) -> Self:
        needs_error = self.status not in (CommandStatus.VALIDATED, CommandStatus.SUCCEEDED)
        if needs_error != (self.error is not None):
            raise ValueError(f"status {self.status.value!r} requires error={needs_error}")
        return self
