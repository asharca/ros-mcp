# ROS-MCP

[![CI](https://github.com/asharca/ros-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/asharca/ros-mcp/actions/workflows/ci.yml)
[![Container](https://github.com/asharca/ros-mcp/actions/workflows/container.yml/badge.svg)](https://github.com/asharca/ros-mcp/actions/workflows/container.yml)

ROS-MCP is a small MCP gateway for managing multiple MikroTik RouterOS devices
over SSH. It exposes three tools and keeps device credentials, SSH session
reuse, retries, timeouts, and output limits behind the gateway.

Despite the project name, `ROS` means MikroTik RouterOS, not Robot Operating
System.

## MCP tools

### `device_list`

Returns the configured, non-sensitive device inventory: ID, display name,
description, host, enabled flag, and tags. It performs no network I/O.

### `command_read`

```text
command_read(device: string, command: string)
```

Runs one `print`, `export`, `get`, `monitor`, or `monitor-traffic` command, for
example `/ip address print where interface=ether1`. It is annotated read-only,
so MCP clients can allow it without per-call approval.

The gateway rejects scripting (`;`, `[ ]`, `{ }`, `$`, and `:` commands) and
the `file=` and `show-sensitive` arguments. It then asks the device to parse the
command with `:parse` and runs it only when RouterOS reports exactly one command
with a read verb. This is a guardrail for client auto-approval, not an
authorization boundary: to enforce read-only access, give the SSH user a
RouterOS group without the `write` policy.

### `command_execute`

```text
command_execute(device: string, command: string, dry_run: boolean = false)
```

Runs one RouterOS CLI line that may change state. It is annotated destructive;
keep manual approval enabled for it in the MCP client.

- `command` is one line, limited to 8 KiB.
- Before running, the device parses the command with `:parse`. A syntax error,
  such as an unknown command or parameter, returns `rejected` without running
  anything.
- `dry_run=true` stops after that check and returns `validated`. The check
  covers syntax only, not values, references to items, or effects.

### Results

Both command tools return `status`, `output`, `output_truncated`,
`duration_ms`, and `error` (`code`, `message`, `retryable`).

| `status` | Meaning |
| --- | --- |
| `validated` | `dry_run` only: the command parsed; nothing ran. |
| `rejected` | The command did not run (validation, syntax, or connection failure). |
| `succeeded` | The command ran and RouterOS reported no error. |
| `failed` | The command ran and RouterOS printed an error. Earlier statements may have taken effect. |
| `unknown` | The command was sent but the session failed or timed out. A change may have taken effect: inspect the device before retrying. |

RouterOS's SSH server returns exit status 0 even for failed commands. The
gateway therefore detects failures from RouterOS's error line, such as
`no such item (/ip/address/get; line 1)`, which ends the output. Output is
returned with carriage returns and RouterOS's column padding removed.

The gateway does not implement RouterOS Safe Mode.

## Configuration

Choose exactly one device-registry source:

- `ROS_DEVICES_JSON`, containing the JSON object directly; or
- `ros-mcp --config PATH`, where `PATH` is a UTF-8 JSON file.

The two sources use the same schema. Do not set `ROS_DEVICES_JSON` when using
`--config`; the server rejects ambiguous configuration sources. Each device
defines its SSH authentication method.

```json
{
  "main": {
    "display_name": "Main Router",
    "description": "Internet edge",
    "host": "192.168.88.1",
    "port": 22,
    "username": "ai-mgmt",
    "enabled": true,
    "tags": ["production", "edge"],
    "connect_timeout_seconds": 15,
    "command_timeout_seconds": 25,
    "keepalive_seconds": 30,
    "idle_ttl_seconds": 300,
    "output_limit_bytes": 65536,
    "auth": {
      "type": "password",
      "password": "REPLACE_WITH_ROUTEROS_SSH_PASSWORD"
    },
    "host_key": {
      "fingerprint_sha256": "SHA256:REPLACE_WITH_43_BASE64_CHARACTERS"
    }
  },
  "office": {
    "display_name": "Office Router",
    "host": "10.0.0.1",
    "port": 22,
    "username": "ai-mgmt",
    "auth": {
      "type": "private_key",
      "private_key_env": "ROS_OFFICE_PRIVATE_KEY",
      "passphrase_env": "ROS_OFFICE_KEY_PASSPHRASE"
    },
    "host_key": {
      "fingerprint_sha256": "SHA256:REPLACE_WITH_43_BASE64_CHARACTERS"
    }
  }
}
```

`devices.example.json` contains the same sanitized configuration as a starting
point. Keep actual device inventories outside version control.

For password authentication, set exactly one of these fields:

- `password`: the RouterOS SSH password directly in the configuration; no
  credential environment variable is required.
- `password_env`: the name of an environment variable containing the password.

Private-key authentication takes the key from exactly one of
`private_key_file` (a path; relative paths resolve against the configuration
file's directory, or the working directory with `ROS_DEVICES_JSON`) or
`private_key_env`. An optional `passphrase_env` names the passphrase variable:

```text
ROS_MAIN_PASSWORD=<main RouterOS SSH password>
ROS_OFFICE_PRIVATE_KEY=<complete PEM/OpenSSH private-key text>
ROS_OFFICE_KEY_PASSPHRASE=<optional key passphrase>
```

`output_limit_bytes` (default 65536) caps the output returned per command;
larger output is cut and reported with `output_truncated=true`. Keep it small
enough for the model's context.

An inline `password` is plaintext in the configuration file. Treat that file as
a secret: do not commit it, and mount it read-only in containers. For a local
process, restrict it to the deployment user (for example, `chmod 600
devices.json`). The default `devices.json` name is excluded from Git and Docker
build contexts.

Device IDs must match `^[a-z][a-z0-9_-]{0,63}$`. Configuration is validated and
resolved once at startup, so restart the server after changing a configuration
file. Missing secrets, unknown fields, duplicate JSON keys, invalid IDs, and
malformed SHA-256 fingerprints prevent startup.

The host-key fingerprint is mandatory and is checked before authentication.
Unknown keys are never accepted through TOFU or Paramiko's `AutoAddPolicy`.

## Run locally

Python 3.11 or newer and [uv](https://docs.astral.sh/uv/) are required for local
development.

```bash
uv sync --all-groups
export ROS_DEVICES_JSON='{"main":{"host":"192.168.88.1","username":"ai-mgmt","auth":{"type":"password","password_env":"ROS_MAIN_PASSWORD"},"host_key":{"fingerprint_sha256":"SHA256:REPLACE_WITH_43_BASE64_CHARACTERS"}}}'
export ROS_MAIN_PASSWORD='replace-me'
uv run ros-mcp
```

To deploy from a file instead, put the JSON object above in a UTF-8 file and
pass its path. The inline password in the file requires no credential
environment variable.

```bash
chmod 600 /absolute/path/to/devices.json
uv run ros-mcp --config /absolute/path/to/devices.json
```

The process speaks MCP over stdio. Application code does not write ordinary
messages to stdout because stdout belongs to the protocol.

## Run with uvx

Use `uvx` to run a released version without cloning this repository. Pin the
Git tag (or a full commit SHA) so deployments do not move with a branch:

```bash
uvx --from 'git+https://github.com/asharca/ros-mcp.git@v0.2.0' \
  ros-mcp --config /absolute/path/to/devices.json
```

The final `ros-mcp` selects this project's console command. This requires `uv`
and Git. Do not use `uvx ros-mcp`: that PyPI name belongs to a different
project. This repository is installed from its Git source instead.

## Docker

Published images are available from GHCR:

```bash
docker pull ghcr.io/asharca/ros-mcp:latest
```

`main` publishes `latest`, `main`, and `sha-<commit>` tags. Git tags such as
`v1.2.3` additionally publish `1.2.3` and `1.2`.

Pushing a `v*` tag also creates a GitHub Release. Its notes list each commit
since the previous `v*` tag and every `BREAKING CHANGE:` footer, so describe
incompatible changes and their migration in that footer.

To build locally:

```bash
docker build -t ros-mcp:local .
docker run --rm -i \
  --read-only \
  --tmpfs /tmp:rw,size=16m \
  -e ROS_DEVICES_JSON \
  -e ROS_MAIN_PASSWORD \
  ros-mcp:local
```

The image runs as a non-root user, exposes no port, and starts the stdio MCP
server directly. Its root filesystem is safe to run read-only.

### Docker with a configuration file

Mount the configuration file read-only and pass the container path to
`--config` after the image name. A file with an inline password needs no
credential environment variable.

```bash
docker run --rm -i \
  --read-only \
  --tmpfs /tmp:rw,size=16m \
  --mount type=bind,src="/absolute/path/to/devices.json",dst=/config/devices.json,readonly \
  ghcr.io/asharca/ros-mcp:latest \
  --config /config/devices.json
```

Use an absolute source path that is visible to the Docker daemon. With Docker
Desktop, share the source directory; with a remote daemon, use a file or secret
mount managed on that daemon rather than a path from the MCP client's machine.
The mounted file must be readable by the image's UID/GID `10001`. Do not use
`-t` or `-d`: the MCP transport needs attached stdin and stdout. Do not disable
networking because the gateway needs outbound SSH access to RouterOS devices.
Use a managed secret mount or set an owner/ACL that permits UID/GID `10001` to
read the file without making it world-readable. If the file uses `password_env`,
`private_key_env`, or `passphrase_env`, forward each referenced variable with
Docker's `-e` option. A `private_key_file` must also be mounted into the
container at the path the configuration names.

## Deploy as an MCP server

ROS-MCP uses the stdio transport. Configure your MCP client to start one process
per server instance and keep its stdin and stdout connected to the client.
Client configuration formats differ; clients that use an `mcpServers` object can
use either of the following shapes.

### uvx

```json
{
  "mcpServers": {
    "ros-mcp": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/asharca/ros-mcp.git@v0.2.0",
        "ros-mcp",
        "--config",
        "/absolute/path/to/devices.json"
      ]
    }
  }
}
```

### Docker

```json
{
  "mcpServers": {
    "ros-mcp": {
      "command": "docker",
      "args": [
        "run",
        "--rm",
        "-i",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,size=16m",
        "--mount",
        "type=bind,src=/absolute/path/to/devices.json,dst=/config/devices.json,readonly",
        "ghcr.io/asharca/ros-mcp:latest",
        "--config",
        "/config/devices.json"
      ]
    }
  }
}
```

For a file that uses environment-variable credential references instead, add the
client's environment entries and matching Docker `-e` arguments. Verify host-key
fingerprints through a trusted out-of-band channel, use a least-privileged
RouterOS account, and keep manual approval enabled for `command_execute` in the
MCP client.

## ToolPlane

1. Publish the image to a registry reachable by ToolPlane's Docker daemon.
2. In a workspace, choose `MCP > Add custom MCP > Docker`.
3. For environment configuration, enter the image reference and leave Start
   Command empty. Add `ROS_DEVICES_JSON` and all referenced secret variables on
   the deployment's Variables page, then restart it.
4. For file configuration, use ToolPlane's file or secret-mount facility to
   place the file at (for example) `/config/devices.json`, then set Start Command
   to `--config /config/devices.json`. Add deployment variables only when the
   file uses environment-variable credential references, then restart it.
5. Leave `Disconnect from network` disabled so the container can reach RouterOS
   SSH addresses.

ToolPlane currently has a 30-second call timeout. Configure
`command_timeout_seconds` to about 25 seconds there, or raise ToolPlane's timeout
above the gateway's command timeout.

## Execution behavior

- One reusable SSH session is maintained per device.
- Commands for the same device are serialized in a bounded FIFO. The syntax
  check and the command it guards are two separate requests on that session.
- Different devices can execute concurrently.
- A stale session may reconnect once before command dispatch.
- A command is never replayed after dispatch.
- stdout and stderr are read as one stream and retained up to
  `output_limit_bytes`; the last 1 KiB is always kept to detect a RouterOS
  error after truncated output.
- All SSH clients are explicitly closed during MCP server shutdown.

## Logging

ROS-MCP has no audit-log Module, log-query tool, command history, or persistent
request/output storage. Expected operational failures are returned as structured
tool results. The MCP runtime is configured to emit only error-level diagnostics
to stderr.

## Development

```bash
uv run pytest
uv run ruff check src tests
uv run ruff format --check src tests
```
