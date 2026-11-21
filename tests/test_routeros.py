"""RouterOS parsing rules, checked against output recorded from RouterOS 7.25.1."""

from __future__ import annotations

import pytest

from ros_mcp.routeros import (
    interpret_parse_output,
    normalize_output,
    parse_check_script,
    read_only_violation,
    read_verb_violation,
    runtime_error,
)


def test_parse_check_script_hex_escapes_every_byte() -> None:
    script = parse_check_script('/x "$y" 中')

    assert script == (':put [:parse "\\2F\\78\\20\\22\\24\\79\\22\\20\\E4\\B8\\AD"]')


@pytest.mark.parametrize(
    ("printed", "errors"),
    [
        ("(evl /ip/address/print)\r\n", ()),
        ("(evl /system/reboot)\r\n", ()),
        (
            "(<%% bad command name foo (line 1 column 2) foo;bar)\r\n",
            ("bad command name foo (line 1 column 2)",),
        ),
        (
            "(evl bad parameter detail (line 1 column 30) /system/identity/print)\r\n",
            ("bad parameter detail (line 1 column 30)",),
        ),
        (
            "expected end of command (line 1 column 19)\r\n",
            ("expected end of command (line 1 column 19)",),
        ),
        (
            "(evl /ip/address/print);(<%% bad command name foo (line 1 column 21) foo)\r\n",
            ("bad command name foo (line 1 column 21)",),
        ),
        ("(<%% something new)\r\n", ("RouterOS rejected the command syntax",)),
    ],
)
def test_parse_errors_are_extracted(printed: str, errors: tuple[str, ...]) -> None:
    assert interpret_parse_output(printed).errors == errors


@pytest.mark.parametrize(
    "printed",
    [
        "(evl /ip/address/print)",
        "(evl /ip/address/printdetail=true)",
        "(evl /system/identity/getvalue-name=name)",
        "(evl /export)",
        "(evl /ip/firewall/filter/exportterse=true)",
        "(evl /interface/monitor-trafficinterface=ether1;once=true)",
        "(evl /interface/ethernet/monitornumbers=ether1;once=true)",
        "(evl /ip/route/printwhere=$dst-address;$gateway;(= $dst-address 0.0.0.0/0);5)",
    ],
)
def test_read_verbs_are_accepted(printed: str) -> None:
    assert read_verb_violation(interpret_parse_output(printed)) is None


@pytest.mark.parametrize(
    "printed",
    [
        "(evl /system/reboot)",
        "(evl /ip/address/addaddress=192.0.2.1;32;interface=x)",
        "(evl /interface/setmtu=abc;numbers=ether1)",
        "(evl /ip/address/removenumbers=(evl (evl /ip/address/find)))",
        "(evl /ip/address/print);(evl /system/reboot)",
        "(evl /errormessage=x)",
        "/ip/address/",
        # A value with an unbalanced parenthesis must not hide a second statement.
        "(evl /ip/address/printwhere=$comment;(= $comment a)b;c);5)",
        # A verb that merely starts like a read verb.
        "(evl /tool/printer)",
    ],
)
def test_non_read_commands_are_rejected(printed: str) -> None:
    assert read_verb_violation(interpret_parse_output(printed)) is not None


@pytest.mark.parametrize(
    "command",
    [
        "/ip address print",
        '/ip address print where comment="a;b [c] {d}"',
        "/ip route print where dst-address=0.0.0.0/0",
        "/ipv6 address print where address=::1/128",
        '/log print where message~"\\"quoted\\""',
    ],
)
def test_plain_read_commands_pass_the_local_check(command: str) -> None:
    assert read_only_violation(command) is None


@pytest.mark.parametrize(
    "command",
    [
        "/ip address print; /system reboot",
        "/ip address remove [find]",
        ":put [/system identity get name]",
        ":global x",
        '/ip address print where comment="$x"',
        "/ip address print where comment=$x",
        "/ip address print file=out",
        "/export show-sensitive",
        '/ip address print where comment="open',
        "/system script run { x }",
    ],
)
def test_scripting_and_side_effects_fail_the_local_check(command: str) -> None:
    assert read_only_violation(command) is not None


@pytest.mark.parametrize(
    ("tail", "error"),
    [
        (b"bad command name foo (line 1 column 2)\n", "bad command name foo (line 1 column 2)"),
        (b"no such item (/ip/address/get; line 1)\n", "no such item (/ip/address/get; line 1)"),
        (b"a\r\nboom (:error; line 1)\n", "boom (:error; line 1)"),
        (
            b"11\r\nno such item (/ip/address/get; line 1)\n",
            "no such item (/ip/address/get; line 1)",
        ),
        (
            b"Script Error: missing value(s) of argument(s) address interface "
            b"(/ip/address/add; line 1)\n",
            "Script Error: missing value(s) of argument(s) address interface "
            "(/ip/address/add; line 1)",
        ),
    ],
)
def test_runtime_errors_are_detected(tail: bytes, error: str) -> None:
    assert runtime_error(tail) == error


@pytest.mark.parametrize(
    "tail",
    [
        b"  name: CCR1072\r\n\r\n",
        b"\r\n",
        b"",
        # Ordinary output lines end with CRLF, even when they look like an error.
        b"note (line 1 column 2)\r\n",
        b"error (x; line 3)\r\nmore\r\n",
    ],
)
def test_ordinary_output_is_not_an_error(tail: bytes) -> None:
    assert runtime_error(tail) is None


def test_output_is_normalized() -> None:
    raw = b"   uptime: 2w1d      \r\n  version: 7.25.1   \r\n\r\n"

    assert normalize_output(raw) == "   uptime: 2w1d\n  version: 7.25.1"
