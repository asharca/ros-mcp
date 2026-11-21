"""RouterOS CLI semantics: syntax checks, read-only checks, and error detection.

RouterOS's SSH server reports exit status 0 even when a command fails. Errors are only
visible in the output, as a final line terminated by a bare ``\\n`` (ordinary output uses
``\\r\\n``), for example::

    bad command name foo (line 1 column 2)
    no such item (/ip/address/get; line 1)

``:parse`` compiles a script without running it. Its printed form is undocumented, so every
check built on it fails closed when the shape is not recognised.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

READ_VERBS = ("monitor-traffic", "monitor", "export", "print", "get")
_READ_FORBIDDEN_ARGUMENTS = frozenset({"file", "show-sensitive"})

_POSITION_RE = re.compile(r"\(line \d+ column \d+\)")
_PARSE_ERROR_RE = re.compile(
    r"(?:^|\(evl |\(<%% )(?P<message>[^()]*?) \(line (?P<line>\d+) column (?P<column>\d+)\)"
)
_COMMAND_PATH_RE = re.compile(r"\(evl (/[A-Za-z0-9/_.-]*)")
_RUNTIME_ERROR_RE = re.compile(
    rb"(?:\A|\n)(?P<line>[^\r\n]* \((?:line \d+ column \d+|[^()\r\n]*; line \d+)\))\n\Z"
)


@dataclass(frozen=True, slots=True)
class ParsedCommand:
    """RouterOS's view of a command, from ``:put [:parse ...]``."""

    errors: tuple[str, ...]
    statements: tuple[str, ...]


def parse_check_script(command: str) -> str:
    """Return a script that prints RouterOS's parse of ``command`` without running it.

    Every byte is hex-escaped, so the command cannot terminate the string or trigger
    ``$`` substitution inside it.
    """

    escaped = "".join(f"\\{byte:02X}" for byte in command.encode("utf-8"))
    return f':put [:parse "{escaped}"]'


def interpret_parse_output(output: str) -> ParsedCommand:
    text = output.strip()
    errors = tuple(
        f"{match['message'].strip()} (line {match['line']} column {match['column']})"
        for match in _PARSE_ERROR_RE.finditer(text)
    )
    if not errors and (_POSITION_RE.search(text) or "<%%" in text):
        errors = ("RouterOS rejected the command syntax",)
    return ParsedCommand(errors=errors, statements=_split_top_level(text))


def read_only_violation(command: str) -> str | None:
    """Reject syntax that could run more than one read command, before contacting a device."""

    tokens: list[str] = []
    current: list[str] = []
    in_quote = False
    escaped = False
    for character in command:
        if character == "$":
            return "variables and substitutions are not allowed in command_read"
        if in_quote:
            current.append(character)
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_quote = False
            continue
        if character in ";[]{}":
            return "scripting syntax (; [ ] { }) is not allowed in command_read"
        if character.isspace():
            if current:
                tokens.append("".join(current))
                current = []
            continue
        if character == '"':
            in_quote = True
        current.append(character)
    if in_quote:
        return "command has an unterminated quote"
    if current:
        tokens.append("".join(current))

    for token in tokens:
        if token.startswith(":"):
            return "scripting commands are not allowed in command_read"
        name = token.split("=", 1)[0]
        if name in _READ_FORBIDDEN_ARGUMENTS:
            return f"argument {name!r} is not allowed in command_read"
    return None


def read_verb_violation(parsed: ParsedCommand) -> str | None:
    """Require exactly one RouterOS command whose verb is a read verb."""

    rejection = f"command_read only runs one {'/'.join(READ_VERBS)} command; use command_execute"
    if len(parsed.statements) != 1:
        return rejection
    statement = parsed.statements[0]
    match = _COMMAND_PATH_RE.match(statement)
    if match is None or statement.count("(evl ") != 1:
        return rejection

    # The printed form glues the first argument name to the verb: "/ip/address/printwhere=...".
    segment = match[1].rsplit("/", 1)[-1]
    verb = next((verb for verb in READ_VERBS if segment.startswith(verb)), None)
    if verb is None:
        return rejection
    if len(segment) > len(verb) and statement[match.end() : match.end() + 1] != "=":
        return rejection
    return None


def runtime_error(tail: bytes) -> str | None:
    """Return RouterOS's error line if the output ends with one."""

    match = _RUNTIME_ERROR_RE.search(tail)
    if match is None:
        return None
    return match["line"].decode("utf-8", errors="replace").strip()


def normalize_output(raw: bytes) -> str:
    """Decode output and drop RouterOS's CRs and column padding."""

    text = raw.decode("utf-8", errors="replace")
    return "\n".join(line.rstrip(" \r") for line in text.split("\n")).strip("\n")


def _split_top_level(text: str) -> tuple[str, ...]:
    statements: list[str] = []
    depth = 0
    start = 0
    for index, character in enumerate(text):
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
        elif character == ";" and depth == 0:
            statements.append(text[start:index])
            start = index + 1
    statements.append(text[start:])
    return tuple(statement for statement in statements if statement)
