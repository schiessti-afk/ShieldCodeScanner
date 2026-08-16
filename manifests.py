"""Structured walks of package.json and pyproject.toml.

Lifecycle scripts and tool-hook commands are read from the parsed
document, not from a line-regex over a minified file. ``json`` and
``tomllib`` (or a small TOML subset fallback) never execute hooks.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, List, Optional, Pattern, Tuple

from models import Finding
from utils import make_snippet

try:
    import tomllib
except ImportError:  # Python < 3.11
    tomllib = None  # type: ignore[assignment]


NPM_LIFECYCLE = frozenset(
    {
        "preinstall",
        "install",
        "postinstall",
        "prepare",
        "preuninstall",
        "postuninstall",
        "prepublish",
        "prepublishOnly",
        "prepack",
        "postpack",
    }
)

_HOOK_CHECKS: List[Tuple[Pattern[str], str, str, str]] = [
    (
        re.compile(r"(?i)(?:curl|wget)\b[^\n]{0,300}\|\s*(?:sudo\s+)?(?:ba)?sh\b"),
        "npm_lifecycle_execution",
        "high",
        "Suspicious package lifecycle script detected: a hook downloads "
        "remote content and pipes it to a shell.",
    ),
    (
        re.compile(r"(?i)powershell[^\n]{0,80}-(?:enc|encodedcommand|e)\b"),
        "npm_lifecycle_execution",
        "high",
        "Suspicious package lifecycle script detected: a hook launches "
        "encoded PowerShell.",
    ),
    (
        re.compile(
            r"(?i)(?:curl|wget|invoke-webrequest).{0,200}"
            r"(?:API_KEY|SECRET|TOKEN|PASSWORD|AWS_|ANTHROPIC_|OPENAI_)"
        ),
        "npm_lifecycle_execution",
        "critical",
        "Suspicious package lifecycle script detected: a hook appears "
        "to transmit secret-like values to a remote endpoint.",
    ),
    (
        re.compile(
            r"(?i)(?:crontab|\.bashrc|\.zshrc|LaunchAgents|"
            r"CurrentVersion\\\\Run|schtasks)"
        ),
        "npm_lifecycle_execution",
        "high",
        "Suspicious package lifecycle script detected: a hook appears "
        "to modify a persistence location.",
    ),
    (
        re.compile(r"(?i)(?:IEX|Invoke-Expression|eval\s*\(|node\s+-e\s+.*http)"),
        "npm_lifecycle_execution",
        "high",
        "Suspicious package lifecycle script detected: a hook uses "
        "dynamic evaluation together with remote content.",
    ),
]


def suspicious_hook_command(command: str) -> Optional[Tuple[str, str, str]]:
    """Return ``(pattern, severity, description)`` if *command* looks abusive."""
    for regex, pattern, severity, description in _HOOK_CHECKS:
        if regex.search(command):
            return pattern, severity, description
    return None


def analyze_package_json(report_path: str, text: str, lines: List[str]) -> List[Finding]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []
    return _findings_from_commands(
        report_path, text, lines, _package_json_commands(data)
    )


def analyze_pyproject_toml(report_path: str, text: str, lines: List[str]) -> List[Finding]:
    data = load_toml(text)
    if not isinstance(data, dict):
        return []
    return _findings_from_commands(
        report_path, text, lines, _pyproject_commands(data)
    )


def load_toml(text: str) -> Optional[Dict[str, Any]]:
    """Parse TOML via stdlib ``tomllib`` or a conservative subset fallback."""
    if tomllib is not None:
        try:
            loaded = tomllib.loads(text)
        except (tomllib.TOMLDecodeError, ValueError):
            return None
        return loaded if isinstance(loaded, dict) else None
    try:
        loaded = _parse_toml_subset(text)
    except (ValueError, KeyError):
        return None
    return loaded if isinstance(loaded, dict) else None


def _package_json_commands(data: Dict[str, Any]) -> List[Tuple[str, str]]:
    commands: List[Tuple[str, str]] = []
    scripts = data.get("scripts")
    if isinstance(scripts, dict):
        for name, command in scripts.items():
            if name in NPM_LIFECYCLE and isinstance(command, str):
                commands.append((str(name), command))

    husky = data.get("husky")
    if isinstance(husky, dict):
        hooks = husky.get("hooks")
        if isinstance(hooks, dict):
            for name, command in hooks.items():
                if isinstance(command, str):
                    commands.append((f"husky.{name}", command))

    simple = data.get("simple-git-hooks")
    if isinstance(simple, dict):
        for name, command in simple.items():
            if isinstance(command, str):
                commands.append((f"simple-git-hooks.{name}", command))

    ghooks = data.get("config")
    if isinstance(ghooks, dict):
        nested = ghooks.get("ghooks")
        if isinstance(nested, dict):
            for name, command in nested.items():
                if isinstance(command, str):
                    commands.append((f"ghooks.{name}", command))

    lint_staged = data.get("lint-staged")
    if isinstance(lint_staged, dict):
        for name, command in lint_staged.items():
            for item in _as_command_list(command):
                commands.append((f"lint-staged.{name}", item))
    return commands


def _pyproject_commands(data: Dict[str, Any]) -> List[Tuple[str, str]]:
    commands: List[Tuple[str, str]] = []
    tool = data.get("tool")
    if not isinstance(tool, dict):
        return commands

    pdm = tool.get("pdm")
    if isinstance(pdm, dict):
        commands.extend(_named_commands("pdm.scripts", pdm.get("scripts")))

    poe = tool.get("poe")
    if isinstance(poe, dict):
        commands.extend(_named_commands("poe.tasks", poe.get("tasks")))

    taskipy = tool.get("taskipy")
    if isinstance(taskipy, dict):
        commands.extend(_named_commands("taskipy.tasks", taskipy.get("tasks")))

    hatch = tool.get("hatch")
    if isinstance(hatch, dict):
        envs = hatch.get("envs")
        if isinstance(envs, dict):
            for env_name, env in envs.items():
                if isinstance(env, dict):
                    commands.extend(
                        _named_commands(
                            f"hatch.envs.{env_name}.scripts", env.get("scripts")
                        )
                    )

    poetry = tool.get("poetry")
    if isinstance(poetry, dict):
        scripts = poetry.get("scripts")
        if isinstance(scripts, dict):
            for name, command in scripts.items():
                if isinstance(command, str) and _looks_like_shell(command):
                    commands.append((f"poetry.scripts.{name}", command))
    return commands


def _named_commands(prefix: str, value: Any) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    if isinstance(value, dict):
        for name, command in value.items():
            for item in _as_command_list(command):
                out.append((f"{prefix}.{name}", item))
    elif isinstance(value, list):
        for index, command in enumerate(value):
            for item in _as_command_list(command):
                out.append((f"{prefix}[{index}]", item))
    elif isinstance(value, str):
        out.append((prefix, value))
    return out


def _as_command_list(value: Any) -> List[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    if isinstance(value, dict):
        collected: List[str] = []
        for key in ("cmd", "command", "shell", "script"):
            item = value.get(key)
            if isinstance(item, str):
                collected.append(item)
        return collected
    return []


def _looks_like_shell(command: str) -> bool:
    return bool(re.search(r"(?i)\b(?:curl|wget|bash|sh|powershell)\b", command))


def _findings_from_commands(
    report_path: str,
    text: str,
    lines: List[str],
    commands: Iterable[Tuple[str, str]],
) -> List[Finding]:
    findings: List[Finding] = []
    seen = set()
    for name, command in commands:
        hit = suspicious_hook_command(command)
        if hit is None:
            continue
        pattern, severity, description = hit
        line_no = _line_of(text, name, command)
        key = (line_no, pattern, name)
        if key in seen:
            continue
        seen.add(key)
        dest_kind, dest_hint = _destination_of(command)
        findings.append(
            Finding(
                file=report_path,
                line=line_no,
                pattern=pattern,
                severity=severity,
                description=description,
                code_snippet=make_snippet(lines, line_no),
                source_kind="download",
                sink_kind="exec_dynamic",
                destination_kind=dest_kind,
                destination_hint=dest_hint,
                flow=(
                    f"{report_path}:{line_no} install hook → dynamic exec",
                ),
            )
        )
    return findings


def _destination_of(command: str) -> Tuple[str, str]:
    from incidents import destination_from_text

    return destination_from_text(command)


def _line_of(text: str, name: str, command: str) -> int:
    for needle in (command[: min(80, len(command))], name.split(".")[-1], name):
        if not needle:
            continue
        idx = text.find(needle)
        if idx >= 0:
            return text.count("\n", 0, idx) + 1
    return 1


def _parse_toml_subset(text: str) -> Dict[str, Any]:
    """Parse tables and string/array/inline-table assignments (Python 3.9–3.10)."""
    root: Dict[str, Any] = {}
    current: Dict[str, Any] = root
    pending = ""
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].rstrip()
        if pending:
            pending += "\n" + line
            if _balanced(pending):
                _assign_line(current, pending)
                pending = ""
            continue
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            header = stripped[1:-1].strip()
            if header.startswith("["):
                continue
            current = _ensure_table(root, header)
            continue
        if "=" not in stripped:
            continue
        if not _balanced(stripped):
            pending = stripped
            continue
        _assign_line(current, stripped)
    return root


def _ensure_table(root: Dict[str, Any], header: str) -> Dict[str, Any]:
    node: Dict[str, Any] = root
    for part in _split_dotted(header):
        existing = node.get(part)
        if not isinstance(existing, dict):
            existing = {}
            node[part] = existing
        node = existing
    return node


def _assign_line(current: Dict[str, Any], line: str) -> None:
    key, _, raw_value = line.partition("=")
    name = key.strip().strip("\"'")
    if not name:
        return
    value = _parse_toml_value(raw_value.strip())
    target = current
    parts = _split_dotted(name)
    for part in parts[:-1]:
        existing = target.get(part)
        if not isinstance(existing, dict):
            existing = {}
            target[part] = existing
        target = existing
    target[parts[-1]] = value


def _parse_toml_value(raw: str) -> Any:
    text = raw.strip()
    if not text:
        return ""
    if text in {"true", "false"}:
        return text == "true"
    if text.startswith("[") and text.endswith("]"):
        inner = text[1:-1].strip()
        if not inner:
            return []
        return [
            item
            for item in (_parse_toml_value(part.strip()) for part in _split_top(inner, ","))
            if item != ""
        ]
    if text.startswith("{") and text.endswith("}"):
        table: Dict[str, Any] = {}
        inner = text[1:-1].strip()
        if inner:
            for part in _split_top(inner, ","):
                if "=" in part:
                    _assign_line(table, part)
        return table
    if text.startswith('"""') and text.endswith('"""') and len(text) >= 6:
        return text[3:-3]
    if text.startswith("'''") and text.endswith("'''") and len(text) >= 6:
        return text[3:-3]
    if (text.startswith('"') and text.endswith('"')) or (
        text.startswith("'") and text.endswith("'")
    ):
        return text[1:-1]
    return text


def _split_dotted(header: str) -> List[str]:
    parts: List[str] = []
    buf = []
    in_quote = False
    for char in header:
        if char in {'"', "'"}:
            in_quote = not in_quote
            continue
        if char == "." and not in_quote:
            part = "".join(buf).strip()
            if part:
                parts.append(part)
            buf = []
            continue
        buf.append(char)
    tail = "".join(buf).strip()
    if tail:
        parts.append(tail)
    return parts


def _split_top(text: str, sep: str) -> List[str]:
    parts: List[str] = []
    buf: List[str] = []
    depth = 0
    in_quote = ""
    for char in text:
        if in_quote:
            buf.append(char)
            if char == in_quote:
                in_quote = ""
            continue
        if char in {'"', "'"}:
            in_quote = char
            buf.append(char)
            continue
        if char in "{[":
            depth += 1
        elif char in "}]":
            depth = max(0, depth - 1)
        if char == sep and depth == 0:
            parts.append("".join(buf))
            buf = []
            continue
        buf.append(char)
    if buf:
        parts.append("".join(buf))
    return parts


def _balanced(text: str) -> bool:
    return (
        text.count("{") == text.count("}")
        and text.count("[") == text.count("]")
        and text.count('"""') % 2 == 0
    )


# Keep a stable alias used by older tests that imported the rules helper.
_suspicious_install_script = suspicious_hook_command
