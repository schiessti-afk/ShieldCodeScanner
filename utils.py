"""Filesystem, language, and text helpers for the static scanner.

The helpers in this module never execute repository code. File reads are
bounded, binary content is skipped, and paths are normalized for reports.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import FrozenSet, Iterable, Iterator, List, Optional, Set, Tuple

from models import SkipReason


# Directories skipped entirely during recursive traversal. Append names here
# to extend the exclusion list without changing walk logic.
SKIP_DIRECTORIES: List[str] = [
    ".git",
    "node_modules",
    "venv",
    ".venv",
    "env",
    ".env",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".tox",
    "dist",
    "build",
    "target",
    "vendor",
    "coverage",
]

DEFAULT_MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB
BINARY_SAMPLE_SIZE = 8192
MAX_SNIPPET_CHARS = 500
SNIPPET_RADIUS = 1

CODE_EXTENSIONS: FrozenSet[str] = frozenset(
    {
        ".py",
        ".js",
        ".ts",
        ".jsx",
        ".tsx",
        ".sh",
        ".bash",
        ".zsh",
        ".rb",
        ".go",
        ".rs",
        ".swift",
        ".bat",
        ".cmd",
        ".ps1",
        ".vbs",
    }
)

CONFIG_EXTENSIONS: FrozenSet[str] = frozenset(
    {
        ".yaml",
        ".yml",
        ".json",
        ".toml",
        ".ini",
        ".cfg",
        ".conf",
    }
)

# Exact filenames (case-insensitive) that should be scanned even without a
# code extension. Includes lockfiles and install-manifest names from §15.
EXACT_FILENAMES: FrozenSet[str] = frozenset(
    {
        "package.json",
        "package-lock.json",
        "npm-shrinkwrap.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "requirements.txt",
        "requirements-dev.txt",
        "pipfile",
        "pipfile.lock",
        "pyproject.toml",
        "poetry.lock",
        "makefile",
        "dockerfile",
        "docker-compose.yml",
        "docker-compose.yaml",
        "gemfile",
        "go.mod",
        "cargo.toml",
        ".env",
    }
)

EXT_TO_LANGUAGE = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "javascript",
    ".jsx": "javascript",
    ".tsx": "javascript",
    ".sh": "shell",
    ".bash": "shell",
    ".zsh": "shell",
    ".rb": "ruby",
    ".go": "go",
    ".rs": "rust",
    ".swift": "swift",
    ".bat": "batch",
    ".cmd": "batch",
    ".ps1": "powershell",
    ".vbs": "vbscript",
    ".yaml": "config",
    ".yml": "config",
    ".json": "config",
    ".toml": "config",
    ".ini": "config",
    ".cfg": "config",
    ".conf": "config",
}

FILENAME_TO_LANGUAGE = {
    "package.json": "package_json",
    "package-lock.json": "config",
    "npm-shrinkwrap.json": "config",
    "yarn.lock": "config",
    "pnpm-lock.yaml": "config",
    "requirements.txt": "python_deps",
    "requirements-dev.txt": "python_deps",
    "pipfile": "python_deps",
    "pipfile.lock": "config",
    "pyproject.toml": "python_deps",
    "poetry.lock": "config",
    "makefile": "makefile",
    "dockerfile": "dockerfile",
    "docker-compose.yml": "config",
    "docker-compose.yaml": "config",
    "gemfile": "ruby",
    "go.mod": "go",
    "cargo.toml": "rust",
}

PYTHON_KEYWORDS = frozenset(
    {
        "and",
        "as",
        "assert",
        "async",
        "await",
        "break",
        "class",
        "continue",
        "def",
        "del",
        "elif",
        "else",
        "except",
        "False",
        "finally",
        "for",
        "from",
        "global",
        "if",
        "import",
        "in",
        "is",
        "lambda",
        "None",
        "nonlocal",
        "not",
        "or",
        "pass",
        "raise",
        "return",
        "True",
        "try",
        "while",
        "with",
        "yield",
    }
)

_IDENT_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\b")
_SHELL_VAR_RE = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?")
_PS_VAR_RE = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)")

_ASSIGN_RES = {
    "python": re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$"),
    "javascript": re.compile(
        r"^\s*(?:(?:const|let|var)\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$"
    ),
    "ruby": re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$"),
    "go": re.compile(
        r"^\s*(?:var\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*(?::=|=)\s*(.+)$"
    ),
    "rust": re.compile(
        r"^\s*let\s+(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$"
    ),
    "swift": re.compile(
        r"^\s*(?:let|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$"
    ),
    "shell": re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=([^=].*)$"),
    "powershell": re.compile(r"^\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$"),
    "batch": re.compile(r"(?i)^\s*set\s+(?:/[a-z]\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.+)$"),
}


def skip_directory_names() -> FrozenSet[str]:
    """Return the live exclusion set so callers always see list updates."""
    return frozenset(SKIP_DIRECTORIES)


def should_skip_dir(name: str) -> bool:
    return name in skip_directory_names()


def is_env_filename(name: str) -> bool:
    return name == ".env" or name.startswith(".env.")


def should_scan_file(path: Path) -> bool:
    """Return True if filename/extension rules say this file is in scope."""
    name = path.name
    lower = name.lower()
    if lower in EXACT_FILENAMES or is_env_filename(name):
        return True
    suffix = path.suffix.lower()
    return suffix in CODE_EXTENSIONS or suffix in CONFIG_EXTENSIONS


def detect_language(path: Path) -> Optional[str]:
    name = path.name
    lower = name.lower()
    if is_env_filename(name):
        return "dotenv"
    if lower in FILENAME_TO_LANGUAGE:
        return FILENAME_TO_LANGUAGE[lower]
    suffix = path.suffix.lower()
    return EXT_TO_LANGUAGE.get(suffix)


def normalize_report_path(path: Path, root: Path) -> str:
    """Return a deterministic repo-relative POSIX path."""
    try:
        relative = path.resolve().relative_to(root.resolve())
    except ValueError:
        relative = Path(os.path.relpath(str(path), str(root)))
    return relative.as_posix()


def iter_scannable_files(root: Path) -> Iterator[Path]:
    """Yield unique files under *root*, skipping excluded directories.

    Directory symlinks are not followed. Duplicate real paths are skipped.
    """
    seen: Set[str] = set()
    root = root.resolve()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [name for name in dirnames if not should_skip_dir(name)]
        dirnames.sort()
        for filename in sorted(filenames):
            path = Path(dirpath) / filename
            if not should_scan_file(path):
                continue
            try:
                real = str(path.resolve())
            except OSError:
                continue
            if real in seen:
                continue
            seen.add(real)
            yield path


def read_text_file(
    path: Path, max_file_size: int
) -> Tuple[Optional[str], Optional[SkipReason]]:
    """Read a file as UTF-8 text, or return a skip reason.

    Never raises for malformed content. Unexpected OS errors are returned as
    ``UNREADABLE`` so the scan can continue.
    """
    try:
        size = path.stat().st_size
    except OSError:
        return None, SkipReason.UNREADABLE

    if size > max_file_size:
        return None, SkipReason.OVERSIZE
    if size == 0:
        return "", None

    try:
        with path.open("rb") as handle:
            sample = handle.read(BINARY_SAMPLE_SIZE)
            if b"\x00" in sample:
                return None, SkipReason.BINARY
            remaining = max(0, min(size, max_file_size) - len(sample))
            data = sample + handle.read(remaining)
    except OSError:
        return None, SkipReason.UNREADABLE

    if b"\x00" in data:
        return None, SkipReason.BINARY

    try:
        return data.decode("utf-8"), None
    except UnicodeDecodeError:
        return None, SkipReason.INVALID_UTF8


def split_lines(text: str) -> List[str]:
    return text.splitlines()


def extract_assignment(language: str, line: str) -> Optional[Tuple[str, str]]:
    """Return ``(name, rhs)`` if *line* looks like a simple assignment."""
    lang = language
    if lang in {"makefile", "dockerfile"}:
        lang = "shell"
    pattern = _ASSIGN_RES.get(lang)
    if pattern is None:
        return None
    match = pattern.match(line.rstrip())
    if not match:
        return None
    return match.group(1), match.group(2)


def identifiers_in(text: str, language: str) -> Set[str]:
    """Extract identifier / variable names referenced in *text*."""
    names: Set[str] = set(_IDENT_RE.findall(text))
    if language in {"shell", "makefile", "dockerfile", "batch"}:
        names.update(_SHELL_VAR_RE.findall(text))
    if language == "powershell":
        names.update(_PS_VAR_RE.findall(text))
    names.difference_update(PYTHON_KEYWORDS)
    return names


def make_snippet(
    lines: List[str],
    primary_line: int,
    extra_lines: Optional[Iterable[int]] = None,
    radius: int = SNIPPET_RADIUS,
    max_chars: int = MAX_SNIPPET_CHARS,
) -> str:
    """Build a short, original-text snippet around the triggering line(s)."""
    selected: Set[int] = set()
    anchors = {primary_line}
    if extra_lines:
        anchors.update(extra_lines)
    for line_no in anchors:
        for candidate in range(line_no - radius, line_no + radius + 1):
            if 1 <= candidate <= len(lines):
                selected.add(candidate)
    snippet = "\n".join(lines[idx - 1].rstrip("\n") for idx in sorted(selected))
    if len(snippet) > max_chars:
        return snippet[: max_chars - 3] + "..."
    return snippet
