"""Local static security scanner.

This tool identifies *suspicious source-code patterns* for human review. It
never executes, imports, compiles, or modifies scanned files, never contacts
URLs found in repositories, and never blocks, deletes, or quarantines code.

Exit codes:
    0  no findings
    1  findings detected
    2  scanner or input error
"""

from __future__ import annotations

import argparse
import json
import posixpath
import re
import sys
from pathlib import Path
from typing import Dict, Iterable, List, NamedTuple, Optional, Sequence, Set, Tuple

from models import (
    SCANNER_VERSION,
    SEVERITY_RANK,
    Finding,
    ScanReport,
    SkipReason,
    SkippedFile,
)
from rules import (
    ComboRule,
    DirectRule,
    SignalDef,
    combo_rules_for_language,
    direct_rules_for_language,
    file_rules_for,
    signals_for_language,
)
from utils import (
    DEFAULT_MAX_FILE_SIZE,
    detect_language,
    extract_assignment,
    identifiers_in,
    iter_scannable_files,
    make_snippet,
    normalize_report_path,
    read_text_file,
    split_lines,
)

AMBIENT_WINDOW = 25
AMBIENT_LANGUAGES = frozenset(
    {
        "shell",
        "powershell",
        "batch",
        "dockerfile",
        "makefile",
        "config",
        "package_json",
        "vbscript",
    }
)

SINK_SIGNAL_IDS = frozenset(
    {
        "network",
        "exec_dynamic",
        "delete_recursive",
        "persistence",
        "chmod_exec",
    }
)

# Findings that represent the same underlying behavior on one line are merged,
# keeping the strongest severity. Distinct pattern IDs on different lines stay
# separate.
PATTERN_GROUPS = {
    "destructive_root_deletion": "destructive",
    "destructive_path_deletion": "destructive",
    "privilege_destructive": "destructive",
    "download_and_execute": "download_exec",
    "pipe_to_shell": "download_exec",
    "powershell_download_iex": "download_exec",
    "privilege_download_execute": "download_exec",
    "obfuscated_download_execution": "download_exec",
    "standalone_file_download": "download_exec",
    "obfuscated_execution": "obfuscated_exec",
    "encoded_powershell": "obfuscated_exec",
    "api_key_exfiltration": "exfil",
    "sensitive_file_exfiltration": "exfil",
    "sensitive_file_access": "exfil",
    "persistence_modification": "persistence",
    "persistence_with_remote_payload": "persistence",
    "persistence_with_obfuscation": "persistence",
    "npm_lifecycle_execution": "npm",
}

_WITH_AS_RE = re.compile(
    r"^\s*with\s+.+\bas\s+([A-Za-z_][A-Za-z0-9_]*)\s*:"
)

_COMMENT_PREFIXES = {
    "python": ("#",),
    "shell": ("#",),
    "makefile": ("#",),
    "dockerfile": ("#",),
    "ruby": ("#",),
    "python_deps": ("#",),
    "dotenv": ("#",),
    "config": ("#",),
    "javascript": ("//", "/*"),
    "go": ("//", "/*"),
    "rust": ("//", "/*"),
    "swift": ("//", "/*"),
    "powershell": ("#",),
    "batch": ("rem ", "::"),
}


STATEMENT_GROUP_LANGUAGES = frozenset(
    {
        "python",
        "javascript",
        "go",
        "rust",
        "swift",
        "ruby",
    }
)

# Languages whose imports/exports are indexed for cross-file taint.
INDEX_LANGUAGES = frozenset({"python", "javascript"})
_CODE_MODULE_EXTS = (".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs")

_DOT_ATTR_RE = re.compile(r"\.([A-Za-z_][A-Za-z0-9_]*)")
_PY_DEF_RE = re.compile(r"^(\s*)(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_JS_DEF_RE = re.compile(
    r"^(\s*)(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\("
)
_RETURN_RE = re.compile(r"^\s*return(?:\s+|$)(.*)$")
_PY_IMPORT_RE = re.compile(r"^\s*import\s+(.+)$")
_PY_FROM_RE = re.compile(
    r"^\s*from\s+(\.+[A-Za-z_][A-Za-z0-9_.]*|\.+|[A-Za-z_][A-Za-z0-9_.]*)"
    r"\s+import\s+(.+)$"
)
_JS_IMPORT_NAMED_RE = re.compile(
    r"""import\s+\{([^}]*)\}\s+from\s+['"]([^'"]+)['"]"""
)
_JS_IMPORT_STAR_RE = re.compile(
    r"""import\s+\*\s+as\s+([A-Za-z_][A-Za-z0-9_]*)\s+from\s+['"]([^'"]+)['"]"""
)
_JS_IMPORT_DEFAULT_RE = re.compile(
    r"""import\s+([A-Za-z_][A-Za-z0-9_]*)\s+from\s+['"]([^'"]+)['"]"""
)
_JS_REQUIRE_RE = re.compile(
    r"""(?:const|let|var)\s+(?:\{([^}]+)\}|([A-Za-z_][A-Za-z0-9_]*))"""
    r"""\s*=\s*require\(\s*['"]([^'"]+)['"]\s*\)"""
)
_IMPORT_NAME_RE = re.compile(
    r"^([A-Za-z_][A-Za-z0-9_.]*)(?:\s+as\s+([A-Za-z_][A-Za-z0-9_]*))?$"
)
_JS_IMPORT_ITEM_RE = re.compile(
    r"^([A-Za-z_][A-Za-z0-9_]*)(?:\s+as\s+([A-Za-z_][A-Za-z0-9_]*))?$"
)


def _is_comment_line(line: str, language: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return True
    prefixes = _COMMENT_PREFIXES.get(language, ())
    lowered = stripped.lower()
    return any(lowered.startswith(prefix) for prefix in prefixes)


def _paren_delta(text: str) -> int:
    return (
        text.count("(")
        + text.count("[")
        + text.count("{")
        - text.count(")")
        - text.count("]")
        - text.count("}")
    )


def iter_logical_statements(
    lines: List[str], language: str, max_continue: int = 12
):
    """Group physical lines that continue an unclosed `(...)` / `[...]` / `{...}`.

    This is a lightweight approximation so ``requests.post(\\n..., data=secret)``
    is treated as one statement for taint purposes. It does not parse strings.
    Config and shell files are processed line-by-line so JSON/YAML braces do
    not swallow an entire file.
    """
    if language not in STATEMENT_GROUP_LANGUAGES:
        for index, text in enumerate(lines, start=1):
            yield index, index, text
        return
    index = 0
    total = len(lines)
    while index < total:
        start = index
        depth = _paren_delta(lines[index])
        while depth > 0 and index + 1 < total and (index - start) < max_continue:
            index += 1
            depth += _paren_delta(lines[index])
        start_line = start + 1
        end_line = index + 1
        text = "\n".join(lines[start:index + 1])
        yield start_line, end_line, text
        index += 1


class _LoadedFile(NamedTuple):
    path: Path
    report_path: str
    language: str
    filename: str
    text: str


class ExportIndex:
    """Static map of scanned modules to exported names and their taint kinds.

    Built from source text only. Never imports, compiles, or executes modules.
    """

    def __init__(self) -> None:
        self.by_path: Dict[str, Dict[str, Set[str]]] = {}
        self.by_key: Dict[str, List[str]] = {}

    def add(self, report_path: str, exports: Dict[str, Set[str]]) -> None:
        self.by_path[report_path] = {name: set(kinds) for name, kinds in exports.items()}
        for key in _module_keys(report_path):
            self.by_key.setdefault(key, []).append(report_path)

    def exports_of(self, report_path: str, name: str) -> Set[str]:
        return set(self.by_path.get(report_path, {}).get(name, ()))

    def all_exports(self, report_path: str) -> Dict[str, Set[str]]:
        stored = self.by_path.get(report_path)
        if not stored:
            return {}
        return {name: set(kinds) for name, kinds in stored.items()}


class ImportContext:
    """Resolved imports for one file, used to seed and look up foreign taint."""

    def __init__(self, index: ExportIndex) -> None:
        self.index = index
        self.names: Dict[str, Set[str]] = {}
        self.imported_paths: Set[str] = set()

    def extra_taints(self, line: str) -> Set[str]:
        found: Set[str] = set()
        if not self.imported_paths:
            return found
        for attr in _DOT_ATTR_RE.findall(line):
            for path in self.imported_paths:
                found.update(self.index.exports_of(path, attr))
        return found


def _leading_indent(line: str) -> int:
    if not line.strip():
        return -1
    prefix = line[: len(line) - len(line.lstrip(" \t"))]
    return len(prefix.expandtabs(4))


def _module_keys(report_path: str) -> List[str]:
    posix = report_path.replace("\\", "/")
    stem = posix
    lower = posix.lower()
    for ext in _CODE_MODULE_EXTS:
        if lower.endswith(ext):
            stem = posix[: -len(ext)]
            break
    if stem.endswith("/__init__"):
        stem = stem[: -len("/__init__")]
    dotted = stem.replace("/", ".")
    keys: List[str] = []
    seen: Set[str] = set()
    if dotted:
        keys.append(dotted)
        tail = dotted.rsplit(".", 1)[-1]
        if tail != dotted:
            keys.append(tail)
    out: List[str] = []
    for key in keys:
        if key and key not in seen:
            seen.add(key)
            out.append(key)
    return out


def _dir_of(report_path: str) -> str:
    posix = report_path.replace("\\", "/")
    if "/" not in posix:
        return ""
    return posix.rsplit("/", 1)[0]


def _path_stem(report_path: str) -> str:
    posix = report_path.replace("\\", "/")
    lower = posix.lower()
    for ext in _CODE_MODULE_EXTS:
        if lower.endswith(ext):
            posix = posix[: -len(ext)]
            break
    if posix.endswith("/__init__"):
        posix = posix[: -len("/__init__")]
    return posix


def _resolve_relative_path(
    index: ExportIndex, importer_path: str, spec: str
) -> Optional[str]:
    importer_dir = _dir_of(importer_path)
    joined = posixpath.normpath(
        posixpath.join(importer_dir, spec) if importer_dir else spec
    )
    if joined.startswith("./"):
        joined = joined[2:]
    variants = [joined]
    if not any(joined.endswith(ext) for ext in _CODE_MODULE_EXTS):
        variants.extend(joined + ext for ext in _CODE_MODULE_EXTS)
        variants.extend(joined + "/index" + ext for ext in (".js", ".ts"))
        variants.append(joined + "/__init__.py")
    by_stem = {_path_stem(path): path for path in index.by_path}
    for variant in variants:
        if variant in index.by_path:
            return variant
        stem = variant
        for ext in _CODE_MODULE_EXTS:
            if stem.endswith(ext):
                stem = stem[: -len(ext)]
                break
        if stem.endswith("/__init__") or stem.endswith("/index"):
            stem = stem.rsplit("/", 1)[0]
        if stem in by_stem:
            return by_stem[stem]
    return None


def resolve_module(
    index: ExportIndex,
    module_ref: str,
    relative_dots: int,
    importer_path: str,
) -> Optional[str]:
    """Resolve an import specifier to a scanned report path, or None."""
    if module_ref.startswith(".") and (
        "/" in module_ref or module_ref.startswith("./") or module_ref.startswith("../")
    ):
        return _resolve_relative_path(index, importer_path, module_ref)

    if relative_dots:
        base_parts = [part for part in _dir_of(importer_path).split("/") if part]
        up = relative_dots - 1
        if up:
            base_parts = base_parts[:-up] if up <= len(base_parts) else []
        extra = [part for part in module_ref.split(".") if part]
        target = "/".join(base_parts + extra)
        by_stem = {_path_stem(path): path for path in index.by_path}
        if target in by_stem:
            return by_stem[target]
        if extra:
            return resolve_module(index, extra[-1], 0, importer_path)
        return None

    candidates = list(index.by_key.get(module_ref, ()))
    if not candidates:
        return None
    if len(candidates) == 1:
        return candidates[0]
    importer_dir = _dir_of(importer_path)
    same_dir = [path for path in candidates if _dir_of(path) == importer_dir]
    if len(same_dir) == 1:
        return same_dir[0]
    exact = [path for path in candidates if _module_keys(path)[0] == module_ref]
    if len(exact) == 1:
        return exact[0]
    return None


def _parse_import_items(spec: str) -> List[Tuple[str, str]]:
    cleaned = spec.replace("(", " ").replace(")", " ").replace("\\", " ")
    if "#" in cleaned:
        cleaned = cleaned.split("#", 1)[0]
    items: List[Tuple[str, str]] = []
    for part in cleaned.split(","):
        part = part.strip()
        if not part:
            continue
        if part == "*":
            items.append(("*", "*"))
            continue
        match = _IMPORT_NAME_RE.match(part)
        if match:
            items.append((match.group(1), match.group(2) or match.group(1)))
    return items


def _split_py_module(mod: str) -> Tuple[int, str]:
    dots = 0
    while dots < len(mod) and mod[dots] == ".":
        dots += 1
    return dots, mod[dots:]


def _bind_resolved_names(
    ctx: ImportContext, resolved: Optional[str], items: Sequence[Tuple[str, str]]
) -> None:
    if resolved is None:
        return
    ctx.imported_paths.add(resolved)
    exports = ctx.index.all_exports(resolved)
    for exported, alias in items:
        if exported == "*":
            for name, kinds in exports.items():
                if kinds:
                    ctx.names.setdefault(name, set()).update(kinds)
            continue
        kinds = exports.get(exported)
        if kinds:
            ctx.names.setdefault(alias, set()).update(kinds)


def _bind_python_imports(
    statement: str, importer_path: str, ctx: ImportContext
) -> None:
    compact = " ".join(statement.split())
    from_match = _PY_FROM_RE.match(compact)
    if from_match:
        dots, remainder = _split_py_module(from_match.group(1))
        items = _parse_import_items(from_match.group(2))
        if remainder:
            resolved = resolve_module(ctx.index, remainder, dots, importer_path)
            _bind_resolved_names(ctx, resolved, items)
            return
        parent = resolve_module(ctx.index, "", dots, importer_path)
        parent_exports = ctx.index.all_exports(parent) if parent else {}
        for exported, alias in items:
            if parent and exported in parent_exports:
                _bind_resolved_names(ctx, parent, [(exported, alias)])
                continue
            sibling = resolve_module(ctx.index, exported, dots, importer_path)
            if sibling is not None:
                ctx.imported_paths.add(sibling)
        return

    import_match = _PY_IMPORT_RE.match(compact)
    if import_match:
        for exported, alias in _parse_import_items(import_match.group(1)):
            resolved = resolve_module(ctx.index, exported, 0, importer_path)
            if resolved is None:
                continue
            ctx.imported_paths.add(resolved)


def _bind_js_imports(statement: str, importer_path: str, ctx: ImportContext) -> None:
    for match in _JS_IMPORT_NAMED_RE.finditer(statement):
        items: List[Tuple[str, str]] = []
        for part in match.group(1).split(","):
            part = part.strip()
            item = _JS_IMPORT_ITEM_RE.match(part)
            if item:
                items.append((item.group(1), item.group(2) or item.group(1)))
        resolved = resolve_module(ctx.index, match.group(2), 0, importer_path)
        _bind_resolved_names(ctx, resolved, items)

    for match in _JS_IMPORT_STAR_RE.finditer(statement):
        resolved = resolve_module(ctx.index, match.group(2), 0, importer_path)
        if resolved is not None:
            ctx.imported_paths.add(resolved)

    for match in _JS_IMPORT_DEFAULT_RE.finditer(statement):
        if match.group(1) == "from" or "{" in match.group(0) or "*" in match.group(0):
            continue
        resolved = resolve_module(ctx.index, match.group(2), 0, importer_path)
        if resolved is None:
            continue
        ctx.imported_paths.add(resolved)
        union: Set[str] = set()
        for kinds in ctx.index.all_exports(resolved).values():
            union.update(kinds)
        if union:
            ctx.names.setdefault(match.group(1), set()).update(union)

    for match in _JS_REQUIRE_RE.finditer(statement):
        resolved = resolve_module(ctx.index, match.group(3), 0, importer_path)
        if match.group(1):
            items = []
            for part in match.group(1).split(","):
                part = part.strip()
                item = _JS_IMPORT_ITEM_RE.match(part)
                if item:
                    items.append((item.group(1), item.group(2) or item.group(1)))
            _bind_resolved_names(ctx, resolved, items)
        elif match.group(2) and resolved is not None:
            ctx.imported_paths.add(resolved)
            union = set()
            for kinds in ctx.index.all_exports(resolved).values():
                union.update(kinds)
            if union:
                ctx.names.setdefault(match.group(2), set()).update(union)


def bind_imports(
    report_path: str,
    language: str,
    text: str,
    index: ExportIndex,
) -> ImportContext:
    """Parse import/require lines and attach exported taint from *index*."""
    ctx = ImportContext(index)
    if language not in INDEX_LANGUAGES:
        return ctx
    lines = split_lines(text)
    for start_line, _end_line, statement in iter_logical_statements(lines, language):
        first = lines[start_line - 1]
        if _is_comment_line(first, language):
            continue
        if language == "python":
            _bind_python_imports(statement, report_path, ctx)
        elif language == "javascript":
            _bind_js_imports(statement, report_path, ctx)
    return ctx


def collect_module_exports(language: str, text: str) -> Dict[str, Set[str]]:
    """Return names this file exports, with taint kinds. Never executes *text*."""
    if language not in INDEX_LANGUAGES:
        return {}
    lines = split_lines(text)
    signal_defs = signals_for_language(language)
    tainted: Dict[str, Set[str]] = {}
    taint_origin: Dict[str, int] = {}
    exports: Dict[str, Set[str]] = {}
    func_stack: List[Tuple[int, str]] = []
    def_re = _PY_DEF_RE if language == "python" else _JS_DEF_RE

    for start_line, _end_line, statement in iter_logical_statements(lines, language):
        first = lines[start_line - 1]
        if _is_comment_line(first, language):
            continue

        indent = _leading_indent(first)
        if indent >= 0:
            while func_stack and indent <= func_stack[-1][0]:
                func_stack.pop()
            def_match = def_re.match(first)
            if def_match:
                func_stack.append((indent, def_match.group(2)))

        statement_taints: Set[str] = set()
        for signal in signal_defs:
            if signal.taint and signal.regex.search(statement) is not None:
                statement_taints.add(signal.taint)

        physical_lines = statement.splitlines() or [statement]
        for offset, physical in enumerate(physical_lines):
            if _is_comment_line(physical, language):
                continue
            line_taints: Set[str] = set()
            for signal in signal_defs:
                if signal.taint and signal.regex.search(physical) is not None:
                    line_taints.add(signal.taint)
            _apply_assignment(
                language,
                physical,
                line_taints,
                tainted,
                taint_origin,
                start_line + offset,
            )
            if not func_stack:
                assigned = extract_assignment(language, " ".join(physical.splitlines()))
                if assigned is not None:
                    kinds = tainted.get(assigned[0], set())
                    if kinds:
                        exports.setdefault(assigned[0], set()).update(kinds)

            ret_match = _RETURN_RE.match(physical)
            if ret_match and func_stack:
                rhs = ret_match.group(1)
                kinds = set(line_taints)
                for ref in identifiers_in(rhs or physical, language):
                    if ref in tainted:
                        kinds.update(tainted[ref])
                if kinds:
                    fname = func_stack[-1][1]
                    tainted.setdefault(fname, set()).update(kinds)
                    exports.setdefault(fname, set()).update(kinds)

        if func_stack and statement_taints and language == "javascript":
            # Grouped `function f() { return process.env.API_KEY }` is one statement.
            if _RETURN_RE.search(statement):
                fname = func_stack[-1][1]
                tainted.setdefault(fname, set()).update(statement_taints)
                exports.setdefault(fname, set()).update(statement_taints)

    return {name: kinds for name, kinds in exports.items() if kinds}


def build_export_index(files: Sequence[_LoadedFile]) -> ExportIndex:
    """Index exported taint for every loaded Python/JS file, then re-exports."""
    index = ExportIndex()
    for item in files:
        if item.language not in INDEX_LANGUAGES:
            continue
        index.add(item.report_path, collect_module_exports(item.language, item.text))
    for _ in range(4):
        changed = False
        for item in files:
            if item.language not in INDEX_LANGUAGES:
                continue
            ctx = bind_imports(item.report_path, item.language, item.text, index)
            current = index.by_path.setdefault(item.report_path, {})
            for name, kinds in ctx.names.items():
                if not kinds:
                    continue
                existing = current.setdefault(name, set())
                before = len(existing)
                existing.update(kinds)
                if len(existing) > before:
                    changed = True
                    for key in _module_keys(item.report_path):
                        if item.report_path not in index.by_key.get(key, ()):
                            index.by_key.setdefault(key, []).append(item.report_path)
        if not changed:
            break
    return index


def _used_taints(
    line: str,
    language: str,
    line_taints: Set[str],
    tainted: Dict[str, Set[str]],
    ambient: Sequence[Tuple[int, Set[str]]],
    line_no: int,
    import_ctx: Optional[ImportContext] = None,
) -> Set[str]:
    used = set(line_taints)
    for name in identifiers_in(line, language):
        if name in tainted:
            used.update(tainted[name])
    if import_ctx is not None:
        used.update(import_ctx.extra_taints(line))
    if language in AMBIENT_LANGUAGES:
        for src_line, taints in ambient:
            if 0 < line_no - src_line <= AMBIENT_WINDOW:
                used.update(taints)
    return used


def _taint_source_line(
    used: Set[str],
    required: Tuple[str, ...],
    line: str,
    language: str,
    tainted: Dict[str, Set[str]],
    taint_origin: Dict[str, int],
    ambient: Sequence[Tuple[int, Set[str]]],
    line_no: int,
) -> Optional[int]:
    """Best-effort origin line for snippet context (not used as the finding line)."""
    origins: List[int] = []
    for name in identifiers_in(line, language):
        kinds = tainted.get(name)
        if kinds and any(item in kinds for item in required):
            origin = taint_origin.get(name)
            if origin is not None and origin != line_no:
                origins.append(origin)
    if language in AMBIENT_LANGUAGES:
        needed = set(required)
        for src_line, taints in reversed(list(ambient)):
            if needed & taints and src_line != line_no:
                origins.append(src_line)
                break
    if not origins:
        return None
    return min(origins, default=None)


def _apply_assignment(
    language: str,
    line: str,
    line_taints: Set[str],
    tainted: Dict[str, Set[str]],
    taint_origin: Dict[str, int],
    line_no: int,
    import_ctx: Optional[ImportContext] = None,
) -> None:
    assigned = extract_assignment(language, " ".join(line.splitlines()))
    if assigned is not None:
        name, rhs = assigned
        merged = set(line_taints)
        for ref in identifiers_in(rhs, language):
            if ref in tainted:
                merged.update(tainted[ref])
        if import_ctx is not None:
            merged.update(import_ctx.extra_taints(rhs))
            merged.update(import_ctx.extra_taints(line))
        tainted[name] = merged
        if merged:
            taint_origin[name] = line_no
        else:
            taint_origin.pop(name, None)

    if language == "python" and line_taints:
        with_as = _WITH_AS_RE.match(" ".join(line.splitlines()))
        if with_as:
            name = with_as.group(1)
            merged = set(line_taints) | set(tainted.get(name, ()))
            tainted[name] = merged
            taint_origin[name] = line_no


def _emit_combo(
    rule: ComboRule,
    report_path: str,
    line_no: int,
    lines: List[str],
    extra_lines: Optional[Iterable[int]],
) -> Finding:
    return Finding(
        file=report_path,
        line=line_no,
        pattern=rule.name,
        severity=rule.severity,
        description=rule.description,
        code_snippet=make_snippet(lines, line_no, extra_lines),
    )


def _emit_direct(
    rule: DirectRule,
    report_path: str,
    line_no: int,
    lines: List[str],
    severity: str,
    extra_lines: Optional[Iterable[int]] = None,
) -> Finding:
    return Finding(
        file=report_path,
        line=line_no,
        pattern=rule.name,
        severity=severity,
        description=rule.description,
        code_snippet=make_snippet(lines, line_no, extra_lines),
    )


def analyze_content(
    report_path: str,
    language: str,
    filename: str,
    text: str,
    export_index: Optional[ExportIndex] = None,
) -> List[Finding]:
    """Analyze a single already-read text file. Never executes *text*."""
    lines = split_lines(text)
    findings: List[Finding] = []

    for file_rule in file_rules_for(language, filename):
        findings.extend(file_rule.analyzer(report_path, text, lines))

    signal_defs: List[SignalDef] = signals_for_language(language)
    combo_rules: List[ComboRule] = combo_rules_for_language(language)
    direct_rules: List[DirectRule] = direct_rules_for_language(language)

    tainted: Dict[str, Set[str]] = {}
    taint_origin: Dict[str, int] = {}
    ambient: List[Tuple[int, Set[str]]] = []
    import_ctx: Optional[ImportContext] = None
    if language in INDEX_LANGUAGES:
        if export_index is not None:
            for name, kinds in export_index.all_exports(report_path).items():
                tainted[name] = set(kinds)
            import_ctx = bind_imports(report_path, language, text, export_index)
        else:
            for name, kinds in collect_module_exports(language, text).items():
                tainted[name] = set(kinds)
            import_ctx = None
        if import_ctx is not None:
            for name, kinds in import_ctx.names.items():
                tainted.setdefault(name, set()).update(kinds)

    for start_line, end_line, statement in iter_logical_statements(lines, language):
        first_physical = lines[start_line - 1]
        if _is_comment_line(first_physical, language):
            continue

        line_taints: Set[str] = set()
        sinks: Set[str] = set()
        for signal in signal_defs:
            if signal.regex.search(statement) is None:
                continue
            if signal.taint:
                line_taints.add(signal.taint)
            if signal.id in SINK_SIGNAL_IDS:
                sinks.add(signal.id)

        _apply_assignment(
            language,
            statement,
            line_taints,
            tainted,
            taint_origin,
            start_line,
            import_ctx,
        )

        if language in AMBIENT_LANGUAGES and line_taints:
            ambient.append((start_line, set(line_taints)))
            cutoff = start_line - AMBIENT_WINDOW
            ambient[:] = [item for item in ambient if item[0] >= cutoff]

        used = _used_taints(
            statement,
            language,
            line_taints,
            tainted,
            ambient,
            start_line,
            import_ctx,
        )
        extra_lines = range(start_line, end_line + 1)
        matched_taint_sets: List[Set[str]] = []
        ordered_combos = sorted(
            combo_rules, key=lambda item: (-len(item.required_taints), item.name)
        )
        for rule in ordered_combos:
            if rule.sink not in sinks:
                continue
            required = set(rule.required_taints)
            if not required.issubset(used):
                continue
            if any(required <= existing for existing in matched_taint_sets):
                continue
            matched_taint_sets.append(required)
            extra = _taint_source_line(
                used,
                rule.required_taints,
                statement,
                language,
                tainted,
                taint_origin,
                ambient,
                start_line,
            )
            snippet_extra = list(extra_lines)
            if extra:
                snippet_extra.append(extra)
            findings.append(
                _emit_combo(rule, report_path, start_line, lines, snippet_extra)
            )

        for rule in direct_rules:
            if rule.regex.search(statement) is None:
                continue
            severity = rule.severity
            if rule.classify is not None:
                classified = rule.classify(statement)
                if classified is None:
                    continue
                severity = classified
            findings.append(
                _emit_direct(
                    rule, report_path, start_line, lines, severity, extra_lines
                )
            )

    return findings


def dedupe_findings(findings: Iterable[Finding]) -> List[Finding]:
    """Drop duplicate detections of the same behavior on the same line."""
    best_by_pattern: Dict[Tuple[str, int, str], Finding] = {}
    for finding in findings:
        key = (finding.file, finding.line, finding.pattern)
        existing = best_by_pattern.get(key)
        if existing is None or SEVERITY_RANK[finding.severity] < SEVERITY_RANK[
            existing.severity
        ]:
            best_by_pattern[key] = finding

    grouped: Dict[Tuple[str, int, str], Finding] = {}
    ungrouped: List[Finding] = []
    for finding in best_by_pattern.values():
        group = PATTERN_GROUPS.get(finding.pattern)
        if group is None:
            ungrouped.append(finding)
            continue
        key = (finding.file, finding.line, group)
        existing = grouped.get(key)
        if existing is None:
            grouped[key] = finding
            continue
        existing_rank = SEVERITY_RANK[existing.severity]
        new_rank = SEVERITY_RANK[finding.severity]
        if new_rank < existing_rank or (
            new_rank == existing_rank and finding.pattern < existing.pattern
        ):
            grouped[key] = finding

    merged = ungrouped + list(grouped.values())
    merged.sort(
        key=lambda item: (
            item.file,
            item.line,
            SEVERITY_RANK.get(item.severity, 99),
            item.pattern,
        )
    )
    return merged


def scan_directory(
    root: Path,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    verbose: bool = False,
) -> ScanReport:
    findings: List[Finding] = []
    skipped: List[SkippedFile] = []
    scanned = 0
    loaded: List[_LoadedFile] = []

    for path in iter_scannable_files(root):
        report_path = normalize_report_path(path, root)
        language = detect_language(path)
        if language is None:
            continue
        if verbose:
            print(f"scan {report_path}", file=sys.stderr)

        text, reason = read_text_file(path, max_file_size)
        if reason is not None:
            skipped.append(SkippedFile(file=report_path, reason=reason.value))
            if verbose:
                print(f"skip {report_path} ({reason.value})", file=sys.stderr)
            continue
        if text is None:
            skipped.append(SkippedFile(file=report_path, reason=SkipReason.UNREADABLE.value))
            continue

        scanned += 1
        loaded.append(
            _LoadedFile(
                path=path,
                report_path=report_path,
                language=language,
                filename=path.name,
                text=text,
            )
        )

    export_index = build_export_index(loaded)

    for item in loaded:
        try:
            file_findings = analyze_content(
                item.report_path,
                item.language,
                item.filename,
                item.text,
                export_index,
            )
        except Exception as exc:  # noqa: BLE001 — one bad file must not abort the scan
            skipped.append(
                SkippedFile(
                    file=item.report_path,
                    reason=f"analyze_error:{type(exc).__name__}",
                )
            )
            if verbose:
                print(f"error {item.report_path}: {exc}", file=sys.stderr)
            continue
        findings.extend(file_findings)

    findings = dedupe_findings(findings)
    skipped.sort(key=lambda item: (item.file, item.reason))
    status = "flagged" if findings else "clean"
    return ScanReport(
        status=status,
        scanner_version=SCANNER_VERSION,
        scanned_files=scanned,
        skipped_files=len(skipped),
        skipped=skipped,
        findings=findings,
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Statically scan a source repository for suspicious behavior. "
            "Findings are advisory and require human verification. "
            "Scanned code is never executed or modified."
        )
    )
    parser.add_argument(
        "path",
        help="Directory to scan recursively",
    )
    parser.add_argument(
        "--output",
        metavar="FILE",
        help="Write JSON report to FILE instead of stdout",
    )
    parser.add_argument(
        "--format",
        default="json",
        choices=("json",),
        help="Report format (only json is supported)",
    )
    parser.add_argument(
        "--max-file-size",
        type=int,
        default=DEFAULT_MAX_FILE_SIZE,
        metavar="BYTES",
        help=f"Skip files larger than this (default {DEFAULT_MAX_FILE_SIZE})",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print diagnostic messages to stderr",
    )
    return parser


def render_report(report: ScanReport) -> str:
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False) + "\n"


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        code = exc.code
        if code in (0, 1, 2):
            return int(code) if code is not None else 0
        return 2

    if args.max_file_size <= 0:
        print("error: --max-file-size must be a positive integer", file=sys.stderr)
        return 2

    root = Path(args.path)
    try:
        if not root.exists():
            print(f"error: path does not exist: {args.path}", file=sys.stderr)
            return 2
        if not root.is_dir():
            print(f"error: path is not a directory: {args.path}", file=sys.stderr)
            return 2
    except OSError as exc:
        print(f"error: cannot access path: {exc}", file=sys.stderr)
        return 2

    try:
        report = scan_directory(
            root,
            max_file_size=args.max_file_size,
            verbose=args.verbose,
        )
        payload = render_report(report)
    except Exception as exc:  # noqa: BLE001 — unexpected scanner failure
        print(f"error: scanner failed: {exc}", file=sys.stderr)
        return 2

    if args.output:
        output_path = Path(args.output)
        try:
            output_path.write_text(payload, encoding="utf-8")
        except OSError as exc:
            print(f"error: cannot write output file: {exc}", file=sys.stderr)
            return 2
    else:
        sys.stdout.write(payload)

    return 1 if report.findings else 0


if __name__ == "__main__":
    sys.exit(main())
