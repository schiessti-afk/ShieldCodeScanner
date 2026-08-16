"""Stdlib ``ast`` analysis for Python sources.

``ast.parse`` builds a tree from source text. This module never calls
``exec``, ``eval``, or ``compile`` on scanned code, and never imports
the file as a module.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Dict, Iterable, Iterator, List, Optional, Set, Tuple

from rules import is_secret_env_name, is_sensitive_path


SECRET_CALLS = frozenset(
    {
        "os.getenv",
        "os.environ.get",
        "getenv",
        "environ.get",
    }
)
SECRET_SUBSCRIPTS = frozenset(
    {
        "os.environ",
        "environ",
    }
)
NETWORK_EXACT = frozenset(
    {
        "urllib.request.urlopen",
        "urllib.request.Request",
        "urllib.request.urlretrieve",
        "urlretrieve",
        "urlopen",
        "http.client.HTTPSConnection",
        "http.client.HTTPConnection",
        "aiohttp.ClientSession",
        "aiohttp.request",
        "socket.send",
        "socket.sendall",
        "socket.connect",
        "socket.create_connection",
    }
)
NETWORK_PREFIXES = (
    "requests.",
    "httpx.",
    "paramiko.",
    "ftplib.",
    "smtplib.",
)
NETWORK_CLIENT_METHODS = frozenset(
    {"get", "post", "put", "patch", "delete", "request", "head"}
)
NETWORK_CLIENT_BASES = frozenset({"client", "session", "http", "api", "svc"})
DOWNLOAD_CALLS = frozenset(
    {
        "urllib.request.urlretrieve",
        "urllib.request.urlopen",
        "urlretrieve",
        "urlopen",
        "requests.get",
        "requests.post",
        "httpx.get",
        "httpx.post",
    }
)
EXEC_CALLS = frozenset(
    {
        "eval",
        "exec",
        "os.system",
        "os.popen",
        "commands.getoutput",
        "pty.spawn",
    }
)
SUBPROCESS_CALLS = frozenset(
    {
        "subprocess.run",
        "subprocess.call",
        "subprocess.Popen",
        "subprocess.check_output",
        "subprocess.check_call",
        "run",
        "call",
        "Popen",
        "check_output",
        "check_call",
    }
)
OBFUSCATION_CALLS = frozenset(
    {
        "base64.b64decode",
        "binascii.unhexlify",
        "binascii.a2b_base64",
        "bytes.fromhex",
        "gzip.decompress",
        "zlib.decompress",
        "lzma.decompress",
        "marshal.loads",
        "pickle.loads",
        "codecs.decode",
    }
)
DELETE_CALLS = frozenset({"shutil.rmtree", "os.removedirs"})
PRIVILEGE_CALLS = frozenset({"os.setuid"})
CHMOD_CALLS = frozenset({"os.chmod"})
USER_INPUT_CALLS = frozenset({"input"})
DANGEROUS_PATH_CALLS = frozenset(
    {
        "os.path.expanduser",
        "os.path.expandvars",
        "Path.home",
        "pathlib.Path.home",
    }
)

_HTTP_URL_PREFIXES = ("http://", "https://")


@dataclass
class ImportSpec:
    module: str
    relative_dots: int
    items: List[Tuple[str, str]]
    is_from: bool


@dataclass
class AstAssignment:
    name: str
    line: int
    taints: Set[str]
    refs: Set[str]


@dataclass
class AstEvent:
    line: int
    end_line: int
    taints: Set[str] = field(default_factory=set)
    sinks: Set[str] = field(default_factory=set)
    refs: Set[str] = field(default_factory=set)
    destination: str = ""
    assignments: List[AstAssignment] = field(default_factory=list)
    returned: Set[str] = field(default_factory=set)
    function: str = ""


@dataclass
class PythonAstAnalysis:
    events: List[AstEvent]
    exports: Dict[str, Set[str]]
    import_specs: List[ImportSpec]
    aliases: Dict[str, str]


def analyze_python_ast(text: str) -> Optional[PythonAstAnalysis]:
    """Parse *text* and return structured taint events, or None on syntax errors."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return None
    walker = _ModuleWalker()
    walker.run(tree)
    return walker.result()


def _lineno(node: ast.AST) -> int:
    return int(getattr(node, "lineno", 1) or 1)


def _end_lineno(node: ast.AST) -> int:
    end = getattr(node, "end_lineno", None)
    return int(end) if end else _lineno(node)


def _const_str(node: Optional[ast.AST]) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _is_true(node: Optional[ast.AST]) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _dict_items(node: ast.AST) -> Dict[str, bool]:
    """Best-effort literal mapping for ``{"shell": True}`` / ``dict(shell=True)``."""
    out: Dict[str, bool] = {}
    if isinstance(node, ast.Dict):
        for key, value in zip(node.keys, node.values):
            name = _const_str(key)
            if name is not None:
                out[name] = _is_true(value)
        return out
    if isinstance(node, ast.Call) and _name_of(node.func) in {"dict", "builtins.dict"}:
        for kw in node.keywords:
            if kw.arg:
                out[kw.arg] = _is_true(kw.value)
    return out


def _name_of(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _name_of(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def _attr_target(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _attr_target(node.value)
        if base:
            return f"{base}.{node.attr}"
        return node.attr
    return None


def flatten_statements(
    body: Iterable[ast.stmt],
    func_stack: Optional[List[str]] = None,
) -> Iterator[Tuple[ast.stmt, str]]:
    """Yield statements in source order with the enclosing function name."""
    stack = list(func_stack or [])
    for stmt in body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            stack.append(stmt.name)
            yield from flatten_statements(stmt.body, stack)
            stack.pop()
            continue
        if isinstance(stmt, ast.ClassDef):
            yield from flatten_statements(stmt.body, stack)
            continue
        if isinstance(stmt, (ast.If, ast.For, ast.AsyncFor, ast.While)):
            yield stmt, (stack[-1] if stack else "")
            yield from flatten_statements(stmt.body, stack)
            yield from flatten_statements(stmt.orelse, stack)
            continue
        if isinstance(stmt, (ast.With, ast.AsyncWith)):
            yield stmt, (stack[-1] if stack else "")
            yield from flatten_statements(stmt.body, stack)
            continue
        if isinstance(stmt, ast.Try):
            yield from flatten_statements(stmt.body, stack)
            for handler in stmt.handlers:
                yield from flatten_statements(handler.body, stack)
            yield from flatten_statements(stmt.orelse, stack)
            yield from flatten_statements(stmt.finalbody, stack)
            continue
        yield stmt, (stack[-1] if stack else "")


def expression_nodes(stmt: ast.stmt) -> Iterator[ast.AST]:
    """Walk expressions that belong to *stmt*, not nested statement bodies."""
    if isinstance(stmt, ast.Assign):
        yield from ast.walk(stmt.value)
        return
    if isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
        yield from ast.walk(stmt.value)
        return
    if isinstance(stmt, ast.Expr):
        yield from ast.walk(stmt.value)
        return
    if isinstance(stmt, ast.Return) and stmt.value is not None:
        yield from ast.walk(stmt.value)
        return
    if isinstance(stmt, (ast.With, ast.AsyncWith)):
        for item in stmt.items:
            yield from ast.walk(item.context_expr)
        return
    if isinstance(stmt, ast.If):
        yield from ast.walk(stmt.test)
        return
    if isinstance(stmt, (ast.For, ast.AsyncFor)):
        yield from ast.walk(stmt.iter)
        return
    if isinstance(stmt, ast.While):
        yield from ast.walk(stmt.test)
        return
    for child in ast.iter_child_nodes(stmt):
        if not isinstance(child, ast.stmt):
            yield from ast.walk(child)


class _ModuleWalker:
    def __init__(self) -> None:
        self.aliases: Dict[str, str] = {}
        self.import_specs: List[ImportSpec] = []
        self.events: List[AstEvent] = []
        self.exports: Dict[str, Set[str]] = {}

    def run(self, tree: ast.Module) -> None:
        for stmt, function in flatten_statements(tree.body):
            if isinstance(stmt, (ast.Import, ast.ImportFrom)):
                self._handle_import(stmt)
                continue
            event = self._event_for(stmt, function)
            self.events.append(event)
            if function:
                if event.returned:
                    self.exports.setdefault(function, set()).update(event.returned)
                if event.taints and isinstance(stmt, ast.Return):
                    self.exports.setdefault(function, set()).update(event.taints)
            else:
                for assignment in event.assignments:
                    if assignment.taints:
                        self.exports.setdefault(assignment.name, set()).update(
                            assignment.taints
                        )

    def result(self) -> PythonAstAnalysis:
        return PythonAstAnalysis(
            events=self.events,
            exports={name: set(kinds) for name, kinds in self.exports.items() if kinds},
            import_specs=self.import_specs,
            aliases=dict(self.aliases),
        )

    def _qualify(self, raw: str) -> str:
        if not raw:
            return ""
        parts = raw.split(".")
        head = self.aliases.get(parts[0], parts[0])
        if len(parts) == 1:
            return head
        return head + "." + ".".join(parts[1:])

    def _handle_import(self, stmt: ast.stmt) -> None:
        if isinstance(stmt, ast.Import):
            items: List[Tuple[str, str]] = []
            for alias in stmt.names:
                local = alias.asname or alias.name.split(".")[0]
                self.aliases[local] = alias.name
                items.append((alias.name, local))
            if items:
                self.import_specs.append(
                    ImportSpec(
                        module=items[0][0],
                        relative_dots=0,
                        items=items,
                        is_from=False,
                    )
                )
            return
        if not isinstance(stmt, ast.ImportFrom):
            return
        module = stmt.module or ""
        items = []
        for alias in stmt.names:
            exported = alias.name
            local = alias.asname or alias.name
            items.append((exported, local))
            if exported != "*":
                qualified = f"{module}.{exported}" if module else exported
                self.aliases[local] = qualified
        self.import_specs.append(
            ImportSpec(
                module=module,
                relative_dots=stmt.level or 0,
                items=items,
                is_from=True,
            )
        )

    def _event_for(self, stmt: ast.stmt, function: str) -> AstEvent:
        taints: Set[str] = set()
        sinks: Set[str] = set()
        refs: Set[str] = set()
        destination = ""
        for node in expression_nodes(stmt):
            if isinstance(node, ast.Name):
                refs.add(node.id)
            elif isinstance(node, ast.Attribute):
                target = _attr_target(node)
                if target:
                    refs.add(target)
            if isinstance(node, ast.Call):
                kind_taints, kind_sinks, dest = self._call_effects(node)
                taints.update(kind_taints)
                sinks.update(kind_sinks)
                if dest and not destination:
                    destination = dest
            elif isinstance(node, ast.Subscript):
                extra = self._subscript_taints(node)
                taints.update(extra)
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                if is_sensitive_path(node.value):
                    taints.add("sensitive_file")
                if self._dangerous_path_literal(node.value):
                    taints.add("dangerous_path")
            elif isinstance(node, ast.Attribute) and _name_of(node) in {
                "sys.argv",
            }:
                taints.add("user_input")

        assignments = self._assignments(stmt, taints, refs)
        returned: Set[str] = set()
        if isinstance(stmt, ast.Return):
            returned.update(taints)
            returned.update(refs)

        return AstEvent(
            line=_lineno(stmt),
            end_line=_end_lineno(stmt),
            taints=taints,
            sinks=sinks,
            refs=refs,
            destination=destination,
            assignments=assignments,
            returned=returned,
            function=function,
        )

    def _call_effects(self, node: ast.Call) -> Tuple[Set[str], Set[str], str]:
        raw = _name_of(node.func)
        qualified = self._qualify(raw)
        taints: Set[str] = set()
        sinks: Set[str] = set()

        secret_key = self._secret_key_arg(node)
        if qualified in SECRET_CALLS or raw in SECRET_CALLS:
            if secret_key and is_secret_env_name(secret_key):
                taints.add("secret")
        if qualified in DOWNLOAD_CALLS or raw in DOWNLOAD_CALLS:
            taints.add("download")
        if qualified in OBFUSCATION_CALLS or raw in OBFUSCATION_CALLS:
            taints.add("obfuscated")
        if qualified in USER_INPUT_CALLS or raw in USER_INPUT_CALLS:
            taints.add("user_input")
        if qualified in DANGEROUS_PATH_CALLS or raw in DANGEROUS_PATH_CALLS:
            if self._expanduser_is_home(node):
                taints.add("dangerous_path")
        if self._open_sensitive(qualified, raw, node):
            taints.add("sensitive_file")

        if self._is_network_call(qualified, raw):
            sinks.add("network")
        if qualified in EXEC_CALLS or raw in EXEC_CALLS:
            sinks.add("exec_dynamic")
        if self._is_subprocess_shell(qualified, raw, node):
            sinks.add("exec_dynamic")
        if qualified in DELETE_CALLS or raw in DELETE_CALLS:
            sinks.add("delete_recursive")
        if qualified in PRIVILEGE_CALLS or raw in PRIVILEGE_CALLS:
            taints.add("privilege")
        if qualified in CHMOD_CALLS or raw in CHMOD_CALLS:
            sinks.add("chmod_exec")

        return taints, sinks, self._call_destination(node)

    def _secret_key_arg(self, node: ast.Call) -> Optional[str]:
        if node.args:
            return _const_str(node.args[0])
        for kw in node.keywords:
            if kw.arg in {"key", None}:
                value = _const_str(kw.value)
                if value:
                    return value
        return None

    def _subscript_taints(self, node: ast.Subscript) -> Set[str]:
        qualified = self._qualify(_name_of(node.value))
        raw = _name_of(node.value)
        key = _const_str(node.slice)
        if key is None:
            return set()
        if qualified in SECRET_SUBSCRIPTS or raw in SECRET_SUBSCRIPTS:
            if is_secret_env_name(key):
                return {"secret"}
        return set()

    def _is_network_call(self, qualified: str, raw: str) -> bool:
        name = qualified or raw
        if name in NETWORK_EXACT:
            return True
        if any(name.startswith(prefix) for prefix in NETWORK_PREFIXES):
            method = name.rsplit(".", 1)[-1]
            return method in NETWORK_CLIENT_METHODS or name in NETWORK_EXACT
        if "." in name:
            base, method = name.rsplit(".", 1)
            if method in NETWORK_CLIENT_METHODS and base.split(".")[-1] in NETWORK_CLIENT_BASES:
                return True
        return False

    def _is_subprocess_shell(self, qualified: str, raw: str, node: ast.Call) -> bool:
        name = qualified or raw
        if name not in SUBPROCESS_CALLS and not name.startswith("subprocess."):
            return False
        for kw in node.keywords:
            if kw.arg == "shell" and _is_true(kw.value):
                return True
            if kw.arg is None and _dict_items(kw.value).get("shell"):
                return True
        return False

    def _open_sensitive(self, qualified: str, raw: str, node: ast.Call) -> bool:
        if (qualified or raw) not in {"open", "builtins.open", "io.open"}:
            return False
        if not node.args:
            return False
        first = node.args[0]
        literal = _const_str(first)
        if literal and is_sensitive_path(literal):
            return True
        if isinstance(first, ast.Call):
            inner = self._qualify(_name_of(first.func))
            if inner in {"os.path.expanduser", "os.path.expandvars"} and first.args:
                inner_lit = _const_str(first.args[0])
                if inner_lit and is_sensitive_path(inner_lit):
                    return True
        return False

    def _expanduser_is_home(self, node: ast.Call) -> bool:
        if not node.args:
            return True
        value = _const_str(node.args[0])
        if value is None:
            return False
        compact = value.replace("\\", "/").rstrip("/")
        return compact in {"~", "~/", "$HOME", "%USERPROFILE%"}

    def _dangerous_path_literal(self, value: str) -> bool:
        compact = value.replace("\\", "/").rstrip("/")
        return compact in {"/", "~", "C:", "C:/"}

    def _call_destination(self, node: ast.Call) -> str:
        candidates: List[ast.AST] = list(node.args[:1])
        for kw in node.keywords:
            if kw.arg in {"url", "host", "hostname"}:
                candidates.append(kw.value)
        for item in candidates:
            literal = _const_str(item)
            if literal and (
                literal.startswith(_HTTP_URL_PREFIXES) or _looks_like_host(literal)
            ):
                return literal
        return ""

    def _assignments(
        self, stmt: ast.stmt, line_taints: Set[str], refs: Set[str]
    ) -> List[AstAssignment]:
        out: List[AstAssignment] = []
        line = _lineno(stmt)
        if isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                self._collect_targets(target, line_taints, refs, line, out)
        elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
            self._collect_targets(stmt.target, line_taints, refs, line, out)
        elif isinstance(stmt, (ast.With, ast.AsyncWith)):
            for item in stmt.items:
                if item.optional_vars is None:
                    continue
                self._collect_targets(item.optional_vars, line_taints, refs, line, out)
        return out

    def _collect_targets(
        self,
        target: ast.AST,
        line_taints: Set[str],
        refs: Set[str],
        line: int,
        out: List[AstAssignment],
    ) -> None:
        name = _attr_target(target)
        if name:
            out.append(
                AstAssignment(name=name, line=line, taints=set(line_taints), refs=set(refs))
            )
            return
        if isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self._collect_targets(elt, line_taints, refs, line, out)


def _looks_like_host(value: str) -> bool:
    if "://" in value or "/" in value or " " in value:
        return False
    return "." in value or ":" in value
