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
import re
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

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


def _used_taints(
    line: str,
    language: str,
    line_taints: Set[str],
    tainted: Dict[str, Set[str]],
    ambient: Sequence[Tuple[int, Set[str]]],
    line_no: int,
) -> Set[str]:
    used = set(line_taints)
    for name in identifiers_in(line, language):
        if name in tainted:
            used.update(tainted[name])
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
) -> None:
    assigned = extract_assignment(language, " ".join(line.splitlines()))
    if assigned is not None:
        name, rhs = assigned
        merged = set(line_taints)
        for ref in identifiers_in(rhs, language):
            if ref in tainted:
                merged.update(tainted[ref])
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
            language, statement, line_taints, tainted, taint_origin, start_line
        )

        if language in AMBIENT_LANGUAGES and line_taints:
            ambient.append((start_line, set(line_taints)))
            cutoff = start_line - AMBIENT_WINDOW
            ambient[:] = [item for item in ambient if item[0] >= cutoff]

        used = _used_taints(
            statement, language, line_taints, tainted, ambient, start_line
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
        try:
            file_findings = analyze_content(report_path, language, path.name, text)
        except Exception as exc:  # noqa: BLE001 — one bad file must not abort the scan
            skipped.append(SkippedFile(file=report_path, reason=f"analyze_error:{type(exc).__name__}"))
            if verbose:
                print(f"error {report_path}: {exc}", file=sys.stderr)
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
