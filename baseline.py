"""Accepted-finding baseline and inline suppressions.

A committed ``scanner-baseline.json`` records findings a reviewer has
accepted (hash of file + line + pattern). Inline comments such as
``# code-scanner: ignore api_key_exfiltration`` suppress a pattern at
that location without a baseline entry.

Neither helper executes repository code. ``git`` is invoked only when
the caller asks for ``--since`` changed-file filtering.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

from models import SCANNER_VERSION, Finding, ScanReport
from utils import BASELINE_FILENAME, is_comment_line, split_lines


BASELINE_FORMAT_VERSION = 1

_IGNORE_PATTERN = re.compile(
    r"code-scanner:\s*(ignore(?:-next-line)?)"
    r"(?:\s+([A-Za-z0-9_.,\s-]+))?",
    re.IGNORECASE,
)


class BaselineError(Exception):
    """Baseline file is missing or not valid JSON."""


class GitError(Exception):
    """git is unavailable or the requested revision is invalid."""


def finding_fingerprint(file: str, line: int, pattern: str) -> str:
    """Stable SHA-256 of file + line + pattern (POSIX path, no snippet)."""
    payload = f"{file}\n{line}\n{pattern}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def fingerprint_for(finding: Finding) -> str:
    return finding_fingerprint(finding.file, finding.line, finding.pattern)


@dataclass(frozen=True)
class Baseline:
    """Set of accepted finding fingerprints."""

    ids: frozenset
    path: Optional[str] = None

    def contains(self, finding: Finding) -> bool:
        return fingerprint_for(finding) in self.ids


def default_baseline_path(root: Path) -> Path:
    return root / BASELINE_FILENAME


def load_baseline(path: Path) -> Baseline:
    """Load a committed baseline. Recomputes ids from file/line/pattern."""
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise BaselineError(f"cannot read baseline file: {exc}") from exc
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise BaselineError(f"baseline is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise BaselineError("baseline root must be a JSON object")
    entries = payload.get("findings", [])
    if not isinstance(entries, list):
        raise BaselineError("baseline 'findings' must be an array")
    ids: Set[str] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise BaselineError(f"baseline findings[{index}] must be an object")
        if "file" in entry and "line" in entry and "pattern" in entry:
            try:
                line = int(entry["line"])
            except (TypeError, ValueError) as exc:
                raise BaselineError(
                    f"baseline findings[{index}].line must be an integer"
                ) from exc
            file_name = entry["file"]
            pattern = entry["pattern"]
            if not isinstance(file_name, str) or not isinstance(pattern, str):
                raise BaselineError(
                    f"baseline findings[{index}] file and pattern must be strings"
                )
            ids.add(finding_fingerprint(file_name.replace("\\", "/"), line, pattern))
            continue
        stored = entry.get("id")
        if isinstance(stored, str) and stored:
            ids.add(stored)
            continue
        raise BaselineError(
            f"baseline findings[{index}] needs file, line, and pattern (or id)"
        )
    return Baseline(ids=frozenset(ids), path=path.as_posix())


def baseline_document(findings: Iterable[Finding]) -> Dict[str, object]:
    """Build a deterministic baseline document from *findings*."""
    rows = []
    seen: Set[str] = set()
    for finding in findings:
        ident = fingerprint_for(finding)
        if ident in seen:
            continue
        seen.add(ident)
        rows.append(
            {
                "id": ident,
                "file": finding.file,
                "line": finding.line,
                "pattern": finding.pattern,
            }
        )
    rows.sort(key=lambda item: (item["file"], item["line"], item["pattern"]))
    return {
        "version": BASELINE_FORMAT_VERSION,
        "scanner_version": SCANNER_VERSION,
        "findings": rows,
    }


def write_baseline(path: Path, findings: Iterable[Finding]) -> None:
    payload = json.dumps(baseline_document(findings), indent=2, ensure_ascii=False)
    path.write_text(payload + "\n", encoding="utf-8")


def _parse_ignore_patterns(raw: Optional[str]) -> Set[str]:
    if raw is None:
        return {"*"}
    cleaned = raw.split("*/", 1)[0]
    names = {part.strip() for part in cleaned.replace(",", " ").split() if part.strip()}
    return names or {"*"}


def parse_inline_suppressions(text: str, language: str) -> Dict[int, Set[str]]:
    """Map 1-based line numbers to ignored pattern names (or ``*`` for all)."""
    lines = split_lines(text)
    mapped: Dict[int, Set[str]] = {}

    def add(line_no: int, patterns: Set[str]) -> None:
        mapped.setdefault(line_no, set()).update(patterns)

    for index, line in enumerate(lines):
        match = _IGNORE_PATTERN.search(line)
        if match is None:
            continue
        kind = match.group(1).lower()
        patterns = _parse_ignore_patterns(match.group(2))
        line_no = index + 1
        add(line_no, patterns)
        applies_to_next = kind == "ignore-next-line" or is_comment_line(line, language)
        if not applies_to_next:
            continue
        for following in range(index + 1, len(lines)):
            if lines[following].strip():
                add(following + 1, patterns)
                break
    return mapped


def is_suppressed(
    finding: Finding,
    suppressions: Dict[int, Set[str]],
    extra_lines: Optional[Iterable[int]] = None,
) -> bool:
    lines: Set[int] = {finding.line}
    end = finding.end_line if finding.end_line else finding.line
    if end > finding.line:
        lines.update(range(finding.line, end + 1))
    if extra_lines:
        lines.update(extra_lines)
    for line_no in lines:
        patterns = suppressions.get(line_no)
        if patterns and ("*" in patterns or finding.pattern in patterns):
            return True
    return False


def filter_inline_suppressions(
    findings: List[Finding],
    text: str,
    language: str,
) -> Tuple[List[Finding], int]:
    """Drop findings covered by ``code-scanner: ignore`` comments."""
    if not findings:
        return findings, 0
    suppressions = parse_inline_suppressions(text, language)
    if not suppressions:
        return findings, 0
    kept = [item for item in findings if not is_suppressed(item, suppressions)]
    return kept, len(findings) - len(kept)


def apply_baseline(report: ScanReport, baseline: Baseline) -> ScanReport:
    """Remove findings that match the committed baseline."""
    kept: List[Finding] = []
    ignored = 0
    for finding in report.findings:
        if baseline.contains(finding):
            ignored += 1
        else:
            kept.append(finding)
    report.findings = kept
    report.ignored_baseline = ignored
    report.status = "flagged" if kept else "clean"
    return report


def apply_changed_files(report: ScanReport, changed: Set[str]) -> ScanReport:
    """Keep findings whose file is in the git-changed set."""
    kept: List[Finding] = []
    ignored = 0
    for finding in report.findings:
        if finding.file in changed:
            kept.append(finding)
        else:
            ignored += 1
    report.findings = kept
    report.ignored_unchanged = ignored
    report.status = "flagged" if kept else "clean"
    return report


def _run_git(root: Path, args: List[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )


def git_changed_files(root: Path, since: str) -> List[str]:
    """Return scan-root-relative POSIX paths changed since *since*.

    Uses ``git diff --name-only`` (working tree vs *since*) plus untracked
    files. Paths outside *root* are dropped. Does not execute repository
    scripts; only the host ``git`` binary is invoked.
    """
    if not since or since.startswith("-"):
        raise GitError("invalid --since revision")
    root = root.resolve()
    try:
        top = _run_git(root, ["rev-parse", "--show-toplevel"])
    except OSError as exc:
        raise GitError(f"cannot run git: {exc}") from exc
    if top.returncode != 0:
        message = (top.stderr or top.stdout or "not a git repository").strip()
        raise GitError(message.splitlines()[0] if message else "not a git repository")
    repo_root = Path(top.stdout.strip())

    diff = _run_git(
        root,
        ["diff", "--name-only", "-z", "--diff-filter=ACMRT", since],
    )
    if diff.returncode != 0:
        message = (diff.stderr or diff.stdout or f"git diff failed for {since!r}").strip()
        raise GitError(message.splitlines()[0] if message else f"git diff failed for {since!r}")

    extra = _run_git(root, ["ls-files", "--others", "--exclude-standard", "-z"])
    raw_parts: List[str] = []
    for blob in (diff.stdout, extra.stdout if extra.returncode == 0 else ""):
        if blob:
            raw_parts.extend(part for part in blob.split("\0") if part)

    try:
        prefix = root.relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        prefix = ""
    if prefix in {".", ""}:
        prefix = ""

    seen: Set[str] = set()
    out: List[str] = []
    for raw in raw_parts:
        posix = raw.replace("\\", "/")
        if prefix:
            if posix == prefix:
                continue
            headed = prefix + "/"
            if not posix.startswith(headed):
                continue
            posix = posix[len(headed) :]
        if posix and posix not in seen:
            seen.add(posix)
            out.append(posix)
    out.sort()
    return out
