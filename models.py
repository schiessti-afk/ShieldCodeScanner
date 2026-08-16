"""Data models for the static code security scanner.

Assumptions
-----------
* Findings are advisory only. Severity describes pattern confidence/impact
  for a human reviewer, not a verdict that code is malicious.
* Paths stored on findings are repository-relative and use ``/`` separators
  so reports are deterministic across operating systems.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List


SCANNER_VERSION = "1.1.0"

SEVERITY_RANK = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
}


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class SkipReason(str, Enum):
    BINARY = "binary"
    OVERSIZE = "oversize"
    INVALID_UTF8 = "invalid_utf8"
    UNREADABLE = "unreadable"
    EMPTY = "empty"


@dataclass(frozen=True)
class Finding:
    file: str
    line: int
    pattern: str
    severity: str
    description: str
    code_snippet: str
    end_line: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file": self.file,
            "line": self.line,
            "pattern": self.pattern,
            "severity": self.severity,
            "description": self.description,
            "code_snippet": self.code_snippet,
        }


@dataclass(frozen=True)
class SkippedFile:
    file: str
    reason: str

    def to_dict(self) -> Dict[str, str]:
        return {"file": self.file, "reason": self.reason}


@dataclass
class ScanReport:
    status: str
    scanned_files: int
    findings: List[Finding] = field(default_factory=list)
    scanner_version: str = SCANNER_VERSION
    skipped_files: int = 0
    skipped: List[SkippedFile] = field(default_factory=list)
    ignored_inline: int = 0
    ignored_baseline: int = 0
    ignored_unchanged: int = 0

    def to_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "status": self.status,
            "scanner_version": self.scanner_version,
            "scanned_files": self.scanned_files,
            "skipped_files": self.skipped_files,
            "findings": [finding.to_dict() for finding in self.findings],
        }
        if self.skipped:
            payload["skipped"] = [item.to_dict() for item in self.skipped]
        ignored: Dict[str, int] = {}
        if self.ignored_inline:
            ignored["inline"] = self.ignored_inline
        if self.ignored_baseline:
            ignored["baseline"] = self.ignored_baseline
        if self.ignored_unchanged:
            ignored["unchanged"] = self.ignored_unchanged
        if ignored:
            payload["ignored"] = ignored
        return payload
