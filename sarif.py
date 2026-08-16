"""SARIF 2.1.0 report rendering for CI annotations.

Output is deterministic (no timestamps). Paths stay repository-relative
with ``/`` separators so GitHub and GitLab can mark the exact lines.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from baseline import fingerprint_for
from models import SCANNER_VERSION, Finding, ScanReport
from rules import COMBO_RULES, DIRECT_RULES, FILE_RULES


SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"

_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}

_SECURITY_SEVERITY = {
    "critical": "9.0",
    "high": "7.0",
    "medium": "5.0",
    "low": "3.0",
}


def _sarif_level(severity: str) -> str:
    return _LEVEL.get(severity, "warning")


def _rule_index() -> Dict[str, Dict[str, str]]:
    catalog: Dict[str, Dict[str, str]] = {}
    for rule in COMBO_RULES:
        catalog[rule.name] = {
            "severity": rule.severity,
            "description": rule.description,
        }
    for rule in DIRECT_RULES:
        catalog.setdefault(
            rule.name,
            {"severity": rule.severity, "description": rule.description},
        )
    for rule in FILE_RULES:
        catalog.setdefault(
            rule.name,
            {
                "severity": "high",
                "description": "Suspicious package lifecycle or file-level pattern detected.",
            },
        )
    return catalog


def _driver_rules(findings: List[Finding]) -> List[Dict[str, Any]]:
    catalog = _rule_index()
    names = sorted({item.pattern for item in findings})
    rules: List[Dict[str, Any]] = []
    for name in names:
        meta = catalog.get(name, {})
        finding = next((item for item in findings if item.pattern == name), None)
        severity = (finding.severity if finding else meta.get("severity")) or "medium"
        description = (
            (finding.description if finding else None)
            or meta.get("description")
            or name
        )
        rules.append(
            {
                "id": name,
                "name": name,
                "shortDescription": {"text": description},
                "fullDescription": {"text": description},
                "defaultConfiguration": {"level": _sarif_level(severity)},
                "properties": {
                    "tags": ["security"],
                    "precision": "medium",
                    "security-severity": _SECURITY_SEVERITY.get(severity, "5.0"),
                },
            }
        )
    return rules


def _result(finding: Finding) -> Dict[str, Any]:
    return {
        "ruleId": finding.pattern,
        "level": _sarif_level(finding.severity),
        "message": {"text": finding.description},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": finding.file,
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {
                        "startLine": finding.line,
                        "snippet": {"text": finding.code_snippet},
                    },
                }
            }
        ],
        "partialFingerprints": {
            "primaryLocationLineHash": fingerprint_for(finding),
        },
        "properties": {
            "severity": finding.severity,
        },
    }


def report_to_sarif(report: ScanReport) -> Dict[str, Any]:
    run_properties: Dict[str, Any] = {
        "status": report.status,
        "scanned_files": report.scanned_files,
        "skipped_files": report.skipped_files,
    }
    ignored = report.to_dict().get("ignored")
    if ignored:
        run_properties["ignored"] = ignored
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "code-scanner",
                        "version": report.scanner_version or SCANNER_VERSION,
                        "rules": _driver_rules(report.findings),
                    }
                },
                "results": [_result(item) for item in report.findings],
                "properties": run_properties,
            }
        ],
    }


def render_sarif(report: ScanReport) -> str:
    return json.dumps(report_to_sarif(report), indent=2, ensure_ascii=False) + "\n"
