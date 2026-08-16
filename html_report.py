"""Self-contained HTML report rendering for human review.

Output is deterministic (no timestamps). All user-controlled text is escaped.
"""

from __future__ import annotations

import html
from typing import List

from models import Finding, Incident, ScanReport

_SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
}


def _esc(value: str) -> str:
    return html.escape(value, quote=True)


def _severity_class(severity: str) -> str:
    return severity if severity in _SEVERITY_ORDER else "medium"


def _sort_incidents(incidents: List[Incident]) -> List[Incident]:
    return sorted(
        incidents,
        key=lambda item: (
            _SEVERITY_ORDER.get(item.severity, 99),
            item.file,
            item.line,
            item.pattern,
        ),
    )


def _sort_findings(findings: List[Finding]) -> List[Finding]:
    return sorted(
        findings,
        key=lambda item: (
            _SEVERITY_ORDER.get(item.severity, 99),
            item.file,
            item.line,
            item.pattern,
        ),
    )


def _render_chain(steps: tuple[str, ...]) -> str:
    if not steps:
        return ""
    items = "".join(f"<li>{_esc(step)}</li>" for step in steps)
    return f"<ol class=\"chain\">{items}</ol>"


def _render_incident(incident: Incident) -> str:
    severity = _severity_class(incident.severity)
    location = f"{incident.file}:{incident.line}"
    destination = ""
    if incident.destination_kind:
        hint = incident.destination_hint
        if hint:
            destination = (
                f"<p class=\"meta\">"
                f"Destination: <span class=\"dest\">{_esc(incident.destination_kind)}</span> "
                f"({_esc(hint)})"
                f"</p>"
            )
        else:
            destination = (
                f"<p class=\"meta\">"
                f"Destination: <span class=\"dest\">{_esc(incident.destination_kind)}</span>"
                f"</p>"
            )
    description = ""
    if incident.description:
        description = f"<p class=\"desc\">{_esc(incident.description)}</p>"
    patterns = ", ".join(_esc(name) for name in incident.patterns)
    return (
        f"<article class=\"card incident severity-{severity}\">"
        f"<header>"
        f"<span class=\"badge\">{_esc(incident.severity)}</span> "
        f"<strong>{_esc(incident.pattern)}</strong>"
        f"</header>"
        f"<p class=\"meta\">{_esc(location)}</p>"
        f"{description}"
        f"{destination}"
        f"<p class=\"meta\">Patterns: {patterns}</p>"
        f"{_render_chain(incident.chain)}"
        f"</article>"
    )


def _render_finding(finding: Finding) -> str:
    severity = _severity_class(finding.severity)
    location = f"{finding.file}:{finding.line}"
    destination = ""
    if finding.destination_kind:
        hint = finding.destination_hint
        if hint:
            destination = (
                f"<p class=\"meta\">"
                f"Destination: {_esc(finding.destination_kind)} ({_esc(hint)})"
                f"</p>"
            )
        else:
            destination = (
                f"<p class=\"meta\">Destination: {_esc(finding.destination_kind)}</p>"
            )
    flow = ""
    if finding.flow:
        flow = _render_chain(finding.flow)
    return (
        f"<article class=\"card finding severity-{severity}\">"
        f"<header>"
        f"<span class=\"badge\">{_esc(finding.severity)}</span> "
        f"<strong>{_esc(finding.pattern)}</strong>"
        f"</header>"
        f"<p class=\"meta\">{_esc(location)}</p>"
        f"<p class=\"desc\">{_esc(finding.description)}</p>"
        f"{destination}"
        f"{flow}"
        f"<pre class=\"snippet\">{_esc(finding.code_snippet)}</pre>"
        f"</article>"
    )


def _render_skipped(report: ScanReport) -> str:
    if not report.skipped:
        return ""
    rows = "".join(
        f"<tr><td>{_esc(item.file)}</td><td>{_esc(item.reason)}</td></tr>"
        for item in report.skipped
    )
    return (
        "<section>"
        "<h2>Skipped files</h2>"
        f"<p class=\"meta\">{report.skipped_files} file(s) were not analyzed.</p>"
        "<table>"
        "<thead><tr><th>File</th><th>Reason</th></tr></thead>"
        f"<tbody>{rows}</tbody>"
        "</table>"
        "</section>"
    )


def _render_ignored(report: ScanReport) -> str:
    parts: List[str] = []
    if report.ignored_inline:
        parts.append(f"inline suppressions: {report.ignored_inline}")
    if report.ignored_baseline:
        parts.append(f"baseline: {report.ignored_baseline}")
    if report.ignored_unchanged:
        parts.append(f"unchanged since ref: {report.ignored_unchanged}")
    if not parts:
        return ""
    joined = "; ".join(parts)
    return (
        "<section>"
        "<h2>Ignored findings</h2>"
        f"<p class=\"meta\">{_esc(joined)}</p>"
        "</section>"
    )


def render_html(report: ScanReport) -> str:
    """Return a complete HTML document for ``report``."""
    status = report.status
    status_class = "clean" if status == "clean" else "flagged"
    incidents = _sort_incidents(list(report.incidents))
    findings = _sort_findings(list(report.findings))

    if incidents:
        incident_block = (
            "<section>"
            "<h2>Incidents</h2>"
            "<p class=\"intro\">Each incident is one reviewer-facing story.</p>"
            + "".join(_render_incident(item) for item in incidents)
            + "</section>"
        )
    else:
        incident_block = (
            "<section>"
            "<h2>Incidents</h2>"
            "<p class=\"intro\">No incidents reported.</p>"
            "</section>"
        )

    if findings:
        finding_block = (
            "<section>"
            "<h2>Findings</h2>"
            + "".join(_render_finding(item) for item in findings)
            + "</section>"
        )
    else:
        finding_block = (
            "<section>"
            "<h2>Findings</h2>"
            "<p class=\"intro\">No findings reported.</p>"
            "</section>"
        )

    return (
        "<!DOCTYPE html>"
        "<html lang=\"en\">"
        "<head>"
        "<meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        "<title>Shield Code Scanner Report</title>"
        "<style>"
        ":root {"
        "  --bg: #f6f8fa;"
        "  --surface: #ffffff;"
        "  --text: #1f2328;"
        "  --muted: #656d76;"
        "  --border: #d0d7de;"
        "  --critical: #cf222e;"
        "  --high: #bc4c00;"
        "  --medium: #9a6700;"
        "  --low: #0969da;"
        "  --clean: #1a7f37;"
        "  --flagged: #cf222e;"
        "}"
        "body {"
        "  margin: 0;"
        "  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;"
        "  background: var(--bg);"
        "  color: var(--text);"
        "  line-height: 1.5;"
        "}"
        "main {"
        "  max-width: 960px;"
        "  margin: 0 auto;"
        "  padding: 24px 16px 48px;"
        "}"
        "h1 { margin: 0 0 8px; font-size: 1.75rem; }"
        "h2 { margin: 32px 0 12px; font-size: 1.25rem; border-bottom: 1px solid var(--border); padding-bottom: 8px; }"
        ".summary {"
        "  background: var(--surface);"
        "  border: 1px solid var(--border);"
        "  border-radius: 8px;"
        "  padding: 16px;"
        "  display: grid;"
        "  gap: 8px;"
        "}"
        ".status {"
        "  display: inline-block;"
        "  font-weight: 600;"
        "  text-transform: uppercase;"
        "  letter-spacing: 0.04em;"
        "  font-size: 0.85rem;"
        "  padding: 2px 8px;"
        "  border-radius: 999px;"
        "  border: 1px solid transparent;"
        "}"
        ".status-clean { color: var(--clean); background: #dafbe1; border-color: #aceebb; }"
        ".status-flagged { color: var(--flagged); background: #ffebe9; border-color: #ff8182; }"
        ".stats { color: var(--muted); margin: 0; }"
        ".intro { color: var(--muted); margin: 0 0 12px; }"
        ".card {"
        "  background: var(--surface);"
        "  border: 1px solid var(--border);"
        "  border-left-width: 4px;"
        "  border-radius: 8px;"
        "  padding: 14px 16px;"
        "  margin-bottom: 12px;"
        "}"
        ".severity-critical { border-left-color: var(--critical); }"
        ".severity-high { border-left-color: var(--high); }"
        ".severity-medium { border-left-color: var(--medium); }"
        ".severity-low { border-left-color: var(--low); }"
        ".badge {"
        "  display: inline-block;"
        "  font-size: 0.75rem;"
        "  font-weight: 600;"
        "  text-transform: uppercase;"
        "  margin-right: 8px;"
        "  color: var(--muted);"
        "}"
        ".meta { margin: 6px 0; color: var(--muted); font-size: 0.95rem; }"
        ".desc { margin: 8px 0; }"
        ".dest { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; }"
        ".chain { margin: 8px 0 0 18px; padding: 0; }"
        ".snippet {"
        "  margin: 10px 0 0;"
        "  padding: 12px;"
        "  background: #f6f8fa;"
        "  border: 1px solid var(--border);"
        "  border-radius: 6px;"
        "  overflow-x: auto;"
        "  white-space: pre-wrap;"
        "  word-break: break-word;"
        "  font-family: ui-monospace, SFMono-Regular, Consolas, monospace;"
        "  font-size: 0.85rem;"
        "}"
        "table {"
        "  width: 100%;"
        "  border-collapse: collapse;"
        "  background: var(--surface);"
        "  border: 1px solid var(--border);"
        "  border-radius: 8px;"
        "  overflow: hidden;"
        "}"
        "th, td {"
        "  text-align: left;"
        "  padding: 10px 12px;"
        "  border-bottom: 1px solid var(--border);"
        "  font-size: 0.95rem;"
        "}"
        "th { background: #f6f8fa; color: var(--muted); font-weight: 600; }"
        "tr:last-child td { border-bottom: none; }"
        "footer { margin-top: 32px; color: var(--muted); font-size: 0.85rem; }"
        "</style>"
        "</head>"
        "<body>"
        "<main>"
        "<h1>Shield Code Scanner Report</h1>"
        "<div class=\"summary\">"
        f"<span class=\"status status-{status_class}\">{_esc(status)}</span>"
        f"<p class=\"stats\">"
        f"Scanned files: {report.scanned_files} · "
        f"Incidents: {len(incidents)} · "
        f"Findings: {len(findings)} · "
        f"Skipped: {report.skipped_files}"
        f"</p>"
        f"<p class=\"stats\">Scanner version: {_esc(report.scanner_version)}</p>"
        "</div>"
        f"{incident_block}"
        f"{finding_block}"
        f"{_render_skipped(report)}"
        f"{_render_ignored(report)}"
        "<footer>Findings are advisory and require human verification.</footer>"
        "</main>"
        "</body>"
        "</html>\n"
    )
