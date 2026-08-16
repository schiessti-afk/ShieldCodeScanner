"""Cluster findings into reviewer-facing incidents with a destination hint.

Same detections as the engine; this module only groups and labels them.
Hosts are classified from literal strings already in the source. No URL
is fetched.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from typing import Dict, List, Sequence, Tuple
from urllib.parse import urlparse

from models import SEVERITY_RANK, Finding, Incident, ScanReport


SOURCE_LABELS = {
    "secret": "credential read",
    "sensitive_file": "credential read",
    "download": "download",
    "obfuscated": "decode",
    "user_input": "user input",
    "dangerous_path": "dangerous path",
    "privilege": "privilege",
    "persistence": "persistence",
}

SINK_LABELS = {
    "network": "network sink",
    "exec_dynamic": "dynamic exec",
    "delete_recursive": "recursive delete",
    "persistence": "persistence write",
    "chmod_exec": "mark executable",
}

PATTERN_SOURCE_KIND = {
    "api_key_exfiltration": "secret",
    "sensitive_file_exfiltration": "sensitive_file",
    "sensitive_file_access": "sensitive_file",
    "download_and_execute": "download",
    "pipe_to_shell": "download",
    "powershell_download_iex": "download",
    "privilege_download_execute": "download",
    "obfuscated_download_execution": "download",
    "standalone_file_download": "download",
    "obfuscated_execution": "obfuscated",
    "encoded_powershell": "obfuscated",
    "secret_in_execution": "secret",
    "user_input_execution": "user_input",
    "destructive_root_deletion": "dangerous_path",
    "destructive_path_deletion": "dangerous_path",
    "privilege_destructive": "dangerous_path",
    "persistence_modification": "persistence",
    "persistence_with_remote_payload": "download",
    "persistence_with_obfuscation": "obfuscated",
    "npm_lifecycle_execution": "download",
}

PATTERN_SINK_KIND = {
    "api_key_exfiltration": "network",
    "sensitive_file_exfiltration": "network",
    "download_and_execute": "exec_dynamic",
    "pipe_to_shell": "exec_dynamic",
    "powershell_download_iex": "exec_dynamic",
    "privilege_download_execute": "exec_dynamic",
    "obfuscated_download_execution": "exec_dynamic",
    "obfuscated_execution": "exec_dynamic",
    "encoded_powershell": "exec_dynamic",
    "secret_in_execution": "exec_dynamic",
    "user_input_execution": "exec_dynamic",
    "destructive_root_deletion": "delete_recursive",
    "destructive_path_deletion": "delete_recursive",
    "privilege_destructive": "delete_recursive",
    "persistence_modification": "persistence",
    "persistence_with_remote_payload": "persistence",
    "persistence_with_obfuscation": "persistence",
    "npm_lifecycle_execution": "exec_dynamic",
}

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
    "secret_in_execution": "secret_exec",
    "user_input_execution": "user_exec",
    "persistence_modification": "persistence",
    "persistence_with_remote_payload": "persistence",
    "persistence_with_obfuscation": "persistence",
    "npm_lifecycle_execution": "npm",
}

PASTE_HOSTS = frozenset(
    {
        "pastebin.com",
        "paste.ee",
        "hastebin.com",
        "ghostbin.com",
        "dpaste.com",
        "dpaste.org",
        "paste.mozilla.org",
        "gist.github.com",
        "gist.githubusercontent.com",
        "transfer.sh",
        "file.io",
        "0x0.st",
        "catbox.moe",
        "termbin.com",
        "ix.io",
        "clbin.com",
        "paste.debian.net",
    }
)

WEBHOOK_HOSTS = frozenset(
    {
        "hooks.slack.com",
        "discord.com",
        "discordapp.com",
        "webhook.site",
        "eo.requestbin.com",
        "requestbin.com",
        "hooks.zapier.com",
        "hook.eu1.make.com",
        "in.pipedream.com",
    }
)

WEBHOOK_HOST_SUFFIXES = (
    ".ngrok.io",
    ".ngrok-free.app",
    ".webhook.office.com",
)

FIRST_PARTY_HOSTS = frozenset(
    {
        "api.openai.com",
        "api.anthropic.com",
        "api.github.com",
        "api.stripe.com",
        "api.slack.com",
        "api.heroku.com",
        "api.npmjs.org",
        "pypi.org",
        "graph.microsoft.com",
        "oauth2.googleapis.com",
        "www.googleapis.com",
        "api.sendgrid.com",
        "api.twilio.com",
    }
)

FIRST_PARTY_SUFFIXES = (
    ".googleapis.com",
    ".amazonaws.com",
    ".cloudflare.com",
)

_URL_RE = re.compile(r"https?://[^\s'\"\\)>\]]+", re.IGNORECASE)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def classify_destination(raw: str) -> Tuple[str, str]:
    """Return ``(kind, hint)`` for a URL or host literal. Hint is host-only."""
    text = (raw or "").strip().strip("\"'`")
    if not text:
        return "", ""
    host = _host_of(text)
    if not host:
        ip_match = _IPV4_RE.search(text)
        if ip_match:
            return "hardcoded_ip", ip_match.group(0)
        return "", ""
    hint = host
    if _is_ip_host(host):
        return "hardcoded_ip", host
    lowered = host.lower()
    path = _path_of(text).lower()
    if (
        lowered in WEBHOOK_HOSTS
        or any(lowered.endswith(suffix) for suffix in WEBHOOK_HOST_SUFFIXES)
        or "webhook" in lowered
        or "/webhook" in path
        or "/hooks/" in path
    ):
        return "webhook", hint
    if lowered in PASTE_HOSTS or lowered.startswith("paste."):
        return "paste_host", hint
    if lowered in FIRST_PARTY_HOSTS or any(
        lowered.endswith(suffix) for suffix in FIRST_PARTY_SUFFIXES
    ):
        return "first_party_api", hint
    return "remote_host", hint


def destination_from_text(text: str) -> Tuple[str, str]:
    """Classify the first URL or IP found in *text*."""
    if not text:
        return "", ""
    match = _URL_RE.search(text)
    if match:
        return classify_destination(match.group(0).rstrip(".,;"))
    ip_match = _IPV4_RE.search(text)
    if ip_match:
        return "hardcoded_ip", ip_match.group(0)
    return "", ""


def source_kind_for(finding: Finding) -> str:
    return finding.source_kind or PATTERN_SOURCE_KIND.get(finding.pattern, "")


def sink_kind_for(finding: Finding) -> str:
    return finding.sink_kind or PATTERN_SINK_KIND.get(finding.pattern, "")


def flow_for(
    report_path: str,
    source_line: int,
    sink_line: int,
    source_kind: str,
    sink_kind: str,
) -> Tuple[str, ...]:
    """Build a short ``file:line role`` chain for a source/sink pair."""
    steps: List[str] = []
    source_label = SOURCE_LABELS.get(source_kind, source_kind or "source")
    sink_label = SINK_LABELS.get(sink_kind, sink_kind or "sink")
    if source_line and source_line != sink_line:
        steps.append(f"{report_path}:{source_line} {source_label}")
    if sink_line:
        if source_line == sink_line and source_kind and sink_kind:
            steps.append(f"{report_path}:{sink_line} {source_label} → {sink_label}")
        else:
            steps.append(f"{report_path}:{sink_line} {sink_label}")
    return tuple(steps)


def cluster_incidents(findings: Sequence[Finding]) -> List[Incident]:
    """Group findings that share a taint source into one incident each."""
    if not findings:
        return []
    families: Dict[Tuple[str, str], List[Finding]] = {}
    for finding in findings:
        families.setdefault(_cluster_family(finding), []).append(finding)

    incidents: List[Incident] = []
    for family_key, items in families.items():
        items = sorted(items, key=lambda item: (item.line, item.pattern))
        used: set = set()
        sinks = [
            item
            for item in items
            if sink_kind_for(item) or item.source_line
        ]
        if not sinks:
            sinks = list(items)
        for sink in sinks:
            if id(sink) in used:
                continue
            source_line = sink.source_line or sink.line
            group = [sink]
            used.add(id(sink))
            for other in items:
                if id(other) in used:
                    continue
                other_anchor = other.source_line or other.line
                on_path = other.line <= sink.line and not sink_kind_for(other)
                same_source = other_anchor == source_line or other.line == source_line
                if same_source or on_path:
                    group.append(other)
                    used.add(id(other))
            incidents.append(_incident_from_group(family_key, group))
        for leftover in items:
            if id(leftover) not in used:
                incidents.append(_incident_from_group(family_key, [leftover]))
    incidents.sort(
        key=lambda item: (
            item.file,
            item.line,
            SEVERITY_RANK.get(item.severity, 99),
            item.pattern,
        )
    )
    return incidents


def _incident_from_group(
    family_key: Tuple[str, str], group: Sequence[Finding]
) -> Incident:
    primary = _primary_finding(group)
    source_line = min((item.source_line or item.line) for item in group)
    source_kind = source_kind_for(primary) or family_key[1]
    sink_kind = sink_kind_for(primary)
    chain = primary.flow or flow_for(
        primary.file,
        source_line,
        primary.line,
        source_kind,
        sink_kind,
    )
    if len(group) > 1 and source_line != primary.line:
        chain = flow_for(
            primary.file,
            source_line,
            primary.line,
            source_kind,
            sink_kind or "sink",
        )
    dest_kind = primary.destination_kind
    dest_hint = primary.destination_hint
    if not dest_kind:
        dest_kind, dest_hint = destination_from_text(primary.code_snippet)
    patterns = tuple(sorted({item.pattern for item in group}))
    ident = _incident_id(family_key[0], source_line, family_key[1], primary.pattern)
    return Incident(
        id=ident,
        severity=primary.severity,
        pattern=primary.pattern,
        file=primary.file,
        line=primary.line,
        chain=chain,
        patterns=patterns,
        destination_kind=dest_kind,
        destination_hint=dest_hint,
        description=primary.description,
    )


def attach_incidents(report: ScanReport) -> ScanReport:
    """Rebuild ``report.incidents`` from the current finding list."""
    report.incidents = cluster_incidents(report.findings)
    return report


def _cluster_family(finding: Finding) -> Tuple[str, str]:
    kind = source_kind_for(finding)
    if kind:
        return (finding.file, kind)
    return (finding.file, PATTERN_GROUPS.get(finding.pattern, finding.pattern))


def _primary_finding(group: Sequence[Finding]) -> Finding:
    return min(
        group,
        key=lambda item: (
            SEVERITY_RANK.get(item.severity, 99),
            0 if sink_kind_for(item) else 1,
            item.line,
            item.pattern,
        ),
    )


def _incident_id(file: str, source_line: int, group: str, pattern: str) -> str:
    payload = f"{file}\n{source_line}\n{group}\n{pattern}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:12]


def _host_of(raw: str) -> str:
    text = raw.strip()
    if "://" not in text:
        candidate = text.split("/", 1)[0]
        return candidate.split(":", 1)[0] if _is_ip_host(candidate.split(":", 1)[0]) or "." in candidate else candidate
    parsed = urlparse(text)
    return parsed.hostname or ""


def _path_of(raw: str) -> str:
    if "://" not in raw:
        return ""
    return urlparse(raw).path or ""


def _is_ip_host(host: str) -> bool:
    if not host:
        return False
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False
