# Code Scanner

Local **static** security scanner for source-code repositories.

It helps a human reviewer find *suspicious* combinations of behavior
(credential access plus network transmission, download-and-execute,
destructive deletes of `/` or `$HOME`, persistence installs, and similar
patterns). It does **not** decide that a repository is malicious.

## Security boundary

This is a static analysis aid, not an antivirus engine.

The scanner **will**:

- recursively read selected source and config files
- report advisory findings with file, line, pattern, severity, description, and a short snippet
- skip binaries, oversized files, and unreadable files without aborting the scan

The scanner **will not**:

- execute, import, compile, or evaluate scanned code
- invoke shells, package managers, or `make` from the repository
- contact URLs found in the repository
- modify, delete, quarantine, or block files
- claim with certainty that code is malicious

Findings require human verification.

## Requirements

- Python 3.9+
- Standard library only (no third-party runtime dependencies)

## Usage

```bash
python scanner.py /path/to/project
```

JSON is written to stdout. Optional flags:

```bash
python scanner.py /path/to/project --output report.json
python scanner.py /path/to/project --format json --max-file-size 5242880 --verbose
```

`--verbose` diagnostics go to stderr so stdout stays machine-readable.

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | no findings |
| 1 | one or more findings |
| 2 | scanner or input error |

Exit status does not encode severity.

## Output

```json
{
  "status": "flagged",
  "scanner_version": "1.0.0",
  "scanned_files": 142,
  "skipped_files": 3,
  "findings": [
    {
      "file": "src/sync.py",
      "line": 47,
      "pattern": "api_key_exfiltration",
      "severity": "critical",
      "description": "Suspicious credential exfiltration pattern detected: ...",
      "code_snippet": "secret = os.environ['API_KEY']\nrequests.post(url, data=secret)"
    }
  ]
}
```

`status` is `clean` when there are zero findings, otherwise `flagged`.
Reports are deterministic: no timestamps, stable finding order, and `/`
path separators even on Windows.

## What is scanned

Code extensions: `.py`, `.js`, `.ts`, `.jsx`, `.tsx`, `.sh`, `.bash`,
`.zsh`, `.rb`, `.go`, `.rs`, `.swift`, `.bat`, `.cmd`, `.ps1`, `.vbs`.

Important names and config extensions such as `package.json`,
`requirements.txt`, `Dockerfile`, `.env`, `.env.*`, `*.yml`, `*.json`,
and `*.toml` are also inspected.

These directories are skipped entirely (edit `SKIP_DIRECTORIES` in
`utils.py` to extend the list):

`.git`, `node_modules`, `venv`, `.venv`, `env`, `.env`, `__pycache__`,
`.pytest_cache`, `.mypy_cache`, `.tox`, `dist`, `build`, `target`,
`vendor`, `coverage`.

Default maximum file size is 5 MB (`--max-file-size` overrides).

## Detection approach

Rules live in `rules.py` as:

- **signals** — atomic line matches (secret access, network, exec, …)
- **combo rules** — sink plus taint (secret flowing into a POST, download flowing into `exec`, …)
- **direct rules** — high-signal single lines (`rm -rf /`, `curl | sh`, encoded PowerShell)
- **file rules** — structured parsers (currently `package.json` lifecycle scripts)

The engine in `scanner.py` tracks simple forward, file-local assignments
so this is reported even when the operations are on different lines:

```python
secret = os.environ["API_KEY"]
requests.post(url, data=secret)
```

### Assumptions

- Isolated keywords (`rm`, `eval`, `requests.get`, `os.environ`) are not
  treated as malicious by themselves.
- Environment-variable reads are only escalated when the value appears to
  reach a network sink, unusual write, or dynamic execution.
- `requests.get` / `fetch` used as a normal API call is not a “download”.
  Downloads are file writes, pipe-to-shell, or feeding bytes into `exec` / `IEX`.
- `rm -rf ./build` and `rm -rf "$BUILD_DIR"` are treated as cleanup.
- `rm -rf /`, `rm -rf ~`, and `rm -rf "$HOME"` are reported as critical.
- Ordinary npm lifecycle scripts (`tsc`, `husky install`, `node-gyp rebuild`)
  are not reported; download-and-execute or credential-sending hooks are.
- Base64 used as a data format, without execution, is not reported.
- `subprocess.run(["git", "status"], check=True)` is not reported.
- There is no cross-file taint tracking and no full AST for every language.
- Shell-family files also use a 25-line ambient window because assignment
  tracking is weaker there.
- Wording is always advisory (“suspicious pattern detected”).

False positives are expected. Severity reflects combination strength, not
a verdict.

## Adding a rule

1. Open `rules.py`.
2. Add a `SignalDef`, `DirectRule`, `ComboRule`, or `FileRule`.
3. Keep the `name` stable; it is the `pattern` ID in reports.
4. Restrict `languages` so Python regexes do not run on unrelated files.
5. Add a true-positive fixture and, when relevant, a benign counter-example
   under `tests/fixtures/`.

The scan engine does not need to change for new rules.

## Tests

```bash
python -m unittest discover -s tests -v
```

## Layout

```text
.
├── scanner.py      # CLI and analysis engine
├── rules.py        # signals, combo/direct/file rules
├── models.py       # Finding / ScanReport
├── utils.py        # traversal, binary detection, snippets
├── tests/
│   ├── test_scanner.py
│   └── fixtures/
│       ├── malicious/
│       └── benign/
├── README.md
└── pyproject.toml
```
