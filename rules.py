"""Structured detection rules for the static security scanner.

Assumptions about threat patterns
---------------------------------
* The scanner is a human-review aid, not an antivirus. Wording describes
  *suspicious patterns*, never a definitive malice verdict.
* Isolated keywords (``rm``, ``eval``, ``requests.get``, ``os.environ``)
  are not treated as malicious by themselves.
* Environment-variable *reads* are only escalated when the value appears to
  flow into a network sink, an unusual write, or dynamic execution.
* ``requests.get`` / ``fetch`` / ``http.Get`` used as a normal API call is
  not a "download". A download is writing remote bytes to a file, piping
  them to a shell, or feeding them to ``exec`` / ``IEX``.
* Recursive deletes of ``./build``, ``$BUILD_DIR``, or similarly local
  artifacts are treated as cleanup and are not reported.
* Recursive deletes of ``/``, ``~``, ``$HOME``, or equivalent drive roots
  are reported as critical.
* Ordinary npm lifecycle scripts (``tsc``, ``husky install``,
  ``node-gyp rebuild``) are not reported. Scripts that download-and-execute
  or exfiltrate credentials are reported.
* Base64/hex encode or decode used without a nearby execution or network
  sink is not reported (ordinary data-format use).
* ``subprocess.run([...], check=True)`` without ``shell=True`` and without
  tainted input is not reported.
* Python is analyzed with the stdlib ``ast`` module (parse only, never
  ``exec``). That covers ``from os import getenv``, attribute writes
  such as ``self.token = ...``, and ``subprocess.run(..., **{"shell": True})``.
  Other languages still use lexical assignment tracking. Cross-file flow
  uses a static export/import index (no execution): a function or module
  binding that returns a secret in ``secrets.py`` can taint
  ``key = config.get_api_key()`` in ``sync.py``.
* Package manifests (``package.json``, ``pyproject.toml``) are walked as
  structured documents, not as minified line-regex targets.
* Language-specific regexes are restricted to matching file kinds so a
  Python ``os.system`` rule cannot fire inside a YAML comment by accident
  unless that file kind opted in.

Adding a rule
-------------
Append a :class:`SignalDef`, :class:`DirectRule`, or :class:`ComboRule` to
the module-level lists below. The scan engine compiles patterns once at
import time and does not need to change.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, FrozenSet, List, Optional, Pattern, Tuple

from manifests import analyze_package_json, analyze_pyproject_toml
from models import Finding


PY = frozenset({"python"})
JS = frozenset({"javascript"})
SHELL = frozenset({"shell", "makefile", "dockerfile"})
PS = frozenset({"powershell"})
BATCH = frozenset({"batch"})
RB = frozenset({"ruby"})
GO = frozenset({"go"})
RS = frozenset({"rust"})
SWIFT = frozenset({"swift"})
VBS = frozenset({"vbscript"})
CONFIG = frozenset({"config", "python_deps", "dotenv"})
CODE = PY | JS | SHELL | PS | BATCH | RB | GO | RS | SWIFT | VBS
SHELLISH = SHELL | PS | BATCH | CONFIG | frozenset({"vbscript"})

# Secret-like environment variable name fragment. Bounded to avoid
# catastrophic backtracking and to skip HOME/PATH/USER/PWD.
_SECRET_NAME = (
    r"(?:"
    r"[A-Za-z0-9_]{0,40}(?:API_KEY|API_TOKEN|ACCESS_KEY|SECRET_KEY|"
    r"PRIVATE_KEY|AUTH_TOKEN|PASSWORD|SECRET|CREDENTIAL|CONN_STR|"
    r"CONNECTION_STRING|TOKEN)"
    r"|AWS_[A-Za-z0-9_]{0,40}"
    r"|ANTHROPIC_[A-Za-z0-9_]{0,40}"
    r"|OPENAI_[A-Za-z0-9_]{0,40}"
    r"|GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|PYPI_TOKEN|STRIPE_SECRET"
    r")"
)

_SENSITIVE_PATH = (
    r"(?:"
    r"~/?\.ssh/(?:id_rsa|id_dsa|id_ecdsa|id_ed25519|id_ecdsa_sk|id_ed25519_sk)"
    r"|~/?\.ssh/config"
    r"|~/?\.aws/credentials"
    r"|~/?\.aws/config"
    r"|~/?\.config/gcloud/[A-Za-z0-9_./-]{0,80}"
    r"|~/?\.docker/config\.json"
    r"|~/?\.gnupg/"
    r"|~/?\.kube/config"
    r"|/etc/shadow"
    r"|/etc/sudoers"
    r"|%USERPROFILE%\\AppData\\Local\\Google\\Chrome\\.*Login Data"
    r"|%APPDATA%\\(?:Mozilla|Google)\\"
    r"|Credential Manager"
    r"|Windows\\.+(?:Vault|Credentials)"
    r")"
)

_SECRET_NAME_RE = re.compile(r"^(?:" + _SECRET_NAME + r")$")
_SENSITIVE_PATH_RE = re.compile(_SENSITIVE_PATH, re.I)


def is_secret_env_name(name: str) -> bool:
    """Return True if *name* looks like a credential-bearing environment variable."""
    return bool(name) and _SECRET_NAME_RE.match(name) is not None


def is_sensitive_path(value: str) -> bool:
    """Return True if *value* references a well-known credential file path."""
    return bool(value) and _SENSITIVE_PATH_RE.search(value) is not None


def _compile(pattern: str, flags: int = 0) -> Pattern[str]:
    return re.compile(pattern, flags)


@dataclass(frozen=True)
class SignalDef:
    """Atomic line-level detector. Does not emit a finding by itself."""

    id: str
    regex: Pattern[str]
    languages: FrozenSet[str]
    taint: Optional[str] = None
    description: str = ""


@dataclass(frozen=True)
class DirectRule:
    """Emits a finding when a single line matches, with no taint required."""

    name: str
    severity: str
    description: str
    regex: Pattern[str]
    languages: FrozenSet[str]
    classify: Optional[Callable[[str], Optional[str]]] = None


@dataclass(frozen=True)
class ComboRule:
    """Emits a finding when a sink line uses the required taint kinds."""

    name: str
    severity: str
    description: str
    sink: str
    required_taints: Tuple[str, ...]
    languages: Optional[FrozenSet[str]] = None


@dataclass(frozen=True)
class FileRule:
    """Whole-file analyzer registered by language or exact filename."""

    name: str
    languages: FrozenSet[str]
    filenames: FrozenSet[str]
    analyzer: Callable[[str, str, List[str]], List[Finding]]


def _rm_severity(target: str) -> Optional[str]:
    """Classify a recursive-delete target. None means do not report."""
    raw = target.strip().strip("\"'`")
    raw = raw.rstrip(";")
    if not raw:
        return None
    # Strip common shell expansions for comparison.
    normalized = raw.replace("${HOME}", "$HOME").replace("%USERPROFILE%", "~")
    normalized = normalized.replace("%HOMEPATH%", "~")
    compact = normalized.replace("\\", "/").rstrip("/")

    critical_exact = {
        "/",
        "/*",
        "~",
        "~/",
        "$HOME",
        "$HOME/",
        "${HOME}",
        "${HOME}/",
        "C:",
        "C:/",
        "C:/*",
        "$env:USERPROFILE",
        "$env:HOME",
    }
    if compact in {"/", "~", "$HOME", "${HOME}", "C:", "C:/"} or normalized in critical_exact:
        return "critical"
    if compact in {".", ".."} or compact.endswith("/.") or compact.endswith("/.."):
        return "high"
    if compact in {"*", "./*", "./**"}:
        return "high"

    high_prefixes = (
        "/etc",
        "/usr",
        "/var",
        "/bin",
        "/sbin",
        "/root",
        "/home",
        "/System",
        "/Windows",
        "C:/Windows",
        "C:/Users",
    )
    for prefix in high_prefixes:
        if compact == prefix or compact.startswith(prefix + "/"):
            return "high"

    # Home-relative deletes of a project tree are suspicious but not root wipes.
    if compact.startswith("~/") or compact.startswith("$HOME/") or compact.startswith("${HOME}/"):
        return "high"

    # Local cleanup: ./build, build/, $BUILD_DIR, dist, node_modules, etc.
    return None


_RM_RF_RE = _compile(
    r"(?i)\brm\s+(?:--[a-z-]{1,40}\s+)*(?:-[a-zA-Z0-9]{1,16}\s+)*"
    r"-(?:[a-zA-Z]*r[a-zA-Z]*f|[a-zA-Z]*f[a-zA-Z]*r)[a-zA-Z]*"
    r"(?:\s+--[a-z-]{1,40})*\s+(?P<target>\S{1,300})"
)

_RMTREE_RE = _compile(
    r"(?i)(?:shutil\.rmtree|os\.removedirs|Path\([^)]{0,80}\)\.rmdir|"
    r"Remove-Item\b[^\n]{0,200}-Recurse|"
    r"FileUtils\.rm_rf|os\.RemoveAll|fs::remove_dir_all|"
    r"FileManager\.[A-Za-z]*remove|"
    r"rmdir\s+/s)\s*\(?\s*(?P<target>[^)\n]{1,300})"
)


def classify_rm_line(line: str) -> Optional[str]:
    match = _RM_RF_RE.search(line)
    if not match:
        return None
    return _rm_severity(match.group("target"))


def classify_rmtree_line(line: str) -> Optional[str]:
    match = _RMTREE_RE.search(line)
    if not match:
        return None
    return _rm_severity(match.group("target"))


# ---------------------------------------------------------------------------
# Atomic signals
# ---------------------------------------------------------------------------

SIGNAL_DEFS: List[SignalDef] = [
    # --- secrets / credentials ------------------------------------------------
    SignalDef(
        id="secret_env",
        taint="secret",
        languages=PY,
        regex=_compile(
            r"(?:os\.environ(?:\.get)?|os\.getenv)\s*(?:\[\s*)?\(\s*['\"]"
            + _SECRET_NAME
            + r"['\"]|(?:os\.environ\s*\[\s*['\"]"
            + _SECRET_NAME
            + r"['\"]\s*\])"
        ),
        description="Python environment secret access",
    ),
    SignalDef(
        id="secret_env",
        taint="secret",
        languages=JS,
        regex=_compile(
            r"process\.env(?:\." + _SECRET_NAME + r"|\s*\[\s*['\"]" + _SECRET_NAME + r"['\"]\s*\])"
        ),
        description="Node environment secret access",
    ),
    SignalDef(
        id="secret_env",
        taint="secret",
        languages=GO,
        regex=_compile(r"os\.Getenv\(\s*[\"']" + _SECRET_NAME + r"[\"']\s*\)"),
        description="Go environment secret access",
    ),
    SignalDef(
        id="secret_env",
        taint="secret",
        languages=RB,
        regex=_compile(r"ENV(?:\[|\.fetch)\s*[\[(]\s*['\"]" + _SECRET_NAME + r"['\"]"),
        description="Ruby environment secret access",
    ),
    SignalDef(
        id="secret_env",
        taint="secret",
        languages=RS,
        regex=_compile(
            r"(?:std::)?env::var(?:_os)?\(\s*[\"']" + _SECRET_NAME + r"[\"']\s*\)"
        ),
        description="Rust environment secret access",
    ),
    SignalDef(
        id="secret_env",
        taint="secret",
        languages=SHELL,
        regex=_compile(r"(?i)\$\{?" + _SECRET_NAME + r"\}?"),
        description="Shell environment secret access",
    ),
    SignalDef(
        id="secret_env",
        taint="secret",
        languages=PS,
        regex=_compile(r"(?i)\$env:" + _SECRET_NAME),
        description="PowerShell environment secret access",
    ),
    SignalDef(
        id="secret_env",
        taint="secret",
        languages=SWIFT,
        regex=_compile(
            r"ProcessInfo\.processInfo\.environment\s*\[\s*[\"']"
            + _SECRET_NAME
            + r"[\"']\s*\]"
        ),
        description="Swift environment secret access",
    ),
    # --- sensitive files -----------------------------------------------------
    SignalDef(
        id="sensitive_file",
        taint="sensitive_file",
        languages=CODE | CONFIG,
        regex=_compile(r"(?i)(?:" + _SENSITIVE_PATH + r")"),
        description="Reference to a credential or secret-bearing file path",
    ),
    SignalDef(
        id="sensitive_file",
        taint="sensitive_file",
        languages=PY,
        regex=_compile(
            r"(?i)open\(\s*(?:os\.path\.expanduser\s*\(\s*)?['\"]"
            r"(?:~/?\.ssh/|~/?\.aws/|~/?\.gnupg/|/etc/shadow)"
        ),
        description="Python open() of a sensitive path",
    ),
    # --- network sinks -------------------------------------------------------
    SignalDef(
        id="network",
        taint=None,
        languages=PY,
        regex=_compile(
            r"(?:"
            r"requests\.(?:get|post|put|patch|delete|request|head)\s*\("
            r"|urllib\.request\.(?:urlopen|Request|urlretrieve)\s*\("
            r"|http\.client\.(?:HTTPSConnection|HTTPConnection)\s*\("
            r"|httpx\.(?:get|post|put|patch|delete|request)\s*\("
            r"|aiohttp\.(?:ClientSession|request)\s*\("
            r"|socket\.(?:send(?:all)?|connect|create_connection)\s*\("
            r"|paramiko\.|ftplib\.|smtplib\."
            r"|\b(?:client|session)\.(?:get|post|put|patch|delete|request)\s*\("
            r")"
        ),
        description="Python network operation",
    ),
    SignalDef(
        id="network",
        languages=JS,
        regex=_compile(
            r"(?:"
            r"\bfetch\s*\("
            r"|axios\.(?:get|post|put|patch|delete|request)\s*\("
            r"|https?\.(?:request|get|post)\s*\("
            r"|new\s+XMLHttpRequest\s*\("
            r"|navigator\.sendBeacon\s*\("
            r"|WebSocket\s*\("
            r")"
        ),
        description="JavaScript network operation",
    ),
    SignalDef(
        id="network",
        languages=GO,
        regex=_compile(
            r"(?:http\.(?:Get|Post|PostForm|Head|Do|NewRequest)|"
            r"(?:\w+\.)?Dial(?:Timeout)?\s*\()"
        ),
        description="Go network operation",
    ),
    SignalDef(
        id="network",
        languages=RS,
        regex=_compile(
            r"(?:reqwest::|ureq::|hyper::|"
            r"TcpStream::connect|UdpSocket::send)"
        ),
        description="Rust network operation",
    ),
    SignalDef(
        id="network",
        languages=RB,
        regex=_compile(
            r"(?:Net::HTTP|URI\.open|open-uri|HTTParty\.|Faraday\.|RestClient\.)"
        ),
        description="Ruby network operation",
    ),
    SignalDef(
        id="network",
        languages=SHELL,
        regex=_compile(
            r"(?i)\b(?:curl|wget|nc|ncat|netcat|openssl\s+s_client)\b"
        ),
        description="Shell network tool",
    ),
    SignalDef(
        id="network",
        languages=PS,
        regex=_compile(
            r"(?i)(?:Invoke-WebRequest|Invoke-RestMethod|"
            r"New-Object\s+(?:Net|System\.Net)\.WebClient|"
            r"\[(?:Net|System\.Net)\.WebClient\]|"
            r"Start-BitsTransfer)"
        ),
        description="PowerShell network operation",
    ),
    SignalDef(
        id="network",
        languages=SWIFT,
        regex=_compile(r"URLSession|URLRequest"),
        description="Swift network operation",
    ),
    SignalDef(
        id="network",
        languages=VBS,
        regex=_compile(
            r"(?i)CreateObject\(\s*[\"'](?:MSXML2\.XMLHTTP|WinHttp\.WinHttpRequest)"
        ),
        description="VBScript HTTP object",
    ),
    # --- downloads (file-oriented / retrieve) --------------------------------
    SignalDef(
        id="download",
        taint="download",
        languages=PY,
        regex=_compile(
            r"(?:urllib\.request\.(?:urlretrieve|urlopen)\s*\(|"
            r"requests\.(?:get|post)\s*\(|"
            r"httpx\.(?:get|post)\s*\(|"
            r"urlretrieve\s*\()"
        ),
        description="Python HTTP retrieve (taints assigned variables as download)",
    ),
    SignalDef(
        id="download",
        taint="download",
        languages=SHELL | CONFIG | frozenset({"package_json", "dockerfile", "makefile"}),
        regex=_compile(
            r"(?i)\b(?:curl|wget)\b[^\n]{0,240}(?:\s-(?:O|o)\s|\s--output\s|\s-o\b)"
        ),
        description="curl/wget write to a file",
    ),
    SignalDef(
        id="download",
        taint="download",
        languages=PS,
        regex=_compile(
            r"(?i)(?:DownloadFile|DownloadString|Invoke-WebRequest[^\n]{0,160}"
            r"-OutFile|Start-BitsTransfer)"
        ),
        description="PowerShell download-to-file/string",
    ),
    SignalDef(
        id="download",
        taint="download",
        languages=JS,
        regex=_compile(
            r"(?:fs\.writeFile(?:Sync)?\s*\([^\n]{0,160}(?:await\s+)?fetch|"
            r"https?\.get\s*\([^\n]{0,160}createWriteStream)"
        ),
        description="Node download piped to a file",
    ),
    # Generic curl/wget still taints as download so `curl|sh` combos work even
    # when -o is absent (pipe-to-shell is also a DirectRule).
    SignalDef(
        id="download",
        taint="download",
        languages=SHELL | CONFIG | frozenset({"package_json", "dockerfile", "makefile"}),
        regex=_compile(r"(?i)\b(?:curl|wget)\s+https?://"),
        description="curl/wget of a remote URL",
    ),
    # --- dynamic execution ---------------------------------------------------
    SignalDef(
        id="exec_dynamic",
        taint=None,
        languages=PY,
        regex=_compile(
            r"(?:"
            r"\beval\s*\(|\bexec\s*\(|"
            r"os\.system\s*\(|os\.popen\s*\(|"
            r"subprocess\.(?:call|run|Popen|check_output|check_call)\s*\("
            r"[^\n]{0,200}shell\s*=\s*True|"
            r"commands\.getoutput\s*\(|pty\.spawn\s*\("
            r")"
        ),
        description="Python dynamic or shell execution",
    ),
    SignalDef(
        id="exec_dynamic",
        languages=JS,
        regex=_compile(
            r"(?:\beval\s*\(|new\s+Function\s*\(|"
            r"child_process\.(?:exec|execSync|spawn|execFile)\s*\(|"
            r"\bexec(?:Sync)?\s*\()"
        ),
        description="JavaScript dynamic or child-process execution",
    ),
    SignalDef(
        id="exec_dynamic",
        languages=SHELL,
        regex=_compile(
            r"(?i)(?:\beval\s+|bash\s+-c\s+|sh\s+-c\s+|"
            r"source\s+<\(|\$\(\s*(?:curl|wget)\b)"
        ),
        description="Shell eval / bash -c",
    ),
    SignalDef(
        id="exec_dynamic",
        languages=PS,
        regex=_compile(
            r"(?i)(?:Invoke-Expression|\bIEX\b|Invoke-Command|"
            r"Start-Process|"
            r"powershell(?:\.exe)?\s+[^\n]{0,80}-(?:enc|encodedcommand|e)\b)"
        ),
        description="PowerShell Invoke-Expression / encoded command",
    ),
    SignalDef(
        id="exec_dynamic",
        languages=RB,
        regex=_compile(r"\b(?:eval|system|exec|`|Open3\.|IO\.popen)\b"),
        description="Ruby dynamic execution",
    ),
    SignalDef(
        id="exec_dynamic",
        languages=GO,
        regex=_compile(r"exec\.Command\s*\("),
        description="Go exec.Command",
    ),
    SignalDef(
        id="exec_dynamic",
        languages=RS,
        regex=_compile(r"Command::new\s*\("),
        description="Rust Command::new",
    ),
    SignalDef(
        id="exec_dynamic",
        languages=BATCH,
        regex=_compile(r"(?i)\b(?:cmd\s+/c|call\s+|start\s+)"),
        description="cmd.exe execution",
    ),
    SignalDef(
        id="exec_dynamic",
        languages=VBS,
        regex=_compile(r"(?i)(?:WScript\.Shell|Execute(?:Global)?|Eval\s*\()"),
        description="VBScript execution",
    ),
    SignalDef(
        id="exec_dynamic",
        languages=SWIFT,
        regex=_compile(r"Process\(\)|NSTask|shell/bash"),
        description="Swift process launch",
    ),
    # --- obfuscation ---------------------------------------------------------
    SignalDef(
        id="obfuscation",
        taint="obfuscated",
        languages=PY,
        regex=_compile(
            r"(?:base64\.b64decode|binascii\.(?:unhexlify|a2b_base64)|"
            r"bytes\.fromhex|codecs\.decode\s*\([^\n]{0,80}['\"]hex|"
            r"gzip\.decompress|zlib\.decompress|lzma\.decompress|"
            r"marshal\.loads|pickle\.loads|"
            r"['\"]{1,3}(?:\\x[0-9a-fA-F]{2}){8,})"
        ),
        description="Python decode / decompress / pickle",
    ),
    SignalDef(
        id="obfuscation",
        taint="obfuscated",
        languages=JS,
        regex=_compile(
            r"(?:Buffer\.from\s*\([^\n]{0,120}['\"]base64['\"]|"
            r"atob\s*\(|String\.fromCharCode\s*\(|"
            r"\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){7,})"
        ),
        description="JavaScript base64 / char-code reconstruction",
    ),
    SignalDef(
        id="obfuscation",
        taint="obfuscated",
        languages=PS,
        regex=_compile(
            r"(?i)(?:FromBase64String|-EncodedCommand|\s-enc\s|"
            r"-e\s+[A-Za-z0-9+/=]{12,}|\[Convert\]::FromBase64String)"
        ),
        description="PowerShell encoded / base64 command",
    ),
    SignalDef(
        id="obfuscation",
        taint="obfuscated",
        languages=SHELL,
        regex=_compile(
            r"(?i)(?:base64\s+-d|base64\s+--decode|xxd\s+-r|"
            r"openssl\s+(?:enc|base64)\s+-d)"
        ),
        description="Shell base64/hex decode",
    ),
    SignalDef(
        id="obfuscation",
        taint="obfuscated",
        languages=RB,
        regex=_compile(r"Base64\.decode64|pack\(\s*['\"]H"),
        description="Ruby decode",
    ),
    SignalDef(
        id="obfuscation",
        taint="obfuscated",
        languages=GO,
        regex=_compile(r"base64\.(?:StdEncoding|URLEncoding)\.Decode"),
        description="Go base64 decode",
    ),
    # --- dangerous paths (for delete combos) ---------------------------------
    SignalDef(
        id="dangerous_path",
        taint="dangerous_path",
        languages=PY,
        regex=_compile(
            r"(?:os\.path\.expanduser\s*\(\s*['\"]~/?['\"]\s*\)|"
            r"['\"]/(?:['\"]|$)|['\"]C:\\\\['\"]|"
            r"Path\.home\s*\(\s*\)|"
            r"os\.path\.expandvars\s*\(\s*['\"]%USERPROFILE%)"
        ),
        description="Python home/root path expression",
    ),
    SignalDef(
        id="dangerous_path",
        taint="dangerous_path",
        languages=SHELL | PS | BATCH,
        regex=_compile(
            r"(?i)(?:\b(?:\$HOME|\$\{HOME\}|%USERPROFILE%|\$env:USERPROFILE)\b|"
            r"(?<!\S)~/?(?=\s|$)|(?<!\S)/(?=\s|$))"
        ),
        description="Shell home/root path token",
    ),
    SignalDef(
        id="delete_recursive",
        taint=None,
        languages=PY,
        regex=_compile(r"shutil\.rmtree\s*\(|os\.removedirs\s*\(|Path\([^)]*\)\.rmdir"),
        description="Python recursive delete",
    ),
    SignalDef(
        id="delete_recursive",
        languages=SHELL,
        regex=_compile(r"(?i)\brm\s+(?:-[a-zA-Z0-9]+\s+)*-[a-zA-Z]*r"),
        description="rm recursive",
    ),
    SignalDef(
        id="delete_recursive",
        languages=PS,
        regex=_compile(r"(?i)Remove-Item\b[^\n]{0,160}-Recurse"),
        description="PowerShell Remove-Item -Recurse",
    ),
    SignalDef(
        id="delete_recursive",
        languages=RB,
        regex=_compile(r"FileUtils\.rm_rf\s*\("),
        description="Ruby recursive delete",
    ),
    SignalDef(
        id="delete_recursive",
        languages=GO,
        regex=_compile(r"os\.RemoveAll\s*\("),
        description="Go RemoveAll",
    ),
    SignalDef(
        id="delete_recursive",
        languages=RS,
        regex=_compile(r"fs::remove_dir_all\s*\("),
        description="Rust remove_dir_all",
    ),
    # --- persistence ---------------------------------------------------------
    SignalDef(
        id="persistence",
        taint="persistence",
        languages=CODE | CONFIG,
        regex=_compile(
            r"(?i)(?:"
            r"~/?\.(?:bashrc|zshrc|profile|bash_profile|zprofile|login)|"
            r"/etc/cron|(?:crontab)\s+-|"
            r"/etc/systemd/|/Library/LaunchAgents|"
            r"~/Library/LaunchAgents|"
            r"CurrentVersion\\\\Run|"
            r"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run|"
            r"schtasks\s+/create|"
            r"New-ScheduledTask|"
            r"Startup\\(?:.+\.)?(?:lnk|bat|vbs|cmd)|"
            r"com\.apple\.loginwindow|"
            r"authorized_keys"
            r")"
        ),
        description="Persistence location reference",
    ),
    # --- privilege -----------------------------------------------------------
    SignalDef(
        id="privilege",
        taint="privilege",
        languages=SHELL | PS | BATCH | PY | frozenset({"dockerfile", "makefile"}),
        regex=_compile(
            r"(?i)(?:\bsudo\b|\bsu\s+|\brunas\b|\bpkexec\b|"
            r"Set-ExecutionPolicy\s+(?:Unrestricted|Bypass)|"
            r"Start-Process\s+[^\n]{0,80}-Verb\s+RunAs|"
            r"ctypes\.windll|"
            r"os\.setuid\s*\()"
        ),
        description="Privilege elevation mechanism",
    ),
    # --- chmod +x ------------------------------------------------------------
    SignalDef(
        id="chmod_exec",
        taint=None,
        languages=SHELL | PY,
        regex=_compile(r"(?i)chmod\s+(?:\+x|[0-7]*[1357]\b)|os\.chmod\s*\("),
        description="Mark a file executable",
    ),
    # --- user input (for exec escalation) ------------------------------------
    SignalDef(
        id="user_input",
        taint="user_input",
        languages=PY,
        regex=_compile(
            r"(?:\binput\s*\(|sys\.argv|argparse\.|request\.(?:args|form|json|data)|"
            r"flask\.request|django\.http)"
        ),
        description="Python user-controlled input",
    ),
    SignalDef(
        id="user_input",
        taint="user_input",
        languages=JS,
        regex=_compile(r"process\.argv|req\.(?:body|query|params)|window\.location"),
        description="JavaScript user-controlled input",
    ),
]


# ---------------------------------------------------------------------------
# Combination rules (sink + taint)
# ---------------------------------------------------------------------------

COMBO_RULES: List[ComboRule] = [
    ComboRule(
        name="api_key_exfiltration",
        severity="critical",
        sink="network",
        required_taints=("secret",),
        description=(
            "Suspicious credential exfiltration pattern detected: a secret-like "
            "environment variable is read and its value appears to be sent over "
            "the network."
        ),
    ),
    ComboRule(
        name="sensitive_file_exfiltration",
        severity="critical",
        sink="network",
        required_taints=("sensitive_file",),
        description=(
            "Suspicious credential exfiltration pattern detected: contents of a "
            "sensitive credential file appear to be transmitted over the network."
        ),
    ),
    ComboRule(
        name="download_and_execute",
        severity="high",
        sink="exec_dynamic",
        required_taints=("download",),
        description=(
            "Suspicious download-and-execute pattern detected: remote content "
            "appears to be retrieved and then executed."
        ),
    ),
    ComboRule(
        name="download_and_execute",
        severity="high",
        sink="chmod_exec",
        required_taints=("download",),
        description=(
            "Suspicious download-and-execute pattern detected: remote content "
            "appears to be retrieved and then marked executable."
        ),
    ),
    ComboRule(
        name="obfuscated_execution",
        severity="high",
        sink="exec_dynamic",
        required_taints=("obfuscated",),
        description=(
            "Suspicious obfuscated execution pattern detected: decoded or "
            "decompressed content appears to be passed to a dynamic execution "
            "mechanism."
        ),
    ),
    ComboRule(
        name="obfuscated_download_execution",
        severity="critical",
        sink="exec_dynamic",
        required_taints=("download", "obfuscated"),
        description=(
            "Suspicious obfuscated download-and-execute pattern detected: "
            "remote content appears to be decoded and then executed."
        ),
    ),
    ComboRule(
        name="secret_in_execution",
        severity="high",
        sink="exec_dynamic",
        required_taints=("secret",),
        description=(
            "Suspicious command-execution pattern detected: a secret-like "
            "environment value appears to be incorporated into a dynamic "
            "command."
        ),
    ),
    ComboRule(
        name="user_input_execution",
        severity="high",
        sink="exec_dynamic",
        required_taints=("user_input",),
        description=(
            "Suspicious command-execution pattern detected: user-controlled "
            "input appears to reach a dynamic execution mechanism."
        ),
    ),
    ComboRule(
        name="destructive_root_deletion",
        severity="critical",
        sink="delete_recursive",
        required_taints=("dangerous_path",),
        description=(
            "Suspicious destructive file operation detected: recursive deletion "
            "appears to target a home or root filesystem path."
        ),
    ),
    ComboRule(
        name="persistence_with_remote_payload",
        severity="critical",
        sink="persistence",
        required_taints=("download",),
        description=(
            "Suspicious persistence pattern detected: a startup/autostart "
            "location appears to be modified using remotely downloaded content."
        ),
    ),
    ComboRule(
        name="persistence_with_obfuscation",
        severity="critical",
        sink="persistence",
        required_taints=("obfuscated",),
        description=(
            "Suspicious persistence pattern detected: obfuscated content "
            "appears to be written to a startup/autostart location."
        ),
    ),
    ComboRule(
        name="privilege_destructive",
        severity="critical",
        sink="delete_recursive",
        required_taints=("privilege", "dangerous_path"),
        description=(
            "Suspicious elevated destructive operation detected: privilege "
            "escalation appears combined with recursive deletion of a "
            "sensitive path."
        ),
    ),
    ComboRule(
        name="privilege_download_execute",
        severity="critical",
        sink="exec_dynamic",
        required_taints=("privilege", "download"),
        description=(
            "Suspicious elevated download-and-execute pattern detected: "
            "privilege escalation appears combined with retrieving and "
            "running remote content."
        ),
    ),
]


# ---------------------------------------------------------------------------
# Direct (single-line) rules
# ---------------------------------------------------------------------------

DIRECT_RULES: List[DirectRule] = [
    DirectRule(
        name="destructive_root_deletion",
        severity="critical",
        languages=SHELL | CONFIG | frozenset({"dockerfile", "makefile"}),
        regex=_RM_RF_RE,
        classify=classify_rm_line,
        description=(
            "Suspicious destructive file operation detected: recursive deletion "
            "of a filesystem root or home directory."
        ),
    ),
    DirectRule(
        name="destructive_root_deletion",
        severity="critical",
        languages=PY | PS | RB | GO | RS | BATCH,
        regex=_RMTREE_RE,
        classify=classify_rmtree_line,
        description=(
            "Suspicious destructive file operation detected: recursive deletion "
            "of a filesystem root or home directory."
        ),
    ),
    DirectRule(
        name="pipe_to_shell",
        severity="high",
        languages=SHELL | CONFIG | PS | frozenset({"dockerfile", "makefile"}),
        regex=_compile(
            r"(?i)(?:curl|wget)\b[^\n]{0,300}\|\s*(?:sudo\s+)?(?:ba)?sh\b"
        ),
        description=(
            "Suspicious download-and-execute pattern detected: remote content "
            "is piped directly into a shell interpreter."
        ),
    ),
    DirectRule(
        name="encoded_powershell",
        severity="high",
        languages=PS | SHELL | BATCH | CONFIG,
        regex=_compile(
            r"(?i)powershell(?:\.exe)?[^\n]{0,160}"
            r"-(?:e|en|enc|encodedcommand)\b"
        ),
        description=(
            "Suspicious obfuscated PowerShell execution detected: an encoded "
            "command flag is used, which commonly hides the payload from review."
        ),
    ),
    DirectRule(
        name="powershell_download_iex",
        severity="critical",
        languages=PS | CONFIG,
        regex=_compile(
            r"(?i)(?:IEX|Invoke-Expression)\s*\(\s*(?:New-Object\s+"
            r"(?:Net|System\.Net)\.WebClient\)|"
            r"IEX\s*\(\s*\((?:New-Object|Invoke-WebRequest)|"
            r"DownloadString\s*\()"
        ),
        description=(
            "Suspicious download-and-execute pattern detected: PowerShell "
            "downloads a remote string and immediately invokes it."
        ),
    ),
    DirectRule(
        name="sensitive_file_access",
        severity="medium",
        languages=CODE | CONFIG,
        regex=_compile(r"(?i)(?:" + _SENSITIVE_PATH + r")"),
        description=(
            "Suspicious sensitive-file access pattern detected: the code "
            "references a location that commonly stores credentials or keys. "
            "Access alone is not proof of exfiltration."
        ),
    ),
    DirectRule(
        name="persistence_modification",
        severity="high",
        languages=SHELL | PS | BATCH | PY | JS,
        regex=_compile(
            r"(?i)(?:"
            r"(?:>>|tee\s+-a)\s+[^\n]{0,80}(?:\.bashrc|\.zshrc|\.profile|"
            r"\.bash_profile|/etc/cron|/etc/systemd/|"
            r"LaunchAgents|CurrentVersion\\\\Run)|"
            r"crontab\s+|"
            r"schtasks\s+/create|"
            r"New-ItemProperty[^\n]{0,120}CurrentVersion\\\\Run|"
            r"launchctl\s+load|"
            r"systemctl\s+(?:enable|link)\b"
            r")"
        ),
        description=(
            "Suspicious persistence pattern detected: the code appears to "
            "modify a login, cron, systemd, launch-agent, or autostart location."
        ),
    ),
    DirectRule(
        name="standalone_file_download",
        severity="medium",
        languages=SHELL | PS | PY | frozenset({"dockerfile", "makefile"}),
        regex=_compile(
            r"(?i)(?:urllib\.request\.urlretrieve\s*\(|"
            r"DownloadFile\s*\(|"
            r"Invoke-WebRequest[^\n]{0,160}-OutFile|"
            r"\b(?:curl|wget)\b[^\n]{0,160}(?:\s-O\b|\s-o\s|\s--output\s))"
        ),
        description=(
            "Suspicious remote-download pattern detected: content is retrieved "
            "from the network and written to a local file. A download alone is "
            "not proof of malicious execution."
        ),
    ),
]


FILE_RULES: List[FileRule] = [
    FileRule(
        name="npm_lifecycle_execution",
        languages=frozenset({"package_json"}),
        filenames=frozenset({"package.json"}),
        analyzer=analyze_package_json,
    ),
    FileRule(
        name="npm_lifecycle_execution",
        languages=frozenset({"python_deps"}),
        filenames=frozenset({"pyproject.toml"}),
        analyzer=analyze_pyproject_toml,
    ),
]


def signals_for_language(language: str) -> List[SignalDef]:
    return [item for item in SIGNAL_DEFS if language in item.languages]


def direct_rules_for_language(language: str) -> List[DirectRule]:
    return [item for item in DIRECT_RULES if language in item.languages]


def combo_rules_for_language(language: str) -> List[ComboRule]:
    selected: List[ComboRule] = []
    for rule in COMBO_RULES:
        if rule.languages is None or language in rule.languages:
            selected.append(rule)
    return selected


def file_rules_for(language: str, filename: str) -> List[FileRule]:
    lower = filename.lower()
    return [
        rule
        for rule in FILE_RULES
        if language in rule.languages or lower in rule.filenames
    ]
