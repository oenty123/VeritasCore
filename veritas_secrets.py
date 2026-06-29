#!/usr/bin/env python3
"""veritas_secrets.py — high-precision secret / credential detection.

Secret scanners are notorious for crying wolf (test keys, placeholders, example
values). True to Principle Zero, this module prefers PRECISION: it matches
well-known, distinctive credential formats (which rarely false-positive) and
treats generic high-entropy strings as a separate, lower-confidence signal that
is clearly labelled — never dressed up as a confirmed secret.

Findings are reported as file:line:type with a MASKED preview; the full secret is
never echoed back (echoing secrets is itself a leak).
"""
from __future__ import annotations

import math
import re
import sys
from collections import Counter

# (name, compiled regex, confidence). These formats are distinctive enough that
# a match is almost certainly a real credential, not a coincidence.
_PATTERNS = [
    ("AWS Access Key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "high"),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b"), "high"),
    ("GitHub fine-grained PAT", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82}\b"), "high"),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "high"),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b"), "high"),
    ("Stripe secret key", re.compile(r"\b[sr]k_live_[0-9A-Za-z]{24,}\b"), "high"),
    ("Twilio API key", re.compile(r"\bSK[0-9a-fA-F]{32}\b"), "high"),
    ("npm token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), "high"),
    ("Private key block", re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"), "high"),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\."
                       r"[A-Za-z0-9_\-]{10,}\b"), "medium"),
    ("Slack webhook", re.compile(
        r"https://hooks\.slack\.com/services/T[0-9A-Za-z]+/B[0-9A-Za-z]+/"
        r"[0-9A-Za-z]+"), "high"),
]

# generic "<keyword> = '<value>'" assignments
_ASSIGN = re.compile(
    r"""(?ix)\b(password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key|
        auth[_-]?token|token|client[_-]?secret|private[_-]?key)\b\s*[:=]\s*
        ['"]([^'"]{6,})['"]""", re.VERBOSE)

# values that are obviously NOT real secrets — avoid the classic false positives
_PLACEHOLDER = re.compile(
    r"(?i)^(?:x{3,}|\.{3,}|none|null|true|false|changeme|example|test|dummy|"
    r"your[_-]?\w+|placeholder|todo|fixme|<[^>]+>|\$\{[^}]+\}|%\([^)]+\)s|"
    r"\{\{[^}]+\}\}|sample|redacted|fake|secret|password|xxx+)$")


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


# Documented example/dummy credentials that are never real (AWS docs, etc.).
_KNOWN_DUMMY = {
    "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "AKIAI44QH8DHBEXAMPLE",
}

# file paths that hold fixtures by design — findings here are demoted, not trusted
_TEST_PATH = re.compile(
    r"(?i)(^|[/\\])(tests?|fixtures?|examples?|samples?|mocks?|spec|__tests__)"
    r"([/\\]|$)|(^|[/\\])(test_|conftest)|(_test|\.test|\.spec)\.")


def _is_test_path(filename: str) -> bool:
    return bool(filename) and bool(_TEST_PATH.search(filename))


def _is_synthetic(value: str) -> bool:
    """A matched secret that is obviously fabricated: a long run of one repeated
    character, or implausibly low entropy for its length (e.g. 'aaaa…aaaa')."""
    if len(value) >= 12:
        if re.search(r"(.)\1{7,}", value):           # 8+ of the same char in a row
            return True
        if _entropy(value) < 2.0:                     # almost no variety
            return True
    return False


def _looks_placeholder(value: str) -> bool:
    return bool(_PLACEHOLDER.match(value.strip()))


def _mask(s: str) -> str:
    s = s.strip()
    if len(s) <= 8:
        return s[0] + "***" if s else "***"
    return f"{s[:4]}…{s[-2:]} ({len(s)} chars)"


def scan_text(text: str, filename: str = "<text>") -> list:
    findings = []
    in_test = _is_test_path(filename)

    def add(line, typ, conf, raw):
        if raw in _KNOWN_DUMMY or _is_synthetic(raw):
            return                                   # documented/synthetic: never real
        ctx = ""
        if in_test:
            conf = "low"                             # fixture by design -> demote
            ctx = " (test fixture)"
        findings.append({"file": filename, "line": line, "type": typ + ctx,
                         "confidence": conf, "preview": _mask(raw)})

    for i, line in enumerate(text.splitlines(), 1):
        if len(line) > 4096:                         # skip minified/generated
            continue                                 # lines: bounds regex work
        for name, rx, conf in _PATTERNS:             # distinctive formats first
            m = rx.search(line)
            if m:
                add(i, name, conf, m.group(0))
        for m in _ASSIGN.finditer(line):             # keyword = "value"
            value = m.group(2)
            if _looks_placeholder(value):
                continue
            ent = _entropy(value)
            conf = "high" if ent >= 3.5 and len(value) >= 12 else "medium"
            add(i, f"hardcoded {m.group(1).lower()}", conf, value)
    return findings


def scan_file(path: str) -> list:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return scan_text(fh.read(), path)
    except OSError:
        return []


_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist",
              "build", ".veritascore"}
_SCAN_EXT = {".py", ".js", ".ts", ".env", ".yml", ".yaml", ".json", ".txt",
             ".cfg", ".ini", ".toml", ".sh", ".rb", ".go", ".java", ".pem",
             ".conf", ".properties", ""}


def scan_dir(root: str, max_bytes: int = 1_000_000) -> list:
    import os
    out = []
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for fn in files:
            ext = os.path.splitext(fn)[1].lower()
            if ext not in _SCAN_EXT:
                continue
            p = os.path.join(dirpath, fn)
            try:
                if os.path.getsize(p) > max_bytes:
                    continue
            except OSError:
                continue
            for f in scan_file(p):
                f["file"] = os.path.relpath(p, root)
                out.append(f)
    out.sort(key=lambda f: (f["confidence"] != "high", f["file"], f["line"]))
    return out


def cli() -> int:
    """Console-script entry point (`veritas-secrets`)."""
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    found = scan_dir(root)
    for f in found:
        print(f"  [{f['confidence']:6}] {f['file']}:{f['line']}  {f['type']}  "
              f"{f['preview']}")
    print(f"\n{len(found)} potential secret(s). Verify before acting; previews "
          f"are masked.")
    return 1 if any(f["confidence"] == "high" for f in found) else 0


if __name__ == "__main__":
    sys.exit(cli())
