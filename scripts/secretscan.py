#!/usr/bin/env python3
"""Secret Scan: find keys, tokens and passwords that were ever committed to a
repository, including ones deleted later, and say which are still in the
working tree. Local only: no network code, and it never runs git.

  git log -p --all > history.patch                (you run this, outside the repo)
  python secretscan.py history.patch --tree .     history and working tree
  python secretscan.py history.patch              history only
  python secretscan.py --tree .                   working tree only

A value is never printed in full: only its first 4 characters and its length.
Add `secretscan:ignore` to a line to skip a known false positive.
"""
import hashlib
import json
import math
import re
import sys
from pathlib import Path

PATTERNS = [(name, re.compile(rx)) for name, rx in (
    ("AWS access key id", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("GitHub token", r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b"),
    ("Stripe live key", r"\b[sr]k_live_[0-9a-zA-Z]{20,}\b"),
    ("Slack token", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    ("Google API key", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ("AI provider key", r"\b(?:sk-(?:ant-|proj-)?[A-Za-z0-9_\-]{20,}|gsk_[A-Za-z0-9]{20,})\b"),
    ("Private key block", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    ("JSON web token", r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
)]
URL_PASSWORD = re.compile(r"\b[a-z][a-z0-9+.\-]*://[^\s:@/]+:([^\s@/]{6,})@[^\s/]+")
ASSIGNED = re.compile(r"(?i)(?<![a-z0-9])(?:[a-z0-9]+[_-])*(pass(?:word|wd)?|secret|api[_-]?key|access[_-]?key|token|auth)"
                      r"(?:[_-][a-z0-9]+)*[\"']?\s*[:=]\s*[\"']([^\"'\s]{12,})[\"']")
PLACEHOLDER = re.compile(r"(?i)example|sample|dummy|changeme|your[_-]|xxxx|<[^>]+>|\$\{|\{\{|process\.env|placeholder|\*{4}")
SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "dist", "build", "__pycache__", ".next", "vendor"}
MAX_FILE = 1_000_000


def fail(msg):
    print(json.dumps({"error": msg}), file=sys.stderr)
    sys.exit(1)


def entropy(s):
    return -sum(s.count(c) / len(s) * math.log2(s.count(c) / len(s)) for c in set(s)) if s else 0.0


def hits(line):
    """(type, value) pairs found in one line of text."""
    if "secretscan:ignore" in line:
        return []
    out = [(name, m.group(0)) for name, rx in PATTERNS for m in rx.finditer(line)]
    out += [("Password in a URL", m.group(1)) for m in URL_PASSWORD.finditer(line) if not PLACEHOLDER.search(m.group(1))]
    for m in ASSIGNED.finditer(line):
        value = m.group(2)
        if not PLACEHOLDER.search(value) and entropy(value) >= 3.2 and not any(value in v for _, v in out):
            out.append((f"Hard-coded {m.group(1).lower()}", value))
    return out


def key(kind, value):
    return kind, hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:16]


def scan_history(path, found):
    commit = name = ""
    commits = lines = 0
    with Path(path).open(encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            if raw.startswith("commit ") and len(raw) > 14:
                commit, commits = raw[7:19], commits + 1
            elif raw.startswith("+++ "):
                name = raw[6:].strip() if raw.startswith("+++ b/") else ""
            elif raw.startswith("+") and not raw.startswith("+++"):
                lines += 1
                for kind, value in hits(raw[1:]):
                    f = found.setdefault(key(kind, value), {"type": kind, "value": value, "file": name,
                                                            "commit": commit, "times_seen": 0, "in_working_tree": False})
                    f["times_seen"] += 1
                    f["commit"], f["file"] = commit, name or f["file"]  # ends on the oldest commit
    return {"commits": commits, "added_lines": lines}


def scan_tree(root, found):
    root, files = Path(root), 0
    if not root.is_dir():
        fail(f"not a folder: {root}")
    for p in sorted(root.rglob("*")):
        if not p.is_file() or SKIP_DIRS & set(p.relative_to(root).parts) or p.stat().st_size > MAX_FILE:
            continue
        data = p.read_bytes()
        if b"\x00" in data[:2048]:
            continue
        files += 1
        for n, line in enumerate(data.decode("utf-8", "replace").splitlines(), 1):
            for kind, value in hits(line):
                f = found.setdefault(key(kind, value), {"type": kind, "value": value, "commit": "", "times_seen": 0})
                f.update(in_working_tree=True, file=p.relative_to(root).as_posix(), line=n)
                f["times_seen"] += 1
    return {"files": files}


def main(argv):
    args = [a for a in argv if a != "--tree"]
    tree = argv[argv.index("--tree") + 1] if "--tree" in argv and argv.index("--tree") + 1 < len(argv) else None
    history = next((a for a in args if a != tree), None)
    if not history and not tree:
        fail("usage: secretscan.py [history.patch] [--tree <folder>]")
    if history and not Path(history).is_file():
        fail(f"no such file: {history}  (create it with: git log -p --all > history.patch)")
    found, scanned = {}, {}
    if history:
        scanned.update(scan_history(history, found))
    if tree:
        scanned.update(scan_tree(tree, found))
    findings = sorted(found.values(), key=lambda f: (not f.get("in_working_tree"), f["type"], f.get("file", "")))
    by_type = {}
    for f in findings:
        by_type[f["type"]] = by_type.get(f["type"], 0) + 1
        v = f.pop("value")
        f["value"] = f"{v[:4]}... ({len(v)} chars)"
        if not tree:
            f["in_working_tree"] = None  # not checked
    out = {"clean": not findings, "scanned": scanned, "found": len(findings), "by_type": by_type,
           "findings": findings[:200], "not_shown": max(0, len(findings) - 200)}
    if findings:
        out["next"] = ["Rotate or revoke every key listed, starting now. A key that was ever pushed is leaked, "
                       "whether or not it was deleted later.",
                       "Remove values still in the working tree and load them from the environment or a secret store.",
                       "Rewriting history is optional and destructive: only with the owner's yes, and never "
                       "instead of rotating."]
    else:
        out["note"] = "No known key format was found. This is a pattern scan: it cannot prove nothing was leaked."
    print(json.dumps(out, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
