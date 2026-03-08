import re
from pathlib import Path
from dataclasses import dataclass
from typing import Iterable


@dataclass
class Finding:
    severity: str
    category: str
    message: str
    file: str
    line: int


WEB_PATTERNS = [
    ("high", "SQLi", re.compile(r"select.+\+|select.+%s|f\"select|execute\(.+\+", re.IGNORECASE)),
    ("medium", "XSS", re.compile(r"innerHTML\s*=|render_template_string\(")),
    ("medium", "CSRF", re.compile(r"@app\.route\(.+methods=.*POST")),
    ("medium", "IDOR", re.compile(r"/user/<int:id>|request\.args\.get\(['\"]id")),
    ("high", "PathTraversal", re.compile(r"open\(\s*request\.(args|form|values)\.get\(")),
]
C_PATTERNS = [
    ("high", "BufferOverflow", re.compile(r"\b(gets|strcpy|sprintf)\s*\(")),
]
SECRET_PATTERNS = [
    ("high", "HardcodedSecret", re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*=\s*['\"][^'\"]{8,}['\"]")),
]
CODE_PATTERNS = [
    ("high", "CodeInjection", re.compile(r"\beval\s*\(|\bexec\s*\(")),
]


LOOP_RE = re.compile(r"\b(for|while)\b")


def _collect_files(target: Path) -> list[Path]:
    if target.is_file():
        return [target]
    return sorted(
        [f for f in target.rglob("*") if f.suffix in {".py", ".c", ".js", ".ts"} and f.is_file()],
        key=lambda p: str(p),
    )


def _max_loop_nesting(lines: Iterable[str]) -> int:
    max_depth = 0
    stack: list[int] = []
    for line in lines:
        stripped = line.rstrip("\n")
        if not stripped.strip() or stripped.lstrip().startswith("#"):
            continue
        indent = len(stripped) - len(stripped.lstrip(" "))
        while stack and indent <= stack[-1]:
            stack.pop()
        if LOOP_RE.search(stripped):
            stack.append(indent)
            max_depth = max(max_depth, len(stack))
    return max_depth


def scan_file(path: Path):
    if path.stat().st_size > 1_000_000:
        return [Finding("low", "Performance", "Skipped very large file (>1MB)", str(path), 1)]
    text = path.read_text(encoding="utf-8", errors="ignore")
    findings = []
    lines = text.splitlines()
    patterns = WEB_PATTERNS + C_PATTERNS + SECRET_PATTERNS + CODE_PATTERNS
    for idx, line in enumerate(lines, start=1):
        check_line = line.split("#", 1)[0]
        for sev, cat, pat in patterns:
            if pat.search(check_line):
                findings.append(Finding(sev, cat, f"Potential {cat} pattern", str(path), idx))

    if _max_loop_nesting(lines) >= 3:
        findings.append(Finding("low", "Performance", "Deeply nested loops detected, review complexity", str(path), 1))
    return findings


def scan_path(target: str):
    p = Path(target)
    out = []
    for f in _collect_files(p):
        out.extend(scan_file(f))
    severity_rank = {"high": 0, "medium": 1, "low": 2}
    return sorted(out, key=lambda x: (severity_rank.get(x.severity, 99), x.file, x.line, x.category))


def to_markdown(findings):
    if not findings:
        return "## Review Report\n\n- No obvious issues found."
    rows = ["## Review Report", "", "|Severity|Category|File|Line|Message|", "|---|---|---|---:|---|"]
    for f in findings:
        rows.append(f"|{f.severity}|{f.category}|{f.file}|{f.line}|{f.message}|")
    rows.append("\n## Suggested Diff\n\n```diff\n- execute(\"SELECT * FROM users WHERE id=\" + user_id)\n+ execute(\"SELECT * FROM users WHERE id=%s\", (user_id,))\n```")
    return "\n".join(rows)
