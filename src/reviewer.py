import re
from pathlib import Path
from dataclasses import dataclass

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
]
C_PATTERNS = [
    ("high", "BufferOverflow", re.compile(r"\b(gets|strcpy|sprintf)\s*\(")),
]


def scan_file(path: Path):
    text = path.read_text(encoding="utf-8", errors="ignore")
    findings = []
    lines = text.splitlines()
    patterns = WEB_PATTERNS + C_PATTERNS
    for idx, line in enumerate(lines, start=1):
        for sev, cat, pat in patterns:
            if pat.search(line):
                findings.append(Finding(sev, cat, f"Potential {cat} pattern", str(path), idx))

    # naive perf check: nested loops
    nested = sum(1 for l in lines if re.search(r"\bfor\b|\bwhile\b", l))
    if nested >= 3:
        findings.append(Finding("low", "Performance", "Multiple loops detected, review complexity", str(path), 1))
    return findings


def scan_path(target: str):
    p = Path(target)
    files = [p] if p.is_file() else [f for f in p.rglob("*") if f.suffix in {".py", ".c", ".js", ".ts"}]
    out = []
    for f in files:
        out.extend(scan_file(f))
    return out


def to_markdown(findings):
    if not findings:
        return "## Review Report\n\n- No obvious issues found."
    rows = ["## Review Report", "", "|Severity|Category|File|Line|Message|", "|---|---|---|---:|---|"]
    for f in findings:
        rows.append(f"|{f.severity}|{f.category}|{f.file}|{f.line}|{f.message}|")
    rows.append("\n## Suggested Diff\n\n```diff\n- execute(\"SELECT * FROM users WHERE id=\" + user_id)\n+ execute(\"SELECT * FROM users WHERE id=%s\", (user_id,))\n```")
    return "\n".join(rows)
