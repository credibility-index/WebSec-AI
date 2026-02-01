import re
from pathlib import Path
from typing import Any, Dict, List, Optional

PATTERNS = [
    (r"eval\s*\([^)]+\)", "Dangerous eval()", "high"),
    (r"exec\s*\([^)]+\)", "Dangerous exec()", "high"),
    (r"__import__\s*\([^)]+\)", "Dynamic __import__", "medium"),
    (r"subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True", "Shell=True in subprocess", "high"),
    (r"os\.system\s*\([^)]+\)", "os.system()", "high"),
    (r"pickle\.loads?\s*\([^)]+\)", "Unsafe pickle.loads", "high"),
    (r"yaml\.load\s*\([^)]*\)", "yaml.load() without Loader", "medium"),
    (r"raw_input\s*\([^)]*\)", "raw_input (Py2)", "low"),
    (r"input\s*\([^)]*\)", "input() - validate in prod", "low"),
    (r"SELECT\s+.*\s+FROM\s+.*\s+WHERE\s+.*%s|%\(|format\s*\(|f[\"'].*\{.*\}[\"']", "Possible SQL concatenation", "high"),
    (r"requests\.(get|post)\s*\([^)]*params\s*=\s*\w+\)", "Params from variable - SSRF?", "medium"),
    (r"open\s*\([^)]*\+[^)]+\)", "Path concatenation - path traversal?", "medium"),
    (r"md5\s*\(|hashlib\.md5\s*\(|sha1\s*\(", "Weak hash (MD5/SHA1)", "medium"),
]

def scan_content(content: str, path: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for i, line in enumerate(content.splitlines(), 1):
        for pattern, msg, severity in PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append({"file": path, "line": i, "message": msg, "severity": severity, "snippet": line.strip()[:120]})
    return findings

def sast_scan(root: str, extensions: Optional[List[str]] = None, exclude_dirs: Optional[List[str]] = None) -> Dict[str, Any]:
    extensions = extensions or [".py", ".js", ".ts", ".jsx", ".tsx"]
    exclude_dirs = exclude_dirs or ["node_modules", ".git", "__pycache__", "venv"]
    root_path = Path(root)
    all_findings: List[Dict[str, Any]] = []
    for f in root_path.rglob("*"):
        if not f.is_file() or f.suffix.lower() not in extensions:
            continue
        if any(d in f.parts for d in exclude_dirs):
            continue
        try:
            content = f.read_text(encoding="utf-8", errors="ignore")
            all_findings.extend(scan_content(content, str(f.relative_to(root_path))))
        except Exception:
            pass
    by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for x in all_findings:
        by_sev[x.get("severity", "low")] = by_sev.get(x.get("severity", "low"), 0) + 1
    return {"path": root, "findings": all_findings, "count": len(all_findings), "by_severity": by_sev}
