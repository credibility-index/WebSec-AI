import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

SECRET_PATTERNS = [
    (r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"]?([a-zA-Z0-9_\-]{20,})['\"]?", "API Key"),
    (r"(?i)(secret|password|passwd|pwd)\s*[=:]\s*['\"]?([^\s'\"]{8,})['\"]?", "Secret/Password"),
    (r"(?i)(aws_access_key_id|aws_secret_access_key)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{20,})['\"]?", "AWS Key"),
    (r"(?i)(bearer|token)\s+([a-zA-Z0-9_\-\.]{20,})", "Bearer/Token"),
    (r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----", "Private Key"),
    (r"(?i)ghp_[a-zA-Z0-9]{36}", "GitHub Token"),
    (r"(?i)gho_[a-zA-Z0-9]{36}", "GitHub OAuth"),
    (r"[0-9a-fA-F]{32}", "MD5-like (context)"),
]

def scan_file(path: str, content: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for pattern, name in SECRET_PATTERNS:
        for m in re.finditer(pattern, content):
            val = m.group(0) if m.lastindex is None else (m.group(2) if m.lastindex >= 2 else m.group(0))
            if name == "MD5-like (context)" and ("key" in content.lower() or "secret" in content.lower() or "pass" in content.lower()):
                findings.append({"file": path, "type": name, "match": val[:50] + "..." if len(val) > 50 else val})
            elif name != "MD5-like (context)":
                findings.append({"file": path, "type": name, "match": val[:80] + "..." if len(str(val)) > 80 else str(val)})
    return findings

def scan_path(root: str, extensions: Optional[List[str]] = None, exclude_dirs: Optional[List[str]] = None) -> Dict[str, Any]:
    extensions = extensions or [".py", ".js", ".ts", ".env", ".yaml", ".yml", ".json", ".sh", ".go", ".java"]
    exclude_dirs = exclude_dirs or ["node_modules", ".git", "__pycache__", "venv", ".venv"]
    root_path = Path(root)
    all_findings: List[Dict[str, Any]] = []
    files_scanned = 0
    for f in root_path.rglob("*"):
        if not f.is_file():
            continue
        if any(d in f.parts for d in exclude_dirs):
            continue
        if f.suffix.lower() not in extensions and f.name not in [".env", ".env.local"]:
            continue
        try:
            content = f.read_text(encoding="utf-8", errors="ignore")
            files_scanned += 1
            findings = scan_file(str(f.relative_to(root_path)), content)
            all_findings.extend(findings)
        except Exception:
            pass
    return {"path": root, "files_scanned": files_scanned, "findings": all_findings, "count": len(all_findings)}
