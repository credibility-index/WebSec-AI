import re
from pathlib import Path
from typing import Any, Dict, List

def scan_yaml(content: str, path: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    if "password" in content.lower() and ":" in content and not content.strip().startswith("#"):
        for i, line in enumerate(content.splitlines(), 1):
            if re.search(r"password\s*:\s*['\"]?[^'\"]+['\"]?", line, re.I) and "xxx" not in line.lower():
                findings.append({"file": path, "line": i, "type": "Hardcoded password", "snippet": line.strip()[:80]})
    if "private_key" in content.lower() or "secret_key" in content.lower():
        for i, line in enumerate(content.splitlines(), 1):
            if re.search(r"(private_key|secret_key)\s*:\s*['\"]?[^'\"]+['\"]?", line, re.I):
                findings.append({"file": path, "line": i, "type": "Possible secret key", "snippet": line.strip()[:80]})
    return findings

def scan_tf(content: str, path: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    if "aws_s3_bucket" in content and "public_access_block" not in content.lower():
        findings.append({"file": path, "line": 0, "type": "S3 bucket - check public_access_block", "snippet": ""})
    if re.search(r"cidr_block\s*=\s*[\"']0\.0\.0\.0/0[\"']", content):
        findings.append({"file": path, "line": 0, "type": "Open CIDR 0.0.0.0/0", "snippet": ""})
    if "password" in content or "secret" in content:
        for i, line in enumerate(content.splitlines(), 1):
            if "password" in line.lower() or "secret" in line.lower():
                if "variable" not in line and "=" in line:
                    findings.append({"file": path, "line": i, "type": "Possible hardcoded secret", "snippet": line.strip()[:80]})
    return findings

def iac_scan(root: str) -> Dict[str, Any]:
    root_path = Path(root)
    all_findings: List[Dict[str, Any]] = []
    for f in root_path.rglob("*"):
        if not f.is_file():
            continue
        if ".git" in f.parts or "node_modules" in f.parts:
            continue
        try:
            content = f.read_text(encoding="utf-8", errors="ignore")
            rel = str(f.relative_to(root_path))
            if f.suffix in (".yaml", ".yml"):
                all_findings.extend(scan_yaml(content, rel))
            if f.suffix == ".tf":
                all_findings.extend(scan_tf(content, rel))
        except Exception:
            pass
    return {"path": root, "findings": all_findings, "count": len(all_findings)}
