import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

def _run(cmd: List[str], cwd: Optional[str] = None, timeout: int = 60) -> Optional[str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd)
        return r.stdout or r.stderr or None
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
        return None

def pip_audit(path: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {"tool": "pip", "vulnerabilities": [], "error": None}
    req_file = Path(path) / "requirements.txt"
    if not req_file.exists():
        out["error"] = "requirements.txt not found"
        return out
    stdout = _run(["pip-audit", "-r", str(req_file), "--format", "json"], cwd=path)
    if stdout:
        try:
            data = json.loads(stdout)
            out["vulnerabilities"] = data.get("vulnerabilities", [])
        except json.JSONDecodeError:
            out["vulnerabilities"] = []
    else:
        stdout = _run(["pip", "list", "--format", "json"], cwd=path)
        if stdout:
            out["note"] = "pip-audit not installed; run: pip install pip-audit"
    return out

def npm_audit(path: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {"tool": "npm", "vulnerabilities": [], "error": None}
    pkg = Path(path) / "package.json"
    if not pkg.exists():
        out["error"] = "package.json not found"
        return out
    stdout = _run(["npm", "audit", "--json"], cwd=path)
    if stdout:
        try:
            data = json.loads(stdout)
            vulns = data.get("vulnerabilities") or {}
            for name, v in vulns.items():
                if isinstance(v, dict) and v.get("severity"):
                    out["vulnerabilities"].append({"package": name, "severity": v.get("severity"), "via": v.get("via")})
        except json.JSONDecodeError:
            pass
    return out

def osv_query(ecosystem: str, package: str, version: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {"ecosystem": ecosystem, "package": package, "version": version, "vulns": []}
    try:
        import requests
        r = requests.post(
            "https://api.osv.dev/v1/query",
            json={"package": {"name": package, "ecosystem": ecosystem}, "version": version},
            timeout=10,
        )
        if r.status_code == 200:
            data = r.json()
            out["vulns"] = data.get("vulns", [])[:20]
    except Exception as e:
        out["error"] = str(e)
    return out

def dependency_scan(path: str) -> Dict[str, Any]:
    path = str(Path(path).resolve())
    out: Dict[str, Any] = {"path": path, "pip": {}, "npm": {}, "summary": {"critical": 0, "high": 0}}
    out["pip"] = pip_audit(path)
    out["npm"] = npm_audit(path)
    for v in out["pip"].get("vulnerabilities", []) + out["npm"].get("vulnerabilities", []):
        sev = (v.get("severity") or v.get("id") or "").lower()
        if "critical" in sev:
            out["summary"]["critical"] += 1
        elif "high" in sev:
            out["summary"]["high"] += 1
    return out
