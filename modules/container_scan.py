import re
from pathlib import Path
from typing import Any, Dict, List

def parse_dockerfile(path: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {"path": path, "base": None, "layers": [], "issues": [], "user": None}
    p = Path(path)
    if not p.exists():
        out["error"] = "File not found"
        return out
    content = p.read_text(encoding="utf-8", errors="ignore")
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.upper().startswith("FROM "):
            out["base"] = line[4:].strip().split()[0]
        if line.upper().startswith("RUN "):
            cmd = line[3:].strip()
            out["layers"].append({"type": "RUN", "cmd": cmd[:200]})
            if "curl" in cmd.lower() and "|" in cmd or "wget" in cmd.lower() and "|" in cmd:
                out["issues"].append({"type": "Pipe to shell", "snippet": cmd[:150]})
        if line.upper().startswith("COPY ") or line.upper().startswith("ADD "):
            parts = line.split(maxsplit=2)
            if len(parts) >= 3:
                out["layers"].append({"type": parts[0], "args": parts[1:][:100]})
        if line.upper().startswith("USER "):
            out["user"] = line[4:].strip()
        if "password" in line.lower() or "secret" in line.lower() or "api_key" in line.lower():
            if not line.strip().startswith("#"):
                out["issues"].append({"type": "Possible secret in layer", "snippet": line[:100]})
    if not out["user"] and out["base"]:
        out["issues"].append({"type": "Info", "snippet": "Consider non-root USER"})
    return out

def container_scan(dockerfile_path: str) -> Dict[str, Any]:
    return parse_dockerfile(dockerfile_path)
