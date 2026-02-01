"""Automation: fuzzing (dir/param), rate-limit detection, chain hints."""
import os
import time
from typing import Any, Dict, List, Optional

import requests

COMMON_DIRS = [
    "/admin", "/login", "/flag", "/flags", "/secret", "/backup", "/api",
    "/.git", "/.env", "/config", "/debug", "/static", "/uploads",
    "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
]

COMMON_PARAMS = ["id", "file", "page", "q", "query", "search", "cmd", "exec", "debug", "flag", "key"]


def dir_fuzz(base_url: str, paths: Optional[List[str]] = None, timeout: int = 5) -> List[Dict[str, Any]]:
    """Simple directory fuzzing: GET each path, return status and length."""
    paths = paths or COMMON_DIRS
    results: List[Dict[str, Any]] = []
    session = requests.Session()
    session.headers["User-Agent"] = "WebSecAI-Fuzz/1.0"
    base = base_url.rstrip("/")
    for path in paths:
        try:
            url = base + path if path.startswith("/") else base + "/" + path
            r = session.get(url, timeout=timeout, allow_redirects=False)
            results.append({
                "path": path,
                "url": url,
                "status": r.status_code,
                "length": len(r.content),
            })
        except Exception:
            pass
    return results


def param_fuzz(url: str, params: Optional[List[str]] = None, timeout: int = 5) -> List[Dict[str, Any]]:
    """Add common params one-by-one; detect change in response (hidden params)."""
    params = params or COMMON_PARAMS
    results: List[Dict[str, Any]] = []
    session = requests.Session()
    try:
        r0 = session.get(url, timeout=timeout)
        base_len = len(r0.content)
        base_status = r0.status_code
        for p in params:
            try:
                r = session.get(url, params={p: "1"}, timeout=timeout)
                if r.status_code != base_status or abs(len(r.content) - base_len) > 50:
                    results.append({"param": p, "status": r.status_code, "length": len(r.content), "hint": "response_differs"})
            except Exception:
                pass
    except Exception:
        pass
    return results


def rate_limit_detect(url: str, requests_count: int = 15, delay: float = 0.1) -> Dict[str, Any]:
    """Send burst of requests; detect 429 or increasing latency."""
    out: Dict[str, Any] = {"rate_limited": False, "status_codes": [], "latencies": []}
    session = requests.Session()
    for _ in range(requests_count):
        try:
            t0 = time.time()
            r = session.get(url, timeout=5)
            out["latencies"].append(round(time.time() - t0, 3))
            out["status_codes"].append(r.status_code)
            if r.status_code == 429:
                out["rate_limited"] = True
        except Exception:
            pass
        time.sleep(delay)
    return out


def chain_exploitation_hint(vulns: List[str]) -> str:
    """Suggest next step for chaining vulnerabilities (e.g. SSRF -> RCE)."""
    vulns_lower = [v.lower() for v in vulns]
    if "ssrf" in vulns_lower:
        return "SSRF found: try cloud metadata (169.254.169.254) or internal services; chain with LFI/RCE if you get response."
    if "lfi" in vulns_lower:
        return "LFI found: try /etc/passwd, php://filter, log poisoning; chain with RCE if you can write logs."
    if "sqli" in vulns_lower or "sql injection" in " ".join(vulns_lower):
        return "SQLi found: extract DB credentials; use for SSH/panel or further DB dumps (flags table)."
    if "xss" in vulns_lower:
        return "XSS found: try cookie stealing or keylogging; chain with CSRF if same origin."
    return "Chain: use recon (subdomains, wayback) then fuzz; combine SSRF+LFI or SQLi+file read where applicable."


def automation_run(url: str, do_dir: bool = True, do_param: bool = True) -> Dict[str, Any]:
    """Run dir + param fuzzing and return combined result."""
    out: Dict[str, Any] = {"url": url, "dir_fuzz": [], "param_fuzz": []}
    if do_dir:
        out["dir_fuzz"] = dir_fuzz(url, timeout=8)
    if do_param:
        out["param_fuzz"] = param_fuzz(url, timeout=8)
    return out
