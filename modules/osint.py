import os
import re
import socket
import subprocess
from typing import Any, Dict, List, Optional

import requests

def _session() -> requests.Session:
    s = requests.Session()
    s.headers["User-Agent"] = "WebSecAI-OSINT/1.0"
    return s

def dns_lookup(domain: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {"domain": domain, "A": [], "AAAA": [], "MX": [], "TXT": [], "NS": [], "CNAME": []}
    try:
        out["A"] = list(socket.gethostbyname_ex(domain)[2]) if domain else []
    except (socket.gaierror, socket.timeout, OSError):
        pass
    try:
        import dns.resolver
        for rtype in ["AAAA", "MX", "TXT", "NS", "CNAME"]:
            try:
                ans = dns.resolver.resolve(domain, rtype)
                out[rtype] = [str(r) for r in ans]
            except Exception:
                pass
    except ImportError:
        pass
    return out

def whois_lookup(domain: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {"domain": domain, "raw": "", "parsed": {}}
    try:
        proc = subprocess.run(
            ["whois", domain],
            capture_output=True,
            text=True,
            timeout=15,
        )
        out["raw"] = (proc.stdout or "") + (proc.stderr or "")
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
        try:
            r = _session().get(f"https://whois.domaintools.com/{domain}", timeout=10)
            if r.status_code == 200:
                out["raw"] = r.text[:8000]
        except Exception:
            pass
    return out

def wayback_urls(domain: str, limit: int = 50) -> Dict[str, Any]:
    out: Dict[str, Any] = {"domain": domain, "urls": [], "count": 0}
    try:
        url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&limit={limit}&collapse=urlkey"
        r = _session().get(url, timeout=20)
        if r.status_code == 200 and r.text.strip():
            data = r.json()
            if isinstance(data, list) and len(data) > 1:
                out["urls"] = [row[2] if len(row) > 2 else row[0] for row in data[1:]]
                out["count"] = len(out["urls"])
    except Exception:
        pass
    return out

def shodan_host(ip: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {"ip": ip, "available": False, "data": {}}
    key = os.environ.get("SHODAN_API_KEY", "").strip()
    if not key:
        return out
    try:
        r = _session().get(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": key},
            timeout=15,
        )
        if r.status_code == 200:
            out["available"] = True
            out["data"] = r.json()
    except Exception:
        pass
    return out

def shodan_search(query: str, limit: int = 20) -> Dict[str, Any]:
    out: Dict[str, Any] = {"query": query, "available": False, "matches": []}
    key = os.environ.get("SHODAN_API_KEY", "").strip()
    if not key:
        return out
    try:
        r = _session().get(
            "https://api.shodan.io/shodan/host/search",
            params={"key": key, "query": query},
            timeout=15,
        )
        if r.status_code == 200:
            data = r.json()
            out["available"] = True
            out["matches"] = data.get("matches", [])[:limit]
    except Exception:
        pass
    return out

def censys_search(domain: str, limit: int = 20) -> Dict[str, Any]:
    out: Dict[str, Any] = {"domain": domain, "available": False, "results": []}
    api_id = os.environ.get("CENSYS_API_ID", "").strip()
    api_secret = os.environ.get("CENSYS_API_SECRET", "").strip()
    if not api_id or not api_secret:
        return out
    try:
        r = _session().get(
            "https://search.censys.io/api/v2/hosts/search",
            params={"q": f"names: {domain}", "per_page": limit},
            auth=(api_id, api_secret),
            timeout=15,
        )
        if r.status_code == 200:
            data = r.json()
            out["available"] = True
            out["results"] = data.get("result", {}).get("hits", [])[:limit]
    except Exception:
        pass
    return out

def hackertarget_lookup(domain: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {"domain": domain, "dns": "", "whois": ""}
    try:
        r = _session().get(f"https://api.hackertarget.com/dnslookup/?q={domain}", timeout=10)
        if r.status_code == 200 and "error" not in r.text.lower()[:100]:
            out["dns"] = r.text[:4000]
        r2 = _session().get(f"https://api.hackertarget.com/whois/?q={domain}", timeout=10)
        if r2.status_code == 200 and "error" not in r2.text.lower()[:100]:
            out["whois"] = r2.text[:4000]
    except Exception:
        pass
    return out

def osint_run(domain_or_ip: str, include_shodan: bool = True, wayback_limit: int = 30) -> Dict[str, Any]:
    domain = domain_or_ip.split("/")[0].split(":")[0].strip()
    is_ip = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain) is not None
    out: Dict[str, Any] = {
        "target": domain,
        "is_ip": is_ip,
        "dns": {},
        "whois": {},
        "wayback": {},
        "shodan": {},
        "censys": {},
        "hackertarget": {},
    }
    if not is_ip:
        out["dns"] = dns_lookup(domain)
        out["whois"] = whois_lookup(domain)
        out["wayback"] = wayback_urls(domain, limit=wayback_limit)
        out["hackertarget"] = hackertarget_lookup(domain)
        out["censys"] = censys_search(domain, limit=10)
    if include_shodan:
        out["shodan"] = shodan_host(domain) if is_ip else shodan_search(f"hostname:{domain}", limit=15)
    return out
